#!/usr/bin/env python3
"""Build and validate a fixed-source analysis artifact. Never touches Phorge data."""
import csv
import hashlib
import html
import io
import json
from pathlib import Path
import re
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parent
SCHEMA = json.loads((ROOT/'work/authoring-schema.json').read_text())
MANIFEST = json.loads((ROOT/'work/source-manifest.json').read_text())
REFERENCE = json.loads((ROOT/'work/reference-134.json').read_text())
REF = {x['id']:x for x in REFERENCE}
SRC = {x['pr']:x for x in MANIFEST['sources']}
PACKAGES = {
 'D01':'隔离回归与 CI 门禁', 'D02':'文件来源隐私与拒绝页保护',
 'D03':'策略呈现、本地化与安全替换', 'D04':'可选层级导航',
 'D05':'项目记录与历史兼容', 'D06':'统一工作区与任务草稿',
 'D07':'原生权限决策、审计与候选模型', 'D08':'组织团队目录与策略求值',
 'D09':'团队授权与受限项目角色', 'D10':'一次性成员导入',
 'D11':'受控权限移交', 'D12':'团队/角色组合历史与 Feed 撤权',
 'D13':'工作流状态与私有策略模板', 'D14':'文件能力链接当前策略守卫',
 'D15':'网关入口与原生会话绑定', 'D16':'账户维护只读界面与 RPC',
 'D17':'账户维护写能力', 'D18':'外部持久防重放与幂等账本', 'D19':'入口绑定安全清理'
}
AXES = {'ancestor_visibility':'祖先查看约束','parent_edit_inheritance':'父编辑继承',
        'membership_aggregation':'成员聚合/索引','historical_membership_edges':'历史成员边'}
FILES = {}
def blob(pr,path):
    key = (pr,path)
    if key not in FILES:
        FILES[key] = subprocess.check_output(['git','-C',SRC[pr]['repo'],'show',SRC[pr]['head']+':'+path]).decode('utf-8')
    return FILES[key]

def resolve(pr, ref):
    path = ref['path']
    text = blob(pr,path)
    symbol = ref.get('symbol','').strip()
    lines = text.splitlines()
    found = []
    if '::' in symbol:
        cls, method = symbol.split('::',1)
        method = method.removesuffix('()')
        active = None
        for index,line in enumerate(lines,1):
            match = re.search(r'^\s*(?:(?:final|abstract|readonly)\s+)*(?:class|interface|trait)\s+(\w+)',line)
            if match and not line.lstrip().startswith(('*','//','#')):
                active = match.group(1)
            if active == cls and re.search(r'\bfunction\s+'+re.escape(method)+r'\s*\(',line):
                found.append(index)
    elif symbol:
        name = symbol.removesuffix('()')
        for index,line in enumerate(lines,1):
            if re.search(r'\b(?:function|def|class|interface|trait)\s+'+re.escape(name)+r'\b',line):
                found.append(index)
    supplied = ref.get('line')
    if len(found)==1:
        ref['line']=found[0]
        ref['symbol_resolved']=True
    elif supplied and 1 <= supplied <= len(lines):
        ref['line']=supplied
        ref['symbol_resolved']=False
    else:
        ref['line']=None
        ref['symbol_resolved']=False
    ref['url']='https://github.com/Luzexuan/phorge/blob/'+SRC[pr]['head']+'/'+path+(('#L'+str(ref['line'])) if ref['line'] else '')
    return ref

def csv_file(name, columns, rows):
    with (ROOT/name).open('w',encoding='utf-8-sig',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=[x[0] for x in columns])
        writer.writerow({k:v for k,v in columns})
        writer.writerows(rows)

def compact(value):
    return json.dumps(value,ensure_ascii=False,separators=(',',':')) if isinstance(value,(dict,list)) else value

def main():
    atoms=[]; errors=[]; warnings=[]
    for pr in (48,49,50):
        rows=json.loads((ROOT/f'work/pr{pr}-atoms.json').read_text())
        for row in rows:
            if row.get('pr') != pr: errors.append(f"{row.get('id')}: incorrect PR")
            missing=set(SCHEMA['rowFormat'])-set(row)
            if missing: errors.append(f"{row.get('id')}: missing {sorted(missing)}")
            if missing: continue
            for key,example in SCHEMA['rowFormat'].items():
                if isinstance(example,str) and (not isinstance(row[key],str) or (key!='notes' and not row[key].strip())):errors.append(f"{row['id']}: empty/invalid {key}")
            for field,allow in [('kind',SCHEMA['allowedKinds']),('risk',SCHEMA['allowedRisks']),('source_status',SCHEMA['allowedSourceStatus'])]:
                if row[field] not in allow:errors.append(f"{row['id']}: invalid {field}={row[field]}")
            if row['package'] not in PACKAGES:errors.append(f"{row['id']}: unknown package")
            if set(row['axes']) != set(AXES):errors.append(f"{row['id']}: four-axis keys differ")
            for axis,value in row['axes'].items():
                if value not in SCHEMA['allowedAxisValues']:errors.append(f"{row['id']}: invalid axis {axis}={value}")
            if not isinstance(row['legacy_ids'],list) or not isinstance(row['depends_on'],list):errors.append(f"{row['id']}: IDs/dependencies must be lists")
            for old in row['legacy_ids']:
                if old not in REF:errors.append(f"{row['id']}: unknown legacy ID {old}")
            if not row['sources']:errors.append(f"{row['id']}: no source evidence")
            for field in ('sources','test_refs'):
                for reference in row[field]:
                    try:
                        resolve(pr,reference)
                        if field=='test_refs' and reference.get('symbol') and not reference['symbol_resolved']:
                            errors.append(f"{row['id']}: test symbol not uniquely resolved: {reference}")
                    except (subprocess.CalledProcessError,UnicodeDecodeError,KeyError) as exc:
                        errors.append(f"{row['id']}: invalid {field}: {exc}")
            parents=[REF[x] for x in row['legacy_ids']]
            strategies=sorted({x['strategy'] for x in parents})
            row['reference_strategy']=' / '.join(strategies) if strategies else '旧表未单列'
            row['adoption_scope']='仅引用2026-11-02父项采用快照；未逐子原子验证当前主干或生产'
            row['verification']='关联方法尚未逐断言核销' if row['test_refs'] else '无直接测试方法引用；正反验收为本次设计'
            row['package_name']=PACKAGES[row['package']]
            row['reference_relations']={}
            atoms.append(row)
    ids=[x['id'] for x in atoms]
    if len(ids)!=len(set(ids)):errors.append('Duplicate atomic IDs')
    byid={x['id']:x for x in atoms}
    for row in atoms:
        for dep in row['depends_on']:
            if dep == row['id']:errors.append(f"{row['id']}: self dependency")
            if dep not in byid and not any(dep.startswith(x) for x in SCHEMA['dependencyPrefixes']):errors.append(f"{row['id']}: unresolved dependency {dep}")
    reviews=[]
    for path in sorted((ROOT/'reviews').glob('*.json')):
        review=json.loads(path.read_text());reviews.append(review)
        for issue in review.get('issues',[]):
            if issue.get('severity') in ('blocking','major') and issue.get('status') not in ('resolved','accepted_limit'):
                errors.append(f"Unresolved review issue {issue.get('id')}")
        if review.get('target_pr') in (48,49,50):
            pr=review['target_pr']; raw=(ROOT/f'work/pr{pr}-atoms.json').read_bytes()
            if review.get('reviewed_dataset_sha256') != hashlib.sha256(raw).hexdigest():errors.append(f"PR{pr} peer review hash differs from final author data")
    for pr in (48,49,50):
        peers=[r for r in reviews if r.get('target_pr')==pr and r.get('reviewer')!=f'atom_author_pr{pr}']
        if not peers:errors.append(f"PR{pr} has no independent completed peer review")
    atoms.sort(key=lambda x:(x['pr'],x['id']))
    legacy=[]; exclusions=json.loads((ROOT/'work/reference-exclusions.json').read_text()) if (ROOT/'work/reference-exclusions.json').exists() else {}
    for old in REFERENCE:
        children=[x['id'] for x in atoms if old['id'] in x['legacy_ids']]
        exclusion=exclusions.get(old['id'])
        if not children and not exclusion:errors.append(f"Legacy ID {old['id']} has neither decomposition nor explicit exclusion")
        direct=[];related=[]
        for row in atoms:
            if old['id'] not in row['legacy_ids']:continue
            if old['id']=='B05':relation='测试支撑关联；源PR未新增CI门禁接入'
            elif old['id']=='B03':relation='本地化/既有测试关联；非完整双语回归门禁'
            elif old['id']=='B08':relation='语义差异/前提；不能等同后续主干ANY模型决策'
            elif old['id']=='H09':relation='原生权限消费者前提；非团队/角色组合实现'
            elif old['package']=='D07' and old['strategy']=='保留原生' and '候选改变' in row['axes'].values():relation='候选语义差异；不等于当前保留原生路线已采用'
            elif old['id']=='A19' and row['source_status']!='源PR仅客户端合同':relation='PHP请求侧前提；非外部持久防重放/幂等账本'
            elif old['id']=='A20' and row['source_status']=='源PR仅客户端合同':relation='客户端/外部合同关联；非服务端实现'
            elif row['source_status']=='源PR仅客户端合同':relation='客户端/外部合同关联；非服务端实现'
            elif row['package']!=old['package']:relation='跨包前置/关联；非该父项完整实现'
            else:relation='直接细分；不等于完整覆盖或逐项通过'
            row.setdefault('reference_relations',{})[old['id']]=relation
            (direct if relation.startswith('直接细分') else related).append(row['id'])
        legacy.append({'legacy_id':old['id'],'title':old['title'],'package':old['package'],'reference_category':old['category'],'reference_strategy':old['strategy'],'reference_implementation':old['implementation'],'child_count':len(children),'direct_child_count':len(direct),'related_child_count':len(related),'child_ids':' | '.join(children),'direct_child_ids':' | '.join(direct),'related_child_ids':' | '.join(related),'disposition':'有直接细分及可能的关联项' if direct else '仅前置/合同/差异关联' if related else '无本次源PR实现原子','limit':exclusion or '父项采用不等于所有子原子已采用或通过；以每个子原子的源码与限制为准'})
    coverage=[]
    for pr,source in SRC.items():
        for file in source['files']:
            direct=[x['id'] for x in atoms if x['pr']==pr and any(r['path']==file['path'] for r in x['sources'])]
            tests=[x['id'] for x in atoms if x['pr']==pr and any(r['path']==file['path'] for r in x['test_refs'])]
            support=('/__tests__/' in file['path'] or file['path'].startswith(('docs/','tests/')) or file['path'] in ('.gitignore','src/__phutil_library_map__.php'))
            if not direct and not tests and not support:errors.append(f"PR{pr} runtime/source file not mapped: {file['path']}")
            coverage.append({'pr':pr,'path':file['path'],'sha256':file['sha256'],'classification':'直接源码映射' if direct else '测试关联' if tests else '文档/测试/生成或依赖支持工件','atom_ids':' | '.join(direct),'test_atom_ids':' | '.join(tests),'limit':'文件级来源覆盖，不等于每行代码或每项行为已经测试通过'})
    # Report dependency cycles instead of hiding coupling behind an atom count.
    visited=set();active=[];cycles=[]
    def visit(key):
        if key in active:
            cycle=active[active.index(key):]+[key]
            if cycle not in cycles:cycles.append(cycle)
            return
        if key in visited:return
        active.append(key)
        for dep in byid[key]['depends_on']:
            if dep in byid:visit(dep)
        active.pop();visited.add(key)
    for key in ids:visit(key)
    for cycle in cycles:
        if len({byid[key]['safe_unit'] for key in cycle})>1:errors.append('Dependency cycle spans separate safe units: '+' -> '.join(cycle))
    if cycles:warnings.append({'dependency_cycles':cycles,'meaning':'存在互依行为；须作为共同安全单元审查，不得声称可任意独立部署'})
    summary={'atoms':len(atoms),'per_pr':{str(pr):sum(x['pr']==pr for x in atoms) for pr in (48,49,50)},'per_package':{k:sum(x['package']==k for x in atoms) for k in PACKAGES},'kinds':{k:sum(x['kind']==k for x in atoms) for k in SCHEMA['allowedKinds']},'source_statuses':{k:sum(x['source_status']==k for x in atoms) for k in SCHEMA['allowedSourceStatus']},'safe_units':len({x['safe_unit'] for x in atoms}),'source_file_occurrences':len(coverage),'reference_parents':len(legacy),'mapped_reference_parents':sum(x['child_count']>0 for x in legacy),'directly_decomposed_reference_parents':sum(x['direct_child_count']>0 for x in legacy),'review_records':len(reviews),'test_execution':'本轮未执行Phorge/生产测试；本表为拆分、来源核对和验收设计'}
    result={'passed':not errors,'errors':errors,'warnings':warnings,'summary':summary}
    (ROOT/'validation.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    if errors:
        print(json.dumps(result,ensure_ascii=False,indent=2));return 1
    document={'schema_version':'1.0','analysis_date':'2026-11-03','scope':'仅PR48–50固定head，非PR47重做、非主干整包采用、非生产启用或迁移授权','methodology':SCHEMA['rules'],'native_axes':AXES,'source_manifest':MANIFEST,'reference_snapshot':'2026-11-02附件；不能代替当前主干逐项采用审计','summary':summary,'atoms':atoms,'reference_crosswalk':legacy,'source_coverage':coverage,'reviews':reviews,'author_notes':{str(pr):json.loads((ROOT/f'work/pr{pr}-notes.json').read_text()) for pr in (48,49,50)},'limitations':['独立定义/验收不等于独立部署/回退。','安全单元是抽取与发布分析分组，并非源PR已有运行时开关。','旧父项已交付不认证本次所有更细子断言。','现有测试引用不代表本轮新执行或逐原子PASS。','固定源码事实与未来控制/外部后端义务分别记录。']}
    (ROOT/'atomic-decomposition.json').write_text(json.dumps(document,ensure_ascii=False,indent=2)+'\n')
    columns=[('id','原子ID'),('pr','源PR'),('package','开发包'),('legacy_ids','旧表父原子'),('reference_relations','父项映射关系'),('kind','原子类型'),('title','原子行为'),('object','对象定义'),('actor','执行者'),('entry','实际入口'),('given','前置条件'),('when','单一触发'),('then','正向可观察结果'),('denied','反向验收/拒绝结果'),('reads','读取范围'),('writes','写入与副作用'),('permission_effect','权限影响'),('control','源PR实际控制'),('rollback','回退/补偿边界'),('risk','风险'),('axes','四原生轴'),('depends_on','硬依赖与原生/外部前提'),('safe_unit','建议最小安全单元'),('source_status','源PR实现状态'),('reference_strategy','旧表父项采用策略'),('adoption_scope','采用状态口径'),('verification','验收证据状态'),('sources','固定源码证据'),('test_refs','现有测试方法关联'),('notes','限制与抽取备注')]
    csv_file('atomic-decomposition.csv',columns,[{k:compact(x[k]) for k,v in columns} for x in atoms])
    csv_file('reference-crosswalk.csv',[(k,k) for k in legacy[0]],legacy)
    csv_file('source-coverage.csv',[(k,k) for k in coverage[0]],coverage)
    (ROOT/'review-ledger.json').write_text(json.dumps(reviews,ensure_ascii=False,indent=2)+'\n')
    payload=json.dumps(document,ensure_ascii=False,separators=(',',':')).replace('<','\\u003c').replace('>','\\u003e').replace('&','\\u0026')
    template=(ROOT/'work/report-template.html').read_text()
    (ROOT/'atomic-decomposition.html').write_text(template.replace('<!--DATA-->',payload))
    artifacts=['atomic-decomposition.html','atomic-decomposition.csv','atomic-decomposition.json','reference-crosswalk.csv','source-coverage.csv','review-ledger.json','validation.json','build_report.py','work/authoring-schema.json','work/source-manifest.json','work/reference-exclusions.json','work/reference-134.json','work/report-template.html']+[f'work/pr{pr}-{kind}.json' for pr in (48,49,50) for kind in ('atoms','notes')]+[str(path.relative_to(ROOT)) for path in sorted((ROOT/'reviews').glob('*.json'))]
    artifacts+=['work/check-report-ui.mjs','work/check-integrity.py']
    ui_path=ROOT/'artifact-browser-check.json'
    if ui_path.exists():
        ui=json.loads(ui_path.read_text())
        if ui.get('passed') and all(hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==digest for name,digest in ui.get('checkedFiles',{}).items()) and ui.get('checkedFiles'):
            artifacts+=['artifact-browser-check.json','table-desktop.png','table-mobile.png']
    if (ROOT/'artifact-integrity.json').exists():artifacts+=['artifact-integrity.json']
    checksums={name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in artifacts}
    (ROOT/'artifact-checksums.json').write_text(json.dumps(checksums,indent=2)+'\n')
    with zipfile.ZipFile(ROOT/'phorge-pr48-50-atomic-decomposition-20261103.zip','w',compression=zipfile.ZIP_DEFLATED) as archive:
        for name in artifacts+['artifact-checksums.json']:archive.write(ROOT/name,name)
    print(json.dumps(result,ensure_ascii=False,indent=2));return 0

if __name__=='__main__':raise SystemExit(main())
