#!/usr/bin/env python3
"""Exercise a running core; creates harmless queue fixtures and deletes test blobs.

Verifies PHP -> Queue -> Worker -> Conduit -> PHP execution and followups,
inbox replay, each blob backend, API authentication, and SQL denial checks.
No business objects or users are created. Queue fixture audit records remain.
"""
import importlib.util
import datetime
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("core_generator", ROOT / "scripts/generate-core.py")
generator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(generator)

PHP = r'''
ini_set('display_errors', '0');
$input = json_decode(stream_get_contents(STDIN), true);
$root = '/opt/phorge/phorge';
$config = json_decode(file_get_contents($root.'/conf/local/deployment.json'), true)
  + json_decode(file_get_contents($root.'/conf/local/local.json'), true);
$results = array();
class CoreSmokeFailure extends Exception {}
function ensure($condition, $message) {
  if (!$condition) { throw new CoreSmokeFailure($message); }
}
function check($name, $callback) {
  global $results;
  try { $detail = $callback(); $results[$name] = array('pass' => true, 'detail' => $detail); }
  catch (Throwable $ex) {
    $results[$name] = array('pass' => false, 'error' => get_class($ex));
    if ($ex instanceof CoreSmokeFailure) { $results[$name]['detail'] = $ex->getMessage(); }
  }
}
function request($uri, $token = null, $method = 'GET', $body = null, $type = 'application/json') {
  $curl = curl_init($uri);
  $headers = array('Content-Type: '.$type);
  if ($token !== null) { $headers[] = 'X-Service-Token: '.$token; }
  curl_setopt_array($curl, array(CURLOPT_CUSTOMREQUEST => $method,
    CURLOPT_HTTPHEADER => $headers, CURLOPT_RETURNTRANSFER => true,
    CURLOPT_TIMEOUT => 12, CURLOPT_FOLLOWLOCATION => false));
  if ($body !== null) { curl_setopt($curl, CURLOPT_POSTFIELDS, $body); }
  $bytes = curl_exec($curl);
  $status = curl_getinfo($curl, CURLINFO_HTTP_CODE);
  curl_close($curl);
  return array($status, $bytes, json_decode($bytes ?: '', true));
}
function api($service, $path, $method = 'GET', $data = null) {
  global $config;
  $body = $data === null ? null : json_encode($data);
  return request(rtrim($config['gorge.'.$service.'.uri'], '/').$path,
    $config['gorge.'.$service.'.token'], $method, $body);
}

$protected = array(
  'render' => array('/api/highlight/languages', 'GET'),
  'conduit' => array('/api/worker.execute', 'POST'),
  'file' => array('/api/file/engines', 'GET'),
  'webhook' => array('/api/webhook/stats', 'GET'),
  'taskqueue' => array('/api/queue/meta', 'GET'),
  'db' => array('/api/db/meta', 'GET'));
foreach ($protected as $service => $route) {
  check('reject_unauthorized_'.$service, function() use ($config, $service, $route) {
    $uri = rtrim($config['gorge.'.$service.'.uri'], '/').$route[0];
    foreach (array(null, 'invalid-smoke-token') as $token) {
      list($status) = request($uri, $token, $route[1], $route[1] === 'POST' ? '{}' : null);
      ensure($status === 401, 'Unauthorized request accepted');
    }
    return 'missing and wrong tokens return 401';
  });
}
check('reject_unauthorized_worker', function() {
  foreach (array(null, 'invalid-smoke-token') as $token) {
    list($status) = request('http://gorge-worker:8170/api/worker/meta', $token);
    ensure($status === 401, 'Unauthorized worker request accepted');
  }
  return 'missing and wrong tokens return 401';
});
check('render_diff', function() {
  list($status, , $json) = api('render', '/api/diff/generate', 'POST',
    array('old' => "before\n", 'new' => "after\n"));
  ensure($status === 200 && strpos($json['data']['diff'] ?? '', '+after') !== false,
    'Diff output unavailable');
  return 'changed lines generated';
});
foreach (array('blob', 'local-disk') as $engine) {
  check('file_roundtrip_'.$engine, function() use ($engine, $config) {
    $bytes = 'team-management-smoke:'.bin2hex(random_bytes(32))."\n";
    $uri = rtrim($config['gorge.file.uri'], '/').'/api/file/blob';
    $token = $config['gorge.file.token'];
    list($status, , $json) = request($uri.'?engine='.$engine.'&name=smoke.txt', $token,
      'POST', $bytes, 'application/octet-stream');
    ensure($status === 200 && ($json['data']['engine'] ?? '') === $engine,
      'Selected storage engine failed');
    $query = http_build_query(array('engine' => $engine, 'handle' => $json['data']['handle']));
    try {
      list($status, $fetched) = request($uri.'?'.$query, $token);
      ensure($status === 200 && hash_equals($bytes, $fetched), 'Byte integrity failed');
    } finally {
      list($deleted) = request($uri.'?'.$query, $token, 'DELETE');
      ensure($deleted === 200, 'Fixture cleanup failed');
    }
    list($status) = request($uri.'?'.$query, $token);
    ensure($status === 404, 'Deleted blob remains readable');
    return 'write, exact read, delete, then 404';
  });
}
check('notification_listener_isolation', function() {
  list($status) = request('http://172.29.241.10:22281/healthz');
  ensure($status === 200, 'Admin listener unavailable');
  $socket = @fsockopen('172.29.241.10', 22280, $number, $message, 2);
  if ($socket) { fclose($socket); }
  ensure($socket === false, 'Client listener bound on admin interface');
  return 'admin interface serves only admin port';
});

function conduit($url, $token, $parameters) {
  return request($url.'/api/worker.execute', $token, 'POST',
    http_build_query(array('params' => json_encode($parameters), 'output' => 'json')),
    'application/x-www-form-urlencoded');
}
$probe = array('taskID' => 0, 'phase' => 'capabilities', 'executionVersion' => 1,
  'failureCount' => 0, 'priority' => 0, 'leaseOwner' => '', 'leaseExpires' => 0, 'taskClass' => '');
check('php_independent_token_validation', function() use ($probe) {
  list($status, , $json) = conduit('http://phorge', 'invalid-smoke-token', $probe);
  ensure(($json['error_code'] ?? '') === 'ERR-WORKER-AUTH', 'PHP token validation failed');
  return 'direct PHP rejects wrong token';
});
check('php_capabilities_and_context', function() use ($config, $probe) {
  list($status, , $json) = conduit($config['gorge.conduit.uri'], $config['gorge.conduit.token'], $probe);
  ensure(($json['result']['executionVersion'] ?? null) === 1, 'PHP capabilities failed');
  $probe['phase'] = 'execute'; $probe['taskClass'] = 'PhabricatorTestWorker';
  list($status, , $json) = conduit($config['gorge.conduit.uri'], $config['gorge.conduit.token'], $probe);
  ensure(($json['error_code'] ?? '') === 'ERR-WORKER-CONTEXT', 'Invalid execution context accepted');
  return 'gateway capabilities pass; expired context rejected';
});

check('readonly_database_account', function() use ($input, $config) {
  $namespace = $config['storage.default-namespace'];
  mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
  $db = new mysqli('mysql', 'gorge_db', $input['GORGE_DB_MYSQL_PASSWORD'], $namespace.'_worker');
  $row = $db->query('SELECT COUNT(*) AS n FROM worker_activetask')->fetch_assoc();
  $denied = false;
  try { $db->query('UPDATE worker_activetask SET id=id WHERE 1=0'); }
  catch (mysqli_sql_exception $ex) { $denied = in_array($ex->getCode(), array(1142, 1143)); }
  ensure($denied, 'Read-only account permits update');
  $db->close();
  return 'SELECT works; zero-row UPDATE denied';
});
check('queue_database_scope', function() use ($input, $config) {
  $namespace = $config['storage.default-namespace'];
  $db = new mysqli('mysql', 'gorge_queue', $input['GORGE_QUEUE_MYSQL_PASSWORD'], $namespace.'_worker');
  $db->query('SELECT COUNT(*) FROM worker_activetask');
  $denied = false;
  try { $db->query('SELECT COUNT(*) FROM `'.$namespace.'_user`.user WHERE 1=0'); }
  catch (mysqli_sql_exception $ex) { $denied = in_array($ex->getCode(), array(1044, 1142)); }
  ensure($denied, 'Queue account can access user schema');
  $db->close();
  return 'queue SELECT works; user schema denied';
});

require_once $root.'/scripts/__init_script__.php';
function wait_archive($id) {
  $deadline = microtime(true) + 35;
  while (microtime(true) < $deadline) {
    $task = (new PhabricatorWorkerArchiveTask())->load($id);
    if ($task) {
      ensure((int)$task->getResult() === PhabricatorWorkerArchiveTask::RESULT_SUCCESS,
        'Task did not complete successfully');
      return $task;
    }
    usleep(300000);
  }
  throw new CoreSmokeFailure('Task archive deadline exceeded');
}
check('php_queue_worker_delegate_followup', function() {
  $task = PhabricatorWorker::scheduleTask('PhabricatorTestWorker',
    array('queueFollowup' => true, 'followupCount' => 1));
  $parent = wait_archive($task->getID());
  $db = $parent->establishConnection('r');
  $deadline = microtime(true) + 35;
  do {
    $rows = queryfx_all($db,
      'SELECT a.id, a.result, d.data FROM %T a JOIN %T d ON a.dataID=d.id '
      .'WHERE a.id>%d AND a.taskClass=%s ORDER BY a.id LIMIT 10',
      $parent->getTableName(), (new PhabricatorWorkerTaskData())->getTableName(),
      $parent->getID(), 'PhabricatorTestWorker');
    foreach ($rows as $row) {
      $data = json_decode($row['data'], true);
      if (!empty($data['isFollowup'])) {
        ensure((int)$row['result'] === 0, 'Followup failed');
        return array('parentTaskID' => (int)$parent->getID(), 'followupTaskID' => (int)$row['id']);
      }
    }
    usleep(300000);
  } while (microtime(true) < $deadline);
  throw new CoreSmokeFailure('Followup deadline exceeded');
});
check('queue_inbox_replay', function() {
  $event = 'deployment-smoke:'.bin2hex(random_bytes(16));
  $payload = array('eventID' => $event,
    'task' => array('taskClass' => 'PhabricatorTestWorker', 'data' => '{}'));
  list($status, , $first) = api('taskqueue', '/api/queue/enqueue-event', 'POST', $payload);
  ensure($status === 200 && isset($first['data']['id']), 'Event enqueue failed');
  wait_archive($first['data']['id']);
  list($status, , $second) = api('taskqueue', '/api/queue/enqueue-event', 'POST', $payload);
  ensure($status === 200 && $first['data']['id'] === $second['data']['id'], 'Replay duplicated task');
  return array('taskID' => $first['data']['id'], 'replayReturnedSameTask' => true);
});
$failed = array_filter($results, function($result) { return !$result['pass']; });
echo json_encode(array('passed' => count($failed) === 0, 'checks' => $results), JSON_PRETTY_PRINT)."\n";
exit($failed ? 1 : 0);
'''


def main():
    env = generator.load_env(ROOT / ".env")
    secret_input = {key: env[key] for key in (
        "GORGE_DB_MYSQL_PASSWORD", "GORGE_QUEUE_MYSQL_PASSWORD")}
    container = subprocess.check_output([
        "docker", "compose", "--env-file", str(ROOT / ".env"),
        "-f", str(ROOT / "compose.core.yaml"), "ps", "-q", "phorge"],
        text=True, cwd=ROOT).strip()
    if not container:
        raise SystemExit("Phorge is not running")
    result = subprocess.run(["docker", "exec", "-i", container, "php", "-r", PHP],
                            input=json.dumps(secret_input), capture_output=True,
                            text=True, timeout=180)
    # Only structured test results are released. Raw application exceptions may
    # contain internal connection details, so stderr is not forwarded.
    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError:
        print(json.dumps({"passed": False, "error": "PHP smoke did not return JSON",
                          "exitCode": result.returncode}))
        return 1
    report['verified_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    report['scope'] = 'internal initialization; no browser identity, object Policy, or fault recovery acceptance'
    print(json.dumps(report, indent=2))
    (ROOT / "state/core-smoke.json").write_text(json.dumps(report, indent=2) + "\n")
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
