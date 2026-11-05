<?php

// Apache sets this as auto_prepend_file before any Phorge request bootstrap.
// CLI workers and maintenance commands retain their existing environment.
if (PHP_SAPI !== 'apache2handler') {
    return;
}

(static function () {
    // This is the directly connected Traefik address on the dedicated web
    // network. Never derive trust from a client-supplied forwarding header.
    if (($_SERVER['REMOTE_ADDR'] ?? '') === '172.29.240.2') {
        return;
    }

    foreach (array_keys($_SERVER) as $name) {
        // PHP normalizes HTTP header aliases before application code runs.
        // Clear the whole identity namespace, including future identity fields.
        $normalized = strtoupper(strtr((string) $name, array('-' => '_', '.' => '_')));
        if (str_starts_with($normalized, 'HTTP_X_AUTH_') ||
            $normalized === 'HTTP_X_FORWARDED_USER') {
            unset($_SERVER[$name]);
        }
    }
})();
