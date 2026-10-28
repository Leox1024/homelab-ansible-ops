<?php

/*
 * Sets one authorized_keys entry (AUTH_ENTRY, options included) on the OPNsense user
 * AUTH_USER, replacing any entry of the same key and keeping the others. Prints
 * "changed" or "unchanged"; sync_user.php then writes the file.
 */

require_once('config.inc');
require_once('auth.inc');

$user = (string)getenv('AUTH_USER');
$entry = trim((string)getenv('AUTH_ENTRY'));
if (!preg_match('/(?:ssh-[a-z0-9-]+|ecdsa-[a-z0-9-]+) ([A-Za-z0-9+\/=]+)/', $entry, $m)) {
    fwrite(STDERR, "AUTH_ENTRY holds no public key\n");
    exit(1);
}
$blob = $m[1];

$found = false;
$changed = false;
$users = &config_read_array('system', 'user');
foreach ($users as &$u) {
    if ($u['name'] !== $user) {
        continue;
    }
    $found = true;
    $keys = array_values(array_filter(array_map('trim', explode("\n", base64_decode($u['authorizedkeys'] ?? ''))), 'strlen'));
    $same = array_values(array_filter($keys, function ($k) use ($blob) {
        return strpos($k, $blob) !== false;
    }));
    if ($same === [$entry]) {
        break;
    }
    $kept = array_values(array_filter($keys, function ($k) use ($blob) {
        return strpos($k, $blob) === false;
    }));
    $u['authorizedkeys'] = base64_encode(implode("\n", array_merge($kept, [$entry])));
    $changed = true;
}
unset($u);

if (!$found) {
    fwrite(STDERR, "no user $user\n");
    exit(1);
}
if ($changed) {
    write_config("Automation key of $user updated");
}
echo $changed ? "changed\n" : "unchanged\n";
