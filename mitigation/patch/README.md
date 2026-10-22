# PHP Source Patch

C-level fix for `ext/session/session.c` — replaces dangling `zval *` bucket
pointers with direct `zend_long` counters and introduces safe sync function.

## Apply

```bash
cd /path/to/php-src
patch -p1 --dry-run < session-upload-progress-counters.patch   # test
patch -p1 < session-upload-progress-counters.patch             # apply
make -j$(nproc) && sudo make install
sudo systemctl restart php-fpm   # or apache2
```

## What It Fixes

The root cause: `post_bytes_processed` and `current_file_bytes_processed`
were stored as raw `zval *` pointers into a HashTable that could be freed
and reallocated during progress updates. The patch stores them as plain
`zend_long` values and resolves array entries on demand via
`php_session_rfc1867_sync_counters()`.

For EOL PHP (5.x, 7.x, 8.0, 8.1) backports, see:
https://github.com/Anton-Barinov/php2shell-patches
