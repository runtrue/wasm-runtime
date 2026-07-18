# AOT cache operations

The disk AOT cache is an optional performance layer, not the source of a
package. Keep the original component available so an intentionally cleared
cache can be rebuilt.

## Inspect

Run the inspection command as the same operating-system user as the runtime:

```text
scripts/cache-admin.sh inspect /srv/runtrue/aot-cache
```

The command reports artifact, metadata, temporary-file, and byte counts. A
count mismatch or leftover temporary file reports `attention-required`. This
is a structural check; authentication is performed only when the runtime loads
an artifact.

The runtime creates the directory with mode `0700` and cache files with mode
`0600` on Unix. Alert on permission or ownership changes. Never expose the
cache or its authentication key to a guest or tenant.

## Clear and recover

Cache clearing is deliberately an offline operation because the runtime does
not coordinate writers with an external administration process:

1. Stop every runtime process using the directory.
2. Preserve the original components and the current authentication key.
3. Inspect the directory and record unexpected files before removal.
4. Supply the canonical path twice to clear only recognized cache files:

   ```text
   scripts/cache-admin.sh clear /srv/runtrue/aot-cache \
       --confirm /srv/runtrue/aot-cache
   ```

5. Restart one runtime and prepare a known component.
6. Inspect again, then restore normal traffic.

The command rejects symlinks and broad paths and removes only `.aot`,
`.aot.json`, and interrupted-publication temporary files in the cache
directory. It does not recursively remove directories or unrelated files.

## Required maintenance windows

An existing artifact with the wrong authentication key, Wasmtime version,
target, compiler profile, WASI profile, digest, length, or authentication tag
fails closed. It is not silently treated as trusted input or overwritten.
Therefore use the offline clear procedure before:

- rotating `AotAuthenticationKey`;
- upgrading the pinned Wasmtime version or changing engine/compiler settings;
- moving a cache between architectures or operating systems; or
- recovering from malformed, truncated, or half-published entries.

Deploy the new binary and authentication key only after the old cache is
clear. Rolling upgrades must use a new cache directory per runtime/cache
identity until all old processes have stopped.

## Capacity and write failures

Set `DiskCacheConfig::max_entry_bytes` below the filesystem and operational
quota. If a newly compiled artifact cannot be published because the cache is
full, read-only, missing, or over quota, the call continues with the compiled
warm and warmish in-memory entries. A fresh runtime will compile again because
there is no durable cache hit. Monitor free space and keep enough headroom for
one artifact plus its metadata to be published atomically. Export and alert on
`Runtime::metrics().disk_publish_failures`; any nonzero increase means the
durable tier is not receiving newly compiled entries.

Two runtime processes may publish the same authenticated entry concurrently;
unique temporary names and atomic renames leave a loadable final pair. Do not
run external cleanup concurrently with those writers.
