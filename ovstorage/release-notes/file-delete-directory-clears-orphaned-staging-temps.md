**The file backend's `delete_directory` now clears an atomic-write staging
temp left behind by a writer that died, so a directory that held an
interrupted upload can be removed through the API instead of staying
permanently undeletable.**

Each writer holds an exclusive advisory lock on its staging file from creation
until the rename that publishes it. The Rust reference and pure-C host probe
that lock before touching anything: a held lock is a write in flight and the
removal refuses with `DirectoryNotEmpty` naming it, a free lock is an orphan
and the removal clears it. The pid in the temp's name is no longer consulted,
so a reused pid cannot misclassify a live write.
