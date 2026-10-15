**The file backend's `delete_directory` now refuses an operator-configured
symlink with `InvalidArgument` instead of destroying its target's metadata
sidecar and reporting `NotFound`.**

The Rust reference and pure-C host classify the addressed entry without
following it, before any sidecar cleanup. The operator-owned link remains in
place, and host-side recursive deletion stops at it with explanatory guidance
after deleting the linked directory's contents.
