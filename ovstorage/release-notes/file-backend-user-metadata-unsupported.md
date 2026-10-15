**The built-in `file` backend refuses a write that carries a non-empty `user_metadata`
with `Unsupported` and stores none.**

`update_metadata` on `file` returns `Unsupported`, and `stat` / `list` report
an empty user-metadata map. The kind declares no user-metadata support, so the
broker and the REST gateway place no attribution layer over a `file` branch: a
brokered write's principal is not stamped as `ovstorage_modified_by`, and
`modified_by` on `file` reflects the filesystem owner of the file — the broker
process's user, for a brokered write. A configuration that names an
attribution layer over a `file` backend refuses to start; the remedy is to
delete that layer, as the shipped `ovstorage-broker.toml` and
`ovstorage-rest.toml` do by routing the router to `file` directly. That
startup check sees only the immediate child: an attribution layer over a
`broker` connection whose far side routes to `file` starts normally, stamps
`ovstorage_modified_by` into every write, and has each of those writes refused
with `Unsupported` by the `file` backend at runtime. Keep attribution off a
`broker` branch whose upstream lands on `file`, or let the upstream host route
it to a backend that stores user metadata.
`.ovstorage-meta` directories left by earlier installations are ordinary
entries: `list` shows them and `delete_directory` counts them as content. Both
the Rust reference host and the C baseline behave this way.
