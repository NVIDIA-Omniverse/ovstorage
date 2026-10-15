**The CLI can initialize a usable storage configuration from a fresh install.**
`ovstorage init` writes and loads the minimal built-in `file` layer graph, enabling `connect file <dir>` and `write-config` to produce a reusable configuration without hand-authoring its layer tables.
