**Python stacks can now load the same startup configuration as the CLI.**
`Stack.from_config()` reads CLI-written `[ovstorage]` graphs and connections,
using the shared environment and default-path resolution so applications can
reuse one configuration instead of reconstructing it in Python.
