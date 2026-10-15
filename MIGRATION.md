# Working with the combined source layout

The public checkout contains the storage library under `ovstorage/` and the
USD resolver under `ovstorage-usd-resolver/`. Shared product documentation and
skills live at the checkout root. See [docs/building.md](docs/building.md) for build commands
and [VERSION.md](VERSION.md) for the selected component versions.

## Paths and builds

| Storage path in a flat checkout | Path in this checkout |
| --- | --- |
| `Cargo.toml` | `ovstorage/Cargo.toml` |
| `Makefile` | `ovstorage/Makefile` |
| `ovstorage-core/` | `ovstorage/ovstorage-core/` |
| `ovstorage-c-source/` | `ovstorage/ovstorage-c-source/` |
| `docs/public/` | `ovstorage/docs/public/` |
| `skills/` | `ovstorage/skills/` for storage skills; `skills/` for shared skills |

From the repository root, use `make -C ovstorage dist` for storage builds.
Run other storage commands from `ovstorage/`, or pass their explicit manifest
or working-directory option. Storage examples use `$PWD/dist/plugins` or
`$PWD/target/release` from that component directory; the Git top-level directory
identifies the outer product checkout. Point the resolver's `OVS_OVSTORAGE_SDK_ROOT` at
`$PWD/ovstorage`. Update path dependencies, checkout subdirectories, scripts,
and bookmarks to include the component directory.

Existing tags and commit pins retain the layout recorded at those revisions.
Git dependencies should pin a reviewed release or commit and name the intended
package. A component package version and a combined source label are different
identifiers; consult the snapshot's version and provenance files.

## Documentation destinations

The [Python guide](ovstorage/docs/public/library-python/README.md) has a
forwarding page at `docs/public/library-python/README.md`, preserving the link
embedded in released Python package descriptions. This is a navigation page,
not a filesystem alias for build inputs or raw source URLs.

The [C++ examples](ovstorage/ovstorage-c-source/examples/tutorial/README.md)
live within the storage component. Use that nested path for links to this
checkout, or the [versioned 0.3.0 tutorial](https://github.com/NVIDIA-Omniverse/ovstorage/tree/v0.3.0/ovstorage-c-source/examples/tutorial)
for the 0.3.0 layout. The public root has no `ovstorage-c-source/` directory.

Use relative links within this checkout. When linking from an external package
or document, prefer an immutable public tag or commit for version-specific
instructions. Links to `main` follow the current source layout.
