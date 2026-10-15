# ovstorage source agent entry

This entry applies to the assembled public checkout. Read
[README.md](README.md) for component scope, [getting started](docs/getting-started.md)
for the combined build and dependency selection, and
[MIGRATION.md](MIGRATION.md) for component working directories.

- Questions spanning both components, or from another agent: [ovstorage expert](skills/ovstorage-expert/SKILL.md).
- Skills and component workflow guides: [skills/README.md](skills/README.md).
- Storage APIs, providers, and language bindings: [ovstorage/AGENTS.md](ovstorage/AGENTS.md).
- USD resolution and integration: [ovstorage-usd-resolver/AGENTS.md](ovstorage-usd-resolver/AGENTS.md).

Build the resolver against this checkout's storage source using the explicit
SDK path in [the combined build guide](docs/building.md). A prebuilt provider bundle must be
compatible with that source. If a platform lacks binaries, follow the source
build instructions and report unsupported prerequisites explicitly.

The storage library publishes packages; the resolver publishes no wheels for
this release. Keep current Kit 25.11 monolithic build restrictions explicit.
`ovstorage/ovstorage-services/` contains vendored API contracts and reference
material, not production services or their deployment assets. Read the
[component boundaries](docs/getting-started.md#component-boundaries) before
routing service or broker work.
