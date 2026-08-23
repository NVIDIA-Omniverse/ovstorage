# Platform support and release provenance

The prebuilt ovstorage release consists of three platform archives and three
platform wheels. Each archive contains the native hosts and plugins, the
source-distributed C baseline, public documentation, and operator assets.

The `abi3-py310` Python wheel is published beside the archives as its own
release asset rather than inside them, and it bundles the first-party plugin
libraries, so `pip install ovstorage` yields a complete runtime. Python
consumers take the wheel alone; the archive carries the same plugins for the
native hosts, and shipping both inside one file would ship every plugin twice.

## Supported release platforms

<!-- BEGIN GENERATED PLATFORM MATRIX -->
| Platform | OS | Architecture | Archive | Wheel tag | Runtime floor |
|---|---|---|---|---|---|
| `linux-x86_64` | Linux | x86_64 | `tar.gz` | `manylinux_2_34_x86_64` | glibc 2.39 (archive); glibc 2.34 (wheel) |
| `linux-arm64` | Linux | ARM64 (aarch64) | `tar.gz` | `manylinux_2_34_aarch64` | glibc 2.39 (archive); glibc 2.34 (wheel) |
| `windows-x86_64` | Windows | x86_64 | `zip` | `win_amd64` | Windows 10 or Windows Server 2016 and later |
<!-- END GENERATED PLATFORM MATRIX -->

Linux wheels and native archive binaries have separate glibc floors. Packaging
checks the wheel tag and imported symbols inside the wheel against the wheel
floor, then checks the prebuilt Rust hosts and plugins against the archive
floor. The C baseline ships as source and builds in the consumer's toolchain,
but its repository gates run on the same Linux and Windows families.

Check the floors above against your deployment targets.

The release publishes no macOS archive or wheel. macOS is a source portability
target rather than a supported prebuilt release platform. Windows ARM64 and
Linux architectures other than x86_64 and aarch64 also have no prebuilt
artifact.

The marked table is generated from the packaging platform registry.
`make verify` checks the table, release and verification workflow matrices,
final-release artifact allowlist, and Kitmaker wheel tags against that one
registry.

## Self-verifying archives

Every platform archive contains `release-manifest.json` at its root. It records:

- release version and exact source commit;
- whether the packaging checkout contains tracked or untracked modifications;
- the public platform record: operating system, architecture, archive format,
  wheel tag, and runtime floor;
- a SHA-256 digest for every other file in the archive.

Archive creation verifies the manifest against the completed `.tar.gz` or
`.zip` before reporting success. The separately published release manifest
checksums the outer platform archives and records the release
workflow/finalization provenance. These checks detect corruption and mismatched
artifacts; authenticity still depends on obtaining the release and its
manifest through a trusted publication channel. An offline mirror therefore keeps the
platform identity and complete inner file inventory with the archive itself,
while the outer manifest associates the archive with one release asset.
