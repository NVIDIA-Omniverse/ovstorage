# ovstorage

`ovstorage` is a portable storage abstraction for Rust, C, C++, and Python:
one address-routed object API with a stable C ABI for backend plugins.
Switching backends is a route-registration change, not a recompile.

The core library, CLI, MCP server, result-envelope contract, C ABI cdylib,
C++ header, and Python wheel live in [`ovstorage-core/`](ovstorage-core/),
along with first-party plugins for `file://` and HTTP(S) addresses. First-
party cloud, services-client, Nucleus, broker, REST, and authz components
extend the surface across `ovstorage-services-client/`, `ovstorage-cloud/`,
`ovstorage-nucleus/`, and `ovstorage-remote/`.

## Layout

| Path | Purpose |
|---|---|
| [`ovstorage-core/`](ovstorage-core/) | Core Rust library, CLI, MCP server, result envelope, cache, plugin SPI, C/C++/Python bindings, and `file`/`http`/test plugins |
| [`ovstorage-services-client/`](ovstorage-services-client/) | Omniverse Storage Service client: cdylib backend plugin + tonic-generated proto stubs compiled against `ovstorage-services/` |
| [`ovstorage-cloud/`](ovstorage-cloud/) | First-party cloud-storage plugins: `s3`, `gcs`, `azure`, `opendal` cdylibs |
| [`ovstorage-nucleus/`](ovstorage-nucleus/) | Transitional Nucleus compatibility: `nucleus` cdylib plugin plus five `nucleus-*` protocol-binding crates (omni1 client/transport/discovery/auth/codegen) |
| [`ovstorage-remote/`](ovstorage-remote/) | Broker daemon (`ovstorage-broker`), REST gateway (`ovstorage-rest`), broker-client cdylib, authz SPI + first-party TOML authz plugin, and the broker wire-protocol crate |
| [`ovstorage-services/`](ovstorage-services/) | Service/API contracts, conformance material, deployment guidance, and service skills (vendored source of truth — do not modify in place) |
| [`docs/`](docs/) | PRD/SRD/SDD, glossary, agent MCP/envelope reference, and persona docs |
| [`skills/`](skills/) | Agent skills for user, operator, and contributor workflows |
| [`xtask/`](xtask/) | Repo automation for verify, distribution, release versioning, generated headers, and skill validation |

## Start Here

| Goal | Entry |
|---|---|
| Use the Rust library | [`docs/public/library-rust/README.md`](docs/public/library-rust/README.md) |
| Use the Python binding | [`docs/public/library-python/README.md`](docs/public/library-python/README.md) |
| Use the C++ binding | [`docs/public/library-cpp/README.md`](docs/public/library-cpp/README.md) |
| Call ovstorage over HTTP/REST | [`docs/public/library-web/README.md`](docs/public/library-web/README.md) |
| Write a storage plugin | [`docs/public/plugin-storage/README.md`](docs/public/plugin-storage/README.md) |
| Write an authz plugin | [`docs/public/plugin-authz/README.md`](docs/public/plugin-authz/README.md) |
| Operate the broker daemon | [`docs/public/broker-operator/README.md`](docs/public/broker-operator/README.md) |
| Work on the repo | Start at [`AGENTS.md`](AGENTS.md), then use the source-developer skills under [`skills/`](skills/) |
| Use the MCP/envelope contract | [`docs/public/agent/README.md`](docs/public/agent/README.md) |
| Work on service/API material | [`ovstorage-services/AGENTS.md`](ovstorage-services/AGENTS.md) |

## Skills

`skills/` is the catalog of invocable agent skills for ovstorage workflows
that can be reviewed for external publication. The dist layout assembled by
`make dist` ships `skills/ovstorage-user-*` and
`skills/ovstorage-operator-*` to end users and operators;
`skills/ovstorage-contributor-*` stays in the repo for developers and is
intentionally excluded from release archives.

- **User skills** — connecting over MCP, discovering backends,
  choosing one, authenticating, reading / writing / listing safely,
  materializing, handling errors.
- **Operator skills** — deploying `ovstorage-broker`, authoring its authz
  policy, monitoring the running daemon, debugging incidents.
- **Source-developer skills** — authoring storage plugins or authz plugins,
  running the broker locally, regenerating C headers, running conformance,
  running the verification gate.

These root skills are for the ovstorage library/plugin/broker surface.
They are deliberately separate from the heavier `ovstorage-services`
Kubernetes stack and its service-deployment skills, which live under
`ovstorage-services/skills/` in source checkouts.

See [`AGENTS.md`](AGENTS.md) for the per-skill routing table.

## Vendored Omniverse Storage Service contracts

[`ovstorage-services/`](ovstorage-services/) is a vendored snapshot of the
Omniverse Storage Service API definitions, conformance suite, and
deployment guidance. The `ovstorage-services-client` workspace compiles
its tonic stubs directly from `ovstorage-services/apis/storage-api/proto/`,
so the in-repo client always matches the canonical wire contract.

`ovstorage-services/` is not licensed by the root Apache-2.0 grant. It
contains separately licensed service/API material, including files marked
`LicenseRef-NvidiaProprietary` and NVIDIA Software License Agreement /
Omniverse product terms. The applicable license files are preserved in that
subtree and summarized in [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).

**Do not modify `ovstorage-services/` in place** — consumer-side adapters live
in `docs/public/` and the `*-client` workspaces; CI flags any edits to the
vendored subtree.

## External Contributions

This project is currently not accepting contributions.

## Verification

`make verify` is the non-test repo gate. It validates generated headers,
Rust and TOML formatting, license / advisory / unused-dependency checks,
clippy, rustdoc broken-link checks, public-doc links, and publication-ready
skill frontmatter.
Run `make test` for the Rust test suite across all five active workspaces.

`make dist` assembles the release layout, including
`skills/ovstorage-user-*`, `skills/ovstorage-operator-*`, and a filtered
`services/` copy of the `ovstorage-services` service/API release surface
while excluding `skills/ovstorage-contributor-*`. The `services/` copy keeps
contracts, conformance material, service examples, deployment guidance,
templates, service skills, generated API HTML docs, and the license/product-term
files that govern them; build/dependency caches are not packaged.
The Python wheel currently does not package agent skills.

## License

ovstorage uses a split license:

- **Source code** — Rust crates, C/C++ headers, the Python binding, the CLI,
  the MCP server, and all first-party plugins — is licensed under the Apache
  License, Version 2.0. See [`LICENSE`](LICENSE).
- **Agent skills under [`skills/`](skills/)** — the user, operator, and
  contributor skill prose — is licensed under the Creative Commons
  Attribution 4.0 International License (CC BY 4.0). See
  [`skills/LICENSE.txt`](skills/LICENSE.txt) for the verbatim license text
  and [`skills/NOTICE.txt`](skills/NOTICE.txt) for the NVIDIA grant. Each
  `skills/<slug>/SKILL.md` also carries `license: CC-BY-4.0` in its YAML
  frontmatter.
- **Vendored service/API material under [`ovstorage-services/`](ovstorage-services/)**
  is not covered by the root Apache-2.0 grant. It includes NVIDIA proprietary
  material and NVIDIA Software License Agreement / Omniverse product terms;
  see the in-subtree license files and the
  [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) vendored service/API
  section.

Third-party attribution is recorded in
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
