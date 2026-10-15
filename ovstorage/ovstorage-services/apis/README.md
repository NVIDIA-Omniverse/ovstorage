# ovstorage Service APIs

This directory contains published API snapshots used by ovstorage service-mode
clients and service implementations. Keep each API self-contained: specs,
conformance tests, examples, docs, and changelog live under that API's folder.

## Local API Snapshots

| API | Local path | Status |
|---|---|---|
| Storage API | [`storage-api/`](storage-api/) | Present: `1.0.0-beta.4` release snapshot with proto, OpenAPI, conformance tests, filesystem example, templates, and generated docs |
| Notifications API | [`notifications-api/`](notifications-api/) | Present: grouped Aggregation and Consumer API release snapshots |
| Permissions API | [`permissions-api/`](permissions-api/) | Present: `v1beta` release snapshot with proto, OpenAPI, and generated docs |

Known import issue: the Storage API `1.0.0-beta.4` OpenAPI YAML files contain
blank `$ref` keys as shipped, for example `- : '#/components/...'`. They are
mirrored here unchanged and should be fixed in the upstream release bundle
rather than patched locally.

Notifications and Permissions API material must remain siblings of
`storage-api/`, not nested inside it:

```text
ovstorage-services/apis/
├── storage-api/
├── notifications-api/
└── permissions-api/
```

## Expected Per-API Layout

These directories mirror upstream release artifacts as shipped, so exact folder
names vary by API (`proto/` vs `protos/`, generated `docs/`, example folders,
and release-specific helper scripts). Keep each API self-contained.

```text
apis/<api-name>/
├── proto|protos/       # Protocol buffer definitions for gRPC
├── openapi/            # REST OpenAPI specifications
├── conformance_tests/  # API conformance suite
├── examples/           # Client and service examples when available
├── docs/               # API-specific docs
├── RFCs/               # API-specific design/history notes when available
├── README.md
└── CHANGELOG.md
```

## Editing Rules

1. Treat mirrored API content as read-only unless the task explicitly asks for
   a contract snapshot update.
2. Proto, OpenAPI, conformance tests, and examples must stay aligned for the
   API being changed.
3. Service implementation source, charts, and deployment assets do not live in
   this directory.
4. Generated HTML docs and release-package helper files are kept with their
   owning API snapshot.

## Related Skills

- Read API contracts: [`../skills/api-reference.md`](../skills/api-reference.md)
- Run conformance: [`../skills/conformance-testing.md`](../skills/conformance-testing.md)
- Contribute API changes: [`../skills/api-contribute/AGENTS.md`](../skills/api-contribute/AGENTS.md)
