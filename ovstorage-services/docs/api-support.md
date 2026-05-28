# API Support Declaration

Service implementations should declare which published API versions they
support. The template lives at
[`../templates/api-support.yaml`](../templates/api-support.yaml).

Use this declaration to align:

- service runtime capability discovery;
- release notes;
- conformance gates;
- library service-adapter compatibility;
- deployment and rollback decisions.

## API Layout

Published API snapshots belong under:

```text
ovstorage-services/apis/<api-name>/
```

Current snapshots:

| API | Local path |
|---|---|
| Storage API | [`../apis/storage-api/`](../apis/storage-api/) |
| Notifications API | [`../apis/notifications-api/`](../apis/notifications-api/) |
| Permissions API | [`../apis/permissions-api/`](../apis/permissions-api/) |

Notifications and Permissions API snapshots are siblings of Storage API, not
nested under it.

## Validation Expectations

- Every advertised API/version should have a spec snapshot available to the
  service release process.
- Every advertised API/version should identify its conformance status.
- Partial implementations must report unsupported operations explicitly rather
  than silently accepting or dropping requests.

## Relationship to Client Adapters

`api-support.yaml` describes a deployed service release, not every client
adapter in this repo. The `ovstorage-services-client` plugin compiles only the
API versions it currently needs from the vendored proto tree; at the time of
this scrub, that means Storage API `v1alpha` protos plus the Notifications
Consumer `v1beta` proto. A service may publish additional snapshots, such as
Storage API `v1beta`, before a specific client adapter has switched to them.

When a service changes its advertised versions, update all three surfaces
together:

- the service repo's concrete `api-support.yaml`;
- the conformance gates for those advertised versions;
- any client adapter docs or generated-proto build files that claim support for
  those versions.

## Related Material

- API index: [`../apis/README.md`](../apis/README.md)
- Release skill: [`../skills/release.md`](../skills/release.md)
