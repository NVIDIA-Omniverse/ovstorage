# Permissions API

This folder contains the Permissions API `v1beta` release snapshot.

| Surface | Local path |
|---|---|
| gRPC proto | [`protos/nvidia/omniverse/permission/v1beta/permission_service.proto`](protos/nvidia/omniverse/permission/v1beta/permission_service.proto) |
| REST OpenAPI | [`openapi/permissions/v1beta/openapi.json`](openapi/permissions/v1beta/openapi.json) |
| Generated docs | [`docs/`](docs/) |

The API exposes `PermissionService` with `CheckPermission` and
`CheckPermissionBatch`, plus REST authorization endpoints under `/v1beta`.

See [`../README.md`](../README.md) for the overall service API map.
