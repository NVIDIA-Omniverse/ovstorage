Up: [USD workflows](README.md)

# How a USD request reaches storage

Sources:
- `ovstorage-usd-resolver/src/openusd/resolver.cpp` for the `ArResolver` overrides;
- [architecture.md](../../../../ovstorage-usd-resolver/docs/architecture.md);
- [plugin ownership](../../../../ovstorage/docs/public/plugin-storage/OWNERSHIP.md) for which Layer produces local files.

## Read path

| OpenUSD call | Resolver behavior | Storage call |
| --- | --- | --- |
| `CreateIdentifier(path, anchor)` | Normalizes the path, or joins a relative path to its anchor's URI, then applies the runtime's scheme gate | None |
| `Resolve(identifier)` | Returns the identifier unchanged for claimed schemes and empty for local paths. Doesn't check existence by default | `stat` only when `resolveVerifiesExistence` is on. Only an authoritative `NotFound` returns empty, and results are cached per runtime with time limits |
| `OpenAsset(resolved)` | Strips SDF format arguments and any package inner path, then materializes the outer object and wraps the leased local file in an `ArFilesystemAsset` | `materialize`, which becomes the Stack's `read_local_file` |
| `GetModificationTimestamp` | Converts the reported mtime to an `ArTimestamp`. Returns an invalid timestamp if none is available | `stat` |
| `GetAssetInfo` | Sets `version` from the provider version or the ETag. Fills `resolverInfo` with `url`, `size`, and `etag` | `stat` |

## Inside the Stack

`materialize` passes through whatever the config declares, from the outermost Layer inward:

1. Wrapper Layers that are present, such as `alias`, `retry`, `metadata_cache`, `byte_cache`, `hub_cache`, and `redirect_follower`. A cache wrapper returns a hit under a live lease. On a miss it fills from the Layer inside it.
2. The `router`, which picks the connection that serves the address prefix.
3. The backend plugin, which speaks the provider protocol to the origin with that connection's credentials ([authentication](../authentication/README.md)).

A `file` backend returns the file's own path without copying. A remote backend has no local file of its own, so the Stack supplies one: from a cache wrapper, from `redirect_follower` staging, or from the bridge's fallback, which reads the whole object into a `TempFileLease`. Either way, OpenUSD gets a local path held open by a lease. The lease is released when the `ArAsset` is dropped, and ovstorage decides when to clean up the local file.

## Packages (USDZ)

For `outer.usdz[inner.usd]`, the resolver materializes **only the outer** object. OpenUSD's package resolver then reads the inner members from that local file. A relative path inside a package stays package-relative. An absolute URI inside a package leaves the package and resolves on its own.

## Write

`UsdStage::Save` or `SdfLayer::Save` goes through these steps:

1. `CanWriteAssetToPath` checks that the route can be written, using the route's capability bits. Package-inner paths are refused.
2. `OpenAssetForWrite` stages a private local file. In `Update` mode it is seeded from the current object, and its ETag is recorded.
3. `Close` uploads the whole object with a precondition:
   - `Replace` overwrites the object.
   - A missing `Update` target is create-only.
   - An existing `Update` target uses If-Match where the route supports it.

A rejected precondition comes back as `Conflict` or `PreconditionFailed` and is never retried as an overwrite. Permission and quota failures show up at `Close`, not at the capability check.

## Failure mapping

Authentication, routing, transient, and backend errors are never reported as "missing asset". Only an authoritative storage `NotFound` means absent. When OpenUSD says it can't open an asset, check the storage side first ([storage/validate.md](../storage/validate.md)).
