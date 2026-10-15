Up: [USD workflows](README.md)

# Sequence diagrams on request

Draw diagrams in Mermaid `sequenceDiagram` unless the caller asks for another format. Base them on the templates below, then fit them to the caller's setup:

1. **Ask or infer the setup:** the backend scheme, the Layers declared in their `ovstorage.toml` (show only those), whether `resolveVerifiesExistence` is on, whether the asset is a USDZ package, and whether the operation reads, writes, or both.
2. **Draw only what runs.** Leave out wrappers that aren't configured. The template below is for `s3`, whose reads always redirect, so its miss path goes through `redirect_follower`. For a backend that returns bytes itself, swap in the [direct read](#backend-that-returns-bytes) miss path. Show a cache hit and a miss as an `alt` block. Show optional steps as `opt` blocks.
3. **Ground it.** When a build is available, run `ovstorage-usd-resolver trace <uri> --stack-config ovstorage.toml --json`. Order the resolver steps by the trace events, such as `create_identifier.*`, `resolve.*`, and `open_asset.*`. Say whether the diagram is traced or derived from source.
4. Behavior rules are in [data-flow.md](data-flow.md). Don't invent steps that aren't there.
5. **Keep `;` out of message and note text.** Mermaid reads it as a statement separator and the diagram fails to render; write "and" or break the line with `<br/>`.

## Open a remote `s3` stage

```mermaid
sequenceDiagram
    autonumber
    participant App as Host app
    participant Usd as OpenUSD (Usd/Sdf/Ar)
    participant Res as ovstorage USD resolver
    participant Br as StorageBridge
    participant Stk as ovstorage Stack
    participant Be as Backend plugin
    participant Org as Origin storage

    App->>Res: bind context (Runtime.bind / ScopedDefaultContext)
    App->>Usd: UsdStage::Open("s3://bucket/scene/root.usd")
    Usd->>Res: CreateIdentifier(path) — normalize + scheme gate, no I/O
    Usd->>Res: Resolve(identifier)
    opt resolveVerifiesExistence
        Res->>Br: stat(identifier)
        Br->>Stk: stat
        Stk-->>Br: Info or NotFound
    end
    Res-->>Usd: ArResolvedPath (same identifier)
    Usd->>Res: OpenAsset(resolved)
    Res->>Br: materialize(outer identifier)
    Br->>Stk: read_local_file
    alt cache Layer hit (if configured)
        Stk-->>Br: local file under lease
    else miss
        Stk->>Be: read via router → connection
        Be-->>Stk: redirect
        Stk->>Org: redirect_follower fetches the URL
        Org-->>Stk: bytes
        Stk-->>Br: local file under lease (cache Layer fills)
    end
    Br-->>Res: MaterializedAsset (lease)
    Res-->>Usd: ArFilesystemAsset over leased file
    Usd->>Usd: parse layer, discover sublayers/references/payloads
```

## Backend that returns bytes

For a backend that serves reads without a redirect, replace the miss path's backend steps with these. Draw no `redirect_follower` step:

```mermaid
sequenceDiagram
    participant Stk as ovstorage Stack
    participant Be as Backend plugin
    participant Org as Origin storage
    Stk->>Be: read via router → connection
    Be->>Org: GET (with connection credentials)
    Org-->>Be: bytes
    Be-->>Stk: bytes
```

## Each dependency

Repeat this block for each sublayer, reference, or loaded payload:

```mermaid
sequenceDiagram
    participant Usd as OpenUSD
    participant Res as ovstorage USD resolver
    participant Br as StorageBridge
    Usd->>Res: CreateIdentifier("./props/chair.usd", anchor=root.usd URI)
    Res-->>Usd: s3://bucket/scene/props/chair.usd
    Usd->>Res: Resolve → OpenAsset
    Res->>Br: materialize (same path as above)
    Usd->>Res: GetModificationTimestamp / GetAssetInfo
    Res->>Br: stat
    Note over Usd,Res: dropping the ArAsset releases the lease<br/>and ovstorage owns local-file cleanup
```

## USDZ

Use this variation for a package:

```mermaid
sequenceDiagram
    participant Usd as OpenUSD package resolver
    participant Res as ovstorage USD resolver
    participant Br as StorageBridge
    Usd->>Res: OpenAsset("s3://b/asset.usdz")
    Res->>Br: materialize(outer only)
    Br-->>Res: leased local .usdz
    Res-->>Usd: ArFilesystemAsset
    Usd->>Usd: read [inner.usd] from local package
```

## Save to remote storage

```mermaid
sequenceDiagram
    participant Usd as OpenUSD (SdfLayer::Save)
    participant Res as ovstorage USD resolver
    participant Br as StorageBridge
    participant Stk as ovstorage Stack
    Usd->>Res: CanWriteAssetToPath — route write capability
    Usd->>Res: OpenAssetForWrite(mode)
    opt Update on existing object
        Res->>Br: materialize seed (record ETag)
    end
    Res-->>Usd: writable asset on private staged file
    Usd->>Res: Write(...) then Close()
    Res->>Br: write(whole object, precondition)
    Note right of Br: Replace → overwrite<br/>Update missing → create-only<br/>Update existing → If-Match where supported
    Br->>Stk: write → router → backend → origin
    Stk-->>Res: ok, or Conflict / PreconditionFailed / PermissionDenied
```
