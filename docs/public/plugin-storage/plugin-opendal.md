# OpenDAL plugin (`opendal`)

The `opendal` plugin: a first-party adapter `Backend` fronting
[Apache OpenDAL](https://opendal.apache.org/) for long-tail backends
that don't justify a native first-party plugin. Lives in
`ovstorage-cloud/ovstorage-plugin-opendal/` and compiles as a
cdylib loaded through the C ABI declared by `ovstorage-plugin`. The
plugin wraps an `opendal::Operator` (workspace-pinned to OpenDAL
`0.50`) behind the same `Factory` / `Backend` Layer contract as the other
first-party storage plugins. Capabilities and `UserMetadata`
behaviour depend on the underlying OpenDAL service driver, and the
adapter exposes a deliberately stricter capability set than OpenDAL's
raw matrix would advertise: a capability becomes visible only after
the ovstorage adapter can prove the Layer's behaviour end-to-end.

The plugin is pinned to a specific OpenDAL minor version rather than
tracking OpenDAL's `^` range — OpenDAL's public surface moves fast
enough that re-exporting its versioning would force ovstorage callers
to coordinate breaking-change adoption with OpenDAL's release
cadence. The plugin takes the lag and bumps the pin in its own minor
releases.

## Public surface

- **Schemes**: long-tail. The descriptor advertises the single
  backend `kind = "opendal"`; per-instance OpenDAL service selection
  happens through the `service` config field on each connection. Each
  connection picks one OpenDAL service plus its route prefix.
- **Descriptor**: `kind = "opendal"`, `display_name = "OpenDAL"`,
  `supports_runtime_add = true`. The schema-level `capabilities` are
  `Capabilities::empty()`; per-instance capabilities are filled in at
  `instantiate` time from the per-driver allow-list.
- **Config keys**:
  - `service` (**required** enum). Supported values:
    `fs`, `s3`, `webdav`. (The workspace pins OpenDAL's
    `services-fs`, `services-http`, `services-s3`, and
    `services-webdav` features; other OpenDAL services are not
    compiled in and are not advertised.)
  - `endpoint` (optional text; passed to the chosen driver — e.g.
    `http://127.0.0.1:9000` for an S3-compatible deployment, a
    WebDAV server URL).
  - `config_json` (optional text; flat JSON object whose values are
    strings. The per-driver knobs — `bucket`, `region`, `root`,
    `username`, etc. — are accepted through this field. Nested
    arrays/objects and non-string scalars are rejected; ordinary JSON
    string escapes are accepted).
  - `prefix` (optional URL; caller-facing route prefix. Defaults to
    `opendal://<service>/`). **It may not carry a query or a
    fragment** — an address names a node, and routing reads its scheme,
    authority and path alone. Both spellings are a load error naming
    the component. The refusal exists because address canonicalization
    parses a fragment away: accepted unrefused, such a config would
    silently publish the fragment-free route, so the connection would
    serve an address space other than the one its `prefix` names.
- **Credential keys**: a fixed set of secret fields covering the
  supported drivers — `access_key_id`, `secret_access_key` (S3),
  `password` (WebDAV). The adapter accepts only `SecretValue::Bytes`,
  `SecretValue::OAuthToken`, and `SecretValue::File` for these
  fields and rejects `SecretValue::SystemIdentity` and
  `SecretValue::MtlsCertPair` with typed `Unsupported`.

### Per-service config

| Service  | What it gives you                                                                  | Driver options                                                  |
| -------- | ---------------------------------------------------------------------------------- | --------------------------------------------------------------- |
| `fs`     | Local filesystem. Real directories, recursive + one-level list, atomic single-file writes, server-side copy/rename. No version listing. | `root` (via `config_json`)                                      |
| `s3`     | S3-compatible object storage via OpenDAL. Flat namespace, recursive + one-level list with delimiter, no-overwrite-write. | `bucket`, `region`, `endpoint`, `root`, `access_key_id`, `secret_access_key` |
| `webdav` | WebDAV servers. Real directories, recursive + one-level list, overwrite, server-side copy. | `endpoint`, `username`, `root`, `password`                      |

For the `s3` service through OpenDAL, conditional writes
(`supports_if_match_write`), native metadata patch, version listing,
and server-side copy/rename are all withheld — callers that need
those should use the first-party `s3` plugin instead, which proves
the Layer's behaviour end-to-end.

**Capability discovery.** Because capabilities vary per service,
callers that need to know what a particular connection supports
should inspect the runtime `Capabilities` returned at instantiate
time rather than assuming. The schema-level capabilities in the
descriptor are `Capabilities::empty()` by design.

## Auth

Credential behaviour is descriptor-driven. Drivers that need
passwords, private keys, or access keys expose secret
`CredentialField`s. The plugin does not scrape arbitrary environment
variables unless the selected OpenDAL driver documents that behaviour
and the descriptor names it. Ambient-identity credentials (for
example Kerberos through a ticket cache) are not threaded through.

`instantiate` validates the allow-listed service, computes the
configured prefix (defaulting to `opendal://<service>/`), constructs
the OpenDAL operator with `Operator::via_iter(scheme, ...)`, and runs
`Operator::check()` so that misconfiguration surfaces at instantiate
time instead of on the first object op.

## URL handling and version-pinned addresses

OpenDAL drivers do not share one URL grammar. The plugin normalises
them at the route boundary: the descriptor declares the schemes
compiled into the build, each configured backend instance declares
exactly one OpenDAL service plus its root, and every `ResolvedTarget`
handed to the driver is converted into that driver's path string
without provider-specific interpretation by the core library. The
route prefix is matched with `address::is_ancestor_or_self`, and the OpenDAL
key is derived from the percent-decoded path via `address::key_utf8`, so
addresses such as `opendal://fs/a%20b.txt` reach the driver as the
literal key `a b.txt` instead of the encoded byte sequence; listing
entries return `ObjectInfo.address` values in the same canonical
address form so callers do not need to rebuild URLs from driver keys.

The plugin does **not** reinterpret cloud-provider HTTPS URLs
generically. If an HTTPS prefix is routed to `opendal`, the selected
OpenDAL driver must understand it; S3 / GCS / Azure-native HTTPS
compatibility is the native first-party plugin's job unless the
route explicitly chooses an OpenDAL driver that documents equivalent
support.

Mutating operations reject addresses that pin a version —
`?versionId=`, `?generation=`, `?versionid=`, `?version=`,
`?checkpoint=` — with `InvalidArgument`. OpenDAL's adapter cannot
pass version pins through to most drivers, and silently dropping the
pin would route the write to head while the caller asked for a
historical pin.

## Layer-to-API mapping

The plugin maps each `Backend` Layer call onto OpenDAL's `Operator`
API.

| Layer method | OpenDAL Operator call |
|---|---|
| `instantiate` | `Operator::via_iter(scheme, ...)` + `Operator::check()` |
| `stat` | `Operator::stat` |
| `read` (whole object) | `Operator::reader(...).into_bytes_stream(..)` → `ReadResult::Stream` (no `to_vec()` copy, no internal mpsc bridge) |
| `read` (range) | `Operator::reader(...).into_bytes_stream(range)` → `ReadResult::Stream` (same streaming path as the whole-object read; the requested range is forwarded to OpenDAL, no full-object buffering) |
| `write` (Body::Bytes / LocalFile) | `Operator::write_with(...)` → `WriteStep::Done(WriteResult)` directly. A non-empty `WriteOptions.user_metadata` on a driver whose `Capability::write_with_user_metadata` is false returns `Unsupported` before any bytes commit — see *Metadata mapping*. |
| `write_stream` | `Operator::writer_with(...)` + per-chunk `write(...)` + `close()` — each `BodyStream` chunk goes straight into the writer, no full-payload buffering at the host. Carries the same `user_metadata` refusal as `write`. |
| `write_redirect` | Drivers whose `Capability::presign_write` is true (`s3` among the compiled-in drivers) emit a single presigned `PUT` `WriteRedirect`; other drivers return typed `Unsupported`. Requires `WriteOptions.size_hint`. `IfDestExists::Fail` and non-empty `user_metadata` return `Unsupported` on the redirect path so the dispatcher can fall through. Presign lifetime is fixed at 5 minutes. |
| `continue_write` | Re-stats the destination after the host POSTs the body; maps non-2xx HTTP status through `map_redirect_status` (401/403 → `PermissionDenied`/`AuthRequired`, 404/410 → `NotFound`, 408/5xx → `Transient`, 412 → `PreconditionFailed`, 416 → `InvalidArgument`, 429 → `ResourceExhausted`). |
| `delete` | `Operator::delete` |
| `list` | `Operator::lister_with(..)`. Recursive listings preserve directory facts from the driver: real-directory profiles return `Directory`, flat profiles return `DirectoryInferred` for directory entries, and zero-byte slash files return `DirectoryMarker`. |
| `copy` / `rename` | `Operator::copy` / `rename` for drivers in the per-driver allow-list; otherwise typed `Unsupported`. |
| `create_directory` (real-directory profile) | `Operator::create_dir` |
| `delete_directory` (real-directory profile: `fs`, `webdav`) | Descendant scan + delete; non-empty surfaces `DirectoryNotEmpty`. |
| `delete_directory` (flat profile: `s3`) | Removes the directory marker only (flat-backend Layer contract). |
| `list_versions` / `update_metadata` / `check_access` / `watch_directory` | Typed `Unsupported` — the OpenDAL adapter does not promise these. Polling and native change-feed support are deferred to the native first-party plugins. |

`opendal::Error::kind()` is mapped onto ovstorage `ErrorCode`:
`NotFound` → `NotFound`, `PermissionDenied` → `PermissionDenied`,
`IsADirectory` / `NotADirectory` → `IncompatibleType`,
`RangeNotSatisfied` → `InvalidArgument`, `Unsupported` →
`Unsupported`, `RateLimited` → `ResourceExhausted`,
`ConditionNotMatch` → `PreconditionFailed`, `AlreadyExists` →
`AlreadyExists`, `IsSameFile` → `Conflict`, `ConfigInvalid` →
`InvalidArgument`, anything else → `Transient`.

## Streaming guarantees

Whole-object reads are forwarded as a
`futures::Stream<Item = Result<Bytes>>` without an internal mpsc
bridge or `to_vec()` copy. Streamed writes pump each `BodyStream`
chunk straight into `Operator::writer().write(...)` so the adapter
never buffers a full payload at the host (matching the workspace
streaming-writes invariant). Both `Operator` and the `OpenDalLayer`
methods are async, so the adapter forwards each call directly with
`.await`. There is no internal `block_on` / runtime construction.

## Capability bits

`Capabilities` is populated from an ovstorage-owned per-driver
allow-list rather than from OpenDAL's runtime `Capability` struct.
The allow-list is intentionally stricter than what OpenDAL would
advertise: a capability becomes visible only after the ovstorage
adapter can prove the Layer's behaviour end-to-end.
`supports_if_match_write`, `supports_native_metadata_patch`, and
`supports_watch_directory` are off for every OpenDAL driver until a
native conformance test pins them per driver.

Preconditions follow the same rule.
`WriteOptions::if_dest = IfDestExists::MatchEtag(_)` is rejected
with typed `Unsupported` because the OpenDAL adapter does not
promise pass-through ETag preconditions across the supported driver
set. `IfDestExists::Fail` is honoured on the buffered `write` path
via `write_with(...).if_none_match("*")` for drivers whose
`Capability::write_with_if_none_match` is true (`s3` among the
compiled-in drivers). `writer_with` and `presign_write_with` do not expose
conditional headers in OpenDAL 0.50, so the streamed (`write_stream`)
and redirect (`write_redirect`) paths return typed `Unsupported`
whenever `IfDestExists::Fail` is set. The dispatcher does **not**
retry a streamed body against the buffered path — a `Body::Stream`
is consumed during the first attempt; the caller must instead pass
`Body::Bytes` or `Body::LocalFile` to use the buffered fail-if-exists
path that can enforce the precondition atomically. The plugin never
"best-effort" accepts a precondition it cannot enforce.

For real-directory profiles (`fs`, `webdav`), `has_real_directories`
is on; for `s3`, it is off and the same single-marker convention
applies as for the native cloud plugins (see [plugin-s3](plugin-s3.md)
for the pattern).

`address_roots` returns one entry per configured `(driver, root)`
pair.

**Enforcement**

Unlike the wire-conditional plugins (s3, gcs, azure), the OpenDAL
plugin enforces `ReadOptions::if_match` via post-stat compare against
the live object's etag string; a mismatch returns `ObjectModified`,
the read path's code. A populated `DeleteOptions::if_match` returns
`Unsupported` rather than being compared, because the compare cannot
be made atomic with the delete, and the plugin implements no
`update_metadata`.

Inverted byte ranges (`start > end_inclusive`) return `InvalidArgument`
at the Layer boundary before any OpenDAL operator call.

## Redirect credential scope

`write_redirect` is the only call that mints a redirect — reads are
streamed straight off `Operator::reader(...)` and never redirect — and
it declares `RedirectScope.credential = unspecified` for every driver
whose `Capability::presign_write` is true.

`unspecified` means the plugin does not know, and hosts treat it exactly
as `connection`. That is the accurate declaration rather than a
placeholder. The redirect's URL and headers come out of OpenDAL's
`PresignedRequest` verbatim: the driver's operator constructed that
credential, the adapter did not, and nothing in the presigned form
distinguishes a signature over one object from a connection credential
the driver forwarded. A per-object presign is the likely shape for the
S3 driver, but "likely" is not a declaration, and a wrong guess in the
permissive direction is the one that costs a credential rather than a
round trip. So the adapter declines to guess and lets the host fail
safe.

The consequence for an operator: under the default
`redirect_credential_disclosure = "refuse"`, an OpenDAL write redirect
is not handed to a client. The host takes the body itself and the write
still succeeds, paying a proxied transfer. Setting the key to `allow`
delegates it, which is the right choice where the clients are already
inside the trust boundary — the same call an operator would make for any
credential the driver might have put on that URL.

## Metadata mapping

Metadata mapping is intentionally thin. `ObjectInfo` carries `size`
(when OpenDAL `Metakey::ContentLength` is present), `mtime` (from
`Metadata::last_modified()`), `etag` (from `Metadata::etag()`), and
`version` (from `Metadata::version()` when the driver populates it).
`UserMetadata` is forwarded as-is from
`Metadata::user_metadata()` when the driver returns it.
`ObjectInfo.checksums`, `system_metadata`, and
`effective_permissions` are left empty for the OpenDAL adapter;
populating them is gated on a stable per-driver mapping.

Whether a write can carry `user_metadata` at all is a per-connection
fact: it is the resolved driver's `Capability::write_with_user_metadata`,
which in the pinned OpenDAL 0.50 is set by `s3` and by neither `fs` nor
`webdav`. On a driver where it is
false, `write` and `write_stream` **refuse** a non-empty
`WriteOptions.user_metadata` with `Unsupported` rather than storing the
bytes and discarding the map, so a caller's `--metadata foo=bar` cannot
vanish behind a successful write. `write_redirect` refuses a non-empty
map on every driver, because a presigned PUT minted here carries no
metadata headers; that refusal is about the *mechanism*, and the host's
redirect follower falls back to the buffered or streaming slot — which
then applies the rule above.

`WriteOptions.message` is weaker: the adapter stashes it under the
reserved user-metadata key `x-ov-message` where the driver can keep it,
and drops it where the driver cannot. A write carrying only a message
therefore still succeeds on `fs` — the plugin contract treats a
per-operation annotation as droppable, and `user_metadata` as not.

## Threat model

The plugin holds whatever credentials the chosen driver requires in
process memory for the lifetime of the connection. In Brokered mode
the broker holds them; the library sees only the redirects (or
streamed bytes) the broker forwards.

OpenDAL's service-driver matrix is the trust surface: a vulnerability
in one driver lands in this plugin unless the OpenDAL pin is bumped.
Mitigation: the OpenDAL pin is part of the plugin's release cadence;
security-relevant OpenDAL releases trigger a plugin point-release.

## Deferred / out of scope

- `watch_directory`, `list_versions`, `update_metadata`,
  `check_access` — typed `Unsupported`. Polling and native
  change-feed support are deferred to the native first-party plugins.
- OpenDAL retry / metrics / tracing layer stack. ovstorage's own
  retry, metrics, and tracing layers are the portable surface;
  OpenDAL-specific layers can be reconsidered for a deployment that
  needs one explicitly.
- Drivers that need ambient-identity credentials (Kerberos ticket
  cache, etc.).
