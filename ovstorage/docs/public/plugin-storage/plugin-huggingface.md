# Hugging Face Hub plugin (`huggingface`)

The `huggingface` plugin: a first-party **read-only** `Backend`
implementation against the Hugging Face Hub. Lives in
`ovstorage-cloud/ovstorage-plugin-huggingface/` and compiles as a
cdylib loaded through the C ABI declared by `ovstorage-plugin`. The
plugin hand-rolls the Hub REST client against the async
`reqwest::Client` — no `hf-hub` or vendor SDK dependency. One
connection serves one repository (model, dataset, or space); reads of
LFS-backed files follow the Hub's signed CDN redirect in-process and
stream the bytes, reporting the canonical LFS identity. All mutating
operations keep the `Layer` trait defaults and answer `Unsupported` —
writing to the Hub (its NDJSON commit API plus the LFS/Xet upload
protocol) is deliberately out of scope.

## Public surface

- **Schemes**: `hf://{models|datasets|spaces}/<namespace>/<name>/…` —
  the plural repository type is the address host, the repository id is
  the leading path, and an optional `?revision=<ref>` query pins any
  address to a git revision (branch, tag, or commit sha; refs with
  slashes such as `refs/pr/1` are percent-encoded on the wire, not in
  the address). Under an `alias` layer the connection also answers the
  Hub's own repository URL — `https://huggingface.co/<namespace>/<name>/…`
  with its `http://`, `www.` and `hf.co` twins, prefixed `datasets/` or
  `spaces/` for those repository types — as generated spellings of that
  root (see "Generated URL spellings").
- **Descriptor**: `kind = "huggingface"`,
  `display_name = "Hugging Face Hub"`, `supports_runtime_add = true`,
  `supports_user_metadata = false`.
- **Config keys**:
  - `repo_id` (**required**; `namespace/name`).
  - `repo_type` (optional; `model` | `dataset` | `space`, default
    `model`).
  - `revision` (optional; the connection's default revision, default
    `main`; callers pin another per address with `?revision=`).
  - `endpoint` (optional; default `https://huggingface.co`. Non-default
    values are restricted to loopback hosts — the hermetic-test seam —
    and an endpoint carrying a query or credentials is refused with
    `InvalidArgument`; the token is the only credential channel. There is
    no supported enterprise-endpoint override yet.)
- **Credential keys**: `token` — a single static access token
  (`hf_…`); a read-scoped token is sufficient. The field's descriptor
  default is the literal string `${HF_TOKEN}`, resolved at TOML load
  in the host's bundle-resolution layer; the plugin itself never reads
  the environment. An empty bundle connects anonymously, which serves
  public repositories.

## Auth

The token is a static bearer: it is validated once at add time with a
single `GET /api/whoami-v2`, judged leniently — only a definitive 401
rejects the credential (the connection parks `AwaitingAuth` with the
attempt recorded; adding a connection never blocks host startup).
403, 429, 5xx, and transport failures pass verification and surface
per operation at data time. There is no interactive flow and no
refresh: `authenticate_connection` answers `Unsupported` (so `reauth`
is not a route back), and rotation goes through
`update_connection_credentials` — the proven token is installed onto
the live cell the backend reads per request. Shape changes
(anonymous → tokened or back) are refused with remove-and-re-add
guidance.

## Address handling and version pins

The caller-facing root is `hf://{plural}/{repo_id}/`, fixed at connect
time (snapshot-only roots, no dynamic-root stream). Two connections to
the same repository collide with `RouteConflict` — alternate revisions
ride as address pins on one connection, never as extra connections.
On the canonical `hf://` form `?revision=` is the only recognized
address modifier; any other query key — and an empty pin value — is
refused with `InvalidArgument` rather than silently dropped. A generated
`https://` spelling, by contrast, declines a key outside the shared
carried-query allowlist before the plugin sees the address (see
"Generated URL spellings"). A revision names a whole tree snapshot, so a pinned-prefix `list` emits pinned child addresses —
an unpinned child would silently resolve back to head. The child's
`address` carries the caller's pin as typed (a ref such as `main` is only
as stable as the ref); `ObjectInfo.versioned_address`, when populated, is
the immutable `?revision=<commit sha>` form.

## Generated URL spellings

`hf://{plural}/{repo_id}/…` is the connection's only canonical address
form; the Hub's own URLs for the same repository are the **alias
layer's** job. So that an operator does not have to author them, each
connection advertises the URL prefixes it accepts as alternate spellings
of its root (`org.omniverse.ovstorage/accepted-url-spellings` on its
connection row), and an alias layer composed above installs one
**hidden** alias rule per spelling at registration — addressable,
reported with `visible = false` so listings of visible roots keep
showing the canonical form only, withdrawn with the connection, marked
`org.omniverse.ovstorage/alias-derived-from` in `list_connections`
output, and evicted by an explicit alias rule you author on the same
prefix. See "Generated aliases" in [configuration.md](../configuration.md)
for the alias-layer and authorization semantics.

The spellings follow the Hub's own URL layout — a model sits at the site
root, a dataset under `datasets/`, a space under `spaces/` — which is the
same path the plugin resolves file content against. With the default
endpoint every connection accepts six origins — `https://` and `http://`
on `huggingface.co`, on `www.huggingface.co`, and on the Hub's short
domain `hf.co` — so for the model `acme/demo` the canonical root
`hf://models/acme/demo/` also answers as:

- `https://huggingface.co/acme/demo/`
- `http://huggingface.co/acme/demo/`
- `https://www.huggingface.co/acme/demo/`
- `http://www.huggingface.co/acme/demo/`
- `https://hf.co/acme/demo/`
- `http://hf.co/acme/demo/`

A dataset connection accepts `https://huggingface.co/datasets/acme/demo/`
and a space `https://huggingface.co/spaces/acme/demo/`, each with the
same five alternate origins. A loopback `endpoint` (the hermetic-test
seam) accepts exactly its own shape, path included —
`http://127.0.0.1:8080/acme/demo/` — and no `huggingface.co` twin. The
`http://`, `www.` and `hf.co` forms are spellings only: an alias rule
selects inbound addresses, and every request this connection sends goes
to its configured endpoint over the transport that endpoint names.

The `?revision=` pin rides through a generated rule, so
`https://huggingface.co/acme/demo/config.json?revision=main` reaches the
plugin as `hf://models/acme/demo/config.json?revision=main`, and results
— pinned `list` children, `versioned_address` — project back onto the
caller's spelling with the pin intact. Any other query key makes the
generated rule stand aside and the address falls through to whatever
else routes it, normally `NoRoute`: the shared carried-query allowlist
exists so a credential-bearing URL is never re-served with a connection's
own credentials, and it admits only the version selectors the backends
read. A carried key this backend does not read (`?versionId=`) rides
through the rule unchanged and is refused by the backend with
`InvalidArgument`, exactly as on `hf://`.

A spelling names exactly the address its canonical form names: the
repository root and the paths beneath it. The Hub's web-view and download
URLs are not unwrapped — `https://huggingface.co/acme/demo/blob/main/config.json`,
`…/resolve/main/config.json` and `…/tree/main/weights` are read as the
in-repository paths `blob/main/config.json`, `resolve/main/config.json`
and `tree/main/weights` at the connection's default revision, which
normally answers `NotFound`; write such an address as
`https://huggingface.co/acme/demo/config.json?revision=main` instead. A
download link's `?download=true` is not a carried key, so for
`https://huggingface.co/acme/demo/resolve/main/config.json?download=true`
the generated rule stands aside and the address falls through to
whatever else routes it — normally `NoRoute`, or an `http` connection
that covers the origin. `https://huggingface.co/api/…`, the search
pages, and namespace pages name different resources and are never
aliased. For the same reason a model whose namespace is `api`,
`datasets`, `models` or `spaces` gets no web spelling: those are the
site-root segments this plugin already addresses something else under —
its dataset and space spellings and its API requests — so the prefix
such a model would derive names one of those rather than any model (the
Hub reserves the names, so no such model exists); its `hf://` root is
unaffected. The spellings are a property of a connection, so a Hub URL
for a repository no connection serves matches no generated rule and
falls through the same way — normally `NoRoute`. The repository id is
matched as configured — only the host is case-folded — so
`https://huggingface.co/Acme/Demo/` matches no rule for a connection
configured as `acme/demo`.

An `http` connection rooted at the site origin (`https://huggingface.co/`)
does not outrank a generated repository rule: the rule is the more
specific prefix, so repository URLs still reach this plugin, and only
the addresses the rule declines fall through to that connection. An
`http` connection rooted at or below the repository prefix is at least
as specific and takes those addresses instead.

Authorization is untouched. Policy evaluates the caller-supplied address
before alias resolution, so a grant on `hf://models/acme/demo/` does not
cover `https://huggingface.co/acme/demo/`; each origin is its own scope,
granted alongside the canonical form exactly as for an alias you author
by hand.

## Layer-to-API mapping

| Layer slot | Hub endpoint |
|---|---|
| `stat` | `POST /api/{plural}/{repo_id}/paths-info/{rev}` (repo root: `GET …/revision/{rev}`). `StatOptions::versioned_address`, like `full_metadata`, sends `expand=true` and reports `versioned_address = …?revision=<lastCommit.id>`; without either flag a 40-hex sha the caller pinned is echoed and a ref such as `main` is not; the repository root answers `None`. |
| `read` | `GET /{resolve_prefix}{repo_id}/resolve/{rev}/{path}` |
| `list` | `GET /api/{plural}/{repo_id}/tree/{rev}/{path}` (`recursive=true` server-side; `Link: rel="next"` pagination followed in-backend, same-origin only). `ListOptions::versioned_address` sends `expand=true` the same way and pins each file with its `lastCommit.id`; directories answer `None`. |
| `list_stream` | The same tree walk, yielding one decoded Hub page at a time and following `Link: rel="next"` only as the consumer advances. |
| `list_versions` | `GET /api/{plural}/{repo_id}/commits/{rev}` |
| `get_latest_version` | `GET /api/{plural}/{repo_id}/revision/{rev}` (+ paths-info for file facts) |

paths-info reports a missing path as `200` with an **empty array**;
the plugin maps that to `NotFound`. `stat` treats a trailing slash as
a hint only — paths-info answers the entry's real kind either way.
The buffered `list` and `list_versions` slots page with the shared
numeric-offset token convention over the fully-walked result, never the Hub cursor:
`max_results` selects a page and `next_page_token` resumes the rest, so
a truncated page never hides the tail (and `max_results = 0` is
rejected). `list_stream` instead walks the native same-origin `Link` cursor
lazily, retaining one provider page and a fixed-size continuation-cycle
window; it accepts neither caller paging field. `full_metadata` and
`versioned_address` both map to the Hub's `expand=true`, which adds per-entry
last-commit id/date at extra provider cost.

Versioning is the git model: **versions are repository commits.**
`list_versions` returns the commit history of the connection's default
revision (newest first) — an address pin selects a version and never
filters the walk, so a pinned input still sees the full history. Each
entry is pinned onto the input address and carries only truthful
per-commit facts (`version`, `mtime`, `modified_by`, the commit title
as `hf.commit.title` system metadata) — per-commit file size/etag are
unknown to the commits API and never fabricated. Adjacent versions of
a file may be byte-identical, and a pin predating the file answers
`NotFound` on dereference. `get_latest_version` resolves the effective
revision to its immutable commit sha, reads the entry at that sha, and
returns the object pinned to it — so the reported `version`, the entry
facts, and the pinned address are one consistent snapshot even if the
ref advances mid-call, and the address matches the form `list_versions`
emits. Every `list_versions` and `get_latest_version` entry returns
`versioned_address` equal to its own `?revision=<sha>` address.
`get_latest_version` pins the resolved head sha while `stat` and `list` pin
`lastCommit.id` — both immutable, and different strings for one entry.

## Identity, streaming, and redirects

The SPI etag is the LFS content sha256 for LFS-backed entries (the
`resolve` 302 reports the same value in `x-linked-etag`) and the git
blob oid otherwise (the non-LFS `resolve` answer reports it as
`ETag`), so a `stat → read if_match=etag` round-trip holds on both
paths. Tree and paths-info results declare these content-addressed LFS and Git
object ids `Strong`. Direct reads derive strength from the standard HTTP
`ETag` syntax: a conformant quoted tag is `Strong`, an explicit `W/` tag is
`Weak`, and a bare or malformed tag is `Unspecified`. LFS entries also carry a
`sha256` checksum. Direct-read response headers such as `x-repo-commit` are
republished as system metadata; credential/session headers never are.

Whole-object and open-ended ranged reads stream; a closed range
buffers under the smaller of the range length and the caller's
`max_bytes`, so a large range with a small cap cannot allocate the
whole range before the cap is enforced. An origin that answers a
ranged request with `200` is refused with `Unsupported` before any
body is buffered, and a `206` whose `Content-Range` does not select
the requested interval is refused rather than returning bytes from the
wrong offset. Inverted ranges are refused at the plugin boundary with
`InvalidArgument`. Reads honor cancellation mid-body.

`resolve` answers with `3xx` redirects and the plugin **follows them
in-process** rather than delegating a `ReadResult::Redirect` to the
host follower. A **same-origin** hop (often a relative `Location`: the
resolve-cache path for non-LFS files, or a renamed repository) is
followed with the bearer re-attached; an **off-origin** hop is the
signed CDN URL for an LFS file, followed **without** a bearer (its
signature is the grant). The chain is bounded to five hops, and every
off-origin target is scheme-restricted: only `https` (plus the
loopback-`http` test seam) is followed, so a hostile endpoint cannot
steer the read at a `file://` path or an internal/link-local `http`
service. The caller's `if_match` and a whole-object `max_bytes` settle
against the 302's `x-linked-etag`/`x-linked-size` before the CDN is
fetched.

Following in-process (rather than delegating a redirect) is what keeps
the read's reported identity consistent with `stat`: the LFS canonical
etag is the content sha256 the 302 carries in `x-linked-etag`, which
the CDN response itself does not carry, so only an in-process follow
can report it. For an LFS read the returned `ObjectInfo` therefore
takes its etag, size, `sha256` checksum, and `x-repo-commit` version
from the 302's linked headers, while the byte stream comes from the
CDN response.

## Capability bits

From `Capabilities::empty()`, the plugin raises exactly:
`supports_list`, `supports_list_stream`, `supports_recursive_list`,
`has_real_directories`, `supports_version_listing`, and
`version_list_order = Some(Newest)` — identical for anonymous and
tokened connections (a token widens which repositories answer, not
which operations exist). Deliberately false: `wants_list_backed_stat`
(paths-info is the real stat) and `populates_subdirectory_metadata`
(directory entries carry no truthful size, and mtime only under
`expand=true`). Every write, delete, copy, rename, watch, and
metadata bit is false, and the matching slots self-gate with a typed
`Unsupported` before any wire traffic.

## Error mapping

The HTTP baseline: 401 → `AuthRequired` (with auth context, reason
`hf_unauthorized`); 403 → `PermissionDenied` (final — no auth
context); 404/410 → `NotFound`; 405 → `Unsupported`;
412 → `ObjectModified` (carrying the response etag);
416 → `InvalidArgument`; 408/504 → `DeadlineExceeded`;
429/503 → `ResourceExhausted`; other 5xx → `Transient` (no in-plugin
retry — the host retry wrapper drives). A 3xx from a JSON API endpoint
means the repository has been renamed or moved and maps to `NotFound`
with an update-`repo_id` hint. The Hub's sanitized
`x-error-code` header refines messages: `GatedRepo` maps to
`PermissionDenied` with accept-the-conditions guidance;
`RepoNotFound` / `RevisionNotFound` / `EntryNotFound` keep `NotFound`
with the code named. The Hub hides private repositories behind 404, so
an anonymous miss adds a supply-a-token hint to the message — the code
stays `NotFound`, never `AuthRequired`, because no drivable auth flow
exists. Error messages never echo provider body text or request URLs.

## Deferred capabilities

Hub writes (NDJSON commit API + LFS/Xet upload), `watch_directory`,
`check_access`, `update_metadata`, enterprise/private endpoint
overrides, one-connection-many-repos dynamic roots, and unwrapping the
Hub's `/blob/`, `/resolve/` and `/tree/<rev>/` web-view URL forms (with
their `?download=` query) into pinned addresses are all deferred.
Caching belongs to the cache wrapper layer, not this plugin.
