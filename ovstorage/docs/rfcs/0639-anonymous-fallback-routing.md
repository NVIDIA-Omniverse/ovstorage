<!--
SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# RFC-0639: anonymous fallback routing for addresses no connection serves

- **Status:** Accepted
- **Depends-on:** RFC-0066 (layered architecture)
- **Supersedes:** —
- **Superseded-by:** —

> An `s3://`, `gs://` or `azure://` address that no configured connection serves
> answers `NoRoute`, and nothing is attempted. This RFC adds an opt-in,
> per-scheme, off-by-default fallback. Under an operator's grant, the scheme's
> backend layer publishes one hidden **scheme fallback root** (`s3:///`,
> `gs:///`, `azure:///`) marked in `user_metadata`; the shared `RouteTable`
> consults such a root as a second tier after the longest-prefix scan misses;
> and the backend attempts the address **anonymously** — a client built with no
> credential source at all, never the process's ambient identity — and
> read-only. The grant is a layer key on library, CLI and MCP hosts and two
> top-level keys on the broker and REST gateway, shaped like
> `redirect_credential_disclosure`. Authorization is untouched: a fallback
> grants routability, never authority. Cloud instance-metadata endpoints — a
> fallback's derived host, a configured fallback endpoint, and every redirect
> destination the http plugin and the redirect follower are handed — are
> refused before any socket opens, whatever is granted. Nothing changes on the
> plugin C ABI, the broker wire or the capability set, and no error code is
> added. `http` and `https` get their own switch, which this release refuses to
> turn on.

## Context

**The miss has one site.** `Router::route`
(`ovstorage-core/ovstorage-plugin-core/src/router.rs`) looks the address up in
its `RouteTable`, built from every child's `list_address_roots` as RFC-0066 §
Stack and routing describes, and on a miss answers `NoRoute` with the message
`no route matches address`. Each cloud backend layer holds the same shape one
level down: a `ConnectionSet` plus its own `RouteTable<Arc<Instance>>`, one root
per connection (`s3://{bucket}/`, `gs://{bucket}/`,
`azure://{account}/{container}/`), and its own `NoRoute` on its own miss. A
fallback therefore has to be expressible at both sites, or an address that
arrives at a bare backend layer — a router-less graph, a brokered client —
behaves differently from one that arrives at the Router.

**A scheme-only root is inert through the existing table.** `RouteTable::lookup`
reduces to `address::relative_suffix`, which reduces to `is_ancestor_or_self`
(`ovstorage-core/ovstorage-plugin/src/address.rs`), and that relation requires
scheme, host **and** port equality before it looks at a path. `s3://`
canonicalizes to `s3:///` with `host_str() == None`, which is never an ancestor
of `s3://bucket/key`. Publishing `s3:///` as an ordinary root does nothing for a
hosted address, so any catch-all needs a second tier consulted only after the
prefix scan misses. The guard is load-bearing elsewhere — it is what keeps
`file:///` from claiming `file://host/share` — so the second tier has to be
something the guard cannot be talked into.

**The plugins pin the bucket.** `parse_s3_address`, `parse_gcs_address` and
Azure's `validate_target` refuse an address whose authority is not the
connection's configured bucket, account or container. The pin is a correctness
property — a connection's credential is scoped to its bucket — and the fallback
must not loosen it: the anonymous client for `s3://other/key` has to be an
ordinary per-bucket client whose config pins `other`, not a bucketless client
that accepts anything.

**Anonymity is already structural.** `S3Backend::anonymous`
(`ovstorage-cloud/ovstorage-plugin-s3/src/client.rs`) builds a service config
with no credentials provider; the GCS and Azure resolvers map an empty
`SecretBundle` to an anonymous source with no discovery chain. None of the three
plugins reads `AWS_*`, `GOOGLE_APPLICATION_CREDENTIALS` or `AZURE_*` on its own.
An anonymous client therefore costs no RPC to build and cannot spend the
process's ambient identity by accident, which is the property the request turns
on.

**The information test decides who owns what.**
[`OWNERSHIP.md`](../public/plugin-storage/OWNERSHIP.md) states the placement
rule that RFC-0066 § Behavior placement records: a concern belongs to the Layer
that can see what the decision needs and that the other Layer cannot see. Only
the backend can derive a bucket, account or container from an address, build a
client for it, and know which of its slots mutate. Only the host knows whether
reaching an unconfigured bucket from this process's network position is
acceptable in this deployment. The fallback is one concern split across that
boundary, the same way per-connection auth state (backend) and persistent secret
storage (host) are.

**Request extensions carry facts, never instructions.** RFC-0066 forbids a
behaviour selector addressed to a layer kind; behaviour is selected by
composition and configuration. "Attempt this anonymously" is an instruction, so
it cannot ride the request. It has to be a property of the graph.

**`redirect_credential_disclosure` is the template for a deputy decision.**
RFC-0066 § Redirect credential disclosure and the shipped broker configuration
state the shape: a property of the deployment rather than of any credential,
decided by the operator because the host cannot decide it by inspection, default
closed, with the hand-set layer spelling refused so the policy lives in exactly
one place. An anonymous fallback on a broker is the same kind of decision — a
brokered fetch runs from the broker's network position and reaches whatever that
position reaches — and takes the same shape.

**The request has four requirements.** An opt-in, per-scheme, off-by-default
fallback that routes an unrouted `s3://`, `gs://` or `azure://` address to its
scheme's backend and attempts it anonymously, never with ambient credentials; an
`http`/`https` fallback on its **own** switch, shaped like the
redirect-disclosure key, because an arbitrary origin is a different exposure
from a public bucket; authorization untouched; and cloud instance-metadata
endpoints refused unconditionally. Everything below follows from those four and
the constraints above.

Touches the Software Design Document's routing and configuration sections and
the plugin-storage ownership registry.

## Decision

**A granted backend layer publishes one marked, hidden scheme fallback root; the
shared `RouteTable` answers with it in a second tier after the longest-prefix
scan misses; the backend serves the hit anonymously and read-only; and the grant
is host configuration that never touches authorization.**

### The marker rides `RootInfo.user_metadata`

A granted layer publishes one extra `RootInfo` per scheme it serves: root
`s3:///`, `gs:///` or `azure:///`; `visibility: Hidden` and `visible: false`;
`connection_id: None` and `owning_target: None`, mirroring its sibling
connection roots; `source: RouteSource::Static { layer:
ConfigLayer::Programmatic }`; a display name of the form
`anonymous s3:// fallback`; read-only capabilities; the `Native` ranged-read
strategy the kind's connection roots advertise, set by the backend because the
shared constructor does not know it; and exactly one `user_metadata` entry,
`org.omniverse.ovstorage/scheme-fallback = anonymous`.
That entry is the marker. `ovstorage_layer::fallback::scheme_fallback_root`
builds the root and `is_scheme_fallback_root` recognises it.

The marker is metadata rather than a new `RouteSource` variant because
`RouteSource` is a `#[repr(C)]` tag on the plugin ABI (`RouteSourceTag` in
`ovstorage-core/ovstorage-plugin/src/ffi/v2/introspect.rs`) and on the pure C
header (`OvStorage_RouteSourceKind` in
`ovstorage-c-source/include/ovstorage.h`), and the broker re-labels every
advertised root `BrokerDelivered` on the wire. A new variant costs an ABI
revision and a protocol change and is still lost at the broker boundary.
`user_metadata` already crosses the ABI and the wire verbatim, so a loaded
plugin, a composite host and a brokered client see one marker with no new field
anywhere. The alias wrapper's presentation patch treats the marker key as
reserved, alongside its own alias-to, alias-visibility and alias-derived-from
keys, so an attribute patch can neither mint nor remove a marker.

There is no new `RouteSource` variant, no new `ErrorCode`, no new `Capabilities`
bit and no new `*_KIND` constant. The read-only contract is the existing
capability self-gate: `read_only_capabilities` clears every write, delete, copy,
rename, directory-mutation, metadata-patch and watch bit and keeps list,
recursive list, version listing and access check, and `scheme_fallback_root`
applies it whatever capabilities a backend passes.

### Two tiers in one shared table

`RouteTable::lookup` answers in two tiers. The first is the longest-prefix scan
every consumer has. The second runs only when the first misses and only when
`generated_rule_may_answer(url)` is true — the gate that protects a generated
alias rule, because an S3 presigned or Azure SAS URL authenticates itself with
its query and an anonymous attempt would silently discard the authority the
caller presented — and returns the marked scheme root registered for
`url.scheme()`, if the table holds one. `RouteTable::build` indexes marked roots
per scheme after ranking; where two marked roots name one scheme, the existing
`overlapping address root shadowed` warning fires once and the earliest-ranked
root keeps the tier. `RouteTable::lookup_prefix` exposes the first tier alone
for the caller whose question is "who serves this exact node"; the Router's
`cross_child_conflict` is that caller, so adding a real connection for a bucket
the fallback is serving is not a `RouteConflict`.

The gate's allowlist, `CARRIED_QUERY_KEYS`, is the one the generated alias
rules already consult: the version selectors `versionId`, `versionid` and
`generation`. `generation` is carried because it names a version of the same
object, exactly as the other two do, so a generation-pinned `gs://` address
reaches the fallback and generated alias rules answer the pinned spelling; a
query outside the set is treated as the caller's authority and keeps the
address out of both.

`is_scheme_fallback_root` is structural **and** marker-based: the exact key and
value, a path of `/`, no query, and either a hostless authority or the reserved
placeholder host `anonymous-fallback.invalid`. The placeholder exists because
`url` 2.5.8 refuses an empty host on its special schemes —
`Url::parse("http://")` fails where `Url::parse("s3://")` yields `s3:///` — so
`http` and `https` spell their root as `http://anonymous-fallback.invalid/` and
`https://anonymous-fallback.invalid/`, under the top-level domain RFC 6761
reserves never to resolve. Both halves of the predicate are load-bearing. A
hostless root **without** the marker (`file:///`, `mem:///`, an operator's
unmarked `s3:///`) is an ordinary prefix root and the tier never consults it;
for an unmarked table, `lookup` is `lookup_prefix`. A marked root that names a
bucket is not a fallback either: it serves its prefix through tier 1 and the
marker on it is inert.

**A second-tier hit is not a prefix hit.** For it,
`relative_suffix(url, &root.root)` is `None`, because `s3://bucket/key` is not
under `s3:///` in the prefix sense. No consumer computes a suffix after a hit —
every in-tree table maps the hit to its target only — and the backend derives
the bucket, account or container from the address itself. A hostless address
with a path (`s3:///k`) is a tier-1 hit under the scheme root, so a backend
refuses every empty-authority address, not only the bare root.

Because `RouteTable` is one type shared by the host `Router`, every
connection-owning plugin's internal table and the brokered client's, all of them
gain the tier at once and the Router needs no rule of its own: a marked root
reaches the same backend whether the address arrives at the Router or directly
at the layer that published it. A tier-2 hit logs one `debug!` naming the scheme
and the origin only, never the path or the query.

### What the backend does with a hit

Inside each cloud layer the route table's target is an enum —
`Connection(Arc<Instance>)` or `Fallback(Arc<SchemeFallback>)` — and every
`Layer` slot has an explicit arm for each. On the `Fallback` arm the layer:

- derives the bucket (`s3://`, `gs://`) or the account and container
  (`azure://`) from the address, answering `InvalidArgument`
  (`an s3:// address names no bucket`,
  `an azure:// address names no storage account`) for an empty authority, so the
  scheme root itself and every hostless spelling are refused before any cache or
  wire activity;
- synthesizes an ordinary per-node anonymous config — `fallback_config`,
  `GcsConnectionConfig::anonymous_for_bucket`,
  `AzureConnectionConfig::anonymous_for` — so the plugin's own address parser
  keeps its pin, and builds the client with a literal `SecretBundle::default()`;
- caches the client in a bounded LRU (`FallbackCache`, default 64 entries) under
  a mint budget (default 120 mints per minute, past which the answer is a
  retryable `ResourceExhausted`,
  `anonymous fallback mint budget exhausted; retry later`), with single-flight
  per node so concurrent misses build once, and evicts the entry when
  `install()` registers an explicit connection for that node, so a configured
  root outranks the fallback the moment it exists;
- registers **no** `Connection`: nothing appears in `list_connections`, nothing
  is persisted, nothing is probed on start, and `probe`, `remove_connection`,
  `update_credentials` and `authenticate` cannot name it because it has no
  `ConnectionId`;
- refuses every mutating slot — `write`, `write_stream`, `write_redirect`,
  `continue_write`, `delete`, `copy`, `rename`, `create_directory`,
  `delete_directory`, `update_metadata` — and `watch_directory` with
  `Unsupported`, `this address is reached through the anonymous s3:// fallback,
  which is read-only`, and a `next_action` naming the node root (`add a
  connection for s3://{bucket}/ with credentials to modify it`), before any
  acceptance witness, body or request; `copy` and `rename` judge **both**
  addresses and name the fallback-served end;
- serves `stat`, `read`, `list`, `list_stream`, `list_versions`,
  `get_latest_version` and `check_access`, with `read` returning the backend's
  ordinary unsigned `ReadResult::Redirect` carrying `RedirectCredential::None`,
  which is delegable under either redirect-disclosure setting; and
- logs one `info!` at target `ovstorage.fallback` per built client, naming the
  origin only.

The `BackendId` on a fallback-served result is `s3-fallback:{bucket}:{region}`,
`gcs-fallback:{bucket}` or `azure-fallback:{account}/{container}`. The Azure
fallback assumes a flat namespace (`has_real_directories = false`) and no change
feed; GCS builds against the public endpoint with zero probes.

### Instance-metadata endpoints are refused before a socket opens

One predicate in `ovstorage_layer::instance_metadata` refuses the hosts that
hand a cloud instance its own identity: `169.254.0.0/16` (AWS and Azure IMDS,
the ECS task-credential endpoint, GCE's address), `100.100.100.200` (Alibaba
Cloud ECS metadata), `168.63.129.16` (the Azure wireserver), `fe80::/10`,
`fd00:ec2::254`, the IPv4-mapped and IPv4-compatible embeddings of a refused
IPv4 address, and the exact names `metadata.google.internal`, `metadata.goog`
and `metadata` — ASCII-case-insensitive, with brackets and one trailing dot
stripped, and **never by suffix**, so `metadata.google.internal.evil.test` and
`evil.metadata.goog` are somebody else's hosts and pass. True means refuse;
`ovstorage::net::is_local_cleartext_host` answers the opposite question and is
not reused in either direction.

`refuse_instance_metadata` answers `PermissionDenied`, `refusing to contact
{origin}: it is a cloud instance-metadata endpoint, and ovstorage never fetches
from one on a caller's behalf`. It is applied to the host the fallback derives
from an address, before any probe or client build; to a configured
`anonymous_fallback_endpoint` at `create_backend`, granted or not; to every http
redirect destination in `send_following_redirects_with_timeout`, before the
`redirect_policy` gate, so `none`, `same_origin` and an allow-list naming the
host all refuse; and in the redirect follower's `ensure_redirect_scope`, which
every read and write executor path validates through before any socket opens, on
the first attempt and on every re-mint. A configured connection endpoint
(`endpoint`, `blob_endpoint`, `root_url`) at such a host is honoured with one
advisory `warn!` and never refused: the operator wrote it, and the shape follows
the Azure cleartext diagnostic, which names an exposure once at construction and
leaves refusal to a separate decision. The predicate judges the host as written;
a DNS name that resolves to a link-local address is not caught, and only a
resolve-then-check connector can close that.

### S3 learns a bucket's region once

S3 `region` is a required connection key with no default, and the fallback has
no connection to read it from. So the S3 fallback sends one unsigned
`HeadBucket` per cold bucket to `anonymous_fallback_region` (default
`us-east-1`) and reads `x-amz-bucket-region` off whatever status comes back —
200, 301, 400 and 403 all carry it — admitting the value only through
`^[a-z0-9-]{1,32}$`, so it can be placed in a hostname. The answer is cached per
bucket for the layer's life and survives eviction of the client, because a
region is a fact about the bucket. A 404 is `NotFound` and is not cached; an
absent header on a 2xx or 4xx means the default region, because the store
judged the bucket from there; a 3xx naming no region, a 429 or 5xx, or a
transport failure is a failed probe that teaches no region and is
negative-cached for 60 seconds, during which the bucket answers
`ResourceExhausted` naming the wait, before the cache is entered and any mint
charged, so a repeated refusal costs no budget. A built backend whose own
request answers 301 naming a valid region other than the one it was built for
relearns that region and is rebuilt on the next touch, once and without a probe,
so a region learned wrongly heals from the store's own redirect. A 301 naming
the built region, or none, changes nothing a rebuild could use, so the backend
stays, nothing is evicted or charged, and the caller sees the `InvalidArgument`
the 301 maps to; an unnamed 301 does drop the learned region, so a later miss
probes afresh. The rule is that narrow because the verdict on a backend is
permanent and the mint budget is charged per miss and shared by the layer: an
eviction that rebuilt the same backend would recur on every touch of the bucket
for the layer's life. The probe and the heal are both skipped when
`anonymous_fallback_endpoint` is set, because a MinIO or emulator endpoint has
one region and no region a 301 could name reaches the wire on an unsigned
request. A bucket whose name contains a dot is addressed
path-style regardless of `anonymous_fallback_force_path_style`, because a
dotted bucket sits outside AWS's wildcard certificate.

The S3 error mapping is corrected in the same change, as its own commit, because
the probe depends on it: HTTP 301 maps to `InvalidArgument` (`S3 answered HTTP
301 (PermanentRedirect): the bucket is not served from the configured region`),
307 to `Transient`, and the modeled `AuthorizationHeaderMalformed` code to
`InvalidArgument`; when the response carries a valid `x-amz-bucket-region`,
the mapping attaches a `next_action` naming the setting the receiving backend
actually has — `set region = "{region}" on this connection` on a connection
backend, and `set anonymous_fallback_region = "{region}" on the layer, or add
a connection for s3://{bucket}/ with region = "{region}"` on a fallback
backend, which has no connection.

### Introspection never mints

`root_info_for` on a fallback-served address returns the scheme root
**verbatim** — `s3:///`, `connection_id: None`, `Hidden` — never a synthesized
per-bucket root and never a built client. `list_address_roots` publishes the
marked root Hidden, in ranked order after every deeper root. `list_connections`
is unchanged. `ovstorage connect s3://bucket/` sees no incumbent, because
`incumbent_id` requires `same_node` and `s3:///` is not the node `s3://bucket/`.
The CLI route listing omits hidden roots, so the scheme root does not appear
there; `ovstorage doctor` shows it, because `AddressRootEntry` carries
`connection_id` (null for the scheme root) and `user_metadata` (the marker). An
address whose query carries anything other than a carried version selector
(`versionId`, `versionid`, `generation`), a scheme with no grant, and a host
with the grant off all answer `NoRoute` with the message `no route matches
address` — byte-identical to a graph that has never heard of the feature, so a
client cannot distinguish "not granted" from "not configured".

### Who grants, and where the grant lives

Library, CLI and MCP hosts set the key on the backend layer's table, like every
other layer key:

```toml
[ovstorage.layers.s3]
anonymous_fallback = ["s3"]              # absent or [] = off
anonymous_fallback_region = "us-east-1"  # probe target and default region
anonymous_fallback_endpoint = "http://minio:9000"  # optional; skips the probe

[ovstorage.layers.gcs]
anonymous_fallback = ["gs"]

[ovstorage.layers.azure]
anonymous_fallback = ["azure"]
anonymous_fallback_endpoint_suffix = "core.windows.net"
```

Every `anonymous_fallback*` key is split off the layer table by
`split_anonymous_fallback_keys` **before** the factory's static-seed check,
because every backend factory treats any non-empty layer table as a static
connection to seed; a table holding only the grant seeds nothing. The value must
be a TOML array of strings from the closed set `s3`, `gs`, `azure`, `http`,
`https` (`decode_anonymous_fallback`); a layer refuses a scheme its kind does
not serve by name; and a connection request carrying any of these keys is
refused with `InvalidArgument` naming the layer table, on probe and add alike,
so a grant cannot be smuggled onto a connection. The per-kind tunables — bounds
on the cache and the budget, the S3 region and endpoint, the GCS endpoint, the
Azure endpoint suffix — are validated whether or not the grant names the layer's
scheme, so a misspelt key or an instance-metadata endpoint fails at startup
either way. The GCS `anonymous_fallback_endpoint` is kept as scheme, host, port
and path only, and one that embeds credentials, carries a query or a fragment,
uses a scheme other than http or https, or names no host is refused with
`InvalidArgument` naming the key and the layer, never the value: the string is
what every request URL and every anonymous `read` redirect is built from, and
reqwest would turn URL userinfo into an `Authorization` header on a tier whose
promise is that none is sent. The S3 key of the same name is screened the same
way, down to scheme, host and port: S3 addresses the bucket and key under the
origin and its host derivation keeps nothing else, so a path is refused too
rather than dropped silently. None of the keys is added to a kind's
`config_schema`: they are policy on the layer, not fields of a connection.

The broker and the REST gateway carry two **top-level** keys directly under
`redirect_credential_disclosure`, default closed at TOML parse and in every
constructor:

```toml
anonymous_fallback_schemes = []      # "s3", "gs", "azure"; empty = NoRoute
anonymous_http_fallback = "refuse"   # "allow" is refused at startup
```

`ovstorage::host::stamp_anonymous_fallback` writes the grant onto the graph. It
stamps `anonymous_fallback = [..]` onto the single layer of each tier-owning
kind (`s3`, `gcs`, `azure`) that has a granted scheme, and stamps **only
non-empty grants**: an empty array is never written, so a graph built with the
default is byte-identical to the parsed graph and a bare
`[ovstorage.layers.http]` stays an empty, routable-but-unconnected table. The
carrier is resolved against the **routed** graph — the layers `root` reaches
through `inner` and `children`, transitively — rather than the declaration
table, because the Stack builder instantiates exactly that set: a declared
layer nothing routes to is never built, so a grant stamped onto it would
publish no root while startup reported success. A backend reached only through
a wrapper chain, or one that is itself the root, is therefore a valid carrier,
and a declared-but-unrouted layer is never counted. It refuses with
`InvalidArgument` naming the fix: a hand-set `anonymous_fallback` layer key,
checked even when the grant is empty, because the policy has one spelling; a
grant whose kind has zero layers (`declare [ovstorage.layers.gcs] and add it to
the router's children`), because a grant that sits silently inert is worse than
one that fails loud; a grant whose kind's only layers are declared but
unrouted, naming them (`layer gcs of kind gcs is declared and not reachable
from the graph's root, so the grant would sit inert: add it to the router's
children (or make it the root, or a wrapper's inner)`), for the same reason; a
grant whose kind has two or more routed layers, because two scheme roots for
one scheme shadow each other silently — a disconnected duplicate declaration
does not trip this; and any
`http` or `https` grant, including `anonymous_http_fallback = "allow"`, because
the http tier is not available in this release. It never touches an `http`
layer. One `info!` names the granted set at startup. The broker's
`CloudFallbackScheme` deliberately has no `http` variant, so
`anonymous_fallback_schemes = ["http"]` is a parse error rather than a
stamp-time refusal.

### The brokered client requires a local grant

A `BrokerClientLayer` reads the same `anonymous_fallback = [..]` key from its
own layer table (`[ovstorage.layers.broker]`) and uses it as an admission
filter: `should_ingest_root` drops a wire-delivered marked scheme root whose
scheme the local table does not grant, with one `debug!`, so the address is
`NoRoute` on the client. With the grant the client honours the advertised root,
forwards the caller's address verbatim — never a suffix — and the broker's own
two tiers do the rest. The root is projected read-only whatever capability bits
the wire asserted — `root_info` runs `read_only_capabilities` over the
projection, so the client holds the invariant every backend states through
`scheme_fallback_root` rather than trusting the wire to have lowered it — and
every mutating slot and `watch_directory` on an address the root answers is
refused on the client with `fallback_mutation_refused`, before any body is
buffered or request sent; the root it names is the address's origin, because
the client routes for every scheme the broker serves and knows none of their
node shapes. `copy` and `rename` are refused when either end is
fallback-routed. The client publishes no scheme root of its own; a broker that
grants nothing advertises nothing to honour. A grant-only broker layer table
seeds no static connection, for the same split reason as the backends.

### Authorization is untouched

The authorization layer is outermost, evaluates the caller-supplied address, and
is deny-by-default. The rule the policy documentation states for generated
aliases is the rule here, extended in the same voice: policy sees the caller's
address, before alias resolution and before routing; a fallback changes what is
**reachable**, never what is **authorized**; and no grant is ever generated for
it — that would be automatic widening of a deny-by-default policy. A denied
caller is refused before the Router is consulted, so a caller the policy does
not cover can never cause an outbound request or a client build. A bucket-scoped
rule (`prefix = "s3://public/"`) covers that bucket and nothing else: not a
sibling bucket, not a host that merely starts with the same text, and not
`s3:///`. `root_info_for` on an ungranted fallback-served address answers the
router's verbatim `NoRoute`, not `PermissionDenied`. The hidden scheme root is
listed only to a principal whose rule covers the bare scheme —
`prefix = "s3://"` loads as the scope `s3:///` — and that rule grants nothing on
any bucket, because `s3:///` is an ancestor of no hosted address. A brokered CLI
therefore sees the hidden root only with a bare-scheme rule on the broker and a
local grant on its own layer.

### The http tier's recorded shape

`http` and `https` are in the closed scheme set and refused everywhere they
could be granted in this release. The follow-up under this RFC gives them the
tier with this shape: marked placeholder roots
`http://anonymous-fallback.invalid/` and `https://anonymous-fallback.invalid/`;
one anonymous `HttpBackend` per **origin**, built with
`redirect_policy = "none"` so a fallback fetch follows nothing; refusal of any
address carrying userinfo; the origin judged by the instance-metadata predicate
before the client is built; and the
`org.omniverse.ovstorage/resolved-oauth-credential@1` request extension stripped
(`take_resolved_oauth_credential`) before dispatch, so the broker's upstream
OAuth credential can never attach to a fallback fetch. Open for that follow-up
is whether to refuse non-public address ranges by default as well.

## Consequences

**Plugin C ABI: unchanged.** No new `RouteSource` variant, no new struct field,
no new vtable slot; `ovstorage_plugin.h` and `ovstorage.h` are untouched. A
plugin that knows nothing of the marker and publishes a hostless root sees no
change: the root is an ordinary prefix root.

**Wire contract: unchanged.** The marker rides `user_metadata`, which the broker
protocol already carries on every advertised root.

**Capability set: unchanged; no new error code.** The read-only contract is the
existing capability self-gate applied by the tier; `NoRoute`, `Unsupported`,
`InvalidArgument`, `PermissionDenied` and `ResourceExhausted` carry every new
refusal. `lint-layer-ownership` stays silent because no `*_KIND` is added; the
edited registry rows are the reviewable act.

**Public Rust additions**, by path:

- `ovstorage-core/ovstorage-layer/src/fallback.rs` —
  `ovstorage_layer::fallback`: the key and marker constants, the closed scheme
  set, `schemes_for_kind`, `is_anonymous_fallback_key`,
  `decode_anonymous_fallback`, `split_anonymous_fallback_keys`,
  `scheme_fallback_root`, `is_scheme_fallback_root`, `read_only_capabilities`
  and `fallback_mutation_refused`; re-exported as `ovstorage_plugin::fallback`
  and `ovstorage::fallback`.
- `ovstorage-core/ovstorage-layer/src/instance_metadata.rs` —
  `is_instance_metadata_host_str`, `is_instance_metadata_url` and
  `refuse_instance_metadata`, re-exported the same way.
- `ovstorage-core/ovstorage-plugin/src/routing.rs` —
  `RouteTable::lookup_prefix`; `RouteTable::lookup` keeps its signature and
  gains the second tier.
- `ovstorage-core/ovstorage-plugin/src/fallback_cache.rs` —
  `ovstorage_plugin::fallback_cache::FallbackCache<K, V>`, the bounded
  single-flight LRU with a mint budget.
- `ovstorage-core/ovstorage/src/host.rs` —
  `ovstorage::host::stamp_anonymous_fallback`.
- `ovstorage-remote/ovstorage-broker/src/config.rs` —
  `BrokerConfig::anonymous_fallback_schemes`,
  `BrokerConfig::anonymous_http_fallback`,
  `BrokerConfig::anonymous_fallback_set`, `CloudFallbackScheme` and
  `AnonymousHttpFallbackConfig`.
- `ovstorage-remote/ovstorage-rest/src/stack.rs` —
  `GatewayStackBuilder::anonymous_fallback`.
- `ovstorage-core/ovstorage-cli/src/commands/doctor.rs` —
  `AddressRootEntry::connection_id` and `AddressRootEntry::user_metadata`, an
  additive change to the `ovstorage doctor --json` contract.

**Behaviour change for configured S3 connections with a wrong region.** HTTP 301
is `InvalidArgument`, not `Transient`, so a connection whose `region` does not
serve its bucket fails fast with a `next_action` naming the region S3 reports,
where a `Transient` classification buys only a pointless retry. A caller that
tolerated the retry sees a non-retryable error instead. HTTP 307 is `Transient`.

**Behaviour change for every http connection.** A redirect whose destination is
an instance-metadata host is `PermissionDenied` under every `redirect_policy`,
including an allow-list that names the host and including `none`, where the
caller receives a typed refusal instead of the 3xx it otherwise sees. The
redirect follower refuses a backend-minted read or write redirect to such a host
on the first attempt and on every re-mint, so a remote store cannot steer a
follower at the instance's credentials. A credentialed connection whose root
answers a 3xx to such a host fails `instantiate` with `PermissionDenied`.

**Behaviour change for cloud connection requests.** A connection request
carrying an `anonymous_fallback*` key is refused by the S3, GCS and Azure layers
with a message naming the layer table, so a grant cannot be smuggled onto a
connection. A configured S3, GCS, Azure or http endpoint at an instance-metadata
host is honoured with one advisory `warn!`.

**Ownership registry.** Two rows in
[`OWNERSHIP.md`](../public/plugin-storage/OWNERSHIP.md) are edited in the same
change as the code. The `Router` row reads "routing across child Layers by URL
prefix (longest prefix, then a marked scheme-fallback root for the address's
scheme), and connection ops by target name". The owning-backend row for
address-level routing gains "and the per-scheme anonymous fallback for an
address on that kind's scheme that no connection serves: the hidden scheme root,
the per-bucket anonymous client, the read-only refusal and the instance-metadata
refusal". The split is stated once: the backend owns reaching an address
anonymously; the host owns whether that is permitted.

**Cost.** An ungranted graph pays one hash probe per route miss and nothing
else; an unmarked table's `lookup` is its `lookup_prefix`. A granted S3 layer
pays one unsigned `HeadBucket` per cold bucket; GCS and Azure pay no probe.
Every built client is bounded by the LRU and the budget.

**Follow-ups**, recorded here so the decision record is complete:

- the `http`/`https` per-origin tier, in the shape recorded above, which moves
  those schemes into the available set;
- a `file:` tier (issue #491), as a future entry in the closed scheme set;
- DNS rebinding — a name resolving to a link-local address passes the predicate;
  closing it needs a resolve-then-check connector in the reqwest (`plugin-http`)
  and smithy (`plugin-s3`) clients;
- the `https://` spellings of GCS and Azure objects reaching the cloud tier,
  which needs an inverse of `alternate_url_prefixes`;
- refusing an operator-configured instance-metadata endpoint (`endpoint`,
  `blob_endpoint`, `root_url`) rather than warning;
- `install()` `RouteConflict` hardening for the S3, GCS and Azure layers, on the
  model of the http plugin's `install`;
- read-only capabilities for every configured anonymous GCS and Azure
  connection, a capability-shape change;
- a layer-name grant form for two layers of one kind on stamped hosts, and an
  `s3+minio://` fallback.

## Alternatives considered

**A Router-owned scheme → child map.** A `[ovstorage.layers.router]` key naming
a child per scheme, consulted on a miss. Rejected on three counts. Introspection
asymmetry: a Router publishes only what its children publish, so it would route
an address that `root_info_for` on the same Stack answers `NoRoute` for, and
every wrapper that asks what `inner` can do before acting — the redirect
follower's write-protocol selection, the metadata cache — would be misled.
Shadowing along the alias chain: the alias wrapper projects the roots below it,
so a Router-private rule is invisible to the alias layer's own
`list_address_roots`, and an operator's authored root on a child's table and the
Router's catch-all would be two places deciding one address space, with graph
order picking the winner. Dead for brokered clients: the brokered client is a
backend Layer with its own table and no host Router above it in the brokered
graph, and a Router-private rule never crosses the wire, where a marked root
does.

**A new `RouteSource` variant.** The natural spelling, and the most expensive:
`RouteSource` is a `repr(C)` tag on the plugin ABI and the C header, so a
variant is an ABI revision, and the broker re-labels every advertised root
`BrokerDelivered`, so the variant is lost on the wire anyway. A reserved
metadata key crosses both boundaries with no change to either.

**Minting real `Connection`s per touched bucket.** A `Connection` has an id, is
listed by `list_connections`, is persisted by hosts that persist connections, is
probed on start, contests `RouteConflict`, and is the incumbent
`ovstorage connect` reports. One per bucket a caller invents is a resource the
caller controls. A bounded cache of clients with no `Connection` has none of
those properties, and `install()` eviction gives a real connection precedence
the moment an operator adds one.

**A wrapper Layer kind.** Fails the information test twice. A wrapper cannot
derive an account and container from an `azure://` address without Azure's
address grammar, or build a client without the plugin's config types. And it has
no place to stand: below the Router it never sees the miss, because the Router
misses before dispatching to any child; above the Router it is routing. It would
also need a `*_KIND` and a registry row for a concern the backend already owns.

**A request-extension selector.** An extension saying "attempt anonymously" is
an instruction addressed to a layer kind, which RFC-0066 forbids. It also puts
the grant in the caller's hands: any client the policy admits could ask for it,
so the operator's deployment decision becomes the caller's.

**One boolean per scheme.** `anonymous_s3_fallback = true` and kin cost one key
per scheme per host and still need the scheme-to-kind table. A closed array is
one key, grows by one string, validates at parse against the closed set, and
names the kind that must carry each grant.

**Suffix matching for the instance-metadata names.**
`metadata.google.internal.evil.test` is somebody else's host, and the http
plugin's `is_loopback_host` documents the reverse mistake for `localhost`. Exact
match after one trailing-dot strip is what the resolver does.

**`NoRoute` or `InvalidArgument` for the metadata refusal.** `NoRoute` is
byte-identical to "not granted" and would hide a security refusal as a
configuration gap. `InvalidArgument` says the address is malformed, and it is
not. `PermissionDenied` says what happened and is not retried.

**Refusing configured link-local endpoints.** The operator wrote
`endpoint = "http://169.254.169.254"`, and refusal belongs to a shared
transport-boundary decision across providers, as the Azure cleartext diagnostic
records for the same situation. The connection is honoured and the exposure is
named once at construction.

**Read-only capabilities for every anonymous GCS and Azure connection.** A
capability-shape change for configured connections, with its own review and its
own consumers. The fallback's clamp belongs to the tier; a configured anonymous
connection keeps the bits it declares.

**Synthesizing a per-bucket root from `root_info_for`.** The table never held
such a root, so `list_address_roots` and `root_info_for` would disagree about
what exists, and an introspection call would build a client or send a probe.
Returning the scheme root verbatim keeps "what is published" and "what is
answered" one set and keeps introspection free of side effects.

**Publishing the scheme root `Visible`.** A visible `s3:///` would appear in
every route listing and picker as a browsable root, and no bucket enumeration
exists to browse it. `Hidden` keeps it addressable, keeps it out of the CLI
route listing, and shows it to `doctor` and MCP with its true visibility.

**Stamping empty grants.** Every backend factory seeds a static connection from
a non-empty layer table, so an empty array on a layer of an ungranted kind is a
key every tool has to know to ignore. Writing only non-empty grants keeps the
default graph byte-identical to the parsed one and keeps
`[ovstorage.layers.http]` an empty table.

---

### Lifecycle

`Proposed` → (flip to `Accepted` in the final commit before this PR merges) →
`Accepted` → (implementation lands, durable detail folded into the Software
Design Document) → `Implemented`. A later RFC may set this one's
**Superseded-by** and move it to `Superseded`. The file never moves — status
lives in this header and the [index](README.md), so links and `Depends-on`
references stay stable for the RFC's whole life.
