# Authorization policy

`ovstorage-broker` and `ovstorage-rest` compose one listener-auth wrapper above
the host's storage Stack. The first-party `builtin-auth` wrapper combines
listener authentication with the in-tree TOML policy engine documented here.
Loaded plugin wrapper kinds whose descriptor declares `auth_capable = true`
may provide their own authentication and authorization behavior.

There is no standalone authorization-plugin ABI and no authorization-cdylib
loader. Plugin auth wrappers use the ordinary storage Layer ABI and own their
configuration schema and policy lifecycle. A missing or unknown auth kind, a
backend or router kind, or a wrapper without `auth_capable = true` fails
startup.

## Configuration

Broker listeners and REST servers require an explicit auth choice. This guide
covers the built-in form:

```toml
[listener.auth]
kind = "builtin-auth"

[listener.auth.config]
jwt_issuer = "https://login.example.com"
jwt_audience = "ovstorage"
jwt_jwks_url = "https://login.example.com/.well-known/jwks.json"

[listener.auth.config.policy]

[[listener.auth.config.policy.policy]]
id = "team-read"
effect = "allow"
principal = "team-*"
operations = ["read", "stat", "list"]
prefix = "s3://corp-prod/team/"

[[listener.auth.config.policy.policy]]
id = "team-upstream-auth"
effect = "allow"
principal = "team-*"
operations = ["update_connection_credentials"]
prefix = "https://assets.example.com/team/"
```

Both interactive `authenticate_connection` and proactive
`update_connection_credentials` requests use the
`update_connection_credentials` policy operation. Add an allow rule for that
operation and the bound upstream-address prefix when principals must establish
or replace broker-side upstream credentials. A policy that allows only data
operations denies both credential slots by default.

The `plugin` key accepted inside the policy document is a schema
discriminator. Its only supported value is `ovstorage-authz-toml`; it does
not select or load a cdylib.

Use `auth = "anonymous"` only when the listener's transport is the trust
boundary and unauthenticated access is intentional. Omitting auth
configuration is a startup error.

A plugin form names its loaded auth-capable wrapper and passes its config
verbatim to that factory:

```toml
[listener.auth]
kind = "corp-auth"

[listener.auth.config]
issuer_alias = "production"
```

The built-in `authn_mode`, `jwt_*`, and `peer_dev_current_user` settings do not
configure plugin kinds. On a broker TCP listener, host-owned `trusted_proxy`
and `trusted_peers` protect forwarded metadata for either auth form. A plugin
may select its captured identity and claim metadata with
`forwarded_identity_header` (default `x-forwarded-user`) and
`forwarded_claim_headers`; those fields are also passed unchanged to its
factory.

## Matching

A rule matches when its `principal` glob-matches the caller's principal id,
its `operations` contains the requested operation (or is `"*"`), and its
`prefix` covers the request address.

`prefix = "*"` matches every request, including operations that carry no
address (`list_address_roots`, `list_backend_kinds`, `list_connections`, …).
A concrete prefix matches only requests that carry one.

A concrete prefix covers an address when the prefix's **decoded path
components** are a leading run of the address's, under the same scheme, host
and port. Component alignment is what stops `s3://bucket/foo` covering
`s3://bucket/foobar`. Comparison is on the parsed address — scheme, host,
port, path — and never on its serialized text, so **the query and the
fragment are not compared**, and a prefix that carries either is a load
error.

When several rules match, the one pinning the **most path components** wins;
ties go to the **later declared** rule. Writing the same prefix text twice is
how a later rule deliberately supersedes an earlier one. Two different
spellings that resolve to one scope are refused at load rather than decided
by declaration order.

A trailing slash is not part of a node's identity: `s3://bucket/team/` covers
the node `s3://bucket/team` as well as everything under it. On a flat store
those are two distinct objects, so **a rule written for a subtree also covers
the sibling object of that name.** This is a widening, and it holds for
`allow` as much as for `deny`.

### How a prefix must be spelled

Because matching is on the parsed address, a prefix whose text does not
resolve to the scope it reads as is refused at load rather than matched
loosely:

- **`prefix_escapes_are_decoded = true` is required** — a sibling of `plugin`
  in the policy document, so `[listener.auth.config.policy]` in the broker's
  nested form — before a policy whose prefix carries a percent-escape loads.
  A prefix's serialized form carries one whenever the URL parser adds it, so
  this reaches prefixes written without an escape. The escape decodes:
  `s3://b/100%25` names `100%`. The load error lists each affected rule with
  the scope it resolves to.
- **Four prefix spellings are refused at load**: two spellings of one
  scope, a `\` path separator on `file:`/`http:`/`https:`/`ws:`/`wss:`/`ftp:`,
  leading or trailing whitespace and embedded tab/newline/carriage return,
  and an authority not separated from the path by `/`. Each would scope
  something wider than it reads as. The
  [broker operator guide](../broker-operator/README.md) has the worked
  examples.
- **Userinfo in a prefix does not narrow it.** An `allow` prefix carrying
  credentials is refused at load, because dropping them from the comparison
  widens the rule to every credential.

## Built-in runtime contract

- Policy evaluation is deny-by-default and runs on every request. There is no
  policy-epoch counter, no freshness window, and no persisted policy state.
- Policy reload swaps the active policy atomically; the next request observes
  the new rules.
- The Layer gates data operations and filters per-item list and watch results.
- The Layer also gates `authenticate_connection` and
  `update_connection_credentials` as the policy operation
  `update_connection_credentials` against the upstream address, when present.
- **The `list` post-filter authorizes `stat`, not `read`.** A principal
  granted `stat` but not `read` sees entries — names, sizes, mtimes — it
  cannot read the bytes of. Byte reads are gated by the separate `read`
  check.
- `copy` and `rename` are authorized as their primitive read, write, and delete
  operations.
- The winning rule's `id` rides as the decision's audit explanation.
- Decisions emit `ovstorage_auth_decisions_total` with an
  `allow`, `deny`, or `error` outcome.

The built-in typed policy reload operation applies only to `builtin-auth`.
Plugin auth kinds do not receive an in-place policy mutation: broker SIGHUP
reconstructs the wrapper from its verbatim config as part of the fresh broker,
and the REST gateway requires a process restart for auth configuration changes.

For complete operator configuration, see the
[broker operator guide](../broker-operator/README.md#auth-layer).
Contributors changing the implementation should start with
`ovstorage-remote/ovstorage-authz-layer` and
`ovstorage-remote/ovstorage-authz-policy`.
