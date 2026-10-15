Up: [ovstorage-expert](../../SKILL.md)

# Configure ovstorage

Every host — CLI, MCP, Python `Stack.from_config()`, REST, broker, and the resolver — loads the same `ovstorage.toml` schema. Full reference: [configuration.md](../../../../ovstorage/docs/public/configuration.md).

## Shape

```toml
[ovstorage]
root = "file"                  # name of the root Layer

[ovstorage.layers.file]        # one table per Layer; `kind` defaults to the table name
# wrappers name `inner`; routers name `children = [...]`

[[ovstorage.connections]]      # credential and endpoint bindings
backend_kind = "file"
# target, display_name, [config], [credentials] — credentials use ${ENV_VAR}
```

- Never write literal secrets; use `${NAME}` references. Substitution happens when the Stack is built, so a missing variable fails at build time with `NotConfigured` naming it.
- The quickest correct file is generated: `ovstorage init`, then `connect <backend> …` in the interactive shell, then `write-config ovstorage.toml --secrets env`. See the [CLI README](../../../../ovstorage/ovstorage-core/ovstorage-cli/README.md).
- Which backend and which credential method: [choose a backend](../../../../ovstorage/skills/ovstorage-user-choose-a-backend/SKILL.md) and [authenticate](../../../../ovstorage/skills/ovstorage-user-authenticate-to-backend/SKILL.md). For sign-in flows and unattended credentials, see [authentication](../authentication/README.md).

## Redirects

A Stack has only the wrappers its graph declares; `build_stack` adds none. Backends that answer reads with a redirect need a `redirect_follower` above them, or the read hands the redirect back to the caller instead of bytes. `s3` answers every read with a redirect, presigned with SigV4 or a plain URL for an anonymous connection ([plugin-s3.md](../../../../ovstorage/docs/public/plugin-storage/plugin-s3.md)); Nucleus LFT, Azure under Entra OAuth or a SAS token, and the Omniverse Storage Service client also redirect, and without the follower their credential-bearing redirects fail instead of being fetched locally ([configuration.md](../../../../ovstorage/docs/public/configuration.md), wrappers). The follower comes from the HTTP plugin, which the Python wheel bundles.

```toml
[ovstorage]
root = "redirects"

[ovstorage.layers.redirects]
kind = "redirect_follower"
inner = "s3"

[ovstorage.layers.s3]

[[ovstorage.connections]]
backend_kind = "s3"
config = { bucket = "my-bucket", region = "us-west-2" }
credentials = { aws_access_key_id = "${AWS_ACCESS_KEY_ID}", aws_secret_access_key = "${AWS_SECRET_ACCESS_KEY}" }
```

- With several backends, point `inner` at a `router` (`kind = "router"`, `children = [...]`), which the core plugin provides.
- S3 credential fields are `aws_access_key_id`, `aws_secret_access_key`, and optional `aws_session_token`, or `file_path` and `profile` for a credentials file; the plugin reads no others (`ovstorage-plugin-s3/src/credentials.rs`).
- `follow_reads_max_bytes` is unbounded by default and `read_bytes` buffers a followed object whole; bound reads with `max_bytes`, or use `materialize` for large objects.

## Where configuration is found

CLI order: `--no-config`, `--config PATH`, `$OVSTORAGE_CONFIG`, `./ovstorage.toml`, `$XDG_CONFIG_HOME/ovstorage/ovstorage.toml`, then an empty Stack. MCP and Python follow the same order without the CLI flags. The resolver takes an explicit path (`--stack-config`, or `configPath` when embedding).

## Environment

| Variable | Effect |
| --- | --- |
| `OVSTORAGE_CONFIG` | Configuration file path |
| `OVSTORAGE__…` | Override any key; `__` separates levels (for example `OVSTORAGE__LAYERS__BYTE_CACHE__MAX_OBJECT_BYTES`). Broker and REST use `OVSTORAGE_BROKER__OVSTORAGE__…` and `OVSTORAGE_REST__OVSTORAGE__…` |
| `OVSTORAGE_PLUGIN_DIR` | Provider plugin directory; otherwise `<exe-dir>/plugins/`. The Python wheel exposes `ovstorage.bundled_plugins_dir()` |
| `OVSTORAGE_CACHE_ROOT`, `OVSTORAGE_STATE_ROOT` | Local byte-cache objects and its SQLite index, leases, and locks. Network filesystems are refused unless `OVSTORAGE_ALLOW_NETWORK_FS=1` |
| `OVSTORAGE_AUTH_DIR` | Auth database location, separate from cache and state |

Cache details: [ovstorage-cache README](../../../../ovstorage/ovstorage-core/ovstorage-cache/README.md). The local byte and metadata cache Layers help one process or host; they are not a shared cache. For shared or scale-out caching see [related experts](../related-experts.md).

## Check

```sh
ovstorage --config ovstorage.toml list-routes      # parses, resolves ${…}, builds the Stack
ovstorage --config ovstorage.toml list-connections # auth_state per connection
```

Any subcommand exits non-zero on malformed layer or connection configuration, so `list-routes` is the pre-deploy validation step.
