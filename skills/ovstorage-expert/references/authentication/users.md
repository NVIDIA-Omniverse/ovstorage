Up: [authentication](README.md)

# Help a person or agent sign in

## Choose the route

| Who is connecting | Route |
| --- | --- |
| A person at a desktop with a browser | Browser sign-in through `connect` or `reauth` |
| An agent, a script, or a remote shell supervised by a person | Device code: the agent shows the URL and code, and the person finishes in any browser |
| A backend with no sign-in flow (keys, tokens, signed URLs) | Supply the credential the descriptor names, using a `${VAR}` reference |
| Nobody present | [workloads.md](workloads.md) |

An agent never completes sign-in for the person and never asks for their password. It relays the `OpenBrowser` URL or the `DeviceCode` verification URL and user code, keeps consuming events until a terminal event arrives, and reports the outcome.

## CLI path

Reference: [CLI README](../../../../ovstorage/ovstorage-core/ovstorage-cli/README.md).

1. In the interactive shell, run `connect <backend>`. It lists only the credential methods that backend and address can use, then streams the sign-in events.
2. Save the result with `write-config ovstorage.toml --secrets env`. Literal secrets become `${OVSTORAGE_…}` references, and the command prints the variable names to export.
3. Later, run `ovstorage reauth <name>` (or `reauth <name>` in the interactive shell) to sign in again or as a different account. It answers `Unsupported` (exit `6`) when the backend has no flow. The fix then is a corrected credential through `connect`, not another sign-in.

MCP agents get the same view from `ovstorage_doctor` and `ovstorage_connections_list` ([MCP tools](../../../../ovstorage/docs/public/agent/mcp-tools.md)).

## Prove it worked

Check in the tool that will do the work, because a browser session proves nothing about the CLI or the agent:

```sh
ovstorage list-connections        # auth_state should be authenticated or anonymous
ovstorage list-routes             # the target address is covered
ovstorage list <address>          # a real read; write and read back a scratch object if writes matter
```

## Read the failure

| Signal | Meaning | Next step |
| --- | --- | --- |
| `awaiting-auth`, or exit `14` `AuthRequired` | No usable credential, or the refresh failed | `reauth`, or supply the credential |
| `auth-failed` | The origin refused the credential | Correct it through `connect` |
| Exit `3` `PermissionDenied` after sign-in | Identity is fine, access isn't | Ask the content owner for access; signing in again won't help |
| Network or discovery errors | Not an auth problem | Check the address and connectivity |

More: [handle errors](../../../../ovstorage/skills/ovstorage-user-handle-errors/SKILL.md). Keep secret values out of chat, logs, and committed files. Pass them through environment references.
