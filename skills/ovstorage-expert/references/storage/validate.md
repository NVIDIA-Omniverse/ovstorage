Up: [ovstorage-expert](../../SKILL.md)

# Validate ovstorage

## Smoke check an install

From a directory with an `ovstorage.toml` (or after `ovstorage init` and a `file` connection):

```sh
ovstorage list-routes                                  # Stack builds; routes visible
ovstorage list-connections                             # auth_state is authenticated or anonymous
printf hi | ovstorage write file:///tmp/ovs-smoke.txt -i -
ovstorage stat file:///tmp/ovs-smoke.txt
ovstorage read file:///tmp/ovs-smoke.txt -o -          # prints: hi
```

Repeat `stat` and `read` against a real address on each configured backend. For agents, call the MCP `ovstorage_doctor` tool and compare its backends, connections, and address roots with the configuration ([getting-started skill](../../../../ovstorage/skills/ovstorage-user-getting-started/SKILL.md)).

## Test suites

Run from `ovstorage/`; see [build.md](build.md) for what each target covers. `make test-integration` is hermetic. `make test-integration-live` needs live credentials and is a maintainer check ([integration tests skill](../../../../ovstorage/skills/ovstorage-contributor-run-integration-tests/SKILL.md)).

## Reading failures

CLI exit codes follow the error taxonomy: `0` success, `2` NotFound, `3` PermissionDenied, `4` PreconditionFailed, `6` Unsupported, `7` InvalidArgument, `10` Transient, `13` BrokerUnavailable, `14` AuthRequired, `19` PartialCompletion, `20` CommitAmbiguous. Codes `19` and `20` mean the operation happened; don't retry or roll back. The full table is in the [CLI README](../../../../ovstorage/ovstorage-core/ovstorage-cli/README.md).

| Symptom | Usual cause | Next step |
| --- | --- | --- |
| `NotConfigured` at startup | No `[ovstorage]` table, or an unset `${VAR}` | Fix the file or export the variable named in the error |
| `NoRoute` | No Layer owns the address root | Compare with `list-routes`; add a connection or fix the address |
| `Unsupported` | That backend lacks the operation | Use another operation or backend ([choose a backend](../../../../ovstorage/skills/ovstorage-user-choose-a-backend/SKILL.md)) |
| `awaiting-auth` or `auth-failed` | Credential missing or refused | [Authenticate](../../../../ovstorage/skills/ovstorage-user-authenticate-to-backend/SKILL.md); `ovstorage reauth <name>` for interactive flows |
| Plugin kind not found | Plugin directory not discovered | Set `OVSTORAGE_PLUGIN_DIR`; confirm the library exists there |

For error-envelope handling in agent loops, use the [handle-errors skill](../../../../ovstorage/skills/ovstorage-user-handle-errors/SKILL.md).
