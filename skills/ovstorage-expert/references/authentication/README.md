Up: [ovstorage-expert](../../SKILL.md)

# Authentication model

Authentication in this checkout belongs to **ovstorage**. The resolver holds no credentials and has no auth settings: it reaches storage through the Stack the host builds or the `ovstorage.toml` it names, and it redacts URI-shaped tokens from its diagnostics ([resolver configuration](../../../../ovstorage-usd-resolver/docs/configuration.md)). A resolver auth problem is therefore a storage connection problem, so fix it there.

## Concepts

- **Connection.** Each backend endpoint is a connection, owned by a layer and named by `(target, id)`. It carries its own credentials and an `auth_state`: `authenticated`, `anonymous`, `awaiting-auth`, or `auth-failed`.
- **Credential method.** Each backend kind's descriptor lists the methods it accepts and the fields each one needs, such as a static key, a session token, a bearer, sign-in, or workload identity. Read the descriptor before asking anyone for a secret.
- **Interactive sign-in.** Backends that offer it run `authenticate_connection`, which returns an event stream: `OpenBrowser`, `DeviceCode`, `Progress`, then a terminal `Succeeded`, `Failed`, or `Cancelled`. `Unsupported` means no flow exists for that connection. Its credential comes with the connection instead.
- **Capability.** The host declares what it can do: `Browser` (a local browser with a loopback callback), `Headless` (device code), or `None` (fail fast and never prompt).
- **Identity is not access.** A successful sign-in proves who the caller is. Whether they may read or write a location is decided by the origin, or by the broker or REST gateway's policy. Diagnose `AuthRequired` and `PermissionDenied` separately.
- **Every client authenticates on its own.** A browser session, the CLI, a Python process, and a remote agent each hold separate credentials. Signing in to one doesn't sign in another.

## Pick the guide

| Situation | Open |
| --- | --- |
| A person or an agent needs to sign in, or to fix a connection that won't authenticate | [users.md](users.md) |
| A developer is adding authentication to an application or resolver host | [integrate.md](integrate.md) |
| A farm, CI, or service runs with nobody present | [workloads.md](workloads.md) |
| The exact fields for one backend kind | [authenticate to a backend](../../../../ovstorage/skills/ovstorage-user-authenticate-to-backend/SKILL.md) |
