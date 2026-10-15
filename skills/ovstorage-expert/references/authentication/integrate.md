Up: [authentication](README.md)

# Integrate authentication into an application

## Decide who supplies credentials

| Source | Use | API |
| --- | --- | --- |
| Configuration | Keys and tokens the operator provides | `[[ovstorage.connections]].credentials` with `${VAR}` references, resolved when the Stack builds ([configuration](../../../../ovstorage/docs/public/configuration.md)) |
| Interactive sign-in | A person is present | Set the Stack's capability, then drive `authenticate_connection` |
| An external issuer the app already trusts | A portal, sidecar, or token service mints credentials | Python `credential_callback`; push rotations with `set_credential` |
| A remote daemon | Clients shouldn't hold backend credentials | The broker client backend; see [workloads.md](workloads.md) |

## Drive sign-in

The Python sequence is in [Interactive authentication](../../../../ovstorage/docs/public/library-python/README.md#interactive-authentication):

1. Construct the Stack with `interactive_auth_capability`: `InteractiveAuthCapability.BROWSER`, `HEADLESS`, or `NONE`. Choose the one the host can actually satisfy. A GUI app uses `BROWSER`, a remote or agent host uses `HEADLESS`, and a service uses `NONE`.
2. Keep the owning layer target and the connection id. The target is a layer name, not an address.
3. Consume every event. Open or show `OpenBrowser` URLs before `expires_at_unix_nanos`. Show the `DeviceCode` URL and code and keep pulling, because the layer polls the provider itself. Stop on `Succeeded`, `Failed`, or `Cancelled`, and `aclose()` the stream to abandon a flow.
4. If `Succeeded` carries tokens, re-apply them with `update_connection_credentials`.

C and C++ expose the same events and capability (`OvStorage_AuthEvent`, `OvStorage_InteractiveAuthCapability`): see the [C++ guide](../../../../ovstorage/docs/public/library-cpp/README.md) and the [C ABI](../../../../ovstorage/ovstorage-c-source/README.md). For Rust, see the [library README](../../../../ovstorage/docs/public/library-rust/README.md).

## Lifecycle facts to design around

- The resolved-credential cache is per Stack and in memory. Whether a sign-in survives the process depends on the backend: some persist it through the host's secret store under the auth directory (`OVSTORAGE_AUTH_DIR`) or through the OS keyring. Python allows one auth directory per process.
- Backends that sign in refresh tokens themselves. Hosts that inject tokens rotate them with `update_connection_credentials`; the rotation can't change the credential's shape.
- There is no getter for a connection's token. A companion API that needs one gets it only from a `Succeeded` event the host drove itself.
- Credentials never go in an address. Use the backend's credential fields.

## Resolver hosts

Build and authenticate the Stack before binding the resolver, then pass it in with `OvStorageBridgeOptions::layerHandle`, or name a config with `configPath` ([embed](../resolver/embed.md)). The resolver adds no prompts and no credential settings of its own. Validate the connection with the storage checks first, then with `ovstorage-usd-resolver doctor --uri <address>`.

## Serving other clients

The broker and the REST gateway authenticate their own callers through a per-listener auth layer, separate from the backend credentials they hold. Configure that with [deploy the broker](../../../../ovstorage/skills/ovstorage-operator-deploy-broker/SKILL.md), the [broker operator guide](../../../../ovstorage/docs/public/broker-operator/README.md#auth-layer), and the [REST README](../../../../ovstorage/ovstorage-remote/ovstorage-rest/README.md).
