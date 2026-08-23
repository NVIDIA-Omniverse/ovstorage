# Credential-provider support

ovstorage connections use explicit, host-resolved credential bundles. A storage
plugin receives the fields declared by its descriptor and does not silently
instantiate the provider SDK's complete ambient credential chain. This keeps
credential choice auditable, but it means selecting ovstorage can require an
integration step even when a provider-native application already authenticates
on the same machine.

## Support matrix

| Provider | Credential source | Support | Bundle shape or limitation |
|---|---|---:|---|
| S3 | Access key + secret, optional session token | Yes | `aws_access_key_id`, `aws_secret_access_key`, optional `aws_session_token` |
| S3 | Static environment variables | Host bridge | The host maps `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and optional `AWS_SESSION_TOKEN` into the corresponding bundle fields; the plugin does not read them. |
| S3 | Shared credentials profile | Yes | Pass `file_path` and optional `profile`; the plugin reads the selected INI section. A host may alternatively resolve it into the three static credential fields. |
| S3 | IMDS / instance profile | Host bridge | Resolve outside the plugin and pass the resulting temporary key, secret, and session token. |
| S3 | AWS SSO, web identity, STS assume-role | Host bridge | Resolve outside the plugin and pass the resulting temporary key, secret, and session token. The plugin does not execute these grants. |
| GCS | Service-account JSON | Yes | `service_account_key` inline or `file_path` |
| GCS | Authorized-user ADC JSON | Yes | `service_account_key` inline or `file_path`; the JSON `type` is `authorized_user` |
| GCS | `GOOGLE_APPLICATION_CREDENTIALS` path selection | Host bridge | The host expands the environment variable into `file_path`; the plugin does not read it. |
| GCS | Metadata server, workload identity, service-account impersonation | No representable token bridge | These flows produce bearer/provider state that the GCS bundle cannot accept. Use a supported JSON credential or a native client instead. |
| Azure | Shared Key or SAS | Yes | `account_key` or `sas_token` |
| Azure | Entra service principal | Yes | `tenant_id`, `client_id`, and `client_secret` |
| Azure | Federated workload-identity token file | Yes | `tenant_id`, `client_id`, and `federated_token_file` |
| Azure | Managed Identity / IMDS | No representable token bridge | Managed Identity produces a bearer credential; the Azure bundle has no bearer-token input. |
| Azure | Azure CLI, VS Code, or PowerShell identity | No representable token bridge | These cached identities are not consumed by the plugin. Use an explicit supported credential shape or a native client. |
| HTTP | Bearer token | Yes | `bearer_token`, sent as `Authorization: Bearer` (RFC 6750). Requires `https://` unless the host is loopback; scoped to `root_url`'s origin. |
| HTTP | Username and password | Yes | `username` + `password`, sent as `Authorization: Basic` (RFC 7617). Both required together. |
| HTTP | Userinfo in `root_url` | Discouraged | `https://user:pass@host/` authenticates, but the credential is not published in the caller-facing address, and it cannot be combined with the fields above. Prefer `username`/`password`. |
| HTTP | Custom header, mTLS, OAuth | Not implemented | The schema and method lists are additive, so these can be added without an ABI change; none is implemented. |

“Host bridge” means the application deliberately invokes its native SDK or
credential helper before constructing the ovstorage connection. It does not
mean copying a long-lived secret to disk. For S3, every ambient chain resolves
to the same temporary three-field credential shape the plugin already accepts.
GCS workload identity and Azure Managed Identity resolve to bearer/provider
objects that have no equivalent input field; serializing them into an
invented bundle field does not work.

The `http` plugin has no ambient chain at all: its credential fields carry no
environment-variable default, because no convention exists for “the token for
arbitrary HTTP origin X” and the plugin can be routed at any host. Resolve the
token in the host process and pass it as `bearer_token`.

## S3 host-bridge recipe

Resolve the desired AWS chain in the host process, then copy the resolved
temporary credential into the connection request:

```python
def add_resolved_aws_credentials(
    request: ovstorage.ConnectionRequest,
    *,
    access_key_id: str,
    secret_access_key: str,
    session_token: str | None,
) -> None:
    request.add_credential(
        "aws_access_key_id",
        ovstorage.SecretValue.bytes(access_key_id.encode()),
    )
    request.add_credential(
        "aws_secret_access_key",
        ovstorage.SecretValue.bytes(secret_access_key.encode()),
    )
    if session_token is not None:
        request.add_credential(
            "aws_session_token",
            ovstorage.SecretValue.bytes(session_token.encode()),
        )
```

The values may come from an AWS SDK default-chain resolver, an AWS CLI
credential export, or an organization-specific helper. Refresh the connection
credentials before the temporary session expires. Keep `persist = false` for
ephemeral credentials unless the host's persistence policy explicitly permits
them.

## GCS host integration

The plugin accepts only `service_account` and `authorized_user` JSON:

```python
request.add_credential(
    "file_path",
    ovstorage.SecretValue.bytes(
        os.environ["GOOGLE_APPLICATION_CREDENTIALS"].encode()
    ),
)
```

This recipe maps an environment-selected supported JSON file into the declared
bundle field. It does not make `external_account` workload-identity or
`impersonated_service_account` JSON supported. Hosts using those native ADC
flows keep the native client on that path: the credential pipeline does not
carry refreshable provider-backed credentials.

## Azure host integration

The host may map explicit environment values into the declared service-principal
or federated-token-file fields:

```python
for key, env_name in {
    "tenant_id": "AZURE_TENANT_ID",
    "client_id": "AZURE_CLIENT_ID",
    "federated_token_file": "AZURE_FEDERATED_TOKEN_FILE",
}.items():
    request.add_credential(
        key,
        ovstorage.SecretValue.bytes(os.environ[env_name].encode()),
    )
```

The federated-token-file flow is the supported workload-identity path. Managed
Identity and cached developer logins expose bearer/provider objects instead of
this field set, so the plugin cannot consume them through
`SecretBundle`.

## Security requirements for host bridges

- Resolve ambient credentials only when connection policy selects that
  provider; do not let ambient state override explicit bundle fields.
- Keep temporary credentials in `SecretValue` so debug and error surfaces
  preserve redaction.
- Do not persist provider-derived session material unless host policy permits
  it and the expiry is preserved.
- Distinguish “provider unavailable” from “credential rejected” in host
  diagnostics without logging token or key material.

See the per-plugin pages for exact resolution order and error behavior:
[S3](plugin-s3.md), [GCS](plugin-gcs.md), and [Azure](plugin-azure.md).
