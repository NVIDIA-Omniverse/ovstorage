**Choosing "OIDC sign-in (browser / device flow)" in `connect` now opens the sign-in flow instead of demanding a token bundle.**

The new `token` method accepts a pre-issued or host-minted access token for a
direct `grpc://` or `grpcs://` endpoint. `connect` exposes only methods the
address mode can use and rejects an inapplicable explicit `--auth` value before
prompting. In non-interactive use, `--auth interactive` selects browser or
device sign-in, while `--auth token` prompts for the direct bearer. A saved
sign-in for the same service that is still valid is reused without a new flow;
`reauth <name>` re-runs sign-in explicitly, to log in again or as a different
account.
