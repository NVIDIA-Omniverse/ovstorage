**A connection now reports the layer that owns it.** `Connection` carries
`owning_target`, the target half of the key a connection op addresses, so
`list-connections` names the owning layer for a connection that publishes no
address — one parked or refused, which previously left that column blank — and
`disconnect` and `reauth` address that layer directly instead of discovering it
by attempting the operation against each candidate in turn. A row a loaded
plugin leaves unattributed still falls back to the previous behaviour. The
Python `Connection` type exposes the field too, as do the C
`OvStorage_Connection` struct and the C++ `Connection` wrapper.

This raises the storage plugin ABI to 16, so a prebuilt plugin compiled against
the previous ABI must be rebuilt. **A stale plugin is skipped rather than
reported.** Loading one directly fails with `IncompatibleType`, but the
directory scan every first-party host uses classifies an ABI mismatch as
skippable and continues, logging at debug — so the symptom is that the plugin's
backend kind is silently absent, and the first config referencing it fails with
`unknown layer kind`. Rebuild every plugin in the directory alongside the host,
and check the kinds you expect are present after an upgrade.
