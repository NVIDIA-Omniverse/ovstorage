**A new `hub_cache` wrapper layer caches object bytes in a local Omniverse
Hub (usd-workstation-cache), as an experimental feature.** The layer speaks
the hub's cache-aside protocol directly: reads probe the object's current
validator, serve hub hits from the hub's local file pool under live leases,
and fill the hub on a miss while the body streams to the caller unchanged;
`materialize` answers with the hub's own file, which is how backends that
stream bytes but stage no local file gain one. Entries are keyed by strong
validators only, digest-keyed entries are proven byte-for-byte on both fill
and hit, and every hub failure degrades to the wrapped layer. Two key
schemes are offered: `ovstorage` (the default, namespaced per partition)
and `omni-client-compat`, which shares cache entries with omni.client on
the same workstation. In support of the compat scheme, the direct HTTP
backend now surfaces a `Content-MD5` response header as the object's raw
md5 checksum.

Experimental means the configuration keys and observable behavior may
change between releases; the kind descriptor carries the same declaration,
so listing surfaces (CLI, REST, Python) show it without consulting the
documentation.
