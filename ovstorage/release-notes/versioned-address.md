**Object metadata carries the address that names the exact version it
describes.** `ObjectInfo.versioned_address` is the backend's own pin spelling
— `?versionId=` on S3, `?versionid=` on Azure, `?generation=` on GCS,
`?revision=<commit sha>` on Hugging Face, `?<branch>&<checkpoint>` on Nucleus,
and the Omniverse Storage Service's `VersionInfo.resource_address` verbatim —
projected into the caller's namespace like every other address. Rust callers
read `ObjectInfo::versioned_address`; C callers read
`OvStorage_Info.versioned_address`, `NULL` when absent; C++ callers use
`has_versioned_address()` and `versioned_address()` on `Info` and `InfoView`
and request it through the `stat` and `list` overloads that take the C options
struct by value; Python callers read `Info.versioned_address` and pass
`versioned_address=True` to `stat` and `list`; REST callers add
`versioned_address=true` to `objects:stat` and `objects:list` and read a field
that is omitted when absent; broker clients receive it forwarded untouched;
MCP callers pass `"versioned_address": true` to `ovstorage_stat` and
`ovstorage_list` and read a nullable field; and the CLI takes
`--versioned-address` on `stat` and `list`. `list_versions` and
`get_latest_version` fill it with the entry's own pinned address, directories
carry none, and the `file`, `http`, and OpenDAL backends answer none.

`StatOptions` and `ListOptions` gain a `versioned_address` flag with the same
meaning as `full_metadata`: a cost knob, not an inclusion list. Set it and a
versioning backend pays for the answer — an S3 listing switches to
`ListObjectVersions` and needs `s3:ListBucketVersions`, an Azure listing adds
`include=versions` or one properties call per blob, Hugging Face sends
`expand=true`, and the Omniverse Storage Service and Nucleus make their version
lookup per object; leave it clear and a backend still fills the field when it
is free, as S3 and Azure do on `stat` and GCS does everywhere. An absent field
under the flag means the backend does not version that object, and a stat of
an address that already carries an immutable pin echoes that pin whatever the
flag says. The address is a pin, not an identity or a capability: mutations
through it are refused with `InvalidArgument`, and retention and alias rules
decide how long it resolves.

The metadata cache keeps one row per address and records the cost flags the
row was fetched under. A request the row covers is served from it, so a
default `stat` may return the richer fields an earlier flagged call paid for;
a wider request goes upstream once with the union of the stored and requested
flags and replaces the row. `full_metadata = true` results are cached. The
cache API changes with it: `MetadataCacheKey::options_hash` and the
`hash_stat_options`, `hash_list_options` and `hash_list_versions_options`
helpers are removed, `MetadataCache::get` takes the requested `CostFlags` and
returns a `MetadataLookup`, and `MetadataCache::insert` takes the flags the
payload was fetched under.

Layer plugin ABI 18 identifies the etag-strength layout. The versioned address
uses ABI 19, an ABI break from ABI 18: `ObjectInfo` and `BackendItemInfo` grow
by a tail-appended optional string and have no `struct_size` prefix, the
options flags land in padding `StatOptions` and `ListOptions` already carry so
`struct_size` cannot see the change, and the exact-match check at load is the
only guard. Every out-of-tree ABI-18 plugin is refused at load and must be
rebuilt against the ABI-19 headers before it can load.
