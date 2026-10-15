// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The scheme-fallback contract between a backend layer, the shared route
//! table, and the hosts that grant an anonymous fallback.
//!
//! An address such as `s3://bucket/key` that no configured connection serves
//! has nowhere to go: the longest-prefix route scan misses and the caller sees
//! `NoRoute`. A **scheme fallback root** is the opt-in answer. A backend layer
//! whose operator granted `anonymous_fallback = ["s3"]` publishes one extra
//! [`RootInfo`] whose address is the bare scheme (`s3:///`), whose
//! `user_metadata` carries [`SCHEME_FALLBACK_METADATA_KEY`] valued
//! [`SCHEME_FALLBACK_ANONYMOUS`], and whose capabilities are read-only. The
//! root says: *an address on this scheme that nothing else routes may be
//! attempted here, anonymously.* Anonymously is the whole of the promise —
//! the backend builds the client with no credential source at all, so the
//! process's ambient identity can never be spent on an address the operator
//! did not configure.
//!
//! # The two-tier route-table contract
//!
//! A scheme root cannot be a catch-all through ordinary prefix matching: the
//! prefix relation requires scheme, host and port equality, and `s3:///` has
//! no host to equal `bucket`. The route table therefore looks up in two
//! tiers:
//!
//! 1. the longest-prefix scan over every root; and
//! 2. only on a miss, and only for an address whose query carries no
//!    credential — [`generated_rule_may_answer`](crate::generated_rule_may_answer)
//!    is the gate, because an S3 presigned or Azure SAS URL authenticates
//!    itself and an anonymous attempt would silently discard the authority the
//!    caller presented — the marked scheme root registered for `url.scheme()`.
//!
//! A tier-2 hit is not a prefix hit: `relative_suffix(url, root)` is `None`,
//! because the address is not under the root in the prefix sense. A consumer
//! that computes a suffix after a lookup must not do so for a scheme root; the
//! backend derives the bucket, account or container from the address itself.
//!
//! # What is, and is not, a fallback root
//!
//! [`is_scheme_fallback_root`] is both marker-based and structural: the exact
//! key and value, a path of `/`, no query, and either a hostless authority or
//! the reserved placeholder host [`SCHEME_FALLBACK_PLACEHOLDER_HOST`]. The
//! placeholder exists because the `url` crate refuses an empty host on its
//! special schemes (`http`, `https`), so those schemes spell their root
//! through a name under the `.invalid` TLD, which RFC 6761 guarantees never
//! resolves. Both halves of the predicate are load-bearing:
//!
//! - A hostless root **without** the marker is not a catch-all. `file:///` and
//!   `mem:///` are ordinary roots whose prefix relation already answers every
//!   address under them, and the table treats them byte-for-byte as it always
//!   has.
//! - A marked root that names a bucket (`s3://bucket/`) is not a fallback
//!   either: it serves its prefix through tier 1 like any other root, and the
//!   marker on it is inert.
//!
//! # Why the marker rides `user_metadata`
//!
//! `RootInfo.user_metadata` crosses the plugin ABI and the broker wire as-is,
//! so a foreign plugin, a loaded composite, and a brokered client all see the
//! same marker without a new field anywhere. `RouteSource` is a `repr(C)` tag
//! on the ABI and is re-labelled `BrokerDelivered` on the wire, so a new
//! variant there would need an ABI revision and a protocol change, and would
//! still be lost at the broker boundary. A reserved metadata key needs
//! neither.

use std::collections::BTreeSet;

use serde::Deserialize;

use crate::{
    AddressVisibility, Capabilities, ChangeKindSet, ConfigLayer, ConfigValue, Error, ErrorCode,
    LayerConfig, RangeReadStrategy, Result, RootInfo, RouteSource, Url, UserMetadata, canonicalize,
};

/// Layer-config key carrying the operator's grant: a TOML array of the
/// schemes this layer may serve anonymously when no connection routes an
/// address. Absent or empty means off, which is the default everywhere.
pub const ANONYMOUS_FALLBACK_KEY: &str = "anonymous_fallback";

/// Prefix of every layer-config key that tunes the fallback rather than a
/// connection (`anonymous_fallback_region`, `anonymous_fallback_endpoint`, …).
/// [`split_anonymous_fallback_keys`] uses it to keep these keys away from the
/// static-connection seed, which treats any other non-empty layer table as a
/// connection to instantiate.
pub const ANONYMOUS_FALLBACK_KEY_PREFIX: &str = "anonymous_fallback_";

/// The closed set of schemes a grant may name. Closed rather than open so a
/// typo (`"S3"`, `"gcs"`) is refused at config load instead of silently
/// granting nothing, and so a scheme nobody has reasoned about cannot be
/// switched on by spelling it.
pub const ANONYMOUS_FALLBACK_SCHEMES: &[&str] = &["s3", "gs", "azure", "http", "https"];

/// The subset of [`ANONYMOUS_FALLBACK_SCHEMES`] a backend layer serves in this
/// release. `http` and `https` are in the closed set so their switch exists
/// and parses, and outside this set so a host refuses to grant them until the
/// per-origin tier that would honour the grant exists.
pub const ANONYMOUS_FALLBACK_AVAILABLE_SCHEMES: &[&str] = &["s3", "gs", "azure"];

/// Which backend kind owns which schemes, for a host that stamps a top-level
/// grant onto the layer of the owning kind. One table, so the host and the
/// backends cannot disagree about who serves `gs`.
pub const ANONYMOUS_FALLBACK_KINDS: &[(&str, &[&str])] = &[
    ("s3", &["s3"]),
    ("gcs", &["gs"]),
    ("azure", &["azure"]),
    ("http", &["http", "https"]),
];

/// Reserved `RootInfo.user_metadata` key marking a scheme fallback root. Read
/// by the route table's second tier and by a brokered client deciding whether
/// to honour a wire-delivered root; a presentation patch may not set it.
pub const SCHEME_FALLBACK_METADATA_KEY: &str = "org.omniverse.ovstorage/scheme-fallback";

/// The one value [`SCHEME_FALLBACK_METADATA_KEY`] takes. Matched exactly: a
/// root marked with any other value is not a fallback root, so a future
/// flavour of fallback cannot be mistaken for the anonymous one by code that
/// predates it.
pub const SCHEME_FALLBACK_ANONYMOUS: &str = "anonymous";

/// Host a scheme fallback root uses when the scheme cannot be spelled hostless.
/// The `url` crate refuses an empty host on `http` and `https`, so their root
/// is `http://anonymous-fallback.invalid/`. RFC 6761 reserves `.invalid` to
/// never resolve, so no request can ever be sent to this name by mistake.
pub const SCHEME_FALLBACK_PLACEHOLDER_HOST: &str = "anonymous-fallback.invalid";

/// The schemes the backend kind `kind` serves through a fallback, per
/// [`ANONYMOUS_FALLBACK_KINDS`]; empty for a kind that owns no tier.
pub fn schemes_for_kind(kind: &str) -> &'static [&'static str] {
    ANONYMOUS_FALLBACK_KINDS
        .iter()
        .find(|(owner, _)| *owner == kind)
        .map_or(&[], |(_, schemes)| schemes)
}

/// Whether `key` is a layer-config key that belongs to the fallback policy
/// rather than to a connection: [`ANONYMOUS_FALLBACK_KEY`] itself or anything
/// under [`ANONYMOUS_FALLBACK_KEY_PREFIX`]. A backend refuses a connection
/// request that carries one, because a fallback key on a connection would be
/// silently ignored otherwise and the operator would believe it took effect.
pub fn is_anonymous_fallback_key(key: &str) -> bool {
    key == ANONYMOUS_FALLBACK_KEY || key.starts_with(ANONYMOUS_FALLBACK_KEY_PREFIX)
}

/// The wrapper shape the host produces for an array-valued layer key: the
/// array reserialized under its own key, so the TOML text for
/// `anonymous_fallback = ["s3"]` is literally that line.
#[derive(Deserialize)]
struct AnonymousFallbackGrant {
    anonymous_fallback: Vec<String>,
}

/// Decode the operator's grant from a layer table.
///
/// An absent key is the empty grant: off. A present key must be the host's
/// `ConfigValue::Toml` wrapper around an array of scheme strings, each in
/// [`ANONYMOUS_FALLBACK_SCHEMES`]; duplicates collapse. The shape is
/// deliberately strict — a bare string `"s3"` is refused rather than read as
/// a one-element array — because a grant is a security decision and a lenient
/// reading would let a mis-typed key grant something the operator did not
/// write.
///
/// # Errors
///
/// - [`ErrorCode::InvalidArgument`] — the value is not a TOML array of
///   strings, or names a scheme outside the closed set.
pub fn decode_anonymous_fallback(config: &LayerConfig) -> Result<BTreeSet<String>> {
    let Some(value) = config.get(ANONYMOUS_FALLBACK_KEY) else {
        return Ok(BTreeSet::new());
    };
    let shape_error = || {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("`{ANONYMOUS_FALLBACK_KEY}` must be a TOML array of scheme strings"),
        )
    };
    let ConfigValue::Toml(text) = value else {
        return Err(shape_error());
    };
    let grant: AnonymousFallbackGrant = toml::from_str(text).map_err(|_| shape_error())?;
    let mut schemes = BTreeSet::new();
    for scheme in grant.anonymous_fallback {
        if !ANONYMOUS_FALLBACK_SCHEMES.contains(&scheme.as_str()) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "`{ANONYMOUS_FALLBACK_KEY}` names `{scheme}`, which is not a fallback \
                     scheme; the accepted schemes are {}",
                    ANONYMOUS_FALLBACK_SCHEMES.join(", ")
                ),
            ));
        }
        schemes.insert(scheme);
    }
    Ok(schemes)
}

/// Split a layer table into `(policy, connection)`: every fallback key
/// ([`is_anonymous_fallback_key`]) on one side, everything else on the other.
///
/// The backend factories treat any non-empty layer table as a static
/// connection to seed, so a layer carrying only `anonymous_fallback = ["s3"]`
/// would otherwise be read as a connection with no bucket and fail at
/// startup. Splitting first keeps the seed check honest: it sees only the
/// keys that describe a connection.
pub fn split_anonymous_fallback_keys(config: &LayerConfig) -> (LayerConfig, LayerConfig) {
    let mut policy = LayerConfig::new();
    let mut connection = LayerConfig::new();
    for (key, value) in config {
        if is_anonymous_fallback_key(key) {
            policy.insert(key.clone(), value.clone());
        } else {
            connection.insert(key.clone(), value.clone());
        }
    }
    (policy, connection)
}

/// The root address of the fallback for `scheme`: the bare scheme when the
/// `url` crate accepts an empty authority (`s3:///`), the placeholder host
/// when it does not (`http://anonymous-fallback.invalid/`).
fn scheme_fallback_root_url(scheme: &str) -> Result<Url> {
    if !ANONYMOUS_FALLBACK_SCHEMES.contains(&scheme) {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "`{scheme}` is not a fallback scheme; the accepted schemes are {}",
                ANONYMOUS_FALLBACK_SCHEMES.join(", ")
            ),
        ));
    }
    // A non-special scheme parses with an empty host and an empty path, and
    // `canonicalize` gives the empty path its `/`. A special scheme refuses
    // the empty host outright, which is what selects the placeholder.
    if let Ok(hostless) = Url::parse(&format!("{scheme}://")) {
        return Ok(canonicalize(hostless));
    }
    Url::parse(&format!("{scheme}://{SCHEME_FALLBACK_PLACEHOLDER_HOST}/"))
        .map(canonicalize)
        .map_err(|error| {
            Error::new(
                ErrorCode::Internal,
                format!("the {scheme}:// fallback root does not parse: {error}"),
            )
        })
}

/// Build the hidden, read-only, marked [`RootInfo`] a backend layer of kind
/// `layer_kind` publishes for its `scheme` fallback.
///
/// The root is `Hidden` and `visible: false` because it is a routing fact,
/// not a place a user browses to; it has no `connection_id` and no
/// `owning_target` because no connection exists — mirroring the sibling roots
/// a connection publishes, which also leave `owning_target` unset. Its source
/// is `Static { Programmatic }`: the operator's grant is layer config, not a
/// connection anyone added. `capabilities` are lowered through
/// [`read_only_capabilities`] whatever the caller passes, so a fallback root
/// can never advertise a mutation; the caller adds nothing but read-side
/// bits on top (`supports_list_stream`, say). `range_read_strategy` is left
/// at its default here because the constructor does not know the backend: a
/// caller whose connection roots advertise `Native` ranged reads sets the
/// same on the returned root, so `root_info_for` answers the same strategy
/// for a fallback-served address as for a configured one on the same store.
///
/// # Errors
///
/// - [`ErrorCode::InvalidArgument`] — `scheme` is outside
///   [`ANONYMOUS_FALLBACK_SCHEMES`].
pub fn scheme_fallback_root(
    scheme: &str,
    layer_kind: &str,
    capabilities: Capabilities,
    icon: Option<Vec<u8>>,
) -> Result<RootInfo> {
    let root = scheme_fallback_root_url(scheme)?;
    let mut user_metadata = UserMetadata::new();
    user_metadata.insert(
        SCHEME_FALLBACK_METADATA_KEY.to_string(),
        SCHEME_FALLBACK_ANONYMOUS.to_string(),
    );
    Ok(RootInfo {
        root,
        display_name: Some(format!("anonymous {scheme}:// fallback")),
        layer_kind: layer_kind.to_string(),
        connection_id: None,
        owning_target: None,
        capabilities: read_only_capabilities(capabilities),
        range_read_strategy: RangeReadStrategy::default(),
        source: RouteSource::Static {
            layer: ConfigLayer::Programmatic,
        },
        visible: false,
        visibility: AddressVisibility::Hidden,
        alias_state: None,
        icon,
        user_metadata,
    })
}

/// Whether `root` is a scheme fallback root: marked with the exact key and
/// value, and shaped like one — path `/`, no query, and a hostless authority
/// or the reserved placeholder host.
///
/// Both tests are required. Without the structural half a marked bucket root
/// (`s3://bucket/`) would become a catch-all for every bucket; without the
/// marker every hostless root (`file:///`, `mem:///`) would become one, and
/// those are ordinary prefix roots that must keep behaving as such.
pub fn is_scheme_fallback_root(root: &RootInfo) -> bool {
    let marked = root
        .user_metadata
        .get(SCHEME_FALLBACK_METADATA_KEY)
        .is_some_and(|value| value == SCHEME_FALLBACK_ANONYMOUS);
    if !marked {
        return false;
    }
    let url = &root.root;
    // `s3:///` reports its host as `None`; the empty-string spelling is
    // accepted too so the predicate does not hinge on which of the two a
    // `url` release chooses for an empty authority.
    let hostless_or_placeholder = match url.host_str() {
        None | Some("") => true,
        Some(host) => host == SCHEME_FALLBACK_PLACEHOLDER_HOST,
    };
    hostless_or_placeholder && url.path() == "/" && url.query().is_none()
}

/// Lower a capability set to what an anonymous, read-only fallback may
/// advertise.
///
/// Every mutation bit is cleared — write, delete, copy, rename, directory
/// mutation, metadata patch — along with watch, whose subscription is a
/// standing server-side registration the fallback has no identity to hold.
/// The read side survives untouched: list, stat, versions, access check, and
/// the shape facts (`has_real_directories`, `populates_*`) that describe what
/// a read returns. Destructured field by field, with no `..`, so a new
/// capability bit fails to compile here until someone decides which side it
/// belongs on; defaulting a new bit to "kept" would be the wrong direction
/// for a surface whose promise is that it cannot change anything.
pub fn read_only_capabilities(caps: Capabilities) -> Capabilities {
    let Capabilities {
        supports_if_match_write: _,
        supports_no_overwrite_write: _,
        supports_native_metadata_patch: _,
        supports_metadata_rewrite_emulation: _,
        writes_are_atomic: _,
        supports_copy: _,
        supports_rename: _,
        supports_server_side_copy: _,
        supports_server_side_rename: _,
        supports_atomic_rename: _,
        has_real_directories,
        supports_write: _,
        supports_write_stream: _,
        supports_write_redirect: _,
        supports_delete: _,
        supports_list,
        supports_list_stream,
        wants_list_backed_stat,
        supports_recursive_list,
        populates_subdirectory_metadata,
        supports_create_directory: _,
        supports_delete_directory: _,
        supports_version_listing,
        version_list_order,
        populates_effective_permissions_on_stat,
        supports_access_check,
        supports_watch_directory: _,
        watch_directory_kinds: _,
        watch_directory_resumable: _,
        watch_directory_max_lag: _,
        redirect_size_threshold: _,
    } = caps;
    Capabilities {
        supports_if_match_write: false,
        supports_no_overwrite_write: false,
        supports_native_metadata_patch: false,
        supports_metadata_rewrite_emulation: false,
        writes_are_atomic: false,
        supports_copy: false,
        supports_rename: false,
        supports_server_side_copy: false,
        supports_server_side_rename: false,
        supports_atomic_rename: false,
        has_real_directories,
        supports_write: false,
        supports_write_stream: false,
        supports_write_redirect: false,
        supports_delete: false,
        supports_list,
        supports_list_stream,
        wants_list_backed_stat,
        supports_recursive_list,
        populates_subdirectory_metadata,
        supports_create_directory: false,
        supports_delete_directory: false,
        supports_version_listing,
        version_list_order,
        populates_effective_permissions_on_stat,
        supports_access_check,
        supports_watch_directory: false,
        watch_directory_kinds: ChangeKindSet::empty(),
        watch_directory_resumable: false,
        watch_directory_max_lag: None,
        redirect_size_threshold: None,
    }
}

/// The refusal a backend returns for a mutating operation on an address it
/// reaches through the `scheme` fallback. `root` is the node root the
/// backend derived for the address (`s3://bucket/`,
/// `azure://account/container/`), which is what the operator would configure
/// a connection for; it is never the caller's full address, whose path and
/// query are not the backend's to print.
pub fn fallback_mutation_refused(scheme: &str, root: &Url) -> Error {
    Error::new(
        ErrorCode::Unsupported,
        format!(
            "this address is reached through the anonymous {scheme}:// fallback, which is read-only"
        ),
    )
    .with_next_action(format!(
        "add a connection for {root} with credentials to modify it"
    ))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::VersionListOrder;

    fn wrapped(text: &str) -> LayerConfig {
        LayerConfig::from([(
            ANONYMOUS_FALLBACK_KEY.to_string(),
            ConfigValue::Toml(text.to_string()),
        )])
    }

    fn root_for(scheme: &str) -> RootInfo {
        scheme_fallback_root(scheme, "kind", Capabilities::empty(), None).unwrap()
    }

    fn every_bit_set() -> Capabilities {
        Capabilities {
            supports_if_match_write: true,
            supports_no_overwrite_write: true,
            supports_native_metadata_patch: true,
            supports_metadata_rewrite_emulation: true,
            writes_are_atomic: true,
            supports_copy: true,
            supports_rename: true,
            supports_server_side_copy: true,
            supports_server_side_rename: true,
            supports_atomic_rename: true,
            has_real_directories: true,
            supports_write: true,
            supports_write_stream: true,
            supports_write_redirect: true,
            supports_delete: true,
            supports_list: true,
            supports_list_stream: true,
            wants_list_backed_stat: true,
            supports_recursive_list: true,
            populates_subdirectory_metadata: true,
            supports_create_directory: true,
            supports_delete_directory: true,
            supports_version_listing: true,
            version_list_order: Some(VersionListOrder::Newest),
            populates_effective_permissions_on_stat: true,
            supports_access_check: true,
            supports_watch_directory: true,
            watch_directory_kinds: ChangeKindSet {
                created: true,
                modified: true,
                deleted: true,
                metadata_changed: true,
            },
            watch_directory_resumable: true,
            watch_directory_max_lag: Some(Duration::from_secs(5)),
            redirect_size_threshold: Some(1 << 20),
        }
    }

    #[test]
    fn an_absent_key_decodes_to_the_empty_set() {
        let config = LayerConfig::from([(
            "region".to_string(),
            ConfigValue::String("us-east-1".to_string()),
        )]);
        assert!(decode_anonymous_fallback(&config).unwrap().is_empty());
        assert!(
            decode_anonymous_fallback(&LayerConfig::new())
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn a_wrapped_array_decodes() {
        let grant =
            decode_anonymous_fallback(&wrapped("anonymous_fallback = [\"s3\", \"gs\"]\n")).unwrap();
        assert_eq!(
            grant,
            BTreeSet::from(["s3".to_string(), "gs".to_string()]),
            "the wrapper the host writes decodes to the set it spells"
        );

        // An empty array is the explicit off switch.
        assert!(
            decode_anonymous_fallback(&wrapped("anonymous_fallback = []\n"))
                .unwrap()
                .is_empty()
        );

        // Duplicates collapse rather than refuse: a repeated scheme is not a
        // different decision.
        let grant =
            decode_anonymous_fallback(&wrapped("anonymous_fallback = [\"s3\", \"s3\"]\n")).unwrap();
        assert_eq!(grant, BTreeSet::from(["s3".to_string()]));
    }

    /// The set is closed so a scheme nobody has reasoned about cannot be
    /// switched on by spelling it, and so `file` stays off until its own tier
    /// exists.
    #[test]
    fn a_scheme_outside_the_closed_set_is_refused() {
        for text in [
            "anonymous_fallback = [\"ftp\"]\n",
            "anonymous_fallback = [\"file\"]\n",
            "anonymous_fallback = [\"s3\", \"S3\"]\n",
            "anonymous_fallback = [\"gcs\"]\n",
        ] {
            let error = decode_anonymous_fallback(&wrapped(text)).unwrap_err();
            assert_eq!(error.code(), ErrorCode::InvalidArgument, "{text}");
            assert!(
                error
                    .message()
                    .contains("accepted schemes are s3, gs, azure, http, https"),
                "the refusal names the closed set: {}",
                error.message()
            );
        }
    }

    /// A grant is a security decision; a lenient reading of a mis-typed value
    /// would grant something the operator did not write.
    #[test]
    fn a_non_array_value_is_refused() {
        let cases: [(&str, ConfigValue); 5] = [
            ("bool", ConfigValue::Bool(true)),
            ("string", ConfigValue::String("s3".to_string())),
            ("int", ConfigValue::Int(1)),
            (
                "scalar under the key",
                ConfigValue::Toml("anonymous_fallback = \"s3\"\n".to_string()),
            ),
            (
                "array of non-strings",
                ConfigValue::Toml("anonymous_fallback = [1, 2]\n".to_string()),
            ),
        ];
        for (label, value) in cases {
            let config = LayerConfig::from([(ANONYMOUS_FALLBACK_KEY.to_string(), value)]);
            let error = decode_anonymous_fallback(&config).unwrap_err();
            assert_eq!(error.code(), ErrorCode::InvalidArgument, "{label}");
            assert_eq!(
                error.message(),
                "`anonymous_fallback` must be a TOML array of scheme strings",
                "{label}"
            );
        }
    }

    #[test]
    fn split_keys_separates_policy_from_connection_config() {
        let config = LayerConfig::from([
            (
                "anonymous_fallback".to_string(),
                ConfigValue::Toml("anonymous_fallback = [\"s3\"]\n".to_string()),
            ),
            (
                "anonymous_fallback_region".to_string(),
                ConfigValue::String("us-east-1".to_string()),
            ),
            (
                "anonymous_fallback_endpoint".to_string(),
                ConfigValue::String("http://minio:9000".to_string()),
            ),
            ("bucket".to_string(), ConfigValue::String("b".to_string())),
            (
                "region".to_string(),
                ConfigValue::String("eu-west-1".to_string()),
            ),
            // A key that merely resembles the prefix is connection config.
            ("anonymous".to_string(), ConfigValue::Bool(true)),
            ("anonymous_fallbacks".to_string(), ConfigValue::Bool(true)),
        ]);
        let (policy, connection) = split_anonymous_fallback_keys(&config);

        let mut policy_keys: Vec<&str> = policy.keys().map(String::as_str).collect();
        policy_keys.sort_unstable();
        assert_eq!(
            policy_keys,
            [
                "anonymous_fallback",
                "anonymous_fallback_endpoint",
                "anonymous_fallback_region"
            ]
        );

        let mut connection_keys: Vec<&str> = connection.keys().map(String::as_str).collect();
        connection_keys.sort_unstable();
        assert_eq!(
            connection_keys,
            ["anonymous", "anonymous_fallbacks", "bucket", "region"]
        );

        // Nothing is lost or duplicated in the split.
        assert_eq!(policy.len() + connection.len(), config.len());
        for (key, value) in &config {
            let kept = policy.get(key).or_else(|| connection.get(key));
            assert_eq!(kept, Some(value), "{key}");
        }
    }

    #[test]
    fn a_scheme_root_is_hidden_unlisted_marked_and_structural() {
        for (scheme, expected_root, expected_host) in [
            ("s3", "s3:///", None),
            ("gs", "gs:///", None),
            ("azure", "azure:///", None),
            (
                "http",
                "http://anonymous-fallback.invalid/",
                Some(SCHEME_FALLBACK_PLACEHOLDER_HOST),
            ),
            (
                "https",
                "https://anonymous-fallback.invalid/",
                Some(SCHEME_FALLBACK_PLACEHOLDER_HOST),
            ),
        ] {
            let root =
                scheme_fallback_root(scheme, "kind", every_bit_set(), Some(vec![1, 2])).unwrap();
            assert_eq!(root.root.as_str(), expected_root, "{scheme}");
            assert_eq!(root.root.scheme(), scheme);
            assert_eq!(root.root.host_str(), expected_host, "{scheme}");
            assert_eq!(root.root.path(), "/");
            assert_eq!(root.root.query(), None);
            assert_eq!(
                root.display_name.as_deref(),
                Some(format!("anonymous {scheme}:// fallback").as_str())
            );
            assert_eq!(root.layer_kind, "kind");
            assert_eq!(root.connection_id, None);
            assert_eq!(root.owning_target, None);
            assert_eq!(
                root.source,
                RouteSource::Static {
                    layer: ConfigLayer::Programmatic
                }
            );
            assert!(
                !root.visible,
                "{scheme}: a routing fact, not a browsable place"
            );
            assert_eq!(root.visibility, AddressVisibility::Hidden);
            assert_eq!(root.alias_state, None);
            assert_eq!(root.icon, Some(vec![1, 2]));
            assert_eq!(
                root.user_metadata
                    .get(SCHEME_FALLBACK_METADATA_KEY)
                    .map(String::as_str),
                Some(SCHEME_FALLBACK_ANONYMOUS)
            );
            assert_eq!(
                root.user_metadata.len(),
                1,
                "the marker is the only metadata"
            );
            assert_eq!(
                root.capabilities,
                read_only_capabilities(every_bit_set()),
                "{scheme}: the root cannot advertise a mutation whatever it is handed"
            );
            assert!(is_scheme_fallback_root(&root), "{scheme}");
        }
    }

    #[test]
    fn a_scheme_outside_the_closed_set_has_no_root() {
        for scheme in ["ftp", "file", "mem", "S3"] {
            let error =
                scheme_fallback_root(scheme, "kind", Capabilities::empty(), None).unwrap_err();
            assert_eq!(error.code(), ErrorCode::InvalidArgument, "{scheme}");
        }
    }

    /// The structural half of the predicate: a marked root that names a
    /// bucket serves its prefix through the ordinary tier and is never a
    /// catch-all for every bucket on the scheme.
    #[test]
    fn a_marked_bucket_root_is_not_a_scheme_fallback() {
        for spelling in [
            "s3://bucket/",
            "gs://bucket/",
            "azure://account/container/",
            "http://anonymous-fallback.invalid/prefix/",
            "s3:///?versionId=1",
        ] {
            let mut root = root_for("s3");
            root.root = Url::parse(spelling).unwrap();
            assert!(!is_scheme_fallback_root(&root), "{spelling}");
        }

        // A marker with a different value is not the anonymous marker.
        let mut root = root_for("s3");
        root.user_metadata.insert(
            SCHEME_FALLBACK_METADATA_KEY.to_string(),
            "Anonymous".to_string(),
        );
        assert!(!is_scheme_fallback_root(&root));
    }

    /// The marker half of the predicate: a hostless root without the marker
    /// is an ordinary prefix root and must keep behaving as one.
    #[test]
    fn an_unmarked_hostless_root_is_not_a_scheme_fallback() {
        for spelling in ["file:///", "mem:///", "s3:///", "my:///"] {
            let mut root = root_for("s3");
            root.root = canonicalize(Url::parse(spelling).unwrap());
            root.user_metadata.clear();
            assert!(!is_scheme_fallback_root(&root), "{spelling}");

            // An unrelated reserved key on a hostless root is still not the marker.
            root.user_metadata.insert(
                "org.omniverse.ovstorage/something-else".to_string(),
                SCHEME_FALLBACK_ANONYMOUS.to_string(),
            );
            assert!(!is_scheme_fallback_root(&root), "{spelling}");
        }
    }

    #[test]
    fn read_only_capabilities_clears_every_mutation_bit_and_keeps_the_read_side() {
        let lowered = read_only_capabilities(every_bit_set());

        // Cleared: everything that changes or watches state.
        assert!(!lowered.supports_if_match_write);
        assert!(!lowered.supports_no_overwrite_write);
        assert!(!lowered.supports_native_metadata_patch);
        assert!(!lowered.supports_metadata_rewrite_emulation);
        assert!(!lowered.writes_are_atomic);
        assert!(!lowered.supports_copy);
        assert!(!lowered.supports_rename);
        assert!(!lowered.supports_server_side_copy);
        assert!(!lowered.supports_server_side_rename);
        assert!(!lowered.supports_atomic_rename);
        assert!(!lowered.supports_write);
        assert!(!lowered.supports_write_stream);
        assert!(!lowered.supports_write_redirect);
        assert!(!lowered.supports_delete);
        assert!(!lowered.supports_create_directory);
        assert!(!lowered.supports_delete_directory);
        assert!(!lowered.supports_watch_directory);
        assert!(!lowered.watch_directory_resumable);
        assert_eq!(lowered.watch_directory_kinds, ChangeKindSet::empty());
        assert_eq!(lowered.watch_directory_max_lag, None);
        assert_eq!(lowered.redirect_size_threshold, None);

        // Kept: everything a read consults.
        assert!(lowered.has_real_directories);
        assert!(lowered.supports_list);
        assert!(lowered.supports_list_stream);
        assert!(lowered.wants_list_backed_stat);
        assert!(lowered.supports_recursive_list);
        assert!(lowered.populates_subdirectory_metadata);
        assert!(lowered.supports_version_listing);
        assert_eq!(lowered.version_list_order, Some(VersionListOrder::Newest));
        assert!(lowered.populates_effective_permissions_on_stat);
        assert!(lowered.supports_access_check);

        // Idempotent, and the floor stays the floor.
        assert_eq!(read_only_capabilities(lowered.clone()), lowered);
        assert_eq!(
            read_only_capabilities(Capabilities::empty()),
            Capabilities::empty()
        );
    }

    #[test]
    fn every_kind_in_the_table_maps_to_schemes_in_the_closed_set() {
        let mut seen = BTreeSet::new();
        for (kind, schemes) in ANONYMOUS_FALLBACK_KINDS {
            assert!(!schemes.is_empty(), "{kind} owns no scheme");
            for scheme in *schemes {
                assert!(
                    ANONYMOUS_FALLBACK_SCHEMES.contains(scheme),
                    "{kind} claims {scheme}, which is outside the closed set"
                );
                assert!(seen.insert(*scheme), "{scheme} is owned by two kinds");
            }
            assert_eq!(schemes_for_kind(kind), *schemes);
        }
        // Every scheme in the closed set has exactly one owner, so a host can
        // always find the layer to stamp.
        assert_eq!(
            seen,
            ANONYMOUS_FALLBACK_SCHEMES
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
        );
        for scheme in ANONYMOUS_FALLBACK_AVAILABLE_SCHEMES {
            assert!(ANONYMOUS_FALLBACK_SCHEMES.contains(scheme), "{scheme}");
        }
        assert_eq!(schemes_for_kind("nucleus"), &[] as &[&str]);
        assert_eq!(schemes_for_kind("gcs"), ["gs"]);
        assert_eq!(schemes_for_kind("http"), ["http", "https"]);
    }

    #[test]
    fn a_mutation_refusal_is_unsupported_and_names_the_node_root() {
        let root = Url::parse("azure://account/container/").unwrap();
        let error = fallback_mutation_refused("azure", &root);
        assert_eq!(error.code(), ErrorCode::Unsupported);
        assert_eq!(
            error.message(),
            "this address is reached through the anonymous azure:// fallback, which is read-only"
        );
        assert_eq!(
            error.next_action(),
            Some("add a connection for azure://account/container/ with credentials to modify it")
        );
    }

    #[test]
    fn fallback_key_recognition_is_exact_or_prefixed() {
        assert!(is_anonymous_fallback_key("anonymous_fallback"));
        assert!(is_anonymous_fallback_key("anonymous_fallback_region"));
        assert!(is_anonymous_fallback_key("anonymous_fallback_"));
        assert!(!is_anonymous_fallback_key("anonymous"));
        assert!(!is_anonymous_fallback_key("anonymous_fallbacks"));
        assert!(!is_anonymous_fallback_key("region"));
    }
}
