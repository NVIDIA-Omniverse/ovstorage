// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Every address spelling this repository **publishes** must still load and
//! still route.
//!
//! This exists because of a defect shape that recurred six times on one branch:
//! a refusal written from an enumeration of hazards reaches a spelling the
//! parser normalizes on purpose, and the only thing standing between it and a
//! release is a reviewer noticing that some document publishes that spelling.
//! `file:/data/` was refused while `plugin-file.md` published it — and while the
//! worked example in the doc comment four lines above the refusal used it.
//!
//! **A question somebody must remember to ask is not a control.** So the
//! spellings are a corpus here, and a refusal that reaches one reddens a named
//! test instead. If a published spelling *should* be refused, the doc and the
//! corpus change in the same commit — which is the conversation this file
//! exists to force.
//!
//! What each row asserts is the ADDRESS layer's answer, not a backend's: the
//! `file` plugin serves no UNC share and will refuse `file://server/share/` on
//! its own authority rule, which is a different check at a different layer and
//! is not what a corpus of spellings can speak for. The end-to-end test at the
//! bottom closes that gap for the one backend a test can build without a
//! network: a real `file` root, spelled every way the docs publish, built into
//! a real Stack and read through.

use futures::StreamExt as _;
use ovstorage::address;
use ovstorage::host::build_stack;
use ovstorage::{
    Layer as _, ObjectKind, ReadOptions, ReadRequest, ReadResult, Request, StackConfig,
    StatOptions, StatRequest, Url,
};

/// Where a spelling is published. Doc sources are `include_str!`d so a moved
/// file breaks the build, and `every_row_appears_where_it_says_it_does` checks
/// the text is really there rather than trusting the label.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Source {
    Doc(&'static str),
    /// Published only as an assertion in the tree's own tests — no operator
    /// reads it, so there is nothing to check the text against.
    Tests,
}

/// What role the spelling is published in. A **configuration** address names a
/// scope an operator writes; a **request** address is what a caller sends, and
/// it may carry the query that pins a version, which no configuration address
/// may.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    Config,
    Request,
}

/// The address-layer rule a published-as-refused spelling must trip. Named
/// rather than "refused somehow", so a row cannot go on passing because a
/// different rule happened to catch it after the one it names was narrowed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Refused {
    /// `address::refused_config_component` — a query on a configuration
    /// address.
    Query,
    /// `address::refused_config_component` — a fragment.
    Fragment,
    /// `ovstorage_layer::parsing_preserves_authority` — parsing moves, creates
    /// or destroys the authority the spelling names.
    Authority,
    /// `ovstorage_layer::parsing_preserves_node` — parsing moves the address to
    /// a different node. This is the **returned**-address contract; a
    /// configuration address's path is normalized on purpose.
    Node,
}

struct Published {
    raw: &'static str,
    source: Source,
    role: Role,
    /// `None` when the spelling is published as one that works.
    refused: Option<Refused>,
}

/// A spelling published as one an operator or a caller may write.
const fn ok(raw: &'static str, source: Source, role: Role) -> Published {
    Published {
        raw,
        source,
        role,
        refused: None,
    }
}

/// A spelling published as one the address layer refuses, and by which rule.
const fn no(raw: &'static str, source: Source, role: Role, rule: Refused) -> Published {
    Published {
        raw,
        source,
        role,
        refused: Some(rule),
    }
}

const FILE_MD: &str = "docs/public/plugin-storage/plugin-file.md";
const HTTP_MD: &str = "docs/public/plugin-storage/plugin-http.md";
const S3_MD: &str = "docs/public/plugin-storage/plugin-s3.md";
const GCS_MD: &str = "docs/public/plugin-storage/plugin-gcs.md";
const OPENDAL_MD: &str = "docs/public/plugin-storage/plugin-opendal.md";
const CONFORMANCE_MD: &str = "docs/public/plugin-storage/CONFORMANCE.md";
const CONFIGURATION_MD: &str = "docs/public/configuration.md";
const BROKER_MD: &str = "docs/public/broker-operator/README.md";
const AGENT_MD: &str = "docs/public/agent/README.md";
const RUST_MD: &str = "docs/public/library-rust/README.md";
const CPP_MD: &str = "docs/public/library-cpp/README.md";
const PYTHON_MD: &str = "docs/public/library-python/README.md";
const PLUGIN_DEV_MD: &str = "docs/public/plugin-development/README.md";

/// The text of every document a row cites, bound at compile time.
const DOC_TEXT: &[(&str, &str)] = &[
    (
        FILE_MD,
        include_str!("../../../docs/public/plugin-storage/plugin-file.md"),
    ),
    (
        HTTP_MD,
        include_str!("../../../docs/public/plugin-storage/plugin-http.md"),
    ),
    (
        S3_MD,
        include_str!("../../../docs/public/plugin-storage/plugin-s3.md"),
    ),
    (
        GCS_MD,
        include_str!("../../../docs/public/plugin-storage/plugin-gcs.md"),
    ),
    (
        OPENDAL_MD,
        include_str!("../../../docs/public/plugin-storage/plugin-opendal.md"),
    ),
    (
        CONFORMANCE_MD,
        include_str!("../../../docs/public/plugin-storage/CONFORMANCE.md"),
    ),
    (
        CONFIGURATION_MD,
        include_str!("../../../docs/public/configuration.md"),
    ),
    (
        BROKER_MD,
        include_str!("../../../docs/public/broker-operator/README.md"),
    ),
    (
        AGENT_MD,
        include_str!("../../../docs/public/agent/README.md"),
    ),
    (
        RUST_MD,
        include_str!("../../../docs/public/library-rust/README.md"),
    ),
    (
        CPP_MD,
        include_str!("../../../docs/public/library-cpp/README.md"),
    ),
    (
        PYTHON_MD,
        include_str!("../../../docs/public/library-python/README.md"),
    ),
    (
        PLUGIN_DEV_MD,
        include_str!("../../../docs/public/plugin-development/README.md"),
    ),
];

/// The corpus. Add a row when a document starts publishing a spelling; change
/// one only together with the document that publishes it.
const CORPUS: &[Published] = &[
    // ---- `file:`, the three RFC 8089 shapes plugin-file.md publishes ------
    ok("file:/path", Source::Doc(FILE_MD), Role::Config),
    ok("file:///path", Source::Doc(FILE_MD), Role::Config),
    ok(
        "file:///C:/path/to/object",
        Source::Doc(FILE_MD),
        Role::Config,
    ),
    // The plugin's documented pipeline "normalizes backslashes to forward
    // slashes", so the spelling a Windows operator writes for a local root is
    // a working one. It parses to the same URL as the forward-slash form, with
    // no authority in either — refusing it reports a lost authority for an
    // address that never spelled one.
    ok("file:///C:\\data\\", Source::Tests, Role::Config),
    ok(
        "file:///srv/data/",
        Source::Doc(CONFIGURATION_MD),
        Role::Config,
    ),
    ok("file:///srv/assets/", Source::Doc(CPP_MD), Role::Config),
    ok(
        "file:///data/scene.usd",
        Source::Doc(RUST_MD),
        Role::Request,
    ),
    ok("file:///srv/a.usd", Source::Doc(CPP_MD), Role::Request),
    ok("file:///tmp/x", Source::Doc(AGENT_MD), Role::Request),
    ok(
        "file:///etc/hostname",
        Source::Doc(PYTHON_MD),
        Role::Request,
    ),
    // Published as honored (`only localhost and the empty hostname`), and the
    // parser drops that authority by design rather than as a side effect.
    ok("file://localhost/tmp/x", Source::Tests, Role::Config),
    // ---- object stores ---------------------------------------------------
    ok(
        "s3://assets/scene.usd",
        Source::Doc(CONFIGURATION_MD),
        Role::Request,
    ),
    ok("s3://bucket/x", Source::Doc(S3_MD), Role::Request),
    ok("s3://bucket:443/x", Source::Doc(S3_MD), Role::Request),
    ok("s3://bucket/pub%20x", Source::Doc(S3_MD), Role::Request),
    ok("s3://bucket/100%25", Source::Doc(S3_MD), Role::Request),
    ok("s3://b/%70rivate/", Source::Doc(BROKER_MD), Role::Config),
    ok("s3://b/pub%20x/", Source::Doc(BROKER_MD), Role::Config),
    // A bare `%` is an ordinary key byte, and the operator guide publishes all
    // three of these as distinct, loadable scopes.
    ok("s3://b/100%", Source::Doc(BROKER_MD), Role::Config),
    ok("s3://b/100%25", Source::Doc(BROKER_MD), Role::Config),
    ok("s3://b/100%2525", Source::Doc(BROKER_MD), Role::Config),
    ok("s3://corp-prod/team/", Source::Doc(BROKER_MD), Role::Config),
    ok("s3://bucket/key", Source::Doc(AGENT_MD), Role::Request),
    ok(
        "s3://bucket/key?versionId=abc123",
        Source::Doc(CONFORMANCE_MD),
        Role::Request,
    ),
    ok("gs://bucket/", Source::Doc(GCS_MD), Role::Config),
    ok("gs://bucket/pub%20x", Source::Doc(GCS_MD), Role::Request),
    ok(
        "gs://bucket/object?generation=12345",
        Source::Doc(CONFORMANCE_MD),
        Role::Request,
    ),
    ok(
        "opendal://fs/a%20b.txt",
        Source::Doc(OPENDAL_MD),
        Role::Request,
    ),
    ok(
        "s3://b/pub%2520x",
        Source::Doc(PLUGIN_DEV_MD),
        Role::Request,
    ),
    // ---- http(s) ---------------------------------------------------------
    ok(
        "https://datasets.example.com/",
        Source::Doc(HTTP_MD),
        Role::Config,
    ),
    ok("https://host/private/", Source::Doc(HTTP_MD), Role::Config),
    ok("https://h/a/b", Source::Doc(HTTP_MD), Role::Request),
    ok("https://h/a%252Fb", Source::Doc(HTTP_MD), Role::Request),
    ok(
        "https://h/pkg%2Fv1.tgz",
        Source::Doc(HTTP_MD),
        Role::Request,
    ),
    ok("https://h/x%3Bj=1", Source::Doc(HTTP_MD), Role::Request),
    ok("https://h/x;j=1", Source::Doc(HTTP_MD), Role::Request),
    // Published as a spelling the path pipeline NORMALIZES rather than one it
    // refuses: the doc says it fetches `/a/b`. A refusal reaching a row like
    // this is the exact defect this file exists to catch.
    ok("https://h/a//b", Source::Doc(HTTP_MD), Role::Request),
    // `root_url` is the one configuration address that may carry credentials:
    // for `plugin-http` they are the credential channel, not a scope. This row
    // is why userinfo is refused per-boundary and never folded into
    // `refused_config_component`.
    ok(
        "https://user:pass@host/",
        Source::Doc(HTTP_MD),
        Role::Config,
    ),
    ok(
        "https://user:pass@host/x",
        Source::Doc(HTTP_MD),
        Role::Request,
    ),
    ok("https://h/team/", Source::Doc(BROKER_MD), Role::Config),
    ok("https://h:443/team/", Source::Doc(BROKER_MD), Role::Config),
    ok(
        "https://xn--bcher-kva.example/t/",
        Source::Doc(BROKER_MD),
        Role::Config,
    ),
    ok(
        "https://example.test/x",
        Source::Doc(AGENT_MD),
        Role::Request,
    ),
    // ---- other schemes ---------------------------------------------------
    ok("logical://h/public", Source::Doc(BROKER_MD), Role::Config),
    ok("memory://python/", Source::Doc(PYTHON_MD), Role::Config),
    ok("ov:///public/", Source::Doc(CONFIGURATION_MD), Role::Config),
    // A hostless address on a scheme the parser does not normalize. Both
    // spellings are one node, which is what `node_address` has to render one
    // way for a cache row written under one to be found under the other.
    ok("broker:/x", Source::Tests, Role::Request),
    ok("broker:///x", Source::Tests, Role::Request),
    // ---- published as refused, so a narrowing cannot overshoot ------------
    no(
        "logical://h/public#note",
        Source::Doc(BROKER_MD),
        Role::Config,
        Refused::Fragment,
    ),
    no(
        "https://h/private?v=1",
        Source::Doc(BROKER_MD),
        Role::Config,
        Refused::Query,
    ),
    // The UNC spelling with no `//` for a raw scan to find: it HAS an authority
    // and the drive-letter rewrite destroys it, so a root naming a remote share
    // would install and serve the local disk of the same name.
    no(
        "file:\\\\server\\C:\\data\\",
        Source::Tests,
        Role::Config,
        Refused::Authority,
    ),
    no(
        "file:\\\\server\\share\\x",
        Source::Tests,
        Role::Config,
        Refused::Authority,
    ),
    no(
        "file://server\\C:/x",
        Source::Tests,
        Role::Config,
        Refused::Authority,
    ),
    no(
        "https:/\\evil.example.com/x",
        Source::Tests,
        Role::Config,
        Refused::Authority,
    ),
    no(
        "https:///evil.example.com/x",
        Source::Tests,
        Role::Config,
        Refused::Authority,
    ),
    // ONE leading separator, either spelling. A scheme that skips the extra
    // slash reads the first path segment as a host, so both create one out of
    // what reads as a path. `file:/path` above is the control: the same shape
    // on a scheme that does not fill, and a published spelling of a root.
    no(
        "https:/evil.example.com/x",
        Source::Tests,
        Role::Config,
        Refused::Authority,
    ),
    no(
        "https:\\evil.example.com/x",
        Source::Tests,
        Role::Config,
        Refused::Authority,
    ),
    no(
        "https:evil.example.com/x",
        Source::Tests,
        Role::Config,
        Refused::Authority,
    ),
    // A byte the parser DELETES moves every boundary a raw scan looks for, so
    // it defeats the guard rather than merely changing a name. The second
    // hides the scheme from the scan as well.
    no(
        "file:/\t/server/C:/data/",
        Source::Tests,
        Role::Config,
        Refused::Authority,
    ),
    no(
        " file:\\\\server\\C:\\data\\",
        Source::Tests,
        Role::Config,
        Refused::Authority,
    ),
    no(
        "https://h\\evil/data",
        Source::Doc(BROKER_MD),
        Role::Config,
        Refused::Authority,
    ),
    no(
        "s3://corp:\\secret",
        Source::Doc(BROKER_MD),
        Role::Request,
        Refused::Node,
    ),
    no(
        "s3://bucket/public/../private/secret",
        Source::Doc(PLUGIN_DEV_MD),
        Role::Request,
        Refused::Node,
    ),
];

fn doc_text(path: &str) -> &'static str {
    DOC_TEXT
        .iter()
        .find(|(name, _)| *name == path)
        .map(|(_, text)| *text)
        .unwrap_or_else(|| panic!("{path} is cited by the corpus but not bound in DOC_TEXT"))
}

/// A row cannot cite a document that does not contain it. Without this the
/// corpus can drift into a list of spellings nobody publishes, which would
/// still pass the assertions below while proving nothing about the docs.
#[test]
fn every_row_appears_where_it_says_it_does() {
    let mut checked = 0;
    for row in CORPUS {
        let Source::Doc(path) = row.source else {
            continue;
        };
        assert!(
            doc_text(path).contains(row.raw),
            "{path} no longer contains the spelling `{}` this corpus pins. If the doc \
             dropped it deliberately, drop the row in the same commit",
            row.raw
        );
        checked += 1;
    }
    assert!(
        checked >= 30,
        "expected the corpus to be mostly doc-sourced; only {checked} rows cite a document"
    );
}

/// Every published spelling still passes the boundary its role sends it
/// through, and every published-as-refused spelling still trips the rule it
/// names.
#[test]
fn every_published_spelling_still_loads() {
    let (mut accepted, mut refused) = (0, 0);
    for row in CORPUS {
        let raw = row.raw;
        match row.refused {
            None => {
                accepted += 1;
                assert!(
                    ovstorage_layer::parsing_preserves_authority(raw),
                    "`{raw}` is published as a working spelling and the authority rule \
                     refuses it"
                );
                if row.role == Role::Config {
                    assert_eq!(
                        address::refused_config_component(raw).map(|c| c.name()),
                        None,
                        "`{raw}` is published as a configuration address and the \
                         config-component rule refuses it"
                    );
                }
                let parsed = address::parse(raw).unwrap_or_else(|error| {
                    panic!("`{raw}` is published as an address and does not parse: {error:?}")
                });
                // The comparison form must round-trip: a consumer that keys on
                // `node_address` has to be able to parse its own key back and
                // land on the same node, or an invalidation written from the
                // parsed address cannot reach the row.
                let keyed = ovstorage_layer::node_address(&parsed);
                let reparsed = Url::parse(&keyed).unwrap_or_else(|error| {
                    panic!("`{keyed}` (from `{raw}`) does not parse: {error}")
                });
                assert_eq!(
                    ovstorage_layer::node_key(&reparsed),
                    ovstorage_layer::node_key(&parsed),
                    "`{raw}` and its own cache key name different nodes"
                );
            }
            Some(rule) => {
                refused += 1;
                let tripped = match rule {
                    Refused::Query => {
                        address::refused_config_component(raw).map(|c| c.name()) == Some("query")
                    }
                    Refused::Fragment => {
                        address::refused_config_component(raw).map(|c| c.name()) == Some("fragment")
                    }
                    Refused::Authority => !ovstorage_layer::parsing_preserves_authority(raw),
                    Refused::Node => !ovstorage_layer::parsing_preserves_node(raw),
                };
                assert!(
                    tripped,
                    "`{raw}` is published as refused by {rule:?} and that rule now accepts it"
                );
            }
        }
    }
    assert!(
        accepted >= 35 && refused >= 8,
        "the corpus went thin: {accepted} accepted, {refused} refused rows"
    );
}

/// Every accepted spelling still ROUTES: the containment predicate every
/// selecting surface asks — router, alias, visibility, authz, the broker's
/// OAuth routes — must still cover the spelling's own subtree.
///
/// This is the half a refusal test cannot see. A spelling that loads and then
/// selects nothing is a working configuration that answers `NoRoute`, which is
/// how the alias empty-suffix and the Nucleus dead-prefix defects presented.
#[test]
fn every_accepted_spelling_still_routes() {
    let mut routed = 0;
    for row in CORPUS.iter().filter(|row| row.refused.is_none()) {
        let prefix = address::parse(row.raw).expect("checked by the load test");
        assert!(
            address::is_ancestor_or_self(&prefix, &prefix),
            "`{}` does not contain itself",
            row.raw
        );
        // A query pins a version, and a pinned prefix covers exactly its own
        // query by design — so the child it must still reach is one carrying
        // the same pin. Asserting only self-containment here would be a
        // tautology dressed as a routing check.
        if let Some(pinned) = prefix.query() {
            let mut child = prefix.clone();
            child.set_query(None);
            let mut child = address::join_relative(&child, "child")
                .unwrap_or_else(|error| panic!("`{}` cannot name a child: {error:?}", row.raw));
            child.set_query(Some(pinned));
            assert!(
                address::is_ancestor_or_self(&prefix, &child),
                "`{}` no longer covers `{child}`, which carries its own pin",
                row.raw
            );
            routed += 1;
            continue;
        }
        let child = address::join_relative(&prefix, "child")
            .unwrap_or_else(|error| panic!("`{}` cannot name a child: {error:?}", row.raw));
        assert!(
            address::is_ancestor_or_self(&prefix, &child),
            "`{}` no longer covers `{child}`, so a route written with it selects nothing \
             beneath it",
            row.raw
        );
        routed += 1;
    }
    assert!(routed >= 35, "the corpus went thin: {routed} routed rows");
}

/// Buffer a `ReadResult`'s content: the file backend returns a
/// `LocalDelegate` for whole-object reads.
async fn buffer_read(result: ReadResult) -> Vec<u8> {
    match result {
        ReadResult::Bytes { bytes, .. } => bytes,
        ReadResult::Stream { mut stream, .. } => {
            let mut out = Vec::new();
            while let Some(chunk) = stream.next().await {
                out.extend_from_slice(&chunk.expect("stream chunk"));
            }
            out
        }
        ReadResult::LocalDelegate(local) => tokio::fs::read(&local.path).await.expect("local read"),
        other => panic!("unexpected read result: {other:?}"),
    }
}

/// The `file` backend end to end: a real directory, spelled every way the docs
/// publish, built into a real Stack and read through.
///
/// The predicate corpus above asks the address layer; this asks the boundary
/// the operator actually crosses. Both halves are needed — `file:/data/` passed
/// `Url::parse` for the whole time the config loader was refusing it.
#[tokio::test]
async fn a_file_root_loads_and_routes_in_every_published_spelling() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("data");
    std::fs::create_dir(&root).expect("create root");
    std::fs::write(root.join("object.txt"), b"hello").expect("write object");
    let path = root.to_str().expect("utf-8 temp path").to_string();

    // Every shape `plugin-file.md` publishes, plus the plain filesystem path
    // the shipped sample configs use for `root`, plus the backslash separator
    // the plugin's documented pipeline normalizes.
    let spellings = [
        format!("file:{path}"),
        format!("file://{path}"),
        format!("file://localhost{path}"),
        // The separator a Windows operator writes, in the position
        // `file:///C:\data\` puts it: after the empty authority, wholly inside
        // the path, where the parser folds it to `/` and no authority moves.
        format!(
            "file:///{}",
            path.trim_start_matches('/').replace('/', "\\")
        ),
        path.clone(),
    ];

    let mut built = 0;
    for root_value in &spellings {
        let toml = format!(
            r#"
[ovstorage]
root = "file"

[ovstorage.layers.file]

[[ovstorage.connections]]
name = "local"
backend_kind = "file"
config = {{ root = "{}" }}
"#,
            root_value.replace('\\', "\\\\")
        );
        let config = StackConfig::from_toml_str(&toml)
            .unwrap_or_else(|error| panic!("`{root_value}` did not parse as config: {error:?}"));
        let stack = build_stack(&config, Vec::new())
            .await
            .unwrap_or_else(|error| panic!("`{root_value}` did not build a stack: {error:?}"));
        // Loading is half of it. Read the object back through the stack it
        // built, so a spelling that installs a root nothing routes under fails
        // here rather than passing as a load.
        let address = address::parse(&format!("file://{path}/object.txt"))
            .expect("the request address parses");
        let result = stack
            .read(
                Request::new(ReadRequest {
                    address: address.clone(),
                    options: ReadOptions::default(),
                }),
                None,
            )
            .await
            .unwrap_or_else(|error| panic!("`{root_value}` did not serve {address}: {error:?}"));
        assert_eq!(
            buffer_read(result).await,
            b"hello",
            "`{root_value}` served the wrong bytes"
        );

        // The call the issue actually turns on. `list` was the example in the
        // report and `list` always worked — the normalizers rewrote the
        // address to its directory form before the router saw it — so the
        // reproduction is a `stat` of the connection ROOT, spelled without its
        // trailing slash. Both spellings, because a root that answers only one
        // of them is the defect.
        for spelling in [format!("file://{path}"), format!("file://{path}/")] {
            let root_address = address::parse(&spelling).expect("the root parses");
            let info = stack
                .stat(
                    Request::new(StatRequest {
                        address: root_address.clone(),
                        options: StatOptions::default(),
                    }),
                    None,
                )
                .await
                .unwrap_or_else(|error| {
                    panic!("root `{root_value}` did not stat as `{spelling}`: {error:?}")
                });
            assert_eq!(info.kind, ObjectKind::Directory, "{spelling}");
        }
        built += 1;
    }
    assert_eq!(built, spellings.len());
}

/// `file://path` — two slashes and no hostname — is the mistake `plugin-file.md`
/// names, and a UNC share is the other one. The backend refuses both, for a
/// NON-empty authority that is not `localhost`.
///
/// This is not a corpus row because the rule that refuses it is the backend's,
/// not the address layer's: the address layer accepts the spelling, exactly as
/// it accepts every other whose authority survives the parse. Pinning which
/// layer owns the answer is the point — a future narrowing of the address rules
/// must not quietly take the refusal over and leave this one working by
/// accident.
///
/// **Measured, and asserted here rather than changed:** the refusal lands on
/// every REQUEST, not on the connection, so a root naming a share builds a
/// stack and then answers `InvalidArgument` for everything under it. Making it
/// a load error is a change to the backend's config loader, not to an address
/// rule, and it is not what this test exists to hold.
#[tokio::test]
async fn a_file_root_with_a_foreign_authority_is_refused_by_the_backend() {
    assert!(
        ovstorage_layer::parsing_preserves_authority("file://server/share/"),
        "the address layer has no quarrel with this spelling"
    );
    let toml = r#"
[ovstorage]
root = "file"

[ovstorage.layers.file]

[[ovstorage.connections]]
name = "local"
backend_kind = "file"
config = { root = "file://server/share/" }
"#;
    let config = StackConfig::from_toml_str(toml).expect("parses as config");
    let stack = build_stack(&config, Vec::new())
        .await
        .expect("the connection builds; the authority check is per-request");
    let error = stack
        .read(
            Request::new(ReadRequest {
                address: Url::parse("file://server/share/x").expect("parses"),
                options: ReadOptions::default(),
            }),
            None,
        )
        .await
        .expect_err("a non-localhost authority must be refused");
    assert!(
        error.message().contains("'localhost'") && error.message().contains("server"),
        "the refusal must name the rule and the offending host: {error:?}"
    );
}
