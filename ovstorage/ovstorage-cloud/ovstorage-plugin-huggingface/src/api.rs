// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Hub wire layer: endpoint URL builders, response JSON models, `Link`-header
//! pagination, and the `x-error-code` sanitizer.
//!
//! Everything here is string-in/string-out with no I/O of its own; the request
//! bodies live in [`crate::HfBackend`] so every send funnels through one
//! error-mapping seam.

use ovstorage_plugin::{Error, ErrorCode, Result, Url};
use serde::Deserialize;

use crate::HfConnectionConfig;

/// Which kind of Hub repository a connection serves. Decides both the
/// `/api/{plural}/…` segment and the `hf://{plural}/…` caller-facing host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RepoType {
    Model,
    Dataset,
    Space,
}

impl RepoType {
    pub(crate) fn parse(text: &str) -> Result<Self> {
        match text {
            "model" => Ok(Self::Model),
            "dataset" => Ok(Self::Dataset),
            "space" => Ok(Self::Space),
            other => Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "huggingface repo_type '{other}' is not one of 'model', 'dataset', 'space'"
                ),
            )),
        }
    }

    /// The plural spelling used by both the `/api/{plural}` URL family and the
    /// `hf://{plural}/…` address host.
    pub(crate) fn plural(self) -> &'static str {
        match self {
            Self::Model => "models",
            Self::Dataset => "datasets",
            Self::Space => "spaces",
        }
    }

    /// The content-resolution URL prefix: models resolve at the site root,
    /// datasets and spaces under their plural.
    pub(crate) fn resolve_prefix(self) -> &'static str {
        match self {
            Self::Model => "",
            Self::Dataset => "datasets/",
            Self::Space => "spaces/",
        }
    }
}

/// Percent-encode a revision for use as ONE path segment. A ref such as
/// `refs/pr/1` carries slashes that must not create URL path structure.
pub(crate) fn enc_rev(revision: &str) -> String {
    urlencoding::encode(revision).into_owned()
}

/// Percent-encode a repo-relative path, preserving its segment structure.
pub(crate) fn enc_path(path: &str) -> String {
    path.split('/')
        .map(|segment| urlencoding::encode(segment).into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

fn api_base(config: &HfConnectionConfig) -> String {
    format!(
        "{}/api/{}/{}",
        config.endpoint,
        config.repo_type.plural(),
        config.repo_id
    )
}

/// `GET` — repository tree listing at `revision`, rooted at `dir_path`
/// (repo-relative, no trailing slash, empty = repo root).
pub(crate) fn tree_url(config: &HfConnectionConfig, revision: &str, dir_path: &str) -> String {
    let base = format!("{}/tree/{}", api_base(config), enc_rev(revision));
    if dir_path.is_empty() {
        base
    } else {
        format!("{base}/{}", enc_path(dir_path))
    }
}

/// `POST` — batched path metadata at `revision`.
pub(crate) fn paths_info_url(config: &HfConnectionConfig, revision: &str) -> String {
    format!("{}/paths-info/{}", api_base(config), enc_rev(revision))
}

/// `GET` — commit history of `revision` (newest first, `Link`-paginated).
pub(crate) fn commits_url(config: &HfConnectionConfig, revision: &str) -> String {
    format!("{}/commits/{}", api_base(config), enc_rev(revision))
}

/// `GET` — repository info pinned at `revision`; carries the resolved `sha`.
pub(crate) fn revision_url(config: &HfConnectionConfig, revision: &str) -> String {
    format!("{}/revision/{}", api_base(config), enc_rev(revision))
}

/// `GET`/`HEAD` — file content at `revision`. Non-LFS answers `200` with the
/// bytes; LFS answers `302` with a signed CDN URL in `Location`.
pub(crate) fn resolve_url(config: &HfConnectionConfig, revision: &str, path: &str) -> String {
    format!(
        "{}/{}{}/resolve/{}/{}",
        config.endpoint,
        config.repo_type.resolve_prefix(),
        config.repo_id,
        enc_rev(revision),
        enc_path(path)
    )
}

/// `GET` — token validity check.
pub(crate) fn whoami_url(endpoint: &str) -> String {
    format!("{endpoint}/api/whoami-v2")
}

/// One tree / paths-info entry. Tolerant of absent fields so a Hub schema
/// addition never fails a page; `type` is the only load-bearing discriminator.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TreeEntry {
    #[serde(rename = "type")]
    pub(crate) entry_type: String,
    pub(crate) path: String,
    #[serde(default)]
    pub(crate) oid: Option<String>,
    #[serde(default)]
    pub(crate) size: Option<u64>,
    #[serde(default)]
    pub(crate) lfs: Option<LfsInfo>,
    #[serde(default)]
    pub(crate) last_commit: Option<LastCommit>,
}

/// LFS pointer facts: `oid` is the content sha256; the entry-level `size` is
/// already the real content size, `pointer_size` is the pointer file's.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LfsInfo {
    pub(crate) oid: String,
    #[serde(default)]
    pub(crate) pointer_size: Option<u64>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LastCommit {
    pub(crate) id: String,
    #[serde(default)]
    pub(crate) title: Option<String>,
    #[serde(default)]
    pub(crate) date: Option<String>,
}

/// One entry of the commits history.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CommitInfo {
    pub(crate) id: String,
    #[serde(default)]
    pub(crate) title: Option<String>,
    #[serde(default)]
    pub(crate) date: Option<String>,
    #[serde(default)]
    pub(crate) authors: Vec<CommitAuthor>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CommitAuthor {
    #[serde(default)]
    pub(crate) user: Option<String>,
}

/// Repo-info projection: only the resolved commit sha is read.
#[derive(Clone, Debug, Deserialize)]
pub(crate) struct RepoInfo {
    #[serde(default)]
    pub(crate) sha: Option<String>,
}

/// The `rel="next"` target of a `Link` response header, or `None` when the
/// page is the last one.
///
/// The next-URL is followed with this connection's bearer, so a target on a
/// foreign origin is refused rather than followed: a response header must not
/// be able to steer credentialed requests off the configured endpoint.
pub(crate) fn parse_link_next(
    headers: &reqwest::header::HeaderMap,
    endpoint: &str,
) -> Result<Option<Url>> {
    let Some(raw) = headers
        .get(reqwest::header::LINK)
        .and_then(|value| value.to_str().ok())
    else {
        return Ok(None);
    };
    for part in raw.split(',') {
        let mut sections = part.split(';');
        let Some(target) = sections.next() else {
            continue;
        };
        let target = target.trim();
        let Some(target) = target
            .strip_prefix('<')
            .and_then(|rest| rest.strip_suffix('>'))
        else {
            continue;
        };
        let is_next = sections.any(|param| {
            let param = param.trim();
            param == "rel=\"next\"" || param == "rel=next"
        });
        if !is_next {
            continue;
        }
        let next = Url::parse(target).map_err(|_| {
            Error::new(
                ErrorCode::Internal,
                "huggingface pagination Link header carries an unparsable next URL",
            )
        })?;
        let origin = Url::parse(endpoint).map_err(|_| {
            Error::new(
                ErrorCode::Internal,
                "huggingface endpoint is not an absolute URL",
            )
        })?;
        if next.scheme() != origin.scheme()
            || next.host_str() != origin.host_str()
            || next.port_or_known_default() != origin.port_or_known_default()
        {
            return Err(Error::new(
                ErrorCode::Internal,
                "huggingface pagination Link header points off the configured endpoint; \
                 refusing to follow it",
            ));
        }
        return Ok(Some(next));
    }
    Ok(None)
}

/// The sanitized `x-error-code` response header, when present. Only the
/// alphanumeric/`_`/`-` charset survives and the value is capped, so a
/// hostile header cannot smuggle free text into an error message.
pub(crate) fn error_code_header(headers: &reqwest::header::HeaderMap) -> Option<String> {
    let raw = headers.get("x-error-code")?.to_str().ok()?;
    let cleaned: String = raw
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-'))
        .take(64)
        .collect();
    if cleaned.is_empty() {
        None
    } else {
        Some(cleaned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn config(repo_type: RepoType) -> HfConnectionConfig {
        let mut config = HashMap::new();
        config.insert(
            "repo_id".into(),
            ovstorage_plugin::ConfigValue::String("acme/demo".into()),
        );
        let type_text = match repo_type {
            RepoType::Model => "model",
            RepoType::Dataset => "dataset",
            RepoType::Space => "space",
        };
        config.insert(
            "repo_type".into(),
            ovstorage_plugin::ConfigValue::String(type_text.into()),
        );
        crate::__test_only_parse_config(&config).unwrap()
    }

    #[test]
    fn url_spelling_covers_all_repo_types() {
        let model = config(RepoType::Model);
        assert_eq!(
            tree_url(&model, "main", ""),
            "https://huggingface.co/api/models/acme/demo/tree/main"
        );
        assert_eq!(
            resolve_url(&model, "main", "weights/model.bin"),
            "https://huggingface.co/acme/demo/resolve/main/weights/model.bin"
        );
        let dataset = config(RepoType::Dataset);
        assert_eq!(
            paths_info_url(&dataset, "main"),
            "https://huggingface.co/api/datasets/acme/demo/paths-info/main"
        );
        assert_eq!(
            resolve_url(&dataset, "main", "data.csv"),
            "https://huggingface.co/datasets/acme/demo/resolve/main/data.csv"
        );
        let space = config(RepoType::Space);
        assert_eq!(
            commits_url(&space, "main"),
            "https://huggingface.co/api/spaces/acme/demo/commits/main"
        );
        assert_eq!(
            resolve_url(&space, "main", "app.py"),
            "https://huggingface.co/spaces/acme/demo/resolve/main/app.py"
        );
    }

    #[test]
    fn revision_with_slashes_is_percent_encoded() {
        let model = config(RepoType::Model);
        assert_eq!(
            tree_url(&model, "refs/pr/1", "sub dir"),
            "https://huggingface.co/api/models/acme/demo/tree/refs%2Fpr%2F1/sub%20dir"
        );
        assert_eq!(
            resolve_url(&model, "refs/convert/parquet", "a/b c.txt"),
            "https://huggingface.co/acme/demo/resolve/refs%2Fconvert%2Fparquet/a/b%20c.txt"
        );
        assert_eq!(
            revision_url(&model, "refs/pr/1"),
            "https://huggingface.co/api/models/acme/demo/revision/refs%2Fpr%2F1"
        );
    }

    #[test]
    fn link_header_pagination_parses_rel_next() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::LINK,
            "<https://huggingface.co/api/models/acme/demo/tree/main?cursor=abc>; rel=\"next\""
                .parse()
                .unwrap(),
        );
        let next = parse_link_next(&headers, "https://huggingface.co")
            .unwrap()
            .expect("next link");
        assert_eq!(
            next.as_str(),
            "https://huggingface.co/api/models/acme/demo/tree/main?cursor=abc"
        );
        assert!(
            parse_link_next(&reqwest::header::HeaderMap::new(), "https://huggingface.co")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn link_header_on_a_foreign_origin_is_refused() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::LINK,
            "<https://evil.example/steal>; rel=\"next\""
                .parse()
                .unwrap(),
        );
        let err = parse_link_next(&headers, "https://huggingface.co").unwrap_err();
        assert_eq!(err.code(), ErrorCode::Internal);
    }

    #[test]
    fn error_code_header_is_sanitized() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("x-error-code", "RepoNotFound".parse().unwrap());
        assert_eq!(error_code_header(&headers).as_deref(), Some("RepoNotFound"));
        let mut hostile = reqwest::header::HeaderMap::new();
        hostile.insert(
            "x-error-code",
            "Gated Repo: visit https://evil.example".parse().unwrap(),
        );
        assert_eq!(
            error_code_header(&hostile).as_deref(),
            Some("GatedRepovisithttpsevilexample")
        );
        assert!(error_code_header(&reqwest::header::HeaderMap::new()).is_none());
    }
}
