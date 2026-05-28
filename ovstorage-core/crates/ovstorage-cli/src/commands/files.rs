// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};

use ovstorage::{
    Body, CancellationToken, CopyOptions, DeleteOptions, IfDestExists, ListVersionsOptions,
    ReadOptions, RenameOptions, StatOptions, Storage, UpdateMetadataOptions, WriteOptions,
};

use crate::commands::util::{
    OutputFormat, parse_if_dest_opt, parse_if_match_opt, parse_key_value, parse_ops, parse_range,
    print_info, print_table, resolve_address, stdin_body_stream, stream_read_to_path,
    stream_read_to_writer,
};
use crate::session::SessionState;

pub(crate) async fn stat(
    state: &SessionState,
    address: &str,
    full_metadata: bool,
    cancel: &CancellationToken,
) -> ovstorage::Result<()> {
    let lib = &state.library;
    let info = lib
        .stat(
            resolve_address(address, state.pwd.as_ref())?,
            StatOptions { full_metadata },
            Some(cancel.clone()),
        )
        .await?;
    print_info(&info);
    Ok(())
}

pub(crate) async fn read(
    state: &SessionState,
    address: &str,
    output: Option<&str>,
    range: Option<&str>,
    if_match: Option<&str>,
    cancel: &CancellationToken,
) -> ovstorage::Result<()> {
    let lib = &state.library;
    let range = range.map(parse_range).transpose()?;
    let if_match = parse_if_match_opt(if_match)?;
    let addr = resolve_address(address, state.pwd.as_ref())?;
    let opts = ReadOptions {
        range,
        if_match,
        max_bytes: None,
    };
    match output {
        None | Some("-") => {
            stream_read_to_writer(lib, addr, opts, &mut std::io::stdout().lock(), cancel).await
        }
        Some(path) => stream_read_to_path(lib, addr, opts, Path::new(path), cancel).await,
    }
}

pub(crate) struct WriteArgs {
    pub address: String,
    pub input: Option<String>,
    pub no_overwrite: bool,
    pub if_match: Option<String>,
    pub metadata: Vec<String>,
    pub message: Option<String>,
}

pub(crate) async fn write(
    state: &SessionState,
    args: WriteArgs,
    cancel: &CancellationToken,
) -> ovstorage::Result<()> {
    let lib = &state.library;
    let body = match args.input.as_deref() {
        None | Some("-") => Body::Stream(stdin_body_stream()),
        Some(path) => Body::LocalFile(PathBuf::from(path)),
    };
    let if_match = parse_if_match_opt(args.if_match.as_deref())?;
    if if_match.is_some() && args.no_overwrite {
        return Err(ovstorage::Error::new(
            ovstorage::ErrorCode::InvalidArgument,
            "--if-match and --no-overwrite are mutually exclusive",
        ));
    }
    let user_metadata = if args.metadata.is_empty() {
        None
    } else {
        let mut map = ovstorage::UserMetadata::new();
        for entry in args.metadata {
            let (key, value) = parse_key_value(&entry)?;
            map.insert(key, value);
        }
        Some(map)
    };
    let result = lib
        .write(
            resolve_address(&args.address, state.pwd.as_ref())?,
            body,
            WriteOptions {
                if_dest: match (if_match, args.no_overwrite) {
                    (Some(etag), _) => IfDestExists::MatchEtag(etag),
                    (None, true) => IfDestExists::Fail,
                    (None, false) => IfDestExists::Overwrite,
                },
                size_hint: None,
                user_metadata,
                message: args.message,
            },
            Some(cancel.clone()),
        )
        .await?;
    print_info(&result.info);
    Ok(())
}

pub(crate) async fn delete(
    state: &SessionState,
    address: &str,
    if_match: Option<&str>,
    cancel: &CancellationToken,
) -> ovstorage::Result<()> {
    let lib = &state.library;
    let if_match = parse_if_match_opt(if_match)?;
    lib.delete(
        resolve_address(address, state.pwd.as_ref())?,
        DeleteOptions { if_match },
        Some(cancel.clone()),
    )
    .await
}

pub(crate) struct UpdateMetadataArgs {
    pub address: String,
    pub set: Vec<String>,
    pub remove: Vec<String>,
    pub if_match: Option<String>,
    pub allow_rewrite_emulation: bool,
    pub message: Option<String>,
}

pub(crate) async fn update_metadata(
    state: &SessionState,
    args: UpdateMetadataArgs,
    cancel: &CancellationToken,
) -> ovstorage::Result<()> {
    let lib = &state.library;
    let mut options = UpdateMetadataOptions::default();
    for entry in args.set {
        let (key, value) = parse_key_value(&entry)?;
        options.user_metadata_set.insert(key, value);
    }
    options.user_metadata_remove = args.remove;
    options.if_match = parse_if_match_opt(args.if_match.as_deref())?;
    options.allow_rewrite_emulation = args.allow_rewrite_emulation;
    options.message = args.message;
    let info = lib
        .update_metadata(
            resolve_address(&args.address, state.pwd.as_ref())?,
            options,
            Some(cancel.clone()),
        )
        .await?;
    print_info(&info);
    Ok(())
}

pub(crate) async fn check_access(
    state: &SessionState,
    address: &str,
    ops: &str,
    cancel: &CancellationToken,
) -> ovstorage::Result<()> {
    let lib = &state.library;
    let decision = lib
        .check_access(
            resolve_address(address, state.pwd.as_ref())?,
            parse_ops(ops)?,
            Some(cancel.clone()),
        )
        .await?;
    println!("allowed={}", decision.allowed);
    if let Some(reason) = decision.reason {
        println!("reason={reason}");
    }
    Ok(())
}

pub(crate) async fn cp(
    state: &SessionState,
    src: &str,
    dest: &str,
    if_source: Option<&str>,
    if_dest: Option<&str>,
    message: Option<String>,
    cancel: &CancellationToken,
) -> ovstorage::Result<()> {
    let lib = &state.library;
    let if_source = parse_if_match_opt(if_source)?;
    let if_dest = parse_if_dest_opt(if_dest)?;
    let result = lib
        .copy(
            resolve_address(src, state.pwd.as_ref())?,
            resolve_address(dest, state.pwd.as_ref())?,
            CopyOptions {
                if_source,
                if_dest,
                message,
            },
            Some(cancel.clone()),
        )
        .await?;
    print_info(&result.info);
    Ok(())
}

pub(crate) async fn mv(
    state: &SessionState,
    src: &str,
    dest: &str,
    if_source: Option<&str>,
    if_dest: Option<&str>,
    message: Option<String>,
    cancel: &CancellationToken,
) -> ovstorage::Result<()> {
    let lib = &state.library;
    let if_source = parse_if_match_opt(if_source)?;
    let if_dest = parse_if_dest_opt(if_dest)?;
    lib.rename(
        resolve_address(src, state.pwd.as_ref())?,
        resolve_address(dest, state.pwd.as_ref())?,
        RenameOptions {
            if_source,
            if_dest,
            message,
        },
        Some(cancel.clone()),
    )
    .await
}

pub(crate) async fn list_versions(
    state: &SessionState,
    address: &str,
    max_results: Option<u32>,
    page_token: Option<String>,
    format: OutputFormat,
    cancel: &CancellationToken,
) -> ovstorage::Result<()> {
    let lib = &state.library;
    let items = lib
        .list_versions(
            resolve_address(address, state.pwd.as_ref())?,
            ListVersionsOptions {
                max_results,
                page_token,
            },
            Some(cancel.clone()),
        )
        .await?;
    match format {
        OutputFormat::Human => {
            for item in &items {
                println!("{}", item.address);
            }
        }
        OutputFormat::Table => {
            let rows: Vec<Vec<String>> = items
                .iter()
                .map(|item| {
                    let size = item
                        .size
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "-".into());
                    vec![size, item.address.to_string()]
                })
                .collect();
            print_table(&["SIZE", "ADDRESS"], &rows);
        }
    }
    Ok(())
}

pub(crate) async fn get_latest_version(
    state: &SessionState,
    address: &str,
    cancel: &CancellationToken,
) -> ovstorage::Result<()> {
    let lib = &state.library;
    let item = lib
        .get_latest_version(
            resolve_address(address, state.pwd.as_ref())?,
            Some(cancel.clone()),
        )
        .await?;
    print_info(&item);
    Ok(())
}
