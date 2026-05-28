// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::{HashSet, VecDeque};
use std::io::IsTerminal;

use ovstorage::{
    CancellationToken, CreateDirectoryOptions, DeleteDirectoryOptions, DeleteOptions, Error,
    ErrorCode, Library, ListOptions, ObjectKind, Storage, Url, WatchDirectoryCursor,
    WatchDirectoryOptions,
};

use crate::commands::util::{
    OutputFormat, Step, decode_cursor_b64, ensure_trailing_slash, invalid, next_or_cancel,
    print_change_event, print_info, print_table, resolve_address,
};
use crate::session::SessionState;

pub(crate) async fn cd(
    state: &mut SessionState,
    address: &str,
    cancel: &CancellationToken,
) -> ovstorage::Result<()> {
    if !state.interactive {
        return Err(invalid(
            "cd has no effect outside the interactive shell — pass full URLs to other commands instead",
        ));
    }
    let lib = state.library.clone();
    let resolved = resolve_address(address, state.pwd.as_ref())?;
    let with_slash = ensure_trailing_slash(resolved)?;
    // Probe the prefix so typos / unreachable backends fail at `cd`
    // rather than at every subsequent relative-path command.
    lib.list_page(
        with_slash.clone(),
        ListOptions {
            max_results: Some(1),
            ..ListOptions::default()
        },
        Some(cancel.clone()),
    )
    .await?;
    state.pwd = Some(with_slash);
    Ok(())
}

pub(crate) async fn create_directory(
    state: &SessionState,
    address: &str,
    cancel: &CancellationToken,
) -> ovstorage::Result<()> {
    let lib = &state.library;
    let info = lib
        .create_directory(
            resolve_address(address, state.pwd.as_ref())?,
            CreateDirectoryOptions::default(),
            Some(cancel.clone()),
        )
        .await?;
    print_info(&info);
    Ok(())
}

pub(crate) async fn delete_directory(
    state: &SessionState,
    address: &str,
    recursive: bool,
    dry_run: bool,
    yes: bool,
    cancel: &CancellationToken,
) -> ovstorage::Result<()> {
    let lib = &state.library;
    let resolved = resolve_address(address, state.pwd.as_ref())?;

    if !recursive && !dry_run {
        return lib
            .delete_directory(resolved, DeleteDirectoryOptions, Some(cancel.clone()))
            .await;
    }

    let entries = enumerate_recursive(lib, &resolved, cancel).await?;

    if dry_run {
        print_delete_plan(&resolved, &entries);
        println!(
            "dry-run: {} entries would be deleted (no mutation)",
            entries.len()
        );
        return Ok(());
    }

    if !yes {
        if !state.interactive && !std::io::stdin().is_terminal() {
            return Err(invalid(
                "recursive delete-directory requires --yes when no interactive prompt is available; \
                 pass --dry-run first to preview the plan",
            ));
        }
        print_delete_plan(&resolved, &entries);
        println!("{} entries will be deleted.", entries.len());
        if !confirm_prompt("Continue? [y/N]: ")? {
            return Err(Error::new(
                ErrorCode::Cancelled,
                "user declined recursive delete",
            ));
        }
    }

    execute_delete_plan(lib, resolved, entries, cancel).await
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DeletePlanEntryKind {
    Object,
    Directory,
}

#[derive(Clone, Debug)]
struct DeletePlanEntry {
    address: Url,
    kind: DeletePlanEntryKind,
}

async fn enumerate_recursive(
    lib: &Library,
    root: &Url,
    cancel: &CancellationToken,
) -> ovstorage::Result<Vec<DeletePlanEntry>> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let recursive_result =
        collect_list_page(lib, root, true, true, &mut out, &mut seen, cancel).await;
    let recursive_collected = match recursive_result {
        Ok(()) => true,
        Err(err) if err.code() == ErrorCode::NotFound => return Ok(out),
        Err(err) if err.code() == ErrorCode::Unsupported => false,
        Err(err) => return Err(err),
    };

    let mut queued = VecDeque::from([root.clone()]);
    let mut scanned = HashSet::new();
    while let Some(dir) = queued.pop_front() {
        if !scanned.insert(dir.as_str().to_owned()) {
            continue;
        }
        let before = out.len();
        collect_list_page(
            lib,
            &dir,
            false,
            !recursive_collected,
            &mut out,
            &mut seen,
            cancel,
        )
        .await?;
        for entry in out[before..].iter().filter(|entry| {
            entry.kind == DeletePlanEntryKind::Directory && entry.address.as_str() != root.as_str()
        }) {
            queued.push_back(entry.address.clone());
        }
    }

    Ok(out)
}

async fn collect_list_page(
    lib: &Library,
    root: &Url,
    recursive: bool,
    include_objects: bool,
    out: &mut Vec<DeletePlanEntry>,
    seen: &mut HashSet<String>,
    cancel: &CancellationToken,
) -> ovstorage::Result<()> {
    let mut page_token = None;
    loop {
        let page = lib
            .list_page(
                root.clone(),
                ListOptions {
                    recursive,
                    max_results: Some(1000),
                    page_token: page_token.clone(),
                    ..ListOptions::default()
                },
                Some(cancel.clone()),
            )
            .await?;

        for item in page.items {
            if item.kind == ObjectKind::File {
                if include_objects {
                    push_delete_plan_entry(
                        out,
                        seen,
                        DeletePlanEntry {
                            address: item.address,
                            kind: DeletePlanEntryKind::Object,
                        },
                    )?;
                }
            } else {
                push_delete_plan_entry(
                    out,
                    seen,
                    DeletePlanEntry {
                        address: item.address,
                        kind: DeletePlanEntryKind::Directory,
                    },
                )?;
            }
        }

        match page.next_page_token {
            Some(token) => page_token = Some(token),
            None => return Ok(()),
        }
    }
}

fn push_delete_plan_entry(
    out: &mut Vec<DeletePlanEntry>,
    seen: &mut HashSet<String>,
    entry: DeletePlanEntry,
) -> ovstorage::Result<()> {
    if seen.insert(entry.address.as_str().to_owned()) {
        out.push(entry);
    }
    if out.len() >= 100_000 {
        return Err(Error::new(
            ErrorCode::ResourceExhausted,
            "recursive enumeration exceeded 100,000 entries; delete in batches or use a more specific prefix",
        ));
    }
    Ok(())
}

async fn execute_delete_plan(
    lib: &Library,
    root: Url,
    entries: Vec<DeletePlanEntry>,
    cancel: &CancellationToken,
) -> ovstorage::Result<()> {
    let mut objects: Vec<Url> = entries
        .iter()
        .filter(|entry| entry.kind == DeletePlanEntryKind::Object)
        .map(|entry| entry.address.clone())
        .collect();
    objects.sort_by(|a, b| {
        b.as_str()
            .len()
            .cmp(&a.as_str().len())
            .then_with(|| b.as_str().cmp(a.as_str()))
    });
    for address in objects {
        if cancel.is_cancelled() {
            return Err(Error::new(
                ErrorCode::Cancelled,
                "delete cancelled mid-operation",
            ));
        }
        lib.delete(address, DeleteOptions::default(), Some(cancel.clone()))
            .await?;
    }

    let mut directories: Vec<Url> = entries
        .into_iter()
        .filter(|entry| entry.kind == DeletePlanEntryKind::Directory)
        .map(|entry| entry.address)
        .collect();
    directories.sort_by(|a, b| {
        b.as_str()
            .len()
            .cmp(&a.as_str().len())
            .then_with(|| b.as_str().cmp(a.as_str()))
    });
    for address in directories {
        if cancel.is_cancelled() {
            return Err(Error::new(
                ErrorCode::Cancelled,
                "delete cancelled mid-operation",
            ));
        }
        lib.delete_directory(address, DeleteDirectoryOptions, Some(cancel.clone()))
            .await?;
    }

    lib.delete_directory(root, DeleteDirectoryOptions, Some(cancel.clone()))
        .await
}

fn print_delete_plan(root: &Url, entries: &[DeletePlanEntry]) {
    println!("Recursive delete plan for {root}:");
    let preview_limit = 20;
    for entry in entries.iter().take(preview_limit) {
        println!("  - {}", entry.address);
    }
    if entries.len() > preview_limit {
        println!("  ... ({} more)", entries.len() - preview_limit);
    }
}

fn confirm_prompt(prompt: &str) -> ovstorage::Result<bool> {
    use std::io::{BufRead, Write};
    print!("{prompt}");
    std::io::stdout()
        .flush()
        .map_err(|err| Error::new(ErrorCode::Internal, format!("stdout flush: {err}")))?;
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|err| Error::new(ErrorCode::Internal, format!("stdin read: {err}")))?;
    let answer = line.trim().to_lowercase();
    Ok(answer == "y" || answer == "yes")
}

pub(crate) async fn watch_directory(
    state: &SessionState,
    prefix: &str,
    recursive: bool,
    no_metadata_changes: bool,
    since: Option<&str>,
    cancel: &CancellationToken,
) -> ovstorage::Result<()> {
    let lib = &state.library;
    let since = since
        .map(|cursor| decode_cursor_b64(cursor).map(WatchDirectoryCursor))
        .transpose()?;
    let mut stream = lib
        .watch_directory(
            resolve_address(prefix, state.pwd.as_ref())?,
            WatchDirectoryOptions {
                recursive,
                include_metadata_changes: !no_metadata_changes,
                since,
                ..WatchDirectoryOptions::default()
            },
            Some(cancel.clone()),
        )
        .await?;
    loop {
        match next_or_cancel(stream, cancel).await {
            Step::Event(returned, event) => {
                stream = returned;
                print_change_event(&event?)?;
            }
            Step::Done(_) => return Ok(()),
            Step::Cancelled => {
                return Err(Error::new(ErrorCode::Cancelled, "operation cancelled"));
            }
        }
    }
}

pub(crate) struct ListArgs {
    pub prefix: Option<String>,
    pub recursive: bool,
    pub full_metadata: bool,
    pub max_results: Option<u32>,
    pub page_token: Option<String>,
    pub format: OutputFormat,
}

pub(crate) async fn list(
    state: &SessionState,
    args: ListArgs,
    cancel: &CancellationToken,
) -> ovstorage::Result<()> {
    let lib = &state.library;
    let target = match (args.prefix.as_deref(), state.pwd.as_ref()) {
        (Some(p), _) => resolve_address(p, state.pwd.as_ref())?,
        (None, Some(pwd)) => pwd.clone(),
        (None, None) => {
            return Err(invalid(
                "ls requires a prefix when not in the interactive shell",
            ));
        }
    };
    let page = lib
        .list_page(
            target,
            ListOptions {
                recursive: args.recursive,
                max_results: args.max_results,
                page_token: args.page_token,
                full_metadata: args.full_metadata,
            },
            Some(cancel.clone()),
        )
        .await?;
    match args.format {
        OutputFormat::Human => {
            for item in &page.items {
                println!("{}", item.address);
            }
        }
        OutputFormat::Table => {
            let rows: Vec<Vec<String>> = page
                .items
                .iter()
                .map(|item| {
                    let kind = if item.kind == ObjectKind::File {
                        "object"
                    } else {
                        "subdirectory"
                    };
                    let size = item
                        .size
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "-".into());
                    vec![kind.into(), size, item.address.to_string()]
                })
                .collect();
            print_table(&["KIND", "SIZE", "ADDRESS"], &rows);
        }
    }
    if let Some(token) = page.next_page_token {
        eprintln!("next_page_token={token}");
    }
    Ok(())
}
