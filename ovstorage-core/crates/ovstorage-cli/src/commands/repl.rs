// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Interactive shell.
//!
//! Reuses the same clap-based parser as one-shot mode: each typed line is split
//! with `shell-words` and parsed with `Cli::try_parse_from`. The same
//! `SessionState` persists across every command typed during the session, so
//! `connect` followed by `write-config` chains naturally.

use std::path::PathBuf;

use clap::{CommandFactory, Parser};
use ovstorage::{Error, ErrorCode};
use rustyline::DefaultEditor;
use rustyline::error::ReadlineError;

use crate::interrupt::{INTERRUPT_WINDOW, InterruptDecision, interrupt_decision};
use crate::session::SessionState;
use crate::{Cli, dispatch_with_cancel, error_code_name};

pub async fn run(state: &mut SessionState) -> ovstorage::Result<()> {
    let mut rl = DefaultEditor::new().map_err(map_rl)?;

    let history_path = history_file_path();
    if let Some(path) = &history_path {
        let _ = rl.load_history(path);
    }

    state.interactive = true;
    println!("type help for commands, quit to exit.");

    let mut last_interrupt_at: Option<std::time::Instant> = None;

    loop {
        let prompt = match &state.pwd {
            Some(pwd) => format!("{pwd}> "),
            None => "> ".to_string(),
        };
        let line = match rl.readline(&prompt) {
            Ok(line) => {
                last_interrupt_at = None;
                line
            }
            Err(ReadlineError::Interrupted) => {
                let now = std::time::Instant::now();
                match interrupt_decision(last_interrupt_at, now) {
                    InterruptDecision::Escalate => break,
                    InterruptDecision::Arm => {
                        eprintln!(
                            "Press Ctrl+C again within {}s to exit, or type 'quit'.",
                            INTERRUPT_WINDOW.as_secs(),
                        );
                        last_interrupt_at = Some(now);
                        continue;
                    }
                }
            }
            Err(ReadlineError::Eof) => break, // Ctrl+D: clean exit
            Err(err) => return Err(map_rl(err)),
        };

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let _ = rl.add_history_entry(line.as_str());

        if trimmed == "quit" {
            break;
        }

        let words = match shell_words::split(&line) {
            Ok(w) => w,
            Err(err) => {
                eprintln!("parse error: {err}");
                continue;
            }
        };

        // Bare `help` / `--help` / `-h` shows the REPL command list (terser
        // than clap's full top-level help). Anything more specific —
        // `help <cmd>` or `<cmd> --help` — falls through to clap, which
        // surfaces per-subcommand help via a DisplayHelp error.
        let bare_help = matches!(
            words.as_slice(),
            [only] if only == "help" || only == "--help" || only == "-h"
        );
        if bare_help {
            print_repl_help();
            continue;
        }

        let mut argv = Vec::with_capacity(words.len() + 1);
        argv.push("ovstorage".to_string());
        argv.extend(words);

        match Cli::try_parse_from(&argv) {
            Ok(cli) => match cli.command {
                Some(command) => {
                    if let Err(err) = dispatch_with_cancel(command, state).await {
                        eprintln!("{}: {}", error_code_name(err.code()), err.message());
                    }
                }
                None => print_repl_help(),
            },
            Err(err) => {
                // clap pre-formats parser errors; print verbatim and keep the loop alive.
                eprint!("{err}");
            }
        }
    }

    if let Some(path) = &history_path {
        let _ = rl.save_history(path);
    }
    Ok(())
}

fn print_repl_help() {
    let cmd = Cli::command();
    let visible: Vec<_> = cmd.get_subcommands().filter(|s| !s.is_hide_set()).collect();
    let width = visible
        .iter()
        .map(|s| s.get_name().len())
        .max()
        .unwrap_or(0);

    println!("Commands:");
    for sub in visible {
        let about = sub.get_about().map(ToString::to_string).unwrap_or_default();
        let about = about.lines().next().unwrap_or("");
        println!(
            "  {name:<width$}  {about}",
            name = sub.get_name(),
            width = width,
            about = about,
        );
    }
    println!();
    println!("Type `quit` (or Ctrl+D) to exit.");
}

fn history_file_path() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))?;
    let dir = base.join("ovstorage");
    let _ = std::fs::create_dir_all(&dir);
    Some(dir.join("repl_history"))
}

fn map_rl(err: ReadlineError) -> Error {
    Error::new(
        ErrorCode::Internal,
        format!("interactive shell error: {err}"),
    )
}
