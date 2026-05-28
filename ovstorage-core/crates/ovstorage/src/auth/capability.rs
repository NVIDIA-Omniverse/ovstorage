// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Resolve [`InteractiveAuthCapability`] for a [`crate::Library`].
//!
//! Precedence: builder > env var (`OV_INTERACTIVE_AUTH_CAPABILITY=
//! browser|headless|none`) > config file > smart default. Invalid env
//! values warn + fall through rather than failing startup.
//!
//! Smart-default detection ([`detect_default_capability`]) errs toward
//! the less-capable mode when a positive GUI signal is missing — a
//! wrong `Headless` just asks the user to open a URL, while a wrong
//! `Browser` is a broken auth flow on a server.

use std::collections::HashMap;

use ovstorage_plugin::InteractiveAuthCapability;

pub const ENV_VAR: &str = "OV_INTERACTIVE_AUTH_CAPABILITY";

/// Abstraction over `std::env::var` so tests can drive detection from
/// a `HashMap` snapshot. Production code uses [`StdEnv`].
pub trait EnvSource {
    fn get(&self, key: &str) -> Option<String>;
}

pub struct StdEnv;

impl EnvSource for StdEnv {
    fn get(&self, key: &str) -> Option<String> {
        std::env::var(key).ok()
    }
}

#[derive(Default, Clone)]
pub struct MockEnv {
    inner: HashMap<String, String>,
}

impl MockEnv {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.inner.insert(key.into(), value.into());
        self
    }
}

impl EnvSource for MockEnv {
    fn get(&self, key: &str) -> Option<String> {
        self.inner.get(key).cloned()
    }
}

/// Recognises `browser` / `headless` / `none` (case-insensitive).
/// Returns `None` for anything else; callers decide warn vs. fall
/// through.
pub fn parse_capability_str(value: &str) -> Option<InteractiveAuthCapability> {
    match value.trim().to_ascii_lowercase().as_str() {
        "browser" => Some(InteractiveAuthCapability::Browser),
        "headless" => Some(InteractiveAuthCapability::Headless),
        "none" => Some(InteractiveAuthCapability::None),
        _ => None,
    }
}

/// `None` for unset or unrecognised; unrecognised also logs a warning.
pub fn read_env_capability<E: EnvSource>(env: &E) -> Option<InteractiveAuthCapability> {
    let raw = env.get(ENV_VAR)?;
    if let Some(parsed) = parse_capability_str(&raw) {
        return Some(parsed);
    }
    tracing::warn!(
        env_var = ENV_VAR,
        value = %raw,
        "ignoring unrecognised {ENV_VAR} value (expected one of: browser, headless, none); \
         falling through to next capability source"
    );
    None
}

fn is_truthy(raw: &str) -> bool {
    matches!(
        raw.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// Smart default from OS signals. First match wins:
///
/// 1. `CI` truthy → `None`.
/// 2. `SSH_CONNECTION` / `SSH_CLIENT` set → `Headless` (no loopback
///    listener possible across the SSH boundary).
/// 3. Linux: neither `DISPLAY` nor `WAYLAND_DISPLAY` → `Headless`.
/// 4. Windows: `SESSIONNAME` absent or `Services-*` (Session 0) →
///    `Headless`.
/// 5. macOS / fallthrough: `Browser`.
pub fn detect_default_capability<E: EnvSource>(env: &E) -> InteractiveAuthCapability {
    if let Some(raw) = env.get("CI")
        && is_truthy(&raw)
    {
        return InteractiveAuthCapability::None;
    }
    if env.get("SSH_CONNECTION").is_some() || env.get("SSH_CLIENT").is_some() {
        return InteractiveAuthCapability::Headless;
    }
    detect_platform_default(env)
}

#[cfg(target_os = "linux")]
fn detect_platform_default<E: EnvSource>(env: &E) -> InteractiveAuthCapability {
    if env.get("DISPLAY").is_none() && env.get("WAYLAND_DISPLAY").is_none() {
        InteractiveAuthCapability::Headless
    } else {
        InteractiveAuthCapability::Browser
    }
}

#[cfg(target_os = "windows")]
fn detect_platform_default<E: EnvSource>(env: &E) -> InteractiveAuthCapability {
    match env.get("SESSIONNAME") {
        None => InteractiveAuthCapability::Headless,
        Some(name) if name.starts_with("Services-") => InteractiveAuthCapability::Headless,
        Some(_) => InteractiveAuthCapability::Browser,
    }
}

#[cfg(target_os = "macos")]
fn detect_platform_default<E: EnvSource>(_env: &E) -> InteractiveAuthCapability {
    InteractiveAuthCapability::Browser
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
fn detect_platform_default<E: EnvSource>(_env: &E) -> InteractiveAuthCapability {
    InteractiveAuthCapability::Browser
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_capability_str_recognises_three_shapes() {
        assert_eq!(
            parse_capability_str("browser"),
            Some(InteractiveAuthCapability::Browser)
        );
        assert_eq!(
            parse_capability_str("headless"),
            Some(InteractiveAuthCapability::Headless)
        );
        assert_eq!(
            parse_capability_str("none"),
            Some(InteractiveAuthCapability::None)
        );
        // Case-insensitive + trim — operators get a small grace.
        assert_eq!(
            parse_capability_str("  Browser  "),
            Some(InteractiveAuthCapability::Browser)
        );
        assert_eq!(parse_capability_str("garbage"), None);
        assert_eq!(parse_capability_str(""), None);
    }

    #[test]
    fn read_env_unset_returns_none() {
        let env = MockEnv::new();
        assert_eq!(read_env_capability(&env), None);
    }

    #[test]
    fn read_env_invalid_returns_none() {
        // Falls through to next source rather than erroring; the
        // builder's resolution chain treats `None` as "advance".
        let env = MockEnv::new().with(ENV_VAR, "totally-bogus");
        assert_eq!(read_env_capability(&env), None);
    }

    #[test]
    fn read_env_valid_returns_parsed() {
        let env = MockEnv::new().with(ENV_VAR, "headless");
        assert_eq!(
            read_env_capability(&env),
            Some(InteractiveAuthCapability::Headless)
        );
    }

    #[test]
    fn detect_ci_truthy_yields_none_capability() {
        for ci in ["1", "true", "TRUE", "yes", "on"] {
            let env = MockEnv::new()
                .with("CI", ci)
                // Force a strong GUI signal so platform default would
                // otherwise return Browser — proves CI takes priority.
                .with("DISPLAY", ":0")
                .with("WAYLAND_DISPLAY", "wayland-0")
                .with("SESSIONNAME", "Console");
            assert_eq!(
                detect_default_capability(&env),
                InteractiveAuthCapability::None,
                "CI={ci} must yield None"
            );
        }
    }

    #[test]
    fn detect_ci_falsy_does_not_short_circuit() {
        // Linux build: a non-truthy `CI` still falls through to the
        // platform branch; with both DISPLAY + WAYLAND_DISPLAY set we
        // expect Browser.
        let env = MockEnv::new()
            .with("CI", "false")
            .with("DISPLAY", ":0")
            .with("WAYLAND_DISPLAY", "wayland-0")
            .with("SESSIONNAME", "Console");
        let detected = detect_default_capability(&env);
        // Linux + Windows + macOS all return Browser here; only the
        // generic-other branch could differ, and CI wouldn't trigger.
        assert_eq!(detected, InteractiveAuthCapability::Browser);
    }

    #[test]
    fn detect_ssh_connection_yields_headless() {
        let env = MockEnv::new()
            .with("SSH_CONNECTION", "10.0.0.1 22 10.0.0.2 51000")
            .with("DISPLAY", ":0")
            .with("WAYLAND_DISPLAY", "wayland-0")
            .with("SESSIONNAME", "Console");
        assert_eq!(
            detect_default_capability(&env),
            InteractiveAuthCapability::Headless
        );
    }

    #[test]
    fn detect_ssh_client_yields_headless() {
        let env = MockEnv::new().with("SSH_CLIENT", "10.0.0.1 51000 22");
        assert_eq!(
            detect_default_capability(&env),
            InteractiveAuthCapability::Headless
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn detect_linux_no_display_yields_headless() {
        let env = MockEnv::new();
        assert_eq!(
            detect_default_capability(&env),
            InteractiveAuthCapability::Headless
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn detect_linux_with_x11_yields_browser() {
        let env = MockEnv::new().with("DISPLAY", ":0");
        assert_eq!(
            detect_default_capability(&env),
            InteractiveAuthCapability::Browser
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn detect_linux_with_wayland_yields_browser() {
        let env = MockEnv::new().with("WAYLAND_DISPLAY", "wayland-0");
        assert_eq!(
            detect_default_capability(&env),
            InteractiveAuthCapability::Browser
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn detect_linux_with_both_displays_yields_browser() {
        let env = MockEnv::new()
            .with("DISPLAY", ":0")
            .with("WAYLAND_DISPLAY", "wayland-0");
        assert_eq!(
            detect_default_capability(&env),
            InteractiveAuthCapability::Browser
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn detect_windows_no_session_yields_headless() {
        let env = MockEnv::new();
        assert_eq!(
            detect_default_capability(&env),
            InteractiveAuthCapability::Headless
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn detect_windows_services_session_yields_headless() {
        let env = MockEnv::new().with("SESSIONNAME", "Services-0x3e7");
        assert_eq!(
            detect_default_capability(&env),
            InteractiveAuthCapability::Headless
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn detect_windows_console_session_yields_browser() {
        let env = MockEnv::new().with("SESSIONNAME", "Console");
        assert_eq!(
            detect_default_capability(&env),
            InteractiveAuthCapability::Browser
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn detect_macos_yields_browser_with_no_signals() {
        let env = MockEnv::new();
        assert_eq!(
            detect_default_capability(&env),
            InteractiveAuthCapability::Browser
        );
    }
}
