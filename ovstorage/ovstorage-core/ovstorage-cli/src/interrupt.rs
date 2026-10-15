// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared timing logic for the Ctrl+C double-tap state machine. Both the
//! REPL idle-prompt loop and the in-command `dispatch_with_cancel`
//! wrapper consume the same helper so the 10s-window semantics stay
//! consistent across contexts.

use std::time::{Duration, Instant};

/// Window in which a follow-up Ctrl+C escalates from "arm" to "exit".
pub(crate) const INTERRUPT_WINDOW: Duration = Duration::from_secs(10);

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum InterruptDecision {
    /// First Ctrl+C (or follow-up after the window expired). Caller
    /// should arm the flag and print its context-appropriate hint.
    Arm,
    /// Second Ctrl+C within the window. Caller should escalate (clean
    /// exit at the prompt; `exit(130)` in the middle of a command).
    Escalate,
}

/// Given the timestamp of the previous Ctrl+C (or `None` if no recent
/// press) and the current instant, decide whether the next press is an
/// arm or an escalate.
pub(crate) fn interrupt_decision(previous: Option<Instant>, now: Instant) -> InterruptDecision {
    match previous {
        Some(t) if now.duration_since(t) < INTERRUPT_WINDOW => InterruptDecision::Escalate,
        _ => InterruptDecision::Arm,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_press_arms() {
        let now = Instant::now();
        assert_eq!(interrupt_decision(None, now), InterruptDecision::Arm);
    }

    #[test]
    fn second_press_inside_window_escalates() {
        let earlier = Instant::now();
        let now = earlier + Duration::from_secs(5);
        assert_eq!(
            interrupt_decision(Some(earlier), now),
            InterruptDecision::Escalate
        );
    }

    #[test]
    fn second_press_at_window_boundary_arms() {
        let earlier = Instant::now();
        let now = earlier + INTERRUPT_WINDOW;
        assert_eq!(
            interrupt_decision(Some(earlier), now),
            InterruptDecision::Arm
        );
    }

    #[test]
    fn second_press_beyond_window_arms() {
        let earlier = Instant::now();
        let now = earlier + Duration::from_secs(11);
        assert_eq!(
            interrupt_decision(Some(earlier), now),
            InterruptDecision::Arm
        );
    }
}
