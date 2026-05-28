// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Scenario runner harness and report format. Verifies recorded SPI
//! call sequences against [`crate::ScenarioRegistry`] entries and
//! aggregates per-scenario outcomes for snapshot diffing.

use std::time::SystemTime;

use crate::recorder::ObservedCall;
use crate::scenarios::{ExpectedCall, FailureContract, Scenario, ScenarioRegistry};

/// One scenario's outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScenarioOutcome {
    Passed,
    Failed { reason: String },
    Skipped { reason: String },
}

/// One per-scenario report entry.
#[derive(Clone, Debug)]
pub struct ScenarioReport {
    pub name: &'static str,
    pub outcome: ScenarioOutcome,
    pub recorded: Vec<ObservedCall>,
    pub at: SystemTime,
}

impl ScenarioReport {
    pub fn passed(scenario: &Scenario, recorded: Vec<ObservedCall>) -> Self {
        Self {
            name: scenario.name,
            outcome: ScenarioOutcome::Passed,
            recorded,
            at: SystemTime::now(),
        }
    }

    pub fn failed(scenario: &Scenario, reason: String, recorded: Vec<ObservedCall>) -> Self {
        Self {
            name: scenario.name,
            outcome: ScenarioOutcome::Failed { reason },
            recorded,
            at: SystemTime::now(),
        }
    }

    pub fn skipped(scenario: &Scenario, reason: String) -> Self {
        Self {
            name: scenario.name,
            outcome: ScenarioOutcome::Skipped { reason },
            recorded: Vec::new(),
            at: SystemTime::now(),
        }
    }

    pub fn is_pass(&self) -> bool {
        matches!(self.outcome, ScenarioOutcome::Passed)
    }
}

/// Aggregate report across one conformance pass. A pass fails iff any
/// scenario `Failed`; `Skipped` requires an explicit reason but does
/// not fail.
#[derive(Clone, Debug, Default)]
pub struct ConformanceReport {
    pub entries: Vec<ScenarioReport>,
}

impl ConformanceReport {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, report: ScenarioReport) {
        self.entries.push(report);
    }

    pub fn passed(&self) -> usize {
        self.entries
            .iter()
            .filter(|r| matches!(r.outcome, ScenarioOutcome::Passed))
            .count()
    }

    pub fn failed(&self) -> usize {
        self.entries
            .iter()
            .filter(|r| matches!(r.outcome, ScenarioOutcome::Failed { .. }))
            .count()
    }

    pub fn skipped(&self) -> usize {
        self.entries
            .iter()
            .filter(|r| matches!(r.outcome, ScenarioOutcome::Skipped { .. }))
            .count()
    }

    /// True iff no scenario failed.
    pub fn ok(&self) -> bool {
        self.failed() == 0
    }

    /// Human-readable line-per-entry summary.
    pub fn render_human(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "conformance: {}/{} passed, {} skipped, {} failed\n",
            self.passed(),
            self.entries.len(),
            self.skipped(),
            self.failed(),
        ));
        for entry in &self.entries {
            match &entry.outcome {
                ScenarioOutcome::Passed => {
                    out.push_str(&format!("  PASS  {}\n", entry.name));
                }
                ScenarioOutcome::Skipped { reason } => {
                    out.push_str(&format!("  SKIP  {}  ({reason})\n", entry.name));
                }
                ScenarioOutcome::Failed { reason } => {
                    out.push_str(&format!("  FAIL  {}\n        {reason}\n", entry.name));
                }
            }
        }
        out
    }

    /// Stable JSON snapshot for regression diff. Format:
    /// `[{"name":"...","outcome":"passed|skipped|failed",
    ///   "reason":"...","calls":["stat",...]},...]`
    pub fn render_json(&self) -> String {
        let mut out = String::from("[");
        for (i, entry) in self.entries.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            let (outcome, reason) = match &entry.outcome {
                ScenarioOutcome::Passed => ("passed", String::new()),
                ScenarioOutcome::Failed { reason } => ("failed", reason.clone()),
                ScenarioOutcome::Skipped { reason } => ("skipped", reason.clone()),
            };
            out.push_str("{\"name\":");
            out.push_str(&json_string(entry.name));
            out.push_str(",\"outcome\":");
            out.push_str(&json_string(outcome));
            if !reason.is_empty() {
                out.push_str(",\"reason\":");
                out.push_str(&json_string(&reason));
            }
            out.push_str(",\"calls\":[");
            for (j, call) in entry.recorded.iter().enumerate() {
                if j > 0 {
                    out.push(',');
                }
                out.push_str(&json_string(call.method_name()));
            }
            out.push_str("]}");
        }
        out.push(']');
        out
    }
}

/// Verification harness for one [`ScenarioRegistry`].
pub struct ScenarioRunner<'a> {
    registry: &'a ScenarioRegistry,
}

impl<'a> ScenarioRunner<'a> {
    pub fn new(registry: &'a ScenarioRegistry) -> Self {
        Self { registry }
    }

    /// Look up a scenario by name.
    pub fn scenario(&self, name: &str) -> Option<&Scenario> {
        self.registry.get(name)
    }

    /// Verify a recorded call sequence against `expected_calls`.
    ///
    /// Recorded calls must appear in the expected order; intermediate
    /// calls are tolerated only when
    /// [`ExpectedCall::allow_extra`] is set on the surrounding entry.
    /// For [`FailureContract::Errors`], use [`Self::verify_with_failure`];
    /// this method only checks call ordering.
    pub fn verify_recorded(&self, name: &str, recorded: Vec<ObservedCall>) -> ScenarioReport {
        let Some(scenario) = self.scenario(name) else {
            return ScenarioReport {
                name: "<unknown>",
                outcome: ScenarioOutcome::Failed {
                    reason: format!("scenario `{name}` is not registered"),
                },
                recorded,
                at: SystemTime::now(),
            };
        };
        match check_call_sequence(scenario.expected_calls, &recorded) {
            Ok(()) => ScenarioReport::passed(scenario, recorded),
            Err(reason) => ScenarioReport::failed(scenario, reason, recorded),
        }
    }

    /// Verify call sequence + failure contract together.
    pub fn verify_with_failure(
        &self,
        name: &str,
        recorded: Vec<ObservedCall>,
        observed_error: Option<(String, ovstorage_plugin::ErrorCode)>,
    ) -> ScenarioReport {
        let Some(scenario) = self.scenario(name) else {
            return ScenarioReport {
                name: "<unknown>",
                outcome: ScenarioOutcome::Failed {
                    reason: format!("scenario `{name}` is not registered"),
                },
                recorded,
                at: SystemTime::now(),
            };
        };
        if let Err(reason) = check_call_sequence(scenario.expected_calls, &recorded) {
            return ScenarioReport::failed(scenario, reason, recorded);
        }
        match (&scenario.failure_contract, observed_error) {
            (FailureContract::Success, None) => ScenarioReport::passed(scenario, recorded),
            (FailureContract::Success, Some((m, c))) => ScenarioReport::failed(
                scenario,
                format!("scenario expected success but `{m}` returned {c:?}"),
                recorded,
            ),
            (FailureContract::Errors { method, code }, Some((m, c))) => {
                if &m == method && c == *code {
                    ScenarioReport::passed(scenario, recorded)
                } else {
                    ScenarioReport::failed(
                        scenario,
                        format!("expected error `{code:?}` on `{method}`, got `{c:?}` on `{m}`"),
                        recorded,
                    )
                }
            }
            (FailureContract::Errors { method, code }, None) => ScenarioReport::failed(
                scenario,
                format!("scenario expected error `{code:?}` on `{method}`, no error fired"),
                recorded,
            ),
        }
    }

    /// Skip a scenario with an explicit reason.
    pub fn skip(&self, name: &str, reason: impl Into<String>) -> ScenarioReport {
        let reason = reason.into();
        match self.scenario(name) {
            Some(s) => ScenarioReport {
                name: s.name,
                outcome: ScenarioOutcome::Skipped { reason },
                recorded: Vec::new(),
                at: SystemTime::now(),
            },
            None => ScenarioReport {
                name: "<unknown>",
                outcome: ScenarioOutcome::Skipped {
                    reason: format!("unknown scenario `{name}`: {reason}"),
                },
                recorded: Vec::new(),
                at: SystemTime::now(),
            },
        }
    }
}

fn check_call_sequence(expected: &[ExpectedCall], recorded: &[ObservedCall]) -> Result<(), String> {
    let mut record_idx = 0;
    for (i, want) in expected.iter().enumerate() {
        let mut found = None;
        while record_idx < recorded.len() {
            if recorded[record_idx].method_name() == want.method {
                found = Some(record_idx);
                record_idx += 1;
                break;
            }
            let prior_allows_same_method_extra = i > 0
                && expected[i - 1].allow_extra
                && recorded[record_idx].method_name() == expected[i - 1].method;
            if !prior_allows_same_method_extra {
                return Err(format!(
                    "unexpected call `{}` between `{}` and `{}` (recorded #{})",
                    recorded[record_idx].method_name(),
                    if i == 0 {
                        "<start>"
                    } else {
                        expected[i - 1].method
                    },
                    want.method,
                    record_idx
                ));
            }
            record_idx += 1;
        }
        if found.is_none() {
            return Err(format!(
                "expected `{}` was never observed (only saw {} calls)",
                want.method,
                recorded.len()
            ));
        }
    }
    if let Some(last) = expected.last() {
        while record_idx < recorded.len() {
            if !last.allow_extra || recorded[record_idx].method_name() != last.method {
                return Err(format!(
                    "unexpected trailing call `{}` after expected `{}`",
                    recorded[record_idx].method_name(),
                    last.method
                ));
            }
            record_idx += 1;
        }
    } else if !recorded.is_empty() {
        return Err(format!(
            "scenario forbids calls but observed `{}`",
            recorded[0].method_name()
        ));
    }
    Ok(())
}

fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scenarios::ScenarioRegistry;
    use ovstorage_plugin::{ErrorCode, Url};

    fn fixture_registry() -> ScenarioRegistry {
        ScenarioRegistry::with_defaults()
    }

    #[test]
    fn verify_recorded_passes_on_matching_sequence() {
        let registry = fixture_registry();
        let runner = ScenarioRunner::new(&registry);
        let recorded = vec![ObservedCall::Stat {
            target: Url::parse("test://demo/x").unwrap(),
        }];
        let report = runner.verify_recorded("stat-basic-objectinfo", recorded);
        assert!(matches!(report.outcome, ScenarioOutcome::Passed));
    }

    #[test]
    fn verify_recorded_fails_on_missing_call() {
        let registry = fixture_registry();
        let runner = ScenarioRunner::new(&registry);
        let report = runner.verify_recorded("write-done-inline", Vec::new());
        match report.outcome {
            ScenarioOutcome::Failed { reason } => {
                assert!(reason.contains("write"), "{reason}");
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn verify_recorded_fails_on_unexpected_call() {
        let registry = fixture_registry();
        let runner = ScenarioRunner::new(&registry);
        let recorded = vec![
            ObservedCall::Stat {
                target: Url::parse("test://demo/x").unwrap(),
            },
            ObservedCall::UpdateMetadata {
                target: Url::parse("test://demo/x").unwrap(),
            },
        ];
        let report = runner.verify_recorded("stat-basic-objectinfo", recorded);
        assert!(matches!(report.outcome, ScenarioOutcome::Failed { .. }));
    }

    #[test]
    fn verify_recorded_passes_on_negative_scenario_with_no_calls() {
        let registry = fixture_registry();
        let runner = ScenarioRunner::new(&registry);
        let report = runner.verify_recorded("metadata-unsupported-not-called", Vec::new());
        assert!(matches!(report.outcome, ScenarioOutcome::Passed));
    }

    #[test]
    fn verify_recorded_fails_negative_scenario_with_any_call() {
        let registry = fixture_registry();
        let runner = ScenarioRunner::new(&registry);
        let recorded = vec![ObservedCall::UpdateMetadata {
            target: Url::parse("test://demo/x").unwrap(),
        }];
        let report = runner.verify_recorded("metadata-unsupported-not-called", recorded);
        assert!(matches!(report.outcome, ScenarioOutcome::Failed { .. }));
    }

    #[test]
    fn verify_with_failure_matches_scripted_error() {
        let registry = fixture_registry();
        let runner = ScenarioRunner::new(&registry);
        let recorded = vec![ObservedCall::Stat {
            target: Url::parse("test://demo/missing").unwrap(),
        }];
        let report = runner.verify_with_failure(
            "stat-not-found",
            recorded,
            Some(("stat".into(), ErrorCode::NotFound)),
        );
        assert!(matches!(report.outcome, ScenarioOutcome::Passed));
    }

    #[test]
    fn verify_with_failure_fails_on_wrong_error_code() {
        let registry = fixture_registry();
        let runner = ScenarioRunner::new(&registry);
        let recorded = vec![ObservedCall::Stat {
            target: Url::parse("test://demo/missing").unwrap(),
        }];
        let report = runner.verify_with_failure(
            "stat-not-found",
            recorded,
            Some(("stat".into(), ErrorCode::Internal)),
        );
        assert!(matches!(report.outcome, ScenarioOutcome::Failed { .. }));
    }

    #[test]
    fn skip_records_reason() {
        let registry = fixture_registry();
        let runner = ScenarioRunner::new(&registry);
        let report = runner.skip("stat-basic-objectinfo", "no host wired");
        match report.outcome {
            ScenarioOutcome::Skipped { reason } => {
                assert_eq!(reason, "no host wired");
            }
            other => panic!("expected Skipped, got {other:?}"),
        }
    }

    #[test]
    fn report_aggregates_pass_skip_fail_counts() {
        let registry = fixture_registry();
        let runner = ScenarioRunner::new(&registry);
        let mut report = ConformanceReport::new();
        report.push(runner.verify_recorded(
            "stat-basic-objectinfo",
            vec![ObservedCall::Stat {
                target: Url::parse("test://demo/x").unwrap(),
            }],
        ));
        report.push(runner.skip("write-done-inline", "no library"));
        report.push(runner.verify_recorded("delete-existing-object", Vec::new()));

        assert_eq!(report.passed(), 1);
        assert_eq!(report.skipped(), 1);
        assert_eq!(report.failed(), 1);
        assert!(!report.ok());
        let json = report.render_json();
        assert!(json.contains("\"passed\""));
        assert!(json.contains("\"skipped\""));
        assert!(json.contains("\"failed\""));
        let human = report.render_human();
        assert!(human.contains("PASS"));
        assert!(human.contains("SKIP"));
        assert!(human.contains("FAIL"));
    }

    #[test]
    fn unknown_scenario_name_records_failure() {
        let registry = fixture_registry();
        let runner = ScenarioRunner::new(&registry);
        let report = runner.verify_recorded("not-a-real-scenario", Vec::new());
        assert!(matches!(report.outcome, ScenarioOutcome::Failed { .. }));
    }

    #[test]
    fn scenario_with_optional_extra_calls_passes_with_extras() {
        let registry = fixture_registry();
        let runner = ScenarioRunner::new(&registry);
        let recorded = vec![
            ObservedCall::List {
                prefix: Url::parse("test://demo/").unwrap(),
                recursive: false,
            },
            ObservedCall::List {
                prefix: Url::parse("test://demo/").unwrap(),
                recursive: true,
            },
        ];
        let report = runner.verify_recorded("list-one-level-vs-recursive", recorded);
        assert!(matches!(report.outcome, ScenarioOutcome::Passed));
    }

    #[test]
    fn allow_extra_does_not_admit_different_trailing_method() {
        let registry = fixture_registry();
        let runner = ScenarioRunner::new(&registry);
        let recorded = vec![
            ObservedCall::List {
                prefix: Url::parse("test://demo/").unwrap(),
                recursive: false,
            },
            ObservedCall::UpdateMetadata {
                target: Url::parse("test://demo/x").unwrap(),
            },
        ];
        let report = runner.verify_recorded("list-one-level-vs-recursive", recorded);
        assert!(matches!(report.outcome, ScenarioOutcome::Failed { .. }));
    }
}
