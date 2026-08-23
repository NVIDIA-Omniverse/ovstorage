# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the release-finalize precondition that `main` can take the
back-merge as a merge commit.

The decision is a pure function over what GitHub reports, so every arm is
exercised here rather than in a workflow run: the repository setting off, a
linear-history rule on `main`, a pull-request rule whose `allowed_merge_methods`
omits `merge`, the field missing from the response, and the accepting case.
The API calls that supply the data are covered separately, for the shapes they
refuse.

The rule fixtures are shaped like the API's own answer for this repository's
`main` — a list of objects carrying `type` and, for the pull-request rule,
`parameters` — because a check that reduced them to type names alone would let
a squash-only ruleset through."""

import json

import pytest

import _back_merge
from _repo import TaskError

REPO = "example-org/example-repo"

MERGE_COMMITS_ON = {"allow_merge_commit": True, "allow_squash_merge": True}
MERGE_COMMITS_OFF = {"allow_merge_commit": False, "allow_squash_merge": True}

# The rule types GitHub reports for `main` on a repository configured the way
# this one is: a required pull request, required checks, and no force-push.
# None of them forbids a merge commit.
ORDINARY_MAIN_RULES = [
    {"type": "deletion"},
    {"type": "non_fast_forward"},
    {
        "type": "pull_request",
        "parameters": {
            "allowed_merge_methods": ["merge", "squash", "rebase"],
            "required_approving_review_count": 1,
        },
    },
    {"type": "required_status_checks"},
]


def _main_rules_allowing(methods):
    """`main`'s rules with the pull-request rule restricted to ``methods``."""
    return [
        {**rule, "parameters": {**rule["parameters"], "allowed_merge_methods": methods}}
        if rule["type"] == "pull_request"
        else rule
        for rule in ORDINARY_MAIN_RULES
    ]


def test_merge_commits_enabled_and_no_linear_history_is_accepted():
    _back_merge.assert_merge_commit_available(
        REPO, MERGE_COMMITS_ON, ORDINARY_MAIN_RULES
    )


def test_merge_commits_disabled_is_refused():
    with pytest.raises(TaskError) as err:
        _back_merge.assert_merge_commit_available(
            REPO, MERGE_COMMITS_OFF, ORDINARY_MAIN_RULES
        )
    message = str(err.value)
    assert REPO in message
    assert "Allow merge commits" in message


def test_squash_only_repository_is_refused_even_with_no_rules_at_all():
    # An empty ruleset is not the accepting case: the repository setting is
    # what decides whether the button exists.
    with pytest.raises(TaskError):
        _back_merge.assert_merge_commit_available(REPO, MERGE_COMMITS_OFF, [])


def test_required_linear_history_on_main_is_refused():
    with pytest.raises(TaskError) as err:
        _back_merge.assert_merge_commit_available(
            REPO,
            MERGE_COMMITS_ON,
            ORDINARY_MAIN_RULES + [{"type": "required_linear_history"}],
        )
    assert "linear history" in str(err.value)


def test_missing_field_is_refused_rather_than_taken_as_permission():
    # A response without the field is an unmodelled input. Reading it as
    # "nothing unusual" is the failure this check exists to avoid.
    with pytest.raises(TaskError) as err:
        _back_merge.assert_merge_commit_available(REPO, {}, ORDINARY_MAIN_RULES)
    assert "allow_merge_commit" in str(err.value)


def test_a_truthy_non_true_value_is_refused():
    with pytest.raises(TaskError):
        _back_merge.assert_merge_commit_available(
            REPO, {"allow_merge_commit": "true"}, ORDINARY_MAIN_RULES
        )


def test_a_squash_only_pull_request_rule_is_refused():
    # The repository setting and the ruleset restrict the button
    # independently, so `allow_merge_commit: true` does not save this.
    with pytest.raises(TaskError) as err:
        _back_merge.assert_merge_commit_available(
            REPO, MERGE_COMMITS_ON, _main_rules_allowing(["squash"])
        )
    message = str(err.value)
    assert "allowed_merge_methods" in message
    assert "squash" in message


def test_a_rule_allowing_no_method_at_all_is_refused():
    with pytest.raises(TaskError):
        _back_merge.assert_merge_commit_available(
            REPO, MERGE_COMMITS_ON, _main_rules_allowing([])
        )


def test_a_rule_allowing_the_merge_commit_alongside_others_is_accepted():
    _back_merge.assert_merge_commit_available(
        REPO, MERGE_COMMITS_ON, _main_rules_allowing(["merge", "rebase"])
    )


def test_a_pull_request_rule_without_the_parameter_restricts_nothing():
    # The parameter is optional. Its absence is the rule declining to
    # restrict the methods, which is not the same input as an empty list.
    rules = [
        {"type": "pull_request", "parameters": {"required_approving_review_count": 1}}
    ]
    _back_merge.assert_merge_commit_available(REPO, MERGE_COMMITS_ON, rules)


def test_a_second_pull_request_rule_restricts_on_its_own():
    # More than one ruleset can target `main`; each restricts independently,
    # so an accepting rule beside a squash-only one is still a refusal.
    rules = _main_rules_allowing(["merge", "squash"]) + [
        {"type": "pull_request", "parameters": {"allowed_merge_methods": ["squash"]}}
    ]
    with pytest.raises(TaskError):
        _back_merge.assert_merge_commit_available(REPO, MERGE_COMMITS_ON, rules)


def test_a_non_list_allowed_merge_methods_is_refused():
    rules = [
        {"type": "pull_request", "parameters": {"allowed_merge_methods": "merge"}}
    ]
    with pytest.raises(TaskError) as err:
        _back_merge.assert_merge_commit_available(REPO, MERGE_COMMITS_ON, rules)
    assert "not a list" in str(err.value)


def test_a_rule_whose_parameters_are_absent_is_not_a_refusal():
    _back_merge.assert_merge_commit_available(
        REPO, MERGE_COMMITS_ON, [{"type": "pull_request"}]
    )


def test_a_squash_merge_queue_on_main_is_refused():
    # A merge queue replaces the maintainer's choice with the rule's method.
    rules = ORDINARY_MAIN_RULES + [
        {"type": "merge_queue", "parameters": {"merge_method": "SQUASH"}}
    ]
    with pytest.raises(TaskError) as err:
        _back_merge.assert_merge_commit_available(REPO, MERGE_COMMITS_ON, rules)
    assert "merge-queue" in str(err.value)


def test_a_rebase_merge_queue_on_main_is_refused():
    rules = ORDINARY_MAIN_RULES + [
        {"type": "merge_queue", "parameters": {"merge_method": "REBASE"}}
    ]
    with pytest.raises(TaskError):
        _back_merge.assert_merge_commit_available(REPO, MERGE_COMMITS_ON, rules)


def test_a_merge_queue_without_a_method_is_refused_rather_than_assumed():
    rules = ORDINARY_MAIN_RULES + [{"type": "merge_queue", "parameters": {}}]
    with pytest.raises(TaskError):
        _back_merge.assert_merge_commit_available(REPO, MERGE_COMMITS_ON, rules)


def test_a_merge_queue_merging_with_a_merge_commit_is_accepted():
    rules = ORDINARY_MAIN_RULES + [
        {"type": "merge_queue", "parameters": {"merge_method": "MERGE"}}
    ]
    _back_merge.assert_merge_commit_available(REPO, MERGE_COMMITS_ON, rules)


def test_no_merge_queue_rule_is_accepted():
    # The ordinary fixture carries no merge-queue rule; this pins that the
    # merge-queue arm refuses on the rule's method rather than on its absence.
    _back_merge.assert_merge_commit_available(
        REPO, MERGE_COMMITS_ON, ORDINARY_MAIN_RULES
    )


RULES_PATH = f"repos/{REPO}/rules/branches/main"


def _page_path(page):
    """The paged rules URL the fetch is required to request for ``page``."""
    return (
        f"{RULES_PATH}?per_page={_back_merge.PAGE_SIZE}&page={page}"
    )


def _paged(*pages):
    """Responses for a rules walk that answers ``pages``, then runs out.

    Keyed by the exact paged URL, so a fetch that stopped asking for pages --
    or asked without `per_page` -- raises `unexpected gh api path` here rather
    than quietly reading a prefix of the ruleset. A dropped page is otherwise
    indistinguishable from a clean ruleset, which is the defect these fixtures
    exist for.

    A terminating empty page is appended, because the walk stops on an empty
    page rather than a short one: a server that clamps the page size makes
    every page short, and stopping there would read a prefix and report a pass.
    """
    served = [*pages, []]
    return {_page_path(n): json.dumps(page) for n, page in enumerate(served, 1)}


def _full_page(rule):
    """A page of exactly `PAGE_SIZE` rules, the last of which is ``rule``.

    A full page is what tells the walk to ask for another, so a fixture that
    puts a restriction on page two has to fill page one to be reached at all.
    """
    filler = [{"type": "required_status_checks"}] * (_back_merge.PAGE_SIZE - 1)
    return [*filler, rule]


def _fake_capture(responses):
    """Stand in for `_repo.capture`, keyed by the API path in the argv."""

    def capture(args, **kwargs):
        path = args[-1]
        if path not in responses:
            raise AssertionError(f"unexpected gh api path {path}")
        return responses[path]

    return capture


def test_fetch_reads_both_endpoints_and_accepts(monkeypatch, capsys):
    monkeypatch.setattr(
        _back_merge,
        "capture",
        _fake_capture(
            {
                f"repos/{REPO}": json.dumps(MERGE_COMMITS_ON),
                **_paged(ORDINARY_MAIN_RULES),
            }
        ),
    )
    _back_merge.fetch_and_assert(REPO)
    assert "merge commit" in capsys.readouterr().out


def test_a_squash_only_rule_on_the_second_page_is_refused(monkeypatch):
    # The finding this paging exists for: page one is unremarkable and full,
    # and the rule that removes the merge commit is on page two. Reading one
    # page reports the accepting configuration that page one describes.
    monkeypatch.setattr(
        _back_merge,
        "capture",
        _fake_capture(
            {
                f"repos/{REPO}": json.dumps(MERGE_COMMITS_ON),
                **_paged(
                    _full_page({"type": "non_fast_forward"}),
                    [
                        {
                            "type": "pull_request",
                            "parameters": {"allowed_merge_methods": ["squash"]},
                        }
                    ],
                ),
            }
        ),
    )
    with pytest.raises(TaskError) as err:
        _back_merge.fetch_and_assert(REPO)
    assert "allowed_merge_methods" in str(err.value)


def test_a_squash_merge_queue_on_the_second_page_is_refused(monkeypatch):
    monkeypatch.setattr(
        _back_merge,
        "capture",
        _fake_capture(
            {
                f"repos/{REPO}": json.dumps(MERGE_COMMITS_ON),
                **_paged(
                    _full_page({"type": "deletion"}),
                    [
                        {
                            "type": "merge_queue",
                            "parameters": {"merge_method": "SQUASH"},
                        }
                    ],
                ),
            }
        ),
    )
    with pytest.raises(TaskError) as err:
        _back_merge.fetch_and_assert(REPO)
    assert "merge-queue" in str(err.value)


def test_a_linear_history_rule_on_the_third_page_is_refused(monkeypatch):
    # Two full pages, so the walk has to continue past a page it has already
    # accepted rather than stopping at the first restriction-free one.
    monkeypatch.setattr(
        _back_merge,
        "capture",
        _fake_capture(
            {
                f"repos/{REPO}": json.dumps(MERGE_COMMITS_ON),
                **_paged(
                    _full_page({"type": "deletion"}),
                    _full_page({"type": "non_fast_forward"}),
                    [{"type": "required_linear_history"}],
                ),
            }
        ),
    )
    with pytest.raises(TaskError) as err:
        _back_merge.fetch_and_assert(REPO)
    assert "linear" in str(err.value)


def test_a_short_page_does_not_end_the_walk(monkeypatch):
    # A short page is not the end: an endpoint or proxy that serves fewer
    # entries than `per_page` asked for makes EVERY page short, and treating
    # the first one as the last reads a prefix of the ruleset while reporting
    # a pass -- the defect this paging exists to remove. Here every page is
    # short, and the restriction sits on the third; a walk that stopped at the
    # first short page would accept.
    monkeypatch.setattr(
        _back_merge,
        "capture",
        _fake_capture(
            {
                f"repos/{REPO}": json.dumps(MERGE_COMMITS_ON),
                **_paged(
                    [{"type": "deletion"}],
                    [{"type": "non_fast_forward"}],
                    [{"type": "required_linear_history"}],
                ),
            }
        ),
    )
    with pytest.raises(TaskError) as err:
        _back_merge.fetch_and_assert(REPO)
    assert "linear" in str(err.value)


def test_an_empty_page_ends_the_walk(monkeypatch):
    # And the walk stops there rather than asking on. If it asked for the page
    # after the empty one the fixture has no answer and `_fake_capture` says
    # so, which pins the stopping rule rather than merely tolerating it.
    monkeypatch.setattr(
        _back_merge,
        "capture",
        _fake_capture(
            {
                f"repos/{REPO}": json.dumps(MERGE_COMMITS_ON),
                **_paged(ORDINARY_MAIN_RULES),
            }
        ),
    )
    _back_merge.fetch_and_assert(REPO)


def test_an_endpoint_that_never_runs_out_of_pages_is_refused(monkeypatch):
    # Rather than looping forever, or judging `main` on the prefix it managed
    # to read.
    def capture(args, **kwargs):
        if args[-1] == f"repos/{REPO}":
            return json.dumps(MERGE_COMMITS_ON)
        return json.dumps(_full_page({"type": "deletion"}))

    monkeypatch.setattr(_back_merge, "capture", capture)
    with pytest.raises(TaskError) as err:
        _back_merge.fetch_and_assert(REPO)
    assert "partial ruleset" in str(err.value)


def test_fetch_refuses_when_the_repository_response_is_not_an_object(monkeypatch):
    monkeypatch.setattr(
        _back_merge,
        "capture",
        _fake_capture({f"repos/{REPO}": json.dumps([1, 2, 3])}),
    )
    with pytest.raises(TaskError):
        _back_merge.fetch_and_assert(REPO)


def test_fetch_refuses_on_a_response_that_is_not_json(monkeypatch):
    monkeypatch.setattr(
        _back_merge, "capture", _fake_capture({f"repos/{REPO}": "not json"})
    )
    with pytest.raises(TaskError):
        _back_merge.fetch_and_assert(REPO)


def test_fetch_refuses_when_a_rule_entry_is_not_an_object(monkeypatch):
    # Dropping a non-object entry instead would narrow what the decision sees
    # without saying so, which is how a restriction goes unread.
    monkeypatch.setattr(
        _back_merge,
        "capture",
        _fake_capture(
            {
                f"repos/{REPO}": json.dumps(MERGE_COMMITS_ON),
                **_paged([{"type": "pull_request"}, "deletion"]),
            }
        ),
    )
    with pytest.raises(TaskError):
        _back_merge.fetch_and_assert(REPO)


def test_fetch_refuses_when_a_rules_page_is_not_a_list(monkeypatch):
    monkeypatch.setattr(
        _back_merge,
        "capture",
        _fake_capture(
            {
                f"repos/{REPO}": json.dumps(MERGE_COMMITS_ON),
                _page_path(1): json.dumps({"type": "x"}),
            }
        ),
    )
    with pytest.raises(TaskError):
        _back_merge.fetch_and_assert(REPO)


def test_fetch_refuses_when_a_later_page_is_not_a_list(monkeypatch):
    # The guard covers every page, not only the first one it happened to read.
    monkeypatch.setattr(
        _back_merge,
        "capture",
        _fake_capture(
            {
                f"repos/{REPO}": json.dumps(MERGE_COMMITS_ON),
                _page_path(1): json.dumps(_full_page({"type": "deletion"})),
                _page_path(2): json.dumps({"type": "x"}),
            }
        ),
    )
    with pytest.raises(TaskError) as err:
        _back_merge.fetch_and_assert(REPO)
    assert "page 2" in str(err.value)


def test_unset_repository_environment_is_refused(monkeypatch):
    monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
    with pytest.raises(TaskError) as err:
        _back_merge.assert_back_merge_mergeable()
    assert "GITHUB_REPOSITORY" in str(err.value)


def test_blank_repository_environment_is_refused(monkeypatch):
    # The message is asserted, not just the exception type. Whitespace that
    # reached `gh api repos/   ` would also raise `TaskError` -- from the
    # subprocess, after a real network call -- so a bare `pytest.raises` here
    # passes whether or not the name is trimmed before it is used.
    monkeypatch.setenv("GITHUB_REPOSITORY", "   ")
    with pytest.raises(TaskError) as err:
        _back_merge.assert_back_merge_mergeable()
    assert "GITHUB_REPOSITORY" in str(err.value)


# --- Whether the release advances main at all ------------------------------
#
# The merge-commit precondition guards the back-merge pull request, so it must
# not refuse a release that opens none.  A patch cut on an older line opens
# none.


@pytest.mark.parametrize(
    "released, main",
    [
        ("0.2.1", "0.3.0"),  # the newest line has moved on by a minor
        ("0.2.5", "0.10.0"),  # 10 > 2 numerically, though not as a string
        ("1.4.0", "2.0.0"),  # and by a major
    ],
)
def test_a_patch_on_an_older_line_does_not_advance_main(released, main):
    assert _back_merge.back_merge_applies(released, main) is False


@pytest.mark.parametrize(
    "released, main",
    [
        ("0.2.1", "0.2.0"),  # the ordinary case: main carries the open minor
        ("0.3.0", "0.3.0"),  # main already at the released minor
        ("0.10.0", "0.9.0"),  # again numerically rather than lexically
        ("2.0.0", "1.9.0"),
    ],
)
def test_the_newest_line_advances_main(released, main):
    assert _back_merge.back_merge_applies(released, main) is True


def test_the_patch_component_does_not_decide_it():
    # The comparison is over the line, not the point on it: main's patch is
    # 0 by the `patch == 0` invariant, and a released patch of 7 on the same
    # minor still advances main.
    assert _back_merge.back_merge_applies("0.3.7", "0.3.0") is True


@pytest.mark.parametrize("version", ["", "0", "main", "0.x.1", "x.0.1"])
def test_a_version_it_cannot_read_is_refused_rather_than_defaulted(version):
    # Both argument positions, because a default on either one answers
    # "does this release advance main" without having been able to.
    with pytest.raises(TaskError):
        _back_merge.back_merge_applies(version, "0.3.0")
    with pytest.raises(TaskError):
        _back_merge.back_merge_applies("0.3.0", version)


@pytest.mark.parametrize(
    "released, main, expected",
    [("0.3.0", "0.2.0", "true"), ("0.2.1", "0.3.0", "false")],
)
def test_the_reported_form_is_the_one_the_workflow_compares(
    released, main, expected, capsys
):
    # The workflow tests this against the string `true`, and gates a step on
    # `env.BACK_MERGE_APPLIES == 'true'`.  Anything else -- `True`, `1`, an
    # empty line -- reads as "does not apply" at both sites without failing.
    _back_merge.report_back_merge_applies(released, main)
    assert capsys.readouterr().out == f"{expected}\n"
