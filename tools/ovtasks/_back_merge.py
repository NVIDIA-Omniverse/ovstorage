# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Whether `main` can take the back-merge pull request as a merge commit.

`release-finalize` merges the published tag into a `back-merge/vX.Y.Z` branch
and opens a pull request; merging that pull request with a merge commit is what
makes `vX.Y.Z` an ancestor of `main` in the case the arrangement exists for --
where `main` moved during the candidate window, so the tag is on a history of
its own. Squash and rebase both give `main` that tree and the version bump
without the merge commit, and the loss is silent: the `patch == 0` invariant is
restored either way and the next `release-open` unblocks. It resurfaces one
release later, as a back-merge conflict between two histories that were never
joined. (When `main` and the tag are at the same SHA the tag is already an
ancestor and the merge is a no-op, so that release loses nothing whichever
button is pressed. The button still has to exist for the releases that are not
that case, and nothing tells the two apart at configuration time.)

Whether the merge-commit button exists at all is repository and ruleset
configuration rather than a choice at merge time, so it is checked before the
release is published rather than discovered after.

GitHub publishes no "which merge methods can this branch take" answer, so this
is an enumeration of the ways it can take the merge commit away, and an
enumeration is only as good as its list. The list, and where each is read:

- the repository's `allow_merge_commit`, from `repos/{repo}`;
- a `required_linear_history` rule on `main`;
- `allowed_merge_methods` on a pull-request rule targeting `main`, which
  restricts the buttons independently of the repository setting;
- a `merge_queue` rule targeting `main`, whose `merge_method` parameter
  replaces the maintainer's choice entirely.

The last three come from `repos/{repo}/rules/branches/main`, read to its last
page: that endpoint is paginated, and a restricting rule past the first page
is a restriction this check would otherwise report as absent. An absent
`allow_merge_commit`, and a merge-queue rule that names no method, are each a
refusal rather than a pass. A pull-request rule carrying no `allowed_merge_methods`
is the separate case of a rule declining to restrict the methods, and is
accepted.

Two things it does not see. Classic branch protection carries its own
`required_linear_history`, and it is not reported by the rules endpoint; the
endpoint that does report it needs `Administration: read`, which this
workflow's `GITHUB_TOKEN` cannot be granted -- a GitHub App installation token
can hold that permission, so the limit is this credential rather than every
credential a workflow could use. (This repository configures `main` through
rulesets: `repos/{repo}/branches/main/protection` answers 404 "Branch not
protected" while five rulesets are active.) And with the merge commit on offer
alongside squash and rebase, nothing in the API constrains which button a
maintainer presses -- the pull request body and RELEASING.md name the required
one, and this check is what removes the case where it is not on offer.

`allow_merge_commit` is reported to a token with push access -- measured
against four repositories, present for the two where `permissions.push` is
true (`permissions.admin` false in both) and absent for the two where it is
false. `release-finalize` holds `contents: write`, which is push access, and
that is why the check runs from that workflow rather than from `release-open`'s
read-only preflight.
"""

from __future__ import annotations

from _repo import TaskError, capture

MERGE_COMMIT_FIELD = "allow_merge_commit"
LINEAR_HISTORY_RULE = "required_linear_history"
PULL_REQUEST_RULE = "pull_request"
ALLOWED_METHODS_PARAMETER = "allowed_merge_methods"
MERGE_METHOD = "merge"
MERGE_QUEUE_RULE = "merge_queue"
QUEUE_METHOD_PARAMETER = "merge_method"
QUEUE_MERGE_METHOD = "MERGE"

DOC_POINTER = "See RELEASING.md, Required Branch Protection."

# The rules endpoint is paginated.  100 is the REST API's maximum page size,
# and the limit bounds the walk at 10,000 rules -- far past any ruleset
# arrangement, and a refusal rather than an unbounded loop if that is wrong.
PAGE_SIZE = 100
PAGE_LIMIT = 100


def assert_merge_commit_available(
    repository: str, settings: dict, main_rules: list[dict]
) -> None:
    """Refuse unless `main` can take a merge commit in `repository`.

    ``settings`` is the repository object GitHub returns and ``main_rules`` the
    rules active on `main`, each with its ``type`` and ``parameters``. Both are
    passed in so the decision is separable from the API calls that supply it.
    """
    if MERGE_COMMIT_FIELD not in settings:
        raise TaskError(
            f"{repository}: GitHub did not report `{MERGE_COMMIT_FIELD}`. It is "
            "reported to a token with push access, so read the setting by hand "
            "and find out why this token did not get it before releasing: the "
            "back-merge pull request has to be merged with a merge commit. "
            f"{DOC_POINTER}"
        )
    if settings[MERGE_COMMIT_FIELD] is not True:
        raise TaskError(
            f"{repository} does not allow merge commits, so the back-merge "
            "pull request `release-finalize` opens at the end of this release "
            "cannot be merged in the way the release history depends on. "
            "Enable **Allow merge commits** in the repository's settings. "
            "Squash and rebase give `main` the release tree without the "
            "release point, and the next back-merge conflicts on two "
            f"histories that were never joined. {DOC_POINTER}"
        )

    for rule in main_rules:
        if rule.get("type") == LINEAR_HISTORY_RULE:
            raise TaskError(
                f"{repository} requires linear history on `main`, which "
                "forbids the merge commit the back-merge pull request has to "
                "land as. Drop that rule from `main`'s ruleset, or the "
                f"release point is not recorded in `main`'s history. {DOC_POINTER}"
            )

    # A pull-request rule can carry `allowed_merge_methods`, which restricts
    # the buttons independently of the repository setting above.  The parameter
    # is optional: a rule without it restricts nothing.  More than one
    # pull-request rule can apply to a branch, and each one restricts on its
    # own, so every one of them has to offer the merge commit.
    for rule in main_rules:
        if rule.get("type") != PULL_REQUEST_RULE:
            continue
        parameters = rule.get("parameters")
        if not isinstance(parameters, dict):
            continue
        if ALLOWED_METHODS_PARAMETER not in parameters:
            continue
        allowed = parameters[ALLOWED_METHODS_PARAMETER]
        if not isinstance(allowed, list):
            raise TaskError(
                f"{repository}: `main`'s pull-request rule reports "
                f"`{ALLOWED_METHODS_PARAMETER}` as {allowed!r}, which is not a "
                f"list of merge methods. {DOC_POINTER}"
            )
        if MERGE_METHOD not in allowed:
            raise TaskError(
                f"{repository}: `main`'s pull-request rule allows only "
                f"{', '.join(str(method) for method in allowed) or 'nothing'}, "
                "so the back-merge pull request cannot be merged as a merge "
                f"commit. Add `{MERGE_METHOD}` to that rule's "
                f"`{ALLOWED_METHODS_PARAMETER}`. {DOC_POINTER}"
            )

    # A merge-queue rule takes the choice away from the maintainer: the queue
    # merges with the method the rule names.  `MERGE` still produces the merge
    # commit the release point needs, so it is accepted; the pull request body
    # tells the reviewer to press a button that a queue would replace with
    # "Merge when ready", which is a difference in the instruction rather than
    # in the history it produces.
    for rule in main_rules:
        if rule.get("type") != MERGE_QUEUE_RULE:
            continue
        parameters = rule.get("parameters")
        method = parameters.get(QUEUE_METHOD_PARAMETER) if isinstance(
            parameters, dict
        ) else None
        if method != QUEUE_MERGE_METHOD:
            raise TaskError(
                f"{repository}: `main` has a merge-queue rule whose "
                f"`{QUEUE_METHOD_PARAMETER}` is {method!r}. The queue merges "
                "with that method and the maintainer does not choose, so the "
                "back-merge pull request does not land as a merge commit. Set "
                f"it to `{QUEUE_MERGE_METHOD}`, or take `main` out of the "
                f"merge queue. {DOC_POINTER}"
            )


def _gh_json(args: list[str], label: str):
    import json

    out = capture(["gh", "api", *args], label=label)
    try:
        return json.loads(out)
    except ValueError as err:
        raise TaskError(f"{label} did not return JSON: {err}") from err


def _gh_json_all_pages(path: str, label: str) -> list:
    """Every page of a paginated `gh api` list endpoint, concatenated.

    The rules endpoint is paginated -- measured against this repository, a
    request with `per_page=1` answers with a `Link` header carrying `rel="next"`
    and `rel="last"` -- and `gh api` fetches one page unless asked. An
    unpaginated read of a restricting ruleset that sits past the first page
    reports the restriction as absent, which is a PASS on the configuration
    this check exists to refuse.

    The paging is written out here rather than delegated to `gh api
    --paginate` for two reasons. `--paginate` concatenates the pages' JSON
    arrays into a stream that is not itself a JSON document, so it needs
    `--slurp` or a re-wrap; and `--slurp` is not available on every `gh` a
    runner or an operator may hold. Requesting `page=N` explicitly asks for
    nothing beyond the REST API itself, and each response parses on its own.

    An EMPTY page ends the walk, not a short one. A short page looks like the
    end only if the server honoured the `per_page` that was asked for; a proxy
    or an API that clamps the page size below `PAGE_SIZE` makes every page
    short, and stopping on the first one reads a prefix while reporting a
    pass -- the same defect this paging exists to remove, in a new spelling.
    Asking until a page comes back empty costs one extra request and assumes
    nothing about the page size actually served. `PAGE_LIMIT` bounds the walk
    so an endpoint that never empties fails loudly instead of looping forever.

    Entries are type-checked per page, and the refusal names the page, because
    a message naming the unpaginated path sends the reader to a request that
    was never made.
    """
    pages = []
    for page in range(1, PAGE_LIMIT + 1):
        query = f"{path}?per_page={PAGE_SIZE}&page={page}"
        entries = _gh_json([query], f"{label} (page {page})")
        if not isinstance(entries, list):
            raise TaskError(f"{label} (page {page}) did not return a list")
        if not entries:
            return pages
        for entry in entries:
            if not isinstance(entry, dict):
                raise TaskError(
                    f"{label} (page {page}) returned an entry that is not an "
                    f"object: {entry!r}"
                )
        pages.extend(entries)
    raise TaskError(
        f"{label} was still answering entries at page {PAGE_LIMIT}; refusing "
        f"to read further rather than judge `main` on a partial ruleset. "
        f"{DOC_POINTER}"
    )


def _line(version: str, label: str) -> tuple[int, int]:
    """The `(major, minor)` of ``version``, or a refusal.

    Refusing a version this cannot read is the point. The caller turns the
    answer into "does this release advance `main`", and a default for an
    unreadable version would answer that question without having been able to.
    """
    parts = version.strip().split(".")
    if len(parts) < 2:
        raise TaskError(
            f"{label} is {version!r}, which has no major.minor to compare."
        )
    try:
        return int(parts[0]), int(parts[1])
    except ValueError as err:
        raise TaskError(
            f"{label} is {version!r}, whose major.minor is not numeric: {err}"
        ) from err


def back_merge_applies(released_version: str, main_version: str) -> bool:
    """Whether finalizing ``released_version`` advances `main`.

    `release-finalize` back-merges the published tag into `main` and bumps
    `main` to the next minor. That is the arrangement for the newest line. A
    patch cut on an older line (Operation A) is finalized while `main` has
    already moved to a later minor, and back-merging it would conflict on every
    version surface and could move `main` backwards -- so that release opens no
    pull request and never touches `main`, and is complete once the release
    branch is bumped to its next patch.

    Both the merge-commit precondition and the back-merge step ask this one
    question, and they ask it here rather than each deciding for itself:
    a precondition that refused a release the back-merge never runs for would
    block a hotfix on an older line over a setting that release does not use.
    """
    released = _line(released_version, "the released version")
    main = _line(main_version, "`main`'s version")
    return released >= main


def report_back_merge_applies(released_version: str, main_version: str) -> None:
    """Print the classification as a shell-readable `true`/`false`."""
    applies = back_merge_applies(released_version, main_version)
    print("true" if applies else "false")


def fetch_and_assert(repository: str) -> None:
    settings = _gh_json([f"repos/{repository}"], f"gh api repos/{repository}")
    if not isinstance(settings, dict):
        raise TaskError(f"gh api repos/{repository} did not return an object")
    rules = _gh_json_all_pages(
        f"repos/{repository}/rules/branches/main",
        f"gh api repos/{repository}/rules/branches/main",
    )
    assert_merge_commit_available(repository, settings, rules)
    print(f"{repository}: `main` can take the back-merge as a merge commit")


def assert_back_merge_mergeable() -> None:
    import os

    repository = os.environ.get("GITHUB_REPOSITORY", "").strip()
    if repository == "":
        raise TaskError(
            "GITHUB_REPOSITORY is unset; this check reads the repository's "
            "merge settings and has no other way to name the repository"
        )
    fetch_and_assert(repository)
