<!--
SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# RFCs

Design proposals for **substantive changes** to `ovstorage` — public API,
plugin C ABI, wire contracts, OV-PLC lifecycle, or cross-cutting architecture.
Per the project's governance rules, substantive changes require an RFC here (or
a lifecycle design doc) before implementation lands.

An RFC is a *decision* record, not a *spec*. The living how-it-works surface is
the Software Design Document; an Accepted RFC records what we chose and why, and
stops changing.

## How it works

1. Copy [`0000-template.md`](0000-template.md) to `NNNN-short-title.md`, where
   `NNNN` is the number this RFC's PR will receive — guess it as **(latest PR
   number + 1)**. Open the PR with **Status: Proposed**, add a row to the index
   below, and iterate in review. The open PR is the discussion vehicle. If
   another PR claimed your guessed number first, push a fixup commit renaming the
   file and updating the id.
2. As the **final commit before merge**, flip **Status: Proposed → Accepted** in
   both the header and the index row, then merge. The flip happens in the PR, not
   on `main`, so no bot needs write access to the default branch. (Don't merge an
   RFC you don't intend to accept — keep it open while it's still Proposed.)
3. As implementation lands, fold the durable detail into the Software Design
   Document and flip the RFC to **Implemented**.
4. A later RFC that replaces this one sets its own **Supersedes** and this one's
   **Superseded-by**; this one moves to **Superseded**.

The RFC number **is its PR number** — globally unique and never reused, so two
RFCs can never collide and an abandoned proposal never frees a number for reuse.
Numbers are therefore gappy and not strictly sequential; always cite an RFC by
its id, never by position. Files stay put for their whole life — status lives in
the header and this index, not in the path — so links and `Depends-on`
references never break.

## Index

| RFC | Title | Status | Depends-on |
| --- | --- | --- | --- |
| [0066](0066-layered-architecture.md) | Layered ovstorage | Implemented | — |
| [0395](0395-c-value-types-as-visible-structs.md) | C snapshot types as visible structs | Implemented | 0066 |
