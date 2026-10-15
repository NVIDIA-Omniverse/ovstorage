<!--
SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# RFC-NNNN: <short title>

<!-- NNNN is this RFC's PR number. Guess it as (latest PR number + 1) when you
     create the branch; fix it with a fixup commit if another PR claimed it. -->

- **Status:** Proposed
- **Depends-on:** —
- **Supersedes:** —
- **Superseded-by:** —

> One-paragraph summary: what this RFC decides and why it matters.

## Context

The problem being solved and the constraints that apply. Name the PRD / SDD /
SRD sections this touches.

## Decision

The shape we are committing to. This section is the durable decision record:
once the RFC is **Accepted**, its content stops changing.

## Consequences

What this enables, what it breaks, and what migration it forces. Call out any
**plugin C ABI**, public Rust API, wire-contract, or Python-surface impact
explicitly — those are the changes GOVERNANCE requires an RFC for.

## Alternatives considered

What else was on the table and why it lost.

---

### Lifecycle

`Proposed` → (flip to `Accepted` in the final commit before this PR merges) →
`Accepted` → (implementation lands, durable detail folded into the Software
Design Document) → `Implemented`. A later RFC may set this
one's **Superseded-by** and move it to `Superseded`. The file never moves —
status lives in this header and the [index](README.md), so links and
`Depends-on` references stay stable for the RFC's whole life.
