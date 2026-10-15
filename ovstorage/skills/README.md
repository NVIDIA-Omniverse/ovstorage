<!--
SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: CC-BY-4.0
-->

# ovstorage Skills

This directory is the external-publication review surface for ovstorage agent
skills. Public skill names are product-scoped so they can be registered in a
shared catalog without colliding with other libraries.

User and operator skills cover the ovstorage library, MCP server, plugins,
and broker daemon. Contributor skills describe source-development and
conformance workflows; use them when working on the component sources.

## Groups

- `ovstorage-user-*` — runtime storage-client workflows. These are the only
  skills that should be considered for a future `pip install ovstorage`
  bundle.
- `ovstorage-operator-*` — daemon deployment, policy, monitoring, and
  debugging workflows. These ship in release archives and can be cataloged
  after public-safe review.
- `ovstorage-contributor-*` — source-tree workflows for repository developers.
  These stay repo-only unless the contribution posture changes.

Runtime wheels do not install skills today. Skills are distributed through the
source tree and release archives unless a future packaging decision says
otherwise.
