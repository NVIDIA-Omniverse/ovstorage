<!--
SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: CC-BY-4.0
-->

# ovstorage Skills

This directory is the external-publication review surface for ovstorage agent
skills. Public skill names are product-scoped so they can be registered in a
shared catalog without colliding with other libraries.

These skills cover the ovstorage library, MCP server, plugins, broker, and
repo workflows. They are not the deployment skills for the heavier
`ovstorage-services` Kubernetes stack; those remain under
`ovstorage-services/skills/` in source checkouts.

## Groups

- `ovstorage-user-*` — runtime storage-client workflows. These are the only
  skills that should be considered for a future `pip install ovstorage`
  bundle.
- `ovstorage-operator-*` — broker deployment, policy, monitoring, and
  debugging workflows. These ship in release archives and can be cataloged
  after public-safe review.
- `ovstorage-contributor-*` — source-tree workflows for repository developers.
  These stay repo-only unless the contribution posture changes.

Runtime wheels do not install skills today. Skills are distributed through the
source tree and release archives unless a future packaging decision says
otherwise.
