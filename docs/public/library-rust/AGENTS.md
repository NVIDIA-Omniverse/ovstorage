<!--
SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# Agent routing: Rust library callers

Use `ovstorage::Stack` as the application handle and `ovstorage::Layer` as the
typed operational contract.

## Construction

- `Stack::builder(root_name) -> StackBuilder` starts an explicit composition.
- Add `LayerSpec::backend`, `LayerSpec::wrapper`, and `LayerSpec::router` nodes.
- Register `BackendFactory`, `WrapperFactory`, and `RouterFactory` values.
- Add `LayerConnectionRequest` values before `build().await`.
- `layers::register_default_layer_factories` registers exactly the built-in
  `file` backend.
- `load_layer_plugin` and `load_layer_plugins_from_dir` load ABI-v2 factories.
- `StackConfig` is the shared `[ovstorage]` TOML schema; graph shape is data.

The built Stack is immutable. Rebuild a new Stack when composition changes.

## Calling operations

- `Layer` takes typed `Request<T>` envelopes plus optional cancellation.
- `ovstorage::ext::LayerExt` provides ergonomic URL-plus-options helpers.
- Names such as `stat` overlap intentionally; use UFCS when both traits apply.
- The Stack canonicalizes addresses at entry.
- Check `RootInfo.capabilities` before optional operations.
- Put retry, redirect following, caches, aliases, and copy/rename fallback in
  explicit wrapper Layers.

## Plugin loading

Call `init_auth_substrate` before Rust-side plugin loading — `load_layer_plugin`
fails without it. Loading a cdylib is unsafe and must be limited
to trusted paths. Storage plugins use only the ABI-v2 Layer contract.

## Verification

Run focused crate tests while editing, then the repo-required `make verify` and
the relevant test target. Keep public examples aligned with the actual graph
and factory APIs.
