<!--
SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

**Client-driven write continuations are now tamper-evident at the broker RPC edge.** The broker seals every continuation sent to a remote client in an address-bound HMAC-SHA256 envelope and rejects edited, unsigned, foreign-key, or different-address continuations as `InvalidArgument` before dispatch. Broker replicas behind one endpoint must use the same `[continuation_seal] key_path`; without it, each process uses an independent random key and cannot continue another process's writes or preserve them across a restart. Replicas that emit raw continuations and replicas that require sealed continuations cannot exchange in-flight writes in either direction. During a rolling upgrade, drain redirected writes, route each write stickily to one compatible version, or expect repeated failures until every serving replica has upgraded; clients must restart affected writes, including writes already in flight before the upgrade.
