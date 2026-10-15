<!--
SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

**Broker directory watches now have central admission limits, and broker-client
subscriptions share non-resumable upstream streams.** The broker admits at most
256 live watches per principal and 4,096 process-wide by default; excess opens
return `ResourceExhausted`. Raise those limits with positive
`max_watches_per_principal` and `max_watches_total` values on the broker-native
`[ovstorage.layers.watch_limit]` layer. Omit that broker-only table from a shared
configuration read by the CLI or REST host, which do not register this layer
kind. Within one broker-client connection, non-resumable watches for the same
resolved prefix now coalesce onto one recursive, metadata-inclusive gRPC stream;
roots advertising resumable watches continue to receive one dedicated stream
per logical subscription with its cursor and options unchanged.
