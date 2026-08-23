// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Authentication front-ends for the built-in combined auth layer. Each
//! sub-module resolves a [`crate::ResolvedPrincipal`] from one class of
//! credential material: [`jwt`] validates an OIDC bearer token against a
//! configured JWKS; [`peer`] maps OS peer credentials (`Uds`/`NamedPipe`) or the
//! host's current OS user (`dev_current_user`) to a principal.

pub(crate) mod jwt;
pub(crate) mod peer;
