// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

pub fn access_ops_to_ffi(value: AccessOps) -> ffi::AccessOps {
    ffi::AccessOps {
        read: value.read,
        write: value.write,
        delete: value.delete,
        update_metadata: value.update_metadata,
    }
}

pub fn access_ops_from_ffi(value: ffi::AccessOps) -> AccessOps {
    AccessOps {
        read: value.read,
        write: value.write,
        delete: value.delete,
        update_metadata: value.update_metadata,
    }
}
