// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tonic-generated bindings for the Omniverse Storage Service.
//!
//! Each `nvidia.omniverse.storage.*.v1alpha` service compiles into its own
//! `OUT_DIR` subtree so prost emits separate `google.protobuf` stanzas
//! per service (avoids module collisions on `Timestamp`, `Value`, etc.).
//! The plugin imports per-service modules directly:
//!
//! ```ignore
//! use ovstorage_services_protos::nvidia::omniverse::storage::fileobject::v1alpha as fo;
//! ```

#![allow(clippy::all)]

pub mod google {
    pub mod protobuf {
        tonic::include_proto!("fileobject-v1alpha/google.protobuf");
        tonic::include_proto!("metadata-v1alpha/google.protobuf");
    }
}

pub mod nvidia {
    pub mod omniverse {
        pub mod notifications {
            pub mod consumer {
                pub mod v1beta {
                    tonic::include_proto!(
                        "notifications-v1beta/nvidia.omniverse.notifications.consumer.v1beta"
                    );
                }
            }
        }
        pub mod storage {
            pub mod capabilities {
                pub mod v1alpha {
                    tonic::include_proto!(
                        "capabilities-v1alpha/nvidia.omniverse.storage.capabilities.v1alpha"
                    );
                }
            }
            pub mod fileobject {
                pub mod v1alpha {
                    tonic::include_proto!(
                        "fileobject-v1alpha/nvidia.omniverse.storage.fileobject.v1alpha"
                    );
                }
            }
            pub mod filefolder {
                pub mod v1alpha {
                    tonic::include_proto!(
                        "filefolder-v1alpha/nvidia.omniverse.storage.filefolder.v1alpha"
                    );
                }
            }
            pub mod metadata {
                pub mod v1alpha {
                    tonic::include_proto!(
                        "metadata-v1alpha/nvidia.omniverse.storage.metadata.v1alpha"
                    );
                }
            }
            pub mod versioning {
                pub mod v1alpha {
                    tonic::include_proto!(
                        "versioning-v1alpha/nvidia.omniverse.storage.versioning.v1alpha"
                    );
                }
            }
        }
    }
}
