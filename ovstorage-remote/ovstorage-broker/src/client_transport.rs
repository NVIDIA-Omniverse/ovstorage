// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

#[async_trait::async_trait]
impl BrokerClientTransport for Broker {
    async fn list_address_roots(&self) -> ovstorage::Result<Vec<ovstorage::AddressRoot>> {
        let context = default_context();
        Broker::list_address_roots(self, &context).await
    }

    async fn stat(&self, address: Url, options: StatOptions) -> ovstorage::Result<ObjectInfo> {
        let context = default_context();
        Broker::stat(self, &context, address, options).await
    }

    async fn read(
        &self,
        address: Url,
        options: ovstorage::ReadOptions,
    ) -> ovstorage::Result<ovstorage_plugin::ReadResult> {
        let context = default_context();
        match Broker::read(self, &context, address, options).await? {
            BrokerReadOutcome::Bytes { info, bytes } => {
                Ok(ovstorage_plugin::ReadResult::Bytes { bytes, info })
            }
            BrokerReadOutcome::Stream { info, stream } => {
                Ok(ovstorage_plugin::ReadResult::Stream { stream, info })
            }
            BrokerReadOutcome::Redirect(redirect) => {
                Ok(ovstorage_plugin::ReadResult::Redirect(redirect))
            }
        }
    }

    async fn write(
        &self,
        address: Url,
        body: Body,
        options: WriteOptions,
    ) -> ovstorage::Result<ovstorage_plugin::WriteStep> {
        let context = default_context();
        match Broker::write(self, &context, address, body, options).await? {
            BrokerWriteOutcome::Done(result) => Ok(ovstorage_plugin::WriteStep::Done(result)),
            BrokerWriteOutcome::Redirects(batch) => {
                Ok(ovstorage_plugin::WriteStep::Redirects(batch))
            }
        }
    }

    async fn write_redirect(
        &self,
        address: Url,
        options: WriteOptions,
    ) -> ovstorage::Result<WriteRedirectBatch> {
        let context = default_context();
        Broker::write_redirect(self, &context, address, options).await
    }

    async fn continue_write(
        &self,
        address: Url,
        redirects: WriteRedirectBatch,
        results: RedirectResultBatch,
    ) -> ovstorage::Result<ovstorage_plugin::WriteStep> {
        let context = default_context();
        Broker::continue_write(self, &context, address, redirects, results).await
    }

    async fn delete(
        &self,
        address: Url,
        options: ovstorage::DeleteOptions,
    ) -> ovstorage::Result<()> {
        let context = default_context();
        Broker::delete(self, &context, address, options).await
    }

    async fn list(
        &self,
        prefix: Url,
        options: ovstorage::ListOptions,
    ) -> ovstorage::Result<ovstorage::ListPage> {
        let context = default_context();
        Broker::list(self, &context, prefix, options).await
    }

    async fn list_versions(
        &self,
        address: Url,
        options: ovstorage::ListVersionsOptions,
    ) -> ovstorage::Result<Vec<ovstorage::ObjectInfo>> {
        let context = default_context();
        Broker::list_versions(self, &context, address, options).await
    }

    async fn get_latest_version(&self, address: Url) -> ovstorage::Result<ovstorage::ObjectInfo> {
        let context = default_context();
        Broker::get_latest_version(self, &context, address).await
    }

    async fn watch_directory(
        &self,
        prefix: Url,
        opts: ovstorage::WatchDirectoryOptions,
    ) -> ovstorage::Result<BrokerClientWatchDirectoryStream> {
        let context = default_context();
        Broker::watch_directory(self, &context, prefix, opts).await
    }

    async fn create_directory(
        &self,
        address: Url,
        options: ovstorage::CreateDirectoryOptions,
    ) -> ovstorage::Result<ObjectInfo> {
        let context = default_context();
        Broker::create_directory(self, &context, address, options).await
    }

    async fn delete_directory(
        &self,
        address: Url,
        options: ovstorage::DeleteDirectoryOptions,
    ) -> ovstorage::Result<()> {
        let context = default_context();
        Broker::delete_directory(self, &context, address, options).await
    }

    async fn copy(
        &self,
        source: Url,
        destination: Url,
        options: ovstorage::CopyOptions,
    ) -> ovstorage::Result<WriteResult> {
        let context = default_context();
        Broker::copy(self, &context, source, destination, options).await
    }

    async fn rename(
        &self,
        source: Url,
        destination: Url,
        options: ovstorage::RenameOptions,
    ) -> ovstorage::Result<()> {
        let context = default_context();
        Broker::rename(self, &context, source, destination, options).await
    }

    async fn update_metadata(
        &self,
        address: Url,
        options: ovstorage::UpdateMetadataOptions,
    ) -> ovstorage::Result<ObjectInfo> {
        let context = default_context();
        Broker::update_metadata(self, &context, address, options).await
    }

    async fn check_access(
        &self,
        address: Url,
        operations: AccessOps,
    ) -> ovstorage::Result<ovstorage::AccessDecision> {
        let context = default_context();
        Broker::check_access(self, &context, address, operations).await
    }
}
