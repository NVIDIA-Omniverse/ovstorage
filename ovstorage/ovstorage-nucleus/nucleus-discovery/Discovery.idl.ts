// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { Capabilities } from "@plugins/capabilities";
import { ClientVersion, Version } from "@plugins/versions";

interface DiscoveryRegistration {
  /**
   * Registers a new service with specified connection settings and interfaces.
   * The discovery keeps a subscription to ensure that registered service is still available.
   * The service is removed from discovery as soon as it stops receiving health checks from the subscription.
   *
   * You can use `register_unsafe` to register a service without a subscription and health checks.
   * @version 2
   */
  register(manifest: Manifest, version?: ClientVersion): HealthCheck[];

  /**
   * Registers a new service without a health checking.
   * It's a service responsibility to call `unregister_unsafe` when the provided functions become not available.
   * @version 2
   */
  register_unsafe(manifest: Manifest, version?: ClientVersion): HealthCheck;

  /**
   * Removes the service registered with `register_unsafe` from the discovery.
   * @version 2
   */
  unregister_unsafe(manifest: Manifest, version?: ClientVersion): HealthCheck;
}


interface DiscoverySearch {
  /**
   * Finds an entry for specified origin and interface.
   * A query can specify the required capabilities, connection settings and other metadata.
   * @version 2
   */
  find(query: DiscoverInterfaceQuery, version?: ClientVersion): SearchResult;

  /**
   * Retrieves all registered interfaces for this discovery service.
   * @version 2
   */
  find_all(version?: ClientVersion): SearchResult[];
}

type DiscoverInterfaceQuery = {
  service_interface: ServiceInterface;
  supported_transport?: SupportedTransport[];
  meta?: Meta;
}

type ServiceInterface = {
  origin: string;
  name: string;
  capabilities?: Capabilities;
}

type SupportedTransport = {
  name: string;
  meta?: Meta;
}

type SearchResult = {
  found: boolean;
  version?: Version;
  service_interface?: ServiceInterface;
  transport?: TransportSettings;
  meta?: Meta;
}

type TransportSettings = {
  name: string;
  params: string;
  meta: Meta;
}

type Meta = {
  [field: string]: string;
}

type Manifest = {
  interfaces: ServiceInterfaceMap;
  transport: TransportSettings;
  token: string;
  meta?: Meta;
}

type ServiceInterfaceMap = {
  [interface_name: string]: ServiceInterface;
}


type HealthCheck = {
  status: HealthStatus;
  time: string;
  version?: Version;
  message?: string;
  meta?: Meta;
}

enum HealthStatus {
  OK = "OK",

  // Informs that discovery service has been closed.
  // The response can contain service settings that should be used for new registration.
  Closed = "CLOSED",
  Denied = "DENIED",
  AlreadyExists = "ALREADY_EXISTS",
  InvalidSettings = "INVALID_SETTINGS",
  InvalidCapabilities = "INVALID_CAPABILITIES",
}