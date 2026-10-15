// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

#[derive(Clone, Debug, Deserialize)]
pub struct BrokerDiscoveryConfig {
    #[serde(default = "default_discovery_name")]
    pub name: String,
    #[serde(default)]
    pub services: Vec<BrokerDiscoveryService>,
    #[serde(default)]
    pub auth_config: Option<BrokerAuthConfigDocument>,
    /// HTTP bind (`HOST:PORT`) for `/api/v1/services` +
    /// `/api/v1/auth-config`. Opt-in.
    #[serde(default)]
    pub bind: Option<String>,
    /// Endpoint advertised in `/api/v1/services` when `services` is
    /// empty. Set this when the broker sits behind a proxy whose
    /// public address differs from the broker's bind. Falls back to
    /// the bind-derived gRPC URL when unset.
    #[serde(default)]
    pub broker_endpoint: Option<String>,
}

impl Default for BrokerDiscoveryConfig {
    fn default() -> Self {
        Self {
            name: default_discovery_name(),
            services: Vec::new(),
            auth_config: None,
            bind: None,
            broker_endpoint: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct BrokerDiscoveryService {
    #[serde(rename = "type")]
    pub service_type: String,
    pub endpoint: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct BrokerAuthConfigDocument {
    pub openid_configuration: String,
    pub clients: BTreeMap<String, BrokerAuthClientDocument>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct BrokerAuthClientDocument {
    pub client_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct BrokerServicesDocument {
    pub name: String,
    pub services: Vec<BrokerDiscoveryService>,
}

#[derive(Clone)]
pub struct BrokerDiscoveryState {
    discovery: BrokerDiscoveryConfig,
    default_broker_endpoint: String,
}

impl BrokerDiscoveryState {
    pub fn new(discovery: BrokerDiscoveryConfig, default_broker_endpoint: String) -> Self {
        Self {
            discovery,
            default_broker_endpoint,
        }
    }
}

impl BrokerDiscoveryConfig {
    pub fn services_document(
        &self,
        default_broker_endpoint: &str,
    ) -> ovstorage::Result<BrokerServicesDocument> {
        let name = self.name.trim();
        if name.is_empty() {
            return Err(invalid_config("broker discovery name must not be empty"));
        }

        let services = if self.services.is_empty() {
            let endpoint = self
                .broker_endpoint
                .clone()
                .unwrap_or_else(|| default_broker_endpoint.to_string());
            vec![BrokerDiscoveryService {
                service_type: "ovstorage-broker".into(),
                endpoint,
            }]
        } else {
            self.services.clone()
        };

        for service in &services {
            if service.service_type.trim().is_empty() {
                return Err(invalid_config(
                    "broker discovery service type must not be empty",
                ));
            }
            validate_url("broker discovery service endpoint", &service.endpoint)?;
        }
        if !services
            .iter()
            .any(|service| service.service_type == "ovstorage-broker")
        {
            return Err(Error::new(
                ErrorCode::NotConfigured,
                "broker discovery services must include an ovstorage-broker entry",
            ));
        }

        Ok(BrokerServicesDocument {
            name: name.to_string(),
            services,
        })
    }

    pub fn auth_config_document(&self) -> ovstorage::Result<BrokerAuthConfigDocument> {
        let Some(document) = self.auth_config.clone() else {
            return Err(Error::new(
                ErrorCode::NotConfigured,
                "broker auth discovery is not configured",
            ));
        };
        validate_url(
            "broker auth discovery openid_configuration",
            &document.openid_configuration,
        )?;
        if !document.clients.contains_key("default") {
            return Err(Error::new(
                ErrorCode::NotConfigured,
                "broker auth discovery must include clients.default",
            ));
        }
        for (name, client) in &document.clients {
            if name.trim().is_empty() {
                return Err(invalid_config(
                    "broker auth discovery client name must not be empty",
                ));
            }
            if client.client_id.trim().is_empty() {
                return Err(invalid_config(
                    "broker auth discovery client_id must not be empty",
                ));
            }
        }
        Ok(document)
    }
}

pub fn broker_discovery_app(state: BrokerDiscoveryState) -> Router {
    Router::new()
        .route("/api/v1/services", get(discovery_services))
        .route("/api/v1/auth-config", get(discovery_auth_config))
        .with_state(state)
}

/// Discovery server handle; dropping shuts down the server.
pub struct BrokerDiscoveryServer {
    local_addr: std::net::SocketAddr,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
}

impl BrokerDiscoveryServer {
    pub fn local_addr(&self) -> std::net::SocketAddr {
        self.local_addr
    }

    /// Base URL for logging. Discovery is plaintext; TLS terminates at
    /// a reverse proxy.
    pub fn base_url(&self) -> String {
        format!("http://{}", self.local_addr)
    }
}

impl Drop for BrokerDiscoveryServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

/// Bind discovery to `bind` on a background thread with its own runtime;
/// drop-to-shutdown lifecycle matches `spawn_broker_grpc_tcp_listener`.
pub fn spawn_broker_discovery_http_listener(
    state: BrokerDiscoveryState,
    bind: &str,
) -> ovstorage::Result<BrokerDiscoveryServer> {
    let listener = std::net::TcpListener::bind(bind).map_err(|error| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("failed to bind broker discovery on '{bind}': {error}"),
        )
    })?;
    listener.set_nonblocking(true).map_err(|error| {
        Error::new(
            ErrorCode::Internal,
            format!("failed to set discovery listener nonblocking: {error}"),
        )
    })?;
    let local_addr = listener.local_addr().map_err(|error| {
        Error::new(
            ErrorCode::Internal,
            format!("failed to read discovery listener address: {error}"),
        )
    })?;
    tracing::info!(
        target: "ovstorage.broker.discovery",
        bind = %local_addr,
        "broker discovery listener started"
    );
    let app = broker_discovery_app(state);
    let (shutdown, shutdown_rx) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("ovs-disco".into())
        .spawn(move || {
            let Ok(runtime) = tokio::runtime::Runtime::new() else {
                return;
            };
            runtime.block_on(async move {
                let Ok(listener) = tokio::net::TcpListener::from_std(listener) else {
                    return;
                };
                let _ = axum::serve(listener, app)
                    .with_graceful_shutdown(async {
                        let _ = shutdown_rx.await;
                    })
                    .await;
                tracing::info!(
                    target: "ovstorage.broker.discovery",
                    "broker discovery listener stopped"
                );
            });
        })
        .expect("failed to spawn thread");
    Ok(BrokerDiscoveryServer {
        local_addr,
        shutdown: Some(shutdown),
    })
}

async fn discovery_services(State(state): State<BrokerDiscoveryState>) -> Response {
    match state
        .discovery
        .services_document(&state.default_broker_endpoint)
    {
        Ok(document) => {
            tracing::debug!(
                target: "ovstorage.broker.discovery",
                broker_name = %document.name,
                service_count = document.services.len(),
                "discovery services document resolved"
            );
            Json(document).into_response()
        }
        Err(error) => http_error_response(error),
    }
}

async fn discovery_auth_config(State(state): State<BrokerDiscoveryState>) -> Response {
    match state.discovery.auth_config_document() {
        Ok(document) => Json(document).into_response(),
        Err(error) => http_error_response(error),
    }
}
