// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use ovstorage::{Error, ErrorCode};
use ovstorage_broker::{
    BrokerDiscoveryServer, BrokerDiscoveryState, BrokerGrpcServer, BrokerHandle,
    BrokerListenerConfig, BrokerTransport, LifecycleController, PrometheusServer,
    apply_listen_override, broker_handle, build_broker_from_config, build_zero_config_broker,
    check_listen_override, install_recorders, load_broker_config_file,
    spawn_broker_discovery_http_listener, spawn_broker_grpc_named_pipe_listener_with_handle,
    spawn_broker_grpc_tcp_listener_with_handle_and_config,
    spawn_broker_grpc_unix_socket_listener_with_handle, spawn_prometheus_listener,
    validate_broker_config_for_startup, zero_config_broker_config,
};

#[tokio::main]
async fn main() {
    let _tracing = match ovstorage::init_tracing_from_env() {
        Ok(guard) => guard,
        Err(error) if error.code() == ErrorCode::AlreadyExists => ovstorage::TracingGuard::noop(),
        Err(error) => {
            eprintln!("{}: {}", error_code_name(error.code()), error.message());
            std::process::exit(exit_code(error.code()));
        }
    };
    if let Err(error) = run().await {
        eprintln!("{}: {}", error_code_name(error.code()), error.message());
        std::process::exit(exit_code(error.code()));
    }
}

async fn run() -> ovstorage::Result<()> {
    let Args {
        config_path,
        listen_override,
    } = parse_args()?;

    // Explicit --config wins; else ./ovstorage.toml; else zero-config
    // mode (UDS / npipe + sandbox dir + allow-all toml authz).
    let resolved_config_path = match config_path {
        Some(p) => Some(p),
        None => {
            let cwd_default = "./ovstorage.toml";
            if std::path::Path::new(cwd_default).is_file() {
                Some(cwd_default.to_string())
            } else {
                None
            }
        }
    };

    let (broker, mut config, source_path) = match resolved_config_path {
        Some(path) => {
            let config = load_broker_config_file(&path)?;
            // Fail fast on an empty stack: an operator config that declares no
            // `[ovstorage.layers]` must not start a listener that serves nothing.
            // The build path re-checks this uniformly; the explicit call here
            // fails before dlopen.
            // Zero-config mode (the `None` arm) declares its own explicit forward
            // graph, so it passes the same guard.
            ovstorage::host::require_configured_stack(&config.ovstorage)?;
            let broker = build_broker_from_config(&config).await?;
            (broker, config, Some(path))
        }
        None => {
            let (config, sandbox) = zero_config_broker_config()?;
            println!(
                "zero-config mode: serving file:/ from {} (alias: broker:///)",
                sandbox.display()
            );
            tracing::info!(
                target: "ovstorage.broker.lifecycle",
                event = "zero_config",
                sandbox = %sandbox.display(),
                "no config file found; running with zero-config defaults"
            );
            let broker = build_zero_config_broker(&config, &sandbox).await?;
            (broker, config, None)
        }
    };

    // CLI override stamps the listener bind so a single dev-time
    // `--listen` flag still works without editing config. We re-run
    // startup validation afterwards: build_broker_from_config*
    // validated the original config, but the override above can
    // introduce non-loopback plaintext binds or OAuth/listener
    // mismatches that the unmodified config passed.
    if let Some(bind) = listen_override.clone() {
        // Fail closed BEFORE the listener is spawned: a zero-config broker
        // serves anonymous allow-all on a local socket, so a transport-changing
        // `--listen` (UDS → TCP) override would expose that surface to the
        // network. Refuse it unless the operator supplied an explicit config
        // with its own auth.
        check_listen_override(
            source_path.is_none(),
            config
                .listener
                .as_ref()
                .map(|listener| listener.bind.as_str()),
            &bind,
        )?;
        apply_listen_override(&mut config, bind);
        validate_broker_config_for_startup(&config)?;
    }

    let listener = config.listener.as_ref().ok_or_else(|| {
        invalid(
            "broker config has no [listener]; configure one or pass --listen \
             (UDS path / pipe:NAME / host:port)",
        )
    })?;

    let handle: BrokerHandle = broker_handle(broker);
    let server = spawn_listener(handle.clone(), listener)?;
    let endpoint = server.endpoint_url();
    println!("serving broker gRPC on {endpoint}");
    tracing::info!(
        target: "ovstorage.broker.lifecycle",
        event = "startup",
        version = env!("CARGO_PKG_VERSION"),
        endpoint = %endpoint,
        "broker started"
    );

    let _discovery: Option<BrokerDiscoveryServer> = match config.discovery.bind.as_deref() {
        Some(bind) => {
            let advertise = if server.endpoint_url().starts_with("grpc+tcp://")
                || server.endpoint_url().starts_with("grpc+tls://")
            {
                server.endpoint_url()
            } else {
                config.discovery.broker_endpoint.clone().ok_or_else(|| {
                    invalid(
                        "[discovery] bind is set but the listener is not a gRPC TCP listener; \
                         set [discovery] broker_endpoint to advertise an external endpoint",
                    )
                })?
            };
            let state = BrokerDiscoveryState::new(config.discovery.clone(), advertise);
            let server = spawn_broker_discovery_http_listener(state, bind)?;
            println!("serving broker discovery on {}", server.base_url());
            Some(server)
        }
        None => None,
    };

    // Install metrics recorder; Prometheus scrape is opt-in via
    // `[observability] prometheus_bind`. OTLP push via `otlp_endpoint`.
    let (prom_handle, _metrics_guard) = install_recorders(config.observability.as_ref())?;
    let _prometheus: Option<PrometheusServer> = match config
        .observability
        .as_ref()
        .and_then(|o| o.prometheus_bind.as_deref())
    {
        Some(bind) => {
            let server = spawn_prometheus_listener(prom_handle, bind)?;
            println!("serving broker metrics on http://{}/metrics", server.bind);
            Some(server)
        }
        None => None,
    };

    let mut controller = LifecycleController::new(handle, vec![server]);
    if let Some(path) = source_path {
        controller = controller
            .with_config_path(PathBuf::from(&path))?
            .with_runtime_listener(config.listener.as_ref(), listen_override)?;
    }
    controller.run().await
}

struct Args {
    config_path: Option<String>,
    listen_override: Option<String>,
}

fn parse_args() -> ovstorage::Result<Args> {
    let mut config_path = None;
    let mut listen_override = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => {
                config_path = Some(
                    args.next()
                        .ok_or_else(|| invalid("missing path after --config"))?,
                );
            }
            "--listen" => {
                listen_override = Some(
                    args.next()
                        .ok_or_else(|| invalid("missing address after --listen"))?,
                );
            }
            "--help" | "-h" | "help" => {
                print_usage();
                std::process::exit(0);
            }
            other => return Err(invalid(format!("unknown argument '{other}'"))),
        }
    }
    Ok(Args {
        config_path,
        listen_override,
    })
}

fn spawn_listener(
    handle: BrokerHandle,
    listener: &BrokerListenerConfig,
) -> ovstorage::Result<BrokerGrpcServer> {
    match listener.transport()? {
        BrokerTransport::Tcp(addr) => {
            spawn_broker_grpc_tcp_listener_with_handle_and_config(handle, addr, listener)
        }
        BrokerTransport::UnixSocket(path) => {
            spawn_broker_grpc_unix_socket_listener_with_handle(handle, path, listener)
        }
        BrokerTransport::NamedPipe(name) => {
            spawn_broker_grpc_named_pipe_listener_with_handle(handle, name, listener)
        }
    }
}

fn print_usage() {
    eprintln!(
        "usage: ovstorage-broker [--config PATH] [--listen ADDRESS]\n\
         \n\
         Resolution: --config PATH > ./ovstorage.toml > zero-config defaults.\n\
         Zero-config mode binds a local UDS / named-pipe at a well-known path,\n\
         mounts file:/ at a sandbox dir under your data home, and allows the\n\
         OS user to do anything. Useful for `just want to play around`.\n\
         \n\
         --listen ADDRESS overrides [listener] bind. Accepts:\n\
           - /path/to/sock      (Unix domain socket)\n\
           - pipe:NAME          (Windows named pipe)\n\
           - host:port          (TCP)\n\
         \n\
         The broker validates and serves the configured gRPC API. Bad configs\n\
         surface as typed errors at startup. Use `ovstorage-cli --config PATH\n\
         list-routes` to inspect what a config would expose without serving."
    );
}

fn invalid(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::InvalidArgument, message)
}

fn error_code_name(code: ErrorCode) -> &'static str {
    match code {
        ErrorCode::NotFound => "NotFound",
        ErrorCode::AlreadyExists => "AlreadyExists",
        ErrorCode::PermissionDenied => "PermissionDenied",
        ErrorCode::DirectoryNotEmpty => "DirectoryNotEmpty",
        ErrorCode::InvalidArgument => "InvalidArgument",
        ErrorCode::Unsupported => "Unsupported",
        ErrorCode::NoRoute => "NoRoute",
        ErrorCode::BrokerUnavailable => "BrokerUnavailable",
        _ => "Error",
    }
}

fn exit_code(code: ErrorCode) -> i32 {
    match code {
        ErrorCode::NotFound => 2,
        ErrorCode::PermissionDenied => 3,
        ErrorCode::InvalidArgument => 7,
        ErrorCode::Unsupported => 6,
        ErrorCode::BrokerUnavailable => 13,
        _ => 1,
    }
}
