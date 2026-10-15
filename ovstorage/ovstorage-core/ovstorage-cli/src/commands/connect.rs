// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Interactive backend setup. Picks a backend, walks only the visible
//! config fields (skipping `advanced` ones), then offers the backend's
//! credential methods (skipping `advanced` ones). After the connection
//! is registered, drives `authenticate_connection` for methods that delegate
//! authentication to a flow, and surfaces auth events live to the user.
//!
//! Positional KIND + required-field values skip the wizard end-to-end
//! (secrets for the chosen auth method are still prompted at the TTY).
//! `--advanced` re-exposes hidden config fields and falls back to walking
//! every credential field individually (the legacy per-field path);
//! wizard-only — incompatible with positional fields.
//!
//! `reauth <name>` (also in this module) drives the same auth flow for an
//! *existing* connection — used when a refresh token expired or the user
//! wants to log in again without rebuilding the connection config.

use std::collections::{HashMap, HashSet};
use std::time::SystemTime;

use inquire::{Password, PasswordDisplayMode, Select, Text};
use ovstorage::ext::LayerExt;
use ovstorage::{
    AddressVisibility, AuthEvent, AuthReason, AuthenticateRequest, CancellationToken, ConfigField,
    ConfigFieldKind, ConfigValue, Connection, ConnectionAuthState, ConnectionId, ConnectionKey,
    CredentialField, CredentialMethod, EnumSource, Error, ErrorCode, Extensions,
    LayerConnectionRequest, LayerType, Request, RootInfo, Stack, StackSpec,
    StorageBackendKindDescriptor, UpdateConnectionCredentialsRequest, Url, config_value_to_toml,
};

use crate::commands::util::{Step, next_or_cancel};
use crate::session::{SessionConnection, SessionState};

pub struct Args {
    pub kind: Option<String>,
    pub fields: Vec<String>,
    pub auth: Option<String>,
    pub name: Option<String>,
    /// The layer instance to attach to, when the kind alone does not name one.
    pub target: Option<String>,
    pub advanced: bool,
}

/// What the selected credential path permits after registration.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum AuthenticationIntent {
    /// No complete credential was selected; the backend may offer a flow.
    BackendMayDrive,
    /// A field-bearing method supplied the intended identity.
    CredentialSupplied,
}

impl AuthenticationIntent {
    fn for_method(method: &CredentialMethod) -> Self {
        if method.fields.is_empty() {
            Self::BackendMayDrive
        } else {
            Self::CredentialSupplied
        }
    }

    fn should_drive(self, state: &ConnectionAuthState) -> bool {
        self == Self::BackendMayDrive && !is_settled(state)
    }

    fn supplied_credential_error(self, state: &ConnectionAuthState) -> Option<Error> {
        if self != Self::CredentialSupplied {
            return None;
        }
        match state {
            // These reasons are not credential verdicts. Keep a routable,
            // unconfirmed registration and let the ordinary unusable check
            // below decide whether the command can still succeed.
            ConnectionAuthState::AwaitingAuth {
                reason: AuthReason::BackendUnreachable | AuthReason::Unknown { .. },
                ..
            } => None,
            ConnectionAuthState::AwaitingAuth {
                last_attempt: Some(attempt),
                ..
            } => attempt.error.clone(),
            ConnectionAuthState::AuthFailed { error, .. } => Some(error.clone()),
            ConnectionAuthState::Anonymous | ConnectionAuthState::Authenticated { .. } => None,
            ConnectionAuthState::AwaitingAuth {
                last_attempt: None, ..
            } => None,
        }
    }
}

#[derive(Debug)]
struct GatheredCredentials {
    fields: HashMap<String, String>,
    intent: AuthenticationIntent,
}

impl GatheredCredentials {
    fn backend_decides(fields: HashMap<String, String>) -> Self {
        Self {
            fields,
            intent: AuthenticationIntent::BackendMayDrive,
        }
    }

    fn from_method(fields: HashMap<String, String>, method: &CredentialMethod) -> Self {
        Self {
            fields,
            intent: AuthenticationIntent::for_method(method),
        }
    }
}

pub async fn run(
    state: &mut SessionState,
    args: Args,
    cancel: &CancellationToken,
) -> ovstorage::Result<()> {
    let descriptors = state.stack.list_backend_kinds()?;
    if descriptors.is_empty() {
        return Err(Error::new(
            ErrorCode::NotConfigured,
            "no backend kinds are registered; run `ovstorage init` to register the built-in \
             `file` backend, or load a config that declares `[ovstorage.layers]`",
        ));
    }

    if args.advanced && (!args.fields.is_empty() || args.auth.is_some()) {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "--advanced is wizard-only; cannot be combined with positional fields or --auth",
        ));
    }

    let descriptor = match &args.kind {
        Some(kind) => find_descriptor(descriptors, kind)?,
        None => pick_backend(descriptors)?,
    };
    println!(
        "Configuring {} ({})",
        descriptor.display_name, descriptor.kind
    );
    if let Some(desc) = &descriptor.description {
        println!("  {desc}");
    }

    let required_count = descriptor
        .config_schema
        .iter()
        .filter(|f| f.required)
        .count();
    let non_interactive = args.kind.is_some() && args.fields.len() == required_count;
    if !args.fields.is_empty() && !non_interactive {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "{} expects {} required field value(s) (got {}); supply all of them or none",
                descriptor.kind,
                required_count,
                args.fields.len(),
            ),
        ));
    }

    let (config_runtime, gathered_credentials, display_name) = if non_interactive {
        let config_runtime = build_config_from_positional(&descriptor, &args.fields)?;
        let credentials =
            pick_credentials_non_interactive(&descriptor, &config_runtime, args.auth.as_deref())?;
        (config_runtime, credentials, args.name.clone())
    } else {
        let config_runtime = walk_config_schema(&descriptor, args.advanced)?;
        let credentials = gather_credentials(&descriptor, &config_runtime, args.advanced)?;
        // Ask all interactive questions up front so the long-running authentication
        // step is the last thing the user waits on, not interrupted by a prompt.
        let display_name = match args.name.clone() {
            Some(n) => Some(n),
            None => prompt_display_name()?,
        };
        (config_runtime, credentials, display_name)
    };
    let GatheredCredentials {
        fields: credentials,
        intent: authentication_intent,
    } = gathered_credentials;

    // Resolve the owning-layer target up front so it can be recorded on the
    // session connection for `write-config` round-tripping (renamed backend
    // layers) as well as used for addressing the connection-lifecycle calls.
    let target = match args.target.as_deref() {
        Some(named) => backend_target_named(state.stack.spec(), &descriptor.kind, named)?,
        None => resolve_backend_target(state.stack.spec(), &descriptor.kind)?,
    };

    let session_conn = SessionConnection {
        backend_kind: descriptor.kind.clone(),
        target: Some(target.clone()),
        display_name: display_name.clone(),
        config: config_runtime
            .iter()
            .map(|(k, v)| (k.clone(), config_value_to_toml(v)))
            .collect(),
        credentials,
    };

    let request = session_conn.to_connection_request()?;
    // Connection-lifecycle calls are `Layer` primitives (no `LayerExt` verb);
    // UFCS avoids a trait-method collision with `LayerExt`'s data-plane verbs.
    let added = ovstorage::Layer::add_connection(
        state.stack.as_ref(),
        Request::new(LayerConnectionRequest {
            target: target.clone(),
            connection: request,
        }),
        Some(cancel.clone()),
    )
    .await;
    let mut connection = match added {
        Ok(connection) => connection,
        // The route prefix is already served, and the overwhelmingly common
        // reason an operator types `connect` twice on one origin is that the
        // first credential was refused. A route prefix never carries userinfo,
        // so `user:bad@host` and `user:good@host` are ONE node — the corrected
        // credential collides with the mistake it is correcting, and without
        // this arm the only way out of a live session is to restart the CLI.
        //
        // Rotation is attempted, not assumed: it runs only when the collision
        // resolves to exactly one incumbent connection, and any doubt
        // re-surfaces this refusal untouched. See `rotate_on_conflict`.
        Err(conflict) if conflict.code() == ErrorCode::RouteConflict => {
            return rotate_on_conflict(
                state,
                &descriptor,
                session_conn,
                non_interactive,
                conflict,
                cancel,
            )
            .await;
        }
        // The add COMMITTED and only the graph's derived state did not follow —
        // the code's whole meaning, and what the Router raises when its
        // post-commit catch-up fails. The session bookkeeping follows the
        // commit, not the exit status: leaving the declaration out would let
        // `write-config` omit a connection that is registered right now, so the
        // file would describe a graph the operator does not have and the next
        // startup would silently drop it. `disconnect` treats an ambiguous
        // removal the same way from the other side, dropping the declaration
        // because the removal happened.
        //
        // The error still travels back — exit `20` says the mutation stuck and
        // must not be retried — and no state is claimed for the connection here:
        // finding it in a listing would mean matching a row to this declaration
        // structurally, which is the guesswork this command refuses everywhere
        // else. `list-connections` shows what it settled on.
        Err(err) if err.code() == ErrorCode::CommitAmbiguous => {
            return Err(record_committed_but_unconfirmed(
                &mut state.connections,
                session_conn,
                err,
            ));
        }
        Err(err) => return Err(err),
    };

    // When an authentication flow runs and fails, the half-registered
    // connection is dropped so the operator can retry `connect` — typically
    // with a different credential method — without hitting a route-prefix
    // conflict. A flow that was never offered, and a credential the origin
    // refused, both leave the registration in place; see below.
    let key = ConnectionKey {
        target: target.clone(),
        id: connection.id.clone(),
    };
    // `add_connection` may already have settled the identity. An unsettled
    // zero-field or backend-decides path may ask the backend for a flow; a
    // field-bearing method must preserve the identity the caller supplied and
    // surface its verdict instead of silently switching to an interactive one.
    // Kept so the exit-status decision below can hand back the backend's own
    // explanation rather than inventing one.
    let mut no_flow_offered: Option<Error> = None;
    if authentication_intent.should_drive(&connection.auth_state) {
        match drive_authentication(state.stack.as_ref(), key.clone(), cancel).await {
            Ok(AuthOutcome::Flowed(authenticated)) => connection = authenticated,
            // Nothing was ever offered to drive, so there is nothing to have
            // failed. Keep the connection: `add_connection` accepted it, and
            // where it publishes roots it serves reads. `print_success` reports
            // what the state is, and the exit status follows whether the
            // connection can serve anything at all.
            Ok(AuthOutcome::NoFlowOffered(err)) => no_flow_offered = Some(err),
            // This path resolved its own target and holds an id
            // `add_connection` just returned, so `NotFound` is not a candidate
            // to move past — it is the failure it says it is, and it is handled
            // exactly as any other. Only the owner SCAN in `reauth` has another
            // target to try.
            Ok(AuthOutcome::TargetNotFound(err)) | Err(err) => {
                let _ = ovstorage::Layer::remove_connection(
                    state.stack.as_ref(),
                    Request::new(key),
                    None,
                )
                .await;
                return Err(err);
            }
        }
    }

    state.connections.push(session_conn);
    print_success(&connection, display_name.as_deref());

    if let Some(error) = authentication_intent.supplied_credential_error(&connection.auth_state) {
        return Err(error);
    }

    if state.interactive
        && state.pwd.is_none()
        && let [only] = connection.current_addresses.as_slice()
    {
        state.pwd = Some(only.clone());
        println!("(pwd set to {only})");
    }

    // A refusal is reported through the exit status, not only through the
    // warning `print_success` prints: a script sees the status and cannot see
    // stderr prose, so `Connected` plus exit 0 was the opposite of what
    // happened.
    //
    // The registration deliberately survives. The probe is a `HEAD` on the
    // root, and an origin that challenges its root while serving the objects
    // beneath it is an ordinary shape — so deleting the connection would
    // discard a configuration whose data path works, and the operator has no
    // flag to overrule it. Reporting the failure is recoverable in both
    // directions; deleting the operator's typed credential is not.
    if let ConnectionAuthState::AuthFailed { error, .. } = &connection.auth_state {
        return Err(error.clone());
    }
    // The same rule for a connection that cannot serve anything. Keeping the
    // registration and reporting success are independent decisions, and only
    // the first is about not destroying the operator's typed credential: a
    // connection that is neither settled nor routable answers `NoRoute` to
    // every operation, so exiting 0 tells a script the opposite of what
    // happened. A backend with no interactive flow reaches here through
    // `NoFlowOffered`, whose error explains itself better than anything this
    // module could invent, so it is what travels back.
    if is_unusable(&connection) {
        return Err(no_flow_offered.unwrap_or_else(|| {
            Error::new(
                ErrorCode::AuthRequired,
                "connection registered but neither authenticated nor routable",
            )
        }));
    }
    Ok(())
}

/// Whether a registered connection can serve nothing at all.
///
/// A parked connection is not automatically useless: the cloud backends derive
/// their roots from config and publish them while parked, so they keep serving
/// reads on a credential the origin has not confirmed, and reporting that as a
/// failure would be wrong. A connection that is *also* routeless is different —
/// every operation answers `NoRoute` — and that is the shape a backend with no
/// interactive flow leaves behind when its credential is refused at bring-up,
/// because root discovery is skipped for a parked connection.
fn is_unusable(connection: &Connection) -> bool {
    !is_settled(&connection.auth_state) && connection.current_addresses.is_empty()
}

/// Whether the connection's identity is decided, either way.
///
/// `Anonymous` and `Authenticated` are both settled: one says there is no
/// credential to establish, the other that the origin accepted the credential
/// there is. The other two are not — `AwaitingAuth` has an unproven credential
/// and `AuthFailed` a refused one — and that boundary is what separates a
/// connection with nothing left to do from one an operator can still repair.
fn is_settled(auth_state: &ConnectionAuthState) -> bool {
    matches!(
        auth_state,
        ConnectionAuthState::Anonymous | ConnectionAuthState::Authenticated { .. }
    )
}

/// Repair the connection the refused `add_connection` collided with, by
/// replacing its credentials in place.
///
/// **Why an address is the handle here.** Nothing exposes the layer→connection
/// ownership edge directly, and the usual proxies are each lossy: a
/// `display_name` is absent until a backend defaults it, and a `backend_kind`
/// cannot name one of two same-kind layers. What this path DOES hold is the
/// address the caller just typed, and the collision is by definition about that
/// address — so ownership is resolved from it, through [`owner_at`]: one
/// [`ovstorage::Layer::root_info_for`] yielding both the connection id and the
/// layer that holds it. That answers for a connection in ANY auth state wherever
/// the layer publishes roots unconditionally (plugin-http does), which matters
/// because `AwaitingAuth` and `AuthFailed` are exactly the states this command
/// exists to repair.
///
/// **Every uncertainty re-surfaces the conflict unchanged.** Rotating the wrong
/// connection's credentials is worse than the refusal the operator already
/// understands, so this returns `conflict` untouched when no address resolves
/// an incumbent, when two addresses resolve to *different* incumbents, when the
/// resolved incumbent is not of the kind the operator named (or is absent from
/// the connection listing entirely), when a script would be replacing a SETTLED
/// incumbent's credential with nobody to confirm it, or when the operator
/// declines the prompt. The refusal is the honest answer in each case, and it
/// is what the previous behavior was.
async fn rotate_on_conflict(
    state: &mut SessionState,
    descriptor: &StorageBackendKindDescriptor,
    session_conn: SessionConnection,
    non_interactive: bool,
    conflict: Error,
    cancel: &CancellationToken,
) -> ovstorage::Result<()> {
    let credentials = session_conn.to_connection_request()?.credentials;
    // An empty bundle is not a credential to rotate. `update_connection_credentials`
    // replaces the values inside a connection's existing credential CHANNELS,
    // and a credential that rides in a config field instead — HTTP userinfo on
    // `root_url` is the one in-tree example — is not in the bundle at all, so
    // sending an empty one would re-probe the OLD secret and report its verdict
    // as if it were the new one. Refusing is what the operator can act on.
    if credentials.fields.is_empty() {
        return Err(conflict);
    }

    let candidates = route_candidates(descriptor, &session_conn.config);
    // One endpoint, or no rotation. See [`names_one_endpoint`]: a request whose
    // config names two different nodes cannot be shown to be about the
    // connection its route collided with, and the credential in hand would be
    // sent to whatever endpoint that connection retained.
    if !names_one_endpoint(&candidates) {
        eprintln!(
            "note: this request names more than one address, so `connect` cannot show that the \
             credential belongs to the connection already serving the prefix; not replacing it. \
             `disconnect` that connection and connect afresh if that is what you meant."
        );
        return Err(conflict);
    }
    let Some((key, prefix)) = resolve_incumbent(state.stack.as_ref(), &candidates, cancel).await?
    else {
        return Err(conflict);
    };
    // **The incumbent must be on the layer the add was aimed at.** A route
    // collision is now reachable ACROSS sibling layers — the Router refuses a
    // same-node root from another child — so the connection holding the prefix
    // can belong to a layer the operator did not name. Rotating it would send a
    // credential meant for one tenant into another's connection and report
    // success, while nothing at all landed on the requested layer; the kind gate
    // below cannot see it, because two `http` tenants are the same kind. The
    // target the add used is on the declaration this rotation was built from,
    // so the comparison costs nothing.
    //
    // Refusing a mismatch can cost a rotation that would have been right, where
    // a loaded composite backend reports an internal `owning_target` that is not
    // the host layer name the operator passed to `--target`. That is the safe
    // side of the trade: the operator sees the conflict they already understand
    // and can `disconnect` and connect afresh, where the other side sends a
    // secret to the wrong tenant.
    if session_conn.target.as_deref() != Some(key.target.as_str()) {
        eprintln!(
            "note: {} is served by a connection on layer '{}', not the layer this connect was \
             aimed at; not replacing its credentials. Re-run with `--target {}` if that is the \
             connection you meant to repair.",
            ovstorage::origin_only(&prefix),
            key.target,
            key.target,
        );
        return Err(conflict);
    }
    // The incumbent must be one this `connect` could plausibly have been about.
    // A collision ACROSS backend kinds became reachable when the Router started
    // refusing a sibling child's same-node root — a graph over an `http` child
    // and a services-client child can now collide on one address — and the
    // bundle in hand is shaped for the kind the operator named. Pushing it into
    // another backend's connection re-probes a working tenant against a
    // credential meant for something else, and a backend that rotates on
    // whatever it is handed parks that tenant. A connection missing from the
    // listing is the same doubt in a different spelling: nothing there confirms
    // what it is, so neither case may proceed. [`sole_incumbent_row`] carries
    // that argument, and the one about an id two layers both hold.
    let listing = state.stack.list_connections(Some(cancel.clone())).await?;
    let Some(incumbent) = sole_incumbent_row(listing, &key, &descriptor.kind) else {
        return Err(conflict);
    };
    let label = if incumbent.display_name.is_empty() {
        key.id.0.clone()
    } else {
        incumbent.display_name.clone()
    };
    let auth_state = auth_state_word(&incumbent.auth_state);

    // Replacing a credential is not what the operator asked for — they asked to
    // add a connection — so it is confirmed wherever there is someone to
    // confirm it. The wizard asks, naming the incumbent and its state, and
    // defaults to no.
    //
    // A script has no one to ask, so what it may do without an answer is
    // narrower: repair an incumbent the origin has REFUSED. `AuthFailed` is that
    // and only that — a credential the origin turned down, which is serving
    // nobody and is the whole case this fallback exists for.
    //
    // **Every other state is left to a human, `AwaitingAuth` included.** It is
    // tempting to read "not settled" as "not working" and rotate on it, and that
    // is wrong: `AwaitingAuth` means the credential is UNPROVEN, not rejected.
    // For `plugin-http` it is what an inconclusive probe produces — a root
    // answering 403, 404, 405 or 429 neither accepts nor refuses a credential,
    // and neither does one that redirected the probe elsewhere or did not answer
    // at all — while the connection stays routable and objects beneath the root
    // may be reading perfectly well the entire time. Rotating that unattended
    // turns a duplicate `connect`, which is a no-op the operator very likely
    // typed by mistake, into an outage the moment the replacement has a typo in
    // it: exactly the failure the settled-state guard was written to prevent,
    // arrived at through a different door. So the conflict is re-surfaced, which
    // is the answer an operator got before this fallback existed and can act on.
    // The escapes are the ones this command already documents: run it
    // interactively and answer the prompt, or `disconnect` and connect afresh,
    // which a script can do as readily as a person.
    if non_interactive {
        let ConnectionAuthState::AuthFailed { .. } = &incumbent.auth_state else {
            return Err(conflict);
        };
        eprintln!("{}", replacement_note(&prefix, &label, auth_state));
    } else if !confirm_replace_credentials(&prefix, &label, auth_state)? {
        return Err(conflict);
    }

    // The backend re-probes against the new bundle — carrying an old
    // `Authenticated` verdict onto a new bearer would be a success that is not
    // one — and answers `Unsupported` for a credential-shape change it cannot
    // express as a rotation. That message names the remove-and-re-add the
    // operator needs, so it travels back verbatim rather than being folded into
    // the conflict.
    let connection = ovstorage::Layer::update_connection_credentials(
        state.stack.as_ref(),
        Request::new(UpdateConnectionCredentialsRequest { key, credentials }),
        Some(cancel.clone()),
    )
    .await?;

    record_rotated_credentials(&mut state.connections, descriptor, session_conn, &prefix);
    print_rotated(&connection);

    // The same exit-status rules `connect` applies to a fresh registration: a
    // refusal the origin stated, and a connection that can serve nothing, are
    // both failures a script can only see through the status.
    if let ConnectionAuthState::AuthFailed { error, .. } = &connection.auth_state {
        return Err(error.clone());
    }
    if is_unusable(&connection) {
        return Err(Error::new(
            ErrorCode::AuthRequired,
            "credentials replaced, but the connection is neither authenticated nor routable",
        ));
    }
    Ok(())
}

/// The caller-facing addresses a connection request would publish: every
/// `Url`-kind config value, with userinfo stripped.
///
/// Stripping userinfo is what makes these comparable to a route prefix, which
/// never carries any — plugin-http's `default_prefix` strips it when it derives
/// the prefix from `root_url`, and that is precisely why two spellings of one
/// origin that differ only in credentials collide on one node.
///
/// Read from the schema rather than from a fixed key list so this says nothing
/// about `http` in particular: any backend whose route derives from a `Url`
/// config field resolves the same way.
pub(crate) fn route_candidates(
    descriptor: &StorageBackendKindDescriptor,
    config: &HashMap<String, toml::Value>,
) -> Vec<Url> {
    descriptor
        .config_schema
        .iter()
        .filter(|field| matches!(field.kind, ConfigFieldKind::Url))
        .filter_map(|field| config.get(&field.key)?.as_str())
        .filter_map(|raw| {
            let mut url = ovstorage::address::parse(raw).ok()?;
            let _ = url.set_username("");
            let _ = url.set_password(None);
            Some(url)
        })
        .collect()
}

/// The connection a refused `add_connection` collided with, and the address
/// that named it.
///
/// `None` means "no single incumbent", which is the answer whenever the caller
/// must not proceed: nothing serves any of these addresses, what serves them
/// publishes no connection id (a synthesized or static root owns no
/// credential), or two addresses name two DIFFERENT connections — a request
/// whose `prefix` and `root_url` land on separate tenants is not a rotation any
/// answer here could get right.
///
/// The I/O half: ask the graph what serves each candidate, and hand the
/// answers to [`choose_incumbent`].
///
/// **An address the graph could not answer for abandons the whole resolution.**
/// [`choose_incumbent`]'s safeguard is that every candidate address must agree,
/// and that only means anything if every candidate was actually read. Dropping
/// an unread one shrinks the set instead of failing it: two addresses naming two
/// different tenants, one of them behind a `Transient` introspection failure,
/// would leave a single surviving candidate, and a set of one agrees with itself
/// — so the rotation the disagreement was supposed to refuse would go ahead on a
/// tenant nobody had disambiguated. `Ok(None)` here re-surfaces the operator's
/// original route conflict, which is the same answer this function gives for
/// every other uncertainty. Only `NoRoute` skips a candidate, because that IS an
/// answer: this address names no connection.
async fn resolve_incumbent(
    graph: &dyn ovstorage::Layer,
    candidates: &[Url],
    cancel: &CancellationToken,
) -> ovstorage::Result<Option<(ConnectionKey, Url)>> {
    let mut resolved = Vec::new();
    for url in candidates {
        match owner_at(graph, url, cancel).await {
            Ok(Some(key)) => resolved.push((key, url.clone())),
            Ok(None) => continue,
            // The caller leaving is not a rotation decision at all.
            Err(err) if err.code() == ErrorCode::Cancelled => return Err(err),
            Err(_) => return Ok(None),
        }
    }
    Ok(choose_incumbent(resolved))
}

/// Decide what the session remembers about an add that answered
/// [`ErrorCode::CommitAmbiguous`], and hand back the error the caller still has
/// to see.
///
/// **That code covers two facts, and they want opposite bookkeeping.** A
/// refusal whose rollback failed leaves a connection that will never route, and
/// remembering it would re-apply a failed attempt on the next start. An add that
/// LANDED and whose routes could not be confirmed leaves one that is registered
/// and wanted, and forgetting it would have `write-config` omit a connection
/// that exists. The two are told apart here by the marker the refusing Layer
/// sets, not by the code they share.
///
/// **For the second, session bookkeeping follows the COMMIT, not the exit
/// status.** The Router raises this when its post-commit catch-up fails, over a
/// mutation that landed. Returning without
/// recording the declaration left the session describing a graph the operator
/// does not have: the connection is registered right now, `write-config` would
/// omit it, and the next startup would drop it silently. `disconnect` treats an
/// ambiguous removal the same way from the other side, dropping the declaration
/// *because* the removal happened.
///
/// The error still travels: exit `20` is what tells a script the mutation stuck
/// and must not be retried, and re-running `connect` on that reading is how a
/// success turns into a route conflict.
///
/// **No state is claimed for the connection.** Reporting what it settled on
/// would mean finding it in a listing, and `add_connection` returned no
/// `Connection` to find it by — matching a row to this declaration structurally
/// is the guesswork this command refuses everywhere else, and getting it wrong
/// would report another connection's auth state as this one's.
/// `list-connections` answers that question without guessing.
fn record_committed_but_unconfirmed(
    declared: &mut Vec<SessionConnection>,
    session_conn: SessionConnection,
    err: Error,
) -> Error {
    // **A refusal that could not be undone is not a connection to remember.**
    // The graph turned this add down for another layer's address prefix and
    // could not take it off its child, so it is registered there and will never
    // route — the refusing Layer withholds its roots. Recording it would put an
    // `[[ovstorage.connections]]` entry in `write-config`'s output for an
    // attempt that failed, and the next start would re-apply the same mistake
    // and leave another leftover behind. The declaration is dropped instead, and
    // the error already names the layer holding the leftover and says to remove
    // it by hand.
    //
    // Told apart by the marker the refusing Layer sets, which is the same test
    // `StackBuilder::build_with_cancel` and the Python composer apply — one
    // fact, one signal, three readers.
    if err.next_action() == Some(ovstorage::NEXT_ACTION_REFUSED_LEFTOVER) {
        eprintln!(
            "note: that connection was refused and could not be removed, so it is NOT recorded \
             for `write-config` — the next start would otherwise re-apply it and leave another \
             registration behind. The error names the layer still holding this one."
        );
        return err;
    }
    // Everything else here is an add that LANDED and whose routes the graph
    // could not confirm: the connection is registered and wanted, so the
    // session keeps its declaration or `write-config` would omit a connection
    // that exists.
    declared.push(session_conn);
    eprintln!(
        "note: the connection was registered, but this graph could not confirm its routes \
         ({err}). It is recorded for `write-config`; do not re-run `connect` for it — check \
         `list-connections` for what it settled on."
    );
    err
}

/// Does this request's configuration name a single endpoint?
///
/// **A rotation is only defensible when the address that collided IS the
/// address the credential is for**, and for a backend whose route is derived
/// from its endpoint that is the same thing. It stops being the same thing the
/// moment a request names both: `{ root_url = B, prefix = P }` collides on `P`,
/// because `P` is the route, while `B` — the physical endpoint the credential
/// was typed for — is not a route at all and resolves to nothing. The incumbent
/// serving `P` retains its own endpoint `A`, which no caller can see: a
/// `Connection` publishes the caller-facing roots and not the URL behind them.
/// Rotating anyway would hand `B`'s secret to a connection that speaks to `A`,
/// and `plugin-http` would then re-probe `A` with it — a credential disclosed to
/// an origin it was never meant for, and a working tenant's credential replaced.
/// The kind and auth-state gates cannot see it: two `http` connections on one
/// prefix are the same kind, and the incumbent being `AuthFailed` is exactly the
/// state the unattended path allows.
///
/// So the test is agreement between the request's own addresses, by node —
/// which for the ordinary shapes is free. One `Url` field (`root_url` alone,
/// prefix defaulted from it) trivially agrees, and a `prefix` spelled to the
/// same node as its `root_url` agrees too.
///
/// **What this does not prove**, and cannot from here: that the incumbent's
/// retained endpoint is the one the request names. Where a connection was
/// declared with an explicit `prefix` pointing at a different physical origin,
/// this refuses a rotation that would in fact have been correct, and the
/// operator's route back is `disconnect` and a fresh `connect`. Closing that
/// properly needs the backend to publish a non-secret identity for the endpoint
/// a connection speaks to — a config fingerprint on the connection, or a
/// verification argument on the rotation itself — which is an API this change
/// does not add. Refusing is the side to err on: the cost is a command an
/// operator can run two of instead, against a secret sent to the wrong host.
fn names_one_endpoint(candidates: &[Url]) -> bool {
    let mut named = candidates.iter();
    let Some(first) = named.next() else {
        // Nothing to disagree, and nothing to resolve either — the caller finds
        // no incumbent and re-surfaces the conflict on its own.
        return true;
    };
    named.all(|other| ovstorage::address::same_node(first, other))
}

/// The `(target, id)` a published root names for `url` — the whole
/// `ConnectionKey` a connection operation needs — or `None` when nothing there
/// is an answer about `url`.
///
/// **One `root_info_for` yields both halves, and that is the point.** The id and
/// the layer that holds it are two facts about one route, so reading them from
/// one answer is what keeps them consistent: a live route change cannot race two
/// independent lookups into pairing one backend's id with another backend's
/// target.
///
/// **The target comes from [`RootInfo::owning_target`] first.**
/// `owning_target_for` is only a fallback, for a plugin that reports a
/// connection but predates that field — the same precedence the alias layer's
/// auth delegation applies (`AliasWrapper`'s `delegate_auth`), and for the same
/// reason. `owning_target` crosses the plugin ABI and names the layer instance
/// that actually holds the connection, while `owning_target_for` bottoms out in
/// the `Layer` default's leaf rule (`leaf_owning_target`: the sole
/// `owned_targets` entry, else `name()`). A loaded composite backend reporting
/// SEVERAL owned targets therefore answers with its outer host-layer name, which
/// is not a target any `route_target` can find — so a rotation or a
/// re-authentication built on it failed `NotFound` on a graph where the
/// connection was sitting right there.
///
/// **`Ok(None)` means the graph ANSWERED and there is nothing here; `Err` means
/// it did not answer.** The two are not interchangeable, and collapsing them is
/// a way to act on a graph nobody has actually read. `NoRoute` is the answer —
/// no configured root matches, which is the ordinary result for a config address
/// that is not itself a route (an `http` `root_url` behind a distinct `prefix`),
/// as is a root about another node or one owning no connection. `Transient`,
/// `PermissionDenied`, `Internal`, a fired token: none of those says anything
/// about what this address names, so each travels back as the failure it is and
/// every caller decides for itself what an unread address costs it.
pub(crate) async fn owner_at(
    graph: &dyn ovstorage::Layer,
    url: &Url,
    cancel: &CancellationToken,
) -> ovstorage::Result<Option<ConnectionKey>> {
    let root =
        match ovstorage::Layer::root_info_for(graph, url, &Extensions::new(), Some(cancel.clone()))
            .await
        {
            Ok(root) => root,
            Err(err) if err.code() == ErrorCode::NoRoute => return Ok(None),
            Err(err) => return Err(err),
        };
    let Some(id) = incumbent_id(&root, url) else {
        return Ok(None);
    };
    if let Some(target) = root.owning_target {
        return Ok(Some(ConnectionKey { target, id }));
    }
    // The fallback naming nobody for an address whose root just resolved is the
    // two-lookup race this helper exists to avoid, seen from the inside: the
    // route moved between the calls. Not an answer about the address, so it is
    // not reported as one.
    ovstorage::Layer::owning_target_for(graph, url, &Extensions::new(), Some(cancel.clone()))
        .await
        .map(|target| Some(ConnectionKey { target, id }))
        .ok_or_else(|| {
            Error::new(
                ErrorCode::Transient,
                "the route serving this address named no owning layer; it may have changed \
                 between the two lookups",
            )
        })
}

/// The connection `root` names for `url`, or `None` if `root` is not an answer
/// about `url` at all.
///
/// The `same_node` guard is the load-bearing part. `root_info_for` answers with
/// the longest-prefix match, so a broader root that merely *contains* the
/// address — a sibling serving `https://h/` under a request for
/// `https://h/team/` — comes back as a hit. That connection is not the one the
/// refusal was about, and rotating its credentials would break a tenant that
/// was working. A root with no `connection_id` is not one either: a synthesized
/// or statically declared root owns no credential to replace.
///
/// Shared with `connections`, which needs the same guard for the same reason:
/// what a route resolves to is not by itself an answer about a given connection.
pub(crate) fn incumbent_id(root: &RootInfo, url: &Url) -> Option<ConnectionId> {
    if !ovstorage::address::same_node(&root.root, url) {
        return None;
    }
    root.connection_id.clone()
}

/// Reduce the per-address answers to the single connection this rotation may
/// touch — or to `None`, which means the caller re-surfaces the refusal.
///
/// Agreement is required rather than ranked. A request whose `prefix` and
/// `root_url` land on two DIFFERENT connections is not a rotation any answer
/// here could get right, and guessing which address "really" named the
/// incumbent would replace a refusal the operator understands with a silent
/// credential change on a tenant they did not name. In the ordinary case the
/// question does not arise: an explicit `prefix` is the only one of the two
/// that is a route, so it is the only one that resolves.
///
/// **Agreement is on the whole `ConnectionKey`, because that is what identity
/// is.** A `ConnectionId` names a connection only WITHIN its owning target — the
/// Layer contract says so and the alias layer takes a caller-supplied id
/// verbatim — so two addresses landing on two layers that both hold `rule` are
/// two connections, not one, however alike the ids read. Comparing ids alone
/// called that agreement and rotated whichever address came first, which is the
/// silent credential change on an unnamed tenant this function exists to
/// prevent.
fn choose_incumbent(mut resolved: Vec<(ConnectionKey, Url)>) -> Option<(ConnectionKey, Url)> {
    let first = resolved.first()?.0.clone();
    if resolved.iter().any(|(key, _)| *key != first) {
        return None;
    }
    Some(resolved.remove(0))
}

/// The listing row describing the incumbent — or `None` whenever the rotation
/// must not proceed on what the listing says.
///
/// [`resolve_incumbent`] answers with a `ConnectionKey`, which names the layer
/// as well as the id — and a `Connection` reports the same pair, so a row that
/// carries a target is matched on the WHOLE key. That is what identity is: an
/// id names a connection only WITHIN its owning target, the alias layer takes a
/// caller-supplied one verbatim, and an `alias` rule declaring `id = "http-3"`
/// beside the `http` connection that minted it puts two rows with one id in the
/// graph's own listing. Matching the pair tells those two apart exactly.
///
/// **Three decisions are read from this row, and all three are about identity.**
/// The backend kind gates the rotation at all; the auth state decides whether an
/// unattended `connect` may replace the credential; the display name is what the
/// operator is shown before they answer. A namesake's row answers each of them
/// about a connection that is not the one being rotated — it can pass a kind
/// check the incumbent would fail, or report `auth-failed` for an incumbent that
/// is authenticated and serving.
///
/// So the fallback is withdrawn wherever the rows cannot be told apart: two
/// UNATTRIBUTED rows sharing the id are indistinguishable in every field this
/// can see, and the caller re-surfaces the route conflict — precisely the error
/// an operator saw before this fallback existed and can still act on. An
/// attributed row is not that case, and refusing it would decline to act on an
/// answer the graph gave.
///
/// **An exact match is taken over an unattributed namesake, not weighed against
/// it.** A graph may hold both — an attributed row on `http_b` and a row a
/// loaded composite plugin left unattributed, both answering to `rule`. Treating
/// those as two candidates would let a row that reports nothing veto a row that
/// names this exact key, refusing a rotation the graph had already identified.
/// Targets are graph-unique, so at most one row can match the whole key, and an
/// unattributed row is not a claim on it. Only when no row matches the key
/// exactly does the id-only search run, and there the ambiguity refusal stands.
///
/// A missing row is refused for a reason of its own: nothing confirms what the
/// connection is, and rotating on that is a guess.
fn sole_incumbent_row(
    listing: Vec<Connection>,
    key: &ConnectionKey,
    kind: &str,
) -> Option<Connection> {
    let exact = |row: &Connection| {
        row.id == key.id && row.owning_target.as_ref().is_some_and(|t| *t == key.target)
    };
    // A row naming a DIFFERENT target is not a weaker candidate, it is a
    // positive claim that it is somebody else's — so it is excluded outright
    // rather than counted. Only rows that report no owner can stand in for this
    // one, and only when there is exactly one of them.
    let unclaimed = |row: &Connection| row.id == key.id && row.owning_target.is_none();

    let row = if listing.iter().any(exact) {
        listing.into_iter().find(exact)?
    } else {
        let mut rows = listing.into_iter().filter(unclaimed);
        let row = rows.next()?;
        if rows.next().is_some() {
            return None;
        }
        row
    };
    (row.backend_kind == kind).then_some(row)
}

/// Keep `write-config` round-tripping the CORRECTED credential without emitting
/// a second `[[ovstorage.connections]]` entry for one origin — which would
/// reproduce this very conflict on the next boot.
///
/// Matched structurally, because a `SessionConnection` carries no connection
/// id: it is the *declaration* a connection was built from, not the connection,
/// and the ids the graph mints never reach the session (`host::build_stack`
/// applies the declared connections and does not hand their ids back). The
/// addresses a declaration names are the only handle there is.
///
/// **Matched on the ROUTE, not on every address a declaration mentions.** The
/// route is the address that actually resolved the incumbent, and comparing
/// against a declaration's whole `Url`-field set instead is what made this
/// wrong: a `root_url` participates even when it is not the routable address,
/// so two connections sharing one physical origin under distinct explicit
/// `prefix` values — the arrangement `plugin-http`'s own documentation
/// recommends for exactly that case — collided through the `root_url` they
/// share, and rotating the second wrote its credential onto the first
/// declaration while leaving the repaired connection's stale.
///
/// **Ambiguity is refused, not guessed.** Narrowing to the route removes the
/// reported collision but cannot remove every one: a declaration that names the
/// route among its other addresses still matches, so a graph where one
/// connection routes `R` and another declares `root_url = R` with a `prefix`
/// elsewhere can produce two candidates. Writing a credential into a
/// declaration the operator did not name is silent corruption of a file they
/// will later deploy; saying so and leaving the file alone is not. The live
/// graph is repaired either way — this function only decides what
/// `write-config` writes.
fn record_rotated_credentials(
    declared: &mut Vec<SessionConnection>,
    descriptor: &StorageBackendKindDescriptor,
    session_conn: SessionConnection,
    route: &Url,
) {
    let matches: Vec<usize> = declared
        .iter()
        .enumerate()
        .filter(|(_, entry)| {
            entry.backend_kind == session_conn.backend_kind
                // Pinned to another layer means it did not produce the
                // connection this rotation touched: the rotation is on the
                // layer the add was aimed at, which is this declaration's
                // target. Narrows and never widens — an entry that names no
                // target is "wherever the kind landed" and stays a candidate.
                && entry
                    .target
                    .as_deref()
                    .is_none_or(|pinned| Some(pinned) == session_conn.target.as_deref())
                && route_candidates(descriptor, &entry.config)
                    .iter()
                    .any(|address| ovstorage::address::same_node(address, route))
        })
        .map(|(index, _)| index)
        .collect();
    match matches.as_slice() {
        [index] => declared[*index].credentials = session_conn.credentials,
        // Nothing in the session declares this connection, so there is no entry
        // to corrupt and `write-config` would otherwise omit it entirely.
        [] => declared.push(session_conn),
        several => eprintln!(
            "note: {} declared connections name this address, so the new credential was not \
             recorded for `write-config`; update the intended [[ovstorage.connections]] entry \
             by hand. The live connection was repaired.",
            several.len(),
        ),
    }
}

/// What an unattended `connect` prints before replacing a credential.
///
/// **The ORIGIN, never the whole prefix.** A route prefix keeps its path and
/// query — `route_candidates` strips only userinfo — and either can carry a
/// secret no redaction list recognises: a signed query under an unlisted name, a
/// capability token in a path segment. [`ovstorage::origin_only`] is the same
/// rule the route-conflict refusals apply, and this line needs it more than they
/// do: it is printed on the SUCCESS path, which is the one that ends up in CI
/// output, terminal captures and shipped logs. The label and auth state say
/// which connection is meant; the origin says where.
///
/// Built as a string rather than printed inline so the rule is testable.
fn replacement_note(prefix: &Url, label: &str, auth_state: &str) -> String {
    format!(
        "note: {} is already served by connection '{label}' ({auth_state}), \
         whose credential the origin refused; replacing it.",
        ovstorage::origin_only(prefix)
    )
}

/// The wizard's question, held to [`replacement_note`]'s rule for the same
/// reason: a terminal prompt is captured as readily as a log line — by `script`,
/// by a CI runner's transcript, by a screen recording.
fn replace_prompt(prefix: &Url, label: &str, auth_state: &str) -> String {
    format!(
        "{} is already served by connection '{label}' ({auth_state}); \
         replace its credentials?",
        ovstorage::origin_only(prefix)
    )
}

fn confirm_replace_credentials(
    prefix: &Url,
    label: &str,
    auth_state: &str,
) -> ovstorage::Result<bool> {
    inquire::Confirm::new(&replace_prompt(prefix, label, auth_state))
        .with_default(false)
        .prompt()
        .map_err(map_inquire)
}

/// One stable lowercase word per auth state, for line-oriented output.
///
/// A pinned vocabulary, not a rendering of the enum: `{:?}` would print the
/// variant's payload (a `SystemTime`, a nested `Error`) and would change under
/// operators' scripts whenever a field is added. Shared with `list-connections`
/// so one connection reads the same in a listing and in a prompt.
pub(crate) fn auth_state_word(state: &ConnectionAuthState) -> &'static str {
    match state {
        ConnectionAuthState::Authenticated { .. } => "authenticated",
        ConnectionAuthState::Anonymous => "anonymous",
        ConnectionAuthState::AwaitingAuth { .. } => "awaiting-auth",
        ConnectionAuthState::AuthFailed { .. } => "auth-failed",
    }
}

fn find_descriptor(
    descriptors: Vec<StorageBackendKindDescriptor>,
    kind: &str,
) -> ovstorage::Result<StorageBackendKindDescriptor> {
    descriptors
        .into_iter()
        .find(|d| d.kind == kind)
        .ok_or_else(|| {
            Error::new(
                ErrorCode::NotFound,
                format!("no backend kind '{kind}' is registered"),
            )
        })
}

/// Resolve the Layer `target` a NEW connection of `backend_kind` should be
/// added to, from the live stack graph, so `add_connection` addresses a real
/// Layer even when a backend Layer is named differently from its kind (e.g.
/// layer `s3_prod` of kind `s3`).
///
/// - exactly one backend Layer of that kind → its `name` (handles the renamed
///   `s3_prod`/`s3` case);
/// - none → fall back to `backend_kind` itself, the default-stack convention
///   (backend Layer named after its kind);
/// - several backend Layers of that kind → the target is genuinely ambiguous,
///   so return an error instead of synthesizing `backend_kind`, which names no
///   Layer and would make `add_connection` fail against a nonexistent target.
///
/// **The add path only.** The ambiguity error is the right answer here and
/// nowhere else: a connection that does not exist yet has no owner to discover,
/// so a graph with two same-kind layers genuinely needs the operator to say
/// which one. Every path that starts from an EXISTING connection has a better
/// handle than a kind — an address, or the id itself — and uses it:
/// [`rotate_on_conflict`], [`drive_authentication_on_owner`], and
/// `disconnect`'s owner scan. `reauth` used to come through here, and was
/// therefore unreachable on a two-tenant graph.
fn resolve_backend_target(spec: &StackSpec, backend_kind: &str) -> ovstorage::Result<String> {
    let names = backend_layers_of_kind(spec, backend_kind);
    match names.as_slice() {
        [name] => Ok((*name).to_string()),
        [] => Ok(backend_kind.to_string()),
        several => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "kind '{backend_kind}' is ambiguous: {} backend layers share it ({}); \
                 name one with `--target <LAYER>`",
                several.len(),
                several.join(", "),
            ),
        )),
    }
}

/// The layer an explicit `--target` names, checked against the graph.
///
/// **This is what makes a two-layer graph usable at all.** Without it the kind
/// is the only handle `connect` has, and a graph with two backend layers of one
/// kind — the two-tenant arrangement `plugin-http.md` recommends — has no
/// answer: [`resolve_backend_target`] refuses before `add_connection` is
/// reached, so neither a new connection nor the rotation that repairs a refused
/// one is available, and the refusal's own advice to "target it by layer name"
/// had nothing to name it with.
///
/// Checked here rather than left to the graph so the error is the one the
/// operator can act on. A name that is not a backend layer of this kind, or not
/// a layer at all, comes back naming what IS available; `add_connection` would
/// answer `NotFound` about a target, which says nothing about which names exist.
fn backend_target_named(
    spec: &StackSpec,
    backend_kind: &str,
    target: &str,
) -> ovstorage::Result<String> {
    let names = backend_layers_of_kind(spec, backend_kind);
    if names.contains(&target) {
        return Ok(target.to_string());
    }
    // A layer of ANOTHER kind under this name is worth saying out loud: the
    // operator named a real layer and the mismatch is the point, not a typo.
    let other_kind = spec
        .layers
        .iter()
        .find(|l| l.name == target)
        .map(|l| l.kind.as_str());
    Err(Error::new(
        ErrorCode::InvalidArgument,
        match (other_kind, names.as_slice()) {
            (Some(kind), _) => format!(
                "layer '{target}' is of kind '{kind}', not '{backend_kind}'; \
                 backend layers of that kind: {}",
                describe_candidates(&names),
            ),
            (None, _) => format!(
                "no backend layer named '{target}'; backend layers of kind \
                 '{backend_kind}': {}",
                describe_candidates(&names),
            ),
        },
    ))
}

fn backend_layers_of_kind<'a>(spec: &'a StackSpec, backend_kind: &str) -> Vec<&'a str> {
    spec.layers
        .iter()
        .filter(|l| l.layer_type == LayerType::Backend && l.kind == backend_kind)
        .map(|l| l.name.as_str())
        .collect()
}

fn describe_candidates(names: &[&str]) -> String {
    if names.is_empty() {
        "none are configured".to_string()
    } else {
        names.join(", ")
    }
}

fn build_config_from_positional(
    descriptor: &StorageBackendKindDescriptor,
    values: &[String],
) -> ovstorage::Result<HashMap<String, ConfigValue>> {
    let required: Vec<&ConfigField> = descriptor
        .config_schema
        .iter()
        .filter(|f| f.required)
        .collect();
    debug_assert_eq!(required.len(), values.len());
    let mut out = HashMap::with_capacity(required.len());
    for (field, raw) in required.iter().zip(values.iter()) {
        out.insert(field.key.clone(), parse_config_value(field, raw)?);
    }
    Ok(out)
}

fn parse_config_value(field: &ConfigField, raw: &str) -> ovstorage::Result<ConfigValue> {
    match &field.kind {
        ConfigFieldKind::Url | ConfigFieldKind::Text | ConfigFieldKind::Path => {
            Ok(ConfigValue::String(raw.to_string()))
        }
        ConfigFieldKind::Integer => raw
            .parse::<i64>()
            .map(ConfigValue::Int)
            .map_err(|_| invalid_field(field, raw, "expected an integer")),
        ConfigFieldKind::Bool => match raw {
            "true" | "1" | "yes" | "y" => Ok(ConfigValue::Bool(true)),
            "false" | "0" | "no" | "n" => Ok(ConfigValue::Bool(false)),
            _ => Err(invalid_field(field, raw, "expected true/false")),
        },
        ConfigFieldKind::Enum {
            source: EnumSource::Static(variants),
        } => {
            if variants.iter().any(|v| v == raw) {
                Ok(ConfigValue::String(raw.to_string()))
            } else {
                Err(invalid_field(
                    field,
                    raw,
                    &format!("expected one of: {}", variants.join(", ")),
                ))
            }
        }
        ConfigFieldKind::Enum {
            source: EnumSource::Discovered,
        } => Err(Error::new(
            ErrorCode::Unsupported,
            format!(
                "field '{}' uses runtime-discovered enum values, which are not yet supported in connect",
                field.display_name
            ),
        )),
    }
}

fn invalid_field(field: &ConfigField, raw: &str, why: &str) -> Error {
    Error::new(
        ErrorCode::InvalidArgument,
        format!("invalid value '{raw}' for {}: {why}", field.display_name),
    )
}

fn pick_credentials_non_interactive(
    descriptor: &StorageBackendKindDescriptor,
    config: &HashMap<String, ConfigValue>,
    auth: Option<&str>,
) -> ovstorage::Result<GatheredCredentials> {
    // No --auth (or `--auth none`) means an empty bundle: the plugin decides
    // what to do (anonymous for cloud, OAuth-via-AwaitingAuth for Nucleus,
    // no-op for filesystem-style backends).
    if auth.is_none() || auth == Some("none") {
        return Ok(GatheredCredentials::backend_decides(HashMap::new()));
    }
    if descriptor.credential_methods.is_empty() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "backend '{}' has no credential methods; --auth not applicable",
                descriptor.kind
            ),
        ));
    }
    let id = auth.expect("checked above");
    let method = descriptor
        .credential_methods
        .iter()
        .find(|m| m.key == id)
        .ok_or_else(|| {
            let mut known: Vec<&str> = descriptor
                .credential_methods
                .iter()
                .map(|m| m.key.as_str())
                .collect();
            known.push("none");
            Error::new(
                ErrorCode::NotFound,
                format!(
                    "no credential method '{id}' on backend '{}'; known methods: {}",
                    descriptor.kind,
                    known.join(", "),
                ),
            )
        })?;
    require_credential_method_applies(descriptor, config, method)?;
    let fields = populate_from_method(descriptor, method)?;
    Ok(GatheredCredentials::from_method(fields, method))
}

/// Whether a credential method applies to the configured address.
///
/// Credential methods are kind-wide descriptor data. The services client is
/// the one backend whose two address modes disagree: a direct gRPC endpoint
/// consumes a pre-issued string token, while a discovery endpoint obtains
/// credentials through its published OIDC endpoints. The address is already
/// available here, so expose only the methods the configured mode can use.
fn credential_method_applies(
    descriptor: &StorageBackendKindDescriptor,
    config: &HashMap<String, ConfigValue>,
    method: &CredentialMethod,
) -> bool {
    if descriptor.kind != "omniverse-storage-service" {
        return true;
    }
    let direct = match config.get("address") {
        Some(ConfigValue::String(address)) => {
            let address = address.trim().as_bytes();
            [b"grpc://".as_slice(), b"grpcs://".as_slice()]
                .into_iter()
                .any(|prefix| {
                    address
                        .get(..prefix.len())
                        .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
                })
        }
        _ => false,
    };
    match method.key.as_str() {
        "token" => direct,
        "interactive" | "client_credentials" => !direct,
        _ => true,
    }
}

fn require_credential_method_applies(
    descriptor: &StorageBackendKindDescriptor,
    config: &HashMap<String, ConfigValue>,
    method: &CredentialMethod,
) -> ovstorage::Result<()> {
    if credential_method_applies(descriptor, config, method) {
        return Ok(());
    }
    Err(Error::new(
        ErrorCode::InvalidArgument,
        format!(
            "credential method '{}' does not apply to this services-client address; use 'token' \
             for a direct grpc:// or grpcs:// address, and 'interactive' or \
             'client_credentials' for a discovery URL",
            method.key,
        ),
    ))
}

/// Build a credential map from a chosen method by prompting for each
/// referenced field.
fn populate_from_method(
    descriptor: &StorageBackendKindDescriptor,
    method: &CredentialMethod,
) -> ovstorage::Result<HashMap<String, String>> {
    let mut out = HashMap::new();
    for key in &method.fields {
        let Some(field) = descriptor.credential_schema.iter().find(|f| f.key == *key) else {
            return Err(Error::new(
                ErrorCode::Internal,
                format!(
                    "credential method '{}' references unknown field '{}'",
                    method.display_name, key
                ),
            ));
        };
        // Every field of a chosen method must be answered. Passing an empty
        // answer through to the backend instead would be silently unsafe for
        // the backends that treat empty as absent: S3 and Azure map an empty
        // secret to `None`, so an operator who explicitly picked a credential
        // method and pressed Enter would get an *anonymous* client, and
        // against a public bucket that reports success.
        //
        // HTTP Basic does have a legitimate empty half (an API key as the
        // user-id, RFC 7617). It is reachable through a declared
        // `[[ovstorage.connections]]` credentials table or a supplied bundle,
        // which is where a caller that wants it is; making the shared
        // interactive prompt permit it would trade a real cross-backend
        // hazard for that convenience.
        out.insert(field.key.clone(), prompt_credential_field_required(field)?);
    }
    Ok(out)
}

fn pick_backend(
    descriptors: Vec<StorageBackendKindDescriptor>,
) -> ovstorage::Result<StorageBackendKindDescriptor> {
    let labels: Vec<String> = descriptors
        .iter()
        .map(|d| {
            if d.display_name == d.kind {
                d.kind.clone()
            } else {
                format!("{}  ({})", d.display_name, d.kind)
            }
        })
        .collect();
    let chosen = Select::new("Backend?", labels.clone())
        .prompt()
        .map_err(map_inquire)?;
    let idx = labels.iter().position(|l| *l == chosen).expect("found");
    Ok(descriptors.into_iter().nth(idx).expect("found"))
}

fn walk_config_schema(
    descriptor: &StorageBackendKindDescriptor,
    advanced: bool,
) -> ovstorage::Result<HashMap<String, ConfigValue>> {
    let mut config = HashMap::new();
    for field in &descriptor.config_schema {
        if field.advanced && !advanced {
            continue;
        }
        if let Some(value) = prompt_config_field(field)? {
            config.insert(field.key.clone(), value);
        }
    }
    Ok(config)
}

fn prompt_config_field(field: &ConfigField) -> ovstorage::Result<Option<ConfigValue>> {
    let label = field_label(&field.display_name, field.required);
    match &field.kind {
        ConfigFieldKind::Url | ConfigFieldKind::Text | ConfigFieldKind::Path => {
            let text = text_prompt(&label, field, default_as_string(field))?;
            require_non_empty(field, text).map(|opt| opt.map(ConfigValue::String))
        }
        ConfigFieldKind::Integer => {
            if !field.required && !confirm_set_field(&field.display_name)? {
                return Ok(None);
            }
            let mut prompt = inquire::CustomType::<i64>::new(&label)
                .with_error_message("Please enter an integer.");
            if let Some(help) = &field.help {
                prompt = prompt.with_help_message(help);
            }
            if let Some(ConfigValue::Int(n)) = field.default {
                prompt = prompt.with_default(n);
            }
            let value = prompt.prompt().map_err(map_inquire)?;
            Ok(Some(ConfigValue::Int(value)))
        }
        ConfigFieldKind::Bool => {
            let mut prompt = inquire::Confirm::new(&label);
            if let Some(help) = &field.help {
                prompt = prompt.with_help_message(help);
            }
            if let Some(ConfigValue::Bool(b)) = field.default {
                prompt = prompt.with_default(b);
            } else {
                prompt = prompt.with_default(false);
            }
            let value = prompt.prompt().map_err(map_inquire)?;
            Ok(Some(ConfigValue::Bool(value)))
        }
        ConfigFieldKind::Enum {
            source: EnumSource::Static(variants),
        } => {
            if !field.required && !confirm_set_field(&field.display_name)? {
                return Ok(None);
            }
            let mut prompt = Select::new(&label, variants.clone());
            if let Some(help) = &field.help {
                prompt = prompt.with_help_message(help);
            }
            let value = prompt.prompt().map_err(map_inquire)?;
            Ok(Some(ConfigValue::String(value)))
        }
        ConfigFieldKind::Enum {
            source: EnumSource::Discovered,
        } => Err(Error::new(
            ErrorCode::Unsupported,
            format!(
                "field '{}' uses runtime-discovered enum values, which are not yet supported in connect",
                field.display_name
            ),
        )),
    }
}

/// Pick a credential method (when the descriptor advertises any) and
/// prompt only that method's referenced fields. The picker always offers
/// a `None` entry that produces an empty bundle (the plugin decides what
/// to do — anonymous, OAuth, no-op). Falls back to the per-field walk
/// when `--advanced` was passed.
fn gather_credentials(
    descriptor: &StorageBackendKindDescriptor,
    config: &HashMap<String, ConfigValue>,
    advanced: bool,
) -> ovstorage::Result<GatheredCredentials> {
    let visible_methods = visible_credential_methods(descriptor, config, advanced);
    if advanced {
        return Ok(GatheredCredentials::backend_decides(
            walk_credential_schema(descriptor)?,
        ));
    }
    if visible_methods.is_empty() {
        // Backend declares no methods (e.g. filesystem): no picker, empty bundle.
        return Ok(GatheredCredentials::backend_decides(HashMap::new()));
    }
    let Some(method) = pick_credential_method(&visible_methods)? else {
        return Ok(GatheredCredentials::backend_decides(HashMap::new()));
    };
    let fields = populate_from_method(descriptor, method)?;
    Ok(GatheredCredentials::from_method(fields, method))
}

fn visible_credential_methods<'a>(
    descriptor: &'a StorageBackendKindDescriptor,
    config: &HashMap<String, ConfigValue>,
    advanced: bool,
) -> Vec<&'a CredentialMethod> {
    descriptor
        .credential_methods
        .iter()
        .filter(|m| (!m.advanced || advanced) && credential_method_applies(descriptor, config, m))
        .collect()
}

/// Returns `Ok(None)` when the user picked the synthetic `None` entry.
fn pick_credential_method<'a>(
    methods: &[&'a CredentialMethod],
) -> ovstorage::Result<Option<&'a CredentialMethod>> {
    const NONE_LABEL: &str = "None";
    let mut labels: Vec<String> = Vec::with_capacity(methods.len() + 1);
    labels.push(NONE_LABEL.into());
    labels.extend(methods.iter().map(|m| m.display_name.clone()));
    let chosen = Select::new("Credential method?", labels.clone())
        .with_help_message(
            "Pick how you want to authenticate (pick None to send no credential and let the backend decide, for example for public buckets).",
        )
        .prompt()
        .map_err(map_inquire)?;
    if chosen == NONE_LABEL {
        return Ok(None);
    }
    let idx = labels
        .iter()
        .position(|l| *l == chosen)
        .expect("selection comes from this list");
    // labels[0] is None; methods[i] corresponds to labels[i+1]
    Ok(Some(methods[idx - 1]))
}

/// Legacy per-field walk: prompt every credential field individually.
/// Reachable via `--advanced` or when a backend's `credential_methods`
/// are empty.
fn walk_credential_schema(
    descriptor: &StorageBackendKindDescriptor,
) -> ovstorage::Result<HashMap<String, String>> {
    let mut out = HashMap::new();
    for field in &descriptor.credential_schema {
        if let Some(cred) = prompt_credential_field(field)? {
            out.insert(field.key.clone(), cred);
        }
    }
    Ok(out)
}

/// Prompt for a credential field driven by a chosen credential method.
/// Method-referenced fields are mandatory (the user already opted in by
/// picking the method).
/// Prompt for one field of a chosen credential method. Every field of a
/// chosen method must be answered — see `populate_from_method`.
fn prompt_credential_field_required(field: &CredentialField) -> ovstorage::Result<String> {
    let label = field_label(&field.display_name, true);
    let mut prompt = Password::new(&label)
        .with_display_mode(PasswordDisplayMode::Masked)
        .without_confirmation();
    if let Some(help) = &field.help {
        prompt = prompt.with_help_message(help);
    }
    let value = prompt.prompt().map_err(map_inquire)?;
    if value.is_empty() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("{} is required", field.display_name),
        ));
    }
    Ok(value)
}

fn prompt_credential_field(field: &CredentialField) -> ovstorage::Result<Option<String>> {
    if !confirm_set_field(&field.display_name)? {
        return Ok(None);
    }
    let label = field_label(&field.display_name, false);
    let mut prompt = Password::new(&label)
        .with_display_mode(PasswordDisplayMode::Masked)
        .without_confirmation();
    if let Some(help) = &field.help {
        prompt = prompt.with_help_message(help);
    }
    let value = prompt.prompt().map_err(map_inquire)?;
    if value.is_empty() {
        Ok(None)
    } else {
        Ok(Some(value))
    }
}

/// Drive interactive auth for an existing connection (looked up by
/// `display_name`). Used by the `reauth <name>` CLI subcommand when a
/// refresh token has expired or the user wants to re-authenticate
/// without rebuilding the connection config. Surfaces the same
/// `OpenBrowser` / `DeviceCode` / `Progress` events as `connect`.
pub async fn reauth(
    state: &SessionState,
    name: &str,
    cancel: &CancellationToken,
) -> ovstorage::Result<()> {
    let connections = state.stack.list_connections(None).await?;
    let mut matches = connections
        .iter()
        .filter(|c| c.display_name == name)
        .collect::<Vec<_>>();
    if matches.is_empty() {
        return Err(Error::new(
            ErrorCode::NotFound,
            format!("no connection with display_name '{name}'"),
        ));
    }
    if matches.len() > 1 {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "display_name '{name}' is ambiguous ({} connections); rename one to disambiguate",
                matches.len()
            ),
        ));
    }
    let connection = matches.remove(0);
    eprintln!("authenticating '{}'…", connection.display_name);
    // `NoFlowOffered` is "the first `authenticate_connection` answered
    // `Unsupported`". That is usually the `Layer` leaf default, but not
    // always — an alias layer refuses a credentialless visibility-override
    // row with `Unsupported` too, and so does a remote service that does not
    // implement the RPC. Each says something different and more useful than
    // "this backend kind has no flow", so the backend's own error is what
    // `drive_authentication` hands back rather than one invented here.
    let connection =
        match drive_authentication_on_owner(state.stack.as_ref(), connection, cancel).await? {
            AuthOutcome::Flowed(connection) => connection,
            // `NoFlowOffered` arrives when no candidate offered a flow — every
            // layer that could hold this connection answered `Unsupported`, so
            // there is genuinely nothing to sign in to. `TargetNotFound` cannot
            // arrive (an exhausted scan is an error); handled rather than
            // `unreachable!` so a later change cannot make it a panic.
            AuthOutcome::NoFlowOffered(err) | AuthOutcome::TargetNotFound(err) => return Err(err),
        };
    // Same rule as `connect`: a flow that ends with the credential still
    // refused is not an `ok`, and the exit status is the only part of that a
    // script can read.
    if let ConnectionAuthState::AuthFailed { error, .. } = &connection.auth_state {
        eprintln!("  the backend refused these credentials.");
        return Err(error.clone());
    }
    eprintln!("ok ({}).", connection.display_name);
    Ok(())
}

/// Drive interactive auth for a connection whose OWNING LAYER is unknown.
///
/// `reauth` starts from a `Connection` snapshot, and a snapshot carries no
/// owning target — but a `ConnectionKey` needs one. The old answer was to
/// derive it from `backend_kind`, which cannot work: connection identity is
/// `(target, id)` where `target` is a graph-unique layer INSTANCE name, so a
/// graph with two layers of one kind made `resolve_backend_target` report "kind
/// is ambiguous" and `reauth` was simply unreachable there. That resolution
/// stays where it is correct — [`run`]'s add path, where a genuinely new
/// connection does need the operator to name a layer — and is not used here.
///
/// **The connection's own `owning_target` is the first and best answer**, and it
/// is not one of the two mechanisms below: the layer holding the connection
/// reported which layer that is, so nothing is derived and nothing is
/// attempted. It also answers in the states this command exists for — a
/// connection parked in `AwaitingAuth` or refused into `AuthFailed` carries its
/// target whether or not it publishes a root. Everything after it is the
/// fallback for a row a loaded composite plugin left unattributed.
///
/// Two exact mechanisms replace it, chosen by what is actually in hand:
///
/// 1. **An address the connection is PROVEN to serve.** A route lookup answers
///    which layer instance *serves* an address — but "serves" is longest-prefix,
///    and the layer that wins a route is not always the layer that holds this
///    connection. A broader sibling root that merely contains the address
///    answers, and so does the incumbent of a partial collision: the Router
///    keeps a connection whose roots collide only in part and shadows the
///    contested one, so a connection really can publish an address another
///    layer's connection won. The published root is therefore checked first —
///    same node, and a `connection_id` equal to this connection's — and the
///    target is read from that same root, which is [`owner_at`], the helper the
///    rotation path uses. That is what makes it a derivation rather than a
///    search: no flow is driven against a layer that turns out not to own the
///    connection.
/// 2. **The id alone, otherwise.** A connection parked in `AwaitingAuth` or
///    refused into `AuthFailed` may publish no root at all — and those are the
///    states `reauth` exists to serve — so there is nothing to derive from. The
///    same is true of an address whose route belongs to somebody else: an answer
///    about another connection is not a weaker derivation, it is none.
///    Ownership is discovered instead, by attempting the operation against each
///    of `owned_targets()`.
///
/// **Both rest on the id naming ONE connection in the graph, so that is checked
/// first.** An id is unique only within its owning target, and the alias layer
/// takes a caller-supplied one verbatim, so two layers really can both hold
/// `rule`. The scan would then reach a namesake and drive an interactive flow
/// against it. Less obviously, so would the derivation: a shadowed address
/// resolves to the layer that WON that root, and if the winner's connection
/// carries the same id, the published root names our id while describing
/// somebody else's connection — and once both rows are unattributed, which is
/// the only way execution reaches here, the two are identical in every field
/// the check can see. A shared id is therefore refused outright,
/// as `disconnect` refuses it (`connections::resolve_selector`,
/// `connections::remove_resolved`), and nothing downstream has to reason about
/// it. Once the id is known unique, id equality IS ownership: only one
/// connection in the graph can answer to it.
///
/// **Two answers advance the scan, because neither is about ownership.**
///
/// [`AuthOutcome::TargetNotFound`] is the obvious one — a `NotFound` the FIRST
/// `authenticate_connection` raised, before any flow began. (A `NotFound` from a
/// flow already in progress propagates, because retrying that against a sibling
/// would drive a second interactive flow over a failure that had nothing to do
/// with ownership.)
///
/// [`AuthOutcome::NoFlowOffered`] is the one that is easy to get wrong. The
/// `Layer` leaf default answers `Unsupported` for `authenticate_connection`
/// **without ever reading the key**, so a layer that has no interactive flow at
/// all — `plugin-http` is the in-tree example — says exactly that for an id it
/// does not hold. Treating it as final ended the scan at whichever such layer
/// came first in `owned_targets()`, and reported "this backend has no
/// interactive flow" about a backend that was never asked. That is not a
/// hypothesis about ordering: the scan runs only when derivation failed, and it
/// fails for the connection that publishes no address at all — the parked
/// broker / services-client case, in a graph pairing one of those with an
/// `http` child, which is ordinary — as well as for one whose address resolves
/// to somebody else. So a `NoFlowOffered` is REMEMBERED and the scan continues;
/// a later candidate that actually owns the connection wins, and the remembered
/// answer is returned only if none does.
///
/// **Unless the candidate was DERIVED.** A derived candidate is the layer whose
/// published root names THIS connection, so ownership is established before
/// anything is attempted and that candidate's `Unsupported` is an answer about
/// this connection rather than about a key nobody read; it is returned at once.
/// The proof is what earns the finality — a bare `owning_target_for` would only
/// name the winner of a route, and making a route winner's key-blind
/// `Unsupported` final is how a shadowed address would end `reauth` on a layer
/// that never held the connection. Scanning past a proven owner, on the other
/// hand, asks layers that have nothing to do with this connection to
/// authenticate a key they do not hold — and a layer is under no obligation to
/// read that key before answering, which is the very premise of the paragraph
/// above. The owner has spoken; a flow driven anywhere else is at best noise
/// and at worst a browser opened on the wrong tenant. Remembering therefore
/// applies only to `owned_targets()` candidates, whose ownership is unknown, and
/// among those the first is kept because none of their `Unsupported` answers is
/// more authoritative than another's.
///
/// Anything else propagates. A layer that fails with some other code got far
/// enough to fail meaningfully, and continuing past it would bury a real
/// diagnosis under a final `NotFound`.
async fn drive_authentication_on_owner(
    graph: &dyn ovstorage::Layer,
    connection: &Connection,
    cancel: &CancellationToken,
) -> ovstorage::Result<AuthOutcome> {
    // **The row's own answer settles both questions at once.** `owning_target`
    // is the other half of the key, so there is nothing to derive and nothing
    // to scan — and the shared-id count below becomes moot, because a namesake
    // is a different `(target, id)` pair and this one names its own. A derived
    // candidate is what makes an `Unsupported` authoritative below; a reported
    // one is stronger still, so it is marked the same way.
    if let Some(target) = connection.owning_target.clone() {
        let key = ConnectionKey {
            target,
            id: connection.id.clone(),
        };
        return match drive_authentication(graph, key, cancel).await? {
            // Not "not mine, try the next" — the owning layer says this id is
            // gone. There is nowhere else to look and nothing to remember.
            AuthOutcome::TargetNotFound(err) => Err(err),
            outcome => Ok(outcome),
        };
    }

    // Everything below reasons from the id, so it has to name one connection
    // first. Counted in the graph's own listing rather than assumed from the
    // selector: `reauth` selects by display name, and a uniquely-named
    // connection may still share its id with another layer's row.
    let shared = ovstorage::ext::LayerExt::list_connections(graph, Some(cancel.clone()))
        .await?
        .iter()
        .filter(|other| other.id == connection.id)
        .count();
    if shared > 1 {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "connection id '{}' is held by {shared} connections and this one reports no \
                 owning layer, so it has to be found by trying each layer in turn — and that \
                 search drives a sign-in against whichever holds the id first, which may be a \
                 namesake rather than this connection. `list-connections` shows them with the \
                 owning target where there is one",
                connection.id.0
            ),
        ));
    }
    // Each candidate carries whether it was DERIVED — that is what decides
    // whether its `Unsupported` is authoritative below, so the flag is set only
    // where the published root says this connection is the one being served.
    let mut candidates: Vec<(String, bool)> = Vec::new();
    if let Some(address) = connection.current_addresses.first() {
        match owner_at(graph, address, cancel).await {
            Ok(Some(key)) if key.id == connection.id => candidates.push((key.target, true)),
            // Nothing derived, from an answer or from the lack of one. Unlike
            // the rotation path, an unread address costs nothing here: the scan
            // below needs no address at all, and it establishes ownership by
            // ATTEMPTING the operation rather than by trusting a lookup. Failing
            // the command over a derivation that is only ever a shortcut would
            // be strictly worse than taking the long way.
            Ok(_) => {}
            Err(err) if err.code() == ErrorCode::Cancelled => return Err(err),
            Err(_) => {}
        }
    }
    // Appended, not used instead: the derived target above is only a
    // preference. A duplicate costs nothing, since the derived candidate ends
    // the loop on every answer except `TargetNotFound` — and one target that
    // does not hold the id is not going to hold it a second time.
    candidates.extend(
        ovstorage::Layer::owned_targets(graph)
            .into_iter()
            .map(|target| (target, false)),
    );

    let mut no_flow: Option<AuthOutcome> = None;
    for (target, derived) in candidates {
        let key = ConnectionKey {
            target,
            id: connection.id.clone(),
        };
        match drive_authentication(graph, key, cancel).await? {
            AuthOutcome::TargetNotFound(_) => continue,
            // Final from the owner the published root proved; only a guess from
            // a candidate whose ownership was never established.
            outcome @ AuthOutcome::NoFlowOffered(_) => {
                if derived {
                    return Ok(outcome);
                }
                if no_flow.is_none() {
                    no_flow = Some(outcome);
                }
            }
            outcome => return Ok(outcome),
        }
    }
    if let Some(outcome) = no_flow {
        return Ok(outcome);
    }
    // Said in terms of the scan rather than by forwarding the last candidate's
    // refusal, which is a generic "connection not found" about one layer and
    // would read as though a particular layer had been addressed.
    Err(Error::new(
        ErrorCode::NotFound,
        format!("no layer owns connection '{}'", connection.id.0),
    ))
}

/// What driving `authenticate_connection` established.
#[allow(clippy::large_enum_variant)] // The common variant is the large one.
enum AuthOutcome {
    /// A flow ran to a terminal event, and this is the connection it left.
    Flowed(Connection),
    /// No flow was ever offered: the very first `authenticate_connection`
    /// answered `Unsupported`, carried here verbatim.
    ///
    /// That is usually the `Layer` leaf default, but not only — an alias
    /// layer refuses a credentialless visibility-override row the same way,
    /// and so does a remote service that has not implemented the RPC. Each
    /// explains itself better than any message this module could invent, so
    /// the error travels with the outcome instead of being discarded.
    ///
    /// **It says nothing about ownership.** The leaf default answers it without
    /// reading the key at all, so a layer with no flow says this for an id it
    /// does not hold just as readily as for one it does — which is why
    /// [`drive_authentication_on_owner`] keeps scanning past it rather than
    /// taking it as the answer. It is final only where ownership was
    /// established some other way first, as it is for that function's
    /// address-derived candidate.
    NoFlowOffered(Error),
    /// The key named no registered connection, and said so on the FIRST
    /// `authenticate_connection` — before any flow began.
    ///
    /// Separated from a plain `Err` so a caller SCANNING for the owning layer
    /// can tell "not mine, try the next target" from a `NotFound` raised part
    /// way through a running flow, which means something else entirely and must
    /// not restart the flow somewhere else. See
    /// [`drive_authentication_on_owner`]. A caller that resolved its own target
    /// treats this as the failure it is.
    TargetNotFound(Error),
}

/// `NoFlowOffered` is a different fact from a flow that ran and then failed
/// with `Unsupported`, which `AuthEvent::Failed` and
/// `update_connection_credentials` can both raise. Only the first is a reason
/// to keep a connection the caller asked for; the second means the flow
/// genuinely failed, so it propagates like any other error.
async fn drive_authentication(
    graph: &dyn ovstorage::Layer,
    key: ConnectionKey,
    cancel: &CancellationToken,
) -> ovstorage::Result<AuthOutcome> {
    let capability = ovstorage::auth::read_env_capability(&ovstorage::auth::StdEnv)
        .unwrap_or_else(|| ovstorage::auth::detect_default_capability(&ovstorage::auth::StdEnv));
    let mut stream = match ovstorage::Layer::authenticate_connection(
        graph,
        Request::new(AuthenticateRequest {
            key: key.clone(),
            capability,
            // The CLI opens the browser itself on the `OpenBrowser` event
            // (see below), so the backend must not auto-open it.
            auto_open_browser: false,
        }),
        Some(cancel.clone()),
    )
    .await
    {
        Ok(stream) => stream,
        Err(err) if err.code() == ErrorCode::Unsupported => {
            return Ok(AuthOutcome::NoFlowOffered(err));
        }
        // Only here, on the first call, can `NotFound` still mean "this layer
        // does not hold that key" rather than "the flow broke". Distinguishing
        // the two is what lets a caller scan for the owning layer.
        Err(err) if err.code() == ErrorCode::NotFound => {
            return Ok(AuthOutcome::TargetNotFound(err));
        }
        Err(err) => return Err(err),
    };
    let mut final_connection: Option<Connection> = None;
    loop {
        match next_or_cancel(stream, cancel).await {
            Step::Event(returned, event) => {
                stream = returned;
                match event? {
                    AuthEvent::OpenBrowser { url, expires_at } => {
                        eprintln!();
                        eprintln!("Open this URL to authenticate:");
                        eprintln!("  {url}");
                        if let Some(message) = expires_message(expires_at) {
                            eprintln!("  ({message})");
                        }
                        let _ = webbrowser::open(&url);
                    }
                    AuthEvent::DeviceCode {
                        user_code,
                        verification_url,
                        expires_at,
                        ..
                    } => {
                        eprintln!();
                        eprintln!("Visit {verification_url} and enter code:");
                        eprintln!("  {user_code}");
                        if let Some(message) = expires_message(expires_at) {
                            eprintln!("  ({message})");
                        }
                    }
                    AuthEvent::Progress { message } => {
                        eprintln!("  {message}");
                    }
                    AuthEvent::Succeeded {
                        connection,
                        credentials,
                    } => {
                        // The OAuth/interactive flow surfaces tokens on
                        // `Succeeded`; the Layer forwards the event without
                        // installing it, so route the bundle to the backend via
                        // `update_connection_credentials` before finishing.
                        // Without this the connection stays unauthenticated and
                        // the next RPC runs with no tokens. `credentials: None`
                        // means the flow installed tokens itself (warm-continue)
                        // or uses static creds — nothing to apply.
                        final_connection = Some(match credentials {
                            Some(bundle) => {
                                ovstorage::Layer::update_connection_credentials(
                                    graph,
                                    Request::new(UpdateConnectionCredentialsRequest {
                                        key: key.clone(),
                                        credentials: bundle,
                                    }),
                                    Some(cancel.clone()),
                                )
                                .await?
                            }
                            None => *connection,
                        });
                    }
                    AuthEvent::Failed { error } => return Err(error),
                    AuthEvent::Cancelled => {
                        return Err(Error::new(ErrorCode::Cancelled, "authentication cancelled"));
                    }
                }
            }
            Step::Done(_) => break,
            Step::Cancelled => {
                return Err(Error::new(ErrorCode::Cancelled, "operation cancelled"));
            }
        }
    }
    final_connection.map(AuthOutcome::Flowed).ok_or_else(|| {
        Error::new(
            ErrorCode::Internal,
            "authentication stream ended without a terminal event",
        )
    })
}

fn expires_message(expires_at: SystemTime) -> Option<String> {
    let remaining = expires_at.duration_since(SystemTime::now()).ok()?;
    let secs = remaining.as_secs();
    if secs == 0 {
        return None;
    }
    if secs >= 60 {
        Some(format!("expires in about {} minutes", secs / 60))
    } else {
        Some(format!("expires in {secs} seconds"))
    }
}

fn prompt_display_name() -> ovstorage::Result<Option<String>> {
    let value = Text::new("Display name (optional):")
        .with_help_message("Friendly label shown alongside this connection. Press Enter to skip.")
        .prompt_skippable()
        .map_err(map_inquire)?;
    Ok(value.and_then(non_empty_string))
}

fn print_success(connection: &Connection, display_name: Option<&str>) {
    // A refused credential is still a registration — a backend records what
    // its probe learned rather than refusing the add — but it is not a
    // connection the operator can use, so it must not be announced as one.
    // Only a settled identity is announced as a connection. An unproven one
    // is registered and serves reads, but saying `Connected` over it is the
    // same over-claim as saying it over a refusal — the stderr note beneath
    // carries the detail, and the headline must not contradict it.
    let headline = match connection.auth_state {
        ConnectionAuthState::AuthFailed { .. } => "Registered, but not authenticated",
        ConnectionAuthState::AwaitingAuth { .. } => "Registered, credential unconfirmed",
        ConnectionAuthState::Anonymous | ConnectionAuthState::Authenticated { .. } => "Connected",
    };
    print_outcome(connection, display_name, headline);
}

/// The same report for a connection whose credentials were REPLACED rather
/// than registered.
///
/// The headlines are separate strings, not a shared "Connected", because the
/// two outcomes are different facts: nothing was added here, and an operator
/// who typed `connect` needs to see that what happened was a repair of a
/// connection that already existed. The state mapping underneath is the same
/// one `print_success` uses, for the same reason — a refusal must not read as
/// a clean success.
fn print_rotated(connection: &Connection) {
    let headline = match connection.auth_state {
        ConnectionAuthState::AuthFailed { .. } => {
            "Credentials replaced, but the origin refused them"
        }
        ConnectionAuthState::AwaitingAuth { .. } => "Credentials replaced, still unconfirmed",
        ConnectionAuthState::Anonymous | ConnectionAuthState::Authenticated { .. } => {
            "Credentials updated"
        }
    };
    // Credential rotation does not rename the incumbent connection. Report
    // the name returned by the backend, not the new request's `--name`.
    print_outcome(connection, None, headline);
}

fn print_outcome(connection: &Connection, display_name: Option<&str>, headline: &str) {
    println!();
    let label = display_name.filter(|s| !s.is_empty()).or({
        if connection.display_name.is_empty() {
            None
        } else {
            Some(connection.display_name.as_str())
        }
    });
    match label {
        Some(name) => println!("{headline}: {name} ({}).", connection.id.0),
        None => println!("{headline} ({}).", connection.id.0),
    }
    // Say plainly when the identity is not settled, or a refused credential
    // reads as a clean success.
    match &connection.auth_state {
        ConnectionAuthState::AuthFailed { error, .. } => {
            eprintln!(
                "  warning: the backend refused these credentials: {}",
                error.message()
            );
        }
        ConnectionAuthState::AwaitingAuth { reason, .. } => {
            // Not a failure: the connection is registered and serves reads.
            // The credential simply was not established, so say why in the
            // backend's own words rather than printing the enum.
            let because = match reason {
                ovstorage::AuthReason::Unknown { details } => details.clone(),
                other => format!("{other:?}"),
            };
            eprintln!("  note: registered, but the credential was not confirmed ({because}).");
        }
        ConnectionAuthState::Anonymous | ConnectionAuthState::Authenticated { .. } => {}
    }
    if !connection.current_addresses.is_empty() {
        println!("Visible roots:");
        for addr in &connection.current_addresses {
            println!("  {addr}");
        }
    }
    println!();
    println!("Run `write-config <PATH>` to persist this connection to TOML.");
}

fn text_prompt(
    label: &str,
    field: &ConfigField,
    default: Option<String>,
) -> ovstorage::Result<String> {
    let mut prompt = Text::new(label);
    if let Some(help) = &field.help {
        prompt = prompt.with_help_message(help);
    }
    if let Some(example) = &field.example {
        prompt = prompt.with_placeholder(example);
    }
    if let Some(d) = default.as_deref() {
        prompt = prompt.with_default(d);
    }
    prompt.prompt().map_err(map_inquire)
}

fn confirm_set_field(name: &str) -> ovstorage::Result<bool> {
    inquire::Confirm::new(&format!("Set optional field '{name}'?"))
        .with_default(false)
        .prompt()
        .map_err(map_inquire)
}

fn field_label(display_name: &str, required: bool) -> String {
    if required {
        format!("{display_name} *")
    } else {
        display_name.to_string()
    }
}

fn default_as_string(field: &ConfigField) -> Option<String> {
    match &field.default {
        Some(ConfigValue::String(s)) => Some(s.clone()),
        _ => None,
    }
}

fn non_empty_string(s: String) -> Option<String> {
    if s.trim().is_empty() { None } else { Some(s) }
}

/// Required schema fields must be filled. The CLI's contract with
/// `descriptor.config_schema` is that `required = true` is honored before
/// the value reaches `add_connection`; otherwise the backend sees a
/// missing field and surfaces a less actionable error.
fn require_non_empty(field: &ConfigField, value: String) -> ovstorage::Result<Option<String>> {
    match (non_empty_string(value), field.required) {
        (Some(v), _) => Ok(Some(v)),
        (None, true) => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("{} is required", field.display_name),
        )),
        (None, false) => Ok(None),
    }
}

fn map_inquire(err: inquire::InquireError) -> Error {
    use inquire::InquireError::*;
    match err {
        OperationCanceled | OperationInterrupted => {
            Error::new(ErrorCode::Cancelled, "operation cancelled")
        }
        IO(io) => Error::new(ErrorCode::Internal, format!("input error: {io}")),
        InvalidConfiguration(msg) => Error::new(ErrorCode::InvalidArgument, msg),
        NotTTY => Error::new(
            ErrorCode::InvalidArgument,
            "interactive prompts require a terminal; run from a TTY",
        ),
        Custom(msg) => Error::new(ErrorCode::Internal, msg.to_string()),
    }
}

/// The route table's prefixes, one per line.
///
/// Prefixes go through [`ovstorage::redact_url`] for the reason
/// `list-connections`' address column does — an inventory command's output is
/// kept, and a route prefix can carry userinfo or a signed-URL credential — and
/// the two are redacted the same way so a prefix reads identically in both.
pub(crate) async fn list_routes(
    state: &SessionState,
    cancel: &CancellationToken,
) -> ovstorage::Result<()> {
    let stack = &state.stack;
    println!("prefix\tbackend\tvisibility\talias_state");
    let roots = stack.list_address_roots(None).await?;
    let advertised: HashSet<_> = roots.iter().map(|root| root.root.clone()).collect();
    for root in roots {
        if let Some(row) = route_row(&root) {
            println!("{row}");
        }
    }
    for root in unresolved_alias_roots(stack.as_ref(), &advertised, cancel).await? {
        println!(
            "{}",
            route_row(&root).expect("visible alias diagnostic row")
        );
    }
    Ok(())
}

/// Return local alias diagnostics that advertised roots deliberately omit.
///
/// A dangling alias is a broker configuration error, not a route a client can
/// use, so it must not enter a brokered client's root snapshot. Its own alias
/// connection remains locally enumerable, however. Looking it up through the
/// live Stack produces the caller-facing `RootInfo` and its terminal state.
async fn unresolved_alias_roots(
    stack: &Stack,
    advertised: &HashSet<Url>,
    cancel: &CancellationToken,
) -> ovstorage::Result<Vec<RootInfo>> {
    let connections = stack.list_connections(Some(cancel.clone())).await?;
    let mut roots = Vec::new();
    let mut seen = HashSet::new();
    for connection in connections {
        if connection.backend_kind != ovstorage::layers::ALIAS_KIND
            || !connection
                .user_metadata
                .contains_key(ovstorage::layers::ALIAS_TO_METADATA_KEY)
        {
            continue;
        }
        for address in connection.current_addresses {
            if advertised.contains(&address) {
                continue;
            }
            match ovstorage::Layer::root_info_for(
                stack,
                &address,
                &Extensions::new(),
                Some(cancel.clone()),
            )
            .await
            {
                Ok(info) => {
                    let unresolved = info
                        .alias_state
                        .as_ref()
                        .is_some_and(|state| state != &ovstorage::AliasState::Live);
                    if unresolved
                        && info.visibility == AddressVisibility::Visible
                        && !advertised.contains(&info.root)
                        && seen.insert(info.root.clone())
                    {
                        roots.push(info);
                    }
                }
                Err(error) if error.code() == ErrorCode::NoRoute => {}
                Err(error) => return Err(error),
            }
        }
    }
    Ok(roots)
}

fn route_row(root: &RootInfo) -> Option<String> {
    // Hidden roots stay addressable and appear in doctor/MCP with their true
    // visibility. Suppressed roots never reach this surface because the
    // advertised-root projection omits them.
    (root.visibility == AddressVisibility::Visible).then(|| {
        format!(
            "{}\t{}\t{:?}\t{}",
            ovstorage::redact_url(&root.root),
            root.layer_kind,
            root.visibility,
            root.alias_state
                .as_ref()
                .map_or_else(String::new, |state| format!("{state:?}"))
        )
    })
}

pub(crate) fn list_backends(state: &SessionState) -> ovstorage::Result<()> {
    let stack = &state.stack;
    println!("kind\tdisplay_name\truntime_add");
    for descriptor in stack.list_backend_kinds()? {
        println!(
            "{}\t{}\t{}",
            descriptor.kind, descriptor.display_name, descriptor.supports_runtime_add
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};
    use std::sync::Arc;
    use std::time::Duration;

    use super::{
        Args, AuthenticationIntent, GatheredCredentials, backend_target_named,
        credential_method_applies, is_unusable, pick_credentials_non_interactive,
        populate_from_method, require_credential_method_applies, resolve_backend_target, route_row,
        run, unresolved_alias_roots, visible_credential_methods,
    };
    use ovstorage::{
        AddressVisibility, AliasState, AuthAttempt, AuthReason, CancellationToken, Capabilities,
        ConfigValue, Connection, ConnectionAuthState, ConnectionId, ConnectionSnapshot,
        ConnectionSource, ConnectionUpdateStream, CredentialMethod, Error, ErrorCode, Extensions,
        Layer, LayerKindDescriptor, LayerSpec, LayerType, RootInfo, StackSpec,
        StorageBackendKindDescriptor, Url, UserMetadata,
    };
    use tokio::sync::Notify;

    struct DiagnosticParkingLayer {
        park_connections: bool,
        entered: Notify,
    }

    impl DiagnosticParkingLayer {
        fn new(park_connections: bool) -> Arc<Self> {
            Arc::new(Self {
                park_connections,
                entered: Notify::new(),
            })
        }

        async fn park(&self, cancel: Option<CancellationToken>) -> ovstorage::Result<()> {
            self.entered.notify_one();
            match cancel {
                Some(token) => {
                    token.cancelled().await;
                    Err(Error::new(
                        ErrorCode::Cancelled,
                        "diagnostic operation cancelled",
                    ))
                }
                None => std::future::pending().await,
            }
        }
    }

    #[async_trait::async_trait]
    impl Layer for DiagnosticParkingLayer {
        fn name(&self) -> &str {
            "diagnostics"
        }

        fn descriptor(&self) -> LayerKindDescriptor {
            LayerKindDescriptor {
                kind: "diagnostics".to_string(),
                layer_type: LayerType::Backend,
                display_name: "diagnostics".to_string(),
                description: None,
                config_schema: Vec::new(),
                credential_schema: Vec::new(),
                credential_methods: Vec::new(),
                icon: None,
                accepts_connections: false,
                auth_capable: false,
                supports_user_metadata: false,
            }
        }

        async fn root_info_for(
            &self,
            _url: &Url,
            _cx: &Extensions,
            cancel: Option<CancellationToken>,
        ) -> ovstorage::Result<RootInfo> {
            self.park(cancel).await?;
            unreachable!("a parked diagnostic root lookup cannot complete")
        }

        async fn list_connections(
            &self,
            _cx: &Extensions,
            cancel: Option<CancellationToken>,
        ) -> ovstorage::Result<(ConnectionSnapshot, Option<ConnectionUpdateStream>)> {
            if self.park_connections {
                self.park(cancel).await?;
            }
            Ok((
                ConnectionSnapshot {
                    connections: vec![Connection {
                        id: ConnectionId("alias".to_string()),
                        backend_kind: ovstorage::layers::ALIAS_KIND.to_string(),
                        display_name: "alias".to_string(),
                        source: ConnectionSource::Runtime { persisted: false },
                        capabilities: Capabilities::empty(),
                        current_addresses: vec![Url::parse("alias:///dangling/").unwrap()],
                        auth_state: ConnectionAuthState::Anonymous,
                        last_probed: None,
                        user_metadata: UserMetadata::from([(
                            ovstorage::layers::ALIAS_TO_METADATA_KEY.to_string(),
                            "missing:///target/".to_string(),
                        )]),
                        owning_target: None,
                    }],
                    updates: false,
                },
                None,
            ))
        }
    }

    fn route_with_visibility(visibility: AddressVisibility) -> RootInfo {
        RootInfo {
            root: ovstorage::address::parse("https://user:secret@example.test/assets/").unwrap(),
            display_name: None,
            layer_kind: "test".into(),
            connection_id: None,
            owning_target: None,
            capabilities: ovstorage::Capabilities::empty(),
            range_read_strategy: ovstorage::RangeReadStrategy::default(),
            source: ovstorage::RouteSource::Static {
                layer: ovstorage::ConfigLayer::Programmatic,
            },
            visible: visibility == AddressVisibility::Visible,
            visibility,
            alias_state: None,
            icon: None,
            user_metadata: ovstorage::UserMetadata::new(),
        }
    }

    #[test]
    fn route_rows_include_only_visible_roots() {
        assert_eq!(
            route_row(&route_with_visibility(AddressVisibility::Visible)),
            Some("https://example.test/assets/\ttest\tVisible\t".into())
        );
        assert_eq!(
            route_row(&route_with_visibility(AddressVisibility::Hidden)),
            None
        );
        assert_eq!(
            route_row(&route_with_visibility(AddressVisibility::Suppressed)),
            None
        );

        let mut unresolved = route_with_visibility(AddressVisibility::Visible);
        unresolved.alias_state = Some(AliasState::Dangling);
        assert_eq!(
            route_row(&unresolved),
            Some("https://example.test/assets/\ttest\tVisible\tDangling".into())
        );
    }

    #[tokio::test]
    async fn list_routes_includes_unresolved_local_alias_diagnostics() {
        let config = ovstorage::StackConfig::from_toml_str(
            r#"
[ovstorage]
root = "alias"

[ovstorage.layers.alias]
kind = "alias"
inner = "file"

[[ovstorage.layers.alias.aliases]]
from = "alias:///content/"
to = "missing:///target/"

[ovstorage.layers.file]
kind = "file"
"#,
        )
        .unwrap();
        let stack = ovstorage::host::build_stack(&config, crate::commands::test_layer_factories())
            .await
            .unwrap();

        let advertised = ovstorage::ext::LayerExt::list_address_roots(stack.as_ref(), None)
            .await
            .unwrap();
        assert!(advertised.is_empty(), "dangling aliases are not advertised");
        let cancel = ovstorage::CancellationToken::new();
        let diagnostics = unresolved_alias_roots(stack.as_ref(), &HashSet::new(), &cancel)
            .await
            .unwrap();
        assert_eq!(diagnostics.len(), 1, "the local alias is diagnosed");
        assert_eq!(diagnostics[0].root.as_str(), "alias:///content/");
        assert_eq!(diagnostics[0].alias_state, Some(AliasState::Dangling));
        assert_eq!(
            route_row(&diagnostics[0]),
            Some("alias:///content/\talias\tVisible\tDangling".into())
        );

        let advertised: HashSet<_> = diagnostics.iter().map(|root| root.root.clone()).collect();
        assert!(
            unresolved_alias_roots(stack.as_ref(), &advertised, &cancel)
                .await
                .unwrap()
                .is_empty(),
            "a root already advertised must not be repeated as a local diagnostic"
        );
    }

    #[tokio::test]
    async fn live_alias_visibility_rows_do_not_duplicate_advertised_routes() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Url::from_directory_path(tmp.path()).unwrap();
        let config = ovstorage::StackConfig::from_toml_str(&format!(
            r#"
[ovstorage]
root = "alias"

[ovstorage.layers.alias]
kind = "alias"
inner = "file"

[[ovstorage.layers.alias.aliases]]
from = "alias:///content/"
to = "{root}"

[[ovstorage.layers.alias.visibility]]
address = "alias:///content/sub/"
visibility = "hidden"

[ovstorage.layers.file]
kind = "file"

[[ovstorage.connections]]
backend_kind = "file"

[ovstorage.connections.config]
root = "{root}"
"#
        ))
        .unwrap();
        let stack = ovstorage::host::build_stack(&config, crate::commands::test_layer_factories())
            .await
            .unwrap();
        let advertised: HashSet<_> =
            ovstorage::ext::LayerExt::list_address_roots(stack.as_ref(), None)
                .await
                .unwrap()
                .into_iter()
                .map(|info| info.root)
                .collect();

        assert!(advertised.contains(&Url::parse("alias:///content/").unwrap()));
        assert!(
            unresolved_alias_roots(stack.as_ref(), &advertised, &CancellationToken::new())
                .await
                .unwrap()
                .is_empty(),
            "a visibility-only connection must neither be queried nor duplicate its live alias root"
        );
    }

    #[tokio::test]
    async fn list_routes_propagates_dangling_state_through_stacked_aliases() {
        let config = ovstorage::StackConfig::from_toml_str(
            r#"
[ovstorage]
root = "outer"

[ovstorage.layers.outer]
kind = "alias"
inner = "inner"

[[ovstorage.layers.outer.aliases]]
from = "outer:///content/"
to = "inner:///content/"

[ovstorage.layers.inner]
kind = "alias"
inner = "file"

[[ovstorage.layers.inner.aliases]]
from = "inner:///content/"
to = "missing:///target/"

[ovstorage.layers.file]
kind = "file"
"#,
        )
        .unwrap();
        let stack = ovstorage::host::build_stack(&config, crate::commands::test_layer_factories())
            .await
            .unwrap();
        let cancel = ovstorage::CancellationToken::new();

        let diagnostics = unresolved_alias_roots(stack.as_ref(), &HashSet::new(), &cancel)
            .await
            .unwrap();
        let outer = diagnostics
            .iter()
            .find(|root| root.root.as_str() == "outer:///content/")
            .expect("the outer dangling alias is diagnosed");

        assert_eq!(outer.alias_state, Some(AliasState::Dangling));
        assert_eq!(
            route_row(outer),
            Some("outer:///content/\talias\tVisible\tDangling".into())
        );
    }

    #[tokio::test]
    async fn unresolved_alias_diagnostics_cancel_parked_inventory_and_root_lookups() {
        for park_connections in [true, false] {
            let layer = DiagnosticParkingLayer::new(park_connections);
            let stack = Arc::new(
                ovstorage::Stack::builder("diagnostics")
                    .attach("diagnostics", layer.clone())
                    .build()
                    .await
                    .unwrap(),
            );
            let cancel = CancellationToken::new();
            let query_cancel = cancel.clone();
            let query_stack = stack.clone();
            let query = tokio::spawn(async move {
                unresolved_alias_roots(query_stack.as_ref(), &HashSet::new(), &query_cancel).await
            });

            layer.entered.notified().await;
            cancel.cancel();
            let err = tokio::time::timeout(Duration::from_millis(100), query)
                .await
                .expect("cancelled diagnostic query must not remain parked")
                .expect("diagnostic query task must not panic")
                .expect_err("cancelled diagnostic query must fail");
            assert_eq!(err.code(), ErrorCode::Cancelled);
        }
    }

    #[tokio::test]
    async fn connect_unconfigured_stack_points_to_init() {
        let config = ovstorage::StackConfig::default();
        let stack = ovstorage::host::build_stack(&config, crate::commands::test_layer_factories())
            .await
            .unwrap();
        let mut state = crate::session::SessionState::build(stack, config)
            .await
            .unwrap();
        let args = Args {
            kind: None,
            fields: Vec::new(),
            auth: None,
            name: None,
            target: None,
            advanced: false,
        };

        let err = run(&mut state, args, &ovstorage::CancellationToken::new())
            .await
            .unwrap_err();

        assert_eq!(err.code(), ErrorCode::NotConfigured);
        assert!(
            err.message().contains("ovstorage init"),
            "empty-stack recovery must point users to init: {}",
            err.message()
        );
        assert!(
            err.message().contains("[ovstorage.layers]"),
            "configured-stack recovery must remain discoverable: {}",
            err.message()
        );
    }

    /// A flow-driving credential method declares no fields because
    /// `authenticate_connection` performs the interaction. The services-client
    /// method correction relies on that declaration producing an empty bundle
    /// immediately, without entering the credential prompt path.
    #[test]
    fn a_zero_field_credential_method_produces_an_empty_bundle_without_prompting() {
        let descriptor = StorageBackendKindDescriptor {
            kind: "flow-driven".to_string(),
            display_name: "Flow-driven backend".to_string(),
            description: None,
            config_schema: Vec::new(),
            credential_schema: Vec::new(),
            credential_methods: Vec::new(),
            icon: None,
            supports_runtime_add: true,
            supports_user_metadata: false,
        };
        let method = CredentialMethod {
            key: "interactive".to_string(),
            display_name: "Interactive sign-in".to_string(),
            fields: Vec::new(),
            help: None,
            advanced: false,
        };

        let bundle = populate_from_method(&descriptor, &method).expect("zero fields are valid");

        assert!(bundle.is_empty());
        let intent = AuthenticationIntent::for_method(&method);
        assert_eq!(intent, AuthenticationIntent::BackendMayDrive);
        let authenticated = ConnectionAuthState::Authenticated {
            last_authenticated_at: std::time::SystemTime::now(),
            expires_at: None,
        };
        assert!(
            !intent.should_drive(&authenticated),
            "a warm-continued identity must not be replaced by an unnecessary flow",
        );
        assert!(
            intent.should_drive(&ConnectionAuthState::AwaitingAuth {
                reason: AuthReason::NeverAuthenticated,
                last_attempt: None,
            }),
            "an unsettled zero-field method must still drive its authentication flow",
        );
        assert!(
            !GatheredCredentials::backend_decides(HashMap::new())
                .intent
                .should_drive(&authenticated),
            "the synthetic backend-decides path still accepts a settled identity",
        );
    }

    /// A field-bearing method names the complete intended identity. A concrete
    /// credential refusal must travel back without an interactive replacement,
    /// while a transient or inconclusive probe remains a routable unconfirmed
    /// registration rather than becoming a credential verdict.
    #[test]
    fn a_field_bearing_method_preserves_refusals_without_treating_outages_as_verdicts() {
        let method = CredentialMethod {
            key: "client_credentials".into(),
            display_name: "Client credentials".into(),
            fields: vec!["client_id".into(), "client_secret".into()],
            help: None,
            advanced: false,
        };
        let intent = AuthenticationIntent::for_method(&method);
        let refusal = Error::new(ErrorCode::AuthRequired, "client credentials were refused");
        let state = ConnectionAuthState::AwaitingAuth {
            reason: AuthReason::NeverAuthenticated,
            last_attempt: Some(AuthAttempt {
                at: std::time::SystemTime::now(),
                error: Some(refusal.clone()),
            }),
        };

        assert_eq!(intent, AuthenticationIntent::CredentialSupplied);
        assert!(!intent.should_drive(&state));
        assert_eq!(intent.supplied_credential_error(&state), Some(refusal));

        for reason in [
            AuthReason::BackendUnreachable,
            AuthReason::Unknown {
                details: "the root probe was inconclusive".into(),
            },
        ] {
            let state = ConnectionAuthState::AwaitingAuth {
                reason,
                last_attempt: Some(AuthAttempt {
                    at: std::time::SystemTime::now(),
                    error: Some(Error::new(ErrorCode::Transient, "probe unavailable")),
                }),
            };
            assert_eq!(
                intent.supplied_credential_error(&state),
                None,
                "an inconclusive attempt is not a credential refusal",
            );
            assert!(
                !is_unusable(&connection_with(state, &["https://storage.test/"])),
                "a routed unconfirmed connection keeps the successful registration outcome",
            );
        }
    }

    /// The services client's two address modes publish disjoint authentication
    /// facilities. Each picker must expose only its usable methods, and an
    /// explicit method from the other mode must fail before any credential
    /// prompt can gather a value that the endpoint cannot consume.
    #[test]
    fn services_client_methods_apply_only_to_the_address_mode_that_can_use_them() {
        let mut descriptor = StorageBackendKindDescriptor {
            kind: "omniverse-storage-service".into(),
            display_name: "Services client".into(),
            description: None,
            config_schema: Vec::new(),
            credential_schema: Vec::new(),
            credential_methods: Vec::new(),
            icon: None,
            supports_runtime_add: true,
            supports_user_metadata: false,
        };
        let token = CredentialMethod {
            key: "token".into(),
            display_name: "Pre-issued token".into(),
            fields: vec!["oauth".into()],
            help: None,
            advanced: false,
        };
        let interactive = CredentialMethod {
            key: "interactive".into(),
            display_name: "Interactive sign-in".into(),
            fields: Vec::new(),
            help: None,
            advanced: false,
        };
        let client_credentials = CredentialMethod {
            key: "client_credentials".into(),
            display_name: "Client credentials".into(),
            fields: vec!["client_id".into(), "client_secret".into()],
            help: None,
            advanced: false,
        };
        descriptor.credential_methods = vec![
            interactive.clone(),
            token.clone(),
            client_credentials.clone(),
        ];
        let config = |address: &str| {
            HashMap::from([("address".into(), ConfigValue::String(address.into()))])
        };

        for address in ["grpc://storage.test:50051", "GRPCS://storage.test:443"] {
            let direct = config(address);
            assert!(
                credential_method_applies(&descriptor, &direct, &token),
                "the token method must remain available for {address}",
            );
            for method in [&interactive, &client_credentials] {
                assert!(
                    !credential_method_applies(&descriptor, &direct, method),
                    "{} must be unavailable for {address}",
                    method.key,
                );
                let error = pick_credentials_non_interactive(
                    &descriptor,
                    &direct,
                    Some(method.key.as_str()),
                )
                .expect_err("a discovery-only method must be rejected before prompting");
                assert_eq!(error.code(), ErrorCode::InvalidArgument);
            }
        }
        let direct = config("grpcs://storage.test:443");
        assert_eq!(
            visible_credential_methods(&descriptor, &direct, false)
                .into_iter()
                .map(|method| method.key.as_str())
                .collect::<Vec<_>>(),
            ["token"],
            "the direct-endpoint picker must omit discovery-only methods",
        );

        let discovery = config("https://discovery.test");
        assert!(!credential_method_applies(&descriptor, &discovery, &token));
        assert_eq!(
            visible_credential_methods(&descriptor, &discovery, false)
                .into_iter()
                .map(|method| method.key.as_str())
                .collect::<Vec<_>>(),
            ["interactive", "client_credentials"],
            "the discovery picker must omit the unusable token method",
        );
        assert!(credential_method_applies(
            &descriptor,
            &discovery,
            &client_credentials
        ));
        let error = require_credential_method_applies(&descriptor, &discovery, &token)
            .expect_err("an explicit discovery token method is rejected before prompting");
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
        assert!(error.message().contains("does not apply"));
        let error = pick_credentials_non_interactive(&descriptor, &discovery, Some("token"))
            .expect_err("--auth token must be rejected before its field prompt");
        assert_eq!(error.code(), ErrorCode::InvalidArgument);

        let mut unrelated = descriptor;
        unrelated.kind = "another-backend".into();
        for method in [&interactive, &token, &client_credentials] {
            assert!(credential_method_applies(&unrelated, &direct, method));
            assert!(credential_method_applies(&unrelated, &discovery, method));
        }
    }

    fn connection_with(
        auth_state: ovstorage::ConnectionAuthState,
        roots: &[&str],
    ) -> ovstorage::Connection {
        ovstorage::Connection {
            id: ovstorage::ConnectionId("c1".into()),
            backend_kind: "test".into(),
            display_name: "test".into(),
            source: ovstorage::ConnectionSource::Runtime { persisted: false },
            capabilities: ovstorage::Capabilities::empty(),
            current_addresses: roots
                .iter()
                .map(|r| ovstorage::address::parse(r).unwrap())
                .collect(),
            auth_state,
            last_probed: None,
            user_metadata: ovstorage::UserMetadata::new(),
            owning_target: None,
        }
    }

    fn parked() -> ovstorage::ConnectionAuthState {
        ovstorage::ConnectionAuthState::AwaitingAuth {
            reason: ovstorage::AuthReason::NeverAuthenticated,
            last_attempt: None,
        }
    }

    /// The exit status turns on whether the connection can serve anything, not
    /// on whether its credential was confirmed. Both halves matter:
    ///
    /// - A parked connection that still publishes roots serves reads — the
    ///   cloud backends derive roots from config and publish them while parked
    ///   — so `connect` reports the state and exits 0.
    /// - A parked connection with no roots answers `NoRoute` to everything.
    ///   That is what a backend with no interactive flow leaves behind when its
    ///   credential is refused at bring-up, and exiting 0 over it tells a
    ///   script the opposite of what happened.
    #[test]
    fn only_a_parked_connection_with_no_roots_is_unusable() {
        assert!(
            is_unusable(&connection_with(parked(), &[])),
            "parked with no roots can serve nothing"
        );
        assert!(
            !is_unusable(&connection_with(parked(), &["azure://acct123/assets/"])),
            "parked but routable still serves reads"
        );
        assert!(
            !is_unusable(&connection_with(
                ovstorage::ConnectionAuthState::Anonymous,
                &[]
            )),
            "a settled connection is never unusable on this test, roots or not"
        );
        assert!(
            !is_unusable(&connection_with(
                ovstorage::ConnectionAuthState::Authenticated {
                    last_authenticated_at: std::time::SystemTime::now(),
                    expires_at: None,
                },
                &[],
            )),
            "an authenticated connection is settled"
        );
    }

    fn spec_with(layers: Vec<LayerSpec>) -> StackSpec {
        let mut spec = StackSpec::new("root");
        spec.layers = layers;
        spec
    }

    #[test]
    fn resolves_to_kind_when_backend_layer_is_named_after_its_kind() {
        // Default-stack convention: behavior is unchanged (target == kind).
        let spec = spec_with(vec![LayerSpec::backend("file", "file")]);
        assert_eq!(resolve_backend_target(&spec, "file").unwrap(), "file");
    }

    #[test]
    fn resolves_to_layer_name_when_named_differently_from_kind() {
        // Layer `s3_prod` of kind `s3` -> target is the Layer name.
        let spec = spec_with(vec![LayerSpec::backend("s3_prod", "s3")]);
        assert_eq!(resolve_backend_target(&spec, "s3").unwrap(), "s3_prod");
    }

    #[test]
    fn falls_back_to_kind_when_no_backend_layer_matches() {
        let spec = spec_with(vec![LayerSpec::backend("file", "file")]);
        assert_eq!(resolve_backend_target(&spec, "s3").unwrap(), "s3");
    }

    #[test]
    fn errors_when_several_backend_layers_match() {
        // Two backends of the same kind: the owning target is ambiguous, so the
        // kind cannot stand in for a real layer name. Resolution must reject the
        // ambiguity rather than synthesize `s3` (which names no layer and would
        // route `add_connection`/`authenticate_connection` at nothing).
        let spec = spec_with(vec![
            LayerSpec::backend("s3_a", "s3"),
            LayerSpec::backend("s3_b", "s3"),
        ]);
        let err = resolve_backend_target(&spec, "s3").unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        // Both candidate layer names are surfaced so the operator can target one.
        assert!(err.message().contains("s3_a"));
        assert!(err.message().contains("s3_b"));
    }

    #[test]
    fn the_ambiguity_error_names_the_flag_that_resolves_it() {
        // It told the operator to "target it by layer name" when nothing could.
        let spec = spec_with(vec![
            LayerSpec::backend("s3_a", "s3"),
            LayerSpec::backend("s3_b", "s3"),
        ]);
        let err = resolve_backend_target(&spec, "s3").unwrap_err();
        assert!(
            err.message().contains("--target"),
            "the advice has to name the thing that carries it out: {err}",
        );
    }

    #[test]
    fn an_explicit_target_resolves_an_ambiguous_kind() {
        // The whole point: a two-tenant graph is usable again — both for a new
        // connection and for the rotation that repairs a refused one, which
        // could never be reached while resolution failed before the add.
        let spec = spec_with(vec![
            LayerSpec::backend("http_a", "http"),
            LayerSpec::backend("http_b", "http"),
        ]);
        assert_eq!(
            backend_target_named(&spec, "http", "http_b").unwrap(),
            "http_b",
        );
    }

    #[test]
    fn an_explicit_target_of_another_kind_is_refused_by_name() {
        // The operator named a real layer and the mismatch is the point, so the
        // error says which kind it actually is rather than "not found".
        let spec = spec_with(vec![
            LayerSpec::backend("http_a", "http"),
            LayerSpec::backend("files", "file"),
        ]);
        let err = backend_target_named(&spec, "http", "files").unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert!(err.message().contains("'file'"), "{err}");
        assert!(
            err.message().contains("http_a"),
            "and what could have been meant: {err}",
        );
    }

    #[test]
    fn an_explicit_target_that_names_nothing_lists_what_exists() {
        let spec = spec_with(vec![LayerSpec::backend("http_a", "http")]);
        let err = backend_target_named(&spec, "http", "typo").unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert!(err.message().contains("http_a"), "{err}");
    }

    #[test]
    fn an_explicit_target_is_still_checked_when_the_kind_is_unambiguous() {
        // A single-layer graph must not accept any name at all: the connection
        // would be addressed at a target nothing routes.
        let spec = spec_with(vec![LayerSpec::backend("http_a", "http")]);
        assert_eq!(
            backend_target_named(&spec, "http", "http_a").unwrap(),
            "http_a",
        );
        assert!(backend_target_named(&spec, "http", "http_b").is_err());
    }

    #[test]
    fn ignores_non_backend_layers_of_the_same_kind() {
        // A wrapper/router named like the kind must not be selected as target.
        let spec = spec_with(vec![
            LayerSpec::wrapper("s3", "s3", "s3_prod"),
            LayerSpec::backend("s3_prod", "s3"),
        ]);
        assert_eq!(resolve_backend_target(&spec, "s3").unwrap(), "s3_prod");
    }

    mod rotation {
        use std::collections::HashMap;
        use std::io::{Read as _, Write as _};
        use std::net::TcpListener;
        use std::sync::{Arc, Mutex};
        use std::thread;

        use ovstorage::ext::LayerExt as _;
        use ovstorage::{
            ConfigField, ConfigFieldKind, ConnectionAuthState, ConnectionId, ConnectionKey, Error,
            ErrorCode, LayerConnectionRequest, Request, RootInfo, StorageBackendKindDescriptor,
            Url,
        };

        use super::super::{
            AuthOutcome, choose_incumbent, drive_authentication_on_owner, incumbent_id,
            names_one_endpoint, owner_at, record_committed_but_unconfirmed,
            record_rotated_credentials, replace_prompt, replacement_note, resolve_incumbent,
            rotate_on_conflict, route_candidates, sole_incumbent_row,
        };
        use crate::session::{SessionConnection, SessionState};

        // ---------------------------------------------------------------
        // The pure halves of incumbent resolution.
        // ---------------------------------------------------------------

        fn url(raw: &str) -> Url {
            ovstorage::address::parse(raw).unwrap()
        }

        fn root_at(root: &str, connection_id: Option<&str>) -> RootInfo {
            RootInfo {
                root: url(root),
                display_name: None,
                layer_kind: "http".to_string(),
                connection_id: connection_id.map(|id| ConnectionId(id.to_string())),
                owning_target: Some("http".to_string()),
                capabilities: ovstorage::Capabilities::empty(),
                range_read_strategy: ovstorage::RangeReadStrategy::default(),
                source: ovstorage::RouteSource::Static {
                    layer: ovstorage::ConfigLayer::Programmatic,
                },
                visible: true,
                visibility: ovstorage::AddressVisibility::Visible,
                alias_state: None,
                icon: None,
                user_metadata: ovstorage::UserMetadata::new(),
            }
        }

        #[test]
        fn a_root_that_merely_contains_the_address_is_not_the_incumbent() {
            // `root_info_for` answers with the longest-prefix match, so a
            // sibling serving the whole host comes back as a hit for an address
            // nested under it. That connection is not the one the refusal was
            // about; rotating its credentials would break a working tenant.
            let containing = root_at("https://h/", Some("c-other"));
            assert_eq!(incumbent_id(&containing, &url("https://h/team/")), None);
        }

        #[test]
        fn the_same_node_under_another_spelling_is_the_incumbent() {
            // `assets` and `assets/` are one node, and so are two spellings
            // differing only in userinfo — which is the whole reason a corrected
            // credential collides with the mistake it corrects.
            let incumbent = root_at("https://h/assets/", Some("c1"));
            assert_eq!(
                incumbent_id(&incumbent, &url("https://h/assets")),
                Some(ConnectionId("c1".to_string())),
            );
        }

        #[test]
        fn a_root_owning_no_connection_is_not_the_incumbent() {
            // A synthesized or statically declared root has no credential to
            // replace, so there is nothing here to rotate.
            let static_root = root_at("https://h/assets/", None);
            assert_eq!(incumbent_id(&static_root, &url("https://h/assets/")), None);
        }

        /// A graph whose only route is a granted scheme fallback: the route
        /// table's second tier answers every `s3://…` address that nothing
        /// else routes with the `s3:///` root itself. `owning_target_for`
        /// names the layer, the way a real graph's leaf rule would, so the
        /// test proves the answer is refused BEFORE the target is consulted.
        struct SchemeFallbackGraph;

        #[async_trait::async_trait]
        impl ovstorage::Layer for SchemeFallbackGraph {
            fn name(&self) -> &str {
                "s3"
            }

            fn descriptor(&self) -> ovstorage::LayerKindDescriptor {
                ovstorage::LayerKindDescriptor {
                    kind: "s3".to_string(),
                    layer_type: ovstorage::LayerType::Backend,
                    display_name: "s3".to_string(),
                    description: None,
                    config_schema: Vec::new(),
                    credential_schema: Vec::new(),
                    credential_methods: Vec::new(),
                    icon: None,
                    accepts_connections: true,
                    auth_capable: false,
                    supports_user_metadata: false,
                }
            }

            async fn root_info_for(
                &self,
                _url: &Url,
                _cx: &ovstorage::Extensions,
                _cancel: Option<ovstorage::CancellationToken>,
            ) -> ovstorage::Result<RootInfo> {
                ovstorage::fallback::scheme_fallback_root(
                    "s3",
                    "s3",
                    ovstorage::Capabilities::empty(),
                    None,
                )
            }

            async fn owning_target_for(
                &self,
                _url: &Url,
                _cx: &ovstorage::Extensions,
                _cancel: Option<ovstorage::CancellationToken>,
            ) -> Option<String> {
                Some("s3".to_string())
            }
        }

        #[tokio::test]
        async fn owner_at_treats_a_scheme_fallback_root_as_no_incumbent() {
            // The scheme root is a tier-two answer, not a prefix hit: `s3:///`
            // and `s3://x/` are different nodes, and the root owns no
            // connection besides. Either fact alone is enough for the
            // `same_node` guard; together they mean `ovstorage connect
            // s3://x/` sees an empty slot rather than a credential to rotate,
            // which is what lets the operator add the real connection.
            let fallback = ovstorage::fallback::scheme_fallback_root(
                "s3",
                "s3",
                ovstorage::Capabilities::empty(),
                None,
            )
            .unwrap();
            assert_eq!(incumbent_id(&fallback, &url("s3://x/")), None);
            assert_eq!(incumbent_id(&fallback, &url("s3://x/key")), None);

            let owner = owner_at(
                &SchemeFallbackGraph,
                &url("s3://x/"),
                &ovstorage::CancellationToken::new(),
            )
            .await
            .expect("a resolving address is not an error");
            assert!(
                owner.is_none(),
                "a fallback-served address names nothing to act on: {owner:?}"
            );
        }

        /// A graph whose published root names the layer that holds the
        /// connection, while `owning_target_for` answers with something else —
        /// the shape a LOADED COMPOSITE backend takes. Such a plugin reports
        /// several `owned_targets`, so the `Layer` default's leaf rule
        /// (`leaf_owning_target`) stops distinguishing them and falls back to
        /// the outer host-layer name, which no `route_target` can find. The
        /// root's own `owning_target` crossed the ABI and names the internal
        /// child.
        struct CompositeGraph {
            /// What the published root says: `(owning_target, connection id)`.
            /// `owning_target` is `None` for a plugin predating the field, and
            /// the id is `None` for a synthesized or static root.
            root: (Option<String>, Option<String>),
            /// What the leaf fallback answers — here the outer name.
            fallback: String,
        }

        #[async_trait::async_trait]
        impl ovstorage::Layer for CompositeGraph {
            fn name(&self) -> &str {
                "outer"
            }

            fn descriptor(&self) -> ovstorage::LayerKindDescriptor {
                ovstorage::LayerKindDescriptor {
                    kind: "composite".to_string(),
                    layer_type: ovstorage::LayerType::Backend,
                    display_name: "composite".to_string(),
                    description: None,
                    config_schema: Vec::new(),
                    credential_schema: Vec::new(),
                    credential_methods: Vec::new(),
                    icon: None,
                    accepts_connections: true,
                    // Not a listener authentication Layer; mirrors
                    // `plugin-http`, which declares no user metadata.
                    auth_capable: false,
                    supports_user_metadata: false,
                }
            }

            async fn root_info_for(
                &self,
                url: &Url,
                _cx: &ovstorage::Extensions,
                _cancel: Option<ovstorage::CancellationToken>,
            ) -> ovstorage::Result<RootInfo> {
                let mut info = root_at(url.as_str(), self.root.1.as_deref());
                info.owning_target = self.root.0.clone();
                Ok(info)
            }

            async fn owning_target_for(
                &self,
                _url: &Url,
                _cx: &ovstorage::Extensions,
                _cancel: Option<ovstorage::CancellationToken>,
            ) -> Option<String> {
                Some(self.fallback.clone())
            }
        }

        #[tokio::test]
        async fn the_target_comes_from_the_root_that_named_the_connection() {
            // Both halves of the key are facts about ONE route, so they are read
            // from one answer. Taking the target from a second lookup instead
            // built `ConnectionKey { target: "outer", .. }` for a connection
            // held by `inner`, and `update_connection_credentials` then answered
            // `NotFound` on a graph where the connection was sitting right
            // there.
            let graph = CompositeGraph {
                root: (Some("inner".to_string()), Some("c1".to_string())),
                fallback: "outer".to_string(),
            };
            let key = owner_at(
                &graph,
                &url("https://h/assets/"),
                &ovstorage::CancellationToken::new(),
            )
            .await
            .expect("a resolving address is not an error")
            .expect("the root names a connection");
            assert_eq!(
                key.target, "inner",
                "the layer that HOLDS the connection, not the one a leaf lookup falls back to",
            );
            assert_eq!(key.id, ConnectionId("c1".to_string()));
        }

        #[tokio::test]
        async fn a_root_without_an_owning_target_still_falls_back() {
            // The field crosses the plugin ABI, so a backend built before it
            // reports a connection and no target. The lookup is the
            // compatibility path for exactly that, and must stay.
            let graph = CompositeGraph {
                root: (None, Some("c1".to_string())),
                fallback: "http".to_string(),
            };
            let key = owner_at(
                &graph,
                &url("https://h/assets/"),
                &ovstorage::CancellationToken::new(),
            )
            .await
            .expect("a resolving address is not an error")
            .expect("the root names a connection");
            assert_eq!(key.target, "http");
        }

        #[tokio::test]
        async fn an_address_naming_no_connection_resolves_to_nothing() {
            // A synthesized or statically declared root owns no credential to
            // rotate, and a target on its own is not a connection: the key must
            // not be invented from the half that IS there.
            let graph = CompositeGraph {
                root: (Some("inner".to_string()), None),
                fallback: "outer".to_string(),
            };
            assert!(
                owner_at(
                    &graph,
                    &url("https://h/assets/"),
                    &ovstorage::CancellationToken::new()
                )
                .await
                .expect("a resolving address is not an error")
                .is_none(),
                "a root owning no connection names nothing to act on",
            );
        }

        /// A graph that answers each address differently: a root naming
        /// `(target, id)`, or a failure code. An address it was not told about
        /// answers `NoRoute`, which is what a config address that is not itself
        /// a route gets.
        struct PerAddressGraph {
            answers: Vec<(String, Answer)>,
        }

        /// What the graph says about one address.
        #[derive(Clone)]
        enum Answer {
            /// A published root naming `(owning target, connection id)`.
            Root(String, String),
            /// The graph could not say, with this code.
            Failure(ErrorCode),
        }

        impl PerAddressGraph {
            fn new(answers: &[(&str, Answer)]) -> Self {
                Self {
                    answers: answers
                        .iter()
                        .map(|(address, answer)| ((*address).to_string(), answer.clone()))
                        .collect(),
                }
            }
        }

        fn root(target: &str, id: &str) -> Answer {
            Answer::Root(target.to_string(), id.to_string())
        }

        #[async_trait::async_trait]
        impl ovstorage::Layer for PerAddressGraph {
            fn name(&self) -> &str {
                "graph"
            }

            fn descriptor(&self) -> ovstorage::LayerKindDescriptor {
                ovstorage::LayerKindDescriptor {
                    kind: "graph".to_string(),
                    layer_type: ovstorage::LayerType::Router,
                    display_name: "graph".to_string(),
                    description: None,
                    config_schema: Vec::new(),
                    credential_schema: Vec::new(),
                    credential_methods: Vec::new(),
                    icon: None,
                    accepts_connections: false,
                    // Not a listener authentication Layer, and it owns no
                    // storage — the declaration a router makes.
                    auth_capable: false,
                    supports_user_metadata: false,
                }
            }

            async fn root_info_for(
                &self,
                url: &Url,
                _cx: &ovstorage::Extensions,
                _cancel: Option<ovstorage::CancellationToken>,
            ) -> ovstorage::Result<RootInfo> {
                match self
                    .answers
                    .iter()
                    .find(|(address, _)| address == url.as_str())
                {
                    Some((_, Answer::Root(target, id))) => {
                        let mut info = root_at(url.as_str(), Some(id));
                        info.owning_target = Some(target.clone());
                        Ok(info)
                    }
                    Some((_, Answer::Failure(code))) => {
                        Err(Error::new(*code, "the graph could not answer"))
                    }
                    None => Err(Error::new(ErrorCode::NoRoute, "no route matches address")),
                }
            }
        }

        #[tokio::test]
        async fn an_address_the_graph_could_not_read_refuses_the_rotation() {
            // The agreement safeguard is only worth anything if every candidate
            // was actually READ. These two addresses name two different tenants,
            // and introspecting one fails transiently: dropping it leaves a set
            // of one, a set of one agrees with itself, and the rotation the
            // disagreement exists to refuse would go ahead on a tenant nobody
            // disambiguated.
            let graph = PerAddressGraph::new(&[
                ("https://h/team/", root("prod", "c1")),
                ("https://h/other/", Answer::Failure(ErrorCode::Transient)),
            ]);
            let chosen = resolve_incumbent(
                &graph,
                &[url("https://h/team/"), url("https://h/other/")],
                &ovstorage::CancellationToken::new(),
            )
            .await
            .expect("an unread address is not a failure of the command");
            assert!(
                chosen.is_none(),
                "an unread candidate must refuse, leaving the caller to re-surface the conflict",
            );
        }

        #[tokio::test]
        async fn an_address_that_is_no_route_is_skipped_not_refused() {
            // The ordinary shape must keep working: an `http` `root_url` behind
            // a distinct `prefix` is not itself a route, and `NoRoute` is the
            // graph ANSWERING that it names no connection.
            let graph = PerAddressGraph::new(&[("https://h/team/", root("prod", "c1"))]);
            let chosen = resolve_incumbent(
                &graph,
                &[url("https://h/team/"), url("https://h/not-a-route/")],
                &ovstorage::CancellationToken::new(),
            )
            .await
            .expect("a definite answer is not an error")
            .expect("the one address that resolves names the incumbent");
            assert_eq!(chosen.0.target, "prod");
            assert_eq!(chosen.0.id, ConnectionId("c1".to_string()));
        }

        #[tokio::test]
        async fn a_fired_token_is_not_a_rotation_decision() {
            // Distinguished from the refusal above: the caller left, so the
            // answer is neither "rotate" nor "re-surface the conflict".
            let graph =
                PerAddressGraph::new(&[("https://h/team/", Answer::Failure(ErrorCode::Cancelled))]);
            let error = resolve_incumbent(
                &graph,
                &[url("https://h/team/")],
                &ovstorage::CancellationToken::new(),
            )
            .await
            .expect_err("cancellation travels back as itself");
            assert_eq!(error.code(), ErrorCode::Cancelled);
        }

        #[test]
        fn the_operator_facing_messages_name_only_the_origin() {
            // The path segment and the query key are both secrets under names no
            // redaction list carries — a capability token, and a signed query of
            // the sort `plugin-http.md` invites. `route_candidates` strips
            // userinfo and nothing else, so a prefix reaching these messages can
            // hold either, and one of the two is printed on the SUCCESS path,
            // straight into CI output and terminal captures.
            let prefix = url("https://h.example:8443/s/CAP4B0RT/?sig=SECRET");
            for message in [
                replacement_note(&prefix, "assets", "auth-failed"),
                replace_prompt(&prefix, "assets", "auth-failed"),
            ] {
                assert!(
                    message.contains("https://h.example:8443"),
                    "the origin says where, and must survive: {message}",
                );
                assert!(
                    !message.contains("CAP4B0RT"),
                    "a path capability token must not be rendered: {message}",
                );
                assert!(
                    !message.contains("SECRET"),
                    "nor a signed query under a name no list carries: {message}",
                );
                assert!(
                    message.contains("assets"),
                    "the connection is still named, which is what disambiguates two \
                     prefixes on one origin: {message}",
                );
            }
        }

        fn resolved(id: &str, address: &str) -> (ConnectionKey, Url) {
            resolved_on("http", id, address)
        }

        /// The same, on a named layer — the half of a `ConnectionKey` that an
        /// id-only comparison cannot see.
        fn resolved_on(target: &str, id: &str, address: &str) -> (ConnectionKey, Url) {
            (
                ConnectionKey {
                    target: target.to_string(),
                    id: ConnectionId(id.to_string()),
                },
                url(address),
            )
        }

        #[test]
        fn one_resolving_address_names_the_incumbent() {
            // The ordinary shape: an explicit `prefix` is the only one of the
            // two config addresses that is actually a route, so it is the only
            // one that resolves — "prefix wins over root_url" falls out of that
            // rather than being ranked here.
            let chosen = choose_incumbent(vec![resolved("c1", "https://h/team/")]);
            assert_eq!(
                chosen.map(|(key, _)| key.id),
                Some(ConnectionId("c1".to_string())),
            );
        }

        #[test]
        fn addresses_agreeing_on_one_connection_keep_the_first() {
            // `prefix` defaulted from `root_url`: both name one node, one
            // connection, and the address carried forward is the one the
            // operator's message will quote.
            let chosen = choose_incumbent(vec![
                resolved("c1", "https://h/assets/"),
                resolved("c1", "https://h/assets"),
            ])
            .expect("agreement is not ambiguity");
            assert_eq!(chosen.1.as_str(), "https://h/assets/");
        }

        #[test]
        fn addresses_naming_two_connections_refuse_to_choose() {
            // A request whose `prefix` and `root_url` land on separate tenants
            // is not a rotation any answer here could get right. `None` means
            // the caller re-surfaces the route conflict untouched.
            assert!(
                choose_incumbent(vec![
                    resolved("c1", "https://h/team/"),
                    resolved("c2", "https://other/"),
                ])
                .is_none(),
                "two candidate incumbents must refuse, not pick",
            );
        }

        #[test]
        fn one_id_on_two_layers_is_two_connections() {
            // The ids read alike, but a `ConnectionId` names a connection only
            // within its owning target — the alias layer takes a caller-supplied
            // one verbatim, so `prod` and `stage` can both hold `rule`. Calling
            // that agreement rotated `prod`'s credential because its address came
            // first, which is a working tenant the operator never named.
            assert!(
                choose_incumbent(vec![
                    resolved_on("prod", "rule", "https://h/team/"),
                    resolved_on("stage", "rule", "https://other/"),
                ])
                .is_none(),
                "one id on two layers is two connections, not agreement",
            );
        }

        #[test]
        fn agreement_on_one_layer_still_keeps_the_first() {
            // The comparison tightened to the whole key must not refuse the
            // ordinary case: two spellings of one node on one layer.
            let chosen = choose_incumbent(vec![
                resolved_on("prod", "rule", "https://h/assets/"),
                resolved_on("prod", "rule", "https://h/assets"),
            ])
            .expect("one connection named twice is agreement");
            assert_eq!(chosen.0.target, "prod");
            assert_eq!(chosen.1.as_str(), "https://h/assets/");
        }

        #[test]
        fn no_resolving_address_names_no_incumbent() {
            assert!(choose_incumbent(Vec::new()).is_none());
        }

        /// An UNATTRIBUTED listing row -- the shape a loaded composite plugin
        /// leaves behind, where the id is all there is to match on.
        fn listed(id: &str, kind: &str, display_name: &str) -> ovstorage::Connection {
            ovstorage::Connection {
                id: ConnectionId(id.to_string()),
                backend_kind: kind.to_string(),
                display_name: display_name.to_string(),
                source: ovstorage::ConnectionSource::Runtime { persisted: false },
                capabilities: ovstorage::Capabilities::empty(),
                current_addresses: Vec::new(),
                auth_state: ConnectionAuthState::Anonymous,
                last_probed: None,
                user_metadata: ovstorage::UserMetadata::new(),
                owning_target: None,
            }
        }

        /// The same row, reporting the layer that owns it.
        fn listed_at(
            id: &str,
            kind: &str,
            display_name: &str,
            target: &str,
        ) -> ovstorage::Connection {
            ovstorage::Connection {
                owning_target: Some(target.to_string()),
                ..listed(id, kind, display_name)
            }
        }

        fn key_for(target: &str, id: &str) -> ConnectionKey {
            ConnectionKey {
                target: target.to_string(),
                id: ConnectionId(id.to_string()),
            }
        }

        #[test]
        fn one_row_of_the_named_kind_is_the_incumbent() {
            let row = sole_incumbent_row(
                vec![
                    listed("http-1", "http", "assets"),
                    listed("s3-1", "s3", "b"),
                ],
                &key_for("http_a", "http-1"),
                "http",
            );
            assert_eq!(row.map(|row| row.display_name), Some("assets".to_string()));
        }

        #[test]
        fn a_same_kind_namesake_withdraws_the_rotation() {
            // Two rows, one id, both of the kind the operator named, and
            // NEITHER reporting an owner — so the kind gate cannot separate
            // them and nothing else in these rows can either. Whichever came
            // first would answer the kind check, the settled-state check and
            // the label about a connection that may not be the one being
            // rotated, so the fallback is withdrawn and the caller re-surfaces
            // the conflict.
            assert!(
                sole_incumbent_row(
                    vec![
                        listed("rule", "http", "prod"),
                        listed("rule", "http", "stage"),
                    ],
                    &key_for("http_a", "rule"),
                    "http",
                )
                .is_none(),
                "a shared id must not be resolved by listing order",
            );
        }

        #[test]
        fn attributed_namesakes_are_told_apart_by_their_owner() {
            // The same two rows as above, each now reporting the layer that
            // holds it. `(target, id)` is what identity is, so the pair picks
            // out one of them exactly and the rotation proceeds against the one
            // the route resolved -- there is nothing indistinguishable left to
            // refuse.
            let row = sole_incumbent_row(
                vec![
                    listed_at("rule", "http", "prod", "http_a"),
                    listed_at("rule", "http", "stage", "http_b"),
                ],
                &key_for("http_b", "rule"),
                "http",
            );
            assert_eq!(row.map(|row| row.display_name), Some("stage".to_string()));
        }

        #[test]
        fn an_unattributed_namesake_does_not_veto_an_exact_match() {
            // A mixed graph: one row names `http_b/rule`, and a loaded
            // composite plugin contributes a row that also answers to `rule`
            // but reports no owner. Weighing those as two candidates would let
            // a row that claims nothing refuse a rotation the graph had already
            // identified exactly. Targets are graph-unique, so at most one row
            // can match the whole key.
            let row = sole_incumbent_row(
                vec![
                    listed("rule", "http", "unattributed"),
                    listed_at("rule", "http", "prod", "http_b"),
                ],
                &key_for("http_b", "rule"),
                "http",
            );
            assert_eq!(row.map(|row| row.display_name), Some("prod".to_string()));
        }

        #[test]
        fn an_unattributed_pair_still_withdraws_it_when_no_row_claims_the_key() {
            // The same two-row shape with nothing claiming `http_b/rule`: the
            // id-only search runs, finds two, and refuses. The exact-match
            // preference above must not weaken this.
            assert!(
                sole_incumbent_row(
                    vec![listed("rule", "http", "one"), listed("rule", "http", "two"),],
                    &key_for("http_b", "rule"),
                    "http",
                )
                .is_none(),
            );
        }

        #[test]
        fn an_attributed_row_owned_elsewhere_is_not_the_incumbent() {
            // The id matches and the kind matches, but this row belongs to
            // another layer. Before the pair was readable this was the case
            // that rotated a namesake's credential.
            assert!(
                sole_incumbent_row(
                    vec![listed_at("rule", "http", "prod", "http_a")],
                    &key_for("http_b", "rule"),
                    "http",
                )
                .is_none(),
            );
        }

        #[test]
        fn a_cross_kind_namesake_withdraws_it_too() {
            // The shape the graph builds today: an `alias` rule declaring
            // `id = "http-1"` beside the `http` connection that minted it. The
            // kind gate happens to catch this one when the alias row comes
            // first, but the refusal must not depend on which row that is.
            assert!(
                sole_incumbent_row(
                    vec![
                        listed("http-1", "http", "assets"),
                        listed("http-1", "alias", "shadow"),
                    ],
                    &key_for("http_a", "http-1"),
                    "http",
                )
                .is_none(),
                "the id is shared whichever row the listing yields first",
            );
        }

        #[test]
        fn a_row_of_another_kind_is_not_the_incumbent() {
            // One row, but the bundle in hand is shaped for the kind the
            // operator named; pushing it into another backend re-probes a
            // working tenant against a credential meant for something else.
            assert!(
                sole_incumbent_row(
                    vec![listed("c1", "s3", "bucket")],
                    &key_for("s3_a", "c1"),
                    "http",
                )
                .is_none(),
            );
        }

        #[test]
        fn a_connection_missing_from_the_listing_is_not_rotated() {
            assert!(sole_incumbent_row(Vec::new(), &key_for("http_a", "c1"), "http").is_none(),);
        }

        // ---------------------------------------------------------------
        // Candidate extraction.
        // ---------------------------------------------------------------

        fn field(key: &str, kind: ConfigFieldKind) -> ConfigField {
            ConfigField {
                key: key.to_string(),
                display_name: key.to_string(),
                kind,
                required: key == "root_url",
                default: None,
                help: None,
                example: None,
                group: None,
                advanced: false,
            }
        }

        /// `plugin-http`'s config shape, hand-built so the candidate tests stay
        /// pure: two `Url` fields and one that is not an address.
        fn http_like_descriptor() -> StorageBackendKindDescriptor {
            StorageBackendKindDescriptor {
                kind: "http".to_string(),
                display_name: "HTTP".to_string(),
                description: None,
                config_schema: vec![
                    field("root_url", ConfigFieldKind::Url),
                    field("prefix", ConfigFieldKind::Url),
                    field("timeout_secs", ConfigFieldKind::Integer),
                ],
                credential_schema: Vec::new(),
                credential_methods: Vec::new(),
                icon: None,
                supports_runtime_add: true,
                // What `plugin-http` declares, which is what this stands in for.
                supports_user_metadata: false,
            }
        }

        fn toml_config(pairs: &[(&str, &str)]) -> HashMap<String, toml::Value> {
            pairs
                .iter()
                .map(|(key, value)| (key.to_string(), toml::Value::String(value.to_string())))
                .collect()
        }

        #[test]
        fn candidates_strip_userinfo_from_every_url_field() {
            // A route prefix never carries userinfo, so this is what makes a
            // config address comparable to one — and it is exactly why
            // `user:bad@h` and `user:good@h` are one node.
            let candidates = route_candidates(
                &http_like_descriptor(),
                &toml_config(&[
                    ("root_url", "https://ops:hunter2@h/assets/"),
                    ("prefix", "https://h/team/"),
                    ("timeout_secs", "30"),
                ]),
            );
            let rendered: Vec<&str> = candidates.iter().map(Url::as_str).collect();
            assert_eq!(rendered, ["https://h/assets/", "https://h/team/"]);
        }

        #[test]
        fn candidates_skip_absent_and_non_url_fields() {
            // The integer field is in the schema and in the config; a non-`Url`
            // kind is not an address and must not be probed as one.
            let candidates = route_candidates(
                &http_like_descriptor(),
                &toml_config(&[("root_url", "https://h/assets/"), ("timeout_secs", "30")]),
            );
            assert_eq!(candidates.len(), 1, "only the one Url field is a candidate");
        }

        // ---------------------------------------------------------------
        // Recording the rotation for `write-config`.
        // ---------------------------------------------------------------

        fn declaration(config: &[(&str, &str)], password: &str) -> SessionConnection {
            SessionConnection {
                backend_kind: "http".to_string(),
                target: Some("http".to_string()),
                display_name: None,
                config: toml_config(config),
                credentials: HashMap::from([
                    ("username".to_string(), "ops".to_string()),
                    ("password".to_string(), password.to_string()),
                ]),
            }
        }

        fn password_of(entry: &SessionConnection) -> &str {
            entry.credentials["password"].as_str()
        }

        #[test]
        fn a_rotation_records_against_the_declaration_that_routes_the_address() {
            // Two tenants on ONE physical origin, told apart by explicit
            // prefixes — the arrangement `plugin-http`'s own documentation
            // recommends for exactly this case. Matching a declaration on every
            // address it names would collide them through the `root_url` they
            // share, and write the second tenant's corrected credential onto the
            // first tenant's declaration.
            let shared = "https://h/";
            let mut declared = vec![
                declaration(
                    &[("root_url", shared), ("prefix", "https://h/team-a/")],
                    "a",
                ),
                declaration(
                    &[("root_url", shared), ("prefix", "https://h/team-b/")],
                    "b",
                ),
            ];
            record_rotated_credentials(
                &mut declared,
                &http_like_descriptor(),
                declaration(
                    &[("root_url", shared), ("prefix", "https://h/team-b/")],
                    "fixed",
                ),
                &url("https://h/team-b/"),
            );
            assert_eq!(declared.len(), 2, "no declaration may be added");
            assert_eq!(password_of(&declared[0]), "a", "team A must be untouched");
            assert_eq!(
                password_of(&declared[1]),
                "fixed",
                "the corrected credential belongs to the tenant that routes it",
            );
        }

        #[test]
        fn an_ambiguous_declaration_set_is_left_alone() {
            // Narrowing to the route removes the collision above but cannot
            // remove every one: a declaration that names the route among its
            // OTHER addresses still matches. Writing into a declaration the
            // operator did not name is silent corruption of a file they will
            // deploy, so neither is written and the operator is told.
            let mut declared = vec![
                declaration(&[("root_url", "https://h/team/")], "a"),
                declaration(
                    &[
                        ("root_url", "https://h/team/"),
                        ("prefix", "https://h/other/"),
                    ],
                    "b",
                ),
            ];
            record_rotated_credentials(
                &mut declared,
                &http_like_descriptor(),
                declaration(&[("root_url", "https://h/team/")], "fixed"),
                &url("https://h/team/"),
            );
            assert_eq!(declared.len(), 2, "an ambiguous set gains no entry either");
            assert_eq!(password_of(&declared[0]), "a");
            assert_eq!(password_of(&declared[1]), "b");
        }

        #[test]
        fn a_connection_the_session_never_declared_is_recorded() {
            // Nothing to corrupt, and `write-config` would otherwise omit a
            // connection the graph is serving.
            let mut declared = Vec::new();
            record_rotated_credentials(
                &mut declared,
                &http_like_descriptor(),
                declaration(&[("root_url", "https://h/team/")], "fixed"),
                &url("https://h/team/"),
            );
            assert_eq!(declared.len(), 1);
            assert_eq!(password_of(&declared[0]), "fixed");
        }

        // ---------------------------------------------------------------
        // Finding the layer that owns a connection with no route.
        // ---------------------------------------------------------------

        /// A graph of two connection-owning targets where the FIRST offers no
        /// interactive flow at all and the second owns the connection.
        ///
        /// This is the ordinary `children = ["http", <broker-ish>]` shape. The
        /// point is what the first target answers for a key it does not hold:
        /// the `Layer` leaf default answers `Unsupported` without reading the
        /// key, so `http` says "no interactive flow" about a connection it has
        /// never seen.
        struct FlowlessThenOwner {
            /// The id the SECOND target owns. Everything else is not its.
            owned: ConnectionId,
            /// The route any address resolves to: the target that serves it,
            /// and the id of the connection whose root WON it. The two come
            /// together because that is how a route answers — `root_info_for`
            /// and `owning_target_for` describe one winner — and they differ
            /// whenever the asking connection's root is the shadowed side of a
            /// partial collision. `None` is the parked case, where nothing is
            /// published and the scan is all there is.
            routed_to: Option<(String, ConnectionId)>,
            /// The ids the graph's own listing reports, which is where a shared
            /// id becomes visible: one entry per connection, so a repeat means
            /// two layers hold that id.
            listed: Vec<ConnectionId>,
            /// Every target `authenticate_connection` was asked, in order, so a
            /// test can assert which layers were left alone.
            asked: Mutex<Vec<String>>,
        }

        impl FlowlessThenOwner {
            /// `owner` holds `owned` and the graph lists `listed`; `routed_to`
            /// is the `(target, winning connection id)` any address resolves
            /// to, or `None` for a graph publishing no routes at all.
            fn new(owned: &str, listed: &[&str], routed_to: Option<(&str, &str)>) -> Self {
                Self {
                    owned: ConnectionId(owned.to_string()),
                    routed_to: routed_to.map(|(target, winner)| {
                        (target.to_string(), ConnectionId(winner.to_string()))
                    }),
                    listed: listed
                        .iter()
                        .map(|id| ConnectionId((*id).to_string()))
                        .collect(),
                    asked: Mutex::new(Vec::new()),
                }
            }

            fn asked(&self) -> Vec<String> {
                self.asked.lock().unwrap().clone()
            }
        }

        #[async_trait::async_trait]
        impl ovstorage::Layer for FlowlessThenOwner {
            fn name(&self) -> &str {
                "graph"
            }

            fn descriptor(&self) -> ovstorage::LayerKindDescriptor {
                ovstorage::LayerKindDescriptor {
                    kind: "graph".to_string(),
                    layer_type: ovstorage::LayerType::Router,
                    display_name: "graph".to_string(),
                    description: None,
                    config_schema: Vec::new(),
                    credential_schema: Vec::new(),
                    credential_methods: Vec::new(),
                    icon: None,
                    accepts_connections: false,
                    // Not a listener authentication Layer, and it owns no
                    // storage — the declaration a router makes.
                    auth_capable: false,
                    supports_user_metadata: false,
                }
            }

            fn owned_targets(&self) -> Vec<String> {
                vec!["flowless".to_string(), "owner".to_string()]
            }

            async fn root_info_for(
                &self,
                url: &ovstorage::Url,
                _cx: &ovstorage::Extensions,
                _cancel: Option<ovstorage::CancellationToken>,
            ) -> ovstorage::Result<RootInfo> {
                match &self.routed_to {
                    // The winning root, at the address asked about — so the
                    // `same_node` half of the guard passes and only the
                    // `connection_id` decides. `owning_target` names the same
                    // layer `owning_target_for` does, because both describe one
                    // route's one winner; a stub that disagreed with itself
                    // would be testing nothing a real graph can do.
                    Some((target, winner)) => {
                        let mut root = root_at(url.as_str(), Some(winner.0.as_str()));
                        root.owning_target = Some(target.clone());
                        Ok(root)
                    }
                    None => Err(ovstorage::Error::new(
                        ErrorCode::NoRoute,
                        "no route matches address",
                    )),
                }
            }

            async fn owning_target_for(
                &self,
                _url: &ovstorage::Url,
                _cx: &ovstorage::Extensions,
                _cancel: Option<ovstorage::CancellationToken>,
            ) -> Option<String> {
                self.routed_to.as_ref().map(|(target, _)| target.clone())
            }

            async fn list_connections(
                &self,
                _cx: &ovstorage::Extensions,
                _cancel: Option<ovstorage::CancellationToken>,
            ) -> ovstorage::Result<(
                ovstorage::ConnectionSnapshot,
                Option<ovstorage::ConnectionUpdateStream>,
            )> {
                let connections = self
                    .listed
                    .iter()
                    .map(|id| {
                        let mut connection = super::connection_with(super::parked(), &[]);
                        connection.id = id.clone();
                        connection
                    })
                    .collect();
                Ok((
                    ovstorage::ConnectionSnapshot {
                        connections,
                        updates: false,
                    },
                    None,
                ))
            }

            async fn authenticate_connection(
                &self,
                request: Request<ovstorage::AuthenticateRequest>,
                _cancel: Option<ovstorage::CancellationToken>,
            ) -> ovstorage::Result<ovstorage::AuthEventStream> {
                self.asked
                    .lock()
                    .unwrap()
                    .push(request.input.key.target.clone());
                // `flowless` never inspects the key — that is the whole bug.
                if request.input.key.target == "flowless" {
                    return Err(ovstorage::Error::new(
                        ErrorCode::Unsupported,
                        "authenticate_connection is not supported",
                    ));
                }
                if request.input.key.id != self.owned {
                    return Err(ovstorage::Error::new(
                        ErrorCode::NotFound,
                        "connection not found",
                    ));
                }
                let mut connection = super::connection_with(
                    ovstorage::ConnectionAuthState::Authenticated {
                        last_authenticated_at: std::time::SystemTime::now(),
                        expires_at: None,
                    },
                    &[],
                );
                connection.id = self.owned.clone();
                Ok(Box::new(std::iter::once(Ok(
                    ovstorage::AuthEvent::Succeeded {
                        connection: Box::new(connection),
                        credentials: None,
                    },
                ))))
            }
        }

        #[tokio::test]
        async fn an_attributed_row_drives_the_flow_only_on_its_named_owner() {
            // `flowless` comes first in `owned_targets`, so a regression that
            // fell through to the scan would ask it before reaching `owner` --
            // and the answer would look the same, because the scan is built to
            // step past a key-blind `Unsupported`. What differs is that the
            // sibling was contacted at all, and for `authenticate_connection`
            // that is not a wasted call: it is an interactive flow driven
            // against a layer that never held this connection, which a later
            // answer cannot take back. So the call list is the assertion.
            let owned = ConnectionId("c-parked".to_string());
            let graph = FlowlessThenOwner::new("c-parked", &["c-parked"], None);
            let mut parked = super::connection_with(
                ovstorage::ConnectionAuthState::AwaitingAuth {
                    reason: ovstorage::AuthReason::NeverAuthenticated,
                    last_attempt: None,
                },
                &[],
            );
            parked.id = owned.clone();
            parked.owning_target = Some("owner".to_string());

            let outcome = drive_authentication_on_owner(
                &graph,
                &parked,
                &ovstorage::CancellationToken::new(),
            )
            .await
            .expect("the named owner answers");
            match outcome {
                AuthOutcome::Flowed(connection) => assert_eq!(connection.id, owned),
                AuthOutcome::NoFlowOffered(err) => {
                    panic!("the named owner must run the flow, got NoFlowOffered: {err}")
                }
                AuthOutcome::TargetNotFound(err) => {
                    panic!("the named owner must run the flow, got TargetNotFound: {err}")
                }
            }
            assert_eq!(
                graph.asked(),
                ["owner"],
                "no layer but the named owner may be asked to authenticate",
            );
        }

        #[tokio::test]
        async fn a_named_owner_that_does_not_hold_the_id_reports_not_found() {
            // `NotFound` from the layer the row named is not "not mine, try the
            // next" -- there is nowhere else to look, and continuing would ask
            // a sibling to authenticate a key it was never meant to see. It
            // means the connection is gone, and it travels back as that.
            let graph = FlowlessThenOwner::new("c-other", &["c-parked"], None);
            let mut parked = super::connection_with(
                ovstorage::ConnectionAuthState::AwaitingAuth {
                    reason: ovstorage::AuthReason::NeverAuthenticated,
                    last_attempt: None,
                },
                &[],
            );
            parked.id = ConnectionId("c-parked".to_string());
            parked.owning_target = Some("owner".to_string());

            let error = match drive_authentication_on_owner(
                &graph,
                &parked,
                &ovstorage::CancellationToken::new(),
            )
            .await
            {
                Err(error) => error,
                Ok(_) => panic!("the named owner does not hold this id"),
            };
            assert_eq!(error.code(), ErrorCode::NotFound);
            assert_eq!(
                graph.asked(),
                ["owner"],
                "the scan must not resume after the named owner answered",
            );
        }

        #[tokio::test]
        async fn the_owner_scan_looks_past_a_layer_that_offers_no_flow() {
            // The scan runs only when the address derivation failed, which means
            // the connection publishes no root — the parked broker /
            // services-client case. If a flowless sibling ends the scan, that
            // connection can never be authenticated from the CLI, which is the
            // unreachability this whole change set out to remove.
            let owned = ConnectionId("c-parked".to_string());
            let graph = FlowlessThenOwner::new("c-parked", &["c-parked"], None);
            let mut parked = super::connection_with(
                ovstorage::ConnectionAuthState::AwaitingAuth {
                    reason: ovstorage::AuthReason::NeverAuthenticated,
                    last_attempt: None,
                },
                // No address: nothing to derive an owner from.
                &[],
            );
            parked.id = owned.clone();

            let outcome = drive_authentication_on_owner(
                &graph,
                &parked,
                &ovstorage::CancellationToken::new(),
            )
            .await
            .expect("the owning layer must be reached");
            match outcome {
                AuthOutcome::Flowed(connection) => {
                    assert_eq!(connection.id, owned);
                }
                AuthOutcome::NoFlowOffered(err) => panic!(
                    "the scan stopped at the flowless sibling instead of reaching the owner: \
                     {err}"
                ),
                AuthOutcome::TargetNotFound(err) => panic!("unexpected: {err}"),
            }
        }

        /// The remembered answer is still the answer when nothing owns a flow.
        #[tokio::test]
        async fn a_graph_with_no_flow_anywhere_still_reports_unsupported() {
            // Owned by nobody: `owner` answers `NotFound`, `flowless` answers
            // `Unsupported`.
            let graph = FlowlessThenOwner::new("someone-else", &["c-parked"], None);
            let mut parked = super::connection_with(
                ovstorage::ConnectionAuthState::AwaitingAuth {
                    reason: ovstorage::AuthReason::NeverAuthenticated,
                    last_attempt: None,
                },
                &[],
            );
            parked.id = ConnectionId("c-parked".to_string());

            let outcome = drive_authentication_on_owner(
                &graph,
                &parked,
                &ovstorage::CancellationToken::new(),
            )
            .await
            .expect("a remembered `Unsupported` is an answer, not an error");
            assert!(
                matches!(outcome, AuthOutcome::NoFlowOffered(_)),
                "the backend's own `Unsupported` must survive the scan",
            );
        }

        /// The derived owner's `Unsupported` is FINAL: nothing else is asked.
        #[tokio::test]
        async fn a_routed_connections_owner_refusal_ends_the_scan() {
            // The route resolves to `flowless` and the root that won it names
            // this very connection, which is the whole proof of ownership — so
            // its "no interactive flow" is an answer ABOUT this connection.
            // `owner` here would drive a flow for the same key, as a layer that
            // answers without reading it may; asking it at all would open a
            // browser on a tenant the operator never named, over an answer that
            // was already final.
            let graph =
                FlowlessThenOwner::new("c-owned", &["c-owned"], Some(("flowless", "c-owned")));
            let mut routed = super::connection_with(super::parked(), &["https://h/team/"]);
            routed.id = ConnectionId("c-owned".to_string());

            let outcome = drive_authentication_on_owner(
                &graph,
                &routed,
                &ovstorage::CancellationToken::new(),
            )
            .await
            .expect("the derived owner's refusal is an answer, not an error");
            match outcome {
                AuthOutcome::NoFlowOffered(_) => {}
                AuthOutcome::Flowed(_) => {
                    panic!("the scan ran on past the proven owner and drove a flow elsewhere")
                }
                AuthOutcome::TargetNotFound(err) => panic!("unexpected: {err}"),
            }
            assert_eq!(
                graph.asked(),
                ["flowless"],
                "no layer but the proven owner may be asked to authenticate",
            );
        }

        /// A shared id is refused before any layer is asked anything.
        #[tokio::test]
        async fn a_shared_id_is_refused_rather_than_reauthenticated_by_guess() {
            // Two layers holding one id, the shape the alias layer's
            // caller-supplied `connection_id` makes reachable. The published
            // root names that id and the route resolves to `flowless` — but a
            // root naming OUR id is not a root naming OUR connection when a
            // namesake exists, and `Connection` carries no target to tell the
            // two apart. Deriving would sign in to whichever of them won the
            // route; scanning would sign in to whichever target came first.
            // Neither is an answer, so `reauth` says so instead.
            let graph =
                FlowlessThenOwner::new("rule", &["rule", "rule"], Some(("flowless", "rule")));
            let mut routed = super::connection_with(super::parked(), &["https://h/team/"]);
            routed.id = ConnectionId("rule".to_string());

            let error = match drive_authentication_on_owner(
                &graph,
                &routed,
                &ovstorage::CancellationToken::new(),
            )
            .await
            {
                Err(error) => error,
                Ok(_) => panic!("a shared id names no single connection"),
            };
            assert_eq!(error.code(), ErrorCode::InvalidArgument);
            assert!(
                error.message().contains("rule"),
                "the message must name the id: {error}",
            );
            assert!(
                graph.asked().is_empty(),
                "no flow may be driven anywhere while the id is ambiguous: {:?}",
                graph.asked(),
            );
        }

        /// An address whose ROUTE belongs to another connection derives
        /// nothing, so the scan still runs and still reaches the owner.
        #[tokio::test]
        async fn a_shadowed_address_does_not_make_the_route_winner_final() {
            // The Router keeps a connection whose roots collide only in part
            // and shadows the contested one, so a connection can publish an
            // address that resolves to somebody else's root — here to
            // `flowless`, which answers `Unsupported` without ever reading the
            // key. Taking a bare `owning_target_for` as proof of ownership
            // would return that verbatim and report "no interactive flow" about
            // a connection `flowless` has never held, with the layer that does
            // hold it never asked: the unreachable `reauth` the owner scan
            // exists to remove.
            let owned = ConnectionId("c-owned".to_string());
            // `c-incumbent` is the connection that won the contested root — a
            // different one from the connection being reauthenticated, so the
            // published root cannot be mistaken for a proof of ownership.
            let graph = FlowlessThenOwner::new(
                "c-owned",
                &["c-owned", "c-incumbent"],
                Some(("flowless", "c-incumbent")),
            );
            let mut shadowed = super::connection_with(super::parked(), &["https://h/team/"]);
            shadowed.id = owned.clone();

            let outcome = drive_authentication_on_owner(
                &graph,
                &shadowed,
                &ovstorage::CancellationToken::new(),
            )
            .await
            .expect("the owning layer must still be reached");
            match outcome {
                AuthOutcome::Flowed(connection) => assert_eq!(connection.id, owned),
                AuthOutcome::NoFlowOffered(err) => {
                    panic!("a route winner that does not hold the connection ended the scan: {err}")
                }
                AuthOutcome::TargetNotFound(err) => panic!("unexpected: {err}"),
            }
        }

        // ---------------------------------------------------------------
        // The rotation itself, against a live `plugin-http` layer.
        // ---------------------------------------------------------------

        /// An origin that accepts exactly one `Authorization` value and records
        /// every one it is shown, so a test can prove the NEW credential — not
        /// the old one — reached the wire.
        struct Origin {
            authority: String,
            seen: Arc<Mutex<Vec<String>>>,
        }

        fn basic(user: &str, password: &str) -> String {
            use base64::Engine as _;
            format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"))
            )
        }

        fn spawn_origin(accepted: String) -> Origin {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let seen = Arc::new(Mutex::new(Vec::new()));
            let recorder = Arc::clone(&seen);
            thread::spawn(move || {
                while let Ok((mut stream, _)) = listener.accept() {
                    let mut buf = [0_u8; 2048];
                    let read = stream.read(&mut buf).unwrap_or(0);
                    let request = String::from_utf8_lossy(&buf[..read]).to_string();
                    // hyper writes header names lowercase; accept either
                    // spelling rather than depending on that.
                    let authorization = request.lines().find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("authorization")
                            .then(|| value.trim().to_string())
                    });
                    if let Some(value) = &authorization {
                        recorder.lock().unwrap().push(value.clone());
                    }
                    // `Connection: close` on purpose: this stub serves one
                    // request per accepted socket, and a rotation re-probes
                    // through the SAME retained client as the original probe.
                    // Without it that client would offer a pooled socket this
                    // loop has already dropped.
                    let response = if authorization.as_deref() == Some(accepted.as_str()) {
                        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    } else {
                        "HTTP/1.1 401 Unauthorized\r\n\
                         WWW-Authenticate: Basic realm=\"test\"\r\n\
                         Content-Length: 0\r\nConnection: close\r\n\r\n"
                    };
                    let _ = stream.write_all(response.as_bytes());
                    let _ = stream.flush();
                }
            });
            Origin {
                authority: format!("{addr}"),
                seen,
            }
        }

        /// An origin whose root answers every probe `403` — neither accepting
        /// nor refusing the credential — while objects beneath it are none of
        /// the probe's business. That is the ordinary shape of a root that is
        /// not itself readable, and `plugin-http` records it as `AwaitingAuth`.
        fn spawn_inconclusive_origin() -> Origin {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let seen = Arc::new(Mutex::new(Vec::new()));
            let recorder = Arc::clone(&seen);
            thread::spawn(move || {
                while let Ok((mut stream, _)) = listener.accept() {
                    let mut buf = [0_u8; 2048];
                    let read = stream.read(&mut buf).unwrap_or(0);
                    let request = String::from_utf8_lossy(&buf[..read]).to_string();
                    if let Some(value) = request.lines().find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("authorization")
                            .then(|| value.trim().to_string())
                    }) {
                        recorder.lock().unwrap().push(value);
                    }
                    let _ = stream.write_all(
                        b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    );
                    let _ = stream.flush();
                }
            });
            Origin {
                authority: format!("{addr}"),
                seen,
            }
        }

        /// A one-layer `http` stack. `plugin-http` is a dev-dependency, so this
        /// is the real backend — the probe, the credential shape check and the
        /// route-prefix refusal are all the shipping ones.
        async fn http_state() -> SessionState {
            let config = ovstorage::StackConfig::from_toml_str(
                "[ovstorage]\nroot = \"http\"\n\n[ovstorage.layers.http]\n",
            )
            .unwrap();
            let mut factories = crate::commands::test_layer_factories();
            factories.push(ovstorage::LoadedLayerFactory::Backend(Arc::new(
                ovstorage_plugin_http::HttpBackendLayerFactory::default(),
            )));
            let stack = ovstorage::host::build_stack(&config, factories)
                .await
                .unwrap();
            SessionState::build(stack, config).await.unwrap()
        }

        fn http_connection(root_url: &str, credentials: &[(&str, &str)]) -> SessionConnection {
            SessionConnection {
                backend_kind: "http".to_string(),
                target: Some("http".to_string()),
                display_name: None,
                config: toml_config(&[("root_url", root_url)]),
                credentials: credentials
                    .iter()
                    .map(|(key, value)| (key.to_string(), value.to_string()))
                    .collect(),
            }
        }

        /// A router over TWO `http` layers — the two-tenant arrangement
        /// `plugin-http.md` recommends, and the graph where a route collision
        /// can cross a layer boundary.
        async fn two_http_state() -> SessionState {
            let config = ovstorage::StackConfig::from_toml_str(
                "[ovstorage]\nroot = \"r\"\n\n\
                 [ovstorage.layers.r]\nkind = \"router\"\nchildren = [\"http_a\", \"http_b\"]\n\n\
                 [ovstorage.layers.http_a]\nkind = \"http\"\n\n\
                 [ovstorage.layers.http_b]\nkind = \"http\"\n",
            )
            .unwrap();
            let mut factories = crate::commands::test_layer_factories();
            factories.push(ovstorage::LoadedLayerFactory::Backend(Arc::new(
                ovstorage_plugin_http::HttpBackendLayerFactory::default(),
            )));
            let stack = ovstorage::host::build_stack(&config, factories)
                .await
                .unwrap();
            SessionState::build(stack, config).await.unwrap()
        }

        /// `add`, aimed at a named layer.
        async fn add_to(
            state: &SessionState,
            target: &str,
            session_conn: &SessionConnection,
        ) -> ovstorage::Result<ovstorage::Connection> {
            ovstorage::Layer::add_connection(
                state.stack.as_ref(),
                Request::new(LayerConnectionRequest {
                    target: target.to_string(),
                    connection: session_conn.to_connection_request()?,
                }),
                None,
            )
            .await
        }

        async fn add(
            state: &SessionState,
            session_conn: &SessionConnection,
        ) -> ovstorage::Result<ovstorage::Connection> {
            ovstorage::Layer::add_connection(
                state.stack.as_ref(),
                Request::new(LayerConnectionRequest {
                    target: "http".to_string(),
                    connection: session_conn.to_connection_request()?,
                }),
                None,
            )
            .await
        }

        fn descriptor_for(state: &SessionState) -> StorageBackendKindDescriptor {
            state
                .stack
                .list_backend_kinds()
                .unwrap()
                .into_iter()
                .find(|descriptor| descriptor.kind == "http")
                .expect("the http backend is registered")
        }

        #[tokio::test]
        async fn a_refused_credential_is_replaced_in_place_and_re_probed() {
            let origin = spawn_origin(basic("ops", "right"));
            let root_url = format!("http://{}/assets/", origin.authority);
            let mut state = http_state().await;
            let descriptor = descriptor_for(&state);
            let cancel = ovstorage::CancellationToken::new();

            // The mistyped secret. `plugin-http` registers it anyway — the probe
            // is a HEAD on the root, and an origin that challenges its root
            // while serving objects beneath it is an ordinary shape — so the
            // prefix is taken and the operator is stuck.
            let wrong = http_connection(&root_url, &[("username", "ops"), ("password", "wrong")]);
            let registered = add(&state, &wrong)
                .await
                .expect("a refusal still registers");
            assert!(
                matches!(
                    registered.auth_state,
                    ConnectionAuthState::AuthFailed { .. }
                ),
                "the origin refused this credential: {:?}",
                registered.auth_state,
            );
            state.connections.push(wrong);

            // The correction, on the same origin. Without the fallback this is
            // where the session dead-ends.
            let corrected =
                http_connection(&root_url, &[("username", "ops"), ("password", "right")]);
            let conflict = add(&state, &corrected)
                .await
                .expect_err("the corrected credential collides with the mistake");
            assert_eq!(conflict.code(), ErrorCode::RouteConflict);

            // The refused add probed on its way to the refusal, so only traffic
            // from HERE proves the ROTATION re-probed.
            origin.seen.lock().unwrap().clear();

            rotate_on_conflict(&mut state, &descriptor, corrected, true, conflict, &cancel)
                .await
                .expect("the corrected credential must replace the refused one");

            // Replaced, not added: a second registration is exactly the state
            // the route conflict exists to prevent.
            let connections = state.stack.list_connections(None).await.unwrap();
            assert_eq!(connections.len(), 1, "rotation must not add a connection");
            assert!(
                matches!(
                    connections[0].auth_state,
                    ConnectionAuthState::Authenticated { .. }
                ),
                "the re-probe must settle the identity: {:?}",
                connections[0].auth_state,
            );

            // The probe RE-RAN against the new bundle. Carrying the old verdict
            // forward would be a success that is not one; carrying the old
            // credential would be worse.
            let seen = origin.seen.lock().unwrap().clone();
            assert!(
                seen.contains(&basic("ops", "right")),
                "the new credential must have reached the origin: {seen:?}",
            );

            // One session entry, with the corrected secret, so `write-config`
            // does not emit a duplicate that reproduces this conflict at boot.
            assert_eq!(state.connections.len(), 1);
            assert_eq!(
                state.connections[0]
                    .credentials
                    .get("password")
                    .map(String::as_str),
                Some("right"),
            );
        }

        #[tokio::test]
        async fn a_replacement_the_origin_refuses_reports_the_refusal() {
            // The probe must re-run and its verdict must travel back as the exit
            // status: a second wrong secret is not a repair.
            let origin = spawn_origin(basic("ops", "right"));
            let root_url = format!("http://{}/assets/", origin.authority);
            let mut state = http_state().await;
            let descriptor = descriptor_for(&state);
            let cancel = ovstorage::CancellationToken::new();

            let wrong = http_connection(&root_url, &[("username", "ops"), ("password", "wrong")]);
            add(&state, &wrong)
                .await
                .expect("a refusal still registers");

            let also_wrong = http_connection(
                &root_url,
                &[("username", "ops"), ("password", "also-wrong")],
            );
            let conflict = add(&state, &also_wrong).await.expect_err("same origin");
            // Only traffic from here is the rotation's own probe.
            origin.seen.lock().unwrap().clear();
            let error =
                rotate_on_conflict(&mut state, &descriptor, also_wrong, true, conflict, &cancel)
                    .await
                    .expect_err("a refused replacement is not a success");
            // The origin's own answer, not merely "not the collision": a 401 is
            // `AuthRequired`, and asserting that is what distinguishes the
            // refusal travelling back from the rotation failing for some
            // unrelated reason — `Unsupported` for a shape it could not express,
            // `Transient` for an origin it never reached — each of which would
            // mean the replacement was never judged at all.
            assert_eq!(
                error.code(),
                ErrorCode::AuthRequired,
                "the answer must be the origin's refusal of the new credential: {error}",
            );

            let seen = origin.seen.lock().unwrap().clone();
            assert!(
                seen.contains(&basic("ops", "also-wrong")),
                "the replacement must have been probed: {seen:?}",
            );

            // And the refusal is the LIVE connection's state, not just an exit
            // status: the replacement installed, so what the operator inspects
            // next has to say the origin turned this credential down too.
            let connections = state.stack.list_connections(None).await.unwrap();
            assert_eq!(connections.len(), 1, "rotation must not add a connection");
            assert!(
                matches!(
                    connections[0].auth_state,
                    ConnectionAuthState::AuthFailed { .. }
                ),
                "the re-probe's verdict must be the connection's state: {:?}",
                connections[0].auth_state,
            );
        }

        #[tokio::test]
        async fn a_credential_shape_change_is_refused_verbatim() {
            // Rotation replaces values inside the channels a connection already
            // has. Swapping Basic for a bearer is a different connection, and
            // the backend's own message names the remove-and-re-add that gets
            // there — so it must not be folded into the route conflict.
            let origin = spawn_origin(basic("ops", "right"));
            let root_url = format!("http://{}/assets/", origin.authority);
            let mut state = http_state().await;
            let descriptor = descriptor_for(&state);
            let cancel = ovstorage::CancellationToken::new();

            let basic_conn =
                http_connection(&root_url, &[("username", "ops"), ("password", "wrong")]);
            add(&state, &basic_conn).await.expect("registers");

            let bearer = http_connection(&root_url, &[("bearer_token", "t0ken")]);
            let conflict = add(&state, &bearer).await.expect_err("same origin");
            let error =
                rotate_on_conflict(&mut state, &descriptor, bearer, true, conflict, &cancel)
                    .await
                    .expect_err("a shape change is not a rotation");
            assert_eq!(error.code(), ErrorCode::Unsupported);
            assert!(
                error.message().contains("remove and re-add"),
                "the backend's own instruction must survive: {error}",
            );
        }

        #[tokio::test]
        async fn a_credential_that_is_not_in_the_bundle_re_surfaces_the_conflict() {
            // HTTP userinfo rides in a config field, not in the bundle, so there
            // is nothing for `update_connection_credentials` to replace. Sending
            // an empty bundle would re-probe the OLD secret and report its
            // verdict as the new one's — the refusal is the honest answer.
            let origin = spawn_origin(basic("ops", "right"));
            let mut state = http_state().await;
            let descriptor = descriptor_for(&state);
            let cancel = ovstorage::CancellationToken::new();

            let wrong = http_connection(
                &format!("http://ops:wrong@{}/assets/", origin.authority),
                &[],
            );
            add(&state, &wrong)
                .await
                .expect("a refusal still registers");

            let corrected = http_connection(
                &format!("http://ops:right@{}/assets/", origin.authority),
                &[],
            );
            let conflict = add(&state, &corrected)
                .await
                .expect_err("one node, one route");
            let message = conflict.message().to_string();
            let error =
                rotate_on_conflict(&mut state, &descriptor, corrected, true, conflict, &cancel)
                    .await
                    .expect_err("an empty bundle is not a credential to rotate");
            assert_eq!(error.code(), ErrorCode::RouteConflict);
            assert_eq!(
                error.message(),
                message,
                "the original refusal must travel back untouched",
            );
        }

        #[tokio::test]
        async fn moving_a_userinfo_credential_into_the_bundle_is_refused() {
            // The other half of the userinfo story, and the one an operator
            // reaches for after the refusal above: correct the secret by
            // supplying it as `--auth basic` instead. Refused, and by the
            // narrower of the two guards that would catch it — the connection
            // keeps the `root_url` it was built with, userinfo and all, so a
            // Basic bundle beside it would write `Authorization` twice. (The
            // credential-shape check refuses it too, one line further on; this
            // one answers first and says more.) For a connection seeded by a
            // layer's own config this is the second of the two dead ends
            // `plugin-http.md` documents; the way out is the layer block.
            let origin = spawn_origin(basic("ops", "right"));
            let mut state = http_state().await;
            let descriptor = descriptor_for(&state);
            let cancel = ovstorage::CancellationToken::new();

            let seeded = http_connection(
                &format!("http://ops:wrong@{}/assets/", origin.authority),
                &[],
            );
            let registered = add(&state, &seeded).await.expect("registers");
            assert!(
                matches!(
                    registered.auth_state,
                    ConnectionAuthState::AuthFailed { .. }
                ),
                "the origin refused the userinfo credential: {:?}",
                registered.auth_state,
            );

            // The same origin, the secret moved into the bundle where rotation
            // could otherwise reach it.
            let in_the_bundle = http_connection(
                &format!("http://{}/assets/", origin.authority),
                &[("username", "ops"), ("password", "right")],
            );
            let conflict = add(&state, &in_the_bundle)
                .await
                .expect_err("one node, one route");
            let error = rotate_on_conflict(
                &mut state,
                &descriptor,
                in_the_bundle,
                true,
                conflict,
                &cancel,
            )
            .await
            .expect_err("userinfo and a bundle cannot both hold the credential");
            assert_eq!(error.code(), ErrorCode::InvalidArgument);
            assert!(
                error.message().contains("exactly one"),
                "the backend's own instruction must survive: {error}",
            );
        }

        /// A declaration naming a physical endpoint AND a caller-facing prefix
        /// — the arrangement `plugin-http.md` recommends for two connections on
        /// one origin.
        fn prefixed_connection(
            root_url: &str,
            prefix: &str,
            credentials: &[(&str, &str)],
        ) -> SessionConnection {
            SessionConnection {
                config: toml_config(&[("root_url", root_url), ("prefix", prefix)]),
                ..http_connection(root_url, credentials)
            }
        }

        #[tokio::test]
        async fn a_credential_for_another_endpoint_is_never_sent_to_the_incumbent() {
            // Two DIFFERENT origins behind one caller-facing prefix. Only the
            // prefix is a route, so it is the only candidate that resolves, and
            // the incumbent it names speaks to origin A while the credential in
            // hand was typed for origin B. Rotating would disclose B's secret to
            // A and replace a working tenant's credential — and neither the kind
            // gate (both `http`) nor the auth-state gate (`AuthFailed` is what
            // the unattended path is FOR) can see it.
            let origin_a = spawn_origin(basic("ops", "a-secret"));
            let origin_b = spawn_origin(basic("ops", "b-secret"));
            let prefix = "http://tenant.example/shared/";
            let mut state = http_state().await;
            let descriptor = descriptor_for(&state);
            let cancel = ovstorage::CancellationToken::new();

            let incumbent = prefixed_connection(
                &format!("http://{}/assets/", origin_a.authority),
                prefix,
                &[("username", "ops"), ("password", "wrong")],
            );
            let registered = add(&state, &incumbent).await.expect("registers");
            assert!(
                matches!(
                    registered.auth_state,
                    ConnectionAuthState::AuthFailed { .. }
                ),
                "origin A refused it, which is the state rotation is allowed in: {:?}",
                registered.auth_state,
            );

            let elsewhere = prefixed_connection(
                &format!("http://{}/assets/", origin_b.authority),
                prefix,
                &[("username", "ops"), ("password", "b-secret")],
            );
            let conflict = add(&state, &elsewhere)
                .await
                .expect_err("the prefix is taken");
            let message = conflict.message().to_string();
            // Only traffic from here could be a rotation's probe.
            origin_a.seen.lock().unwrap().clear();

            let error =
                rotate_on_conflict(&mut state, &descriptor, elsewhere, true, conflict, &cancel)
                    .await
                    .expect_err("a credential for another endpoint is not a rotation");
            assert_eq!(error.code(), ErrorCode::RouteConflict);
            assert_eq!(
                error.message(),
                message,
                "the original refusal must travel back untouched",
            );

            // The assertion this test exists for: B's secret never reached A.
            let seen = origin_a.seen.lock().unwrap().clone();
            assert!(
                !seen.contains(&basic("ops", "b-secret")),
                "a credential typed for another origin must not be probed against this one: \
                 {seen:?}",
            );
            let connections = state.stack.list_connections(None).await.unwrap();
            assert_eq!(connections.len(), 1, "nothing may have been added");
            assert!(
                matches!(
                    connections[0].auth_state,
                    ConnectionAuthState::AuthFailed { .. }
                ),
                "and the incumbent's own credential is untouched: {:?}",
                connections[0].auth_state,
            );
        }

        #[tokio::test]
        async fn an_add_that_committed_without_confirming_is_still_declared() {
            // The connection is registered whatever the exit status says, so the
            // session has to hold its declaration: without it `write-config`
            // writes a graph the operator does not have, and the next startup
            // drops a connection nothing ever removed.
            //
            // Driven at this seam rather than through `run`, because producing a
            // real `CommitAmbiguous` needs a router whose post-commit catch-up
            // fails — which the `Router` tests cover directly, and which the
            // CLI's http-backed harness has no way to arrange.
            let mut declared = Vec::new();
            let session_conn = http_connection("http://h/assets/", &[("password", "s3cret")]);
            let returned = record_committed_but_unconfirmed(
                &mut declared,
                session_conn,
                ovstorage::Error::new(ErrorCode::CommitAmbiguous, "the catch-up was abandoned"),
            );
            assert_eq!(
                returned.code(),
                ErrorCode::CommitAmbiguous,
                "the caller still has to be told the mutation stuck: {returned}",
            );
            assert_eq!(
                declared.len(),
                1,
                "and the declaration is what keeps `write-config` honest",
            );
            assert_eq!(
                declared[0].config["root_url"].as_str(),
                Some("http://h/assets/"),
            );
            assert_eq!(
                declared[0].credentials.get("password").map(String::as_str),
                Some("s3cret"),
                "credentials included: the connection that is registered has them",
            );
        }

        #[tokio::test]
        async fn a_refused_leftover_is_not_declared_for_write_config() {
            // The other `CommitAmbiguous`: the graph turned this add down for
            // another layer's prefix and could not take it off its child, so it
            // is registered there and will never route. Recording it would put
            // an `[[ovstorage.connections]]` entry in `write-config`'s output
            // for an attempt that failed, and the next start would re-apply the
            // same mistake and leave a second registration behind.
            let mut declared = Vec::new();
            let session_conn = http_connection("http://h/assets/", &[("password", "s3cret")]);
            let returned = record_committed_but_unconfirmed(
                &mut declared,
                session_conn,
                ovstorage::Error::new(
                    ErrorCode::CommitAmbiguous,
                    "refused for a sibling's prefix and the removal failed",
                )
                .with_next_action(ovstorage::NEXT_ACTION_REFUSED_LEFTOVER),
            );
            assert_eq!(
                returned.code(),
                ErrorCode::CommitAmbiguous,
                "the caller is still told the attempt left something behind: {returned}",
            );
            assert!(
                declared.is_empty(),
                "a refusal that could not be undone is not a connection to remember",
            );
        }

        #[test]
        fn one_endpoint_named_twice_still_agrees() {
            // The guard must not refuse the ordinary shapes: a lone `root_url`
            // (the prefix is defaulted from it), and a `prefix` spelled to the
            // same node as its `root_url` — including the spellings the route
            // table treats as one node.
            assert!(names_one_endpoint(&[]));
            assert!(names_one_endpoint(&[url("https://h/assets/")]));
            assert!(names_one_endpoint(&[
                url("https://h/assets/"),
                url("https://h/assets"),
            ]));
            assert!(!names_one_endpoint(&[
                url("https://h/assets/"),
                url("https://tenant/shared/"),
            ]));
        }

        #[tokio::test]
        async fn a_connect_aimed_at_one_layer_never_rotates_another_layers_connection() {
            // The collision can now cross a layer boundary: the Router refuses a
            // sibling child's same-node root, so the connection holding the
            // prefix may belong to a layer the operator did not name. Rotating
            // it would send the credential meant for `http_b`'s tenant into
            // `http_a`'s connection and report success, with nothing landing on
            // the requested layer — and neither the kind gate (both `http`) nor
            // the auth-state gate (`AuthFailed` is what the unattended path is
            // FOR) can see it.
            let origin = spawn_origin(basic("ops", "a-secret"));
            let root_url = format!("http://{}/assets/", origin.authority);
            let mut state = two_http_state().await;
            let descriptor = descriptor_for(&state);
            let cancel = ovstorage::CancellationToken::new();

            // The incumbent lives on http_a and the origin refused it.
            let on_a = SessionConnection {
                target: Some("http_a".to_string()),
                ..http_connection(&root_url, &[("username", "ops"), ("password", "wrong")])
            };
            let registered = add_to(&state, "http_a", &on_a).await.expect("registers");
            assert!(
                matches!(
                    registered.auth_state,
                    ConnectionAuthState::AuthFailed { .. }
                ),
                "the state the unattended rotation path allows: {:?}",
                registered.auth_state,
            );

            // The operator aims a connection at http_b, on the same origin.
            let on_b = SessionConnection {
                target: Some("http_b".to_string()),
                ..http_connection(&root_url, &[("username", "ops"), ("password", "b-secret")])
            };
            let conflict = add_to(&state, "http_b", &on_b)
                .await
                .expect_err("the sibling layer already serves that root");
            assert_eq!(conflict.code(), ErrorCode::RouteConflict);
            let message = conflict.message().to_string();
            origin.seen.lock().unwrap().clear();

            let error = rotate_on_conflict(&mut state, &descriptor, on_b, true, conflict, &cancel)
                .await
                .expect_err("a connection on another layer is not this one's to rotate");
            assert_eq!(error.code(), ErrorCode::RouteConflict);
            assert_eq!(
                error.message(),
                message,
                "the original refusal must travel back untouched",
            );

            // The assertion this test exists for: http_a's connection is
            // untouched and http_b's credential never went anywhere.
            let seen = origin.seen.lock().unwrap().clone();
            assert!(
                !seen.contains(&basic("ops", "b-secret")),
                "a credential aimed at another layer must not be probed here: {seen:?}",
            );
            let connections = state.stack.list_connections(None).await.unwrap();
            assert_eq!(connections.len(), 1, "nothing may have been added");
            assert!(
                matches!(
                    connections[0].auth_state,
                    ConnectionAuthState::AuthFailed { .. }
                ),
                "the other layer's connection keeps its own credential: {:?}",
                connections[0].auth_state,
            );
        }

        #[tokio::test]
        async fn a_connect_aimed_at_the_owning_layer_still_rotates() {
            // The guard must not cost the case rotation exists for: same graph,
            // same collision, but aimed at the layer that actually holds it.
            let origin = spawn_origin(basic("ops", "right"));
            let root_url = format!("http://{}/assets/", origin.authority);
            let mut state = two_http_state().await;
            let descriptor = descriptor_for(&state);
            let cancel = ovstorage::CancellationToken::new();

            let wrong = SessionConnection {
                target: Some("http_a".to_string()),
                ..http_connection(&root_url, &[("username", "ops"), ("password", "wrong")])
            };
            add_to(&state, "http_a", &wrong).await.expect("registers");

            let corrected = SessionConnection {
                target: Some("http_a".to_string()),
                ..http_connection(&root_url, &[("username", "ops"), ("password", "right")])
            };
            let conflict = add_to(&state, "http_a", &corrected)
                .await
                .expect_err("same node, same layer");
            rotate_on_conflict(&mut state, &descriptor, corrected, true, conflict, &cancel)
                .await
                .expect("the layer that holds the prefix is the one being repaired");

            let connections = state.stack.list_connections(None).await.unwrap();
            assert_eq!(connections.len(), 1);
            assert!(
                matches!(
                    connections[0].auth_state,
                    ConnectionAuthState::Authenticated { .. }
                ),
                "the corrected credential must have replaced the refused one: {:?}",
                connections[0].auth_state,
            );
        }

        #[tokio::test]
        async fn a_script_may_not_silently_replace_a_working_credential() {
            // A duplicate `connect` is usually a mistake, and the incumbent here
            // is settled — it serves. Rotating it without an answer turns that
            // mistake into an outage the moment the new secret has a typo, so
            // the refusal is what a script gets.
            let origin = spawn_origin(basic("ops", "right"));
            let root_url = format!("http://{}/assets/", origin.authority);
            let mut state = http_state().await;
            let descriptor = descriptor_for(&state);
            let cancel = ovstorage::CancellationToken::new();

            // No credential at all: `plugin-http` reports `Anonymous` without
            // probing, so this connection is settled and working.
            let anonymous = http_connection(&root_url, &[]);
            let registered = add(&state, &anonymous).await.expect("registers");
            assert!(
                matches!(registered.auth_state, ConnectionAuthState::Anonymous),
                "this test needs a SETTLED incumbent: {:?}",
                registered.auth_state,
            );

            let credentialed =
                http_connection(&root_url, &[("username", "ops"), ("password", "right")]);
            let conflict = add(&state, &credentialed).await.expect_err("same origin");
            let message = conflict.message().to_string();
            let error = rotate_on_conflict(
                &mut state,
                &descriptor,
                credentialed,
                true,
                conflict,
                &cancel,
            )
            .await
            .expect_err("a settled incumbent may not be rotated unattended");
            // `RouteConflict` specifically, and the original message: reaching
            // the backend would have answered `Unsupported` for the shape
            // change, so this asserts the gate fired BEFORE the rotation.
            assert_eq!(error.code(), ErrorCode::RouteConflict);
            assert_eq!(
                error.message(),
                message,
                "the original refusal must travel back untouched",
            );
            let connections = state.stack.list_connections(None).await.unwrap();
            assert_eq!(connections.len(), 1, "nothing may have been added");
            assert!(
                matches!(connections[0].auth_state, ConnectionAuthState::Anonymous),
                "the working connection must be untouched: {:?}",
                connections[0].auth_state,
            );
        }

        #[tokio::test]
        async fn a_script_may_not_replace_a_credential_that_was_merely_unproven() {
            // `AwaitingAuth` is not a refusal. This origin answers the probe
            // `403` — neither accepting nor refusing — so the credential is
            // UNPROVEN while the connection stays routable and reads beneath the
            // root may be succeeding the whole time. Reading "not settled" as
            // "not working" and rotating unattended would overwrite a live
            // credential on a duplicate `connect`, which is the outage the
            // settled-state guard exists to prevent, reached another way.
            let origin = spawn_inconclusive_origin();
            let root_url = format!("http://{}/assets/", origin.authority);
            let mut state = http_state().await;
            let descriptor = descriptor_for(&state);
            let cancel = ovstorage::CancellationToken::new();

            let serving = http_connection(&root_url, &[("username", "ops"), ("password", "right")]);
            let registered = add(&state, &serving).await.expect("registers");
            assert!(
                matches!(
                    registered.auth_state,
                    ConnectionAuthState::AwaitingAuth { .. }
                ),
                "this test needs an UNPROVEN incumbent: {:?}",
                registered.auth_state,
            );
            assert!(
                !registered.current_addresses.is_empty(),
                "an unproven connection still publishes its root, which is what makes \
                 replacing its credential an outage",
            );

            let typo = http_connection(&root_url, &[("username", "ops"), ("password", "rihgt")]);
            let conflict = add(&state, &typo).await.expect_err("same origin");
            let message = conflict.message().to_string();
            // Only traffic from here could be the rotation's own probe.
            origin.seen.lock().unwrap().clear();
            let error = rotate_on_conflict(&mut state, &descriptor, typo, true, conflict, &cancel)
                .await
                .expect_err("an unproven credential is not a refused one");
            assert_eq!(error.code(), ErrorCode::RouteConflict);
            assert_eq!(
                error.message(),
                message,
                "the original refusal must travel back untouched",
            );

            // The gate fired BEFORE the backend was asked to rotate: the typo
            // never reached the origin, so the credential in place is still the
            // one that was serving.
            let seen = origin.seen.lock().unwrap().clone();
            assert!(
                !seen.contains(&basic("ops", "rihgt")),
                "the replacement must not have been probed: {seen:?}",
            );
            let connections = state.stack.list_connections(None).await.unwrap();
            assert_eq!(connections.len(), 1, "nothing may have been added");
            assert!(
                matches!(
                    connections[0].auth_state,
                    ConnectionAuthState::AwaitingAuth { .. }
                ),
                "the incumbent must be untouched: {:?}",
                connections[0].auth_state,
            );
        }

        #[tokio::test]
        async fn a_script_may_still_repair_a_refused_credential() {
            // The narrowing must not close the case this fallback exists for: an
            // origin that REFUSED the credential leaves `AuthFailed`, which is a
            // definite answer about a connection serving nobody.
            let origin = spawn_origin(basic("ops", "right"));
            let root_url = format!("http://{}/assets/", origin.authority);
            let mut state = http_state().await;
            let descriptor = descriptor_for(&state);
            let cancel = ovstorage::CancellationToken::new();

            let wrong = http_connection(&root_url, &[("username", "ops"), ("password", "wrong")]);
            let registered = add(&state, &wrong).await.expect("registers");
            assert!(
                matches!(
                    registered.auth_state,
                    ConnectionAuthState::AuthFailed { .. }
                ),
                "this test needs a REFUSED incumbent: {:?}",
                registered.auth_state,
            );

            let corrected =
                http_connection(&root_url, &[("username", "ops"), ("password", "right")]);
            let conflict = add(&state, &corrected).await.expect_err("same origin");
            rotate_on_conflict(&mut state, &descriptor, corrected, true, conflict, &cancel)
                .await
                .expect("a refused credential is still repairable unattended");

            let connections = state.stack.list_connections(None).await.unwrap();
            assert_eq!(connections.len(), 1);
            assert!(
                matches!(
                    connections[0].auth_state,
                    ConnectionAuthState::Authenticated { .. }
                ),
                "the corrected credential must have replaced the refused one: {:?}",
                connections[0].auth_state,
            );
        }
    }
}
