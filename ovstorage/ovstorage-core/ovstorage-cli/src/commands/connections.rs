// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The connection inventory and its removal: what is registered, under what
//! identity, and how to take one away.
//!
//! Distinct from `list-routes`, which answers a different question. Routes are
//! addresses the graph will serve, and a connection that is parked or refused
//! may publish none of them — so the connection an operator needs to repair is
//! exactly the one `list-routes` cannot show. These commands work on
//! connections instead, including the ones with no route at all.
//!
//! Both commands address a connection by **id**, which is why `list-connections`
//! prints it first: a display name is free-form and a backend kind cannot
//! distinguish two same-kind layers, so neither substitutes. An id is not by
//! itself a whole identity either — it is unique only within the layer that owns
//! it — so the owning `target` is printed beside it, and [`remove_resolved`]
//! explains how that layer is found and what it does when the pair cannot be
//! completed.

use ovstorage::ext::LayerExt as _;
use ovstorage::{
    CancellationToken, Connection, ConnectionKey, ConnectionSource, Error, ErrorCode, Request,
    StorageBackendKindDescriptor,
};

use crate::commands::connect::{auth_state_word, owner_at, route_candidates};
use crate::session::{SessionConnection, SessionState};

/// One tab-separated row per connection, under a header, per the crate's
/// line-oriented output contract.
///
/// **`id` and `target` together are the identity.** A connection id names a
/// connection only *within* the layer that owns it — that is the Layer
/// contract, and the alias layer takes caller-supplied ids verbatim, so two
/// layers really can both hold an id like `rule`. `display_name` is free-form
/// caller text and `backend_kind` cannot tell two same-kind layers apart, so
/// neither substitutes. The two identity columns lead, in that order.
///
/// `target` is blank where it cannot be PROVEN, which is a stronger bar than
/// "resolves". [`proven_owner`] explains it: a route lookup answers about
/// whoever won the address, so a connection parked in `AwaitingAuth` or refused
/// into `AuthFailed` publishes nothing to prove anything with, and one whose
/// root a sibling won would otherwise be labelled with the sibling's layer. A
/// namesake claiming the proving node blanks it too — that is the same case
/// `disconnect` refuses, and this column is what an operator reads before
/// deciding what to disconnect, so the two must not disagree.
///
/// Addresses are space-joined into the last column rather than given a line
/// each, so one connection is one line and a row survives `grep`. A canonical
/// address never contains a literal space — [`ovstorage::address::parse`]
/// percent-encodes one — so the join is reversible.
///
/// **Each one goes through [`ovstorage::redact_url`] first**, the same pass
/// `doctor` applies to the roots it reports and errors apply to the addresses
/// they name: userinfo out, and the values of query parameters known to carry a
/// signed-URL credential replaced. An inventory command is run from CI and its
/// output is kept, so an address that carries a credential should not be the
/// thing that puts it in a log.
///
/// **Not origin-only, which is the rule for a message that merely NAMES a
/// connection.** Here the addresses are what the command is for: an operator
/// runs it to see which address spaces the graph serves, and two connections on
/// one origin under distinct prefixes — the arrangement `plugin-http.md`
/// recommends — would print identically with the path removed. The same is true
/// of `list-routes`, `list` and `stat`: this tool exists to say where things
/// are, so it says it, and redacts what within an address is a secret rather
/// than treating every address as one.
///
/// The residue is a credential in a path SEGMENT, which no list recognises and
/// this pass does not remove. An operator who mounts a capability URL has to
/// treat every address-printing command as sensitive, not this one alone.
///
/// Empty fields are left empty rather than filled with a placeholder: a
/// connection with no display name and one with the display name `-` must not
/// print the same row, and an empty column is what `cut -f3` already expects.
pub(crate) async fn list(
    state: &SessionState,
    cancel: &CancellationToken,
) -> ovstorage::Result<()> {
    // Cancellable, unlike `list-routes`' cached-snapshot read: this fans out
    // across every child, each of which may answer over the plugin ABI or a
    // network, so Ctrl+C has to reach it.
    let connections = state.stack.list_connections(Some(cancel.clone())).await?;
    println!("id\ttarget\tbackend\tdisplay_name\tauth_state\taddresses");
    for connection in &connections {
        let addresses = address_column(connection);
        // The row's own answer first: a connection reports the layer that owns
        // it, and that is the whole `ConnectionKey` half this column exists to
        // show — no proof needed, because it is not an inference.
        //
        // Deriving it is the fallback, for a row a loaded composite plugin left
        // unattributed. There it is printed only where it is proven AND
        // unambiguous: a namesake claiming the proving node makes the root's
        // `connection_id` an answer about either of them, and a column naming
        // the wrong tenant's layer is worse than an empty one — this is the
        // column an operator reads before deciding what to disconnect.
        let target = match &connection.owning_target {
            Some(target) => target.clone(),
            None => proven_owner(state.stack.as_ref(), connection, &connections, cancel)
                .await
                .map(|(target, _)| target)
                .unwrap_or_default(),
        };
        println!(
            "{}\t{target}\t{}\t{}\t{}\t{}",
            connection.id.0,
            connection.backend_kind,
            connection.display_name,
            auth_state_word(&connection.auth_state),
            addresses,
        );
    }
    Ok(())
}

/// The `addresses` column: every root the connection publishes, redacted and
/// space-joined. Built as a string rather than printed inline so the redaction
/// is testable. See [`list`] for what it removes and what it deliberately keeps.
fn address_column(connection: &Connection) -> String {
    connection
        .current_addresses
        .iter()
        .map(ovstorage::redact_url)
        .collect::<Vec<_>>()
        .join(" ")
}

/// The layer instance that owns `connection`, **proven** from an address whose
/// published root names this connection — or `None` when no address proves it.
///
/// This is the exact half of connection addressing, but only with the proof.
/// `owning_target_for` answers which layer *serves* an address, and serving is a
/// longest-prefix route lookup, so the answer is about whoever WON the route and
/// not necessarily about the connection that published it. Two overlaps make
/// those different layers: a broader sibling root that merely contains the
/// address, and the shadowed side of a partial collision — the Router keeps a
/// connection whose roots collide only in part and shadows the contested one, so
/// a connection really can publish an address a sibling's connection won.
/// Trusting the bare lookup then named the wrong tenant's layer, which
/// [`remove_resolved`] addresses directly for a shared id: it would have removed
/// the incumbent namesake's live connection instead of the one the operator
/// selected.
///
/// So each address is checked before its target is taken — the published root
/// must be about the same node and must name THIS connection's id, and the
/// target is read from that same root rather than looked up separately. That is
/// [`crate::commands::connect::owner_at`], shared verbatim with the rotation and
/// re-authentication paths. Every address is tried rather than only the first,
/// because a connection's first address may be the shadowed one while a later
/// address still routes to it.
///
/// `None` is the honest answer for a connection parked in `AwaitingAuth` or
/// refused into `AuthFailed`, which publishes no root, and now also for one
/// whose every published root belongs to somebody else. Callers treat it as "not
/// derivable", never as "no owner".
///
/// **A proof no namesake contests, or none at all.** Id equality is only as
/// strong as the id: where two layers hold one id, a root naming it at a node
/// they BOTH publish is a sentence true of either. That is judged here, per
/// address, rather than by the caller on whichever address happened to come
/// first — a connection can be contested on one root and alone on another, and
/// the one it holds alone names its owner exactly. Every address is therefore
/// tried against both tests, and what comes back is already unambiguous; the
/// proving address travels with the target because that is what the check was
/// made against.
async fn proven_owner(
    graph: &dyn ovstorage::Layer,
    connection: &Connection,
    listing: &[Connection],
    cancel: &CancellationToken,
) -> Option<(String, ovstorage::Url)> {
    for address in &connection.current_addresses {
        // An address the graph could not answer for is not derivable, which is
        // the same place a definite "nothing here" leads — and unlike the
        // rotation path, both are safe: every caller treats `None` as "not
        // derivable" and falls back to something that establishes ownership
        // another way, or prints an empty column rather than a wrong one.
        // Cancellation included: each caller goes on to a `list_connections`
        // that raises it for itself.
        let Ok(Some(key)) = owner_at(graph, address, cancel).await else {
            continue;
        };
        if key.id != connection.id {
            continue;
        }
        // **Contested here, not by the caller.** A root naming this id proves
        // ownership only while one connection answers to that id at that node;
        // where a namesake publishes it too — the shadowed side of a partial
        // collision — the root is a sentence true of both, and it proves
        // nothing. That is a reason to try the NEXT address, not to give up:
        // a connection publishing several roots can be contested on one and
        // alone on another, and the one it holds alone names its owner exactly.
        // Judged in the caller instead, only the first proof was ever examined
        // and a connection that could be addressed exactly was refused.
        if contested(
            namesakes(listing, connection),
            address,
            &connection.display_name,
        ) {
            continue;
        }
        return Some((key.target, address.clone()));
    }
    None
}

/// Every connection in `listing` that answers to `connection`'s id, including
/// `connection` itself — the rows a `ConnectionKey` built from that id could
/// reach.
fn namesakes<'a>(
    listing: &'a [Connection],
    connection: &Connection,
) -> impl Iterator<Item = &'a Connection> {
    let id = connection.id.clone();
    listing.iter().filter(move |other| other.id == id)
}

/// Is the proof [`proven_owner`] found also an answer about somebody else?
///
/// A published root proves "a connection with this id serves that node". Where
/// one id is held by two layers, that sentence is true of both, and a
/// `Connection` carries nothing else the check could compare — no target, and
/// two rows print identically. So the listing is asked instead: if another row
/// with this id publishes the same node, the root cannot be attributed, and the
/// caller must refuse rather than act on it.
///
/// `display_name` is what separates this connection from its namesakes, and it
/// is sound here because it is the only way a caller can have selected one:
/// [`resolve_selector`] refuses a shared id outright and refuses an ambiguous
/// name, so a connection that reaches here with a shared id was named uniquely.
/// A second row carrying BOTH this id and this name would break that assumption,
/// so it counts as contested too — indistinguishable is indistinguishable.
fn contested<'a>(
    namesakes: impl Iterator<Item = &'a Connection>,
    address: &ovstorage::Url,
    display_name: &str,
) -> bool {
    let rows: Vec<&Connection> = namesakes.collect();
    if rows
        .iter()
        .filter(|row| row.display_name == display_name)
        .count()
        > 1
    {
        return true;
    }
    rows.iter()
        .filter(|row| row.display_name != display_name)
        .any(|row| {
            row.current_addresses
                .iter()
                .any(|live| ovstorage::address::same_node(live, address))
        })
}

/// Remove a registered connection, freeing the route prefix it held.
///
/// **The session bookkeeping follows the COMMIT, not the exit status.** A
/// removal can commit and still answer with an error: the Router runs a
/// route-table catch-up after the child has already removed the connection, and
/// every way that catch-up can fail — a fired caller token, a failed or
/// timed-out fan-out — reports [`ErrorCode::CommitAmbiguous`] over a mutation
/// that happened. Leaving the declaration in place there was wrong in a way the
/// operator would only discover later: `write-config` re-emits it and the next
/// startup recreates the connection they disconnected. So [`Removed`] carries
/// the acting target through that outcome, the declaration is dropped either
/// way, and what is uncertain — whether this graph still routes to a connection
/// that is gone — is said plainly and carried out in the exit status.
///
/// That status is `20`, not the generic `1` (`exit_code` in `main.rs`). The
/// distinction is the one the binary already draws for `PartialCompletion`: a
/// script reading only the status must be able to tell "the removal happened,
/// carry on" from "nothing happened, for a reason nobody classified", because
/// re-running `disconnect` on the first takes the `NotFound` of an
/// already-removed connection and reads a success as a failure. The prose
/// explaining which it was goes to stderr, which is precisely where a
/// status-checking script does not look.
pub(crate) async fn disconnect(
    state: &mut SessionState,
    selector: &str,
    cancel: &CancellationToken,
) -> ovstorage::Result<()> {
    let connection = resolve_selector(state.stack.as_ref(), selector, cancel).await?;
    // Before anything is removed: a connection this command cannot finish the
    // job for must not have its live half torn down.
    //
    // **The row's own answer serves this refusal too, and only its absence
    // costs a SECOND fan-out.** The message names the config block an operator
    // has to edit, so it wants the owning layer — which a `Static` connection
    // parked in `AwaitingAuth` publishes no root to derive, and which is
    // exactly the state this refusal exists for. Deriving it is the fallback.
    //
    // This saves the second listing, not the first: `resolve_selector` above
    // has already fanned out across every child to turn the selector into a
    // `Connection`, with `?`, and it must — `owning_target` cannot be read
    // until there is a row to read it from. So a child erroring on
    // `list_connections` still fails this command before any of the below
    // runs, and no arrangement of these lines changes that. Tolerating a
    // partial fan-out is a Router-level question.
    let owner = match &connection.owning_target {
        Some(target) => Some(target.clone()),
        None => {
            let listed = state.stack.list_connections(Some(cancel.clone())).await?;
            proven_owner(state.stack.as_ref(), &connection, &listed, cancel)
                .await
                .map(|(target, _)| target)
        }
    };
    if let Some(refusal) = layer_seeded_refusal(&connection, owner.as_deref()) {
        return Err(refusal);
    }
    let removed = remove_resolved(state.stack.as_ref(), &connection, cancel).await?;
    let target = &removed.target;
    // Best-effort by design: the live removal has already succeeded, so a
    // descriptor lookup that fails must not turn a completed disconnect into an
    // error. Without it the address pass below is simply skipped.
    let descriptor = state.stack.list_backend_kinds().ok().and_then(|kinds| {
        kinds
            .into_iter()
            .find(|kind| kind.kind == connection.backend_kind)
    });
    forget_session_entry(
        &mut state.connections,
        &connection,
        target,
        descriptor.as_ref(),
    );
    eprintln!(
        "disconnected '{}' ({}) from layer '{target}'.",
        connection.display_name, connection.id.0
    );
    if let Some(unreconciled) = removed.unreconciled {
        eprintln!(
            "warning: the connection is gone, but this graph could not confirm its route \
             table caught up ({unreconciled}); an address it served may still resolve to it \
             until the layer re-publishes its roots. The session no longer holds the \
             declaration, so `write-config` will not re-emit it."
        );
        return Err(unreconciled);
    }
    Ok(())
}

/// Refuse a connection whose seed is LAYER configuration, before the live half
/// is torn down.
///
/// `disconnect` finishes in two places: the graph, and the session's record of
/// what to write back. [`forget_session_entry`] can only reach the second for a
/// connection declared as `[[ovstorage.connections]]`, because that is the only
/// kind of record the session holds. A connection can also be seeded by a
/// layer's own configuration — a non-empty `[ovstorage.layers.<name>]` block
/// makes `plugin-http` instantiate one connection from it at build time
/// (`HttpBackendLayerFactory::create_backend`), credentials and all — and that
/// seed lives in the layer graph, which `write-config` re-serializes from
/// `Stack::spec()`, the spec the stack was BUILT from. A live removal does not
/// touch it.
///
/// So the removal would succeed, this command would report success, and the
/// next `write-config` would emit the same layer block it always did — putting
/// the connection back on the next boot, credential and all. For a refused
/// static credential that is precisely the recovery this command advertises,
/// which makes reporting it as done the worst of the available answers.
///
/// **Refusing rather than papering over it.** The alternative would be to omit
/// the seed from the written config, and there is nothing to omit it from: the
/// CLI has no mutable model of the layer graph, `Stack::spec()` is what the
/// stack was built from, and "the part of a layer's config that seeded a
/// connection" is not a distinguishable subset in general — for `plugin-http`
/// it is the whole block, so dropping it would rewrite what the layer IS rather
/// than what it holds. The operator's edit is a small one and it is the one that
/// lasts, so the message names it.
///
/// `ConnectionSource` is the discriminator and it is exact: a declared
/// connection is applied through `add_connection` and recorded `Runtime`, a
/// layer-config seed is `Static`. A `BrokerDelivered` connection is neither —
/// it comes from a broker rather than from local configuration, so no local
/// config re-creates it and `write-config` never emitted it in the first place.
fn layer_seeded_refusal(connection: &Connection, target: Option<&str>) -> Option<Error> {
    if !matches!(connection.source, ConnectionSource::Static { .. }) {
        return None;
    }
    let block = match target {
        Some(target) => format!("[ovstorage.layers.{target}]"),
        // Unnameable only where the row reports no owner AND no published root
        // derives one — a loaded composite's row with nothing to derive from.
        // A parked or refused connection used to land here, because it
        // publishes no root; it now carries its owner, which is the whole point
        // of the field and the case this refusal exists for.
        None => "the `[ovstorage.layers.*]` block for this backend".to_string(),
    };
    Some(Error::new(
        ErrorCode::Unsupported,
        format!(
            "connection '{}' ({}) was seeded by layer configuration, not declared as an \
             [[ovstorage.connections]] entry, so `disconnect` cannot finish the job: removing \
             it here would not change {block}, `write-config` re-serializes the layer graph \
             from it, and the next startup would build this connection again. Edit {block} \
             instead — that is the change that lasts.",
            connection.display_name, connection.id.0
        ),
    ))
}

/// A removal that reached the layer holding the connection.
#[derive(Debug)]
struct Removed {
    /// The layer that acted, which is also what identifies the declaration the
    /// session should forget.
    target: String,
    /// `Some` when the removal COMMITTED but the graph could not confirm its
    /// route table reflects that — [`ErrorCode::CommitAmbiguous`], carried
    /// rather than propagated so the caller can finish the bookkeeping the
    /// commit calls for before reporting it.
    unreconciled: Option<Error>,
}

/// The connection a `<selector>` argument names — a connection id, or a display
/// name.
///
/// **The id wins when both could match.** It is what `list-connections` puts
/// first and what these commands document as the selector; a display name is
/// free-form caller text that could be typed to look like an id, and resolving
/// that to a different connection than the one whose id it is would be the
/// worst possible reading.
///
/// **Neither selector may resolve to more than one connection.** An id is not a
/// whole identity — it names a connection only within its owning target, and the
/// alias layer takes a caller-supplied one verbatim — so two layers can both
/// hold `rule`, and `disconnect` takes no target to qualify which. Taking the
/// first match would remove a live connection the operator did not name, and
/// silently: both rows print the same id, so nothing about the outcome would
/// reveal which one went. A shared id is therefore refused here, before any
/// removal is attempted, and the operator is pointed at the display name, which
/// `list-connections` prints and which *can* tell the two apart. That refusal is
/// first, not last: [`remove_resolved`] withdraws its scan for a shared id too,
/// but by then a connection has already been chosen.
///
/// The ambiguity error is `reauth`'s, in its words: a repeated display name is
/// the operator's to resolve by renaming, and no answer here can guess which of
/// two they meant.
async fn resolve_selector(
    graph: &dyn ovstorage::Layer,
    selector: &str,
    cancel: &CancellationToken,
) -> ovstorage::Result<Connection> {
    let mut connections =
        ovstorage::ext::LayerExt::list_connections(graph, Some(cancel.clone())).await?;
    let by_id: Vec<usize> = connections
        .iter()
        .enumerate()
        .filter(|(_, connection)| connection.id.0 == selector)
        .map(|(index, _)| index)
        .collect();
    match by_id.as_slice() {
        // No id matched — fall through to the display name below.
        [] => {}
        [index] => return Ok(connections.swap_remove(*index)),
        several => {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "connection id '{selector}' is held by {} connections; an id is unique \
                     only within the layer that owns it, and `disconnect` takes no target to \
                     qualify one, so select it by display_name instead — `list-connections` \
                     prints that beside the owning target",
                    several.len()
                ),
            ));
        }
    }
    let named: Vec<usize> = connections
        .iter()
        .enumerate()
        .filter(|(_, connection)| connection.display_name == selector)
        .map(|(index, _)| index)
        .collect();
    match named.as_slice() {
        [] => Err(Error::new(
            ErrorCode::NotFound,
            format!("no connection with id or display_name '{selector}'"),
        )),
        [index] => Ok(connections.swap_remove(*index)),
        several => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "display_name '{selector}' is ambiguous ({} connections); \
                 rename one to disambiguate",
                several.len()
            ),
        )),
    }
}

/// Remove `connection`, addressing the layer that actually owns it, and answer
/// with that layer's name.
///
/// A `ConnectionKey` names a layer as well as an id, and a `Connection` reports
/// which layer owns it. **That answer is taken whenever it is there**, and it
/// is not one of the mechanisms below: the layer that holds the connection said
/// so, which is neither a derivation nor a search, so no proof qualifies it and
/// no namesake weakens it. [`remove_at`] is that path.
///
/// The rest of this is the fallback for a row that came back unattributed — a
/// loaded composite plugin reporting several `owned_targets`, which the host
/// cannot attribute for it. Two mechanisms recover the target there, and the
/// choice between them is not a preference — it is a correctness argument:
///
/// **Derivation is exact, but only once it is proven.** [`proven_owner`] takes
/// an address whose published root is about the same node AND carries this
/// connection's id; a bare `owning_target_for` names whoever won the route,
/// which for a shadowed address is a sibling. Tried first, always.
///
/// **A shared id weakens even that proof, so it is re-earned.** The root proves
/// "a connection with this id serves that node" — which, where two layers hold
/// one id, may be describing the namesake rather than the connection selected.
/// The listing settles it: if no OTHER connection with this id publishes that
/// node, the root can only have been about this one. If one does, the two are
/// indistinguishable and the removal is refused rather than aimed at a guess —
/// removing a live tenant's connection is not something to be sorry about
/// afterwards.
///
/// **The scan is not exact, and is sound only while the id is unique in the
/// graph.**
/// A connection parked in `AwaitingAuth` or refused into `AuthFailed` may
/// publish no address — and those are exactly the connections `disconnect`
/// exists to clear — so there is nothing to derive from, and ownership has to
/// be discovered by attempting the removal against each of `owned_targets()`.
/// That works only because the id picks out one connection: **a connection id
/// is unique only WITHIN its owning target**, which the Layer contract states
/// and the alias layer relies on, taking a caller-supplied `id` verbatim
/// (`AliasWrapper`'s `connection_id`). Two layers can therefore both hold
/// `rule`, and a scan would remove whichever `owned_targets()` yields first —
/// not the one the selector resolved. So when the id is shared, the scan is
/// withdrawn: only an exactly derived target is addressed, and if there is
/// none the operator is told the id cannot be told apart rather than having a
/// working connection removed out from under them.
///
/// That check still earns its place now that [`resolve_selector`] refuses a
/// shared id outright: it refuses the *selector*, and a connection selected by
/// its unique display name may perfectly well share its id with another layer's
/// row. This function is what keeps that removal off the namesake.
///
/// **Two answers advance the scan, because neither is about ownership.**
///
/// `NotFound` is the obvious one, and both of its spellings mean "not mine": a
/// Router answers it for a target it does not route, and a backend answers it
/// for an id it does not hold.
///
/// `Unsupported` is the one that is easy to get wrong. The `Layer` leaf default
/// for `remove_connection` answers it **without ever reading the key**, so a
/// layer that holds no connections at all — anything that never overrode the
/// method — says exactly that for an id it does not hold. Taking it as final
/// ended the scan at whichever such layer `owned_targets()` happened to yield
/// first: in a router ordered `[file, broker]`, disconnecting a parked broker
/// connection — the routeless case this command exists for, so there is no
/// address to derive an owner from — reported `file`'s key-blind refusal and
/// never reached the layer that held it. So an `Unsupported` is REMEMBERED and
/// the scan continues; a later target that actually owns the connection wins,
/// and the remembered answer is returned only if none does, because a layer that
/// refuses a removal it *does* own has said something the operator needs.
///
/// Unlike the equivalent step in `connect`'s authentication scan, that needs no
/// "unless the candidate was derived" carve-out. Continuing there could drive a
/// second interactive flow against a layer that never held the connection; here
/// the attempt is a removal keyed by an id, it is made only where the id is
/// unique in the graph, and a layer that does not hold that id cannot act on it.
/// Stepping past an `Unsupported` therefore costs one more call and removes
/// nothing — and it recovers the case where the derived target named the winner
/// of a route rather than the layer holding the connection.
///
/// **`CommitAmbiguous` ends the scan as a success, because it IS one.** The
/// Router reconciles its route table after the child has already removed the
/// connection, and every way that reconcile can fail — the caller's token fired,
/// the fan-out failed, its deadline passed — reports that code over a mutation
/// that happened; the Router's own contract is that this code is only ever
/// raised post-commit. Reading it as "not mine" would scan on and remove a
/// second connection; propagating it as a plain error told the caller nothing
/// had happened, and the caller's session bookkeeping then kept a declaration
/// for a connection that was gone, which `write-config` re-emitted and the next
/// startup recreated. So the acting target travels back in [`Removed`] with the
/// error beside it, and the caller decides what to finish before reporting it.
///
/// Every other error propagates: a layer that got far enough to fail
/// meaningfully has diagnosed something, and swallowing it to try the next
/// target would bury it under a final `NotFound`.
async fn remove_resolved(
    graph: &dyn ovstorage::Layer,
    connection: &Connection,
    cancel: &CancellationToken,
) -> ovstorage::Result<Removed> {
    // **The row's own answer ends it, before anything else is asked here.**
    // `owning_target` IS the other half of the key, so there is nothing to
    // prove and nothing to scan: no address has to publish, no namesake has to
    // be counted, and the removal is aimed at the layer that said it holds this
    // connection. Taken before the listing below rather than after it, because
    // that listing is a fan-out across every child and this path has no use for
    // it. The cancellation the fan-out would have observed is checked directly.
    //
    // **Scoped to this function.** The property is that an attributed row here
    // costs no fan-out and does not depend on every child answering. It is not
    // a property of `disconnect`, whose `resolve_selector` has already fanned
    // out to produce the `connection` argument — a row has to exist before its
    // `owning_target` can be read, so that cost is structural rather than an
    // ordering mistake.
    ovstorage::bail_if_cancelled(&Some(cancel.clone()))?;
    if let Some(target) = connection.owning_target.clone() {
        return remove_at(graph, &target, connection, cancel).await;
    }

    // Everything below is the fallback for a row that came back unattributed.
    let listing = ovstorage::ext::LayerExt::list_connections(graph, Some(cancel.clone())).await?;
    let derived = proven_owner(graph, connection, &listing, cancel).await;
    let shared = namesakes(&listing, connection).count();

    let candidates: Vec<String> = match (shared > 1, derived) {
        // A shared id and an address that proves ownership: every proof
        // `proven_owner` returns is one no namesake contests, so the root can
        // only have been about this connection. Address that layer alone —
        // never the scan, which would reach the namesake.
        (true, Some((target, _address))) => vec![target],
        (true, _) => {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "connection id '{}' is held by {shared} connections and this one reports no \
                     owning layer, so it has to be found by trying each layer in turn — and that \
                     search would reach the others, whether or not they report one. No address \
                     proves which connection this is either, or a namesake serves the same node, \
                     so a `ConnectionKey` built from this id could reach either. \
                     `list-connections` prints the owning target where there is one; select a \
                     connection that reports one by its display_name, and a connection whose \
                     only root a namesake has taken over cannot be aimed at from here at all.",
                    connection.id.0
                ),
            ));
        }
        // A unique id makes the scan sound: at most one layer can answer
        // anything but `NotFound`. The derived target leads it as a preference,
        // costing at most one extra attempt when it is wrong.
        //
        // `owned_targets` may repeat a name — a Stack whose root itself accepts
        // connections reports it once for the Stack and once through the root —
        // and a repeat is only a second identical attempt on a path that
        // already answered `NotFound`, so it needs no dedup.
        (false, derived) => derived
            .map(|(target, _)| target)
            .into_iter()
            .chain(ovstorage::Layer::owned_targets(graph))
            .collect(),
    };

    // UFCS throughout, as everywhere else that reaches a `Layer` primitive from
    // the CLI: `LayerExt`'s data-plane verbs are in scope here and share names
    // with several of them.
    let mut unsupported: Option<Error> = None;
    for target in candidates {
        let key = ConnectionKey {
            target: target.clone(),
            id: connection.id.clone(),
        };
        match ovstorage::Layer::remove_connection(graph, Request::new(key), Some(cancel.clone()))
            .await
        {
            Ok(()) => {
                return Ok(Removed {
                    target,
                    unreconciled: None,
                });
            }
            Err(err) if err.code() == ErrorCode::NotFound => continue,
            // Says nothing about ownership — the leaf default raises it without
            // reading the key — so it is kept in case no target owns the id,
            // and stepped over meanwhile. The first is kept: none of them is
            // more authoritative than another.
            Err(err) if err.code() == ErrorCode::Unsupported => {
                unsupported.get_or_insert(err);
            }
            // The removal COMMITTED and only the reconcile is in doubt, so this
            // target is the answer and the scan stops here — continuing would
            // aim a second removal at a layer that never held this connection.
            Err(err) if err.code() == ErrorCode::CommitAmbiguous => {
                return Ok(Removed {
                    target,
                    unreconciled: Some(err),
                });
            }
            Err(err) => return Err(err),
        }
    }
    // A refusal from the layer that did hold it reads better than the scan's own
    // summary, and where it came from a layer that did not, nothing was removed
    // either way.
    if let Some(err) = unsupported {
        return Err(err);
    }
    Err(Error::new(
        ErrorCode::NotFound,
        format!("no layer owns connection '{}'", connection.id.0),
    ))
}

/// Remove `connection` at the layer that owns it, when that layer is known
/// rather than searched for.
///
/// The scan in [`remove_resolved`] classifies four answers because it is asking
/// a question — "is this yours?" — of a layer that may not hold the key. Here
/// the owner is already named, so three of those four collapse: a `NotFound`
/// means the connection is gone, not "try the next"; an `Unsupported` is this
/// layer refusing a removal it does own, which is a diagnosis and not a step;
/// and each travels back as the error it is. `CommitAmbiguous` keeps its
/// meaning, because that meaning is about the Router's post-commit reconcile
/// and not about ownership: the removal happened, the caller's bookkeeping
/// still has to run, and the acting target travels back beside the error.
async fn remove_at(
    graph: &dyn ovstorage::Layer,
    target: &str,
    connection: &Connection,
    cancel: &CancellationToken,
) -> ovstorage::Result<Removed> {
    let key = ConnectionKey {
        target: target.to_string(),
        id: connection.id.clone(),
    };
    match ovstorage::Layer::remove_connection(graph, Request::new(key), Some(cancel.clone())).await
    {
        Ok(()) => Ok(Removed {
            target: target.to_string(),
            unreconciled: None,
        }),
        Err(err) if err.code() == ErrorCode::CommitAmbiguous => Ok(Removed {
            target: target.to_string(),
            unreconciled: Some(err),
        }),
        Err(err) => Err(err),
    }
}

/// Drop the session's record of a removed connection, so `write-config` does
/// not re-emit an `[[ovstorage.connections]]` entry for a connection that is
/// gone.
///
/// A `SessionConnection` carries no connection id — it is the *declaration* a
/// connection was built from, not the connection, and the ids the graph mints
/// never reach the session (`host::build_stack` applies the declared
/// connections and does not hand their ids back). The declaration therefore has
/// to be recovered structurally, and the only safe way to do that is to ask
/// which declarations **could** have produced this connection and to act only
/// when exactly one could.
///
/// Two facts narrow the field before anything is compared: the backend kind, and
/// the layer the removal acted on — a declaration pinned to a different
/// `target` did not produce a connection some other layer held.
///
/// **The address is the strongest answer available.** A declaration configuring
/// a node this connection actually serves is very likely the declaration it was
/// built from: a declared connection reaches the graph through `add_connection`,
/// where a router refuses a same-node root from a sibling child, so two
/// *applied* declarations cannot both be serving one node. Not quite an
/// exclusivity proof, though — a declaration whose add was refused at startup is
/// skipped with a warning and stays in the config, so the session can hold a
/// second declaration naming that node which never became a connection. That is
/// why the pass still requires a unique match instead of taking the first. It is
/// the same handle `connect`'s rotation bookkeeping uses, and it is unavailable
/// exactly for the parked and refused connections `disconnect` exists to clear,
/// which publish no address at all.
///
/// **Names are evidence, not proof, so they are weighed together rather than
/// ranked.** A `Connection`'s `display_name` is not necessarily the one the
/// session recorded: a backend synthesizes one for a declaration that named none
/// (`plugin-http` synthesizes `http`, and the trait default falls back to the
/// kind descriptor's `HTTP`). So a session holding one declaration named `HTTP`
/// and one unnamed declaration has TWO plausible sources for a removed
/// connection called `HTTP`, and they are different declarations. Ranking the
/// name comparison first picked the explicitly named one and dropped it —
/// `write-config` then re-emitted the connection that was removed and omitted
/// the one still running, corrupting a file the operator deploys. So when the
/// removed name is one the backend could have synthesized, a declaration
/// recording that name and a declaration recording none are **both** candidates,
/// and two candidates is a refusal. Only where the name cannot be synthetic —
/// nothing else could have produced `stage` — does recording it identify a
/// declaration.
///
/// **Where no answer is unique, the session is left alone and the operator is
/// told.** The live graph is already correct; this function decides only what
/// `write-config` writes, and dropping the wrong declaration is worse than
/// dropping none.
///
/// The residue is a backend that synthesizes a name resembling neither its kind
/// nor its descriptor's display name, and a session that declares that same
/// string on a *different* connection of that kind, and no address on either to
/// separate them. Closing that would take the graph handing connection ids back
/// to the session at startup — an `(target, id)` → declaration map made where
/// `host::build_stack` applies them — which no current API offers.
fn forget_session_entry(
    declared: &mut Vec<SessionConnection>,
    removed: &Connection,
    target: &str,
    descriptor: Option<&StorageBackendKindDescriptor>,
) {
    // A declaration that could not have produced this connection at all. The
    // `target` comparison narrows and never widens: `None` is "wherever the
    // kind landed", which this layer satisfies like any other.
    let possible = |entry: &SessionConnection| {
        entry.backend_kind == removed.backend_kind
            && entry
                .target
                .as_deref()
                .is_none_or(|pinned| pinned == target)
    };

    let indices = |predicate: &dyn Fn(&SessionConnection) -> bool| -> Vec<usize> {
        declared
            .iter()
            .enumerate()
            .filter(|(_, entry)| possible(entry) && predicate(entry))
            .map(|(index, _)| index)
            .collect()
    };

    let by_address = indices(&|entry: &SessionConnection| match descriptor {
        Some(descriptor) => route_candidates(descriptor, &entry.config)
            .iter()
            .any(|address| {
                removed
                    .current_addresses
                    .iter()
                    .any(|live| ovstorage::address::same_node(address, live))
            }),
        None => false,
    });
    let by_name = indices(&|entry: &SessionConnection| {
        entry.display_name.as_deref() == Some(removed.display_name.as_str())
    });
    let unnamed = indices(&|entry: &SessionConnection| entry.display_name.is_none());

    match by_address.as_slice() {
        [only] => {
            declared.remove(*only);
            return;
        }
        // No address to reason from — the parked case. Fall through to the
        // name evidence below.
        [] => {}
        // Two declarations claiming one node is uncommon — the add path refuses
        // the second, so at most one of them ever became a connection — but it
        // is not impossible: the refused one is skipped with a warning and stays
        // in the config, so the session still holds it. Which of the two the
        // live connection came from is not something to settle by picking one.
        _ => return note(),
    }

    // Could the backend have invented this name for a declaration that recorded
    // none? Both spellings the in-tree defaulting produces are checked — the
    // kind itself (`plugin-http`'s `http`) and the kind descriptor's display
    // name (`HTTP`) — case-insensitively, since they differ only in case and the
    // descriptor is a best-effort lookup that may be absent.
    let synthetic = removed
        .display_name
        .eq_ignore_ascii_case(&removed.backend_kind)
        || descriptor.is_some_and(|descriptor| {
            removed
                .display_name
                .eq_ignore_ascii_case(&descriptor.display_name)
        });

    let candidates: Vec<usize> = if synthetic {
        // Indistinguishable sources: the declaration recording this name, and
        // every declaration whose name the backend would have invented. One
        // candidate identifies a declaration; more than one is a refusal.
        let mut both = by_name;
        for index in unnamed {
            if !both.contains(&index) {
                both.push(index);
            }
        }
        both.sort_unstable();
        both
    } else if by_name.is_empty() {
        // A name no declaration recorded and the backend is not known to
        // synthesize. Some backend invented it, so its source is a declaration
        // that recorded none — usable only while there is exactly one.
        unnamed
    } else {
        by_name
    };

    match candidates.as_slice() {
        [only] => {
            declared.remove(*only);
        }
        // Silent when NOTHING matched: the session simply never declared this
        // connection, and there is nothing to forget.
        [] => {}
        _ => note(),
    }
}

/// Told, not guessed: the removal itself succeeded, and only the session's
/// record of it is left for the operator to finish.
fn note() {
    eprintln!(
        "note: more than one declared connection could be the one just removed, so none \
         was dropped; delete the intended [[ovstorage.connections]] entry by hand before \
         `write-config`."
    );
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use ovstorage::{
        AuthReason, Capabilities, ConnectionAuthState, ConnectionId, ConnectionSnapshot,
        ConnectionSource, ConnectionUpdateStream, Extensions, LayerKindDescriptor, LayerType,
        UserMetadata,
    };

    use super::*;

    /// A graph with two connection-owning targets, standing in for the shape
    /// that defeated every kind- or name-based resolution: a router over two
    /// same-kind children.
    ///
    /// Only the surface the owner scan touches is implemented — `owned_targets`,
    /// `list_connections`, `remove_connection` — because that surface IS the
    /// contract under test. A target that does not hold the id answers
    /// `NotFound`, exactly as a Router does for a target it does not route and a
    /// backend does for an id it does not hold.
    struct TwoTenantGraph {
        tenants: Mutex<Vec<(String, Vec<Connection>)>>,
        /// A target that answers something OTHER than `NotFound`, so a test can
        /// prove a real refusal is not swallowed as "not mine".
        refusing: Option<String>,
        /// A target that answers `Unsupported` **without reading the key**, as
        /// the `Layer` leaf default does for any layer that never overrode
        /// `remove_connection`.
        key_blind: Option<String>,
        /// `(address, target, connection_id)` the way a route table would
        /// resolve it: which layer serves the node, and which connection the
        /// published root there says it is serving. The third element is what
        /// makes a SHADOWED root expressible — the winner's id at an address the
        /// loser also publishes.
        routes: Vec<(String, String, String)>,
        /// A target that removes the connection and THEN answers
        /// `CommitAmbiguous`, as a Router does when its post-commit route-table
        /// catch-up cannot be confirmed. The mutation happened; only the
        /// reconcile is in doubt.
        unreconciled: Option<String>,
        /// Every target `remove_connection` was called against, in order.
        ///
        /// The scan establishes ownership by ATTEMPTING the operation, so
        /// "which targets were addressed" is the only way to tell a direct
        /// removal from a scan that happened to reach the same layer: both end
        /// with the same connection gone and the same target reported. Asserting
        /// on the outcome alone leaves the probing this field exists to
        /// eliminate free to come back unnoticed.
        addressed: Mutex<Vec<String>>,
    }

    impl TwoTenantGraph {
        fn new(tenants: &[(&str, &[(&str, &str)])]) -> Self {
            Self {
                tenants: Mutex::new(
                    tenants
                        .iter()
                        .map(|(target, connections)| {
                            (
                                (*target).to_string(),
                                connections
                                    .iter()
                                    .map(|(id, display_name)| connection(id, display_name))
                                    .collect(),
                            )
                        })
                        .collect(),
                ),
                refusing: None,
                key_blind: None,
                addressed: Mutex::new(Vec::new()),
                routes: Vec::new(),
                unreconciled: None,
            }
        }

        fn refusing(mut self, target: &str) -> Self {
            self.refusing = Some(target.to_string());
            self
        }

        fn key_blind(mut self, target: &str) -> Self {
            self.key_blind = Some(target.to_string());
            self
        }

        fn unreconciled(mut self, target: &str) -> Self {
            self.unreconciled = Some(target.to_string());
            self
        }

        /// Publish `address` as served by `target`, with a root naming
        /// connection `id` — the pair a proven derivation needs.
        fn owning(mut self, target: &str, address: &str, id: &str) -> Self {
            self.routes
                .push((address.to_string(), target.to_string(), id.to_string()));
            self
        }

        /// Make the connection `id` on `target` publish `address`, the way the
        /// shadowed and the winning side of an overlap both do.
        fn publishing(self, target: &str, id: &str, address: &str) -> Self {
            {
                let mut tenants = self.tenants.lock().unwrap();
                let (_, connections) = tenants
                    .iter_mut()
                    .find(|(name, _)| name == target)
                    .expect("the target exists");
                let connection = connections
                    .iter_mut()
                    .find(|connection| connection.id.0 == id)
                    .expect("the connection exists");
                connection
                    .current_addresses
                    .push(ovstorage::address::parse(address).unwrap());
            }
            self
        }

        fn addressed(&self) -> Vec<String> {
            self.addressed.lock().unwrap().clone()
        }

        fn ids(&self) -> Vec<String> {
            self.tenants
                .lock()
                .unwrap()
                .iter()
                .flat_map(|(_, connections)| {
                    connections.iter().map(|connection| connection.id.0.clone())
                })
                .collect()
        }

        fn remaining_of(&self, target: &str) -> Vec<String> {
            self.tenants
                .lock()
                .unwrap()
                .iter()
                .filter(|(name, _)| name == target)
                .flat_map(|(_, connections)| {
                    connections.iter().map(|connection| connection.id.0.clone())
                })
                .collect()
        }
    }

    /// Parked with no address, which is both the state these commands exist to
    /// serve and the one no address-based resolution can answer for.
    fn connection(id: &str, display_name: &str) -> Connection {
        Connection {
            id: ConnectionId(id.to_string()),
            backend_kind: "http".to_string(),
            display_name: display_name.to_string(),
            source: ConnectionSource::Runtime { persisted: false },
            capabilities: Capabilities::empty(),
            current_addresses: Vec::new(),
            auth_state: ConnectionAuthState::AwaitingAuth {
                reason: AuthReason::NeverAuthenticated,
                last_attempt: None,
            },
            last_probed: None,
            user_metadata: UserMetadata::new(),
            owning_target: None,
        }
    }

    #[async_trait]
    impl ovstorage::Layer for TwoTenantGraph {
        fn name(&self) -> &str {
            "graph"
        }

        fn descriptor(&self) -> LayerKindDescriptor {
            // A router: it owns no connections itself, which is what makes the
            // `owned_targets` override below the only source of targets.
            LayerKindDescriptor {
                kind: "graph".to_string(),
                layer_type: LayerType::Router,
                display_name: "graph".to_string(),
                description: None,
                config_schema: Vec::new(),
                credential_schema: Vec::new(),
                credential_methods: Vec::new(),
                icon: None,
                accepts_connections: false,
                // Not a listener authentication Layer, and it owns no storage.
                auth_capable: false,
                supports_user_metadata: false,
            }
        }

        fn owned_targets(&self) -> Vec<String> {
            self.tenants
                .lock()
                .unwrap()
                .iter()
                .map(|(target, _)| target.clone())
                .collect()
        }

        async fn owning_target_for(
            &self,
            url: &ovstorage::Url,
            _cx: &Extensions,
            _cancel: Option<CancellationToken>,
        ) -> Option<String> {
            self.routes
                .iter()
                .find(|(address, _, _)| address == url.as_str())
                .map(|(_, target, _)| target.clone())
        }

        /// The root the route table would answer with, naming whichever
        /// connection won that node — which for a shadowed address is not the
        /// connection that asked.
        async fn root_info_for(
            &self,
            url: &ovstorage::Url,
            _cx: &Extensions,
            _cancel: Option<CancellationToken>,
        ) -> ovstorage::Result<ovstorage::RootInfo> {
            let (address, _, id) = self
                .routes
                .iter()
                .find(|(address, _, _)| address == url.as_str())
                .ok_or_else(|| Error::new(ErrorCode::NoRoute, "no route matches address"))?;
            Ok(ovstorage::RootInfo {
                root: ovstorage::address::parse(address).unwrap(),
                display_name: None,
                layer_kind: "http".to_string(),
                connection_id: Some(ovstorage::ConnectionId(id.clone())),
                owning_target: None,
                capabilities: Capabilities::empty(),
                range_read_strategy: ovstorage::RangeReadStrategy::default(),
                source: ovstorage::RouteSource::Static {
                    layer: ovstorage::ConfigLayer::Programmatic,
                },
                visible: true,
                visibility: ovstorage::AddressVisibility::Visible,
                alias_state: None,
                icon: None,
                user_metadata: UserMetadata::new(),
            })
        }

        async fn list_connections(
            &self,
            _cx: &Extensions,
            _cancel: Option<CancellationToken>,
        ) -> ovstorage::Result<(ConnectionSnapshot, Option<ConnectionUpdateStream>)> {
            let connections = self
                .tenants
                .lock()
                .unwrap()
                .iter()
                .flat_map(|(_, connections)| connections.iter().cloned())
                .collect();
            Ok((
                ConnectionSnapshot {
                    connections,
                    updates: false,
                },
                None,
            ))
        }

        async fn remove_connection(
            &self,
            key: Request<ConnectionKey>,
            _cancel: Option<CancellationToken>,
        ) -> ovstorage::Result<()> {
            self.addressed
                .lock()
                .unwrap()
                .push(key.input.target.clone());
            if self.refusing.as_deref() == Some(key.input.target.as_str()) {
                return Err(Error::new(
                    ErrorCode::PermissionDenied,
                    "this layer refuses removals",
                ));
            }
            // Before the id is looked at, exactly as the leaf default answers.
            if self.key_blind.as_deref() == Some(key.input.target.as_str()) {
                return Err(Error::new(
                    ErrorCode::Unsupported,
                    "remove_connection is not supported by this layer",
                ));
            }
            let mut tenants = self.tenants.lock().unwrap();
            let Some((_, connections)) = tenants
                .iter_mut()
                .find(|(target, _)| *target == key.input.target)
            else {
                // A Router's answer for a target it does not route.
                return Err(Error::new(ErrorCode::NotFound, "target layer not found"));
            };
            let before = connections.len();
            connections.retain(|connection| connection.id != key.input.id);
            if connections.len() == before {
                // A backend's answer for an id it does not hold. The scan must
                // read both spellings the same way.
                return Err(Error::new(ErrorCode::NotFound, "connection not found"));
            }
            // AFTER the removal has taken effect, which is the whole point: the
            // Router raises this over a mutation the child already committed.
            if self.unreconciled.as_deref() == Some(key.input.target.as_str()) {
                return Err(Error::new(
                    ErrorCode::CommitAmbiguous,
                    "the route-table catch-up was abandoned",
                ));
            }
            Ok(())
        }
    }

    fn cancel() -> CancellationToken {
        CancellationToken::new()
    }

    /// The same row as a layer's own configuration seeds — `plugin-http` builds
    /// one of these from a non-empty `[ovstorage.layers.http]` block.
    fn layer_seeded(id: &str, display_name: &str) -> Connection {
        Connection {
            source: ConnectionSource::Static {
                layer: ovstorage::ConfigLayer::Programmatic,
            },
            ..connection(id, display_name)
        }
    }

    #[test]
    fn a_layer_seeded_connection_is_refused_rather_than_half_removed() {
        // `forget_session_entry` reaches `[[ovstorage.connections]]` and nothing
        // else, and this connection's seed is the layer block, which
        // `write-config` re-serializes from the spec the stack was built from.
        // Removing the live half would report success and be undone by the next
        // startup — on the very recovery path this command advertises.
        let refusal = layer_seeded_refusal(&layer_seeded("http-1", "assets"), Some("http"))
            .expect("a layer-config seed cannot be finished here");
        assert_eq!(refusal.code(), ErrorCode::Unsupported);
        assert!(
            refusal.message().contains("[ovstorage.layers.http]"),
            "the message must name the block to edit: {refusal}",
        );
        assert!(
            refusal.message().contains("assets"),
            "and the connection the operator named: {refusal}",
        );
    }

    #[test]
    fn a_layer_seeded_connection_with_no_derivable_owner_still_refuses() {
        // Parked and refused connections publish no address, which is exactly
        // what this command exists to clear — so the layer cannot always be
        // named, and the refusal must not depend on naming it.
        let refusal = layer_seeded_refusal(&layer_seeded("http-1", "assets"), None)
            .expect("the refusal does not depend on deriving the layer");
        assert_eq!(refusal.code(), ErrorCode::Unsupported);
        assert!(
            refusal.message().contains("[ovstorage.layers.*]"),
            "it names the shape instead of guessing a layer: {refusal}",
        );
    }

    #[test]
    fn a_declared_connection_is_not_refused() {
        // The ordinary case: applied through `add_connection` from an
        // `[[ovstorage.connections]]` entry, which the session holds and can
        // drop.
        assert!(
            layer_seeded_refusal(&connection("c-1", "assets"), Some("http")).is_none(),
            "a runtime connection is exactly what `disconnect` is for",
        );
    }

    #[test]
    fn a_broker_delivered_connection_is_not_refused() {
        // It came from a broker rather than local configuration, so no local
        // config re-creates it and `write-config` never emitted it.
        let delivered = Connection {
            source: ConnectionSource::BrokerDelivered {
                broker_principal: "ops".to_string(),
            },
            ..connection("c-1", "assets")
        };
        assert!(layer_seeded_refusal(&delivered, Some("broker")).is_none());
    }

    /// The same row, reporting the layer that owns it -- which every in-tree
    /// backend does, and only a loaded composite plugin leaves unset.
    fn connection_at(id: &str, display_name: &str, target: &str) -> Connection {
        Connection {
            owning_target: Some(target.to_string()),
            ..connection(id, display_name)
        }
    }

    #[tokio::test]
    async fn an_attributed_row_is_removed_without_scanning() {
        // These fixtures are parked (`AwaitingAuth`) and publish no address,
        // which is the case `disconnect` exists for and the one no published
        // root can answer -- so the target here can only have come from the row
        // itself.
        //
        // The row says `stage`, so `prod` is never asked. That matters beyond
        // the saved call: the scan establishes ownership by ATTEMPTING the
        // removal, and a layer is under no obligation to read the key before
        // acting on it -- so not asking is the whole point, not an
        // optimization.
        let graph = TwoTenantGraph::new(&[
            ("prod", &[("c-prod", "prod")]),
            ("stage", &[("c-stage", "stage")]),
        ]);
        let removed = remove_resolved(
            &graph,
            &connection_at("c-stage", "stage", "stage"),
            &cancel(),
        )
        .await
        .expect("the row named its owner");
        assert_eq!(removed.target, "stage");
        assert_eq!(graph.ids(), ["c-prod"]);
        // The load-bearing assertion. A regression that fell back to the scan
        // would address `prod` first, take a harmless `NotFound`, then remove
        // from `stage` -- reaching the same reported target and the same final
        // ids as the direct path. Only the call list tells them apart.
        assert_eq!(
            graph.addressed(),
            ["stage"],
            "no layer but the named owner may be addressed",
        );
    }

    #[tokio::test]
    async fn an_attributed_shared_id_is_removed_from_the_layer_that_reported_it() {
        // Two layers both hold `rule` -- legal, since an id is unique only
        // WITHIN its target, and the alias layer takes a caller-supplied id
        // verbatim. Unattributed, this is the case that must be refused: a key
        // built from the id alone could reach either. Attributed, the pair
        // picks one out exactly, and the namesake is left running.
        let graph = TwoTenantGraph::new(&[
            ("prod", &[("rule", "prod-rule")]),
            ("stage", &[("rule", "stage-rule")]),
        ]);
        let removed = remove_resolved(
            &graph,
            &connection_at("rule", "stage-rule", "stage"),
            &cancel(),
        )
        .await
        .expect("the pair is unambiguous even though the id is not");
        assert_eq!(removed.target, "stage");
        assert_eq!(
            graph.ids(),
            ["rule"],
            "the namesake on the other target must survive",
        );
        assert_eq!(
            graph.remaining_of("prod"),
            ["rule"],
            "and it must be `prod`'s that survived, not `stage`'s",
        );
        assert!(graph.remaining_of("stage").is_empty());
        assert_eq!(
            graph.addressed(),
            ["stage"],
            "`prod` holds a namesake, so probing it is exactly the damage this \
             avoids -- it must never be addressed",
        );
    }

    #[tokio::test]
    async fn an_unattributed_shared_id_is_still_refused() {
        // The fallback keeps its refusal where it is still earned: neither row
        // reports an owner, neither publishes an address to derive one from,
        // and removing a live tenant's connection is not something to be sorry
        // about afterwards.
        let graph = TwoTenantGraph::new(&[
            ("prod", &[("rule", "prod-rule")]),
            ("stage", &[("rule", "stage-rule")]),
        ]);
        let error = remove_resolved(&graph, &connection("rule", "stage-rule"), &cancel())
            .await
            .expect_err("nothing can tell the two apart");
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
        assert_eq!(graph.ids(), ["rule", "rule"], "nothing may be removed");
    }

    #[tokio::test]
    async fn an_attributed_row_the_owner_no_longer_holds_reports_not_found() {
        // `NotFound` from the named owner is not "not mine, try the next" --
        // there is nowhere else to look. It means the connection is gone, and
        // it travels back as the answer it is rather than being restated as a
        // scan summary.
        let graph = TwoTenantGraph::new(&[("prod", &[("c-prod", "prod")]), ("stage", &[])]);
        let error = remove_resolved(
            &graph,
            &connection_at("c-ghost", "ghost", "stage"),
            &cancel(),
        )
        .await
        .expect_err("that target does not hold it");
        assert_eq!(error.code(), ErrorCode::NotFound);
        assert_eq!(graph.ids(), ["c-prod"]);
    }

    #[tokio::test]
    async fn the_owner_scan_removes_from_the_target_that_holds_the_id() {
        // The point of the scan: nothing said which target owns `stage-1`, and
        // the connection publishes no address to derive it from. `prod` answers
        // `NotFound` and the scan moves on rather than reporting it.
        let graph = TwoTenantGraph::new(&[
            ("prod", &[("c-prod", "prod")]),
            ("stage", &[("c-stage", "stage")]),
        ]);
        let removed = remove_resolved(&graph, &connection("c-stage", "stage"), &cancel())
            .await
            .expect("the second target owns it");
        assert_eq!(
            removed.target, "stage",
            "the scan must name the target that acted",
        );
        assert!(
            removed.unreconciled.is_none(),
            "a clean removal leaves nothing in doubt",
        );
        assert_eq!(
            graph.ids(),
            ["c-prod"],
            "exactly one connection may be removed",
        );
    }

    #[tokio::test]
    async fn an_id_no_layer_owns_is_reported_as_such() {
        let graph = TwoTenantGraph::new(&[("prod", &[("c-prod", "prod")]), ("stage", &[])]);
        let error = remove_resolved(&graph, &connection("c-ghost", "ghost"), &cancel())
            .await
            .expect_err("no target holds it");
        assert_eq!(error.code(), ErrorCode::NotFound);
        assert!(
            error.message().contains("c-ghost"),
            "the message must name the id the operator typed: {error}",
        );
        assert_eq!(graph.ids(), ["c-prod"], "an exhausted scan removes nothing");
    }

    #[tokio::test]
    async fn a_refusal_is_not_read_as_not_mine() {
        // `NotFound` is the only "try the next target" answer. A layer that
        // refuses a removal it does own has said something the operator needs,
        // and continuing the scan would bury it under a final `NotFound`.
        let graph = TwoTenantGraph::new(&[
            ("prod", &[("c-prod", "prod")]),
            ("stage", &[("c-stage", "stage")]),
        ])
        .refusing("prod");
        let error = remove_resolved(&graph, &connection("c-stage", "stage"), &cancel())
            .await
            .expect_err("the refusal must travel back");
        assert_eq!(error.code(), ErrorCode::PermissionDenied);
        assert_eq!(
            graph.ids(),
            ["c-prod", "c-stage"],
            "a scan stopped by a refusal must not have removed anything",
        );
    }

    #[tokio::test]
    async fn a_key_blind_unsupported_does_not_end_the_scan() {
        // The `Layer` leaf default answers `Unsupported` without reading the
        // key, so a layer that owns no connections says it for an id it does
        // not hold. `file` leads `owned_targets()` here and the connection is
        // parked with no address to derive an owner from — the routeless case
        // this command exists for — so taking that answer as final would report
        // it about a layer that was never really asked.
        let graph = TwoTenantGraph::new(&[("file", &[]), ("broker", &[("c-broker", "broker")])])
            .key_blind("file");
        let removed = remove_resolved(&graph, &connection("c-broker", "broker"), &cancel())
            .await
            .expect("the scan must reach the layer that holds the id");
        assert_eq!(removed.target, "broker");
        assert!(
            graph.ids().is_empty(),
            "the connection the operator named must be gone",
        );
    }

    #[tokio::test]
    async fn an_unsupported_outlives_a_scan_that_finds_no_owner() {
        // Remembered, not discarded: where no target owns the id, a layer's own
        // refusal explains more than the scan's summary can, and nothing was
        // removed either way.
        let graph = TwoTenantGraph::new(&[("file", &[]), ("broker", &[("c-broker", "broker")])])
            .key_blind("file");
        let error = remove_resolved(&graph, &connection("c-ghost", "ghost"), &cancel())
            .await
            .expect_err("no target holds it");
        assert_eq!(error.code(), ErrorCode::Unsupported);
        assert_eq!(graph.ids(), ["c-broker"], "nothing may be removed");
    }

    /// A connection with one address, so the exact derivation has something to
    /// work from.
    #[test]
    fn the_address_column_redacts_what_a_list_can_recognise() {
        // An inventory command's output is kept — CI logs, a pasted terminal —
        // so an address that carries a credential must not be what puts it
        // there. Userinfo and the query keys known to carry a signed-URL
        // credential go; the path stays, because the path is what the column is
        // FOR: two connections on one origin under distinct prefixes are the
        // arrangement `plugin-http.md` recommends, and they would print
        // identically without it.
        let mut connection = connection("c-1", "assets");
        connection.current_addresses = vec![
            ovstorage::address::parse("https://ops:secret@h/team-a/?sig=SIGNED&page=2").unwrap(),
            ovstorage::address::parse("https://h/team-b/").unwrap(),
        ];
        let column = address_column(&connection);
        assert!(!column.contains("secret"), "userinfo must go: {column}");
        assert!(!column.contains("SIGNED"), "and a signed query: {column}");
        assert!(
            column.contains("team-a") && column.contains("team-b"),
            "while the paths that distinguish the two stay: {column}",
        );
        assert!(
            column.contains("page=2"),
            "a query that is not a credential is diagnostic and stays: {column}",
        );
        assert_eq!(
            column.split(' ').count(),
            2,
            "one field per address, and nothing redacted introduces a space: {column}",
        );
    }

    #[test]
    fn the_address_column_cannot_redact_a_path_capability() {
        // Stated rather than implied: no list recognises a credential spelled
        // as a path segment, and origin-only — which would remove it — is the
        // rule for messages that merely NAME a connection, not for the column
        // whose job is to say which address spaces are served.
        let mut connection = connection("c-1", "assets");
        connection.current_addresses =
            vec![ovstorage::address::parse("https://h/s/CAP4B0RT/").unwrap()];
        assert!(address_column(&connection).contains("CAP4B0RT"));
    }

    fn routed(id: &str, display_name: &str, address: &str) -> Connection {
        let mut connection = connection(id, display_name);
        connection.current_addresses = vec![ovstorage::address::parse(address).unwrap()];
        connection
    }

    #[tokio::test]
    async fn an_unreconciled_removal_still_names_the_target_that_acted() {
        // The Router runs its route-table catch-up AFTER the child has removed
        // the connection, so `CommitAmbiguous` is raised over a mutation that
        // happened. Reading it as a plain error lost the acting target, and
        // `disconnect` then skipped the session bookkeeping the commit calls
        // for — leaving a declaration `write-config` would re-emit and the next
        // startup would act on, recreating the connection just disconnected.
        let graph = TwoTenantGraph::new(&[
            ("prod", &[("c-prod", "prod")]),
            ("stage", &[("c-stage", "stage")]),
        ])
        .unreconciled("stage");
        let removed = remove_resolved(&graph, &connection("c-stage", "stage"), &cancel())
            .await
            .expect("a committed removal is not a failed one");
        assert_eq!(
            removed.target, "stage",
            "the target that acted must survive the ambiguity",
        );
        let unreconciled = removed
            .unreconciled
            .expect("the reconcile doubt must travel with it");
        assert_eq!(unreconciled.code(), ErrorCode::CommitAmbiguous);
        assert_eq!(
            graph.ids(),
            ["c-prod"],
            "the connection really is gone from the child",
        );
    }

    #[tokio::test]
    async fn an_unreconciled_removal_does_not_scan_on() {
        // The removal committed, so the scan is over — `CommitAmbiguous` is not
        // a "not mine". `prod` leads `owned_targets()` and holds the id, so
        // treating it as one would step past the layer that acted, exhaust the
        // scan on a sibling that answers `NotFound`, and report that nothing
        // owned the connection — over a connection it had just removed.
        let graph = TwoTenantGraph::new(&[
            ("prod", &[("c-1", "prod-row")]),
            ("stage", &[("c-2", "stage-row")]),
        ])
        .unreconciled("prod");
        let removed = remove_resolved(&graph, &connection("c-1", "prod-row"), &cancel())
            .await
            .expect("a committed removal must not be reported as unowned");
        assert_eq!(removed.target, "prod");
        assert!(removed.unreconciled.is_some());
        assert_eq!(
            graph.remaining_of("stage"),
            ["c-2"],
            "no sibling may be touched after the owner has acted",
        );
    }

    #[tokio::test]
    async fn a_shared_id_is_never_removed_by_scanning() {
        // A connection id is unique only WITHIN its owning target — the Layer
        // contract says so, and the alias layer takes a caller-supplied `id`
        // verbatim, so two layers really can both hold `rule`. Scanning would
        // remove whichever `owned_targets()` yields first, which is not the
        // connection the selector resolved.
        let graph = TwoTenantGraph::new(&[
            ("prod", &[("rule", "prod-rule")]),
            ("stage", &[("rule", "stage-rule")]),
        ]);
        let error = remove_resolved(&graph, &connection("rule", "stage-rule"), &cancel())
            .await
            .expect_err("a shared id with no address cannot be told apart");
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
        assert!(
            error.message().contains("rule"),
            "the message must name the id: {error}",
        );
        assert_eq!(
            graph.ids(),
            ["rule", "rule"],
            "neither namesake may be removed",
        );
    }

    #[tokio::test]
    async fn a_shared_id_is_removed_from_the_target_its_address_derives() {
        // The same collision, but this connection publishes an address, so the
        // owner is derived exactly and the scan is never consulted. `prod` leads
        // `owned_targets()`, so a scan would have taken the wrong one.
        let graph = TwoTenantGraph::new(&[
            ("prod", &[("rule", "prod-rule")]),
            ("stage", &[("rule", "stage-rule")]),
        ])
        .owning("stage", "alias://h/stage/", "rule")
        .publishing("stage", "rule", "alias://h/stage/");
        let removed = remove_resolved(
            &graph,
            &routed("rule", "stage-rule", "alias://h/stage/"),
            &cancel(),
        )
        .await
        .expect("the address names its owner exactly");
        assert_eq!(removed.target, "stage");
        assert_eq!(
            graph.remaining_of("prod"),
            ["rule"],
            "the namesake on the other layer must survive",
        );
        assert!(graph.remaining_of("stage").is_empty());
    }

    #[tokio::test]
    async fn a_shadowed_address_does_not_aim_a_shared_id_removal_at_the_incumbent() {
        // The destructive shape. Both layers hold `rule` and both publish
        // `alias://h/shared/` — a partial collision, which the Router keeps by
        // shadowing the loser's root — and `prod` won the route. The published
        // root there carries the id `rule`, which is OUR id too, so id equality
        // proves nothing: taking the derived target would have removed `prod`'s
        // live connection instead of the `stage-rule` row the operator named.
        let graph = TwoTenantGraph::new(&[
            ("prod", &[("rule", "prod-rule")]),
            ("stage", &[("rule", "stage-rule")]),
        ])
        .owning("prod", "alias://h/shared/", "rule")
        .publishing("prod", "rule", "alias://h/shared/")
        .publishing("stage", "rule", "alias://h/shared/");
        let error = remove_resolved(
            &graph,
            &routed("rule", "stage-rule", "alias://h/shared/"),
            &cancel(),
        )
        .await
        .expect_err("a contested root proves nothing about which namesake it is");
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
        assert_eq!(
            graph.ids(),
            ["rule", "rule"],
            "neither tenant's connection may be removed",
        );
    }

    #[tokio::test]
    async fn a_root_about_another_connection_derives_no_owner() {
        // The other half of the guard, with a unique id: the address resolves,
        // but the root there names a different connection — a broader sibling
        // root containing this address, or the winner of a shadowed one. That is
        // not a derivation, so the scan runs and finds the real owner instead of
        // the route winner.
        let graph = TwoTenantGraph::new(&[
            ("prod", &[("c-prod", "prod")]),
            ("stage", &[("c-stage", "stage")]),
        ])
        .owning("prod", "alias://h/shared/", "c-prod");
        let removed = remove_resolved(
            &graph,
            &routed("c-stage", "stage", "alias://h/shared/"),
            &cancel(),
        )
        .await
        .expect("the scan reaches the layer that holds the id");
        assert_eq!(
            removed.target, "stage",
            "the route winner is not the owner and must not be addressed as one",
        );
        assert_eq!(graph.ids(), ["c-prod"], "the winner's connection survives");
    }

    #[tokio::test]
    async fn a_contested_first_address_does_not_hide_the_proving_one() {
        // The same shape one turn further on. Both layers hold `rule` and both
        // publish `alias://h/shared/`, so the root there names an id BOTH
        // answer to and proves nothing — but this connection also publishes
        // `alias://h/stage/`, which it holds alone and whose root names it.
        //
        // Judging the contest in the caller, only the first proof was examined:
        // it came back contested, the caller refused, and a connection that
        // could be addressed exactly was declared indistinguishable. The
        // contest is a reason to try the NEXT address.
        let graph = TwoTenantGraph::new(&[
            ("prod", &[("rule", "prod-rule")]),
            ("stage", &[("rule", "stage-rule")]),
        ])
        .owning("prod", "alias://h/shared/", "rule")
        .owning("stage", "alias://h/stage/", "rule")
        .publishing("prod", "rule", "alias://h/shared/");

        let mut removed = connection("rule", "stage-rule");
        removed.current_addresses = ["alias://h/shared/", "alias://h/stage/"]
            .iter()
            .map(|address| ovstorage::address::parse(address).unwrap())
            .collect();
        // The namesake on `prod` publishes the contested node, which is what
        // makes the first address prove nothing.
        let mut namesake = connection("rule", "prod-rule");
        namesake.current_addresses = vec![ovstorage::address::parse("alias://h/shared/").unwrap()];
        let listing = vec![namesake, removed.clone()];

        let proof = proven_owner(&graph, &removed, &listing, &cancel())
            .await
            .expect("the address this connection holds alone proves its owner");
        assert_eq!(
            proof,
            (
                "stage".to_string(),
                ovstorage::address::parse("alias://h/stage/").unwrap()
            ),
            "the contested address must be stepped over, not taken as the answer",
        );
    }

    #[tokio::test]
    async fn a_shadowed_first_address_does_not_hide_the_proving_one() {
        // Two published addresses, and the first is the shadowed one: its root
        // names `prod`'s connection. Reading only the first address derived
        // `prod` and gave up on proof entirely; the second address routes here
        // and its root says so, which is the answer.
        let graph = TwoTenantGraph::new(&[
            ("prod", &[("c-prod", "prod")]),
            ("stage", &[("c-stage", "stage")]),
        ])
        .owning("prod", "alias://h/shared/", "c-prod")
        .owning("stage", "alias://h/stage/", "c-stage");
        let mut removed = connection("c-stage", "stage");
        removed.current_addresses = ["alias://h/shared/", "alias://h/stage/"]
            .iter()
            .map(|address| ovstorage::address::parse(address).unwrap())
            .collect();
        // Listing carries only this connection: no namesake, so nothing here
        // is contested and the skip under test is the id mismatch alone.
        let listing = vec![removed.clone()];
        let target = proven_owner(&graph, &removed, &listing, &cancel())
            .await
            .expect("a later address proves the owner");
        assert_eq!(
            target,
            (
                "stage".to_string(),
                ovstorage::address::parse("alias://h/stage/").unwrap()
            ),
            "the proving address comes back with the target it proved",
        );
    }

    #[tokio::test]
    async fn a_selector_resolves_an_id_before_a_display_name() {
        // A display name is free-form caller text and can be spelled like an
        // id. Resolving it to a connection OTHER than the one whose id it is
        // would be the worst available reading.
        let graph =
            TwoTenantGraph::new(&[("prod", &[("c-1", "c-2")]), ("stage", &[("c-2", "stage")])]);
        let resolved = resolve_selector(&graph, "c-2", &cancel())
            .await
            .expect("`c-2` is an id");
        assert_eq!(resolved.id.0, "c-2");
        assert_eq!(resolved.display_name, "stage");
    }

    #[tokio::test]
    async fn a_selector_resolves_a_display_name_when_no_id_matches() {
        let graph =
            TwoTenantGraph::new(&[("prod", &[("c-1", "prod")]), ("stage", &[("c-2", "stage")])]);
        let resolved = resolve_selector(&graph, "stage", &cancel())
            .await
            .expect("a unique display name resolves");
        assert_eq!(resolved.id.0, "c-2");
    }

    #[tokio::test]
    async fn a_repeated_display_name_is_ambiguous_rather_than_guessed() {
        // The two-tenant shape again: one name, two connections, and nothing
        // here can know which the operator meant. `reauth`'s error, verbatim.
        let graph = TwoTenantGraph::new(&[
            ("prod", &[("c-1", "shared")]),
            ("stage", &[("c-2", "shared")]),
        ]);
        let error = resolve_selector(&graph, "shared", &cancel())
            .await
            .expect_err("two connections share the name");
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
        assert!(
            error.message().contains("ambiguous") && error.message().contains("rename"),
            "the operator must be told how to resolve it: {error}",
        );
    }

    #[tokio::test]
    async fn a_shared_id_selector_is_refused_rather_than_guessed() {
        // Two layers both holding `rule` — the alias layer's caller-supplied id
        // makes this reachable. `disconnect` takes no target, so there is no
        // spelling of this id that names one of them; taking the first would
        // remove a live connection the operator did not name, and both rows
        // print the same id, so nothing would reveal which one went.
        let graph = TwoTenantGraph::new(&[
            ("prod", &[("rule", "prod-rule")]),
            ("stage", &[("rule", "stage-rule")]),
        ]);
        let error = resolve_selector(&graph, "rule", &cancel())
            .await
            .expect_err("a shared id names no single connection");
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
        assert!(
            error.message().contains("display_name"),
            "the operator must be pointed at the selector that can tell them apart: {error}",
        );
    }

    #[tokio::test]
    async fn a_display_name_still_reaches_one_of_two_namesakes() {
        // The remedy the error above advertises has to exist: the ids collide,
        // the display names do not, and the id path must not swallow a name
        // that matches nothing.
        let graph = TwoTenantGraph::new(&[
            ("prod", &[("rule", "prod-rule")]),
            ("stage", &[("rule", "stage-rule")]),
        ]);
        let resolved = resolve_selector(&graph, "stage-rule", &cancel())
            .await
            .expect("the display names are unique");
        assert_eq!(resolved.id.0, "rule");
        assert_eq!(resolved.display_name, "stage-rule");
    }

    #[tokio::test]
    async fn an_unknown_selector_is_not_found() {
        let graph = TwoTenantGraph::new(&[("prod", &[("c-1", "prod")]), ("stage", &[])]);
        let error = resolve_selector(&graph, "nope", &cancel())
            .await
            .expect_err("neither an id nor a name");
        assert_eq!(error.code(), ErrorCode::NotFound);
    }

    #[test]
    fn forgetting_a_session_entry_prefers_an_exact_display_name() {
        // `stage` is not a name any backend would have invented — it is neither
        // the kind nor the kind descriptor's display name — so the declaration
        // recording it IS the source, and the unnamed sibling cannot be.
        let mut declared = vec![session_entry(None), session_entry(Some("stage"))];
        forget_session_entry(&mut declared, &connection("c-stage", "stage"), "http", None);
        assert_eq!(declared.len(), 1);
        assert_eq!(
            declared[0].display_name, None,
            "the entry that names the removed connection is the one that goes",
        );
    }

    #[test]
    fn forgetting_falls_back_to_the_only_unnamed_entry_of_the_same_kind() {
        // `http` is what `plugin-http` defaults the display name to for an
        // entry that declared none — so nothing in the session can match it by
        // name, and this fallback is the only thing that keeps `write-config`
        // from re-emitting a connection that is gone.
        let mut declared = vec![session_entry(None)];
        forget_session_entry(&mut declared, &connection("c-1", "http"), "http", None);
        assert!(
            declared.is_empty(),
            "an unnamed declaration is still the one that produced it",
        );
    }

    #[test]
    fn forgetting_refuses_a_name_the_backend_could_have_invented() {
        // The dangerous shape: one declaration explicitly named `HTTP`, one
        // unnamed — for which the backend invents exactly `HTTP` — and no
        // address on the removed connection to separate them. Comparing names
        // first identified the explicitly named declaration and dropped it,
        // leaving `write-config` to re-emit the connection that was removed and
        // omit the one still running. Both are plausible sources, so neither
        // may go.
        let mut declared = vec![session_entry(None), session_entry(Some("HTTP"))];
        forget_session_entry(
            &mut declared,
            &connection("c-1", "HTTP"),
            "http",
            Some(&http_like_descriptor()),
        );
        assert_eq!(
            declared.len(),
            2,
            "a synthesizable name identifies no declaration on its own",
        );
    }

    #[test]
    fn forgetting_reads_the_address_over_a_name_the_backend_could_have_invented() {
        // The same collision, recoverable: the removed connection publishes an
        // address, and only one declaration configures that node. That is proof
        // the name cannot give, and it points at the OTHER declaration than the
        // name comparison would have.
        let mut declared = vec![
            routed_entry("https://h/team-a/"),
            SessionConnection {
                display_name: Some("HTTP".to_string()),
                ..routed_entry("https://h/team-b/")
            },
        ];
        let mut removed = connection("c-1", "HTTP");
        removed.current_addresses = vec![ovstorage::address::parse("https://h/team-a/").unwrap()];
        forget_session_entry(
            &mut declared,
            &removed,
            "http",
            Some(&http_like_descriptor()),
        );
        assert_eq!(declared.len(), 1);
        assert_eq!(
            declared[0].display_name.as_deref(),
            Some("HTTP"),
            "the declaration serving another node is the one that survives",
        );
    }

    #[test]
    fn forgetting_leaves_a_declaration_pinned_to_another_layer_alone() {
        // A declaration pinned to `other` did not produce a connection the
        // layer `http` was holding, whatever it is called.
        let mut declared = vec![SessionConnection {
            target: Some("other".to_string()),
            ..session_entry(Some("stage"))
        }];
        forget_session_entry(&mut declared, &connection("c-1", "stage"), "http", None);
        assert_eq!(
            declared.len(),
            1,
            "another layer's declaration is not a candidate",
        );
    }

    #[test]
    fn forgetting_leaves_another_kind_alone() {
        let mut declared = vec![SessionConnection {
            backend_kind: "s3".to_string(),
            ..session_entry(None)
        }];
        forget_session_entry(&mut declared, &connection("c-1", "HTTP"), "http", None);
        assert_eq!(declared.len(), 1, "a different backend kind is not a match");
    }

    #[test]
    fn forgetting_never_drops_a_declaration_it_cannot_identify() {
        // Two unnamed declarations of one kind. Neither names the removed
        // connection — the backend defaulted its display name — and with no
        // address to tell them apart, "the first unnamed one" is a coin flip.
        // Dropping the WRONG one is worse than dropping none: `write-config`
        // would then omit the connection that survived and re-emit the one that
        // was removed.
        let mut declared = vec![session_entry(None), session_entry(None)];
        forget_session_entry(&mut declared, &connection("c-2", "http"), "http", None);
        assert_eq!(
            declared.len(),
            2,
            "an unidentifiable declaration set must be left intact",
        );
    }

    #[test]
    fn forgetting_tells_two_unnamed_declarations_apart_by_address() {
        // The recoverable half of the same shape: two unnamed declarations must
        // name different addresses or they would be colliding on one route, so
        // the address the removed connection publishes identifies its
        // declaration exactly.
        let mut declared = vec![
            routed_entry("https://h/team-a/"),
            routed_entry("https://h/team-b/"),
        ];
        let mut removed = connection("c-2", "http");
        removed.current_addresses = vec![ovstorage::address::parse("https://h/team-b/").unwrap()];
        forget_session_entry(
            &mut declared,
            &removed,
            "http",
            Some(&http_like_descriptor()),
        );
        assert_eq!(declared.len(), 1, "exactly one declaration goes");
        assert_eq!(
            declared[0].config["root_url"].as_str(),
            Some("https://h/team-a/"),
            "the declaration that survives is the one still serving",
        );
    }

    #[test]
    fn forgetting_a_connection_the_session_never_declared_does_nothing() {
        let mut declared = vec![SessionConnection {
            backend_kind: "s3".to_string(),
            ..session_entry(Some("other"))
        }];
        forget_session_entry(&mut declared, &connection("c-1", "http"), "http", None);
        assert_eq!(declared.len(), 1);
    }

    fn session_entry(display_name: Option<&str>) -> SessionConnection {
        SessionConnection {
            backend_kind: "http".to_string(),
            target: None,
            display_name: display_name.map(str::to_string),
            config: std::collections::HashMap::new(),
            credentials: std::collections::HashMap::new(),
        }
    }

    /// An unnamed declaration that names one address, as an ordinary
    /// `[[ovstorage.connections]]` entry does.
    fn routed_entry(root_url: &str) -> SessionConnection {
        SessionConnection {
            config: std::collections::HashMap::from([(
                "root_url".to_string(),
                toml::Value::String(root_url.to_string()),
            )]),
            ..session_entry(None)
        }
    }

    /// `plugin-http`'s config shape, far enough to make `root_url` a `Url`
    /// field.
    fn http_like_descriptor() -> StorageBackendKindDescriptor {
        StorageBackendKindDescriptor {
            kind: "http".to_string(),
            display_name: "HTTP".to_string(),
            description: None,
            config_schema: vec![ovstorage::ConfigField {
                key: "root_url".to_string(),
                display_name: "Root URL".to_string(),
                kind: ovstorage::ConfigFieldKind::Url,
                required: true,
                default: None,
                help: None,
                example: None,
                group: None,
                advanced: false,
            }],
            credential_schema: Vec::new(),
            credential_methods: Vec::new(),
            icon: None,
            supports_runtime_add: true,
            // What `plugin-http` declares, which is what this stands in for.
            supports_user_metadata: false,
        }
    }
}
