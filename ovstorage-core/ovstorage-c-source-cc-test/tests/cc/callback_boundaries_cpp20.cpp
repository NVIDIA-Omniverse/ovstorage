// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Allocation-failure coverage for the C-callback boundaries in the shipped
// C++ wrapper `ovstorage.hpp`.
//
// Every `on_complete`/`on_chunk` thunk in the header is invoked by a C frame
// (the runtime's dispatch and stream pumps). Allocation inside one is
// therefore a hazard the wrapper owns, and the only allocating statements in
// those thunks are `Error(const OvStorage_Error&)`'s copy of the C error
// message and `read_stream_awaiter::on_chunk`'s accumulate.
//
// `std::bad_alloc` is driven deterministically here rather than assumed
// undrivable: a replacement global `operator new` throws once for a single
// magic allocation size. The sizes below assume a standard library that
// allocates exactly `len + 1` for a `std::string` copy of a `len >= 16` C
// string and exactly `n` for a range insert of `n` bytes into an empty
// `std::vector` — true of libstdc++, and NOT a property this file may assume
// of a library it has not met.
//
// So the arming is self-verifying rather than enumerated against known-good
// toolchains: the trap is one-shot and counts its firings, and every case that
// arms asserts its own trap fired. A library whose sizes differ fails loudly
// with "the injection never fired" instead of passing while proving nothing.
// That failure is the point — this file is about tests that would pass with
// the defect present, so it must not be one.
//
// Its own process, because two of the failure modes are process-wide: a
// boundary that swallows without resuming its coroutine HANGS, and a boundary
// that lets the exception escape a `noexcept` thunk calls `std::terminate`.
// The launching Rust test bounds the run; every wait inside it is bounded too.
//
// No sanitizers: the leak assertion interposes `free`, which conflicts with
// ASan's own allocator interception. The assertion is exact rather than
// heuristic, so it needs no leak checker.

#include "ovstorage.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <new>
#include <thread>
#include <utility>
#include <vector>

namespace {

// ---------------------------------------------------------------------------
// One-shot allocation-failure injection.
// ---------------------------------------------------------------------------

constexpr std::size_t kDisarmed = static_cast<std::size_t>(-1);

std::atomic<std::size_t> g_armed_size{kDisarmed};
std::atomic<long> g_trap_fired{0};
std::atomic<long> g_allocations{0};

long trap_fired() { return g_trap_fired.load(std::memory_order_relaxed); }
long allocations() { return g_allocations.load(std::memory_order_relaxed); }

// Arming is a claim: "the next allocation of exactly this size is the one this
// case is about." A case that arms and never asks whether the trap FIRED
// passes whether or not the failing path was reached, so the arming and the
// question are one protocol here rather than two things a case is trusted to
// remember.
//
// `arm` opens an arming and `expect_trap_fired` is the only thing that closes
// it. Opening a second one over an open one, or reaching the end of the
// program with one still open, is a hard failure `main` reports -- so a
// fourteenth boundary that arms without checking fails loudly on its first
// run instead of passing silently.
//
// The pair cannot be a scope guard: the arming happens on the callback thread
// (inside the `fire_*` thunks, as late as possible so no incidental
// allocation of the armed size can consume the one-shot trap) while the
// question is asked on the driving thread once the operation has resolved.
// The protocol spans those two threads, which no single scope does.
const char* const kNoArming = nullptr;
std::atomic<const char*> g_open_arming{kNoArming};
std::atomic<long> g_arming_baseline{0};
std::atomic<bool> g_arming_protocol_violated{false};

void arm(std::size_t size, const char* site)
{
    const char* previous = g_open_arming.exchange(site, std::memory_order_relaxed);
    if (previous != kNoArming) {
        std::fprintf(stderr,
                     "%s armed the allocation trap while %s's arming was "
                     "still unchecked: an arming that is never checked proves "
                     "nothing about the failing path\n",
                     site, previous);
        g_arming_protocol_violated.store(true, std::memory_order_relaxed);
    }
    g_arming_baseline.store(trap_fired(), std::memory_order_relaxed);
    g_armed_size.store(size, std::memory_order_relaxed);
}

// Closes the arming opened by `arm`, disarming first so a later allocation of
// the armed size cannot consume the trap. Returns whether the injection fired
// exactly once, reporting the standard diagnostic when it did not.
bool expect_trap_fired(const char* site)
{
    g_armed_size.store(kDisarmed, std::memory_order_relaxed);
    const char* open = g_open_arming.exchange(kNoArming, std::memory_order_relaxed);
    if (open == kNoArming) {
        std::fprintf(stderr,
                     "%s asked whether the allocation trap fired without "
                     "having armed it\n",
                     site);
        g_arming_protocol_violated.store(true, std::memory_order_relaxed);
        return false;
    }
    const long expected = g_arming_baseline.load(std::memory_order_relaxed) + 1;
    if (trap_fired() != expected) {
        std::fprintf(stderr,
                     "%s: the allocation-failure injection never fired, so the "
                     "failing path was not driven and this case proves "
                     "nothing\n",
                     site);
        return false;
    }
    return true;
}

// Every arming must have been closed by the time the program ends.
bool arming_protocol_held()
{
    const char* open = g_open_arming.load(std::memory_order_relaxed);
    if (open != kNoArming) {
        std::fprintf(stderr,
                     "%s armed the allocation trap and never checked whether "
                     "it fired\n",
                     open);
        return false;
    }
    return !g_arming_protocol_violated.load(std::memory_order_relaxed);
}

// ---------------------------------------------------------------------------
// Exact leak observation: watch one heap block and record whether it is freed.
// ---------------------------------------------------------------------------

std::atomic<void*> g_watched{nullptr};
std::atomic<std::size_t> g_watched_size{0};
std::atomic<bool> g_watched_freed{false};

// Poison written over the watched block as it is released, so that reading it
// afterwards yields deterministically wrong bytes. Without this, a
// free-before-copy defect is invisible: glibc frequently leaves a just-freed
// block's contents intact (a 4 KiB block adjacent to the top chunk is
// consolidated without writing bin pointers into it), so the copy reads the
// right bytes out of freed memory and the test passes. This driver cannot use
// AddressSanitizer — it interposes `free` — so it poisons its own block.
constexpr unsigned char kFreedPoison = 0xdd;

void watch(void* pointer, std::size_t size)
{
    g_watched_freed.store(false, std::memory_order_relaxed);
    g_watched_size.store(size, std::memory_order_relaxed);
    g_watched.store(pointer, std::memory_order_relaxed);
}

bool watched_was_freed() { return g_watched_freed.load(std::memory_order_relaxed); }

} // namespace

// A replacement global `operator new`, so the injection is thread-agnostic and
// has no arming window a worker thread could race: the callback fires on a
// thread whose identity cannot be known in advance.
void* operator new(std::size_t size)
{
    g_allocations.fetch_add(1, std::memory_order_relaxed);
    std::size_t armed = g_armed_size.load(std::memory_order_relaxed);
    if (size == armed &&
        g_armed_size.compare_exchange_strong(armed, kDisarmed,
                                             std::memory_order_relaxed)) {
        g_trap_fired.fetch_add(1, std::memory_order_relaxed);
        throw std::bad_alloc();
    }
    void* allocated = std::malloc(size == 0 ? 1 : size);
    if (allocated == nullptr) {
        throw std::bad_alloc();
    }
    return allocated;
}

void operator delete(void* pointer) noexcept { std::free(pointer); }
void operator delete(void* pointer, std::size_t) noexcept { std::free(pointer); }

// Interposing `free` is what makes "the chunk buffer was released" an exact
// observation rather than a leak-checker heuristic. `ovstorage_bytes_destroy`
// releases an `OvStorage_Bytes` by calling `free(free_ctx)`, and this driver
// owns the block it hands in, so watching that one pointer answers the
// question directly.
extern "C" void __libc_free(void* pointer);

extern "C" void free(void* pointer) noexcept
{
    // One-shot: the watch is CLAIMED before poisoning, so a later allocation
    // that happens to reuse this address is not poisoned with the previous
    // block's (possibly larger) size — which corrupts the heap.
    if (pointer != nullptr &&
        g_watched.load(std::memory_order_relaxed) == pointer) {
        void* claimed = pointer;
        if (g_watched.compare_exchange_strong(claimed, nullptr,
                                              std::memory_order_relaxed)) {
            std::memset(pointer, kFreedPoison,
                        g_watched_size.load(std::memory_order_relaxed));
            g_watched_freed.store(true, std::memory_order_relaxed);
        }
    }
    __libc_free(pointer);
}

namespace {

// A chunk length distinctive enough that arming it traps the accumulate and
// nothing else in this program.
constexpr std::size_t kChunkLength = 4099;
constexpr unsigned char kChunkFill = 0x5a;

// Drive `read_stream_awaiter::on_chunk`'s accumulate branch with an allocation
// failure, and pin that the C-owned chunk buffer is released anyway.
//
// The thunk is called directly rather than through a coroutine: the branch
// under test neither reclaims the state nor resumes anything, so a direct call
// is the whole of it. The terminal fire afterwards reclaims the leaked state
// reference and settles the outcome.
bool a_failed_accumulate_still_releases_the_chunk()
{
    ovstorage::detail::read_stream_awaiter awaiter;
    void* user_data = awaiter.release_user_data();

    auto* buffer = static_cast<std::uint8_t*>(std::malloc(kChunkLength));
    if (buffer == nullptr) {
        std::fprintf(stderr, "failed to allocate the fixture chunk\n");
        return false;
    }
    std::memset(buffer, kChunkFill, kChunkLength);
    watch(buffer, kChunkLength);

    OvStorage_Bytes chunk{};
    chunk.data = buffer;
    chunk.len = kChunkLength;
    chunk.free_ctx = buffer;

    arm(kChunkLength, "the chunk accumulate");
    // No try/catch: `on_chunk` is `noexcept`, so an escaping exception would
    // abort this process rather than reach a handler here.
    ovstorage::detail::read_stream_awaiter::on_chunk(chunk, nullptr, false,
                                                     user_data);

    bool ok = true;
    if (!expect_trap_fired("the chunk accumulate")) {
        ok = false;
    } else if (!watched_was_freed()) {
        std::fprintf(stderr,
                     "the chunk buffer was NOT released when the accumulate "
                     "failed: `ovstorage_bytes_destroy` is sequenced after a "
                     "statement that can throw\n");
        ok = false;
    }

    // Reclaim the leaked state reference and settle the awaiter, whether or
    // not the assertions above held.
    ovstorage::detail::read_stream_awaiter::on_chunk(OvStorage_Bytes{}, nullptr,
                                                    true, user_data);
    auto outcome = awaiter.await_resume();
    if (ok && outcome) {
        std::fprintf(stderr,
                     "a stream that lost a chunk to an allocation failure "
                     "resolved as a SUCCESS carrying %zu of %zu bytes\n",
                     outcome.value().size(), kChunkLength);
        ok = false;
    }
    return ok;
}

// The same path with no injection: the chunk is accumulated AND released, and
// the stream resolves successfully. Without this, a boundary that released the
// chunk by never accumulating it would pass the assertion above.
bool a_successful_accumulate_releases_the_chunk_and_keeps_the_bytes()
{
    ovstorage::detail::read_stream_awaiter awaiter;
    void* user_data = awaiter.release_user_data();

    auto* buffer = static_cast<std::uint8_t*>(std::malloc(kChunkLength));
    if (buffer == nullptr) {
        std::fprintf(stderr, "failed to allocate the fixture chunk\n");
        return false;
    }
    std::memset(buffer, kChunkFill, kChunkLength);
    watch(buffer, kChunkLength);

    OvStorage_Bytes chunk{};
    chunk.data = buffer;
    chunk.len = kChunkLength;
    chunk.free_ctx = buffer;

    ovstorage::detail::read_stream_awaiter::on_chunk(chunk, nullptr, false,
                                                    user_data);
    const bool freed = watched_was_freed();
    ovstorage::detail::read_stream_awaiter::on_chunk(OvStorage_Bytes{}, nullptr,
                                                    true, user_data);

    if (!freed) {
        std::fprintf(stderr,
                     "the chunk buffer was not released on the ordinary "
                     "accumulate path\n");
        return false;
    }
    auto outcome = awaiter.await_resume();
    if (!outcome) {
        std::fprintf(stderr,
                     "an uneventful stream resolved as a failure (status %d)\n",
                     static_cast<int>(outcome.error().code()));
        return false;
    }
    if (outcome.value().size() != kChunkLength) {
        std::fprintf(stderr,
                     "the stream accumulated %zu bytes, want %zu\n",
                     outcome.value().size(), kChunkLength);
        return false;
    }
    // The CONTENT, not just the length: releasing the chunk before copying out
    // of it is exactly the ordering this file exists to guard against, and it
    // yields a buffer of the right length holding whatever the allocator left
    // behind.
    for (std::size_t index = 0; index < kChunkLength; ++index) {
        if (outcome.value()[index] != std::byte{kChunkFill}) {
            std::fprintf(stderr,
                         "the stream accumulated the right LENGTH but wrong "
                         "content: byte %zu is 0x%02x, want 0x%02x — the chunk "
                         "was read after it was released\n",
                         index,
                         static_cast<unsigned>(outcome.value()[index]),
                         static_cast<unsigned>(kChunkFill));
            return false;
        }
    }
    return true;
}

// ---------------------------------------------------------------------------
// The error branch of every C-callback boundary, driven through a real
// coroutine with a failing allocation.
// ---------------------------------------------------------------------------

// `Error(const OvStorage_Error&)` copies the message into a `std::string`, and
// libstdc++ allocates exactly `len + 1` for a `len >= 16` C string. A length
// this distinctive means arming `len + 1` traps that copy and nothing else.
constexpr std::size_t kErrorMessageLength = 1237;
constexpr std::size_t kErrorMessageAllocation = kErrorMessageLength + 1;

struct MagicMessage {
    char storage[kErrorMessageLength + 1];
    MagicMessage()
    {
        std::memset(storage, 'x', kErrorMessageLength);
        storage[kErrorMessageLength] = '\0';
    }
};

OvStorage_Error magic_error()
{
    static MagicMessage message;
    OvStorage_Error error{};
    error.code = OvStorage_Status_Internal;
    error.message = message.storage;
    error.code_name = nullptr;
    return error;
}

// Holds the simulated C callback until the coroutine has actually suspended,
// so every boundary is exercised on `deliver`'s resume path rather than on
// whichever interleaving the scheduler happened to pick.
struct Gate {
    std::mutex mutex;
    std::condition_variable ready;
    bool opened = false;

    void wait()
    {
        std::unique_lock<std::mutex> lock(mutex);
        ready.wait(lock, [this] { return opened; });
    }
    void open()
    {
        {
            std::lock_guard<std::mutex> lock(mutex);
            opened = true;
        }
        ready.notify_all();
    }
};

// Simulated callback threads still running. A wedged one never decrements, so
// the bounded drain in `main` reports it instead of racing process exit.
std::atomic<int> g_workers{0};

// Stands in for a per-method awaiter (`LayerHandle::stat`'s `op`, ...). It
// reuses the real plumbing — the typed body handle, the leaked `user_data`
// ref, `commit_suspend` — and calls the real thunk from another thread, which
// is what the C runtime does.
template <class Awaiter>
struct fired_op : Awaiter {
    void (*fire)(void*) = nullptr;

    bool await_suspend(typename Awaiter::body_handle body)
    {
        this->s->continuation = body;
        void* user_data = this->release_user_data();
        auto gate = std::make_shared<Gate>();
        void (*thunk)(void*) = fire;
        g_workers.fetch_add(1, std::memory_order_relaxed);
        std::thread([user_data, gate, thunk] {
            gate->wait();
            thunk(user_data);
            g_workers.fetch_sub(1, std::memory_order_relaxed);
        }).detach();
        const bool suspended = this->commit_suspend(body);
        // `gate` is a local, not a member: safe to touch now that the frame
        // holding `*this` may be resumed.
        gate->open();
        return suspended;
    }
};

template <class Awaiter, class Out>
ovstorage::task<Out> drive(void (*fire)(void*))
{
    fired_op<Awaiter> op{};
    op.fire = fire;
    co_return co_await op;
}

// Shared-owned, and notified UNDER the lock, for the reason
// `detail::sync_wait_state` in the header gives: `wait_for` re-checks its
// predicate before blocking, so the waiter can return the instant `done` is
// published. A waiter that then destroyed these primitives would tear them
// down while the producer is still inside them — and on the timeout path the
// producer is still running by definition. Shared ownership keeps them alive
// until both sides are done with them.
struct Rendezvous {
    std::mutex mutex;
    std::condition_variable settled;
    bool done = false;
    bool ok = false;

    void finish(bool value)
    {
        std::lock_guard<std::mutex> lock(mutex);
        ok = value;
        done = true;
        settled.notify_all();
    }
    bool wait_for(std::chrono::seconds limit, bool& out)
    {
        std::unique_lock<std::mutex> lock(mutex);
        if (!settled.wait_for(lock, limit, [this] { return done; })) {
            return false;
        }
        out = ok;
        return true;
    }
};

// Run `body` on its own thread under a bound, because the failure mode of a
// boundary that consumes its state without delivering is an unbounded block
// inside `sync_wait`. An unbounded wait here would look identical to a healthy
// run right up until the CI job timed out.
template <class Body>
bool run_bounded(const char* label, Body body)
{
    auto rendezvous = std::make_shared<Rendezvous>();
    std::thread([rendezvous, body] { rendezvous->finish(body()); }).detach();
    bool ok = false;
    if (!rendezvous->wait_for(std::chrono::seconds(30), ok)) {
        std::fprintf(stderr,
                     "%s: TIMED OUT after 30s — the boundary reclaimed its "
                     "awaiter state and returned without calling deliver(), so "
                     "the awaiting coroutine is never resumed and its caller "
                     "blocks forever\n",
                     label);
        return false;
    }
    return ok;
}

// `verify`, when set, runs on the driving thread after the operation has
// resolved — so a boundary that was handed a payload to release can be asked
// whether it released it.
template <class Awaiter, class Out>
bool boundary_reports_the_failure(const char* label, void (*fire)(void*),
                                  bool (*verify)(const char*) = nullptr)
{
    return run_bounded(label, [label, fire, verify] {
        auto outcome = ovstorage::sync_wait(drive<Awaiter, Out>(fire));
        // Closed here rather than on the callback thread: the thunk is what
        // releases this thread, so a disarm placed after it there could land
        // after the NEXT case has armed.
        if (!expect_trap_fired(label)) {
            return false;
        }
        if (outcome) {
            std::fprintf(stderr,
                         "%s: an allocation failure while marshaling the error "
                         "resolved as a SUCCESS\n",
                         label);
            return false;
        }
        // A failed `Result` whose status says `Ok` tells the caller nothing.
        if (outcome.error().code() != OvStorage_Status_Internal ||
            outcome.error().message().empty()) {
            std::fprintf(stderr,
                         "%s: the failure the caller receives does not name "
                         "itself: status %d \"%s\"\n",
                         label, static_cast<int>(outcome.error().code()),
                         outcome.error().message().c_str());
            return false;
        }
        if (verify != nullptr && !verify(label)) {
            return false;
        }
        return true;
    });
}

// The arming is closed at the case boundary (above), not here: see the
// comment there. The trap is one-shot in `operator new` anyway, so the common
// path disarms itself the moment it fires.
#define OVSTORAGE_FIRE(name, awaiter, call)                                  \
    void name(void* user_data)                                               \
    {                                                                        \
        OvStorage_Error error = magic_error();                               \
        arm(kErrorMessageAllocation, #awaiter);                              \
        ovstorage::detail::awaiter::call;                                     \
    }

OVSTORAGE_FIRE(fire_status, status_awaiter,
               on_complete(OvStorage_Status_Internal, &error, user_data))
OVSTORAGE_FIRE(fire_info, info_awaiter,
               on_complete(OvStorage_Status_Internal, nullptr, &error,
                           user_data))
OVSTORAGE_FIRE(fire_local_delegate, local_delegate_awaiter,
               on_complete(OvStorage_Status_Internal, nullptr, &error,
                           user_data))
OVSTORAGE_FIRE(fire_list, list_awaiter,
               on_complete(OvStorage_Status_Internal, nullptr, &error,
                           user_data))
OVSTORAGE_FIRE(fire_list_versions, list_versions_awaiter,
               on_complete(OvStorage_Status_Internal, nullptr, &error,
                           user_data))
OVSTORAGE_FIRE(fire_read_stream, read_stream_awaiter,
               on_chunk(OvStorage_Bytes{}, &error, false, user_data))
OVSTORAGE_FIRE(fire_connection, connection_awaiter,
               on_complete(OvStorage_Status_Internal, nullptr, &error,
                           user_data))
OVSTORAGE_FIRE(fire_connection_list, connection_list_awaiter,
               on_complete(OvStorage_Status_Internal, nullptr, &error,
                           user_data))
OVSTORAGE_FIRE(fire_root_info_list, root_info_list_awaiter,
               on_complete(OvStorage_Status_Internal, nullptr, &error,
                           user_data))
OVSTORAGE_FIRE(fire_stack_build, stack_build_awaiter,
               on_complete(OvStorage_Status_Internal, nullptr, &error,
                           user_data))
// `on_event` only reaches its terminal on the `done` fire, unlike `on_chunk`,
// whose error branch falls through to the terminal whatever `done` says.
OVSTORAGE_FIRE(fire_auth_event_drain, auth_event_drain_awaiter,
               on_event(nullptr, &error, true, user_data))

#undef OVSTORAGE_FIRE

// Two boundaries are handed a callback-owned payload alongside the error, and
// release it before the copy that can throw. Handing them an EMPTY payload
// would exercise nothing — `ovstorage_bytes_destroy(nullptr)` and
// `ovstorage_access_decision_clear` with a null `reason` are both no-ops — so
// deleting that release would leak a real allocation and the case would still
// pass. These two hand in a watched block and assert it was released.

constexpr std::size_t kPayloadLength = 8191;

void* watched_payload()
{
    void* block = std::malloc(kPayloadLength);
    if (block != nullptr) {
        std::memset(block, 0, kPayloadLength);
        watch(block, kPayloadLength);
    }
    return block;
}

bool payload_was_released(const char* label)
{
    if (!watched_was_freed()) {
        std::fprintf(stderr,
                     "%s: the callback-owned payload delivered alongside the "
                     "error was NOT released\n",
                     label);
        return false;
    }
    return true;
}

void fire_read_bytes(void* user_data)
{
    OvStorage_Error error = magic_error();
    OvStorage_Bytes bytes{};
    bytes.data = static_cast<const std::uint8_t*>(watched_payload());
    bytes.len = kPayloadLength;
    bytes.free_ctx = const_cast<std::uint8_t*>(bytes.data);
    arm(kErrorMessageAllocation, "read_bytes_awaiter");
    ovstorage::detail::read_bytes_awaiter::on_complete(
        OvStorage_Status_Internal, bytes, nullptr, &error, user_data);
}

void fire_check_access(void* user_data)
{
    OvStorage_Error error = magic_error();
    OvStorage_AccessDecision decision{};
    // `ovstorage_access_decision_clear` frees `reason`, so that is the
    // callback-owned allocation to watch.
    decision.reason = static_cast<char*>(watched_payload());
    arm(kErrorMessageAllocation, "check_access_awaiter");
    ovstorage::detail::check_access_awaiter::on_complete(
        OvStorage_Status_Internal, decision, &error, user_data);
}

// The full boundary checklist. A partial sweep is indistinguishable from a
// complete one in a diff, so the list is the artifact: one entry per
// C-callback thunk in `ovstorage.hpp`, each driven through a real coroutine.
bool every_boundary_reports_an_allocation_failure()
{
    using namespace ovstorage;
    using namespace ovstorage::detail;

    bool ok = true;
    ok &= boundary_reports_the_failure<status_awaiter, void>(
        "status_awaiter::on_complete", fire_status);
    ok &= boundary_reports_the_failure<info_awaiter, Info>(
        "info_awaiter::on_complete", fire_info);
    ok &= boundary_reports_the_failure<read_bytes_awaiter,
                                       std::pair<Bytes, Info>>(
        "read_bytes_awaiter::on_complete", fire_read_bytes,
        payload_was_released);
    ok &= boundary_reports_the_failure<local_delegate_awaiter, LocalDelegate>(
        "local_delegate_awaiter::on_complete", fire_local_delegate);
    ok &= boundary_reports_the_failure<list_awaiter, List>(
        "list_awaiter::on_complete", fire_list);
    ok &= boundary_reports_the_failure<list_versions_awaiter, VersionList>(
        "list_versions_awaiter::on_complete", fire_list_versions);
    ok &= boundary_reports_the_failure<check_access_awaiter, AccessDecision>(
        "check_access_awaiter::on_complete", fire_check_access,
        payload_was_released);
    ok &= boundary_reports_the_failure<read_stream_awaiter,
                                       std::vector<std::byte>>(
        "read_stream_awaiter::on_chunk (error branch)", fire_read_stream);
    ok &= boundary_reports_the_failure<connection_awaiter, Connection>(
        "connection_awaiter::on_complete", fire_connection);
    ok &= boundary_reports_the_failure<connection_list_awaiter, ConnectionList>(
        "connection_list_awaiter::on_complete", fire_connection_list);
    ok &= boundary_reports_the_failure<root_info_list_awaiter, RootInfoList>(
        "root_info_list_awaiter::on_complete", fire_root_info_list);
    ok &= boundary_reports_the_failure<stack_build_awaiter, LayerHandle>(
        "stack_build_awaiter::on_complete", fire_stack_build);
    ok &= boundary_reports_the_failure<auth_event_drain_awaiter,
                                       std::vector<AuthEvent>>(
        "auth_event_drain_awaiter::on_event", fire_auth_event_drain);
    return ok;
}

// The seed every boundary falls back to when marshaling the real error ran out
// of memory. Two things have to hold, and neither is self-evident: it must name
// the failure (a failed `Result` reporting status `Ok` tells the caller
// nothing), and building it must not itself allocate — it is the value reached
// precisely when allocation is what failed.
template <class Out>
bool seed_names_itself_without_allocating(const char* label)
{
    const long before = allocations();
    ovstorage::detail::awaiter_state<Out> state;
    const long spent = allocations() - before;

    if (spent != 0) {
        std::fprintf(stderr,
                     "%s: seeding the fallback failure performed %ld "
                     "allocation(s); it is the value used when allocation "
                     "failed, so it must perform none\n",
                     label, spent);
        return false;
    }
    if (state.outcome) {
        std::fprintf(stderr, "%s: the seeded outcome is a SUCCESS\n", label);
        return false;
    }
    if (state.outcome.error().code() != OvStorage_Status_Internal ||
        state.outcome.error().message().empty()) {
        std::fprintf(stderr,
                     "%s: the seeded failure does not name itself: status %d "
                     "\"%s\"\n",
                     label, static_cast<int>(state.outcome.error().code()),
                     state.outcome.error().message().c_str());
        return false;
    }
    return true;
}

bool the_seeded_failure_names_itself_without_allocating()
{
    return seed_names_itself_without_allocating<void>("awaiter_state<void>") &&
        seed_names_itself_without_allocating<ovstorage::Info>(
            "awaiter_state<Info>") &&
        seed_names_itself_without_allocating<std::vector<std::byte>>(
            "awaiter_state<vector<byte>>");
}

struct Case {
    const char* name;
    bool (*run)();
};

constexpr Case kCases[] = {
    {"the_seeded_failure_names_itself_without_allocating",
     the_seeded_failure_names_itself_without_allocating},
    {"a_failed_accumulate_still_releases_the_chunk",
     a_failed_accumulate_still_releases_the_chunk},
    {"a_successful_accumulate_releases_the_chunk_and_keeps_the_bytes",
     a_successful_accumulate_releases_the_chunk_and_keeps_the_bytes},
    {"every_boundary_reports_an_allocation_failure",
     every_boundary_reports_an_allocation_failure},
};

// Bounded drain, so a simulated callback thread still inside a boundary is
// named here rather than racing process exit.
bool workers_quiesced()
{
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
    while (g_workers.load(std::memory_order_relaxed) != 0) {
        if (std::chrono::steady_clock::now() >= deadline) {
            std::fprintf(stderr,
                         "%d simulated callback thread(s) never returned from a "
                         "boundary after 30s\n",
                         g_workers.load(std::memory_order_relaxed));
            return false;
        }
        std::this_thread::yield();
    }
    return true;
}

} // namespace

int main()
{
    bool ok = true;
    for (const Case& entry : kCases) {
        if (entry.run()) {
            std::printf("%s: ok\n", entry.name);
        } else {
            std::fprintf(stderr, "%s: FAILED\n", entry.name);
            ok = false;
        }
    }
    ok = workers_quiesced() && ok;
    // An arming left open by any case above -- the silent pass this protocol
    // exists to make impossible -- fails the program even if every case
    // reported ok.
    ok = arming_protocol_held() && ok;
    return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
