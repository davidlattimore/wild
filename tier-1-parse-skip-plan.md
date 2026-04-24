# Tier-1 parse-skip: integration plan

*Authored 2026-04-24. Picks up where `01f2236` + `f900907` leave off:
the storage layer (`libwild/src/parsed_input_cache.rs`) is ready,
nothing consumes it yet. This doc is the next session's spec.*

## What's landed

- Zero-copy on-disk format (`repr(C)` header + symbol array + names
  blob), mmap-compatible, schema v1.
- `CacheView<'data>` reader + `CacheBuilder` writer with
  name-dedup.
- `CacheBuilder::write_to(&Path)` (atomic tmp-and-rename).
- `cache_path_for_input(&Path)` — `$XDG_CACHE_HOME/wild/parsed-inputs/<blake3>.wildpi`.
- 12 unit tests: round-trip, name-dedup, bad-magic/schema, truncated,
  misaligned, unknown-kind, empty, zero-copy assertion, atomic write,
  path collision-freeness.

## What ships tier-1

A `load_symbols` fast path that, for an input whose fingerprint is
clean, replays a cached symbol stream instead of iterating the
object crate. Measured target on bevy-dylib: −50 to −150 ms off the
370 ms cold link when the dev-loop touched only a few crates.

## The refactor

### `SymbolSink` trait

`libwild/src/symbol_db.rs` currently writes parsed symbols into two
places in `load_symbols_from_file`:

```rust
outputs.add_non_versioned(pending);
outputs.add_versioned(pending);
symbols_out.set_next(flags, resolution, file_id);
```

Extract a trait:

```rust
trait SymbolSink<'data> {
    fn set_next(&mut self, flags: ValueFlags, resolution: SymbolId, file_id: FileId);
    fn add_non_versioned(&mut self, p: PendingSymbol<'data>);
    fn add_versioned(&mut self, p: PendingVersionedSymbol<'data>);
}
```

Existing code becomes the default `SymbolSink` impl on the pair
`(&mut SymbolWriterShard, &mut SymbolLoadOutputs)`.

### Teeing impl

```rust
struct TeeSink<'a, 'data, S: SymbolSink<'data>> {
    inner: S,
    cache: Option<&'a mut CacheBuilder>,
}
```

When `cache: Some(b)`, every `set_next` / `add_*` duplicates into `b`.
This captures the exact symbol stream — no schema drift, no
replicated flag-computation logic.

### Cache-replay path

Add to `load_symbols_from_file` (before dispatching to
`RegularObjectSymbolLoader`/`DynamicObjectSymbolLoader`):

```rust
if let Some(cache_bytes) = try_load_cache(s.parsed.input.path()) {
    if let Some(view) = CacheView::from_bytes(&cache_bytes) {
        return replay_cached_symbols(view, s.file_id, sink);
    }
}
```

`replay_cached_symbols` iterates `CachedEntry` → `SymbolSink::add_*`.

### Gate

Under `WILD_INCREMENTAL_DEBUG=1`:

- Write path: `TeeSink` wraps the default sink, `CacheBuilder`
  captures the parse output, `write_to(cache_path_for_input(input))`
  at end.
- Read path: only consume a cache file when the `.wild-hashes`
  side-car reports the input clean. Otherwise fall through to
  re-parse (and refresh the cache from that parse).

Default off until the canary below is green for a session.

## The canary

Before flipping `WILD_INCREMENTAL_DEBUG` default, a second env var
`WILD_INCREMENTAL_PARSE_SKIP_CANARY=1` runs BOTH paths per input:

1. Parse via object crate into a scratch `SymbolWriterShard +
   SymbolLoadOutputs`.
2. If a cache exists, replay into a second scratch pair.
3. Compare structurally — same symbol count per bucket, same
   `(name, hash, flags, kind, resolution)` in insertion order.
4. Panic with a clear diff on mismatch.

Ship once a bevy-dylib + rust-analyzer + ripgrep run under
`CANARY=1` is clean across 3 consecutive sessions.

## Lifetime contract

`CachedEntry<'data>` borrows from the cache mmap. Pushing into
`pending_symbols_by_bucket` is fine — those structs hold
`UnversionedSymbolName<'data>` which accepts any `&[u8]`
with the link's 'data lifetime. The cache mmap needs to live at
least as long as the rest of the input mmaps.

Plumb the cache mmap through `FileLoader` alongside the input
mmap (same arena, same lifetime) so Rust's borrow checker sees
them as equivalent.

## File layout the next session touches

- `libwild/src/symbol_db.rs` — trait extraction + teeing sink.
- `libwild/src/platform.rs` — default sink impl on the pair.
- `libwild/src/input_data.rs` — mmap-hold for cache files.
- `libwild/src/lib.rs` — gate, canary wiring.
- `libwild/src/parsed_input_cache.rs` — maybe extend with
  `try_load_cache(&Path) -> Option<Mmap>`.
- `libwild/tests/incremental_parse_skip.rs` (new) — canary
  integration test.

## Measurement script

```sh
export WILD_INCREMENTAL_DEBUG=1
# First link: writes caches.
time /tmp/wild-saves-macho/bevy-dylib/run-with $WILD
ls ~/.cache/wild/parsed-inputs/ | wc -l   # should match input count
# Second link: consumes caches.
time /tmp/wild-saves-macho/bevy-dylib/run-with $WILD
# Target: ≥100 ms shaved from the 370 ms cold.
```

## Risks the canary should catch

1. Symbol-version metadata lost (weak version string).
2. COMDAT group selector lost.
3. `N_ARM_THUMB_DEF` / `N_NO_DEAD_STRIP` bits lost.
4. TLS flags lost.
5. Hidden/protected visibility lost (Mach-O N_PEXT).
6. Local symbol ordering changed (some callers rely on order).

Any of these is a subtle miscompile. The canary runs BOTH loaders
and compares, so a divergence panics the link rather than shipping
a bad binary.

## After tier-1

- Tier 2 (sticky layout) is the next beat — persist section
  offsets + symbol addresses, reuse for clean-input subsets.
- Tier 3 (per-section memcpy skip) builds on tier-1's clean-input
  bit to skip content-addressed sections like `__cstring`.
- Both need tier 1's per-input clean/dirty verdict to mean what
  this module says it means. Ship that foundation first.
