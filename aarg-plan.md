# Mach-O Linker Flag Implementation Plan

Current state: `libwild/src/args/macho.rs` parses ~73 flags but silently ignores most of them.
Test state: `wild/tests/sold_macho_tests.rs` skips tests for many of these.

## Completed (wired to shared ELF infrastructure)

The `Strip` enum has been moved from `args/elf.rs` to the shared `args.rs` module.
These flags are now parsed and wired to the platform trait, reusing ELF backend infra:

- **`-S`** -- Sets `Strip::Debug`, wired to `should_strip_debug()` / `should_strip_all()`.
  Note: Mach-O writer doesn't yet emit stab debug symbols at all (even without -S),
  so the test still fails. Needs debug info pass-through first.
- **`-demangle`** -- Sets `common.demangle` (shared `CommonArgs` field).
- **`-export_dynamic`** -- Sets `export_dynamic` field, wired to
  `should_export_all_dynamic_symbols()`.
- **`-dead_strip`** -- Sets `gc_sections` field, wired to `should_gc_sections()`.
  Previously defaulted to true via trait; now opt-in (matching ld64 behaviour).
- **`-exported_symbols_list`** -- Stores path, wired to `export_list_path()` trait method.
  `ExportList::parse()` auto-detects Mach-O format (one symbol per line) vs ELF format
  (`{ sym; }` braces).
- **`-unexported_symbols_list`** -- Stores path, loaded into `SymbolDb::unexport_list`.
  New `unexport_list_path()` trait method added. Filtering not yet wired in layout.

## Completed (Mach-O specific)

- **`-compatibility_version` / `-current_version`** -- Parsed via `parse_macho_version()`,
  stored in `MachOArgs`, emitted in `LC_ID_DYLIB` (was hardcoded to 1.0.0).
- **`-bundle`** -- Sets `is_bundle` field. Writer emits `MH_BUNDLE` filetype, skips
  `LC_MAIN` (bundles have no entry point), keeps `LC_LOAD_DYLINKER`.
- **`-sectcreate`** -- File data now read and stored in `MachOArgs.sectcreate` (was
  discarding the file path). Writer integration deferred -- needs segment layout work.

## Prior art reference

| Linker | Repo / Path | Notes |
| ------ | ----------- | ----- |
| **lld** (LLVM) | `lld/MachO/` in llvm-project | Most complete reference. `Driver.cpp` (arg parsing), `MarkLive.cpp` (dead strip), `MapFile.cpp`, `SyntheticSections.cpp` |
| **sold** | `bluewhalesystems/sold` (archived) | Simpler/shorter. `macho/cmdline.cc`, `macho/dead-strip.cc` (~130 lines), `macho/mapfile.cc`, `macho/output-chunks.cc` |
| **mold** | `rui314/mold` | ELF-only, but `src/gc-sections.cc` and `src/mapfile.cc` show the algorithm patterns |
| **wild ELF** | `libwild/src/args/elf.rs`, `libwild/src/layout.rs` | Same codebase -- closest starting point for shared infrastructure |

## Tier 1 -- HIGH priority (blocks real-world macOS builds)

### 1.1 Framework support: `-framework`, `-F`, `-weak_framework`, `-needed_framework`

- `-F<path>` adds a framework search path (like `-L` for libraries)
- `-framework <name>` searches `<F-paths>/<name>.framework/<name>` (.tbd or dylib)
- `-weak_framework` emits `LC_LOAD_WEAK_DYLIB` (binary runs even if framework absent)
- `-needed_framework` forces `LC_LOAD_DYLIB` even if no symbols referenced

Implementation: extend `-l` search logic to also search framework bundles. Store
`-F` paths in `MachOArgs`. Emit appropriate load commands based on weak/needed modifier.

| Linker | Reference |
| ------ | --------- |
| lld | `Driver.cpp` ~line 1820 (framework resolution), `Options.td` (flag defs) |
| sold | `macho/cmdline.cc` ~line 466, `macho/input-files.cc` (framework file resolution) |
| wild ELF | No equivalent (ELF has no framework concept) |

### 1.2 Dead stripping: `-dead_strip`, `-subsections_via_symbols`

- `-dead_strip` removes unreachable code/data by tracing from entry + exports
- `-subsections_via_symbols` enables per-symbol granularity (set by compiler in object metadata)

Implementation: build a reachability graph from entry point and exported symbols.
Mark reachable atoms, discard the rest. Requires understanding of relocation references.
This is the single most impactful size optimization.

| Linker | Reference |
| ------ | --------- |
| lld | `MarkLive.cpp` (~265 lines). Worklist-based reachability, fixpoint iteration for live-support sections |
| sold | `macho/dead-strip.cc` (~130 lines). Mark-and-sweep with TBB parallelisation. Three phases: collect roots, mark via relocs, sweep |
| mold | `src/gc-sections.cc` (ELF equivalent, same algorithm pattern) |
| wild ELF | `layout.rs` ~line 3572 (section liveness check), `gc_stats.rs`. Already has `--gc-sections` **fully implemented** -- reachability from entry via `load_entry_point()` at line 2756. **Best starting point.** |

### 1.3 Symbol visibility: `-exported_symbols_list`, `-unexported_symbols_list`

- `-exported_symbols_list <file>` -- only listed symbols are exported
- `-unexported_symbols_list <file>` -- listed symbols are hidden

Implementation: parse the file (one symbol per line, supports wildcards). Apply filter
during symbol table emission. Mutually exclusive with each other.

| Linker | Reference |
| ------ | --------- |
| lld | `Driver.cpp` ~line 1970 (parsing), symbol table emission filters |
| sold | `macho/cmdline.cc` ~line 450 |
| wild ELF | `args/elf.rs` ~line 1253 (`--version-script`), `version_script.rs` (parser). Also `export_list` field and filtering in `elf.rs` ~line 1293. **Reuse the version-script glob/pattern matching infra.** |

### 1.4 Dylib versioning: `-compatibility_version`, `-current_version`

- Set in `LC_ID_DYLIB` load command. dyld checks compatibility version at load time.
- Already have `parse_macho_version()`. Just needs wiring into the output.

Implementation: store in `MachOArgs`, emit in `LC_ID_DYLIB`. Smallest Tier 1 item.

| Linker | Reference |
| ------ | --------- |
| lld | `Driver.cpp` (parsing), `SyntheticSections.cpp` (LC_ID_DYLIB emission) |
| sold | `macho/cmdline.cc`, `macho/output-chunks.cc` |
| wild ELF | No equivalent (ELF uses soname/DT_SONAME, no version pair) |

### 1.5 `-sectcreate <segname> <sectname> <file>`

- Embeds file contents as a section. Xcode uses this for `__TEXT,__info_plist`.

Implementation: read file, create section with given segment/section names and file content.
Already have `-add_empty_section` (line 296) as a template -- extend it with file content.

| Linker | Reference |
| ------ | --------- |
| lld | `Driver.cpp` ~line 2095 (parsing), `SyntheticSections.cpp` (OpaqueSection class) |
| sold | `macho/cmdline.cc` ~line 511, `macho/output-chunks.cc` |
| wild ELF | No direct equivalent, but `--section-start` (elf.rs ~line 1398) shows section creation pattern |

### 1.6 `-ObjC`

- Forces loading of all archive members containing ObjC class or category definitions.
- Without this, categories in static libraries silently break at runtime.

Implementation: scan archive members for ObjC metadata sections (`__objc_classlist`,
`__objc_catlist`). Force-load matching members.

| Linker | Reference |
| ------ | --------- |
| lld | `Driver.cpp` ~line 1647, `SyntheticSections.cpp` ~line 836 (ObjC stubs/image-info) |
| sold | `macho/cmdline.cc` ~line 393, `macho/input-files.cc` (archive member scanning) |
| wild ELF | `--whole-archive` (elf.rs ~line 995) is the blunt equivalent. `-ObjC` is selective -- needs section name matching on archive members. |

### 1.7 `-bundle` (output type)

- Produces `MH_BUNDLE` (loadable plugin for `dlopen`). Currently accepted but ignored.

Implementation: set `filetype` in mach header. Bundles have no `LC_MAIN` (like dylibs)
but are not dylibs (no `LC_ID_DYLIB`).

| Linker | Reference |
| ------ | --------- |
| lld | `Driver.cpp` ~line 128 (filetype selection) |
| sold | `macho/cmdline.cc` ~line 413 |
| wild ELF | No equivalent (ELF uses `ET_DYN` for both shared libs and PIE executables) |

### 1.8 `-S` (strip debug symbols)

- Omits STABS/DWARF debug symbol entries from the output.

Implementation: filter `N_STAB` entries from the symbol table, skip debug sections.

| Linker | Reference |
| ------ | --------- |
| lld | `Driver.cpp` ~line 1625 |
| sold | `macho/cmdline.cc` ~line 390 |
| wild ELF | `args/elf.rs` ~line 725 (`Strip` enum), `elf_writer.rs` lines 1487/3282/3621. **Fully implemented. Reuse the `Strip` enum and `should_strip_debug()` trait method from `platform.rs` ~line 1092.** |

### 1.9 `-arch` validation

- Currently consumed and ignored. Should validate it matches input object files.

Implementation: compare against object file cputype/cpusubtype. Error on mismatch.

| Linker | Reference |
| ------ | --------- |
| lld | `Driver.cpp` (validates arch early, errors on mismatch) |
| sold | `macho/cmdline.cc` (stores target arch, validates in input-files.cc) |
| wild ELF | No equivalent (ELF uses `e_machine` field checked during input parsing) |

## Tier 2 -- MEDIUM priority (common in production builds)

### 2.1 `-demangle`

- Demangle C++/Rust/Swift symbol names in error messages and diagnostics.
- Use the `rustc-demangle` and `cpp_demangle` crates (or `symbolic-demangle`).

| Linker | Reference |
| ------ | --------- |
| lld | Uses LLVM's `Demangle.h` throughout diagnostics |
| sold | `macho/cmdline.cc` ~line 430 |
| wild ELF | `args/elf.rs` ~line 857 (sets `common.demangle`). **Already parsed, plumbing may be partial.** |

### 2.2 `-headerpad <size>`, `-headerpad_max_install_names`

- Reserve extra space after load commands for `install_name_tool` to rewrite paths.
- `-headerpad_max_install_names` pads to `MAXPATHLEN` for all dylib paths.

| Linker | Reference |
| ------ | --------- |
| lld | `Driver.cpp` ~line 1618, `SyntheticSections.cpp` ~line 108 (padding calculation) |
| sold | `macho/cmdline.cc` ~line 439 |
| wild ELF | No equivalent |

### 2.3 `-dependency_info <file>`

- Write binary dependency-info file for Xcode incremental build tracking.
- Format: version byte, then records of (tag, null-terminated path).
- Xcode always passes this flag.

| Linker | Reference |
| ------ | --------- |
| lld | `Driver.cpp` (writes dep info at end of link) |
| sold | `macho/cmdline.cc` (accepted but ignored) |
| wild ELF | No equivalent |

### 2.4 `-map <file>`

- Write a link map showing address, size, and source for every symbol.

| Linker | Reference |
| ------ | --------- |
| lld | `MapFile.cpp` (dedicated file, ~200 lines: object list, sections table, symbols in address order, dead-stripped symbols) |
| sold | `macho/mapfile.cc` |
| mold | `src/mapfile.cc` (ELF equivalent, same structure) |
| wild ELF | **Not implemented** -- neither ELF nor Mach-O has a map writer yet |

### 2.5 `-order_file <file>`

- Reorder functions/data in output per the file. Used for startup/cache optimization.

| Linker | Reference |
| ------ | --------- |
| lld | `Driver.cpp` ~line 2045 (parsing + priority assignment to symbols) |
| sold | `macho/cmdline.cc` ~line 499 |
| wild ELF | No equivalent (ELF uses linker scripts for section ordering) |

### 2.6 `-no_compact_unwind`

- Omit `__unwind_info` section, relying on `.eh_frame` only.

| Linker | Reference |
| ------ | --------- |
| lld | `SyntheticSections.cpp` (conditional `__unwind_info` emission) |
| sold | `macho/output-chunks.cc` |
| wild ELF | No equivalent (ELF always uses `.eh_frame`) |

### 2.7 Prefix link modifiers: `-hidden-l`, `-needed-l`, `-reexport-l`, `-weak-l`

- Variations of `-l` with different binding semantics

| Linker | Reference |
| ------ | --------- |
| lld | `Driver.cpp` (each prefix sets a modifier on the library input, emits different LC_LOAD_* command) |
| sold | `macho/cmdline.cc` ~lines 444/492/528/557 |
| wild ELF | Partial: `--as-needed` / `--no-as-needed` (elf.rs ~line 1015) is similar to needed-l |

### 2.8 `-reexport_library`, `-weak_library`

- Full-path variants of the prefix link modifiers above.

| Linker | Reference |
| ------ | --------- |
| lld | `Driver.cpp` (same modifier system as prefix variants) |
| sold | `macho/cmdline.cc` |

### 2.9 `-undefined <treatment>`

- Control undefined symbol behavior: `error` (default), `warning`, `suppress`, `dynamic_lookup`.

| Linker | Reference |
| ------ | --------- |
| lld | `Driver.cpp` ~line 1935 |
| sold | `macho/cmdline.cc` ~line 547 |
| wild ELF | `--unresolved-symbols` (elf.rs) handles similar semantics |

### 2.10 `-U <symbol>` (dynamic lookup)

- Allow specific symbol to remain undefined (resolved at runtime via `dlsym`).

| Linker | Reference |
| ------ | --------- |
| lld | `Driver.cpp` (adds to `config->dynamicLookupSymbols` set, checked during undef error) |
| sold | `macho/cmdline.cc` |
| wild ELF | No direct equivalent |

### 2.11 `-pagezero_size <size>`

- Set `__PAGEZERO` segment size. Default 4GB on 64-bit.

| Linker | Reference |
| ------ | --------- |
| lld | `Driver.cpp` (stores in config), segment layout code checks it |
| sold | `macho/cmdline.cc` |
| wild ELF | No equivalent (ELF has no PAGEZERO concept) |

### 2.12 `-fixup_chains` / `-no_fixup_chains`

- Toggle between chained fixups (`LC_DYLD_CHAINED_FIXUPS`, macOS 12+) and classic
  `DYLD_INFO` relocations.

| Linker | Reference |
| ------ | --------- |
| lld | `Driver.cpp` ~line 1844, `SyntheticSections.cpp` ~line 354+783 (`ChainedFixupsSection` class) |
| sold | `macho/cmdline.cc` ~line 462 |
| wild ELF | No equivalent |

### 2.13 `-oso_prefix`, `-reproducible`

- `-oso_prefix <prefix>` strips prefix from OSO debug paths for reproducible builds.
- `-reproducible` zeroes timestamps and sorts structures for deterministic output.

| Linker | Reference |
| ------ | --------- |
| lld | `Driver.cpp` (both flags), applied in symbol table and timestamp emission |
| sold | `macho/cmdline.cc` |
| wild ELF | No direct equivalent, but wild's design is already deterministic by default |

### 2.14 `-export_dynamic`

- Preserve all global symbols in executable's symbol table (like ELF `--export-dynamic`).

| Linker | Reference |
| ------ | --------- |
| lld | `Driver.cpp` |
| sold | `macho/cmdline.cc` ~line 448 |
| wild ELF | `args/elf.rs` ~line 1052 (`export_all_dynamic_symbols`), `elf.rs` ~line 1309. **Fully implemented.** |

### 2.15 `-application_extension`

- Set `MH_APP_EXTENSION_SAFE` bit. Validates linked dylibs are extension-safe.

| Linker | Reference |
| ------ | --------- |
| lld | `Driver.cpp` (sets bit + validates linked dylibs) |
| sold | `macho/cmdline.cc` |
| wild ELF | No equivalent |

### 2.16 `-platform_version` platform validation

- Currently ignores the platform argument (assumes macOS). Should store it for
  iOS/watchOS/tvOS cross-compilation support.

| Linker | Reference |
| ------ | --------- |
| lld | `Driver.cpp` (full platform enum, affects min version checks and output format) |
| sold | `macho/cmdline.cc` |
| wild ELF | No equivalent |

### 2.17 `-dead_strip_dylibs`

- Omit `LC_LOAD_DYLIB` for dylibs whose symbols are never actually referenced.

| Linker | Reference |
| ------ | --------- |
| lld | `Driver.cpp` (tracks referenced dylibs, omits unreferenced from output) |
| sold | `macho/cmdline.cc` ~line 428 |
| wild ELF | `--as-needed` (elf.rs ~line 1015) is the exact ELF equivalent |

## Tier 3 -- LOW priority (niche / safe to keep ignoring)

| Flag | Notes |
| ---- | ----- |
| `-two_levelnamespace` | Already the default; ignoring is correct |
| `-flat_namespace` | Legacy mode, very few modern projects use it |
| `-umbrella`, `-allowable_client`, `-client_name` | Apple internal framework machinery |
| `-sub_library`, `-sub_umbrella` | Legacy umbrella mechanism |
| `-upward-l` | Circular dylib deps; Apple system library builds only |
| `-mark_dead_strippable_dylib` | Sets `MH_DEAD_STRIPPABLE_DYLIB` bit |
| `-no_deduplicate` | Disables ICF; safe to never deduplicate |
| `-no_objc_category_merging` | Category merging is an optimization |
| `-objc_abi_version` | Always 2 on 64-bit; informational only |
| `-no_implicit_dylibs` | Fine-grained dylib control |
| `-search_paths_first` / `-search_dylibs_first` | Search order; default is fine |
| `-multiply_defined` | Legacy symbol conflict control |
| `-bind_at_load` | Sets `MH_BINDATLOAD`; rarely used |
| `-pie` / `-no_pie` | Default is PIE; ignoring is fine |
| `-execute` / `-dynamic` | Default output mode; ignoring is correct |
| `-image_base` | Nearly never used with ASLR/PIE |
| `-alignment` | Manual section alignment override |
| `-add_ast_path` | Debugger integration for Swift/Clang ASTs |
| `-w` | Suppress warnings; cosmetic |
| `-Z` | Don't search default lib dirs; dev/testing |
| `-data_in_code_info` / `-function_starts` | Already enabled by default |
| `-lto_library`, `-mllvm`, `-object_path_lto` | Requires LTO support first |
| `-adhoc_codesign` | Already handled implicitly on arm64 |

## Known bugs blocking test passes (from `sold_macho_tests.rs`)

These are separate from flag support -- they're correctness issues:

- TLS descriptors and type mismatches
- cstring dedup/merging
- Duplicate/undefined symbol error formatting
- Indirect symbol table
- Init offsets and fixup chains interaction
- Literal section merging
- libunwind integration
- ObjC selector references
- Debug info pass-through
- `.tbd` parsing edge cases

## Suggested implementation sequence

Ordered by effort-to-value ratio, with the best reference source noted:

| Step | Flag(s) | Best reference |
| ---- | ------- | -------------- |
| 1 | `-compatibility_version` / `-current_version` | lld `SyntheticSections.cpp` |
| 2 | `-S` (strip debug) | **wild ELF** `Strip` enum + `should_strip_debug()` in `platform.rs` |
| 3 | `-sectcreate` | lld `SyntheticSections.cpp` (OpaqueSection), extend wild's `-add_empty_section` |
| 4 | `-F` / `-framework` / `-weak_framework` | lld `Driver.cpp`, sold `input-files.cc` |
| 5 | `-exported_symbols_list` / `-unexported_symbols_list` | **wild ELF** `version_script.rs` (pattern matching infra) |
| 6 | `-dead_strip` + `-subsections_via_symbols` | **wild ELF** `layout.rs` gc_sections (closest code), sold `dead-strip.cc` (simplest Mach-O specific) |
| 7 | `-bundle` | lld `Driver.cpp` (trivial filetype switch) |
| 8 | `-ObjC` | sold `input-files.cc` (archive member scanning) |
| 9 | `-headerpad` / `-headerpad_max_install_names` | lld `SyntheticSections.cpp` |
| 10 | `-demangle` | **wild ELF** `common.demangle` (already plumbed) |
