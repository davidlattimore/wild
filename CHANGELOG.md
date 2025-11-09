## 0.7.0

### 🚀 Features

- Add handling of the .symver asm directives (#994)
- Allow absolute-value symbol to be used as an entry point
- Allow setting entry point for shared objects
- Reintroduce handling of tail-merged strings (#1117)
- Implement --retain-symbols-file (#1262)
- Allow mixing of @file and regular arguments (#1148)
- Support `VERSION` command in linker script
- Ignore '-no-fatal-warnings' option (#1192)
- Increase maximal supported alignment to 2^16 (#1190)
- Include git commit in linker version (#1203)
- Add support for .note.stapsdt sections (#1202)
- Check for overflow on 32bit relocations (#1175)
- Support tokens enclosed in double quotes in linker scripts
- Support flag --no-mmap-output-file (#1215)

### ⚡ Performance

- Limit default parallelism in string merging
- Rewrite scheduling of string merging tasks (#1240)

### 🪲 Bug Fixes

- Fill some bytes with zeros (affects --update-in-place) (#1237)
- Improve handling of non-absolute paths in save-dir (#1244)
- Pad copy relocations according to alignment (#1251)
- Don't allow hidden/protected symbols to reference shared objects (#1258)
- Use local symbol interposability when processing relocations (#1259)
- Make --strip-debug suppress earlier --strip-all (#1261)
- Fix compilation on riscv (#1100)
- Distinguish default version (@@) from non-default (@). (#1129)
- Only emit `PT_INTERP` for shared executables
- Add RISCV_ATTRIBUTE program segment (#1166)
- Don't create GOT/PLT entries for ifuncs that aren't referenced (#1185)
- Improve handling of relocations in non-alloc sections (#1196)
- Fix lookup of the riscv-fix-hi-part (#1198)
- Make --warn-unresolved-symbols match GNU ld's behaviour (#1217)
- Handle missing GNU_PROPERTY .note.gnu.property values (#1222)
- Allow dynamic symbols to refer to merged strings (#1147)

### 🏗️ Builds
- Build for `(aarch|x86_|riscv)64(|gc)-unknown-linux-(musl|gnu)` (#1151)
- Link musl releases with Wild

### 📚 Documentation

- Move nix docs to a separate file and update supported features list (#1113)
- Remove `archive_splitter.rs` reference from DESIGN.md (#1145)
- Update benchmarks, this time with bar charts
- Add instructions for using Wild with Rust on Illumos. (#1171)
- Document crate dependency version policy (#1140)
- Customise git-cliff config and document commit message format (#1267)

### 🕹️ Porting

- Initial support for Illumos (#1197)

### ⚖️ Linker Diff

- Add support for RISC-V (#920)
- Ensure all columns in tables have same width (#1247)

### 🧪 Testing

- Use wild for build in CI (#1091)
- Verify build on riscv (#1101)
- Verify minimal versions in CI (#1142)
- Ignore some diffs in risc-v tests (#1236)
- Use test-config-ci.toml in CI (#1234)
- Report sections where --update-in-place misses writes (#1239)
- Set the `TRIPLE` environment variable if needed when running mold tests
- Fix potential template-injection in CI
- Fix a couple of tests that were failing on recent opensuse (#1241)
- Don't skip running dynamically linked executables (#1248)
- Apt-get update before installing for riscv build workflow (#1255)
- Prevent race between test cases re-creating the same .so file (#1107)
- Use depfile in integrationtests (#1123)
- Use correct exit syscall number on Illumos (#1138)
- Look for dynamic linker in /bin/less in integ test (#1159)
- Unignore `symbol-versions3.sh` Mold test
- Make integration test diffing an opt-in feature (#1158)
- Integration tests: Make symbol assertions more extensible (#1169)
- Better error message when test unexpectedly pasess (#1176)
- Print clang version when clang-format fails (#1183)
- Clarify clang-format version mismatch instructions (#1193)
- Increase test binary execution timeout (#1188)
- Add a test for handling of note sections (#1211)
- Integration tests: Make skipping tests on unsupported flags more generic (#1225)
- Integration tests: Make compilation errors easier to find (#1224)
- Add basic testing for update-in-place flag (#1230)
- Limit the conditions for executing `update-nix-lockfile`

### 🔨 Refactor

- Use u32_from_slice (#1128)
- Introduce BitExtraction trait for u64 (#1157)
- Restructure code in symbol_db.rs a bit (#1252)
- Build only C++ and Rust demanglers
- Simplify get_host_architecture (#1164)
- Merge ResolutionFlags and ValueFlags (#1180)
- Move per-symbol-flags out of SymbolDb (#1186)
- Delete ValueFlags::ADDRESS (#1189)
- Replace all uses of bytemuck with zerocopy (#1210)
- Add readable Debug implementations for internal data structures (#1227)
- Macro to generate ELF newtypes and new SymbolType (#1228)

### 👥 Contributors

- davidlattimore
- marxin
- mati865
- daniel-levin
- lapla-cogito
- karolzwolak
- andrewdavidmackenzie
- el-yawd
- TechnoPorg
- jarjk
- jakobhellermann
- YamasouA

## 0.6.0

274 commits since the last release.

* Installation changes
  * Now requires at least rust 1.89.0 to build #1065 (lapla-cogito)
  * We no longer have an installer script (sorry) #1093 (davidlattimore)
  * Wild's release builds are now linked with wild #1093 (davidlattimore)
* Mold's test suite is now run in CI #903 (lapla-cogito)
* Override `-shared` by (-no)-pie #1095 (mati865)
* Emit error if as-yet unsupported .symver directive is used #1089 (marxin)
* Discard sections with exclude bit set #1077 (lqd)
* Do not look up files from args in search paths #1058 (mati865)
* Support escaping in version scripts #1053 (lapla-cogito)
* Avoid adding input files multiple times #1057 (mati865)
* Fix R_X86_64_GOTPC32_TLSDESC relaxations #1051 (marxin)
* Improve error message when LTO objects cause undefined symbols #1050 (AadiWaghray)
* Support -z interpose #1048 (lapla-cogito)
* Obtain verdefnum from verdef section header #1041 (mati865)
* Added support for CREL #981 (marxin)
* Support --help #1029 (lapla-cogito)
* Support -z undefs #1030 (AadiWaghray)
* Support --time=cycles,instructions,cache-misses etc #1027 (davidlattimore)
* Don't error when there are multiple alias definitions pointing to the same symbol #1021
  (lapla-cogito)
* Autoformat C/C++ test code #1006 (mati865)
* Implement `--allow-multiple-definition` and `-z muldefs` #1015 (lapla-cogito)
* Implement more arguments for exporting symbols #974 (mati865)
* Add `--unresolved-symbols=` and `--{warn, error}-unresolved-symbols` options support #993
  (lapla-cogito)
* Discard empty string-merge sections. Fixes #932 (davidlattimore)
* Write dynsym in parallel. Fixes #1000 (davidlattimore)
* Compute dynamic symbols versions during layout. #1000 (davidlattimore)
* Fix infinite loop on string-merge errors. #1008 (davidlattimore)
* Implement --wrap. #998 (davidlattimore)
* Support `extern "C"` and `extern "C++"` in version scripts. #963 (marxin), #1004 (mati865)
* Allow parallelism when resolving symbols for an object. #1001 (davidlattimore)
* Implement proper symbol lookup in a collections of versions #972 (marxin)
* Fix handling of custom NOBITS TLS sections #966 (davidlattimore)
* Use segment rather than section layout for TLS addresses #975 (davidlattimore)
* Change behaviour of --no-allow-shlib-undefined to match lld #897 (davidlattimore)
* Put custom TLS section into TLS segment #965 (davidlattimore)
* Don't emit non-standard .phdr and .shdr section headers #957 (davidlattimore)
* Support `-R` option if it points to a directory #956 (marxin)
* Version script glob support #943 (marxin)
* Added jobserver support #923 (marxin)
* Improve symbol priority handling #826 (davidlattimore)
* Don't propagate retain bit to output sections #914 (davidlattimore)
* linker-diff: Handle empty .got #831 (Noratrieb)
* Allow undefined symbols in shared objects to trigger archive entries #930 (davidlattimore)
* Report errors as coming from wild and add some colour #896 (davidlattimore)
* Input shared objects now implies -shared #879 (mati865)
* Support `--no-relax` only for mandatory situations #885 (mati865)
* Don't report shlib undefined when writing an shlib #884 (davidlattimore)
* Add support for --[no-]allow-shlib-undefined #881 (davidlattimore)
* Use TLS end-offset for TLSLD GOT entry in executables #882 (davidlattimore)
* Allow R_X86_64_GOTPC32_TLSDESC for all executable outputs. Fixes #849 (marxin)
* Add Nix package, overlay, stdenv adapter, and flake. #847 (RossSmyth with help from dawnofmidnight
  and Noratrieb)
* Add support for -z defs #850 (AadiWaghray)
* Fix when TLSDESC and TLSDESC_CALL aren't adjacent. Fixes #842 (davidlattimore)
* Fix infinite loop when we have no input files. Fixes #835 (davidlattimore)
* Add flag non-standard flag `--got-plt-syms` #827 (lapla-cogito)
* Parallelise opening of input files. #816 (davidlattimore)
* Sort .eh_frame_hdr in parallel. #824 (davidlattimore)
* Add support for --exclude-libs ALL. #812 (davidlattimore)
* Don't apply -Bsymbolic* to undefined symbols (davidlattimore)
* Don't error if debug info references undefined / GCed symbol
* Alias `-shared` to `-Bshareable` (lapla-cogito)
* Support `-Bsymbolic`, `-Bsymbolic-non-weak`, `-Bsymbolic-non-weak-functions` and `-Bno-symbolic`
  #782 (lapla-cogito)
* RISC-V support #704 + other commits (marxin)
* save-dir:
  * Skip non-existent paths #829 (Noratrieb)
  * Handle `@filename` and thin archives #777 (davidlattimore)
  * Replicate original directory structure. #575 (davidlattimore)
* Improve handling of relative sysroots #772 (davidlattimore)
* Support `-Bsymbolic-functions` #770 (lapla-cogito)
* Use debug info to show where error came from #768 (davidlattimore)
* Update .preinit_array section locations and flags #761 (marxin)
* Set DT_PREINIT_ARRAY{,SZ} if .preinit_array is present #759 (marxin)

## 0.5.0

A lot of fixes and new features since 0.4.0. We had 200 commits.

* Improve error message for LTO objects in archives (mati865)
* Fix setting of STATIC_TLS on non-x86-64 arch (marxin)
* linker-diff: Diff program segments (lapla-cogito)
* Fix alignment of stack segment (lapla-cogito)
* Basic linker script support #44 (davidlattimore)
  * Defining custom output sections
  * Mapping input sections to output sections
  * Defining symbols relative to sections
  * Setting the address of output sections
  * Setting alignment
  * KEEP command
  * ENTRY command
* Support for --entry flag (davidlattimore)
* Ignore some flags that we don't yet support (mati865)
* Don't error if multiple COMDAT groups define the same symbol (davidlattimore)
* Output section attributes now inherit from corresponding input section attributes (davidlattimore)
* Fix linking against protected symbols in shared objects (davidlattimore)
* Integration tests now support a test configuration file (lapla-cogito)
* Added support for -z norelro (davidlattimore)
* Fix misalignment of TLS when TDATA is absent #614 (davidlattimore)
* TLSDESC handling improvements (marxin)
* Set DF_ORIGIN and DF_1_ORIGIN when -z origin is passed (davidlattimore)
* Don't error if _start is undefined #613 (davidlattimore)
* Fix direct references to ifuncs in relocatable executables #580 (davidlattimore)
* Support `-l:<name.ext>` args (mati865)
* Make sure that we don't export hidden symbols #604 (davidlattimore)
* Don't emit duplicate symbol error on STB_GNU_UNIQUE #598 (davidlattimore)
* Fix dynamic relocations with non-zero addends on recent glibc #576 (davidlattimore)
* Better error reporting for duplicate symbols (lapla-cogito)
* Fix sysroot handling when sysroot indicators are not followed by a slash #590 (mati865)
* Handle symbol aliases when doing copy relocations #576 (davidlattimore)
* Fix error message if an empty linker script is provided (marxin)
* A few performance improvements (davidlattimore, mati865, marxin)
* Support outputting versioned symbols in shared objects #41 (mati865)
* Support for --start-lib and --end-lib (davidlattimore)
* Verify that input files didn't change while we were running (davidlattimore)
* Added support for thin archives (GlowingScrewdriver)
* Don't delete old output file if it's not a regular file #546 (davidlattimore)
* Added support for --undefined #528 (davidlattimore)
* More aarch64 relaxations (marxin)

## 0.4.0

A huge release with more than 250 commits since 0.3.0. We've also had several new contributors,
which is awesome.

* Wild now supports aarch64 on Linux (marxin)
* Support for TLSDESC (marxin)
* Linker diff mostly rewritten. Now gives much less false positives and diffs more stuff.
  (davidlattimore)
* Added support for --sysroot (mati865)
* Added support for --whole-archive (riverbl)
* Added support for -z nocopyreloc (davidlattimore)
* Added support for references to versioned symbols (davidlattimore)
* Added support declaring default symbol versions via '@@' in symbol names (davidlattimore)
* Added support for RELRO (inflation)
* Report errors on undefined symbols (mati865)
* Allow --version to be specified with regular linker arguments (inflation)
* Detect objects built for wrong architecture and report proper error (inflation)
* Keep sections if `__start_/__stop_{SEC}` is referenced. Fixes linkme crate (davidlattimore)
* Improved performance of string merging, which affects debug info link time (davidlattimore,
  marxin)
* Remove unnecessary and unwanted copy relocations (davidlattimore)
* Emit debug symbols for copy relocations (davidlattimore)
* Demangle symbol names in various error messages (davidlattimore, marxin)
* Improve error message when an absolute relocation is used against a read-only section with a
  relocatable output (davidlattimore)
* Handle initialisers / destructors in .ctors.* / .dtors.* (davidlattimore)
* Added flag --update-in-place (davidlattimore)
* Fixed referenced to merged strings in relocatable binaries (davidlattimore)
* Optimise x86-64 jmp instructions to bypass GOT (mati865)
* Ignore or warn on various flags that we don't yet support (marxin)
* Don't strip `.debug_` sections if they have the alloc flag set (davidlattimore)
* Lots of improvements to testing (marxin, mati865, davidlattimore)
* Fixed link error if a shared object had a strong reference to a symbol defined by a discarded
  archive entry (davidlattimore)
* We should now be publishing to crates.io, so tools like cargo-binstall should work.
* Numerous bugfixes

## 0.3.0

This release had 581 commits. Since the release notes are being added retrospectively, we just focus
on contributions from people other than davidlattimore.

* Added support for linking debug info (marxin)
* Fork on startup so that shut down runs in the background. Override with --no-fork.
  (andrewdavidmackenzie)
* Refactored to use lower-level APIs from the `object` crate, extending the `object` crate as needed
  (philipc)
* Added support for --build-id (mostafa-khaled775)
* Added support .note.gnu.property (marxin)
* Added support .note.ABI-tag section and NOTE segment (marxin)
* Emit GNU_STACK segment (marxin)

## 0.2.0

Also added retrospectively.

* First tagged release
* Move most of the linker into a separate lib crate (pinkforest)
