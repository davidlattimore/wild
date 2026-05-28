## 0.9.0

The Wild repository moved to a GitHub org, so is now at https://github.com/wild-linker/wild. The old
URL should redirect to the new one.

A lot of work in this release was related to porting to other platforms. We did a large number of
refactorings to put ELF-specific behaviour behind traits. We've also started work on porting to
Mach-O and WebAssembly. These aren't yet ready for use, but if you'd like to help out with porting,
get in touch.

Wild now supports the linker plugin API that was originally part of the Gold linker, but which is
also supported by GNU ld and Mold. This lets us do linker-plugin LTO (link time optimisation). There
are still a few known issues, but it's already working on a good range of programs. Pure Rust
projects generally don't use linker plugins, since Rust can do LTO within the compiler, so this is
mostly helpful for C, C++ or mixed language projects. Note that when using a linker plugin, link
times will be very slow.

Lots more linker-script features were implemented during this release.

### 🚀 Features

- Support `--dependency-file` (#1467)
- Add built-in symbol __executable_start (#1473)
- Allow specifying library search paths in version scripts and export lists (#1477)
- Add support for `--auxiliary` arg (#1488)
- Allow excluding symbols from specific libraries via `--exclude-libs` (#1494)
- Support `--enable-new-dtags` and `--disable-new-dtags` (#1507)
- Add flag to turn off version in .comment (#1504)
- Support `PROVIDE` and `PROVIDE_HIDDEN` linker script directives (#1525)
- Reject conflicting RISC-V ISA extensions (#1526)
- Add support for linker plugins (#1411)
- Add base to track byte reduction due to relaxation (#1527)
- Support RISC-V call relaxation (#1552)
- Define `_etext`, `__etext` and `_edata` special symbols (#1563)
- Don't bail on `--use-android-relr-tags` and `--pack-dyn-relocs=relr` (#1566)
- Support RISC-V HI20 relaxation (#1574)
- Support matching based on linker script input filenames (#1596)
- Support lui deletion in RISC-V HI20 relaxation when %hi is zero (#1636)
- Implement PROVIDE semantics for linker-defined symbols (#1534)
- Implement R_X86_64_CODE_* relocations with relaxations (#1632)
- Add ASSERT command parsing support to linker scripts (#1607)
- Support building on Windows (#1629)
- Bail when an input file requests exec stack and it is not allowed (#1675)
- Add support for `--trace` (#1699)
- Evaluate linker script ASSERT commands (#1695)
- *(loongarch64)* Add allowed range and alignment by spec (#1734)
- Allow users of libwild to capture all warnings (#1756)
- *(AArch64)* Support 2 more relocations (#1760)
- Add support for generating static relocatables (#1698)
- Support bitwise, logical, and unary operators in linker script expressions (#1768)
- Implement ALIGNOF linker script function (#1770)
- Support `R_RISCV_ALIGN` relaxation (#1772)
- Support LOADADDR in linker scripts (#1780)
- Support K and M suffixes in linker script number literals (#1782)
- Support `-o/path` (without the space) (#1785)
- Add MEMORY block parsing and LENGTH/ORIGIN expression variants (#1792)
- Support `-z pack-relative-relocs` without actual packing (#1701)
- Support `--pack-dynamic-relocs=relr` (#1804)
- Implement ORIGIN and LENGTH evaluation in linker script expression eval (#1803)
- Generate a .symtab_shndx section when shnum > 65k (#1783)
- Handle output section header start addresses in linker scripts (#1850)
- Support `--use-android-relr-tags` (#1805)
- Implement range-extension thunks for aarch64 (#1847)
- Select platform based on `-flavor`, arg0 then host (#1873)
- Add -Ttext/-Tdata/-Tbss segment layout for SEGMENT_START support (#1877)
- Support SEGMENT_START function in Linker Script (#1851)
- Support `--compress-debug-sections` (#1881)
- Evaluate expressions within PROVIDE with `evaluate_expression` (#1925)
- Implement symbol resolution within the ASSERT command (#1931)
- Support `--nmagic` (#1884)
- Support PROVIDE within the SECTIONS toplevel command (#1947)

### ⚡ Performance

- Reduce use of starts_with in version script parsing (#1514)
- Add fast path for non-glob version script matchers (#1515)
- Reduce atomic operations for tracking sections with content (#1517)
- Fix performance loss of ctor/dtor ordering (#1522)
- Parallelize section and symbol address computation in relaxation scan (#1575)
- Skip fully-resolved sections in subsequent relaxation iterations (#1580)
- Skip relaxation iteration early when no rescan candidates remain (#1582)
- Change release profile to use codegen-units=1 (#1500)
- Fill padding bytes once instead of 3 times (#1889)

### 🪲 Bug Fixes

- *(benchmarks)* Use parent directory of args.tmp for filesystem checking (#1458)
- Delete the file instead of truncating it when updating busy executable (#1466)
- Use version_r when resolving undefined symbols in shared objects (#1469)
- Address equality for exported ifunc symbols (#1452)
- Resolve weak undefined symbols to zero in read-only sections (#1474)
- Properly merge `.ctors`/`.dtors` sections into `.init_array`/`.fini_array` (#1479)
- Align RELRO segment end to page boundary (#1496)
- Handle symbols with empty versions (#1480)
- Use actual segment alignment in `layout_section_parts` (#1501)
- Properly handle version script WRT symbols with multiple defs (#1519)
- Make `--version` exit immediately, `-v` continue linking (#1521)
- Properly handle entry symbol being weak and overridden (#1530)
- Placed downgraded symbols from version script correctly in .symtab (#1553)
- Do not bail when encountering unsupported SFrame version (#1577)
- Avoid updates to perf-event due to breaking changes (#1591)
- Use correct symbol priority when primary definition is dynamic (#1601)
- Prevent panic when writing to stdout fails in `--version` and `--help` (#1631)
- Don't use nop for calls to undefined functions (#1649)
- Make three more x86_64 relaxations required for static binaries (#1654)
- Print the correct message in `--sym-info` (#1673)
- Emit error for unterminated block comments in linker scripts (#1674)
- Warn rather than error on `--sort-section` flag (#1684)
- Emit error when shared objects required symbols are not provided (#1666)
- Hide linker-defined symbols in shared libraries (#1686)
-  fix: Register linker plugin message callback first (#1697)
- Only emit `__global_pointer$` on RISC-V (#1715)
- COMMON/ABS symbols are now defined in .dynsym (#1685)
- Emit undefined symbol error even if primary reference is GCed (#1737)
- *(AllowedRange)* Tweak and add `AllowedRange::from_bit_size` (#1742)
- Don't report undefined symbols when writing executables with -z undefs (#1741)
- Make our warning format consistent with the other linkers (#1738)
- Don't skip undefined symbol error due to previous weak ref (#1740)
- Write warnings to stderr not stdout (#1752)
- Preserve hidden visibility when merging symbols and localize dynsym exports (#1700)
- Format linker plugin messages via C shim and prints full log messages. (#1774)
- Null-terminate linker identity string in .comment section (#1776)
- Correct `--help` messages (#1784)
- GC of sections referenced from debug info (#1787)
- Clear instruction immediate fields before writing relocations in LoongArch64 (#1791)
- Clear opcode and immediate fields before rewriting MOVZ/MOVN relocations in AArch64 (#1794)
- Correct debug relocation values for local symbols (#1806)
- Symtab symbol version added by .symver (#1811)
- Import just `GLIBC_ABI_DT_RELR` version (#1826)
- Don't bypass dynamic symbol lookup due to unused hidden in archive (#1837)
- Copying debug symbols from debug info section (#1820)
- Sync GLOB_DAT allocation and writing conditions (#1845)
- Improve SHT_SYMTAB_SHNDX handling (#1846)
- Always handle elf::SHN_XINDEX when reading (#1852)
- Use correct addend for relocs referencing STT_SECTION (#1854)
- Resolve warning of cargo regarding yanked package (#1859)
- Support merging multiple eh_frame sections (#1867)
- Don't warn if unsupported `--pack-dyn-relocs` is overridden (#1874)
- Disable SFrame support by default (#1871)
- Emit error if attempting static link of dynamic object (#1886)
- Only keep RELRO_PADDING section when relro is enabled (#1892)
- Make --whole-archive work with linker plugins (#1900)
- *(jobserver)* ThreadPoolBuilder must use 1 thread with available_threads == 1 (#1904)
- Increase file limit when linker plugin is active (#1901)
- Implement plugin callsbacks required for thin LTO (#1902)
- Set file limit before we open input files (#1911)
- Bad allocation for versioned internal symbol (#1914)
- More robust code to get line numbers from debug info (#1923)
- Do not output SFrame section unless asked (#1916)
- Allow LTO to eliminate dead code (#1942)
- Handle missing version node for synthetic symbols (#1924)
- Fix resolution following linker scripts / synthetic symbols (#1953)
- Prevent GC of linker script symbol aliases (#1956)
- Load archive entries targeted by `--defsym` and linker script aliases (#1957)
- Emit error on missing resolution for symbol alias (#1961)

### 📚 Documentation

- Add code of conduct (#1630)
- Write up LLM use policy (#1618)
- Add governance documentation (#1656)
- Update communication options section in `CONTRIBUTING.md` (#1676)
- Add linker script support matrix and feature tracking (#1827)
- Use icons for implementation status (#1839)
- Simplify usage with GCC 16.1 (-fuse-ld=wild) (#1883)
- *(README.md)* Adjust what's not supported yet (#1906)
- Add instructions for installing with Brew (#1913)

### 🕹️ Porting

- *(MachO)* Copy __text section from input, introduce more output commands (#1810)
- *(MachO)* Emit code signature (#1919)
- *(MachO)* Fat binary support (#1910)
- *(MachO)* Include collected notes (#1812)
- *(MachO)* Initial scaffolding and input file parsing (#1748)
- *(MachO)* Introduce feature and smaller refactoring (#1929)
- *(MachO)* Make __DATA segment optional (#1862)
- *(MachO)* Make simple executable running on a real system (#1816)
- *(MachO)* Section/segment mapping and first final output (#1795)
- *(MachO)* Support relocation handling (#1869)
- *(MachO)* Support symbol table (#1888)
- *(MachO)* Unify and refactor segment writer (#1821)
- *(MachO)* Use args.output for CS identifier (#1949)
- *(wasm)* Add section and program segment mapping (#1926)
- *(wasm)* Implement object file section accessors (#1936)
- *(wasm)* Implement object file symbol accessors and `Symbol` trait (#1946)
- *(wasm)* Initial scaffolding for WebAssembly support (#1912)
- *(wasm)* Parse `linking` and `reloc.*` custom sections (#1918)
- *(wasm)* Support relocation encoding (#1964)
- Support running on wasi (#1723)

### 🎨 Styling

- Change C to 100 columns (#1928)
- Format TOML files and use taplo for checking (#1930)
- Add ymlfmt and format existing YAML files (#1652)

### 🛠️ Dev tooling

- Support passing a symbol ID to `--sym-info` (#1511)
- Fix save-dir when input filenames contain '=' (#1833)
- Save-dir now keeps at-files as separate files (#1834)
- Add some colour to `--sym-info` output (#1844)
- Use WILD_LOG environment variable rather than RUST_LOG (#1951)
- Make `--sym-info` show canonical targets regardless of order (#1952)
- Fix save-dir handling of response files (#1858)

### ⚖️ Linker Diff

- Identify some relaxations that LLD does (#1510)
- Support RISC-V attributes (#1535)
- Recognise additional indirections (#1642)
- `possible_relaxations_do` in RISC-V (#1767)

### 🧪 Testing

- Use a separate subdirectory for each test config (#1495)
- Use wild 0.8.0 in CI (#1503)
- Add local config option to skip specific external tests (#1502)
- Hash input files rather than using timestamps (#1505)
- Allow ExpectError directive to use regular expressions (#1513)
- Enhance symbol expectation and configuration test coverage (#1597)
- Verify that all source files use unix line endings (#1671)
- Don't silently pass section assertion if symbol is undefined (#1683)
- Add test for weak ref to as-needed shared library (#1672)
- Add test for hidden symbol that can only be resolved from a DSO (#1688)
- Disable Go caching (#1696)
- Enable some libc-integration variants for riscv (#1704)
- Add support for cross-testing with clang (#1703)
- Include macOS build (#1733)
- Report file and line number when rejecting test directives (#1743)
- Integration tests can now call dynamic libraries (#1690)
- Remove command hash from object filenames (#1745)
- Use deps files to track gcc/clang inputs (#1747)
- Move integration tests to one dir per test (#1754)
- Switch from rstest to libtest-mimic (#1757)
- Speed up running single arch with nextest (#1758)
- Fix external test CI that was running but ineffective (#1761)
- Allow substring matching in test filters (#1764)
- Fix clang-format formatting check (#1779)
- Allow running external tests with third-party linkers (#1786)
- Support running unit tests on wasi (#1759)
- Remove regex from linker plugin test (#1790)
- Actually run wasm32-wasip1 tests (#1808)
- Move tidy tests to libwild (#1807)
- Add test to check for ELF-specific code in shared locations (#1809)
- Add a test for #1817 (#1819)
- Rebuild object files if command-line changes (#1818)
- Fix colourisation of test output when using nextest (#1843)
- Add an integration test for `--write-gc-stats` (#1840)
- Get cross tests working in OpenSUSE docker image (#1864)
- Add a test that verifies debug line info (#1878)
- Add basic support for running MachO tests (#1876)
- Check for unexpected warnings (#1885)
- Test handling of empty aligned section (#1894)
- Fix cache step: /bin/tar: unrecognized option: posix (#1896)
- Run tests on Mach-O (skip ELF tests), reorder CI jobs (#1895)
- Include stderr/stdout in failure message when match fails (#1944)
- Don't register plugin tests when plugins feature is disabled (#1954)
- Add test for linker script without `-T` (#1955)
- Validate that loadable segments don't overlap (#1950)

## 0.8.0

### 🚀 Features

- Support `--hash-style={sysv, both}` (#1281)
- Support negation ('^') in version script globs (#1284)
- Support `PT_GNU_PROPERTY` (#1297)
- Support `--defsym=symbol=expression` (#1300)
- Support symbol definitions in linker script (#1307)
- Support merging non-string sections (#1306)
- Handle `-z x86-64-*` ISA needed (#1320)
- Ignore `--discard-all/-x` option (#1377)
- Support SFrame (#1287)
- Support `--section-start=.section=address` (#1385)
- Add --no-update-in-place flag (#1395)
- Support `-z max-page-size` (#1400)
- LoongArch64 support (#1409)
- Support expressions in `--defsym` and linker script symbol assignment (#1418)
- Sort .init_array and .fini_array by priority (#1408)
- Support `--no-eh-frame-hdr` (#1440)
- Support `-z stack-size=SIZE` (#1448)
- Include metrics connected to '.eh_frame' (#1443)
- Add `--pic-executable` as an alias for `--pie` (#1453)
- Support `variant_pcs` (#1272)
- Support `.variant_cc` (#1280)

### ⚡ Performance

- Make --update-in-place default and fallback to unlinking on ETXTBSY (#1238)
- Parallelize copying data sections (#1277)
- Avoid heap allocating each task during string merging (#1286)
- Minor improvement to cache efficiency of resolution (#1294)
- Merge some of the GC phases into a single phase (#1330)
- Process merge-string sections in mostly equal chunks (#1345)
- Run string merging and GC in parallel (#1339)
- Preallocate a Vec to avoid resizes (#1349)
- Optimize version script from rustc (#1355)
- Tweak how we determine the target number of groups (#1432)

### 🪲 Bug Fixes

- Ensure we write every byte of file even when updating in-place (#1276)
- Align output kind with LD in more cases (#1279)
- Don't try to emit copy relocations for non-canonical symbol aliases (#1308)
- Put common TLS symbols into correct section (#1310)
- Handle non-absolute paths with `--no-allow-shlib-undefined` (#1321)
- Do not add duplicated rpath entries (#1338)
- `save_dir::make_relative_path()` now works as expected (#1337)
- Reorder some sections so that objcopy doesn't complain (#1358)
- *(save-dir)* Handle @filename when processing save-dir (#1362)
- Use DT_SONAME to help determine if SO deps are met (#1390)
- *(save-dir)* Don't make paths in linker scripts relative if in sysroot (#1393)
- Relax debug info comparison against bfd (#1397)
- Don't exclude all libs when not yet supported --exclude-libs <lib> is passed (#1394)
- Properly resolve and retain defsym target symbols (#1402)
- *(save-dir)* Normalize source paths before checking if it's in sysroot (#1406)
- Resolve `__real_foo` in `--wrap` even without `__wrap_foo` (#1419)
- *(CREL)* Reduce allocation for non-EH relocations (#1426)
- Don't try to copy CREL sections to output file (#1438)
- Ifunc address equality for data section references (#1441)
- Ifunc address equality for GOT-relative relocations (#1446)

### 📚 Documentation

- Improve building and benching docs for rustc (#1283)
- Add some info about our monthly dev team meetings (#1291)
- Update rustc building instructions & format all the rustflags consistently (#1324)
- Add alternative Clang invocation (#1334)
- Add instructions for using wild with clang and gcc (#1354)
- Add `PACKAGING.md` instructions (#1342)
- Improve instructions on checking if wild was actually used (#1316)

### 🎨 Styling

- Wrap comments at 100 characters (#1268)

### 📦 Packaging

- Update for inclusion in Nixpkgs (#1318)

### 🛠️ Dev tooling

- Make absolute address checking work correctly (#1417)
- Add support for writing perfetto traces (#1323)
- Add a tool to aid with running benchmarks (#1454)
- Add Dockerfile for Gentoo (#1373)

### ⚖️ Linker Diff

- Ignore VER_NDX_LOCAL vs GLOBAL for undefined symbols (#1424)
- LoongArch64 support (#1428)

### 🧪 Testing

- Make a test failure message less confusing (#1275)
- Set `timeout-minutes` for CI jobs (#1301)
- Add a test for backtraces (#1353)
- Use a separate subdirectory for each tests build (#1404)
- Drop ubuntu 25.04 (#1433)
- Improve robustness of integration-test usage of run-with (#1437)
- Add cache for a couple of build jobs (#1434)
- Use separate archive sources for a couple of tests (#1401)
- Move contents of `exit.c` to `runtime.c` (#1447)
- Add a test for `-Bsymbolic-non-weak` (#1427)
- Use rust-cache actions (#1444)
- Introduce `WILD_TEST_CROSS=all` (#1425)
- Introduce `SkipArch` integration test directive (#1415)
- Include next upcoming LTS Ubuntu release (#1416)
- Run loongarch64 external tests (#1421)

### 🔨 Refactor

- A few simplifications to sysvs .hash computations (#1282)
- Change resolution to use a work queue (#1290)
- Make timing annotations use tracing indirectly (#1295)
- Make secondary output sections more flexible (#1312)
- Decouple OutputKind from Args (#1293)
- Preparations to run string merging in parallel with GC (#1329)
- Change GC to use a channel for work control (#1331)
- Change GC phase to use rayon scopes (#1344)
- Rewrite input opening work control (#1348)
- Change symbol resolution to use rayon scopes (#1363)
- Have linker script emit symbol defs directly (#1364)
- Work towards being able to load additional batches of files (#1365)
- Separate Epilogue into two separate entities (#1367)
- Move dynamic symbol definitions onto layout (#1368)
- Move gnu property notes to the layout (#1369)
- Move riscv attributes to the layout (#1370)
- Move eflags out of the prelude (#1371)
- Get rid of SymbolDb::num_symbols_per_group (#1372)
- Allow SymbolDb to be built in stages (#1374)
- Allow symbol resolution to be done in stages (#1375)
- Parse files as we open them (#1380)
- Make InputRef implement Copy (#1382)
- Get rid of InputFile::kind (#1383)
- Split ResolvedObject into dynamic and non-dynamic variants (#1389)
- Drop fd-lock dev dependency (#1319)
- Port linked-diff table to tabled crate (#1361)

### 👥 Contributors

- davidlattimore
- lapla-cogito
- marxin
- mati865
- karolzwolak
- RossSmyth
- YamasouA
- csfore
- zyxhere
- tshepang
- TechnoPorg

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
