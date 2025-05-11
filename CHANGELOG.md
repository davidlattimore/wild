# 0.5.0

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

# 0.4.0

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

# 0.3.0

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

# 0.2.0

Also added retrospectively.

* First tagged release
* Move most of the linker into a separate lib crate (pinkforest)
