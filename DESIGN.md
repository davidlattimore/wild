# Design

This document provides a high level overview of Wild's design. The intent is to not go into too much
detail, otherwise we increase the risk that it'll get out-of-sync with the code. For full details,
see comments in the code and the code itself.

## Phases

The linker runs several phases. Each phase borrows data immutably from the previous phases. The high
level phases are:

* `args.rs`: Parse command-line arguments.
* `input_data.rs`: Open input files with mmap.
* `archive_splitter.rs`: Split archives into their separate objects.
* `string_merging.rs`: Strings in string-merge sections are deduplicated.
* `symbol_db.rs`: Build a hashmap from symbol names to symbol IDs.
* `resolution.rs`: Resolve all undefined symbols and in the process decide which archived objects
  will be processed.
* `layout.rs`:
  * Traverse graph of relocations, in the process, determining which input sections are needed and
    how much space is needed in the various linker-generated sections such as the GOT (global offset
    table), symbol tables, dynamic relocation tables etc.
  * Allocate addresses for sections, symbols, program segments etc.
* `elf_writer.rs`: Copy input sections to the output file, applying relocations as we go. Write
  linker-generated sections.

For a more detailed look at the phases of the linker, run with the `--time` flag.

## Threading

The linker makes extensive use of multiple threads. The thread pool is owned by the rayon library.
Where possible, we use functions like rayon's `par_iter` to process collections in parallel. Failing
that, we use `par_bridge` which allows the main thread to create work to send out to the thread
pool. In a couple of cases however, we have graph algorithms that don't fit neatly into rayon's
model. In those cases, we spawn one rayon scoped task per thread and then do job control ourselves.

There are various phases within the linker that are single threaded. This is fine, so long as those
phases run quickly enough.

## Testing

Most testing is done by `integration_tests.rs`. This compiles various programs that are written in
C, C++, Rust and assembly. It then links them with our reference linkers - GNU ld and in some cases
also LLD. It links them with Wild and compares the resulting binaries using our own custom diff
tool, `linker-diff`. Provided that succeeds, it then executes all the linked programs and checks
that they give the correct answer.
