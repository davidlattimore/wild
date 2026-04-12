# Linker Script Support

This page documents which linker script features Wild supports, which are partially implemented,
and which are planned for the future. Each feature is marked with one of four statuses: Supported,
Partial, Planned, or Not planned. A dedicated section at the end lists the features required to
link the Linux kernel.

## Top-Level Commands

| Feature | Status | Notes |
|---------|--------|-------|
| `GROUP(files...)` | Supported | |
| `INPUT(files...)` | Supported | |
| `AS_NEEDED(files...)` | Supported | |
| `INCLUDE(file)` | Planned | |
| `OUTPUT_FORMAT(...)` | Supported | Parsed and ignored |
| `OUTPUT_ARCH(arch)` | Not planned | |
| `OUTPUT(filename)` | Not planned | |
| `SECTIONS { ... }` | Supported | |
| `ENTRY(symbol)` | Supported | |
| `VERSION { ... }` | Supported | |
| `PROVIDE(sym = expr)` | Supported | |
| `PROVIDE_HIDDEN(sym = expr)` | Supported | |
| `ASSERT(expr, "msg")` | Supported | |
| `MEMORY { ... }` | Partial | Region parsing supported; attribute flags and `>region` placement not yet implemented |
| `REGION_ALIAS(alias, region)` | Not planned | |
| `SEARCH_DIR(path)` | Not planned | |
| `STARTUP(filename)` | Not planned | |
| `TARGET(bfdname)` | Not planned | |
| `NOCROSSREFS(sections...)` | Not planned | |
| `INSERT [AFTER\|BEFORE] section` | Not planned | |
| Top-level symbol assignment (`sym = expr`) | Supported | |
| Compound assignment operators (`+=`, `-=`, etc.) | Not planned | |

## SECTIONS Block

| Feature | Status | Notes |
|---------|--------|-------|
| Output section definitions (`name : { ... }`) | Supported | |
| Input section matchers (`*(pattern)`, `file(pattern)`) | Supported | |
| Glob patterns in section and file names | Supported | |
| `KEEP(...)` to prevent garbage collection | Supported | |
| `PROVIDE(sym = expr)` inside sections | Supported | |
| `PROVIDE_HIDDEN(sym = expr)` inside sections | Supported | |
| Symbol assignment inside sections (`sym = .`) | Partial | Only assignment of the location counter (`sym = .`) is supported; arbitrary expressions on the right-hand side are not |
| Location counter assignment (`. = expr`) | Partial | Hex address literals (e.g. `. = 0x1000`) supported between output sections only; not inside section contents |
| `ALIGN(n)` on the location counter (`. = ALIGN(n)`) | Supported | |
| Per-section `ALIGN(n)` specifier | Supported | |
| `ASSERT(expr, "msg")` inside `SECTIONS` | Supported | |
| `OVERLAY { ... }` | Not planned | |
| Output section type specifiers (`(NOLOAD)`, `(COPY)`, etc.) | Planned | |
| `FILL(value)` and `=fillexp` | Planned | |
| `AT(addr)` load-address specifier on output sections | Planned | |
| Numeric address between section name and `:` (e.g. `name 0 : { ... }`) | Planned | |
| `SORT_BY_NAME(...)`, `SORT_BY_ALIGNMENT(...)`, `SORT_BY_INIT_PRIORITY(...)` | Planned | |
| `EXCLUDE_FILE(...)` inside input section matchers | Planned | |
| `BYTE(expr)`, `SHORT(expr)`, `LONG(expr)`, `QUAD(expr)` output data | Not planned | |
| `SUBALIGN(n)` forced input alignment | Not planned | |
| `ONLY_IF_RO` / `ONLY_IF_RW` output section constraints | Not planned | |

## Expressions and Functions

| Feature | Status | Notes |
|---------|--------|-------|
| Arithmetic operators: `+`, `-`, `*`, `/` | Supported | |
| Comparison operators: `<`, `>`, `<=`, `>=`, `==`, `!=` | Supported | |
| Bitwise operators: `&`, `\|`, `^`, `~`, `<<`, `>>` | Supported | |
| Logical operators: `&&`, `\|\|` | Supported | |
| Unary operators: `-`, `!`, `~` | Supported | |
| Numeric literals: decimal and hexadecimal | Supported | |
| Numeric literal K/M suffixes (e.g. `64K`, `2M`) | Supported | |
| Symbol references and location counter (`.`) | Supported | |
| Parenthesised sub-expressions | Supported | |
| `SIZEOF(section)` | Supported | |
| `ALIGNOF(section)` | Supported | |
| `ADDR(section)` | Supported | |
| `LOADADDR(section)` | Partial | Implemented as alias for `ADDR` (returns VMA); full LMA requires `AT(addr)` support |
| `ALIGN(expr)` | Supported | |
| `LENGTH(region)` | Supported | |
| `ORIGIN(region)` | Supported | |
| `MIN(a, b)` | Supported | |
| `MAX(a, b)` | Supported | |
| Ternary operator (`condition ? a : b`) | Planned | |
| `DEFINED(sym)` | Planned | |
| `SIZEOF_HEADERS` | Planned | |
| `SEGMENT_START(segment, default)` | Planned | |

## MEMORY Command

The `MEMORY` command defines named memory regions with an origin address and a length. Wild parses
`MEMORY` blocks including the `ORIGIN`/`org`/`o` and `LENGTH`/`len`/`l` attribute keywords and
their expressions. Attribute flags such as `(rwx)` are not yet parsed. Placement directives that
assign an output section to a named region (`>region`, `AT>region`) are not yet implemented.

| Feature | Status | Notes |
|---------|--------|-------|
| `MEMORY { ... }` block parsing | Supported | |
| Region name | Supported | |
| `ORIGIN`/`org`/`o` attribute | Supported | |
| `LENGTH`/`len`/`l` attribute | Supported | |
| Attribute flags (`(rwx)`, `(rx)`, etc.) | Planned | |
| `>region` output section placement | Planned | |
| `AT>region` load-region placement | Planned | |

## Linux Kernel Requirements

The Linux kernel's build system uses a rich set of linker script features across `vmlinux.lds` and
related architecture-specific scripts. Several of these features are not yet fully supported by
Wild. The table below lists each such feature along with its current status, so contributors can
see at a glance what remains before Wild can link the kernel.

| Feature | Status | Notes |
|---------|--------|-------|
| `OVERLAY { ... }` sections | Not planned | |
| Output section type specifiers (`(NOLOAD)`, `(COPY)`) | Planned | |
| `FILL(value)` and `=fillexp` | Planned | |
| `AT(addr)` load-address specifier on output sections | Planned | |
| `>region` and `AT>region` memory region placement | Planned | |
| `SORT_BY_NAME(...)`, `SORT_BY_ALIGNMENT(...)`, `SORT_BY_INIT_PRIORITY(...)` | Planned | |
| `EXCLUDE_FILE(...)` inside input section matchers | Planned | |
| `CONSTRUCTORS` command | Planned | |
| `PHDRS` command for explicit program header definition | Planned | |
| Ternary operator (`condition ? a : b`) | Planned | |
| `DEFINED(sym)` function | Planned | |
| `SIZEOF_HEADERS` built-in symbol | Planned | |
