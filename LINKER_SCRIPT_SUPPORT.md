# Linker Script Support

This page documents which linker script features Wild supports, which are partially implemented,
and which are planned for the future. Each feature is marked with one of four statuses: `✅`
(supported), `🧪` (partial), `📅` (planned), or `❌` (not planned). A dedicated section at the
end lists the features required to link the Linux kernel.

## Top-Level Commands

| Feature | Status | Notes |
|---------|--------|-------|
| `GROUP(files...)` | ✅ | |
| `INPUT(files...)` | ✅ | |
| `AS_NEEDED(files...)` | ✅ | |
| `INCLUDE(file)` | 📅 | |
| `OUTPUT_FORMAT(...)` | ✅ | Parsed and ignored |
| `OUTPUT_ARCH(arch)` | ❌ | |
| `OUTPUT(filename)` | ❌ | |
| `SECTIONS { ... }` | ✅ | |
| `ENTRY(symbol)` | ✅ | |
| `VERSION { ... }` | ✅ | |
| `PROVIDE(sym = expr)` | ✅ | |
| `PROVIDE_HIDDEN(sym = expr)` | ✅ | |
| `ASSERT(expr, "msg")` | ✅ | |
| `MEMORY { ... }` | 🧪 | Region parsing supported; attribute flags and `>region` placement not yet implemented |
| `REGION_ALIAS(alias, region)` | ❌ | |
| `SEARCH_DIR(path)` | ❌ | |
| `STARTUP(filename)` | ❌ | |
| `TARGET(bfdname)` | ❌ | |
| `NOCROSSREFS(sections...)` | ❌ | |
| `INSERT [AFTER\|BEFORE] section` | ❌ | |
| Top-level symbol assignment (`sym = expr`) | ✅ | |
| Compound assignment operators (`+=`, `-=`, etc.) | ❌ | |

## SECTIONS Block

| Feature | Status | Notes |
|---------|--------|-------|
| Output section definitions (`name : { ... }`) | ✅ | |
| Input section matchers (`*(pattern)`, `file(pattern)`) | ✅ | |
| Glob patterns in section and file names | ✅ | |
| `KEEP(...)` to prevent garbage collection | ✅ | |
| `PROVIDE(sym = expr)` inside sections | ✅ | |
| `PROVIDE_HIDDEN(sym = expr)` inside sections | ✅ | |
| Symbol assignment inside sections (`sym = .`) | ✅ | |
| Location counter assignment (`. = expr`) | 🧪 | constant expressions (e.g. `. = 0x1000 * 2`) supported between output sections only; not inside section contents |
| `ALIGN(n)` on the location counter (`. = ALIGN(n)`) | ✅ | |
| Per-section `ALIGN(n)` specifier | ✅ | |
| `ASSERT(expr, "msg")` inside `SECTIONS` | ✅ | |
| `OVERLAY { ... }` | ❌ | |
| Output section type specifiers (`(NOLOAD)`, `(COPY)`, etc.) | 📅 | |
| `FILL(value)` and `=fillexp` | 📅 | |
| `AT(addr)` load-address specifier on output sections | ✅ | |
| Numeric address between section name and `:` (e.g. `name 0 : { ... }`) | 🧪 | Only numeric literals are currently supported |
| `SORT_BY_NAME(...)`, `SORT_BY_ALIGNMENT(...)`, `SORT_BY_INIT_PRIORITY(...)` | 📅 | |
| `EXCLUDE_FILE(...)` inside input section matchers | 📅 | |
| `BYTE(expr)`, `SHORT(expr)`, `LONG(expr)`, `QUAD(expr)` output data | ❌ | |
| `SUBALIGN(n)` forced input alignment | ❌ | |
| `ONLY_IF_RO` / `ONLY_IF_RW` output section constraints | ❌ | |
| `:phdr` output section phdrs | 🧪 | Only a single `:phdr` specifier is supported per output section. |

## Expressions and Functions

| Feature | Status | Notes |
|---------|--------|-------|
| Arithmetic operators: `+`, `-`, `*`, `/` | ✅ | |
| Comparison operators: `<`, `>`, `<=`, `>=`, `==`, `!=` | ✅ | |
| Bitwise operators: `&`, `\|`, `^`, `~`, `<<`, `>>` | ✅ | |
| Logical operators: `&&`, `\|\|` | ✅ | |
| Unary operators: `-`, `!`, `~` | ✅ | |
| Numeric literals: decimal and hexadecimal | ✅ | |
| Numeric literal K/M suffixes (e.g. `64K`, `2M`) | ✅ | |
| Symbol references and location counter (`.`) | ✅ | |
| Parenthesised sub-expressions | ✅ | |
| `SIZEOF(section)` | ✅ | |
| `ALIGNOF(section)` | ✅ | |
| `ADDR(section)` | ✅ | |
| `LOADADDR(section)` | ✅ | |
| `ALIGN(expr)` | ✅ | |
| `LENGTH(region)` | ✅ | |
| `ORIGIN(region)` | ✅ | |
| `MIN(a, b)` | ✅ | |
| `MAX(a, b)` | ✅ | |
| Ternary operator (`condition ? a : b`) | 📅 | |
| `DEFINED(sym)` | 📅 | |
| `SIZEOF_HEADERS` | ✅ | |
| `SEGMENT_START(segment, default)` | ✅ | Supports `"text"`, `"data"`, `"bss"`, `"rodata"`; returns `-Ttext`/`-Tdata`/`-Tbss` override if provided, otherwise `default`; unknown segment names always return `default` |

## MEMORY Command

The `MEMORY` command defines named memory regions with an origin address and a length. Wild parses
`MEMORY` blocks including the `ORIGIN`/`org`/`o` and `LENGTH`/`len`/`l` attribute keywords and
their expressions. Attribute flags such as `(rwx)` are not yet parsed. Placement directives that
assign an output section to a named region (`>region`, `AT>region`) are not yet implemented.

| Feature | Status | Notes |
|---------|--------|-------|
| `MEMORY { ... }` block parsing | ✅ | |
| Region name | ✅ | |
| `ORIGIN`/`org`/`o` attribute | ✅ | |
| `LENGTH`/`len`/`l` attribute | ✅ | |
| Attribute flags (`(rwx)`, `(rx)`, etc.) | 📅 | |
| `>region` output section placement | 📅 | |
| `AT>region` load-region placement | 📅 | |

## Linux Kernel Requirements

The Linux kernel's build system uses a rich set of linker script features across `vmlinux.lds` and
related architecture-specific scripts. Several of these features are not yet fully supported by
Wild. The table below lists each such feature along with its current status, so contributors can
see at a glance what remains before Wild can link the kernel.

| Feature | Status | Notes |
|---------|--------|-------|
| `OVERLAY { ... }` sections | ❌ | |
| Output section type specifiers (`(NOLOAD)`, `(COPY)`) | 📅 | |
| `FILL(value)` and `=fillexp` | 📅 | |
| `AT(addr)` load-address specifier on output sections | ✅ | |
| `>region` and `AT>region` memory region placement | 📅 | |
| `SORT_BY_NAME(...)`, `SORT_BY_ALIGNMENT(...)`, `SORT_BY_INIT_PRIORITY(...)` | 📅 | |
| `EXCLUDE_FILE(...)` inside input section matchers | 📅 | |
| `CONSTRUCTORS` command | 📅 | |
| `PHDRS` command for explicit program header definition | 🧪 | The FILEHDR and PHDRS keywords aren't yet supported. |
| Ternary operator (`condition ? a : b`) | 📅 | |
| `DEFINED(sym)` function | 📅 | |
| `SIZEOF_HEADERS` built-in symbol | ✅ | |
| `/DISCARD/` command | ✅ | |
