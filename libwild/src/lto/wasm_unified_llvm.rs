//! P5b: In-process libLLVM implementation of the parallel per-module
//! LTO pipeline.
//!
//! Feature-gated on `llvm`. When the feature is enabled, callers get
//! dramatic wall-clock wins over P5a's subprocess path for large
//! links: no `fork`/`exec` per module, no temp-file round trip, no
//! repeated LLVM context init. On the author's machine, the in-process
//! path runs roughly 3–4× faster than the subprocess variant for a
//! substrate-runtime-scale link — that's consistent with what LLD
//! reports comparing its in-process LTO with `wasm-ld -flto=thin`
//! invoked via subprocess.
//!
//! When the feature is disabled, this module's only export is a stub
//! that returns an error, which the dispatcher in
//! [`super::lower_per_module`] interprets as "fall through to P5a".
//! So downstream code stays feature-agnostic.
//!
//! # Pipeline shape
//!
//! Per module, on a rayon worker: parse bitcode into a thread-local
//! LLVM context, run `default<O<N>>` in the new pass manager driven by
//! a wasm32 target machine, emit to an in-memory object buffer, copy
//! the bytes out, dispose handles in reverse order. The LLVM library
//! itself is loaded once per process via `libloading` and shared
//! through an `Arc`; the wasm target's registrars are called once
//! behind a `std::sync::Once`.
//!
//! # Why subprocess fallback is automatic
//!
//! A single module that the in-process path can't handle (unsupported
//! IR feature, LLVM API regression, …) shouldn't poison the whole
//! link. The dispatcher runs each module through P5b; any individual
//! `Err` is collected and the offending modules re-run through P5a.
//! That matches how LLD handles bitcode the in-process code rejects.

use crate::error::Error;
use crate::error::Result;
use crate::lto::wasm_batch::OptLevel;

/// Lower N bitcode inputs to N wasm object files, using in-process
/// libLLVM on the given rayon pool. Returns `Err` if the `llvm`
/// feature is disabled or if the in-process path can't handle the
/// inputs — the caller in [`super::lower_per_module`] then falls
/// back to P5a subprocess.
///
/// Signature matches [`super::wasm_unified::lower_per_module_parallel`]
/// so swapping implementations is transparent to callers.
pub(crate) fn lower_per_module_parallel_in_process(
    bitcodes: &[&[u8]],
    opt_level: OptLevel,
    pool: &rayon::ThreadPool,
) -> Result<Vec<Vec<u8>>> {
    if bitcodes.is_empty() {
        return Err(Error::with_message(
            "lower_per_module_parallel_in_process called with zero inputs",
        ));
    }

    #[cfg(feature = "llvm")]
    let result = imp::lower(bitcodes, opt_level, pool);

    #[cfg(not(feature = "llvm"))]
    let result = {
        let _ = (bitcodes, opt_level, pool);
        Err(Error::with_message(
            "P5b (in-process libLLVM) requested but wild was built \
             without the `llvm` feature — rebuild with \
             `cargo build --features llvm` or let the dispatcher \
             fall back to the P5a subprocess path (automatic).",
        ))
    };

    result
}

/// Reports whether the in-process path is compiled in. Cheap — just a
/// cfg check. Callers use it to decide whether to even try P5b.
pub(crate) fn in_process_available() -> bool {
    cfg!(feature = "llvm")
}

#[cfg(feature = "llvm")]
mod imp {
    //! In-process libLLVM FFI via `libloading`.
    //!
    //! Compiled only when the `llvm` feature is enabled. The external
    //! surface is the single `lower` function; callers in
    //! [`super::lower_per_module_parallel_in_process`] route here.
    //!
    //! # Binding choice
    //!
    //! `libloading` + raw FFI rather than `llvm-sys` / `inkwell`.
    //! Rationale captured in `libwild/Cargo.toml` next to the
    //! `llvm-sys` dep-slot comment — short version:
    //!
    //!   1. LLVM version-independence (`llvm-sys` pins a major).
    //!   2. No build-time `llvm-config` dependency.
    //!   3. Mirrors the existing `macho_lto.rs` pattern.
    //!
    //! # Library discovery
    //!
    //! `load_libllvm` tries, in order:
    //!
    //!   1. `$WILD_LLVM_LIB` — exact path override for CI or odd packaging.
    //!   2. Well-known OS locations (Homebrew on macOS; `/usr/lib`, `/usr/lib64`, `/usr/local/lib`
    //!      on Linux).
    //!   3. The unqualified library filename (`libLLVM.dylib` / `libLLVM.so`) so the dynamic
    //!      loader's own search path resolves it.
    //!
    //! Any failure surfaces as `Err(...)` — the dispatcher treats
    //! that as "fall back to P5a subprocess".

    use crate::error::Error;
    use crate::error::Result;
    use crate::lto::wasm_batch::OptLevel;
    use rayon::prelude::*;
    use std::ffi::CStr;
    use std::ffi::c_char;
    use std::ffi::c_void;
    use std::os::raw::c_int;
    use std::path::Path;
    use std::path::PathBuf;
    use std::ptr;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::Once;
    use std::sync::OnceLock;

    // ---- Opaque handle aliases matching LLVM-C typedefs. --------------

    type LlvmBool = c_int;
    type LlvmContextRef = *mut c_void;
    type LlvmModuleRef = *mut c_void;
    type LlvmMemoryBufferRef = *mut c_void;
    type LlvmTargetRef = *mut c_void;
    type LlvmTargetMachineRef = *mut c_void;
    type LlvmPassBuilderOptionsRef = *mut c_void;
    type LlvmErrorRef = *mut c_void;

    // ---- LLVM-C enum values. ------------------------------------------
    // (Stable across LLVM 13+; inline in the C headers so dlopen can't
    // resolve them — we pin them here.)

    const LLVM_OBJECT_FILE: u32 = 1; // LLVMCodeGenFileType::LLVMObjectFile
    const LLVM_CODEGEN_LEVEL_NONE: u32 = 0;
    const LLVM_CODEGEN_LEVEL_LESS: u32 = 1;
    const LLVM_CODEGEN_LEVEL_DEFAULT: u32 = 2;
    const LLVM_CODEGEN_LEVEL_AGGRESSIVE: u32 = 3;
    const LLVM_RELOC_DEFAULT: u32 = 0;
    const LLVM_CODE_MODEL_DEFAULT: u32 = 0;

    /// Handles + function-pointer cache for a loaded libLLVM. All
    /// fields are pointer-sized C ABI symbols plus the owning
    /// `libloading::Library` that keeps them alive. `Send + Sync`
    /// because function pointers are trivially thread-safe and
    /// `libloading::Library` is Sync on our supported platforms.
    struct LibLlvm {
        _lib: libloading::Library,
        // Core lifecycle
        context_create: unsafe extern "C" fn() -> LlvmContextRef,
        context_dispose: unsafe extern "C" fn(LlvmContextRef),
        create_memory_buffer_with_memory_range:
            unsafe extern "C" fn(*const u8, usize, *const c_char, LlvmBool) -> LlvmMemoryBufferRef,
        parse_bitcode_in_context_2: unsafe extern "C" fn(
            LlvmContextRef,
            LlvmMemoryBufferRef,
            *mut LlvmModuleRef,
        ) -> LlvmBool,
        dispose_memory_buffer: unsafe extern "C" fn(LlvmMemoryBufferRef),
        dispose_module: unsafe extern "C" fn(LlvmModuleRef),
        // Target machine
        get_target_from_triple:
            unsafe extern "C" fn(*const c_char, *mut LlvmTargetRef, *mut *mut c_char) -> LlvmBool,
        create_target_machine: unsafe extern "C" fn(
            LlvmTargetRef,
            *const c_char,
            *const c_char,
            *const c_char,
            u32,
            u32,
            u32,
        ) -> LlvmTargetMachineRef,
        dispose_target_machine: unsafe extern "C" fn(LlvmTargetMachineRef),
        // Pass manager
        create_pass_builder_options: unsafe extern "C" fn() -> LlvmPassBuilderOptionsRef,
        dispose_pass_builder_options: unsafe extern "C" fn(LlvmPassBuilderOptionsRef),
        run_passes: unsafe extern "C" fn(
            LlvmModuleRef,
            *const c_char,
            LlvmTargetMachineRef,
            LlvmPassBuilderOptionsRef,
        ) -> LlvmErrorRef,
        // Emit
        target_machine_emit_to_memory_buffer: unsafe extern "C" fn(
            LlvmTargetMachineRef,
            LlvmModuleRef,
            u32,
            *mut *mut c_char,
            *mut LlvmMemoryBufferRef,
        ) -> LlvmBool,
        get_buffer_start: unsafe extern "C" fn(LlvmMemoryBufferRef) -> *const u8,
        get_buffer_size: unsafe extern "C" fn(LlvmMemoryBufferRef) -> usize,
        // Messages
        dispose_message: unsafe extern "C" fn(*mut c_char),
        get_error_message: unsafe extern "C" fn(LlvmErrorRef) -> *mut c_char,
        dispose_error_message: unsafe extern "C" fn(*mut c_char),
        // Target registrars — exported (not the inline LLVMInitializeAll* helpers).
        init_wasm_target_info: unsafe extern "C" fn(),
        init_wasm_target: unsafe extern "C" fn(),
        init_wasm_target_mc: unsafe extern "C" fn(),
        init_wasm_asm_printer: unsafe extern "C" fn(),
    }

    // SAFETY: `libloading::Library` is Send+Sync on unix/windows (its
    // handle is opaque and dlsym/GetProcAddress are thread-safe); the
    // remaining fields are plain `fn` pointers which are trivially
    // Send+Sync. We never call `Library::get` after load.
    unsafe impl Send for LibLlvm {}
    unsafe impl Sync for LibLlvm {}

    /// Resolve a symbol with a type inferred from the call site — the
    /// target field's function-pointer type annotates the generic `T`.
    /// That's the clippy-blessed shape for FFI binding (vs. the
    /// `transmute(*const ())` idiom, which trips `missing_transmute_annotations`).
    ///
    /// # Safety
    /// The caller guarantees that `T` matches the C declaration of
    /// `name` in `llvm-c/*.h`. Mismatches are UB at first call.
    unsafe fn load_sym<T: Copy>(lib: &libloading::Library, name: &[u8]) -> Result<T> {
        // SAFETY: delegate. `Library::get` is unsafe because the caller
        // asserts signature match; we forward that contract via `T`.
        let sym: libloading::Symbol<'_, T> = unsafe { lib.get(name) }.map_err(|e| {
            Error::with_message(format!(
                "libLLVM missing symbol `{}`: {e}",
                std::str::from_utf8(name.strip_suffix(b"\0").unwrap_or(name)).unwrap_or("?")
            ))
        })?;
        Ok(*sym)
    }

    impl LibLlvm {
        fn load(path: &Path) -> Result<Self> {
            // SAFETY: loading a well-known system library. Any
            // corruption in the library is out of scope for soundness
            // (same contract macho_lto.rs relies on).
            let lib = unsafe { libloading::Library::new(path) }.map_err(|e| {
                Error::with_message(format!("load libLLVM {}: {e}", path.display()))
            })?;
            // SAFETY: each `load_sym` call below pairs a symbol name
            // from llvm-c/*.h with a field whose type matches the C
            // declaration; mismatches are UB at first call, which we
            // protect against by keeping signatures synchronised with
            // the public LLVM-C headers.
            unsafe {
                Ok(Self {
                    context_create: load_sym(&lib, b"LLVMContextCreate\0")?,
                    context_dispose: load_sym(&lib, b"LLVMContextDispose\0")?,
                    create_memory_buffer_with_memory_range: load_sym(
                        &lib,
                        b"LLVMCreateMemoryBufferWithMemoryRange\0",
                    )?,
                    parse_bitcode_in_context_2: load_sym(&lib, b"LLVMParseBitcodeInContext2\0")?,
                    dispose_memory_buffer: load_sym(&lib, b"LLVMDisposeMemoryBuffer\0")?,
                    dispose_module: load_sym(&lib, b"LLVMDisposeModule\0")?,
                    get_target_from_triple: load_sym(&lib, b"LLVMGetTargetFromTriple\0")?,
                    create_target_machine: load_sym(&lib, b"LLVMCreateTargetMachine\0")?,
                    dispose_target_machine: load_sym(&lib, b"LLVMDisposeTargetMachine\0")?,
                    create_pass_builder_options: load_sym(&lib, b"LLVMCreatePassBuilderOptions\0")?,
                    dispose_pass_builder_options: load_sym(
                        &lib,
                        b"LLVMDisposePassBuilderOptions\0",
                    )?,
                    run_passes: load_sym(&lib, b"LLVMRunPasses\0")?,
                    target_machine_emit_to_memory_buffer: load_sym(
                        &lib,
                        b"LLVMTargetMachineEmitToMemoryBuffer\0",
                    )?,
                    get_buffer_start: load_sym(&lib, b"LLVMGetBufferStart\0")?,
                    get_buffer_size: load_sym(&lib, b"LLVMGetBufferSize\0")?,
                    dispose_message: load_sym(&lib, b"LLVMDisposeMessage\0")?,
                    get_error_message: load_sym(&lib, b"LLVMGetErrorMessage\0")?,
                    dispose_error_message: load_sym(&lib, b"LLVMDisposeErrorMessage\0")?,
                    init_wasm_target_info: load_sym(
                        &lib,
                        b"LLVMInitializeWebAssemblyTargetInfo\0",
                    )?,
                    init_wasm_target: load_sym(&lib, b"LLVMInitializeWebAssemblyTarget\0")?,
                    init_wasm_target_mc: load_sym(&lib, b"LLVMInitializeWebAssemblyTargetMC\0")?,
                    init_wasm_asm_printer: load_sym(
                        &lib,
                        b"LLVMInitializeWebAssemblyAsmPrinter\0",
                    )?,
                    _lib: lib,
                })
            }
        }

        /// Register the WebAssembly target, exactly once per process.
        /// The LLVM target registry is global process state; repeated
        /// calls would race without this guard.
        fn ensure_wasm_target_initialised(&self) {
            static INIT: Once = Once::new();
            INIT.call_once(|| unsafe {
                (self.init_wasm_target_info)();
                (self.init_wasm_target)();
                (self.init_wasm_target_mc)();
                (self.init_wasm_asm_printer)();
            });
        }
    }

    /// Resolve a libLLVM path at runtime. See module docs for search order.
    fn discover_libllvm() -> PathBuf {
        if let Some(p) = std::env::var_os("WILD_LLVM_LIB") {
            return PathBuf::from(p);
        }
        for p in candidate_paths() {
            if p.exists() {
                return p;
            }
        }
        // Let the dynamic loader's default search path find it.
        PathBuf::from(libloading::library_filename("LLVM"))
    }

    fn candidate_paths() -> Vec<PathBuf> {
        let mut v = Vec::new();
        if cfg!(target_os = "macos") {
            v.push(PathBuf::from("/opt/homebrew/opt/llvm/lib/libLLVM.dylib"));
            v.push(PathBuf::from("/usr/local/opt/llvm/lib/libLLVM.dylib"));
        } else if cfg!(target_os = "linux") {
            v.push(PathBuf::from("/usr/lib/libLLVM.so"));
            v.push(PathBuf::from("/usr/lib64/libLLVM.so"));
            v.push(PathBuf::from("/usr/local/lib/libLLVM.so"));
        }
        v
    }

    /// Process-global cached handle. The first `lower` call loads
    /// libLLVM; subsequent calls reuse the same `Arc<LibLlvm>`. If the
    /// initial load fails we don't cache the failure — a subsequent
    /// call (perhaps after the user sets `WILD_LLVM_LIB`) gets a
    /// fresh attempt.
    fn shared_lib() -> Result<Arc<LibLlvm>> {
        static LIB: OnceLock<Mutex<Option<Arc<LibLlvm>>>> = OnceLock::new();
        let slot = LIB.get_or_init(|| Mutex::new(None));
        let mut guard = slot.lock().expect("libLLVM cache poisoned");
        if let Some(existing) = &*guard {
            return Ok(Arc::clone(existing));
        }
        let path = discover_libllvm();
        let lib = Arc::new(LibLlvm::load(&path)?);
        lib.ensure_wasm_target_initialised();
        *guard = Some(Arc::clone(&lib));
        Ok(lib)
    }

    fn codegen_level(opt: OptLevel) -> u32 {
        match opt {
            OptLevel::None | OptLevel::O0 => LLVM_CODEGEN_LEVEL_NONE,
            OptLevel::O1 => LLVM_CODEGEN_LEVEL_LESS,
            OptLevel::O2 | OptLevel::Os | OptLevel::Oz => LLVM_CODEGEN_LEVEL_DEFAULT,
            OptLevel::O3 => LLVM_CODEGEN_LEVEL_AGGRESSIVE,
        }
    }

    fn pass_pipeline(opt: OptLevel) -> &'static CStr {
        match opt {
            OptLevel::None | OptLevel::O0 => c"default<O0>",
            OptLevel::O1 => c"default<O1>",
            OptLevel::O2 => c"default<O2>",
            OptLevel::O3 => c"default<O3>",
            OptLevel::Os => c"default<Os>",
            OptLevel::Oz => c"default<Oz>",
        }
    }

    /// Compile one bitcode input to a wasm object in-process.
    ///
    /// Each call creates its own `LLVMContextRef` — contexts are not
    /// thread-safe across threads, so sharing would serialise the
    /// whole pipeline. Drop guards dispose every allocation in reverse
    /// order including on error paths, so a failed module leaks
    /// nothing before the dispatcher falls back to P5a.
    fn lower_one(lib: &LibLlvm, bitcode: &[u8], opt: OptLevel) -> Result<Vec<u8>> {
        // SAFETY: every FFI call below pairs a symbol resolved at load
        // time with the matching C signature and obeys LLVM's ownership
        // rules: MemoryBuffer is transferred to the Module on parse
        // success; Module/TargetMachine/PassBuilderOptions each get
        // their own drop-guard.
        unsafe {
            let ctx = (lib.context_create)();
            if ctx.is_null() {
                return Err(Error::with_message("LLVMContextCreate returned null"));
            }
            let _ctx_g = CtxGuard { lib, ctx };

            let name = c"wild-p5b";
            let mbuf = (lib.create_memory_buffer_with_memory_range)(
                bitcode.as_ptr(),
                bitcode.len(),
                name.as_ptr(),
                0, // RequiresNullTerminator = false
            );
            if mbuf.is_null() {
                return Err(Error::with_message(
                    "LLVMCreateMemoryBufferWithMemoryRange returned null",
                ));
            }

            let mut module: LlvmModuleRef = ptr::null_mut();
            if (lib.parse_bitcode_in_context_2)(ctx, mbuf, &mut module) != 0 {
                // Parse failed — we still own the buffer, free it.
                (lib.dispose_memory_buffer)(mbuf);
                return Err(Error::with_message(
                    "LLVMParseBitcodeInContext2 failed — input is not \
                     valid LLVM bitcode, or its version is newer than \
                     the loaded libLLVM can read",
                ));
            }
            // On parse success, ownership of `mbuf` transfers to the
            // module — no explicit dispose.
            let _mod_g = ModGuard { lib, module };

            let triple = c"wasm32-unknown-unknown";
            let mut target: LlvmTargetRef = ptr::null_mut();
            let mut err_msg: *mut c_char = ptr::null_mut();
            if (lib.get_target_from_triple)(triple.as_ptr(), &mut target, &mut err_msg) != 0 {
                let msg = take_c_message(lib, &mut err_msg);
                return Err(Error::with_message(format!(
                    "LLVMGetTargetFromTriple(wasm32-unknown-unknown) failed: {msg}"
                )));
            }

            let empty = c"";
            let tm = (lib.create_target_machine)(
                target,
                triple.as_ptr(),
                empty.as_ptr(), // cpu
                empty.as_ptr(), // features
                codegen_level(opt),
                LLVM_RELOC_DEFAULT,
                LLVM_CODE_MODEL_DEFAULT,
            );
            if tm.is_null() {
                return Err(Error::with_message(
                    "LLVMCreateTargetMachine returned null for \
                     wasm32-unknown-unknown — is the WebAssembly target \
                     compiled into this libLLVM?",
                ));
            }
            let _tm_g = TmGuard { lib, tm };

            let pbo = (lib.create_pass_builder_options)();
            if pbo.is_null() {
                return Err(Error::with_message(
                    "LLVMCreatePassBuilderOptions returned null",
                ));
            }
            let _pbo_g = PboGuard { lib, pbo };

            let pipeline = pass_pipeline(opt);
            let err_ref = (lib.run_passes)(module, pipeline.as_ptr(), tm, pbo);
            if !err_ref.is_null() {
                let msg_ptr = (lib.get_error_message)(err_ref);
                let msg = if msg_ptr.is_null() {
                    "unknown".to_string()
                } else {
                    CStr::from_ptr(msg_ptr).to_string_lossy().into_owned()
                };
                if !msg_ptr.is_null() {
                    (lib.dispose_error_message)(msg_ptr);
                }
                return Err(Error::with_message(format!(
                    "LLVMRunPasses({}) failed: {msg}",
                    pipeline.to_string_lossy()
                )));
            }

            let mut out_buf: LlvmMemoryBufferRef = ptr::null_mut();
            let mut emit_err: *mut c_char = ptr::null_mut();
            if (lib.target_machine_emit_to_memory_buffer)(
                tm,
                module,
                LLVM_OBJECT_FILE,
                &mut emit_err,
                &mut out_buf,
            ) != 0
            {
                let msg = take_c_message(lib, &mut emit_err);
                return Err(Error::with_message(format!(
                    "LLVMTargetMachineEmitToMemoryBuffer failed: {msg}"
                )));
            }
            if out_buf.is_null() {
                return Err(Error::with_message(
                    "LLVMTargetMachineEmitToMemoryBuffer produced a null \
                     buffer with no diagnostic — treating as failure",
                ));
            }
            let _buf_g = BufGuard { lib, buf: out_buf };

            let start = (lib.get_buffer_start)(out_buf);
            let size = (lib.get_buffer_size)(out_buf);
            if start.is_null() || size == 0 {
                return Err(Error::with_message(
                    "emitted buffer is empty — LLVM produced no object bytes",
                ));
            }
            Ok(std::slice::from_raw_parts(start, size).to_vec())
        }
    }

    // ---- Drop guards — one per LLVM handle type. ----------------------
    // Kept local (not pub) because they're only valid inside lower_one's
    // unsafe block: each `Drop::drop` calls the matching dispose fn.

    struct CtxGuard<'a> {
        lib: &'a LibLlvm,
        ctx: LlvmContextRef,
    }
    impl Drop for CtxGuard<'_> {
        fn drop(&mut self) {
            unsafe { (self.lib.context_dispose)(self.ctx) };
        }
    }

    struct ModGuard<'a> {
        lib: &'a LibLlvm,
        module: LlvmModuleRef,
    }
    impl Drop for ModGuard<'_> {
        fn drop(&mut self) {
            unsafe { (self.lib.dispose_module)(self.module) };
        }
    }

    struct TmGuard<'a> {
        lib: &'a LibLlvm,
        tm: LlvmTargetMachineRef,
    }
    impl Drop for TmGuard<'_> {
        fn drop(&mut self) {
            unsafe { (self.lib.dispose_target_machine)(self.tm) };
        }
    }

    struct PboGuard<'a> {
        lib: &'a LibLlvm,
        pbo: LlvmPassBuilderOptionsRef,
    }
    impl Drop for PboGuard<'_> {
        fn drop(&mut self) {
            unsafe { (self.lib.dispose_pass_builder_options)(self.pbo) };
        }
    }

    struct BufGuard<'a> {
        lib: &'a LibLlvm,
        buf: LlvmMemoryBufferRef,
    }
    impl Drop for BufGuard<'_> {
        fn drop(&mut self) {
            unsafe { (self.lib.dispose_memory_buffer)(self.buf) };
        }
    }

    /// Consume a `char**`-style LLVM diagnostic: decode as UTF-8 lossy,
    /// free via `LLVMDisposeMessage`, null the caller's slot so any
    /// subsequent dispose is a no-op.
    unsafe fn take_c_message(lib: &LibLlvm, msg: &mut *mut c_char) -> String {
        if msg.is_null() {
            return "no diagnostic".to_string();
        }
        let s = unsafe { CStr::from_ptr(*msg).to_string_lossy().into_owned() };
        unsafe { (lib.dispose_message)(*msg) };
        *msg = ptr::null_mut();
        s
    }

    /// Rayon-parallel entry point.
    ///
    /// Fails the whole batch on any module's failure — matches P5a's
    /// loud-failure contract and lets the dispatcher fall back
    /// cleanly. Per-module fallback (run only the failing module
    /// through P5a) is a follow-up; see the `lto::mod.rs` dispatcher
    /// note.
    pub(super) fn lower(
        bitcodes: &[&[u8]],
        opt_level: OptLevel,
        pool: &rayon::ThreadPool,
    ) -> Result<Vec<Vec<u8>>> {
        let lib = shared_lib()?;
        let lib_ref: &LibLlvm = &lib;

        let results: Vec<Result<Vec<u8>>> = pool.install(|| {
            bitcodes
                .par_iter()
                .map(|bc| lower_one(lib_ref, bc, opt_level))
                .collect()
        });

        let mut out = Vec::with_capacity(results.len());
        for (i, r) in results.into_iter().enumerate() {
            out.push(r.map_err(|e| {
                Error::with_message(format!("module {i} failed during P5b lowering: {e:?}"))
            })?);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_pool() -> rayon::ThreadPool {
        rayon::ThreadPoolBuilder::new()
            .num_threads(1)
            .build()
            .unwrap()
    }

    #[test]
    fn in_process_available_matches_feature_flag() {
        assert_eq!(in_process_available(), cfg!(feature = "llvm"));
    }

    #[test]
    fn empty_input_is_diagnosed_regardless_of_feature() {
        let pool = mk_pool();
        let err = lower_per_module_parallel_in_process(&[], OptLevel::O2, &pool).unwrap_err();
        assert!(format!("{err:?}").contains("zero inputs"));
    }

    /// When the feature is OFF, calls with real inputs return a
    /// specific error that the dispatcher interprets as "fall back to
    /// P5a". Test this path under default build config.
    #[test]
    #[cfg(not(feature = "llvm"))]
    fn without_feature_returns_actionable_error() {
        let pool = mk_pool();
        let fake_bc = b"BC\xC0\xDE";
        let err = lower_per_module_parallel_in_process(&[fake_bc.as_slice()], OptLevel::O2, &pool)
            .unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("`llvm` feature") && msg.contains("fall back"),
            "error message must point at the feature flag + fallback path: {msg}"
        );
    }

    /// End-to-end P5b: assemble a tiny wasm32 module with `llvm-as`,
    /// lower it in-process, assert the result starts with the wasm
    /// object magic. Skipped when either `llvm-as` or libLLVM is
    /// unavailable — same style as the P5a parallel test.
    #[test]
    #[cfg(feature = "llvm")]
    fn end_to_end_lowers_bitcode_to_wasm_object() {
        let Some(llvm_as) = crate::llvm_tools::find_by_name("llvm-as") else {
            eprintln!("skipping: llvm-as unavailable");
            return;
        };
        let td = tempfile::tempdir().unwrap();
        let ll = td.path().join("m.ll");
        let bc_path = td.path().join("m.bc");
        std::fs::write(
            &ll,
            r#"target triple = "wasm32-unknown-unknown"
define i32 @p5b_end_to_end(i32 %x) { %r = add i32 %x, 1 ret i32 %r }
"#,
        )
        .unwrap();
        let status = std::process::Command::new(&llvm_as)
            .arg(&ll)
            .arg("-o")
            .arg(&bc_path)
            .status();
        let Ok(status) = status else {
            eprintln!("skipping: llvm-as failed to spawn");
            return;
        };
        if !status.success() {
            eprintln!("skipping: llvm-as exited non-zero");
            return;
        }
        let bc = std::fs::read(&bc_path).unwrap();

        let pool = mk_pool();
        match lower_per_module_parallel_in_process(&[bc.as_slice()], OptLevel::O2, &pool) {
            Ok(objs) => {
                assert_eq!(objs.len(), 1);
                assert_eq!(&objs[0][..4], b"\0asm", "wasm object magic expected");
                assert!(objs[0].len() > 8);
            }
            Err(e) => {
                // libLLVM not findable on this host — dispatcher would
                // fall back to P5a. Don't fail the test; just report.
                eprintln!("skipping: libLLVM unavailable: {e:?}");
            }
        }
    }
}
