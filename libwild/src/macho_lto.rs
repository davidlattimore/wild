//! Mach-O LTO support via Apple's libLTO.dylib.
//!
//! When clang links with `-flto`, it passes `-lto_library <path>` to the linker.
//! The linker loads libLTO.dylib and uses its C API to compile LLVM bitcode
//! modules into native Mach-O object code.

use crate::bail;
use crate::error;
use crate::error::Result;
use crate::platform::Args;
use libloading::Library;
use libloading::Symbol;
use std::ffi::CStr;
use std::ffi::CString;
use std::path::Path;
use std::path::PathBuf;
use std::ptr;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;

// Opaque handles from the libLTO C API.
type LtoModuleT = *mut std::ffi::c_void;
type LtoCodeGenT = *mut std::ffi::c_void;

// lto_codegen_model enum values.
const LTO_CODEGEN_PIC_MODEL_DYNAMIC: u32 = 1;

// lto_symbol_attributes flag masks.
pub(crate) const LTO_SYMBOL_DEFINITION_MASK: u32 = 0x0000_0700;
pub(crate) const LTO_SYMBOL_DEFINITION_UNDEFINED: u32 = 0x0000_0400;

/// Holds a loaded libLTO.dylib and provides safe wrappers around its C API.
pub(crate) struct LibLto {
    _lib: Library,
    // Module functions
    module_create_from_memory: unsafe extern "C" fn(*const u8, usize) -> LtoModuleT,
    module_dispose: unsafe extern "C" fn(LtoModuleT),
    module_get_num_symbols: unsafe extern "C" fn(LtoModuleT) -> u32,
    module_get_symbol_name: unsafe extern "C" fn(LtoModuleT, u32) -> *const std::ffi::c_char,
    module_get_symbol_attribute: unsafe extern "C" fn(LtoModuleT, u32) -> u32,
    // Codegen functions
    codegen_create: unsafe extern "C" fn() -> LtoCodeGenT,
    codegen_dispose: unsafe extern "C" fn(LtoCodeGenT),
    codegen_add_module: unsafe extern "C" fn(LtoCodeGenT, LtoModuleT) -> bool,
    codegen_add_must_preserve_symbol: unsafe extern "C" fn(LtoCodeGenT, *const std::ffi::c_char),
    codegen_set_pic_model: unsafe extern "C" fn(LtoCodeGenT, u32) -> bool,
    codegen_compile: unsafe extern "C" fn(LtoCodeGenT, *mut usize) -> *const u8,
    // Error reporting
    get_error_message: unsafe extern "C" fn() -> *const std::ffi::c_char,
    // Optional: compile to file
    codegen_compile_to_file:
        unsafe extern "C" fn(LtoCodeGenT, *mut *const std::ffi::c_char) -> bool,
    // Debug options
    codegen_debug_options: unsafe extern "C" fn(LtoCodeGenT, *const std::ffi::c_char),
}

impl LibLto {
    /// Load libLTO.dylib from the given path.
    pub(crate) fn load(path: &Path) -> Result<Self> {
        // SAFETY: we're loading a well-known Apple/LLVM library.
        let lib = unsafe { Library::new(path) }
            .map_err(|e| error!("Failed to load libLTO from {}: {e}", path.display()))?;

        // SAFETY: these symbols have stable C ABI guaranteed by LLVM's lto.h.
        unsafe {
            let get = |name: &[u8]| -> Result<*const ()> {
                let sym: Symbol<*const ()> = lib
                    .get(name)
                    .map_err(|e| error!("Missing symbol in libLTO: {e}"))?;
                Ok(*sym)
            };

            Ok(Self {
                module_create_from_memory: std::mem::transmute(get(
                    b"lto_module_create_from_memory\0",
                )?),
                module_dispose: std::mem::transmute(get(b"lto_module_dispose\0")?),
                module_get_num_symbols: std::mem::transmute(get(b"lto_module_get_num_symbols\0")?),
                module_get_symbol_name: std::mem::transmute(get(b"lto_module_get_symbol_name\0")?),
                module_get_symbol_attribute: std::mem::transmute(get(
                    b"lto_module_get_symbol_attribute\0",
                )?),
                codegen_create: std::mem::transmute(get(b"lto_codegen_create\0")?),
                codegen_dispose: std::mem::transmute(get(b"lto_codegen_dispose\0")?),
                codegen_add_module: std::mem::transmute(get(b"lto_codegen_add_module\0")?),
                codegen_add_must_preserve_symbol: std::mem::transmute(get(
                    b"lto_codegen_add_must_preserve_symbol\0",
                )?),
                codegen_set_pic_model: std::mem::transmute(get(b"lto_codegen_set_pic_model\0")?),
                codegen_compile: std::mem::transmute(get(b"lto_codegen_compile\0")?),
                get_error_message: std::mem::transmute(get(b"lto_get_error_message\0")?),
                codegen_compile_to_file: std::mem::transmute(get(
                    b"lto_codegen_compile_to_file\0",
                )?),
                codegen_debug_options: std::mem::transmute(get(b"lto_codegen_debug_options\0")?),
                _lib: lib,
            })
        }
    }

    fn error_message(&self) -> String {
        unsafe {
            let ptr = (self.get_error_message)();
            if ptr.is_null() {
                "unknown LTO error".to_string()
            } else {
                CStr::from_ptr(ptr).to_string_lossy().into_owned()
            }
        }
    }

    /// Compile one or more LLVM bitcode buffers into a native Mach-O object.
    ///
    /// `inputs` is a list of (filename, bitcode_bytes) pairs.
    /// `preserve_symbols` lists symbols that must not be optimized away.
    /// `mllvm_options` are extra LLVM options from -mllvm flags.
    ///
    /// Returns the native object bytes.
    pub(crate) fn compile(
        &self,
        inputs: &[(&str, &[u8])],
        preserve_symbols: &[&[u8]],
        mllvm_options: &[String],
        object_path_lto: Option<&Path>,
    ) -> Result<Vec<u8>> {
        unsafe {
            let cg = (self.codegen_create)();
            if cg.is_null() {
                bail!("lto_codegen_create failed: {}", self.error_message());
            }

            // Set PIC model (macOS always uses dynamic PIC).
            (self.codegen_set_pic_model)(cg, LTO_CODEGEN_PIC_MODEL_DYNAMIC);

            // Pass -mllvm options.
            for opt in mllvm_options {
                if let Ok(c) = CString::new(opt.as_bytes()) {
                    (self.codegen_debug_options)(cg, c.as_ptr());
                }
            }

            // Add all bitcode modules.
            for (name, data) in inputs {
                let module = (self.module_create_from_memory)(data.as_ptr(), data.len());
                if module.is_null() {
                    (self.codegen_dispose)(cg);
                    bail!(
                        "lto_module_create_from_memory failed for {name}: {}",
                        self.error_message()
                    );
                }

                let err = (self.codegen_add_module)(cg, module);
                // add_module takes ownership of the module on success.
                if err {
                    (self.module_dispose)(module);
                    (self.codegen_dispose)(cg);
                    bail!(
                        "lto_codegen_add_module failed for {name}: {}",
                        self.error_message()
                    );
                }
            }

            // Mark symbols that must survive optimization.
            for sym in preserve_symbols {
                if let Ok(c) = CString::new(*sym) {
                    (self.codegen_add_must_preserve_symbol)(cg, c.as_ptr());
                }
            }

            // If -object_path_lto was given, compile to file.
            if let Some(path) = object_path_lto {
                let mut out_path: *const std::ffi::c_char = ptr::null();
                let err = (self.codegen_compile_to_file)(cg, &mut out_path);
                if err {
                    let msg = self.error_message();
                    (self.codegen_dispose)(cg);
                    bail!("LTO codegen failed: {msg}");
                }
                // The codegen wrote to a temp file. Copy it to the requested path,
                // then read it back as our result.
                if !out_path.is_null() {
                    let tmp = CStr::from_ptr(out_path).to_string_lossy();
                    std::fs::copy(tmp.as_ref(), path).map_err(|e| {
                        error!("Failed to copy LTO object to {}: {e}", path.display())
                    })?;
                }
                let result = std::fs::read(path).map_err(|e| {
                    error!("Failed to read LTO object from {}: {e}", path.display())
                })?;
                (self.codegen_dispose)(cg);
                return Ok(result);
            }

            // Compile in-memory.
            let mut length: usize = 0;
            let ptr = (self.codegen_compile)(cg, &mut length);
            if ptr.is_null() || length == 0 {
                let msg = self.error_message();
                (self.codegen_dispose)(cg);
                bail!("LTO codegen failed: {msg}");
            }

            let result = std::slice::from_raw_parts(ptr, length).to_vec();
            (self.codegen_dispose)(cg);
            Ok(result)
        }
    }

    /// Extract defined symbol names from a bitcode module (for preserve list).
    fn get_defined_symbol_names(&self, data: &[u8]) -> Result<Vec<Vec<u8>>> {
        let symbols = self.get_symbols(data)?;
        Ok(symbols
            .into_iter()
            .filter(|(_, attrs)| {
                let def = attrs & LTO_SYMBOL_DEFINITION_MASK;
                def != LTO_SYMBOL_DEFINITION_UNDEFINED
            })
            .map(|(name, _)| name)
            .collect())
    }

    /// Extract symbol information from a bitcode module without compiling it.
    /// Returns (name, attributes) pairs.
    pub(crate) fn get_symbols(&self, data: &[u8]) -> Result<Vec<(Vec<u8>, u32)>> {
        unsafe {
            let module = (self.module_create_from_memory)(data.as_ptr(), data.len());
            if module.is_null() {
                bail!(
                    "lto_module_create_from_memory failed: {}",
                    self.error_message()
                );
            }

            let count = (self.module_get_num_symbols)(module);
            let mut symbols = Vec::with_capacity(count as usize);
            for i in 0..count {
                let name_ptr = (self.module_get_symbol_name)(module, i);
                let attrs = (self.module_get_symbol_attribute)(module, i);
                if !name_ptr.is_null() {
                    let name = CStr::from_ptr(name_ptr).to_bytes().to_vec();
                    symbols.push((name, attrs));
                }
            }

            (self.module_dispose)(module);
            Ok(symbols)
        }
    }
}

static LTO_TEMP_COUNTER: AtomicU32 = AtomicU32::new(0);

/// Compile a single bitcode input to a native Mach-O object file.
/// Returns the path to the native object (temp file or -object_path_lto).
pub(crate) fn compile_bitcode_to_file<A: Args>(
    bitcode: &[u8],
    lto_lib_path: &Path,
    input_name: &str,
    args: &A,
) -> Result<PathBuf> {
    let lib_lto = LibLto::load(lto_lib_path)?;

    // Determine which symbols must be preserved (entry point + exports).
    let mut preserve: Vec<&[u8]> = Vec::new();
    let entry = args.entry_symbol_name(None);
    preserve.push(entry);

    // If -export_dynamic is set, preserve all defined symbols so they survive
    // LTO and can be made global by the linker.
    let all_symbols;
    if args.should_export_all_dynamic_symbols() {
        all_symbols = lib_lto.get_defined_symbol_names(bitcode)?;
        for sym in &all_symbols {
            preserve.push(sym);
        }
    }

    let object_path = if let Some(opl) = args.object_path_lto() {
        opl.to_path_buf()
    } else {
        let n = LTO_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("wild_lto_{}_{n}.o", std::process::id()))
    };

    let native_bytes =
        lib_lto.compile(&[(input_name, bitcode)], &preserve, &[], Some(&object_path))?;

    // compile_to_file writes directly; if bytes were returned, write them.
    if !object_path.exists() {
        std::fs::write(&object_path, &native_bytes).map_err(|e| {
            error!(
                "Failed to write LTO object to {}: {e}",
                object_path.display()
            )
        })?;
    }

    Ok(object_path)
}
