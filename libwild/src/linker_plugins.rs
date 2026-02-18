//! Implements support for using linker plugins that follow the GNU Gold linker plugin API. Although
//! GNU Gold is now deprecated, this API is implemented by other linkers such as GNU ld and Mold.
//! Plugins that follow the API are provided by GCC and Clang.
//!
//! See the linker plugin API docs at https://gcc.gnu.org/wiki/whopr/driver
//!
//! Note, the lifetimes in the plugin API are a bit of a pain to deal with. The API docs don't
//! actually document lifetimes at all, so it's a case of observing what actual plugins do. We end
//! up having to make quite a bit of use of thread locals in order to get state to where it needs to
//! be.

use crate::Args;
use crate::args::Input;
use crate::args::Modifiers;
use crate::bail;
use crate::elf::RawSymbolName;
use crate::error;
use crate::error::Context as _;
use crate::error::Error;
use crate::error::Result;
use crate::file_kind::FileKind;
use crate::input_data::FileId;
use crate::input_data::FileLoader;
use crate::input_data::InputRef;
use crate::layout_rules::LayoutRulesBuilder;
use crate::output_section_id::OutputSections;
use crate::platform::RawSymbolName as _;
use crate::resolution::ResolvedFile;
use crate::resolution::ResolvedGroup;
use crate::resolution::Resolver;
use crate::symbol::PreHashedSymbolName;
use crate::symbol::UnversionedSymbolName;
use crate::symbol_db::SymbolDb;
use crate::symbol_db::SymbolId;
use crate::symbol_db::SymbolIdRange;
use crate::timing_phase;
use crate::value_flags::PerSymbolFlags;
use crate::verbose_timing_phase;
use bumpalo_herd::Herd;
use colosseum::sync::Arena;
use crossbeam_utils::atomic::AtomicCell;
use libloading::Library;
use std::cell::Cell;
use std::cell::RefCell;
use std::ffi::CStr;
use std::ffi::CString;
use std::ffi::OsStr;
use std::fs::File;
use std::ops::Not as _;
use std::os::fd::AsRawFd as _;
use std::os::fd::RawFd;
use std::os::unix::ffi::OsStrExt;
use std::panic::AssertUnwindSafe;
use std::path::Path;
use std::path::PathBuf;

pub(crate) struct LinkerPlugin<'data> {
    store: Store<'data>,
    herd: &'data Herd,
    wrap_symbols: WrapSymbols<'data>,
    path: PathBuf,
}

enum Store<'data> {
    Unloaded(LoadInfo<'data>),
    Loaded(&'data mut LoadedPlugin),
}

struct LoadInfo<'data> {
    args: &'data Args,
    arena: &'data Arena<LoadedPlugin>,
}

/// Manages the lifetime of the linker plugin. Once dropped, the plugin will be deinitialised and
/// unloaded.
pub(crate) struct LoadedPlugin {
    callbacks: Callbacks,

    /// Dropping this will unload the plugin, so although we don't make use of this, we need to
    /// keep it alive until we're done.
    _lib: Library,

    version_info: Option<VersionInfo>,
}

#[derive(Debug)]
pub(crate) struct LtoInput<'data> {
    pub(crate) file_id: FileId,
    pub(crate) symbol_id_range: SymbolIdRange,
    pub(crate) input_ref: InputRef<'data>,
    pub(crate) symbols: Vec<PluginSymbol<'data>>,
    /// Set to false once symbols from this object should be ignored. This is done once LTO has
    /// been performed.
    pub(crate) enabled: bool,
}

#[derive(Debug)]
pub(crate) struct LtoInputInfo<'data> {
    input_ref: InputRef<'data>,
    symbols: Vec<PluginSymbol<'data>>,
    handle: &'data FileHandle<'data>,
}

/// Stores symbol names passed to --wrap in a form that we can pass to the linker plugin if
/// requested. Note, that this appears to only be used by the LLVM plugin. See comment on call to
/// apply_wrapped_symbol_overrides.
#[derive(Clone, Copy)]
struct WrapSymbols<'data>(&'data [*const libc::c_char]);

unsafe impl Send for WrapSymbols<'_> {}
unsafe impl Sync for WrapSymbols<'_> {}

const API_VERSION: u32 = 1;

#[derive(Debug)]
struct FileHandle<'data> {
    data: &'data [u8],

    /// This isn't known initially because we allocate file IDs later.
    file_id: AtomicCell<Option<FileId>>,
}

#[derive(Default)]
pub(crate) struct PluginOutputs {
    pub(crate) generated_inputs: Vec<Input>,
}

impl<'data> LinkerPlugin<'data> {
    pub(crate) fn from_args(
        args: &'data crate::Args,
        arena: &'data Arena<LoadedPlugin>,
        herd: &'data Herd,
    ) -> Result<Option<LinkerPlugin<'data>>> {
        match args.plugin_path.as_ref() {
            Some(path) => {
                let wrap_symbols = WrapSymbols::new(&args.wrap, herd)?;

                Ok(Some(LinkerPlugin {
                    path: PathBuf::from(&path),
                    store: Store::Unloaded(LoadInfo { args, arena }),
                    herd,
                    wrap_symbols,
                }))
            }
            None => Ok(None),
        }
    }

    pub(crate) fn process_input(
        &'_ mut self,
        input_ref: InputRef<'data>,
        file: &File,
        kind: FileKind,
    ) -> Result<Box<LtoInputInfo<'data>>> {
        verbose_timing_phase!("Linker plugin process input");

        let fd = file.as_raw_fd();

        self.claim_file(input_ref, fd)
            .transpose()
            .with_context(|| {
                format!(
                    "Input file {input_ref} contains {kind}, \
                            but the linker plugin ({self}) didn't claim it"
                )
            })
            .flatten()
    }

    /// Notify the plugin that all symbols have now been read. This will cause it to build
    /// additional object files that it will then pass to us for processing.
    pub(crate) fn all_symbols_read(
        &mut self,
        symbol_db: &mut SymbolDb<'data, crate::elf::File<'data>>,
        resolver: &mut Resolver<'data>,
        file_loader: &mut FileLoader<'data>,
        per_symbol_flags: &mut PerSymbolFlags,
        output_sections: &mut OutputSections<'data>,
        layout_rules_builder: &mut LayoutRulesBuilder<'data>,
    ) -> Result {
        // If no LTO files were activated, and we proceed with LTO, the GCC plugin tries to invoke
        // GCC with no input file, resulting in an error.
        if !has_loaded_lto_input(&resolver.resolved_groups) {
            return Ok(());
        }

        timing_phase!("Linker plugin codegen");

        let plugin_outputs = self.store.loaded()?.with_callbacks(|callbacks| {
            if let Some(cb) = callbacks.all_symbols_read {
                let ctx = AllSymbolsReadContext {
                    symbol_db,
                    resolved_groups: &resolver.resolved_groups,
                };

                ctx.set_current_while(|| cb().to_result("all_symbols_read"))?;
            }
            Ok(PLUGIN_OUTPUTS.take())
        })?;

        let plugin_loaded =
            file_loader.load_inputs(&plugin_outputs.generated_inputs, symbol_db.args, &mut None)?;

        symbol_db.add_inputs(
            per_symbol_flags,
            output_sections,
            layout_rules_builder,
            plugin_loaded,
        )?;

        resolver.resolve_symbols_and_select_archive_entries(symbol_db)?;

        symbol_db.disable_lto_inputs();

        crate::symbol_db::resolve_alternative_symbol_definitions(
            symbol_db,
            per_symbol_flags,
            &resolver.resolved_groups,
        )?;

        Ok(())
    }

    fn claim_file(
        &'_ mut self,
        input_ref: InputRef<'data>,
        fd: RawFd,
    ) -> Result<Option<Box<LtoInputInfo<'data>>>> {
        self.store.loaded()?.with_callbacks(|callbacks| {
            let data = input_ref.data();
            let offset = input_ref
                .entry
                .as_ref()
                .map_or(0, |entry| entry.start_offset as u64);

            let cb = callbacks
                .claim_file_hook
                .context("Missing claim file hook")?;

            let mut ctx = ClaimContext {
                symbols: Vec::new(),
                herd: self.herd,
                wrap_symbols: self.wrap_symbols,
            };

            let handle = FileHandle {
                data,
                file_id: AtomicCell::new(None),
            };

            let handle = self.herd.get().alloc(handle);

            let name = CString::new(input_ref.file.filename.as_os_str().as_encoded_bytes())?;
            let file = LdPluginInputFile {
                name: name.as_ptr(),
                fd,
                offset: offset as libc::off_t,
                file_size: data.len() as libc::off_t,
                // Whatever we store here needs to be valid for 'data, since the plugin might pass
                // this back to us at a later point. e.g. get_symbols does so.
                handle: handle as *const FileHandle as *mut libc::c_void,
            };

            let mut claimed = 0;

            ctx.set_current_while(|| {
                unsafe { cb(&file as *const LdPluginInputFile, &mut claimed as *mut i32) }
                    .to_result("claim_file")
            })?;

            check_for_errors()?;

            if claimed != 1 {
                return Ok(None);
            }

            Ok(Some(Box::new(LtoInputInfo {
                input_ref,
                symbols: ctx.symbols,
                handle,
            })))
        })
    }

    pub(crate) fn is_initialised(&self) -> bool {
        matches!(self.store, Store::Loaded(_))
    }
}

fn has_loaded_lto_input(resolved_groups: &[ResolvedGroup]) -> bool {
    resolved_groups.iter().any(|group| {
        group
            .files
            .iter()
            .any(|file| matches!(file, ResolvedFile::LtoInput(_)))
    })
}

impl<'data> WrapSymbols<'data> {
    fn new(wrap: &[String], herd: &'data Herd) -> Result<Self> {
        if wrap.is_empty() {
            return Ok(Self(&[]));
        }

        let allocator = herd.get();

        let mut wrap_args = Vec::new();
        for w in wrap {
            let w_cstring = CString::new(w.as_bytes())?;
            wrap_args
                .push(allocator.alloc_slice_copy(w_cstring.as_bytes()).as_ptr()
                    as *const libc::c_char);
        }
        Ok(Self(&*allocator.alloc_slice_copy(wrap_args.as_slice())))
    }
}

impl LoadedPlugin {
    fn new(plugin_path: &Path, args: &Args) -> Result<LoadedPlugin> {
        timing_phase!("Load linker plugin");

        if cfg!(target_feature = "crt-static") {
            bail!(
                "Linker plugins cannot be used when Wild was built as a statically linked binary"
            );
        }

        // Safety: Truthfully, we don't control the file we're loading. The user gave it to us and
        // there's nothing we can do to guarantee that loading and running it won't trigger UB. The
        // best we can say is that we at least try to conform to the expected plugin API.
        let lib = unsafe { Library::new(plugin_path) }.context("Failed to open linker plugin")?;

        timing_phase!("Initialise linker plugin");

        // Clear any existing state in case this thread previously made it part way through
        // initialisation.
        CALLBACKS.take();

        let onload_fn: libloading::Symbol<unsafe extern "C" fn(*mut LdPluginTv)> =
            unsafe { lib.get(b"onload") }
                .context("Failed to get `onload` function from linker plugin")?;

        let output_name = CString::new(args.output.as_os_str().as_encoded_bytes())?;

        let output_kind = if args.should_output_executable {
            match args.relocation_model {
                crate::args::RelocationModel::NonRelocatable => OutputFileType::Exec,
                crate::args::RelocationModel::Relocatable => OutputFileType::Pie,
            }
        } else {
            OutputFileType::Dyn
        };

        let mut transfer_vector = Vec::new();

        for arg in &args.plugin_args {
            transfer_vector.push(LdPluginTv::c_str(Tag::Option, arg));
        }

        transfer_vector.push(LdPluginTv::value(Tag::ApiVersion, API_VERSION as usize));
        transfer_vector.push(LdPluginTv::value(Tag::LinkerOutput, output_kind as usize));
        transfer_vector.push(LdPluginTv::c_str(Tag::OutputName, &output_name));
        transfer_vector.push(LdPluginTv::fn_ptr1(
            Tag::RegisterClaimFileHook,
            register_claim_file_hook,
        ));
        transfer_vector.push(LdPluginTv::fn_ptr1(
            Tag::RegisterCleanupHook,
            register_cleanup_hook,
        ));
        transfer_vector.push(LdPluginTv::fn_ptr1(
            Tag::RegisterAllSymbolsReadHook,
            register_all_symbols_read_hook,
        ));
        transfer_vector.push(LdPluginTv::fn_ptr6(Tag::GetApiVersion, get_api_version));
        transfer_vector.push(LdPluginTv::fn_ptr2(Tag::Message, message));
        transfer_vector.push(LdPluginTv::fn_ptr3(Tag::AddSymbols, add_symbols));
        transfer_vector.push(LdPluginTv::fn_ptr3(Tag::AddSymbolsV2, add_symbols));
        transfer_vector.push(LdPluginTv::fn_ptr3(Tag::GetSymbolsV3, get_symbols_v3));
        transfer_vector.push(LdPluginTv::fn_ptr1(Tag::AddInputFile, add_input_file));
        transfer_vector.push(LdPluginTv::fn_ptr1(Tag::AddInputLibrary, add_input_library));

        transfer_vector.push(LdPluginTv::fn_ptr0(
            Tag::GetSymbols,
            unsupported_api_version,
        ));
        transfer_vector.push(LdPluginTv::fn_ptr0(
            Tag::GetSymbolsV2,
            unsupported_api_version,
        ));

        // These don't seem to be used by the GCC plugin but are used by the clang (LLVM) plugin.
        transfer_vector.push(LdPluginTv::fn_ptr2(Tag::GetView, get_view));
        transfer_vector.push(LdPluginTv::fn_ptr2(Tag::GetWrapSymbols, get_wrap_symbols));
        transfer_vector.push(LdPluginTv::fn_ptr2(Tag::GetInputFile, get_input_file));
        transfer_vector.push(LdPluginTv::fn_ptr1(
            Tag::ReleaseInputFile,
            release_input_file,
        ));

        transfer_vector.push(LdPluginTv::value(Tag::Null, 0));

        unsafe { onload_fn(transfer_vector.as_mut_ptr()) };

        let callbacks = CALLBACKS.take();
        let version_info = VERSION_INFO.take();

        Ok(LoadedPlugin {
            _lib: lib,
            callbacks,
            version_info,
        })
    }

    /// Calls `f` with our callbacks. Checks for errors after `f` completes. We require an exclusive
    /// reference to self because the plugins callbacks aren't always threadsafe. The GCC plugin
    /// appears to be threadsafe, however the clang/LLVM plugin isn't, at least not as of clang 20.
    /// We could instead wrap the callbacks in a mutex to ensure that only one thread makes use of
    /// the callbacks at a time. In practice however, this doesn't help, since if multiple threads
    /// ask the plugin to claim files at once, then the claim order ends up non-deterministic which
    /// appears to cause the plugin to give non-deterministic output.
    fn with_callbacks<T>(&mut self, f: impl FnOnce(&mut Callbacks) -> Result<T>) -> Result<T> {
        let r = match f(&mut self.callbacks) {
            Ok(v) => v,
            Err(error) => {
                // If we encountered an error in a callback, that should take precedence over any
                // error reported by the linker plugin, since it will likely just be reporting an
                // error since we returned an error code.
                if let Some(error) = ERROR.take() {
                    return Err(error);
                }
                // If the plugin reported an error to us, then attach that as context.
                if let Some(message) = ERROR_MESSAGE.take() {
                    return Err(error).with_context(|| format!("Linker plugin error: {message}"));
                }
                return Err(error);
            }
        };
        // If the plugin reported an error to us, but then returned a successful return code, still
        // propagate the error.
        if let Some(error) = ERROR_MESSAGE.take() {
            bail!("Linker plugin error: {error}");
        }
        Ok(r)
    }
}

/// Checks for any errors reported by the linker plugin during a callback. Should be called after
/// each callback.
fn check_for_errors() -> Result {
    if let Some(message) = ERROR_MESSAGE.take() {
        bail!("Error from linker plugin: {message}");
    }
    Ok(())
}

type ClaimFileHook = unsafe extern "C" fn(*const LdPluginInputFile, *mut libc::c_int) -> Status;
type CleanupHook = extern "C" fn() -> Status;
type AllSymbolsReadHook = extern "C" fn() -> Status;

#[derive(Default)]
struct Callbacks {
    claim_file_hook: Option<ClaimFileHook>,
    cleanup_hook: Option<CleanupHook>,
    all_symbols_read: Option<AllSymbolsReadHook>,
}

struct VersionInfo {
    identifier: Vec<u8>,
    version: Vec<u8>,
}

impl<'data> LtoInputInfo<'data> {
    pub(crate) fn num_symbols(&self) -> usize {
        self.symbols.len()
    }

    pub(crate) fn into_input_object(
        self,
        file_id: FileId,
        symbol_id_range: SymbolIdRange,
    ) -> LtoInput<'data> {
        self.handle.file_id.store(Some(file_id));

        LtoInput {
            file_id,
            symbol_id_range,
            input_ref: self.input_ref,
            symbols: self.symbols,
            enabled: true,
        }
    }
}

impl<'data> LtoInput<'data> {
    pub(crate) fn symbol_name(
        &self,
        symbol_id: crate::symbol_db::SymbolId,
    ) -> UnversionedSymbolName<'data> {
        let local_index = self.symbol_id_range.id_to_offset(symbol_id);
        self.symbols[local_index].name
    }

    pub(crate) fn symbol_visibility(
        &self,
        symbol_id: crate::symbol_db::SymbolId,
    ) -> crate::symbol_db::Visibility {
        let local_index = self.symbol_id_range.id_to_offset(symbol_id);
        crate::symbol_db::Visibility::from_elf_st_visibility(self.symbols[local_index].visibility)
    }

    pub(crate) fn symbols_iter(&self) -> impl Iterator<Item = (SymbolId, &PluginSymbol<'data>)> {
        self.symbol_id_range.into_iter().zip(self.symbols.iter())
    }

    pub(crate) fn symbol_properties_display(
        &'_ self,
        symbol_id: SymbolId,
    ) -> SymbolPropertiesDisplay<'_> {
        SymbolPropertiesDisplay(&self.symbols[self.symbol_id_range.id_to_offset(symbol_id)])
    }

    pub(crate) fn is_optional(&self) -> bool {
        self.input_ref.has_archive_semantics()
    }
}

pub(crate) struct SymbolPropertiesDisplay<'data>(&'data PluginSymbol<'data>);

// Some APIs don't let us pass along a pointer to our own data, so we need to store our state in
// thread-locals.
thread_local! {
    static CALLBACKS: RefCell<Callbacks> = const { RefCell::new(Callbacks::new()) };
    static VERSION_INFO: Cell<Option<VersionInfo>> = const { Cell::new(None) };
    static PLUGIN_OUTPUTS: RefCell<PluginOutputs> = const { RefCell::new(PluginOutputs::new()) };
    static ERROR: RefCell<Option<Error>>  = const { RefCell::new(None) };
    static ERROR_MESSAGE: RefCell<Option<String>> = const { RefCell::new(None) };

    // Holds a ClaimContext. We store this as a void pointer since the actual type has non-static
    // lifetimes that we wouldn't be able to store here.
    static CLAIM_CONTEXT: Cell<*mut libc::c_void> = const { Cell::new(std::ptr::null_mut()) };

    // Same thing, but this one holds an AllSymbolsReadContext.
    static ALL_SYMBOLS_READ_CONTEXT: Cell<*const libc::c_void> = const { Cell::new(std::ptr::null()) };
}

#[repr(C)]
struct LdPluginTv {
    /// Obtained from casting a `Tag`.
    tag: u32,

    /// This is either a pointer or a numeric value depending on the tag.
    value: usize,
}

impl LdPluginTv {
    fn value(tag: Tag, value: usize) -> Self {
        Self {
            tag: tag as u32,
            value,
        }
    }

    fn c_str(tag: Tag, value: &CStr) -> Self {
        Self {
            tag: tag as u32,
            value: value.as_ptr() as usize,
        }
    }

    fn fn_ptr0<RET>(tag: Tag, value: extern "C" fn() -> RET) -> Self {
        Self {
            tag: tag as u32,
            value: value as *const fn() -> RET as usize,
        }
    }

    fn fn_ptr1<P1, RET>(tag: Tag, value: extern "C" fn(P1) -> RET) -> Self {
        Self {
            tag: tag as u32,
            value: value as *const fn(P1) -> RET as usize,
        }
    }

    fn fn_ptr2<P1, P2, RET>(tag: Tag, value: extern "C" fn(P1, P2) -> RET) -> Self {
        Self {
            tag: tag as u32,
            value: value as *const fn(P1, P2) -> RET as usize,
        }
    }

    fn fn_ptr3<P1, P2, P3, RET>(tag: Tag, value: extern "C" fn(P1, P2, P3) -> RET) -> Self {
        Self {
            tag: tag as u32,
            value: value as *const fn(P1, P2, P3) -> RET as usize,
        }
    }

    fn fn_ptr6<P1, P2, P3, P4, P5, P6, RET>(
        tag: Tag,
        value: extern "C" fn(P1, P2, P3, P4, P5, P6) -> RET,
    ) -> Self {
        Self {
            tag: tag as u32,
            value: value as *const fn(P1, P2, P3, P4, P5, P6) -> RET as usize,
        }
    }
}

#[allow(dead_code)]
enum Tag {
    Null = 0,
    ApiVersion = 1,
    GoldVersion = 2,
    LinkerOutput = 3,
    Option = 4,
    RegisterClaimFileHook = 5,
    RegisterAllSymbolsReadHook = 6,
    RegisterCleanupHook = 7,
    AddSymbols = 8,
    GetSymbols = 9,
    AddInputFile = 10,
    Message = 11,
    GetInputFile = 12,
    ReleaseInputFile = 13,
    AddInputLibrary = 14,
    OutputName = 15,
    SetExtraLibraryPath = 16,
    GnuLdVersion = 17,
    GetView = 18,
    GetInputSectionCount = 19,
    GetInputSectionType = 20,
    GetInputSectionName = 21,
    GetInputSectionContents = 22,
    UpdateSectionOrder = 23,
    AllowSectionOrdering = 24,
    GetSymbolsV2 = 25,
    AllowUniqueSegmentForSections = 26,
    UniqueSegmentForSections = 27,
    GetSymbolsV3 = 28,
    GetInputSectionAlignment = 29,
    GetInputSectionSize = 30,
    RegisterNewInputHook = 31,
    GetWrapSymbols = 32,
    AddSymbolsV2 = 33,
    GetApiVersion = 34,
    RegisterClaimFileHookV2 = 35,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MessageLevel {
    Info = 0,
    Warning = 1,
    Error = 2,
    Fatal = 3,
}

impl MessageLevel {
    fn from_raw(level: i32) -> Option<Self> {
        match level {
            0 => Some(MessageLevel::Info),
            1 => Some(MessageLevel::Warning),
            2 => Some(MessageLevel::Error),
            3 => Some(MessageLevel::Fatal),
            _ => None,
        }
    }
}

#[allow(dead_code)]
#[derive(Clone, Copy)]
#[repr(C)]
enum Status {
    Ok = 0,
    NoSyms,
    BadHandle,
    Err,
}

#[allow(dead_code)]
enum OutputFileType {
    Rel = 0,
    Exec = 1,
    Dyn = 2,
    Pie = 3,
}

#[repr(C)]
struct LdPluginInputFile {
    name: *const libc::c_char,
    fd: libc::c_int,
    offset: libc::off_t,
    file_size: libc::off_t,
    handle: *mut libc::c_void,
}

#[allow(dead_code)]
#[derive(Debug)]
enum PluginSymbolResolution {
    Unknown = 0,
    Undef,
    PrevailingDef,
    PrevailingDefIronly,
    PreemptedReg,
    PreemptedIr,
    ResolvedIr,
    ResolvedExec,
    ResolvedDyn,
    PrevailingDefIronlyExp,
}

#[derive(Debug)]
pub(crate) struct PluginSymbol<'data> {
    pub(crate) name: UnversionedSymbolName<'data>,
    pub(crate) version: Option<&'data [u8]>,
    pub(crate) visibility: u8,
    pub(crate) kind: Option<SymbolKind>,
    pub(crate) size: u64,
}

#[repr(C)]
struct RawPluginSymbol {
    name: *const libc::c_char,
    version: *const libc::c_char,
    def: libc::c_char,
    symbol_type: libc::c_char,
    section_kind: libc::c_char,
    unused: libc::c_char,
    visibility: libc::c_int,
    size: u64,
    comdat_key: *const libc::c_char,
    resolution: libc::c_int,
}

unsafe impl Sync for RawPluginSymbol {}
unsafe impl Send for RawPluginSymbol {}

extern "C" fn register_claim_file_hook(cb: ClaimFileHook) -> Status {
    CALLBACKS.with_borrow_mut(|c| c.claim_file_hook = Some(cb));
    Status::Ok
}

extern "C" fn register_cleanup_hook(cb: CleanupHook) -> Status {
    CALLBACKS.with_borrow_mut(|c| c.cleanup_hook = Some(cb));
    Status::Ok
}

extern "C" fn register_all_symbols_read_hook(cb: AllSymbolsReadHook) -> Status {
    CALLBACKS.with_borrow_mut(|c| c.all_symbols_read = Some(cb));
    Status::Ok
}

extern "C" fn get_api_version(
    plugin_identifier: *const libc::c_char,
    plugin_version: *const libc::c_char,
    _minimal_version: libc::c_int,
    _maximal_version: libc::c_int,
    _linker_identifier: *mut *const libc::c_char,
    _linker_version: *mut *const libc::c_char,
) -> libc::c_int {
    if !plugin_identifier.is_null() && !plugin_version.is_null() {
        let identifier = unsafe { CStr::from_ptr(plugin_identifier) };
        let version = unsafe { CStr::from_ptr(plugin_version) };
        let version_info = VersionInfo {
            identifier: identifier.to_bytes().to_owned(),
            version: version.to_bytes().to_owned(),
        };
        VERSION_INFO.replace(Some(version_info));
    }

    API_VERSION as libc::c_int
}

extern "C" fn unsupported_api_version() -> Status {
    ERROR_MESSAGE.replace(Some(
        "Compiler plugin uses an older, unsupported version of the API".to_owned(),
    ));
    Status::Err
}

extern "C" fn add_symbols(
    _handle: *const libc::c_void,
    num_symbols: libc::c_int,
    symbols: *const RawPluginSymbol,
) -> Status {
    catch_panics(|| {
        ClaimContext::with_current(|ctx| {
            let raw_symbols = unsafe { std::slice::from_raw_parts(symbols, num_symbols as usize) };

            // Unfortunately we need to copy the symbol info that the plugin gives us because it
            // doesn't keep it alive for long enough.
            let arena = ctx.herd.get();
            ctx.symbols = raw_symbols
                .iter()
                .map(|sym| PluginSymbol {
                    name: UnversionedSymbolName::new(
                        arena.alloc_slice_copy(unsafe { CStr::from_ptr(sym.name) }.to_bytes()),
                    ),
                    version: sym.version.is_null().not().then(|| {
                        &*arena.alloc_slice_copy(unsafe { CStr::from_ptr(sym.version) }.to_bytes())
                    }),
                    kind: sym.kind(),
                    visibility: sym.visibility as u8,
                    size: sym.size,
                })
                .collect();

            Status::Ok
        })
    })
}

extern "C" fn get_symbols_v3(
    handle: *const libc::c_void,
    num_symbols: libc::c_int,
    symbols: *mut RawPluginSymbol,
) -> Status {
    catch_panics(|| {
        AllSymbolsReadContext::with_current(|ctx| {
            let handle = unsafe { &*(handle as *const FileHandle) };

            let Some(file_id) = handle.file_id.load() else {
                panic!("get_symbols_v3 called without first supplying FileId");
            };
            let ResolvedFile::LtoInput(file) =
                &ctx.resolved_groups[file_id.group()].files[file_id.file()]
            else {
                // An archive entry that we decided not to load.
                return Status::NoSyms;
            };

            if num_symbols == 0 {
                return Status::Ok;
            }

            let symbols = unsafe { std::slice::from_raw_parts_mut(symbols, num_symbols as usize) };

            let symbol_id_range = file.symbol_id_range;

            for sym in symbols.iter_mut() {
                let resolution = get_symbol_resolution(sym, ctx.symbol_db, symbol_id_range);
                sym.resolution = resolution as i32;
            }

            Status::Ok
        })
    })
}

fn get_symbol_resolution<'data>(
    sym: &mut RawPluginSymbol,
    symbol_db: &SymbolDb<'data, crate::elf::File<'data>>,
    symbol_id_range: SymbolIdRange,
) -> PluginSymbolResolution {
    // It'd be nice if we didn't have to do hashmap lookups for all the symbols again, since we
    // effectively did that when the symbols were added. We could do that if the plugin provided us
    // with the index of the symbol in the list of symbols that it passed to add_symbols, but
    // unfortunately it doesn't give us that information.
    let name = unsafe { CStr::from_ptr(sym.name) }.to_bytes();
    let mut raw_name = RawSymbolName::parse(name);
    if !sym.version.is_null() {
        raw_name.version_name = Some(unsafe { CStr::from_ptr(sym.version) }.to_bytes());
    }
    let symbol_id = symbol_db
        .get(&PreHashedSymbolName::from_raw(&raw_name), true)
        .map(|id| symbol_db.definition(id));

    let Some(symbol_id) = symbol_id else {
        return PluginSymbolResolution::Undef;
    };

    if symbol_id.is_undefined() {
        PluginSymbolResolution::Undef
    } else if sym.is_undefined() {
        let defining_file = symbol_db.file(symbol_db.file_id_for_symbol(symbol_id));

        match defining_file {
            crate::grouping::SequencedInput::LtoInput(_) => PluginSymbolResolution::ResolvedIr,
            crate::grouping::SequencedInput::Object(obj) => {
                if obj.is_dynamic() {
                    PluginSymbolResolution::ResolvedDyn
                } else {
                    PluginSymbolResolution::ResolvedExec
                }
            }
            _ => PluginSymbolResolution::ResolvedExec,
        }
    } else if symbol_id_range.contains(symbol_id) {
        // TODO: Distinguish based on kinds of references.
        PluginSymbolResolution::PrevailingDef
    } else {
        let defining_file = symbol_db.file(symbol_db.file_id_for_symbol(symbol_id));
        match defining_file {
            crate::grouping::SequencedInput::LtoInput(_) => PluginSymbolResolution::PreemptedIr,
            _ => PluginSymbolResolution::PreemptedReg,
        }
    }
}

// We don't currently implement this. The LLVM plugin gives an error if we don't define it, but then
// it doesn't appear to actually call it. Or maybe we just haven't found a test case that causes it
// to be called.
extern "C" fn get_input_file(
    _handle: *const libc::c_void,
    _file: *mut LdPluginInputFile,
) -> Status {
    Status::Err
}

extern "C" fn release_input_file(_handle: *const libc::c_void) -> Status {
    Status::Err
}

extern "C" fn get_view(
    handle: *const libc::c_void,
    view_pointer: *mut *const libc::c_void,
) -> Status {
    catch_panics(|| {
        if handle.is_null() {
            return Status::Err;
        }
        let handle = unsafe { &*(handle as *const FileHandle) };
        unsafe { view_pointer.write(handle.data.as_ptr() as *const libc::c_void) };
        Status::Ok
    })
}

extern "C" fn get_wrap_symbols(
    num_symbols: *mut u64,
    wrap_symbols_list: *mut *const *const libc::c_char,
) -> Status {
    catch_panics(|| {
        ClaimContext::with_current(|ctx| {
            unsafe {
                wrap_symbols_list.write(ctx.wrap_symbols.0.as_ptr());
                num_symbols.write(ctx.wrap_symbols.0.len() as u64);
            }
            Status::Ok
        })
    })
}

extern "C" fn add_input_file(path: *const libc::c_char) -> Status {
    catch_panics(|| {
        let path = unsafe { CStr::from_ptr(path) };
        let path = OsStr::from_bytes(path.to_bytes());
        let path = Box::from(Path::new(path));
        PLUGIN_OUTPUTS.with_borrow_mut(|state| {
            state.generated_inputs.push(Input {
                spec: crate::args::InputSpec::File(path),
                search_first: None,
                modifiers: Modifiers {
                    temporary: true,
                    ..Default::default()
                },
            });
        });
        Status::Ok
    })
}

extern "C" fn add_input_library(lib_name: *const libc::c_char) -> Status {
    let lib_name = unsafe { CStr::from_ptr(lib_name) };
    let Ok(lib_name) = lib_name.to_str() else {
        ERROR.replace(Some(error!(
            "Linker plugin added library name that wasn't valid UTF-8: `{}`",
            lib_name.to_string_lossy()
        )));
        return Status::Err;
    };

    PLUGIN_OUTPUTS.with_borrow_mut(|state| {
        state.generated_inputs.push(Input {
            spec: crate::args::InputSpec::Lib(Box::from(lib_name)),
            search_first: None,
            modifiers: Modifiers {
                as_needed: true,
                ..Default::default()
            },
        });
    });

    Status::Ok
}

/// This function is called when the plugin wants to emit a message. It's supposed to accept varargs
/// similar to printf. Unfortunately that's not exactly easy for us to do, so we just report the
/// format string.
extern "C" fn message(level: libc::c_int, format: *const libc::c_char) -> Status {
    catch_panics(|| {
        let Some(level) = MessageLevel::from_raw(level) else {
            return Status::Err;
        };

        let format = unsafe { CStr::from_ptr(format) };

        if level == MessageLevel::Error || level == MessageLevel::Fatal {
            println!("Linker plugin {level}: {}", format.to_string_lossy());
            ERROR_MESSAGE.replace(Some(format.to_string_lossy().to_string()));
        } else {
            println!("Linker plugin {level}: {}", format.to_string_lossy());
        }

        Status::Ok
    })
}

/// Runs `body`, catching any panics. In the case of a panic, the return status is changed to an
/// error, otherwise the return status returned by `body` is passed through. This should be called
/// from all non-trivial hooks in order to ensure that we don't try to propagate a panic back into
/// the linker-plugin which would be undefined behaviour.
fn catch_panics(body: impl FnOnce() -> Status) -> Status {
    match std::panic::catch_unwind(AssertUnwindSafe(body)) {
        Ok(status) => status,
        Err(_) => {
            ERROR_MESSAGE.replace(Some("Panic in plugin callback".to_owned()));
            Status::Err
        }
    }
}

struct ClaimContext<'data> {
    symbols: Vec<PluginSymbol<'data>>,
    herd: &'data Herd,
    wrap_symbols: WrapSymbols<'data>,
}

impl ClaimContext<'_> {
    fn with_current(cb: impl FnOnce(&mut ClaimContext) -> Status) -> Status {
        let ptr = CLAIM_CONTEXT.get();
        if ptr.is_null() {
            ERROR_MESSAGE.set(Some("Tried to obtain ClaimContext when not set".to_owned()));
            return Status::Err;
        };
        let ctx = unsafe { &mut *(ptr as *mut ClaimContext) };
        cb(ctx)
    }

    fn set_current_while<R>(&mut self, cb: impl FnOnce() -> R) -> R {
        CLAIM_CONTEXT.set(self as *mut _ as *mut libc::c_void);
        let r = cb();
        CLAIM_CONTEXT.take();
        r
    }
}

struct AllSymbolsReadContext<'data> {
    symbol_db: &'data SymbolDb<'data, crate::elf::File<'data>>,
    resolved_groups: &'data [ResolvedGroup<'data>],
}

impl AllSymbolsReadContext<'_> {
    fn with_current(cb: impl FnOnce(&mut AllSymbolsReadContext) -> Status) -> Status {
        let ptr = ALL_SYMBOLS_READ_CONTEXT.get();
        if ptr.is_null() {
            ERROR_MESSAGE.set(Some(
                "Tried to obtain AllSymbolsReadContext when not set".to_owned(),
            ));
            return Status::Err;
        };
        let ctx = unsafe { &mut *(ptr as *mut AllSymbolsReadContext) };
        cb(ctx)
    }

    fn set_current_while<R>(&self, cb: impl FnOnce() -> R) -> R {
        ALL_SYMBOLS_READ_CONTEXT.set(self as *const AllSymbolsReadContext as *const libc::c_void);
        let r = cb();
        ALL_SYMBOLS_READ_CONTEXT.take();
        r
    }
}

impl Drop for LoadedPlugin {
    fn drop(&mut self) {
        let _ = self.with_callbacks(|callbacks| {
            if let Some(hook) = callbacks.cleanup_hook {
                hook();
            }
            Ok(())
        });
    }
}

impl Status {
    fn to_result(self, context: &str) -> Result {
        match self {
            Status::Ok => Ok(()),
            Status::NoSyms => bail!("{context}: NoSyms"),
            Status::BadHandle => bail!("{context}: BadHandle"),
            Status::Err => bail!("{context}: Err"),
        }
    }
}

impl RawPluginSymbol {
    fn kind(&self) -> Option<SymbolKind> {
        match self.def {
            0 => Some(SymbolKind::Def),
            1 => Some(SymbolKind::WeakDef),
            2 => Some(SymbolKind::Undef),
            3 => Some(SymbolKind::WeakUndef),
            4 => Some(SymbolKind::Common),
            _ => None,
        }
    }

    fn is_undefined(&self) -> bool {
        !self.kind().is_some_and(|kind| kind.is_definition())
    }
}

impl PluginSymbol<'_> {
    pub(crate) fn is_definition(&self) -> bool {
        self.kind.is_some_and(|kind| kind.is_definition())
    }
}

impl std::fmt::Display for MessageLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            MessageLevel::Info => "message",
            MessageLevel::Warning => "warning",
            MessageLevel::Error => "error",
            MessageLevel::Fatal => "fatal error",
        };
        std::fmt::Display::fmt(message, f)
    }
}

impl std::fmt::Display for SymbolPropertiesDisplay<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LTO ")?;
        if let Some(kind) = self.0.kind {
            write!(f, "{kind:?}")?;
        } else {
            write!(f, "UNKNOWN")?;
        }
        Ok(())
    }
}

impl std::fmt::Display for LtoInput<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LTO input `{}`", self.input_ref)
    }
}

impl PluginOutputs {
    const fn new() -> Self {
        Self {
            generated_inputs: Vec::new(),
        }
    }
}

impl Callbacks {
    const fn new() -> Self {
        Self {
            claim_file_hook: None,
            cleanup_hook: None,
            all_symbols_read: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SymbolKind {
    Def = 0,
    WeakDef = 1,
    Undef = 2,
    WeakUndef = 3,
    Common = 4,
}

impl std::fmt::Display for LinkerPlugin<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.store {
            Store::Unloaded(_) => write!(f, "Unloaded plugin")?,
            Store::Loaded(loaded_plugin) => {
                if let Some(version_info) = loaded_plugin.version_info.as_ref() {
                    std::fmt::Display::fmt(version_info, f)?;
                    write!(f, " ")?;
                }
            }
        }
        write!(f, "({})", self.path.display())?;
        Ok(())
    }
}

impl std::fmt::Display for VersionInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} version {}",
            String::from_utf8_lossy(&self.identifier),
            String::from_utf8_lossy(&self.version)
        )
    }
}

impl SymbolKind {
    fn is_definition(self) -> bool {
        matches!(
            self,
            SymbolKind::Def | SymbolKind::WeakDef | SymbolKind::Common
        )
    }
}

impl<'data> Store<'data> {
    fn loaded(&mut self) -> Result<&mut LoadedPlugin> {
        match self {
            Store::Unloaded(load_info) => {
                // Unwrap can't fail because we checked previously that there was a plugin path.
                let path = Path::new(load_info.args.plugin_path.as_ref().unwrap());

                *self = Store::Loaded(load_info.arena.alloc(
                    LoadedPlugin::new(path, load_info.args).with_context(|| {
                        format!("Failed to initialise linker plugin `{}`", path.display())
                    })?,
                ));
                let Store::Loaded(loaded) = self else {
                    unreachable!();
                };
                Ok(*loaded)
            }
            Store::Loaded(loaded_plugin) => Ok(*loaded_plugin),
        }
    }
}
