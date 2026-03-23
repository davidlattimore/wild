//! PE/COFF-specific linker arguments and parsing implementation to match MSVC-style linkers.

use super::ArgumentParser;
use super::Input;
use super::InputSpec;
use super::Modifiers;
use crate::arch::Architecture;
use crate::bail;
use crate::error::Result;
use std::num::NonZeroUsize;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsSubsystem {
    Console,
    Windows,
    Native,
    Posix,
    BootApplication,
    EfiApplication,
    EfiBootServiceDriver,
    EfiRom,
    EfiRuntimeDriver,
}

/// PE/COFF-specific linker arguments.
#[derive(Debug)]
pub struct PeArgs {
    pub(crate) common: super::CommonArgs,

    pub(crate) arch: Architecture,
    pub(crate) lib_search_path: Vec<Box<Path>>,
    pub(crate) output: Arc<Path>,

    // Windows-specific fields
    pub(crate) base_address: Option<u64>,
    pub(crate) subsystem: Option<WindowsSubsystem>,
    pub(crate) heap_size: Option<u64>,
    pub(crate) stack_size: Option<u64>,
    pub(crate) is_dll: bool,
    pub(crate) debug_info: bool,
    pub(crate) def_file: Option<PathBuf>,
    pub(crate) import_lib: Option<PathBuf>,
    pub(crate) manifest_file: Option<PathBuf>,
    pub(crate) map_file: Option<PathBuf>,
    pub(crate) pdb_file: Option<PathBuf>,
    pub(crate) version: Option<String>,
    pub(crate) large_address_aware: bool,
    pub(crate) dynamic_base: bool,
    pub(crate) nx_compat: bool,
    pub(crate) terminal_server_aware: bool,
    pub(crate) high_entropy_va: bool,
    pub(crate) no_default_libs: Vec<String>,
    pub(crate) ignore_all_default_libs: bool,
    pub(crate) entry: Option<String>,
}

impl Default for PeArgs {
    fn default() -> Self {
        Self {
            common: super::CommonArgs::default(),
            arch: Architecture::X86_64,
            lib_search_path: Vec::new(),
            output: Arc::from(Path::new("a.exe")),
            base_address: None,
            subsystem: None,
            heap_size: None,
            stack_size: None,
            is_dll: false,
            debug_info: false,
            def_file: None,
            import_lib: None,
            manifest_file: None,
            map_file: None,
            pdb_file: None,
            version: None,
            large_address_aware: true,
            dynamic_base: true,
            nx_compat: true,
            terminal_server_aware: true,
            high_entropy_va: true,
            no_default_libs: Vec::new(),
            ignore_all_default_libs: false,
            entry: None,
        }
    }
}

impl PeArgs {
    pub(crate) fn new() -> crate::error::Result<Self> {
        Ok(Self {
            common: super::CommonArgs::from_env()?,
            ..Default::default()
        })
    }

    /// Check if a specific library should be ignored due to /NODEFAULTLIB
    pub fn should_ignore_default_lib(&self, lib_name: &str) -> bool {
        self.ignore_all_default_libs || self.no_default_libs.contains(&lib_name.to_string())
    }

    /// Get the list of specifically ignored default libraries
    pub fn ignored_default_libs(&self) -> &[String] {
        &self.no_default_libs
    }

    /// Check if all default libraries should be ignored
    pub fn ignores_all_default_libs(&self) -> bool {
        self.ignore_all_default_libs
    }
}

impl crate::platform::Args for PeArgs {
    fn parse<S: AsRef<str>, I: Iterator<Item = S>>(&mut self, input: I) -> Result {
        super::pe::parse(self, input)
    }

    fn should_strip_debug(&self) -> bool {
        false
    }

    fn should_strip_all(&self) -> bool {
        false
    }

    fn entry_symbol_name<'a>(&'a self, def_file_entry: Option<&'a [u8]>) -> &'a [u8] {
        if let Some(entry) = &self.entry {
            entry.as_bytes()
        } else if let Some(entry) = def_file_entry {
            entry
        } else if self.is_dll {
            b"_DllMainCRTStartup"
        } else {
            b"mainCRTStartup"
        }
    }

    fn lib_search_path(&self) -> &[Box<Path>] {
        &self.lib_search_path
    }

    fn output(&self) -> &Arc<Path> {
        &self.output
    }

    fn common(&self) -> &super::CommonArgs {
        &self.common
    }

    fn common_mut(&mut self) -> &mut super::CommonArgs {
        &mut self.common
    }

    fn should_export_all_dynamic_symbols(&self) -> bool {
        false
    }

    fn should_export_dynamic(&self, _lib_name: &[u8]) -> bool {
        false
    }

    fn loadable_segment_alignment(&self) -> crate::alignment::Alignment {
        crate::alignment::Alignment::new(0x1000).unwrap()
    }

    fn should_merge_sections(&self) -> bool {
        false
    }

    fn relocation_model(&self) -> super::RelocationModel {
        super::RelocationModel::NonRelocatable
    }

    fn should_output_executable(&self) -> bool {
        !self.is_dll
    }
}

// Parse the supplied input arguments, which should not include the program name.
pub(crate) fn parse<S: AsRef<str>, I: Iterator<Item = S>>(
    args: &mut PeArgs,
    mut input: I,
) -> Result {
    let mut modifier_stack = vec![Modifiers::default()];

    let arg_parser = setup_windows_argument_parser();
    while let Some(arg) = input.next() {
        let arg = arg.as_ref();
        arg_parser.handle_argument(args, &mut modifier_stack, arg, &mut input)?;
    }

    if !args.common.unrecognized_options.is_empty() {
        let options_list = args.common.unrecognized_options.join(", ");
        bail!("unrecognized option(s): {}", options_list);
    }

    Ok(())
}

fn warn_unimplemented(args: &PeArgs, option: &str) -> Result {
    use crate::platform::Args as _;
    args.warn_unsupported(option)
}

fn setup_windows_argument_parser() -> ArgumentParser<PeArgs> {
    let mut parser = ArgumentParser::new_windows();
    parser
        .declare_with_param()
        .long("ALIGN")
        .help("/ALIGN - Specifies the alignment of each section.")
        .execute(|args, _, _| warn_unimplemented(args, "/ALIGN"));
    parser
        .declare()
        .long("ALLOWBIND")
        .help("/ALLOWBIND - Specifies that a DLL can't be bound.")
        .execute(|args, _| warn_unimplemented(args, "/ALLOWBIND"));
    parser
        .declare()
        .long("ALLOWISOLATION")
        .help("/ALLOWISOLATION - Specifies behavior for manifest lookup.")
        .execute(|args, _| warn_unimplemented(args, "/ALLOWISOLATION"));
    parser
        .declare()
        .long("APPCONTAINER")
        .help("/APPCONTAINER - Specifies whether the app must run within an appcontainer process environment.")
        .execute(|args, _| warn_unimplemented(args, "/APPCONTAINER"));
    parser
        .declare_with_param()
        .long("ARM64XFUNCTIONPADMINX64")
        .help("/ARM64XFUNCTIONPADMINX64 - Specifies the minimum number of bytes of padding between x64 functions in ARM64X images. 17.8")
        .execute(|args, _, _| warn_unimplemented(args, "/ARM64XFUNCTIONPADMINX64"));
    parser
        .declare()
        .long("ASSEMBLYDEBUG")
        .help("/ASSEMBLYDEBUG - Adds the DebuggableAttribute to a managed image.")
        .execute(|args, _| warn_unimplemented(args, "/ASSEMBLYDEBUG"));
    parser
        .declare_with_param()
        .long("ASSEMBLYLINKRESOURCE")
        .help("/ASSEMBLYLINKRESOURCE - Creates a link to a managed resource.")
        .execute(|args, _, _| warn_unimplemented(args, "/ASSEMBLYLINKRESOURCE"));
    parser
        .declare_with_param()
        .long("ASSEMBLYMODULE")
        .help("/ASSEMBLYMODULE - Specifies that a Microsoft intermediate language (MSIL) module should be imported into the assembly.")
        .execute(|args, _, _| warn_unimplemented(args, "/ASSEMBLYMODULE"));
    parser
        .declare_with_param()
        .long("ASSEMBLYRESOURCE")
        .help("/ASSEMBLYRESOURCE - Embeds a managed resource file in an assembly.")
        .execute(|args, _, _| warn_unimplemented(args, "/ASSEMBLYRESOURCE"));
    parser
        .declare_with_param()
        .long("BASE")
        .help("/BASE - Sets a base address for the program.")
        .execute(|args, _modifier_stack, value| {
            // Parse hexadecimal base address
            let base = if value.starts_with("0x") || value.starts_with("0X") {
                u64::from_str_radix(&value[2..], 16)
            } else {
                value.parse::<u64>()
            };

            match base {
                Ok(addr) => {
                    args.base_address = Some(addr);
                    Ok(())
                }
                Err(_) => {
                    crate::bail!("Invalid base address: {}", value);
                }
            }
        });
    parser
        .declare()
        .long("CETCOMPAT")
        .help("/CETCOMPAT - Marks the binary as CET Shadow Stack compatible.")
        .execute(|args, _| warn_unimplemented(args, "/CETCOMPAT"));
    parser
        .declare_with_param()
        .long("CGTHREADS")
        .help("/CGTHREADS - Sets number of cl.exe threads to use for optimization and code generation when link-time code generation is specified.")
        .execute(|args, _modifier_stack, value| {
            match value.parse::<usize>() {
                Ok(threads) => {
                    if threads > 0 {
                        args.common.num_threads = NonZeroUsize::new(threads);
                    }
                    Ok(())
                }
                Err(_) => {
                    crate::bail!("Invalid thread count: {}", value);
                }
            }
        });
    parser
        .declare_with_param()
        .long("CLRIMAGETYPE")
        .help("/CLRIMAGETYPE - Sets the type (IJW, pure, or safe) of a CLR image.")
        .execute(|args, _, _| warn_unimplemented(args, "/CLRIMAGETYPE"));
    parser
        .declare()
        .long("CLRSUPPORTLASTERROR")
        .help("/CLRSUPPORTLASTERROR - Preserves the last error code of functions that are called through the P/Invoke mechanism.")
        .execute(|args, _| warn_unimplemented(args, "/CLRSUPPORTLASTERROR"));
    parser
        .declare_with_param()
        .long("CLRTHREADATTRIBUTE")
        .help("/CLRTHREADATTRIBUTE - Specifies the threading attribute to apply to the entry point of your CLR program.")
        .execute(|args, _, _| warn_unimplemented(args, "/CLRTHREADATTRIBUTE"));
    parser
        .declare()
        .long("CLRUNMANAGEDCODECHECK")
        .help("/CLRUNMANAGEDCODECHECK - Specifies whether the linker applies the SuppressUnmanagedCodeSecurity attribute to linker-generated P/Invoke stubs that call from managed code into native DLLs.")
        .execute(|args, _| warn_unimplemented(args, "/CLRUNMANAGEDCODECHECK"));
    parser
        .declare_with_optional_param()
        .long("DEBUG")
        .help("/DEBUG - Creates debugging information.")
        .sub_option("FULL", "Full debugging information.", |args, _| {
            args.debug_info = true;
            Ok(())
        })
        .sub_option(
            "FASTLINK",
            "Produces a PDB with limited debug information.",
            |args, _| {
                args.debug_info = true;
                Ok(())
            },
        )
        .execute(|args, _, _value| {
            args.debug_info = true;
            Ok(())
        });
    parser
        .declare_with_param()
        .long("DEBUGTYPE")
        .help("/DEBUGTYPE - Specifies which data to include in debugging information.")
        .execute(|args, _, _| warn_unimplemented(args, "/DEBUGTYPE"));
    parser
        .declare_with_param()
        .long("DEF")
        .help("/DEF - Passes a module-definition (.def) file to the linker.")
        .execute(|args, _modifier_stack, value| {
            args.def_file = Some(PathBuf::from(value));
            Ok(())
        });
    parser
        .declare_with_optional_param()
        .long("DEFAULTLIB") // Add lowercase version for case-insensitive matching
        .help("/DEFAULTLIB - Searches the specified library when external references are resolved.")
        .execute(|args, _modifier_stack, value| {
            if let Some(lib_name) = value {
                // Add library to inputs
                args.common.inputs.push(Input {
                    spec: InputSpec::Lib(lib_name.into()),
                    search_first: None,
                    modifiers: Modifiers::default(),
                });
            }
            Ok(())
        });
    parser
        .declare_with_optional_param()
        .long("DELAY")
        .help("/DELAY - Controls the delayed loading of DLLs.")
        .execute(|args, _, _| warn_unimplemented(args, "/DELAY"));
    parser
        .declare_with_optional_param()
        .long("DELAYLOAD")
        .help("/DELAYLOAD - Causes the delayed loading of the specified DLL.")
        .execute(|args, _, _| warn_unimplemented(args, "/DELAYLOAD"));
    parser
        .declare_with_optional_param()
        .long("DELAYSIGN")
        .help("/DELAYSIGN - Partially signs an assembly.")
        .execute(|args, _, _| warn_unimplemented(args, "/DELAYSIGN"));
    parser
        .declare_with_optional_param()
        .long("DEPENDENTLOADFLAG")
        .help("/DEPENDENTLOADFLAG - Sets default flags on dependent DLL loads.")
        .execute(|args, _, _| warn_unimplemented(args, "/DEPENDENTLOADFLAG"));
    parser
        .declare()
        .long("DLL")
        .help("/DLL - Builds a DLL.")
        .execute(|args, _modifier_stack| {
            args.is_dll = true;
            Ok(())
        });
    parser
        .declare_with_param()
        .long("DRIVER")
        .help("/DRIVER - Creates a kernel mode driver.")
        .sub_option(
            "UPONLY",
            "Runs only on a uniprocessor system.",
            |args, _| warn_unimplemented(args, "/DRIVER:UPONLY"),
        )
        .sub_option(
            "WDM",
            "Creates a Windows Driver Model driver.",
            |args, _| warn_unimplemented(args, "/DRIVER:WDM"),
        )
        .execute(|args, _, _| warn_unimplemented(args, "/DRIVER"));
    parser
        .declare_with_optional_param()
        .long("DYNAMICBASE")
        .help("/DYNAMICBASE - Specifies whether to generate an executable image that's rebased at load time by using the address space layout randomization (ASLR) feature.")
        .execute(|args, _modifier_stack, value| {
            match value {
                Some("NO") => args.dynamic_base = false,
                _ => args.dynamic_base = true,
            }
            Ok(())
        });
    parser
        .declare_with_optional_param()
        .long("DYNAMICDEOPT")
        .help("/DYNAMICDEOPT - Enable C++ Dynamic Debugging (Preview) and step in anywhere with on-demand function deoptimization.")
        .execute(|args, _, _| warn_unimplemented(args, "/DYNAMICDEOPT"));
    parser
        .declare_with_param()
        .long("ENTRY")
        .short("e")
        .help("/ENTRY - Sets the starting address.")
        .execute(|args, _modifier_stack, value| {
            args.entry = Some(value.to_string());
            Ok(())
        });
    parser
        .declare_with_optional_param()
        .long("ERRORREPORT")
        .help("/ERRORREPORT - Deprecated. Error reporting is controlled by Windows Error Reporting (WER) settings.")
        .execute(|args, _, _| warn_unimplemented(args, "/ERRORREPORT"));
    parser
        .declare_with_param()
        .long("EXPORT")
        .help("/EXPORT - Exports a function.")
        .execute(|args, _, _| warn_unimplemented(args, "/EXPORT"));
    parser
        .declare_with_param()
        .long("FILEALIGN")
        .help("/FILEALIGN - Aligns sections within the output file on multiples of a specified value.")
        .execute(|args, _, _| warn_unimplemented(args, "/FILEALIGN"));
    parser
        .declare_with_optional_param()
        .long("FIXED")
        .help("/FIXED - Creates a program that can be loaded only at its preferred base address.")
        .execute(|args, _, _| warn_unimplemented(args, "/FIXED"));
    parser
        .declare_with_optional_param()
        .long("FORCE")
        .help("/FORCE - Forces a link to complete even with unresolved symbols or symbols defined more than once.")
        .execute(|args, _, _| warn_unimplemented(args, "/FORCE"));
    parser
        .declare_with_optional_param()
        .long("FUNCTIONPADMIN")
        .help("/FUNCTIONPADMIN - Creates an image that can be hot patched.")
        .execute(|args, _, _| warn_unimplemented(args, "/FUNCTIONPADMIN"));
    parser
        .declare_with_optional_param()
        .long("GENPROFILE")
        .help("/GENPROFILE , /FASTGENPROFILE - Both of these options specify generation of a .pgd file by the linker to support profile-guided optimization (PGO). /GENPROFILE and /FASTGENPROFILE use different default parameters.")
        .execute(|args, _, _| warn_unimplemented(args, "/GENPROFILE"));
    parser
        .declare_with_optional_param()
        .long("GUARD")
        .help("/GUARD - Enables Control Flow Guard protection.")
        .execute(|args, _, _| warn_unimplemented(args, "/GUARD"));
    parser
        .declare_with_optional_param()
        .long("HEAP")
        .help("/HEAP - Sets the size of the heap, in bytes.")
        .execute(|args, _modifier_stack, value| {
            if let Some(heap_value) = value {
                // Parse heap size format: size[,reserve]
                let heap_size_str = heap_value.split(',').next().unwrap_or(heap_value);
                match heap_size_str.parse::<u64>() {
                    Ok(size) => {
                        args.heap_size = Some(size);
                        Ok(())
                    }
                    Err(_) => {
                        crate::bail!("Invalid heap size: {}", heap_value);
                    }
                }
            } else {
                // Default heap size or just enable heap specification
                Ok(())
            }
        });
    parser
        .declare_with_optional_param()
        .long("HIGHENTROPYVA")
        .help("/HIGHENTROPYVA - Specifies support for high-entropy 64-bit address space layout randomization (ASLR).")
        .execute(|args, _modifier_stack, value| {
            match value {
                Some("NO") => args.high_entropy_va = false,
                _ => args.high_entropy_va = true,
            }
            Ok(())
        });
    parser
        .declare_with_optional_param()
        .long("IDLOUT")
        .help("/IDLOUT - Specifies the name of the .idl file and other MIDL output files.")
        .execute(|args, _, _| warn_unimplemented(args, "/IDLOUT"));
    parser
        .declare_with_optional_param()
        .long("IGNORE")
        .help("/IGNORE - Suppresses output of specified linker warnings.")
        .execute(|args, _, _| warn_unimplemented(args, "/IGNORE"));
    parser
        .declare_with_optional_param()
        .long("IGNOREIDL")
        .help("/IGNOREIDL - Prevents the processing of attribute information into an .idl file.")
        .execute(|args, _, _| warn_unimplemented(args, "/IGNOREIDL"));
    parser
        .declare_with_optional_param()
        .long("ILK")
        .help("/ILK - Overrides the default incremental database file name.")
        .execute(|args, _, _| warn_unimplemented(args, "/ILK"));
    parser
        .declare_with_param()
        .long("IMPLIB")
        .help("/IMPLIB - Overrides the default import library name.")
        .execute(|args, _modifier_stack, value| {
            args.import_lib = Some(PathBuf::from(value));
            Ok(())
        });
    parser
        .declare_with_param()
        .long("INCLUDE")
        .help("/INCLUDE - Forces symbol references.")
        .execute(|_args, _modifier_stack, _value| {
            // TODO: Implement symbol forcing
            Ok(())
        });
    parser
        .declare_with_optional_param()
        .long("INCREMENTAL")
        .help("/INCREMENTAL - Controls incremental linking.")
        .sub_option("NO", "Disable incremental linking.", |args, _| {
            warn_unimplemented(args, "/INCREMENTAL:NO")
        })
        .sub_option("YES", "Enable incremental linking.", |args, _| {
            warn_unimplemented(args, "/INCREMENTAL:YES")
        })
        .execute(|args, _, _| warn_unimplemented(args, "/INCREMENTAL"));
    parser
        .declare_with_optional_param()
        .long("INFERASANLIBS")
        .help("/INFERASANLIBS - Uses inferred sanitizer libraries.")
        .execute(|args, _, _| warn_unimplemented(args, "/INFERASANLIBS"));
    parser
        .declare_with_optional_param()
        .long("INTEGRITYCHECK")
        .help(
            "/INTEGRITYCHECK - Specifies that the module requires a signature check at load time.",
        )
        .execute(|args, _, _| warn_unimplemented(args, "/INTEGRITYCHECK"));
    parser
        .declare_with_optional_param()
        .long("KERNEL")
        .help("/KERNEL - Create a kernel mode binary.")
        .execute(|args, _, _| warn_unimplemented(args, "/KERNEL"));
    parser
        .declare_with_optional_param()
        .long("KEYCONTAINER")
        .help("/KEYCONTAINER - Specifies a key container to sign an assembly.")
        .execute(|args, _, _| warn_unimplemented(args, "/KEYCONTAINER"));
    parser
        .declare_with_optional_param()
        .long("KEYFILE")
        .help("/KEYFILE - Specifies a key or key pair to sign an assembly.")
        .execute(|args, _, _| warn_unimplemented(args, "/KEYFILE"));
    parser
        .declare_with_optional_param()
        .long("LARGEADDRESSAWARE")
        .help("/LARGEADDRESSAWARE - Tells the compiler that the application supports addresses larger than 2 gigabytes")
        .execute(|args, _modifier_stack, value| {
            match value {
                Some("NO") => args.large_address_aware = false,
                _ => args.large_address_aware = true,
            }
            Ok(())
        });
    parser
        .declare_with_param()
        .long("LIBPATH")
        .help("/LIBPATH - Specifies a path to search before the environmental library path.")
        .execute(|args, _modifier_stack, value| {
            let path = Path::new(value).into();
            args.lib_search_path.push(path);
            Ok(())
        });
    parser
        .declare_with_optional_param()
        .long("LINKREPRO")
        .help("/LINKREPRO - Specifies a path to generate link repro artifacts in.")
        .execute(|args, _, _| warn_unimplemented(args, "/LINKREPRO"));
    parser
        .declare_with_optional_param()
        .long("LINKREPROFULLPATHRSP")
        .help("/LINKREPROFULLPATHRSP - Generates a response file containing the absolute paths to all the files that the linker took as input.")
        .execute(|args, _, _| warn_unimplemented(args, "/LINKREPROFULLPATHRSP"));
    parser
        .declare_with_optional_param()
        .long("LINKREPROTARGET")
        .help("/LINKREPROTARGET - Generates a link repro only when producing the specified target. 16.1")
        .execute(|args, _, _| warn_unimplemented(args, "/LINKREPROTARGET"));
    parser
        .declare_with_optional_param()
        .long("LTCG")
        .help("/LTCG - Specifies link-time code generation.")
        .sub_option("NOSTATUS", "Do not display progress.", |args, _| {
            warn_unimplemented(args, "/LTCG:NOSTATUS")
        })
        .sub_option("STATUS", "Display progress.", |args, _| {
            warn_unimplemented(args, "/LTCG:STATUS")
        })
        .sub_option("INCREMENTAL", "Enable incremental LTCG.", |args, _| {
            warn_unimplemented(args, "/LTCG:INCREMENTAL")
        })
        .execute(|args, _, _| warn_unimplemented(args, "/LTCG"));
    parser
        .declare_with_param()
        .long("MACHINE")
        .help("/MACHINE - Specifies the target platform.")
        .sub_option("ARM", "ARM", |args, _| {
            args.arch = Architecture::AArch64;
            Ok(())
        })
        .sub_option("ARM64", "ARM64", |args, _| {
            args.arch = Architecture::AArch64;
            Ok(())
        })
        .sub_option("ARM64EC", "ARM64EC", |args, _| {
            args.arch = Architecture::AArch64;
            Ok(())
        })
        .sub_option("EBC", "EBC", |_args, _| {
            // EFI Byte Code - not commonly supported
            Ok(())
        })
        .sub_option("X64", "X64", |args, _| {
            args.arch = Architecture::X86_64;
            Ok(())
        })
        .sub_option("X86", "X86", |args, _| {
            args.arch = Architecture::X86_64; // Treat as X86_64 for simplicity
            Ok(())
        })
        .execute(|args, _, value| {
            // Handle direct architecture specification
            match value.to_uppercase().as_str() {
                "ARM" | "ARM64" | "ARM64EC" => args.arch = Architecture::AArch64,
                "X64" | "X86" => args.arch = Architecture::X86_64,
                _ => {} // Ignore unknown architectures
            }
            Ok(())
        });
    parser
        .declare_with_optional_param()
        .long("MANIFEST")
        .help("/MANIFEST - Creates a side-by-side manifest file and optionally embeds it in the binary.")
        .execute(|args, _, _| warn_unimplemented(args, "/MANIFEST"));
    parser
        .declare_with_optional_param()
        .long("MANIFESTDEPENDENCY")
        .help("/MANIFESTDEPENDENCY - Specifies a <dependentAssembly> section in the manifest file.")
        .execute(|args, _, _| warn_unimplemented(args, "/MANIFESTDEPENDENCY"));
    parser
        .declare_with_param()
        .long("MANIFESTFILE")
        .help("/MANIFESTFILE - Changes the default name of the manifest file.")
        .execute(|args, _modifier_stack, value| {
            args.manifest_file = Some(PathBuf::from(value));
            Ok(())
        });
    parser
        .declare_with_optional_param()
        .long("MANIFESTINPUT")
        .help("/MANIFESTINPUT - Specifies a manifest input file for the linker to process and embed in the binary. You can use this option multiple times to specify more than one manifest input file.")
        .execute(|args, _, _| warn_unimplemented(args, "/MANIFESTINPUT"));
    parser
        .declare_with_optional_param()
        .long("MANIFESTUAC")
        .help("/MANIFESTUAC - Specifies whether User Account Control (UAC) information is embedded in the program manifest.")
        .execute(|args, _, _| warn_unimplemented(args, "/MANIFESTUAC"));
    parser
        .declare_with_optional_param()
        .long("MAP")
        .help("/MAP - Creates a mapfile.")
        .execute(|args, _modifier_stack, value| {
            match value {
                Some(filename) => args.map_file = Some(PathBuf::from(filename)),
                None => {
                    // Default map file name based on output name
                    let output_stem = args
                        .output
                        .file_stem()
                        .unwrap_or_else(|| std::ffi::OsStr::new("output"));
                    let mut map_name = output_stem.to_os_string();
                    map_name.push(".map");
                    args.map_file = Some(PathBuf::from(map_name));
                }
            }
            Ok(())
        });
    parser
        .declare_with_optional_param()
        .long("MAPINFO")
        .help("/MAPINFO - Includes the specified information in the mapfile.")
        .execute(|args, _, _| warn_unimplemented(args, "/MAPINFO"));
    parser
        .declare_with_optional_param()
        .long("MERGE")
        .help("/MERGE - Combines sections.")
        .execute(|args, _, _| warn_unimplemented(args, "/MERGE"));
    parser
        .declare_with_optional_param()
        .long("MIDL")
        .help("/MIDL - Specifies MIDL command-line options.")
        .execute(|args, _, _| warn_unimplemented(args, "/MIDL"));
    parser
        .declare_with_optional_param()
        .long("NATVIS")
        .help(
            "/NATVIS - Adds debugger visualizers from a Natvis file to the program database (PDB).",
        )
        .execute(|args, _, _| warn_unimplemented(args, "/NATVIS"));
    parser
        .declare_with_optional_param()
        .long("NOASSEMBLY")
        .help("/NOASSEMBLY - Suppresses the creation of a .NET Framework assembly.")
        .execute(|args, _, _| warn_unimplemented(args, "/NOASSEMBLY"));
    parser
        .declare_with_optional_param()
        .long("NODEFAULTLIB")
        .help("/NODEFAULTLIB - Ignores all (or the specified) default libraries when external references are resolved.")
        .execute(|args, _modifier_stack, value| {
            match value {
                Some(lib_name) => {
                    // Ignore specific library
                    args.no_default_libs.push(lib_name.to_string());
                }
                None => {
                    // Ignore all default libraries
                    args.ignore_all_default_libs = true;
                }
            }
            Ok(())
        });
    parser
        .declare_with_optional_param()
        .long("NOENTRY")
        .help("/NOENTRY - Creates a resource-only DLL.")
        .execute(|args, _, _| warn_unimplemented(args, "/NOENTRY"));
    parser
        .declare_with_optional_param()
        .long("NOFUNCTIONPADSECTION")
        .help("/NOFUNCTIONPADSECTION - Disables function padding for functions in the specified section. 17.8")
        .execute(|args, _, _| warn_unimplemented(args, "/NOFUNCTIONPADSECTION"));
    parser
        .declare_with_optional_param()
        .long("NOLOGO")
        .help("/NOLOGO - Suppresses the startup banner.")
        .execute(|_, _, _| Ok(()));
    parser
        .declare_with_optional_param()
        .long("NXCOMPAT")
        .help("/NXCOMPAT - Marks an executable as verified to be compatible with the Windows Data Execution Prevention feature.")
        .execute(|args, _modifier_stack, value| {
            match value {
                Some("NO") => args.nx_compat = false,
                _ => args.nx_compat = true,
            }
            Ok(())
        });
    parser
        .declare_with_param()
        .long("OPT")
        .help("/OPT - Controls LINK optimizations.")
        .sub_option(
            "REF",
            "Eliminate unreferenced functions and data.",
            |args, _| warn_unimplemented(args, "/OPT:REF"),
        )
        .sub_option(
            "NOREF",
            "Keep unreferenced functions and data.",
            |args, _| warn_unimplemented(args, "/OPT:NOREF"),
        )
        .sub_option("ICF", "Fold identical COMDATs.", |args, _| {
            warn_unimplemented(args, "/OPT:ICF")
        })
        .sub_option("NOICF", "Disable identical COMDAT folding.", |args, _| {
            warn_unimplemented(args, "/OPT:NOICF")
        })
        .sub_option(
            "LBR",
            "Enable profile guided optimizations (LBR).",
            |args, _| warn_unimplemented(args, "/OPT:LBR"),
        )
        .sub_option(
            "NOLBR",
            "Disable profile guided optimizations (no LBR).",
            |args, _| warn_unimplemented(args, "/OPT:NOLBR"),
        )
        .execute(|args, _, _| warn_unimplemented(args, "/OPT"));
    parser
        .declare_with_optional_param()
        .long("ORDER")
        .help("/ORDER - Places COMDATs into the image in a predetermined order.")
        .execute(|args, _, _| warn_unimplemented(args, "/ORDER"));
    parser
        .declare_with_param()
        .long("OUT")
        .help("/OUT - Specifies the output file name.")
        .execute(|args, _modifier_stack, value| {
            args.output = Arc::from(Path::new(value));
            Ok(())
        });
    parser
        .declare_with_optional_param()
        .long("PDB")
        .help("/PDB - Creates a PDB file.")
        .execute(|args, _modifier_stack, value| {
            match value {
                Some(filename) => args.pdb_file = Some(PathBuf::from(filename)),
                None => {
                    // Default PDB file name based on output name
                    let output_stem = args
                        .output
                        .file_stem()
                        .unwrap_or_else(|| std::ffi::OsStr::new("output"));
                    let mut pdb_name = output_stem.to_os_string();
                    pdb_name.push(".pdb");
                    args.pdb_file = Some(PathBuf::from(pdb_name));
                }
            }
            Ok(())
        });
    parser
        .declare_with_optional_param()
        .long("PDBALTPATH")
        .help("/PDBALTPATH - Uses an alternate location to save a PDB file.")
        .execute(|args, _, _| warn_unimplemented(args, "/PDBALTPATH"));
    parser
        .declare_with_optional_param()
        .long("PDBSTRIPPED")
        .help("/PDBSTRIPPED - Creates a PDB file that has no private symbols.")
        .execute(|args, _, _| warn_unimplemented(args, "/PDBSTRIPPED"));
    parser
        .declare_with_optional_param()
        .long("PGD")
        .help("/PGD - Specifies a .pgd file for profile-guided optimizations.")
        .execute(|args, _, _| warn_unimplemented(args, "/PGD"));
    parser
        .declare_with_optional_param()
        .long("POGOSAFEMODE")
        .help("/POGOSAFEMODE - Obsolete Creates a thread-safe PGO instrumented build.")
        .execute(|args, _, _| warn_unimplemented(args, "/POGOSAFEMODE"));
    parser
        .declare_with_optional_param()
        .long("PROFILE")
        .help("/PROFILE - Produces an output file that can be used with the Performance Tools profiler.")
        .execute(|args, _, _| warn_unimplemented(args, "/PROFILE"));
    parser
        .declare_with_optional_param()
        .long("RELEASE")
        .help("/RELEASE - Sets the Checksum in the .exe header.")
        .execute(|args, _, _| warn_unimplemented(args, "/RELEASE"));
    parser
        .declare_with_optional_param()
        .long("SAFESEH")
        .help(
            "/SAFESEH - Specifies that the image will contain a table of safe exception handlers.",
        )
        .execute(|args, _, _| warn_unimplemented(args, "/SAFESEH"));
    parser
        .declare_with_optional_param()
        .long("SECTION")
        .help("/SECTION - Overrides the attributes of a section.")
        .execute(|args, _, _| warn_unimplemented(args, "/SECTION"));
    parser
        .declare_with_optional_param()
        .long("SOURCELINK")
        .help("/SOURCELINK - Specifies a SourceLink file to add to the PDB.")
        .execute(|args, _, _| warn_unimplemented(args, "/SOURCELINK"));
    parser
        .declare_with_optional_param()
        .long("STACK")
        .help("/STACK - Sets the size of the stack in bytes.")
        .execute(|args, _modifier_stack, value| {
            if let Some(stack_value) = value {
                // Parse stack size format: size[,reserve]
                let stack_size_str = stack_value.split(',').next().unwrap_or(stack_value);
                match stack_size_str.parse::<u64>() {
                    Ok(size) => {
                        args.stack_size = Some(size);
                        Ok(())
                    }
                    Err(_) => {
                        crate::bail!("Invalid stack size: {}", stack_value);
                    }
                }
            } else {
                // Default stack size or just enable stack specification
                Ok(())
            }
        });
    parser
        .declare_with_optional_param()
        .long("STUB")
        .help("/STUB - Attaches an MS-DOS stub program to a Win32 program.")
        .execute(|args, _, _| warn_unimplemented(args, "/STUB"));
    parser
        .declare_with_param()
        .long("SUBSYSTEM")
        .help("/SUBSYSTEM - Tells the operating system how to run the .exe file.")
        .sub_option("BOOT_APPLICATION", "Boot application", |args, _| {
            args.subsystem = Some(WindowsSubsystem::BootApplication);
            Ok(())
        })
        .sub_option("CONSOLE", "Console", |args, _| {
            args.subsystem = Some(WindowsSubsystem::Console);
            Ok(())
        })
        .sub_option("WINDOWS", "Windows GUI", |args, _| {
            args.subsystem = Some(WindowsSubsystem::Windows);
            Ok(())
        })
        .sub_option("NATIVE", "Native", |args, _| {
            args.subsystem = Some(WindowsSubsystem::Native);
            Ok(())
        })
        .sub_option("POSIX", "POSIX", |args, _| {
            args.subsystem = Some(WindowsSubsystem::Posix);
            Ok(())
        })
        .sub_option("EFI_APPLICATION", "EFI application", |args, _| {
            args.subsystem = Some(WindowsSubsystem::EfiApplication);
            Ok(())
        })
        .sub_option(
            "EFI_BOOT_SERVICE_DRIVER",
            "EFI boot service driver",
            |args, _| {
                args.subsystem = Some(WindowsSubsystem::EfiBootServiceDriver);
                Ok(())
            },
        )
        .sub_option("EFI_ROM", "EFI ROM", |args, _| {
            args.subsystem = Some(WindowsSubsystem::EfiRom);
            Ok(())
        })
        .sub_option("EFI_RUNTIME_DRIVER", "EFI runtime driver", |args, _| {
            args.subsystem = Some(WindowsSubsystem::EfiRuntimeDriver);
            Ok(())
        })
        .execute(|args, _, value| {
            // Handle direct subsystem specification
            match value.to_uppercase().as_str() {
                "BOOT_APPLICATION" => args.subsystem = Some(WindowsSubsystem::BootApplication),
                "CONSOLE" => args.subsystem = Some(WindowsSubsystem::Console),
                "WINDOWS" => args.subsystem = Some(WindowsSubsystem::Windows),
                "NATIVE" => args.subsystem = Some(WindowsSubsystem::Native),
                "POSIX" => args.subsystem = Some(WindowsSubsystem::Posix),
                "EFI_APPLICATION" => args.subsystem = Some(WindowsSubsystem::EfiApplication),
                "EFI_BOOT_SERVICE_DRIVER" => {
                    args.subsystem = Some(WindowsSubsystem::EfiBootServiceDriver);
                }
                "EFI_ROM" => args.subsystem = Some(WindowsSubsystem::EfiRom),
                "EFI_RUNTIME_DRIVER" => args.subsystem = Some(WindowsSubsystem::EfiRuntimeDriver),
                _ => {} // Ignore unknown subsystems
            }
            Ok(())
        });
    parser
        .declare_with_optional_param()
        .long("SWAPRUN")
        .help("/SWAPRUN - Tells the operating system to copy the linker output to a swap file before it's run.")
        .execute(|args, _, _| warn_unimplemented(args, "/SWAPRUN"));
    parser
        .declare_with_optional_param()
        .long("TIME")
        .help("/TIME - Output linker pass timing information.")
        .execute(|args, _, _| warn_unimplemented(args, "/TIME"));
    parser
        .declare_with_optional_param()
        .long("TLBID")
        .help("/TLBID - Specifies the resource ID of the linker-generated type library.")
        .execute(|args, _, _| warn_unimplemented(args, "/TLBID"));
    parser
        .declare_with_optional_param()
        .long("TLBOUT")
        .help("/TLBOUT - Specifies the name of the .tlb file and other MIDL output files.")
        .execute(|args, _, _| warn_unimplemented(args, "/TLBOUT"));
    parser
        .declare_with_optional_param()
        .long("TSAWARE")
        .help("/TSAWARE - Creates an application that is designed specifically to run under Terminal Server.")
        .execute(|args, _modifier_stack, value| {
            match value {
                Some("NO") => args.terminal_server_aware = false,
                _ => args.terminal_server_aware = true,
            }
            Ok(())
        });
    parser
        .declare_with_optional_param()
        .long("USEPROFILE")
        .help("/USEPROFILE - Uses profile-guided optimization training data to create an optimized image.")
        .execute(|args, _, _| warn_unimplemented(args, "/USEPROFILE"));
    parser
        .declare_with_optional_param()
        .long("VERBOSE")
        .help("/VERBOSE - Prints linker progress messages.")
        .execute(|args, _, _| warn_unimplemented(args, "/VERBOSE"));
    parser
        .declare_with_param()
        .long("VERSION")
        .help("/VERSION - Assigns a version number.")
        .execute(|args, _modifier_stack, value| {
            args.version = Some(value.to_string());
            Ok(())
        });
    parser
        .declare_with_optional_param()
        .long("WHOLEARCHIVE")
        .help("/WHOLEARCHIVE - Includes every object file from specified static libraries.")
        .execute(|args, _, _| warn_unimplemented(args, "/WHOLEARCHIVE"));
    parser
        .declare_with_optional_param()
        .long("WINMD")
        .help("/WINMD - Enables generation of a Windows Runtime Metadata file.")
        .execute(|args, _, _| warn_unimplemented(args, "/WINMD"));
    parser
        .declare_with_optional_param()
        .long("WINMDFILE")
        .help("/WINMDFILE - Specifies the file name for the Windows Runtime Metadata (winmd) output file that's generated by the /WINMD linker option.")
        .execute(|args, _, _| warn_unimplemented(args, "/WINMDFILE"));
    parser
        .declare_with_optional_param()
        .long("WINMDKEYFILE")
        .help(
            "/WINMDKEYFILE - Specifies a key or key pair to sign a Windows Runtime Metadata file.",
        )
        .execute(|args, _, _| warn_unimplemented(args, "/WINMDKEYFILE"));
    parser
        .declare_with_optional_param()
        .long("WINMDKEYCONTAINER")
        .help("/WINMDKEYCONTAINER - Specifies a key container to sign a Windows Metadata file.")
        .execute(|args, _, _| warn_unimplemented(args, "/WINMDKEYCONTAINER"));
    parser
        .declare_with_optional_param()
        .long("WINMDDELAYSIGN")
        .help("/WINMDDELAYSIGN - Partially signs a Windows Runtime Metadata ( .winmd ) file by placing the public key in the winmd file.")
        .execute(|args, _, _| warn_unimplemented(args, "/WINMDDELAYSIGN"));
    parser
        .declare_with_optional_param()
        .long("WX")
        .help("/WX - Treats linker warnings as errors.")
        .execute(|args, _, _| warn_unimplemented(args, "/WX"));

    parser
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args::InputSpec;
    use std::path::Path;

    // Linker flags captured from `rustc --print link-args` when building the wild binary
    // via `cargo build -p wild-linker --bin wild`. Absolute paths shortened to filenames.
    const WILD_LINKER_ARGS: [&str; 34] = [
        "/NOLOGO",
        "symbols.o",
        "wild.wild.3361c54eb9823ee-cgu.0.rcgu.o",
        "wild.wild.3361c54eb9823ee-cgu.1.rcgu.o",
        "wild.2a4y8h48s9pponkq2cuzxwq3o.rcgu.o",
        "liblibwild-fa816f2f1a86a5f2.rlib",
        "libobject-34152538eafd6b98.rlib",
        "libgimli-354c1f381e4837c5.rlib",
        "librayon-e8ff4d4eff0d8b9a.rlib",
        "libzstd-2dc15ab9103e8d0a.rlib",
        "libblake3-1ff1843950ce7290.rlib",
        "libstd-2137bdd3874dafb5.rlib",
        "libcore-2dc1efaf7a721ce5.rlib",
        "libcompiler_builtins-7d3a0c55eac2cc40.rlib",
        "kernel32.lib",
        "kernel32.lib",
        "kernel32.lib",
        "kernel32.lib",
        "ntdll.lib",
        "userenv.lib",
        "ws2_32.lib",
        "dbghelp.lib",
        "/defaultlib:msvcrt",
        "/NXCOMPAT",
        "/LIBPATH:target/debug/build/blake3-29c3de56e4a14d98/out",
        "/LIBPATH:target/debug/build/zstd-sys-6858da3c6c6d3e21/out",
        "/OUT:wild.exe",
        "/OPT:REF,NOICF",
        "/DEBUG",
        "/PDBALTPATH:%_PDB%",
        "/NATVIS:intrinsic.natvis",
        "/NATVIS:liballoc.natvis",
        "/NATVIS:libcore.natvis",
        "/NATVIS:libstd.natvis",
    ];

    #[track_caller]
    fn assert_contains_file(inputs: &[Input], file_path: &str) {
        assert!(inputs.iter().any(|input| match &input.spec {
            InputSpec::File(path) => path.as_ref() == Path::new(file_path),
            _ => false,
        }));
    }

    #[track_caller]
    fn assert_contains_lib(inputs: &[Input], lib_name: &str) {
        assert!(inputs.iter().any(|input| match &input.spec {
            InputSpec::Lib(name) => name.as_ref() == lib_name,
            _ => false,
        }));
    }

    fn parse_pe<const N: usize>(input: &[&str; N]) -> PeArgs {
        let mut args = PeArgs::default();
        super::parse(&mut args, input.iter()).unwrap();
        args
    }

    fn try_parse_pe(input: &[&str]) -> Result<PeArgs> {
        let mut args = PeArgs::default();
        super::parse(&mut args, input.iter())?;
        Ok(args)
    }

    #[test]
    fn test_parse_wild_linker_args() {
        let args = parse_pe(&WILD_LINKER_ARGS);

        assert!(args.debug_info);
        assert!(args.nx_compat);
        assert_eq!(args.output.as_ref(), Path::new("wild.exe"));
        assert!(args.common.unrecognized_options.is_empty());

        assert_contains_file(&args.common.inputs, "symbols.o");
        assert_contains_file(
            &args.common.inputs,
            "wild.wild.3361c54eb9823ee-cgu.0.rcgu.o",
        );
        assert_contains_file(&args.common.inputs, "liblibwild-fa816f2f1a86a5f2.rlib");
        assert_contains_file(&args.common.inputs, "libobject-34152538eafd6b98.rlib");
        assert_contains_file(&args.common.inputs, "kernel32.lib");
        assert_contains_file(&args.common.inputs, "ntdll.lib");
        assert_contains_file(&args.common.inputs, "userenv.lib");
        assert_contains_file(&args.common.inputs, "ws2_32.lib");
        assert_contains_file(&args.common.inputs, "dbghelp.lib");
        assert_contains_lib(&args.common.inputs, "msvcrt");
        assert_eq!(args.lib_search_path.len(), 2);
    }

    #[test]
    fn test_minimal_windows_args() {
        let minimal_args = ["/OUT:test.exe", "/DEBUG", "test.obj"];

        let args = parse_pe(&minimal_args);

        assert_eq!(args.output.as_ref(), Path::new("test.exe"));
        println!("Debug info value: {}", args.debug_info);
        assert!(args.debug_info);
        assert_contains_file(&args.common.inputs, "test.obj");
    }

    #[test]
    fn test_debug_flag_simple() {
        let minimal_args = ["/DEBUG"];

        let result = try_parse_pe(&minimal_args);
        match result {
            Ok(args) => {
                println!("Simple debug test - Debug info value: {}", args.debug_info);
                println!(
                    "Unrecognized options: {:?}",
                    args.common.unrecognized_options
                );
                assert!(args.debug_info);
            }
            Err(e) => {
                println!("Parse error: {:?}", e);
                panic!("Failed to parse arguments: {:?}", e);
            }
        }
    }

    #[test]
    fn test_defaultlib_parsing() {
        let minimal_args = ["/defaultlib:msvcrt"];

        let args = parse_pe(&minimal_args);

        let lib_names: Vec<&str> = args
            .common
            .inputs
            .iter()
            .filter_map(|input| match &input.spec {
                InputSpec::Lib(lib_name) => Some(lib_name.as_ref()),
                _ => None,
            })
            .collect();

        println!("Found libraries: {:?}", lib_names);
        println!(
            "Unrecognized options: {:?}",
            args.common.unrecognized_options
        );

        assert_contains_lib(&args.common.inputs, "msvcrt");
    }

    #[test]
    fn test_required_parameters() {
        // Test that IMPLIB requires a parameter
        let implib_args = ["/IMPLIB"];

        let result = try_parse_pe(&implib_args);
        match result {
            Ok(_) => panic!("Expected error for IMPLIB without parameter"),
            Err(e) => {
                let error_msg = format!("{:?}", e);
                assert!(
                    error_msg.contains("Missing argument") || error_msg.contains("IMPLIB"),
                    "Error should mention missing argument for IMPLIB: {}",
                    error_msg
                );
            }
        }

        // Test that EXPORT requires a parameter
        let export_args = ["/EXPORT"];

        let result = try_parse_pe(&export_args);
        match result {
            Ok(_) => panic!("Expected error for EXPORT without parameter"),
            Err(e) => {
                let error_msg = format!("{:?}", e);
                assert!(
                    error_msg.contains("Missing argument") || error_msg.contains("EXPORT"),
                    "Error should mention missing argument for EXPORT: {}",
                    error_msg
                );
            }
        }

        // Test that VERSION requires a parameter
        let version_args = ["/VERSION"];

        let result = try_parse_pe(&version_args);
        match result {
            Ok(_) => panic!("Expected error for VERSION without parameter"),
            Err(e) => {
                let error_msg = format!("{:?}", e);
                assert!(
                    error_msg.contains("Missing argument") || error_msg.contains("VERSION"),
                    "Error should mention missing argument for VERSION: {}",
                    error_msg
                );
            }
        }
    }

    #[test]
    fn test_unimplemented_options() {
        // Unimplemented options emit a warning but don't error
        let appcontainer_args = ["/APPCONTAINER"];
        try_parse_pe(&appcontainer_args).unwrap();

        let assemblydebug_args = ["/ASSEMBLYDEBUG"];
        try_parse_pe(&assemblydebug_args).unwrap();
    }

    #[test]
    fn test_case_insensitive_parsing() {
        // Test uppercase /ENTRY:main and /OUT:test.exe
        let args_upper = ["/ENTRY:main", "/OUT:test.exe"];
        let result_upper = parse_pe(&args_upper);
        assert_eq!(result_upper.entry, Some("main".to_string()));
        assert_eq!(result_upper.output.as_ref(), Path::new("test.exe"));

        // Test lowercase /entry:main and /out:test.exe
        let args_lower = ["/entry:main", "/out:test.exe"];
        let result_lower = parse_pe(&args_lower);
        assert_eq!(result_lower.entry, Some("main".to_string()));
        assert_eq!(result_lower.output.as_ref(), Path::new("test.exe"));

        // Test mixed case /Entry:main and /Out:test.exe
        let args_mixed = ["/Entry:main", "/Out:test.exe"];
        let result_mixed = parse_pe(&args_mixed);
        assert_eq!(result_mixed.entry, Some("main".to_string()));
        assert_eq!(result_mixed.output.as_ref(), Path::new("test.exe"));
    }

    #[test]
    fn test_nodefaultlib_parsing() {
        // Test /NODEFAULTLIB without parameter (ignore all default libraries)
        let args_all = ["/NODEFAULTLIB"];
        let result_all = parse_pe(&args_all);
        assert!(result_all.ignore_all_default_libs);
        assert!(result_all.no_default_libs.is_empty());

        // Test /NODEFAULTLIB with specific library name
        let args_specific = ["/NODEFAULTLIB:msvcrt"];
        let result_specific = parse_pe(&args_specific);
        assert!(!result_specific.ignore_all_default_libs);
        assert_eq!(result_specific.no_default_libs, vec!["msvcrt"]);

        // Test multiple specific libraries
        let args_multiple = ["/NODEFAULTLIB:msvcrt", "/NODEFAULTLIB:kernel32"];
        let result_multiple = parse_pe(&args_multiple);
        assert!(!result_multiple.ignore_all_default_libs);
        assert_eq!(result_multiple.no_default_libs, vec!["msvcrt", "kernel32"]);

        // Test case-insensitive matching
        let args_case_insensitive = ["/nodefaultlib:msvcrt"];
        let result_case_insensitive = parse_pe(&args_case_insensitive);
        assert!(!result_case_insensitive.ignore_all_default_libs);
        assert_eq!(result_case_insensitive.no_default_libs, vec!["msvcrt"]);
    }

    #[test]
    fn test_nodefaultlib_helper_methods() {
        // Test helper methods for ignore all default libraries
        let args_all = ["/NODEFAULTLIB"];
        let result_all = parse_pe(&args_all);

        assert!(result_all.ignores_all_default_libs());
        assert!(result_all.should_ignore_default_lib("msvcrt"));
        assert!(result_all.should_ignore_default_lib("kernel32"));
        assert!(result_all.ignored_default_libs().is_empty());

        // Test helper methods for specific libraries
        let args_specific = ["/NODEFAULTLIB:msvcrt", "/NODEFAULTLIB:kernel32"];
        let result_specific = parse_pe(&args_specific);

        assert!(!result_specific.ignores_all_default_libs());
        assert!(result_specific.should_ignore_default_lib("msvcrt"));
        assert!(result_specific.should_ignore_default_lib("kernel32"));
        assert!(!result_specific.should_ignore_default_lib("user32"));
        assert_eq!(
            result_specific.ignored_default_libs(),
            &["msvcrt", "kernel32"]
        );
    }
}
