use super::ArgumentParser;
use super::Input;
use super::InputSpec;
use super::Modifiers;
use super::add_default_flags;
use super::add_silently_ignored_flags;
use super::consts::FILES_PER_GROUP_ENV;
use super::consts::REFERENCE_LINKER_ENV;
use crate::arch::Architecture;
use crate::bail;
use crate::ensure;
use crate::error::Result;
use crate::output_kind::OutputKind;
use crate::save_dir::SaveDir;
use jobserver::Client;
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

/// PE/COFF-specific linker arguments. Common fields (output, arch, inputs, etc.)
/// live on `Args<PeArgs>`. Access them via direct field access on `Args`,
/// and PE-specific fields are accessible via `Deref`/`DerefMut`.
pub struct PeArgs {
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
}

impl Default for PeArgs {
    fn default() -> Self {
        Self {
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
        }
    }
}


impl super::Args<PeArgs> {
    pub fn output_kind(&self) -> OutputKind {
        if !self.should_output_executable {
            OutputKind::SharedObject
        } else {
            OutputKind::StaticExecutable(self.relocation_model)
        }
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

/// Parse Windows linker arguments from the given input iterator.
pub(crate) fn parse<F: Fn() -> I, S: AsRef<str>, I: Iterator<Item = S>>(
    input: F,
) -> Result<super::Args<PeArgs>> {
    use crate::input_data::MAX_FILES_PER_GROUP;

    // SAFETY: Should be called early before other descriptors are opened.
    let jobserver_client = unsafe { Client::from_env() };

    let files_per_group: Option<u32> = std::env::var(FILES_PER_GROUP_ENV)
        .ok()
        .map(|s| s.parse())
        .transpose()?;

    if let Some(x) = files_per_group {
        ensure!(
            x <= MAX_FILES_PER_GROUP,
            "{FILES_PER_GROUP_ENV}={x} but maximum is {MAX_FILES_PER_GROUP}"
        );
    }

    let mut args = super::Args::<PeArgs> {
        output: Arc::from(Path::new("a.exe")),
        should_write_linker_identity: false,
        files_per_group,
        jobserver_client,
        ..Default::default()
    };

    args.save_dir = SaveDir::new(&input)?;

    let mut input = input();

    let mut modifier_stack = vec![Modifiers::default()];

    if std::env::var(REFERENCE_LINKER_ENV).is_ok() {
        args.write_layout = true;
        args.write_trace = true;
    }

    let arg_parser = setup_windows_argument_parser();
    while let Some(arg) = input.next() {
        let arg = arg.as_ref();
        arg_parser.handle_argument(&mut args, &mut modifier_stack, arg, &mut input)?;
    }

    if !args.unrecognized_options.is_empty() {
        let options_list = args.unrecognized_options.join(", ");
        bail!("unrecognized option(s): {}", options_list);
    }

    Ok(args)
}

pub(crate) fn setup_windows_argument_parser() -> ArgumentParser<PeArgs> {
    // Helper function for unimplemented options
    fn unimplemented_option(option: &str) -> Result<()> {
        crate::bail!("Option {} is not yet implemented", option)
    }

    let mut parser = ArgumentParser::new_case_insensitive();
    // /ALIGN - Specifies the alignment of each section.
    parser
        .declare_with_param()
        .long("ALIGN")
        .help("/ALIGN - Specifies the alignment of each section.")
        .execute(|_args: &mut super::Args<PeArgs>, _modifier_stack, _value| {
            unimplemented_option("/ALIGN")
        });
    // /ALLOWBIND - Specifies that a DLL can't be bound.
    parser
        .declare()
        .long("ALLOWBIND")
        .help("/ALLOWBIND - Specifies that a DLL can't be bound.")
        .execute(|_, _| unimplemented_option("/ALLOWBIND"));
    // /ALLOWISOLATION - Specifies behavior for manifest lookup.
    parser
        .declare()
        .long("ALLOWISOLATION")
        .help("/ALLOWISOLATION - Specifies behavior for manifest lookup.")
        .execute(|_, _| unimplemented_option("/ALLOWISOLATION"));
    // /APPCONTAINER - Specifies whether the app must run within an appcontainer process environment.
    parser
        .declare()
        .long("APPCONTAINER")
        .help("/APPCONTAINER - Specifies whether the app must run within an appcontainer process environment.")
        .execute(|_, _| unimplemented_option("/APPCONTAINER"));
    // /ARM64XFUNCTIONPADMINX64 - Specifies the minimum number of bytes of padding between x64 functions in ARM64X images. 17.8
    parser
        .declare_with_param()
        .long("ARM64XFUNCTIONPADMINX64")
        .help("/ARM64XFUNCTIONPADMINX64 - Specifies the minimum number of bytes of padding between x64 functions in ARM64X images. 17.8")
        .execute(|_, _, _| unimplemented_option("/ARM64XFUNCTIONPADMINX64"));
    // /ASSEMBLYDEBUG - Adds the DebuggableAttribute to a managed image.
    parser
        .declare()
        .long("ASSEMBLYDEBUG")
        .help("/ASSEMBLYDEBUG - Adds the DebuggableAttribute to a managed image.")
        .execute(|_, _| unimplemented_option("/ASSEMBLYDEBUG"));
    // /ASSEMBLYLINKRESOURCE - Creates a link to a managed resource.
    parser
        .declare_with_param()
        .long("ASSEMBLYLINKRESOURCE")
        .help("/ASSEMBLYLINKRESOURCE - Creates a link to a managed resource.")
        .execute(|_, _, _| unimplemented_option("/ASSEMBLYLINKRESOURCE"));
    // /ASSEMBLYMODULE - Specifies that a Microsoft intermediate language (MSIL) module should be imported into the assembly.
    parser
        .declare_with_param()
        .long("ASSEMBLYMODULE")
        .help("/ASSEMBLYMODULE - Specifies that a Microsoft intermediate language (MSIL) module should be imported into the assembly.")
        .execute(|_, _, _| unimplemented_option("/ASSEMBLYMODULE"));
    // /ASSEMBLYRESOURCE - Embeds a managed resource file in an assembly.
    parser
        .declare_with_param()
        .long("ASSEMBLYRESOURCE")
        .help("/ASSEMBLYRESOURCE - Embeds a managed resource file in an assembly.")
        .execute(|_, _, _| unimplemented_option("/ASSEMBLYRESOURCE"));
    // /BASE - Sets a base address for the program.
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
    // /CETCOMPAT - Marks the binary as CET Shadow Stack compatible.
    parser
        .declare()
        .long("CETCOMPAT")
        .help("/CETCOMPAT - Marks the binary as CET Shadow Stack compatible.")
        .execute(|_, _| unimplemented_option("/CETCOMPAT"));
    // /CGTHREADS - Sets number of cl.exe threads to use for optimization and code generation when link-time code generation is specified.
    parser
        .declare_with_param()
        .long("CGTHREADS")
        .help("/CGTHREADS - Sets number of cl.exe threads to use for optimization and code generation when link-time code generation is specified.")
        .execute(|args, _modifier_stack, value| {
            match value.parse::<usize>() {
                Ok(threads) => {
                    if threads > 0 {
                        args.num_threads = NonZeroUsize::new(threads);
                    }
                    Ok(())
                }
                Err(_) => {
                    crate::bail!("Invalid thread count: {}", value);
                }
            }
        });
    // /CLRIMAGETYPE - Sets the type (IJW, pure, or safe) of a CLR image.
    parser
        .declare_with_param()
        .long("CLRIMAGETYPE")
        .help("/CLRIMAGETYPE - Sets the type (IJW, pure, or safe) of a CLR image.")
        .execute(|_, _, _| unimplemented_option("/CLRIMAGETYPE"));
    // /CLRSUPPORTLASTERROR - Preserves the last error code of functions that are called through the P/Invoke mechanism.
    parser
        .declare()
        .long("CLRSUPPORTLASTERROR")
        .help("/CLRSUPPORTLASTERROR - Preserves the last error code of functions that are called through the P/Invoke mechanism.")
        .execute(|_, _| unimplemented_option("/CLRSUPPORTLASTERROR"));
    // /CLRTHREADATTRIBUTE - Specifies the threading attribute to apply to the entry point of your CLR program.
    parser
        .declare_with_param()
        .long("CLRTHREADATTRIBUTE")
        .help("/CLRTHREADATTRIBUTE - Specifies the threading attribute to apply to the entry point of your CLR program.")
        .execute(|_, _, _| unimplemented_option("/CLRTHREADATTRIBUTE"));
    // /CLRUNMANAGEDCODECHECK - Specifies whether the linker applies the SuppressUnmanagedCodeSecurity attribute to linker-generated P/Invoke stubs that call from managed code into native DLLs.
    parser
        .declare()
        .long("CLRUNMANAGEDCODECHECK")
        .help("/CLRUNMANAGEDCODECHECK - Specifies whether the linker applies the SuppressUnmanagedCodeSecurity attribute to linker-generated P/Invoke stubs that call from managed code into native DLLs.")
        .execute(|_, _| unimplemented_option("/CLRUNMANAGEDCODECHECK"));
    // /DEBUG - Creates debugging information.
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
    // /DEBUGTYPE - Specifies which data to include in debugging information.
    parser
        .declare_with_param()
        .long("DEBUGTYPE")
        .help("/DEBUGTYPE - Specifies which data to include in debugging information.")
        .execute(|_, _, _| unimplemented_option("/DEBUGTYPE"));
    // /DEF - Passes a module-definition (.def) file to the linker.
    parser
        .declare_with_param()
        .long("DEF")
        .help("/DEF - Passes a module-definition (.def) file to the linker.")
        .execute(|args, _modifier_stack, value| {
            args.def_file = Some(PathBuf::from(value));
            Ok(())
        });
    // /DEFAULTLIB - Searches the specified library when external references are resolved.
    parser
        .declare_with_optional_param()
        .long("DEFAULTLIB") // Add lowercase version for case-insensitive matching
        .help("/DEFAULTLIB - Searches the specified library when external references are resolved.")
        .execute(|args, _modifier_stack, value| {
            if let Some(lib_name) = value {
                // Add library to inputs
                args.inputs.push(Input {
                    spec: InputSpec::Lib(lib_name.into()),
                    search_first: None,
                    modifiers: Modifiers::default(),
                });
            }
            Ok(())
        });
    // /DELAY - Controls the delayed loading of DLLs.
    parser
        .declare_with_optional_param()
        .long("DELAY")
        .help("/DELAY - Controls the delayed loading of DLLs.")
        .execute(|_, _, _| unimplemented_option("/DELAY"));
    // /DELAYLOAD - Causes the delayed loading of the specified DLL.
    parser
        .declare_with_optional_param()
        .long("DELAYLOAD")
        .help("/DELAYLOAD - Causes the delayed loading of the specified DLL.")
        .execute(|_, _, _| unimplemented_option("/DELAYLOAD"));
    // /DELAYSIGN - Partially signs an assembly.
    parser
        .declare_with_optional_param()
        .long("DELAYSIGN")
        .help("/DELAYSIGN - Partially signs an assembly.")
        .execute(|_, _, _| unimplemented_option("/DELAYSIGN"));
    // /DEPENDENTLOADFLAG - Sets default flags on dependent DLL loads.
    parser
        .declare_with_optional_param()
        .long("DEPENDENTLOADFLAG")
        .help("/DEPENDENTLOADFLAG - Sets default flags on dependent DLL loads.")
        .execute(|_, _, _| unimplemented_option("/DEPENDENTLOADFLAG"));
    // /DLL - Builds a DLL.
    parser
        .declare()
        .long("DLL")
        .help("/DLL - Builds a DLL.")
        .execute(|args, _modifier_stack| {
            args.is_dll = true;
            args.should_output_executable = false;
            Ok(())
        });
    // /DRIVER - Creates a kernel mode driver.
    parser
        .declare_with_param()
        .long("DRIVER")
        .help("/DRIVER - Creates a kernel mode driver.")
        .sub_option(
            "UPONLY",
            "Runs only on a uniprocessor system.",
            |_, _| unimplemented_option("/DRIVER:UPONLY"),
        )
        .sub_option(
            "WDM",
            "Creates a Windows Driver Model driver.",
            |_, _| unimplemented_option("/DRIVER:WDM"),
        )
        .execute(|_, _, _| unimplemented_option("/DRIVER"));
    // /DYNAMICBASE - Specifies whether to generate an executable image that's rebased at load time by using the address space layout randomization (ASLR) feature.
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
    // /DYNAMICDEOPT - Enable C++ Dynamic Debugging (Preview) and step in anywhere with on-demand function deoptimization.
    parser
        .declare_with_optional_param()
        .long("DYNAMICDEOPT")
        .help("/DYNAMICDEOPT - Enable C++ Dynamic Debugging (Preview) and step in anywhere with on-demand function deoptimization.")
        .execute(|_, _, _| unimplemented_option("/DYNAMICDEOPT"));
    // /ENTRY - Sets the starting address.
    parser
        .declare_with_param()
        .long("ENTRY")
        .help("/ENTRY - Sets the starting address.")
        .execute(|args, _modifier_stack, value| {
            args.entry = Some(value.to_string());
            Ok(())
        });
    // /ERRORREPORT - Deprecated. Error reporting is controlled by Windows Error Reporting (WER) settings.
    parser
        .declare_with_optional_param()
        .long("ERRORREPORT")
        .help("/ERRORREPORT - Deprecated. Error reporting is controlled by Windows Error Reporting (WER) settings.")
        .execute(|_, _, _| unimplemented_option("/ERRORREPORT"));
    // /EXPORT - Exports a function.
    parser
        .declare_with_param()
        .long("EXPORT")
        .help("/EXPORT - Exports a function.")
        .execute(|_args, _modifier_stack, _value| unimplemented_option("/EXPORT"));
    // /FILEALIGN - Aligns sections within the output file on multiples of a specified value.
    parser
        .declare_with_param()
        .long("FILEALIGN")
        .help("/FILEALIGN - Aligns sections within the output file on multiples of a specified value.")
        .execute(|_args, _modifier_stack, _value| unimplemented_option("/FILEALIGN"));
    // /FIXED - Creates a program that can be loaded only at its preferred base address.
    parser
        .declare_with_optional_param()
        .long("FIXED")
        .help("/FIXED - Creates a program that can be loaded only at its preferred base address.")
        .execute(|_, _, _| unimplemented_option("/FIXED"));
    // /FORCE - Forces a link to complete even with unresolved symbols or symbols defined more than once.
    parser
        .declare_with_optional_param()
        .long("FORCE")
        .help("/FORCE - Forces a link to complete even with unresolved symbols or symbols defined more than once.")
        .execute(|_, _, _| unimplemented_option("/FORCE"));
    // /FUNCTIONPADMIN - Creates an image that can be hot patched.
    parser
        .declare_with_optional_param()
        .long("FUNCTIONPADMIN")
        .help("/FUNCTIONPADMIN - Creates an image that can be hot patched.")
        .execute(|_, _, _| unimplemented_option("/FUNCTIONPADMIN"));
    // /GENPROFILE , /FASTGENPROFILE - Both of these options specify generation of a .pgd file by the linker to support profile-guided optimization (PGO). /GENPROFILE and /FASTGENPROFILE use different default parameters.
    parser
        .declare_with_optional_param()
        .long("GENPROFILE")
        .help("/GENPROFILE , /FASTGENPROFILE - Both of these options specify generation of a .pgd file by the linker to support profile-guided optimization (PGO). /GENPROFILE and /FASTGENPROFILE use different default parameters.")
        .execute(|_, _, _| unimplemented_option("/GENPROFILE"));
    // /GUARD - Enables Control Flow Guard protection.
    parser
        .declare_with_optional_param()
        .long("GUARD")
        .help("/GUARD - Enables Control Flow Guard protection.")
        .execute(|_, _, _| unimplemented_option("/GUARD"));
    // /HEAP - Sets the size of the heap, in bytes.
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
    // /HIGHENTROPYVA - Specifies support for high-entropy 64-bit address space layout randomization (ASLR).
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
    // /IDLOUT - Specifies the name of the .idl file and other MIDL output files.
    parser
        .declare_with_optional_param()
        .long("IDLOUT")
        .help("/IDLOUT - Specifies the name of the .idl file and other MIDL output files.")
        .execute(|_, _, _| unimplemented_option("/IDLOUT"));
    // /IGNORE - Suppresses output of specified linker warnings.
    parser
        .declare_with_optional_param()
        .long("IGNORE")
        .help("/IGNORE - Suppresses output of specified linker warnings.")
        .execute(|_, _, _| unimplemented_option("/IGNORE"));
    // /IGNOREIDL - Prevents the processing of attribute information into an .idl file.
    parser
        .declare_with_optional_param()
        .long("IGNOREIDL")
        .help("/IGNOREIDL - Prevents the processing of attribute information into an .idl file.")
        .execute(|_, _, _| unimplemented_option("/IGNOREIDL"));
    // /ILK - Overrides the default incremental database file name.
    parser
        .declare_with_optional_param()
        .long("ILK")
        .help("/ILK - Overrides the default incremental database file name.")
        .execute(|_, _, _| unimplemented_option("/ILK"));
    // /IMPLIB - Overrides the default import library name.
    parser
        .declare_with_param()
        .long("IMPLIB")
        .help("/IMPLIB - Overrides the default import library name.")
        .execute(|args, _modifier_stack, value| {
            args.import_lib = Some(PathBuf::from(value));
            Ok(())
        });
    // /INCLUDE - Forces symbol references.
    parser
        .declare_with_param()
        .long("INCLUDE")
        .help("/INCLUDE - Forces symbol references.")
        .execute(|_args, _modifier_stack, _value| {
            // TODO: Implement symbol forcing
            Ok(())
        });
    // /INCREMENTAL - Controls incremental linking.
    parser
        .declare_with_optional_param()
        .long("INCREMENTAL")
        .help("/INCREMENTAL - Controls incremental linking.")
        .sub_option("NO", "Disable incremental linking.", |_, _| {
            unimplemented_option("/INCREMENTAL:NO")
        })
        .sub_option("YES", "Enable incremental linking.", |_, _| {
            unimplemented_option("/INCREMENTAL:YES")
        })
        .execute(|_, _, _| unimplemented_option("/INCREMENTAL"));
    // /INFERASANLIBS - Uses inferred sanitizer libraries.
    parser
        .declare_with_optional_param()
        .long("INFERASANLIBS")
        .help("/INFERASANLIBS - Uses inferred sanitizer libraries.")
        .execute(|_, _, _| unimplemented_option("/INFERASANLIBS"));
    // /INTEGRITYCHECK - Specifies that the module requires a signature check at load time.
    parser
        .declare_with_optional_param()
        .long("INTEGRITYCHECK")
        .help(
            "/INTEGRITYCHECK - Specifies that the module requires a signature check at load time.",
        )
        .execute(|_, _, _| unimplemented_option("/INTEGRITYCHECK"));
    // /KERNEL - Create a kernel mode binary.
    parser
        .declare_with_optional_param()
        .long("KERNEL")
        .help("/KERNEL - Create a kernel mode binary.")
        .execute(|_, _, _| unimplemented_option("/KERNEL"));
    // /KEYCONTAINER - Specifies a key container to sign an assembly.
    parser
        .declare_with_optional_param()
        .long("KEYCONTAINER")
        .help("/KEYCONTAINER - Specifies a key container to sign an assembly.")
        .execute(|_, _, _| unimplemented_option("/KEYCONTAINER"));
    // /KEYFILE - Specifies a key or key pair to sign an assembly.
    parser
        .declare_with_optional_param()
        .long("KEYFILE")
        .help("/KEYFILE - Specifies a key or key pair to sign an assembly.")
        .execute(|_, _, _| unimplemented_option("/KEYFILE"));
    // /LARGEADDRESSAWARE - Tells the compiler that the application supports addresses larger than 2 gigabytes
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
    // /LIBPATH - Specifies a path to search before the environmental library path.
    parser
        .declare_with_param()
        .long("LIBPATH")
        .help("/LIBPATH - Specifies a path to search before the environmental library path.")
        .execute(|args, _modifier_stack, value| {
            let path = Path::new(value).into();
            args.lib_search_path.push(path);
            Ok(())
        });
    // /LINKREPRO - Specifies a path to generate link repro artifacts in.
    parser
        .declare_with_optional_param()
        .long("LINKREPRO")
        .help("/LINKREPRO - Specifies a path to generate link repro artifacts in.")
        .execute(|_, _, _| unimplemented_option("/LINKREPRO"));
    // /LINKREPROFULLPATHRSP - Generates a response file containing the absolute paths to all the files that the linker took as input.
    parser
        .declare_with_optional_param()
        .long("LINKREPROFULLPATHRSP")
        .help("/LINKREPROFULLPATHRSP - Generates a response file containing the absolute paths to all the files that the linker took as input.")
        .execute(|_, _, _| unimplemented_option("/LINKREPROFULLPATHRSP"));
    // /LINKREPROTARGET - Generates a link repro only when producing the specified target. 16.1
    parser
        .declare_with_optional_param()
        .long("LINKREPROTARGET")
        .help("/LINKREPROTARGET - Generates a link repro only when producing the specified target. 16.1")
        .execute(|_, _, _| unimplemented_option("/LINKREPROTARGET"));
    // /LTCG - Specifies link-time code generation.
    parser
        .declare_with_optional_param()
        .long("LTCG")
        .help("/LTCG - Specifies link-time code generation.")
        .sub_option("NOSTATUS", "Do not display progress.", |_, _| {
            unimplemented_option("/LTCG:NOSTATUS")
        })
        .sub_option("STATUS", "Display progress.", |_, _| {
            unimplemented_option("/LTCG:STATUS")
        })
        .sub_option("INCREMENTAL", "Enable incremental LTCG.", |_, _| {
            unimplemented_option("/LTCG:INCREMENTAL")
        })
        .execute(|_, _, _| unimplemented_option("/LTCG"));
    // /MACHINE - Specifies the target platform.
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
    // /MANIFEST - Creates a side-by-side manifest file and optionally embeds it in the binary.
    parser
        .declare_with_optional_param()
        .long("MANIFEST")
        .help("/MANIFEST - Creates a side-by-side manifest file and optionally embeds it in the binary.")
        .execute(|_, _, _| unimplemented_option("/MANIFEST"));
    // /MANIFESTDEPENDENCY - Specifies a <dependentAssembly> section in the manifest file.
    parser
        .declare_with_optional_param()
        .long("MANIFESTDEPENDENCY")
        .help("/MANIFESTDEPENDENCY - Specifies a <dependentAssembly> section in the manifest file.")
        .execute(|_, _, _| unimplemented_option("/MANIFESTDEPENDENCY"));
    // /MANIFESTFILE - Changes the default name of the manifest file.
    parser
        .declare_with_param()
        .long("MANIFESTFILE")
        .help("/MANIFESTFILE - Changes the default name of the manifest file.")
        .execute(|args, _modifier_stack, value| {
            args.manifest_file = Some(PathBuf::from(value));
            Ok(())
        });
    // /MANIFESTINPUT - Specifies a manifest input file for the linker to process and embed in the binary. You can use this option multiple times to specify more than one manifest input file.
    parser
        .declare_with_optional_param()
        .long("MANIFESTINPUT")
        .help("/MANIFESTINPUT - Specifies a manifest input file for the linker to process and embed in the binary. You can use this option multiple times to specify more than one manifest input file.")
        .execute(|_, _, _| unimplemented_option("/MANIFESTINPUT"));
    // /MANIFESTUAC - Specifies whether User Account Control (UAC) information is embedded in the program manifest.
    parser
        .declare_with_optional_param()
        .long("MANIFESTUAC")
        .help("/MANIFESTUAC - Specifies whether User Account Control (UAC) information is embedded in the program manifest.")
        .execute(|_, _, _| unimplemented_option("/MANIFESTUAC"));
    // /MAP - Creates a mapfile.
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
    // /MAPINFO - Includes the specified information in the mapfile.
    parser
        .declare_with_optional_param()
        .long("MAPINFO")
        .help("/MAPINFO - Includes the specified information in the mapfile.")
        .execute(|_, _, _| unimplemented_option("/MAPINFO"));
    // /MERGE - Combines sections.
    parser
        .declare_with_optional_param()
        .long("MERGE")
        .help("/MERGE - Combines sections.")
        .execute(|_, _, _| unimplemented_option("/MERGE"));
    // /MIDL - Specifies MIDL command-line options.
    parser
        .declare_with_optional_param()
        .long("MIDL")
        .help("/MIDL - Specifies MIDL command-line options.")
        .execute(|_, _, _| unimplemented_option("/MIDL"));
    // /NATVIS - Adds debugger visualizers from a Natvis file to the program database (PDB).
    parser
        .declare_with_optional_param()
        .long("NATVIS")
        .help(
            "/NATVIS - Adds debugger visualizers from a Natvis file to the program database (PDB).",
        )
        .execute(|_, _, _| unimplemented_option("/NATVIS"));
    // /NOASSEMBLY - Suppresses the creation of a .NET Framework assembly.
    parser
        .declare_with_optional_param()
        .long("NOASSEMBLY")
        .help("/NOASSEMBLY - Suppresses the creation of a .NET Framework assembly.")
        .execute(|_, _, _| unimplemented_option("/NOASSEMBLY"));
    // /NODEFAULTLIB - Ignores all (or the specified) default libraries when external references are resolved.
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
    // /NOENTRY - Creates a resource-only DLL.
    parser
        .declare_with_optional_param()
        .long("NOENTRY")
        .help("/NOENTRY - Creates a resource-only DLL.")
        .execute(|_, _, _| unimplemented_option("/NOENTRY"));
    // /NOFUNCTIONPADSECTION - Disables function padding for functions in the specified section. 17.8
    parser
        .declare_with_optional_param()
        .long("NOFUNCTIONPADSECTION")
        .help("/NOFUNCTIONPADSECTION - Disables function padding for functions in the specified section. 17.8")
        .execute(|_, _, _| unimplemented_option("/NOFUNCTIONPADSECTION"));
    // /NOLOGO - Suppresses the startup banner.
    parser
        .declare_with_optional_param()
        .long("NOLOGO")
        .help("/NOLOGO - Suppresses the startup banner.")
        .execute(|_, _, _| unimplemented_option("/NOLOGO"));
    // /NXCOMPAT - Marks an executable as verified to be compatible with the Windows Data Execution Prevention feature.
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
    // /OPT - Controls LINK optimizations.
    parser
        .declare_with_param()
        .long("OPT")
        .help("/OPT - Controls LINK optimizations.")
        .sub_option(
            "REF",
            "Eliminate unreferenced functions and data.",
            |_, _| unimplemented_option("/OPT:REF"),
        )
        .sub_option(
            "NOREF",
            "Keep unreferenced functions and data.",
            |_, _| unimplemented_option("/OPT:NOREF"),
        )
        .sub_option("ICF", "Fold identical COMDATs.", |_, _| {
            unimplemented_option("/OPT:ICF")
        })
        .sub_option("NOICF", "Disable identical COMDAT folding.", |_, _| {
            unimplemented_option("/OPT:NOICF")
        })
        .sub_option(
            "LBR",
            "Enable profile guided optimizations (LBR).",
            |_, _| unimplemented_option("/OPT:LBR"),
        )
        .sub_option(
            "NOLBR",
            "Disable profile guided optimizations (no LBR).",
            |_, _| unimplemented_option("/OPT:NOLBR"),
        )
        .execute(|_, _, _| unimplemented_option("/OPT"));
    // /ORDER - Places COMDATs into the image in a predetermined order.
    parser
        .declare_with_optional_param()
        .long("ORDER")
        .help("/ORDER - Places COMDATs into the image in a predetermined order.")
        .execute(|_, _, _| unimplemented_option("/ORDER"));
    // /OUT - Specifies the output file name.
    parser
        .declare_with_param()
        .long("OUT")
        .help("/OUT - Specifies the output file name.")
        .execute(|args, _modifier_stack, value| {
            args.output = Arc::from(Path::new(value));
            Ok(())
        });
    // /PDB - Creates a PDB file.
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
    // /PDBALTPATH - Uses an alternate location to save a PDB file.
    parser
        .declare_with_optional_param()
        .long("PDBALTPATH")
        .help("/PDBALTPATH - Uses an alternate location to save a PDB file.")
        .execute(|_, _, _| unimplemented_option("/PDBALTPATH"));
    // /PDBSTRIPPED - Creates a PDB file that has no private symbols.
    parser
        .declare_with_optional_param()
        .long("PDBSTRIPPED")
        .help("/PDBSTRIPPED - Creates a PDB file that has no private symbols.")
        .execute(|_, _, _| unimplemented_option("/PDBSTRIPPED"));
    // /PGD - Specifies a .pgd file for profile-guided optimizations.
    parser
        .declare_with_optional_param()
        .long("PGD")
        .help("/PGD - Specifies a .pgd file for profile-guided optimizations.")
        .execute(|_, _, _| unimplemented_option("/PGD"));
    // /POGOSAFEMODE - Obsolete Creates a thread-safe PGO instrumented build.
    parser
        .declare_with_optional_param()
        .long("POGOSAFEMODE")
        .help("/POGOSAFEMODE - Obsolete Creates a thread-safe PGO instrumented build.")
        .execute(|_, _, _| unimplemented_option("/POGOSAFEMODE"));
    // /PROFILE - Produces an output file that can be used with the Performance Tools profiler.
    parser
        .declare_with_optional_param()
        .long("PROFILE")
        .help("/PROFILE - Produces an output file that can be used with the Performance Tools profiler.")
        .execute(|_, _, _| unimplemented_option("/PROFILE"));
    // /RELEASE - Sets the Checksum in the .exe header.
    parser
        .declare_with_optional_param()
        .long("RELEASE")
        .help("/RELEASE - Sets the Checksum in the .exe header.")
        .execute(|_, _, _| unimplemented_option("/RELEASE"));
    // /SAFESEH - Specifies that the image will contain a table of safe exception handlers.
    parser
        .declare_with_optional_param()
        .long("SAFESEH")
        .help(
            "/SAFESEH - Specifies that the image will contain a table of safe exception handlers.",
        )
        .execute(|_, _, _| unimplemented_option("/SAFESEH"));
    // /SECTION - Overrides the attributes of a section.
    parser
        .declare_with_optional_param()
        .long("SECTION")
        .help("/SECTION - Overrides the attributes of a section.")
        .execute(|_, _, _| unimplemented_option("/SECTION"));
    // /SOURCELINK - Specifies a SourceLink file to add to the PDB.
    parser
        .declare_with_optional_param()
        .long("SOURCELINK")
        .help("/SOURCELINK - Specifies a SourceLink file to add to the PDB.")
        .execute(|_, _, _| unimplemented_option("/SOURCELINK"));
    // /STACK - Sets the size of the stack in bytes.
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
    // /STUB - Attaches an MS-DOS stub program to a Win32 program.
    parser
        .declare_with_optional_param()
        .long("STUB")
        .help("/STUB - Attaches an MS-DOS stub program to a Win32 program.")
        .execute(|_, _, _| unimplemented_option("/STUB"));
    // /SUBSYSTEM - Tells the operating system how to run the .exe file.
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
                    args.subsystem = Some(WindowsSubsystem::EfiBootServiceDriver)
                }
                "EFI_ROM" => args.subsystem = Some(WindowsSubsystem::EfiRom),
                "EFI_RUNTIME_DRIVER" => args.subsystem = Some(WindowsSubsystem::EfiRuntimeDriver),
                _ => {} // Ignore unknown subsystems
            }
            Ok(())
        });
    // /SWAPRUN - Tells the operating system to copy the linker output to a swap file before it's run.
    parser
        .declare_with_optional_param()
        .long("SWAPRUN")
        .help("/SWAPRUN - Tells the operating system to copy the linker output to a swap file before it's run.")
        .execute(|_, _, _| unimplemented_option("/SWAPRUN"));
    // /TIME - Output linker pass timing information.
    parser
        .declare_with_optional_param()
        .long("TIME")
        .help("/TIME - Output linker pass timing information.")
        .execute(|_, _, _| unimplemented_option("/TIME"));
    // /TLBID - Specifies the resource ID of the linker-generated type library.
    parser
        .declare_with_optional_param()
        .long("TLBID")
        .help("/TLBID - Specifies the resource ID of the linker-generated type library.")
        .execute(|_, _, _| unimplemented_option("/TLBID"));
    // /TLBOUT - Specifies the name of the .tlb file and other MIDL output files.
    parser
        .declare_with_optional_param()
        .long("TLBOUT")
        .help("/TLBOUT - Specifies the name of the .tlb file and other MIDL output files.")
        .execute(|_, _, _| unimplemented_option("/TLBOUT"));
    // /TSAWARE - Creates an application that is designed specifically to run under Terminal Server.
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
    // /USEPROFILE - Uses profile-guided optimization training data to create an optimized image.
    parser
        .declare_with_optional_param()
        .long("USEPROFILE")
        .help("/USEPROFILE - Uses profile-guided optimization training data to create an optimized image.")
        .execute(|_, _, _| unimplemented_option("/USEPROFILE"));
    // /VERBOSE - Prints linker progress messages.
    parser
        .declare_with_optional_param()
        .long("VERBOSE")
        .help("/VERBOSE - Prints linker progress messages.")
        .execute(|_, _, _| unimplemented_option("/VERBOSE"));
    // /VERSION - Assigns a version number.
    parser
        .declare_with_param()
        .long("VERSION")
        .help("/VERSION - Assigns a version number.")
        .execute(|args, _modifier_stack, value| {
            args.version = Some(value.to_string());
            Ok(())
        });
    // /WHOLEARCHIVE - Includes every object file from specified static libraries.
    parser
        .declare_with_optional_param()
        .long("WHOLEARCHIVE")
        .help("/WHOLEARCHIVE - Includes every object file from specified static libraries.")
        .execute(|_, _, _| unimplemented_option("/WHOLEARCHIVE"));
    // /WINMD - Enables generation of a Windows Runtime Metadata file.
    parser
        .declare_with_optional_param()
        .long("WINMD")
        .help("/WINMD - Enables generation of a Windows Runtime Metadata file.")
        .execute(|_, _, _| unimplemented_option("/WINMD"));
    // /WINMDFILE - Specifies the file name for the Windows Runtime Metadata (winmd) output file that's generated by the /WINMD linker option.
    parser
        .declare_with_optional_param()
        .long("WINMDFILE")
        .help("/WINMDFILE - Specifies the file name for the Windows Runtime Metadata (winmd) output file that's generated by the /WINMD linker option.")
        .execute(|_, _, _| unimplemented_option("/WINMDFILE"));
    // /WINMDKEYFILE - Specifies a key or key pair to sign a Windows Runtime Metadata file.
    parser
        .declare_with_optional_param()
        .long("WINMDKEYFILE")
        .help(
            "/WINMDKEYFILE - Specifies a key or key pair to sign a Windows Runtime Metadata file.",
        )
        .execute(|_, _, _| unimplemented_option("/WINMDKEYFILE"));
    // /WINMDKEYCONTAINER - Specifies a key container to sign a Windows Metadata file.
    parser
        .declare_with_optional_param()
        .long("WINMDKEYCONTAINER")
        .help("/WINMDKEYCONTAINER - Specifies a key container to sign a Windows Metadata file.")
        .execute(|_, _, _| unimplemented_option("/WINMDKEYCONTAINER"));
    // /WINMDDELAYSIGN - Partially signs a Windows Runtime Metadata ( .winmd ) file by placing the public key in the winmd file.
    parser
        .declare_with_optional_param()
        .long("WINMDDELAYSIGN")
        .help("/WINMDDELAYSIGN - Partially signs a Windows Runtime Metadata ( .winmd ) file by placing the public key in the winmd file.")
        .execute(|_, _, _| unimplemented_option("/WINMDDELAYSIGN"));
    // /WX - Treats linker warnings as errors.
    parser
        .declare_with_optional_param()
        .long("WX")
        .help("/WX - Treats linker warnings as errors.")
        .execute(|_args: &mut super::Args<PeArgs>, _modifier_stack, _value| {
            unimplemented_option("/WX")
        });

    add_silently_ignored_flags(&mut parser);
    add_default_flags(&mut parser);

    parser
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::args::InputSpec;
    use std::path::Path;

    // Example Windows linker flags from Rust compilation
    const WINDOWS_LINKER_ARGS: &[&str] = &[
        "--target=x86_64-pc-windows-msvc",
        r#"C:\Users\Samuel\AppData\Local\Temp\rustc7RL5Io\symbols.o"#,
        "dummy.dummy.6cfbe55db138f4b-cgu.0.rcgu.o",
        "dummy.3wxfnlvokcqcl6j45c8xeicgz.rcgu.o",
        r#"C:\Users\Samuel\.rustup\toolchains\stable-x86_64-pc-windows-msvc\lib\rustlib\x86_64-pc-windows-msvc\lib\libstd-efa6c7783284bd31.rlib"#,
        r#"C:\Users\Samuel\.rustup\toolchains\stable-x86_64-pc-windows-msvc\lib\rustlib\x86_64-pc-windows-msvc\lib\libpanic_unwind-43468c47cff21662.rlib"#,
        r#"C:\Users\Samuel\.rustup\toolchains\stable-x86_64-pc-windows-msvc\lib\rustlib\x86_64-pc-windows-msvc\lib\libwindows_targets-3935b75a1bd1c449.rlib"#,
        r#"C:\Users\Samuel\.rustup\toolchains\stable-x86_64-pc-windows-msvc\lib\rustlib\x86_64-pc-windows-msvc\lib\librustc_demangle-cc0fa0adec36251f.rlib"#,
        r#"C:\Users\Samuel\.rustup\toolchains\stable-x86_64-pc-windows-msvc\lib\rustlib\x86_64-pc-windows-msvc\lib\libstd_detect-22f2c46a93af1174.rlib"#,
        r#"C:\Users\Samuel\.rustup\toolchains\stable-x86_64-pc-windows-msvc\lib\rustlib\x86_64-pc-windows-msvc\lib\libhashbrown-c835068eb56f6efb.rlib"#,
        r#"C:\Users\Samuel\.rustup\toolchains\stable-x86_64-pc-windows-msvc\lib\rustlib\x86_64-pc-windows-msvc\lib\librustc_std_workspace_alloc-abe24411cb8f5bd4.rlib"#,
        r#"C:\Users\Samuel\.rustup\toolchains\stable-x86_64-pc-windows-msvc\lib\rustlib\x86_64-pc-windows-msvc\lib\libunwind-b5e24931eb1ae1bd.rlib"#,
        r#"C:\Users\Samuel\.rustup\toolchains\stable-x86_64-pc-windows-msvc\lib\rustlib\x86_64-pc-windows-msvc\lib\libcfg_if-8dc64876e32b9d07.rlib"#,
        r#"C:\Users\Samuel\.rustup\toolchains\stable-x86_64-pc-windows-msvc\lib\rustlib\x86_64-pc-windows-msvc\lib\librustc_std_workspace_core-214bcacef209824d.rlib"#,
        r#"C:\Users\Samuel\.rustup\toolchains\stable-x86_64-pc-windows-msvc\lib\rustlib\x86_64-pc-windows-msvc\lib\liballoc-3e14ad51a3206bab.rlib"#,
        r#"C:\Users\Samuel\.rustup\toolchains\stable-x86_64-pc-windows-msvc\lib\rustlib\x86_64-pc-windows-msvc\lib\libcore-a55e6b132b0b5f5d.rlib"#,
        r#"C:\Users\Samuel\.rustup\toolchains\stable-x86_64-pc-windows-msvc\lib\rustlib\x86_64-pc-windows-msvc\lib\libcompiler_builtins-b994e165f6ecc9e9.rlib"#,
        "kernel32.lib",
        "kernel32.lib",
        "kernel32.lib",
        "ntdll.lib",
        "userenv.lib",
        "ws2_32.lib",
        "dbghelp.lib",
        "/defaultlib:msvcrt",
        "/NXCOMPAT",
        "/OUT:dummy.exe",
        "/DEBUG",
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

    /// Extract Args<PeArgs> from unified Args, panicking if it's not the Pe variant.
    #[track_caller]
    fn unwrap_pe(args: crate::args::Args) -> crate::args::Args<PeArgs> {
        args.map_target(|t| match t {
            crate::args::TargetArgs::Pe(pe) => pe,
            other => panic!(
                "Expected Pe variant, got {:?}",
                std::mem::discriminant(&other)
            ),
        })
    }

    #[test]
    fn test_parse_windows_linker_args() {
        let args = unwrap_pe(crate::args::parse(|| WINDOWS_LINKER_ARGS.iter())
            .unwrap());

        // Test that key flags were parsed correctly
        assert!(args.debug_info); // /DEBUG flag
        assert!(args.nx_compat); // /NXCOMPAT flag

        // Test that output file was set
        assert_eq!(args.output.as_ref(), Path::new("dummy.exe"));

        // Test that input files were collected
        assert_contains_file(&args.inputs, "dummy.dummy.6cfbe55db138f4b-cgu.0.rcgu.o");
        assert_contains_file(&args.inputs, "dummy.3wxfnlvokcqcl6j45c8xeicgz.rcgu.o");

        // Test that library files were collected
        assert_contains_file(&args.inputs, "kernel32.lib");
        assert_contains_file(&args.inputs, "ntdll.lib");
        assert_contains_file(&args.inputs, "userenv.lib");
        assert_contains_file(&args.inputs, "ws2_32.lib");
        assert_contains_file(&args.inputs, "dbghelp.lib");

        // Test that rlib files were collected
        assert!(args.inputs.iter().any(|input| {
            match &input.spec {
                InputSpec::File(path) => path
                    .to_string_lossy()
                    .contains("libstd-efa6c7783284bd31.rlib"),
                _ => false,
            }
        }));
        assert!(args.inputs.iter().any(|input| {
            match &input.spec {
                InputSpec::File(path) => path
                    .to_string_lossy()
                    .contains("libcore-a55e6b132b0b5f5d.rlib"),
                _ => false,
            }
        }));

        // Test that /defaultlib was handled and added library to inputs
        assert_contains_lib(&args.inputs, "msvcrt");

        // Verify some key libraries are present
        let lib_names: Vec<&str> = args
            .inputs
            .iter()
            .filter_map(|input| match &input.spec {
                InputSpec::Lib(lib_name) => Some(lib_name.as_ref()),
                _ => None,
            })
            .collect();
        assert!(lib_names.contains(&"msvcrt"));
    }

    #[test]
    fn test_minimal_windows_args() {
        let minimal_args = &[
            "--target=x86_64-pc-windows-msvc",
            "/OUT:test.exe",
            "/DEBUG",
            "test.obj",
        ];

        let args = unwrap_pe(crate::args::parse(|| minimal_args.iter())
            .unwrap());

        assert_eq!(args.output.as_ref(), Path::new("test.exe"));
        println!("Debug info value: {}", args.debug_info);
        assert!(args.debug_info);
        assert_contains_file(&args.inputs, "test.obj");
    }

    #[test]
    fn test_debug_flag_simple() {
        let minimal_args = &["--target=x86_64-pc-windows-msvc","/DEBUG"];

        let result = crate::args::parse(|| minimal_args.iter());
        match result {
            Ok(args) => {
                let windows_args = unwrap_pe(args);
                println!(
                    "Simple debug test - Debug info value: {}",
                    windows_args.debug_info
                );
                println!(
                    "Unrecognized options: {:?}",
                    windows_args.unrecognized_options
                );
                assert!(windows_args.debug_info);
            }
            Err(e) => {
                println!("Parse error: {:?}", e);
                panic!("Failed to parse arguments: {:?}", e);
            }
        }
    }

    #[test]
    fn test_defaultlib_parsing() {
        let minimal_args = &["--target=x86_64-pc-windows-msvc","/defaultlib:msvcrt"];

        let args = unwrap_pe(crate::args::parse(|| minimal_args.iter())
            .unwrap());

        let lib_names: Vec<&str> = args
            .inputs
            .iter()
            .filter_map(|input| match &input.spec {
                InputSpec::Lib(lib_name) => Some(lib_name.as_ref()),
                _ => None,
            })
            .collect();

        println!("Found libraries: {:?}", lib_names);
        println!("Unrecognized options: {:?}", args.unrecognized_options);

        assert_contains_lib(&args.inputs, "msvcrt");
    }

    #[test]
    fn test_required_parameters() {
        // Test that IMPLIB requires a parameter
        let implib_args = &["--target=x86_64-pc-windows-msvc","/IMPLIB"];

        let result = crate::args::parse(|| implib_args.iter());
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
        let export_args = &["--target=x86_64-pc-windows-msvc","/EXPORT"];

        let result = crate::args::parse(|| export_args.iter());
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
        let version_args = &["--target=x86_64-pc-windows-msvc","/VERSION"];

        let result = crate::args::parse(|| version_args.iter());
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
        // Test that unimplemented options return proper error messages
        let appcontainer_args = &["--target=x86_64-pc-windows-msvc","/APPCONTAINER"];

        let result = crate::args::parse(|| appcontainer_args.iter());
        match result {
            Ok(_) => panic!("Expected error for unimplemented APPCONTAINER option"),
            Err(e) => {
                let error_msg = format!("{:?}", e);
                assert!(
                    error_msg.contains("not yet implemented") && error_msg.contains("APPCONTAINER"),
                    "Error should mention APPCONTAINER is not implemented: {}",
                    error_msg
                );
            }
        }

        // Test another unimplemented option
        let assemblydebug_args = &["--target=x86_64-pc-windows-msvc","/ASSEMBLYDEBUG"];

        let result = crate::args::parse(|| assemblydebug_args.iter());
        match result {
            Ok(_) => panic!("Expected error for unimplemented ASSEMBLYDEBUG option"),
            Err(e) => {
                let error_msg = format!("{:?}", e);
                assert!(
                    error_msg.contains("not yet implemented")
                        && error_msg.contains("ASSEMBLYDEBUG"),
                    "Error should mention ASSEMBLYDEBUG is not implemented: {}",
                    error_msg
                );
            }
        }
    }

    #[test]
    fn test_case_insensitive_parsing() {
        // Test uppercase /ENTRY:main and /OUT:test.exe
        let args_upper = &["--target=x86_64-pc-windows-msvc","/ENTRY:main", "/OUT:test.exe"];
        let result_upper = unwrap_pe(crate::args::parse(|| args_upper.iter())
            .unwrap());
        assert_eq!(result_upper.entry, Some("main".to_string()));
        assert_eq!(result_upper.output.as_ref(), Path::new("test.exe"));

        // Test lowercase /entry:main and /out:test.exe
        let args_lower = &["--target=x86_64-pc-windows-msvc","/entry:main", "/out:test.exe"];
        let result_lower = unwrap_pe(crate::args::parse(|| args_lower.iter())
            .unwrap());
        assert_eq!(result_lower.entry, Some("main".to_string()));
        assert_eq!(result_lower.output.as_ref(), Path::new("test.exe"));

        // Test mixed case /Entry:main and /Out:test.exe
        let args_mixed = &["--target=x86_64-pc-windows-msvc","/Entry:main", "/Out:test.exe"];
        let result_mixed = unwrap_pe(crate::args::parse(|| args_mixed.iter())
            .unwrap());
        assert_eq!(result_mixed.entry, Some("main".to_string()));
        assert_eq!(result_mixed.output.as_ref(), Path::new("test.exe"));
    }

    #[test]
    fn test_nodefaultlib_parsing() {
        // Test /NODEFAULTLIB without parameter (ignore all default libraries)
        let args_all = &["--target=x86_64-pc-windows-msvc","/NODEFAULTLIB"];
        let result_all = unwrap_pe(crate::args::parse(|| args_all.iter())
            .unwrap());
        assert!(result_all.ignore_all_default_libs);
        assert!(result_all.no_default_libs.is_empty());

        // Test /NODEFAULTLIB with specific library name
        let args_specific = &["--target=x86_64-pc-windows-msvc","/NODEFAULTLIB:msvcrt"];
        let result_specific = unwrap_pe(crate::args::parse(|| args_specific.iter())
            .unwrap());
        assert!(!result_specific.ignore_all_default_libs);
        assert_eq!(result_specific.no_default_libs, vec!["msvcrt"]);

        // Test multiple specific libraries
        let args_multiple = &[
            "--target=x86_64-pc-windows-msvc",
            "/NODEFAULTLIB:msvcrt",
            "/NODEFAULTLIB:kernel32",
        ];
        let result_multiple = unwrap_pe(crate::args::parse(|| args_multiple.iter())
            .unwrap());
        assert!(!result_multiple.ignore_all_default_libs);
        assert_eq!(result_multiple.no_default_libs, vec!["msvcrt", "kernel32"]);

        // Test case-insensitive matching
        let args_case_insensitive = &["--target=x86_64-pc-windows-msvc","/nodefaultlib:msvcrt"];
        let result_case_insensitive = unwrap_pe(crate::args::parse(|| args_case_insensitive.iter())
            .unwrap());
        assert!(!result_case_insensitive.ignore_all_default_libs);
        assert_eq!(result_case_insensitive.no_default_libs, vec!["msvcrt"]);
    }

    #[test]
    fn test_nodefaultlib_helper_methods() {
        // Test helper methods for ignore all default libraries
        let args_all = &["--target=x86_64-pc-windows-msvc","/NODEFAULTLIB"];
        let result_all = unwrap_pe(crate::args::parse(|| args_all.iter())
            .unwrap());

        assert!(result_all.ignores_all_default_libs());
        assert!(result_all.should_ignore_default_lib("msvcrt"));
        assert!(result_all.should_ignore_default_lib("kernel32"));
        assert!(result_all.ignored_default_libs().is_empty());

        // Test helper methods for specific libraries
        let args_specific = &[
            "--target=x86_64-pc-windows-msvc",
            "/NODEFAULTLIB:msvcrt",
            "/NODEFAULTLIB:kernel32",
        ];
        let result_specific = unwrap_pe(crate::args::parse(|| args_specific.iter())
            .unwrap());

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
