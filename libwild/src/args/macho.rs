use crate::alignment::MACHO_PAGE_ALIGNMENT;
use crate::args::ArgumentParser;
use crate::args::CommonArgs;
use crate::args::Input;
use crate::args::InputSpec;
use crate::args::Modifiers;
use crate::bail;
use crate::error::Result;
use crate::platform;
use crate::platform::Args;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug)]
pub struct MachOArgs {
    pub(crate) common: super::CommonArgs,

    pub(crate) platform_version: Option<PlatformVersion>,
    pub(crate) sysroot: Option<Box<Path>>,
    pub(crate) lib_search_path: Vec<Box<Path>>,
    pub(crate) plugin_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlatformVersion {
    pub(crate) platform: String,
    pub(crate) minimum_version: String,
    pub(crate) sdk_version: String,
}

const SILENTLY_IGNORED_FLAGS: &[&str] = &[
    "no_deduplicate",
    // Mach-O appears to always demangle symbols.
    "demangle",
    "dynamic",
];

const IGNORED_FLAGS: &[&str] = &[];

impl MachOArgs {
    pub(crate) fn new() -> Result<Self> {
        Ok(Self {
            common: CommonArgs::from_env()?,
            ..Default::default()
        })
    }
}

#[expect(clippy::derivable_impls)]
impl Default for MachOArgs {
    fn default() -> Self {
        Self {
            common: CommonArgs::default(),
            platform_version: None,
            sysroot: None,
            lib_search_path: Vec::new(),
            plugin_path: None,
        }
    }
}

impl platform::Args for MachOArgs {
    fn parse<S, I>(&mut self, input: I) -> Result
    where
        S: AsRef<str>,
        I: Iterator<Item = S>,
    {
        parse(self, input)
    }

    fn should_strip_debug(&self) -> bool {
        todo!()
    }

    fn should_strip_all(&self) -> bool {
        false
    }

    fn entry_symbol_name<'a>(&'a self, _linker_script_entry: Option<&'a [u8]>) -> &'a [u8] {
        // TODO: probably add option
        b"_main"
    }

    fn lib_search_path(&self) -> &[Box<std::path::Path>] {
        &self.lib_search_path
    }

    fn common(&self) -> &crate::args::CommonArgs {
        &self.common
    }

    fn common_mut(&mut self) -> &mut crate::args::CommonArgs {
        &mut self.common
    }

    fn sysroot(&self) -> Option<&Path> {
        self.sysroot.as_deref()
    }

    fn should_export_all_dynamic_symbols(&self) -> bool {
        false
    }

    fn should_export_dynamic(&self, _lib_name: &[u8]) -> bool {
        todo!()
    }

    fn loadable_segment_alignment(&self) -> crate::alignment::Alignment {
        MACHO_PAGE_ALIGNMENT
    }

    fn should_merge_sections(&self) -> bool {
        // TODO
        true
    }

    fn should_output_executable(&self) -> bool {
        // TODO
        true
    }

    fn is_ignored_flag(&self, flag: &str) -> bool {
        IGNORED_FLAGS.contains(&flag)
    }
}

// Parse the supplied input arguments, which should not include the program name.
pub(crate) fn parse<S: AsRef<str>, I: Iterator<Item = S>>(
    args: &mut MachOArgs,
    mut input: I,
) -> Result {
    let mut modifier_stack = vec![Modifiers::default()];

    let arg_parser = setup_argument_parser();
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

// TODO: apparently the Mach-O system linker support neither long variants nor the prefixed
// variants.
fn setup_argument_parser() -> ArgumentParser<MachOArgs> {
    let mut parser = ArgumentParser::<MachOArgs>::new();

    parser
        .declare_with_param()
        .prefix("arch")
        .help("Set target architecture")
        .sub_option("arm64", "AArch64 Mach-O target", |_, _| Ok(()))
        .execute(|_, _modifier_stack, value| {
            bail!("-arch {value} is not yet supported");
        });
    parser
        .declare_with_three_params()
        .long("platform_version")
        .help("Set deployment target and the SDK version")
        .execute(
            |args, _modifier_stack, platform, minimum_version, sdk_version| {
                args.platform_version = Some(PlatformVersion {
                    platform: platform.to_owned(),
                    minimum_version: minimum_version.to_owned(),
                    sdk_version: sdk_version.to_owned(),
                });
                Ok(())
            },
        );
    parser
        .declare_with_param()
        .long("syslibroot")
        .help("Set system root")
        .execute(|args, _modifier_stack, value| {
            args.common_mut().save_dir.handle_file(value);
            let sysroot = std::fs::canonicalize(value).unwrap_or_else(|_| PathBuf::from(value));
            // TODO: handle properly
            args.lib_search_path = vec![sysroot.join("usr/lib").into_boxed_path()];
            args.sysroot = Some(Box::from(sysroot.as_path()));
            Ok(())
        });
    parser
        .declare_with_param()
        .long("lto_library")
        .help("Load plugin")
        .execute(|args, _modifier_stack, value| {
            args.plugin_path = Some(value.to_owned());
            Ok(())
        });
    parser
        .declare_with_param()
        .short("mllvm")
        .help("Pass an LLVM option")
        .execute(|args, _modifier_stack, value| match value {
            "-enable-linkonceodr-outlining" => Ok(()),
            _ => args.warn_unsupported(&format!("-mllvm {value}")),
        });
    parser
        .declare_with_param()
        .prefix("L")
        .help("Add directory to library search path")
        .execute(|args, _modifier_stack, value| {
            args.common_mut().save_dir.handle_file(value);
            args.lib_search_path.push(Box::from(Path::new(value)));
            Ok(())
        });
    parser
        .declare_with_param()
        .prefix("l")
        .help("Link with library")
        .sub_option_with_value(
            ":filename",
            "Link with specific file",
            |args, modifier_stack, value| {
                let stripped = value.strip_prefix(':').unwrap_or(value);
                let spec = InputSpec::File(Box::from(Path::new(stripped)));
                args.common_mut().inputs.push(Input {
                    spec,
                    search_first: None,
                    modifiers: *modifier_stack.last().unwrap(),
                });
                Ok(())
            },
        )
        .sub_option_with_value(
            "libname",
            "Link with library libname.dylib or libname.a",
            |args, modifier_stack, value| {
                let spec = InputSpec::Lib(Box::from(value));
                args.common_mut().inputs.push(Input {
                    spec,
                    search_first: None,
                    modifiers: *modifier_stack.last().unwrap(),
                });
                Ok(())
            },
        )
        .execute(|args, modifier_stack, value| {
            let spec = if let Some(stripped) = value.strip_prefix(':') {
                InputSpec::Search(Box::from(stripped))
            } else {
                InputSpec::Lib(Box::from(value))
            };
            args.common_mut().inputs.push(Input {
                spec,
                search_first: None,
                modifiers: *modifier_stack.last().unwrap(),
            });
            Ok(())
        });
    // The option declaration cannot be moved to declare_common_args as other platforms
    // use `prefix("o")`.
    parser
        .declare_with_param()
        .long("output")
        .short("o")
        .help("Set the output filename")
        .execute(|args, _modifier_stack, value| {
            args.common_mut().output = Arc::from(Path::new(value));
            Ok(())
        });

    super::declare_common_args(&mut parser);

    add_silently_ignored_flags(&mut parser);

    parser
}

fn add_silently_ignored_flags(parser: &mut ArgumentParser<MachOArgs>) {
    for flag in SILENTLY_IGNORED_FLAGS {
        let mut declaration = parser.declare();
        declaration = declaration.long(flag);
        declaration.execute(|_args, _modifier_stack| Ok(()));
    }
}

#[cfg(test)]
mod tests {
    use super::MachOArgs;
    use super::PlatformVersion;
    use crate::args::InputSpec;
    use crate::platform::Args as _;
    use std::path::Path;
    use std::sync::Arc;
    use std::sync::Mutex;

    const INPUT1: &[&str] = &[
        "-arch",
        "arm64",
        "-lto_library",
        "/foo/bar/libLTO.dylib",
        "-no_deduplicate",
        "-platform_version",
        "macos",
        "14.0",
        "15.0",
        "-demangle",
        "-syslibroot",
        "/foo/bar",
        "-mllvm",
        "-enable-linkonceodr-outlining",
        "-o",
        "a.out",
        "-L/foo/lib",
        "-L",
        "/bar/lib",
        "main.o",
        "-lc++",
    ];

    fn input1_assertions(args: &MachOArgs) {
        assert_eq!(
            args.platform_version,
            Some(PlatformVersion {
                platform: "macos".to_owned(),
                minimum_version: "14.0".to_owned(),
                sdk_version: "15.0".to_owned(),
            })
        );
        assert!(args.common.demangle);
        assert_eq!(args.sysroot, Some(Box::from(Path::new("/foo/bar"))));
        assert!(args.common.inputs.iter().any(|i| match &i.spec {
            InputSpec::File(f) => f.as_ref() == Path::new("main.o"),
            InputSpec::Lib(_) | InputSpec::Search(_) => false,
        }));
        assert!(args.common.inputs.iter().any(|i| match &i.spec {
            InputSpec::Lib(f) => f.as_ref() == "c++",
            InputSpec::File(_) | InputSpec::Search(_) => false,
        }));
        assert!(
            args.lib_search_path
                .iter()
                .any(|p| p.as_ref() == Path::new("/foo/lib"))
        );
        assert!(
            args.lib_search_path
                .iter()
                .any(|p| p.as_ref() == Path::new("/bar/lib"))
        );
        assert_eq!(args.plugin_path, Some("/foo/bar/libLTO.dylib".to_owned()));
    }

    #[test]
    fn test_parse_inline_only_options() {
        let mut args = MachOArgs::new().unwrap();
        let warnings = Arc::new(Mutex::new(Vec::new()));
        let warnings_clone = warnings.clone();
        args.common.warning_callback = Box::new(move |warning| {
            warnings_clone
                .lock()
                .unwrap()
                .push(warning.warning().to_owned());
        });
        args.parse(INPUT1.iter()).unwrap();
        input1_assertions(&args);
        assert!(warnings.lock().unwrap().is_empty());
    }
}
