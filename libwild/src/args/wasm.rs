use crate::alignment::Alignment;
use crate::args::ArgumentParser;
use crate::args::CommonArgs;
use crate::args::Input;
use crate::args::InputSpec;
use crate::args::Modifiers;
use crate::args::VersionMode;
use crate::args::parse_number;
use crate::bail;
use crate::error::Result;
use crate::platform;
use crate::platform::Args as _;
use std::path::Path;
use std::sync::Arc;

/// Loadable segment alignment for wasm. Wasm doesn't really have program
/// segments in the ELF sense, but we still need to provide a value for the
/// `Args` trait.
pub(crate) const WASM_PAGE_ALIGNMENT: Alignment = Alignment { exponent: 16 };

/// Default page size (in bytes) for a wasm linear memory page.
pub(crate) const WASM_PAGE_SIZE: u64 = WASM_PAGE_ALIGNMENT.value();

/// Default main stack size.
pub(crate) const DEFAULT_STACK_SIZE: u32 = 64 * 1024;

/// Default entry symbol for Wasm command modules.
pub(crate) const DEFAULT_ENTRY: &str = "_start";

/// Default export name for the module's linear memory.
pub(crate) const DEFAULT_MEMORY_EXPORT_NAME: &str = "memory";

#[derive(Debug)]
pub struct WasmArgs {
    pub(crate) common: super::CommonArgs,
    pub(crate) lib_search_path: Vec<Box<Path>>,
    pub(crate) export_symbols: Vec<String>,
    pub(crate) required_export_symbols: Vec<String>,
    pub(crate) extra_features: Vec<String>,
    pub(crate) export_memory: Option<String>,
    pub(crate) z_stack_size: u32,
    // Since LLVM 22, the default option is true.
    pub(crate) stack_first: bool,
    // Entry symbol name. Defaults to `DEFAULT_ENTRY`.
    pub(crate) entry: Option<String>,
    // When set, the output `memory.initial` is raised to at least this many bytes (must be
    // page-aligned). `None` means size is derived from data / stack layout only.
    pub(crate) initial_memory: Option<u64>,
    pub(crate) max_memory: Option<u64>,
    // Emit a shared linear memory (`memory.shared`). Requires the `atomics` and `bulk-memory`
    // target features.
    pub(crate) shared_memory: bool,
    pub(crate) gc_sections: bool,
    pub(crate) allow_undefined: bool,
    pub(crate) allow_multiple_definition: bool,
}

impl WasmArgs {
    pub(crate) fn new() -> Result<Self> {
        Ok(Self {
            common: CommonArgs::from_env()?,
            ..Default::default()
        })
    }

    pub(crate) fn memory_export_name(&self) -> &str {
        self.export_memory
            .as_deref()
            .unwrap_or(DEFAULT_MEMORY_EXPORT_NAME)
    }
}

impl Default for WasmArgs {
    fn default() -> Self {
        Self {
            common: CommonArgs::default(),
            lib_search_path: Vec::new(),
            extra_features: Vec::new(),
            export_symbols: Vec::new(),
            required_export_symbols: Vec::new(),
            z_stack_size: DEFAULT_STACK_SIZE,
            stack_first: true,
            entry: Some(DEFAULT_ENTRY.to_owned()),
            initial_memory: None,
            max_memory: None,
            shared_memory: false,
            export_memory: None,
            gc_sections: true,
            allow_undefined: false,
            allow_multiple_definition: false,
        }
    }
}

impl platform::Args for WasmArgs {
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

    fn entry_point<'a>(
        &'a self,
        _linker_script_entry: Option<&'a [u8]>,
    ) -> platform::EntryPoint<'a> {
        self.entry
            .as_deref()
            .map_or(platform::EntryPoint::None, |entry| {
                platform::EntryPoint::Symbol(entry.as_bytes())
            })
    }

    fn force_export_symbol_names(&self) -> &[String] {
        &self.export_symbols
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

    fn should_export_all_dynamic_symbols(&self) -> bool {
        todo!()
    }

    fn should_export_dynamic(&self, _lib_name: &[u8]) -> bool {
        todo!()
    }

    fn loadable_segment_alignment(&self) -> crate::alignment::Alignment {
        WASM_PAGE_ALIGNMENT
    }

    fn should_gc_sections(&self) -> bool {
        self.gc_sections
    }

    fn should_merge_sections(&self) -> bool {
        // TODO
        true
    }

    fn should_output_executable(&self) -> bool {
        // TODO
        true
    }

    fn is_ignored_flag(&self, _flag: &str) -> bool {
        false
    }

    fn allow_multiple_definitions(&self) -> bool {
        self.allow_multiple_definition
    }
}

pub(crate) fn parse<S: AsRef<str>, I: Iterator<Item = S>>(
    args: &mut WasmArgs,
    mut input: I,
) -> Result {
    let mut modifier_stack = vec![Modifiers::default()];

    let arg_parser = setup_argument_parser();
    while let Some(arg) = input.next() {
        let arg = arg.as_ref();

        arg_parser.handle_argument(args, &mut modifier_stack, arg, &mut input)?;
    }

    args.common.report_unrecognized()?;

    Ok(())
}

fn setup_argument_parser() -> ArgumentParser<WasmArgs> {
    let mut parser = ArgumentParser::<WasmArgs>::new();

    parser
        .declare_with_param()
        .long("output")
        .short("o")
        .help("Set the output filename")
        .execute(|args, _modifier_stack, value| {
            args.common.output = Arc::from(Path::new(value));
            Ok(())
        });

    parser
        .declare_with_param()
        .prefix("L")
        .help("Add directory to library search path")
        .execute(|args, _modifier_stack, value| {
            args.common.save_dir.handle_file(value);
            args.lib_search_path.push(Box::from(Path::new(value)));
            Ok(())
        });

    parser
        .declare_with_param()
        .prefix("l")
        .help("Link with library")
        .execute(|args, modifier_stack, value| {
            // Prefer static archives. Wasm has no shared-object loading.
            let mut modifiers = *modifier_stack.last().unwrap();
            modifiers.allow_shared = false;
            let spec = if let Some(stripped) = value.strip_prefix(':') {
                InputSpec::Search(Box::from(stripped))
            } else {
                InputSpec::Lib(Box::from(value))
            };
            args.common.inputs.push(Input {
                spec,
                search_first: None,
                modifiers,
            });
            Ok(())
        });

    parser
        .declare()
        .long("gc-sections")
        .help("Enable removal of unused sections (default)")
        .execute(|args, _modifier_stack| {
            args.gc_sections = true;
            Ok(())
        });

    parser
        .declare()
        .long("no-gc-sections")
        .help("Disable removal of unused sections")
        .execute(|args, _modifier_stack| {
            args.gc_sections = false;
            Ok(())
        });

    parser
        .declare_with_param()
        .long("export")
        .help("Force a symbol to be exported")
        .execute(|args, _modifier_stack, value| {
            let value = value.to_owned();
            args.export_symbols.push(value.clone());
            args.required_export_symbols.push(value);
            Ok(())
        });

    parser
        .declare_with_param()
        .long("export-if-defined")
        .help("Export a symbol if it is defined")
        .execute(|args, _modifier_stack, value| {
            args.export_symbols.push(value.to_owned());
            Ok(())
        });

    parser
        .declare_with_optional_param()
        .long("export-memory")
        .help("Export the module's memory (default name \"memory\")")
        .execute(|args, _modifier_stack, value| {
            args.export_memory = Some(value.unwrap_or(DEFAULT_MEMORY_EXPORT_NAME).to_owned());
            Ok(())
        });

    parser
        .declare_with_param()
        .long("extra-features")
        .help("Comma-separated list of features to add to the default set of features inferred from input objects")
        .execute(|args, _modifier_stack, value| {
            args.extra_features = value
                .split(',')
                .filter(|feature| !feature.is_empty())
                .map(str::to_owned)
                .collect();
            Ok(())
        });

    parser
        .declare()
        .long("no-entry")
        .help("Do not output any entry point (reactor module)")
        .execute(|args, _modifier_stack| {
            args.entry = None;
            Ok(())
        });

    parser
        .declare_with_param()
        .long("entry")
        .short("e")
        .help("Name of entry point symbol")
        .execute(|args, _modifier_stack, value| {
            args.entry = Some(value.to_owned());
            Ok(())
        });

    parser
        .declare_with_param()
        .long("mllvm")
        .help("Pass an LLVM option")
        .execute(|args, _modifier_stack, value| args.warn_unsupported(&format!("-mllvm {value}")));

    parser
        .declare_with_param()
        .prefix("m")
        .help("Set target architecture")
        .sub_option("wasm32", "Wasm32 target", |_args, _| Ok(()))
        .execute(|_args, _modifier_stack, value| {
            bail!("-m {value} is not supported for Wasm");
        });

    parser
        .declare_with_param()
        .prefix("z")
        .help("Linker options")
        .sub_option("muldefs", "Allow multiple definitions", |args, _| {
            args.allow_multiple_definition = true;
            Ok(())
        })
        .sub_option_with_value(
            "stack-size=",
            "Set the main stack size in linear memory",
            |args, _, value| {
                let size = parse_number(value)?;
                args.z_stack_size = u32::try_from(size)
                    .map_err(|_| crate::error!("-z stack-size is too large for Wasm32: {size}"))?;
                Ok(())
            },
        )
        .execute(|args, _modifier_stack, value| {
            args.warn_unsupported(&(format!("-z {value}")))?;
            Ok(())
        });

    parser
        .declare()
        .long("stack-first")
        .help("Place stack at start of linear memory rather than after data")
        .execute(|args, _modifier_stack| {
            args.stack_first = true;
            Ok(())
        });

    parser
        .declare()
        .long("no-stack-first")
        .help("Place stack at the end of linear memory after data")
        .execute(|args, _modifier_stack| {
            args.stack_first = false;
            Ok(())
        });

    parser
        .declare_with_param()
        .long("initial-memory")
        .help("Initial size of the linear memory in bytes")
        .execute(|args, _modifier_stack, value| {
            args.initial_memory = Some(parse_number(value)?);
            Ok(())
        });

    parser
        .declare()
        .long("allow-undefined")
        .help("Allow undefined symbols in the output")
        .execute(|args, _modifier_stack| {
            args.allow_undefined = true;
            Ok(())
        });

    parser
        .declare()
        .long("allow-multiple-definition")
        .help("Allow multiple definitions of symbols in the output")
        .execute(|args, _modifier_stack| {
            args.allow_multiple_definition = true;
            Ok(())
        });

    parser
        .declare()
        .long("no-allow-multiple-definition")
        .help("Disallow multiple definitions of symbols in the output (default)")
        .execute(|args, _modifier_stack| {
            args.allow_multiple_definition = false;
            Ok(())
        });

    parser
        .declare_with_param()
        .long("max-memory")
        .help("Maximum size of the linear memory in bytes")
        .execute(|args, _modifier_stack, value| {
            args.max_memory = Some(parse_number(value)?);
            Ok(())
        });

    parser
        .declare()
        .long("shared-memory")
        .help("Use shared linear memory")
        .execute(|args, _modifier_stack| {
            args.shared_memory = true;
            Ok(())
        });

    parser
        .declare_with_param()
        .prefix("O")
        .execute(|_args, _modifier_stack, _value|
        // We don't use opt-level for now.
        Ok(()));

    parser
        .declare()
        .long("demangle")
        .help("Demangle symbol names (default)")
        .execute(|args, _modifier_stack| {
            args.common_mut().demangle = true;
            Ok(())
        });

    parser
        .declare()
        .long("no-demangle")
        .help("Disable symbol demangling")
        .execute(|args, _modifier_stack| {
            args.common_mut().demangle = false;
            Ok(())
        });

    parser
        .declare()
        .long("help")
        .help("Show this help message")
        .execute(|_args, _modifier_stack| {
            use std::io::Write as _;
            let parser = setup_argument_parser();
            let mut stdout = std::io::stdout().lock();
            writeln!(stdout, "{}", parser.generate_help())?;
            std::process::exit(0);
        });

    parser
        .declare()
        .long("version")
        .help("Show version information and exit")
        .execute(|args, _modifier_stack| {
            args.common.version_mode = VersionMode::ExitAfterPrint;
            Ok(())
        });

    parser
        .declare()
        .short("v")
        .short("V")
        .help("Print version and continue linking if object files are specified")
        .execute(|args, _modifier_stack| {
            args.common.version_mode = VersionMode::Verbose;
            Ok(())
        });

    parser
        .declare()
        .long("merge-data-segments")
        .help("Merge data segments")
        .execute(|args, _modifier_stack| {
            // TODO: implement and make it default.
            args.warn_unsupported("--merge-data-segments")?;
            Ok(())
        });

    parser
        .declare()
        .long("no-merge-data-segments")
        .help("Disable data segment merging (default)")
        .execute(|_args, _modifier_stack| Ok(()));

    super::declare_common_args(&mut parser);

    parser
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::Args;

    fn parse_args<'a>(args: impl IntoIterator<Item = &'a str>) -> WasmArgs {
        let mut wasm_args = WasmArgs::new().unwrap();
        Args::parse(&mut wasm_args, args.into_iter()).unwrap();
        wasm_args
    }

    #[test]
    fn parse_export_space_and_equals() {
        let args = parse_args(["--export", "foo", "--export=bar", "-o", "out.wasm"]);
        assert_eq!(args.export_symbols, ["foo", "bar"]);
        assert_eq!(Args::force_export_symbol_names(&args), ["foo", "bar"]);
    }

    #[test]
    fn export_is_not_treated_as_input_path() {
        let args = parse_args(["--export", "__main_void", "-o", "out.wasm"]);
        assert_eq!(args.export_symbols, ["__main_void"]);
        assert_eq!(args.common.inputs, []);
    }

    #[test]
    fn export_if_defined() {
        let args = parse_args([
            "--export-if-defined",
            "foo",
            "--export=bar",
            "--export-if-defined=baz",
            "-o",
            "out.wasm",
        ]);

        assert_eq!(args.export_symbols, ["foo", "bar", "baz"]);
        assert_eq!(args.required_export_symbols, ["bar"]);
        assert_eq!(
            Args::force_export_symbol_names(&args),
            ["foo", "bar", "baz"]
        );
    }

    #[test]
    fn extra_features() {
        assert_eq!(
            parse_args(["--extra-features=foo,bar", "-o", "out.wasm"]).extra_features,
            ["foo", "bar"]
        );
        assert_eq!(
            parse_args(["--extra-features=a", "--extra-features=b", "-o", "out.wasm"])
                .extra_features,
            ["b"]
        );
        assert!(
            parse_args(["--extra-features=", "-o", "out.wasm"])
                .extra_features
                .is_empty()
        );
    }
}
