use crate::alignment::MACHO_PAGE_ALIGNMENT;
use crate::args::ArgumentParser;
use crate::args::CommonArgs;
use crate::args::FileWriteMode;
use crate::args::Modifiers;
use crate::args::RelocationModel;
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

    pub(crate) output: Arc<Path>,
    pub(crate) relocation_model: RelocationModel,
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

impl Default for MachOArgs {
    fn default() -> Self {
        Self {
            common: CommonArgs::default(),
            platform_version: None,
            sysroot: None,

            // TODO: move to CommonArgs
            relocation_model: RelocationModel::NonRelocatable,
            output: Arc::from(Path::new("a.out")),
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
        todo!()
    }

    fn output(&self) -> &std::sync::Arc<std::path::Path> {
        &self.output
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
        MACHO_PAGE_ALIGNMENT
    }

    fn should_merge_sections(&self) -> bool {
        // TODO
        true
    }

    fn relocation_model(&self) -> crate::args::RelocationModel {
        self.relocation_model
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
            args.sysroot = Some(Box::from(sysroot.as_path()));
            Ok(())
        });
    parser
        .declare_with_param()
        .long("output")
        .short("o")
        .help("Set the output filename")
        .execute(|args, _modifier_stack, value| {
            args.output = Arc::from(Path::new(value));
            Ok(())
        });
    parser
        .declare_with_optional_param()
        .long("time")
        .help("Show timing information")
        .execute(|args, _modifier_stack, value| {
            args.common.time_phase_options = match value {
                Some(v) => Some(super::parse_time_phase_options(v)?),
                None => Some(Vec::new()),
            };
            Ok(())
        });
    parser
        .declare()
        .long("validate-output")
        .execute(|args, _modifier_stack| {
            args.common_mut().validate_output = true;
            Ok(())
        });
    parser
        .declare()
        .long("update-in-place")
        .help("Update file in place")
        .execute(|args, _modifier_stack| {
            args.common_mut().file_write_mode = Some(FileWriteMode::UpdateInPlace);
            Ok(())
        });

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

    const INPUT1: &[&str] = &[
        "-arch",
        "arm64",
        "-no_deduplicate",
        "-platform_version",
        "macos",
        "14.0",
        "15.0",
        "-demangle",
        "-syslibroot",
        "/foo/bar",
        "-o",
        "a.out",
        "main.o",
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
    }

    #[test]
    fn test_parse_inline_only_options() {
        let mut args = MachOArgs::new().unwrap();
        args.parse(INPUT1.iter()).unwrap();
        input1_assertions(&args);
    }
}
