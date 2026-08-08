use crate::args::CommonArgs;
use crate::args::Input;
use crate::args::InputSpec;
use crate::args::Modifiers;
use crate::bail;
use crate::error::Result;
use crate::platform;
use std::path::Path;
use std::sync::Arc;

/// The only machine type we currently support.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CoffMachine {
    X86_64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Subsystem {
    Console,
    Windows,
}

#[derive(Debug)]
pub struct CoffArgs {
    pub(crate) common: CommonArgs,
    pub(crate) entry: Option<String>,
    pub(crate) subsystem: Option<Subsystem>,
    pub(crate) is_dll: bool,
    pub(crate) machine: CoffMachine,
    pub(crate) lib_search_path: Vec<Box<Path>>,
    pub(crate) default_libraries: Vec<String>,
    /// Libraries named by `/NODEFAULTLIB:name`.
    pub(crate) excluded_default_libraries: Vec<String>,
    /// Set by a bare `/NODEFAULTLIB`, which ignores every default library.
    pub(crate) no_default_libraries: bool,
}

impl CoffArgs {
    pub(crate) fn new() -> Result<Self> {
        Ok(Self {
            common: CommonArgs::from_env()?,
            ..Default::default()
        })
    }
}

impl Default for CoffArgs {
    fn default() -> Self {
        Self {
            common: CommonArgs::default(),
            entry: None,
            subsystem: None,
            is_dll: false,
            machine: CoffMachine::X86_64,
            lib_search_path: Vec::new(),
            default_libraries: Vec::new(),
            excluded_default_libraries: Vec::new(),
            no_default_libraries: false,
        }
    }
}

impl platform::Args for CoffArgs {
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

    fn lib_search_path(&self) -> &[Box<Path>] {
        &self.lib_search_path
    }

    fn common(&self) -> &CommonArgs {
        &self.common
    }

    fn common_mut(&mut self) -> &mut CommonArgs {
        &mut self.common
    }

    fn should_export_all_dynamic_symbols(&self) -> bool {
        todo!()
    }

    fn should_export_dynamic(&self, _lib_name: &[u8]) -> bool {
        todo!()
    }

    fn loadable_segment_alignment(&self) -> crate::alignment::Alignment {
        todo!()
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
}

// Parse the supplied input arguments, which should not include the program name.
pub(crate) fn parse<S: AsRef<str>, I: Iterator<Item = S>>(args: &mut CoffArgs, input: I) -> Result {
    let tokens = input.map(|arg| arg.as_ref().to_owned()).collect::<Vec<_>>();

    parse_tokens(args, tokens.iter().map(String::as_str))?;

    args.common.report_unrecognized()
}

/// Options that rustc's MSVC linker driver emits that we recognise but ignore, because they only
/// affect outputs we don't produce yet or optimisations we don't implement.
const IGNORED_OPTIONS: &[&str] = &[
    // Debug info, PDB paths, import library, visualisers, module definition file and
    // optimisations.
    "debug",
    "pdb",
    "pdbaltpath",
    "implib",
    "natvis",
    "def",
    "opt",
    // Control-flow guard, e.g. `/guard:cf`, and archive member handling.
    "guard",
    "wholearchive",
    // Take an optional `:NO` value, e.g. `/NXCOMPAT:NO`.
    "nxcompat",
    "dynamicbase",
    // Manifest generation and warnings-as-errors, e.g. `/MANIFEST:EMBED`, `/MANIFESTUAC:NO`,
    // `/MANIFESTINPUT:foo.manifest`, `/WX:NO`.
    "manifest",
    "manifestinput",
    "manifestuac",
    "wx",
];

/// Ignored options that take no value, so `/NOLOGO:x` is an error just like `/DLL:x` is.
const IGNORED_NO_VALUE_OPTIONS: &[&str] = &["nologo"];

/// MSVC options don't fit the GNU-style declarative parser used by the other platforms: names are
/// case-insensitive, take either a `/` or a `-` prefix and carry their value as `NAME:value`.
fn parse_tokens<'a, I: Iterator<Item = &'a str>>(args: &mut CoffArgs, input: I) -> Result {
    for arg in input {
        let Some(option) = arg.strip_prefix('/').or_else(|| arg.strip_prefix('-')) else {
            add_input(args, arg);
            continue;
        };

        let (name, value) = option
            .split_once(':')
            .map_or((option, None), |(name, value)| (name, Some(value)));

        match name.to_ascii_lowercase().as_str() {
            "out" => {
                let value = required_value("/OUT", value)?;
                args.common.output = Arc::from(Path::new(value));
            }
            "entry" => {
                args.entry = Some(required_value("/ENTRY", value)?.to_owned());
            }
            "subsystem" => {
                let value = required_value("/SUBSYSTEM", value)?;
                args.subsystem = Some(parse_subsystem(value)?);
            }
            "dll" => {
                no_value("/DLL", value)?;
                args.is_dll = true;
            }
            "machine" => {
                let value = required_value("/MACHINE", value)?;
                if !value.eq_ignore_ascii_case("x64") && !value.eq_ignore_ascii_case("amd64") {
                    bail!("unsupported /MACHINE value `{value}`; only X64 is supported");
                }
                args.machine = CoffMachine::X86_64;
            }
            "libpath" => {
                let value = required_value("/LIBPATH", value)?;
                args.common.save_dir.handle_file(value);
                args.lib_search_path.push(Box::from(Path::new(value)));
            }
            "defaultlib" => {
                let value = required_value("/DEFAULTLIB", value)?;
                args.default_libraries.push(value.to_owned());
            }
            // `/NODEFAULTLIB:lib` excludes one library, a bare `/NODEFAULTLIB` excludes all of
            // them. Precedence over `/DEFAULTLIB` is applied when default libraries are resolved.
            "nodefaultlib" => match value {
                Some(value) if !value.is_empty() => {
                    args.excluded_default_libraries.push(value.to_owned());
                }
                _ => args.no_default_libraries = true,
            },
            name if IGNORED_NO_VALUE_OPTIONS.contains(&name) => {
                no_value(arg, value)?;
            }
            name if IGNORED_OPTIONS.contains(&name) => {}
            // A prefixed token whose name isn't in the table above is an input only if that name
            // looks like a path, since on Unix hosts absolute paths begin with `/` too.
            _ if name.contains(['/', '\\']) => add_input(args, arg),
            _ => args.common.unrecognized_options.push(arg.to_owned()),
        }
    }

    Ok(())
}

/// Returns the non-empty value attached to an option with `:`. link.exe has no separate-token form.
fn required_value<'a>(option: &str, value: Option<&'a str>) -> Result<&'a str> {
    match value {
        Some(value) if !value.is_empty() => Ok(value),
        _ => bail!("missing value for {option}"),
    }
}

/// Rejects `NAME:value` for options that take no value.
fn no_value(option: &str, value: Option<&str>) -> Result {
    if value.is_some() {
        bail!("{option} does not take a value");
    }
    Ok(())
}

/// Parses `/SUBSYSTEM:name[,major[.minor]]`. The version only sets optional-header fields we don't
/// emit yet, so it's validated and ignored.
fn parse_subsystem(value: &str) -> Result<Subsystem> {
    let (name, version) = value
        .split_once(',')
        .map_or((value, None), |(name, version)| (name, Some(version)));

    if let Some(version) = version {
        let (major, minor) = version
            .split_once('.')
            .map_or((version, None), |(major, minor)| (major, Some(minor)));

        if major.is_empty()
            || !major.bytes().all(|b| b.is_ascii_digit())
            || minor
                .is_some_and(|minor| minor.is_empty() || !minor.bytes().all(|b| b.is_ascii_digit()))
        {
            bail!("invalid /SUBSYSTEM version `{version}`; expected `major[.minor]`");
        }
    }

    match name.to_ascii_lowercase().as_str() {
        "console" => Ok(Subsystem::Console),
        "windows" => Ok(Subsystem::Windows),
        _ => bail!("unsupported subsystem `{name}`; only CONSOLE and WINDOWS are supported"),
    }
}

fn add_input(args: &mut CoffArgs, value: &str) {
    args.common.save_dir.handle_file(value);
    args.common.inputs.push(Input {
        spec: InputSpec::File(Box::from(Path::new(value))),
        search_first: None,
        modifiers: Modifiers::default(),
    });
}

#[cfg(test)]
mod tests {
    use super::CoffArgs;
    use super::Subsystem;
    use super::parse;
    use crate::args::InputSpec;
    use std::path::Path;

    /// A link line of the shape that rustc emits when targeting `x86_64-pc-windows-msvc`.
    const RUSTC_LINK_LINE: &[&str] = &[
        "/NOLOGO",
        "/OUT:target\\debug\\hello.exe",
        "/LIBPATH:sdk\\lib\\x64",
        "/DEFAULTLIB:msvcrt.lib",
        "/NODEFAULTLIB:libcmt.lib",
        "/SUBSYSTEM:CONSOLE",
        "/MACHINE:X64",
        "hello.o",
        "kernel32.lib",
    ];

    fn parse_args<'a>(args: impl IntoIterator<Item = &'a str>) -> CoffArgs {
        let mut coff_args = CoffArgs::default();
        parse(&mut coff_args, args.into_iter()).unwrap();
        coff_args
    }

    fn input_paths(args: &CoffArgs) -> Vec<&Path> {
        args.common
            .inputs
            .iter()
            .map(|input| match &input.spec {
                InputSpec::File(path) => path.as_ref(),
                InputSpec::Lib(_) | InputSpec::Search(_) => panic!("unexpected input spec"),
            })
            .collect()
    }

    #[test]
    fn parses_rustc_link_line() {
        let args = parse_args(RUSTC_LINK_LINE.iter().copied());

        assert_eq!(&*args.common.output, Path::new("target\\debug\\hello.exe"));
        assert_eq!(args.subsystem, Some(Subsystem::Console));
        assert_eq!(args.lib_search_path[0].as_ref(), Path::new("sdk\\lib\\x64"));
        assert_eq!(args.default_libraries, ["msvcrt.lib"]);
        assert_eq!(args.excluded_default_libraries, ["libcmt.lib"]);
        assert!(!args.no_default_libraries);
        assert!(!args.is_dll);
        assert_eq!(
            input_paths(&args),
            [Path::new("hello.o"), Path::new("kernel32.lib")]
        );
    }

    #[test]
    fn option_names_are_case_insensitive() {
        let args = parse_args(["/oUt:a.exe", "-ENTRY:main", "/dll"]);

        assert_eq!(&*args.common.output, Path::new("a.exe"));
        assert_eq!(args.entry.as_deref(), Some("main"));
        assert!(args.is_dll);
    }

    #[test]
    fn accepts_both_slash_and_dash_prefixes() {
        let slash = parse_args(["/OUT:a.exe", "/LIBPATH:lib"]);
        let dash = parse_args(["-OUT:a.exe", "-LIBPATH:lib"]);

        assert_eq!(slash.common.output, dash.common.output);
        assert_eq!(slash.lib_search_path, dash.lib_search_path);
    }

    fn parse_error<'a>(args: impl IntoIterator<Item = &'a str>) -> String {
        let mut coff_args = CoffArgs::default();
        parse(&mut coff_args, args.into_iter())
            .unwrap_err()
            .to_string()
    }

    #[test]
    fn values_must_be_attached_to_the_option() {
        for arg in ["/OUT", "/ENTRY", "/LIBPATH", "/DEFAULTLIB", "/SUBSYSTEM"] {
            let message = parse_error([arg, "main.obj"]);
            assert!(
                message.contains("missing value for"),
                "for {arg}: {message}"
            );
        }

        let message = parse_error(["/OUT:", "/DLL", "main.obj"]);
        assert!(message.contains("missing value for /OUT"), "{message}");
    }

    #[test]
    fn empty_value_does_not_consume_the_following_token() {
        let message = parse_error(["/LIBPATH:", "main.obj"]);

        assert!(message.contains("missing value for /LIBPATH"), "{message}");
    }

    #[test]
    fn options_taking_no_value_reject_one() {
        for arg in ["/DLL:x", "/NOLOGO:x"] {
            let message = parse_error([arg]);
            assert!(
                message.contains("does not take a value"),
                "for {arg}: {message}"
            );
        }
    }

    #[test]
    fn unknown_options_with_a_dot_are_not_treated_as_inputs() {
        let message = parse_error(["/DEBUG.FOO"]);

        assert!(message.contains("unrecognized option(s)"), "{message}");
    }

    #[test]
    fn parses_subsystem_with_optional_version() {
        for arg in [
            "/SUBSYSTEM:windows",
            "/SUBSYSTEM:WINDOWS,6",
            "/SUBSYSTEM:windows,6.2",
        ] {
            assert_eq!(
                parse_args([arg]).subsystem,
                Some(Subsystem::Windows),
                "{arg}"
            );
        }
        for arg in ["/SUBSYSTEM:CONSOLE", "/subsystem:console,10.0"] {
            assert_eq!(
                parse_args([arg]).subsystem,
                Some(Subsystem::Console),
                "{arg}"
            );
        }

        let mut args = CoffArgs::default();
        let message = parse(&mut args, ["/SUBSYSTEM:CONSOLE,x"].into_iter())
            .unwrap_err()
            .to_string();
        assert!(message.contains("invalid /SUBSYSTEM version"), "{message}");
    }

    #[test]
    fn other_subsystems_are_unsupported_rather_than_unrecognized() {
        for name in ["NATIVE", "EFI_APPLICATION", "BOOT_APPLICATION", "POSIX"] {
            let mut args = CoffArgs::default();
            let message = parse(&mut args, [&format!("/SUBSYSTEM:{name}")].into_iter())
                .unwrap_err()
                .to_string();

            assert!(
                message.contains("unsupported subsystem"),
                "unexpected error for {name}: {message}"
            );
        }
    }

    #[test]
    fn rejects_machines_other_than_x64() {
        for machine in [
            "/MACHINE:X64",
            "/MACHINE:x64",
            "/MACHINE:amd64",
            "/machine:AMD64",
        ] {
            let mut args = CoffArgs::default();
            parse(&mut args, [machine].into_iter()).unwrap();
        }

        for machine in ["X86", "arm64", "ARM64EC", "arm64x", "ARM", "mips"] {
            let mut args = CoffArgs::default();
            let message = parse(&mut args, [&format!("/MACHINE:{machine}")].into_iter())
                .unwrap_err()
                .to_string();

            assert!(
                message.contains("only X64 is supported"),
                "unexpected error for {machine}: {message}"
            );
        }
    }

    #[test]
    fn bare_nodefaultlib_excludes_all_default_libraries() {
        let args = parse_args(["/NODEFAULTLIB"]);

        assert!(args.no_default_libraries);
        assert!(args.excluded_default_libraries.is_empty());
    }

    #[test]
    fn unknown_options_are_an_error() {
        for arg in ["/FOO", "-FOO:bar"] {
            let mut args = CoffArgs::default();
            let message = parse(&mut args, [arg].into_iter()).unwrap_err().to_string();

            assert!(
                message.contains("unrecognized option(s)"),
                "unexpected error for {arg}: {message}"
            );
        }
    }

    #[test]
    fn unknown_options_are_reported_together_with_valid_ones() {
        let mut args = CoffArgs::default();
        let message = parse(&mut args, ["/OUT:a.exe", "/FOO", "main.obj"].into_iter())
            .unwrap_err()
            .to_string();

        assert!(message.contains("/FOO"), "{message}");
    }

    #[test]
    fn rustc_ignored_options_are_accepted() {
        let ignored = [
            "/NOLOGO",
            "/DEBUG",
            "/DEBUG:FULL",
            "/NXCOMPAT",
            "/NXCOMPAT:NO",
            "/DYNAMICBASE:NO",
            "/OPT:REF,NOICF",
            "/PDBALTPATH:%_PDB%",
            "/PDB:out.pdb",
            "/IMPLIB:out.lib",
            "/NATVIS:types.natvis",
            "/DEF:exports.def",
            "/WHOLEARCHIVE",
            "/WHOLEARCHIVE:foo.lib",
            "/guard:cf",
            "/DYNAMICBASE",
            "/MANIFEST",
            "/MANIFEST:EMBED",
            "/MANIFEST:NO",
            "/MANIFESTINPUT:x/y.xml",
            "/MANIFESTUAC:NO",
            "/WX",
            "/WX:NO",
        ];

        for arg in ignored {
            let args = parse_args([arg, "main.obj"]);

            assert_eq!(input_paths(&args), [Path::new("main.obj")], "for {arg}");
            assert!(args.common.unrecognized_options.is_empty(), "for {arg}");
        }
    }

    #[test]
    fn unknown_options_with_a_path_like_value_are_not_treated_as_inputs() {
        for arg in ["/BOGUSFLAG:a/b", "/BOGUSFLAG:a\\b"] {
            let message = parse_error([arg]);

            assert!(
                message.contains("unrecognized option(s)"),
                "unexpected error for {arg}: {message}"
            );
        }
    }

    #[test]
    fn options_whose_value_contains_a_separator_are_still_options() {
        let args = parse_args(["/LIBPATH:some/dir"]);

        assert_eq!(args.lib_search_path[0].as_ref(), Path::new("some/dir"));
        assert!(args.common.inputs.is_empty());
    }

    #[test]
    fn path_shaped_tokens_are_inputs_not_options() {
        let args = parse_args([
            "/tmp/foo.obj",
            "/usr/lib/bar.lib",
            "./x.obj",
            "foo.lib",
            "/OUT:a.exe",
        ]);

        assert_eq!(
            input_paths(&args),
            [
                Path::new("/tmp/foo.obj"),
                Path::new("/usr/lib/bar.lib"),
                Path::new("./x.obj"),
                Path::new("foo.lib")
            ]
        );
        assert_eq!(&*args.common.output, Path::new("a.exe"));
    }

    #[test]
    fn bare_inputs_are_literal_paths() {
        // rustc passes libraries with the `.lib` suffix already applied, so we never append one.
        let args = parse_args(["foo", "foo.lib"]);

        assert_eq!(input_paths(&args), [Path::new("foo"), Path::new("foo.lib")]);
    }

    #[test]
    fn parses_full_rustc_style_link_line() {
        let args = parse_args([
            "/NOLOGO",
            "/NXCOMPAT",
            "/LIBPATH:C:\\lib",
            "main.o",
            "/OUT:main.exe",
            "/DEBUG",
            "/OPT:REF,NOICF",
            "/SUBSYSTEM:CONSOLE",
            "foo.lib",
        ]);

        assert_eq!(&*args.common.output, Path::new("main.exe"));
        assert_eq!(args.subsystem, Some(Subsystem::Console));
        assert_eq!(args.lib_search_path[0].as_ref(), Path::new("C:\\lib"));
        assert_eq!(
            input_paths(&args),
            [Path::new("main.o"), Path::new("foo.lib")]
        );
        assert!(args.common.unrecognized_options.is_empty());
        assert!(!args.is_dll);
    }
}
