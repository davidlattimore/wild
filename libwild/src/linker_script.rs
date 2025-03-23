//! This module is responsible for parsing very basic linker scripts. These are not the kind of
//! linker script you might write to specify the layout of your program on an embedded platform, we
//! don't currently support those. It's just for supporting small linker scripts that are put in
//! place of .so files to tell the linker to load some other input file(s).

use crate::args::Input;
use crate::args::InputSpec;
use crate::args::Modifiers;
use crate::error::Result;
use crate::hash::PassThroughHasher;
use crate::hash::PreHashed;
use crate::input_data::VersionScriptData;
use crate::symbol::UnversionedSymbolName;
use anyhow::Context as _;
use anyhow::anyhow;
use anyhow::bail;
use normalize_path::NormalizePath;
use std::collections::HashSet;
use std::path::Path;

/// Parse the kind of linker script that's put in place of a shared object to specify that the
/// linker should load several files.
pub(crate) fn linker_script_to_inputs(
    bytes: &[u8],
    path: &Path,
    modifiers: Modifiers,
    sysroot: Option<&Path>,
) -> Result<Vec<Input>> {
    let text = std::str::from_utf8(bytes)?;
    let directory = path
        .parent()
        .ok_or_else(|| anyhow!("Need directory for path `{}`", path.display()))?;
    Ok(inputs_from_script(text, modifiers)
        .with_context(|| format!("Failed to parse linker script `{}`", path.display()))?
        .into_iter()
        .map(|mut input| {
            input.search_first = Some(directory.to_owned());
            if let (Some(sysroot), InputSpec::File(file)) = (sysroot, &mut input.spec) {
                if let Some(new_file) = maybe_apply_sysroot(path, file, sysroot) {
                    *file = new_file;
                }
            }

            input
        })
        .collect())
}

fn maybe_apply_sysroot(
    linker_script_path: &Path,
    input_path: &Path,
    sysroot: &Path,
) -> Option<Box<Path>> {
    if linker_script_path.normalize().starts_with(sysroot) {
        Some(Box::from(sysroot.join(input_path.strip_prefix("/").ok()?)))
    } else {
        maybe_forced_sysroot(input_path, sysroot)
    }
}

pub(crate) fn maybe_forced_sysroot(lib_path: &Path, sysroot: &Path) -> Option<Box<Path>> {
    let lib_path_str = lib_path.to_string_lossy();
    lib_path_str
        .strip_prefix('=')
        .or_else(|| lib_path_str.strip_prefix("$SYSROOT"))
        .map(|stripped| Box::from(sysroot.join(stripped.trim_start_matches('/'))))
}

/// A version script. See https://sourceware.org/binutils/docs/ld/VERSION.html
#[derive(Default)]
pub(crate) struct VersionScript<'data> {
    /// For symbol visibility we only need to know whether the symbol is global or local.
    globals: MatchRules<'data>,
    locals: MatchRules<'data>,
    versions: Vec<Version<'data>>,
}

pub(crate) struct Version<'data> {
    pub(crate) name: &'data str,
    pub(crate) parent_index: Option<u16>,
    symbols: MatchRules<'data>,
}

#[derive(Default)]
struct MatchRules<'data> {
    matches_all: bool,
    exact: HashSet<PreHashed<UnversionedSymbolName<'data>>, PassThroughHasher>,
    prefixes: Vec<&'data [u8]>,
}

impl<'data> MatchRules<'data> {
    fn push(&mut self, pattern: SymbolMatcher<'data>) {
        match pattern {
            SymbolMatcher::All => self.matches_all = true,
            SymbolMatcher::Prefix(prefix) => self.prefixes.push(prefix.as_bytes()),
            SymbolMatcher::Exact(exact) => {
                self.exact
                    .insert(UnversionedSymbolName::prehashed(exact.as_bytes()));
            }
        }
    }

    fn matches(&self, name: &PreHashed<UnversionedSymbolName>) -> bool {
        self.matches_all
            || self.exact.contains(name)
            || self
                .prefixes
                .iter()
                .any(|prefix| name.bytes().starts_with(prefix))
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum SymbolMatcher<'data> {
    All,
    Prefix(&'data str),
    Exact(&'data str),
}

impl<'data> VersionScript<'data> {
    #[tracing::instrument(skip_all, name = "Parse version script")]
    pub(crate) fn parse(data: &'data VersionScriptData) -> Result<VersionScript<'data>> {
        let mut tokens = Tokeniser::new(&data.raw);
        let mut version_script = Self::default();

        // List of version names in the script, used to map parent version to version indexes
        let mut version_names = Vec::new();

        tokens.text = tokens.text.trim();

        let mut token = tokens.next().ok_or_else(|| anyhow!("No tokens found"))?;
        // Simple version script, only defines symbols visibility
        if token.starts_with('{') {
            parse_version_section(
                &mut tokens,
                &mut version_script.locals,
                &mut version_script.globals,
                None,
            )?;
            return Ok(version_script);
        }

        // Base version placeholder
        version_names.push("");
        version_script.versions.push(Version {
            name: "",
            symbols: MatchRules::default(),
            parent_index: None,
        });

        loop {
            tokens.expect("{")?;
            version_names.push(token);

            let mut version_symbols = MatchRules::default();
            let parent = parse_version_section(
                &mut tokens,
                &mut version_script.locals,
                &mut version_script.globals,
                Some(&mut version_symbols),
            )?;
            let parent_index = if let Some(parent) = parent {
                // TODO: For longer version scripts IndexSet makes sense, but is it even realistic use case?
                Some(
                    version_names
                        .iter()
                        .position(|v| v == &parent)
                        .with_context(|| format!("Could not find version {parent}"))?
                        as u16,
                )
            } else {
                None
            };

            version_script.versions.push(Version {
                name: token,
                parent_index,
                symbols: version_symbols,
            });

            // Next version for the symbols
            if let Some(next_token) = tokens.next() {
                token = next_token;
            } else {
                break;
            };
        }

        Ok(version_script)
    }

    pub(crate) fn is_local(&self, name: &PreHashed<UnversionedSymbolName>) -> bool {
        if self.globals.matches(name) {
            return false;
        }
        self.locals.matches(name)
    }

    /// Number of versions in the Version Script, including the base version.
    pub(crate) fn version_count(&self) -> u16 {
        self.versions.len() as u16
    }

    pub(crate) fn parent_count(&self) -> u16 {
        self.versions
            .iter()
            .filter(|v| v.parent_index.is_some())
            .count() as u16
    }

    pub(crate) fn version_iter(&self) -> impl Iterator<Item = &Version> {
        self.versions.iter()
    }

    pub(crate) fn version_for_symbol(
        &self,
        name: &PreHashed<UnversionedSymbolName>,
    ) -> Option<u16> {
        self.versions.iter().enumerate().find_map(|(number, ver)| {
            ver.is_present(name)
                .then(|| number as u16 + object::elf::VER_NDX_GLOBAL)
        })
    }
}

enum VersionRuleSection {
    Global,
    Local,
}

/// Parses contents after opening brace up to closing brace, adding symbols to the respective rules.
/// Returns contents after closing brace if any.
fn parse_version_section<'data>(
    tokens: &mut Tokeniser<'data>,
    locals: &mut MatchRules<'data>,
    globals: &mut MatchRules<'data>,
    mut versioned_symbols: Option<&mut MatchRules<'data>>,
) -> Result<Option<&'data str>> {
    let mut section = None;

    // We read line-by-line rather than token-by-token because it's much faster. This is
    // important when for example rustc emits a version script that's more than 300k lines.
    while let Some(line) = tokens.next_line() {
        let mut line = line.trim();
        if let Some(parent_string) = line.strip_prefix('}') {
            if parent_string.starts_with(';') {
                return Ok(None);
            }
            return Ok(parent_string.trim().strip_suffix(';'));
        }
        // Note, we don't currently support comments that have content after them on the same
        // line. Doing so would require us to search every line for embedded comments, which
        // would hurt performance.
        if line.ends_with("*/") {
            if let Some(start_index) = line.find("/*") {
                line = line[..start_index].trim();
            }
        }

        if line.starts_with("/*") {
            while let Some(line) = tokens.next_line() {
                if line.ends_with("*/") {
                    break;
                }
            }
        } else if line == "global:" {
            section = Some(VersionRuleSection::Global);
        } else if line == "local:" {
            section = Some(VersionRuleSection::Local);
        } else if let Some(pattern) = line.strip_suffix(';') {
            match section {
                Some(VersionRuleSection::Global) | None => {
                    globals.push(SymbolMatcher::from_pattern(pattern)?);
                }
                Some(VersionRuleSection::Local) => {
                    locals.push(SymbolMatcher::from_pattern(pattern)?);
                }
            }
            if let Some(versioned_symbols) = versioned_symbols.as_deref_mut() {
                versioned_symbols.push(SymbolMatcher::from_pattern(pattern)?);
            }
        } else if !line.is_empty() {
            bail!("Unsupported version script line `{line}`");
        }
    }
    bail!("Missing close '}}' in version script");
}

impl Version<'_> {
    fn is_present(&self, name: &PreHashed<UnversionedSymbolName>) -> bool {
        self.symbols.matches(name)
    }
}

impl<'data> SymbolMatcher<'data> {
    fn from_pattern(token: &'data str) -> Result<SymbolMatcher<'data>> {
        if token == "*" {
            return Ok(SymbolMatcher::All);
        }
        if let Some(prefix) = token.strip_suffix('*') {
            if prefix.contains('*') {
                bail!("Unsupported symbol pattern '{token}'");
            }
            return Ok(SymbolMatcher::Prefix(prefix));
        }
        if token.contains('*') {
            bail!("Unsupported symbol pattern '{token}'");
        }
        Ok(SymbolMatcher::Exact(token))
    }
}

struct Tokeniser<'a> {
    text: &'a str,
}

impl<'a> Tokeniser<'a> {
    fn next(&mut self) -> Option<&'a str> {
        loop {
            self.text = self.text.trim_start();
            if try_take(&mut self.text, "/*") {
                if take_up_to(&mut self.text, "*/").is_err() {
                    self.text = "";
                }
                continue;
            }
            if self.text.starts_with('#') {
                if take_up_to(&mut self.text, "\n").is_err() {
                    self.text = "";
                }
                continue;
            }
            if self.text.is_empty() {
                return None;
            }
            let bytes = self.text.as_bytes();
            let mut len = 0;
            for byte in bytes {
                if b" \n\t(){};".contains(byte) {
                    break;
                }
                len += 1;
            }
            if len == 0 {
                len = 1;
            }
            let token = &self.text[..len];
            self.text = &self.text[len..];
            return Some(token);
        }
    }

    fn next_line(&mut self) -> Option<&'a str> {
        while let Some(rest) = self.text.strip_prefix('\n') {
            self.text = rest;
        }
        if self.text.is_empty() {
            return None;
        }
        let bytes = self.text.as_bytes();
        let end_pos = memchr::memchr(b'\n', bytes).unwrap_or(bytes.len());
        let (line, rest) = self.text.split_at(end_pos);
        self.text = rest;
        Some(line)
    }

    fn new(text: &'a str) -> Self {
        Tokeniser { text }
    }

    fn expect(&mut self, expected: &str) -> Result {
        let token = self
            .next()
            .ok_or_else(|| anyhow!("Expected token '{expected}', got end of input"))?;
        if token != expected {
            bail!("Expected token '{expected}', got '{token}'");
        }
        Ok(())
    }
}

enum Command<'a> {
    Arg(&'a str),
    Group(Vec<Command<'a>>),
    AsNeeded(Vec<Command<'a>>),
    Ignored,
}

fn parse_commands_up_to<'a>(
    tokens: &mut Tokeniser<'a>,
    end: Option<&str>,
) -> Result<Vec<Command<'a>>> {
    let mut out = Vec::new();
    while let Some(token) = tokens.next() {
        if end == Some(token) {
            return Ok(out);
        }
        if token.chars().all(|ch| ch.is_ascii_uppercase() || ch == '_') {
            out.push(parse_command(tokens, token)?);
        } else {
            out.push(Command::Arg(token));
        }
    }
    if let Some(expected) = end {
        bail!("Got end of script, expected '{expected}'");
    }
    Ok(out)
}

fn parse_command<'a>(tokens: &mut Tokeniser<'a>, token: &str) -> Result<Command<'a>> {
    match token {
        "GROUP" | "INPUT" => {
            tokens.expect("(")?;
            Ok(Command::Group(parse_commands_up_to(tokens, Some(")"))?))
        }
        "OUTPUT_FORMAT" => {
            tokens.expect("(")?;
            parse_commands_up_to(tokens, Some(")"))?;
            Ok(Command::Ignored)
        }
        "AS_NEEDED" => {
            tokens.expect("(")?;
            Ok(Command::AsNeeded(parse_commands_up_to(tokens, Some(")"))?))
        }
        _ => bail!("Unsupported linker script command `{token}`"),
    }
}

fn inputs_from_script(text: &str, starting_modifiers: Modifiers) -> Result<Vec<Input>> {
    let mut tokens = Tokeniser::new(text);
    let commands = parse_commands_up_to(&mut tokens, None)?;
    let mut inputs = Vec::new();
    collect_inputs(&commands, &mut inputs, starting_modifiers);
    Ok(inputs)
}

fn collect_inputs(commands: &[Command], inputs: &mut Vec<Input>, modifiers: Modifiers) {
    for command in commands {
        match command {
            Command::Arg(arg) => {
                let spec = if let Some(lib_name) = arg.strip_prefix("-l") {
                    InputSpec::Lib(Box::from(lib_name))
                } else {
                    InputSpec::File(Box::from(Path::new(arg)))
                };
                inputs.push(Input {
                    spec,
                    search_first: None,
                    modifiers,
                });
            }
            Command::Group(subs) => collect_inputs(subs, inputs, modifiers),
            Command::AsNeeded(subs) => {
                let sub_modifiers = Modifiers {
                    as_needed: true,
                    ..modifiers
                };
                collect_inputs(subs, inputs, sub_modifiers);
            }
            Command::Ignored => {}
        }
    }
}

fn try_take(input: &mut &str, pattern: &str) -> bool {
    if let Some(rest) = input.strip_prefix(pattern) {
        *input = rest;
        true
    } else {
        false
    }
}

fn take_up_to<'a>(input: &mut &'a str, pattern: &str) -> Result<&'a str> {
    let end = input
        .find(pattern)
        .ok_or_else(|| anyhow!("Missing expected '{pattern}'"))?;
    let content = &input[..end];
    *input = &input[end + pattern.len()..];
    Ok(content)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args::InputSpec;
    use itertools::Itertools;
    use itertools::assert_equal;

    #[test]
    fn test_tokenisation() {
        fn tokenise(text: &str) -> Vec<&str> {
            let mut t = Tokeniser::new(text);
            let mut out = Vec::new();
            while let Some(token) = t.next() {
                assert!(!token.is_empty());
                out.push(token);
            }
            out
        }

        assert_eq!(tokenise("/**/ /* a */ GROUP ()"), vec!["GROUP", "(", ")"]);
        assert_eq!(
            tokenise("GROUP ( AS_NEEDED ( /a/b/c ))"),
            vec!["GROUP", "(", "AS_NEEDED", "(", "/a/b/c", ")", ")"]
        );
        assert_eq!(tokenise(""), Vec::<&str>::new());
    }

    #[test]
    fn test_inputs_from_script() {
        let inputs = inputs_from_script(
            r#"/* GNU ld script */
            GROUP ( libgcc_s.so.1 -lgcc )
        "#,
            Modifiers::default(),
        )
        .unwrap();
        assert_equal(
            inputs.into_iter().map(|i| i.spec),
            [
                InputSpec::File(Box::from(Path::new("libgcc_s.so.1"))),
                InputSpec::Lib(Box::from("gcc")),
            ],
        );

        let inputs = inputs_from_script("INPUT(libfoo.so)", Modifiers::default()).unwrap();
        assert_equal(
            inputs.into_iter().map(|i| i.spec),
            [InputSpec::File(Box::from(Path::new("libfoo.so")))],
        );
    }

    #[test]
    fn test_test_inputs_from_script() {
        let inputs = inputs_from_script(
            r#"OUTPUT_FORMAT(elf64-x86-64)
            GROUP ( /lib/x86_64-linux-gnu/libc.so.6 /usr/lib/x86_64-linux-gnu/libc_nonshared.a  AS_NEEDED ( /lib64/ld-linux-x86-64.so.2 ) )
        "#,
        Modifiers::default(),
        )
        .unwrap();
        assert_equal(
            inputs.into_iter().map(|i| i.spec),
            [
                InputSpec::File(Box::from(Path::new("/lib/x86_64-linux-gnu/libc.so.6"))),
                InputSpec::File(Box::from(Path::new(
                    "/usr/lib/x86_64-linux-gnu/libc_nonshared.a",
                ))),
                InputSpec::File(Box::from(Path::new("/lib64/ld-linux-x86-64.so.2"))),
            ],
        );
    }

    #[test]
    fn test_parse_simple_version_script() {
        let data = VersionScriptData {
            raw: r#"
                    # Comment starting with a hash
                    {global:
                        /* Single-line comment */
                        foo; /* Trailing comment */
                        bar*;
                    local:
                        /* Multi-line
                           comment */
                        *;
                    }"#
            .into(),
        };
        let script = VersionScript::parse(&data).unwrap();
        assert_equal(
            script
                .globals
                .exact
                .iter()
                .map(|s| std::str::from_utf8(s.bytes()).unwrap()),
            ["foo"],
        );
        assert_equal(
            script
                .globals
                .prefixes
                .iter()
                .map(|s| std::str::from_utf8(s).unwrap()),
            ["bar"],
        );
        assert!(script.locals.matches_all);
    }

    #[test]
    fn test_parse_version_script() {
        let data = VersionScriptData {
            raw: r#"
                VERS_1.1 {
                    global:
                        foo1;
                    local:
                        old*;
                };

                VERS_1.2 {
                    foo2;
                } VERS_1.1;
            "#
            .into(),
        };
        let script = VersionScript::parse(&data).unwrap();
        assert_eq!(script.versions.len(), 3);
        assert_equal(
            script
                .globals
                .exact
                .iter()
                .map(|s| std::str::from_utf8(s.bytes()).unwrap())
                .sorted(),
            ["foo1", "foo2"],
        );
        assert_equal(
            script
                .locals
                .prefixes
                .iter()
                .map(|s| std::str::from_utf8(s).unwrap()),
            ["old"],
        );

        let version = &script.versions[1];
        assert_eq!(version.name, "VERS_1.1");
        assert_eq!(version.parent_index, None);
        assert_equal(
            version
                .symbols
                .exact
                .iter()
                .map(|s| std::str::from_utf8(s.bytes()).unwrap()),
            ["foo1"],
        );
        assert_equal(
            version
                .symbols
                .prefixes
                .iter()
                .map(|s| std::str::from_utf8(s).unwrap()),
            ["old"],
        );

        let version = &script.versions[2];
        assert_eq!(version.name, "VERS_1.2");
        assert_eq!(version.parent_index, Some(1));
        assert_equal(
            version
                .symbols
                .exact
                .iter()
                .map(|s| std::str::from_utf8(s.bytes()).unwrap()),
            ["foo2"],
        );
    }

    #[test]
    fn test_sysroot_application() {
        let sysroot = Path::new("/usr/aarch64-linux-gnu");
        // Linker script is located in the sysroot
        assert_equal(
            maybe_apply_sysroot(
                &sysroot.join("lib/libc.so"),
                Path::new("/lib/libc.so.6"),
                sysroot,
            ),
            Some(Box::from(sysroot.join("lib/libc.so.6"))),
        );
        // Linker script is not located in the sysroot
        assert_equal(
            maybe_apply_sysroot(
                Path::new("/lib/libc.so"),
                Path::new("/lib/libc.so.6"),
                sysroot,
            ),
            None,
        );
        // Sysroot enforced by `=/`
        assert_equal(
            maybe_apply_sysroot(
                Path::new("/lib/libc.so"),
                Path::new("=/lib/libc.so.6"),
                sysroot,
            ),
            Some(Box::from(sysroot.join("lib/libc.so.6"))),
        );
        // Sysroot enforced by `=`
        assert_equal(
            maybe_apply_sysroot(
                Path::new("/lib/libc.so"),
                Path::new("=lib/libc.so.6"),
                sysroot,
            ),
            Some(Box::from(sysroot.join("lib/libc.so.6"))),
        );
        // Sysroot enforced by `$SYSROOT`
        assert_equal(
            maybe_apply_sysroot(
                Path::new("/lib/libc.so"),
                Path::new("$SYSROOT/lib/libc.so.6"),
                sysroot,
            ),
            Some(Box::from(sysroot.join("lib/libc.so.6"))),
        );
        // Sysroot enforced by `$SYSROOT`
        assert_equal(
            maybe_apply_sysroot(
                Path::new("/lib/libc.so"),
                Path::new("$SYSROOTlib/libc.so.6"),
                sysroot,
            ),
            Some(Box::from(sysroot.join("lib/libc.so.6"))),
        );
        // Relative sysroot path
        let relative_sysroot = Path::new("foo");
        assert_equal(
            maybe_apply_sysroot(
                &relative_sysroot.join("lib/libc.so"),
                Path::new("/lib/libc.so.6"),
                relative_sysroot,
            ),
            Some(Box::from(relative_sysroot.join("lib/libc.so.6"))),
        );
    }
}
