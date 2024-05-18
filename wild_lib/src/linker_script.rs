//! This module is responsible for parsing very basic linker scripts. These are not the kind of
//! linker script you might write to specify the layout of your program on an embedded platform, we
//! don't currently support those. It's just for supporting small linker scripts that are put in
//! place of .so files to tell the linker to load some other input file(s).

use crate::args::Input;
use crate::args::InputSpec;
use crate::args::Modifiers;
use crate::error::Result;
use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use std::path::Path;

/// Parse the kind of linker script that's put in place of a shared object to specify that the
/// linker should load several files.
pub(crate) fn linker_script_to_inputs(
    bytes: &[u8],
    path: &Path,
    modifiers: Modifiers,
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
            input
        })
        .collect())
}

/// A version script. See https://sourceware.org/binutils/docs/ld/VERSION.html
#[derive(Default)]
pub(crate) struct VersionScript {
    // For now, we only support a single version.
    version: Option<Version>,
}

pub(crate) struct Version {
    globals: Vec<SymbolMatcher>,
    locals: Vec<SymbolMatcher>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SymbolMatcher {
    All,
    Prefix(String),
    Exact(String),
}

impl VersionScript {
    pub(crate) fn parse(script: &str) -> Result<VersionScript> {
        let mut tokens = Tokeniser::new(script);
        // For now, we only support anonymous versions - i.e. a single version that just says what
        // should be global and what should be local.
        tokens.expect("{")?;
        let version = Version::parse(&mut tokens)?;
        Ok(VersionScript {
            version: Some(version),
        })
    }

    pub(crate) fn is_local(&self, name: &[u8]) -> bool {
        self.version.as_ref().is_some_and(|ver| ver.is_local(name))
    }
}

enum VersionRuleSection {
    Global,
    Local,
}

impl Version {
    fn parse(tokens: &mut Tokeniser) -> Result<Version> {
        let mut version = Version {
            globals: Default::default(),
            locals: Default::default(),
        };
        let mut section = None;
        while let Some(token) = tokens.next() {
            match token {
                "}" => return Ok(version),
                "global:" => section = Some(VersionRuleSection::Global),
                "local:" => section = Some(VersionRuleSection::Local),
                pattern => {
                    tokens.expect(";")?;
                    match section {
                        Some(VersionRuleSection::Global) => {
                            version.globals.push(SymbolMatcher::from_pattern(pattern)?)
                        }
                        Some(VersionRuleSection::Local) => {
                            version.locals.push(SymbolMatcher::from_pattern(pattern)?)
                        }
                        None => bail!("Expected global/local, found '{token}'"),
                    }
                }
            }
        }
        bail!("Missing close '}}' in version script");
    }

    fn is_local(&self, name: &[u8]) -> bool {
        for matcher in &self.globals {
            if matcher.matches(name) {
                return false;
            }
        }
        for matcher in &self.locals {
            if matcher.matches(name) {
                return true;
            }
        }
        false
    }
}

impl SymbolMatcher {
    fn from_pattern(token: &str) -> Result<SymbolMatcher> {
        if token == "*" {
            return Ok(SymbolMatcher::All);
        }
        if let Some(prefix) = token.strip_suffix('*') {
            if prefix.contains('*') {
                bail!("Unsupported symbol pattern '{token}'");
            }
            return Ok(SymbolMatcher::Prefix(prefix.to_owned()));
        }
        if token.contains('*') {
            bail!("Unsupported symbol pattern '{token}'");
        }
        Ok(SymbolMatcher::Exact(token.to_owned()))
    }

    fn matches(&self, name: &[u8]) -> bool {
        match self {
            SymbolMatcher::All => true,
            SymbolMatcher::Prefix(prefix) => name.starts_with(prefix.as_bytes()),
            SymbolMatcher::Exact(exact) => name == exact.as_bytes(),
        }
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
            if self.text.is_empty() {
                return None;
            }
            let len = self
                .text
                .char_indices()
                .find(|(_, ch)| " \n\t(){};".contains(*ch))
                .map(|(offset, _)| offset)
                .unwrap_or(self.text.len())
                .max(1);
            let token = &self.text[..len];
            self.text = &self.text[len..];
            return Some(token);
        }
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
    } else {
        Ok(out)
    }
}

fn parse_command<'a>(tokens: &mut Tokeniser<'a>, token: &str) -> Result<Command<'a>> {
    match token {
        "GROUP" => {
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
                collect_inputs(subs, inputs, sub_modifiers)
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
        assert_eq!(
            inputs.into_iter().map(|i| i.spec).collect::<Vec<_>>(),
            vec![
                InputSpec::File(Box::from(Path::new("libgcc_s.so.1"))),
                InputSpec::Lib(Box::from("gcc"))
            ]
        )
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
        assert_eq!(
            inputs.into_iter().map(|i| i.spec).collect::<Vec<_>>(),
            vec![
                InputSpec::File(Box::from(Path::new("/lib/x86_64-linux-gnu/libc.so.6"))),
                InputSpec::File(Box::from(Path::new(
                    "/usr/lib/x86_64-linux-gnu/libc_nonshared.a"
                ))),
                InputSpec::File(Box::from(Path::new("/lib64/ld-linux-x86-64.so.2"))),
            ]
        )
    }

    #[test]
    fn test_parse_version_script() {
        let script = VersionScript::parse("{global:\n foo; bar*; local: *; }").unwrap();
        let version = script.version.unwrap();
        assert_eq!(
            version.globals,
            vec![
                SymbolMatcher::Exact("foo".to_owned()),
                SymbolMatcher::Prefix("bar".to_owned())
            ]
        );
        assert_eq!(version.locals, vec![SymbolMatcher::All]);
    }
}
