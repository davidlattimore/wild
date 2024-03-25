//! This module is responsible for parsing very basic linker scripts. These are not the kind of
//! linker script you might write to specify the layout of your program on an embedded platform, we
//! don't currently support those. It's just for supporting small linker scripts that are put in
//! place of .so files to tell the linker to load some other input file(s).

use crate::args::Input;
use crate::args::InputSpec;
use crate::error::Result;
use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use std::path::Path;

/// Parse the kind of linker script that's put in place of a shared object to specify that the
/// linker should load several files.
pub(crate) fn linker_script_to_inputs(bytes: &[u8], path: &Path) -> Result<Vec<Input>> {
    let text = std::str::from_utf8(bytes)?;
    let directory = path
        .parent()
        .ok_or_else(|| anyhow!("Need directory for path `{}`", path.display()))?;
    Ok(inputs_from_script(text)
        .with_context(|| format!("Failed to parse linker script `{}`", path.display()))?
        .into_iter()
        .map(|mut input| {
            input.search_first = Some(directory.to_owned());
            input
        })
        .collect())
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
                .find(|(_, ch)| matches!(ch, '(' | ' ' | ')'))
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

fn inputs_from_script(text: &str) -> Result<Vec<Input>> {
    let mut tokens = Tokeniser::new(text);
    let commands = parse_commands_up_to(&mut tokens, None)?;
    let mut inputs = Vec::new();
    collect_inputs(&commands, &mut inputs);
    Ok(inputs)
}

fn collect_inputs(commands: &[Command], inputs: &mut Vec<Input>) {
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
                });
            }
            Command::Group(subs) => collect_inputs(subs, inputs),
            Command::AsNeeded(subs) => collect_inputs(subs, inputs),
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
}
