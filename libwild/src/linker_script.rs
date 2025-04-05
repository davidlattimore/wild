//! This module is responsible for parsing linker scripts.

use crate::args::Input;
use crate::args::InputSpec;
use crate::args::Modifiers;
use crate::error::Result;
use anyhow::anyhow;
use normalize_path::NormalizePath;
use std::path::Path;
use winnow::Parser as _;
use winnow::ascii::dec_uint;
use winnow::ascii::multispace0;
use winnow::combinator::alt;
use winnow::combinator::eof;
use winnow::combinator::opt;
use winnow::combinator::repeat_till;
use winnow::token::take_until;
use winnow::token::take_while;

pub(crate) fn maybe_apply_sysroot(
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

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct LinkerScript<'a> {
    pub(crate) commands: Vec<Command<'a>>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Command<'a> {
    Arg(&'a str),
    Group(Vec<Command<'a>>),
    AsNeeded(Vec<Command<'a>>),
    Ignored,
    Sections(Sections<'a>),
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Sections<'a> {
    pub(crate) commands: Vec<SectionCommand<'a>>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SectionCommand<'a> {
    Section(Section<'a>),
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Section<'a> {
    pub(crate) output_section_name: &'a str,
    pub(crate) matchers: Vec<Matcher<'a>>,
    pub(crate) alignment: Option<u32>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Matcher<'a> {
    pub(crate) must_keep: bool,

    // TODO: Add support for matching based on input filenames.
    pub(crate) input_section_name_patterns: Vec<&'a str>,
}

impl<'data> LinkerScript<'data> {
    pub(crate) fn parse(bytes: &'data [u8], path: &Path) -> Result<LinkerScript<'data>> {
        let text = std::str::from_utf8(bytes)?;

        let commands = parse_commands.parse(text).map_err(|error| {
            anyhow!(
                "Failed to parse linker script `{}`:\n{error}",
                path.display()
            )
        })?;

        Ok(LinkerScript { commands })
    }

    pub(crate) fn foreach_input(
        &self,
        starting_modifiers: Modifiers,
        mut cb: impl FnMut(Input) -> Result,
    ) -> Result {
        foreach_input(&self.commands, starting_modifiers, &mut cb)?;
        Ok(())
    }
}

fn parse_token<'input>(input: &mut &'input str) -> winnow::Result<&'input str> {
    take_while(1.., |ch| !" (){}\n\t".contains(ch)).parse_next(input)
}

fn skip_comments_and_whitespace(input: &mut &str) -> winnow::Result<()> {
    loop {
        multispace0(input)?;
        if input.starts_with("/*") {
            take_until(1.., "*/").parse_next(input)?;
            "*/".parse_next(input)?;
        } else {
            return Ok(());
        }
    }
}

fn parse_paren_group<'input>(input: &mut &'input str) -> winnow::Result<Vec<Command<'input>>> {
    '('.parse_next(input)?;
    skip_comments_and_whitespace(input)?;
    let (group_contents, _) = repeat_till(0.., parse_command, ')').parse_next(input)?;
    Ok(group_contents)
}

fn parse_command<'input>(input: &mut &'input str) -> winnow::Result<Command<'input>> {
    let command_str = parse_token(input)?;

    skip_comments_and_whitespace(input)?;

    let command = match command_str {
        "GROUP" | "INPUT" => Command::Group(parse_paren_group(input)?),
        "OUTPUT_FORMAT" => {
            parse_paren_group(input)?;
            Command::Ignored
        }
        "AS_NEEDED" => Command::AsNeeded(parse_paren_group(input)?),
        "SECTIONS" => Command::Sections(parse_sections(input)?),
        other => Command::Arg(other),
    };

    skip_comments_and_whitespace(input)?;

    Ok(command)
}

fn parse_commands<'input>(input: &mut &'input str) -> winnow::Result<Vec<Command<'input>>> {
    skip_comments_and_whitespace(input)?;

    Ok(repeat_till(0.., parse_command, eof).parse_next(input)?.0)
}

fn parse_sections<'input>(input: &mut &'input str) -> winnow::Result<Sections<'input>> {
    '{'.parse_next(input)?;
    skip_comments_and_whitespace(input)?;
    let (commands, _) = repeat_till(0.., parse_section_command, '}').parse_next(input)?;
    skip_comments_and_whitespace(input)?;
    Ok(Sections { commands })
}

fn parse_section_command<'input>(
    input: &mut &'input str,
) -> winnow::Result<SectionCommand<'input>> {
    let name = parse_token(input)?;
    skip_comments_and_whitespace(input)?;

    ':'.parse_next(input)?;

    skip_comments_and_whitespace(input)?;

    let mut alignment = None;

    while !input.starts_with('{') {
        "ALIGN".parse_next(input)?;
        skip_comments_and_whitespace(input)?;
        '('.parse_next(input)?;
        skip_comments_and_whitespace(input)?;
        alignment = Some(dec_uint.parse_next(input)?);
        skip_comments_and_whitespace(input)?;
        ')'.parse_next(input)?;
        skip_comments_and_whitespace(input)?;
    }

    '{'.parse_next(input)?;
    skip_comments_and_whitespace(input)?;

    let (matchers, _) = repeat_till(0.., parse_matcher, '}').parse_next(input)?;

    skip_comments_and_whitespace(input)?;

    Ok(SectionCommand::Section(Section {
        output_section_name: name,
        matchers,
        alignment,
    }))
}

fn parse_matcher<'input>(input: &mut &'input str) -> winnow::Result<Matcher<'input>> {
    let matcher = alt((parse_keep, parse_matcher_pattern)).parse_next(input)?;
    opt(';').parse_next(input)?;
    skip_comments_and_whitespace(input)?;
    Ok(matcher)
}

fn parse_keep<'input>(input: &mut &'input str) -> winnow::Result<Matcher<'input>> {
    "KEEP".parse_next(input)?;
    skip_comments_and_whitespace(input)?;
    '('.parse_next(input)?;
    let mut matcher = parse_matcher_pattern(input)?;
    matcher.must_keep = true;
    ')'.parse_next(input)?;
    skip_comments_and_whitespace(input)?;
    Ok(matcher)
}

fn parse_matcher_pattern<'input>(input: &mut &'input str) -> winnow::Result<Matcher<'input>> {
    // For now, we only support wildcards here.
    '*'.parse_next(input)?;
    skip_comments_and_whitespace(input)?;
    '('.parse_next(input)?;
    skip_comments_and_whitespace(input)?;

    let (patterns, _) = repeat_till(0.., parse_pattern, ')').parse_next(input)?;
    skip_comments_and_whitespace(input)?;

    Ok(Matcher {
        must_keep: false,
        input_section_name_patterns: patterns,
    })
}

fn parse_pattern<'input>(input: &mut &'input str) -> winnow::Result<&'input str> {
    let pattern = take_while(1.., |ch| !" \n\t)".contains(ch)).parse_next(input)?;
    skip_comments_and_whitespace(input)?;
    Ok(pattern)
}

/// Call `cb` for each input file requested by `commands`.
fn foreach_input(
    commands: &[Command],
    modifiers: Modifiers,
    cb: &mut impl FnMut(Input) -> Result,
) -> Result {
    for command in commands {
        match command {
            Command::Arg(arg) => {
                let spec = if let Some(lib_name) = arg.strip_prefix("-l") {
                    InputSpec::Lib(Box::from(lib_name))
                } else {
                    InputSpec::File(Box::from(Path::new(arg)))
                };
                cb(Input {
                    spec,
                    search_first: None,
                    modifiers,
                })?;
            }
            Command::Group(subs) => foreach_input(subs, modifiers, cb)?,
            Command::AsNeeded(subs) => {
                let sub_modifiers = Modifiers {
                    as_needed: true,
                    ..modifiers
                };
                foreach_input(subs, sub_modifiers, cb)?;
            }
            Command::Sections(_) | Command::Ignored => {}
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args::InputSpec;
    use itertools::assert_equal;

    fn parse_script(text: &str) -> Result<LinkerScript> {
        LinkerScript::parse(text.as_bytes(), Path::new("test-linker-script.txt"))
    }

    fn inputs_from_script(text: &str) -> Result<Vec<Input>> {
        let script = parse_script(text)?;
        let mut inputs = Vec::new();
        foreach_input(&script.commands, Modifiers::default(), &mut |input| {
            inputs.push(input);
            Ok(())
        })?;
        Ok(inputs)
    }

    #[test]
    fn test_inputs_from_script() {
        let inputs = inputs_from_script(
            r#"/* GNU ld script */
            GROUP ( libgcc_s.so.1 -lgcc )
        "#,
        )
        .unwrap();
        assert_equal(
            inputs.into_iter().map(|i| i.spec),
            [
                InputSpec::File(Box::from(Path::new("libgcc_s.so.1"))),
                InputSpec::Lib(Box::from("gcc")),
            ],
        );

        let inputs = inputs_from_script("INPUT(libfoo.so)").unwrap();
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

    #[track_caller]
    fn check_section_command(input: &str, expected: &SectionCommand) {
        match parse_section_command.parse(input) {
            Ok(actual) => assert_eq!(&actual, expected),
            Err(e) => panic!("Parse failed:\n{e}"),
        }
    }

    #[test]
    fn test_section_command() {
        check_section_command(
            ".text : { *(.text .text2) *(.text3) }",
            &SectionCommand::Section(Section {
                output_section_name: ".text",
                matchers: vec![
                    Matcher {
                        must_keep: false,
                        input_section_name_patterns: vec![".text", ".text2"],
                    },
                    Matcher {
                        must_keep: false,
                        input_section_name_patterns: vec![".text3"],
                    },
                ],
                alignment: None,
            }),
        );
    }

    #[track_caller]
    fn check_linker_script(input: &str, expected: &LinkerScript) {
        let actual = parse_script(input).unwrap();
        assert_eq!(&actual, expected);
    }

    #[test]
    fn test_basic_linker_script() {
        check_linker_script(
            r"
            SECTIONS {
                .foo : ALIGN(8) {
                    KEEP(*(.rodata.foo));
                }
            }
        ",
            &LinkerScript {
                commands: vec![Command::Sections(Sections {
                    commands: vec![SectionCommand::Section(Section {
                        output_section_name: ".foo",
                        matchers: vec![Matcher {
                            must_keep: true,
                            input_section_name_patterns: vec![".rodata.foo"],
                        }],
                        alignment: Some(8),
                    })],
                })],
            },
        );
    }
}
