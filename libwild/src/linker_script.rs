//! This module is responsible for parsing linker scripts.

use crate::alignment::Alignment;
use crate::args::Input;
use crate::args::InputSpec;
use crate::args::Modifiers;
use crate::error;
use crate::error::Context as _;
use crate::error::Result;
use std::path::Path;
use winnow::BStr;
use winnow::Parser as _;
use winnow::ascii::dec_uint;
use winnow::ascii::hex_digit1;
use winnow::ascii::multispace0;
use winnow::combinator::alt;
use winnow::combinator::eof;
use winnow::combinator::opt;
use winnow::combinator::repeat_till;
use winnow::error::ContextError;
use winnow::error::FromExternalError;
use winnow::token::take_until;
use winnow::token::take_while;

/// Checks if we need to prefix `input_path` with the sysroot. If we do, then returns the resulting
/// path. Otherwise, returns `None`. `linker_script_path` and `sysroot` should be canonical,
/// absolute paths, otherwise we might not apply the sysroot when we actually should.
pub(crate) fn maybe_apply_sysroot(
    linker_script_path: &Path,
    input_path: &Path,
    sysroot: &Path,
) -> Option<Box<Path>> {
    debug_assert!(linker_script_path.is_absolute());
    debug_assert!(sysroot.is_absolute());
    if linker_script_path.starts_with(sysroot) {
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

#[derive(derive_more::Debug, PartialEq, Eq)]
pub(crate) enum Command<'a> {
    #[debug("{}", String::from_utf8_lossy(_0))]
    Arg(&'a [u8]),
    Group(Vec<Command<'a>>),
    AsNeeded(Vec<Command<'a>>),
    Ignored,
    Sections(Sections<'a>),
    #[debug("{}", String::from_utf8_lossy(_0))]
    Entry(&'a [u8]),
    #[debug("{}", String::from_utf8_lossy(_0))]
    Version(&'a [u8]),
    SymbolDefinition {
        name: &'a [u8],
        value: &'a [u8],
    },
    Provide(ProvideSymbolDefinition<'a>),
    Assert(AssertCommand<'a>),
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Sections<'a> {
    pub(crate) commands: Vec<SectionCommand<'a>>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SectionCommand<'a> {
    Section(Section<'a>),
    SetLocation(Location),
    Align(Alignment),
    Assert(AssertCommand<'a>),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) struct Location {
    pub(crate) address: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Section<'a> {
    pub(crate) output_section_name: &'a [u8],
    pub(crate) commands: Vec<ContentsCommand<'a>>,
    pub(crate) alignment: Option<Alignment>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ContentsCommand<'a> {
    Matcher(Matcher<'a>),
    SymbolAssignment(SymbolAssignment<'a>),
    Align(Alignment),
    Provide(ProvideSymbolDefinition<'a>),
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SymbolAssignment<'a> {
    pub(crate) name: &'a [u8],
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ProvideSymbolDefinition<'a> {
    pub(crate) name: &'a [u8],
    pub(crate) value: &'a [u8],
    pub(crate) hidden: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct AssertCommand<'a> {
    pub(crate) expression: Expression<'a>,
    pub(crate) message: &'a [u8],
}

/// Represents a parsed expression in linker scripts (e.g., in ASSERT commands).
///
/// Currently supports:
/// - Arithmetic: +, -, *, /
/// - Comparison: <, >, <=, >=, ==, !=
/// - Functions: SIZEOF, ADDR, ALIGN
/// - Numbers (hex/decimal), symbols, location counter (.)
/// - Parentheses for grouping
///
/// Not yet supported (can be added when needed):
/// - Unary operators (-, !)
/// - Bitwise operators (&, |, ^, ~, <<, >>)
/// - Logical operators (&&, ||)
/// - Ternary operator (? :)
/// - Additional functions (LOADADDR, ALIGNOF, LENGTH, ORIGIN)
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Expression<'a> {
    /// A numeric literal (e.g., 0x1000, 42)
    Number(u64),
    /// A symbol reference (e.g., __bss_start)
    Symbol(&'a [u8]),
    /// The location counter '.'
    LocationCounter,
    /// Binary arithmetic: +, -, *, /
    Add(Box<Expression<'a>>, Box<Expression<'a>>),
    Subtract(Box<Expression<'a>>, Box<Expression<'a>>),
    Multiply(Box<Expression<'a>>, Box<Expression<'a>>),
    Divide(Box<Expression<'a>>, Box<Expression<'a>>),
    /// Comparison operators: <, >, <=, >=, ==, !=
    LessThan(Box<Expression<'a>>, Box<Expression<'a>>),
    GreaterThan(Box<Expression<'a>>, Box<Expression<'a>>),
    LessEqual(Box<Expression<'a>>, Box<Expression<'a>>),
    GreaterEqual(Box<Expression<'a>>, Box<Expression<'a>>),
    Equal(Box<Expression<'a>>, Box<Expression<'a>>),
    NotEqual(Box<Expression<'a>>, Box<Expression<'a>>),
    /// Function calls
    Sizeof(&'a [u8]),
    Addr(&'a [u8]),
    Align(Box<Expression<'a>>),
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Matcher<'a> {
    pub(crate) must_keep: bool,

    /// Optional glob pattern for matching input filenames. `None` means match all files (i.e. the
    /// `*` wildcard was used, or no filename was specified).
    pub(crate) input_file_pattern: Option<&'a [u8]>,

    pub(crate) input_section_name_patterns: Vec<&'a [u8]>,
}

impl<'data> LinkerScript<'data> {
    pub(crate) fn parse(bytes: &'data [u8], path: &Path) -> Result<LinkerScript<'data>> {
        let commands = parse_commands.parse(BStr::new(bytes)).map_err(|error| {
            error!(
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

    pub(crate) fn get_version_script_content(&self) -> Option<&'data [u8]> {
        self.commands.iter().find_map(|cmd| match cmd {
            Command::Version(content) => Some(*content),
            _ => None,
        })
    }
}

fn parse_token<'input>(input: &mut &'input BStr) -> winnow::Result<&'input [u8]> {
    if input.starts_with(b"\"") {
        '"'.parse_next(input)?;
        let content = take_until(0.., "\"").parse_next(input)?;
        '"'.parse_next(input)?;

        Ok(content)
    } else {
        take_while(1.., |b| !b" (){};\n\t".contains(&b)).parse_next(input)
    }
}

pub(crate) fn skip_comments_and_whitespace(input: &mut &BStr) -> winnow::Result<()> {
    loop {
        multispace0(input)?;

        if input.starts_with(b"#") {
            take_until(1.., "\n").parse_next(input)?;
        } else if input.starts_with(b"/*") {
            take_until(1.., "*/").parse_next(input)?;
            "*/".parse_next(input)?;
        } else {
            return Ok(());
        }
    }
}

fn parse_paren_group<'input>(input: &mut &'input BStr) -> winnow::Result<Vec<Command<'input>>> {
    '('.parse_next(input)?;
    skip_comments_and_whitespace(input)?;
    let (group_contents, _) = repeat_till(0.., parse_command, ')').parse_next(input)?;
    Ok(group_contents)
}

fn parse_command<'input>(input: &mut &'input BStr) -> winnow::Result<Command<'input>> {
    let command_str = parse_token(input)?;

    skip_comments_and_whitespace(input)?;

    let command = match command_str {
        b"GROUP" | b"INPUT" => Command::Group(parse_paren_group(input)?),
        b"OUTPUT_FORMAT" => {
            parse_paren_group(input)?;
            Command::Ignored
        }
        b"AS_NEEDED" => Command::AsNeeded(parse_paren_group(input)?),
        b"SECTIONS" => Command::Sections(parse_sections(input)?),
        b"ENTRY" => Command::Entry(parse_entry(input)?),
        b"VERSION" => Command::Version(parse_version(input)?),
        b"PROVIDE" => Command::Provide(parse_provide(input, false)?),
        b"PROVIDE_HIDDEN" => Command::Provide(parse_provide(input, true)?),
        b"ASSERT" => Command::Assert(parse_assert(input)?),
        other => {
            if input.starts_with(b"=") {
                // Symbol definition
                '='.parse_next(input)?;
                skip_comments_and_whitespace(input)?;
                let value = take_while(1.., |b| b != b';').parse_next(input)?;
                let value = value.trim_ascii_end();
                opt(';').parse_next(input)?;
                Command::SymbolDefinition { name: other, value }
            } else {
                Command::Arg(other)
            }
        }
    };

    skip_comments_and_whitespace(input)?;

    Ok(command)
}

fn parse_provide<'input>(
    input: &mut &'input BStr,
    hidden: bool,
) -> winnow::Result<ProvideSymbolDefinition<'input>> {
    '('.parse_next(input)?;
    skip_comments_and_whitespace(input)?;
    let name = parse_token(input)?;
    skip_comments_and_whitespace(input)?;
    '='.parse_next(input)?;
    skip_comments_and_whitespace(input)?;
    let value = take_while(1.., |b| b != b')' && b != b';').parse_next(input)?;
    let value = value.trim_ascii_end();
    skip_comments_and_whitespace(input)?;
    ')'.parse_next(input)?;
    skip_comments_and_whitespace(input)?;
    opt(';').parse_next(input)?;
    skip_comments_and_whitespace(input)?;

    Ok(ProvideSymbolDefinition {
        name,
        value,
        hidden,
    })
}

fn parse_assert<'input>(input: &mut &'input BStr) -> winnow::Result<AssertCommand<'input>> {
    '('.parse_next(input)?;
    skip_comments_and_whitespace(input)?;

    // Parse expression (everything until comma)
    let expr_bytes = take_while(1.., |b| b != b',').parse_next(input)?;
    let expr_bytes = expr_bytes.trim_ascii();

    // Parse the expression
    let expression = match parse_expression(expr_bytes) {
        Ok(expr) => expr,
        Err(_) => return Err(winnow::error::ContextError::default()),
    };

    skip_comments_and_whitespace(input)?;
    ','.parse_next(input)?;
    skip_comments_and_whitespace(input)?;

    // Parse message (quoted string)
    let message = parse_token(input)?;

    skip_comments_and_whitespace(input)?;
    ')'.parse_next(input)?;
    skip_comments_and_whitespace(input)?;
    opt(';').parse_next(input)?;
    skip_comments_and_whitespace(input)?;

    Ok(AssertCommand {
        expression,
        message,
    })
}

/// Parse an expression from bytes
fn parse_expression<'a>(input: &'a [u8]) -> Result<Expression<'a>> {
    let mut pos = 0;
    let expr = parse_comparison(input, &mut pos)?;

    // Ensure we consumed all input
    skip_whitespace(input, &mut pos);
    if pos < input.len() {
        return Err(error!(
            "Unexpected trailing characters in expression: '{}'",
            String::from_utf8_lossy(&input[pos..])
        ));
    }

    Ok(expr)
}

/// Parse comparison operators: <, >, <=, >=, ==, !=
fn parse_comparison<'a>(input: &'a [u8], pos: &mut usize) -> Result<Expression<'a>> {
    let mut left = parse_additive(input, pos)?;

    skip_whitespace(input, pos);

    while *pos < input.len() {
        let op = if input[*pos..].starts_with(b"<=") {
            *pos += 2;
            Some(CompOp::LessEqual)
        } else if input[*pos..].starts_with(b">=") {
            *pos += 2;
            Some(CompOp::GreaterEqual)
        } else if input[*pos..].starts_with(b"==") {
            *pos += 2;
            Some(CompOp::Equal)
        } else if input[*pos..].starts_with(b"!=") {
            *pos += 2;
            Some(CompOp::NotEqual)
        } else if input[*pos..].starts_with(b"<") {
            *pos += 1;
            Some(CompOp::LessThan)
        } else if input[*pos..].starts_with(b">") {
            *pos += 1;
            Some(CompOp::GreaterThan)
        } else {
            None
        };

        if let Some(op) = op {
            skip_whitespace(input, pos);
            let right = parse_additive(input, pos)?;
            left = match op {
                CompOp::LessThan => Expression::LessThan(Box::new(left), Box::new(right)),
                CompOp::GreaterThan => Expression::GreaterThan(Box::new(left), Box::new(right)),
                CompOp::LessEqual => Expression::LessEqual(Box::new(left), Box::new(right)),
                CompOp::GreaterEqual => Expression::GreaterEqual(Box::new(left), Box::new(right)),
                CompOp::Equal => Expression::Equal(Box::new(left), Box::new(right)),
                CompOp::NotEqual => Expression::NotEqual(Box::new(left), Box::new(right)),
            };
            skip_whitespace(input, pos);
        } else {
            break;
        }
    }

    Ok(left)
}

/// Parse additive operators: +, -
fn parse_additive<'a>(input: &'a [u8], pos: &mut usize) -> Result<Expression<'a>> {
    let mut left = parse_multiplicative(input, pos)?;

    skip_whitespace(input, pos);

    while *pos < input.len() {
        let op = if input[*pos] == b'+' {
            *pos += 1;
            Some(AddOp::Add)
        } else if input[*pos] == b'-' {
            *pos += 1;
            Some(AddOp::Subtract)
        } else {
            None
        };

        if let Some(op) = op {
            skip_whitespace(input, pos);
            let right = parse_multiplicative(input, pos)?;
            left = match op {
                AddOp::Add => Expression::Add(Box::new(left), Box::new(right)),
                AddOp::Subtract => Expression::Subtract(Box::new(left), Box::new(right)),
            };
            skip_whitespace(input, pos);
        } else {
            break;
        }
    }

    Ok(left)
}

/// Parse multiplicative operators: *, /
fn parse_multiplicative<'a>(input: &'a [u8], pos: &mut usize) -> Result<Expression<'a>> {
    let mut left = parse_primary(input, pos)?;

    skip_whitespace(input, pos);

    while *pos < input.len() {
        let op = if input[*pos] == b'*' {
            *pos += 1;
            Some(MulOp::Multiply)
        } else if input[*pos] == b'/' {
            *pos += 1;
            Some(MulOp::Divide)
        } else {
            None
        };

        if let Some(op) = op {
            skip_whitespace(input, pos);
            let right = parse_primary(input, pos)?;
            left = match op {
                MulOp::Multiply => Expression::Multiply(Box::new(left), Box::new(right)),
                MulOp::Divide => Expression::Divide(Box::new(left), Box::new(right)),
            };
            skip_whitespace(input, pos);
        } else {
            break;
        }
    }

    Ok(left)
}

/// Parse primary expressions: numbers, symbols, functions, parentheses
fn parse_primary<'a>(input: &'a [u8], pos: &mut usize) -> Result<Expression<'a>> {
    skip_whitespace(input, pos);

    if *pos >= input.len() {
        return Err(error!("Unexpected end of expression"));
    }

    // Handle parentheses
    if input[*pos] == b'(' {
        *pos += 1;
        skip_whitespace(input, pos);
        let expr = parse_comparison(input, pos)?;
        skip_whitespace(input, pos);
        if *pos >= input.len() || input[*pos] != b')' {
            return Err(error!("Expected closing parenthesis"));
        }
        *pos += 1;
        return Ok(expr);
    }

    // Handle location counter '.'
    if input[*pos] == b'.' && (*pos + 1 >= input.len() || !input[*pos + 1].is_ascii_alphanumeric())
    {
        *pos += 1;
        return Ok(Expression::LocationCounter);
    }

    // Handle hex numbers (0x...)
    if input[*pos..].starts_with(b"0x") || input[*pos..].starts_with(b"0X") {
        *pos += 2;
        let start = *pos;
        while *pos < input.len() && input[*pos].is_ascii_hexdigit() {
            *pos += 1;
        }
        let hex_str =
            std::str::from_utf8(&input[start..*pos]).map_err(|_| error!("Invalid hex number"))?;
        let num = u64::from_str_radix(hex_str, 16).map_err(|_| error!("Invalid hex number"))?;
        return Ok(Expression::Number(num));
    }

    // Handle decimal numbers
    if input[*pos].is_ascii_digit() {
        let start = *pos;
        while *pos < input.len() && input[*pos].is_ascii_digit() {
            *pos += 1;
        }
        let num_str =
            std::str::from_utf8(&input[start..*pos]).map_err(|_| error!("Invalid number"))?;
        let num = num_str
            .parse::<u64>()
            .map_err(|_| error!("Invalid number"))?;
        return Ok(Expression::Number(num));
    }

    // Handle identifiers (symbols or functions)
    if input[*pos].is_ascii_alphabetic() || input[*pos] == b'_' {
        let start = *pos;
        while *pos < input.len()
            && (input[*pos].is_ascii_alphanumeric() || input[*pos] == b'_' || input[*pos] == b'.')
        {
            *pos += 1;
        }
        let ident = &input[start..*pos];

        skip_whitespace(input, pos);

        // Check if it's a function call
        if *pos < input.len() && input[*pos] == b'(' {
            *pos += 1;
            skip_whitespace(input, pos);

            match ident {
                b"SIZEOF" => {
                    let arg = parse_function_arg(input, pos)?;
                    Ok(Expression::Sizeof(arg))
                }
                b"ADDR" => {
                    let arg = parse_function_arg(input, pos)?;
                    Ok(Expression::Addr(arg))
                }
                b"ALIGN" => {
                    let arg_expr = parse_comparison(input, pos)?;
                    skip_whitespace(input, pos);
                    if *pos >= input.len() || input[*pos] != b')' {
                        return Err(error!("Expected closing parenthesis"));
                    }
                    *pos += 1;
                    Ok(Expression::Align(Box::new(arg_expr)))
                }
                _ => Err(error!(
                    "Unknown function: {}",
                    String::from_utf8_lossy(ident)
                )),
            }
        } else {
            // It's a symbol
            Ok(Expression::Symbol(ident))
        }
    } else {
        Err(error!(
            "Unexpected character in expression: {}",
            input[*pos] as char
        ))
    }
}

/// Parse a function argument (section name)
fn parse_function_arg<'a>(input: &'a [u8], pos: &mut usize) -> Result<&'a [u8]> {
    skip_whitespace(input, pos);
    let start = *pos;

    // Section names can start with '.' or be alphanumeric
    if *pos < input.len()
        && (input[*pos] == b'.' || input[*pos].is_ascii_alphabetic() || input[*pos] == b'_')
    {
        while *pos < input.len()
            && (input[*pos].is_ascii_alphanumeric() || input[*pos] == b'_' || input[*pos] == b'.')
        {
            *pos += 1;
        }
    }

    if *pos == start {
        return Err(error!("Expected section name"));
    }

    let arg = &input[start..*pos];
    skip_whitespace(input, pos);

    if *pos >= input.len() || input[*pos] != b')' {
        return Err(error!("Expected closing parenthesis"));
    }
    *pos += 1;

    Ok(arg)
}

/// Skip whitespace in expression
fn skip_whitespace(input: &[u8], pos: &mut usize) {
    while *pos < input.len() && input[*pos].is_ascii_whitespace() {
        *pos += 1;
    }
}

#[derive(Debug)]
enum CompOp {
    LessThan,
    GreaterThan,
    LessEqual,
    GreaterEqual,
    Equal,
    NotEqual,
}

#[derive(Debug)]
enum AddOp {
    Add,
    Subtract,
}

#[derive(Debug)]
enum MulOp {
    Multiply,
    Divide,
}

fn parse_location(input: &mut &BStr) -> winnow::Result<Location> {
    "0x".parse_next(input)?;
    let hex_str =
        std::str::from_utf8(hex_digit1.parse_next(input)?).map_err(|_| ContextError::new())?;
    let address = u64::from_str_radix(hex_str, 16).map_err(|_| ContextError::new())?;
    Ok(Location { address })
}

fn parse_commands<'input>(input: &mut &'input BStr) -> winnow::Result<Vec<Command<'input>>> {
    skip_comments_and_whitespace(input)?;

    Ok(repeat_till(0.., parse_command, eof).parse_next(input)?.0)
}

fn parse_entry<'input>(input: &mut &'input BStr) -> winnow::Result<&'input [u8]> {
    skip_comments_and_whitespace(input)?;
    '('.parse_next(input)?;
    skip_comments_and_whitespace(input)?;
    let symbol_name = parse_token(input)?;
    skip_comments_and_whitespace(input)?;
    ')'.parse_next(input)?;
    Ok(symbol_name)
}

fn parse_version<'input>(input: &mut &'input BStr) -> winnow::Result<&'input [u8]> {
    skip_comments_and_whitespace(input)?;
    '{'.parse_next(input)?;
    skip_comments_and_whitespace(input)?;

    let mut brace_count = 1;
    let mut pos = 0;

    while brace_count > 0 && pos < input.len() {
        match input[pos] {
            b'{' => brace_count += 1,
            b'}' => brace_count -= 1,
            _ => {}
        }
        pos += 1;
    }

    if brace_count != 0 {
        return Err(ContextError::new());
    }

    let version_content = &input[..pos - 1];
    *input = &input[pos..];

    skip_comments_and_whitespace(input)?;

    opt(';').parse_next(input)?;

    Ok(version_content)
}

fn parse_sections<'input>(input: &mut &'input BStr) -> winnow::Result<Sections<'input>> {
    '{'.parse_next(input)?;
    skip_comments_and_whitespace(input)?;
    let (commands, _) = repeat_till(0.., parse_section_command, '}').parse_next(input)?;
    skip_comments_and_whitespace(input)?;
    Ok(Sections { commands })
}

fn parse_section_command<'input>(
    input: &mut &'input BStr,
) -> winnow::Result<SectionCommand<'input>> {
    let name = parse_token(input)?;

    skip_comments_and_whitespace(input)?;

    // Handle ASSERT command
    if name == b"ASSERT" {
        return Ok(SectionCommand::Assert(parse_assert(input)?));
    }

    if name == b"." {
        '='.parse_next(input)?;
        skip_comments_and_whitespace(input)?;

        let cmd = if input.starts_with(b"ALIGN") {
            SectionCommand::Align(parse_alignment(input)?)
        } else {
            SectionCommand::SetLocation(parse_location.parse_next(input)?)
        };

        skip_comments_and_whitespace(input)?;
        ';'.parse_next(input)?;
        skip_comments_and_whitespace(input)?;

        return Ok(cmd);
    }

    ':'.parse_next(input)?;

    skip_comments_and_whitespace(input)?;

    let mut alignment = None;

    while !input.starts_with("{".as_bytes()) {
        alignment = Some(parse_alignment.parse_next(input)?);
    }

    '{'.parse_next(input)?;
    skip_comments_and_whitespace(input)?;

    let (commands, _) = repeat_till(0.., parse_contents_command, '}').parse_next(input)?;

    skip_comments_and_whitespace(input)?;

    Ok(SectionCommand::Section(Section {
        output_section_name: name,
        commands,
        alignment,
    }))
}

fn parse_alignment(input: &mut &BStr) -> winnow::Result<Alignment> {
    "ALIGN".parse_next(input)?;
    skip_comments_and_whitespace(input)?;
    '('.parse_next(input)?;
    skip_comments_and_whitespace(input)?;
    let raw_alignment = dec_uint.parse_next(input)?;
    let alignment = Alignment::new(raw_alignment).map_err(|_| {
        ContextError::from_external_error(input, LinkerScriptError::InvalidAlignment)
    })?;
    skip_comments_and_whitespace(input)?;
    ')'.parse_next(input)?;
    skip_comments_and_whitespace(input)?;
    Ok(alignment)
}

fn parse_contents_command<'input>(
    input: &mut &'input BStr,
) -> winnow::Result<ContentsCommand<'input>> {
    alt((parse_contents_provide, parse_matcher, parse_assignment)).parse_next(input)
}

fn parse_contents_provide<'input>(
    input: &mut &'input BStr,
) -> winnow::Result<ContentsCommand<'input>> {
    let hidden = alt(("PROVIDE_HIDDEN", "PROVIDE")).parse_next(input)? == b"PROVIDE_HIDDEN";
    skip_comments_and_whitespace(input)?;
    let provide = parse_provide(input, hidden)?;
    Ok(ContentsCommand::Provide(provide))
}

fn parse_assignment<'input>(input: &mut &'input BStr) -> winnow::Result<ContentsCommand<'input>> {
    let name = parse_token(input)?;
    skip_comments_and_whitespace(input)?;
    '='.parse_next(input)?;
    skip_comments_and_whitespace(input)?;

    let cmd = if name == b"." {
        ContentsCommand::Align(parse_alignment(input)?)
    } else {
        '.'.parse_next(input)?;
        ContentsCommand::SymbolAssignment(SymbolAssignment { name })
    };

    opt(';').parse_next(input)?;
    skip_comments_and_whitespace(input)?;

    Ok(cmd)
}

fn parse_matcher<'input>(input: &mut &'input BStr) -> winnow::Result<ContentsCommand<'input>> {
    let matcher = alt((parse_keep, parse_matcher_pattern)).parse_next(input)?;
    opt(';').parse_next(input)?;
    skip_comments_and_whitespace(input)?;
    Ok(ContentsCommand::Matcher(matcher))
}

fn parse_keep<'input>(input: &mut &'input BStr) -> winnow::Result<Matcher<'input>> {
    "KEEP".parse_next(input)?;
    skip_comments_and_whitespace(input)?;
    '('.parse_next(input)?;
    let mut matcher = parse_matcher_pattern(input)?;
    matcher.must_keep = true;
    ')'.parse_next(input)?;
    skip_comments_and_whitespace(input)?;
    Ok(matcher)
}

fn parse_matcher_pattern<'input>(input: &mut &'input BStr) -> winnow::Result<Matcher<'input>> {
    // Parse the file pattern token (e.g., *, foo.o, *crtbegin*.o).
    let file_pattern = parse_token(input)?;
    skip_comments_and_whitespace(input)?;
    '('.parse_next(input)?;
    skip_comments_and_whitespace(input)?;

    let (patterns, _) = repeat_till(0.., parse_pattern, ')').parse_next(input)?;
    skip_comments_and_whitespace(input)?;

    // A bare `*` means "match all files", represented as None.
    let input_file_pattern = if file_pattern == b"*" {
        None
    } else {
        Some(file_pattern)
    };

    Ok(Matcher {
        must_keep: false,
        input_file_pattern,
        input_section_name_patterns: patterns,
    })
}

fn parse_pattern<'input>(input: &mut &'input BStr) -> winnow::Result<&'input [u8]> {
    let pattern = take_while(1.., |b| !b" \n\t)".contains(&b)).parse_next(input)?;
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
                let spec = if let Some(lib_name) = arg.strip_prefix("-l".as_bytes()) {
                    InputSpec::Lib(Box::from(to_str(lib_name)?))
                } else {
                    InputSpec::File(Box::from(Path::new(to_str(arg)?)))
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
            _ => {}
        }
    }

    Ok(())
}

fn to_str(bytes: &[u8]) -> Result<&str> {
    std::str::from_utf8(bytes)
        .with_context(|| format!("Expected UTF-8, found `{}`", String::from_utf8_lossy(bytes)))
}

#[derive(Debug)]
enum LinkerScriptError {
    InvalidAlignment,
}

impl std::error::Error for LinkerScriptError {}

impl std::fmt::Display for LinkerScriptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LinkerScriptError::InvalidAlignment => write!(f, "Invalid alignment"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args::InputSpec;
    use itertools::assert_equal;

    fn parse_script(text: &str) -> Result<LinkerScript<'_>> {
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

        let inputs = inputs_from_script("INPUT(\"libbar.so\")").unwrap();
        assert_equal(
            inputs.into_iter().map(|i| i.spec),
            [InputSpec::File(Box::from(Path::new("libbar.so")))],
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
    }

    #[track_caller]
    fn check_section_command(input: &str, expected: &SectionCommand) {
        match parse_section_command.parse(BStr::new(input)) {
            Ok(actual) => assert_eq!(&actual, expected),
            Err(e) => panic!("Parse failed:\n{e}"),
        }
    }

    #[test]
    fn test_section_command() {
        check_section_command(
            ".text : { *(.text .text2) *(.text3) }",
            &SectionCommand::Section(Section {
                output_section_name: ".text".as_bytes(),
                commands: vec![
                    ContentsCommand::Matcher(Matcher {
                        must_keep: false,
                        input_file_pattern: None,
                        input_section_name_patterns: vec![".text".as_bytes(), ".text2".as_bytes()],
                    }),
                    ContentsCommand::Matcher(Matcher {
                        must_keep: false,
                        input_file_pattern: None,
                        input_section_name_patterns: vec![".text3".as_bytes()],
                    }),
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
            ENTRY(_start)
            SECTIONS {
                . = 0x1000000;
                . = ALIGN(16);
                .foo : ALIGN(8) {
                    start_foo = .;
                    KEEP(*(.rodata.foo));
                    . = ALIGN(32);
                    end_foo = .;
                }
            }
        ",
            &LinkerScript {
                commands: vec![
                    Command::Entry("_start".as_bytes()),
                    Command::Sections(Sections {
                        commands: vec![
                            SectionCommand::SetLocation(Location { address: 0x1000000 }),
                            SectionCommand::Align(Alignment::new(16).unwrap()),
                            SectionCommand::Section(Section {
                                output_section_name: ".foo".as_bytes(),
                                commands: vec![
                                    ContentsCommand::SymbolAssignment(SymbolAssignment {
                                        name: "start_foo".as_bytes(),
                                    }),
                                    ContentsCommand::Matcher(Matcher {
                                        must_keep: true,
                                        input_file_pattern: None,
                                        input_section_name_patterns: vec![".rodata.foo".as_bytes()],
                                    }),
                                    ContentsCommand::Align(Alignment::new(32).unwrap()),
                                    ContentsCommand::SymbolAssignment(SymbolAssignment {
                                        name: "end_foo".as_bytes(),
                                    }),
                                ],
                                alignment: Some(Alignment::new(8).unwrap()),
                            }),
                        ],
                    }),
                ],
            },
        );
    }

    #[test]
    fn test_version_command() {
        let script = parse_script(
            r#"
            VERSION {
                VERS_1.0 {
                    global: foo; bar*;
                    local: *;
                };
            }
            "#,
        )
        .unwrap();

        let version_content = script.get_version_script_content().unwrap();
        let version_str = std::str::from_utf8(version_content).unwrap().trim();

        assert!(version_str.contains("VERS_1.0"));
        assert!(version_str.contains("global:"));
        assert!(version_str.contains("foo"));
        assert!(version_str.contains("bar*"));
        assert!(version_str.contains("local:"));
    }

    #[test]
    fn test_version_command_with_nested_braces() {
        let script = parse_script(
            r#"
            VERSION {
                VERS_1.0 {
                    global: 
                        extern "C++" {
                            ns::*;
                        };
                };
            }
            "#,
        )
        .unwrap();

        let version_content = script.get_version_script_content().unwrap();
        let version_str = std::str::from_utf8(version_content).unwrap().trim();

        assert!(version_str.contains("VERS_1.0"));
        assert!(version_str.contains(r#"extern "C++""#));
        assert!(version_str.contains("ns::*"));
    }

    #[test]
    fn test_version_command_with_other_commands() {
        let script = parse_script(
            r#"
            ENTRY(_start)
            VERSION {
                VERS_1.0 {
                    global: foo;
                };
            }
            SECTIONS {
                .text : { *(.text) }
            }
            "#,
        )
        .unwrap();

        assert!(script.get_version_script_content().is_some());
        assert!(
            script
                .commands
                .iter()
                .any(|cmd| matches!(cmd, Command::Entry(_)))
        );
        assert!(
            script
                .commands
                .iter()
                .any(|cmd| matches!(cmd, Command::Sections(_)))
        );
    }

    #[test]
    fn test_version_script_parsing_from_version_command() {
        use crate::input_data::ScriptData;
        use crate::version_script::VersionScript;

        let script = parse_script(
            r#"
            VERSION {
                VERS_1.0 {
                    global: foo; bar*;
                    local: *;
                };
            }
            "#,
        )
        .unwrap();

        let version_content = script.get_version_script_content().unwrap();

        let script_data = ScriptData {
            raw: version_content,
        };

        let version_script = VersionScript::parse(script_data).unwrap();

        assert_eq!(version_script.version_count(), 2);
    }

    #[test]
    fn test_section_command_with_filename() {
        check_section_command(
            ".text : { foo.o(.text .text2) *(.text3) }",
            &SectionCommand::Section(Section {
                output_section_name: ".text".as_bytes(),
                commands: vec![
                    ContentsCommand::Matcher(Matcher {
                        must_keep: false,
                        input_file_pattern: Some("foo.o".as_bytes()),
                        input_section_name_patterns: vec![".text".as_bytes(), ".text2".as_bytes()],
                    }),
                    ContentsCommand::Matcher(Matcher {
                        must_keep: false,
                        input_file_pattern: None,
                        input_section_name_patterns: vec![".text3".as_bytes()],
                    }),
                ],
                alignment: None,
            }),
        );
    }

    #[test]
    fn test_section_command_with_glob_filename() {
        check_section_command(
            ".ctors : { *crtbegin*.o(.ctors) }",
            &SectionCommand::Section(Section {
                output_section_name: ".ctors".as_bytes(),
                commands: vec![ContentsCommand::Matcher(Matcher {
                    must_keep: false,
                    input_file_pattern: Some("*crtbegin*.o".as_bytes()),
                    input_section_name_patterns: vec![".ctors".as_bytes()],
                })],
                alignment: None,
            }),
        );
    }

    #[test]
    fn test_keep_with_filename() {
        check_section_command(
            ".init : { KEEP(crti.o(.init)) }",
            &SectionCommand::Section(Section {
                output_section_name: ".init".as_bytes(),
                commands: vec![ContentsCommand::Matcher(Matcher {
                    must_keep: true,
                    input_file_pattern: Some("crti.o".as_bytes()),
                    input_section_name_patterns: vec![".init".as_bytes()],
                })],
                alignment: None,
            }),
        );
    }

    #[test]
    fn test_assert_command() {
        check_linker_script(
            r#"
            SECTIONS {
                .text : { *(.text) }
            }
            ASSERT(. < 0x10000, "Output too large");
            "#,
            &LinkerScript {
                commands: vec![
                    Command::Sections(Sections {
                        commands: vec![SectionCommand::Section(Section {
                            output_section_name: ".text".as_bytes(),
                            commands: vec![ContentsCommand::Matcher(Matcher {
                                must_keep: false,
                                input_file_pattern: None,
                                input_section_name_patterns: vec![".text".as_bytes()],
                            })],
                            alignment: None,
                        })],
                    }),
                    Command::Assert(AssertCommand {
                        expression: Expression::LessThan(
                            Box::new(Expression::LocationCounter),
                            Box::new(Expression::Number(0x10000)),
                        ),
                        message: "Output too large".as_bytes(),
                    }),
                ],
            },
        );
    }

    #[test]
    fn test_assert_in_sections() {
        check_linker_script(
            r#"
            SECTIONS {
                .text : { *(.text) }
                ASSERT(SIZEOF(.text) < 0x1000, "Text section too large");
            }
            "#,
            &LinkerScript {
                commands: vec![Command::Sections(Sections {
                    commands: vec![
                        SectionCommand::Section(Section {
                            output_section_name: ".text".as_bytes(),
                            commands: vec![ContentsCommand::Matcher(Matcher {
                                must_keep: false,
                                input_file_pattern: None,
                                input_section_name_patterns: vec![".text".as_bytes()],
                            })],
                            alignment: None,
                        }),
                        SectionCommand::Assert(AssertCommand {
                            expression: Expression::LessThan(
                                Box::new(Expression::Sizeof(".text".as_bytes())),
                                Box::new(Expression::Number(0x1000)),
                            ),
                            message: "Text section too large".as_bytes(),
                        }),
                    ],
                })],
            },
        );
    }

    #[test]
    fn test_assert_with_complex_expression() {
        let script =
            parse_script(r#"ASSERT(__bss_end - __bss_start <= 0x1000, "BSS too large");"#).unwrap();

        assert_eq!(script.commands.len(), 1);
        match &script.commands[0] {
            Command::Assert(assert_cmd) => {
                assert_eq!(
                    assert_cmd.expression,
                    Expression::LessEqual(
                        Box::new(Expression::Subtract(
                            Box::new(Expression::Symbol("__bss_end".as_bytes())),
                            Box::new(Expression::Symbol("__bss_start".as_bytes())),
                        )),
                        Box::new(Expression::Number(0x1000)),
                    )
                );
                assert_eq!(assert_cmd.message, "BSS too large".as_bytes());
            }
            _ => panic!("Expected Assert command"),
        }
    }

    #[test]
    fn test_expression_operator_precedence() {
        // Test that multiplication has higher precedence than addition: 1 + 2 * 3 = 7
        let script = parse_script(r#"ASSERT(1 + 2 * 3 == 7, "Math is broken");"#).unwrap();

        match &script.commands[0] {
            Command::Assert(assert_cmd) => {
                assert_eq!(
                    assert_cmd.expression,
                    Expression::Equal(
                        Box::new(Expression::Add(
                            Box::new(Expression::Number(1)),
                            Box::new(Expression::Multiply(
                                Box::new(Expression::Number(2)),
                                Box::new(Expression::Number(3)),
                            )),
                        )),
                        Box::new(Expression::Number(7)),
                    )
                );
            }
            _ => panic!("Expected Assert command"),
        }
    }

    #[test]
    fn test_expression_nested_parentheses() {
        // Test nested parentheses: (1 + 2) * (3 + 4) = 21
        let script =
            parse_script(r#"ASSERT((1 + 2) * (3 + 4) == 21, "Parentheses broken");"#).unwrap();

        match &script.commands[0] {
            Command::Assert(assert_cmd) => {
                assert_eq!(
                    assert_cmd.expression,
                    Expression::Equal(
                        Box::new(Expression::Multiply(
                            Box::new(Expression::Add(
                                Box::new(Expression::Number(1)),
                                Box::new(Expression::Number(2)),
                            )),
                            Box::new(Expression::Add(
                                Box::new(Expression::Number(3)),
                                Box::new(Expression::Number(4)),
                            )),
                        )),
                        Box::new(Expression::Number(21)),
                    )
                );
            }
            _ => panic!("Expected Assert command"),
        }
    }

    #[test]
    fn test_expression_function_in_comparison() {
        // Test function call inside comparison: SIZEOF(.data) + SIZEOF(.bss) < 0x2000
        let script = parse_script(
            r#"ASSERT(SIZEOF(.data) + SIZEOF(.bss) < 0x2000, "Data sections too large");"#,
        )
        .unwrap();

        match &script.commands[0] {
            Command::Assert(assert_cmd) => {
                assert_eq!(
                    assert_cmd.expression,
                    Expression::LessThan(
                        Box::new(Expression::Add(
                            Box::new(Expression::Sizeof(".data".as_bytes())),
                            Box::new(Expression::Sizeof(".bss".as_bytes())),
                        )),
                        Box::new(Expression::Number(0x2000)),
                    )
                );
            }
            _ => panic!("Expected Assert command"),
        }
    }

    #[test]
    fn test_expression_hex_numbers() {
        // Test hexadecimal number parsing
        let script = parse_script(r#"ASSERT(. < 0xDEADBEEF, "Too large");"#).unwrap();

        match &script.commands[0] {
            Command::Assert(assert_cmd) => {
                assert_eq!(
                    assert_cmd.expression,
                    Expression::LessThan(
                        Box::new(Expression::LocationCounter),
                        Box::new(Expression::Number(0xDEADBEEF)),
                    )
                );
            }
            _ => panic!("Expected Assert command"),
        }
    }

    #[test]
    fn test_expression_align_function() {
        // Test ALIGN function with expression
        let script =
            parse_script(r#"ASSERT(ALIGN(. + 0x100) < 0x10000, "Aligned too large");"#).unwrap();

        match &script.commands[0] {
            Command::Assert(assert_cmd) => {
                assert_eq!(
                    assert_cmd.expression,
                    Expression::LessThan(
                        Box::new(Expression::Align(Box::new(Expression::Add(
                            Box::new(Expression::LocationCounter),
                            Box::new(Expression::Number(0x100)),
                        )))),
                        Box::new(Expression::Number(0x10000)),
                    )
                );
            }
            _ => panic!("Expected Assert command"),
        }
    }
}
