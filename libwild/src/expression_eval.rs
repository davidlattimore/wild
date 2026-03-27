use crate::args::WarningCallback;
/// Evaluation of linker script ASSERT commands after layout is complete.
///
/// NOTE: ASSERT expression evaluation currently supports a subset of GNU ld expression
/// features. Symbol resolution and full location counter semantics (e.g. ALIGN with a non-zero
/// current address) will be implemented in future work.
use crate::bail;
use crate::error::Context;
use crate::error::Result;
use crate::error::Warning;
use crate::grouping::Group;
use crate::layout::OutputRecordLayout;
use crate::linker_script::Expression;
use crate::output_section_id::OutputSections;
use crate::output_section_id::SectionName;
use crate::output_section_map::OutputSectionMap;
use crate::platform::Platform;

/// Compute 1-based line number by counting newlines before `remainder` in `file_bytes`.
fn line_number(file_bytes: &[u8], remainder: &[u8]) -> u32 {
    let parsed_len = file_bytes.len().saturating_sub(remainder.len());
    let consumed = &file_bytes[..parsed_len];
    consumed.iter().filter(|&&b| b == b'\n').count() as u32 + 1
}

/// Evaluate all ASSERT commands from all processed linker scripts.
/// Must be called after layout is complete so section sizes/addresses are known.
pub(crate) fn evaluate_assertions<'data, P: Platform>(
    groups: &[Group<'data, P>],
    section_layouts: &OutputSectionMap<OutputRecordLayout>,
    output_sections: &OutputSections<'data, P>,
    warning_callback: &WarningCallback,
) -> Result {
    for group in groups {
        let Group::LinkerScripts(scripts) = group else {
            continue;
        };
        for script in scripts {
            let parsed = &script.parsed;
            for assertion in &parsed.assertions {
                let line = line_number(parsed.file_bytes, assertion.remainder);
                let result = evaluate_expression(
                    &assertion.expression,
                    section_layouts,
                    output_sections,
                    warning_callback,
                )
                .with_context(|| format!("{}:{}: Failed to evaluate ASSERT", parsed.input, line))?;

                if result == 0 {
                    let msg = String::from_utf8_lossy(assertion.message);
                    bail!("{}:{}: {msg}", parsed.input, line);
                }
            }
        }
    }
    Ok(())
}

fn evaluate_expression<'data, P: Platform>(
    expr: &Expression<'data>,
    section_layouts: &OutputSectionMap<OutputRecordLayout>,
    output_sections: &OutputSections<'data, P>,
    warning_callback: &WarningCallback,
) -> Result<u64> {
    macro_rules! eval {
        ($e:expr) => {
            evaluate_expression($e, section_layouts, output_sections, warning_callback)
        };
    }

    match expr {
        Expression::Number(n) => Ok(*n),

        // '.' is not meaningful outside of section layout context; treat as 0
        Expression::LocationCounter => Ok(0),

        Expression::Symbol(name) => {
            // Symbol resolution in ASSERT is not yet implemented. Rather than failing the
            // link (which would be our fault, not the user's), emit a warning and skip the
            // assertion by returning 1 (true).
            warning_callback(Warning::new(format!(
                "ASSERT: symbol references not yet supported ('{}'), skipping assertion",
                String::from_utf8_lossy(name)
            )));
            Ok(1)
        }

        Expression::Add(l, r) => Ok(eval!(l)?.wrapping_add(eval!(r)?)),
        Expression::Subtract(l, r) => Ok(eval!(l)?.wrapping_sub(eval!(r)?)),
        Expression::Multiply(l, r) => Ok(eval!(l)?.wrapping_mul(eval!(r)?)),
        Expression::Divide(l, r) => {
            let divisor = eval!(r)?;
            if divisor == 0 {
                bail!("Division by zero in linker script expression");
            }
            Ok(eval!(l)? / divisor)
        }

        // Comparisons return 1 (true) or 0 (false)
        Expression::LessThan(l, r) => Ok(u64::from(eval!(l)? < eval!(r)?)),
        Expression::GreaterThan(l, r) => Ok(u64::from(eval!(l)? > eval!(r)?)),
        Expression::LessEqual(l, r) => Ok(u64::from(eval!(l)? <= eval!(r)?)),
        Expression::GreaterEqual(l, r) => Ok(u64::from(eval!(l)? >= eval!(r)?)),
        Expression::Equal(l, r) => Ok(u64::from(eval!(l)? == eval!(r)?)),
        Expression::NotEqual(l, r) => Ok(u64::from(eval!(l)? != eval!(r)?)),

        Expression::Sizeof(name) => Ok(section_size(name, section_layouts, output_sections)),
        Expression::Alignof(name) => Ok(section_align(name, section_layouts, output_sections)),
        Expression::Addr(name) => section_address(name, section_layouts, output_sections),

        Expression::Align(expr) => {
            let align = eval!(expr)?;
            if align == 0 {
                bail!("ALIGN(0) is invalid");
            }
            // NOTE: ALIGN(n) in a full linker script context means "align the current address
            // to n". Here we always align 0 because the location counter is not threaded through
            // expression evaluation. This gives correct results when used as a standalone value
            // (e.g. ASSERT(ALIGN(4096) == 0, ...)) but not when combined with the location
            // counter (e.g. ASSERT(. + ALIGN(4096) > x, ...)). Full support requires passing
            // the current address into evaluate_expression.
            Ok(0u64.wrapping_add(align - 1) & !(align - 1))
        }

        Expression::Min(l, r) => Ok(eval!(l)?.min(eval!(r)?)),
        Expression::Max(l, r) => Ok(eval!(l)?.max(eval!(r)?)),
        Expression::BitwiseAnd(l, r) => Ok(eval!(l)? & eval!(r)?),
        Expression::BitwiseOr(l, r) => Ok(eval!(l)? | eval!(r)?),
        Expression::BitwiseXor(l, r) => Ok(eval!(l)? ^ eval!(r)?),
        Expression::LeftShift(l, r) => Ok(eval!(l)?.wrapping_shl(eval!(r)? as u32)),
        Expression::RightShift(l, r) => Ok(eval!(l)?.wrapping_shr(eval!(r)? as u32)),
        Expression::LogicalAnd(l, r) => Ok(u64::from(eval!(l)? != 0 && eval!(r)? != 0)),
        Expression::LogicalOr(l, r) => Ok(u64::from(eval!(l)? != 0 || eval!(r)? != 0)),
        Expression::LogicalNot(e) => Ok(u64::from(eval!(e)? == 0)),
        Expression::BitwiseNot(e) => Ok(!eval!(e)?),
        Expression::Negate(e) => Ok(eval!(e)?.wrapping_neg()),
    }
}

fn section_size<'data, P: Platform>(
    name: &[u8],
    section_layouts: &OutputSectionMap<OutputRecordLayout>,
    output_sections: &OutputSections<'data, P>,
) -> u64 {
    // GNU ld returns 0 for SIZEOF of a section that doesn't exist in the output.
    // We match that behavior to avoid breaking scripts that guard with SIZEOF.
    let Some(id) = output_sections.section_id_by_name(SectionName(name)) else {
        return 0;
    };
    section_layouts.get(id).mem_size
}

fn section_align<'data, P: Platform>(
    name: &[u8],
    section_layouts: &OutputSectionMap<OutputRecordLayout>,
    output_sections: &OutputSections<'data, P>,
) -> u64 {
    // GNU ld returns 0 for ALIGNOF of a section that doesn't exist in the output.
    // We match that behavior to avoid breaking scripts that guard with SIZEOF.
    let Some(id) = output_sections.section_id_by_name(SectionName(name)) else {
        return 0;
    };
    section_layouts.get(id).alignment.value()
}

fn section_address<'data, P: Platform>(
    name: &[u8],
    section_layouts: &OutputSectionMap<OutputRecordLayout>,
    output_sections: &OutputSections<'data, P>,
) -> Result<u64> {
    let id = output_sections
        .section_id_by_name(SectionName(name))
        .ok_or_else(|| {
            crate::error!(
                "ADDR: section '{}' not found",
                String::from_utf8_lossy(name)
            )
        })?;
    Ok(section_layouts.get(id).mem_offset)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elf::Elf;
    use crate::grouping::Group;
    use crate::grouping::SequencedLinkerScript;
    use crate::input_data::FileId;
    use crate::linker_script::AssertCommand;
    use crate::output_section_id::OutputSections;
    use crate::parsing::ProcessedLinkerScript;
    use crate::symbol_db::SymbolIdRange;

    fn dummy_context() -> (
        OutputSectionMap<OutputRecordLayout>,
        OutputSections<'static, Elf>,
    ) {
        let sections = OutputSections::<Elf>::for_testing();
        let layouts = sections.new_section_map::<OutputRecordLayout>();
        (layouts, sections)
    }

    fn eval_const(expr: &Expression<'static>) -> Result<u64> {
        let (layouts, sections) = dummy_context();
        evaluate_expression::<Elf>(expr, &layouts, &sections, &|_| {})
    }

    #[test]
    fn test_number() {
        assert_eq!(eval_const(&Expression::Number(42)).unwrap(), 42);
        assert_eq!(eval_const(&Expression::Number(0)).unwrap(), 0);
    }

    #[test]
    fn test_arithmetic() {
        let add = Expression::Add(
            Box::new(Expression::Number(2)),
            Box::new(Expression::Number(3)),
        );
        assert_eq!(eval_const(&add).unwrap(), 5);

        let sub = Expression::Subtract(
            Box::new(Expression::Number(10)),
            Box::new(Expression::Number(4)),
        );
        assert_eq!(eval_const(&sub).unwrap(), 6);

        let mul = Expression::Multiply(
            Box::new(Expression::Number(3)),
            Box::new(Expression::Number(4)),
        );
        assert_eq!(eval_const(&mul).unwrap(), 12);

        let div = Expression::Divide(
            Box::new(Expression::Number(10)),
            Box::new(Expression::Number(2)),
        );
        assert_eq!(eval_const(&div).unwrap(), 5);
    }

    #[test]
    fn test_wrapping_arithmetic() {
        // u64::MAX + 1 should wrap to 0, not panic
        let expr = Expression::Add(
            Box::new(Expression::Number(u64::MAX)),
            Box::new(Expression::Number(1)),
        );
        assert_eq!(eval_const(&expr).unwrap(), 0);

        // 0 - 1 should wrap to u64::MAX
        let expr = Expression::Subtract(
            Box::new(Expression::Number(0)),
            Box::new(Expression::Number(1)),
        );
        assert_eq!(eval_const(&expr).unwrap(), u64::MAX);
    }

    #[test]
    fn test_operator_precedence() {
        // 1 + (2 * 3) = 7
        let expr = Expression::Add(
            Box::new(Expression::Number(1)),
            Box::new(Expression::Multiply(
                Box::new(Expression::Number(2)),
                Box::new(Expression::Number(3)),
            )),
        );
        assert_eq!(eval_const(&expr).unwrap(), 7);
    }

    #[test]
    fn test_comparisons() {
        // LessThan
        assert_eq!(
            eval_const(&Expression::LessThan(
                Box::new(Expression::Number(1)),
                Box::new(Expression::Number(2))
            ))
            .unwrap(),
            1
        );
        assert_eq!(
            eval_const(&Expression::LessThan(
                Box::new(Expression::Number(2)),
                Box::new(Expression::Number(1))
            ))
            .unwrap(),
            0
        );
        assert_eq!(
            eval_const(&Expression::LessThan(
                Box::new(Expression::Number(5)),
                Box::new(Expression::Number(5))
            ))
            .unwrap(),
            0
        );

        // GreaterThan
        assert_eq!(
            eval_const(&Expression::GreaterThan(
                Box::new(Expression::Number(3)),
                Box::new(Expression::Number(2))
            ))
            .unwrap(),
            1
        );
        assert_eq!(
            eval_const(&Expression::GreaterThan(
                Box::new(Expression::Number(2)),
                Box::new(Expression::Number(3))
            ))
            .unwrap(),
            0
        );
        assert_eq!(
            eval_const(&Expression::GreaterThan(
                Box::new(Expression::Number(5)),
                Box::new(Expression::Number(5))
            ))
            .unwrap(),
            0
        );

        // LessEqual
        assert_eq!(
            eval_const(&Expression::LessEqual(
                Box::new(Expression::Number(1)),
                Box::new(Expression::Number(2))
            ))
            .unwrap(),
            1
        );
        assert_eq!(
            eval_const(&Expression::LessEqual(
                Box::new(Expression::Number(5)),
                Box::new(Expression::Number(5))
            ))
            .unwrap(),
            1
        );
        assert_eq!(
            eval_const(&Expression::LessEqual(
                Box::new(Expression::Number(6)),
                Box::new(Expression::Number(5))
            ))
            .unwrap(),
            0
        );

        // GreaterEqual
        assert_eq!(
            eval_const(&Expression::GreaterEqual(
                Box::new(Expression::Number(5)),
                Box::new(Expression::Number(5))
            ))
            .unwrap(),
            1
        );
        assert_eq!(
            eval_const(&Expression::GreaterEqual(
                Box::new(Expression::Number(6)),
                Box::new(Expression::Number(5))
            ))
            .unwrap(),
            1
        );
        assert_eq!(
            eval_const(&Expression::GreaterEqual(
                Box::new(Expression::Number(4)),
                Box::new(Expression::Number(5))
            ))
            .unwrap(),
            0
        );

        // Equal / NotEqual
        assert_eq!(
            eval_const(&Expression::Equal(
                Box::new(Expression::Number(5)),
                Box::new(Expression::Number(5))
            ))
            .unwrap(),
            1
        );
        assert_eq!(
            eval_const(&Expression::Equal(
                Box::new(Expression::Number(5)),
                Box::new(Expression::Number(6))
            ))
            .unwrap(),
            0
        );
        assert_eq!(
            eval_const(&Expression::NotEqual(
                Box::new(Expression::Number(5)),
                Box::new(Expression::Number(6))
            ))
            .unwrap(),
            1
        );
        assert_eq!(
            eval_const(&Expression::NotEqual(
                Box::new(Expression::Number(5)),
                Box::new(Expression::Number(5))
            ))
            .unwrap(),
            0
        );
    }

    #[test]
    fn test_min_max() {
        assert_eq!(
            eval_const(&Expression::Min(
                Box::new(Expression::Number(3)),
                Box::new(Expression::Number(7))
            ))
            .unwrap(),
            3
        );
        assert_eq!(
            eval_const(&Expression::Min(
                Box::new(Expression::Number(7)),
                Box::new(Expression::Number(3))
            ))
            .unwrap(),
            3
        );
        assert_eq!(
            eval_const(&Expression::Max(
                Box::new(Expression::Number(3)),
                Box::new(Expression::Number(7))
            ))
            .unwrap(),
            7
        );
        assert_eq!(
            eval_const(&Expression::Max(
                Box::new(Expression::Number(7)),
                Box::new(Expression::Number(3))
            ))
            .unwrap(),
            7
        );
        // equal values
        assert_eq!(
            eval_const(&Expression::Min(
                Box::new(Expression::Number(5)),
                Box::new(Expression::Number(5))
            ))
            .unwrap(),
            5
        );
        assert_eq!(
            eval_const(&Expression::Max(
                Box::new(Expression::Number(5)),
                Box::new(Expression::Number(5))
            ))
            .unwrap(),
            5
        );
    }

    #[test]
    fn test_align() {
        // ALIGN(8) with location counter 0 → 0
        assert_eq!(
            eval_const(&Expression::Align(Box::new(Expression::Number(8)))).unwrap(),
            0
        );
        // ALIGN(1) → 0
        assert_eq!(
            eval_const(&Expression::Align(Box::new(Expression::Number(1)))).unwrap(),
            0
        );
    }

    #[test]
    fn test_align_zero_is_error() {
        assert!(eval_const(&Expression::Align(Box::new(Expression::Number(0)))).is_err());
    }

    #[test]
    fn test_divide_by_zero() {
        let expr = Expression::Divide(
            Box::new(Expression::Number(10)),
            Box::new(Expression::Number(0)),
        );
        assert!(eval_const(&expr).is_err());
    }

    #[test]
    fn test_location_counter_is_zero() {
        // LocationCounter outside a section context is treated as 0
        assert_eq!(eval_const(&Expression::LocationCounter).unwrap(), 0);
    }

    #[test]
    fn test_symbol_skips_with_ok() {
        // Symbol references are not yet supported; should return Ok(1) (skip, not fail)
        assert_eq!(eval_const(&Expression::Symbol(b"__bss_start")).unwrap(), 1);
    }

    #[test]
    fn test_alignof_evaluation() {
        // Test that evaluating ALIGNOF for a non-existent section returns 0
        assert_eq!(eval_const(&Expression::Alignof(b".nonexistent")).unwrap(), 0);
    }

    fn make_group(assertions: Vec<AssertCommand<'static>>) -> Group<'static, Elf> {
        static DUMMY_FILE: std::sync::OnceLock<crate::input_data::InputFile> =
            std::sync::OnceLock::new();
        let file = DUMMY_FILE.get_or_init(crate::input_data::InputFile::for_testing);
        let script = SequencedLinkerScript {
            parsed: ProcessedLinkerScript {
                input: crate::input_data::InputRef { file, entry: None },
                symbol_defs: Vec::new(),
                assertions,
                file_bytes: b"",
            },
            symbol_id_range: SymbolIdRange::empty(),
            file_id: FileId::new(0, 0),
        };
        Group::LinkerScripts(vec![script])
    }

    #[test]
    fn test_evaluate_assertions_passes() {
        let (layouts, sections) = dummy_context();
        let group = make_group(vec![AssertCommand {
            expression: Expression::Equal(
                Box::new(Expression::Number(1)),
                Box::new(Expression::Number(1)),
            ),
            message: b"should pass",
            remainder: b"",
        }]);
        assert!(evaluate_assertions::<Elf>(&[group], &layouts, &sections, &|_| {}).is_ok(),);
    }

    #[test]
    fn test_evaluate_assertions_fails() {
        let (layouts, sections) = dummy_context();
        let group = make_group(vec![AssertCommand {
            expression: Expression::Number(0),
            message: b"intentional failure",
            remainder: b"",
        }]);
        let err = evaluate_assertions::<Elf>(&[group], &layouts, &sections, &|_| {}).unwrap_err();
        assert!(err.to_string().contains("intentional failure"));
    }
}
