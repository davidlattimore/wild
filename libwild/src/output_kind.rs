use crate::Args;
use crate::args::RelocationModel;
use crate::input_data::FileLoader;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OutputKind {
    /// Relocatable/partial-link output (ET_REL)
    Relocatable,
    StaticExecutable(RelocationModel),
    DynamicExecutable(RelocationModel),
    SharedObject,
}

impl OutputKind {
    pub(crate) fn new(args: &Args, input_data: &FileLoader<'_>) -> OutputKind {
        if args.output_relocatable {
            return OutputKind::Relocatable;
        }
        if !args.should_output_executable {
            OutputKind::SharedObject
        } else if args.dynamic_linker.is_some()
            && args.relocation_model == RelocationModel::Relocatable
        {
            // GNU ld turns static relocatable executables into dynamic ones if dynamic linker is
            // set.
            OutputKind::DynamicExecutable(args.relocation_model)
        } else if input_data.has_dynamic {
            // When attempting to create static executable, but DSO is added as an input we need to
            // proceed with dynamic executable.
            // This is in line with LLD, but GNU ld goes a step further: if no DSO ends up loaded,
            // it'll go back to static one. This would add a lot of complexity with the
            // current design, so we just stick to LLD behaviour.
            OutputKind::DynamicExecutable(args.relocation_model)
        } else {
            OutputKind::StaticExecutable(args.relocation_model)
        }
    }

    pub(crate) fn is_executable(self) -> bool {
        matches!(self, OutputKind::StaticExecutable(_) | OutputKind::DynamicExecutable(_))
    }

    pub(crate) fn is_shared_object(self) -> bool {
        matches!(self, OutputKind::SharedObject)
    }

    pub(crate) fn is_dynamic_executable(self) -> bool {
        matches!(self, OutputKind::DynamicExecutable(_))
    }

    pub(crate) fn is_static_executable(self) -> bool {
        matches!(self, OutputKind::StaticExecutable(_))
    }

    pub(crate) fn is_relocatable(self) -> bool {
        matches!(
            self,
            OutputKind::StaticExecutable(RelocationModel::Relocatable)
                | OutputKind::DynamicExecutable(RelocationModel::Relocatable)
                | OutputKind::SharedObject
        )
    }

    /// Returns true for `-r` / `--relocatable` partial-link output (ET_REL).
    /// This is distinct from `is_relocatable()` which means PIE/PIC.
    pub(crate) fn is_partial_link(self) -> bool {
        matches!(self, OutputKind::Relocatable)
    }

    pub(crate) fn needs_dynsym(self) -> bool {
        matches!(
            self,
            OutputKind::DynamicExecutable(_)
                | OutputKind::SharedObject
                // It seems a bit weird to have dynsym in a static-PIE binary, but that's what GNU
                // ld does. It just doesn't have any symbols besides the undefined symbol.
                | OutputKind::StaticExecutable(RelocationModel::Relocatable)
        )
    }

    pub(crate) fn needs_dynamic(self) -> bool {
        self != OutputKind::StaticExecutable(RelocationModel::NonRelocatable)
            && !matches!(self, OutputKind::Relocatable)
    }

    pub(crate) fn base_address(self) -> u64 {
        if self.is_relocatable() || matches!(self, OutputKind::Relocatable) {
            0
        } else {
            crate::elf::NON_PIE_START_MEM_ADDRESS
        }
    }

    pub(crate) fn should_output_symbol_versions(self) -> bool {
        matches!(
            self,
            OutputKind::DynamicExecutable(_) | OutputKind::SharedObject
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relocatable_output_kind_properties() {
        let kind = OutputKind::Relocatable;
        assert!(!kind.is_executable());
        assert!(!kind.is_shared_object());
        assert!(!kind.needs_dynsym());
        assert!(!kind.needs_dynamic());
        assert!(!kind.should_output_symbol_versions());
        assert_eq!(kind.base_address(), 0);
        assert!(kind.is_partial_link());
        assert!(!kind.is_relocatable());
        assert!(!kind.is_dynamic_executable());
        assert!(!kind.is_static_executable());
    }

    #[test]
    fn test_partial_link_distinct_from_pie() {
        // Relocatable (ET_REL / -r) is distinct from PIE (is_relocatable).
        let partial = OutputKind::Relocatable;
        let pie = OutputKind::DynamicExecutable(RelocationModel::Relocatable);

        assert!(partial.is_partial_link());
        assert!(!partial.is_relocatable());

        assert!(!pie.is_partial_link());
        assert!(pie.is_relocatable());
    }

    #[test]
    fn test_output_kinds_needs_dynamic() {
        // Partial link doesn't need dynamic sections
        assert!(!OutputKind::Relocatable.needs_dynamic());

        // Static non-relocatable doesn't need dynamic
        assert!(!OutputKind::StaticExecutable(RelocationModel::NonRelocatable).needs_dynamic());

        // Everything else does
        assert!(OutputKind::SharedObject.needs_dynamic());
        assert!(OutputKind::DynamicExecutable(RelocationModel::Relocatable).needs_dynamic());
        assert!(OutputKind::StaticExecutable(RelocationModel::Relocatable).needs_dynamic());
    }
}
