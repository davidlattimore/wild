use crate::args::RelocationModel;
use crate::input_data::FileLoader;
use crate::platform;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OutputKind {
    StaticExecutable(RelocationModel),
    DynamicExecutable(RelocationModel),
    SharedObject,
    Relocatable,
}

impl OutputKind {
    pub(crate) fn new(args: &impl platform::Args, input_data: &FileLoader<'_>) -> OutputKind {
        let model = args.relocation_model();
        if !args.should_output_executable() {
            if args.should_output_partial_object() {
                return OutputKind::Relocatable;
            }
            OutputKind::SharedObject
        } else if args.dynamic_linker().is_some() && model == RelocationModel::Relocatable {
            // GNU ld turns static relocatable executables into dynamic ones if dynamic linker is
            // set.
            OutputKind::DynamicExecutable(model)
        } else if input_data.has_dynamic {
            // When attempting to create static executable, but DSO is added as an input we need to
            // proceed with dynamic executable.
            // This is in line with LLD, but GNU ld goes a step further: if no DSO ends up loaded,
            // it'll go back to static one. This would add a lot of complexity with the
            // current design, so we just stick to LLD behaviour.
            OutputKind::DynamicExecutable(model)
        } else {
            OutputKind::StaticExecutable(model)
        }
    }

    pub(crate) fn is_executable(self) -> bool {
        !matches!(self, OutputKind::SharedObject | OutputKind::Relocatable)
    }

    pub(crate) fn is_shared_object(self) -> bool {
        matches!(self, OutputKind::SharedObject)
    }

    pub(crate) fn is_partial_object(self) -> bool {
        matches!(self, OutputKind::Relocatable)
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
                | OutputKind::Relocatable
        )
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
        !matches!(
            self,
            OutputKind::StaticExecutable(RelocationModel::NonRelocatable) | OutputKind::Relocatable
        )
    }

    pub(crate) fn base_address(self) -> u64 {
        if self.is_relocatable() {
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
