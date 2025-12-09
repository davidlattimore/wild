use crate::Args;
use crate::args::RelocationModel;
use crate::input_data::FileLoader;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OutputKind {
    StaticExecutable(RelocationModel),
    DynamicExecutable(RelocationModel),
    SharedObject,
}

impl OutputKind {
    pub(crate) fn new(args: &Args, input_data: &FileLoader<'_>) -> OutputKind {
        if !args.should_output_executable {
            OutputKind::SharedObject
        } else if args.dynamic_linker.is_some()
            && args.relocation_model == RelocationModel::Relocatable
        {
            // GNU ld turns static relocatable executables into dynamic ones if dynamic linker is
            // set.
            OutputKind::DynamicExecutable(args.relocation_model)
        } else if input_data
            .loaded_files
            .iter()
            .any(|file| file.kind == crate::file_kind::FileKind::ElfDynamic)
        {
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
        !matches!(self, OutputKind::SharedObject)
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
