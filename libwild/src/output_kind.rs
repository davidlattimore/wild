use crate::args::RelocationModel;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OutputKind {
    StaticExecutable(RelocationModel),
    DynamicExecutable(RelocationModel),
    SharedObject,
}

impl OutputKind {
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
