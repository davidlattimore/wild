//! Contains code to perform various relocation relaxation optimisations. These are supposed to be
//! optional for the linker to do, but it turns out that libc in some cases won't work unless
//! they're performed. e.g. it uses GOT relocations in _start, which cannot work in a static-PIE
//! binary because dynamic relocations haven't yet been applied to the GOT.
//!
//! For now, we only apply those relaxations that we find we need.

use crate::elf::rel;

#[derive(Debug)]
pub(crate) enum Relaxation {
    /// Transforms a mov instruction to not the GOT. If the GOT entry would have contained a
    /// relocatable address, then the transformation will look like `mov *x(%rip), reg` -> `lea
    /// x(%rip), reg`. If the GOT entry would have contained an absolute value (e.g. a null entry)
    /// then we transform instead to `mov x, reg`.
    BypassGotMov,

    /// Transform a call instruction like `call *x(%rip)` -> `call x(%rip)`.
    BypassGotCall,
}

impl Relaxation {
    /// Tries to create a relaxation for the relocation of the specified kind, to be applied at the
    /// specified offset in the supplied section.
    pub(crate) fn new(relocation_kind: u32, section_bytes: &[u8], offset: usize) -> Option<Self> {
        match relocation_kind {
            rel::R_X86_64_REX_GOTPCRELX => {
                if offset < 3 {
                    return None;
                }
                let b1 = section_bytes[offset - 2];
                if section_bytes[offset - 3] != 0x48 {
                    return None;
                }
                let kind = match b1 {
                    0x8b => Relaxation::BypassGotMov,
                    _ => return None,
                };
                return Some(kind);
            }
            rel::R_X86_64_GOTPCRELX => {
                if offset < 2 {
                    return None;
                }
                let kind = match section_bytes[offset - 2..offset] {
                    [0xff, 0x15] => Relaxation::BypassGotCall,
                    _ => return None,
                };
                return Some(kind);
            }
            _ => {}
        }
        None
    }

    pub(crate) fn new_relocation_kind(&self, value_is_relocatable: bool) -> u32 {
        match self {
            Relaxation::BypassGotMov if value_is_relocatable => rel::R_X86_64_PC32,
            Relaxation::BypassGotMov => rel::R_X86_64_32,
            Relaxation::BypassGotCall => rel::R_X86_64_PC32,
        }
    }

    pub(crate) fn apply(
        &self,
        section_bytes: &mut [u8],
        offset: usize,
        value_is_relocatable: bool,
    ) {
        match self {
            Relaxation::BypassGotMov if value_is_relocatable => {
                // Since the value is relocatable, just transform the mov into an lea.
                section_bytes[offset - 2] = 0x8d;
            }
            Relaxation::BypassGotMov => {
                section_bytes[offset - 2] = 0xc7;
                let mod_rm = &mut section_bytes[offset - 1];
                *mod_rm = (*mod_rm >> 3) & 0x7 | 0xc0;
            }
            Relaxation::BypassGotCall => {
                section_bytes[offset - 2..offset].copy_from_slice(&[0x67, 0xe8]);
            }
        }
    }
}

#[test]
fn test_relaxation() {
    #[track_caller]
    fn check(relocation_kind: u32, bytes_in: &[u8], resolved: &[u8], unresolved: &[u8]) {
        let mut out = bytes_in.to_owned();
        let offset = bytes_in.len();
        if let Some(r) = Relaxation::new(relocation_kind, bytes_in, offset) {
            r.apply(&mut out, offset, true);

            assert_eq!(
                out, resolved,
                "resolved: Expected {resolved:x?}, got {out:x?}"
            );
            out.copy_from_slice(bytes_in);
            r.apply(&mut out, offset, false);
            assert_eq!(
                out, unresolved,
                "unresolved: Expected {unresolved:x?}, got {out:x?}"
            );
        }
    }

    check(
        rel::R_X86_64_REX_GOTPCRELX,
        &[0x48, 0x8b, 0xae],
        &[0x48, 0x8d, 0xae],
        &[0x48, 0xc7, 0xc5],
    );
}
