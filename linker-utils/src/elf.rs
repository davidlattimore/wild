use std::borrow::Cow;

macro_rules! const_name_by_value {
    ($needle: expr, $( $const:ident ),*) => {
        match $needle {
            $(object::elf::$const => Some(stringify!($const)),)*
            _ => None
        }
    };
}

pub fn rel_type_to_string(r_type: u32) -> Cow<'static, str> {
    if let Some(name) = const_name_by_value![
        r_type,
        R_X86_64_NONE,
        R_X86_64_64,
        R_X86_64_PC32,
        R_X86_64_GOT32,
        R_X86_64_PLT32,
        R_X86_64_COPY,
        R_X86_64_GLOB_DAT,
        R_X86_64_JUMP_SLOT,
        R_X86_64_RELATIVE,
        R_X86_64_GOTPCREL,
        R_X86_64_32,
        R_X86_64_32S,
        R_X86_64_16,
        R_X86_64_PC16,
        R_X86_64_8,
        R_X86_64_PC8,
        R_X86_64_DTPMOD64,
        R_X86_64_DTPOFF64,
        R_X86_64_TPOFF64,
        R_X86_64_TLSGD,
        R_X86_64_TLSLD,
        R_X86_64_DTPOFF32,
        R_X86_64_GOTTPOFF,
        R_X86_64_TPOFF32,
        R_X86_64_PC64,
        R_X86_64_GOTOFF64,
        R_X86_64_GOTPC32,
        R_X86_64_GOT64,
        R_X86_64_GOTPCREL64,
        R_X86_64_GOTPC64,
        R_X86_64_GOTPLT64,
        R_X86_64_PLTOFF64,
        R_X86_64_SIZE32,
        R_X86_64_SIZE64,
        R_X86_64_GOTPC32_TLSDESC,
        R_X86_64_TLSDESC_CALL,
        R_X86_64_TLSDESC,
        R_X86_64_IRELATIVE,
        R_X86_64_RELATIVE64,
        R_X86_64_GOTPCRELX,
        R_X86_64_REX_GOTPCRELX
    ] {
        Cow::Borrowed(name)
    } else {
        Cow::Owned(format!("Unknown relocation type 0x{r_type:x}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use object::elf::*;

    #[test]
    fn test_rel_type_to_string() {
        assert_eq!(&rel_type_to_string(R_X86_64_32), stringify!(R_X86_64_32));
        assert_eq!(
            &rel_type_to_string(R_X86_64_GOTPC32_TLSDESC),
            stringify!(R_X86_64_GOTPC32_TLSDESC)
        );
        assert_eq!(&rel_type_to_string(64), "Unknown relocation type 0x40");
    }
}
