use crate::error::Result;
use crate::file_writer::SizedOutput;
use crate::layout::Layout;
use crate::platform::Arch;
use crate::wasm::WASM_MAGIC;
use crate::wasm::WASM_VERSION;
use crate::wasm::Wasm;

pub(crate) fn write<'data, A: Arch<Platform = Wasm>>(
    sized_output: &mut SizedOutput,
    _layout: &Layout<'data, Wasm>,
) -> Result<()> {
    let out: &mut [u8] = &mut sized_output.out;
    let preamble = out
        .get_mut(..8)
        .ok_or_else(|| crate::error!("Wasm output buffer is shorter than the 8-byte preamble"))?;
    preamble[..4].copy_from_slice(&WASM_MAGIC);
    preamble[4..8].copy_from_slice(&WASM_VERSION.to_le_bytes());

    crate::bail!("Wasm section emission is not implemented yet");
}
