//! PE/COFF linking pipeline.

use crate::args::windows::PeArgs;
use crate::args::Args;
use crate::bail;
use crate::coff::CoffObjectFile;
use crate::error::Result;
use crate::input_data::FileLoader;

pub(crate) fn link_pe<'data>(
    linker: &'data crate::Linker,
    args: &'data Args<PeArgs>,
) -> Result {
    let mut file_loader = FileLoader::new(&linker.inputs_arena);
    let loaded = file_loader.load_inputs::<CoffObjectFile>(&args.inputs, args, &mut None)?;

    let num_objects = loaded.objects.len();
    let mut num_symbols = 0;
    for obj in &loaded.objects {
        if let Ok(obj) = obj {
            num_symbols += obj.num_symbols();
        }
    }

    eprintln!("PE link: {num_objects} COFF objects, {num_symbols} symbols");

    bail!("PE layout and output writing not yet implemented");
}
