use crate::archive::ArchiveEntry;
use crate::archive::ArchiveIterator;
use crate::error::Result;
use crate::file_kind::FileKind;
use crate::input_data::InputData;
use crate::input_data::InputRef;
use rayon::iter::IntoParallelRefIterator;
use rayon::iter::ParallelIterator;
use std::fmt::Display;

pub struct InputBytes<'data> {
    pub(crate) input: InputRef<'data>,
    pub(crate) kind: FileKind,
    pub data: &'data [u8],
}

#[tracing::instrument(skip_all, name = "Split archives")]
pub fn split_archives<'data>(
    input_data: &'data InputData,
) -> Result<Vec<InputBytes<'data>>> {
    let split_output = input_data
        .files
        .par_iter()
        .map(|f| {
            match f.kind {
                FileKind::Archive => {
                    let mut extended_filenames = None;
                    let mut outputs = Vec::new();
                    for entry in ArchiveIterator::from_archive_bytes(f.data())? {
                        let entry = entry?;
                        match entry {
                            ArchiveEntry::Symbols(_) => {
                                // We used to read the symbol table from the archive, but when you're linking
                                // lots of archives and discarding very few, it turns out it's faster to just
                                // ignore the symbol table and eagerly read the objects.
                            }
                            ArchiveEntry::Filenames(t) => extended_filenames = Some(t),
                            ArchiveEntry::Regular(archive_entry) => {
                                outputs.push(InputBytes {
                                    kind: f.kind,
                                    input: InputRef {
                                        file: f,
                                        entry_filename: Some(
                                            archive_entry.identifier(extended_filenames),
                                        ),
                                    },
                                    data: archive_entry.entry_data,
                                });
                            }
                        }
                    }
                    Ok(outputs)
                }
                _ => Ok(vec![InputBytes {
                    input: InputRef {
                        file: f,
                        entry_filename: None,
                    },
                    kind: f.kind,
                    data: f.data(),
                }]),
            }
        })
        .collect::<Result<Vec<Vec<InputBytes>>>>()?;
    Ok(split_output.into_iter().flatten().collect())
}

impl<'data> Display for InputBytes<'data> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.input, f)
    }
}
