use crate::archive::ArchiveEntry;
use crate::archive::ArchiveIterator;
use crate::archive::EntryMeta;
use crate::args::Modifiers;
use crate::error::Result;
use crate::file_kind::FileKind;
use crate::input_data::InputData;
use crate::input_data::InputRef;
use crate::input_data::mmap_file;
use memmap2::Mmap;
use rayon::iter::IntoParallelRefIterator;
use rayon::iter::ParallelIterator;
use std::fmt::Display;
use std::path::PathBuf;

pub(crate) enum DataKind<'data> {
    // Data originating from the archive itself,
    // e.g. typical archive contents
    InlineData(&'data [u8]),
    // Data originating from a freshly opened file,
    // e.g. files referenced by thin archive
    NewFileData(Mmap),
}

pub(crate) struct InputBytes<'data> {
    pub(crate) input: InputRef<'data>,
    pub(crate) kind: FileKind,
    pub(crate) data: DataKind<'data>,
    pub(crate) modifiers: Modifiers,
}

#[tracing::instrument(skip_all, name = "Split archives")]
pub fn split_archives<'data>(input_data: &'data InputData) -> Result<Vec<InputBytes<'data>>> {
    let split_output = input_data
        .files
        .par_iter()
        .map(|f| match f.kind {
            FileKind::Archive => {
                let mut extended_filenames = None;
                let mut outputs = Vec::new();
                for entry in ArchiveIterator::from_archive_bytes(f.data())? {
                    let entry = entry?;
                    match entry {
                        ArchiveEntry::Ignored => {}
                        ArchiveEntry::Filenames(t) => extended_filenames = Some(t),
                        ArchiveEntry::Regular(archive_entry) => {
                            let (from, data) = if let Some(entry_data) = archive_entry.entry_data {
                                (archive_entry.data_range().unwrap(), DataKind::InlineData(entry_data))
                            } else {
                                // This is a thin archive entry
                                let fname = archive_entry.parse_as_thin_reference(extended_filenames.unwrap())?;
                                let bytes = mmap_file(&PathBuf::from(fname), false)?;
                                (0..bytes.len(), DataKind::NewFileData(bytes))
                            };
                            outputs.push(InputBytes {
                                kind: f.kind,
                                input: InputRef {
                                    file: f,
                                    entry: Some(EntryMeta {
                                        identifier: archive_entry.identifier(extended_filenames),
                                        from,
                                    }),
                                },
                                data,
                                modifiers: f.modifiers,
                            });
                        },
                    }
                }
                Ok(outputs)
            }
            _ => Ok(vec![InputBytes {
                input: InputRef {
                    file: f,
                    entry: None,
                },
                kind: f.kind,
                data: DataKind::InlineData(f.data()),
                modifiers: f.modifiers,
            }]),
        })
        .collect::<Result<Vec<Vec<InputBytes>>>>()?;
    Ok(split_output.into_iter().flatten().collect())
}

impl Display for InputBytes<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.input, f)
    }
}
