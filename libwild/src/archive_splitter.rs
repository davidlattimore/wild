use crate::archive::ArchiveEntry;
use crate::archive::ArchiveIterator;
use crate::archive::EntryMeta;
use crate::args::Modifiers;
use crate::bail;
use crate::error::Context as _;
use crate::error::Result;
use crate::file_kind::FileKind;
use crate::input_data::InputData;
use crate::input_data::InputRef;
use rayon::iter::IntoParallelRefIterator;
use rayon::iter::ParallelIterator;
use std::fmt::Display;

pub(crate) struct InputBytes<'data> {
    pub(crate) input: InputRef<'data>,
    pub(crate) kind: FileKind,
    pub(crate) data: &'data [u8],
    pub(crate) modifiers: Modifiers,
}

#[tracing::instrument(skip_all, name = "Split archives")]
pub fn split_archives<'data>(input_data: &InputData<'data>) -> Result<Vec<InputBytes<'data>>> {
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
                            let archive_and_member_name = || {
                                format!(
                                    "{} @ {}",
                                    f.filename.to_string_lossy(),
                                    archive_entry
                                        .identifier(extended_filenames)
                                        .as_path()
                                        .to_string_lossy()
                                )
                            };
                            let kind = FileKind::identify_bytes(archive_entry.entry_data)
                                .with_context(|| {
                                    format!(
                                        "Failed to parse archive `{}`",
                                        archive_and_member_name()
                                    )
                                })?;
                            if kind != FileKind::ElfObject {
                                bail!(
                                    "Archive member is not an object `{}`",
                                    archive_and_member_name()
                                )
                            }
                            outputs.push(InputBytes {
                                kind,
                                input: InputRef {
                                    file: f,
                                    entry: Some(EntryMeta {
                                        identifier: archive_entry.identifier(extended_filenames),
                                        from: archive_entry.data_range(),
                                    }),
                                },
                                data: archive_entry.entry_data,
                                modifiers: f.modifiers,
                            });
                        }
                        ArchiveEntry::Thin(_) => unreachable!(),
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
                data: f.data(),
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
