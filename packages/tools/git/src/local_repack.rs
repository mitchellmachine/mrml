//! Deterministic, non-destructive local reachable-object repacking.

#[cfg(unix)]
use mrml_runtime::{File, Vector, join_path, path_is_file, read_file_bounded};

use crate::{ObjectId, Repository, RepositoryError};
#[cfg(unix)]
use crate::{
    PackObject, build_pack_index_v2, encode_pack_with_format, parse_pack_index_v2,
    parse_pack_with_index,
};

#[cfg(unix)]
const MAX_LOCAL_PACK_BYTES: usize = 1024 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalRepackResult {
    pub pack_checksum: ObjectId,
    pub object_count: usize,
}

#[cfg(unix)]
pub(crate) fn repack(repository: &Repository) -> Result<LocalRepackResult, RepositoryError> {
    let mut tips = Vector::new();
    for (_, id) in repository.branches()? {
        push_unique(&mut tips, id);
    }
    // Tag object IDs, rather than peeled commits, retain annotated tag objects.
    for (_, id) in repository.tags()? {
        push_unique(&mut tips, id);
    }
    if let Some(id) = repository.head()? {
        push_unique(&mut tips, id);
    }
    tips.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));

    let pack = if tips.is_empty() {
        encode_pack_with_format(&[], repository.object_format())?
    } else {
        repository.pack_negotiated(&tips, &[])?
    };
    let (objects, entries) = parse_pack_with_index(&pack, repository.object_format())?;
    let checksum = ObjectId::from_bytes(
        repository.object_format(),
        &pack[pack.len() - repository.object_format().hash_len()..],
    )
    .ok_or(RepositoryError::InvalidReference)?;
    let index = build_pack_index_v2(repository.object_format(), &entries, checksum)
        .map_err(|_| RepositoryError::InvalidReference)?;
    verify_pair(repository, &pack, &index, &objects, checksum)?;

    let pack_root = join_path(&repository.git_dir, "objects/pack");
    let stem = mrml_runtime::mrml_format!("pack-{}", checksum.to_hex());
    let pack_path = join_path(&pack_root, &mrml_runtime::mrml_format!("{stem}.pack"));
    let index_path = join_path(&pack_root, &mrml_runtime::mrml_format!("{stem}.idx"));
    install_exact(&pack_path, &pack)?;
    install_exact(&index_path, &index)?;
    mrml_runtime::sync_directory(&pack_root)?;

    let reopened_pack = read_file_bounded(&pack_path, MAX_LOCAL_PACK_BYTES)?;
    let reopened_index = read_file_bounded(&index_path, MAX_LOCAL_PACK_BYTES)?;
    verify_pair(
        repository,
        &reopened_pack,
        &reopened_index,
        &objects,
        checksum,
    )?;
    Ok(LocalRepackResult {
        pack_checksum: checksum,
        object_count: objects.len(),
    })
}

#[cfg(windows)]
pub(crate) fn repack(_: &Repository) -> Result<LocalRepackResult, RepositoryError> {
    // Directory durability is not yet available from the Windows runtime.
    Err(RepositoryError::UnsupportedLayout)
}

#[cfg(unix)]
fn push_unique(ids: &mut Vector<ObjectId>, id: ObjectId) {
    if !ids.contains(&id) {
        ids.push(id);
    }
}

#[cfg(unix)]
fn install_exact(path: &str, expected: &[u8]) -> Result<(), RepositoryError> {
    if path_is_file(path) {
        return exact_existing(path, expected);
    }
    let mut file = match File::create_new(path) {
        Ok(file) => file,
        Err(_) if path_is_file(path) => return exact_existing(path, expected),
        Err(error) => return Err(error.into()),
    };
    file.write_all(expected)?;
    file.sync()?;
    exact_existing(path, expected)
}

#[cfg(unix)]
fn exact_existing(path: &str, expected: &[u8]) -> Result<(), RepositoryError> {
    let actual = read_file_bounded(path, MAX_LOCAL_PACK_BYTES)?;
    if actual != expected {
        return Err(RepositoryError::InvalidReference);
    }
    File::open(path)?.sync()?;
    Ok(())
}

#[cfg(unix)]
fn verify_pair(
    repository: &Repository,
    pack: &[u8],
    index: &[u8],
    expected: &[PackObject],
    checksum: ObjectId,
) -> Result<(), RepositoryError> {
    let (parsed, entries) = parse_pack_with_index(pack, repository.object_format())?;
    if parsed != expected {
        return Err(RepositoryError::InvalidReference);
    }
    let max_objects = u32::try_from(entries.len()).map_err(|_| RepositoryError::TooManyFiles)?;
    let parsed_index = parse_pack_index_v2(repository.object_format(), index, max_objects)
        .map_err(|_| RepositoryError::InvalidReference)?;
    if parsed_index.pack_checksum() != checksum
        || entries
            .iter()
            .any(|entry| parsed_index.find(entry.id) != Some(entry))
    {
        return Err(RepositoryError::InvalidReference);
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::{ObjectKind, Repository};
    use mrml_runtime::{
        Text, join_path, process_id, remove_dir_all, remove_file, temporary_directory, write_file,
    };

    #[test]
    fn local_repack_is_idempotent_and_reopens_every_reachable_object() {
        let root = join_path(
            &temporary_directory(),
            &mrml_runtime::mrml_format!("mrml-local-repack-{}", process_id()),
        );
        let repository = Repository::init(&root).unwrap();
        write_file(&join_path(&root, "tracked"), b"reachable\n").unwrap();
        repository.stage(&[Text::from("tracked")]).unwrap();
        let commit = repository
            .commit("base", "MRML", "mrml@example.invalid", 1)
            .unwrap();
        let tag_contents = mrml_runtime::mrml_format!(
            "object {commit}\ntype commit\ntag annotated\ntagger MRML <mrml@example.invalid> 1 +0000\n\nretained\n"
        );
        let tag = repository
            .write_object(ObjectKind::Tag, tag_contents.as_bytes())
            .unwrap();
        write_file(
            &join_path(&repository.git_dir, "refs/tags/annotated"),
            mrml_runtime::mrml_format!("{tag}\n").as_bytes(),
        )
        .unwrap();

        let first = repository.repack_local().unwrap();
        let second = repository.repack_local().unwrap();
        assert_eq!(first, second);

        let pack_path = join_path(
            &repository.git_dir,
            &mrml_runtime::mrml_format!("objects/pack/pack-{}.pack", first.pack_checksum.to_hex()),
        );
        let packed = read_file_bounded(&pack_path, MAX_LOCAL_PACK_BYTES).unwrap();
        let objects = crate::parse_pack_with_format(&packed, repository.object_format()).unwrap();
        assert!(objects.iter().any(|object| object.id == tag));
        for object in &objects {
            let hex = object.id.to_hex();
            let loose = join_path(
                &repository.git_dir,
                &mrml_runtime::mrml_format!("objects/{}/{}", &hex[..2], &hex[2..]),
            );
            if path_is_file(&loose) {
                remove_file(&loose).unwrap();
            }
        }
        let reopened = Repository::discover(&root).unwrap();
        for object in objects {
            let read = reopened.read_object(object.id).unwrap();
            assert_eq!(read.kind, object.kind);
            assert_eq!(read.contents, object.contents);
        }
        remove_dir_all(&root).unwrap();
    }
}
