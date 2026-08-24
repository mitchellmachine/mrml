use mrml_crypto::Sha3_256;

use crate::{
    AllocationKind, CowMetadataImage, CowPlanError, CowPublicationPlan, DirectoryEntry,
    DirectoryMetadata, MetadataPointer, PreparedAllocationUpdate, StorageAuthorityError,
    StorageAuthorityTable, StorageHandle, StorageName, StorageObjectId, StorageObjectKind,
    StoragePrincipal, StorageRights, StorageTransaction, StorageTransactionId, Superblock,
    TransactionError, TransactionParticipant, TransactionReceipt, VolumeHeader, VolumeId,
};

pub const DIRECTORY_IMAGE_HEADER_BYTES: usize = 96;

const DIRECTORY_IMAGE_MAGIC: [u8; 8] = *b"MRDEI001";
const DIRECTORY_IMAGE_VERSION: u16 = 1;
const DIRECTORY_IMAGE_DIGEST_OFFSET: usize = 64;

pub struct DirectoryAncestryProof<const N: usize> {
    source: StorageObjectId,
    source_generation: u64,
    moved: StorageObjectId,
    moved_generation: u64,
    destination: StorageObjectId,
    destination_generation: u64,
    source_path: DirectoryAncestryPath<N>,
    destination_path: DirectoryAncestryPath<N>,
}

struct DirectoryAncestryPath<const N: usize> {
    nodes: [Option<DirectoryAncestryNode>; N],
    count: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DirectoryAncestryNode {
    object: StorageObjectId,
    generation: u64,
}

impl DirectoryAncestryNode {
    const fn object(self) -> StorageObjectId {
        self.object
    }

    const fn generation(self) -> u64 {
        self.generation
    }
}

impl<const N: usize> DirectoryAncestryProof<N> {
    fn matches<const M: usize>(
        &self,
        source: StorageObjectId,
        source_generation: u64,
        moved: StorageObjectId,
        moved_generation: u64,
        destination: &DirectoryState<M>,
    ) -> bool {
        self.source == source
            && self.source_generation == source_generation
            && self.moved == moved
            && self.moved_generation == moved_generation
            && self.destination == destination.object
            && self.destination_generation == destination.generation
    }

    pub const fn source_path_len(&self) -> usize {
        self.source_path.count
    }

    pub const fn destination_path_len(&self) -> usize {
        self.destination_path.count
    }

    pub const fn source_ancestor(&self, index: usize) -> Option<StorageObjectId> {
        if index < self.source_path.count {
            match self.source_path.nodes[index] {
                Some(node) => Some(node.object()),
                None => None,
            }
        } else {
            None
        }
    }

    pub const fn destination_ancestor(&self, index: usize) -> Option<StorageObjectId> {
        if index < self.destination_path.count {
            match self.destination_path.nodes[index] {
                Some(node) => Some(node.object()),
                None => None,
            }
        } else {
            None
        }
    }

    pub const fn source_ancestor_generation(&self, index: usize) -> Option<u64> {
        if index < self.source_path.count {
            match self.source_path.nodes[index] {
                Some(node) => Some(node.generation()),
                None => None,
            }
        } else {
            None
        }
    }

    pub const fn destination_ancestor_generation(&self, index: usize) -> Option<u64> {
        if index < self.destination_path.count {
            match self.destination_path.nodes[index] {
                Some(node) => Some(node.generation()),
                None => None,
            }
        } else {
            None
        }
    }

    pub fn successor_closure<const M: usize>(
        &self,
    ) -> Result<DirectorySuccessorClosure<M>, DirectoryClosureError> {
        let mut closure = DirectorySuccessorClosure {
            objects: [None; M],
            generations: [0; M],
            depths: [0; M],
            count: 0,
        };
        closure.insert(self.moved, self.moved_generation, usize::MAX)?;
        for index in 0..self.source_path.count {
            let node = self.source_path.nodes[index].ok_or(DirectoryClosureError::InvalidProof)?;
            closure.insert(node.object, node.generation, self.source_path.count - index)?;
        }
        for index in 0..self.destination_path.count {
            let node =
                self.destination_path.nodes[index].ok_or(DirectoryClosureError::InvalidProof)?;
            closure.insert(
                node.object,
                node.generation,
                self.destination_path.count - index,
            )?;
        }
        Ok(closure)
    }

    pub fn construct_move_successors<
        const C: usize,
        const E: usize,
        B: DirectorySuccessorBackend<E>,
    >(
        &self,
        old_name: StorageName,
        new_name: StorageName,
        backend: &mut B,
    ) -> Result<DirectoryMoveSuccessorPlan<C, E>, DirectorySuccessorError<B::Error>> {
        let moved_successor_generation = self
            .moved_generation
            .checked_add(1)
            .ok_or(DirectorySuccessorError::GenerationExhausted)?;
        let closure = self.successor_closure::<C>().map_err(|error| match error {
            DirectoryClosureError::InvalidProof => DirectorySuccessorError::InvalidProof,
            DirectoryClosureError::Capacity => DirectorySuccessorError::Capacity,
        })?;
        let mut successors: [Option<DirectoryMoveSuccessor<E>>; C] = core::array::from_fn(|_| None);
        for (index, slot) in successors.iter_mut().enumerate().take(closure.len()) {
            let object = closure
                .object(index)
                .ok_or(DirectorySuccessorError::InvalidProof)?;
            let predecessor_generation = closure
                .generation(index)
                .ok_or(DirectorySuccessorError::InvalidProof)?;
            let parent = self.parent_of(object)?;
            let predecessor = backend
                .load_directory_state(object, predecessor_generation)
                .map_err(DirectorySuccessorError::Backend)?;
            if predecessor.object != object || predecessor.generation != predecessor_generation {
                return Err(DirectorySuccessorError::InvalidProof);
            }
            let successor_generation = predecessor
                .generation
                .checked_add(1)
                .ok_or(DirectorySuccessorError::GenerationExhausted)?;
            let mut successor = predecessor.clone();
            successor.generation = successor_generation;
            *slot = Some(DirectoryMoveSuccessor {
                predecessor,
                parent,
                state: successor,
            });
        }
        let mut plan = DirectoryMoveSuccessorPlan {
            successors,
            count: closure.len(),
        };
        plan.remove_moved_from_source(self.source, old_name, self.moved, self.moved_generation)?;
        plan.insert_moved_at_destination(
            self.destination,
            new_name,
            self.moved,
            moved_successor_generation,
        )?;
        plan.propagate_parent_links(self.moved)?;
        Ok(plan)
    }

    fn parent_of<E>(
        &self,
        object: StorageObjectId,
    ) -> Result<Option<StorageObjectId>, DirectorySuccessorError<E>> {
        if object == self.moved {
            return Ok(Some(self.destination));
        }
        let mut found = None;
        for path in [&self.source_path, &self.destination_path] {
            for index in 0..path.count {
                if path.nodes[index].is_some_and(|node| node.object == object) {
                    let parent = if index + 1 < path.count {
                        Some(
                            path.nodes[index + 1]
                                .ok_or(DirectorySuccessorError::InvalidProof)?
                                .object,
                        )
                    } else {
                        None
                    };
                    if found.is_some() && found != Some(parent) {
                        return Err(DirectorySuccessorError::InvalidProof);
                    }
                    found = Some(parent);
                }
            }
        }
        found.ok_or(DirectorySuccessorError::InvalidProof)
    }
}

pub struct DirectoryMutationProof<const N: usize> {
    target: StorageObjectId,
    target_generation: u64,
    path: DirectoryAncestryPath<N>,
}

impl<const N: usize> DirectoryMutationProof<N> {
    pub const fn path_len(&self) -> usize {
        self.path.count
    }

    pub const fn ancestor(&self, index: usize) -> Option<StorageObjectId> {
        if index < self.path.count {
            match self.path.nodes[index] {
                Some(node) => Some(node.object),
                None => None,
            }
        } else {
            None
        }
    }

    pub const fn ancestor_generation(&self, index: usize) -> Option<u64> {
        if index < self.path.count {
            match self.path.nodes[index] {
                Some(node) => Some(node.generation),
                None => None,
            }
        } else {
            None
        }
    }

    pub fn construct_create_successors<
        const C: usize,
        const E: usize,
        B: DirectorySuccessorBackend<E>,
    >(
        &self,
        entry: DirectoryEntry,
        backend: &mut B,
    ) -> Result<DirectoryMutationSuccessorPlan<C, E>, DirectorySuccessorError<B::Error>> {
        if self.path.count > C {
            return Err(DirectorySuccessorError::Capacity);
        }
        if entry.object().volume() != self.target.volume() || entry.object() == self.target {
            return Err(DirectorySuccessorError::InvalidProof);
        }
        let mut successors: [Option<DirectoryMoveSuccessor<E>>; C] = core::array::from_fn(|_| None);
        for (index, slot) in successors.iter_mut().enumerate().take(self.path.count) {
            let node = self.path.nodes[index].ok_or(DirectorySuccessorError::InvalidProof)?;
            let predecessor = backend
                .load_directory_state(node.object, node.generation)
                .map_err(DirectorySuccessorError::Backend)?;
            if predecessor.object != node.object || predecessor.generation != node.generation {
                return Err(DirectorySuccessorError::InvalidProof);
            }
            let mut state = predecessor.clone();
            state.generation = state
                .generation
                .checked_add(1)
                .ok_or(DirectorySuccessorError::GenerationExhausted)?;
            let parent = if index + 1 < self.path.count {
                Some(
                    self.path.nodes[index + 1]
                        .ok_or(DirectorySuccessorError::InvalidProof)?
                        .object,
                )
            } else {
                None
            };
            *slot = Some(DirectoryMoveSuccessor {
                predecessor,
                parent,
                state,
            });
        }
        let target = successors[0]
            .as_mut()
            .ok_or(DirectorySuccessorError::InvalidProof)?;
        if target.predecessor.object != self.target
            || target.predecessor.generation != self.target_generation
        {
            return Err(DirectorySuccessorError::InvalidProof);
        }
        if target.state.count == E {
            return Err(DirectorySuccessorError::Capacity);
        }
        if target.state.entries[..target.state.count]
            .iter()
            .flatten()
            .any(|current| current.name() == entry.name() || current.object() == entry.object())
        {
            return Err(DirectorySuccessorError::InvalidProof);
        }
        target.state.entries[target.state.count] = Some(entry);
        target.state.count += 1;

        for index in 0..self.path.count.saturating_sub(1) {
            let child = successors[index]
                .as_ref()
                .ok_or(DirectorySuccessorError::InvalidProof)?;
            let child_object = child.state.object;
            let predecessor_generation = child.predecessor.generation;
            let successor_generation = child.state.generation;
            let parent = successors[index + 1]
                .as_mut()
                .ok_or(DirectorySuccessorError::InvalidProof)?;
            let parent_entry = parent.state.entries[..parent.state.count]
                .iter_mut()
                .flatten()
                .find(|current| current.object() == child_object)
                .ok_or(DirectorySuccessorError::InvalidProof)?;
            if parent_entry.kind() != StorageObjectKind::Directory
                || parent_entry.metadata_generation() != predecessor_generation
            {
                return Err(DirectorySuccessorError::InvalidProof);
            }
            *parent_entry = DirectoryEntry::new(
                parent_entry.name(),
                child_object,
                StorageObjectKind::Directory,
                successor_generation,
            )
            .map_err(|_| DirectorySuccessorError::InvalidProof)?;
        }
        Ok(DirectoryMutationSuccessorPlan {
            successors,
            count: self.path.count,
        })
    }
}

pub struct DirectoryMutationSuccessorPlan<const C: usize, const E: usize> {
    successors: [Option<DirectoryMoveSuccessor<E>>; C],
    count: usize,
}

impl<const C: usize, const E: usize> DirectoryMutationSuccessorPlan<C, E> {
    pub const fn len(&self) -> usize {
        self.count
    }

    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub const fn successor(&self, index: usize) -> Option<&DirectoryMoveSuccessor<E>> {
        if index < self.count {
            self.successors[index].as_ref()
        } else {
            None
        }
    }

    pub fn stage<const S: usize, B: DirectoryWriteBackend>(
        &self,
        header: VolumeHeader,
        layouts: &[DirectorySuccessorLayout; C],
        metadata_outputs: &mut [[u8; crate::DIRECTORY_METADATA_BYTES]; C],
        entries_outputs: &mut [[u8; S]; C],
        backend: &mut B,
    ) -> Result<PreparedDirectoryMovePlan<C, E>, DirectoryMoveStageError<B::Error>> {
        stage_directory_successors(
            &self.successors,
            self.count,
            header,
            layouts,
            metadata_outputs,
            entries_outputs,
            backend,
        )
    }
}

pub struct DirectorySuccessorClosure<const N: usize> {
    objects: [Option<StorageObjectId>; N],
    generations: [u64; N],
    depths: [usize; N],
    count: usize,
}

impl<const N: usize> DirectorySuccessorClosure<N> {
    pub const fn len(&self) -> usize {
        self.count
    }

    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub const fn object(&self, index: usize) -> Option<StorageObjectId> {
        if index < self.count {
            self.objects[index]
        } else {
            None
        }
    }

    pub const fn generation(&self, index: usize) -> Option<u64> {
        if index < self.count {
            Some(self.generations[index])
        } else {
            None
        }
    }

    fn insert(
        &mut self,
        object: StorageObjectId,
        generation: u64,
        depth: usize,
    ) -> Result<(), DirectoryClosureError> {
        if let Some(index) = self.objects[..self.count]
            .iter()
            .position(|entry| *entry == Some(object))
        {
            if generation != self.generations[index] || depth != self.depths[index] {
                return Err(DirectoryClosureError::InvalidProof);
            }
            return Ok(());
        }
        if self.count == N {
            return Err(DirectoryClosureError::Capacity);
        }
        let index = self.depths[..self.count]
            .iter()
            .position(|current| *current < depth)
            .unwrap_or(self.count);
        for slot in (index..self.count).rev() {
            self.objects[slot + 1] = self.objects[slot];
            self.generations[slot + 1] = self.generations[slot];
            self.depths[slot + 1] = self.depths[slot];
        }
        self.objects[index] = Some(object);
        self.generations[index] = generation;
        self.depths[index] = depth;
        self.count += 1;
        Ok(())
    }
}

#[derive(Clone)]
pub struct DirectoryMoveSuccessor<const N: usize> {
    predecessor: DirectoryState<N>,
    parent: Option<StorageObjectId>,
    state: DirectoryState<N>,
}

impl<const N: usize> DirectoryMoveSuccessor<N> {
    pub const fn predecessor_generation(&self) -> u64 {
        self.predecessor.generation
    }

    pub const fn predecessor(&self) -> &DirectoryState<N> {
        &self.predecessor
    }

    pub const fn parent(&self) -> Option<StorageObjectId> {
        self.parent
    }

    pub const fn state(&self) -> &DirectoryState<N> {
        &self.state
    }
}

pub struct DirectoryMoveSuccessorPlan<const C: usize, const E: usize> {
    successors: [Option<DirectoryMoveSuccessor<E>>; C],
    count: usize,
}

impl<const C: usize, const E: usize> DirectoryMoveSuccessorPlan<C, E> {
    pub const fn len(&self) -> usize {
        self.count
    }

    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub const fn successor(&self, index: usize) -> Option<&DirectoryMoveSuccessor<E>> {
        if index < self.count {
            self.successors[index].as_ref()
        } else {
            None
        }
    }

    pub fn stage<const S: usize, B: DirectoryWriteBackend>(
        &self,
        header: VolumeHeader,
        layouts: &[DirectorySuccessorLayout; C],
        metadata_outputs: &mut [[u8; crate::DIRECTORY_METADATA_BYTES]; C],
        entries_outputs: &mut [[u8; S]; C],
        backend: &mut B,
    ) -> Result<PreparedDirectoryMovePlan<C, E>, DirectoryMoveStageError<B::Error>> {
        stage_directory_successors(
            &self.successors,
            self.count,
            header,
            layouts,
            metadata_outputs,
            entries_outputs,
            backend,
        )
    }

    fn find_mut(&mut self, object: StorageObjectId) -> Option<&mut DirectoryMoveSuccessor<E>> {
        self.successors[..self.count]
            .iter_mut()
            .flatten()
            .find(|successor| successor.state.object == object)
    }

    fn remove_moved_from_source<B>(
        &mut self,
        source: StorageObjectId,
        old_name: StorageName,
        moved: StorageObjectId,
        moved_generation: u64,
    ) -> Result<(), DirectorySuccessorError<B>> {
        let source = self
            .find_mut(source)
            .ok_or(DirectorySuccessorError::InvalidProof)?;
        let index = source.state.entries[..source.state.count]
            .iter()
            .position(|entry| {
                entry.is_some_and(|entry| {
                    entry.name() == old_name
                        && entry.object() == moved
                        && entry.kind() == StorageObjectKind::Directory
                        && entry.metadata_generation() == moved_generation
                })
            })
            .ok_or(DirectorySuccessorError::InvalidProof)?;
        source
            .state
            .remove_at(index)
            .map_err(|_| DirectorySuccessorError::InvalidProof)?;
        Ok(())
    }

    fn insert_moved_at_destination<B>(
        &mut self,
        destination: StorageObjectId,
        new_name: StorageName,
        moved: StorageObjectId,
        moved_generation: u64,
    ) -> Result<(), DirectorySuccessorError<B>> {
        let destination = self
            .find_mut(destination)
            .ok_or(DirectorySuccessorError::InvalidProof)?;
        if destination.state.count == E {
            return Err(DirectorySuccessorError::Capacity);
        }
        if destination.state.entries[..destination.state.count]
            .iter()
            .flatten()
            .any(|entry| entry.name() == new_name || entry.object() == moved)
        {
            return Err(DirectorySuccessorError::InvalidProof);
        }
        destination.state.entries[destination.state.count] = Some(
            DirectoryEntry::new(
                new_name,
                moved,
                StorageObjectKind::Directory,
                moved_generation,
            )
            .map_err(|_| DirectorySuccessorError::InvalidProof)?,
        );
        destination.state.count += 1;
        Ok(())
    }

    fn propagate_parent_links<B>(
        &mut self,
        moved: StorageObjectId,
    ) -> Result<(), DirectorySuccessorError<B>> {
        for index in 0..self.count {
            let child = self.successors[index]
                .as_ref()
                .ok_or(DirectorySuccessorError::InvalidProof)?;
            if child.state.object == moved {
                continue;
            }
            let Some(parent_object) = child.parent else {
                continue;
            };
            let child_object = child.state.object;
            let child_predecessor_generation = child.predecessor.generation;
            let child_successor_generation = child.state.generation;
            let parent = self
                .find_mut(parent_object)
                .ok_or(DirectorySuccessorError::InvalidProof)?;
            let entry = parent.state.entries[..parent.state.count]
                .iter_mut()
                .flatten()
                .find(|entry| entry.object() == child_object)
                .ok_or(DirectorySuccessorError::InvalidProof)?;
            if entry.kind() != StorageObjectKind::Directory
                || entry.metadata_generation() != child_predecessor_generation
            {
                return Err(DirectorySuccessorError::InvalidProof);
            }
            *entry = DirectoryEntry::new(
                entry.name(),
                child_object,
                StorageObjectKind::Directory,
                child_successor_generation,
            )
            .map_err(|_| DirectorySuccessorError::InvalidProof)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectorySuccessorLayout {
    metadata: MetadataPointer,
    entries: MetadataPointer,
}

impl DirectorySuccessorLayout {
    pub const fn new(metadata: MetadataPointer, entries: MetadataPointer) -> Self {
        Self { metadata, entries }
    }

    pub const fn metadata(self) -> MetadataPointer {
        self.metadata
    }

    pub const fn entries(self) -> MetadataPointer {
        self.entries
    }
}

#[allow(clippy::too_many_arguments)]
fn stage_directory_successors<
    const C: usize,
    const E: usize,
    const S: usize,
    B: DirectoryWriteBackend,
>(
    successors: &[Option<DirectoryMoveSuccessor<E>>; C],
    count: usize,
    header: VolumeHeader,
    layouts: &[DirectorySuccessorLayout; C],
    metadata_outputs: &mut [[u8; crate::DIRECTORY_METADATA_BYTES]; C],
    entries_outputs: &mut [[u8; S]; C],
    backend: &mut B,
) -> Result<PreparedDirectoryMovePlan<C, E>, DirectoryMoveStageError<B::Error>> {
    if count == 0 || count > C {
        return Err(DirectoryMoveStageError::InvalidPlan);
    }
    for index in 0..count {
        let layout = layouts[index];
        if !metadata_pointer_valid(header, layout.metadata)
            || !metadata_pointer_valid(header, layout.entries)
            || pointers_overlap(layout.metadata, layout.entries)
            || image_bytes(header, layout.entries).ok() != Some(S)
        {
            return Err(DirectoryMoveStageError::InvalidLayout);
        }
        for prior in layouts[..index].iter().copied() {
            if pointers_overlap(prior.metadata, layout.metadata)
                || pointers_overlap(prior.metadata, layout.entries)
                || pointers_overlap(prior.entries, layout.metadata)
                || pointers_overlap(prior.entries, layout.entries)
            {
                return Err(DirectoryMoveStageError::InvalidLayout);
            }
        }
    }

    let mut updates: [Option<PreparedDirectoryUpdate<E>>; C] = core::array::from_fn(|_| None);
    for (index, slot) in updates.iter_mut().enumerate().take(count) {
        let successor = successors[index]
            .as_ref()
            .ok_or(DirectoryMoveStageError::InvalidPlan)?;
        let layout = layouts[index];
        *slot = Some(
            successor
                .predecessor
                .prepare_successor(
                    header,
                    successor.parent,
                    successor.state.clone(),
                    layout.metadata,
                    layout.entries,
                    &mut metadata_outputs[index],
                    &mut entries_outputs[index],
                    backend,
                )
                .map_err(DirectoryMoveStageError::Update)?,
        );
    }
    Ok(PreparedDirectoryMovePlan { updates, count })
}

pub struct PreparedDirectoryMovePlan<const C: usize, const E: usize> {
    updates: [Option<PreparedDirectoryUpdate<E>>; C],
    count: usize,
}

impl<const C: usize, const E: usize> PreparedDirectoryMovePlan<C, E> {
    pub const fn len(&self) -> usize {
        self.count
    }

    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub const fn update(&self, index: usize) -> Option<&PreparedDirectoryUpdate<E>> {
        if index < self.count {
            self.updates[index].as_ref()
        } else {
            None
        }
    }

    pub(crate) fn creation_parent(
        &self,
        child: StorageObjectId,
        kind: StorageObjectKind,
    ) -> Option<StorageObjectId> {
        let mut parent = None;
        for update in self.updates[..self.count].iter().flatten() {
            if update.successor.entries[..update.successor.count]
                .iter()
                .flatten()
                .any(|entry| {
                    entry.object() == child
                        && entry.kind() == kind
                        && entry.metadata_generation() == 1
                })
            {
                if parent.is_some() {
                    return None;
                }
                parent = Some(update.object());
            }
        }
        parent
    }

    pub fn transaction<const P: usize, const W: usize>(
        &self,
        identity: StorageTransactionId,
        publication_generation: u64,
    ) -> Result<StorageTransaction<P, W>, TransactionError> {
        let mut transaction = StorageTransaction::new(identity, publication_generation)?;
        for update in self.updates[..self.count].iter().flatten() {
            transaction.admit_directory(update)?;
        }
        Ok(transaction)
    }

    pub fn transaction_with_allocation<const A: usize, const P: usize, const W: usize>(
        &self,
        allocation: &PreparedAllocationUpdate<A>,
        identity: StorageTransactionId,
        publication_generation: u64,
    ) -> Result<StorageTransaction<P, W>, TransactionError> {
        let mut transaction = StorageTransaction::new(identity, publication_generation)?;
        for update in self.updates[..self.count].iter().flatten() {
            transaction.admit_directory(update)?;
        }
        transaction.admit_allocation(allocation)?;
        Ok(transaction)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn publication_plan<const A: usize, const W: usize>(
        &self,
        allocation: &PreparedAllocationUpdate<A>,
        header: VolumeHeader,
        active_superblock_block: u64,
        active: Superblock,
        root: StorageObjectId,
        protected_active: &[MetadataPointer],
    ) -> Result<CowPublicationPlan<W>, CowPlanError> {
        let publication_generation = active
            .generation()
            .checked_add(1)
            .ok_or(CowPlanError::GenerationExhausted)?;
        if allocation.generation() != publication_generation {
            return Err(CowPlanError::InvalidGeneration);
        }
        if self.count == 0
            || self
                .count
                .checked_mul(2)
                .and_then(|count| count.checked_add(1))
                .is_none_or(|count| count > W)
        {
            return Err(CowPlanError::Capacity);
        }
        let root_metadata = self.updates[..self.count]
            .iter()
            .flatten()
            .find(|update| update.object() == root)
            .ok_or(CowPlanError::MissingPublicationRoot)?
            .metadata_image()
            .pointer();
        for update in self.updates[..self.count].iter().flatten() {
            if !allocation.owns_image(
                update.object(),
                update.generation(),
                update.metadata_image().pointer(),
                AllocationKind::ObjectMetadata,
            ) || !allocation.owns_image(
                update.object(),
                update.generation(),
                update.entries_image().pointer(),
                AllocationKind::DirectoryEntries,
            ) {
                return Err(CowPlanError::InvalidWrite);
            }
        }
        let allocation_write = allocation.metadata_image().bind(publication_generation)?;
        let mut writes = [allocation_write; W];
        let mut count = 0;
        for update in self.updates[..self.count].iter().flatten() {
            for image in update.metadata_images() {
                writes[count] = image.bind(publication_generation)?;
                count += 1;
            }
        }
        writes[count] = allocation_write;
        count += 1;
        CowPublicationPlan::build(
            header,
            active_superblock_block,
            active,
            root,
            root_metadata,
            allocation.pointer(),
            &writes[..count],
            protected_active,
        )
    }

    pub fn commit_transaction<const P: usize>(
        self,
        receipt: &mut TransactionReceipt<P>,
    ) -> Result<CommittedDirectoryMovePlan<C, E>, TransactionError> {
        let mut participants = [None; C];
        for (index, update) in self.updates[..self.count].iter().enumerate() {
            participants[index] = Some(
                update
                    .as_ref()
                    .ok_or(TransactionError::ParticipantMismatch)?
                    .transaction_participant()?,
            );
        }
        receipt.consume_batch(&participants, self.count)?;
        let mut states = core::array::from_fn(|_| None);
        for (index, update) in self.updates.into_iter().take(self.count).enumerate() {
            states[index] = Some(
                update
                    .ok_or(TransactionError::ParticipantMismatch)?
                    .into_successor(),
            );
        }
        Ok(CommittedDirectoryMovePlan {
            states,
            count: self.count,
        })
    }

    pub(crate) fn participants(
        &self,
    ) -> Result<([Option<TransactionParticipant>; C], usize), TransactionError> {
        let mut participants = [None; C];
        for (index, update) in self.updates[..self.count].iter().enumerate() {
            participants[index] = Some(
                update
                    .as_ref()
                    .ok_or(TransactionError::ParticipantMismatch)?
                    .transaction_participant()?,
            );
        }
        Ok((participants, self.count))
    }

    pub(crate) fn into_committed(self) -> CommittedDirectoryMovePlan<C, E> {
        let mut states = core::array::from_fn(|_| None);
        for (index, update) in self.updates.into_iter().take(self.count).enumerate() {
            states[index] = update.map(PreparedDirectoryUpdate::into_successor);
        }
        CommittedDirectoryMovePlan {
            states,
            count: self.count,
        }
    }
}

pub struct CommittedDirectoryMovePlan<const C: usize, const E: usize> {
    states: [Option<DirectoryState<E>>; C],
    count: usize,
}

impl<const C: usize, const E: usize> CommittedDirectoryMovePlan<C, E> {
    pub const fn len(&self) -> usize {
        self.count
    }

    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub const fn state(&self, index: usize) -> Option<&DirectoryState<E>> {
        if index < self.count {
            self.states[index].as_ref()
        } else {
            None
        }
    }
}

/// Immutable selected-generation directory metadata used for ancestry proof.
///
/// # Safety
///
/// Every returned record must be the unique canonical metadata for `object` in
/// one immutable, completely validated selected filesystem generation. The
/// backend must not redirect an object, mix generations, or return mutable or
/// uncommitted metadata.
pub unsafe trait DirectoryAncestryBackend {
    type Error;

    fn load_directory_metadata(
        &mut self,
        object: StorageObjectId,
    ) -> Result<DirectoryMetadata, Self::Error>;
}

/// Immutable selected-generation directory-state backend used to construct a
/// complete directory-move successor plan.
///
/// # Safety
///
/// Every returned state must be the unique canonical, completely validated
/// state for the exact `object` and `generation` in the same immutable selected
/// filesystem generation used by the ancestry proof. Implementations must not
/// redirect objects, mix generations, or return mutable or uncommitted state.
pub unsafe trait DirectorySuccessorBackend<const N: usize> {
    type Error;

    fn load_directory_state(
        &mut self,
        object: StorageObjectId,
        generation: u64,
    ) -> Result<DirectoryState<N>, Self::Error>;
}

#[allow(clippy::too_many_arguments)]
pub fn prove_directory_move_ancestry<const N: usize, B: DirectoryAncestryBackend>(
    root: StorageObjectId,
    source: StorageObjectId,
    source_generation: u64,
    moved: StorageObjectId,
    moved_generation: u64,
    destination: StorageObjectId,
    destination_generation: u64,
    backend: &mut B,
) -> Result<DirectoryAncestryProof<N>, DirectoryAncestryError<B::Error>> {
    if N == 0
        || source == destination
        || root.volume() != source.volume()
        || root.volume() != moved.volume()
        || root.volume() != destination.volume()
        || source_generation == 0
        || moved_generation == 0
        || destination_generation == 0
    {
        return Err(DirectoryAncestryError::InvalidProof);
    }
    let moved_metadata = backend
        .load_directory_metadata(moved)
        .map_err(DirectoryAncestryError::Backend)?;
    if moved_metadata.object() != moved
        || moved_metadata.generation() != moved_generation
        || moved_metadata.parent() != Some(source)
    {
        return Err(DirectoryAncestryError::InvalidProof);
    }
    let source_path =
        load_ancestry_path::<N, B>(root, source, source_generation, Some(moved), backend)?;
    let destination_path = load_ancestry_path::<N, B>(
        root,
        destination,
        destination_generation,
        Some(moved),
        backend,
    )?;
    Ok(DirectoryAncestryProof {
        source,
        source_generation,
        moved,
        moved_generation,
        destination,
        destination_generation,
        source_path,
        destination_path,
    })
}

pub fn prove_directory_mutation_ancestry<const N: usize, B: DirectoryAncestryBackend>(
    root: StorageObjectId,
    target: StorageObjectId,
    target_generation: u64,
    backend: &mut B,
) -> Result<DirectoryMutationProof<N>, DirectoryAncestryError<B::Error>> {
    if N == 0 || root.volume() != target.volume() || target_generation == 0 {
        return Err(DirectoryAncestryError::InvalidProof);
    }
    let path = load_ancestry_path::<N, B>(root, target, target_generation, None, backend)?;
    Ok(DirectoryMutationProof {
        target,
        target_generation,
        path,
    })
}

fn load_ancestry_path<const N: usize, B: DirectoryAncestryBackend>(
    root: StorageObjectId,
    start: StorageObjectId,
    start_generation: u64,
    forbidden: Option<StorageObjectId>,
    backend: &mut B,
) -> Result<DirectoryAncestryPath<N>, DirectoryAncestryError<B::Error>> {
    let mut visited: [Option<DirectoryAncestryNode>; N] = [None; N];
    let mut count = 0;
    let mut current = start;
    loop {
        if forbidden == Some(current)
            || visited[..count]
                .iter()
                .flatten()
                .any(|node| node.object == current)
        {
            return Err(DirectoryAncestryError::Cycle);
        }
        if count == N {
            return Err(DirectoryAncestryError::Capacity);
        }
        let metadata = backend
            .load_directory_metadata(current)
            .map_err(DirectoryAncestryError::Backend)?;
        if metadata.object() != current
            || metadata.object().volume() != root.volume()
            || (current == start && metadata.generation() != start_generation)
        {
            return Err(DirectoryAncestryError::InvalidProof);
        }
        visited[count] = Some(DirectoryAncestryNode {
            object: current,
            generation: metadata.generation(),
        });
        count += 1;
        match metadata.parent() {
            Some(parent) if current != root => current = parent,
            None if current == root => break,
            _ => return Err(DirectoryAncestryError::InvalidProof),
        }
    }
    Ok(DirectoryAncestryPath {
        nodes: visited,
        count,
    })
}

pub struct StorageObjectAllocator {
    volume: VolumeId,
    next_local: Option<u64>,
}

impl StorageObjectAllocator {
    pub const fn new(volume: VolumeId, next_local: u64) -> Result<Self, DirectoryError> {
        if next_local == 0 {
            return Err(DirectoryError::IdentityExhausted);
        }
        Ok(Self {
            volume,
            next_local: Some(next_local),
        })
    }

    pub fn peek(&self) -> Result<StorageObjectId, DirectoryError> {
        StorageObjectId::new(
            self.volume,
            self.next_local.ok_or(DirectoryError::IdentityExhausted)?,
        )
        .map_err(|_| DirectoryError::IdentityExhausted)
    }

    fn consume(&mut self) -> Result<StorageObjectId, DirectoryError> {
        let object = self.peek()?;
        self.next_local = object.local().checked_add(1);
        Ok(object)
    }
}

#[derive(Clone)]
pub struct DirectoryState<const N: usize> {
    object: StorageObjectId,
    generation: u64,
    entries: [Option<DirectoryEntry>; N],
    count: usize,
}

impl<const N: usize> DirectoryState<N> {
    pub fn new(
        object: StorageObjectId,
        generation: u64,
        entries: &[DirectoryEntry],
    ) -> Result<Self, DirectoryError> {
        if entries.len() > N {
            return Err(DirectoryError::InvalidState);
        }
        let mut stored = [None; N];
        for (slot, entry) in stored.iter_mut().zip(entries.iter().copied()) {
            *slot = Some(entry);
        }
        Self::from_stored(object, generation, stored, entries.len())
    }

    fn from_stored(
        object: StorageObjectId,
        generation: u64,
        stored: [Option<DirectoryEntry>; N],
        count: usize,
    ) -> Result<Self, DirectoryError> {
        if generation == 0 || count > N || stored[..count].iter().any(Option::is_none) {
            return Err(DirectoryError::InvalidState);
        }
        for index in 0..count {
            let entry = stored[index].ok_or(DirectoryError::InvalidState)?;
            if entry.object().volume() != object.volume()
                || entry.object() == object
                || stored[..index]
                    .iter()
                    .flatten()
                    .any(|prior| prior.name() == entry.name() || prior.object() == entry.object())
            {
                return Err(DirectoryError::InvalidState);
            }
        }
        Ok(Self {
            object,
            generation,
            entries: stored,
            count,
        })
    }

    pub const fn object(&self) -> StorageObjectId {
        self.object
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn len(&self) -> usize {
        self.count
    }

    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub const fn entry(&self, index: usize) -> Option<DirectoryEntry> {
        if index < self.count {
            self.entries[index]
        } else {
            None
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prepare_successor<B: DirectoryWriteBackend>(
        &self,
        header: VolumeHeader,
        parent: Option<StorageObjectId>,
        successor: DirectoryState<N>,
        metadata_pointer: MetadataPointer,
        entries_pointer: MetadataPointer,
        metadata_output: &mut [u8; crate::DIRECTORY_METADATA_BYTES],
        entries_output: &mut [u8],
        backend: &mut B,
    ) -> Result<PreparedDirectoryUpdate<N>, DirectoryUpdateError<B::Error>> {
        if successor.object != self.object
            || self.generation.checked_add(1) != Some(successor.generation)
            || !metadata_pointer_valid(header, metadata_pointer)
            || !metadata_pointer_valid(header, entries_pointer)
            || pointers_overlap(metadata_pointer, entries_pointer)
        {
            return Err(DirectoryUpdateError::InvalidSuccessor);
        }
        let metadata = successor
            .metadata(header, parent, entries_pointer)
            .map_err(|_| DirectoryUpdateError::InvalidSuccessor)?;
        metadata.encode(metadata_output);
        let entries = DirectoryImage::from_state(header, entries_pointer, successor.clone())
            .map_err(|_| DirectoryUpdateError::InvalidSuccessor)?;
        entries
            .encode(entries_output)
            .map_err(|_| DirectoryUpdateError::InvalidSuccessor)?;
        let metadata_image = CowMetadataImage::new(
            metadata_pointer,
            crate::cow::zero_padded_image_digest(
                header.block_size(),
                metadata_pointer,
                metadata_output,
            )
            .ok_or(DirectoryUpdateError::InvalidSuccessor)?,
        );
        let entries_image = CowMetadataImage::new(entries_pointer, digest(entries_output));
        backend
            .stage_directory_metadata(metadata_image, metadata_output)
            .map_err(DirectoryUpdateError::Backend)?;
        backend
            .stage_directory_entries(entries_image, entries_output)
            .map_err(DirectoryUpdateError::Backend)?;
        backend
            .flush_directory_update()
            .map_err(DirectoryUpdateError::Backend)?;
        Ok(PreparedDirectoryUpdate {
            old_generation: self.generation,
            successor,
            metadata: metadata_image,
            entries: entries_image,
        })
    }

    pub fn metadata(
        &self,
        header: VolumeHeader,
        parent: Option<StorageObjectId>,
        entries: MetadataPointer,
    ) -> Result<DirectoryMetadata, DirectoryError> {
        DirectoryMetadata::new(
            header,
            self.object,
            self.generation,
            parent,
            u32::try_from(self.count).map_err(|_| DirectoryError::Capacity)?,
            entries,
        )
        .map_err(|_| DirectoryError::InvalidState)
    }

    pub fn lookup<const A: usize>(
        &self,
        authority: &StorageAuthorityTable<A>,
        directory: StorageHandle,
        principal: StoragePrincipal,
        name: StorageName,
    ) -> Result<DirectoryEntry, DirectoryError> {
        self.authorize(authority, directory, principal, StorageRights::LOOKUP)?;
        let index = self.find_name(name).ok_or(DirectoryError::NotFound)?;
        self.entries[index].ok_or(DirectoryError::InvalidState)
    }

    /// Opens one named child using explicit authority over this directory.
    ///
    /// The name identifies the child entry. Only the `OPEN_CHILD` capability on
    /// this exact directory authorizes creation of the returned child handle.
    pub fn open_child<const A: usize>(
        &self,
        authority: &mut StorageAuthorityTable<A>,
        directory: StorageHandle,
        principal: StoragePrincipal,
        name: StorageName,
        requested: StorageRights,
    ) -> Result<(DirectoryEntry, StorageHandle), DirectoryError> {
        self.authorize(authority, directory, principal, StorageRights::OPEN_CHILD)?;
        let index = self.find_name(name).ok_or(DirectoryError::NotFound)?;
        let entry = self.entries[index].ok_or(DirectoryError::InvalidState)?;
        let rights = StorageRights::from_bits(entry.kind(), requested.bits())
            .map_err(DirectoryError::Authority)?;
        let handle = authority
            .insert_child_derived(
                directory,
                principal,
                StorageRights::OPEN_CHILD,
                entry.object(),
                entry.kind(),
                rights,
            )
            .map_err(DirectoryError::Authority)?;
        Ok((entry, handle))
    }

    pub fn enumerate<const A: usize>(
        &self,
        authority: &StorageAuthorityTable<A>,
        directory: StorageHandle,
        principal: StoragePrincipal,
        index: usize,
    ) -> Result<DirectoryEntry, DirectoryError> {
        self.authorize(authority, directory, principal, StorageRights::ENUMERATE)?;
        self.entries
            .iter()
            .flatten()
            .nth(index)
            .copied()
            .ok_or(DirectoryError::NotFound)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create<const A: usize>(
        &mut self,
        authority: &mut StorageAuthorityTable<A>,
        directory: StorageHandle,
        principal: StoragePrincipal,
        allocator: &mut StorageObjectAllocator,
        name: StorageName,
        kind: StorageObjectKind,
        initial_rights: StorageRights,
    ) -> Result<(DirectoryEntry, StorageHandle), DirectoryError> {
        let create_right = match kind {
            StorageObjectKind::File => StorageRights::CREATE_FILE,
            StorageObjectKind::Directory => StorageRights::CREATE_DIRECTORY,
            StorageObjectKind::Volume => return Err(DirectoryError::InvalidKind),
        };
        self.authorize(authority, directory, principal, create_right)?;
        let slot = self.preflight_insert(name, allocator.peek()?)?;
        self.next_generation()?;
        StorageRights::from_bits(kind, initial_rights.bits()).map_err(DirectoryError::Authority)?;
        if !authority.has_capacity() {
            return Err(DirectoryError::Authority(StorageAuthorityError::Full));
        }

        let object = allocator.peek()?;
        let entry =
            DirectoryEntry::new(name, object, kind, 1).map_err(|_| DirectoryError::InvalidState)?;
        let child = authority
            .insert_child_derived(
                directory,
                principal,
                create_right,
                object,
                kind,
                initial_rights,
            )
            .map_err(DirectoryError::Authority)?;
        let consumed = allocator.consume()?;
        debug_assert_eq!(consumed, object);
        self.entries[slot] = Some(entry);
        self.count += 1;
        self.generation += 1;
        Ok((entry, child))
    }

    pub fn remove<const A: usize>(
        &mut self,
        authority: &StorageAuthorityTable<A>,
        directory: StorageHandle,
        principal: StoragePrincipal,
        name: StorageName,
    ) -> Result<DirectoryEntry, DirectoryError> {
        self.authorize(authority, directory, principal, StorageRights::REMOVE_CHILD)?;
        let index = self.find_name(name).ok_or(DirectoryError::NotFound)?;
        self.next_generation()?;
        let removed = self.remove_at(index)?;
        self.generation += 1;
        Ok(removed)
    }

    pub fn rename<const A: usize>(
        &mut self,
        authority: &StorageAuthorityTable<A>,
        directory: StorageHandle,
        principal: StoragePrincipal,
        old_name: StorageName,
        new_name: StorageName,
    ) -> Result<DirectoryEntry, DirectoryError> {
        self.authorize(authority, directory, principal, StorageRights::RENAME_CHILD)?;
        let index = self.find_name(old_name).ok_or(DirectoryError::NotFound)?;
        if self.find_name(new_name).is_some() {
            return Err(DirectoryError::AlreadyExists);
        }
        self.next_generation()?;
        let old = self.entries[index].ok_or(DirectoryError::InvalidState)?;
        let renamed = DirectoryEntry::new(
            new_name,
            old.object(),
            old.kind(),
            old.metadata_generation(),
        )
        .map_err(|_| DirectoryError::InvalidState)?;
        self.entries[index] = Some(renamed);
        self.generation += 1;
        Ok(renamed)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn move_to<const M: usize, const A: usize>(
        &mut self,
        source_authority: StorageHandle,
        destination: &mut DirectoryState<M>,
        destination_authority: StorageHandle,
        authority: &StorageAuthorityTable<A>,
        principal: StoragePrincipal,
        old_name: StorageName,
        new_name: StorageName,
    ) -> Result<DirectoryEntry, DirectoryError> {
        self.move_to_inner::<M, A, 1>(
            source_authority,
            destination,
            destination_authority,
            authority,
            principal,
            old_name,
            new_name,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn move_to_with_ancestry<const M: usize, const A: usize, const H: usize>(
        &mut self,
        source_authority: StorageHandle,
        destination: &mut DirectoryState<M>,
        destination_authority: StorageHandle,
        authority: &StorageAuthorityTable<A>,
        principal: StoragePrincipal,
        old_name: StorageName,
        new_name: StorageName,
        ancestry: &DirectoryAncestryProof<H>,
    ) -> Result<DirectoryEntry, DirectoryError> {
        self.move_to_inner(
            source_authority,
            destination,
            destination_authority,
            authority,
            principal,
            old_name,
            new_name,
            Some(ancestry),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn move_to_inner<const M: usize, const A: usize, const H: usize>(
        &mut self,
        source_authority: StorageHandle,
        destination: &mut DirectoryState<M>,
        destination_authority: StorageHandle,
        authority: &StorageAuthorityTable<A>,
        principal: StoragePrincipal,
        old_name: StorageName,
        new_name: StorageName,
        ancestry: Option<&DirectoryAncestryProof<H>>,
    ) -> Result<DirectoryEntry, DirectoryError> {
        if self.object == destination.object {
            return Err(DirectoryError::SameDirectory);
        }
        self.authorize(
            authority,
            source_authority,
            principal,
            StorageRights::RENAME_CHILD,
        )?;
        destination.authorize(
            authority,
            destination_authority,
            principal,
            StorageRights::RENAME_CHILD,
        )?;
        let source_index = self.find_name(old_name).ok_or(DirectoryError::NotFound)?;
        let old = self.entries[source_index].ok_or(DirectoryError::InvalidState)?;
        if old.kind() == StorageObjectKind::Directory
            && !ancestry.is_some_and(|proof| {
                proof.matches(
                    self.object,
                    self.generation,
                    old.object(),
                    old.metadata_generation(),
                    destination,
                )
            })
        {
            return Err(DirectoryError::AncestryRequired);
        }
        let destination_slot = destination.preflight_insert(new_name, old.object())?;
        self.next_generation()?;
        destination.next_generation()?;
        let moved = DirectoryEntry::new(
            new_name,
            old.object(),
            old.kind(),
            old.metadata_generation(),
        )
        .map_err(|_| DirectoryError::InvalidState)?;

        self.remove_at(source_index)?;
        self.generation += 1;
        destination.entries[destination_slot] = Some(moved);
        destination.count += 1;
        destination.generation += 1;
        Ok(moved)
    }

    fn authorize<const A: usize>(
        &self,
        authority: &StorageAuthorityTable<A>,
        handle: StorageHandle,
        principal: StoragePrincipal,
        rights: StorageRights,
    ) -> Result<(), DirectoryError> {
        let object = authority
            .authorize(handle, principal, StorageObjectKind::Directory, rights)
            .map_err(DirectoryError::Authority)?;
        if object != self.object {
            return Err(DirectoryError::WrongDirectory);
        }
        Ok(())
    }

    fn find_name(&self, name: StorageName) -> Option<usize> {
        self.entries
            .iter()
            .position(|entry| entry.is_some_and(|entry| entry.name() == name))
    }

    fn preflight_insert(
        &self,
        name: StorageName,
        object: StorageObjectId,
    ) -> Result<usize, DirectoryError> {
        if object.volume() != self.object.volume() {
            return Err(DirectoryError::WrongVolume);
        }
        if self
            .entries
            .iter()
            .flatten()
            .any(|entry| entry.name() == name || entry.object() == object)
        {
            return Err(DirectoryError::AlreadyExists);
        }
        self.entries
            .iter()
            .position(Option::is_none)
            .ok_or(DirectoryError::Capacity)
    }

    fn next_generation(&self) -> Result<u64, DirectoryError> {
        self.generation
            .checked_add(1)
            .ok_or(DirectoryError::GenerationExhausted)
    }

    fn remove_at(&mut self, index: usize) -> Result<DirectoryEntry, DirectoryError> {
        if index >= self.count {
            return Err(DirectoryError::InvalidState);
        }
        let removed = self.entries[index]
            .take()
            .ok_or(DirectoryError::InvalidState)?;
        for slot in index..self.count - 1 {
            self.entries[slot] = self.entries[slot + 1];
        }
        self.count -= 1;
        self.entries[self.count] = None;
        Ok(removed)
    }
}

pub struct DirectoryImage<const N: usize> {
    volume: VolumeId,
    pointer: MetadataPointer,
    encoded_len: usize,
    state: DirectoryState<N>,
}

pub struct PreparedDirectoryUpdate<const N: usize> {
    old_generation: u64,
    successor: DirectoryState<N>,
    metadata: CowMetadataImage,
    entries: CowMetadataImage,
}

impl<const N: usize> PreparedDirectoryUpdate<N> {
    pub const fn generation(&self) -> u64 {
        self.successor.generation
    }

    pub const fn object(&self) -> StorageObjectId {
        self.successor.object
    }

    pub const fn metadata_image(&self) -> CowMetadataImage {
        self.metadata
    }

    pub const fn entries_image(&self) -> CowMetadataImage {
        self.entries
    }

    pub(crate) fn transaction_participant(
        &self,
    ) -> Result<TransactionParticipant, TransactionError> {
        TransactionParticipant::new(
            self.successor.object,
            StorageObjectKind::Directory,
            self.old_generation,
            self.successor.generation,
        )
    }

    pub(crate) const fn metadata_images(&self) -> [CowMetadataImage; 2] {
        [self.metadata, self.entries]
    }

    pub fn commit_transaction<const P: usize>(
        self,
        receipt: &mut TransactionReceipt<P>,
    ) -> Result<DirectoryState<N>, TransactionError> {
        receipt.consume(self.transaction_participant()?)?;
        Ok(self.successor)
    }

    fn into_successor(self) -> DirectoryState<N> {
        self.successor
    }
}

#[allow(clippy::too_many_arguments)]
pub fn prepare_initial_directory<B: DirectoryWriteBackend>(
    header: VolumeHeader,
    object: StorageObjectId,
    parent: StorageObjectId,
    metadata_pointer: MetadataPointer,
    entries_pointer: MetadataPointer,
    metadata_output: &mut [u8; crate::DIRECTORY_METADATA_BYTES],
    entries_output: &mut [u8],
    backend: &mut B,
) -> Result<PreparedInitialDirectory, DirectoryUpdateError<B::Error>> {
    if object.volume() != header.volume()
        || parent.volume() != header.volume()
        || object == parent
        || !metadata_pointer_valid(header, metadata_pointer)
        || !metadata_pointer_valid(header, entries_pointer)
        || pointers_overlap(metadata_pointer, entries_pointer)
    {
        return Err(DirectoryUpdateError::InvalidSuccessor);
    }
    let state = DirectoryState::<0>::new(object, 1, &[])
        .map_err(|_| DirectoryUpdateError::InvalidSuccessor)?;
    state
        .metadata(header, Some(parent), entries_pointer)
        .map_err(|_| DirectoryUpdateError::InvalidSuccessor)?
        .encode(metadata_output);
    let entries = DirectoryImage::from_state(header, entries_pointer, state.clone())
        .map_err(|_| DirectoryUpdateError::InvalidSuccessor)?;
    entries
        .encode(entries_output)
        .map_err(|_| DirectoryUpdateError::InvalidSuccessor)?;
    let metadata = CowMetadataImage::new(
        metadata_pointer,
        crate::cow::zero_padded_image_digest(
            header.block_size(),
            metadata_pointer,
            metadata_output,
        )
        .ok_or(DirectoryUpdateError::InvalidSuccessor)?,
    );
    let entries = CowMetadataImage::new(entries_pointer, digest(entries_output));
    backend
        .stage_directory_metadata(metadata, metadata_output)
        .map_err(DirectoryUpdateError::Backend)?;
    backend
        .stage_directory_entries(entries, entries_output)
        .map_err(DirectoryUpdateError::Backend)?;
    backend
        .flush_directory_update()
        .map_err(DirectoryUpdateError::Backend)?;
    Ok(PreparedInitialDirectory {
        state,
        parent,
        metadata,
        entries,
    })
}

pub struct PreparedInitialDirectory {
    state: DirectoryState<0>,
    parent: StorageObjectId,
    metadata: CowMetadataImage,
    entries: CowMetadataImage,
}

impl PreparedInitialDirectory {
    pub const fn object(&self) -> StorageObjectId {
        self.state.object
    }

    pub const fn state(&self) -> &DirectoryState<0> {
        &self.state
    }

    pub const fn parent(&self) -> StorageObjectId {
        self.parent
    }

    pub const fn metadata_image(&self) -> CowMetadataImage {
        self.metadata
    }

    pub const fn entries_image(&self) -> CowMetadataImage {
        self.entries
    }

    pub(crate) fn transaction_participant(
        &self,
    ) -> Result<TransactionParticipant, TransactionError> {
        TransactionParticipant::creation(self.state.object, StorageObjectKind::Directory)
    }

    pub(crate) const fn metadata_images(&self) -> [CowMetadataImage; 2] {
        [self.metadata, self.entries]
    }

    pub fn commit_transaction<const P: usize>(
        self,
        receipt: &mut TransactionReceipt<P>,
    ) -> Result<DirectoryState<0>, TransactionError> {
        receipt.consume(self.transaction_participant()?)?;
        Ok(self.state)
    }

    pub(crate) fn into_state(self) -> (DirectoryState<0>, StorageObjectId) {
        (self.state, self.parent)
    }
}

impl<const N: usize> DirectoryImage<N> {
    fn from_state(
        header: VolumeHeader,
        pointer: MetadataPointer,
        state: DirectoryState<N>,
    ) -> Result<Self, DirectoryImageError> {
        if !pointer_fits(header, pointer) || state.object.volume() != header.volume() {
            return Err(DirectoryImageError::InvalidImage);
        }
        let encoded_len = image_bytes(header, pointer)?;
        let used = state
            .len()
            .checked_mul(crate::DIRECTORY_ENTRY_BYTES)
            .and_then(|bytes| bytes.checked_add(DIRECTORY_IMAGE_HEADER_BYTES))
            .ok_or(DirectoryImageError::Arithmetic)?;
        if used > encoded_len {
            return Err(DirectoryImageError::Capacity);
        }
        Ok(Self {
            volume: header.volume(),
            pointer,
            encoded_len,
            state,
        })
    }

    pub fn build(
        header: VolumeHeader,
        object: StorageObjectId,
        generation: u64,
        pointer: MetadataPointer,
        entries: &[DirectoryEntry],
    ) -> Result<Self, DirectoryImageError> {
        if !pointer_fits(header, pointer) {
            return Err(DirectoryImageError::InvalidImage);
        }
        let encoded_len = image_bytes(header, pointer)?;
        let used = entries
            .len()
            .checked_mul(crate::DIRECTORY_ENTRY_BYTES)
            .and_then(|bytes| bytes.checked_add(DIRECTORY_IMAGE_HEADER_BYTES))
            .ok_or(DirectoryImageError::Arithmetic)?;
        if used > encoded_len {
            return Err(DirectoryImageError::Capacity);
        }
        Ok(Self {
            volume: header.volume(),
            pointer,
            encoded_len,
            state: DirectoryState::new(object, generation, entries)
                .map_err(|_| DirectoryImageError::InvalidImage)?,
        })
    }

    pub fn decode(
        header: VolumeHeader,
        object: StorageObjectId,
        generation: u64,
        pointer: MetadataPointer,
        input: &[u8],
    ) -> Result<Self, DirectoryImageError> {
        if !pointer_fits(header, pointer) || input.len() != image_bytes(header, pointer)? {
            return Err(DirectoryImageError::InvalidImage);
        }
        if input[..8] != DIRECTORY_IMAGE_MAGIC
            || get_u16(input, 10)? != DIRECTORY_IMAGE_HEADER_BYTES as u16
            || get_u16(input, 12)? != crate::DIRECTORY_ENTRY_BYTES as u16
            || input[14..16].iter().any(|byte| *byte != 0)
            || input[52..DIRECTORY_IMAGE_DIGEST_OFFSET]
                .iter()
                .any(|byte| *byte != 0)
        {
            return Err(DirectoryImageError::NonCanonical);
        }
        if get_u16(input, 8)? != DIRECTORY_IMAGE_VERSION {
            return Err(DirectoryImageError::UnsupportedVersion);
        }
        if read_volume(input, 16)? != header.volume() {
            return Err(DirectoryImageError::WrongVolume);
        }
        if get_u64(input, 32)? != object.local() || get_u64(input, 40)? != generation {
            return Err(DirectoryImageError::InvalidImage);
        }
        if input[DIRECTORY_IMAGE_DIGEST_OFFSET..DIRECTORY_IMAGE_HEADER_BYTES] != image_digest(input)
        {
            return Err(DirectoryImageError::Corrupt);
        }
        let count =
            usize::try_from(get_u32(input, 48)?).map_err(|_| DirectoryImageError::Capacity)?;
        if count > N {
            return Err(DirectoryImageError::Capacity);
        }
        let used = count
            .checked_mul(crate::DIRECTORY_ENTRY_BYTES)
            .and_then(|bytes| bytes.checked_add(DIRECTORY_IMAGE_HEADER_BYTES))
            .ok_or(DirectoryImageError::Arithmetic)?;
        if used > input.len() || input[used..].iter().any(|byte| *byte != 0) {
            return Err(DirectoryImageError::NonCanonical);
        }
        let mut entries = [None; N];
        for (index, slot) in entries[..count].iter_mut().enumerate() {
            let start = DIRECTORY_IMAGE_HEADER_BYTES + index * crate::DIRECTORY_ENTRY_BYTES;
            *slot = Some(
                DirectoryEntry::decode(
                    &input[start..start + crate::DIRECTORY_ENTRY_BYTES],
                    header.volume(),
                )
                .map_err(|_| DirectoryImageError::InvalidEntry)?,
            );
        }
        Ok(Self {
            volume: header.volume(),
            pointer,
            encoded_len: input.len(),
            state: DirectoryState::from_stored(object, generation, entries, count)
                .map_err(|_| DirectoryImageError::InvalidEntry)?,
        })
    }

    pub const fn pointer(&self) -> MetadataPointer {
        self.pointer
    }

    pub const fn state(&self) -> &DirectoryState<N> {
        &self.state
    }

    pub fn encode(&self, output: &mut [u8]) -> Result<(), DirectoryImageError> {
        if output.len() != self.encoded_len {
            return Err(DirectoryImageError::Truncated);
        }
        output.fill(0);
        output[..8].copy_from_slice(&DIRECTORY_IMAGE_MAGIC);
        put_u16(output, 8, DIRECTORY_IMAGE_VERSION);
        put_u16(output, 10, DIRECTORY_IMAGE_HEADER_BYTES as u16);
        put_u16(output, 12, crate::DIRECTORY_ENTRY_BYTES as u16);
        output[16..32].copy_from_slice(&self.volume.bytes());
        put_u64(output, 32, self.state.object().local());
        put_u64(output, 40, self.state.generation());
        put_u32(output, 48, self.state.len() as u32);
        for index in 0..self.state.len() {
            let start = DIRECTORY_IMAGE_HEADER_BYTES + index * crate::DIRECTORY_ENTRY_BYTES;
            let end = start + crate::DIRECTORY_ENTRY_BYTES;
            let encoded: &mut [u8; crate::DIRECTORY_ENTRY_BYTES] = (&mut output[start..end])
                .try_into()
                .map_err(|_| DirectoryImageError::Truncated)?;
            self.state
                .entry(index)
                .ok_or(DirectoryImageError::InvalidEntry)?
                .encode(encoded);
        }
        let digest = image_digest(output);
        output[DIRECTORY_IMAGE_DIGEST_OFFSET..DIRECTORY_IMAGE_HEADER_BYTES]
            .copy_from_slice(&digest);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectoryImageError {
    Truncated,
    UnsupportedVersion,
    NonCanonical,
    Corrupt,
    WrongVolume,
    InvalidImage,
    InvalidEntry,
    Capacity,
    Arithmetic,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectoryAncestryError<E> {
    InvalidProof,
    Cycle,
    Capacity,
    Backend(E),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectoryClosureError {
    InvalidProof,
    Capacity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectorySuccessorError<E> {
    InvalidProof,
    Capacity,
    GenerationExhausted,
    Backend(E),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectoryMoveStageError<E> {
    InvalidPlan,
    InvalidLayout,
    Update(DirectoryUpdateError<E>),
}

/// Persistence boundary for an unreachable directory metadata successor.
///
/// # Safety
///
/// Implementations must write the fixed directory-metadata record as the exact
/// prefix of its named range, zero every remaining byte in that range, and
/// verify the complete padded range against the supplied digest. They must
/// write and verify the complete entry image at its exact range, keep both
/// ranges unreachable from the active root, and make both images durable before
/// `flush_directory_update` succeeds. They must not redirect, shorten, merge,
/// reorder, or acknowledge stale or partially written images.
pub unsafe trait DirectoryWriteBackend {
    type Error;

    fn stage_directory_metadata(
        &mut self,
        image: CowMetadataImage,
        encoded: &[u8; crate::DIRECTORY_METADATA_BYTES],
    ) -> Result<(), Self::Error>;

    fn stage_directory_entries(
        &mut self,
        image: CowMetadataImage,
        encoded: &[u8],
    ) -> Result<(), Self::Error>;

    fn flush_directory_update(&mut self) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectoryUpdateError<E> {
    InvalidSuccessor,
    Backend(E),
}

fn digest(input: &[u8]) -> [u8; 32] {
    let mut digest = Sha3_256::new();
    digest.update(input);
    digest.finalize()
}

fn image_digest(input: &[u8]) -> [u8; 32] {
    let mut digest = Sha3_256::new();
    digest.update(&input[..DIRECTORY_IMAGE_DIGEST_OFFSET]);
    digest.update(&[0; 32]);
    digest.update(&input[DIRECTORY_IMAGE_HEADER_BYTES..]);
    digest.finalize()
}

fn image_bytes(
    header: VolumeHeader,
    pointer: MetadataPointer,
) -> Result<usize, DirectoryImageError> {
    usize::try_from(
        u64::from(header.block_size())
            .checked_mul(u64::from(pointer.blocks()))
            .ok_or(DirectoryImageError::Arithmetic)?,
    )
    .map_err(|_| DirectoryImageError::Arithmetic)
}

fn pointer_fits(header: VolumeHeader, pointer: MetadataPointer) -> bool {
    pointer
        .block()
        .checked_add(u64::from(pointer.blocks()))
        .is_some_and(|end| end <= header.block_count())
        && !pointer_contains(pointer, 0)
        && !pointer_contains(pointer, header.primary_superblock())
        && !pointer_contains(pointer, header.secondary_superblock())
}

fn metadata_pointer_valid(header: VolumeHeader, pointer: MetadataPointer) -> bool {
    pointer_fits(header, pointer)
}

fn pointers_overlap(left: MetadataPointer, right: MetadataPointer) -> bool {
    left.block() < right.block() + u64::from(right.blocks())
        && right.block() < left.block() + u64::from(left.blocks())
}

fn pointer_contains(pointer: MetadataPointer, block: u64) -> bool {
    block >= pointer.block() && block < pointer.block() + u64::from(pointer.blocks())
}

fn put_u16(output: &mut [u8], offset: usize, value: u16) {
    output[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(output: &mut [u8], offset: usize, value: u32) {
    output[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(output: &mut [u8], offset: usize, value: u64) {
    output[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn get_u16(input: &[u8], offset: usize) -> Result<u16, DirectoryImageError> {
    input
        .get(offset..offset + 2)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or(DirectoryImageError::Truncated)
}

fn get_u32(input: &[u8], offset: usize) -> Result<u32, DirectoryImageError> {
    input
        .get(offset..offset + 4)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(DirectoryImageError::Truncated)
}

fn get_u64(input: &[u8], offset: usize) -> Result<u64, DirectoryImageError> {
    input
        .get(offset..offset + 8)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or(DirectoryImageError::Truncated)
}

fn read_volume(input: &[u8], offset: usize) -> Result<VolumeId, DirectoryImageError> {
    let bytes: [u8; 16] = input
        .get(offset..offset + 16)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(DirectoryImageError::Truncated)?;
    VolumeId::new(bytes).map_err(|_| DirectoryImageError::WrongVolume)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectoryError {
    Authority(StorageAuthorityError),
    InvalidState,
    InvalidKind,
    WrongDirectory,
    WrongVolume,
    NotFound,
    AlreadyExists,
    Capacity,
    GenerationExhausted,
    IdentityExhausted,
    SameDirectory,
    AncestryRequired,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AllocationChange, AllocationImage, AllocationKind, AllocationRecord,
        AllocationWriteBackend, CowMetadataWrite, CowPublicationBackend, CowPublicationPlan,
        StorageTransaction, StorageTransactionId, Superblock,
    };

    fn volume() -> VolumeId {
        VolumeId::new([4; 16]).unwrap()
    }

    fn object(local: u64) -> StorageObjectId {
        StorageObjectId::new(volume(), local).unwrap()
    }

    fn name(value: &str) -> StorageName {
        StorageName::new(value).unwrap()
    }

    fn principal() -> StoragePrincipal {
        StoragePrincipal::new(1).unwrap()
    }

    fn directory_rights() -> StorageRights {
        StorageRights::LOOKUP
            .union(StorageRights::ENUMERATE)
            .union(StorageRights::CREATE_FILE)
            .union(StorageRights::CREATE_DIRECTORY)
            .union(StorageRights::RENAME_CHILD)
            .union(StorageRights::REMOVE_CHILD)
            .union(StorageRights::OPEN_CHILD)
    }

    struct UpdateBackend {
        staged: usize,
        flushed: bool,
        verified: usize,
    }

    struct AncestryBackend {
        records: [Option<DirectoryMetadata>; 5],
    }

    struct SuccessorBackend<const N: usize> {
        records: [Option<DirectoryState<N>>; 5],
    }

    unsafe impl DirectoryAncestryBackend for AncestryBackend {
        type Error = ();

        fn load_directory_metadata(
            &mut self,
            object: StorageObjectId,
        ) -> Result<DirectoryMetadata, Self::Error> {
            self.records
                .iter()
                .flatten()
                .copied()
                .find(|metadata| metadata.object() == object)
                .ok_or(())
        }
    }

    unsafe impl<const N: usize> DirectorySuccessorBackend<N> for SuccessorBackend<N> {
        type Error = ();

        fn load_directory_state(
            &mut self,
            object: StorageObjectId,
            _generation: u64,
        ) -> Result<DirectoryState<N>, Self::Error> {
            self.records
                .iter()
                .flatten()
                .find(|state| state.object() == object)
                .cloned()
                .ok_or(())
        }
    }

    fn directory_metadata(
        object: StorageObjectId,
        generation: u64,
        parent: Option<StorageObjectId>,
    ) -> DirectoryMetadata {
        DirectoryMetadata::new(
            VolumeHeader::new(volume(), 4096, 100, 1, 2).unwrap(),
            object,
            generation,
            parent,
            0,
            MetadataPointer::new(30 + object.local(), 1).unwrap(),
        )
        .unwrap()
    }

    unsafe impl DirectoryWriteBackend for UpdateBackend {
        type Error = ();

        fn stage_directory_metadata(
            &mut self,
            _image: CowMetadataImage,
            _encoded: &[u8; crate::DIRECTORY_METADATA_BYTES],
        ) -> Result<(), Self::Error> {
            self.staged += 1;
            Ok(())
        }

        fn stage_directory_entries(
            &mut self,
            _image: CowMetadataImage,
            _encoded: &[u8],
        ) -> Result<(), Self::Error> {
            self.staged += 1;
            Ok(())
        }

        fn flush_directory_update(&mut self) -> Result<(), Self::Error> {
            self.flushed = true;
            Ok(())
        }
    }

    unsafe impl AllocationWriteBackend for UpdateBackend {
        type Error = ();

        fn stage_allocation_image(
            &mut self,
            _image: CowMetadataImage,
            _encoded: &[u8],
        ) -> Result<(), Self::Error> {
            self.staged += 1;
            Ok(())
        }

        fn flush_allocation_image(&mut self) -> Result<(), Self::Error> {
            self.flushed = true;
            Ok(())
        }
    }

    unsafe impl CowPublicationBackend for UpdateBackend {
        type Error = ();

        fn verify_new_metadata(&mut self, _write: CowMetadataWrite) -> Result<(), Self::Error> {
            self.verified += 1;
            Ok(())
        }

        fn flush_new_metadata(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }

        fn replace_superblock(
            &mut self,
            block: u64,
            _encoded: &[u8; crate::SUPERBLOCK_BYTES],
        ) -> Result<(), Self::Error> {
            assert_eq!(block, 2);
            Ok(())
        }

        fn flush_superblock(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[test]
    fn directory_successor_is_staged_and_activated_by_one_use_receipt() {
        let header = VolumeHeader::new(volume(), 4096, 100, 1, 2).unwrap();
        let active = DirectoryState::<2>::new(object(1), 1, &[]).unwrap();
        let entry =
            DirectoryEntry::new(name("file"), object(2), StorageObjectKind::File, 1).unwrap();
        let successor = DirectoryState::<2>::new(object(1), 2, &[entry]).unwrap();
        let metadata_pointer = MetadataPointer::new(60, 1).unwrap();
        let entries_pointer = MetadataPointer::new(61, 1).unwrap();
        let mut metadata = [0; crate::DIRECTORY_METADATA_BYTES];
        let mut entries = [0; 4096];
        let mut backend = UpdateBackend {
            staged: 0,
            flushed: false,
            verified: 0,
        };
        let prepared = active
            .prepare_successor(
                header,
                None,
                successor,
                metadata_pointer,
                entries_pointer,
                &mut metadata,
                &mut entries,
                &mut backend,
            )
            .unwrap();
        assert_eq!((backend.staged, backend.flushed), (2, true));

        let mut transaction =
            StorageTransaction::<1, 2>::new(StorageTransactionId::new(30).unwrap(), 6).unwrap();
        transaction.admit_directory(&prepared).unwrap();
        let active_root = Superblock::new(
            header,
            5,
            4,
            object(1),
            MetadataPointer::new(10, 1).unwrap(),
            MetadataPointer::new(20, 1).unwrap(),
        )
        .unwrap();
        let allocation =
            CowMetadataWrite::new(MetadataPointer::new(50, 1).unwrap(), 6, [9; 32]).unwrap();
        let plan = CowPublicationPlan::<3>::build(
            header,
            1,
            active_root,
            object(1),
            metadata_pointer,
            allocation.pointer(),
            &[
                prepared.metadata_image().bind(6).unwrap(),
                prepared.entries_image().bind(6).unwrap(),
                allocation,
            ],
            &[
                MetadataPointer::new(10, 1).unwrap(),
                MetadataPointer::new(11, 1).unwrap(),
                MetadataPointer::new(20, 1).unwrap(),
            ],
        )
        .unwrap();
        let mut receipt = transaction.publish(&plan, &mut backend).unwrap();
        let committed = prepared.commit_transaction(&mut receipt).unwrap();
        assert_eq!(committed.generation(), 2);
        assert_eq!(committed.entry(0), Some(entry));
        assert_eq!(receipt.remaining(), 0);
        assert_eq!(backend.verified, 3);
    }

    #[test]
    fn initial_empty_directory_stages_canonical_creation_images() {
        let header = VolumeHeader::new(volume(), 4096, 100, 1, 2).unwrap();
        let metadata_pointer = MetadataPointer::new(60, 1).unwrap();
        let entries_pointer = MetadataPointer::new(61, 1).unwrap();
        let mut metadata = [0; crate::DIRECTORY_METADATA_BYTES];
        let mut entries = [0; 4096];
        let mut backend = UpdateBackend {
            staged: 0,
            flushed: false,
            verified: 0,
        };
        let prepared = prepare_initial_directory(
            header,
            object(8),
            object(1),
            metadata_pointer,
            entries_pointer,
            &mut metadata,
            &mut entries,
            &mut backend,
        )
        .unwrap();
        assert_eq!(
            (prepared.object(), prepared.state().generation()),
            (object(8), 1)
        );
        assert!(prepared.state().is_empty());
        let mut complete_metadata = [0; 4096];
        complete_metadata[..crate::DIRECTORY_METADATA_BYTES].copy_from_slice(&metadata);
        assert_eq!(
            prepared.metadata_image().digest(),
            digest(&complete_metadata)
        );
        assert_ne!(prepared.metadata_image().digest(), digest(&metadata));
        assert_eq!((backend.staged, backend.flushed), (2, true));
        let decoded_metadata = DirectoryMetadata::decode(&metadata, header).unwrap();
        assert_eq!(decoded_metadata.parent(), Some(object(1)));
        assert!(
            DirectoryImage::<0>::decode(header, object(8), 1, entries_pointer, &entries)
                .unwrap()
                .state()
                .is_empty()
        );
        let mut transaction =
            StorageTransaction::<1, 2>::new(StorageTransactionId::new(41).unwrap(), 2).unwrap();
        transaction.admit_initial_directory(&prepared).unwrap();
        assert_eq!(transaction.participant_count(), 1);

        let mut rejected = UpdateBackend {
            staged: 0,
            flushed: false,
            verified: 0,
        };
        assert!(matches!(
            prepare_initial_directory(
                header,
                object(8),
                object(1),
                metadata_pointer,
                metadata_pointer,
                &mut metadata,
                &mut entries,
                &mut rejected,
            ),
            Err(DirectoryUpdateError::InvalidSuccessor)
        ));
        assert_eq!(rejected.staged, 0);
    }

    #[test]
    fn create_successor_closure_propagates_exact_generations_to_root() {
        let mut ancestry = AncestryBackend {
            records: [
                Some(directory_metadata(object(3), 1, Some(object(4)))),
                Some(directory_metadata(object(4), 3, Some(object(1)))),
                Some(directory_metadata(object(1), 5, None)),
                None,
                None,
            ],
        };
        let proof =
            prove_directory_mutation_ancestry::<3, _>(object(1), object(3), 1, &mut ancestry)
                .unwrap();
        assert_eq!(proof.path_len(), 3);
        assert_eq!(proof.ancestor(0), Some(object(3)));
        assert_eq!(proof.ancestor_generation(1), Some(3));
        assert_eq!(proof.ancestor(3), None);

        let retained =
            DirectoryEntry::new(name("retained"), object(8), StorageObjectKind::File, 2).unwrap();
        let target = DirectoryState::<3>::new(object(3), 1, &[retained]).unwrap();
        let target_entry =
            DirectoryEntry::new(name("target"), object(3), StorageObjectKind::Directory, 1)
                .unwrap();
        let common = DirectoryState::<3>::new(object(4), 3, &[target_entry]).unwrap();
        let common_entry =
            DirectoryEntry::new(name("common"), object(4), StorageObjectKind::Directory, 3)
                .unwrap();
        let root = DirectoryState::<3>::new(object(1), 5, &[common_entry]).unwrap();
        let mut backend = SuccessorBackend {
            records: [
                Some(target.clone()),
                Some(common.clone()),
                Some(root.clone()),
                None,
                None,
            ],
        };
        let created =
            DirectoryEntry::new(name("created"), object(9), StorageObjectKind::File, 1).unwrap();
        let plan = proof
            .construct_create_successors::<3, 3, _>(created, &mut backend)
            .unwrap();
        assert_eq!(plan.len(), 3);
        let target_successor = plan.successor(0).unwrap();
        assert_eq!(target_successor.parent(), Some(object(4)));
        assert_eq!(target_successor.state().generation(), 2);
        assert_eq!(target_successor.state().entry(0), Some(retained));
        assert_eq!(target_successor.state().entry(1), Some(created));
        let common_successor = plan.successor(1).unwrap();
        assert_eq!(common_successor.state().generation(), 4);
        assert_eq!(
            common_successor
                .state()
                .entry(0)
                .unwrap()
                .metadata_generation(),
            2
        );
        let root_successor = plan.successor(2).unwrap();
        assert_eq!(root_successor.parent(), None);
        assert_eq!(root_successor.state().generation(), 6);
        assert_eq!(
            root_successor
                .state()
                .entry(0)
                .unwrap()
                .metadata_generation(),
            4
        );
        assert!(plan.successor(3).is_none());

        let header = VolumeHeader::new(volume(), 4096, 100, 1, 2).unwrap();
        let layouts = [
            DirectorySuccessorLayout::new(
                MetadataPointer::new(60, 1).unwrap(),
                MetadataPointer::new(61, 1).unwrap(),
            ),
            DirectorySuccessorLayout::new(
                MetadataPointer::new(62, 1).unwrap(),
                MetadataPointer::new(63, 1).unwrap(),
            ),
            DirectorySuccessorLayout::new(
                MetadataPointer::new(64, 1).unwrap(),
                MetadataPointer::new(65, 1).unwrap(),
            ),
        ];
        let mut metadata_outputs = [[0; crate::DIRECTORY_METADATA_BYTES]; 3];
        let mut entries_outputs = [[0; 4096]; 3];
        let mut update_backend = UpdateBackend {
            staged: 0,
            flushed: false,
            verified: 0,
        };
        let prepared = plan
            .stage(
                header,
                &layouts,
                &mut metadata_outputs,
                &mut entries_outputs,
                &mut update_backend,
            )
            .unwrap();
        assert_eq!((prepared.len(), update_backend.staged), (3, 6));
        let transaction = prepared
            .transaction::<3, 6>(StorageTransactionId::new(42).unwrap(), 6)
            .unwrap();
        assert_eq!(transaction.participant_count(), 3);

        assert!(matches!(
            proof.construct_create_successors::<2, 3, _>(created, &mut backend),
            Err(DirectorySuccessorError::Capacity)
        ));
        let mut stale = SuccessorBackend {
            records: [
                Some(target),
                Some(DirectoryState::<3>::new(object(4), 4, &[target_entry]).unwrap()),
                Some(root),
                None,
                None,
            ],
        };
        assert!(matches!(
            proof.construct_create_successors::<3, 3, _>(created, &mut stale),
            Err(DirectorySuccessorError::InvalidProof)
        ));
    }

    #[test]
    fn create_returns_object_bound_authority_and_supports_lookup() {
        let mut authority = StorageAuthorityTable::<4>::new();
        let root = authority
            .insert(
                object(1),
                StorageObjectKind::Directory,
                directory_rights(),
                principal(),
            )
            .unwrap();
        let mut allocator = StorageObjectAllocator::new(volume(), 10).unwrap();
        let mut directory = DirectoryState::<2>::new(object(1), 1, &[]).unwrap();
        let (entry, child) = directory
            .create(
                &mut authority,
                root,
                principal(),
                &mut allocator,
                name("file"),
                StorageObjectKind::File,
                StorageRights::READ.union(StorageRights::WRITE),
            )
            .unwrap();
        assert_eq!(entry.object(), object(10));
        assert_eq!(directory.generation(), 2);
        assert_eq!(
            directory.lookup(&authority, root, principal(), name("file")),
            Ok(entry)
        );
        assert_eq!(
            directory.enumerate(&authority, root, principal(), 0),
            Ok(entry)
        );
        assert_eq!(
            authority.authorize(
                child,
                principal(),
                StorageObjectKind::File,
                StorageRights::WRITE
            ),
            Ok(object(10))
        );
        let (opened_entry, opened) = directory
            .open_child(
                &mut authority,
                root,
                principal(),
                name("file"),
                StorageRights::READ,
            )
            .unwrap();
        assert_eq!(opened_entry, entry);
        assert_eq!(
            authority.authorize(
                opened,
                principal(),
                StorageObjectKind::File,
                StorageRights::READ,
            ),
            Ok(object(10))
        );
        let lookup_only = authority
            .insert(
                object(1),
                StorageObjectKind::Directory,
                StorageRights::LOOKUP,
                principal(),
            )
            .unwrap();
        assert!(matches!(
            directory.open_child(
                &mut authority,
                lookup_only,
                principal(),
                name("file"),
                StorageRights::READ,
            ),
            Err(DirectoryError::Authority(StorageAuthorityError::Denied))
        ));
        assert_eq!(authority.revoke(root, principal()), Ok(3));
        assert_eq!(
            authority.authorize(
                child,
                principal(),
                StorageObjectKind::File,
                StorageRights::READ,
            ),
            Err(StorageAuthorityError::InvalidHandle)
        );
        assert_eq!(
            authority.authorize(
                opened,
                principal(),
                StorageObjectKind::File,
                StorageRights::READ,
            ),
            Err(StorageAuthorityError::InvalidHandle)
        );
    }

    #[test]
    fn denied_or_full_create_changes_neither_directory_nor_allocator() {
        let mut authority = StorageAuthorityTable::<2>::new();
        let lookup_only = authority
            .insert(
                object(1),
                StorageObjectKind::Directory,
                StorageRights::LOOKUP,
                principal(),
            )
            .unwrap();
        let mut allocator = StorageObjectAllocator::new(volume(), 10).unwrap();
        let mut directory = DirectoryState::<1>::new(object(1), 1, &[]).unwrap();
        assert!(matches!(
            directory.create(
                &mut authority,
                lookup_only,
                principal(),
                &mut allocator,
                name("denied"),
                StorageObjectKind::File,
                StorageRights::READ
            ),
            Err(DirectoryError::Authority(_))
        ));
        assert_eq!(directory.generation(), 1);
        assert_eq!(allocator.peek(), Ok(object(10)));
        let root = authority
            .insert(
                object(2),
                StorageObjectKind::Directory,
                StorageRights::CREATE_FILE,
                principal(),
            )
            .unwrap();
        let mut other = DirectoryState::<1>::new(object(2), 1, &[]).unwrap();
        assert!(matches!(
            other.create(
                &mut authority,
                root,
                principal(),
                &mut allocator,
                name("full"),
                StorageObjectKind::File,
                StorageRights::READ
            ),
            Err(DirectoryError::Authority(StorageAuthorityError::Full))
        ));
        assert_eq!(allocator.peek(), Ok(object(10)));
    }

    #[test]
    fn duplicate_state_and_generation_exhaustion_fail_without_mutation() {
        let first =
            DirectoryEntry::new(name("same"), object(8), StorageObjectKind::File, 1).unwrap();
        let duplicate_name =
            DirectoryEntry::new(name("same"), object(9), StorageObjectKind::File, 1).unwrap();
        assert!(matches!(
            DirectoryState::<2>::new(object(1), 1, &[first, duplicate_name]),
            Err(DirectoryError::InvalidState)
        ));
        let self_entry =
            DirectoryEntry::new(name("self"), object(1), StorageObjectKind::Directory, 1).unwrap();
        assert!(matches!(
            DirectoryState::<1>::new(object(1), 1, &[self_entry]),
            Err(DirectoryError::InvalidState)
        ));
        let mut directory = DirectoryState::<2>::new(object(1), u64::MAX, &[first]).unwrap();
        let mut authority = StorageAuthorityTable::<1>::new();
        let rename = authority
            .insert(
                object(1),
                StorageObjectKind::Directory,
                StorageRights::RENAME_CHILD,
                principal(),
            )
            .unwrap();
        assert_eq!(
            directory.rename(&authority, rename, principal(), name("same"), name("new")),
            Err(DirectoryError::GenerationExhausted)
        );
        assert_eq!((directory.len(), directory.generation()), (1, u64::MAX));
    }

    #[test]
    fn identity_allocator_issues_maximum_identity_once_then_exhausts() {
        let mut allocator = StorageObjectAllocator::new(volume(), u64::MAX).unwrap();
        assert_eq!(allocator.peek(), Ok(object(u64::MAX)));
        assert_eq!(allocator.consume(), Ok(object(u64::MAX)));
        assert_eq!(allocator.peek(), Err(DirectoryError::IdentityExhausted));
        assert_eq!(allocator.consume(), Err(DirectoryError::IdentityExhausted));
    }

    #[test]
    fn rename_preserves_identity_and_existing_object_capability() {
        let entry =
            DirectoryEntry::new(name("old"), object(9), StorageObjectKind::File, 3).unwrap();
        let mut directory = DirectoryState::<2>::new(object(1), 4, &[entry]).unwrap();
        let mut authority = StorageAuthorityTable::<2>::new();
        let root = authority
            .insert(
                object(1),
                StorageObjectKind::Directory,
                StorageRights::RENAME_CHILD,
                principal(),
            )
            .unwrap();
        let open = authority
            .insert(
                object(9),
                StorageObjectKind::File,
                StorageRights::READ,
                principal(),
            )
            .unwrap();
        let renamed = directory
            .rename(&authority, root, principal(), name("old"), name("new"))
            .unwrap();
        assert_eq!(renamed.object(), entry.object());
        assert_eq!(renamed.metadata_generation(), 3);
        assert_eq!(
            authority.authorize(
                open,
                principal(),
                StorageObjectKind::File,
                StorageRights::READ
            ),
            Ok(object(9))
        );
    }

    #[test]
    fn cross_directory_move_preflights_destination_before_mutation() {
        let entry =
            DirectoryEntry::new(name("old"), object(9), StorageObjectKind::File, 3).unwrap();
        let occupied =
            DirectoryEntry::new(name("occupied"), object(8), StorageObjectKind::File, 1).unwrap();
        let mut source = DirectoryState::<1>::new(object(1), 4, &[entry]).unwrap();
        let mut destination = DirectoryState::<1>::new(object(2), 7, &[occupied]).unwrap();
        let mut authority = StorageAuthorityTable::<2>::new();
        let source_handle = authority
            .insert(
                object(1),
                StorageObjectKind::Directory,
                StorageRights::RENAME_CHILD,
                principal(),
            )
            .unwrap();
        let destination_handle = authority
            .insert(
                object(2),
                StorageObjectKind::Directory,
                StorageRights::RENAME_CHILD,
                principal(),
            )
            .unwrap();
        assert_eq!(
            source.move_to(
                source_handle,
                &mut destination,
                destination_handle,
                &authority,
                principal(),
                name("old"),
                name("new")
            ),
            Err(DirectoryError::Capacity)
        );
        assert_eq!((source.len(), source.generation()), (1, 4));
        assert_eq!((destination.len(), destination.generation()), (1, 7));
        let mut empty = DirectoryState::<1>::new(object(3), 1, &[]).unwrap();
        // A distinct destination requires its own exact authority.
        let mut authority = StorageAuthorityTable::<3>::new();
        let source_handle = authority
            .insert(
                object(1),
                StorageObjectKind::Directory,
                StorageRights::RENAME_CHILD,
                principal(),
            )
            .unwrap();
        let empty_authority = authority
            .insert(
                object(3),
                StorageObjectKind::Directory,
                StorageRights::RENAME_CHILD,
                principal(),
            )
            .unwrap();
        let moved = source
            .move_to(
                source_handle,
                &mut empty,
                empty_authority,
                &authority,
                principal(),
                name("old"),
                name("new"),
            )
            .unwrap();
        assert_eq!(moved.object(), object(9));
        assert_eq!((source.len(), source.generation()), (0, 5));
        assert_eq!((empty.len(), empty.generation()), (1, 2));
    }

    #[test]
    fn remove_requires_right_and_does_not_revoke_open_object_authority() {
        let entry =
            DirectoryEntry::new(name("file"), object(9), StorageObjectKind::File, 1).unwrap();
        let mut directory = DirectoryState::<1>::new(object(1), 1, &[entry]).unwrap();
        let mut authority = StorageAuthorityTable::<3>::new();
        let denied = authority
            .insert(
                object(1),
                StorageObjectKind::Directory,
                StorageRights::LOOKUP,
                principal(),
            )
            .unwrap();
        let remove = authority
            .insert(
                object(1),
                StorageObjectKind::Directory,
                StorageRights::REMOVE_CHILD,
                principal(),
            )
            .unwrap();
        let open = authority
            .insert(
                object(9),
                StorageObjectKind::File,
                StorageRights::READ,
                principal(),
            )
            .unwrap();
        assert!(
            directory
                .remove(&authority, denied, principal(), name("file"))
                .is_err()
        );
        assert_eq!(
            directory.remove(&authority, remove, principal(), name("file")),
            Ok(entry)
        );
        assert_eq!(
            authority.authorize(
                open,
                principal(),
                StorageObjectKind::File,
                StorageRights::READ
            ),
            Ok(object(9))
        );
    }

    #[test]
    fn directory_move_requires_exact_bounded_ancestry_proof() {
        let child =
            DirectoryEntry::new(name("child"), object(9), StorageObjectKind::Directory, 1).unwrap();
        let mut source = DirectoryState::<1>::new(object(3), 1, &[child]).unwrap();
        let mut destination = DirectoryState::<1>::new(object(2), 1, &[]).unwrap();
        let mut authority = StorageAuthorityTable::<2>::new();
        let source_handle = authority
            .insert(
                object(3),
                StorageObjectKind::Directory,
                StorageRights::RENAME_CHILD,
                principal(),
            )
            .unwrap();
        let destination_handle = authority
            .insert(
                object(2),
                StorageObjectKind::Directory,
                StorageRights::RENAME_CHILD,
                principal(),
            )
            .unwrap();
        assert_eq!(
            source.move_to(
                source_handle,
                &mut destination,
                destination_handle,
                &authority,
                principal(),
                name("child"),
                name("moved"),
            ),
            Err(DirectoryError::AncestryRequired)
        );
        assert_eq!((source.len(), source.generation()), (1, 1));
        assert_eq!((destination.len(), destination.generation()), (0, 1));

        let mut backend = AncestryBackend {
            records: [
                Some(directory_metadata(object(9), 1, Some(object(3)))),
                Some(directory_metadata(object(2), 1, Some(object(1)))),
                Some(directory_metadata(object(3), 1, Some(object(1)))),
                Some(directory_metadata(object(1), 5, None)),
                None,
            ],
        };
        let proof = prove_directory_move_ancestry::<2, _>(
            object(1),
            object(3),
            1,
            object(9),
            1,
            object(2),
            1,
            &mut backend,
        )
        .unwrap();
        assert_eq!(proof.source_path_len(), 2);
        assert_eq!(proof.source_ancestor(0), Some(object(3)));
        assert_eq!(proof.source_ancestor(1), Some(object(1)));
        assert_eq!(proof.source_ancestor(2), None);
        assert_eq!(proof.source_ancestor_generation(0), Some(1));
        assert_eq!(proof.source_ancestor_generation(1), Some(5));
        assert_eq!(proof.source_ancestor_generation(2), None);
        assert_eq!(proof.destination_path_len(), 2);
        assert_eq!(proof.destination_ancestor(0), Some(object(2)));
        assert_eq!(proof.destination_ancestor(1), Some(object(1)));
        assert_eq!(proof.destination_ancestor_generation(0), Some(1));
        assert_eq!(proof.destination_ancestor_generation(1), Some(5));
        let closure = proof.successor_closure::<4>().unwrap();
        assert_eq!(closure.len(), 4);
        assert_eq!(closure.object(0), Some(object(9)));
        assert_eq!(closure.object(1), Some(object(3)));
        assert_eq!(closure.object(2), Some(object(2)));
        assert_eq!(closure.object(3), Some(object(1)));
        assert_eq!(closure.object(4), None);
        assert_eq!(closure.generation(0), Some(1));
        assert_eq!(closure.generation(1), Some(1));
        assert_eq!(closure.generation(2), Some(1));
        assert_eq!(closure.generation(3), Some(5));
        assert_eq!(closure.generation(4), None);
        assert_eq!(
            proof.successor_closure::<3>().err(),
            Some(DirectoryClosureError::Capacity)
        );
        let mut inconsistent = DirectorySuccessorClosure::<2> {
            objects: [None; 2],
            generations: [0; 2],
            depths: [0; 2],
            count: 0,
        };
        inconsistent.insert(object(1), 5, 1).unwrap();
        assert_eq!(
            inconsistent.insert(object(1), 6, 1),
            Err(DirectoryClosureError::InvalidProof)
        );
        assert_eq!(
            inconsistent.insert(object(1), 5, 2),
            Err(DirectoryClosureError::InvalidProof)
        );
        assert!(matches!(
            prove_directory_move_ancestry::<2, _>(
                object(1),
                object(3),
                2,
                object(9),
                1,
                object(2),
                1,
                &mut backend,
            ),
            Err(DirectoryAncestryError::InvalidProof)
        ));
        let moved = source
            .move_to_with_ancestry(
                source_handle,
                &mut destination,
                destination_handle,
                &authority,
                principal(),
                name("child"),
                name("moved"),
                &proof,
            )
            .unwrap();
        assert_eq!(moved.object(), object(9));
        assert_eq!((source.len(), source.generation()), (0, 2));
        assert_eq!((destination.len(), destination.generation()), (1, 2));
    }

    #[test]
    fn directory_move_constructs_complete_generation_bound_successor_closure() {
        let mut ancestry_backend = AncestryBackend {
            records: [
                Some(directory_metadata(object(9), 1, Some(object(3)))),
                Some(directory_metadata(object(2), 1, Some(object(1)))),
                Some(directory_metadata(object(3), 1, Some(object(1)))),
                Some(directory_metadata(object(1), 5, None)),
                None,
            ],
        };
        let proof = prove_directory_move_ancestry::<2, _>(
            object(1),
            object(3),
            1,
            object(9),
            1,
            object(2),
            1,
            &mut ancestry_backend,
        )
        .unwrap();
        let moved_child =
            DirectoryEntry::new(name("leaf"), object(10), StorageObjectKind::File, 4).unwrap();
        let moved = DirectoryState::<4>::new(object(9), 1, &[moved_child]).unwrap();
        let moved_entry =
            DirectoryEntry::new(name("old"), object(9), StorageObjectKind::Directory, 1).unwrap();
        let retained =
            DirectoryEntry::new(name("keep"), object(8), StorageObjectKind::File, 7).unwrap();
        let source = DirectoryState::<4>::new(object(3), 1, &[moved_entry, retained]).unwrap();
        let destination = DirectoryState::<4>::new(object(2), 1, &[]).unwrap();
        let source_entry =
            DirectoryEntry::new(name("source"), object(3), StorageObjectKind::Directory, 1)
                .unwrap();
        let destination_entry = DirectoryEntry::new(
            name("destination"),
            object(2),
            StorageObjectKind::Directory,
            1,
        )
        .unwrap();
        let root =
            DirectoryState::<4>::new(object(1), 5, &[source_entry, destination_entry]).unwrap();
        let mut successor_backend = SuccessorBackend {
            records: [
                Some(moved),
                Some(source),
                Some(destination),
                Some(root),
                None,
            ],
        };
        let plan = proof
            .construct_move_successors::<4, 4, _>(name("old"), name("new"), &mut successor_backend)
            .unwrap();
        assert_eq!(plan.len(), 4);

        let moved = plan.successor(0).unwrap();
        assert_eq!(moved.predecessor_generation(), 1);
        assert_eq!(moved.predecessor().object(), object(9));
        assert_eq!(moved.predecessor().generation(), 1);
        assert_eq!(moved.parent(), Some(object(2)));
        assert_eq!(
            (moved.state().object(), moved.state().generation()),
            (object(9), 2)
        );
        assert_eq!(moved.state().entry(0), Some(moved_child));

        let source = plan.successor(1).unwrap();
        assert_eq!(source.parent(), Some(object(1)));
        assert_eq!(
            (source.state().object(), source.state().generation()),
            (object(3), 2)
        );
        assert_eq!(source.state().len(), 1);
        assert_eq!(source.state().entry(0), Some(retained));
        assert_eq!(source.state().entry(1), None);

        let destination = plan.successor(2).unwrap();
        assert_eq!(destination.parent(), Some(object(1)));
        assert_eq!(
            (
                destination.state().object(),
                destination.state().generation()
            ),
            (object(2), 2)
        );
        let inserted = destination.state().entry(0).unwrap();
        assert_eq!(inserted.name(), name("new"));
        assert_eq!(inserted.object(), object(9));
        assert_eq!(inserted.metadata_generation(), 2);

        let root = plan.successor(3).unwrap();
        assert_eq!(root.parent(), None);
        assert_eq!(
            (root.state().object(), root.state().generation()),
            (object(1), 6)
        );
        assert_eq!(root.state().entry(0).unwrap().metadata_generation(), 2);
        assert_eq!(root.state().entry(1).unwrap().metadata_generation(), 2);
        assert!(plan.successor(4).is_none());

        let header = VolumeHeader::new(volume(), 4096, 100, 1, 2).unwrap();
        let layouts = [
            DirectorySuccessorLayout::new(
                MetadataPointer::new(50, 1).unwrap(),
                MetadataPointer::new(51, 1).unwrap(),
            ),
            DirectorySuccessorLayout::new(
                MetadataPointer::new(52, 1).unwrap(),
                MetadataPointer::new(53, 1).unwrap(),
            ),
            DirectorySuccessorLayout::new(
                MetadataPointer::new(54, 1).unwrap(),
                MetadataPointer::new(55, 1).unwrap(),
            ),
            DirectorySuccessorLayout::new(
                MetadataPointer::new(56, 1).unwrap(),
                MetadataPointer::new(57, 1).unwrap(),
            ),
        ];
        let mut metadata_outputs = [[0; crate::DIRECTORY_METADATA_BYTES]; 4];
        let mut entries_outputs = [[0; 4096]; 4];
        let mut update_backend = UpdateBackend {
            staged: 0,
            flushed: false,
            verified: 0,
        };
        let prepared = plan
            .stage(
                header,
                &layouts,
                &mut metadata_outputs,
                &mut entries_outputs,
                &mut update_backend,
            )
            .unwrap();
        assert_eq!((update_backend.staged, update_backend.flushed), (8, true));
        assert_eq!(prepared.len(), 4);
        assert_eq!(prepared.update(0).unwrap().object(), object(9));
        assert_eq!(prepared.update(3).unwrap().object(), object(1));
        assert!(prepared.update(4).is_none());
        let transaction = prepared
            .transaction::<4, 8>(StorageTransactionId::new(17).unwrap(), 6)
            .unwrap();
        assert_eq!(transaction.participant_count(), 4);
        assert!(matches!(
            prepared.transaction::<3, 8>(StorageTransactionId::new(18).unwrap(), 6),
            Err(TransactionError::Capacity)
        ));

        let overlapping = [layouts[0], layouts[0], layouts[2], layouts[3]];
        let mut rejected_backend = UpdateBackend {
            staged: 0,
            flushed: false,
            verified: 0,
        };
        assert!(matches!(
            plan.stage(
                header,
                &overlapping,
                &mut metadata_outputs,
                &mut entries_outputs,
                &mut rejected_backend,
            ),
            Err(DirectoryMoveStageError::InvalidLayout)
        ));
        assert_eq!(rejected_backend.staged, 0);

        let active_root =
            AllocationRecord::new(object(1), 5, 10, 1, AllocationKind::ObjectMetadata).unwrap();
        let active_allocation =
            AllocationRecord::new(object(1), 5, 20, 1, AllocationKind::AllocationMetadata).unwrap();
        let active_allocation_image = AllocationImage::<12>::build(
            header,
            5,
            MetadataPointer::new(20, 1).unwrap(),
            &[active_root, active_allocation],
        )
        .unwrap();
        let changes = [
            AllocationChange::Allocate(
                AllocationRecord::new(object(9), 2, 50, 1, AllocationKind::ObjectMetadata).unwrap(),
            ),
            AllocationChange::Allocate(
                AllocationRecord::new(object(9), 2, 51, 1, AllocationKind::DirectoryEntries)
                    .unwrap(),
            ),
            AllocationChange::Allocate(
                AllocationRecord::new(object(3), 2, 52, 1, AllocationKind::ObjectMetadata).unwrap(),
            ),
            AllocationChange::Allocate(
                AllocationRecord::new(object(3), 2, 53, 1, AllocationKind::DirectoryEntries)
                    .unwrap(),
            ),
            AllocationChange::Allocate(
                AllocationRecord::new(object(2), 2, 54, 1, AllocationKind::ObjectMetadata).unwrap(),
            ),
            AllocationChange::Allocate(
                AllocationRecord::new(object(2), 2, 55, 1, AllocationKind::DirectoryEntries)
                    .unwrap(),
            ),
            AllocationChange::Allocate(
                AllocationRecord::new(object(1), 6, 56, 1, AllocationKind::ObjectMetadata).unwrap(),
            ),
            AllocationChange::Allocate(
                AllocationRecord::new(object(1), 6, 57, 1, AllocationKind::DirectoryEntries)
                    .unwrap(),
            ),
        ];
        let mut allocation_output = [0; 4096];
        let allocation = active_allocation_image
            .prepare_successor(
                header,
                object(1),
                MetadataPointer::new(58, 1).unwrap(),
                &changes,
                &mut allocation_output,
                &mut update_backend,
            )
            .unwrap();
        assert_eq!(update_backend.staged, 9);
        let transaction = prepared
            .transaction_with_allocation::<12, 5, 9>(
                &allocation,
                StorageTransactionId::new(19).unwrap(),
                6,
            )
            .unwrap();
        assert_eq!(transaction.participant_count(), 5);
        let active_superblock = Superblock::new(
            header,
            5,
            4,
            object(1),
            MetadataPointer::new(10, 1).unwrap(),
            MetadataPointer::new(20, 1).unwrap(),
        )
        .unwrap();
        let publication = prepared
            .publication_plan::<12, 9>(
                &allocation,
                header,
                1,
                active_superblock,
                object(1),
                &[
                    MetadataPointer::new(10, 1).unwrap(),
                    MetadataPointer::new(20, 1).unwrap(),
                ],
            )
            .unwrap();
        let mut incomplete_allocation_output = [0; 4096];
        let incomplete_allocation = active_allocation_image
            .prepare_successor(
                header,
                object(1),
                MetadataPointer::new(59, 1).unwrap(),
                &changes[..changes.len() - 1],
                &mut incomplete_allocation_output,
                &mut update_backend,
            )
            .unwrap();
        assert!(matches!(
            prepared.publication_plan::<12, 9>(
                &incomplete_allocation,
                header,
                1,
                active_superblock,
                object(1),
                &[
                    MetadataPointer::new(10, 1).unwrap(),
                    MetadataPointer::new(20, 1).unwrap(),
                ],
            ),
            Err(CowPlanError::InvalidWrite)
        ));
        let mut receipt = transaction
            .publish(&publication, &mut update_backend)
            .unwrap();
        assert_eq!((update_backend.verified, receipt.remaining()), (9, 5));
        let committed = prepared.commit_transaction(&mut receipt).unwrap();
        assert_eq!(committed.len(), 4);
        assert_eq!(committed.state(0).unwrap().object(), object(9));
        assert_eq!(committed.state(3).unwrap().generation(), 6);
        assert_eq!(receipt.remaining(), 1);
        let committed_allocation = allocation.commit_transaction(&mut receipt).unwrap();
        assert_eq!(committed_allocation.generation(), 6);
        assert_eq!(receipt.remaining(), 0);
    }

    #[test]
    fn directory_successor_construction_deduplicates_shared_edges_and_rejects_stale_state() {
        let mut ancestry_backend = AncestryBackend {
            records: [
                Some(directory_metadata(object(9), 1, Some(object(3)))),
                Some(directory_metadata(object(2), 1, Some(object(4)))),
                Some(directory_metadata(object(3), 1, Some(object(4)))),
                Some(directory_metadata(object(4), 3, Some(object(1)))),
                Some(directory_metadata(object(1), 5, None)),
            ],
        };
        let proof = prove_directory_move_ancestry::<3, _>(
            object(1),
            object(3),
            1,
            object(9),
            1,
            object(2),
            1,
            &mut ancestry_backend,
        )
        .unwrap();
        let moved = DirectoryState::<3>::new(object(9), 1, &[]).unwrap();
        let moved_entry =
            DirectoryEntry::new(name("old"), object(9), StorageObjectKind::Directory, 1).unwrap();
        let source = DirectoryState::<3>::new(object(3), 1, &[moved_entry]).unwrap();
        let destination = DirectoryState::<3>::new(object(2), 1, &[]).unwrap();
        let source_entry =
            DirectoryEntry::new(name("source"), object(3), StorageObjectKind::Directory, 1)
                .unwrap();
        let destination_entry = DirectoryEntry::new(
            name("destination"),
            object(2),
            StorageObjectKind::Directory,
            1,
        )
        .unwrap();
        let common =
            DirectoryState::<3>::new(object(4), 3, &[source_entry, destination_entry]).unwrap();
        let common_entry =
            DirectoryEntry::new(name("common"), object(4), StorageObjectKind::Directory, 3)
                .unwrap();
        let root = DirectoryState::<3>::new(object(1), 5, &[common_entry]).unwrap();
        let mut backend = SuccessorBackend {
            records: [
                Some(moved.clone()),
                Some(source.clone()),
                Some(destination.clone()),
                Some(common.clone()),
                Some(root.clone()),
            ],
        };
        let plan = proof
            .construct_move_successors::<5, 3, _>(name("old"), name("new"), &mut backend)
            .unwrap();
        assert_eq!(plan.len(), 5);
        let common = plan.successor(3).unwrap().state();
        assert_eq!((common.object(), common.generation()), (object(4), 4));
        assert_eq!(common.entry(0).unwrap().metadata_generation(), 2);
        assert_eq!(common.entry(1).unwrap().metadata_generation(), 2);
        let root = plan.successor(4).unwrap().state();
        assert_eq!((root.object(), root.generation()), (object(1), 6));
        assert_eq!(root.entry(0).unwrap().metadata_generation(), 4);

        let mut stale_root = root.clone();
        stale_root.generation = 7;
        let mut stale = SuccessorBackend {
            records: [
                Some(moved),
                Some(source),
                Some(destination),
                Some(
                    DirectoryState::<3>::new(object(4), 3, &[source_entry, destination_entry])
                        .unwrap(),
                ),
                Some(stale_root),
            ],
        };
        assert!(matches!(
            proof.construct_move_successors::<5, 3, _>(name("old"), name("new"), &mut stale),
            Err(DirectorySuccessorError::InvalidProof)
        ));

        let mut exhausted_ancestry = AncestryBackend {
            records: [
                Some(directory_metadata(object(9), 1, Some(object(3)))),
                Some(directory_metadata(object(2), 1, Some(object(1)))),
                Some(directory_metadata(object(3), u64::MAX, Some(object(1)))),
                Some(directory_metadata(object(1), 5, None)),
                None,
            ],
        };
        let exhausted_proof = prove_directory_move_ancestry::<2, _>(
            object(1),
            object(3),
            u64::MAX,
            object(9),
            1,
            object(2),
            1,
            &mut exhausted_ancestry,
        )
        .unwrap();
        let exhausted_source_entry = DirectoryEntry::new(
            name("source"),
            object(3),
            StorageObjectKind::Directory,
            u64::MAX,
        )
        .unwrap();
        let mut exhausted_backend = SuccessorBackend {
            records: [
                Some(DirectoryState::<2>::new(object(9), 1, &[]).unwrap()),
                Some(DirectoryState::<2>::new(object(3), u64::MAX, &[moved_entry]).unwrap()),
                Some(DirectoryState::<2>::new(object(2), 1, &[]).unwrap()),
                Some(
                    DirectoryState::<2>::new(
                        object(1),
                        5,
                        &[exhausted_source_entry, destination_entry],
                    )
                    .unwrap(),
                ),
                None,
            ],
        };
        assert!(matches!(
            exhausted_proof.construct_move_successors::<4, 2, _>(
                name("old"),
                name("new"),
                &mut exhausted_backend
            ),
            Err(DirectorySuccessorError::GenerationExhausted)
        ));
    }

    #[test]
    fn ancestry_proof_rejects_descendants_stale_state_and_capacity() {
        let mut same_directory = AncestryBackend {
            records: [None, None, None, None, None],
        };
        assert!(matches!(
            prove_directory_move_ancestry::<2, _>(
                object(1),
                object(3),
                1,
                object(9),
                1,
                object(3),
                1,
                &mut same_directory,
            ),
            Err(DirectoryAncestryError::InvalidProof)
        ));

        let mut descendant = AncestryBackend {
            records: [
                Some(directory_metadata(object(9), 1, Some(object(3)))),
                Some(directory_metadata(object(2), 1, Some(object(9)))),
                Some(directory_metadata(object(3), 1, Some(object(1)))),
                Some(directory_metadata(object(1), 5, None)),
                None,
            ],
        };
        assert!(matches!(
            prove_directory_move_ancestry::<4, _>(
                object(1),
                object(3),
                1,
                object(9),
                1,
                object(2),
                1,
                &mut descendant
            ),
            Err(DirectoryAncestryError::Cycle)
        ));

        let mut stale = AncestryBackend {
            records: [
                Some(directory_metadata(object(9), 1, Some(object(3)))),
                Some(directory_metadata(object(2), 2, Some(object(1)))),
                Some(directory_metadata(object(3), 1, Some(object(1)))),
                Some(directory_metadata(object(1), 5, None)),
                None,
            ],
        };
        assert!(matches!(
            prove_directory_move_ancestry::<2, _>(
                object(1),
                object(3),
                1,
                object(9),
                1,
                object(2),
                1,
                &mut stale
            ),
            Err(DirectoryAncestryError::InvalidProof)
        ));

        let mut wrong_child = AncestryBackend {
            records: [
                Some(directory_metadata(object(9), 2, Some(object(4)))),
                Some(directory_metadata(object(2), 1, Some(object(1)))),
                Some(directory_metadata(object(3), 1, Some(object(1)))),
                Some(directory_metadata(object(1), 5, None)),
                None,
            ],
        };
        assert!(matches!(
            prove_directory_move_ancestry::<2, _>(
                object(1),
                object(3),
                1,
                object(9),
                1,
                object(2),
                1,
                &mut wrong_child
            ),
            Err(DirectoryAncestryError::InvalidProof)
        ));

        let mut deep = AncestryBackend {
            records: [
                Some(directory_metadata(object(9), 1, Some(object(3)))),
                Some(directory_metadata(object(2), 1, Some(object(1)))),
                Some(directory_metadata(object(3), 1, Some(object(1)))),
                Some(directory_metadata(object(1), 5, None)),
                None,
            ],
        };
        assert!(matches!(
            prove_directory_move_ancestry::<1, _>(
                object(1),
                object(3),
                1,
                object(9),
                1,
                object(2),
                1,
                &mut deep
            ),
            Err(DirectoryAncestryError::Capacity)
        ));
    }

    #[test]
    fn directory_image_round_trip_binds_owner_generation_and_zero_padding() {
        let pointer = MetadataPointer::new(30, 1).unwrap();
        let entries = [
            DirectoryEntry::new(name("child"), object(8), StorageObjectKind::Directory, 2).unwrap(),
            DirectoryEntry::new(name("file"), object(9), StorageObjectKind::File, 3).unwrap(),
        ];
        let header = VolumeHeader::new(volume(), 4096, 100, 1, 2).unwrap();
        let image = DirectoryImage::<2>::build(header, object(1), 4, pointer, &entries).unwrap();
        let mut encoded = [0; 4096];
        image.encode(&mut encoded).unwrap();
        let decoded = DirectoryImage::<2>::decode(header, object(1), 4, pointer, &encoded).unwrap();
        assert_eq!(decoded.pointer(), pointer);
        assert_eq!(decoded.state().len(), 2);
        assert_eq!(decoded.state().entry(1), Some(entries[1]));
        assert!(matches!(
            DirectoryImage::<2>::decode(header, object(1), 5, pointer, &encoded),
            Err(DirectoryImageError::InvalidImage)
        ));

        encoded[4095] = 1;
        let digest = image_digest(&encoded);
        encoded[DIRECTORY_IMAGE_DIGEST_OFFSET..DIRECTORY_IMAGE_HEADER_BYTES]
            .copy_from_slice(&digest);
        assert!(matches!(
            DirectoryImage::<2>::decode(header, object(1), 4, pointer, &encoded),
            Err(DirectoryImageError::NonCanonical)
        ));
    }
}
