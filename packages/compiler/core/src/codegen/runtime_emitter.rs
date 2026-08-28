struct RuntimeEmitter<'tree, 'source, R, const MAX_BYTES: usize, const MAX_PARAMETERS: usize> {
    bytes: [u8; MAX_BYTES],
    length: usize,
    readonly_data: [u8; MAX_X86_64_READONLY_DATA_BYTES],
    readonly_data_length: usize,
    readonly_relocations: [X86_64ReadonlyDataRelocation; MAX_X86_64_READONLY_RELOCATIONS],
    readonly_relocation_count: usize,
    trap_patches: [usize; MAX_BYTES],
    trap_count: usize,
    function: &'tree Function<'source, MAX_PARAMETERS>,
    resolver: &'tree R,
    abi: X86_64Abi,
    width: RuntimeWidth,
    overflow_checks: bool,
    uses_sret: bool,
    saved_parameter_slots: usize,
    locals: [Option<RuntimeLocal<'tree>>; MAX_PARAMETERS],
    saved_locals: usize,
    body_facts: &'tree mut RuntimeBodyFacts<'tree>,
    preanalyzed_local_count: usize,
    preanalyzed_local_cursor: usize,
    preanalyzed_assignment_access_cursor: usize,
    preanalyzed_assignment_read_cursor: usize,
    evaluation_depth: usize,
    runtime_call_depth: usize,
    runtime_call_names: [Option<&'tree str>; 8],
    runtime_call_local_floor: Option<usize>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReadonlyStringLiteralKind {
    Utf8,
    Bytes,
    C,
}

impl<
    'tree,
    'source: 'tree,
    R: ConstantResolver,
    const MAX_BYTES: usize,
    const MAX_PARAMETERS: usize,
> RuntimeEmitter<'tree, 'source, R, MAX_BYTES, MAX_PARAMETERS>
{
    fn local_stack_slots(&self) -> Result<usize, CodegenError> {
        self.locals[..self.saved_locals]
            .iter()
            .flatten()
            .try_fold(0usize, |total, local| {
                total
                    .checked_add(local.stack_slots)
                    .ok_or(self.error(CodegenErrorKind::OutputTooSmall))
            })
    }

    fn push_runtime_local(
        &mut self,
        name: &'tree str,
        ty: RuntimeExpressionType,
        mutable: bool,
        initialized: bool,
        stack_slots: usize,
        declaration_span: Option<Span>,
    ) -> Result<(), CodegenError> {
        if self.saved_locals == MAX_PARAMETERS {
            return Err(self.error(CodegenErrorKind::TooManyRuntimeLocals));
        }
        let preanalyzed = self.preanalyzed_local_cursor < self.preanalyzed_local_count
            && self.body_facts.locals[self.preanalyzed_local_cursor].is_some_and(|fact| {
                fact.name == name
                    && fact.ty == ty
                    && fact.mutable == mutable
                    && fact.initialized == initialized
                    && fact.declaration_span == declaration_span
            });
        let id = if preanalyzed {
            let fact = self.body_facts.locals[self.preanalyzed_local_cursor]
                .ok_or(self.error(CodegenErrorKind::InvalidRuntimePlaceFacts))?;
            if fact.id != RuntimeLocalId(self.preanalyzed_local_cursor) {
                return Err(self.error(CodegenErrorKind::InvalidRuntimePlaceFacts));
            }
            self.preanalyzed_local_cursor += 1;
            fact.id
        } else {
            self.body_facts
                .push_local(name, ty, mutable, initialized, declaration_span)
                .map_err(|kind| self.error(kind))?
        };
        self.locals[self.saved_locals] = Some(RuntimeLocal {
            id,
            name,
            ty,
            mutable,
            initialized,
            stack_slots,
        });
        self.saved_locals += 1;
        Ok(())
    }

    fn resolve_assignment_place(
        &self,
        assignment: &crate::Assignment<'tree>,
    ) -> Result<RuntimePlace<'tree>, CodegenError> {
        resolve_runtime_assignment_place(
            self.function,
            &self.locals[..self.saved_locals],
            assignment,
        )
        .map_err(|kind| self.error(kind))
    }

    fn record_place_access<const MAX_EXPRESSION_NODES: usize>(
        &mut self,
        place: RuntimePlace<'tree>,
        assignment: &crate::Assignment<'tree>,
    ) -> Result<(), CodegenError> {
        let span = assignment.name_span;
        let base = match place.base {
            RuntimePlaceBase::Local { id, .. } => RuntimePlaceIdentity::Local(id),
            RuntimePlaceBase::Parameter { index } => RuntimePlaceIdentity::Parameter(index),
        };
        let base_ty = self.body_facts.move_paths[..self.body_facts.move_path_count]
            .iter()
            .flatten()
            .find(|path| path.base == base && path.projections == RuntimePlaceProjections::EMPTY)
            .map(|path| path.ty)
            .ok_or(self.error(CodegenErrorKind::InvalidRuntimePlaceFacts))?;
        let projections = RuntimePlaceProjections::from_assignment_with_array_identity::<
            R,
            MAX_EXPRESSION_NODES,
        >(assignment, base_ty, self.resolver)
        .map_err(|kind| self.error(kind))?;
        let fact = RuntimePlaceAccessFact {
            base,
            projections,
            ty: place.ty,
            access: place.access,
            span,
        };
        if self.preanalyzed_assignment_access_cursor < self.body_facts.assignment_access_count
            && self.body_facts.assignment_accesses[self.preanalyzed_assignment_access_cursor]
                == Some(fact)
        {
            self.preanalyzed_assignment_access_cursor += 1;
        }
        self.record_place_access_fact(base, projections, place.ty, place.access, span)
    }

    fn record_place_access_fact(
        &mut self,
        base: RuntimePlaceIdentity,
        projections: RuntimePlaceProjections,
        ty: RuntimeExpressionType,
        access: RuntimePlaceAccess,
        span: Span,
    ) -> Result<(), CodegenError> {
        let capacity_error = self.error(CodegenErrorKind::TooManyRuntimePlaceAccessFacts);
        let slot = self
            .body_facts
            .accesses
            .get_mut(self.body_facts.access_count)
            .ok_or(capacity_error)?;
        *slot = Some(RuntimePlaceAccessFact {
            base,
            projections,
            ty,
            access,
            span,
        });
        self.body_facts.access_count += 1;
        Ok(())
    }

    fn record_x86_64_inline_output_place(
        &mut self,
        place: X86_64InlineOutputPlace<'tree>,
        access: RuntimePlaceAccess,
        span: Span,
    ) -> Result<X86_64InlineResolvedOutputStorage<'tree>, CodegenError> {
        let fact = RuntimePlaceAccessFact {
            base: place.base,
            projections: place.projections,
            ty: place.ty,
            access,
            span,
        };
        if self.preanalyzed_assignment_access_cursor < self.body_facts.assignment_access_count
            && self.body_facts.assignment_accesses[self.preanalyzed_assignment_access_cursor]
                == Some(fact)
        {
            self.preanalyzed_assignment_access_cursor += 1;
        }
        self.record_place_access_fact(
            fact.base,
            fact.projections,
            fact.ty,
            fact.access,
            fact.span,
        )?;
        match place.storage {
            X86_64InlineOutputStorage::LocalStack {
                local_index,
                offset,
            } => self
                .local_stack_slots_from(local_index + 1)?
                .checked_add(offset)
                .map(X86_64InlineResolvedOutputStorage::StackSlot)
                .ok_or(self.error(CodegenErrorKind::OutputTooSmall)),
            X86_64InlineOutputStorage::LocalPointer { local_index } => {
                Ok(X86_64InlineResolvedOutputStorage::PointerSlot(
                    self.local_stack_slots_from(local_index + 1)?,
                ))
            }
            X86_64InlineOutputStorage::ParameterPointer { parameter_index } => {
                Ok(X86_64InlineResolvedOutputStorage::PointerSlot(
                    self.local_stack_slots()?
                        .checked_add(self.parameter_stack_slots_from(parameter_index + 1)?)
                        .ok_or(self.error(CodegenErrorKind::OutputTooSmall))?,
                ))
            }
            X86_64InlineOutputStorage::LocalDynamicArray {
                local_index,
                element,
                count,
                index,
            } => Ok(X86_64InlineResolvedOutputStorage::DynamicArray {
                local_index,
                element,
                count,
                index,
            }),
            X86_64InlineOutputStorage::LocalDynamicReferenceArray {
                local_index,
                element,
                count,
                layout,
                index,
            } => Ok(X86_64InlineResolvedOutputStorage::DynamicReferenceArray {
                pointer_slot: self.local_stack_slots_from(local_index + 1)?,
                element,
                count,
                layout,
                index,
            }),
            X86_64InlineOutputStorage::ParameterDynamicReferenceArray {
                parameter_index,
                element,
                count,
                layout,
                index,
            } => Ok(X86_64InlineResolvedOutputStorage::DynamicReferenceArray {
                pointer_slot: self
                    .local_stack_slots()?
                    .checked_add(self.parameter_stack_slots_from(parameter_index + 1)?)
                    .ok_or(self.error(CodegenErrorKind::OutputTooSmall))?,
                element,
                count,
                layout,
                index,
            }),
            X86_64InlineOutputStorage::LocalDynamicSlice {
                local_index,
                element,
                index,
            } => {
                let length_slot = self.local_stack_slots_from(local_index + 1)?;
                Ok(X86_64InlineResolvedOutputStorage::DynamicSlice {
                    pointer_slot: length_slot
                        .checked_add(1)
                        .ok_or(self.error(CodegenErrorKind::OutputTooSmall))?,
                    length_slot,
                    element,
                    index,
                })
            }
            X86_64InlineOutputStorage::ParameterDynamicSlice {
                parameter_index,
                element,
                index,
            } => {
                let length_slot = self
                    .local_stack_slots()?
                    .checked_add(self.parameter_stack_slots_from(parameter_index + 1)?)
                    .ok_or(self.error(CodegenErrorKind::OutputTooSmall))?;
                Ok(X86_64InlineResolvedOutputStorage::DynamicSlice {
                    pointer_slot: length_slot
                        .checked_add(1)
                        .ok_or(self.error(CodegenErrorKind::OutputTooSmall))?,
                    length_slot,
                    element,
                    index,
                })
            }
        }
    }

    fn emit_x86_64_inline_output_prepare<const MAX_EXPRESSION_NODES: usize>(
        &mut self,
        storage: X86_64InlineResolvedOutputStorage<'tree>,
    ) -> Result<(), CodegenError> {
        let (index, count) = match storage {
            X86_64InlineResolvedOutputStorage::DynamicArray { index, count, .. }
            | X86_64InlineResolvedOutputStorage::DynamicReferenceArray { index, count, .. } => {
                (index, Some(count))
            }
            X86_64InlineResolvedOutputStorage::DynamicSlice { index, .. } => (index, None),
            _ => return Ok(()),
        };
        let tree = crate::ExpressionParser::<MAX_EXPRESSION_NODES>::new(index)
            .parse()
            .map_err(|error| CodegenError {
                kind: CodegenErrorKind::Expression(error.kind),
                span: error.span,
            })?;
        self.emit_expression(&tree, tree.root(), 0)?;
        if let Some(count) = count {
            self.emit(&[0x48, 0x83, 0xf8, count as u8])?;
            self.emit_trap_branch(0x83)?;
            self.emit(&[0x50])?;
            self.evaluation_depth += 1;
        } else if let X86_64InlineResolvedOutputStorage::DynamicSlice { length_slot, .. } = storage
        {
            self.emit(&[0x50])?;
            self.evaluation_depth += 1;
            self.emit_stack_slot(length_slot + self.evaluation_depth)?;
            self.emit(&[0x48, 0x39, 0x04, 0x24])?;
            let in_bounds = self.emit_forward_branch(0x82)?;
            self.emit(&[0x0f, 0x0b])?;
            self.patch_forward_branch(in_bounds)?;
        }
        Ok(())
    }

    fn emit_x86_64_inline_output_load(
        &mut self,
        storage: X86_64InlineResolvedOutputStorage<'tree>,
    ) -> Result<(), CodegenError> {
        match storage {
            X86_64InlineResolvedOutputStorage::StackSlot(slot) => self.emit_stack_slot(slot),
            X86_64InlineResolvedOutputStorage::PointerSlot(slot) => {
                self.emit_stack_slot(slot)?;
                self.emit(&[0x48, 0x8b, 0x00])
            }
            X86_64InlineResolvedOutputStorage::DynamicArray {
                local_index,
                element,
                count,
                ..
            } => self.emit_array_local_element(local_index, element, count, 0),
            X86_64InlineResolvedOutputStorage::DynamicReferenceArray {
                pointer_slot,
                element,
                layout,
                ..
            } => {
                self.emit_stack_slot(pointer_slot + self.evaluation_depth)?;
                let element_bytes = runtime_array_element_bytes(element)
                    .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
                self.emit_reference_array_address_from_stack_index(element_bytes, layout, 0)?;
                self.emit_reference_load(element)
            }
            X86_64InlineResolvedOutputStorage::DynamicSlice {
                pointer_slot,
                element,
                ..
            } => {
                self.emit_stack_slot(pointer_slot + self.evaluation_depth)?;
                let element_bytes = runtime_array_element_bytes(element)
                    .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
                self.emit_reference_array_address_from_stack_index(
                    element_bytes,
                    RuntimeReferenceArrayLayout::Native,
                    0,
                )?;
                self.emit_reference_load(element)
            }
        }
    }

    fn emit_x86_64_inline_output_store(
        &mut self,
        storage: X86_64InlineResolvedOutputStorage<'tree>,
    ) -> Result<(), CodegenError> {
        match storage {
            X86_64InlineResolvedOutputStorage::StackSlot(slot) => self.emit_store_stack_slot(slot),
            X86_64InlineResolvedOutputStorage::PointerSlot(slot) => {
                self.emit(&[0x48, 0x89, 0xc1])?;
                self.emit_stack_slot(slot)?;
                self.emit(&[0x48, 0x89, 0x08])
            }
            X86_64InlineResolvedOutputStorage::DynamicArray {
                local_index,
                element,
                count,
                ..
            } => {
                self.emit(&[0x50])?;
                self.evaluation_depth += 1;
                self.emit_array_local_element_store(local_index, element, count, 1)?;
                self.evaluation_depth -= 2;
                self.emit(&[0x48, 0x83, 0xc4, 16])
            }
            X86_64InlineResolvedOutputStorage::DynamicReferenceArray {
                pointer_slot,
                element,
                layout,
                ..
            } => {
                self.emit(&[0x50])?;
                self.evaluation_depth += 1;
                self.emit_stack_slot(pointer_slot + self.evaluation_depth)?;
                self.emit(&[0x48, 0x89, 0xc2])?;
                let element_bytes = runtime_array_element_bytes(element)
                    .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
                self.emit_reference_array_store_address_from_stack_index(element_bytes, layout, 1)?;
                self.emit_stack_slot(0)?;
                self.emit_reference_store(element)?;
                self.evaluation_depth -= 2;
                self.emit(&[0x48, 0x83, 0xc4, 16])
            }
            X86_64InlineResolvedOutputStorage::DynamicSlice {
                pointer_slot,
                element,
                ..
            } => {
                self.emit(&[0x50])?;
                self.evaluation_depth += 1;
                self.emit_stack_slot(pointer_slot + self.evaluation_depth)?;
                self.emit(&[0x48, 0x89, 0xc2])?;
                let element_bytes = runtime_array_element_bytes(element)
                    .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
                self.emit_reference_array_store_address_from_stack_index(
                    element_bytes,
                    RuntimeReferenceArrayLayout::Native,
                    1,
                )?;
                self.emit_stack_slot(0)?;
                self.emit_reference_store(element)?;
                self.evaluation_depth -= 2;
                self.emit(&[0x48, 0x83, 0xc4, 16])
            }
        }
    }

    fn record_identifier_read(
        &mut self,
        name: &str,
        projections: RuntimePlaceProjections,
        span: Span,
    ) -> Result<(), CodegenError> {
        let local_floor = self.runtime_call_local_floor.unwrap_or(0);
        if let Some(local) = self.locals[local_floor..self.saved_locals]
            .iter()
            .rev()
            .flatten()
            .find(|local| local.name == name)
            .copied()
        {
            let fact = RuntimePlaceAccessFact {
                base: RuntimePlaceIdentity::Local(local.id),
                projections,
                ty: local.ty,
                access: RuntimePlaceAccess::Read,
                span,
            };
            if self.preanalyzed_assignment_read_cursor < self.body_facts.assignment_read_count
                && self.body_facts.assignment_reads[self.preanalyzed_assignment_read_cursor]
                    == Some(fact)
            {
                self.preanalyzed_assignment_read_cursor += 1;
            }
            return self.record_place_access_fact(
                fact.base,
                fact.projections,
                fact.ty,
                fact.access,
                fact.span,
            );
        }
        if self.runtime_call_local_floor.is_none()
            && let Some((index, parameter)) = self
                .function
                .parameters()
                .iter()
                .flatten()
                .enumerate()
                .find(|(_, parameter)| parameter.name == name)
        {
            let ty = runtime_type_from_text(parameter.ty.text)
                .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
            let fact = RuntimePlaceAccessFact {
                base: RuntimePlaceIdentity::Parameter(index),
                projections,
                ty,
                access: RuntimePlaceAccess::Read,
                span,
            };
            if self.preanalyzed_assignment_read_cursor < self.body_facts.assignment_read_count
                && self.body_facts.assignment_reads[self.preanalyzed_assignment_read_cursor]
                    == Some(fact)
            {
                self.preanalyzed_assignment_read_cursor += 1;
            }
            return self.record_place_access_fact(
                fact.base,
                fact.projections,
                fact.ty,
                fact.access,
                fact.span,
            );
        }
        Ok(())
    }

    fn record_expression_place_read<const MAX_NODES: usize>(
        &mut self,
        tree: &crate::ExpressionTree<'_, MAX_NODES>,
        id: crate::ExprId,
        trailing_projection: Option<RuntimePlaceProjection>,
    ) -> Result<(), CodegenError> {
        let mut place = discover_runtime_read_place(tree, id)
            .map_err(|kind| self.error(kind))?
            .ok_or(self.error(CodegenErrorKind::RuntimeExpressionUnsupported))?;
        place = refine_constant_array_read_place(
            self.function,
            self.resolver,
            &self.locals[..self.saved_locals],
            tree,
            id,
            place,
        )
        .map_err(|kind| self.error(kind))?;
        if let Some(projection) = trailing_projection {
            place
                .projections
                .push(projection)
                .map_err(|kind| self.error(kind))?;
        }
        self.record_identifier_read(place.name, place.projections, place.span)
    }

    fn resolved_local(
        &self,
        place: RuntimePlace<'_>,
    ) -> Result<(usize, RuntimeLocal<'tree>), CodegenError> {
        let (id, index) = match place.base {
            RuntimePlaceBase::Local { id, index } => (id, index),
            RuntimePlaceBase::Parameter { index } => {
                if self
                    .function
                    .parameters()
                    .get(index)
                    .and_then(|parameter| *parameter)
                    .is_none()
                {
                    return Err(self.error(CodegenErrorKind::UnknownRuntimeName));
                }
                return Err(self.error(CodegenErrorKind::ImmutableAssignment));
            }
        };
        let local = self
            .locals
            .get(index)
            .and_then(|local| *local)
            .ok_or(self.error(CodegenErrorKind::UnknownRuntimeName))?;
        if local.id != id {
            return Err(self.error(CodegenErrorKind::UnknownRuntimeName));
        }
        Ok((index, local))
    }

    fn local_stack_slots_from(&self, index: usize) -> Result<usize, CodegenError> {
        self.locals[index..self.saved_locals]
            .iter()
            .flatten()
            .try_fold(0usize, |total, local| {
                total
                    .checked_add(local.stack_slots)
                    .ok_or(self.error(CodegenErrorKind::OutputTooSmall))
            })
    }

    fn parameter_stack_slots_from(&self, index: usize) -> Result<usize, CodegenError> {
        self.function
            .parameters()
            .iter()
            .flatten()
            .skip(index)
            .try_fold(0usize, |total, parameter| {
                let slots = runtime_array_type(parameter.ty.text)
                    .or_else(|| runtime_reference_type(parameter.ty.text))
                    .map_or(1, runtime_type_stack_slots);
                total
                    .checked_add(slots)
                    .ok_or(self.error(CodegenErrorKind::TooManyAbiParameters))
            })
    }

    fn emit(&mut self, bytes: &[u8]) -> Result<(), CodegenError> {
        let capacity_error = self.error(CodegenErrorKind::OutputTooSmall);
        let end = self.length.checked_add(bytes.len()).ok_or(capacity_error)?;
        let output = self.bytes.get_mut(self.length..end).ok_or(capacity_error)?;
        output.copy_from_slice(bytes);
        self.length = end;
        Ok(())
    }

    fn error(&self, kind: CodegenErrorKind) -> CodegenError {
        CodegenError {
            kind,
            span: self.function.body_expression_span,
        }
    }

    fn emit_prologue(&mut self, _validated_body: ValidatedRuntimeBody) -> Result<(), CodegenError> {
        match self.abi {
            X86_64Abi::Windows => {
                let mut pushed_slots = usize::from(self.uses_sret);
                if self.uses_sret {
                    self.emit(&[0x51])?;
                }
                for (index, parameter) in self.function.parameters().iter().flatten().enumerate() {
                    let abi_index = index + usize::from(self.uses_sret);
                    if matches!(
                        runtime_reference_type(parameter.ty.text),
                        Some(RuntimeExpressionType::Reference {
                            target: RuntimeReferenceTarget::Slice(_) | RuntimeReferenceTarget::Str,
                            ..
                        })
                    ) {
                        self.emit_windows_parameter_pointer(abi_index, pushed_slots)?;
                        self.emit(&[0x4c, 0x8b, 0x10, 0x41, 0x52])?;
                        self.emit(&[0x4c, 0x8b, 0x50, 0x08, 0x41, 0x52])?;
                        pushed_slots += 2;
                    } else if let Some(array) = runtime_array_type(parameter.ty.text) {
                        let (_, bytes, _) = runtime_array_abi_layout(array)
                            .ok_or(self.error(CodegenErrorKind::UnsupportedParameterType))?;
                        let RuntimeExpressionType::Array { count, .. } = array else {
                            unreachable!()
                        };
                        if bytes == 0 {
                            self.emit_zero_array_slots(count)?;
                        } else if matches!(bytes, 1 | 2 | 4 | 8) {
                            self.emit_parameter_register_or_stack_load(
                                X86_64Abi::Windows,
                                abi_index,
                                40,
                                pushed_slots,
                            )?;
                            self.emit_unpack_array_word(array, 0)?;
                        } else {
                            self.emit_windows_parameter_pointer(abi_index, pushed_slots)?;
                            self.emit_compact_pointer_array_pushes(array)?;
                        }
                        pushed_slots += count;
                    } else {
                        self.emit_windows_parameter_word(abi_index, pushed_slots)?;
                        pushed_slots += 1;
                    }
                }
            }
            X86_64Abi::SystemV => {
                let mut register = usize::from(self.uses_sret);
                let mut stack_offset = 8usize;
                let mut pushed_slots = usize::from(self.uses_sret);
                if self.uses_sret {
                    self.emit(&[0x57])?;
                }
                for parameter in self.function.parameters().iter().flatten() {
                    if matches!(
                        runtime_reference_type(parameter.ty.text),
                        Some(RuntimeExpressionType::Reference {
                            target: RuntimeReferenceTarget::Slice(_) | RuntimeReferenceTarget::Str,
                            ..
                        })
                    ) {
                        if register + 2 <= 6 {
                            for _ in 0..2 {
                                self.emit_parameter_register_load(X86_64Abi::SystemV, register)?;
                                self.emit(&[0x50])?;
                                register += 1;
                                pushed_slots += 1;
                            }
                        } else {
                            for word in 0..2 {
                                self.emit_original_stack_word_push(
                                    stack_offset + word * 8,
                                    pushed_slots,
                                )?;
                                pushed_slots += 1;
                            }
                            stack_offset += 16;
                        }
                    } else if let Some(array) = runtime_array_type(parameter.ty.text) {
                        let (_, _, words) = runtime_array_abi_layout(array)
                            .ok_or(self.error(CodegenErrorKind::UnsupportedParameterType))?;
                        let RuntimeExpressionType::Array { count, .. } = array else {
                            unreachable!()
                        };
                        if words == 0 {
                            self.emit_zero_array_slots(count)?;
                            pushed_slots += count;
                        } else if words <= 2 && register + words <= 6 {
                            for word in 0..words {
                                self.emit_parameter_register_load(X86_64Abi::SystemV, register)?;
                                self.emit_unpack_array_word(array, word)?;
                                pushed_slots += runtime_array_elements_in_word(array, word).ok_or(
                                    self.error(CodegenErrorKind::UnsupportedParameterType),
                                )?;
                                register += 1;
                            }
                        } else {
                            for word in 0..words {
                                let original = stack_offset
                                    .checked_add(word * 8)
                                    .ok_or(self.error(CodegenErrorKind::TooManyAbiParameters))?;
                                self.emit_original_stack_word_load(original, pushed_slots)?;
                                self.emit_unpack_array_word(array, word)?;
                                pushed_slots += runtime_array_elements_in_word(array, word).ok_or(
                                    self.error(CodegenErrorKind::UnsupportedParameterType),
                                )?;
                            }
                            stack_offset = stack_offset
                                .checked_add(words * 8)
                                .ok_or(self.error(CodegenErrorKind::TooManyAbiParameters))?;
                        }
                    } else if register < 6 {
                        self.emit(
                            parameter_push_encoding(X86_64Abi::SystemV, register)
                                .ok_or(self.error(CodegenErrorKind::TooManyAbiParameters))?,
                        )?;
                        register += 1;
                        pushed_slots += 1;
                    } else {
                        self.emit_original_stack_word_push(stack_offset, pushed_slots)?;
                        pushed_slots += 1;
                        stack_offset = stack_offset
                            .checked_add(8)
                            .ok_or(self.error(CodegenErrorKind::TooManyAbiParameters))?;
                    }
                }
            }
        }
        Ok(())
    }

    fn emit_windows_parameter_word(
        &mut self,
        index: usize,
        pushed_slots: usize,
    ) -> Result<(), CodegenError> {
        if let Some(encoding) = parameter_push_encoding(X86_64Abi::Windows, index) {
            self.emit(encoding)
        } else {
            let original = 40usize
                .checked_add((index - 4) * 8)
                .ok_or(self.error(CodegenErrorKind::TooManyAbiParameters))?;
            self.emit_original_stack_word_push(original, pushed_slots)
        }
    }

    fn emit_parameter_register_or_stack_load(
        &mut self,
        abi: X86_64Abi,
        index: usize,
        first_stack_offset: usize,
        pushed_slots: usize,
    ) -> Result<(), CodegenError> {
        let register_count = match abi {
            X86_64Abi::Windows => 4,
            X86_64Abi::SystemV => 6,
        };
        if index < register_count {
            return self.emit_parameter_register_load(abi, index);
        }
        let original = first_stack_offset
            .checked_add((index - register_count) * 8)
            .ok_or(self.error(CodegenErrorKind::TooManyAbiParameters))?;
        self.emit_original_stack_word_load(original, pushed_slots)
    }

    fn emit_parameter_register_load(
        &mut self,
        abi: X86_64Abi,
        index: usize,
    ) -> Result<(), CodegenError> {
        let encoding: &[u8] = match (abi, index) {
            (X86_64Abi::Windows, 0) | (X86_64Abi::SystemV, 3) => &[0x48, 0x89, 0xc8],
            (X86_64Abi::Windows, 1) | (X86_64Abi::SystemV, 2) => &[0x48, 0x89, 0xd0],
            (X86_64Abi::Windows, 2) | (X86_64Abi::SystemV, 4) => &[0x4c, 0x89, 0xc0],
            (X86_64Abi::Windows, 3) | (X86_64Abi::SystemV, 5) => &[0x4c, 0x89, 0xc8],
            (X86_64Abi::SystemV, 0) => &[0x48, 0x89, 0xf8],
            (X86_64Abi::SystemV, 1) => &[0x48, 0x89, 0xf0],
            _ => return Err(self.error(CodegenErrorKind::TooManyAbiParameters)),
        };
        self.emit(encoding)
    }

    fn emit_unpack_array_word(
        &mut self,
        array: RuntimeExpressionType,
        word: usize,
    ) -> Result<(), CodegenError> {
        let RuntimeExpressionType::Array { element, count } = array else {
            return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
        };
        let element_bytes = runtime_array_element_bytes(element)
            .ok_or(self.error(CodegenErrorKind::UnsupportedParameterType))?;
        for index in 0..count {
            let byte_offset = index * element_bytes;
            if byte_offset / 8 != word {
                continue;
            }
            self.emit(&[0x49, 0x89, 0xc2])?;
            let shift = ((byte_offset % 8) * 8) as u8;
            if shift != 0 {
                self.emit(&[0x49, 0xc1, 0xea, shift])?;
            }
            match element_bytes {
                1 => self.emit(&[0x45, 0x0f, 0xb6, 0xd2])?,
                2 => self.emit(&[0x45, 0x0f, 0xb7, 0xd2])?,
                4 | 8 => {}
                _ => return Err(self.error(CodegenErrorKind::UnsupportedParameterType)),
            }
            self.emit(&[0x41, 0x52])?;
        }
        Ok(())
    }

    fn emit_zero_array_slots(&mut self, count: usize) -> Result<(), CodegenError> {
        if count != 0 {
            self.emit(&[0x31, 0xc0])?;
        }
        for _ in 0..count {
            self.emit(&[0x50])?;
        }
        Ok(())
    }

    fn emit_compact_pointer_array_pushes(
        &mut self,
        array: RuntimeExpressionType,
    ) -> Result<(), CodegenError> {
        let RuntimeExpressionType::Array { element, count } = array else {
            return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
        };
        let element_bytes = runtime_array_element_bytes(element)
            .ok_or(self.error(CodegenErrorKind::UnsupportedParameterType))?;
        for index in 0..count {
            let displacement = u8::try_from(index * element_bytes)
                .map_err(|_| self.error(CodegenErrorKind::TooManyAbiParameters))?;
            match element_bytes {
                1 => self.emit(&[0x44, 0x0f, 0xb6, 0x50, displacement])?,
                2 => self.emit(&[0x44, 0x0f, 0xb7, 0x50, displacement])?,
                4 => self.emit(&[0x44, 0x8b, 0x50, displacement])?,
                8 if displacement == 0 => self.emit(&[0x4c, 0x8b, 0x10])?,
                8 => self.emit(&[0x4c, 0x8b, 0x50, displacement])?,
                _ => return Err(self.error(CodegenErrorKind::UnsupportedParameterType)),
            }
            self.emit(&[0x41, 0x52])?;
        }
        Ok(())
    }

    fn emit_windows_parameter_pointer(
        &mut self,
        index: usize,
        pushed_slots: usize,
    ) -> Result<(), CodegenError> {
        match index {
            0 => self.emit(&[0x48, 0x89, 0xc8]),
            1 => self.emit(&[0x48, 0x89, 0xd0]),
            2 => self.emit(&[0x4c, 0x89, 0xc0]),
            3 => self.emit(&[0x4c, 0x89, 0xc8]),
            _ => {
                let original = 40usize
                    .checked_add((index - 4) * 8)
                    .ok_or(self.error(CodegenErrorKind::TooManyAbiParameters))?;
                self.emit_original_stack_word_load(original, pushed_slots)
            }
        }
    }

    fn emit_original_stack_word_push(
        &mut self,
        original_offset: usize,
        pushed_slots: usize,
    ) -> Result<(), CodegenError> {
        self.emit_original_stack_word_load(original_offset, pushed_slots)?;
        self.emit(&[0x50])
    }

    fn emit_original_stack_word_load(
        &mut self,
        original_offset: usize,
        pushed_slots: usize,
    ) -> Result<(), CodegenError> {
        let current_stack_delta = pushed_slots
            .checked_mul(8)
            .ok_or(self.error(CodegenErrorKind::TooManyAbiParameters))?;
        let displacement = original_offset
            .checked_add(current_stack_delta)
            .ok_or(self.error(CodegenErrorKind::TooManyAbiParameters))?;
        if displacement <= i8::MAX as usize {
            self.emit(&[0x48, 0x8b, 0x44, 0x24, displacement as u8])?;
        } else {
            let displacement = u32::try_from(displacement)
                .map_err(|_| self.error(CodegenErrorKind::TooManyAbiParameters))?;
            self.emit(&[0x48, 0x8b, 0x84, 0x24])?;
            self.emit(&displacement.to_le_bytes())?;
        }
        Ok(())
    }

    fn emit_epilogue(&mut self) -> Result<(), CodegenError> {
        let bytes = self
            .saved_parameter_slots
            .checked_add(self.local_stack_slots()?)
            .ok_or(self.error(CodegenErrorKind::OutputTooSmall))?
            .checked_mul(8)
            .ok_or(self.error(CodegenErrorKind::OutputTooSmall))?;
        if bytes != 0 {
            if bytes <= i8::MAX as usize {
                self.emit(&[0x48, 0x83, 0xc4, bytes as u8])?;
            } else {
                let bytes = u32::try_from(bytes)
                    .map_err(|_| self.error(CodegenErrorKind::TooManyAbiParameters))?;
                self.emit(&[0x48, 0x81, 0xc4])?;
                self.emit(&bytes.to_le_bytes())?;
            }
        }
        self.emit(&[0xc3])
    }

    fn emit_stack_cleanup_bytes(&mut self, bytes: usize) -> Result<(), CodegenError> {
        if bytes == 0 {
            return Ok(());
        }
        if bytes <= i8::MAX as usize {
            self.emit(&[0x48, 0x83, 0xc4, bytes as u8])
        } else {
            let bytes =
                u32::try_from(bytes).map_err(|_| self.error(CodegenErrorKind::OutputTooSmall))?;
            self.emit(&[0x48, 0x81, 0xc4])?;
            self.emit(&bytes.to_le_bytes())
        }
    }

    fn emit_trap_branch(&mut self, opcode: u8) -> Result<(), CodegenError> {
        self.emit(&[0x0f, opcode, 0, 0, 0, 0])?;
        let patch = self.length - 4;
        let capacity_error = self.error(CodegenErrorKind::OutputTooSmall);
        let slot = self
            .trap_patches
            .get_mut(self.trap_count)
            .ok_or(capacity_error)?;
        *slot = patch;
        self.trap_count += 1;
        Ok(())
    }

    fn validate_runtime_access_fact(
        &self,
        fact: RuntimePlaceAccessFact,
    ) -> Result<(), CodegenError> {
        if fact.span.end < fact.span.start
            || !runtime_place_projections_valid(fact.ty, fact.projections)
        {
            return Err(self.error(CodegenErrorKind::InvalidRuntimePlaceFacts));
        }
        match fact.base {
            RuntimePlaceIdentity::Local(id) => {
                let local = self
                    .body_facts
                    .locals
                    .get(id.0)
                    .and_then(|fact| *fact)
                    .ok_or(self.error(CodegenErrorKind::InvalidRuntimePlaceFacts))?;
                if local.id != id || local.ty != fact.ty {
                    return Err(self.error(CodegenErrorKind::InvalidRuntimePlaceFacts));
                }
                let mutates_binding = !matches!(
                    (fact.projections.items[0], fact.ty),
                    (
                        Some(RuntimePlaceProjection::Dereference),
                        RuntimeExpressionType::Reference { .. }
                            | RuntimeExpressionType::RawPointer { .. }
                    ) | (
                        Some(RuntimePlaceProjection::Index),
                        RuntimeExpressionType::Reference { .. }
                    )
                );
                if fact.access != RuntimePlaceAccess::Read
                    && mutates_binding
                    && !local.mutable
                    && (local.initialized || fact.access != RuntimePlaceAccess::Write)
                {
                    return Err(self.error(CodegenErrorKind::InvalidRuntimePlaceFacts));
                }
            }
            RuntimePlaceIdentity::Parameter(index) => {
                let parameter = self
                    .function
                    .parameters()
                    .get(index)
                    .and_then(|parameter| *parameter)
                    .ok_or(self.error(CodegenErrorKind::InvalidRuntimePlaceFacts))?;
                if runtime_type_from_text(parameter.ty.text) != Some(fact.ty) {
                    return Err(self.error(CodegenErrorKind::InvalidRuntimePlaceFacts));
                }
            }
        }
        Ok(())
    }

    fn validate_runtime_place_facts(&self) -> Result<(), CodegenError> {
        if self.body_facts.ownership_statement_count > crate::parser::MAX_BODY_STATEMENTS {
            return Err(self.error(CodegenErrorKind::InvalidRuntimePlaceFacts));
        }
        if self.body_facts.ownership_statement_shapes[..self.body_facts.ownership_statement_count]
            .iter()
            .any(Option::is_none)
            || self.body_facts.ownership_statement_shapes
                [self.body_facts.ownership_statement_count..]
                .iter()
                .any(Option::is_some)
        {
            return Err(self.error(CodegenErrorKind::InvalidRuntimePlaceFacts));
        }
        if self.body_facts.conditional_expression_count
            > self.body_facts.conditional_expressions.len()
            || self.body_facts.conditional_expressions
                [..self.body_facts.conditional_expression_count]
                .iter()
                .any(Option::is_none)
            || self.body_facts.conditional_expressions
                [self.body_facts.conditional_expression_count..]
                .iter()
                .any(Option::is_some)
        {
            return Err(self.error(CodegenErrorKind::InvalidRuntimePlaceFacts));
        }
        if self.body_facts.expression_program_point_count
            > self.body_facts.expression_program_points.len()
            || self.body_facts.expression_program_points
                [..self.body_facts.expression_program_point_count]
                .iter()
                .any(Option::is_none)
            || self.body_facts.expression_program_points
                [self.body_facts.expression_program_point_count..]
                .iter()
                .any(Option::is_some)
        {
            return Err(self.error(CodegenErrorKind::InvalidRuntimePlaceFacts));
        }
        for (index, point) in self.body_facts.expression_program_points
            [..self.body_facts.expression_program_point_count]
            .iter()
            .flatten()
            .enumerate()
        {
            let conditional = match point.kind {
                RuntimeExpressionProgramPointKind::Root => None,
                RuntimeExpressionProgramPointKind::Condition(conditional)
                | RuntimeExpressionProgramPointKind::Then(conditional)
                | RuntimeExpressionProgramPointKind::Else(conditional)
                | RuntimeExpressionProgramPointKind::Join(conditional) => Some(conditional),
            };
            if point.id != RuntimeExpressionProgramPointId(index)
                || !self.body_facts.ownership_location_is_valid(point.location)
                || self.body_facts.control_flow_complete
                    && self
                        .body_facts
                        .ownership_control_point(point.location)
                        .is_none()
                || conditional.is_some_and(|conditional| {
                    conditional.0 >= self.body_facts.conditional_expression_count
                })
            {
                return Err(self.error(CodegenErrorKind::InvalidRuntimePlaceFacts));
            }
        }
        for (index, fact) in self.body_facts.conditional_expressions
            [..self.body_facts.conditional_expression_count]
            .iter()
            .flatten()
            .enumerate()
        {
            if fact.id != RuntimeConditionalExpressionId(index)
                || fact.span.end < fact.span.start
                || !self.body_facts.ownership_location_is_valid(fact.location)
                || fact.parent.is_some_and(|parent| parent.0 >= fact.id.0)
                || !self.body_facts.expression_origin_is_valid(
                    fact.location,
                    fact.parent_path,
                    fact.parent,
                )
                || fact.entry.0 >= self.body_facts.expression_program_point_count
                || fact.condition.0 >= self.body_facts.expression_program_point_count
                || fact.then_branch.0 >= self.body_facts.expression_program_point_count
                || fact.else_branch.0 >= self.body_facts.expression_program_point_count
                || fact.join.0 >= self.body_facts.expression_program_point_count
                || fact
                    .then_exit
                    .is_none_or(|point| point.0 >= self.body_facts.expression_program_point_count)
                || fact
                    .else_exit
                    .is_none_or(|point| point.0 >= self.body_facts.expression_program_point_count)
                || fact.condition.0 <= fact.entry.0
                || fact.then_branch.0 != fact.condition.0 + 1
                || fact.else_branch.0 != fact.then_branch.0 + 1
                || fact.join.0 != fact.else_branch.0 + 1
            {
                return Err(self.error(CodegenErrorKind::InvalidRuntimePlaceFacts));
            }
            let expected_points = [
                (
                    fact.condition,
                    RuntimeExpressionProgramPointKind::Condition(fact.id),
                ),
                (
                    fact.then_branch,
                    RuntimeExpressionProgramPointKind::Then(fact.id),
                ),
                (
                    fact.else_branch,
                    RuntimeExpressionProgramPointKind::Else(fact.id),
                ),
                (fact.join, RuntimeExpressionProgramPointKind::Join(fact.id)),
            ];
            if expected_points.iter().any(|(id, kind)| {
                self.body_facts.expression_program_points[id.0]
                    .is_none_or(|point| point.location != fact.location || point.kind != *kind)
            }) || self.body_facts.expression_program_points[fact.entry.0]
                .is_none_or(|point| point.location != fact.location)
            {
                return Err(self.error(CodegenErrorKind::InvalidRuntimePlaceFacts));
            }
        }
        let expected_expression_edge_count = self
            .body_facts
            .conditional_expression_count
            .checked_mul(5)
            .ok_or(self.error(CodegenErrorKind::InvalidRuntimeControlFlowFacts))?;
        if self.body_facts.expression_control_flow_edge_count != expected_expression_edge_count
            || self.body_facts.expression_control_flow_edge_count
                > self.body_facts.expression_control_flow_edges.len()
            || self.body_facts.expression_control_flow_edges
                [..self.body_facts.expression_control_flow_edge_count]
                .iter()
                .any(Option::is_none)
            || self.body_facts.expression_control_flow_edges
                [self.body_facts.expression_control_flow_edge_count..]
                .iter()
                .any(Option::is_some)
        {
            return Err(self.error(CodegenErrorKind::InvalidRuntimeControlFlowFacts));
        }
        for index in 0..self.body_facts.conditional_expression_count {
            let conditional = self.body_facts.conditional_expressions[index]
                .ok_or(self.error(CodegenErrorKind::InvalidRuntimeControlFlowFacts))?;
            let expected = [
                RuntimeExpressionControlFlowEdgeFact {
                    from: conditional.entry,
                    to: conditional.condition,
                },
                RuntimeExpressionControlFlowEdgeFact {
                    from: conditional.condition,
                    to: conditional.then_branch,
                },
                RuntimeExpressionControlFlowEdgeFact {
                    from: conditional.condition,
                    to: conditional.else_branch,
                },
                RuntimeExpressionControlFlowEdgeFact {
                    from: conditional
                        .then_exit
                        .ok_or(self.error(CodegenErrorKind::InvalidRuntimeControlFlowFacts))?,
                    to: conditional.join,
                },
                RuntimeExpressionControlFlowEdgeFact {
                    from: conditional
                        .else_exit
                        .ok_or(self.error(CodegenErrorKind::InvalidRuntimeControlFlowFacts))?,
                    to: conditional.join,
                },
            ];
            let first = index * 5;
            for (offset, edge) in expected.iter().enumerate() {
                if self.body_facts.expression_control_flow_edges[first + offset] != Some(*edge) {
                    return Err(self.error(CodegenErrorKind::InvalidRuntimeControlFlowFacts));
                }
            }
        }
        if self.preanalyzed_local_cursor != self.preanalyzed_local_count
            || self.preanalyzed_local_count > self.body_facts.local_count
            || self.preanalyzed_assignment_access_cursor != self.body_facts.assignment_access_count
            || self.preanalyzed_assignment_read_cursor != self.body_facts.assignment_read_count
        {
            return Err(self.error(CodegenErrorKind::InvalidRuntimePlaceFacts));
        }
        for (index, fact) in self.body_facts.locals[..self.body_facts.local_count]
            .iter()
            .enumerate()
        {
            let fact = fact.ok_or(self.error(CodegenErrorKind::InvalidRuntimePlaceFacts))?;
            if fact.id != RuntimeLocalId(index)
                || fact.name.is_empty()
                || fact
                    .declaration_span
                    .is_some_and(|span| span.end < span.start)
            {
                return Err(self.error(CodegenErrorKind::InvalidRuntimePlaceFacts));
            }
        }
        let parameter_count = self.function.parameters().iter().flatten().count();
        let required_root_count = parameter_count
            .checked_add(self.body_facts.local_count)
            .ok_or(self.error(CodegenErrorKind::InvalidRuntimePlaceFacts))?;
        if self.body_facts.initialization_count > required_root_count
            || self.body_facts.move_path_count < required_root_count
            || self.body_facts.move_paths[..self.body_facts.move_path_count]
                .iter()
                .any(Option::is_none)
            || self.body_facts.initializations[..self.body_facts.initialization_count]
                .iter()
                .any(Option::is_none)
        {
            return Err(self.error(CodegenErrorKind::InvalidRuntimePlaceFacts));
        }
        let mut path_index = 0usize;
        for root_index in 0..required_root_count {
            let root = self.body_facts.move_paths[path_index]
                .ok_or(self.error(CodegenErrorKind::InvalidRuntimePlaceFacts))?;
            let (expected_base, expected_type, expected_origin, expected_span, initialized) =
                if root_index < parameter_count {
                    let parameter = self
                        .function
                        .parameters()
                        .get(root_index)
                        .and_then(|parameter| *parameter)
                        .ok_or(self.error(CodegenErrorKind::InvalidRuntimePlaceFacts))?;
                    (
                        RuntimePlaceIdentity::Parameter(root_index),
                        runtime_type_from_text(parameter.ty.text)
                            .ok_or(self.error(CodegenErrorKind::InvalidRuntimePlaceFacts))?,
                        RuntimeInitializationOrigin::Parameter,
                        Some(parameter.span),
                        true,
                    )
                } else {
                    let id = RuntimeLocalId(root_index - parameter_count);
                    let local = self
                        .body_facts
                        .locals
                        .get(id.0)
                        .and_then(|fact| *fact)
                        .ok_or(self.error(CodegenErrorKind::InvalidRuntimePlaceFacts))?;
                    (
                        RuntimePlaceIdentity::Local(id),
                        local.ty,
                        RuntimeInitializationOrigin::LocalDeclaration,
                        local.declaration_span,
                        local.initialized,
                    )
                };
            let initialization = self.body_facts.initializations
                [..self.body_facts.initialization_count]
                .iter()
                .flatten()
                .find(|initialization| initialization.path == root.id)
                .copied();
            if root.id != RuntimeMovePathId(path_index)
                || root.parent.is_some()
                || root.base != expected_base
                || root.projections != RuntimePlaceProjections::EMPTY
                || root.ty != expected_type
                || initialization.is_some() != initialized
            {
                return Err(self.error(CodegenErrorKind::InvalidRuntimePlaceFacts));
            }
            if let Some(initialization) = initialization
                && (initialization.origin != expected_origin
                    || initialization.span != expected_span
                    || !self.body_facts.expression_origin_is_valid(
                        initialization.location,
                        initialization.expression_path,
                        initialization.expression_conditional,
                    )
                    || initialization.expression_point.is_some_and(|point| {
                        !self
                            .body_facts
                            .expression_program_point_is_valid(initialization.location, point)
                    })
                    || (self.body_facts.control_flow_complete
                        && initialization.location
                            != RuntimeOwnershipEventLocation::EmissionExpansion
                        && self
                            .body_facts
                            .ownership_control_point(initialization.location)
                            .is_none())
                    || match initialization.origin {
                        RuntimeInitializationOrigin::Parameter => {
                            initialization.location != RuntimeOwnershipEventLocation::ParameterEntry
                                || initialization.expression_point.is_some()
                        }
                        RuntimeInitializationOrigin::LocalDeclaration => {
                            !self
                                .body_facts
                                .ownership_location_is_valid(initialization.location)
                                || matches!(
                                    initialization.location,
                                    RuntimeOwnershipEventLocation::ParameterEntry
                                        | RuntimeOwnershipEventLocation::Tail
                                        | RuntimeOwnershipEventLocation::Unassigned
                                )
                        }
                    }
                    || initialization
                        .span
                        .is_some_and(|span| span.end < span.start))
            {
                return Err(self.error(CodegenErrorKind::InvalidRuntimePlaceFacts));
            }
            path_index = path_index
                .checked_add(1)
                .ok_or(self.error(CodegenErrorKind::InvalidRuntimePlaceFacts))?;
            let (elements, element_count) = match root.ty {
                RuntimeExpressionType::Tuple {
                    elements,
                    element_count,
                } => (elements, element_count),
                _ => ([None; crate::expression::MAX_TUPLE_ELEMENTS], 0),
            };
            if element_count > elements.len() {
                return Err(self.error(CodegenErrorKind::InvalidRuntimePlaceFacts));
            }
            for (field, element) in elements[..element_count].iter().enumerate() {
                let element =
                    element.ok_or(self.error(CodegenErrorKind::InvalidRuntimePlaceFacts))?;
                let child = self
                    .body_facts
                    .move_paths
                    .get(path_index)
                    .and_then(|path| *path)
                    .ok_or(self.error(CodegenErrorKind::InvalidRuntimePlaceFacts))?;
                if child.id != RuntimeMovePathId(path_index)
                    || child.parent != Some(root.id)
                    || child.base != root.base
                    || child.projections
                        != RuntimePlaceProjections::single(RuntimePlaceProjection::TupleField(
                            field,
                        ))
                    || child.ty != runtime_type_from_tuple_element(element)
                {
                    return Err(self.error(CodegenErrorKind::InvalidRuntimePlaceFacts));
                }
                path_index = path_index
                    .checked_add(1)
                    .ok_or(self.error(CodegenErrorKind::InvalidRuntimePlaceFacts))?;
            }
        }
        if path_index != self.body_facts.move_path_count {
            return Err(self.error(CodegenErrorKind::InvalidRuntimePlaceFacts));
        }
        if self.body_facts.effect_count > self.body_facts.effects.len()
            || self.body_facts.effects[..self.body_facts.effect_count]
                .iter()
                .any(Option::is_none)
        {
            return Err(self.error(CodegenErrorKind::InvalidRuntimePlaceFacts));
        }
        let expected_event_count = self
            .body_facts
            .initialization_count
            .checked_add(self.body_facts.effect_count)
            .ok_or(self.error(CodegenErrorKind::InvalidRuntimePlaceFacts))?;
        if expected_event_count != self.body_facts.ownership_event_count
            || expected_event_count > MAX_RUNTIME_OWNERSHIP_EVENT_FACTS
        {
            return Err(self.error(CodegenErrorKind::InvalidRuntimePlaceFacts));
        }
        let mut initialization_index = 0usize;
        let mut effect_index = 0usize;
        for expected_event in 0..expected_event_count {
            let initialization_event = self
                .body_facts
                .initializations
                .get(initialization_index)
                .and_then(|fact| *fact)
                .map(|fact| fact.event.0);
            let effect_event = self
                .body_facts
                .effects
                .get(effect_index)
                .and_then(|fact| *fact)
                .map(|fact| fact.event.0);
            match (initialization_event, effect_event) {
                (Some(initialization), Some(effect)) if initialization == effect => {
                    return Err(self.error(CodegenErrorKind::InvalidRuntimePlaceFacts));
                }
                (Some(initialization), Some(effect)) if initialization < effect => {
                    if initialization != expected_event {
                        return Err(self.error(CodegenErrorKind::InvalidRuntimePlaceFacts));
                    }
                    initialization_index += 1;
                }
                (Some(_), Some(effect)) | (None, Some(effect)) => {
                    if effect != expected_event {
                        return Err(self.error(CodegenErrorKind::InvalidRuntimePlaceFacts));
                    }
                    effect_index += 1;
                }
                (Some(initialization), None) => {
                    if initialization != expected_event {
                        return Err(self.error(CodegenErrorKind::InvalidRuntimePlaceFacts));
                    }
                    initialization_index += 1;
                }
                (None, None) => {
                    return Err(self.error(CodegenErrorKind::InvalidRuntimePlaceFacts));
                }
            }
        }
        if initialization_index != self.body_facts.initialization_count
            || effect_index != self.body_facts.effect_count
        {
            return Err(self.error(CodegenErrorKind::InvalidRuntimePlaceFacts));
        }
        for (effect_index, effect) in self.body_facts.effects[..self.body_facts.effect_count]
            .iter()
            .enumerate()
            .filter_map(|(index, effect)| effect.map(|effect| (index, effect)))
        {
            let path = self
                .body_facts
                .move_paths
                .get(effect.path.0)
                .and_then(|path| *path)
                .ok_or(self.error(CodegenErrorKind::InvalidRuntimePlaceFacts))?;
            if path.id != effect.path
                || effect.span.end < effect.span.start
                || !self.body_facts.expression_origin_is_valid(
                    effect.location,
                    effect.expression_path,
                    effect.expression_conditional,
                )
                || effect.expression_point.is_some_and(|point| {
                    !self
                        .body_facts
                        .expression_program_point_is_valid(effect.location, point)
                })
                || (effect.loan_generation_borrower.is_some()
                    && self
                        .body_facts
                        .direct_expression_loan_fact(effect_index)
                        .is_none())
                || !self.body_facts.ownership_location_is_valid(effect.location)
                || (self.body_facts.control_flow_complete
                    && effect.location != RuntimeOwnershipEventLocation::EmissionExpansion
                    && self
                        .body_facts
                        .ownership_control_point(effect.location)
                        .is_none())
                || effect.location == RuntimeOwnershipEventLocation::ParameterEntry
                || match effect.kind {
                    RuntimePlaceEffectKind::Copy => !runtime_type_is_copy(path.ty),
                    RuntimePlaceEffectKind::Move => runtime_type_is_copy(path.ty),
                    RuntimePlaceEffectKind::SharedBorrow
                    | RuntimePlaceEffectKind::MutableBorrow => false,
                    RuntimePlaceEffectKind::LoanUse => {
                        !matches!(path.ty, RuntimeExpressionType::Reference { .. })
                            || match path.base {
                                RuntimePlaceIdentity::Local(borrower) => self
                                    .body_facts
                                    .direct_loan_for_borrower_before(borrower, effect.event)
                                    .is_none(),
                                RuntimePlaceIdentity::Parameter(_) => true,
                            }
                    }
                    RuntimePlaceEffectKind::LoanMutation => {
                        !matches!(
                            path.ty,
                            RuntimeExpressionType::Reference { mutable: true, .. }
                        ) || match path.base {
                            RuntimePlaceIdentity::Local(borrower) => self
                                .body_facts
                                .direct_loan_for_borrower_before(borrower, effect.event)
                                .is_none(),
                            RuntimePlaceIdentity::Parameter(_) => false,
                        }
                    }
                    RuntimePlaceEffectKind::Write => false,
                    RuntimePlaceEffectKind::ReadModifyWrite => !runtime_type_is_copy(path.ty),
                }
            {
                return Err(self.error(CodegenErrorKind::InvalidRuntimePlaceFacts));
            }
        }
        if self.body_facts.assignment_accesses[..self.body_facts.assignment_access_count]
            .iter()
            .any(Option::is_none)
        {
            return Err(self.error(CodegenErrorKind::InvalidRuntimePlaceFacts));
        }
        for fact in self.body_facts.assignment_accesses[..self.body_facts.assignment_access_count]
            .iter()
            .flatten()
        {
            if fact.access == RuntimePlaceAccess::Read {
                return Err(self.error(CodegenErrorKind::InvalidRuntimePlaceFacts));
            }
            self.validate_runtime_access_fact(*fact)?;
        }
        if self.body_facts.assignment_reads[..self.body_facts.assignment_read_count]
            .iter()
            .any(Option::is_none)
        {
            return Err(self.error(CodegenErrorKind::InvalidRuntimePlaceFacts));
        }
        for fact in self.body_facts.assignment_reads[..self.body_facts.assignment_read_count]
            .iter()
            .flatten()
        {
            if fact.access != RuntimePlaceAccess::Read {
                return Err(self.error(CodegenErrorKind::InvalidRuntimePlaceFacts));
            }
            self.validate_runtime_access_fact(*fact)?;
        }
        for fact in self.body_facts.accesses[..self.body_facts.access_count]
            .iter()
            .flatten()
        {
            self.validate_runtime_access_fact(*fact)?;
        }
        if self.body_facts.accesses[..self.body_facts.access_count]
            .iter()
            .any(Option::is_none)
        {
            return Err(self.error(CodegenErrorKind::InvalidRuntimePlaceFacts));
        }
        Ok(())
    }

    fn finish(mut self) -> Result<X86_64RuntimeMachineCode<MAX_BYTES>, CodegenError> {
        self.validate_runtime_place_facts()?;
        if self.trap_count != 0 {
            let trap = self.length;
            self.emit(&[0x0f, 0x0b])?;
            for index in 0..self.trap_count {
                let patch = self.trap_patches[index];
                let displacement = trap as isize - (patch + 4) as isize;
                let displacement = i32::try_from(displacement)
                    .map_err(|_| self.error(CodegenErrorKind::OutputTooSmall))?;
                self.bytes[patch..patch + 4].copy_from_slice(&displacement.to_le_bytes());
            }
        }
        Ok(X86_64RuntimeMachineCode {
            code: MachineCode {
                bytes: self.bytes,
                length: self.length,
            },
            readonly_data: self.readonly_data,
            readonly_data_length: self.readonly_data_length,
            readonly_relocations: self.readonly_relocations,
            readonly_relocation_count: self.readonly_relocation_count,
        })
    }

    fn emit_expression<const MAX_NODES: usize>(
        &mut self,
        tree: &crate::ExpressionTree<'_, MAX_NODES>,
        id: crate::ExprId,
        depth: usize,
    ) -> Result<(), CodegenError> {
        let previous_width = self.width;
        let expression_type = runtime_expression_type_with_locals(
            self.function,
            self.resolver,
            &self.locals[..self.saved_locals],
            tree,
            id,
            depth,
        )
        .map_err(|kind| self.error(kind))?;
        let operation_type = if expression_type == RuntimeExpressionType::Bool {
            match tree.expression(id).map(|expression| expression.kind) {
                Some(ExprKind::Binary { left, .. }) => runtime_expression_type_with_locals(
                    self.function,
                    self.resolver,
                    &self.locals[..self.saved_locals],
                    tree,
                    left,
                    depth + 1,
                )
                .map_err(|kind| self.error(kind))?,
                _ => expression_type,
            }
        } else {
            expression_type
        };
        if let RuntimeExpressionType::Integer(Some(integer_type)) = operation_type {
            self.width = runtime_width(integer_type.name())
                .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
        } else if operation_type == RuntimeExpressionType::Char {
            self.width = runtime_width("char")
                .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
        }
        let result = self.emit_expression_with_width(tree, id, depth);
        self.width = previous_width;
        result
    }

    fn emit_runtime_call<const MAX_NODES: usize>(
        &mut self,
        caller_tree: &crate::ExpressionTree<'_, MAX_NODES>,
        arguments: &[Option<crate::ExprId>],
        target: crate::RuntimeCallTarget<'tree, MAX_PARAMETERS>,
        depth: usize,
    ) -> Result<(), CodegenError> {
        const MAX_RUNTIME_CALL_DEPTH: usize = 8;
        if self.runtime_call_names[..self.runtime_call_depth]
            .iter()
            .flatten()
            .any(|name| *name == target.name)
        {
            return Err(self.error(CodegenErrorKind::RuntimeExpressionUnsupported));
        }
        if self.runtime_call_depth == MAX_RUNTIME_CALL_DEPTH
            || target.parameter_count > MAX_PARAMETERS - self.saved_locals
        {
            return Err(self.error(CodegenErrorKind::TooManyRuntimeLocals));
        }
        let checkpoint = self.saved_locals;
        let mut argument_slots = 0usize;
        for (parameter, argument) in target.parameters[..target.parameter_count]
            .iter()
            .zip(arguments.iter())
        {
            let parameter =
                parameter.ok_or(self.error(CodegenErrorKind::RuntimeExpressionUnsupported))?;
            let argument =
                argument.ok_or(self.error(CodegenErrorKind::RuntimeExpressionUnsupported))?;
            let expected = runtime_type_from_scalar(parameter.ty);
            let actual = runtime_expression_type_with_locals(
                self.function,
                self.resolver,
                &self.locals[..self.saved_locals],
                caller_tree,
                argument,
                depth,
            )
            .map_err(|kind| self.error(kind))?;
            if !runtime_types_compatible(actual, expected) {
                return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
            }
            let previous_width = self.width;
            if let Some(width) = runtime_expression_width(expected) {
                self.width = width;
            }
            let stack_slots = if let RuntimeExpressionType::Array { element, count } = expected {
                self.emit_array_to_stack(caller_tree, argument, count)?;
                let stack_slots = self.pack_temporary_array_for_local(element, count)?;
                self.evaluation_depth -= stack_slots;
                stack_slots
            } else if let RuntimeExpressionType::Tuple { element_count, .. } = expected {
                self.emit_tuple_to_stack(caller_tree, argument, expected)?;
                self.evaluation_depth -= element_count;
                element_count
            } else if runtime_type_is_fat_reference(expected) {
                self.emit_slice_value_to_stack(caller_tree, argument, depth)?;
                2
            } else {
                self.emit_expression(caller_tree, argument, depth)?;
                self.emit(&[0x50])?;
                1
            };
            self.width = previous_width;
            self.evaluation_depth += stack_slots;
            argument_slots = argument_slots
                .checked_add(stack_slots)
                .ok_or(self.error(CodegenErrorKind::OutputTooSmall))?;
        }
        for parameter in target.parameters[..target.parameter_count].iter().flatten() {
            let ty = runtime_type_from_scalar(parameter.ty);
            self.push_runtime_local(
                parameter.name,
                ty,
                false,
                true,
                runtime_local_stack_slots(ty),
                None,
            )?;
        }
        self.evaluation_depth -= argument_slots;
        let body =
            crate::parser::parse_function_body::<MAX_PARAMETERS, MAX_NODES>(target.body_expression)
                .map_err(|error| self.error(CodegenErrorKind::Body(error.kind)))?;
        let return_type = runtime_type_from_scalar(target.return_type);
        let return_type_name = target.return_type_name;
        let previous_width = self.width;
        if let Some(width) = runtime_expression_width(return_type) {
            self.width = width;
        }
        let previous_floor = self.runtime_call_local_floor;
        self.runtime_call_local_floor = Some(checkpoint);
        self.runtime_call_names[self.runtime_call_depth] = Some(target.name);
        self.runtime_call_depth += 1;
        let body_start = self.function.body_expression_span.start;
        let mut return_patches = [None; MAX_BYTES];
        let mut return_count = 0usize;
        let mut tail_unreachable = false;
        let emission = (|| {
            for statement in body.statements().iter().flatten() {
                match statement {
                    crate::BodyStatement::Local(index) => {
                        let local = body.locals()[*index]
                            .ok_or(self.error(CodegenErrorKind::RuntimeExpressionUnsupported))?;
                        self.emit_local::<MAX_NODES>(&local, return_type_name, body_start)?;
                    }
                    crate::BodyStatement::Assignment(index) => {
                        let assignment = body.assignments()[*index]
                            .ok_or(self.error(CodegenErrorKind::RuntimeExpressionUnsupported))?;
                        self.emit_assignment::<MAX_NODES>(&assignment, body_start)?;
                    }
                    crate::BodyStatement::Expression(index) => {
                        let statement = body.expression_statements()[*index]
                            .ok_or(self.error(CodegenErrorKind::RuntimeExpressionUnsupported))?;
                        self.emit_expression_statement::<MAX_NODES>(&statement, body_start)?;
                    }
                    crate::BodyStatement::ConditionalReturn(index) => {
                        let conditional = body.conditional_returns()[*index]
                            .ok_or(self.error(CodegenErrorKind::RuntimeExpressionUnsupported))?;
                        *return_patches
                            .get_mut(return_count)
                            .ok_or(self.error(CodegenErrorKind::OutputTooSmall))? =
                            Some(self.emit_inline_conditional_return::<MAX_NODES>(
                                &conditional,
                                return_type,
                                checkpoint,
                                body_start,
                            )?);
                        return_count += 1;
                    }
                    crate::BodyStatement::ConditionalReturnElse(index) => {
                        let conditional = body.conditional_return_elses()[*index]
                            .ok_or(self.error(CodegenErrorKind::RuntimeExpressionUnsupported))?;
                        for branch in conditional.branches().iter().flatten() {
                            *return_patches
                                .get_mut(return_count)
                                .ok_or(self.error(CodegenErrorKind::OutputTooSmall))? =
                                Some(self.emit_inline_conditional_return::<MAX_NODES>(
                                    branch,
                                    return_type,
                                    checkpoint,
                                    body_start,
                                )?);
                            return_count += 1;
                        }
                        if let Some(else_value) = conditional.else_value.as_ref() {
                            *return_patches
                                .get_mut(return_count)
                                .ok_or(self.error(CodegenErrorKind::OutputTooSmall))? =
                                Some(self.emit_inline_return::<MAX_NODES>(
                                    else_value,
                                    return_type,
                                    checkpoint,
                                    body_start,
                                )?);
                            return_count += 1;
                            tail_unreachable = true;
                        }
                    }
                    crate::BodyStatement::Return(index) => {
                        let return_statement = body.returns()[*index]
                            .ok_or(self.error(CodegenErrorKind::RuntimeExpressionUnsupported))?;
                        *return_patches
                            .get_mut(return_count)
                            .ok_or(self.error(CodegenErrorKind::OutputTooSmall))? =
                            Some(self.emit_inline_return::<MAX_NODES>(
                                &return_statement,
                                return_type,
                                checkpoint,
                                body_start,
                            )?);
                        return_count += 1;
                        tail_unreachable = true;
                    }
                    crate::BodyStatement::ConditionalAssignment(index) => {
                        let conditional = body.conditional_assignments()[*index]
                            .ok_or(self.error(CodegenErrorKind::RuntimeExpressionUnsupported))?;
                        if self.emit_inline_conditional_actions::<MAX_NODES>(
                            &conditional,
                            return_type,
                            return_type_name,
                            checkpoint,
                            body_start,
                            &mut return_patches,
                            &mut return_count,
                        )? {
                            tail_unreachable = true;
                        }
                    }
                    crate::BodyStatement::Loop(index) => {
                        let loop_statement = body.while_loops()[*index]
                            .ok_or(self.error(CodegenErrorKind::RuntimeExpressionUnsupported))?;
                        self.emit_inline_while_loop::<MAX_NODES>(
                            &loop_statement,
                            return_type,
                            return_type_name,
                            checkpoint,
                            body_start,
                            &mut return_patches,
                            &mut return_count,
                        )?;
                    }
                }
            }
            if x86_64_body_tail_diverges(&body) && !tail_unreachable {
                tail_unreachable = true;
            }
            if tail_unreachable {
                return Ok(());
            }
            let tree = body
                .parse_tail::<MAX_NODES>()
                .map_err(|error| self.error(CodegenErrorKind::Expression(error.kind)))?;
            let actual = runtime_expression_type_with_locals(
                self.function,
                self.resolver,
                &self.locals[..self.saved_locals],
                &tree,
                tree.root(),
                depth,
            )
            .map_err(|kind| self.error(kind))?;
            if !runtime_types_compatible(actual, return_type) {
                return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
            }
            if runtime_type_is_fat_reference(return_type) {
                self.emit_inline_fat_value(&tree, tree.root(), depth)
            } else if runtime_type_is_array(return_type) {
                self.emit_inline_array_value(&tree, tree.root(), return_type, checkpoint)
            } else if runtime_type_is_tuple(return_type) {
                self.emit_inline_tuple_value(&tree, tree.root(), return_type, checkpoint)
            } else {
                self.emit_expression(&tree, tree.root(), depth)
            }
        })();
        self.runtime_call_depth -= 1;
        self.runtime_call_names[self.runtime_call_depth] = None;
        self.runtime_call_local_floor = previous_floor;
        emission?;
        if return_type == RuntimeExpressionType::Bool {
            self.emit(&[0x48, 0x85, 0xc0, 0x0f, 0x95, 0xc0, 0x0f, 0xb6, 0xc0])?;
        }
        if !tail_unreachable {
            if runtime_type_is_array(return_type) || runtime_type_is_tuple(return_type) {
                self.truncate_scoped_locals(checkpoint)?;
            } else {
                self.emit_scoped_local_cleanup(checkpoint)?;
            }
        } else {
            self.truncate_scoped_locals(checkpoint)?;
        }
        for patch in return_patches[..return_count].iter().flatten().copied() {
            self.patch_forward_branch(patch)?;
        }
        if tail_unreachable && return_count != 0 {
            match return_type {
                RuntimeExpressionType::Array { count, .. } => self.evaluation_depth += count,
                RuntimeExpressionType::Tuple { element_count, .. } => {
                    self.evaluation_depth += element_count;
                }
                _ => {}
            }
        }
        self.width = previous_width;
        Ok(())
    }

    fn emit_inline_return<const MAX_NODES: usize>(
        &mut self,
        return_statement: &crate::LoopReturn<'_>,
        expected_type: RuntimeExpressionType,
        checkpoint: usize,
        body_start: usize,
    ) -> Result<usize, CodegenError> {
        let tree = return_statement
            .parse_value::<MAX_NODES>()
            .map_err(|error| CodegenError {
                kind: CodegenErrorKind::Expression(error.kind),
                span: translate_span(body_start + return_statement.value_span.start, error.span),
            })?;
        let actual = runtime_expression_type_with_locals(
            self.function,
            self.resolver,
            &self.locals[..self.saved_locals],
            &tree,
            tree.root(),
            0,
        )
        .map_err(|kind| self.error(kind))?;
        if !runtime_types_compatible(actual, expected_type) {
            return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
        }
        if runtime_type_is_fat_reference(expected_type) {
            self.emit_inline_fat_value(&tree, tree.root(), 0)?;
        } else if runtime_type_is_array(expected_type) {
            let RuntimeExpressionType::Array { count, .. } = expected_type else {
                return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
            };
            self.emit_inline_array_value(&tree, tree.root(), expected_type, checkpoint)?;
            let branch = self.emit_unconditional_forward_branch()?;
            self.evaluation_depth -= count;
            return Ok(branch);
        } else if runtime_type_is_tuple(expected_type) {
            let RuntimeExpressionType::Tuple { element_count, .. } = expected_type else {
                return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
            };
            self.emit_inline_tuple_value(&tree, tree.root(), expected_type, checkpoint)?;
            let branch = self.emit_unconditional_forward_branch()?;
            self.evaluation_depth -= element_count;
            return Ok(branch);
        } else {
            self.emit_expression(&tree, tree.root(), 0)?;
        }
        if expected_type == RuntimeExpressionType::Bool {
            self.emit(&[0x48, 0x85, 0xc0, 0x0f, 0x95, 0xc0, 0x0f, 0xb6, 0xc0])?;
        }
        self.emit_stack_cleanup_to(checkpoint)?;
        self.emit_unconditional_forward_branch()
    }

    fn emit_inline_fat_value<const MAX_NODES: usize>(
        &mut self,
        tree: &crate::ExpressionTree<'_, MAX_NODES>,
        root: crate::ExprId,
        depth: usize,
    ) -> Result<(), CodegenError> {
        self.emit_slice_value_to_stack(tree, root, depth)?;
        self.emit_stack_slot(1)?;
        self.emit(&[0x48, 0x89, 0xc1])?;
        self.emit_stack_slot(0)?;
        self.emit(&[0x48, 0x89, 0xc2])?;
        self.emit_stack_cleanup_bytes(16)?;
        self.emit(&[0x48, 0x89, 0xc8])
    }

    fn emit_inline_array_value<const MAX_NODES: usize>(
        &mut self,
        tree: &crate::ExpressionTree<'_, MAX_NODES>,
        root: crate::ExprId,
        expected_type: RuntimeExpressionType,
        checkpoint: usize,
    ) -> Result<(), CodegenError> {
        let RuntimeExpressionType::Array { count, .. } = expected_type else {
            return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
        };
        self.emit_array_to_stack(tree, root, count)?;
        let frame_slots = self.local_stack_slots_from(checkpoint)?;
        if frame_slots != 0 {
            for index in (0..count).rev() {
                self.emit_stack_slot(index)?;
                let destination = frame_slots
                    .checked_add(index)
                    .ok_or(self.error(CodegenErrorKind::OutputTooSmall))?;
                self.emit_store_stack_slot(destination)?;
            }
            self.emit_stack_cleanup_bytes(
                frame_slots
                    .checked_mul(8)
                    .ok_or(self.error(CodegenErrorKind::OutputTooSmall))?,
            )?;
        }
        Ok(())
    }

    fn emit_inline_tuple_value<const MAX_NODES: usize>(
        &mut self,
        tree: &crate::ExpressionTree<'_, MAX_NODES>,
        root: crate::ExprId,
        expected_type: RuntimeExpressionType,
        checkpoint: usize,
    ) -> Result<(), CodegenError> {
        let RuntimeExpressionType::Tuple { element_count, .. } = expected_type else {
            return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
        };
        self.emit_tuple_to_stack(tree, root, expected_type)?;
        let frame_slots = self.local_stack_slots_from(checkpoint)?;
        if frame_slots != 0 {
            for index in (0..element_count).rev() {
                self.emit_stack_slot(index)?;
                let destination = frame_slots
                    .checked_add(index)
                    .ok_or(self.error(CodegenErrorKind::OutputTooSmall))?;
                self.emit_store_stack_slot(destination)?;
            }
            self.emit_stack_cleanup_bytes(
                frame_slots
                    .checked_mul(8)
                    .ok_or(self.error(CodegenErrorKind::OutputTooSmall))?,
            )?;
        }
        Ok(())
    }

    fn emit_inline_conditional_return<const MAX_NODES: usize>(
        &mut self,
        conditional: &crate::ConditionalReturn<'_>,
        expected_type: RuntimeExpressionType,
        checkpoint: usize,
        body_start: usize,
    ) -> Result<usize, CodegenError> {
        let condition = conditional
            .parse_condition::<MAX_NODES>()
            .map_err(|error| CodegenError {
                kind: CodegenErrorKind::Expression(error.kind),
                span: translate_span(body_start + conditional.condition_span.start, error.span),
            })?;
        let condition_type = runtime_expression_type_with_locals(
            self.function,
            self.resolver,
            &self.locals[..self.saved_locals],
            &condition,
            condition.root(),
            0,
        )
        .map_err(|kind| self.error(kind))?;
        if condition_type != RuntimeExpressionType::Bool {
            return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
        }
        self.emit_expression(&condition, condition.root(), 0)?;
        self.emit(&[0x48, 0x85, 0xc0])?;
        let skip = self.emit_forward_branch(0x84)?;
        let value = crate::LoopReturn {
            value: conditional.value,
            value_span: conditional.value_span,
        };
        let return_patch =
            self.emit_inline_return::<MAX_NODES>(&value, expected_type, checkpoint, body_start)?;
        self.patch_forward_branch(skip)?;
        Ok(return_patch)
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_inline_conditional_actions<const MAX_NODES: usize>(
        &mut self,
        conditional: &crate::ConditionalAssignment<'tree>,
        expected_type: RuntimeExpressionType,
        operand_type: &str,
        call_checkpoint: usize,
        body_start: usize,
        return_patches: &mut [Option<usize>],
        return_count: &mut usize,
    ) -> Result<bool, CodegenError> {
        let mut end_patches = [None; crate::MAX_CONDITIONAL_ASSIGNMENT_BRANCHES];
        let mut end_count = 0usize;
        let mut every_branch_returns = true;
        for branch in conditional.branches().iter().flatten() {
            let condition =
                branch
                    .parse_condition::<MAX_NODES>()
                    .map_err(|error| CodegenError {
                        kind: CodegenErrorKind::Expression(error.kind),
                        span: translate_span(body_start + branch.condition_span.start, error.span),
                    })?;
            let condition_type = runtime_expression_type_with_locals(
                self.function,
                self.resolver,
                &self.locals[..self.saved_locals],
                &condition,
                condition.root(),
                0,
            )
            .map_err(|kind| self.error(kind))?;
            if condition_type != RuntimeExpressionType::Bool {
                return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
            }
            self.emit_expression(&condition, condition.root(), 0)?;
            self.emit(&[0x48, 0x85, 0xc0])?;
            let false_branch = self.emit_forward_branch(0x84)?;
            let branch_checkpoint = self.saved_locals;
            let returned = self.emit_inline_conditional_action_list::<MAX_NODES>(
                branch.actions(),
                expected_type,
                operand_type,
                call_checkpoint,
                branch_checkpoint,
                body_start,
                return_patches,
                return_count,
            )?;
            every_branch_returns &= returned;
            if !returned {
                end_patches[end_count] = Some(self.emit_unconditional_forward_branch()?);
                end_count += 1;
            }
            self.patch_forward_branch(false_branch)?;
        }
        let else_checkpoint = self.saved_locals;
        let else_returns = self.emit_inline_conditional_action_list::<MAX_NODES>(
            conditional.else_actions(),
            expected_type,
            operand_type,
            call_checkpoint,
            else_checkpoint,
            body_start,
            return_patches,
            return_count,
        )?;
        for patch in end_patches[..end_count].iter().flatten().copied() {
            self.patch_forward_branch(patch)?;
        }
        Ok(every_branch_returns && else_returns)
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_inline_conditional_action_list<const MAX_NODES: usize>(
        &mut self,
        actions: &[Option<crate::ConditionalAssignmentAction<'tree>>],
        expected_type: RuntimeExpressionType,
        operand_type: &str,
        call_checkpoint: usize,
        branch_checkpoint: usize,
        body_start: usize,
        return_patches: &mut [Option<usize>],
        return_count: &mut usize,
    ) -> Result<bool, CodegenError> {
        for action in actions.iter().flatten() {
            match action {
                crate::ConditionalAssignmentAction::Local(local) => {
                    self.emit_local::<MAX_NODES>(local, operand_type, body_start)?;
                }
                crate::ConditionalAssignmentAction::Assignment(assignment) => {
                    self.emit_assignment::<MAX_NODES>(assignment, body_start)?;
                }
                crate::ConditionalAssignmentAction::Expression(statement) => {
                    self.emit_expression_statement::<MAX_NODES>(statement, body_start)?;
                }
                crate::ConditionalAssignmentAction::Return(return_statement) => {
                    let patch = self.emit_inline_return::<MAX_NODES>(
                        return_statement,
                        expected_type,
                        call_checkpoint,
                        body_start,
                    )?;
                    *return_patches
                        .get_mut(*return_count)
                        .ok_or(self.error(CodegenErrorKind::OutputTooSmall))? = Some(patch);
                    *return_count += 1;
                    self.truncate_scoped_locals(branch_checkpoint)?;
                    return Ok(true);
                }
            }
        }
        self.emit_scoped_local_cleanup(branch_checkpoint)?;
        Ok(false)
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_inline_while_loop<const MAX_NODES: usize>(
        &mut self,
        loop_statement: &crate::WhileLoop<'tree>,
        expected_type: RuntimeExpressionType,
        operand_type: &str,
        call_checkpoint: usize,
        body_start: usize,
        return_patches: &mut [Option<usize>],
        return_count: &mut usize,
    ) -> Result<(), CodegenError> {
        let condition = loop_statement
            .parse_condition::<MAX_NODES>()
            .map_err(|error| CodegenError {
                kind: CodegenErrorKind::Expression(error.kind),
                span: translate_span(body_start + loop_statement.condition_span.start, error.span),
            })?;
        if let Some(condition) = condition.as_ref() {
            let condition_type = runtime_expression_type_with_locals(
                self.function,
                self.resolver,
                &self.locals[..self.saved_locals],
                condition,
                condition.root(),
                0,
            )
            .map_err(|kind| self.error(kind))?;
            if condition_type != RuntimeExpressionType::Bool {
                return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
            }
        }
        let loop_start = self.length;
        let mut exit_patches =
            [None; 1 + crate::MAX_LOOP_OPERATIONS * (crate::MAX_CONDITIONAL_LOOP_ELSE_ARMS + 1)];
        let mut exit_count = 0usize;
        if let Some(condition) = condition.as_ref() {
            self.emit_expression(condition, condition.root(), 0)?;
            self.emit(&[0x48, 0x85, 0xc0])?;
            exit_patches[exit_count] = Some(self.emit_forward_branch(0x84)?);
            exit_count += 1;
        }
        let local_checkpoint = self.saved_locals;
        let mut terminated = false;
        for operation in loop_statement.operations().iter().flatten() {
            match operation {
                crate::LoopOperation::Local(local) => {
                    self.emit_local::<MAX_NODES>(local, operand_type, body_start)?;
                }
                crate::LoopOperation::Assignment(assignment) => {
                    self.emit_assignment::<MAX_NODES>(assignment, body_start)?;
                }
                crate::LoopOperation::Expression(statement) => {
                    self.emit_expression_statement::<MAX_NODES>(statement, body_start)?;
                }
                crate::LoopOperation::Break => {
                    self.emit_stack_cleanup_to(local_checkpoint)?;
                    exit_patches[exit_count] = Some(self.emit_unconditional_forward_branch()?);
                    exit_count += 1;
                    terminated = true;
                    break;
                }
                crate::LoopOperation::Continue => {
                    self.emit_stack_cleanup_to(local_checkpoint)?;
                    self.emit_backward_branch(loop_start)?;
                    terminated = true;
                    break;
                }
                crate::LoopOperation::ConditionalBreak(control) => {
                    let patch = self.emit_inline_conditional_loop_control::<MAX_NODES>(
                        control,
                        local_checkpoint,
                        loop_start,
                        true,
                        body_start,
                    )?;
                    exit_patches[exit_count] = patch;
                    exit_count += usize::from(patch.is_some());
                }
                crate::LoopOperation::ConditionalContinue(control) => {
                    self.emit_inline_conditional_loop_control::<MAX_NODES>(
                        control,
                        local_checkpoint,
                        loop_start,
                        false,
                        body_start,
                    )?;
                }
                crate::LoopOperation::ConditionalReturn(conditional) => {
                    let patch = self.emit_inline_conditional_return::<MAX_NODES>(
                        conditional,
                        expected_type,
                        call_checkpoint,
                        body_start,
                    )?;
                    *return_patches
                        .get_mut(*return_count)
                        .ok_or(self.error(CodegenErrorKind::OutputTooSmall))? = Some(patch);
                    *return_count += 1;
                }
                crate::LoopOperation::Return(return_statement) => {
                    let patch = self.emit_inline_return::<MAX_NODES>(
                        return_statement,
                        expected_type,
                        call_checkpoint,
                        body_start,
                    )?;
                    *return_patches
                        .get_mut(*return_count)
                        .ok_or(self.error(CodegenErrorKind::OutputTooSmall))? = Some(patch);
                    *return_count += 1;
                    terminated = true;
                    break;
                }
                crate::LoopOperation::ConditionalBlock(index) => {
                    let block = loop_statement.conditional_blocks()[*index]
                        .ok_or(self.error(CodegenErrorKind::RuntimeExpressionUnsupported))?;
                    self.emit_inline_conditional_loop_block::<MAX_NODES>(
                        loop_statement,
                        &block,
                        expected_type,
                        operand_type,
                        call_checkpoint,
                        local_checkpoint,
                        loop_start,
                        body_start,
                        return_patches,
                        return_count,
                        &mut exit_patches,
                        &mut exit_count,
                    )?;
                }
                crate::LoopOperation::NestedBlock(index) => {
                    let block = loop_statement.nested_blocks()[*index]
                        .ok_or(self.error(CodegenErrorKind::RuntimeExpressionUnsupported))?;
                    self.emit_inline_nested_loop_block::<MAX_NODES>(
                        &block,
                        expected_type,
                        operand_type,
                        call_checkpoint,
                        local_checkpoint,
                        loop_start,
                        body_start,
                        return_patches,
                        return_count,
                        &mut exit_patches,
                        &mut exit_count,
                    )?;
                }
                crate::LoopOperation::NestedUnitLoop => {}
            }
        }
        if !terminated {
            self.emit_stack_cleanup_to(local_checkpoint)?;
            self.emit_backward_branch(loop_start)?;
        }
        self.truncate_scoped_locals(local_checkpoint)?;
        for patch in exit_patches[..exit_count].iter().flatten().copied() {
            self.patch_forward_branch(patch)?;
        }
        Ok(())
    }

    fn emit_inline_conditional_loop_control<const MAX_NODES: usize>(
        &mut self,
        control: &crate::ConditionalLoopControl<'_>,
        local_checkpoint: usize,
        loop_start: usize,
        is_break: bool,
        body_start: usize,
    ) -> Result<Option<usize>, CodegenError> {
        let condition = control
            .parse_condition::<MAX_NODES>()
            .map_err(|error| CodegenError {
                kind: CodegenErrorKind::Expression(error.kind),
                span: translate_span(body_start + control.condition_span.start, error.span),
            })?;
        let condition_type = runtime_expression_type_with_locals(
            self.function,
            self.resolver,
            &self.locals[..self.saved_locals],
            &condition,
            condition.root(),
            0,
        )
        .map_err(|kind| self.error(kind))?;
        if condition_type != RuntimeExpressionType::Bool {
            return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
        }
        self.emit_expression(&condition, condition.root(), 0)?;
        self.emit(&[0x48, 0x85, 0xc0])?;
        let skip = self.emit_forward_branch(0x84)?;
        self.emit_stack_cleanup_to(local_checkpoint)?;
        let exit = if is_break {
            Some(self.emit_unconditional_forward_branch()?)
        } else {
            self.emit_backward_branch(loop_start)?;
            None
        };
        self.patch_forward_branch(skip)?;
        Ok(exit)
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_inline_conditional_loop_block<const MAX_NODES: usize>(
        &mut self,
        loop_statement: &crate::WhileLoop<'tree>,
        block: &crate::ConditionalLoopBlock<'tree>,
        expected_type: RuntimeExpressionType,
        operand_type: &str,
        call_checkpoint: usize,
        loop_checkpoint: usize,
        loop_start: usize,
        body_start: usize,
        return_patches: &mut [Option<usize>],
        return_count: &mut usize,
        exit_patches: &mut [Option<usize>],
        exit_count: &mut usize,
    ) -> Result<(), CodegenError> {
        let condition = block
            .parse_condition::<MAX_NODES>()
            .map_err(|error| CodegenError {
                kind: CodegenErrorKind::Expression(error.kind),
                span: translate_span(body_start + block.condition_span.start, error.span),
            })?;
        self.emit_inline_loop_arm_condition(&condition)?;
        let skip_block = self.emit_forward_branch(0x84)?;
        let block_checkpoint = self.saved_locals;
        self.emit_inline_loop_actions::<MAX_NODES>(block.actions(), operand_type, body_start)?;
        let block_terminated = self.emit_inline_loop_terminal::<MAX_NODES>(
            block.terminal.as_ref(),
            expected_type,
            call_checkpoint,
            loop_checkpoint,
            loop_start,
            body_start,
            return_patches,
            return_count,
            exit_patches,
            exit_count,
        )?;
        if !block_terminated {
            self.emit_stack_cleanup_to(block_checkpoint)?;
        }
        self.truncate_scoped_locals(block_checkpoint)?;
        let mut end_patches = [None; crate::MAX_CONDITIONAL_LOOP_ELSE_ARMS + 1];
        let mut end_count = 0usize;
        if block.else_arm.is_some() && !block_terminated {
            end_patches[end_count] = Some(self.emit_unconditional_forward_branch()?);
            end_count += 1;
        }
        self.patch_forward_branch(skip_block)?;
        if let Some(else_index) = block.else_arm {
            let end = else_index
                .checked_add(block.else_arm_count)
                .ok_or(self.error(CodegenErrorKind::OutputTooSmall))?;
            let arms = loop_statement
                .conditional_else_arms()
                .get(else_index..end)
                .ok_or(self.error(CodegenErrorKind::RuntimeExpressionUnsupported))?;
            for arm in arms.iter().flatten() {
                let skip_arm = if let Some(condition) =
                    arm.parse_condition::<MAX_NODES>()
                        .map_err(|error| CodegenError {
                            kind: CodegenErrorKind::Expression(error.kind),
                            span: translate_span(body_start + arm.condition_span.start, error.span),
                        })? {
                    self.emit_inline_loop_arm_condition(&condition)?;
                    Some(self.emit_forward_branch(0x84)?)
                } else {
                    None
                };
                let arm_checkpoint = self.saved_locals;
                self.emit_inline_loop_actions::<MAX_NODES>(
                    arm.actions(),
                    operand_type,
                    body_start,
                )?;
                let terminated = self.emit_inline_loop_terminal::<MAX_NODES>(
                    arm.terminal.as_ref(),
                    expected_type,
                    call_checkpoint,
                    loop_checkpoint,
                    loop_start,
                    body_start,
                    return_patches,
                    return_count,
                    exit_patches,
                    exit_count,
                )?;
                if !terminated {
                    self.emit_stack_cleanup_to(arm_checkpoint)?;
                }
                self.truncate_scoped_locals(arm_checkpoint)?;
                if !terminated {
                    end_patches[end_count] = Some(self.emit_unconditional_forward_branch()?);
                    end_count += 1;
                }
                if let Some(skip_arm) = skip_arm {
                    self.patch_forward_branch(skip_arm)?;
                } else {
                    break;
                }
            }
        }
        for patch in end_patches[..end_count].iter().flatten().copied() {
            self.patch_forward_branch(patch)?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_inline_nested_loop_block<const MAX_NODES: usize>(
        &mut self,
        block: &crate::NestedLoopBlock<'tree>,
        expected_type: RuntimeExpressionType,
        operand_type: &str,
        call_checkpoint: usize,
        outer_checkpoint: usize,
        outer_start: usize,
        body_start: usize,
        return_patches: &mut [Option<usize>],
        return_count: &mut usize,
        outer_exit_patches: &mut [Option<usize>],
        outer_exit_count: &mut usize,
    ) -> Result<(), CodegenError> {
        let nested_checkpoint = self.saved_locals;
        let nested_start = self.length;
        let entry_exit = if let Some(condition) = block.entry_condition {
            let tree = condition
                .parse_condition::<MAX_NODES>()
                .map_err(|error| CodegenError {
                    kind: CodegenErrorKind::Expression(error.kind),
                    span: translate_span(body_start + condition.condition_span.start, error.span),
                })?;
            self.emit_inline_loop_arm_condition(&tree)?;
            Some(self.emit_forward_branch(0x84)?)
        } else {
            None
        };
        let mut nested_exit_patches = [None;
            crate::MAX_NESTED_LOOP_CONDITIONAL_BREAKS
                + crate::parser::MAX_NESTED_LOOP_CONDITIONAL_BLOCKS
                + crate::MAX_NESTED_LOOP_UNCONDITIONAL_CONTROLS];
        let mut nested_exit_count = 0usize;
        let control_count = block
            .conditional_blocks()
            .len()
            .checked_add(block.conditional_returns().len())
            .and_then(|count| count.checked_add(block.conditional_continues().len()))
            .and_then(|count| count.checked_add(block.conditional_breaks().len()))
            .and_then(|count| count.checked_add(block.unconditional_controls().len()))
            .ok_or(self.error(CodegenErrorKind::OutputTooSmall))?;
        for action_index in 0..=block.action_count() {
            for control_order in 0..control_count {
                for ((branch, stored_action_index), stored_order) in block
                    .conditional_blocks()
                    .iter()
                    .flatten()
                    .zip(block.conditional_block_action_indices())
                    .zip(block.conditional_block_control_orders())
                {
                    if action_index != *stored_action_index || control_order != *stored_order {
                        continue;
                    }
                    let condition =
                        branch
                            .parse_condition::<MAX_NODES>()
                            .map_err(|error| CodegenError {
                                kind: CodegenErrorKind::Expression(error.kind),
                                span: translate_span(
                                    body_start + branch.condition_span.start,
                                    error.span,
                                ),
                            })?;
                    self.emit_inline_loop_arm_condition(&condition)?;
                    let false_branch = self.emit_forward_branch(0x84)?;
                    let branch_checkpoint = self.saved_locals;
                    for branch_action in branch.actions().iter().flatten() {
                        match branch_action {
                            crate::ConditionalLoopAction::Local(local) => {
                                self.emit_local::<MAX_NODES>(local, operand_type, body_start)?;
                            }
                            crate::ConditionalLoopAction::Assignment(assignment) => {
                                self.emit_assignment::<MAX_NODES>(assignment, body_start)?;
                            }
                            crate::ConditionalLoopAction::Expression(statement) => {
                                self.emit_expression_statement::<MAX_NODES>(statement, body_start)?;
                            }
                        }
                    }
                    match branch.terminal {
                        crate::NestedLoopUnconditionalControl::Break(target) => {
                            let (checkpoint, patches, count) =
                                if target == crate::NestedLoopControlTarget::Outer {
                                    (
                                        outer_checkpoint,
                                        &mut *outer_exit_patches,
                                        &mut *outer_exit_count,
                                    )
                                } else {
                                    (
                                        nested_checkpoint,
                                        &mut nested_exit_patches[..],
                                        &mut nested_exit_count,
                                    )
                                };
                            self.emit_stack_cleanup_to(checkpoint)?;
                            let patch = self.emit_unconditional_forward_branch()?;
                            *patches
                                .get_mut(*count)
                                .ok_or(self.error(CodegenErrorKind::OutputTooSmall))? = Some(patch);
                            *count += 1;
                        }
                        crate::NestedLoopUnconditionalControl::Continue(target) => {
                            let (checkpoint, start) =
                                if target == crate::NestedLoopControlTarget::Outer {
                                    (outer_checkpoint, outer_start)
                                } else {
                                    (nested_checkpoint, nested_start)
                                };
                            self.emit_stack_cleanup_to(checkpoint)?;
                            self.emit_backward_branch(start)?;
                        }
                        crate::NestedLoopUnconditionalControl::Return(value) => {
                            let patch = self.emit_inline_return::<MAX_NODES>(
                                &value,
                                expected_type,
                                call_checkpoint,
                                body_start,
                            )?;
                            *return_patches
                                .get_mut(*return_count)
                                .ok_or(self.error(CodegenErrorKind::OutputTooSmall))? = Some(patch);
                            *return_count += 1;
                        }
                    }
                    self.truncate_scoped_locals(branch_checkpoint)?;
                    if branch.else_arm_count() != 0 {
                        self.patch_forward_branch(false_branch)?;
                        for else_arm in branch.else_arms().iter().flatten() {
                            let else_false_branch = if let Some(condition) = else_arm
                                .parse_condition::<MAX_NODES>()
                                .map_err(|error| CodegenError {
                                    kind: CodegenErrorKind::Expression(error.kind),
                                    span: translate_span(
                                        body_start + else_arm.condition_span().start,
                                        error.span,
                                    ),
                                })? {
                                self.emit_inline_loop_arm_condition(&condition)?;
                                Some(self.emit_forward_branch(0x84)?)
                            } else {
                                None
                            };
                            let else_checkpoint = self.saved_locals;
                            for branch_action in else_arm.actions().iter().flatten() {
                                match branch_action {
                                    crate::ConditionalLoopAction::Local(local) => self
                                        .emit_local::<MAX_NODES>(local, operand_type, body_start)?,
                                    crate::ConditionalLoopAction::Assignment(assignment) => {
                                        self.emit_assignment::<MAX_NODES>(assignment, body_start)?
                                    }
                                    crate::ConditionalLoopAction::Expression(statement) => {
                                        self.emit_expression_statement::<MAX_NODES>(
                                            statement, body_start,
                                        )?
                                    }
                                }
                            }
                            match else_arm.terminal {
                                crate::NestedLoopUnconditionalControl::Break(target) => {
                                    let (checkpoint, patches, count) =
                                        if target == crate::NestedLoopControlTarget::Outer {
                                            (
                                                outer_checkpoint,
                                                &mut *outer_exit_patches,
                                                &mut *outer_exit_count,
                                            )
                                        } else {
                                            (
                                                nested_checkpoint,
                                                &mut nested_exit_patches[..],
                                                &mut nested_exit_count,
                                            )
                                        };
                                    self.emit_stack_cleanup_to(checkpoint)?;
                                    let patch = self.emit_unconditional_forward_branch()?;
                                    *patches
                                        .get_mut(*count)
                                        .ok_or(self.error(CodegenErrorKind::OutputTooSmall))? =
                                        Some(patch);
                                    *count += 1;
                                }
                                crate::NestedLoopUnconditionalControl::Continue(target) => {
                                    let (checkpoint, start) =
                                        if target == crate::NestedLoopControlTarget::Outer {
                                            (outer_checkpoint, outer_start)
                                        } else {
                                            (nested_checkpoint, nested_start)
                                        };
                                    self.emit_stack_cleanup_to(checkpoint)?;
                                    self.emit_backward_branch(start)?;
                                }
                                crate::NestedLoopUnconditionalControl::Return(value) => {
                                    let patch = self.emit_inline_return::<MAX_NODES>(
                                        &value,
                                        expected_type,
                                        call_checkpoint,
                                        body_start,
                                    )?;
                                    *return_patches
                                        .get_mut(*return_count)
                                        .ok_or(self.error(CodegenErrorKind::OutputTooSmall))? =
                                        Some(patch);
                                    *return_count += 1;
                                }
                            }
                            self.truncate_scoped_locals(else_checkpoint)?;
                            if let Some(else_false_branch) = else_false_branch {
                                self.patch_forward_branch(else_false_branch)?;
                            }
                        }
                    } else {
                        self.patch_forward_branch(false_branch)?;
                    }
                }
                for ((control, stored_action_index), stored_order) in block
                    .unconditional_controls()
                    .iter()
                    .flatten()
                    .zip(block.unconditional_control_action_indices())
                    .zip(block.unconditional_control_orders())
                {
                    if action_index != *stored_action_index || control_order != *stored_order {
                        continue;
                    }
                    match control {
                        crate::NestedLoopUnconditionalControl::Break(target) => {
                            let (checkpoint, patches, count) =
                                if *target == crate::NestedLoopControlTarget::Outer {
                                    (
                                        outer_checkpoint,
                                        &mut *outer_exit_patches,
                                        &mut *outer_exit_count,
                                    )
                                } else {
                                    (
                                        nested_checkpoint,
                                        &mut nested_exit_patches[..],
                                        &mut nested_exit_count,
                                    )
                                };
                            self.emit_stack_cleanup_to(checkpoint)?;
                            let patch = self.emit_unconditional_forward_branch()?;
                            *patches
                                .get_mut(*count)
                                .ok_or(self.error(CodegenErrorKind::OutputTooSmall))? = Some(patch);
                            *count += 1;
                        }
                        crate::NestedLoopUnconditionalControl::Continue(target) => {
                            let (checkpoint, start) =
                                if *target == crate::NestedLoopControlTarget::Outer {
                                    (outer_checkpoint, outer_start)
                                } else {
                                    (nested_checkpoint, nested_start)
                                };
                            self.emit_stack_cleanup_to(checkpoint)?;
                            self.emit_backward_branch(start)?;
                        }
                        crate::NestedLoopUnconditionalControl::Return(value) => {
                            let patch = self.emit_inline_return::<MAX_NODES>(
                                value,
                                expected_type,
                                call_checkpoint,
                                body_start,
                            )?;
                            *return_patches
                                .get_mut(*return_count)
                                .ok_or(self.error(CodegenErrorKind::OutputTooSmall))? = Some(patch);
                            *return_count += 1;
                        }
                    }
                }
                for (((condition, stored_action_index), stored_order), target) in block
                    .conditional_breaks()
                    .iter()
                    .flatten()
                    .zip(block.conditional_break_action_indices())
                    .zip(block.conditional_break_control_orders())
                    .zip(block.conditional_break_targets())
                {
                    if action_index != *stored_action_index || control_order != *stored_order {
                        continue;
                    }
                    let tree =
                        condition
                            .parse_condition::<MAX_NODES>()
                            .map_err(|error| CodegenError {
                                kind: CodegenErrorKind::Expression(error.kind),
                                span: translate_span(
                                    body_start + condition.condition_span.start,
                                    error.span,
                                ),
                            })?;
                    self.emit_inline_loop_arm_condition(&tree)?;
                    let skip = self.emit_forward_branch(0x84)?;
                    let (checkpoint, patches, count) =
                        if *target == crate::NestedLoopControlTarget::Outer {
                            (
                                outer_checkpoint,
                                &mut *outer_exit_patches,
                                &mut *outer_exit_count,
                            )
                        } else {
                            (
                                nested_checkpoint,
                                &mut nested_exit_patches[..],
                                &mut nested_exit_count,
                            )
                        };
                    self.emit_stack_cleanup_to(checkpoint)?;
                    let patch = self.emit_unconditional_forward_branch()?;
                    *patches
                        .get_mut(*count)
                        .ok_or(self.error(CodegenErrorKind::OutputTooSmall))? = Some(patch);
                    *count += 1;
                    self.patch_forward_branch(skip)?;
                }
                for ((conditional, stored_action_index), stored_order) in block
                    .conditional_returns()
                    .iter()
                    .flatten()
                    .zip(block.conditional_return_action_indices())
                    .zip(block.conditional_return_control_orders())
                {
                    if action_index != *stored_action_index || control_order != *stored_order {
                        continue;
                    }
                    let patch = self.emit_inline_conditional_return::<MAX_NODES>(
                        conditional,
                        expected_type,
                        call_checkpoint,
                        body_start,
                    )?;
                    *return_patches
                        .get_mut(*return_count)
                        .ok_or(self.error(CodegenErrorKind::OutputTooSmall))? = Some(patch);
                    *return_count += 1;
                }
                for (((condition, stored_action_index), stored_order), target) in block
                    .conditional_continues()
                    .iter()
                    .flatten()
                    .zip(block.conditional_continue_action_indices())
                    .zip(block.conditional_continue_control_orders())
                    .zip(block.conditional_continue_targets())
                {
                    if action_index != *stored_action_index || control_order != *stored_order {
                        continue;
                    }
                    let tree =
                        condition
                            .parse_condition::<MAX_NODES>()
                            .map_err(|error| CodegenError {
                                kind: CodegenErrorKind::Expression(error.kind),
                                span: translate_span(
                                    body_start + condition.condition_span.start,
                                    error.span,
                                ),
                            })?;
                    self.emit_inline_loop_arm_condition(&tree)?;
                    let skip = self.emit_forward_branch(0x84)?;
                    let (checkpoint, start) = if *target == crate::NestedLoopControlTarget::Outer {
                        (outer_checkpoint, outer_start)
                    } else {
                        (nested_checkpoint, nested_start)
                    };
                    self.emit_stack_cleanup_to(checkpoint)?;
                    self.emit_backward_branch(start)?;
                    self.patch_forward_branch(skip)?;
                }
            }
            if action_index == block.action_count() {
                break;
            }
            let action = block.actions()[action_index]
                .ok_or(self.error(CodegenErrorKind::RuntimeExpressionUnsupported))?;
            match action {
                crate::ConditionalLoopAction::Local(local) => {
                    self.emit_local::<MAX_NODES>(&local, operand_type, body_start)?;
                }
                crate::ConditionalLoopAction::Assignment(assignment) => {
                    self.emit_assignment::<MAX_NODES>(&assignment, body_start)?;
                }
                crate::ConditionalLoopAction::Expression(statement) => {
                    self.emit_expression_statement::<MAX_NODES>(&statement, body_start)?;
                }
            }
        }
        self.emit_stack_cleanup_to(nested_checkpoint)?;
        self.truncate_scoped_locals(nested_checkpoint)?;
        if block.unconditional_controls().is_empty() {
            self.emit_backward_branch(nested_start)?;
        }
        for patch in nested_exit_patches[..nested_exit_count]
            .iter()
            .flatten()
            .copied()
        {
            self.patch_forward_branch(patch)?;
        }
        if let Some(entry_exit) = entry_exit {
            self.patch_forward_branch(entry_exit)?;
        }
        Ok(())
    }

    fn emit_inline_loop_arm_condition<const MAX_NODES: usize>(
        &mut self,
        condition: &crate::ExpressionTree<'_, MAX_NODES>,
    ) -> Result<(), CodegenError> {
        let ty = runtime_expression_type_with_locals(
            self.function,
            self.resolver,
            &self.locals[..self.saved_locals],
            condition,
            condition.root(),
            0,
        )
        .map_err(|kind| self.error(kind))?;
        if ty != RuntimeExpressionType::Bool {
            return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
        }
        self.emit_expression(condition, condition.root(), 0)?;
        self.emit(&[0x48, 0x85, 0xc0])
    }

    fn emit_inline_loop_actions<const MAX_NODES: usize>(
        &mut self,
        actions: &[Option<crate::ConditionalLoopAction<'tree>>],
        operand_type: &str,
        body_start: usize,
    ) -> Result<(), CodegenError> {
        for action in actions.iter().flatten() {
            match action {
                crate::ConditionalLoopAction::Local(local) => {
                    self.emit_local::<MAX_NODES>(local, operand_type, body_start)?;
                }
                crate::ConditionalLoopAction::Assignment(assignment) => {
                    self.emit_assignment::<MAX_NODES>(assignment, body_start)?;
                }
                crate::ConditionalLoopAction::Expression(statement) => {
                    self.emit_expression_statement::<MAX_NODES>(statement, body_start)?;
                }
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_inline_loop_terminal<const MAX_NODES: usize>(
        &mut self,
        terminal: Option<&crate::ConditionalLoopTerminal<'tree>>,
        expected_type: RuntimeExpressionType,
        call_checkpoint: usize,
        loop_checkpoint: usize,
        loop_start: usize,
        body_start: usize,
        return_patches: &mut [Option<usize>],
        return_count: &mut usize,
        exit_patches: &mut [Option<usize>],
        exit_count: &mut usize,
    ) -> Result<bool, CodegenError> {
        let Some(terminal) = terminal else {
            return Ok(false);
        };
        match terminal {
            crate::ConditionalLoopTerminal::Break => {
                self.emit_stack_cleanup_to(loop_checkpoint)?;
                let patch = self.emit_unconditional_forward_branch()?;
                *exit_patches
                    .get_mut(*exit_count)
                    .ok_or(self.error(CodegenErrorKind::OutputTooSmall))? = Some(patch);
                *exit_count += 1;
            }
            crate::ConditionalLoopTerminal::Continue => {
                self.emit_stack_cleanup_to(loop_checkpoint)?;
                self.emit_backward_branch(loop_start)?;
            }
            crate::ConditionalLoopTerminal::Return(return_statement) => {
                let patch = self.emit_inline_return::<MAX_NODES>(
                    return_statement,
                    expected_type,
                    call_checkpoint,
                    body_start,
                )?;
                *return_patches
                    .get_mut(*return_count)
                    .ok_or(self.error(CodegenErrorKind::OutputTooSmall))? = Some(patch);
                *return_count += 1;
            }
        }
        Ok(true)
    }

    fn emit_expression_with_width<const MAX_NODES: usize>(
        &mut self,
        tree: &crate::ExpressionTree<'_, MAX_NODES>,
        id: crate::ExprId,
        depth: usize,
    ) -> Result<(), CodegenError> {
        if depth == 64 {
            return Err(self.error(CodegenErrorKind::Lowering(
                IrErrorKind::NestingLimitExceeded,
            )));
        }
        let expression = *tree
            .expression(id)
            .ok_or(self.error(CodegenErrorKind::RuntimeExpressionUnsupported))?;
        match expression.kind {
            ExprKind::UnsafeBlock { operand } => {
                self.emit_expression_with_width(tree, operand, depth + 1)?;
            }
            ExprKind::Unit | ExprKind::DefaultValue => self.emit(&[0x31, 0xc0])?,
            ExprKind::Array { .. } | ExprKind::ArrayRepeat { .. } | ExprKind::Tuple { .. } => {
                return Err(self.error(CodegenErrorKind::RuntimeExpressionUnsupported));
            }
            ExprKind::TupleField { base, field } => {
                self.emit_tuple_field(tree, base, field, depth + 1)?;
            }
            ExprKind::IntegerToBytes { .. } => {
                return Err(self.error(CodegenErrorKind::RuntimeExpressionUnsupported));
            }
            ExprKind::Index { base, index } => {
                let base_type = runtime_expression_type_with_locals(
                    self.function,
                    self.resolver,
                    &self.locals[..self.saved_locals],
                    tree,
                    base,
                    depth + 1,
                )
                .map_err(|kind| self.error(kind))?;
                if let RuntimeExpressionType::Reference {
                    target: RuntimeReferenceTarget::Slice(element),
                    ..
                } = base_type
                {
                    if let Some(source) = reference_source_name(tree, base) {
                        self.emit_slice_runtime_index(
                            tree,
                            base,
                            index,
                            element,
                            source,
                            depth + 1,
                        )?;
                    } else {
                        self.emit_index_address(tree, base, index, depth + 1)?;
                        if runtime_array_element_bytes(element)
                            .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?
                            == 0
                        {
                            self.emit(&[0x31, 0xc0])?;
                        } else {
                            self.emit_reference_load(element)?;
                        }
                    }
                    return Ok(());
                }
                if let RuntimeExpressionType::Reference {
                    target:
                        RuntimeReferenceTarget::Array {
                            element,
                            count,
                            layout,
                        },
                    ..
                } = base_type
                {
                    match tree.evaluate_at(index, self.resolver) {
                        Ok(index) => {
                            let index = usize::try_from(index)
                                .map_err(|_| self.error(CodegenErrorKind::ValueOutOfRange))?;
                            if index >= count {
                                return Err(self.error(CodegenErrorKind::Execution(
                                    ExecutionError::Arithmetic(
                                        crate::ConstEvalError::ArrayIndexOutOfBounds,
                                    ),
                                )));
                            }
                            self.emit_reference_array_constant_index(
                                tree,
                                base,
                                element,
                                index,
                                layout,
                                depth + 1,
                            )?;
                        }
                        Err(crate::ConstEvalError::UnknownIdentifier) => {
                            self.emit_reference_array_runtime_index(
                                tree,
                                base,
                                index,
                                RuntimeReferenceTarget::Array {
                                    element,
                                    count,
                                    layout,
                                },
                                depth + 1,
                            )?;
                        }
                        Err(error) => {
                            return Err(self.error(CodegenErrorKind::Execution(
                                ExecutionError::Arithmetic(error),
                            )));
                        }
                    }
                    return Ok(());
                }
                match tree.evaluate_at(index, self.resolver) {
                    Ok(index) => {
                        let index = usize::try_from(index)
                            .map_err(|_| self.error(CodegenErrorKind::ValueOutOfRange))?;
                        let RuntimeExpressionType::Array { count, .. } =
                            runtime_expression_type_with_locals(
                                self.function,
                                self.resolver,
                                &self.locals[..self.saved_locals],
                                tree,
                                base,
                                depth + 1,
                            )
                            .map_err(|kind| self.error(kind))?
                        else {
                            return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
                        };
                        if index >= count {
                            return Err(self.error(CodegenErrorKind::Execution(
                                ExecutionError::Arithmetic(
                                    crate::ConstEvalError::ArrayIndexOutOfBounds,
                                ),
                            )));
                        }
                        self.emit_constant_array_index(tree, base, index, count, depth + 1)?;
                    }
                    Err(crate::ConstEvalError::UnknownIdentifier) => {
                        let RuntimeExpressionType::Array { count, .. } =
                            runtime_expression_type_with_locals(
                                self.function,
                                self.resolver,
                                &self.locals[..self.saved_locals],
                                tree,
                                base,
                                depth + 1,
                            )
                            .map_err(|kind| self.error(kind))?
                        else {
                            return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
                        };
                        self.emit_runtime_array_index(tree, base, index, count, depth + 1)?;
                    }
                    Err(error) => {
                        return Err(self.error(CodegenErrorKind::Execution(
                            ExecutionError::Arithmetic(error),
                        )));
                    }
                }
            }
            ExprKind::RangeIndex { .. } => {
                return Err(self.error(CodegenErrorKind::RuntimeExpressionUnsupported));
            }
            ExprKind::SliceLen { base } => {
                let base_type = runtime_expression_type_with_locals(
                    self.function,
                    self.resolver,
                    &self.locals[..self.saved_locals],
                    tree,
                    base,
                    depth + 1,
                )
                .map_err(|kind| self.error(kind))?;
                if !matches!(
                    base_type,
                    RuntimeExpressionType::Reference {
                        target: RuntimeReferenceTarget::Slice(_) | RuntimeReferenceTarget::Str,
                        ..
                    }
                ) {
                    return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
                }
                if let Some((_, length)) = self.append_c_string_byte_view(tree, base)? {
                    self.emit(&[0x48, 0xb8])?;
                    self.emit(&(length as u64).to_le_bytes())?;
                    return Ok(());
                }
                let source = reference_source_name(tree, base)
                    .ok_or(self.error(CodegenErrorKind::RuntimeExpressionUnsupported))?;
                self.emit_slice_length(source)?;
            }
            ExprKind::SliceIsEmpty { base } => {
                let base_type = runtime_expression_type_with_locals(
                    self.function,
                    self.resolver,
                    &self.locals[..self.saved_locals],
                    tree,
                    base,
                    depth + 1,
                )
                .map_err(|kind| self.error(kind))?;
                if !matches!(
                    base_type,
                    RuntimeExpressionType::Reference {
                        target: RuntimeReferenceTarget::Slice(_) | RuntimeReferenceTarget::Str,
                        ..
                    }
                ) {
                    return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
                }
                if let Some((_, length)) = self.append_c_string_byte_view(tree, base)? {
                    self.emit(&[0xb8, u8::from(length == 0), 0, 0, 0])?;
                    return Ok(());
                }
                let source = reference_source_name(tree, base)
                    .ok_or(self.error(CodegenErrorKind::RuntimeExpressionUnsupported))?;
                self.emit_slice_length(source)?;
                self.emit(&[0x48, 0x85, 0xc0, 0x0f, 0x94, 0xc0, 0x0f, 0xb6, 0xc0])?;
            }
            ExprKind::StrAsBytes { base } => {
                self.emit_expression(tree, base, depth + 1)?;
            }
            ExprKind::CStrToBytes { .. } => {
                return Err(self.error(CodegenErrorKind::RuntimeExpressionUnsupported));
            }
            ExprKind::StrIsCharBoundary { base, index } => {
                self.emit_string_is_char_boundary(tree, base, index, depth + 1)?;
            }
            ExprKind::ReferenceAsPointer { base, .. } => {
                if let Some(ExprKind::CString(literal)) =
                    tree.expression(base).map(|expression| expression.kind)
                {
                    let (data_offset, _) =
                        self.append_readonly_string_literal(literal, ReadonlyStringLiteralKind::C)?;
                    let capacity_error = self.error(CodegenErrorKind::OutputTooSmall);
                    let relocation_offset = self
                        .length
                        .checked_add(3)
                        .ok_or(self.error(CodegenErrorKind::OutputTooSmall))?;
                    let relocation = self
                        .readonly_relocations
                        .get_mut(self.readonly_relocation_count)
                        .ok_or(capacity_error)?;
                    *relocation = X86_64ReadonlyDataRelocation {
                        offset: relocation_offset,
                        data_offset,
                    };
                    self.readonly_relocation_count += 1;
                    self.emit(&[0x48, 0x8d, 0x05, 0, 0, 0, 0])?;
                } else {
                    self.emit_expression(tree, base, depth + 1)?;
                }
            }
            ExprKind::RawPointerIsNull { base } => {
                self.emit_expression(tree, base, depth + 1)?;
                self.emit(&[0x48, 0x85, 0xc0, 0x0f, 0x94, 0xc0, 0x0f, 0xb6, 0xc0])?;
            }
            ExprKind::RawPointerIsAligned { base } => {
                let RuntimeExpressionType::RawPointer { pointee, .. } =
                    runtime_expression_type_with_locals(
                        self.function,
                        self.resolver,
                        &self.locals[..self.saved_locals],
                        tree,
                        base,
                        depth + 1,
                    )
                    .map_err(|kind| self.error(kind))?
                else {
                    return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
                };
                let alignment = runtime_array_element_bytes(pointee)
                    .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
                self.emit_expression(tree, base, depth + 1)?;
                self.emit(&[0x48, 0xa9])?;
                self.emit(&(alignment as u32 - 1).to_le_bytes())?;
                self.emit(&[0x0f, 0x94, 0xc0, 0x0f, 0xb6, 0xc0])?;
            }
            ExprKind::RawPointerAddress { base }
            | ExprKind::RawPointerMutability { base, .. }
            | ExprKind::RawPointerPointeeCast { base, .. }
            | ExprKind::RawPointerAsReference { base, .. } => {
                self.emit_expression(tree, base, depth + 1)?;
            }
            ExprKind::RawPointerWithAddress { base, address } => {
                self.emit_expression(tree, base, depth + 1)?;
                self.emit(&[0x50])?;
                self.evaluation_depth += 1;
                self.emit_expression(tree, address, depth + 1)?;
                self.evaluation_depth -= 1;
                self.emit(&[0x48, 0x83, 0xc4, 0x08])?;
            }
            ExprKind::RawPointerWithMetadata { base, metadata } => {
                self.emit_expression(tree, base, depth + 1)?;
                self.emit(&[0x50])?;
                self.evaluation_depth += 1;
                self.emit_expression(tree, metadata, depth + 1)?;
                self.emit(&[0x48, 0x8b, 0x04, 0x24, 0x48, 0x83, 0xc4, 0x08])?;
                self.evaluation_depth -= 1;
            }
            ExprKind::RawPointerWrite {
                base,
                value,
                returns_old,
            } => {
                let RuntimeExpressionType::RawPointer { pointee, .. } =
                    runtime_expression_type_with_locals(
                        self.function,
                        self.resolver,
                        &self.locals[..self.saved_locals],
                        tree,
                        base,
                        0,
                    )
                    .map_err(|kind| self.error(kind))?
                else {
                    return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
                };
                self.emit_expression(tree, base, depth + 1)?;
                self.emit(&[0x50])?;
                self.evaluation_depth += 1;
                let previous_width = self.width;
                self.width = runtime_expression_width(runtime_type_from_array_element(pointee))
                    .unwrap_or(previous_width);
                let emission = self.emit_expression(tree, value, depth + 1);
                self.width = previous_width;
                emission?;
                self.emit(&[0x48, 0x8b, 0x14, 0x24])?;
                if returns_old {
                    self.emit(&[0x48, 0x89, 0xc1, 0x48, 0x89, 0xd0])?;
                    self.emit_reference_load(pointee)?;
                    self.emit(&[0x49, 0x89, 0xc0, 0x48, 0x89, 0xc8])?;
                }
                self.emit_reference_store(pointee)?;
                if returns_old {
                    self.emit(&[0x4c, 0x89, 0xc0])?;
                }
                self.emit(&[0x48, 0x83, 0xc4, 0x08])?;
                self.evaluation_depth -= 1;
                if !returns_old {
                    self.emit(&[0x31, 0xc0])?;
                }
            }
            ExprKind::RawPointerWriteBytes { base, value, count } => {
                let RuntimeExpressionType::RawPointer { pointee, .. } =
                    runtime_expression_type_with_locals(
                        self.function,
                        self.resolver,
                        &self.locals[..self.saved_locals],
                        tree,
                        base,
                        0,
                    )
                    .map_err(|kind| self.error(kind))?
                else {
                    return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
                };
                let element_bytes = runtime_array_element_bytes(pointee)
                    .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
                self.emit_expression(tree, base, depth + 1)?;
                self.emit(&[0x50])?;
                self.evaluation_depth += 1;
                let previous_width = self.width;
                self.width = runtime_expression_width(RuntimeExpressionType::Integer(Some(
                    crate::IntegerType::U8,
                )))
                .unwrap_or(previous_width);
                let emission = self.emit_expression(tree, value, depth + 1);
                self.width = previous_width;
                emission?;
                self.emit(&[0x50])?;
                self.evaluation_depth += 1;
                self.width = runtime_expression_width(RuntimeExpressionType::Integer(Some(
                    crate::IntegerType::Usize,
                )))
                .unwrap_or(previous_width);
                let emission = self.emit_expression(tree, count, depth + 1);
                self.width = previous_width;
                emission?;
                self.emit(&[
                    0x49, 0x89, 0xc0, 0x44, 0x0f, 0xb6, 0x0c, 0x24, 0x4c, 0x8b, 0x54, 0x24, 0x08,
                    0x48, 0x83, 0xc4, 0x10,
                ])?;
                self.evaluation_depth -= 2;
                match element_bytes {
                    1 => {}
                    2 => self.emit(&[0x49, 0xd1, 0xe0])?,
                    4 => self.emit(&[0x49, 0xc1, 0xe0, 0x02])?,
                    8 => self.emit(&[0x49, 0xc1, 0xe0, 0x03])?,
                    _ => return Err(self.error(CodegenErrorKind::UnsupportedRuntimeType)),
                }
                let loop_start = self.length;
                self.emit(&[0x4d, 0x85, 0xc0])?;
                let done = self.emit_forward_branch(0x84)?;
                self.emit(&[0x45, 0x88, 0x0a, 0x49, 0xff, 0xc2, 0x49, 0xff, 0xc8])?;
                self.emit_backward_branch(loop_start)?;
                self.patch_forward_branch(done)?;
                self.emit(&[0x31, 0xc0])?;
            }
            ExprKind::RawPointerCopy {
                source,
                destination,
                count,
                overlapping,
                destination_first,
            } => {
                let RuntimeExpressionType::RawPointer { pointee, .. } =
                    runtime_expression_type_with_locals(
                        self.function,
                        self.resolver,
                        &self.locals[..self.saved_locals],
                        tree,
                        source,
                        0,
                    )
                    .map_err(|kind| self.error(kind))?
                else {
                    return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
                };
                let element_bytes = runtime_array_element_bytes(pointee)
                    .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
                let first = if destination_first {
                    destination
                } else {
                    source
                };
                let second = if destination_first {
                    source
                } else {
                    destination
                };
                self.emit_expression(tree, first, depth + 1)?;
                self.emit(&[0x50])?;
                self.evaluation_depth += 1;
                self.emit_expression(tree, second, depth + 1)?;
                self.emit(&[0x50])?;
                self.evaluation_depth += 1;
                let previous_width = self.width;
                self.width = runtime_expression_width(RuntimeExpressionType::Integer(Some(
                    crate::IntegerType::Usize,
                )))
                .unwrap_or(previous_width);
                let emission = self.emit_expression(tree, count, depth + 1);
                self.width = previous_width;
                emission?;
                self.emit(&[0x49, 0x89, 0xc0])?;
                if destination_first {
                    self.emit(&[0x4c, 0x8b, 0x14, 0x24, 0x4c, 0x8b, 0x5c, 0x24, 0x08])?;
                } else {
                    self.emit(&[0x4c, 0x8b, 0x1c, 0x24, 0x4c, 0x8b, 0x54, 0x24, 0x08])?;
                }
                self.emit(&[0x48, 0x83, 0xc4, 0x10])?;
                self.evaluation_depth -= 2;
                match element_bytes {
                    1 => {}
                    2 => self.emit(&[0x49, 0xd1, 0xe0])?,
                    4 => self.emit(&[0x49, 0xc1, 0xe0, 0x02])?,
                    8 => self.emit(&[0x49, 0xc1, 0xe0, 0x03])?,
                    _ => return Err(self.error(CodegenErrorKind::UnsupportedRuntimeType)),
                }
                self.emit(&[0x4d, 0x85, 0xc0])?;
                let empty = self.emit_forward_branch(0x84)?;
                let forward = if overlapping {
                    self.emit(&[0x4d, 0x39, 0xd3])?;
                    Some(self.emit_forward_branch(0x86)?)
                } else {
                    None
                };
                let backward_finished = if overlapping {
                    self.emit(&[0x4d, 0x01, 0xc2, 0x4d, 0x01, 0xc3])?;
                    let loop_start = self.length;
                    self.emit(&[
                        0x49, 0xff, 0xca, 0x49, 0xff, 0xcb, 0x45, 0x8a, 0x0a, 0x45, 0x88, 0x0b,
                        0x49, 0xff, 0xc8,
                    ])?;
                    self.emit(&[0x4d, 0x85, 0xc0])?;
                    let done = self.emit_forward_branch(0x84)?;
                    self.emit_backward_branch(loop_start)?;
                    self.patch_forward_branch(done)?;
                    Some(self.emit_unconditional_forward_branch()?)
                } else {
                    None
                };
                if let Some(forward) = forward {
                    self.patch_forward_branch(forward)?;
                }
                let loop_start = self.length;
                self.emit(&[
                    0x45, 0x8a, 0x0a, 0x45, 0x88, 0x0b, 0x49, 0xff, 0xc2, 0x49, 0xff, 0xc3, 0x49,
                    0xff, 0xc8,
                ])?;
                self.emit(&[0x4d, 0x85, 0xc0])?;
                let done = self.emit_forward_branch(0x84)?;
                self.emit_backward_branch(loop_start)?;
                self.patch_forward_branch(done)?;
                if let Some(backward_finished) = backward_finished {
                    self.patch_forward_branch(backward_finished)?;
                }
                self.patch_forward_branch(empty)?;
                self.emit(&[0x31, 0xc0])?;
            }
            ExprKind::RawPointerSwap { left, right } => {
                let RuntimeExpressionType::RawPointer { pointee, .. } =
                    runtime_expression_type_with_locals(
                        self.function,
                        self.resolver,
                        &self.locals[..self.saved_locals],
                        tree,
                        left,
                        0,
                    )
                    .map_err(|kind| self.error(kind))?
                else {
                    return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
                };
                self.emit_expression(tree, left, depth + 1)?;
                self.emit(&[0x50])?;
                self.evaluation_depth += 1;
                self.emit_expression(tree, right, depth + 1)?;
                self.emit(&[0x50])?;
                self.evaluation_depth += 1;
                self.emit(&[0x48, 0x8b, 0x44, 0x24, 0x08])?;
                self.emit_reference_load(pointee)?;
                self.emit(&[0x49, 0x89, 0xc0, 0x48, 0x8b, 0x04, 0x24])?;
                self.emit_reference_load(pointee)?;
                self.emit(&[0x48, 0x89, 0xc1, 0x48, 0x8b, 0x54, 0x24, 0x08])?;
                self.emit_reference_store(pointee)?;
                self.emit(&[0x4c, 0x89, 0xc0, 0x48, 0x8b, 0x14, 0x24])?;
                self.emit_reference_store(pointee)?;
                self.emit(&[0x48, 0x83, 0xc4, 0x10, 0x31, 0xc0])?;
                self.evaluation_depth -= 2;
            }
            ExprKind::WrappingArithmetic {
                base,
                argument,
                operator,
                euclidean,
                euclidean_wrapping,
                strict,
                mixed_signedness,
            } => {
                let base_type = runtime_expression_type_with_locals(
                    self.function,
                    self.resolver,
                    &self.locals[..self.saved_locals],
                    tree,
                    base,
                    depth + 1,
                )
                .map_err(|kind| self.error(kind))?;
                if let RuntimeExpressionType::RawPointer { pointee, .. } = base_type {
                    let element_bytes = runtime_array_element_bytes(pointee)
                        .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
                    self.emit_expression(tree, base, depth + 1)?;
                    self.emit(&[0x50])?;
                    self.evaluation_depth += 1;
                    self.emit_expression(tree, argument, depth + 1)?;
                    self.evaluation_depth -= 1;
                    self.emit(&[0x59])?;
                    match element_bytes {
                        1 => {}
                        2 => self.emit(&[0x48, 0xd1, 0xe0])?,
                        4 => self.emit(&[0x48, 0xc1, 0xe0, 2])?,
                        8 => self.emit(&[0x48, 0xc1, 0xe0, 3])?,
                        _ => return Err(self.error(CodegenErrorKind::UnsupportedRuntimeType)),
                    }
                    if operator == crate::BinaryOperator::Subtract {
                        self.emit(&[0x48, 0x29, 0xc1, 0x48, 0x89, 0xc8])?;
                    } else {
                        self.emit(&[0x48, 0x01, 0xc8])?;
                    }
                } else {
                    let operand_width = runtime_expression_width(base_type)
                        .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
                    let previous_width = self.width;
                    self.width = operand_width;
                    let left = self.emit_expression(tree, base, depth + 1);
                    left?;
                    self.emit(&[0x50])?;
                    self.evaluation_depth += 1;
                    if mixed_signedness {
                        self.width.signed = !operand_width.signed;
                    }
                    let right = self.emit_expression(tree, argument, depth + 1);
                    right?;
                    self.width = operand_width;
                    self.evaluation_depth -= 1;
                    self.emit(&[0x59])?;
                    let result = if euclidean {
                        self.emit_euclidean_division(operator, euclidean_wrapping)
                    } else if strict && mixed_signedness {
                        self.emit_strict_mixed_arithmetic(operator)
                    } else if strict {
                        let previous_overflow_checks = self.overflow_checks;
                        self.overflow_checks = true;
                        let result = self.emit_binary(operator);
                        self.overflow_checks = previous_overflow_checks;
                        result
                    } else if matches!(
                        operator,
                        crate::BinaryOperator::Divide | crate::BinaryOperator::Remainder
                    ) {
                        self.emit_wrapping_division(operator)
                    } else {
                        let previous_overflow_checks = self.overflow_checks;
                        self.overflow_checks = false;
                        let result = self.emit_binary(operator);
                        self.overflow_checks = previous_overflow_checks;
                        result
                    };
                    self.width = previous_width;
                    result?;
                }
            }
            ExprKind::UncheckedIntegerOperation {
                base,
                argument,
                second_argument,
                operator,
                unary,
                funnel,
                ..
            } => {
                let base_type = runtime_expression_type_with_locals(
                    self.function,
                    self.resolver,
                    &self.locals[..self.saved_locals],
                    tree,
                    base,
                    depth + 1,
                )
                .map_err(|kind| self.error(kind))?;
                let operand_width = runtime_expression_width(base_type)
                    .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
                let previous_width = self.width;
                self.width = operand_width;
                self.emit_expression(tree, base, depth + 1)?;
                if funnel {
                    let other =
                        argument.ok_or(self.error(CodegenErrorKind::RuntimeTypeMismatch))?;
                    let distance =
                        second_argument.ok_or(self.error(CodegenErrorKind::RuntimeTypeMismatch))?;
                    self.emit(&[0x50])?;
                    self.evaluation_depth += 1;
                    self.emit_expression(tree, other, depth + 1)?;
                    self.emit(&[0x50])?;
                    self.evaluation_depth += 1;
                    self.width = runtime_width("u32")
                        .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
                    self.emit_expression(tree, distance, depth + 1)?;
                    self.emit(&[0x49, 0x89, 0xc2, 0x59, 0x58])?;
                    self.evaluation_depth -= 2;
                    self.width = operand_width;
                    self.emit(&[0x4d, 0x85, 0xd2])?;
                    let nonzero = self.emit_forward_branch(0x85)?;
                    self.emit(if operator == crate::BinaryOperator::ShiftLeft {
                        &[0x90][..]
                    } else {
                        &[0x48, 0x89, 0xc8][..]
                    })?;
                    let done = self.emit_unconditional_forward_branch()?;
                    self.patch_forward_branch(nonzero)?;
                    self.emit(&[0x49, 0x89, 0xc0, 0x49, 0x89, 0xc9])?;
                    if operator == crate::BinaryOperator::ShiftLeft {
                        self.emit(&[
                            0x44,
                            0x89,
                            0xd1,
                            0x49,
                            0xd3,
                            0xe0,
                            0xb9,
                            operand_width.bits,
                            0,
                            0,
                            0,
                            0x44,
                            0x29,
                            0xd1,
                            0x49,
                            0xd3,
                            0xe9,
                        ])?;
                    } else {
                        self.emit(&[
                            0xb9,
                            operand_width.bits,
                            0,
                            0,
                            0,
                            0x44,
                            0x29,
                            0xd1,
                            0x49,
                            0xd3,
                            0xe0,
                            0x44,
                            0x89,
                            0xd1,
                            0x49,
                            0xd3,
                            0xe9,
                        ])?;
                    }
                    self.emit(&[0x4d, 0x09, 0xc8, 0x4c, 0x89, 0xc0])?;
                    self.patch_forward_branch(done)?;
                } else if unary {
                    self.emit(&[0x48, 0xf7, 0xd8])?;
                } else {
                    let argument =
                        argument.ok_or(self.error(CodegenErrorKind::RuntimeTypeMismatch))?;
                    self.emit(&[0x50])?;
                    self.evaluation_depth += 1;
                    if matches!(
                        operator,
                        crate::BinaryOperator::ShiftLeft | crate::BinaryOperator::ShiftRight
                    ) {
                        self.width = runtime_width("u32")
                            .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
                    }
                    self.emit_expression(tree, argument, depth + 1)?;
                    self.evaluation_depth -= 1;
                    if matches!(
                        operator,
                        crate::BinaryOperator::ShiftLeft | crate::BinaryOperator::ShiftRight
                    ) {
                        self.emit(&[0x48, 0x89, 0xc1, 0x58])?;
                        self.width = operand_width;
                        if operator == crate::BinaryOperator::ShiftLeft {
                            self.emit(&[0x48, 0xd3, 0xe0])?;
                        } else if operand_width.signed {
                            self.emit(&[0x48, 0xd3, 0xf8])?;
                        } else {
                            self.emit(&[0x48, 0xd3, 0xe8])?;
                        }
                    } else {
                        self.width = operand_width;
                        self.emit(&[0x59])?;
                        let previous_overflow_checks = self.overflow_checks;
                        self.overflow_checks = false;
                        let result = self.emit_binary(operator);
                        self.overflow_checks = previous_overflow_checks;
                        result?;
                    }
                }
                self.width = operand_width;
                self.emit_normalize()?;
                self.width = previous_width;
            }
            ExprKind::CheckedIntegerOption { .. } => {
                return Err(self.error(CodegenErrorKind::RuntimeExpressionUnsupported));
            }
            ExprKind::IntegerOptionUnwrapOr {
                option,
                fallback,
                trap,
                message,
                unchecked,
                lazy,
            } => {
                let (operand_width, previous_width) =
                    self.emit_checked_integer_option(tree, option, depth + 1)?;
                if unchecked {
                    // The caller promises that the checked producer returned `Some`.
                } else if trap {
                    if message {
                        let message =
                            fallback.ok_or(self.error(CodegenErrorKind::RuntimeTypeMismatch))?;
                        self.emit(&[0x50, 0x41, 0x50])?;
                        self.evaluation_depth += 2;
                        if !matches!(
                            tree.expression(message).map(|value| value.kind),
                            Some(ExprKind::String(_))
                        ) {
                            self.emit_expression(tree, message, depth + 1)?;
                        }
                        self.emit(&[0x41, 0x58, 0x58])?;
                        self.evaluation_depth -= 2;
                    }
                    self.emit(&[0x4d, 0x85, 0xc0])?;
                    self.emit_trap_branch(0x84)?;
                } else if lazy {
                    let fallback = fallback
                        .and_then(|fallback| tree.expression(fallback))
                        .ok_or(self.error(CodegenErrorKind::RuntimeTypeMismatch))?;
                    let ExprKind::Closure {
                        parameter: None,
                        body,
                    } = fallback.kind
                    else {
                        return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
                    };
                    self.emit(&[0x4d, 0x85, 0xc0])?;
                    let some = self.emit_forward_branch(0x85)?;
                    self.emit_expression(tree, body, depth + 1)?;
                    self.patch_forward_branch(some)?;
                } else {
                    self.emit(&[0x50, 0x41, 0x50])?;
                    self.evaluation_depth += 2;
                    if let Some(fallback) = fallback {
                        self.emit_expression(tree, fallback, depth + 1)?;
                    } else {
                        self.emit(&[0x31, 0xc0])?;
                    }
                    self.emit(&[0x41, 0x58, 0x59, 0x4d, 0x85, 0xc0, 0x48, 0x0f, 0x45, 0xc1])?;
                    self.evaluation_depth -= 2;
                }
                self.width = operand_width;
                self.emit_normalize()?;
                self.width = previous_width;
            }
            ExprKind::IntegerOptionPredicate {
                option,
                some,
                closure,
            } => {
                let (operand_width, previous_width) =
                    self.emit_checked_integer_option(tree, option, depth + 1)?;
                if let Some(closure) = closure {
                    let closure = tree
                        .expression(closure)
                        .ok_or(self.error(CodegenErrorKind::RuntimeExpressionUnsupported))?;
                    let ExprKind::Closure {
                        parameter: Some(parameter),
                        body,
                    } = closure.kind
                    else {
                        return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
                    };
                    let result_type = checked_option_integer_type(
                        self.function,
                        self.resolver,
                        &self.locals[..self.saved_locals],
                        tree,
                        option,
                        depth + 1,
                    )
                    .map_err(|kind| self.error(kind))?;
                    let mut closure_tree = *tree;
                    closure_tree
                        .bind_closure_parameter(parameter, result_type)
                        .map_err(|kind| self.error(CodegenErrorKind::Expression(kind)))?;
                    self.emit(&[0x4d, 0x85, 0xc0])?;
                    let none = self.emit_forward_branch(0x84)?;
                    self.emit(&[0x50])?;
                    self.evaluation_depth += 1;
                    self.width = operand_width;
                    self.emit_expression(&closure_tree, body, depth + 1)?;
                    self.emit(&[0x48, 0x83, 0xc4, 0x08])?;
                    self.evaluation_depth -= 1;
                    let end = self.emit_unconditional_forward_branch()?;
                    self.patch_forward_branch(none)?;
                    self.emit(&[0x48, 0xb8])?;
                    self.emit(&u64::from(some).to_le_bytes())?;
                    self.patch_forward_branch(end)?;
                } else {
                    self.emit(&[0x4c, 0x89, 0xc0])?;
                    if !some {
                        self.emit(&[0x48, 0x83, 0xf0, 1])?;
                    }
                }
                self.width = runtime_width("u64")
                    .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
                self.emit_normalize()?;
                self.width = previous_width;
            }
            ExprKind::IntegerOptionMapOr {
                option,
                default,
                closure,
            } => {
                let (_, previous_width) =
                    self.emit_checked_integer_option(tree, option, depth + 1)?;
                let input_type = checked_option_integer_type(
                    self.function,
                    self.resolver,
                    &self.locals[..self.saved_locals],
                    tree,
                    option,
                    depth + 1,
                )
                .map_err(|kind| self.error(kind))?;
                let closure_expression = tree
                    .expression(closure)
                    .ok_or(self.error(CodegenErrorKind::RuntimeExpressionUnsupported))?;
                let ExprKind::Closure {
                    parameter: Some(parameter),
                    body,
                } = closure_expression.kind
                else {
                    return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
                };
                let mut closure_tree = *tree;
                closure_tree
                    .bind_closure_parameter(parameter, input_type)
                    .map_err(|kind| self.error(CodegenErrorKind::Expression(kind)))?;
                self.emit(&[0x50, 0x41, 0x50])?;
                self.evaluation_depth += 2;
                self.emit_expression(tree, default, depth + 1)?;
                self.emit(&[0x49, 0x89, 0xc1, 0x41, 0x58, 0x59, 0x4c, 0x89, 0xc8])?;
                self.evaluation_depth -= 2;
                self.emit(&[0x4d, 0x85, 0xc0])?;
                let none = self.emit_forward_branch(0x84)?;
                self.emit(&[0x48, 0x89, 0xc8, 0x50])?;
                self.evaluation_depth += 1;
                self.emit_expression(&closure_tree, body, depth + 1)?;
                self.emit(&[0x48, 0x83, 0xc4, 0x08])?;
                self.evaluation_depth -= 1;
                self.patch_forward_branch(none)?;
                self.width = previous_width;
            }
            ExprKind::IntegerOptionMapOrElse {
                option,
                default_closure,
                map_closure,
            } => {
                let (_, previous_width) =
                    self.emit_checked_integer_option(tree, option, depth + 1)?;
                let input_type = checked_option_integer_type(
                    self.function,
                    self.resolver,
                    &self.locals[..self.saved_locals],
                    tree,
                    option,
                    depth + 1,
                )
                .map_err(|kind| self.error(kind))?;
                let default_expression = tree
                    .expression(default_closure)
                    .ok_or(self.error(CodegenErrorKind::RuntimeExpressionUnsupported))?;
                let ExprKind::Closure {
                    parameter: None,
                    body: default_body,
                } = default_expression.kind
                else {
                    return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
                };
                let map_expression = tree
                    .expression(map_closure)
                    .ok_or(self.error(CodegenErrorKind::RuntimeExpressionUnsupported))?;
                let ExprKind::Closure {
                    parameter: Some(parameter),
                    body: map_body,
                } = map_expression.kind
                else {
                    return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
                };
                let mut closure_tree = *tree;
                closure_tree
                    .bind_closure_parameter(parameter, input_type)
                    .map_err(|kind| self.error(CodegenErrorKind::Expression(kind)))?;
                self.emit(&[0x4d, 0x85, 0xc0])?;
                let none = self.emit_forward_branch(0x84)?;
                self.emit(&[0x50])?;
                self.evaluation_depth += 1;
                self.emit_expression(&closure_tree, map_body, depth + 1)?;
                self.emit(&[0x48, 0x83, 0xc4, 0x08])?;
                self.evaluation_depth -= 1;
                let done = self.emit_unconditional_forward_branch()?;
                self.patch_forward_branch(none)?;
                self.emit_expression(tree, default_body, depth + 1)?;
                self.patch_forward_branch(done)?;
                self.width = previous_width;
            }
            ExprKind::IntegerOptionMapOrDefault {
                option,
                map_closure,
            } => {
                let (_, previous_width) =
                    self.emit_checked_integer_option(tree, option, depth + 1)?;
                let input_type = checked_option_integer_type(
                    self.function,
                    self.resolver,
                    &self.locals[..self.saved_locals],
                    tree,
                    option,
                    depth + 1,
                )
                .map_err(|kind| self.error(kind))?;
                let map_expression = tree
                    .expression(map_closure)
                    .ok_or(self.error(CodegenErrorKind::RuntimeExpressionUnsupported))?;
                let ExprKind::Closure {
                    parameter: Some(parameter),
                    body,
                } = map_expression.kind
                else {
                    return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
                };
                let mut closure_tree = *tree;
                closure_tree
                    .bind_closure_parameter(parameter, input_type)
                    .map_err(|kind| self.error(CodegenErrorKind::Expression(kind)))?;
                self.emit(&[0x4d, 0x85, 0xc0])?;
                let none = self.emit_forward_branch(0x84)?;
                self.emit(&[0x50])?;
                self.evaluation_depth += 1;
                self.emit_expression(&closure_tree, body, depth + 1)?;
                self.emit(&[0x48, 0x83, 0xc4, 0x08])?;
                self.evaluation_depth -= 1;
                let done = self.emit_unconditional_forward_branch()?;
                self.patch_forward_branch(none)?;
                self.emit(&[0x31, 0xc0])?;
                self.patch_forward_branch(done)?;
                self.width = previous_width;
            }
            ExprKind::IntegerOptionMap { .. } => {
                return Err(self.error(CodegenErrorKind::RuntimeExpressionUnsupported));
            }
            ExprKind::IntegerOptionAndThen { .. } => {
                return Err(self.error(CodegenErrorKind::RuntimeExpressionUnsupported));
            }
            ExprKind::IntegerOptionOrElse { .. } => {
                return Err(self.error(CodegenErrorKind::RuntimeExpressionUnsupported));
            }
            ExprKind::IntegerOptionOr { .. } => {
                return Err(self.error(CodegenErrorKind::RuntimeExpressionUnsupported));
            }
            ExprKind::IntegerOptionXor { .. } => {
                return Err(self.error(CodegenErrorKind::RuntimeExpressionUnsupported));
            }
            ExprKind::IntegerOptionAnd { .. } => {
                return Err(self.error(CodegenErrorKind::RuntimeExpressionUnsupported));
            }
            ExprKind::IntegerOptionThenSome { .. } | ExprKind::IntegerOptionThen { .. } => {
                return Err(self.error(CodegenErrorKind::RuntimeExpressionUnsupported));
            }
            ExprKind::IntegerOptionInspect { .. } => {
                return Err(self.error(CodegenErrorKind::RuntimeExpressionUnsupported));
            }
            ExprKind::IntegerOptionFilter { .. } => {
                return Err(self.error(CodegenErrorKind::RuntimeExpressionUnsupported));
            }
            ExprKind::SaturatingArithmetic {
                base,
                argument,
                operator,
                mixed_signedness,
            } => {
                let base_type = runtime_expression_type_with_locals(
                    self.function,
                    self.resolver,
                    &self.locals[..self.saved_locals],
                    tree,
                    base,
                    depth + 1,
                )
                .map_err(|kind| self.error(kind))?;
                let operand_width = runtime_expression_width(base_type)
                    .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
                let previous_width = self.width;
                self.width = operand_width;
                self.emit_expression(tree, base, depth + 1)?;
                self.emit(&[0x50])?;
                self.evaluation_depth += 1;
                if mixed_signedness {
                    self.width.signed = !operand_width.signed;
                }
                self.emit_expression(tree, argument, depth + 1)?;
                self.width = operand_width;
                self.emit(&[0x59])?;
                self.evaluation_depth -= 1;
                if mixed_signedness {
                    self.emit_saturating_mixed_arithmetic(operator)?;
                } else {
                    self.emit_saturating_arithmetic(operator)?;
                }
                self.width = previous_width;
            }
            ExprKind::IntegerRotate {
                base,
                distance,
                left,
            } => {
                let base_type = runtime_expression_type_with_locals(
                    self.function,
                    self.resolver,
                    &self.locals[..self.saved_locals],
                    tree,
                    base,
                    depth + 1,
                )
                .map_err(|kind| self.error(kind))?;
                let operand_width = runtime_expression_width(base_type)
                    .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
                let previous_width = self.width;
                self.width = operand_width;
                self.emit_expression(tree, base, depth + 1)?;
                self.emit(&[0x50])?;
                self.evaluation_depth += 1;
                self.width = runtime_width("u32")
                    .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
                self.emit_expression(tree, distance, depth + 1)?;
                self.emit(&[0x48, 0x89, 0xc1, 0x58])?;
                self.evaluation_depth -= 1;
                self.width = operand_width;
                match (operand_width.bits, left) {
                    (8, true) => self.emit(&[0xd2, 0xc0])?,
                    (8, false) => self.emit(&[0xd2, 0xc8])?,
                    (16, true) => self.emit(&[0x66, 0xd3, 0xc0])?,
                    (16, false) => self.emit(&[0x66, 0xd3, 0xc8])?,
                    (32, true) => self.emit(&[0xd3, 0xc0])?,
                    (32, false) => self.emit(&[0xd3, 0xc8])?,
                    (64, true) => self.emit(&[0x48, 0xd3, 0xc0])?,
                    (64, false) => self.emit(&[0x48, 0xd3, 0xc8])?,
                    _ => return Err(self.error(CodegenErrorKind::UnsupportedRuntimeType)),
                }
                self.emit_normalize()?;
                self.width = previous_width;
            }
            ExprKind::IntegerFunnelShift {
                base,
                other,
                distance,
                left,
            } => {
                let base_type = runtime_expression_type_with_locals(
                    self.function,
                    self.resolver,
                    &self.locals[..self.saved_locals],
                    tree,
                    base,
                    depth + 1,
                )
                .map_err(|kind| self.error(kind))?;
                let operand_width = runtime_expression_width(base_type)
                    .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
                let previous_width = self.width;
                self.width = operand_width;
                self.emit_expression(tree, base, depth + 1)?;
                self.emit(&[0x50])?;
                self.evaluation_depth += 1;
                self.emit_expression(tree, other, depth + 1)?;
                self.emit(&[0x50])?;
                self.evaluation_depth += 1;
                self.width = runtime_width("u32")
                    .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
                self.emit_expression(tree, distance, depth + 1)?;
                self.emit(&[0x49, 0x89, 0xc2, 0x59, 0x58])?;
                self.evaluation_depth -= 2;
                self.width = operand_width;
                self.emit(&[0x41, 0x83, 0xfa, operand_width.bits])?;
                self.emit_trap_branch(0x83)?;
                self.emit(&[0x4d, 0x85, 0xd2])?;
                let nonzero = self.emit_forward_branch(0x85)?;
                self.emit(if left {
                    &[0x90][..]
                } else {
                    &[0x48, 0x89, 0xc8][..]
                })?;
                let done = self.emit_unconditional_forward_branch()?;
                self.patch_forward_branch(nonzero)?;
                self.emit(&[0x49, 0x89, 0xc0, 0x49, 0x89, 0xc9])?;
                if left {
                    self.emit(&[
                        0x44,
                        0x89,
                        0xd1,
                        0x49,
                        0xd3,
                        0xe0,
                        0xb9,
                        operand_width.bits,
                        0,
                        0,
                        0,
                        0x44,
                        0x29,
                        0xd1,
                        0x49,
                        0xd3,
                        0xe9,
                    ])?;
                } else {
                    self.emit(&[
                        0xb9,
                        operand_width.bits,
                        0,
                        0,
                        0,
                        0x44,
                        0x29,
                        0xd1,
                        0x49,
                        0xd3,
                        0xe0,
                        0x44,
                        0x89,
                        0xd1,
                        0x49,
                        0xd3,
                        0xe9,
                    ])?;
                }
                self.emit(&[0x4d, 0x09, 0xc8, 0x4c, 0x89, 0xc0])?;
                self.patch_forward_branch(done)?;
                self.emit_normalize()?;
                self.width = previous_width;
            }
            ExprKind::IntegerSignCast {
                base,
                signed,
                saturating,
                strict,
            } => {
                let RuntimeExpressionType::Integer(Some(source_type)) =
                    runtime_expression_type_with_locals(
                        self.function,
                        self.resolver,
                        &self.locals[..self.saved_locals],
                        tree,
                        base,
                        depth + 1,
                    )
                    .map_err(|kind| self.error(kind))?
                else {
                    return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
                };
                let source_width = runtime_width(source_type.name())
                    .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
                let target_type = if signed {
                    source_type.signed_counterpart()
                } else {
                    source_type.unsigned_counterpart()
                }
                .ok_or(self.error(CodegenErrorKind::RuntimeTypeMismatch))?;
                let target_width = runtime_width(target_type.name())
                    .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
                let previous_width = self.width;
                self.width = source_width;
                self.emit_expression(tree, base, depth + 1)?;
                if saturating || strict {
                    let sign_bit = 1u64 << (source_width.bits - 1);
                    self.emit(&[0x48, 0xba])?;
                    self.emit(&sign_bit.to_le_bytes())?;
                    self.emit(&[0x48, 0x85, 0xd0])?;
                    if strict {
                        self.emit_trap_branch(0x85)?;
                    } else {
                        let in_range = self.emit_forward_branch(0x84)?;
                        let saturated = if signed { sign_bit - 1 } else { 0 };
                        self.emit(&[0x48, 0xb8])?;
                        self.emit(&saturated.to_le_bytes())?;
                        self.patch_forward_branch(in_range)?;
                    }
                }
                self.width = target_width;
                self.emit_normalize()?;
                self.width = previous_width;
            }
            ExprKind::IntegerWidthCast { base, target, mode } => {
                let RuntimeExpressionType::Integer(Some(source_type)) =
                    runtime_expression_type_with_locals(
                        self.function,
                        self.resolver,
                        &self.locals[..self.saved_locals],
                        tree,
                        base,
                        depth + 1,
                    )
                    .map_err(|kind| self.error(kind))?
                else {
                    return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
                };
                if !source_type.supports_width_cast(target, mode) {
                    return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
                }
                let source_width = runtime_width(source_type.name())
                    .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
                let target_width = runtime_width(target.name())
                    .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
                let previous_width = self.width;
                self.width = source_width;
                self.emit_expression(tree, base, depth + 1)?;
                if mode == crate::expression::IntegerWidthCastMode::SaturatingTruncate {
                    self.emit(&[0x48, 0xba])?;
                    self.emit(&target_width.maximum.to_le_bytes())?;
                    self.emit(&[0x48, 0x39, 0xd0])?;
                    let within_maximum =
                        self.emit_forward_branch(if source_width.signed { 0x8e } else { 0x86 })?;
                    self.emit(&[0x48, 0xb8])?;
                    self.emit(&target_width.maximum.to_le_bytes())?;
                    let saturated_maximum = self.emit_unconditional_forward_branch()?;
                    self.patch_forward_branch(within_maximum)?;
                    let saturated_minimum = if source_width.signed {
                        self.emit(&[0x48, 0xba])?;
                        self.emit(&(target_width.minimum as u64).to_le_bytes())?;
                        self.emit(&[0x48, 0x39, 0xd0])?;
                        let within_minimum = self.emit_forward_branch(0x8d)?;
                        self.emit(&[0x48, 0xb8])?;
                        self.emit(&(target_width.minimum as u64).to_le_bytes())?;
                        Some(within_minimum)
                    } else {
                        None
                    };
                    if let Some(within_minimum) = saturated_minimum {
                        self.patch_forward_branch(within_minimum)?;
                    }
                    self.patch_forward_branch(saturated_maximum)?;
                }
                if matches!(
                    mode,
                    crate::expression::IntegerWidthCastMode::Saturating
                        | crate::expression::IntegerWidthCastMode::Strict
                ) {
                    let strict = mode == crate::expression::IntegerWidthCastMode::Strict;
                    let check_minimum = source_width.signed
                        && (!target_width.signed || target_width.bits < source_width.bits);
                    let check_maximum = if source_width.signed {
                        target_width.bits < source_width.bits
                    } else if target_width.signed {
                        target_width.bits <= source_width.bits
                    } else {
                        target_width.bits < source_width.bits
                    };
                    let mut saturated_minimum = None;
                    if check_minimum {
                        let minimum = if target_width.signed {
                            target_width.minimum as u64
                        } else {
                            0
                        };
                        self.emit(&[0x48, 0xba])?;
                        self.emit(&minimum.to_le_bytes())?;
                        self.emit(&[0x48, 0x39, 0xd0])?;
                        if strict {
                            self.emit_trap_branch(0x8c)?;
                        } else {
                            let within_minimum = self.emit_forward_branch(0x8d)?;
                            self.emit(&[0x48, 0xb8])?;
                            self.emit(&minimum.to_le_bytes())?;
                            saturated_minimum = Some(self.emit_unconditional_forward_branch()?);
                            self.patch_forward_branch(within_minimum)?;
                        }
                    }
                    let mut saturated_maximum = None;
                    if check_maximum {
                        self.emit(&[0x48, 0xba])?;
                        self.emit(&target_width.maximum.to_le_bytes())?;
                        self.emit(&[0x48, 0x39, 0xd0])?;
                        let overflow_condition = if source_width.signed { 0x8f } else { 0x87 };
                        if strict {
                            self.emit_trap_branch(overflow_condition)?;
                        } else {
                            let within_maximum =
                                self.emit_forward_branch(if source_width.signed {
                                    0x8e
                                } else {
                                    0x86
                                })?;
                            self.emit(&[0x48, 0xb8])?;
                            self.emit(&target_width.maximum.to_le_bytes())?;
                            saturated_maximum = Some(self.emit_unconditional_forward_branch()?);
                            self.patch_forward_branch(within_maximum)?;
                        }
                    }
                    if let Some(branch) = saturated_minimum {
                        self.patch_forward_branch(branch)?;
                    }
                    if let Some(branch) = saturated_maximum {
                        self.patch_forward_branch(branch)?;
                    }
                }
                self.width = target_width;
                self.emit_normalize()?;
                self.width = previous_width;
            }
            ExprKind::IntegerClampMagnitude { base, limit } => {
                let RuntimeExpressionType::Integer(Some(base_type)) =
                    runtime_expression_type_with_locals(
                        self.function,
                        self.resolver,
                        &self.locals[..self.saved_locals],
                        tree,
                        base,
                        depth + 1,
                    )
                    .map_err(|kind| self.error(kind))?
                else {
                    return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
                };
                let base_width = runtime_width(base_type.name())
                    .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
                let limit_type = base_type
                    .unsigned_counterpart()
                    .ok_or(self.error(CodegenErrorKind::RuntimeTypeMismatch))?;
                let limit_width = runtime_width(limit_type.name())
                    .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
                let previous_width = self.width;
                self.width = base_width;
                self.emit_expression(tree, base, depth + 1)?;
                self.emit(&[0x50])?;
                self.evaluation_depth += 1;
                self.width = limit_width;
                self.emit_expression(tree, limit, depth + 1)?;
                self.emit(&[0x48, 0x89, 0xc2, 0x58])?;
                self.evaluation_depth -= 1;
                self.width = base_width;
                self.emit(&[0x48, 0xb9])?;
                self.emit(&base_width.maximum.to_le_bytes())?;
                self.emit(&[0x48, 0x39, 0xca])?;
                let done_large_limit = self.emit_forward_branch(0x87)?;
                self.emit(&[0x48, 0x39, 0xd0])?;
                let check_lower = self.emit_forward_branch(0x8e)?;
                self.emit(&[0x48, 0x89, 0xd0])?;
                let done_upper = self.emit_unconditional_forward_branch()?;
                self.patch_forward_branch(check_lower)?;
                self.emit(&[0x48, 0xf7, 0xda, 0x48, 0x39, 0xd0])?;
                let done_lower = self.emit_forward_branch(0x8d)?;
                self.emit(&[0x48, 0x89, 0xd0])?;
                self.patch_forward_branch(done_large_limit)?;
                self.patch_forward_branch(done_upper)?;
                self.patch_forward_branch(done_lower)?;
                self.emit_normalize()?;
                self.width = previous_width;
            }
            ExprKind::IntegerEndianFrom {
                value,
                integer_type,
                little,
            } => {
                let previous_width = self.width;
                self.width = runtime_width(integer_type.name())
                    .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
                self.emit_expression(tree, value, depth + 1)?;
                if !little {
                    match self.width.bits {
                        8 => {}
                        16 => self.emit(&[0x66, 0xc1, 0xc8, 8])?,
                        32 => self.emit(&[0x0f, 0xc8])?,
                        64 => self.emit(&[0x48, 0x0f, 0xc8])?,
                        _ => return Err(self.error(CodegenErrorKind::UnsupportedRuntimeType)),
                    }
                }
                self.emit_normalize()?;
                self.width = previous_width;
            }
            ExprKind::IntegerFromBytes {
                bytes,
                integer_type,
                order,
            } => {
                let width = runtime_width(integer_type.name())
                    .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
                let count = usize::from(width.bits / 8);
                let previous_width = self.width;
                self.width = runtime_width("u8")
                    .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
                self.emit_array_to_stack(tree, bytes, count)?;
                self.emit_pack_array_word(
                    RuntimeArrayElementType::Integer(Some(crate::IntegerType::U8)),
                    count,
                    1,
                    0,
                )?;
                self.evaluation_depth -= count;
                self.emit_stack_cleanup_bytes(
                    count
                        .checked_mul(8)
                        .ok_or(self.error(CodegenErrorKind::OutputTooSmall))?,
                )?;
                self.width = width;
                if order == crate::expression::IntegerByteOrder::Big {
                    match width.bits {
                        8 => {}
                        16 => self.emit(&[0x66, 0xc1, 0xc8, 8])?,
                        32 => self.emit(&[0x0f, 0xc8])?,
                        64 => self.emit(&[0x48, 0x0f, 0xc8])?,
                        _ => return Err(self.error(CodegenErrorKind::UnsupportedRuntimeType)),
                    }
                }
                self.emit_normalize()?;
                self.width = previous_width;
            }
            ExprKind::IntegerAssociatedConstant {
                integer_type,
                constant,
            } => {
                let source_width = runtime_width(integer_type.name())
                    .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
                let value = match constant {
                    crate::expression::IntegerAssociatedConstant::Minimum
                        if source_width.signed =>
                    {
                        1u64 << (source_width.bits - 1)
                    }
                    crate::expression::IntegerAssociatedConstant::Minimum => 0,
                    crate::expression::IntegerAssociatedConstant::Maximum => source_width.maximum,
                    crate::expression::IntegerAssociatedConstant::Bits => {
                        u64::from(source_width.bits)
                    }
                };
                let previous_width = self.width;
                self.width = if constant == crate::expression::IntegerAssociatedConstant::Bits {
                    runtime_width("u32")
                        .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?
                } else {
                    source_width
                };
                self.emit(&[0x48, 0xb8])?;
                self.emit(&value.to_le_bytes())?;
                self.emit_normalize()?;
                self.width = previous_width;
            }
            ExprKind::IntegerWrappingShift {
                base,
                distance,
                left,
                unbounded,
                strict,
            } => {
                let base_type = runtime_expression_type_with_locals(
                    self.function,
                    self.resolver,
                    &self.locals[..self.saved_locals],
                    tree,
                    base,
                    depth + 1,
                )
                .map_err(|kind| self.error(kind))?;
                let operand_width = runtime_expression_width(base_type)
                    .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
                let previous_width = self.width;
                self.width = operand_width;
                self.emit_expression(tree, base, depth + 1)?;
                self.emit(&[0x50])?;
                self.evaluation_depth += 1;
                self.width = runtime_width("u32")
                    .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
                self.emit_expression(tree, distance, depth + 1)?;
                self.emit(&[0x48, 0x89, 0xc1, 0x58])?;
                self.evaluation_depth -= 1;
                self.width = operand_width;
                let in_range = if strict {
                    self.emit(&[0x83, 0xf9, operand_width.bits])?;
                    self.emit_trap_branch(0x83)?;
                    None
                } else if unbounded {
                    self.emit(&[0x83, 0xf9, operand_width.bits])?;
                    Some(self.emit_forward_branch(0x82)?)
                } else {
                    self.emit(&[0x83, 0xe1, operand_width.bits - 1])?;
                    None
                };
                let end = if in_range.is_some() {
                    if !left && operand_width.signed {
                        self.emit(&[0xb1, operand_width.bits - 1, 0x48, 0xd3, 0xf8])?;
                    } else {
                        self.emit(&[0x31, 0xc0])?;
                    }
                    Some(self.emit_unconditional_forward_branch()?)
                } else {
                    None
                };
                if let Some(in_range) = in_range {
                    self.patch_forward_branch(in_range)?;
                }
                if left {
                    self.emit(&[0x48, 0xd3, 0xe0])?;
                } else if operand_width.signed {
                    self.emit(&[0x48, 0xd3, 0xf8])?;
                } else {
                    self.emit(&[0x48, 0xd3, 0xe8])?;
                }
                if let Some(end) = end {
                    self.patch_forward_branch(end)?;
                }
                self.emit_normalize()?;
                self.width = previous_width;
            }
            ExprKind::IntegerWrappingPower {
                base,
                exponent,
                mode,
            } => {
                use crate::expression::IntegerPowerMode;
                let base_type = runtime_expression_type_with_locals(
                    self.function,
                    self.resolver,
                    &self.locals[..self.saved_locals],
                    tree,
                    base,
                    depth + 1,
                )
                .map_err(|kind| self.error(kind))?;
                let operand_width = runtime_expression_width(base_type)
                    .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
                let previous_width = self.width;
                self.width = operand_width;
                self.emit_expression(tree, base, depth + 1)?;
                self.emit(&[0x50])?;
                self.evaluation_depth += 1;
                self.width = runtime_width("u32")
                    .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
                self.emit_expression(tree, exponent, depth + 1)?;
                self.emit(&[0x49, 0x89, 0xc0, 0x59, 0xb8, 1, 0, 0, 0])?;
                self.evaluation_depth -= 1;
                self.width = operand_width;
                let loop_start = self.length;
                self.emit(&[0x4d, 0x85, 0xc0])?;
                let done = self.emit_forward_branch(0x84)?;
                self.emit(&[0x41, 0xf6, 0xc0, 1])?;
                let even = self.emit_forward_branch(0x84)?;
                match mode {
                    IntegerPowerMode::Checked => {
                        self.emit(&[0x51])?;
                        self.emit_binary(crate::BinaryOperator::Multiply)?;
                        self.emit(&[0x59])?;
                    }
                    IntegerPowerMode::Strict => {
                        self.emit(&[0x51])?;
                        let previous_overflow_checks = self.overflow_checks;
                        self.overflow_checks = true;
                        let result = self.emit_binary(crate::BinaryOperator::Multiply);
                        self.overflow_checks = previous_overflow_checks;
                        result?;
                        self.emit(&[0x59])?;
                    }
                    IntegerPowerMode::Wrapping => {
                        self.emit(&[0x48, 0x0f, 0xaf, 0xc1])?;
                        self.emit_normalize()?;
                    }
                    IntegerPowerMode::Saturating => self.emit_saturating_multiplication()?,
                }
                self.patch_forward_branch(even)?;
                self.emit(&[0x49, 0xd1, 0xe8, 0x4d, 0x85, 0xc0])?;
                let finished = self.emit_forward_branch(0x84)?;
                if mode == IntegerPowerMode::Wrapping {
                    self.emit(&[0x48, 0x0f, 0xaf, 0xc9])?;
                } else {
                    self.emit(&[0x50, 0x48, 0x89, 0xc8])?;
                    if mode == IntegerPowerMode::Saturating {
                        self.emit_saturating_multiplication()?;
                    } else if mode == IntegerPowerMode::Strict {
                        let previous_overflow_checks = self.overflow_checks;
                        self.overflow_checks = true;
                        let result = self.emit_binary(crate::BinaryOperator::Multiply);
                        self.overflow_checks = previous_overflow_checks;
                        result?;
                    } else {
                        self.emit_binary(crate::BinaryOperator::Multiply)?;
                    }
                    self.emit(&[0x48, 0x89, 0xc1, 0x58])?;
                }
                self.emit_backward_branch(loop_start)?;
                self.patch_forward_branch(finished)?;
                self.patch_forward_branch(done)?;
                self.emit_normalize()?;
                self.width = previous_width;
            }
            ExprKind::IntegerBitTransform { base, transform } => {
                use crate::expression::IntegerBitTransform;
                let base_type = runtime_expression_type_with_locals(
                    self.function,
                    self.resolver,
                    &self.locals[..self.saved_locals],
                    tree,
                    base,
                    depth + 1,
                )
                .map_err(|kind| self.error(kind))?;
                let operand_width = runtime_expression_width(base_type)
                    .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
                let previous_width = self.width;
                self.width = operand_width;
                self.emit_expression(tree, base, depth + 1)?;
                match transform {
                    IntegerBitTransform::IsolateHighestOne => {
                        self.emit(&[0x48, 0x89, 0xc1])?;
                        let mut shift = 1_u8;
                        while shift < operand_width.bits {
                            self.emit(&[
                                0x48, 0x89, 0xca, 0x48, 0xc1, 0xea, shift, 0x48, 0x09, 0xd1,
                            ])?;
                            shift <<= 1;
                        }
                        self.emit(&[0x48, 0x89, 0xc8, 0x48, 0xd1, 0xe9, 0x48, 0x29, 0xc8])?;
                    }
                    IntegerBitTransform::IsolateLowestOne => {
                        self.emit(&[0x48, 0x89, 0xc1, 0x48, 0xf7, 0xd8, 0x48, 0x21, 0xc8])?;
                    }
                    IntegerBitTransform::ToLittleEndian => {}
                    IntegerBitTransform::SwapBytes | IntegerBitTransform::ToBigEndian => {
                        match operand_width.bits {
                            8 => {}
                            16 => self.emit(&[0x66, 0xc1, 0xc8, 8])?,
                            32 => self.emit(&[0x0f, 0xc8])?,
                            64 => self.emit(&[0x48, 0x0f, 0xc8])?,
                            _ => {
                                return Err(self.error(CodegenErrorKind::UnsupportedRuntimeType));
                            }
                        }
                    }
                    IntegerBitTransform::ReverseBits => {
                        self.emit(&[0x31, 0xc9])?;
                        for _ in 0..operand_width.bits {
                            self.emit(&[0x48, 0xd1, 0xe8, 0x48, 0xd1, 0xd1])?;
                        }
                        self.emit(&[0x48, 0x89, 0xc8])?;
                    }
                    IntegerBitTransform::WrappingNegate => self.emit(&[0x48, 0xf7, 0xd8])?,
                    IntegerBitTransform::StrictNegate => {
                        self.emit(&[0x48, 0xf7, 0xd8])?;
                        self.emit_trap_branch(if operand_width.signed { 0x80 } else { 0x82 })?;
                    }
                    IntegerBitTransform::SaturatingNegate
                    | IntegerBitTransform::SaturatingAbsolute => {
                        self.emit(&[0x48, 0xba])?;
                        self.emit(&(operand_width.minimum as u64).to_le_bytes())?;
                        self.emit(&[0x48, 0x39, 0xd0])?;
                        let ordinary = self.emit_forward_branch(0x85)?;
                        self.emit(&[0x48, 0xb8])?;
                        self.emit(&operand_width.maximum.to_le_bytes())?;
                        let saturated = self.emit_unconditional_forward_branch()?;
                        self.patch_forward_branch(ordinary)?;
                        let nonnegative = if transform == IntegerBitTransform::SaturatingAbsolute {
                            self.emit(&[0x48, 0x85, 0xc0])?;
                            Some(self.emit_forward_branch(0x89)?)
                        } else {
                            None
                        };
                        self.emit(&[0x48, 0xf7, 0xd8])?;
                        if let Some(nonnegative) = nonnegative {
                            self.patch_forward_branch(nonnegative)?;
                        }
                        self.patch_forward_branch(saturated)?;
                    }
                    IntegerBitTransform::WrappingAbsolute
                    | IntegerBitTransform::Absolute
                    | IntegerBitTransform::StrictAbsolute => {
                        self.emit(&[0x48, 0x85, 0xc0])?;
                        let nonnegative = self.emit_forward_branch(0x89)?;
                        self.emit(&[0x48, 0xf7, 0xd8])?;
                        if transform == IntegerBitTransform::StrictAbsolute
                            || (transform == IntegerBitTransform::Absolute && self.overflow_checks)
                        {
                            if operand_width.bits == 64 {
                                self.emit_trap_branch(0x80)?;
                            } else {
                                self.emit_range_check()?;
                            }
                        }
                        self.patch_forward_branch(nonnegative)?;
                    }
                    IntegerBitTransform::NextPowerOfTwo
                    | IntegerBitTransform::WrappingNextPowerOfTwo => {
                        self.emit(&[0x48, 0x83, 0xf8, 1])?;
                        let above_one = self.emit_forward_branch(0x87)?;
                        self.emit(&[0xb8, 1, 0, 0, 0])?;
                        let end = self.emit_unconditional_forward_branch()?;
                        self.patch_forward_branch(above_one)?;
                        self.emit(&[0x48, 0xff, 0xc8])?;
                        let mut shift = 1_u8;
                        while shift < operand_width.bits {
                            self.emit(&[
                                0x48, 0x89, 0xc1, 0x48, 0xc1, 0xe9, shift, 0x48, 0x09, 0xc8,
                            ])?;
                            shift <<= 1;
                        }
                        self.emit(&[0x48, 0x83, 0xc0, 1])?;
                        if transform == IntegerBitTransform::NextPowerOfTwo && self.overflow_checks
                        {
                            if operand_width.bits == 64 {
                                self.emit_trap_branch(0x82)?;
                            } else {
                                self.emit_range_check()?;
                            }
                        } else {
                            self.emit_normalize()?;
                        }
                        self.patch_forward_branch(end)?;
                    }
                    IntegerBitTransform::IntegerSquareRoot => {
                        if operand_width.signed {
                            self.emit(&[0x48, 0x85, 0xc0])?;
                            self.emit_trap_branch(0x88)?;
                        }
                        self.emit_integer_square_root(operand_width)?;
                    }
                    IntegerBitTransform::Signum => {
                        self.emit(&[
                            0x48, 0x85, 0xc0, 0x0f, 0x9f, 0xc0, 0x0f, 0x9c, 0xc1, 0x0f, 0xb6, 0xc0,
                            0x0f, 0xb6, 0xc9, 0x48, 0x29, 0xc8,
                        ])?;
                    }
                }
                self.emit_normalize()?;
                self.width = previous_width;
            }
            ExprKind::IntegerUnsignedAbsolute { base } => {
                let RuntimeExpressionType::Integer(Some(base_integer_type)) =
                    runtime_expression_type_with_locals(
                        self.function,
                        self.resolver,
                        &self.locals[..self.saved_locals],
                        tree,
                        base,
                        depth + 1,
                    )
                    .map_err(|kind| self.error(kind))?
                else {
                    return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
                };
                let result_type = base_integer_type
                    .unsigned_counterpart()
                    .ok_or(self.error(CodegenErrorKind::RuntimeTypeMismatch))?;
                let operand_width = runtime_width(base_integer_type.name())
                    .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
                let result_width = runtime_width(result_type.name())
                    .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
                let previous_width = self.width;
                self.width = operand_width;
                self.emit_expression(tree, base, depth + 1)?;
                self.emit(&[0x48, 0x85, 0xc0])?;
                let nonnegative = self.emit_forward_branch(0x89)?;
                self.emit(&[0x48, 0xf7, 0xd8])?;
                self.patch_forward_branch(nonnegative)?;
                self.emit_normalize_width(result_width)?;
                self.width = previous_width;
            }
            ExprKind::IntegerClamp {
                base,
                minimum,
                maximum,
            } => {
                let base_type = runtime_expression_type_with_locals(
                    self.function,
                    self.resolver,
                    &self.locals[..self.saved_locals],
                    tree,
                    base,
                    depth + 1,
                )
                .map_err(|kind| self.error(kind))?;
                let operand_width = runtime_expression_width(base_type)
                    .ok_or(self.error(CodegenErrorKind::RuntimeTypeMismatch))?;
                let previous_width = self.width;
                self.width = operand_width;
                self.emit_expression(tree, base, depth + 1)?;
                self.emit(&[0x50])?;
                self.evaluation_depth += 1;
                self.emit_expression(tree, minimum, depth + 1)?;
                self.emit(&[0x50])?;
                self.evaluation_depth += 1;
                self.emit_expression(tree, maximum, depth + 1)?;
                self.emit(&[0x59, 0x5a])?;
                self.evaluation_depth -= 2;
                self.emit(&[0x48, 0x39, 0xc1])?;
                self.emit_trap_branch(if operand_width.signed { 0x8f } else { 0x87 })?;
                self.emit(&[0x48, 0x39, 0xca])?;
                let check_maximum =
                    self.emit_forward_branch(if operand_width.signed { 0x8d } else { 0x83 })?;
                self.emit(&[0x48, 0x89, 0xc8])?;
                let end_below = self.emit_unconditional_forward_branch()?;
                self.patch_forward_branch(check_maximum)?;
                self.emit(&[0x48, 0x39, 0xc2])?;
                let use_value =
                    self.emit_forward_branch(if operand_width.signed { 0x8e } else { 0x86 })?;
                let end_above = self.emit_unconditional_forward_branch()?;
                self.patch_forward_branch(use_value)?;
                self.emit(&[0x48, 0x89, 0xd0])?;
                self.patch_forward_branch(end_below)?;
                self.patch_forward_branch(end_above)?;
                self.emit_normalize()?;
                self.width = previous_width;
            }
            ExprKind::IntegerPairTransform {
                base,
                other,
                transform,
            } => {
                let RuntimeExpressionType::Integer(Some(base_integer_type)) =
                    runtime_expression_type_with_locals(
                        self.function,
                        self.resolver,
                        &self.locals[..self.saved_locals],
                        tree,
                        base,
                        depth + 1,
                    )
                    .map_err(|kind| self.error(kind))?
                else {
                    return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
                };
                let result_type =
                    if transform == crate::expression::IntegerPairTransform::AbsoluteDifference {
                        base_integer_type
                            .unsigned_counterpart()
                            .unwrap_or(base_integer_type)
                    } else {
                        base_integer_type
                    };
                let operand_width = runtime_width(base_integer_type.name())
                    .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
                let result_width = runtime_width(result_type.name())
                    .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
                let previous_width = self.width;
                self.width = operand_width;
                self.emit_expression(tree, base, depth + 1)?;
                self.emit(&[0x50])?;
                self.evaluation_depth += 1;
                self.emit_expression(tree, other, depth + 1)?;
                self.emit(&[0x59])?;
                self.evaluation_depth -= 1;
                match transform {
                    crate::expression::IntegerPairTransform::Minimum
                    | crate::expression::IntegerPairTransform::Maximum => {
                        self.emit(&[0x48, 0x39, 0xc1])?;
                        let choose_left = self.emit_forward_branch(match transform {
                            crate::expression::IntegerPairTransform::Minimum => {
                                if operand_width.signed { 0x8e } else { 0x86 }
                            }
                            crate::expression::IntegerPairTransform::Maximum => {
                                if operand_width.signed { 0x8d } else { 0x83 }
                            }
                            _ => unreachable!(),
                        })?;
                        let end = self.emit_unconditional_forward_branch()?;
                        self.patch_forward_branch(choose_left)?;
                        self.emit(&[0x48, 0x89, 0xc8])?;
                        self.patch_forward_branch(end)?;
                    }
                    crate::expression::IntegerPairTransform::AbsoluteDifference => {
                        self.emit(&[0x48, 0x89, 0xc2, 0x48, 0x39, 0xd1])?;
                        let left_at_least_right = self
                            .emit_forward_branch(if operand_width.signed { 0x8d } else { 0x83 })?;
                        self.emit(&[0x48, 0x29, 0xc8])?;
                        let end = self.emit_unconditional_forward_branch()?;
                        self.patch_forward_branch(left_at_least_right)?;
                        self.emit(&[0x48, 0x89, 0xc8, 0x48, 0x29, 0xd0])?;
                        self.patch_forward_branch(end)?;
                    }
                    crate::expression::IntegerPairTransform::Midpoint => {
                        self.emit(&[0x49, 0x89, 0xc8, 0x49, 0x31, 0xc0, 0x48, 0x21, 0xc1])?;
                        self.emit(&[0x4c, 0x89, 0xc0])?;
                        self.emit(if operand_width.signed {
                            &[0x48, 0xd1, 0xf8]
                        } else {
                            &[0x48, 0xd1, 0xe8]
                        })?;
                        self.emit(&[0x48, 0x01, 0xc8])?;
                        if operand_width.signed {
                            self.emit(&[0x48, 0x85, 0xc0])?;
                            let nonnegative = self.emit_forward_branch(0x89)?;
                            self.emit(&[0x49, 0x83, 0xe0, 1, 0x4c, 0x01, 0xc0])?;
                            self.patch_forward_branch(nonnegative)?;
                        }
                    }
                    crate::expression::IntegerPairTransform::CarrylessMultiply => {
                        self.emit(&[0x49, 0x89, 0xc0, 0x48, 0x89, 0xc8, 0x31, 0xd2])?;
                        let loop_start = self.length;
                        self.emit(&[0x4d, 0x85, 0xc0])?;
                        let done = self.emit_forward_branch(0x84)?;
                        self.emit(&[0x41, 0xf6, 0xc0, 1])?;
                        let clear = self.emit_forward_branch(0x84)?;
                        self.emit(&[0x48, 0x31, 0xc2])?;
                        self.patch_forward_branch(clear)?;
                        self.emit(&[0x48, 0xd1, 0xe0, 0x49, 0xd1, 0xe8])?;
                        self.emit_backward_branch(loop_start)?;
                        self.patch_forward_branch(done)?;
                        self.emit(&[0x48, 0x89, 0xd0])?;
                    }
                    crate::expression::IntegerPairTransform::ExtractBits
                    | crate::expression::IntegerPairTransform::DepositBits => {
                        self.emit(&[0x49, 0x89, 0xc0, 0x31, 0xd2, 0x41, 0xb9, 1, 0, 0, 0])?;
                        let loop_start = self.length;
                        self.emit(&[0x4d, 0x85, 0xc0])?;
                        let done = self.emit_forward_branch(0x84)?;
                        self.emit(&[0x4d, 0x89, 0xc2, 0x49, 0xf7, 0xda, 0x4d, 0x21, 0xc2])?;
                        if transform == crate::expression::IntegerPairTransform::ExtractBits {
                            self.emit(&[0x4c, 0x85, 0xd1])?;
                        } else {
                            self.emit(&[0x4c, 0x85, 0xc9])?;
                        }
                        let clear = self.emit_forward_branch(0x84)?;
                        if transform == crate::expression::IntegerPairTransform::ExtractBits {
                            self.emit(&[0x4c, 0x09, 0xca])?;
                        } else {
                            self.emit(&[0x4c, 0x09, 0xd2])?;
                        }
                        self.patch_forward_branch(clear)?;
                        self.emit(&[0x4d, 0x31, 0xd0])?;
                        self.emit(&[0x49, 0xd1, 0xe1])?;
                        self.emit_backward_branch(loop_start)?;
                        self.patch_forward_branch(done)?;
                        self.emit(&[0x48, 0x89, 0xd0])?;
                    }
                    crate::expression::IntegerPairTransform::DivideFloor => {
                        self.emit(&[0x48, 0x87, 0xc1, 0x48, 0x85, 0xc9])?;
                        self.emit_trap_branch(0x84)?;
                        if operand_width.signed {
                            self.emit(&[0x49, 0x89, 0xc0, 0x49, 0x31, 0xc8, 0x48, 0x99])?;
                            self.emit(&[0x48, 0xf7, 0xf9, 0x48, 0x85, 0xd2])?;
                            let exact = self.emit_forward_branch(0x84)?;
                            self.emit(&[0x4d, 0x85, 0xc0])?;
                            let same_sign = self.emit_forward_branch(0x89)?;
                            self.emit(&[0x48, 0x83, 0xe8, 1])?;
                            self.patch_forward_branch(same_sign)?;
                            self.patch_forward_branch(exact)?;
                        } else {
                            self.emit(&[0x48, 0x31, 0xd2, 0x48, 0xf7, 0xf1])?;
                        }
                    }
                    crate::expression::IntegerPairTransform::DivideCeiling => {
                        self.emit(&[0x48, 0x87, 0xc1, 0x48, 0x85, 0xc9])?;
                        self.emit_trap_branch(0x84)?;
                        if operand_width.signed {
                            self.emit(&[0x49, 0x89, 0xc0, 0x49, 0x31, 0xc8, 0x48, 0x99])?;
                            self.emit(&[0x48, 0xf7, 0xf9, 0x48, 0x85, 0xd2])?;
                            let exact = self.emit_forward_branch(0x84)?;
                            self.emit(&[0x4d, 0x85, 0xc0])?;
                            let opposite_signs = self.emit_forward_branch(0x88)?;
                            self.emit(&[0x48, 0x83, 0xc0, 1])?;
                            self.patch_forward_branch(opposite_signs)?;
                            self.patch_forward_branch(exact)?;
                        } else {
                            self.emit(&[
                                0x48, 0x31, 0xd2, 0x48, 0xf7, 0xf1, 0x48, 0xf7, 0xda, 0x48, 0x83,
                                0xd0, 0,
                            ])?;
                        }
                    }
                    crate::expression::IntegerPairTransform::NextMultiple => {
                        self.emit(&[0x48, 0x87, 0xc1, 0x48, 0x85, 0xc9])?;
                        self.emit_trap_branch(0x84)?;
                        self.emit(&[0x49, 0x89, 0xc0])?;
                        let negative_one = if operand_width.signed {
                            self.emit(&[0x48, 0x83, 0xf9, 0xff])?;
                            Some(self.emit_forward_branch(0x84)?)
                        } else {
                            None
                        };
                        if operand_width.signed {
                            self.emit(&[
                                0x49, 0x89, 0xc1, 0x49, 0x31, 0xc9, 0x48, 0x99, 0x48, 0xf7, 0xf9,
                            ])?;
                        } else {
                            self.emit(&[0x48, 0x31, 0xd2, 0x48, 0xf7, 0xf1])?;
                        }
                        self.emit(&[0x48, 0x85, 0xd2])?;
                        let exact = self.emit_forward_branch(0x84)?;
                        if operand_width.signed {
                            self.emit(&[0x4d, 0x85, 0xc9])?;
                            let same_sign = self.emit_forward_branch(0x89)?;
                            self.emit(&[0x48, 0x01, 0xca])?;
                            self.patch_forward_branch(same_sign)?;
                        }
                        self.emit(&[0x48, 0x29, 0xd1, 0x4c, 0x89, 0xc0, 0x48, 0x01, 0xc8])?;
                        if self.overflow_checks && operand_width.bits == 64 {
                            self.emit_trap_branch(if operand_width.signed { 0x80 } else { 0x82 })?;
                        } else if self.overflow_checks {
                            self.emit_range_check()?;
                        } else {
                            self.emit_normalize()?;
                        }
                        let end = self.emit_unconditional_forward_branch()?;
                        self.patch_forward_branch(exact)?;
                        self.emit(&[0x4c, 0x89, 0xc0])?;
                        self.patch_forward_branch(end)?;
                        if let Some(negative_one) = negative_one {
                            self.patch_forward_branch(negative_one)?;
                        }
                    }
                }
                self.emit_normalize_width(result_width)?;
                self.width = previous_width;
            }
            ExprKind::IntegerBitCount { base, count } => {
                use crate::expression::IntegerBitCount;
                let base_type = runtime_expression_type_with_locals(
                    self.function,
                    self.resolver,
                    &self.locals[..self.saved_locals],
                    tree,
                    base,
                    depth + 1,
                )
                .map_err(|kind| self.error(kind))?;
                let operand_width = runtime_expression_width(base_type)
                    .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
                let previous_width = self.width;
                self.width = operand_width;
                self.emit_expression(tree, base, depth + 1)?;
                match count {
                    IntegerBitCount::Width => {
                        self.emit(&[0x48, 0x85, 0xc0])?;
                        let zero = self.emit_forward_branch(0x84)?;
                        self.emit(&[0x48, 0x0f, 0xbd, 0xc0, 0x48, 0xff, 0xc0])?;
                        self.patch_forward_branch(zero)?;
                    }
                    IntegerBitCount::Ones | IntegerBitCount::Zeros => {
                        self.emit(&[0x31, 0xc9])?;
                        for _ in 0..operand_width.bits {
                            self.emit(&[0x48, 0xd1, 0xe8, 0x48, 0x83, 0xd1, 0])?;
                        }
                        self.emit(&[0x48, 0x89, 0xc8])?;
                        if count == IntegerBitCount::Zeros {
                            self.emit(&[0xb9])?;
                            self.emit(&u32::from(operand_width.bits).to_le_bytes())?;
                            self.emit(&[0x29, 0xc1, 0x89, 0xc8])?;
                        }
                    }
                    IntegerBitCount::LeadingZeros
                    | IntegerBitCount::TrailingZeros
                    | IntegerBitCount::LeadingOnes
                    | IntegerBitCount::TrailingOnes => {
                        let operand_mask = if operand_width.bits == 64 {
                            u64::MAX
                        } else {
                            (1_u64 << operand_width.bits) - 1
                        };
                        if operand_width.bits < 64 {
                            self.emit(&[0x48, 0x25])?;
                            self.emit(&(operand_mask as u32).to_le_bytes())?;
                        }
                        if matches!(
                            count,
                            IntegerBitCount::LeadingOnes | IntegerBitCount::TrailingOnes
                        ) {
                            if operand_width.bits == 64 {
                                self.emit(&[0x48])?;
                            }
                            self.emit(&[0x35])?;
                            self.emit(&(operand_mask as u32).to_le_bytes())?;
                        }
                        self.emit(&[0x48, 0x85, 0xc0])?;
                        let zero = self.emit_forward_branch(0x84)?;
                        if matches!(
                            count,
                            IntegerBitCount::LeadingZeros | IntegerBitCount::LeadingOnes
                        ) {
                            self.emit(&[0x48, 0x0f, 0xbd, 0xc8, 0xb8])?;
                            self.emit(&u32::from(operand_width.bits - 1).to_le_bytes())?;
                            self.emit(&[0x29, 0xc8])?;
                        } else {
                            self.emit(&[0x48, 0x0f, 0xbc, 0xc0])?;
                        }
                        let end = self.emit_unconditional_forward_branch()?;
                        self.patch_forward_branch(zero)?;
                        self.emit(&[0xb8])?;
                        self.emit(&u32::from(operand_width.bits).to_le_bytes())?;
                        self.patch_forward_branch(end)?;
                    }
                }
                self.width = previous_width;
            }
            ExprKind::IntegerLogarithm {
                base,
                radix,
                binary,
            } => {
                let base_type = runtime_expression_type_with_locals(
                    self.function,
                    self.resolver,
                    &self.locals[..self.saved_locals],
                    tree,
                    base,
                    depth + 1,
                )
                .map_err(|kind| self.error(kind))?;
                let operand_width = runtime_expression_width(base_type)
                    .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
                let previous_width = self.width;
                self.width = operand_width;
                self.emit_expression(tree, base, depth + 1)?;
                if let Some(radix) = radix {
                    self.emit(&[0x50])?;
                    self.evaluation_depth += 1;
                    self.emit_expression(tree, radix, depth + 1)?;
                    self.emit(&[0x49, 0x89, 0xc1, 0x58])?;
                    self.evaluation_depth -= 1;
                } else {
                    self.emit(&[0x49, 0xc7, 0xc1])?;
                    self.emit(&(if binary { 2_u32 } else { 10_u32 }).to_le_bytes())?;
                }
                self.emit(&[0x48, 0x85, 0xc0])?;
                self.emit_trap_branch(if operand_width.signed { 0x8e } else { 0x84 })?;
                self.emit(&[0x49, 0x83, 0xf9, 2])?;
                self.emit_trap_branch(if operand_width.signed { 0x8c } else { 0x82 })?;
                self.emit(&[0x45, 0x31, 0xc0])?;
                let loop_start = self.length;
                self.emit(&[0x4c, 0x39, 0xc8])?;
                let done = self.emit_forward_branch(0x82)?;
                self.emit(&[0x48, 0x31, 0xd2, 0x49, 0xf7, 0xf1, 0x41, 0xff, 0xc0])?;
                self.emit_backward_branch(loop_start)?;
                self.patch_forward_branch(done)?;
                self.emit(&[0x44, 0x89, 0xc0])?;
                self.width = previous_width;
            }
            ExprKind::RawPointerOffset {
                base,
                offset,
                subtract,
                wrapping: _,
                signed: _,
                bytes,
            } => {
                let RuntimeExpressionType::RawPointer { pointee, .. } =
                    runtime_expression_type_with_locals(
                        self.function,
                        self.resolver,
                        &self.locals[..self.saved_locals],
                        tree,
                        base,
                        depth + 1,
                    )
                    .map_err(|kind| self.error(kind))?
                else {
                    return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
                };
                let element_bytes = if bytes {
                    1
                } else {
                    runtime_array_element_bytes(pointee)
                        .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?
                };
                self.emit_expression(tree, base, depth + 1)?;
                self.emit(&[0x50])?;
                self.evaluation_depth += 1;
                self.emit_expression(tree, offset, depth + 1)?;
                self.evaluation_depth -= 1;
                self.emit(&[0x59])?;
                match element_bytes {
                    1 => {}
                    2 => self.emit(&[0x48, 0xd1, 0xe0])?,
                    4 => self.emit(&[0x48, 0xc1, 0xe0, 2])?,
                    8 => self.emit(&[0x48, 0xc1, 0xe0, 3])?,
                    _ => return Err(self.error(CodegenErrorKind::UnsupportedRuntimeType)),
                }
                if subtract {
                    self.emit(&[0x48, 0x29, 0xc1, 0x48, 0x89, 0xc8])?;
                } else {
                    self.emit(&[0x48, 0x01, 0xc8])?;
                }
            }
            ExprKind::RawPointerDifference {
                pointer,
                origin,
                bytes,
                unsigned,
            } => {
                let RuntimeExpressionType::RawPointer { pointee, .. } =
                    runtime_expression_type_with_locals(
                        self.function,
                        self.resolver,
                        &self.locals[..self.saved_locals],
                        tree,
                        pointer,
                        depth + 1,
                    )
                    .map_err(|kind| self.error(kind))?
                else {
                    return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
                };
                let element_bytes = if bytes {
                    1
                } else {
                    runtime_array_element_bytes(pointee)
                        .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?
                };
                self.emit_expression(tree, pointer, depth + 1)?;
                self.emit(&[0x50])?;
                self.evaluation_depth += 1;
                self.emit_expression(tree, origin, depth + 1)?;
                self.evaluation_depth -= 1;
                self.emit(&[0x59])?;
                self.emit(&[0x48, 0x29, 0xc1, 0x48, 0x89, 0xc8])?;
                match element_bytes {
                    1 => {}
                    2 if unsigned => self.emit(&[0x48, 0xd1, 0xe8])?,
                    4 if unsigned => self.emit(&[0x48, 0xc1, 0xe8, 2])?,
                    8 if unsigned => self.emit(&[0x48, 0xc1, 0xe8, 3])?,
                    2 => self.emit(&[0x48, 0xd1, 0xf8])?,
                    4 => self.emit(&[0x48, 0xc1, 0xf8, 2])?,
                    8 => self.emit(&[0x48, 0xc1, 0xf8, 3])?,
                    _ => return Err(self.error(CodegenErrorKind::UnsupportedRuntimeType)),
                }
            }
            ExprKind::RawPointerAlignOffset { base, alignment } => {
                let RuntimeExpressionType::RawPointer { pointee, .. } =
                    runtime_expression_type_with_locals(
                        self.function,
                        self.resolver,
                        &self.locals[..self.saved_locals],
                        tree,
                        base,
                        depth + 1,
                    )
                    .map_err(|kind| self.error(kind))?
                else {
                    return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
                };
                let element_bytes = runtime_array_element_bytes(pointee)
                    .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
                self.emit_expression(tree, base, depth + 1)?;
                self.emit(&[0x50])?;
                self.evaluation_depth += 1;
                self.emit_expression(tree, alignment, depth + 1)?;
                self.evaluation_depth -= 1;
                self.emit(&[0x48, 0x89, 0xc1, 0x48, 0x8b, 0x14, 0x24])?;
                self.emit(&[0x48, 0x83, 0xc4, 0x08, 0x48, 0x85, 0xc9])?;
                self.emit_trap_branch(0x84)?;
                self.emit(&[
                    0x49, 0x89, 0xc8, 0x49, 0x83, 0xe8, 0x01, 0x49, 0x89, 0xc9, 0x4d, 0x21, 0xc1,
                    0x4d, 0x85, 0xc9,
                ])?;
                self.emit_trap_branch(0x85)?;
                self.emit(&[0x48, 0x83, 0xf9, element_bytes as u8])?;
                let large_alignment = self.emit_forward_branch(0x87)?;
                self.emit(&[0x48, 0x89, 0xd0, 0x4c, 0x21, 0xc0, 0x48, 0xf7, 0xd8])?;
                self.emit(&[0x48, 0x19, 0xc0])?;
                let end = self.emit_unconditional_forward_branch()?;
                self.patch_forward_branch(large_alignment)?;
                let misaligned = if element_bytes > 1 {
                    self.emit(&[0x48, 0x89, 0xd0, 0x48, 0xa9])?;
                    self.emit(&(element_bytes as u32 - 1).to_le_bytes())?;
                    Some(self.emit_forward_branch(0x85)?)
                } else {
                    None
                };
                self.emit(&[0x48, 0x89, 0xd0, 0x48, 0xf7, 0xd8, 0x4c, 0x21, 0xc0])?;
                match element_bytes {
                    1 => {}
                    2 => self.emit(&[0x48, 0xd1, 0xe8])?,
                    4 => self.emit(&[0x48, 0xc1, 0xe8, 2])?,
                    8 => self.emit(&[0x48, 0xc1, 0xe8, 3])?,
                    _ => return Err(self.error(CodegenErrorKind::UnsupportedRuntimeType)),
                }
                let aligned_end = self.emit_unconditional_forward_branch()?;
                if let Some(misaligned) = misaligned {
                    self.patch_forward_branch(misaligned)?;
                    self.emit(&[0x48, 0xc7, 0xc0, 0xff, 0xff, 0xff, 0xff])?;
                }
                self.patch_forward_branch(aligned_end)?;
                self.patch_forward_branch(end)?;
            }
            ExprKind::RawPointerMask { base, mask } => {
                self.emit_expression(tree, base, depth + 1)?;
                self.emit(&[0x50])?;
                self.evaluation_depth += 1;
                self.emit_expression(tree, mask, depth + 1)?;
                self.emit(&[
                    0x48, 0x8b, 0x0c, 0x24, 0x48, 0x83, 0xc4, 0x08, 0x48, 0x21, 0xc8,
                ])?;
                self.evaluation_depth -= 1;
            }
            ExprKind::RawPointerIsAlignedTo { base, alignment } => {
                self.emit_expression(tree, base, depth + 1)?;
                self.emit(&[0x50])?;
                self.evaluation_depth += 1;
                self.emit_expression(tree, alignment, depth + 1)?;
                self.evaluation_depth -= 1;
                self.emit(&[
                    0x48, 0x89, 0xc1, 0x48, 0x8b, 0x14, 0x24, 0x48, 0x83, 0xc4, 0x08, 0x48, 0x85,
                    0xc9,
                ])?;
                self.emit_trap_branch(0x84)?;
                self.emit(&[
                    0x49, 0x89, 0xc8, 0x49, 0x83, 0xe8, 0x01, 0x49, 0x89, 0xc9, 0x4d, 0x21, 0xc1,
                    0x4d, 0x85, 0xc9,
                ])?;
                self.emit_trap_branch(0x85)?;
                self.emit(&[
                    0x48, 0x89, 0xd0, 0x4c, 0x21, 0xc0, 0x0f, 0x94, 0xc0, 0x0f, 0xb6, 0xc0,
                ])?;
            }
            ExprKind::RawPointerDrop { base } => {
                self.emit_expression(tree, base, depth + 1)?;
                self.emit(&[0x31, 0xc0])?;
            }
            ExprKind::UnsignedIntegerPredicate {
                base,
                argument,
                power_of_two,
            } => {
                let base_type = runtime_expression_type_with_locals(
                    self.function,
                    self.resolver,
                    &self.locals[..self.saved_locals],
                    tree,
                    base,
                    depth + 1,
                )
                .map_err(|kind| self.error(kind))?;
                let operand_width = runtime_expression_width(base_type)
                    .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
                let previous_width = self.width;
                self.width = operand_width;
                let emission = self.emit_expression(tree, base, depth + 1);
                self.width = previous_width;
                emission?;
                if power_of_two {
                    self.emit(&[
                        0x48, 0x89, 0xc1, 0x48, 0x85, 0xc0, 0x0f, 0x95, 0xc2, 0x48, 0xff, 0xc9,
                        0x48, 0x21, 0xc8, 0x0f, 0x94, 0xc0, 0x0f, 0xb6, 0xc0, 0x0f, 0xb6, 0xd2,
                        0x21, 0xd0,
                    ])?;
                } else {
                    self.emit(&[0x50])?;
                    self.evaluation_depth += 1;
                    self.width = operand_width;
                    let emission = self.emit_expression(
                        tree,
                        argument.ok_or(self.error(CodegenErrorKind::RuntimeTypeMismatch))?,
                        depth + 1,
                    );
                    self.width = previous_width;
                    emission?;
                    self.emit(&[0x49, 0x89, 0xc0, 0x59, 0x4d, 0x85, 0xc0])?;
                    self.evaluation_depth -= 1;
                    let nonzero = self.emit_forward_branch(0x85)?;
                    self.emit(&[0x48, 0x85, 0xc9, 0x0f, 0x94, 0xc0, 0x0f, 0xb6, 0xc0])?;
                    let end = self.emit_unconditional_forward_branch()?;
                    self.patch_forward_branch(nonzero)?;
                    self.emit(&[
                        0x48, 0x89, 0xc8, 0x31, 0xd2, 0x49, 0xf7, 0xf0, 0x48, 0x85, 0xd2, 0x0f,
                        0x94, 0xc0, 0x0f, 0xb6, 0xc0,
                    ])?;
                    self.patch_forward_branch(end)?;
                }
            }
            ExprKind::SignedIntegerPredicate { base, positive } => {
                let base_type = runtime_expression_type_with_locals(
                    self.function,
                    self.resolver,
                    &self.locals[..self.saved_locals],
                    tree,
                    base,
                    depth + 1,
                )
                .map_err(|kind| self.error(kind))?;
                let operand_width = runtime_expression_width(base_type)
                    .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
                let previous_width = self.width;
                self.width = operand_width;
                self.emit_expression(tree, base, depth + 1)?;
                self.width = previous_width;
                self.emit(&[0x48, 0x85, 0xc0, 0x0f])?;
                self.emit(&[if positive { 0x9f } else { 0x9c }, 0xc0, 0x0f, 0xb6, 0xc0])?;
            }
            ExprKind::AsciiPredicate { base, predicate } => {
                let previous_width = self.width;
                self.width = runtime_width("u8")
                    .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
                let emission = self.emit_expression(tree, base, depth + 1);
                self.width = previous_width;
                emission?;
                self.emit_ascii_predicate(predicate)?;
            }
            ExprKind::Integer(literal) => {
                if literal.value > u128::from(self.width.maximum) {
                    return Err(self.error(CodegenErrorKind::ValueOutOfRange));
                }
                let value = u64::try_from(literal.value)
                    .map_err(|_| self.error(CodegenErrorKind::ValueOutOfRange))?;
                self.emit(&[0x48, 0xb8])?;
                self.emit(&value.to_le_bytes())?;
            }
            ExprKind::Bool(value) => {
                self.emit(&[0x48, 0xb8])?;
                self.emit(&u64::from(value).to_le_bytes())?;
            }
            ExprKind::Char(value) => {
                self.emit(&[0x48, 0xb8])?;
                self.emit(&u64::from(value).to_le_bytes())?;
            }
            ExprKind::ByteChar(value) => {
                self.emit(&[0x48, 0xb8])?;
                self.emit(&u64::from(value).to_le_bytes())?;
            }
            ExprKind::String(_) | ExprKind::ByteString(_) => {
                return Err(self.error(CodegenErrorKind::RuntimeExpressionUnsupported));
            }
            ExprKind::CString(_) => {
                return Err(self.error(CodegenErrorKind::UnsupportedCStringLiteral));
            }
            ExprKind::Closure { .. } => {
                return Err(self.error(CodegenErrorKind::RuntimeExpressionUnsupported));
            }
            ExprKind::ClosureParameter {
                target: Some(crate::expression::ClosureParameterTarget::Integer(_)),
                ..
            } => {
                let slot = self
                    .evaluation_depth
                    .checked_sub(1)
                    .ok_or(self.error(CodegenErrorKind::RuntimeExpressionUnsupported))?;
                self.emit_stack_slot(slot)?;
                self.emit_normalize()?;
            }
            ExprKind::ClosureParameter {
                target: Some(crate::expression::ClosureParameterTarget::IntegerReference(_)),
                ..
            } => {
                let slot = self
                    .evaluation_depth
                    .checked_sub(1)
                    .ok_or(self.error(CodegenErrorKind::RuntimeExpressionUnsupported))?;
                self.emit_stack_slot_address(slot)?;
            }
            ExprKind::ClosureParameter { target: None, .. } => {
                return Err(self.error(CodegenErrorKind::RuntimeExpressionUnsupported));
            }
            ExprKind::Identifier(name) => {
                self.record_identifier_read(name, RuntimePlaceProjections::EMPTY, expression.span)?;
                self.emit_identifier(name)?;
            }
            ExprKind::Call {
                callee,
                arguments,
                argument_count,
            } => {
                if let Some(target) = self
                    .resolver
                    .resolve_runtime_call::<MAX_PARAMETERS>(callee, argument_count)
                {
                    return self.emit_runtime_call(tree, &arguments, target, depth + 1);
                }
                let arguments =
                    evaluate_runtime_call_arguments(tree, arguments, argument_count, self.resolver)
                        .map_err(|kind| self.error(kind))?;
                let value = self
                    .resolver
                    .resolve_call(callee, &arguments[..argument_count])
                    .ok_or(self.error(CodegenErrorKind::RuntimeExpressionUnsupported))?;
                let resolved_type = self.resolver.resolve_call_type(callee, argument_count);
                if let Some(ty) = resolved_type
                    && (ty.bits(64) != Some(self.width.bits) || ty.is_signed() != self.width.signed)
                {
                    return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
                }
                let maximum_bits = if self.width.bits == 64 {
                    u128::from(u64::MAX)
                } else {
                    (1u128 << self.width.bits) - 1
                };
                if value > maximum_bits {
                    return Err(self.error(CodegenErrorKind::ValueOutOfRange));
                }
                let mut value = u64::try_from(value)
                    .map_err(|_| self.error(CodegenErrorKind::ValueOutOfRange))?;
                if resolved_type.is_some_and(crate::IntegerType::is_signed) && self.width.bits < 64
                {
                    let sign_bit = 1u64 << (self.width.bits - 1);
                    if value & sign_bit != 0 {
                        value |= !((1u64 << self.width.bits) - 1);
                    }
                }
                self.emit(&[0x48, 0xb8])?;
                self.emit(&value.to_le_bytes())?;
            }
            ExprKind::Cast { operand, target } => {
                self.emit_expression(tree, operand, depth + 1)?;
                if let crate::CastType::Integer(target) = target {
                    let width = runtime_width(target.name())
                        .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
                    self.emit_normalize_width(width)?;
                }
            }
            ExprKind::Ascribe { operand, target } => {
                self.emit_expression(tree, operand, depth + 1)?;
                match target {
                    crate::ScalarType::Integer(target) => {
                        let width = runtime_width(target.name())
                            .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
                        self.emit_normalize_width(width)?;
                    }
                    crate::ScalarType::Bool => {
                        self.emit(&[0x48, 0x85, 0xc0, 0x0f, 0x95, 0xc0, 0x0f, 0xb6, 0xc0])?;
                    }
                    crate::ScalarType::Never
                    | crate::ScalarType::Char
                    | crate::ScalarType::Unit
                    | crate::ScalarType::Array { .. }
                    | crate::ScalarType::Tuple { .. }
                    | crate::ScalarType::RawPointer { .. }
                    | crate::ScalarType::Reference { .. }
                    | crate::ScalarType::ArrayReference { .. }
                    | crate::ScalarType::SliceReference { .. }
                    | crate::ScalarType::StrReference { .. } => {}
                }
            }
            ExprKind::Unary {
                operator: crate::UnaryOperator::Not,
                operand,
            } => {
                let operand_type = runtime_expression_type_with_locals(
                    self.function,
                    self.resolver,
                    &self.locals[..self.saved_locals],
                    tree,
                    operand,
                    0,
                )
                .map_err(|kind| self.error(kind))?;
                self.emit_expression(tree, operand, depth + 1)?;
                if operand_type == RuntimeExpressionType::Bool {
                    self.emit(&[0x48, 0x85, 0xc0, 0x0f, 0x94, 0xc0, 0x0f, 0xb6, 0xc0])?;
                } else {
                    self.emit(&[0x48, 0xf7, 0xd0])?;
                    self.emit_normalize()?;
                }
            }
            ExprKind::Unary {
                operator: crate::UnaryOperator::Negate,
                operand,
            } => {
                if !self.width.signed {
                    return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
                }
                if let Some(ExprKind::Integer(literal)) =
                    tree.expression(operand).map(|expression| expression.kind)
                {
                    let magnitude_limit = u128::from(self.width.maximum) + 1;
                    if literal.value > magnitude_limit {
                        return Err(self.error(CodegenErrorKind::ValueOutOfRange));
                    }
                    self.emit(&[0x48, 0xb8])?;
                    self.emit(&(literal.value as u64).to_le_bytes())?;
                } else {
                    self.emit_expression(tree, operand, depth + 1)?;
                }
                self.emit(&[0x48, 0xf7, 0xd8])?;
                if self.overflow_checks {
                    if self.width.bits == 64 {
                        self.emit_trap_branch(0x80)?;
                    } else {
                        self.emit_range_check()?;
                    }
                }
                self.emit_normalize()?;
            }
            ExprKind::Unary {
                operator: crate::UnaryOperator::Dereference,
                operand,
            } => {
                let operand_type = runtime_expression_type_with_locals(
                    self.function,
                    self.resolver,
                    &self.locals[..self.saved_locals],
                    tree,
                    operand,
                    0,
                )
                .map_err(|kind| self.error(kind))?;
                let pointee = match operand_type {
                    RuntimeExpressionType::Reference {
                        target: RuntimeReferenceTarget::Scalar(pointee),
                        ..
                    }
                    | RuntimeExpressionType::RawPointer { pointee, .. } => pointee,
                    RuntimeExpressionType::Reference { .. } => {
                        return Err(self.error(CodegenErrorKind::RuntimeExpressionUnsupported));
                    }
                    _ => return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch)),
                };
                if let Some(ExprKind::Identifier(name)) =
                    tree.expression(operand).map(|expression| expression.kind)
                {
                    self.record_expression_place_read(tree, id, None)?;
                    self.emit_identifier(name)?;
                } else {
                    self.emit_expression(tree, operand, depth + 1)?;
                }
                self.emit_reference_load(pointee)?;
            }
            ExprKind::Unary {
                operator: crate::UnaryOperator::AddressOf | crate::UnaryOperator::AddressOfMut,
                operand,
            } => match tree.expression(operand).map(|expression| expression.kind) {
                Some(ExprKind::Identifier(name)) => {
                    self.record_expression_place_read(tree, operand, None)?;
                    self.emit_identifier_address(name)?;
                }
                Some(ExprKind::Unary {
                    operator: crate::UnaryOperator::Dereference,
                    operand: reference,
                }) => self.emit_expression(tree, reference, depth + 1)?,
                Some(ExprKind::RangeIndex {
                    base,
                    start,
                    end,
                    inclusive,
                }) => {
                    let base_type = runtime_expression_type_with_locals(
                        self.function,
                        self.resolver,
                        &self.locals[..self.saved_locals],
                        tree,
                        base,
                        depth + 1,
                    )
                    .map_err(|kind| self.error(kind))?;
                    let RuntimeExpressionType::Reference {
                        target:
                            RuntimeReferenceTarget::Array {
                                element,
                                count,
                                layout: RuntimeReferenceArrayLayout::Native,
                            },
                        ..
                    } = base_type
                    else {
                        return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
                    };
                    let (start, _) =
                        constant_range_bounds(tree, start, end, inclusive, count, self.resolver)
                            .map_err(|kind| self.error(kind))?;
                    self.emit_expression(tree, base, depth + 1)?;
                    let offset =
                        start
                            .checked_mul(runtime_array_element_bytes(element).ok_or(
                                self.error(CodegenErrorKind::RuntimeExpressionUnsupported),
                            )?)
                            .ok_or(self.error(CodegenErrorKind::ValueOutOfRange))?;
                    if offset != 0 {
                        let offset = u32::try_from(offset)
                            .map_err(|_| self.error(CodegenErrorKind::ValueOutOfRange))?;
                        self.emit(&[0x48, 0x05])?;
                        self.emit(&offset.to_le_bytes())?;
                    }
                }
                Some(ExprKind::Index { base, index }) => {
                    self.emit_index_address(tree, base, index, depth + 1)?;
                }
                _ => {
                    return Err(self.error(CodegenErrorKind::RuntimeExpressionUnsupported));
                }
            },
            ExprKind::Binary {
                operator,
                left,
                right,
            } => {
                if matches!(
                    operator,
                    crate::BinaryOperator::LogicalAnd | crate::BinaryOperator::LogicalOr
                ) {
                    self.emit_expression(tree, left, depth + 1)?;
                    self.emit(&[0x48, 0x85, 0xc0])?;
                    let branch = self.emit_forward_branch(
                        if operator == crate::BinaryOperator::LogicalAnd {
                            0x84
                        } else {
                            0x85
                        },
                    )?;
                    self.emit_expression(tree, right, depth + 1)?;
                    self.patch_forward_branch(branch)?;
                    return Ok(());
                }
                self.emit_expression(tree, left, depth + 1)?;
                self.emit(&[0x50])?;
                self.evaluation_depth += 1;
                self.emit_expression(tree, right, depth + 1)?;
                self.evaluation_depth -= 1;
                self.emit(&[0x59])?;
                self.emit_binary(operator)?;
            }
            ExprKind::If {
                condition,
                then_branch,
                else_branch,
            }
            | ExprKind::LoopBreakIf {
                condition,
                then_branch,
                else_branch,
            } => {
                self.emit_expression(tree, condition, depth + 1)?;
                self.emit(&[0x48, 0x85, 0xc0])?;
                let else_patch = self.emit_forward_branch(0x84)?;
                self.emit_expression(tree, then_branch, depth + 1)?;
                let end_patch = self.emit_unconditional_forward_branch()?;
                self.patch_forward_branch(else_patch)?;
                self.emit_expression(tree, else_branch, depth + 1)?;
                self.patch_forward_branch(end_patch)?;
            }
            ExprKind::Return { operand } | ExprKind::LoopBreak { operand } => {
                self.emit_expression(tree, operand, depth + 1)?;
            }
            ExprKind::Sequence { first, then } => {
                self.emit_expression(tree, first, depth + 1)?;
                self.emit_expression(tree, then, depth + 1)?;
            }
            ExprKind::InlineConst { operand } => {
                let expression_type = runtime_expression_type_with_locals(
                    self.function,
                    self.resolver,
                    &self.locals[..self.saved_locals],
                    tree,
                    operand,
                    depth + 1,
                )
                .map_err(|kind| self.error(kind))?;
                let value = tree.evaluate_at(operand, self.resolver).map_err(|error| {
                    self.error(CodegenErrorKind::Execution(ExecutionError::Arithmetic(
                        error,
                    )))
                })?;
                match expression_type {
                    RuntimeExpressionType::Never => {
                        return Err(self.error(CodegenErrorKind::RuntimeExpressionUnsupported));
                    }
                    RuntimeExpressionType::Unit | RuntimeExpressionType::Default => {
                        self.emit(&[0x31, 0xc0])?;
                    }
                    RuntimeExpressionType::Bool => {
                        if value > 1 {
                            return Err(self.error(CodegenErrorKind::ValueOutOfRange));
                        }
                        self.emit(&[0x48, 0xb8])?;
                        self.emit(&(value as u64).to_le_bytes())?;
                    }
                    RuntimeExpressionType::Char => {
                        if value > u128::from(u32::MAX) || char::from_u32(value as u32).is_none() {
                            return Err(self.error(CodegenErrorKind::ValueOutOfRange));
                        }
                        self.emit(&[0x48, 0xb8])?;
                        self.emit(&(value as u64).to_le_bytes())?;
                    }
                    RuntimeExpressionType::Integer(resolved_type) => {
                        if let Some(ty) = resolved_type
                            && (ty.bits(64) != Some(self.width.bits)
                                || ty.is_signed() != self.width.signed)
                        {
                            return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
                        }
                        let maximum_bits = if self.width.bits == 64 {
                            u128::from(u64::MAX)
                        } else {
                            (1u128 << self.width.bits) - 1
                        };
                        let low_value = value & maximum_bits;
                        if resolved_type.is_some_and(crate::IntegerType::is_signed) {
                            let sign_extended = if low_value & (1u128 << (self.width.bits - 1)) != 0
                            {
                                low_value | !maximum_bits
                            } else {
                                low_value
                            };
                            if value != low_value && value != sign_extended {
                                return Err(self.error(CodegenErrorKind::ValueOutOfRange));
                            }
                        } else if value != low_value {
                            return Err(self.error(CodegenErrorKind::ValueOutOfRange));
                        }
                        let mut value = low_value as u64;
                        if resolved_type.is_some_and(crate::IntegerType::is_signed)
                            && self.width.bits < 64
                        {
                            let sign_bit = 1u64 << (self.width.bits - 1);
                            if value & sign_bit != 0 {
                                value |= !((1u64 << self.width.bits) - 1);
                            }
                        }
                        self.emit(&[0x48, 0xb8])?;
                        self.emit(&value.to_le_bytes())?;
                    }
                    RuntimeExpressionType::Array { .. } => {
                        return Err(self.error(CodegenErrorKind::RuntimeExpressionUnsupported));
                    }
                    RuntimeExpressionType::Tuple { .. } => {
                        return Err(self.error(CodegenErrorKind::RuntimeExpressionUnsupported));
                    }
                    RuntimeExpressionType::Reference { .. } => {
                        return Err(self.error(CodegenErrorKind::RuntimeExpressionUnsupported));
                    }
                    RuntimeExpressionType::RawPointer { .. } => {
                        return Err(self.error(CodegenErrorKind::RuntimeExpressionUnsupported));
                    }
                }
            }
        }
        Ok(())
    }

    fn emit_array_element<const MAX_NODES: usize>(
        &mut self,
        tree: &crate::ExpressionTree<'_, MAX_NODES>,
        id: crate::ExprId,
        index: usize,
        precise_place: bool,
        depth: usize,
    ) -> Result<(), CodegenError> {
        if depth == 64 {
            return Err(self.error(CodegenErrorKind::Lowering(
                IrErrorKind::NestingLimitExceeded,
            )));
        }
        let expression = *tree
            .expression(id)
            .ok_or(self.error(CodegenErrorKind::RuntimeExpressionUnsupported))?;
        match expression.kind {
            ExprKind::Call { .. } => {
                let RuntimeExpressionType::Array { element, count } =
                    runtime_expression_type_with_locals(
                        self.function,
                        self.resolver,
                        &self.locals[..self.saved_locals],
                        tree,
                        id,
                        depth + 1,
                    )
                    .map_err(|kind| self.error(kind))?
                else {
                    return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
                };
                self.emit_array_to_stack(tree, id, count)?;
                self.emit_stack_slot(index)?;
                self.emit_normalize_array_element(element)?;
                self.evaluation_depth -= count;
                self.emit_stack_cleanup_bytes(
                    count
                        .checked_mul(8)
                        .ok_or(self.error(CodegenErrorKind::OutputTooSmall))?,
                )
            }
            ExprKind::DefaultValue => self.emit(&[0x31, 0xc0]),
            ExprKind::Array {
                elements,
                element_count,
            } => {
                let element = elements
                    .get(index)
                    .filter(|_| index < element_count)
                    .and_then(|element| *element)
                    .ok_or(self.error(CodegenErrorKind::RuntimeExpressionUnsupported))?;
                self.emit_expression(tree, element, depth + 1)
            }
            ExprKind::ArrayRepeat { element, count } => {
                if index >= count {
                    return Err(self.error(CodegenErrorKind::ValueOutOfRange));
                }
                self.emit_expression(tree, element, depth + 1)
            }
            ExprKind::IntegerToBytes { base, order } => {
                let RuntimeExpressionType::Integer(Some(integer_type)) =
                    runtime_expression_type_with_locals(
                        self.function,
                        self.resolver,
                        &self.locals[..self.saved_locals],
                        tree,
                        base,
                        depth + 1,
                    )
                    .map_err(|kind| self.error(kind))?
                else {
                    return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
                };
                let width = runtime_width(integer_type.name())
                    .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
                let count = usize::from(width.bits / 8);
                if index >= count {
                    return Err(self.error(CodegenErrorKind::ValueOutOfRange));
                }
                self.emit_expression(tree, base, depth + 1)?;
                let byte_index = if order == crate::expression::IntegerByteOrder::Big {
                    count - index - 1
                } else {
                    index
                };
                let shift = byte_index * 8;
                if shift != 0 {
                    self.emit(&[0x48, 0xc1, 0xe8, shift as u8])?;
                }
                self.emit(&[0x25, 0xff, 0, 0, 0])
            }
            ExprKind::Identifier(name) => {
                self.record_expression_place_read(
                    tree,
                    id,
                    Some(if precise_place {
                        RuntimePlaceProjection::ArrayElement(index)
                    } else {
                        RuntimePlaceProjection::Index
                    }),
                )?;
                if let Some((local_index, local)) = self.locals[..self.saved_locals]
                    .iter()
                    .enumerate()
                    .rev()
                    .find_map(|(local_index, local)| {
                        local
                            .filter(|local| local.name == name)
                            .map(|local| (local_index, local))
                    })
                {
                    let RuntimeExpressionType::Array { element, count } = local.ty else {
                        return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
                    };
                    if index >= count {
                        return Err(self.error(CodegenErrorKind::ValueOutOfRange));
                    }
                    let element_bytes = runtime_array_element_bytes(element)
                        .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
                    if matches!(element_bytes, 1 | 2 | 4) {
                        let slots = self
                            .local_stack_slots_from(local_index + 1)?
                            .checked_add(self.evaluation_depth)
                            .ok_or(self.error(CodegenErrorKind::OutputTooSmall))?;
                        self.emit_stack_slot_address(slots)?;
                        let offset = index
                            .checked_mul(element_bytes)
                            .ok_or(self.error(CodegenErrorKind::OutputTooSmall))?;
                        if offset != 0 {
                            self.emit(&[0x48, 0x83, 0xc0, offset as u8])?;
                        }
                        return self.emit_reference_load(element);
                    }
                    let slots = self
                        .local_stack_slots_from(local_index + 1)?
                        .checked_add(index)
                        .and_then(|slots| slots.checked_add(self.evaluation_depth))
                        .ok_or(self.error(CodegenErrorKind::OutputTooSmall))?;
                    self.emit_stack_slot(slots)?;
                    return self.emit_normalize_array_element(element);
                }
                let (parameter_index, parameter) = self
                    .function
                    .parameters()
                    .iter()
                    .flatten()
                    .enumerate()
                    .find(|(_, parameter)| parameter.name == name)
                    .ok_or(self.error(CodegenErrorKind::UnknownRuntimeName))?;
                let RuntimeExpressionType::Array { element, count } =
                    runtime_array_type(parameter.ty.text)
                        .ok_or(self.error(CodegenErrorKind::RuntimeTypeMismatch))?
                else {
                    return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
                };
                if index >= count {
                    return Err(self.error(CodegenErrorKind::ValueOutOfRange));
                }
                let slots = self
                    .local_stack_slots()?
                    .checked_add(self.parameter_stack_slots_from(parameter_index + 1)?)
                    .and_then(|slots| slots.checked_add(count - 1 - index))
                    .and_then(|slots| slots.checked_add(self.evaluation_depth))
                    .ok_or(self.error(CodegenErrorKind::OutputTooSmall))?;
                self.emit_stack_slot(slots)?;
                self.emit_normalize_array_element(element)
            }
            ExprKind::If {
                condition,
                then_branch,
                else_branch,
            }
            | ExprKind::LoopBreakIf {
                condition,
                then_branch,
                else_branch,
            } => {
                self.emit_expression(tree, condition, depth + 1)?;
                self.emit(&[0x48, 0x85, 0xc0])?;
                let else_patch = self.emit_forward_branch(0x84)?;
                self.emit_array_element(tree, then_branch, index, precise_place, depth + 1)?;
                let end_patch = self.emit_unconditional_forward_branch()?;
                self.patch_forward_branch(else_patch)?;
                self.emit_array_element(tree, else_branch, index, precise_place, depth + 1)?;
                self.patch_forward_branch(end_patch)
            }
            ExprKind::InlineConst { operand }
            | ExprKind::LoopBreak { operand }
            | ExprKind::Return { operand } => {
                self.emit_array_element(tree, operand, index, precise_place, depth + 1)
            }
            ExprKind::Sequence { first, then } => {
                self.emit_expression(tree, first, depth + 1)?;
                self.emit_array_element(tree, then, index, precise_place, depth + 1)
            }
            _ => Err(self.error(CodegenErrorKind::RuntimeExpressionUnsupported)),
        }
    }

    fn emit_tuple_field<const MAX_NODES: usize>(
        &mut self,
        tree: &crate::ExpressionTree<'_, MAX_NODES>,
        base: crate::ExprId,
        field: usize,
        depth: usize,
    ) -> Result<(), CodegenError> {
        if depth == 64 {
            return Err(self.error(CodegenErrorKind::Lowering(
                IrErrorKind::NestingLimitExceeded,
            )));
        }
        let RuntimeExpressionType::Tuple {
            elements,
            element_count,
        } = runtime_expression_type_with_locals(
            self.function,
            self.resolver,
            &self.locals[..self.saved_locals],
            tree,
            base,
            depth + 1,
        )
        .map_err(|kind| self.error(kind))?
        else {
            return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
        };
        if field >= element_count {
            return Err(self.error(CodegenErrorKind::ValueOutOfRange));
        }
        let element = elements[field].ok_or(self.error(CodegenErrorKind::RuntimeTypeMismatch))?;
        match tree.expression(base).map(|expr| expr.kind) {
            Some(ExprKind::Tuple {
                elements,
                element_count,
            }) => {
                if field >= element_count {
                    return Err(self.error(CodegenErrorKind::ValueOutOfRange));
                }
                let value = elements[field]
                    .ok_or(self.error(CodegenErrorKind::RuntimeExpressionUnsupported))?;
                let previous_width = self.width;
                self.width = runtime_expression_width(runtime_type_from_tuple_element(element))
                    .unwrap_or(previous_width);
                let emission = self.emit_expression(tree, value, depth + 1);
                self.width = previous_width;
                emission?;
                return self.emit_normalize_tuple_element(element);
            }
            Some(ExprKind::Return { operand } | ExprKind::LoopBreak { operand }) => {
                return self.emit_tuple_field(tree, operand, field, depth + 1);
            }
            Some(ExprKind::Ascribe { operand, .. }) => {
                return self.emit_tuple_field(tree, operand, field, depth + 1);
            }
            Some(ExprKind::InlineConst { operand }) => {
                return self.emit_tuple_field(tree, operand, field, depth + 1);
            }
            Some(ExprKind::Sequence { first, then }) => {
                self.emit_expression(tree, first, depth + 1)?;
                return self.emit_tuple_field(tree, then, field, depth + 1);
            }
            _ => {}
        }
        if let Some(ExprKind::Identifier(name)) = tree.expression(base).map(|expr| expr.kind)
            && let Some(index) = self.locals[..self.saved_locals]
                .iter()
                .enumerate()
                .rev()
                .find_map(|(index, local)| {
                    local
                        .filter(|local| {
                            local.name == name
                                && matches!(local.ty, RuntimeExpressionType::Tuple { .. })
                        })
                        .map(|_| index)
                })
        {
            self.record_expression_place_read(
                tree,
                base,
                Some(RuntimePlaceProjection::TupleField(field)),
            )?;
            let slots = self
                .local_stack_slots_from(index + 1)?
                .checked_add(self.evaluation_depth)
                .and_then(|slots| slots.checked_add(field))
                .ok_or(self.error(CodegenErrorKind::OutputTooSmall))?;
            self.emit_stack_slot(slots)?;
            return self.emit_normalize_tuple_element(element);
        }
        self.emit_tuple_to_stack(
            tree,
            base,
            RuntimeExpressionType::Tuple {
                elements,
                element_count,
            },
        )?;
        self.emit_stack_slot(field)?;
        self.emit_normalize_tuple_element(element)?;
        self.evaluation_depth -= element_count;
        self.emit_stack_cleanup_bytes(
            element_count
                .checked_mul(8)
                .ok_or(self.error(CodegenErrorKind::OutputTooSmall))?,
        )
    }

    fn emit_tuple_to_stack<const MAX_NODES: usize>(
        &mut self,
        tree: &crate::ExpressionTree<'_, MAX_NODES>,
        root: crate::ExprId,
        expected: RuntimeExpressionType,
    ) -> Result<(), CodegenError> {
        let RuntimeExpressionType::Tuple {
            elements: expected_elements,
            element_count: expected_count,
        } = expected
        else {
            return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
        };
        let actual = runtime_expression_type_with_locals(
            self.function,
            self.resolver,
            &self.locals[..self.saved_locals],
            tree,
            root,
            0,
        )
        .map_err(|kind| self.error(kind))?;
        if !runtime_types_compatible(actual, expected) {
            return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
        }
        if matches!(
            tree.expression(root).map(|expr| expr.kind),
            Some(ExprKind::Call { .. })
        ) {
            return self.emit_expression(tree, root, 0);
        }
        if let Some(ExprKind::InlineConst { operand }) = tree.expression(root).map(|expr| expr.kind)
        {
            return self.emit_tuple_to_stack(tree, operand, expected);
        }
        if let Some(ExprKind::Sequence { first, then }) =
            tree.expression(root).map(|expr| expr.kind)
        {
            self.emit_expression(tree, first, 0)?;
            return self.emit_tuple_to_stack(tree, then, expected);
        }
        if let Some(
            ExprKind::If {
                condition,
                then_branch,
                else_branch,
            }
            | ExprKind::LoopBreakIf {
                condition,
                then_branch,
                else_branch,
            },
        ) = tree.expression(root).map(|expr| expr.kind)
        {
            self.emit_expression(tree, condition, 0)?;
            self.emit(&[0x48, 0x85, 0xc0])?;
            let else_patch = self.emit_forward_branch(0x84)?;
            let branch_depth = self.evaluation_depth;
            self.emit_tuple_to_stack(tree, then_branch, expected)?;
            let end_patch = self.emit_unconditional_forward_branch()?;
            self.patch_forward_branch(else_patch)?;
            self.evaluation_depth = branch_depth;
            self.emit_tuple_to_stack(tree, else_branch, expected)?;
            self.patch_forward_branch(end_patch)?;
            return Ok(());
        }
        if let Some(ExprKind::Tuple {
            elements,
            element_count,
        }) = tree.expression(root).map(|expr| expr.kind)
        {
            if element_count != expected_count {
                return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
            }
            let previous_width = self.width;
            for (index, element) in elements[..element_count].iter().enumerate() {
                let element = element.ok_or(self.error(CodegenErrorKind::RuntimeTypeMismatch))?;
                let element_type = expected_elements[index]
                    .ok_or(self.error(CodegenErrorKind::RuntimeTypeMismatch))?;
                self.width =
                    runtime_expression_width(runtime_type_from_tuple_element(element_type))
                        .unwrap_or(previous_width);
                self.emit_expression(tree, element, 0)?;
                self.emit(&[0x50])?;
                self.evaluation_depth += 1;
            }
            self.width = previous_width;
        } else {
            for field in 0..expected_count {
                self.emit_tuple_field(tree, root, field, 0)?;
                self.emit(&[0x50])?;
                self.evaluation_depth += 1;
            }
        }
        for left in 0..expected_count / 2 {
            let right = expected_count - 1 - left;
            self.emit_stack_slot(left)?;
            self.emit(&[0x48, 0x89, 0xc2])?;
            self.emit_stack_slot(right)?;
            self.emit_store_stack_slot(left)?;
            self.emit(&[0x48, 0x89, 0xd0])?;
            self.emit_store_stack_slot(right)?;
        }
        Ok(())
    }

    fn emit_normalize_array_element(
        &mut self,
        element: RuntimeArrayElementType,
    ) -> Result<(), CodegenError> {
        match element {
            RuntimeArrayElementType::Bool => self.emit(&[0x0f, 0xb6, 0xc0]),
            RuntimeArrayElementType::Integer(_) => self.emit_normalize(),
            RuntimeArrayElementType::Char => self.emit_normalize_width(
                runtime_width("char")
                    .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?,
            ),
            RuntimeArrayElementType::Unit | RuntimeArrayElementType::Default => Ok(()),
        }
    }

    fn emit_normalize_tuple_element(
        &mut self,
        element: RuntimeTupleElementType,
    ) -> Result<(), CodegenError> {
        match element {
            RuntimeTupleElementType::Scalar(element) => self.emit_normalize_array_element(element),
            RuntimeTupleElementType::Reference { .. }
            | RuntimeTupleElementType::RawPointer { .. } => Ok(()),
        }
    }

    fn emit_runtime_array_index<const MAX_NODES: usize>(
        &mut self,
        tree: &crate::ExpressionTree<'_, MAX_NODES>,
        base: crate::ExprId,
        index: crate::ExprId,
        count: usize,
        depth: usize,
    ) -> Result<(), CodegenError> {
        if count > crate::expression::MAX_ARRAY_ELEMENTS {
            return Err(self.error(CodegenErrorKind::RuntimeExpressionUnsupported));
        }
        self.emit_array_to_stack(tree, base, count)?;
        self.emit_expression(tree, index, depth + 1)?;
        self.emit(&[0x50])?;
        self.evaluation_depth += 1;
        let mut end_patches = [0usize; crate::expression::MAX_ARRAY_ELEMENTS];
        for (candidate, end_patch) in end_patches[..count].iter_mut().enumerate() {
            self.emit_stack_slot(0)?;
            self.emit(&[0x48, 0x83, 0xf8, candidate as u8])?;
            let next = self.emit_forward_branch(0x85)?;
            self.emit_stack_slot(1 + candidate)?;
            *end_patch = self.emit_unconditional_forward_branch()?;
            self.patch_forward_branch(next)?;
        }
        self.emit(&[0x0f, 0x0b])?;
        for patch in end_patches[..count].iter().copied() {
            self.patch_forward_branch(patch)?;
        }
        self.evaluation_depth -= count + 1;
        let bytes = (count + 1)
            .checked_mul(8)
            .ok_or(self.error(CodegenErrorKind::OutputTooSmall))?;
        self.emit_stack_cleanup_bytes(bytes)
    }

    fn emit_index_address<const MAX_NODES: usize>(
        &mut self,
        tree: &crate::ExpressionTree<'_, MAX_NODES>,
        base: crate::ExprId,
        index: crate::ExprId,
        depth: usize,
    ) -> Result<(), CodegenError> {
        let range_source = match tree.expression(base).map(|expression| expression.kind) {
            Some(ExprKind::RangeIndex { base, .. }) => Some(base),
            _ => None,
        };
        let base_type = runtime_expression_type_with_locals(
            self.function,
            self.resolver,
            &self.locals[..self.saved_locals],
            tree,
            range_source.unwrap_or(base),
            depth + 1,
        )
        .map_err(|kind| self.error(kind))?;
        let (element, count, slice_source, materialize_slice, local_name) =
            if range_source.is_some() {
                let element = match base_type {
                    RuntimeExpressionType::Reference {
                        target:
                            RuntimeReferenceTarget::Array { element, .. }
                            | RuntimeReferenceTarget::Slice(element),
                        ..
                    }
                    | RuntimeExpressionType::Array { element, .. } => element,
                    _ => return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch)),
                };
                (element, None, None, true, None)
            } else {
                match base_type {
                    RuntimeExpressionType::Reference {
                        target: RuntimeReferenceTarget::Array { element, count, .. },
                        ..
                    } => (element, Some(count), None, false, None),
                    RuntimeExpressionType::Reference {
                        target: RuntimeReferenceTarget::Slice(element),
                        ..
                    } => {
                        let source = reference_source_name(tree, base);
                        (element, None, source, source.is_none(), None)
                    }
                    RuntimeExpressionType::Array { element, count } => {
                        let Some(ExprKind::Identifier(name)) =
                            tree.expression(base).map(|expression| expression.kind)
                        else {
                            return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
                        };
                        (element, Some(count), None, false, Some(name))
                    }
                    _ => return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch)),
                }
            };
        if materialize_slice {
            if range_source.is_some() {
                self.emit_range_index_value_to_stack(tree, base, depth + 1, true, true)?;
            } else {
                self.emit_slice_value_to_stack(tree, base, depth + 1)?;
            }
            self.evaluation_depth += 2;
        } else if let Some(name) = local_name {
            self.record_expression_place_read(tree, base, Some(RuntimePlaceProjection::Index))?;
            self.emit_identifier_address(name)?;
        } else {
            self.emit_expression(tree, base, depth + 1)?;
        }
        if materialize_slice {
            self.emit_expression(tree, index, depth + 1)?;
            self.emit(&[0x48, 0x3b, 0x04, 0x24])?;
            self.emit_trap_branch(0x83)?;
            self.emit(&[0x48, 0x89, 0xc1, 0x48, 0x8b, 0x44, 0x24, 0x08])?;
            self.emit_stack_cleanup_bytes(16)?;
            self.evaluation_depth -= 2;
        } else if let Some(source) = slice_source {
            if matches!(
                tree.expression(base).map(|expression| expression.kind),
                Some(ExprKind::Identifier(_))
            ) {
                self.record_expression_place_read(tree, base, Some(RuntimePlaceProjection::Index))?;
            } else {
                let span = tree
                    .expression(base)
                    .ok_or(self.error(CodegenErrorKind::RuntimeExpressionUnsupported))?
                    .span;
                self.record_identifier_read(
                    source,
                    RuntimePlaceProjections::single(RuntimePlaceProjection::Index),
                    span,
                )?;
            }
            self.emit(&[0x50])?;
            self.evaluation_depth += 1;
            self.emit_slice_length(source)?;
            self.emit(&[0x50])?;
            self.evaluation_depth += 1;
            self.emit_expression(tree, index, depth + 1)?;
            self.emit(&[0x48, 0x3b, 0x04, 0x24])?;
            self.emit_trap_branch(0x83)?;
            self.emit(&[0x48, 0x89, 0xc1, 0x48, 0x8b, 0x44, 0x24, 0x08])?;
            self.emit_stack_cleanup_bytes(16)?;
            self.evaluation_depth -= 2;
        } else {
            self.emit(&[0x50])?;
            self.evaluation_depth += 1;
            self.emit_expression(tree, index, depth + 1)?;
            self.emit(&[0x48, 0x83, 0xf8])?;
            self.emit(&[u8::try_from(
                count.ok_or(self.error(CodegenErrorKind::RuntimeExpressionUnsupported))?,
            )
            .map_err(|_| self.error(CodegenErrorKind::ValueOutOfRange))?])?;
            self.emit_trap_branch(0x83)?;
            self.emit(&[0x48, 0x89, 0xc1, 0x58])?;
            self.evaluation_depth -= 1;
        }
        match runtime_array_element_bytes(element)
            .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?
        {
            0 => Ok(()),
            1 => self.emit(&[0x48, 0x01, 0xc8]),
            2 => self.emit(&[0x48, 0x8d, 0x04, 0x48]),
            4 => self.emit(&[0x48, 0x8d, 0x04, 0x88]),
            8 => self.emit(&[0x48, 0x8d, 0x04, 0xc8]),
            _ => Err(self.error(CodegenErrorKind::UnsupportedRuntimeType)),
        }
    }

    fn emit_reference_array_constant_index<const MAX_NODES: usize>(
        &mut self,
        tree: &crate::ExpressionTree<'_, MAX_NODES>,
        base: crate::ExprId,
        element: RuntimeArrayElementType,
        index: usize,
        layout: RuntimeReferenceArrayLayout,
        depth: usize,
    ) -> Result<(), CodegenError> {
        self.emit_expression(tree, base, depth + 1)?;
        let element_bytes = runtime_array_element_bytes(element)
            .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
        let stride = if layout == RuntimeReferenceArrayLayout::Native {
            element_bytes
        } else {
            8
        };
        let displacement = stride
            .checked_mul(index)
            .ok_or(self.error(CodegenErrorKind::OutputTooSmall))?;
        if displacement != 0 {
            if displacement <= i8::MAX as usize {
                self.emit(&[0x48, 0x83, 0xc0, displacement as u8])?;
            } else {
                self.emit(&[0x48, 0x05])?;
                self.emit(
                    &u32::try_from(displacement)
                        .map_err(|_| self.error(CodegenErrorKind::OutputTooSmall))?
                        .to_le_bytes(),
                )?;
            }
        }
        if element_bytes == 0 {
            self.emit(&[0x31, 0xc0])
        } else {
            self.emit_reference_load(element)
        }
    }

    fn emit_slice_runtime_index<const MAX_NODES: usize>(
        &mut self,
        tree: &crate::ExpressionTree<'_, MAX_NODES>,
        base: crate::ExprId,
        index: crate::ExprId,
        element: RuntimeArrayElementType,
        source: &str,
        depth: usize,
    ) -> Result<(), CodegenError> {
        self.emit_expression(tree, base, depth + 1)?;
        self.emit(&[0x50])?;
        self.evaluation_depth += 1;
        self.emit_slice_length(source)?;
        self.emit(&[0x50])?;
        self.evaluation_depth += 1;
        self.emit_expression(tree, index, depth + 1)?;
        self.emit(&[0x48, 0x3b, 0x04, 0x24])?;
        let in_bounds = self.emit_forward_branch(0x82)?;
        self.emit(&[0x0f, 0x0b])?;
        self.patch_forward_branch(in_bounds)?;
        let element_bytes = runtime_array_element_bytes(element)
            .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
        if element_bytes == 0 {
            self.emit(&[0x48, 0x83, 0xc4, 16, 0x31, 0xc0])?;
            self.evaluation_depth -= 2;
            return Ok(());
        }
        self.emit(&[0x48, 0x89, 0xc1, 0x48, 0x8b, 0x44, 0x24, 0x08])?;
        self.emit(&[0x48, 0x83, 0xc4, 16])?;
        self.evaluation_depth -= 2;
        match element_bytes {
            1 => self.emit(&[0x48, 0x01, 0xc8])?,
            2 => self.emit(&[0x48, 0x8d, 0x04, 0x48])?,
            4 => self.emit(&[0x48, 0x8d, 0x04, 0x88])?,
            8 => self.emit(&[0x48, 0x8d, 0x04, 0xc8])?,
            _ => return Err(self.error(CodegenErrorKind::UnsupportedRuntimeType)),
        }
        self.emit_reference_load(element)
    }

    fn emit_reference_array_runtime_index<const MAX_NODES: usize>(
        &mut self,
        tree: &crate::ExpressionTree<'_, MAX_NODES>,
        base: crate::ExprId,
        index: crate::ExprId,
        target: RuntimeReferenceTarget,
        depth: usize,
    ) -> Result<(), CodegenError> {
        let RuntimeReferenceTarget::Array {
            element,
            count,
            layout: _,
        } = target
        else {
            return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
        };
        self.emit_expression(tree, base, depth + 1)?;
        self.emit(&[0x50])?;
        self.evaluation_depth += 1;
        self.emit_expression(tree, index, depth + 1)?;
        self.emit(&[0x48, 0x83, 0xf8, count as u8])?;
        let in_bounds = self.emit_forward_branch(0x82)?;
        self.emit(&[0x0f, 0x0b])?;
        self.patch_forward_branch(in_bounds)?;
        let element_bytes = runtime_array_element_bytes(element)
            .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
        if element_bytes == 0 {
            self.emit(&[0x48, 0x83, 0xc4, 0x08, 0x31, 0xc0])?;
            self.evaluation_depth -= 1;
            return Ok(());
        }
        self.emit(&[0x48, 0x89, 0xc1, 0x58])?;
        self.evaluation_depth -= 1;
        match element_bytes {
            1 => self.emit(&[0x48, 0x01, 0xc8])?,
            2 => self.emit(&[0x48, 0x8d, 0x04, 0x48])?,
            4 => self.emit(&[0x48, 0x8d, 0x04, 0x88])?,
            8 => self.emit(&[0x48, 0x8d, 0x04, 0xc8])?,
            _ => return Err(self.error(CodegenErrorKind::UnsupportedRuntimeType)),
        }
        self.emit_reference_load(element)
    }

    fn emit_constant_array_index<const MAX_NODES: usize>(
        &mut self,
        tree: &crate::ExpressionTree<'_, MAX_NODES>,
        base: crate::ExprId,
        index: usize,
        count: usize,
        _depth: usize,
    ) -> Result<(), CodegenError> {
        if count > crate::expression::MAX_ARRAY_ELEMENTS || index >= count {
            return Err(self.error(CodegenErrorKind::RuntimeExpressionUnsupported));
        }
        if matches!(
            tree.expression(base).map(|expression| expression.kind),
            Some(ExprKind::Identifier(_))
        ) {
            return self.emit_array_element(tree, base, index, true, 0);
        }
        self.emit_array_to_stack(tree, base, count)?;
        self.emit_stack_slot(index)?;
        self.evaluation_depth -= count;
        let bytes = count
            .checked_mul(8)
            .ok_or(self.error(CodegenErrorKind::OutputTooSmall))?;
        self.emit_stack_cleanup_bytes(bytes)
    }

    fn emit_forward_branch(&mut self, opcode: u8) -> Result<usize, CodegenError> {
        self.emit(&[0x0f, opcode, 0, 0, 0, 0])?;
        Ok(self.length - 4)
    }

    fn emit_unconditional_forward_branch(&mut self) -> Result<usize, CodegenError> {
        self.emit(&[0xe9, 0, 0, 0, 0])?;
        Ok(self.length - 4)
    }

    fn emit_backward_branch(&mut self, target: usize) -> Result<(), CodegenError> {
        let instruction_end = self
            .length
            .checked_add(5)
            .ok_or(self.error(CodegenErrorKind::OutputTooSmall))?;
        let displacement = isize::try_from(target)
            .ok()
            .and_then(|target| {
                isize::try_from(instruction_end)
                    .ok()
                    .and_then(|end| target.checked_sub(end))
            })
            .and_then(|value| i32::try_from(value).ok())
            .ok_or(self.error(CodegenErrorKind::OutputTooSmall))?;
        self.emit(&[0xe9])?;
        self.emit(&displacement.to_le_bytes())
    }

    fn patch_forward_branch(&mut self, patch: usize) -> Result<(), CodegenError> {
        let displacement = self.length as isize - (patch + 4) as isize;
        let displacement = i32::try_from(displacement)
            .map_err(|_| self.error(CodegenErrorKind::OutputTooSmall))?;
        let capacity_error = self.error(CodegenErrorKind::OutputTooSmall);
        let target = self.bytes.get_mut(patch..patch + 4).ok_or(capacity_error)?;
        target.copy_from_slice(&displacement.to_le_bytes());
        Ok(())
    }

    fn emit_identifier(&mut self, name: &str) -> Result<(), CodegenError> {
        let local_floor = self.runtime_call_local_floor.unwrap_or(0);
        if let Some(index) = self.locals[local_floor..self.saved_locals]
            .iter()
            .enumerate()
            .rev()
            .find_map(|(index, local)| {
                local
                    .filter(|local| local.name == name)
                    .map(|_| index + local_floor)
            })
        {
            let local =
                self.locals[index].ok_or(self.error(CodegenErrorKind::UnknownRuntimeName))?;
            if matches!(
                local.ty,
                RuntimeExpressionType::Array { .. } | RuntimeExpressionType::Tuple { .. }
            ) {
                return Err(self.error(CodegenErrorKind::RuntimeExpressionUnsupported));
            }
            let slots = self
                .local_stack_slots_from(index + 1)?
                .checked_add(self.evaluation_depth)
                .ok_or(self.error(CodegenErrorKind::OutputTooSmall))?;
            let slots = if matches!(
                local.ty,
                RuntimeExpressionType::Reference {
                    target: RuntimeReferenceTarget::Slice(_) | RuntimeReferenceTarget::Str,
                    ..
                }
            ) {
                slots
                    .checked_add(1)
                    .ok_or(self.error(CodegenErrorKind::OutputTooSmall))?
            } else {
                slots
            };
            self.emit_stack_slot(slots)?;
            if local.ty == RuntimeExpressionType::Bool {
                self.emit(&[0x0f, 0xb6, 0xc0])
            } else if matches!(
                local.ty,
                RuntimeExpressionType::Reference { .. } | RuntimeExpressionType::RawPointer { .. }
            ) {
                Ok(())
            } else {
                self.emit_normalize()
            }
        } else if self.runtime_call_local_floor.is_none()
            && let Some(index) = self
                .function
                .parameters()
                .iter()
                .flatten()
                .position(|parameter| parameter.name == name)
        {
            let parameter_type = self
                .function
                .parameters()
                .iter()
                .flatten()
                .nth(index)
                .map(|parameter| parameter.ty.text)
                .ok_or(self.error(CodegenErrorKind::UnknownRuntimeName))?;
            let slots = self
                .local_stack_slots()?
                .checked_add(self.parameter_stack_slots_from(index + 1)?)
                .and_then(|slots| slots.checked_add(self.evaluation_depth))
                .ok_or(self.error(CodegenErrorKind::OutputTooSmall))?;
            let reference_type = runtime_reference_type(parameter_type);
            let pointer_type = runtime_raw_pointer_type(parameter_type);
            let slots = if matches!(
                reference_type,
                Some(RuntimeExpressionType::Reference {
                    target: RuntimeReferenceTarget::Slice(_) | RuntimeReferenceTarget::Str,
                    ..
                })
            ) {
                slots
                    .checked_add(1)
                    .ok_or(self.error(CodegenErrorKind::OutputTooSmall))?
            } else {
                slots
            };
            self.emit_stack_slot(slots)?;
            if parameter_type == "bool" {
                self.emit(&[0x0f, 0xb6, 0xc0])
            } else if reference_type.is_some() || pointer_type.is_some() {
                Ok(())
            } else {
                self.emit_normalize()
            }
        } else {
            let value = self
                .resolver
                .resolve(name)
                .ok_or(self.error(CodegenErrorKind::UnknownRuntimeName))?;
            let resolved_type = self.resolver.resolve_type(name);
            if let Some(ty) = resolved_type {
                if ty.bits(64) != Some(self.width.bits) || ty.is_signed() != self.width.signed {
                    return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
                }
                let maximum_bits = if self.width.bits == 64 {
                    u128::from(u64::MAX)
                } else {
                    (1u128 << self.width.bits) - 1
                };
                if value > maximum_bits {
                    return Err(self.error(CodegenErrorKind::ValueOutOfRange));
                }
            }
            let mut value =
                u64::try_from(value).map_err(|_| self.error(CodegenErrorKind::ValueOutOfRange))?;
            if resolved_type.is_some_and(crate::IntegerType::is_signed) && self.width.bits < 64 {
                let sign_bit = 1u64 << (self.width.bits - 1);
                if value & sign_bit != 0 {
                    value |= !((1u64 << self.width.bits) - 1);
                }
            }
            if resolved_type.is_none() && value > self.width.maximum {
                return Err(self.error(CodegenErrorKind::ValueOutOfRange));
            }
            self.emit(&[0x48, 0xb8])?;
            self.emit(&value.to_le_bytes())
        }
    }

    fn emit_slice_length(&mut self, name: &str) -> Result<(), CodegenError> {
        let slots = if let Some(index) = self.locals[..self.saved_locals]
            .iter()
            .enumerate()
            .rev()
            .find_map(|(index, local)| {
                local
                    .filter(|local| {
                        local.name == name
                            && matches!(
                                local.ty,
                                RuntimeExpressionType::Reference {
                                    target: RuntimeReferenceTarget::Slice(_)
                                        | RuntimeReferenceTarget::Str,
                                    ..
                                }
                            )
                    })
                    .map(|_| index)
            }) {
            self.local_stack_slots_from(index + 1)?
                .checked_add(self.evaluation_depth)
        } else if let Some(index) =
            self.function
                .parameters()
                .iter()
                .flatten()
                .position(|parameter| {
                    parameter.name == name
                        && matches!(
                            runtime_reference_type(parameter.ty.text),
                            Some(RuntimeExpressionType::Reference {
                                target: RuntimeReferenceTarget::Slice(_)
                                    | RuntimeReferenceTarget::Str,
                                ..
                            })
                        )
                })
        {
            self.local_stack_slots()?
                .checked_add(self.parameter_stack_slots_from(index + 1)?)
                .and_then(|slots| slots.checked_add(self.evaluation_depth))
        } else {
            None
        }
        .ok_or(self.error(CodegenErrorKind::UnknownRuntimeName))?;
        self.emit_stack_slot(slots)
    }

    fn emit_range_slice_to_stack<const MAX_NODES: usize>(
        &mut self,
        tree: &crate::ExpressionTree<'_, MAX_NODES>,
        id: crate::ExprId,
        depth: usize,
    ) -> Result<bool, CodegenError> {
        let Some(ExprKind::Unary {
            operator: crate::UnaryOperator::AddressOf | crate::UnaryOperator::AddressOfMut,
            operand,
        }) = tree.expression(id).map(|expression| expression.kind)
        else {
            return Ok(false);
        };
        let Some(ExprKind::RangeIndex { .. }) =
            tree.expression(operand).map(|expression| expression.kind)
        else {
            return Ok(false);
        };
        self.emit_range_index_value_to_stack(tree, operand, depth, false, true)?;
        Ok(true)
    }

    fn emit_range_index_value_to_stack<const MAX_NODES: usize>(
        &mut self,
        tree: &crate::ExpressionTree<'_, MAX_NODES>,
        range: crate::ExprId,
        depth: usize,
        nested_index: bool,
        record_place: bool,
    ) -> Result<(), CodegenError> {
        let Some(ExprKind::RangeIndex {
            base,
            start,
            end,
            inclusive,
        }) = tree.expression(range).map(|expression| expression.kind)
        else {
            return Err(self.error(CodegenErrorKind::RuntimeExpressionUnsupported));
        };
        let materialized_base = matches!(
            tree.expression(base).map(|expression| expression.kind),
            Some(ExprKind::RangeIndex { .. })
        );
        let base_type = runtime_expression_type_with_locals(
            self.function,
            self.resolver,
            &self.locals[..self.saved_locals],
            tree,
            base,
            depth + 1,
        )
        .map_err(|kind| self.error(kind))?;
        let (element, count, local_name, slice_name, string_slice) = match base_type {
            RuntimeExpressionType::Reference {
                target:
                    RuntimeReferenceTarget::Array {
                        element,
                        count,
                        layout: RuntimeReferenceArrayLayout::Native,
                    },
                ..
            } => (element, Some(count), None, None, false),
            RuntimeExpressionType::Reference {
                target: RuntimeReferenceTarget::Slice(element),
                ..
            } => {
                if materialized_base {
                    (element, None, None, None, false)
                } else {
                    let source = reference_source_name(tree, base)
                        .ok_or(self.error(CodegenErrorKind::RuntimeExpressionUnsupported))?;
                    (element, None, None, Some(source), false)
                }
            }
            RuntimeExpressionType::Reference {
                target: RuntimeReferenceTarget::Str,
                ..
            } => {
                let source = reference_source_name(tree, base)
                    .ok_or(self.error(CodegenErrorKind::RuntimeExpressionUnsupported))?;
                (
                    RuntimeArrayElementType::Integer(Some(crate::IntegerType::U8)),
                    None,
                    None,
                    Some(source),
                    true,
                )
            }
            RuntimeExpressionType::Array { element, count } => {
                let Some(ExprKind::Identifier(name)) =
                    tree.expression(base).map(|expression| expression.kind)
                else {
                    return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
                };
                (element, Some(count), Some(name), None, false)
            }
            _ => return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch)),
        };

        if materialized_base {
            self.emit_range_index_value_to_stack(tree, base, depth + 1, true, false)?;
            self.evaluation_depth += 2;
        }
        if let Some(start) = start {
            self.emit_expression(tree, start, depth + 1)?;
        } else {
            self.emit(&[0x31, 0xc0])?;
        }
        self.emit(&[0x50])?;
        self.evaluation_depth += 1;
        if let Some(end) = end {
            self.emit_expression(tree, end, depth + 1)?;
        } else if materialized_base {
            self.emit_stack_slot(1)?;
        } else if let Some(source) = slice_name {
            self.emit_slice_length(source)?;
        } else {
            let count = u64::try_from(
                count.ok_or(self.error(CodegenErrorKind::RuntimeExpressionUnsupported))?,
            )
            .map_err(|_| self.error(CodegenErrorKind::ValueOutOfRange))?;
            self.emit(&[0x48, 0xb8])?;
            self.emit(&count.to_le_bytes())?;
        }
        if inclusive {
            self.emit(&[0x48, 0x83, 0xc0, 0x01])?;
            self.emit_trap_branch(0x82)?;
        }
        self.emit(&[0x48, 0x8b, 0x0c, 0x24, 0x48, 0x39, 0xc1])?;
        self.emit_trap_branch(0x87)?;
        if let Some(count) = count {
            let count =
                u64::try_from(count).map_err(|_| self.error(CodegenErrorKind::ValueOutOfRange))?;
            self.emit(&[0x48, 0xba])?;
            self.emit(&count.to_le_bytes())?;
        } else if materialized_base {
            self.emit(&[0x48, 0x8b, 0x54, 0x24, 0x08])?;
        } else {
            self.emit(&[0x50])?;
            self.evaluation_depth += 1;
            self.emit_slice_length(
                slice_name.ok_or(self.error(CodegenErrorKind::RuntimeExpressionUnsupported))?,
            )?;
            self.emit(&[0x48, 0x89, 0xc2, 0x58])?;
            self.evaluation_depth -= 1;
        }
        self.emit(&[0x48, 0x39, 0xd0])?;
        self.emit_trap_branch(0x87)?;
        self.emit(&[0x48, 0x29, 0xc8, 0x50])?;
        self.evaluation_depth += 1;
        if materialized_base {
            if record_place {
                self.record_expression_place_read(
                    tree,
                    range,
                    nested_index.then_some(RuntimePlaceProjection::Index),
                )?;
            }
            self.emit(&[0x48, 0x8b, 0x44, 0x24, 0x18])?;
        } else if nested_index {
            if record_place {
                self.record_expression_place_read(
                    tree,
                    range,
                    Some(RuntimePlaceProjection::Index),
                )?;
            }
            let source = reference_source_name(tree, base)
                .ok_or(self.error(CodegenErrorKind::RuntimeExpressionUnsupported))?;
            self.emit_identifier(source)?;
        } else if let Some(name) = local_name {
            if record_place {
                self.record_expression_place_read(
                    tree,
                    base,
                    Some(RuntimePlaceProjection::Subslice),
                )?;
            }
            self.emit_identifier_address(name)?;
        } else {
            self.emit_expression(tree, base, depth + 1)?;
        }
        if string_slice {
            self.emit_string_range_boundary_checks(
                slice_name.ok_or(self.error(CodegenErrorKind::RuntimeExpressionUnsupported))?,
            )?;
        }
        self.emit(&[0x48, 0x8b, 0x4c, 0x24, 0x08])?;
        match runtime_array_element_bytes(element)
            .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?
        {
            0 | 1 => {}
            2 => self.emit(&[0x48, 0xc1, 0xe1, 0x01])?,
            4 => self.emit(&[0x48, 0xc1, 0xe1, 0x02])?,
            8 => self.emit(&[0x48, 0xc1, 0xe1, 0x03])?,
            _ => return Err(self.error(CodegenErrorKind::UnsupportedRuntimeType)),
        }
        self.emit(&[0x48, 0x01, 0xc8, 0x48, 0x89, 0xc2, 0x59])?;
        if materialized_base {
            self.emit(&[0x48, 0x83, 0xc4, 0x18])?;
            self.evaluation_depth -= 4;
        } else {
            self.emit(&[0x48, 0x83, 0xc4, 0x08])?;
            self.evaluation_depth -= 2;
        }
        self.emit(&[0x52, 0x51])?;
        Ok(())
    }

    fn emit_string_range_boundary_checks(&mut self, source: &str) -> Result<(), CodegenError> {
        self.emit(&[0x49, 0x89, 0xc0])?;
        self.emit_slice_length(source)?;
        self.emit(&[0x48, 0x89, 0xc2, 0x4c, 0x89, 0xc0])?;
        self.emit(&[0x48, 0x8b, 0x4c, 0x24, 0x08])?;
        self.emit_string_boundary_check()?;
        self.emit(&[0x48, 0x8b, 0x4c, 0x24, 0x08, 0x48, 0x03, 0x0c, 0x24])?;
        self.emit_string_boundary_check()
    }

    fn emit_string_is_char_boundary<const MAX_NODES: usize>(
        &mut self,
        tree: &crate::ExpressionTree<'_, MAX_NODES>,
        base: crate::ExprId,
        index: crate::ExprId,
        depth: usize,
    ) -> Result<(), CodegenError> {
        let source = reference_source_name(tree, base)
            .ok_or(self.error(CodegenErrorKind::RuntimeExpressionUnsupported))?;
        self.emit_expression(tree, base, depth + 1)?;
        self.emit(&[0x50])?;
        self.evaluation_depth += 1;
        self.emit_slice_length(source)?;
        self.emit(&[0x50])?;
        self.evaluation_depth += 1;
        self.emit_expression(tree, index, depth + 1)?;
        self.emit(&[0x48, 0x3b, 0x04, 0x24])?;
        let out_of_bounds = self.emit_forward_branch(0x87)?;
        let at_end = self.emit_forward_branch(0x84)?;
        self.emit(&[0x48, 0x85, 0xc0])?;
        let at_start = self.emit_forward_branch(0x84)?;
        self.emit(&[0x48, 0x89, 0xc1, 0x48, 0x8b, 0x44, 0x24, 0x08])?;
        self.emit(&[0x0f, 0xb6, 0x04, 0x08, 0x25, 0xc0, 0x00, 0x00, 0x00])?;
        self.emit(&[
            0x3d, 0x80, 0x00, 0x00, 0x00, 0x0f, 0x95, 0xc0, 0x0f, 0xb6, 0xc0,
        ])?;
        let value_end = self.emit_unconditional_forward_branch()?;
        self.patch_forward_branch(at_end)?;
        self.patch_forward_branch(at_start)?;
        self.emit(&[0xb8, 0x01, 0x00, 0x00, 0x00])?;
        let true_end = self.emit_unconditional_forward_branch()?;
        self.patch_forward_branch(out_of_bounds)?;
        self.emit(&[0x31, 0xc0])?;
        self.patch_forward_branch(value_end)?;
        self.patch_forward_branch(true_end)?;
        self.emit_stack_cleanup_bytes(16)?;
        self.evaluation_depth -= 2;
        Ok(())
    }

    fn emit_string_boundary_check(&mut self) -> Result<(), CodegenError> {
        self.emit(&[0x48, 0x85, 0xc9])?;
        let at_start = self.emit_forward_branch(0x84)?;
        self.emit(&[0x48, 0x39, 0xd1])?;
        let at_end = self.emit_forward_branch(0x84)?;
        self.emit(&[0x44, 0x0f, 0xb6, 0x04, 0x08])?;
        self.emit(&[0x41, 0x80, 0xe0, 0xc0, 0x41, 0x80, 0xf8, 0x80])?;
        self.emit_trap_branch(0x84)?;
        self.patch_forward_branch(at_start)?;
        self.patch_forward_branch(at_end)
    }

    fn intern_readonly_string_bytes(
        &mut self,
        decoded: &[u8],
    ) -> Result<(usize, usize), CodegenError> {
        let existing = if decoded.is_empty() {
            Some(0)
        } else {
            self.readonly_data[..self.readonly_data_length]
                .windows(decoded.len())
                .position(|candidate| candidate == decoded)
        };
        if let Some(offset) = existing {
            return Ok((offset, decoded.len()));
        }
        let end = self
            .readonly_data_length
            .checked_add(decoded.len())
            .ok_or(self.error(CodegenErrorKind::OutputTooSmall))?;
        let capacity_error = self.error(CodegenErrorKind::OutputTooSmall);
        let destination = self
            .readonly_data
            .get_mut(self.readonly_data_length..end)
            .ok_or(capacity_error)?;
        destination.copy_from_slice(decoded);
        let start = self.readonly_data_length;
        self.readonly_data_length = end;
        Ok((start, decoded.len()))
    }

    fn append_readonly_string_literal(
        &mut self,
        literal: &str,
        kind: ReadonlyStringLiteralKind,
    ) -> Result<(usize, usize), CodegenError> {
        fn hex(byte: u8) -> Option<u32> {
            match byte {
                b'0'..=b'9' => Some(u32::from(byte - b'0')),
                b'a'..=b'f' => Some(u32::from(byte - b'a' + 10)),
                b'A'..=b'F' => Some(u32::from(byte - b'A' + 10)),
                _ => None,
            }
        }

        let mut decoded = [0u8; MAX_X86_64_READONLY_DATA_BYTES];
        let mut decoded_length = 0usize;
        let capacity_error = self.error(CodegenErrorKind::OutputTooSmall);
        let mut push = |byte| {
            let output = decoded.get_mut(decoded_length).ok_or(capacity_error)?;
            *output = byte;
            decoded_length += 1;
            Ok::<(), CodegenError>(())
        };
        let byte_string = kind == ReadonlyStringLiteralKind::Bytes;
        let c_string = kind == ReadonlyStringLiteralKind::C;
        let raw_prefix_length = if byte_string || c_string { 2 } else { 1 };
        let raw_prefix = match kind {
            ReadonlyStringLiteralKind::Utf8 => "r",
            ReadonlyStringLiteralKind::Bytes => "br",
            ReadonlyStringLiteralKind::C => "cr",
        };
        if literal.starts_with(raw_prefix) {
            let bytes = literal.as_bytes();
            let mut quote = raw_prefix_length;
            while bytes.get(quote) == Some(&b'#') {
                quote += 1;
            }
            if quote > raw_prefix_length + 255 || bytes.get(quote) != Some(&b'"') {
                return Err(self.error(CodegenErrorKind::RuntimeExpressionUnsupported));
            }
            let hashes = quote - raw_prefix_length;
            let content_start = quote + 1;
            let delimiter_length = hashes
                .checked_add(1)
                .ok_or(self.error(CodegenErrorKind::RuntimeExpressionUnsupported))?;
            let content_end = bytes
                .len()
                .checked_sub(delimiter_length)
                .ok_or(self.error(CodegenErrorKind::RuntimeExpressionUnsupported))?;
            if content_start > content_end
                || bytes.get(content_end) != Some(&b'"')
                || bytes.get(
                    content_end
                        .checked_add(1)
                        .ok_or(self.error(CodegenErrorKind::RuntimeExpressionUnsupported))?..,
                ) != bytes.get(raw_prefix_length..quote)
            {
                return Err(self.error(CodegenErrorKind::RuntimeExpressionUnsupported));
            }
            for byte in &bytes[content_start..content_end] {
                if byte_string && !byte.is_ascii() {
                    return Err(self.error(CodegenErrorKind::RuntimeExpressionUnsupported));
                }
                push(*byte)?;
            }
            drop(push);
            if c_string {
                if decoded[..decoded_length].contains(&0) {
                    return Err(self.error(CodegenErrorKind::UnsupportedCStringLiteral));
                }
                let output = decoded
                    .get_mut(decoded_length)
                    .ok_or(self.error(CodegenErrorKind::OutputTooSmall))?;
                *output = 0;
                decoded_length += 1;
            }
            return self.intern_readonly_string_bytes(&decoded[..decoded_length]);
        }
        let cooked_prefix = match kind {
            ReadonlyStringLiteralKind::Utf8 => "\"",
            ReadonlyStringLiteralKind::Bytes => "b\"",
            ReadonlyStringLiteralKind::C => "c\"",
        };
        let literal = literal
            .strip_prefix(cooked_prefix)
            .and_then(|literal| literal.strip_suffix('"'))
            .ok_or(self.error(CodegenErrorKind::RuntimeExpressionUnsupported))?;
        let bytes = literal.as_bytes();
        let mut index = 0usize;
        while index < bytes.len() {
            if bytes[index] != b'\\' {
                if byte_string && !bytes[index].is_ascii() {
                    return Err(self.error(CodegenErrorKind::RuntimeExpressionUnsupported));
                }
                push(bytes[index])?;
                index += 1;
                continue;
            }
            index += 1;
            let escaped = *bytes
                .get(index)
                .ok_or(self.error(CodegenErrorKind::RuntimeExpressionUnsupported))?;
            index += 1;
            match escaped {
                b'n' => push(b'\n')?,
                b'r' => push(b'\r')?,
                b't' => push(b'\t')?,
                b'\\' => push(b'\\')?,
                b'0' => push(0)?,
                b'\'' => push(b'\'')?,
                b'"' => push(b'"')?,
                b'x' => {
                    let high = bytes
                        .get(index)
                        .and_then(|byte| hex(*byte))
                        .ok_or(self.error(CodegenErrorKind::RuntimeExpressionUnsupported))?;
                    let low = bytes
                        .get(index + 1)
                        .and_then(|byte| hex(*byte))
                        .ok_or(self.error(CodegenErrorKind::RuntimeExpressionUnsupported))?;
                    let value = (high << 4) | low;
                    if !byte_string && value > 0x7f {
                        return Err(self.error(CodegenErrorKind::RuntimeExpressionUnsupported));
                    }
                    push(value as u8)?;
                    index += 2;
                }
                b'u' => {
                    if byte_string {
                        return Err(self.error(CodegenErrorKind::RuntimeExpressionUnsupported));
                    }
                    if bytes.get(index) != Some(&b'{') {
                        return Err(self.error(CodegenErrorKind::RuntimeExpressionUnsupported));
                    }
                    index += 1;
                    let mut value = 0u32;
                    let mut digits = 0usize;
                    while let Some(&byte) = bytes.get(index) {
                        if byte == b'}' {
                            break;
                        }
                        index += 1;
                        if byte == b'_' {
                            continue;
                        }
                        let digit = hex(byte)
                            .ok_or(self.error(CodegenErrorKind::RuntimeExpressionUnsupported))?;
                        if digits == 6 {
                            return Err(self.error(CodegenErrorKind::RuntimeExpressionUnsupported));
                        }
                        value = value
                            .checked_mul(16)
                            .and_then(|value| value.checked_add(digit))
                            .ok_or(self.error(CodegenErrorKind::RuntimeExpressionUnsupported))?;
                        digits += 1;
                    }
                    if digits == 0 || bytes.get(index) != Some(&b'}') {
                        return Err(self.error(CodegenErrorKind::RuntimeExpressionUnsupported));
                    }
                    index += 1;
                    let value = char::from_u32(value)
                        .ok_or(self.error(CodegenErrorKind::RuntimeExpressionUnsupported))?;
                    let mut encoded = [0u8; 4];
                    for byte in value.encode_utf8(&mut encoded).as_bytes() {
                        push(*byte)?;
                    }
                }
                b'\n' => {
                    while bytes.get(index).is_some_and(u8::is_ascii_whitespace) {
                        index += 1;
                    }
                }
                b'\r' if bytes.get(index) == Some(&b'\n') => {
                    index += 1;
                    while bytes.get(index).is_some_and(u8::is_ascii_whitespace) {
                        index += 1;
                    }
                }
                _ => return Err(self.error(CodegenErrorKind::RuntimeExpressionUnsupported)),
            }
        }
        drop(push);
        if c_string {
            if decoded[..decoded_length].contains(&0) {
                return Err(self.error(CodegenErrorKind::UnsupportedCStringLiteral));
            }
            let output = decoded
                .get_mut(decoded_length)
                .ok_or(self.error(CodegenErrorKind::OutputTooSmall))?;
            *output = 0;
            decoded_length += 1;
        }
        self.intern_readonly_string_bytes(&decoded[..decoded_length])
    }

    fn append_c_string_byte_view<const MAX_NODES: usize>(
        &mut self,
        tree: &crate::ExpressionTree<'_, MAX_NODES>,
        id: crate::ExprId,
    ) -> Result<Option<(usize, usize)>, CodegenError> {
        let Some(ExprKind::CStrToBytes { base, with_nul }) =
            tree.expression(id).map(|expression| expression.kind)
        else {
            return Ok(None);
        };
        let Some(ExprKind::CString(literal)) =
            tree.expression(base).map(|expression| expression.kind)
        else {
            return Err(self.error(CodegenErrorKind::UnsupportedCStringLiteral));
        };
        let (data_offset, c_string_length) =
            self.append_readonly_string_literal(literal, ReadonlyStringLiteralKind::C)?;
        let literal_length = if with_nul {
            c_string_length
        } else {
            c_string_length
                .checked_sub(1)
                .ok_or(self.error(CodegenErrorKind::UnsupportedCStringLiteral))?
        };
        Ok(Some((data_offset, literal_length)))
    }

    fn emit_slice_value_to_stack<const MAX_NODES: usize>(
        &mut self,
        tree: &crate::ExpressionTree<'_, MAX_NODES>,
        id: crate::ExprId,
        depth: usize,
    ) -> Result<(), CodegenError> {
        if let Some((data_offset, literal_length)) = self.append_c_string_byte_view(tree, id)? {
            let capacity_error = self.error(CodegenErrorKind::OutputTooSmall);
            let relocation_offset = self
                .length
                .checked_add(3)
                .ok_or(self.error(CodegenErrorKind::OutputTooSmall))?;
            let relocation = self
                .readonly_relocations
                .get_mut(self.readonly_relocation_count)
                .ok_or(capacity_error)?;
            *relocation = X86_64ReadonlyDataRelocation {
                offset: relocation_offset,
                data_offset,
            };
            self.readonly_relocation_count += 1;
            self.emit(&[0x48, 0x8d, 0x05, 0, 0, 0, 0, 0x50, 0x48, 0xb8])?;
            self.emit(&(literal_length as u64).to_le_bytes())?;
            return self.emit(&[0x50]);
        }
        if let Some(ExprKind::String(literal) | ExprKind::ByteString(literal)) =
            tree.expression(id).map(|expression| expression.kind)
        {
            let kind = if matches!(
                tree.expression(id).map(|expression| expression.kind),
                Some(ExprKind::ByteString(_))
            ) {
                ReadonlyStringLiteralKind::Bytes
            } else {
                ReadonlyStringLiteralKind::Utf8
            };
            let (data_offset, literal_length) =
                self.append_readonly_string_literal(literal, kind)?;
            let capacity_error = self.error(CodegenErrorKind::OutputTooSmall);
            let relocation_offset = self
                .length
                .checked_add(3)
                .ok_or(self.error(CodegenErrorKind::OutputTooSmall))?;
            let relocation = self
                .readonly_relocations
                .get_mut(self.readonly_relocation_count)
                .ok_or(capacity_error)?;
            *relocation = X86_64ReadonlyDataRelocation {
                offset: relocation_offset,
                data_offset,
            };
            self.readonly_relocation_count += 1;
            self.emit(&[0x48, 0x8d, 0x05, 0, 0, 0, 0, 0x50, 0x48, 0xb8])?;
            self.emit(&(literal_length as u64).to_le_bytes())?;
            return self.emit(&[0x50]);
        }
        if matches!(
            tree.expression(id).map(|expression| expression.kind),
            Some(ExprKind::Call { .. })
        ) && runtime_expression_type_with_locals(
            self.function,
            self.resolver,
            &self.locals[..self.saved_locals],
            tree,
            id,
            depth,
        )
        .is_ok_and(runtime_type_is_fat_reference)
        {
            self.emit_expression(tree, id, depth + 1)?;
            self.emit(&[0x50, 0x52])?;
            return Ok(());
        }
        if let Some(
            ExprKind::If {
                condition,
                then_branch,
                else_branch,
            }
            | ExprKind::LoopBreakIf {
                condition,
                then_branch,
                else_branch,
            },
        ) = tree.expression(id).map(|expression| expression.kind)
        {
            self.emit_expression(tree, condition, depth + 1)?;
            self.emit(&[0x48, 0x85, 0xc0])?;
            let else_patch = self.emit_forward_branch(0x84)?;
            self.emit_slice_value_to_stack(tree, then_branch, depth + 1)?;
            let end_patch = self.emit_unconditional_forward_branch()?;
            self.patch_forward_branch(else_patch)?;
            self.emit_slice_value_to_stack(tree, else_branch, depth + 1)?;
            self.patch_forward_branch(end_patch)?;
            return Ok(());
        }
        if let Some(
            ExprKind::LoopBreak { operand }
            | ExprKind::Return { operand }
            | ExprKind::InlineConst { operand },
        ) = tree.expression(id).map(|expression| expression.kind)
        {
            return self.emit_slice_value_to_stack(tree, operand, depth + 1);
        }
        if let Some(ExprKind::Sequence { first, then }) =
            tree.expression(id).map(|expression| expression.kind)
        {
            self.emit_expression(tree, first, depth + 1)?;
            return self.emit_slice_value_to_stack(tree, then, depth + 1);
        }
        if self.emit_range_slice_to_stack(tree, id, depth)? {
            return Ok(());
        }
        let source = reference_source_name(tree, id)
            .ok_or(self.error(CodegenErrorKind::RuntimeExpressionUnsupported))?;
        self.emit_expression(tree, id, depth + 1)?;
        self.emit(&[0x50])?;
        self.evaluation_depth += 1;
        self.emit_slice_length(source)?;
        self.evaluation_depth -= 1;
        self.emit(&[0x50])
    }

    fn emit_reference_load(
        &mut self,
        pointee: RuntimeArrayElementType,
    ) -> Result<(), CodegenError> {
        match pointee {
            RuntimeArrayElementType::Bool => self.emit(&[0x0f, 0xb6, 0x00]),
            RuntimeArrayElementType::Char => self.emit(&[0x8b, 0x00]),
            RuntimeArrayElementType::Integer(Some(ty)) => {
                let bits = ty
                    .bits(64)
                    .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
                match (bits, ty.is_signed()) {
                    (8, false) => self.emit(&[0x0f, 0xb6, 0x00]),
                    (8, true) => self.emit(&[0x48, 0x0f, 0xbe, 0x00]),
                    (16, false) => self.emit(&[0x0f, 0xb7, 0x00]),
                    (16, true) => self.emit(&[0x48, 0x0f, 0xbf, 0x00]),
                    (32, false) => self.emit(&[0x8b, 0x00]),
                    (32, true) => self.emit(&[0x48, 0x63, 0x00]),
                    (64, _) => self.emit(&[0x48, 0x8b, 0x00]),
                    _ => Err(self.error(CodegenErrorKind::UnsupportedRuntimeType)),
                }
            }
            RuntimeArrayElementType::Unit
            | RuntimeArrayElementType::Default
            | RuntimeArrayElementType::Integer(None) => {
                Err(self.error(CodegenErrorKind::UnsupportedRuntimeType))
            }
        }
    }

    fn emit_reference_store(
        &mut self,
        pointee: RuntimeArrayElementType,
    ) -> Result<(), CodegenError> {
        match pointee {
            RuntimeArrayElementType::Bool => self.emit(&[0x88, 0x02]),
            RuntimeArrayElementType::Char => self.emit(&[0x89, 0x02]),
            RuntimeArrayElementType::Integer(Some(ty)) => {
                match ty
                    .bits(64)
                    .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?
                {
                    8 => self.emit(&[0x88, 0x02]),
                    16 => self.emit(&[0x66, 0x89, 0x02]),
                    32 => self.emit(&[0x89, 0x02]),
                    64 => self.emit(&[0x48, 0x89, 0x02]),
                    _ => Err(self.error(CodegenErrorKind::UnsupportedRuntimeType)),
                }
            }
            RuntimeArrayElementType::Unit
            | RuntimeArrayElementType::Default
            | RuntimeArrayElementType::Integer(None) => {
                Err(self.error(CodegenErrorKind::UnsupportedRuntimeType))
            }
        }
    }

    fn emit_identifier_address(&mut self, name: &str) -> Result<(), CodegenError> {
        let slots = if let Some((index, _local)) = self.locals[..self.saved_locals]
            .iter()
            .enumerate()
            .rev()
            .find_map(|(index, local)| {
                local
                    .filter(|local| local.name == name)
                    .map(|local| (index, local))
            }) {
            self.local_stack_slots_from(index + 1)?
                .checked_add(self.evaluation_depth)
        } else if let Some(index) = self
            .function
            .parameters()
            .iter()
            .flatten()
            .position(|parameter| parameter.name == name)
        {
            self.local_stack_slots()?
                .checked_add(self.parameter_stack_slots_from(index + 1)?)
                .and_then(|slots| slots.checked_add(self.evaluation_depth))
        } else {
            None
        }
        .ok_or(self.error(CodegenErrorKind::UnknownRuntimeName))?;
        self.emit_stack_slot_address(slots)
    }

    fn emit_stack_slot_address(&mut self, slots: usize) -> Result<(), CodegenError> {
        let displacement = slots
            .checked_mul(8)
            .ok_or(self.error(CodegenErrorKind::OutputTooSmall))?;
        if displacement <= i8::MAX as usize {
            self.emit(&[0x48, 0x8d, 0x44, 0x24, displacement as u8])
        } else {
            self.emit(&[0x48, 0x8d, 0x84, 0x24])?;
            self.emit(
                &u32::try_from(displacement)
                    .map_err(|_| self.error(CodegenErrorKind::OutputTooSmall))?
                    .to_le_bytes(),
            )
        }
    }

    fn emit_stack_slot(&mut self, slots: usize) -> Result<(), CodegenError> {
        let displacement = slots
            .checked_mul(8)
            .ok_or(self.error(CodegenErrorKind::OutputTooSmall))?;
        if displacement <= i8::MAX as usize {
            self.emit(&[0x48, 0x8b, 0x44, 0x24, displacement as u8])
        } else {
            self.emit(&[0x48, 0x8b, 0x84, 0x24])?;
            self.emit(
                &u32::try_from(displacement)
                    .map_err(|_| self.error(CodegenErrorKind::OutputTooSmall))?
                    .to_le_bytes(),
            )
        }
    }

    fn emit_store_stack_slot(&mut self, slots: usize) -> Result<(), CodegenError> {
        let displacement = slots
            .checked_mul(8)
            .ok_or(self.error(CodegenErrorKind::OutputTooSmall))?;
        if displacement <= i8::MAX as usize {
            self.emit(&[0x48, 0x89, 0x44, 0x24, displacement as u8])
        } else {
            self.emit(&[0x48, 0x89, 0x84, 0x24])?;
            self.emit(
                &u32::try_from(displacement)
                    .map_err(|_| self.error(CodegenErrorKind::OutputTooSmall))?
                    .to_le_bytes(),
            )
        }
    }

    fn emit_local<const MAX_EXPRESSION_NODES: usize>(
        &mut self,
        local: &crate::LocalBinding<'tree>,
        operand_type: &str,
        body_start: usize,
    ) -> Result<(), CodegenError> {
        if !local.initialized {
            let local_type = local
                .ty
                .and_then(|ty| runtime_type_from_text(ty.text))
                .filter(|ty| runtime_type_supports_uninitialized_scalar(*ty))
                .ok_or(CodegenError {
                    kind: CodegenErrorKind::UnsupportedRuntimeType,
                    span: translate_span(body_start, local.name_span),
                })?;
            if self.saved_locals == MAX_PARAMETERS {
                return Err(CodegenError {
                    kind: CodegenErrorKind::TooManyRuntimeLocals,
                    span: translate_span(body_start, local.name_span),
                });
            }
            let stack_slots = runtime_local_stack_slots(local_type);
            self.emit(&[0x31, 0xc0])?;
            for _ in 0..stack_slots {
                self.emit(&[0x50])?;
            }
            return self.push_runtime_local(
                local.name,
                local_type,
                local.mutable,
                false,
                stack_slots,
                Some(translate_span(body_start, local.name_span)),
            );
        }
        let tree = local
            .parse_initializer::<MAX_EXPRESSION_NODES>()
            .map_err(|error| CodegenError {
                kind: CodegenErrorKind::Expression(error.kind),
                span: translate_span(body_start + local.initializer_span.start, error.span),
            })?;
        let local_type = resolve_runtime_local_type::<R, MAX_PARAMETERS, MAX_EXPRESSION_NODES>(
            self.function,
            self.resolver,
            &self.locals[..self.saved_locals],
            local,
            operand_type,
            body_start,
        )?;
        if local.name == "_" {
            let previous_width = self.width;
            self.width = runtime_expression_width(local_type).unwrap_or(previous_width);
            let emission = self.emit_discarded_value(&tree, tree.root(), local_type, 0);
            self.width = previous_width;
            return emission;
        }
        if self.saved_locals == MAX_PARAMETERS {
            return Err(CodegenError {
                kind: CodegenErrorKind::TooManyRuntimeLocals,
                span: translate_span(body_start, local.name_span),
            });
        }
        let stack_slots = runtime_local_stack_slots(local_type);
        let previous_width = self.width;
        self.width = runtime_expression_width(local_type).unwrap_or(previous_width);
        let emission = (|| {
            if let RuntimeExpressionType::Array { element, count } = local_type {
                self.emit_array_to_stack(&tree, tree.root(), count)?;
                self.pack_temporary_array_for_local(element, count)?;
                self.evaluation_depth -= stack_slots;
            } else if runtime_type_is_tuple(local_type) {
                self.emit_tuple_to_stack(&tree, tree.root(), local_type)?;
                self.evaluation_depth -= stack_slots;
            } else if matches!(
                local_type,
                RuntimeExpressionType::Reference {
                    target: RuntimeReferenceTarget::Slice(_) | RuntimeReferenceTarget::Str,
                    ..
                }
            ) {
                self.emit_slice_value_to_stack(&tree, tree.root(), 0)?;
            } else {
                self.emit_expression(&tree, tree.root(), 0)?;
                self.emit(&[0x50])?;
            }
            Ok(())
        })();
        self.width = previous_width;
        emission?;
        self.push_runtime_local(
            local.name,
            local_type,
            local.mutable,
            true,
            stack_slots,
            Some(translate_span(body_start, local.name_span)),
        )
    }

    fn emit_scoped_local_cleanup(&mut self, checkpoint: usize) -> Result<(), CodegenError> {
        self.emit_stack_cleanup_to(checkpoint)?;
        self.truncate_scoped_locals(checkpoint)
    }

    fn emit_stack_cleanup_to(&mut self, checkpoint: usize) -> Result<(), CodegenError> {
        if checkpoint > self.saved_locals {
            return Err(self.error(CodegenErrorKind::OutputTooSmall));
        }
        let bytes = self
            .local_stack_slots_from(checkpoint)?
            .checked_mul(8)
            .ok_or(self.error(CodegenErrorKind::OutputTooSmall))?;
        if bytes != 0 {
            if bytes <= i8::MAX as usize {
                self.emit(&[0x48, 0x83, 0xc4, bytes as u8])?;
            } else {
                let bytes = u32::try_from(bytes)
                    .map_err(|_| self.error(CodegenErrorKind::OutputTooSmall))?;
                self.emit(&[0x48, 0x81, 0xc4])?;
                self.emit(&bytes.to_le_bytes())?;
            }
        }
        Ok(())
    }

    fn truncate_scoped_locals(&mut self, checkpoint: usize) -> Result<(), CodegenError> {
        if checkpoint > self.saved_locals {
            return Err(self.error(CodegenErrorKind::OutputTooSmall));
        }
        for local in &mut self.locals[checkpoint..self.saved_locals] {
            *local = None;
        }
        self.saved_locals = checkpoint;
        Ok(())
    }

    fn emit_discarded_value<const MAX_EXPRESSION_NODES: usize>(
        &mut self,
        tree: &crate::ExpressionTree<'_, MAX_EXPRESSION_NODES>,
        root: crate::ExprId,
        value_type: RuntimeExpressionType,
        depth: usize,
    ) -> Result<(), CodegenError> {
        match value_type {
            RuntimeExpressionType::Array { count, .. } => {
                self.emit_array_to_stack(tree, root, count)?;
                self.evaluation_depth -= count;
                self.emit_stack_cleanup_bytes(
                    count
                        .checked_mul(8)
                        .ok_or(self.error(CodegenErrorKind::OutputTooSmall))?,
                )
            }
            RuntimeExpressionType::Tuple { element_count, .. } => {
                self.emit_tuple_to_stack(tree, root, value_type)?;
                self.evaluation_depth -= element_count;
                self.emit_stack_cleanup_bytes(
                    element_count
                        .checked_mul(8)
                        .ok_or(self.error(CodegenErrorKind::OutputTooSmall))?,
                )
            }
            RuntimeExpressionType::Reference {
                target: RuntimeReferenceTarget::Slice(_) | RuntimeReferenceTarget::Str,
                ..
            } => {
                self.emit_slice_value_to_stack(tree, root, depth)?;
                self.emit_stack_cleanup_bytes(16)
            }
            RuntimeExpressionType::Default => {
                Err(self.error(CodegenErrorKind::RuntimeTypeMismatch))
            }
            _ => self.emit_expression(tree, root, depth),
        }
    }

    fn emit_expression_statement<const MAX_EXPRESSION_NODES: usize>(
        &mut self,
        statement: &crate::ExpressionStatement<'tree>,
        body_start: usize,
    ) -> Result<(), CodegenError> {
        if statement.expression.is_empty() {
            return Ok(());
        }
        match x86_64_inline_assembly(statement.expression) {
            Ok(Some(_)) if !self.function.unsafe_function && !statement.unsafe_context => {
                return Err(CodegenError {
                    kind: CodegenErrorKind::InlineAssemblyRequiresUnsafe,
                    span: translate_span(body_start, statement.span),
                });
            }
            Ok(Some(X86_64InlineAssembly::Nop | X86_64InlineAssembly::NopCClobber)) => {
                return self.emit(&[0x90]);
            }
            Ok(Some(X86_64InlineAssembly::Pause)) => {
                return self.emit(&[0xf3, 0x90]);
            }
            Ok(Some(X86_64InlineAssembly::Int3Noreturn)) if statement.terminal => {
                return self.emit(&[0xcc]);
            }
            Ok(Some(X86_64InlineAssembly::Int3Noreturn)) => {
                return Err(CodegenError {
                    kind: CodegenErrorKind::InvalidInlineAssembly,
                    span: translate_span(body_start, statement.span),
                });
            }
            Ok(Some(X86_64InlineAssembly::HaltLoopNoreturn)) if statement.terminal => {
                return self.emit(&[0xfa, 0xf4, 0xeb, 0xfd]);
            }
            Ok(Some(X86_64InlineAssembly::HaltLoopNoreturn)) => {
                return Err(CodegenError {
                    kind: CodegenErrorKind::InvalidInlineAssembly,
                    span: translate_span(body_start, statement.span),
                });
            }
            Ok(Some(X86_64InlineAssembly::Int80Noreturn { inputs })) if statement.terminal => {
                for input in inputs {
                    let tree = crate::ExpressionParser::<MAX_EXPRESSION_NODES>::new(input)
                        .parse()
                        .map_err(|error| CodegenError {
                            kind: CodegenErrorKind::Expression(error.kind),
                            span: translate_span(body_start + statement.span.start, error.span),
                        })?;
                    let ty = runtime_expression_type_with_locals(
                        self.function,
                        self.resolver,
                        &self.locals[..self.saved_locals],
                        &tree,
                        tree.root(),
                        0,
                    )
                    .map_err(|kind| CodegenError {
                        kind,
                        span: translate_span(body_start, statement.span),
                    })?;
                    if ty != RuntimeExpressionType::Integer(Some(crate::IntegerType::U64)) {
                        return Err(CodegenError {
                            kind: CodegenErrorKind::RuntimeTypeMismatch,
                            span: translate_span(body_start, statement.span),
                        });
                    }
                    let previous_width = self.width;
                    self.width = runtime_expression_width(ty)
                        .ok_or(self.error(CodegenErrorKind::RuntimeTypeMismatch))?;
                    let emission = self.emit_expression(&tree, tree.root(), 0);
                    self.width = previous_width;
                    emission?;
                    self.emit(&[0x50])?;
                    self.evaluation_depth += 1;
                }
                for pop in [
                    &[0x41, 0x59][..],
                    &[0x41, 0x58][..],
                    &[0x41, 0x5a][..],
                    &[0x5a][..],
                    &[0x5e][..],
                    &[0x5f][..],
                    &[0x58][..],
                ] {
                    self.emit(pop)?;
                    self.evaluation_depth -= 1;
                }
                return self.emit(&[0xcd, 0x80]);
            }
            Ok(Some(X86_64InlineAssembly::Int80Noreturn { .. })) => {
                return Err(CodegenError {
                    kind: CodegenErrorKind::InvalidInlineAssembly,
                    span: translate_span(body_start, statement.span),
                });
            }
            Ok(Some(X86_64InlineAssembly::Int80Returning { operands })) => {
                for operand in operands {
                    let tree = crate::ExpressionParser::<MAX_EXPRESSION_NODES>::new(operand.input)
                        .parse()
                        .map_err(|error| CodegenError {
                            kind: CodegenErrorKind::Expression(error.kind),
                            span: translate_span(body_start + statement.span.start, error.span),
                        })?;
                    let ty = runtime_expression_type_with_locals(
                        self.function,
                        self.resolver,
                        &self.locals[..self.saved_locals],
                        &tree,
                        tree.root(),
                        0,
                    )
                    .map_err(|kind| CodegenError {
                        kind,
                        span: translate_span(body_start, statement.span),
                    })?;
                    if ty != RuntimeExpressionType::Integer(Some(crate::IntegerType::U64)) {
                        return Err(CodegenError {
                            kind: CodegenErrorKind::RuntimeTypeMismatch,
                            span: translate_span(body_start, statement.span),
                        });
                    }
                    let previous_width = self.width;
                    self.width = runtime_expression_width(ty)
                        .ok_or(self.error(CodegenErrorKind::RuntimeTypeMismatch))?;
                    let emission = self.emit_expression(&tree, tree.root(), 0);
                    self.width = previous_width;
                    emission?;
                    self.emit(&[0x50])?;
                    self.evaluation_depth += 1;
                }
                for pop in [
                    &[0x41, 0x59][..],
                    &[0x41, 0x58][..],
                    &[0x41, 0x5a][..],
                    &[0x5a][..],
                    &[0x5e][..],
                    &[0x5f][..],
                    &[0x58][..],
                ] {
                    self.emit(pop)?;
                    self.evaluation_depth -= 1;
                }
                self.emit(&[0xcd, 0x80])?;
                for push in [
                    &[0x50][..],
                    &[0x57][..],
                    &[0x56][..],
                    &[0x52][..],
                    &[0x41, 0x52][..],
                    &[0x41, 0x50][..],
                    &[0x41, 0x51][..],
                ] {
                    self.emit(push)?;
                    self.evaluation_depth += 1;
                }
                for (index, operand) in operands.iter().copied().enumerate() {
                    if !operand.inout {
                        continue;
                    }
                    let output = operand.output.unwrap_or(operand.input);
                    if output == "_" {
                        continue;
                    }
                    let (local_index, local) = x86_64_inline_output_local(
                        self.function,
                        &self.locals[..self.saved_locals],
                        output,
                        true,
                    )
                    .map_err(|kind| CodegenError {
                        kind,
                        span: translate_span(body_start, statement.span),
                    })?;
                    let place = X86_64InlineOutputPlace {
                        base: RuntimePlaceIdentity::Local(local.id),
                        ty: local.ty,
                        projections: RuntimePlaceProjections::EMPTY,
                        storage: X86_64InlineOutputStorage::LocalStack {
                            local_index,
                            offset: 0,
                        },
                        marker: core::marker::PhantomData,
                    };
                    let destination = self.record_x86_64_inline_output_place(
                        place,
                        RuntimePlaceAccess::Write,
                        statement.span,
                    )?;
                    let X86_64InlineResolvedOutputStorage::StackSlot(slot) = destination else {
                        return Err(self.error(CodegenErrorKind::InvalidInlineAssembly));
                    };
                    self.emit_stack_slot(6 - index)?;
                    self.emit_store_stack_slot(
                        slot.checked_add(self.evaluation_depth)
                            .ok_or(self.error(CodegenErrorKind::OutputTooSmall))?,
                    )?;
                }
                self.evaluation_depth -= 7;
                self.emit_stack_cleanup_bytes(56)?;
                return Ok(());
            }
            Ok(Some(X86_64InlineAssembly::CompareRegister { register, input })) => {
                let tree = crate::ExpressionParser::<MAX_EXPRESSION_NODES>::new(input)
                    .parse()
                    .map_err(|error| CodegenError {
                        kind: CodegenErrorKind::Expression(error.kind),
                        span: translate_span(body_start + statement.span.start, error.span),
                    })?;
                let ty = runtime_expression_type_with_locals(
                    self.function,
                    self.resolver,
                    &self.locals[..self.saved_locals],
                    &tree,
                    tree.root(),
                    0,
                )
                .map_err(|kind| CodegenError {
                    kind,
                    span: translate_span(body_start, statement.span),
                })?;
                if ty != RuntimeExpressionType::Integer(Some(crate::IntegerType::U64)) {
                    return Err(CodegenError {
                        kind: CodegenErrorKind::RuntimeTypeMismatch,
                        span: translate_span(body_start, statement.span),
                    });
                }
                let previous_width = self.width;
                self.width = runtime_expression_width(ty)
                    .ok_or(self.error(CodegenErrorKind::RuntimeTypeMismatch))?;
                let emission = self.emit_expression(&tree, tree.root(), 0);
                self.width = previous_width;
                emission?;
                if register != X86_64InlineRegister::RAX {
                    self.emit(&x86_64_inline_move_from_rax(register))?;
                }
                return self.emit(&x86_64_inline_compare_self(register));
            }
            Ok(Some(X86_64InlineAssembly::SetRegister { register, output })) => {
                if output == "_" {
                    return self.emit(&x86_64_inline_set_seven(register));
                }
                let place = x86_64_inline_output_place(
                    self.function,
                    &self.locals[..self.saved_locals],
                    output,
                )
                .map_err(|kind| CodegenError {
                    kind,
                    span: translate_span(body_start, statement.span),
                })?;
                let destination = self.record_x86_64_inline_output_place(
                    place,
                    RuntimePlaceAccess::Write,
                    statement.span,
                )?;
                self.emit_x86_64_inline_output_prepare::<MAX_EXPRESSION_NODES>(destination)?;
                self.emit(&x86_64_inline_set_seven(register))?;
                if register != X86_64InlineRegister::RAX {
                    self.emit(&x86_64_inline_move_to_rax(register))?;
                }
                return self.emit_x86_64_inline_output_store(destination);
            }
            Ok(Some(X86_64InlineAssembly::IncrementRegister {
                register,
                input,
                output,
            })) => {
                if let Some(output) = output {
                    let tree = crate::ExpressionParser::<MAX_EXPRESSION_NODES>::new(input)
                        .parse()
                        .map_err(|error| CodegenError {
                            kind: CodegenErrorKind::Expression(error.kind),
                            span: translate_span(body_start + statement.span.start, error.span),
                        })?;
                    let ty = runtime_expression_type_with_locals(
                        self.function,
                        self.resolver,
                        &self.locals[..self.saved_locals],
                        &tree,
                        tree.root(),
                        0,
                    )
                    .map_err(|kind| CodegenError {
                        kind,
                        span: translate_span(body_start, statement.span),
                    })?;
                    if ty != RuntimeExpressionType::Integer(Some(crate::IntegerType::U64)) {
                        return Err(CodegenError {
                            kind: CodegenErrorKind::RuntimeTypeMismatch,
                            span: translate_span(body_start, statement.span),
                        });
                    }
                    let place = x86_64_inline_output_place(
                        self.function,
                        &self.locals[..self.saved_locals],
                        output,
                    )
                    .map_err(|kind| CodegenError {
                        kind,
                        span: translate_span(body_start, statement.span),
                    })?;
                    let destination = self.record_x86_64_inline_output_place(
                        place,
                        RuntimePlaceAccess::Write,
                        statement.span,
                    )?;
                    self.emit_x86_64_inline_output_prepare::<MAX_EXPRESSION_NODES>(destination)?;
                    let previous_width = self.width;
                    self.width = runtime_expression_width(ty)
                        .ok_or(self.error(CodegenErrorKind::RuntimeTypeMismatch))?;
                    let emission = self.emit_expression(&tree, tree.root(), 0);
                    self.width = previous_width;
                    emission?;
                    if register != X86_64InlineRegister::RAX {
                        self.emit(&x86_64_inline_move_from_rax(register))?;
                    }
                    self.emit(&x86_64_inline_increment(register))?;
                    if register != X86_64InlineRegister::RAX {
                        self.emit(&x86_64_inline_move_to_rax(register))?;
                    }
                    return self.emit_x86_64_inline_output_store(destination);
                }
                let place = x86_64_inline_output_place(
                    self.function,
                    &self.locals[..self.saved_locals],
                    input,
                )
                .map_err(|kind| CodegenError {
                    kind,
                    span: translate_span(body_start, statement.span),
                })?;
                let destination = self.record_x86_64_inline_output_place(
                    place,
                    RuntimePlaceAccess::ReadModifyWrite,
                    statement.span,
                )?;
                self.emit_x86_64_inline_output_prepare::<MAX_EXPRESSION_NODES>(destination)?;
                self.emit_x86_64_inline_output_load(destination)?;
                if register != X86_64InlineRegister::RAX {
                    self.emit(&x86_64_inline_move_from_rax(register))?;
                }
                self.emit(&x86_64_inline_increment(register))?;
                if register != X86_64InlineRegister::RAX {
                    self.emit(&x86_64_inline_move_to_rax(register))?;
                }
                return self.emit_x86_64_inline_output_store(destination);
            }
            Ok(Some(X86_64InlineAssembly::AddRaxRcx { left, right })) => {
                let (index, local) = x86_64_inline_output_local(
                    self.function,
                    &self.locals[..self.saved_locals],
                    left,
                    false,
                )
                .map_err(|kind| CodegenError {
                    kind,
                    span: translate_span(body_start, statement.span),
                })?;
                let tree = crate::ExpressionParser::<MAX_EXPRESSION_NODES>::new(right)
                    .parse()
                    .map_err(|error| CodegenError {
                        kind: CodegenErrorKind::Expression(error.kind),
                        span: translate_span(body_start + statement.span.start, error.span),
                    })?;
                let ty = runtime_expression_type_with_locals(
                    self.function,
                    self.resolver,
                    &self.locals[..self.saved_locals],
                    &tree,
                    tree.root(),
                    0,
                )
                .map_err(|kind| CodegenError {
                    kind,
                    span: translate_span(body_start, statement.span),
                })?;
                if ty != RuntimeExpressionType::Integer(Some(crate::IntegerType::U64)) {
                    return Err(CodegenError {
                        kind: CodegenErrorKind::RuntimeTypeMismatch,
                        span: translate_span(body_start, statement.span),
                    });
                }
                let fact = RuntimePlaceAccessFact {
                    base: RuntimePlaceIdentity::Local(local.id),
                    projections: RuntimePlaceProjections::EMPTY,
                    ty: local.ty,
                    access: RuntimePlaceAccess::ReadModifyWrite,
                    span: statement.span,
                };
                if self.preanalyzed_assignment_access_cursor
                    < self.body_facts.assignment_access_count
                    && self.body_facts.assignment_accesses
                        [self.preanalyzed_assignment_access_cursor]
                        == Some(fact)
                {
                    self.preanalyzed_assignment_access_cursor += 1;
                }
                self.record_place_access_fact(
                    fact.base,
                    fact.projections,
                    fact.ty,
                    fact.access,
                    fact.span,
                )?;
                let stack_slot = self.local_stack_slots_from(index + 1)?;
                self.emit_stack_slot(stack_slot)?;
                self.emit(&[0x50])?;
                self.evaluation_depth += 1;
                let previous_width = self.width;
                self.width = runtime_expression_width(ty)
                    .ok_or(self.error(CodegenErrorKind::RuntimeTypeMismatch))?;
                let emission = self.emit_expression(&tree, tree.root(), 0);
                self.width = previous_width;
                if let Err(error) = emission {
                    self.evaluation_depth -= 1;
                    return Err(error);
                }
                self.emit(&[0x48, 0x89, 0xc1])?;
                self.evaluation_depth -= 1;
                self.emit(&[0x58, 0x48, 0x01, 0xc8])?;
                return self.emit_store_stack_slot(stack_slot);
            }
            Ok(None) => {}
            Err(kind) => {
                return Err(CodegenError {
                    kind,
                    span: translate_span(body_start, statement.span),
                });
            }
        }
        let tree = statement
            .parse::<MAX_EXPRESSION_NODES>()
            .map_err(|error| CodegenError {
                kind: CodegenErrorKind::Expression(error.kind),
                span: translate_span(body_start + statement.span.start, error.span),
            })?;
        runtime_expression_type_with_locals(
            self.function,
            self.resolver,
            &self.locals[..self.saved_locals],
            &tree,
            tree.root(),
            0,
        )
        .map_err(|kind| CodegenError {
            kind,
            span: translate_span(body_start, statement.span),
        })?;
        self.emit_expression(&tree, tree.root(), 0)
    }

    fn emit_assignment<const MAX_EXPRESSION_NODES: usize>(
        &mut self,
        assignment: &crate::Assignment<'tree>,
        body_start: usize,
    ) -> Result<(), CodegenError> {
        if assignment.binding_name() == "_" {
            if assignment.index().is_some()
                || assignment.operator != crate::AssignmentOperator::Assign
            {
                return Err(CodegenError {
                    kind: CodegenErrorKind::UnsupportedRuntimeOperator,
                    span: translate_span(body_start, assignment.name_span),
                });
            }
            let tree = assignment
                .parse_value::<MAX_EXPRESSION_NODES>()
                .map_err(|error| CodegenError {
                    kind: CodegenErrorKind::Expression(error.kind),
                    span: translate_span(body_start + assignment.value_span.start, error.span),
                })?;
            let value_type = runtime_expression_type_with_locals(
                self.function,
                self.resolver,
                &self.locals[..self.saved_locals],
                &tree,
                tree.root(),
                0,
            )
            .map_err(|kind| CodegenError {
                kind,
                span: translate_span(body_start, assignment.value_span),
            })?;
            let previous_width = self.width;
            self.width = runtime_expression_width(value_type).unwrap_or(previous_width);
            let emission = self.emit_discarded_value(&tree, tree.root(), value_type, 0);
            self.width = previous_width;
            return emission;
        }
        let place = self
            .resolve_assignment_place(assignment)
            .map_err(|error| CodegenError {
                kind: error.kind,
                span: translate_span(body_start, assignment.name_span),
            })?;
        self.record_place_access::<MAX_EXPRESSION_NODES>(place, assignment)
            .map_err(|error| CodegenError {
                kind: error.kind,
                span: translate_span(body_start, assignment.name_span),
            })?;
        if matches!(
            place.projection,
            Some(crate::parser::AssignmentProjection::Dereference { .. })
        ) {
            return self.emit_dereference_assignment::<MAX_EXPRESSION_NODES>(
                assignment, body_start, place,
            );
        }
        if matches!(
            place.projection,
            Some(crate::parser::AssignmentProjection::Index { .. })
        ) {
            if let RuntimeExpressionType::Reference {
                target:
                    RuntimeReferenceTarget::Array {
                        element,
                        count,
                        layout,
                    },
                ..
            } = place.ty
            {
                return self.emit_reference_array_assignment::<MAX_EXPRESSION_NODES>(
                    assignment, body_start, element, count, layout, place,
                );
            }
            if let RuntimeExpressionType::Reference {
                target: RuntimeReferenceTarget::Slice(element),
                mutable,
            } = place.ty
            {
                return self.emit_slice_assignment::<MAX_EXPRESSION_NODES>(
                    assignment,
                    body_start,
                    element,
                    mutable,
                    place.access,
                );
            }
        }
        if !place.mutable {
            return Err(CodegenError {
                kind: CodegenErrorKind::ImmutableAssignment,
                span: translate_span(body_start, assignment.name_span),
            });
        }
        let (index, target) = self.resolved_local(place).map_err(|error| CodegenError {
            kind: error.kind,
            span: translate_span(body_start, assignment.name_span),
        })?;
        if matches!(
            place.projection,
            Some(crate::parser::AssignmentProjection::Index { .. })
        ) {
            return self.emit_indexed_assignment::<MAX_EXPRESSION_NODES>(
                assignment,
                body_start,
                index,
                target,
                place.access,
            );
        }
        if let Some(field) = assignment.tuple_field() {
            return self.emit_tuple_field_assignment::<MAX_EXPRESSION_NODES>(
                assignment,
                body_start,
                index,
                target,
                field,
                place.access,
            );
        }
        if target.ty == RuntimeExpressionType::Bool
            && !matches!(
                assignment.operator,
                crate::AssignmentOperator::Assign
                    | crate::AssignmentOperator::BitAnd
                    | crate::AssignmentOperator::BitOr
                    | crate::AssignmentOperator::BitXor
            )
        {
            return Err(CodegenError {
                kind: CodegenErrorKind::RuntimeTypeMismatch,
                span: translate_span(body_start, assignment.name_span),
            });
        }
        let tree = assignment
            .parse_value::<MAX_EXPRESSION_NODES>()
            .map_err(|error| CodegenError {
                kind: CodegenErrorKind::Expression(error.kind),
                span: translate_span(body_start + assignment.value_span.start, error.span),
            })?;
        let value_type = runtime_expression_type_with_locals(
            self.function,
            self.resolver,
            &self.locals[..self.saved_locals],
            &tree,
            tree.root(),
            0,
        )
        .map_err(|kind| CodegenError {
            kind,
            span: translate_span(body_start, assignment.value_span),
        })?;
        if !runtime_types_compatible(value_type, target.ty) {
            return Err(CodegenError {
                kind: CodegenErrorKind::RuntimeTypeMismatch,
                span: translate_span(body_start, assignment.value_span),
            });
        }
        let previous_width = self.width;
        self.width = runtime_expression_width(target.ty).unwrap_or(previous_width);
        let emission = (|| {
            if matches!(
                target.ty,
                RuntimeExpressionType::Reference {
                    target: RuntimeReferenceTarget::Slice(_) | RuntimeReferenceTarget::Str,
                    ..
                }
            ) {
                if place.access.reads_previous_value() {
                    return Err(CodegenError {
                        kind: CodegenErrorKind::UnsupportedRuntimeOperator,
                        span: translate_span(body_start, assignment.name_span),
                    });
                }
                self.emit_slice_value_to_stack(&tree, tree.root(), 0)?;
                let target_length_slot = self
                    .local_stack_slots_from(index + 1)?
                    .checked_add(2)
                    .ok_or(self.error(CodegenErrorKind::OutputTooSmall))?;
                self.emit_stack_slot(0)?;
                self.emit_store_stack_slot(target_length_slot)?;
                self.emit_stack_slot(1)?;
                self.emit_store_stack_slot(
                    target_length_slot
                        .checked_add(1)
                        .ok_or(self.error(CodegenErrorKind::OutputTooSmall))?,
                )?;
                return self.emit_stack_cleanup_bytes(16);
            }
            if let RuntimeExpressionType::Array { element, count } = target.ty {
                if place.access.reads_previous_value() {
                    return Err(CodegenError {
                        kind: CodegenErrorKind::UnsupportedRuntimeOperator,
                        span: translate_span(body_start, assignment.name_span),
                    });
                }
                return self.emit_array_assignment(&tree, tree.root(), index, element, count);
            }
            if let RuntimeExpressionType::Tuple { element_count, .. } = target.ty {
                if place.access.reads_previous_value() {
                    return Err(CodegenError {
                        kind: CodegenErrorKind::UnsupportedRuntimeOperator,
                        span: translate_span(body_start, assignment.name_span),
                    });
                }
                self.emit_tuple_to_stack(&tree, tree.root(), target.ty)?;
                let later_slots = self.local_stack_slots_from(index + 1)?;
                for slot in 0..element_count {
                    self.emit_stack_slot(slot)?;
                    let destination = element_count
                        .checked_add(later_slots)
                        .and_then(|slots| slots.checked_add(slot))
                        .ok_or(self.error(CodegenErrorKind::OutputTooSmall))?;
                    self.emit_store_stack_slot(destination)?;
                }
                self.evaluation_depth -= element_count;
                return self.emit_stack_cleanup_bytes(
                    element_count
                        .checked_mul(8)
                        .ok_or(self.error(CodegenErrorKind::OutputTooSmall))?,
                );
            }
            if !place.access.reads_previous_value() {
                self.emit_expression(&tree, tree.root(), 0)?;
            } else {
                self.emit_identifier(assignment.binding_name())?;
                self.emit(&[0x50])?;
                self.evaluation_depth += 1;
                self.emit_expression(&tree, tree.root(), 0)?;
                self.evaluation_depth -= 1;
                self.emit(&[0x59])?;
                self.emit_binary(assignment_binary_operator(assignment.operator).ok_or(
                    CodegenError {
                        kind: CodegenErrorKind::UnsupportedRuntimeOperator,
                        span: translate_span(body_start, assignment.name_span),
                    },
                )?)?;
            }
            self.emit_store_stack_slot(self.local_stack_slots_from(index + 1)?)
        })();
        self.width = previous_width;
        emission
    }

    fn emit_tuple_field_assignment<const MAX_NODES: usize>(
        &mut self,
        assignment: &crate::Assignment<'_>,
        body_start: usize,
        local_index: usize,
        target: RuntimeLocal<'_>,
        field: usize,
        access: RuntimePlaceAccess,
    ) -> Result<(), CodegenError> {
        let RuntimeExpressionType::Tuple {
            elements,
            element_count,
        } = target.ty
        else {
            return Err(CodegenError {
                kind: CodegenErrorKind::RuntimeTypeMismatch,
                span: translate_span(body_start, assignment.name_span),
            });
        };
        if field >= element_count {
            return Err(CodegenError {
                kind: CodegenErrorKind::ValueOutOfRange,
                span: translate_span(body_start, assignment.name_span),
            });
        }
        let element = elements[field].ok_or(CodegenError {
            kind: CodegenErrorKind::RuntimeTypeMismatch,
            span: translate_span(body_start, assignment.name_span),
        })?;
        let element_type = runtime_type_from_tuple_element(element);
        if !matches!(element, RuntimeTupleElementType::Scalar(_))
            && assignment.operator != crate::AssignmentOperator::Assign
        {
            return Err(CodegenError {
                kind: CodegenErrorKind::RuntimeTypeMismatch,
                span: translate_span(body_start, assignment.name_span),
            });
        }
        if element_type == RuntimeExpressionType::Bool
            && !matches!(
                assignment.operator,
                crate::AssignmentOperator::Assign
                    | crate::AssignmentOperator::BitAnd
                    | crate::AssignmentOperator::BitOr
                    | crate::AssignmentOperator::BitXor
            )
        {
            return Err(CodegenError {
                kind: CodegenErrorKind::RuntimeTypeMismatch,
                span: translate_span(body_start, assignment.name_span),
            });
        }
        let tree = assignment
            .parse_value::<MAX_NODES>()
            .map_err(|error| CodegenError {
                kind: CodegenErrorKind::Expression(error.kind),
                span: translate_span(body_start + assignment.value_span.start, error.span),
            })?;
        let value_type = runtime_expression_type_with_locals(
            self.function,
            self.resolver,
            &self.locals[..self.saved_locals],
            &tree,
            tree.root(),
            0,
        )
        .map_err(|kind| CodegenError {
            kind,
            span: translate_span(body_start, assignment.value_span),
        })?;
        if !runtime_types_compatible(value_type, element_type) {
            return Err(CodegenError {
                kind: CodegenErrorKind::RuntimeTypeMismatch,
                span: translate_span(body_start, assignment.value_span),
            });
        }
        let previous_width = self.width;
        self.width = runtime_expression_width(element_type).unwrap_or(previous_width);
        let emission = (|| {
            let destination = self
                .local_stack_slots_from(local_index + 1)?
                .checked_add(field)
                .ok_or(self.error(CodegenErrorKind::OutputTooSmall))?;
            if !access.reads_previous_value() {
                self.emit_expression(&tree, tree.root(), 0)?;
            } else {
                self.emit_stack_slot(destination)?;
                self.emit_normalize_tuple_element(element)?;
                self.emit(&[0x50])?;
                self.evaluation_depth += 1;
                self.emit_expression(&tree, tree.root(), 0)?;
                self.evaluation_depth -= 1;
                self.emit(&[0x59])?;
                self.emit_binary(assignment_binary_operator(assignment.operator).ok_or(
                    CodegenError {
                        kind: CodegenErrorKind::UnsupportedRuntimeOperator,
                        span: translate_span(body_start, assignment.name_span),
                    },
                )?)?;
            }
            self.emit_store_stack_slot(destination)
        })();
        self.width = previous_width;
        emission
    }

    fn emit_reference_array_assignment<const MAX_NODES: usize>(
        &mut self,
        assignment: &crate::Assignment<'_>,
        body_start: usize,
        element: RuntimeArrayElementType,
        count: usize,
        layout: RuntimeReferenceArrayLayout,
        place: RuntimePlace<'_>,
    ) -> Result<(), CodegenError> {
        if !place.mutable {
            return Err(CodegenError {
                kind: CodegenErrorKind::ImmutableAssignment,
                span: translate_span(body_start, assignment.name_span),
            });
        }
        let element_type = runtime_type_from_array_element(element);
        if element_type == RuntimeExpressionType::Bool
            && !matches!(
                assignment.operator,
                crate::AssignmentOperator::Assign
                    | crate::AssignmentOperator::BitAnd
                    | crate::AssignmentOperator::BitOr
                    | crate::AssignmentOperator::BitXor
            )
        {
            return Err(CodegenError {
                kind: CodegenErrorKind::RuntimeTypeMismatch,
                span: translate_span(body_start, assignment.name_span),
            });
        }
        if matches!(
            element_type,
            RuntimeExpressionType::Unit | RuntimeExpressionType::Char
        ) && place.access.reads_previous_value()
        {
            return Err(CodegenError {
                kind: CodegenErrorKind::UnsupportedRuntimeOperator,
                span: translate_span(body_start, assignment.name_span),
            });
        }
        let previous_width = self.width;
        self.width = runtime_expression_width(element_type).unwrap_or(previous_width);
        let emission = (|| {
            self.emit_indexed_assignment_index::<MAX_NODES>(assignment, body_start, count)?;
            self.emit(&[0x50])?;
            self.evaluation_depth += 1;
            self.emit_identifier(assignment.binding_name())?;
            self.emit(&[0x50])?;
            self.evaluation_depth += 1;
            let element_bytes = runtime_array_element_bytes(element)
                .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
            if place.access.reads_previous_value() {
                self.emit_reference_array_address_from_stack_index(element_bytes, layout, 1)?;
                if element_bytes == 0 {
                    self.emit(&[0x31, 0xc0])?;
                } else {
                    self.emit_reference_load(element)?;
                }
                self.emit(&[0x50])?;
                self.evaluation_depth += 1;
            }
            self.emit_indexed_assignment_value::<MAX_NODES>(assignment, body_start, element_type)?;
            if place.access.reads_previous_value() {
                self.evaluation_depth -= 1;
                self.emit(&[0x59])?;
                self.emit_binary(assignment_binary_operator(assignment.operator).ok_or(
                    CodegenError {
                        kind: CodegenErrorKind::UnsupportedRuntimeOperator,
                        span: translate_span(body_start, assignment.name_span),
                    },
                )?)?;
            }
            if element_bytes != 0 {
                self.emit(&[0x48, 0x8b, 0x14, 0x24])?;
                self.emit_reference_array_store_address_from_stack_index(element_bytes, layout, 1)?;
                self.emit_reference_store(element)?;
            }
            self.emit(&[0x48, 0x83, 0xc4, 16])?;
            self.evaluation_depth -= 2;
            Ok(())
        })();
        self.width = previous_width;
        emission
    }

    fn emit_slice_assignment<const MAX_NODES: usize>(
        &mut self,
        assignment: &crate::Assignment<'_>,
        body_start: usize,
        element: RuntimeArrayElementType,
        mutable: bool,
        access: RuntimePlaceAccess,
    ) -> Result<(), CodegenError> {
        if !mutable {
            return Err(CodegenError {
                kind: CodegenErrorKind::ImmutableAssignment,
                span: translate_span(body_start, assignment.name_span),
            });
        }
        let element_type = runtime_type_from_array_element(element);
        if element_type == RuntimeExpressionType::Bool
            && !matches!(
                assignment.operator,
                crate::AssignmentOperator::Assign
                    | crate::AssignmentOperator::BitAnd
                    | crate::AssignmentOperator::BitOr
                    | crate::AssignmentOperator::BitXor
            )
        {
            return Err(CodegenError {
                kind: CodegenErrorKind::RuntimeTypeMismatch,
                span: translate_span(body_start, assignment.name_span),
            });
        }
        if matches!(
            element_type,
            RuntimeExpressionType::Unit | RuntimeExpressionType::Char
        ) && access.reads_previous_value()
        {
            return Err(CodegenError {
                kind: CodegenErrorKind::UnsupportedRuntimeOperator,
                span: translate_span(body_start, assignment.name_span),
            });
        }
        let previous_width = self.width;
        self.width = runtime_expression_width(element_type).unwrap_or(previous_width);
        let emission = (|| {
            self.emit_slice_assignment_index::<MAX_NODES>(assignment, body_start)?;
            self.emit(&[0x50])?;
            self.evaluation_depth += 1;
            self.emit_identifier(assignment.binding_name())?;
            self.emit(&[0x50])?;
            self.evaluation_depth += 1;
            let element_bytes = runtime_array_element_bytes(element)
                .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
            if access.reads_previous_value() {
                self.emit_reference_array_address_from_stack_index(
                    element_bytes,
                    RuntimeReferenceArrayLayout::Native,
                    1,
                )?;
                if element_bytes == 0 {
                    self.emit(&[0x31, 0xc0])?;
                } else {
                    self.emit_reference_load(element)?;
                }
                self.emit(&[0x50])?;
                self.evaluation_depth += 1;
            }
            self.emit_indexed_assignment_value::<MAX_NODES>(assignment, body_start, element_type)?;
            if access.reads_previous_value() {
                self.evaluation_depth -= 1;
                self.emit(&[0x59])?;
                self.emit_binary(assignment_binary_operator(assignment.operator).ok_or(
                    CodegenError {
                        kind: CodegenErrorKind::UnsupportedRuntimeOperator,
                        span: translate_span(body_start, assignment.name_span),
                    },
                )?)?;
            }
            if element_bytes != 0 {
                self.emit(&[0x48, 0x8b, 0x14, 0x24])?;
                self.emit_reference_array_store_address_from_stack_index(
                    element_bytes,
                    RuntimeReferenceArrayLayout::Native,
                    1,
                )?;
                self.emit_reference_store(element)?;
            }
            self.emit(&[0x48, 0x83, 0xc4, 16])?;
            self.evaluation_depth -= 2;
            Ok(())
        })();
        self.width = previous_width;
        emission
    }

    fn emit_slice_assignment_index<const MAX_NODES: usize>(
        &mut self,
        assignment: &crate::Assignment<'_>,
        body_start: usize,
    ) -> Result<(), CodegenError> {
        let index_span = assignment.index_span().ok_or(CodegenError {
            kind: CodegenErrorKind::RuntimeExpressionUnsupported,
            span: translate_span(body_start, assignment.name_span),
        })?;
        let tree = assignment
            .parse_index::<MAX_NODES>()
            .map_err(|error| CodegenError {
                kind: CodegenErrorKind::Expression(error.kind),
                span: translate_span(body_start + index_span.start, error.span),
            })?;
        let index_type = runtime_expression_type_with_locals(
            self.function,
            self.resolver,
            &self.locals[..self.saved_locals],
            &tree,
            tree.root(),
            0,
        )
        .map_err(|kind| CodegenError {
            kind,
            span: translate_span(body_start, index_span),
        })?;
        if !matches!(
            index_type,
            RuntimeExpressionType::Integer(None)
                | RuntimeExpressionType::Integer(Some(crate::IntegerType::Usize))
        ) {
            return Err(CodegenError {
                kind: CodegenErrorKind::RuntimeTypeMismatch,
                span: translate_span(body_start, index_span),
            });
        }
        self.emit_expression(&tree, tree.root(), 0)?;
        self.emit(&[0x50])?;
        self.evaluation_depth += 1;
        self.emit_slice_length(assignment.binding_name())?;
        self.emit(&[0x48, 0x8b, 0x0c, 0x24, 0x48, 0x39, 0xc1])?;
        let in_bounds = self.emit_forward_branch(0x82)?;
        self.emit(&[0x0f, 0x0b])?;
        self.patch_forward_branch(in_bounds)?;
        self.emit(&[0x58])?;
        self.evaluation_depth -= 1;
        Ok(())
    }

    fn emit_reference_array_address_from_stack_index(
        &mut self,
        element_bytes: usize,
        _layout: RuntimeReferenceArrayLayout,
        index_slot: u8,
    ) -> Result<(), CodegenError> {
        self.emit(&[0x48, 0x8b, 0x4c, 0x24, index_slot * 8])?;
        match element_bytes {
            0 => Ok(()),
            1 => self.emit(&[0x48, 0x01, 0xc8]),
            2 => self.emit(&[0x48, 0x8d, 0x04, 0x48]),
            4 => self.emit(&[0x48, 0x8d, 0x04, 0x88]),
            8 => self.emit(&[0x48, 0x8d, 0x04, 0xc8]),
            _ => Err(self.error(CodegenErrorKind::UnsupportedRuntimeType)),
        }
    }

    fn emit_reference_array_store_address_from_stack_index(
        &mut self,
        element_bytes: usize,
        _layout: RuntimeReferenceArrayLayout,
        index_slot: u8,
    ) -> Result<(), CodegenError> {
        self.emit(&[0x48, 0x8b, 0x4c, 0x24, index_slot * 8])?;
        match element_bytes {
            1 => self.emit(&[0x48, 0x01, 0xca]),
            2 => self.emit(&[0x48, 0x8d, 0x14, 0x4a]),
            4 => self.emit(&[0x48, 0x8d, 0x14, 0x8a]),
            8 => self.emit(&[0x48, 0x8d, 0x14, 0xca]),
            _ => Err(self.error(CodegenErrorKind::UnsupportedRuntimeType)),
        }
    }

    fn emit_dereference_assignment<const MAX_EXPRESSION_NODES: usize>(
        &mut self,
        assignment: &crate::Assignment<'_>,
        body_start: usize,
        place: RuntimePlace<'_>,
    ) -> Result<(), CodegenError> {
        if assignment.index().is_some() {
            return Err(CodegenError {
                kind: CodegenErrorKind::RuntimeExpressionUnsupported,
                span: translate_span(body_start, assignment.name_span),
            });
        }
        let name = assignment.binding_name();
        let pointee = match place.ty {
            RuntimeExpressionType::Reference {
                target: RuntimeReferenceTarget::Scalar(pointee),
                ..
            }
            | RuntimeExpressionType::RawPointer { pointee, .. } => pointee,
            _ => {
                return Err(CodegenError {
                    kind: CodegenErrorKind::RuntimeTypeMismatch,
                    span: translate_span(body_start, assignment.name_span),
                });
            }
        };
        if !place.mutable {
            return Err(CodegenError {
                kind: CodegenErrorKind::ImmutableAssignment,
                span: translate_span(body_start, assignment.name_span),
            });
        }
        let value_type = runtime_type_from_array_element(pointee);
        if value_type == RuntimeExpressionType::Bool
            && !matches!(
                assignment.operator,
                crate::AssignmentOperator::Assign
                    | crate::AssignmentOperator::BitAnd
                    | crate::AssignmentOperator::BitOr
                    | crate::AssignmentOperator::BitXor
            )
        {
            return Err(CodegenError {
                kind: CodegenErrorKind::RuntimeTypeMismatch,
                span: translate_span(body_start, assignment.name_span),
            });
        }
        if value_type == RuntimeExpressionType::Char && place.access.reads_previous_value() {
            return Err(CodegenError {
                kind: CodegenErrorKind::UnsupportedRuntimeOperator,
                span: translate_span(body_start, assignment.name_span),
            });
        }

        let previous_width = self.width;
        self.width = runtime_expression_width(value_type).unwrap_or(previous_width);
        let emission = (|| {
            self.emit_identifier(name)?;
            self.emit(&[0x50])?;
            self.evaluation_depth += 1;
            if place.access.reads_previous_value() {
                self.emit_reference_load(pointee)?;
                self.emit(&[0x50])?;
                self.evaluation_depth += 1;
            }
            let tree = assignment
                .parse_value::<MAX_EXPRESSION_NODES>()
                .map_err(|error| CodegenError {
                    kind: CodegenErrorKind::Expression(error.kind),
                    span: translate_span(body_start + assignment.value_span.start, error.span),
                })?;
            let actual_type = runtime_expression_type_with_locals(
                self.function,
                self.resolver,
                &self.locals[..self.saved_locals],
                &tree,
                tree.root(),
                0,
            )
            .map_err(|kind| CodegenError {
                kind,
                span: translate_span(body_start, assignment.value_span),
            })?;
            if !runtime_types_compatible(actual_type, value_type) {
                return Err(CodegenError {
                    kind: CodegenErrorKind::RuntimeTypeMismatch,
                    span: translate_span(body_start, assignment.value_span),
                });
            }
            self.emit_expression(&tree, tree.root(), 0)?;
            if place.access.reads_previous_value() {
                self.evaluation_depth -= 1;
                self.emit(&[0x59])?;
                self.emit_binary(assignment_binary_operator(assignment.operator).ok_or(
                    CodegenError {
                        kind: CodegenErrorKind::UnsupportedRuntimeOperator,
                        span: translate_span(body_start, assignment.name_span),
                    },
                )?)?;
            }
            self.emit(&[0x48, 0x8b, 0x14, 0x24])?;
            self.emit_reference_store(pointee)?;
            self.emit(&[0x48, 0x83, 0xc4, 0x08])?;
            self.evaluation_depth -= 1;
            Ok(())
        })();
        self.width = previous_width;
        emission
    }

    fn emit_indexed_assignment<const MAX_NODES: usize>(
        &mut self,
        assignment: &crate::Assignment<'_>,
        body_start: usize,
        local_index: usize,
        target: RuntimeLocal<'tree>,
        access: RuntimePlaceAccess,
    ) -> Result<(), CodegenError> {
        let RuntimeExpressionType::Array { element, count } = target.ty else {
            return Err(CodegenError {
                kind: CodegenErrorKind::RuntimeTypeMismatch,
                span: translate_span(body_start, assignment.name_span),
            });
        };
        let element_type = runtime_type_from_array_element(element);
        if element_type == RuntimeExpressionType::Bool
            && !matches!(
                assignment.operator,
                crate::AssignmentOperator::Assign
                    | crate::AssignmentOperator::BitAnd
                    | crate::AssignmentOperator::BitOr
                    | crate::AssignmentOperator::BitXor
            )
        {
            return Err(CodegenError {
                kind: CodegenErrorKind::RuntimeTypeMismatch,
                span: translate_span(body_start, assignment.name_span),
            });
        }
        if matches!(
            element_type,
            RuntimeExpressionType::Unit | RuntimeExpressionType::Char
        ) && access.reads_previous_value()
        {
            return Err(CodegenError {
                kind: CodegenErrorKind::UnsupportedRuntimeOperator,
                span: translate_span(body_start, assignment.name_span),
            });
        }
        let previous_width = self.width;
        self.width = runtime_expression_width(element_type).unwrap_or(previous_width);
        let emission = (|| {
            self.emit_indexed_assignment_index::<MAX_NODES>(assignment, body_start, count)?;
            self.emit(&[0x50])?;
            self.evaluation_depth += 1;
            if access.reads_previous_value() {
                self.emit_array_local_element(local_index, element, count, 0)?;
                self.emit(&[0x50])?;
                self.evaluation_depth += 1;
            }
            self.emit_indexed_assignment_value::<MAX_NODES>(assignment, body_start, element_type)?;
            if access.reads_previous_value() {
                self.evaluation_depth -= 1;
                self.emit(&[0x59])?;
                self.emit_binary(assignment_binary_operator(assignment.operator).ok_or(
                    CodegenError {
                        kind: CodegenErrorKind::UnsupportedRuntimeOperator,
                        span: translate_span(body_start, assignment.name_span),
                    },
                )?)?;
            }
            self.emit(&[0x50])?;
            self.evaluation_depth += 1;
            self.emit_array_local_element_store(local_index, element, count, 1)?;
            self.evaluation_depth -= 2;
            self.emit(&[0x48, 0x83, 0xc4, 16])
        })();
        self.width = previous_width;
        emission
    }

    fn emit_indexed_assignment_index<const MAX_NODES: usize>(
        &mut self,
        assignment: &crate::Assignment<'_>,
        body_start: usize,
        count: usize,
    ) -> Result<(), CodegenError> {
        let index_span = assignment.index_span().ok_or(CodegenError {
            kind: CodegenErrorKind::RuntimeExpressionUnsupported,
            span: translate_span(body_start, assignment.name_span),
        })?;
        let tree = assignment
            .parse_index::<MAX_NODES>()
            .map_err(|error| CodegenError {
                kind: CodegenErrorKind::Expression(error.kind),
                span: translate_span(body_start + index_span.start, error.span),
            })?;
        let index_type = runtime_expression_type_with_locals(
            self.function,
            self.resolver,
            &self.locals[..self.saved_locals],
            &tree,
            tree.root(),
            0,
        )
        .map_err(|kind| CodegenError {
            kind,
            span: translate_span(body_start, index_span),
        })?;
        if !matches!(
            index_type,
            RuntimeExpressionType::Integer(None)
                | RuntimeExpressionType::Integer(Some(crate::IntegerType::Usize))
        ) {
            return Err(CodegenError {
                kind: CodegenErrorKind::RuntimeTypeMismatch,
                span: translate_span(body_start, index_span),
            });
        }
        match tree.evaluate_at(tree.root(), self.resolver) {
            Ok(index) => {
                let index = usize::try_from(index).map_err(|_| CodegenError {
                    kind: CodegenErrorKind::ValueOutOfRange,
                    span: translate_span(body_start, index_span),
                })?;
                if index >= count {
                    return Err(CodegenError {
                        kind: CodegenErrorKind::Execution(ExecutionError::Arithmetic(
                            crate::ConstEvalError::ArrayIndexOutOfBounds,
                        )),
                        span: translate_span(body_start, index_span),
                    });
                }
            }
            Err(crate::ConstEvalError::UnknownIdentifier) => {}
            Err(error) => {
                return Err(CodegenError {
                    kind: CodegenErrorKind::Execution(ExecutionError::Arithmetic(error)),
                    span: translate_span(body_start, index_span),
                });
            }
        }
        self.emit_expression(&tree, tree.root(), 0)
    }

    fn emit_indexed_assignment_value<const MAX_NODES: usize>(
        &mut self,
        assignment: &crate::Assignment<'_>,
        body_start: usize,
        element_type: RuntimeExpressionType,
    ) -> Result<(), CodegenError> {
        let tree = assignment
            .parse_value::<MAX_NODES>()
            .map_err(|error| CodegenError {
                kind: CodegenErrorKind::Expression(error.kind),
                span: translate_span(body_start + assignment.value_span.start, error.span),
            })?;
        let value_type = runtime_expression_type_with_locals(
            self.function,
            self.resolver,
            &self.locals[..self.saved_locals],
            &tree,
            tree.root(),
            0,
        )
        .map_err(|kind| CodegenError {
            kind,
            span: translate_span(body_start, assignment.value_span),
        })?;
        if !runtime_types_compatible(value_type, element_type) {
            return Err(CodegenError {
                kind: CodegenErrorKind::RuntimeTypeMismatch,
                span: translate_span(body_start, assignment.value_span),
            });
        }
        self.emit_expression(&tree, tree.root(), 0)
    }

    fn emit_array_local_element(
        &mut self,
        local_index: usize,
        element: RuntimeArrayElementType,
        count: usize,
        index_slot: usize,
    ) -> Result<(), CodegenError> {
        let later_slots = self.local_stack_slots_from(local_index + 1)?;
        let element_bytes = runtime_array_element_bytes(element)
            .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
        if matches!(element_bytes, 1 | 2 | 4) {
            self.emit_stack_slot(index_slot)?;
            self.emit(&[0x48, 0x89, 0xc1])?;
            self.emit_stack_slot_address(self.evaluation_depth + later_slots)?;
            match element_bytes {
                1 => self.emit(&[0x48, 0x01, 0xc8])?,
                2 => self.emit(&[0x48, 0x8d, 0x04, 0x48])?,
                4 => self.emit(&[0x48, 0x8d, 0x04, 0x88])?,
                _ => unreachable!(),
            }
            return self.emit_reference_load(element);
        }
        let mut end_patches = [0usize; crate::expression::MAX_ARRAY_ELEMENTS];
        for (candidate, end_patch) in end_patches[..count].iter_mut().enumerate() {
            self.emit_stack_slot(index_slot)?;
            self.emit(&[0x48, 0x83, 0xf8, candidate as u8])?;
            let next = self.emit_forward_branch(0x85)?;
            self.emit_stack_slot(self.evaluation_depth + later_slots + candidate)?;
            *end_patch = self.emit_unconditional_forward_branch()?;
            self.patch_forward_branch(next)?;
        }
        self.emit(&[0x0f, 0x0b])?;
        for patch in end_patches[..count].iter().copied() {
            self.patch_forward_branch(patch)?;
        }
        Ok(())
    }

    fn emit_array_local_element_store(
        &mut self,
        local_index: usize,
        element: RuntimeArrayElementType,
        count: usize,
        index_slot: usize,
    ) -> Result<(), CodegenError> {
        let later_slots = self.local_stack_slots_from(local_index + 1)?;
        let element_bytes = runtime_array_element_bytes(element)
            .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
        if matches!(element_bytes, 1 | 2 | 4) {
            self.emit_stack_slot(index_slot)?;
            self.emit(&[0x48, 0x89, 0xc1])?;
            self.emit_stack_slot_address(self.evaluation_depth + later_slots)?;
            self.emit(&[0x48, 0x89, 0xc2])?;
            match element_bytes {
                1 => self.emit(&[0x48, 0x01, 0xca])?,
                2 => self.emit(&[0x48, 0x8d, 0x14, 0x4a])?,
                4 => self.emit(&[0x48, 0x8d, 0x14, 0x8a])?,
                _ => unreachable!(),
            }
            self.emit_stack_slot(0)?;
            return self.emit_reference_store(element);
        }
        let mut end_patches = [0usize; crate::expression::MAX_ARRAY_ELEMENTS];
        for (candidate, end_patch) in end_patches[..count].iter_mut().enumerate() {
            self.emit_stack_slot(index_slot)?;
            self.emit(&[0x48, 0x83, 0xf8, candidate as u8])?;
            let next = self.emit_forward_branch(0x85)?;
            self.emit_stack_slot(0)?;
            self.emit_store_stack_slot(self.evaluation_depth + later_slots + candidate)?;
            *end_patch = self.emit_unconditional_forward_branch()?;
            self.patch_forward_branch(next)?;
        }
        self.emit(&[0x0f, 0x0b])?;
        for patch in end_patches[..count].iter().copied() {
            self.patch_forward_branch(patch)?;
        }
        Ok(())
    }

    fn emit_array_assignment<const MAX_NODES: usize>(
        &mut self,
        tree: &crate::ExpressionTree<'_, MAX_NODES>,
        root: crate::ExprId,
        local_index: usize,
        element: RuntimeArrayElementType,
        count: usize,
    ) -> Result<(), CodegenError> {
        if count > crate::expression::MAX_ARRAY_ELEMENTS {
            return Err(self.error(CodegenErrorKind::RuntimeExpressionUnsupported));
        }
        self.emit_array_to_stack(tree, root, count)?;
        let stored_slots = self.pack_temporary_array_for_local(element, count)?;
        let later_slots = self.local_stack_slots_from(local_index + 1)?;
        for slot in 0..stored_slots {
            self.emit_stack_slot(slot)?;
            let destination = stored_slots
                .checked_add(later_slots)
                .and_then(|slots| slots.checked_add(slot))
                .ok_or(self.error(CodegenErrorKind::OutputTooSmall))?;
            self.emit_store_stack_slot(destination)?;
        }
        self.evaluation_depth -= stored_slots;
        let bytes = stored_slots
            .checked_mul(8)
            .ok_or(self.error(CodegenErrorKind::OutputTooSmall))?;
        self.emit_stack_cleanup_bytes(bytes)?;
        Ok(())
    }

    fn emit_array_to_stack<const MAX_NODES: usize>(
        &mut self,
        tree: &crate::ExpressionTree<'_, MAX_NODES>,
        root: crate::ExprId,
        count: usize,
    ) -> Result<(), CodegenError> {
        self.emit_array_to_stack_at(tree, root, count, 0)
    }

    fn emit_array_to_stack_at<const MAX_NODES: usize>(
        &mut self,
        tree: &crate::ExpressionTree<'_, MAX_NODES>,
        root: crate::ExprId,
        count: usize,
        depth: usize,
    ) -> Result<(), CodegenError> {
        if depth == 64 {
            return Err(self.error(CodegenErrorKind::Lowering(
                IrErrorKind::NestingLimitExceeded,
            )));
        }
        let expression = tree
            .expression(root)
            .ok_or(self.error(CodegenErrorKind::RuntimeExpressionUnsupported))?;
        match expression.kind {
            ExprKind::InlineConst { operand }
            | ExprKind::LoopBreak { operand }
            | ExprKind::Return { operand } => {
                return self.emit_array_to_stack_at(tree, operand, count, depth + 1);
            }
            ExprKind::Sequence { first, then } => {
                self.emit_expression(tree, first, depth + 1)?;
                return self.emit_array_to_stack_at(tree, then, count, depth + 1);
            }
            ExprKind::If {
                condition,
                then_branch,
                else_branch,
            }
            | ExprKind::LoopBreakIf {
                condition,
                then_branch,
                else_branch,
            } => {
                self.emit_expression(tree, condition, depth + 1)?;
                self.emit(&[0x48, 0x85, 0xc0])?;
                let else_patch = self.emit_forward_branch(0x84)?;
                let branch_depth = self.evaluation_depth;
                self.emit_array_to_stack_at(tree, then_branch, count, depth + 1)?;
                let end_patch = self.emit_unconditional_forward_branch()?;
                self.patch_forward_branch(else_patch)?;
                self.evaluation_depth = branch_depth;
                self.emit_array_to_stack_at(tree, else_branch, count, depth + 1)?;
                self.patch_forward_branch(end_patch)?;
                return Ok(());
            }
            _ => {}
        }
        if let ExprKind::IntegerToBytes { base, order } = expression.kind {
            let RuntimeExpressionType::Integer(Some(integer_type)) =
                runtime_expression_type_with_locals(
                    self.function,
                    self.resolver,
                    &self.locals[..self.saved_locals],
                    tree,
                    base,
                    depth + 1,
                )
                .map_err(|kind| self.error(kind))?
            else {
                return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
            };
            let width = runtime_width(integer_type.name())
                .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
            let byte_count = usize::from(width.bits / 8);
            if byte_count != count {
                return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
            }
            self.emit_expression(tree, base, depth + 1)?;
            self.emit(&[0x49, 0x89, 0xc3])?;
            for index in 0..count {
                self.emit(&[0x4c, 0x89, 0xd8])?;
                let byte_index = if order == crate::expression::IntegerByteOrder::Big {
                    count - index - 1
                } else {
                    index
                };
                let shift = byte_index * 8;
                if shift != 0 {
                    self.emit(&[0x48, 0xc1, 0xe8, shift as u8])?;
                }
                self.emit(&[0x25, 0xff, 0, 0, 0])?;
                self.emit(&[0x50])?;
                self.evaluation_depth += 1;
            }
            for left in 0..count / 2 {
                let right = count - 1 - left;
                self.emit_stack_slot(left)?;
                self.emit(&[0x48, 0x89, 0xc2])?;
                self.emit_stack_slot(right)?;
                self.emit_store_stack_slot(left)?;
                self.emit(&[0x48, 0x89, 0xd0])?;
                self.emit_store_stack_slot(right)?;
            }
            return Ok(());
        }
        if matches!(expression.kind, ExprKind::Call { .. }) {
            let RuntimeExpressionType::Array {
                count: return_count,
                ..
            } = runtime_expression_type_with_locals(
                self.function,
                self.resolver,
                &self.locals[..self.saved_locals],
                tree,
                root,
                0,
            )
            .map_err(|kind| self.error(kind))?
            else {
                return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
            };
            if return_count != count {
                return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
            }
            return self.emit_expression(tree, root, 0);
        }
        if let ExprKind::ArrayRepeat {
            element,
            count: repeat,
        } = expression.kind
        {
            if repeat != count {
                return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
            }
            self.emit_expression(tree, element, 0)?;
            if count == 0 {
                return Ok(());
            }
            self.emit(&[0x50])?;
            self.evaluation_depth += 1;
            for _ in 1..count {
                self.emit_stack_slot(0)?;
                self.emit(&[0x50])?;
                self.evaluation_depth += 1;
            }
            return Ok(());
        }
        for element in 0..count {
            self.emit_array_element(tree, root, element, false, 0)?;
            self.emit(&[0x50])?;
            self.evaluation_depth += 1;
        }
        for left in 0..count / 2 {
            let right = count - 1 - left;
            self.emit_stack_slot(left)?;
            self.emit(&[0x48, 0x89, 0xc2])?;
            self.emit_stack_slot(right)?;
            self.emit_store_stack_slot(left)?;
            self.emit(&[0x48, 0x89, 0xd0])?;
            self.emit_store_stack_slot(right)?;
        }
        Ok(())
    }

    fn pack_temporary_array_for_local(
        &mut self,
        element: RuntimeArrayElementType,
        count: usize,
    ) -> Result<usize, CodegenError> {
        let local_slots =
            runtime_local_stack_slots(RuntimeExpressionType::Array { element, count });
        if local_slots == count {
            return Ok(count);
        }
        let element_bytes = runtime_array_element_bytes(element)
            .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
        for word in (0..local_slots).rev() {
            self.emit_pack_array_word(element, count, element_bytes, word)?;
            let destination = count
                .checked_sub(local_slots)
                .and_then(|slots| slots.checked_add(word))
                .ok_or(self.error(CodegenErrorKind::OutputTooSmall))?;
            self.emit_store_stack_slot(destination)?;
        }
        let removed_slots = count - local_slots;
        self.evaluation_depth -= removed_slots;
        self.emit_stack_cleanup_bytes(
            removed_slots
                .checked_mul(8)
                .ok_or(self.error(CodegenErrorKind::OutputTooSmall))?,
        )?;
        Ok(local_slots)
    }

    fn emit_conditional_return<const MAX_EXPRESSION_NODES: usize>(
        &mut self,
        conditional: &crate::ConditionalReturn<'_>,
        expected_type: RuntimeExpressionType,
        body_start: usize,
    ) -> Result<(), CodegenError> {
        let condition_tree = conditional
            .parse_condition::<MAX_EXPRESSION_NODES>()
            .map_err(|error| CodegenError {
                kind: CodegenErrorKind::Expression(error.kind),
                span: translate_span(body_start + conditional.condition_span.start, error.span),
            })?;
        let condition_type = runtime_expression_type_with_locals(
            self.function,
            self.resolver,
            &self.locals[..self.saved_locals],
            &condition_tree,
            condition_tree.root(),
            0,
        )
        .map_err(|kind| CodegenError {
            kind,
            span: translate_span(body_start, conditional.condition_span),
        })?;
        if condition_type != RuntimeExpressionType::Bool {
            return Err(CodegenError {
                kind: CodegenErrorKind::RuntimeTypeMismatch,
                span: translate_span(body_start, conditional.condition_span),
            });
        }
        let value_tree = conditional
            .parse_value::<MAX_EXPRESSION_NODES>()
            .map_err(|error| CodegenError {
                kind: CodegenErrorKind::Expression(error.kind),
                span: translate_span(body_start + conditional.value_span.start, error.span),
            })?;
        let value_type = runtime_expression_type_with_locals(
            self.function,
            self.resolver,
            &self.locals[..self.saved_locals],
            &value_tree,
            value_tree.root(),
            0,
        )
        .map_err(|kind| CodegenError {
            kind,
            span: translate_span(body_start, conditional.value_span),
        })?;
        if !runtime_types_compatible(value_type, expected_type) {
            return Err(CodegenError {
                kind: CodegenErrorKind::RuntimeTypeMismatch,
                span: translate_span(body_start, conditional.value_span),
            });
        }
        self.emit_expression(&condition_tree, condition_tree.root(), 0)?;
        self.emit(&[0x48, 0x85, 0xc0])?;
        let skip_return = self.emit_forward_branch(0x84)?;
        self.emit_typed_return(&value_tree, value_tree.root(), expected_type)?;
        self.patch_forward_branch(skip_return)
    }

    fn emit_conditional_assignment<const MAX_EXPRESSION_NODES: usize>(
        &mut self,
        conditional: &crate::ConditionalAssignment<'tree>,
        expected_type: RuntimeExpressionType,
        operand_type: &str,
        body_start: usize,
    ) -> Result<(), CodegenError> {
        let mut end_patches = [None; crate::MAX_CONDITIONAL_ASSIGNMENT_BRANCHES];
        let mut end_count = 0usize;
        for branch in conditional.branches().iter().flatten() {
            let condition_tree =
                branch
                    .parse_condition::<MAX_EXPRESSION_NODES>()
                    .map_err(|error| CodegenError {
                        kind: CodegenErrorKind::Expression(error.kind),
                        span: translate_span(body_start + branch.condition_span.start, error.span),
                    })?;
            let condition_type = runtime_expression_type_with_locals(
                self.function,
                self.resolver,
                &self.locals[..self.saved_locals],
                &condition_tree,
                condition_tree.root(),
                0,
            )
            .map_err(|kind| CodegenError {
                kind,
                span: translate_span(body_start, branch.condition_span),
            })?;
            if condition_type != RuntimeExpressionType::Bool {
                return Err(CodegenError {
                    kind: CodegenErrorKind::RuntimeTypeMismatch,
                    span: translate_span(body_start, branch.condition_span),
                });
            }
            self.emit_expression(&condition_tree, condition_tree.root(), 0)?;
            self.emit(&[0x48, 0x85, 0xc0])?;
            let false_branch = self.emit_forward_branch(0x84)?;
            let local_checkpoint = self.saved_locals;
            for action in branch.actions().iter().flatten() {
                match action {
                    crate::ConditionalAssignmentAction::Local(local) => {
                        self.emit_local::<MAX_EXPRESSION_NODES>(local, operand_type, body_start)?;
                    }
                    crate::ConditionalAssignmentAction::Assignment(assignment) => {
                        self.emit_assignment::<MAX_EXPRESSION_NODES>(assignment, body_start)?;
                    }
                    crate::ConditionalAssignmentAction::Expression(statement) => {
                        self.emit_expression_statement::<MAX_EXPRESSION_NODES>(
                            statement, body_start,
                        )?;
                    }
                    crate::ConditionalAssignmentAction::Return(return_statement) => {
                        self.emit_return::<MAX_EXPRESSION_NODES>(
                            return_statement,
                            expected_type,
                            body_start,
                        )?;
                    }
                }
            }
            self.emit_scoped_local_cleanup(local_checkpoint)?;
            end_patches[end_count] = Some(self.emit_unconditional_forward_branch()?);
            end_count += 1;
            self.patch_forward_branch(false_branch)?;
        }
        let local_checkpoint = self.saved_locals;
        for action in conditional.else_actions().iter().flatten() {
            match action {
                crate::ConditionalAssignmentAction::Local(local) => {
                    self.emit_local::<MAX_EXPRESSION_NODES>(local, operand_type, body_start)?;
                }
                crate::ConditionalAssignmentAction::Assignment(assignment) => {
                    self.emit_assignment::<MAX_EXPRESSION_NODES>(assignment, body_start)?;
                }
                crate::ConditionalAssignmentAction::Expression(statement) => {
                    self.emit_expression_statement::<MAX_EXPRESSION_NODES>(statement, body_start)?;
                }
                crate::ConditionalAssignmentAction::Return(return_statement) => {
                    self.emit_return::<MAX_EXPRESSION_NODES>(
                        return_statement,
                        expected_type,
                        body_start,
                    )?;
                }
            }
        }
        self.emit_scoped_local_cleanup(local_checkpoint)?;
        for patch in end_patches[..end_count].iter().flatten().copied() {
            self.patch_forward_branch(patch)?;
        }
        Ok(())
    }

    fn emit_return<const MAX_EXPRESSION_NODES: usize>(
        &mut self,
        return_statement: &crate::LoopReturn<'_>,
        expected_type: RuntimeExpressionType,
        body_start: usize,
    ) -> Result<(), CodegenError> {
        let value_tree = return_statement
            .parse_value::<MAX_EXPRESSION_NODES>()
            .map_err(|error| CodegenError {
                kind: CodegenErrorKind::Expression(error.kind),
                span: translate_span(body_start + return_statement.value_span.start, error.span),
            })?;
        let value_type = runtime_expression_type_with_locals(
            self.function,
            self.resolver,
            &self.locals[..self.saved_locals],
            &value_tree,
            value_tree.root(),
            0,
        )
        .map_err(|kind| CodegenError {
            kind,
            span: translate_span(body_start, return_statement.value_span),
        })?;
        if !runtime_types_compatible(value_type, expected_type) {
            return Err(CodegenError {
                kind: CodegenErrorKind::RuntimeTypeMismatch,
                span: translate_span(body_start, return_statement.value_span),
            });
        }
        self.emit_typed_return(&value_tree, value_tree.root(), expected_type)
    }

    fn emit_typed_return<const MAX_NODES: usize>(
        &mut self,
        tree: &crate::ExpressionTree<'_, MAX_NODES>,
        root: crate::ExprId,
        expected_type: RuntimeExpressionType,
    ) -> Result<(), CodegenError> {
        if matches!(
            expected_type,
            RuntimeExpressionType::Reference {
                target: RuntimeReferenceTarget::Slice(_) | RuntimeReferenceTarget::Str,
                ..
            }
        ) {
            return self.emit_slice_return(tree, root);
        }
        let RuntimeExpressionType::Array { element, count } = expected_type else {
            self.emit_expression(tree, root, 0)?;
            return self.emit_epilogue();
        };
        let (element_bytes, _, words) = runtime_array_abi_layout(expected_type)
            .ok_or(self.error(CodegenErrorKind::UnsupportedReturnType))?;
        self.emit_array_to_stack(tree, root, count)?;
        if words == 0 {
            // Zero-sized aggregates have no result transport. Their elements are
            // still evaluated and materialized above so expression semantics stay
            // identical to non-zero-sized arrays.
        } else if self.uses_sret {
            let pointer_slot = self
                .evaluation_depth
                .checked_add(self.local_stack_slots()?)
                .and_then(|slots| slots.checked_add(self.saved_parameter_slots - 1))
                .ok_or(self.error(CodegenErrorKind::OutputTooSmall))?;
            self.emit_stack_slot(pointer_slot)?;
            self.emit(&[0x48, 0x89, 0xc2])?;
            for index in 0..count {
                self.emit_stack_slot(index)?;
                let displacement = u8::try_from(index * element_bytes)
                    .map_err(|_| self.error(CodegenErrorKind::OutputTooSmall))?;
                match element_bytes {
                    1 => self.emit(&[0x88, 0x42, displacement])?,
                    2 => self.emit(&[0x66, 0x89, 0x42, displacement])?,
                    4 => self.emit(&[0x89, 0x42, displacement])?,
                    8 if displacement == 0 => self.emit(&[0x48, 0x89, 0x02])?,
                    8 => self.emit(&[0x48, 0x89, 0x42, displacement])?,
                    _ => return Err(self.error(CodegenErrorKind::UnsupportedReturnType)),
                }
            }
            self.emit(&[0x48, 0x89, 0xd0])?;
        } else if words == 1 {
            self.emit_pack_array_word(element, count, element_bytes, 0)?;
        } else if self.abi == X86_64Abi::SystemV && words == 2 {
            self.emit_pack_array_word(element, count, element_bytes, 1)?;
            self.emit(&[0x48, 0x89, 0xc1])?;
            self.emit_pack_array_word(element, count, element_bytes, 0)?;
            self.emit(&[0x48, 0x89, 0xca])?;
        } else {
            return Err(self.error(CodegenErrorKind::UnsupportedReturnType));
        }
        self.evaluation_depth -= count;
        let bytes = count
            .checked_mul(8)
            .ok_or(self.error(CodegenErrorKind::OutputTooSmall))?;
        self.emit_stack_cleanup_bytes(bytes)?;
        self.emit_epilogue()
    }

    fn emit_slice_return<const MAX_NODES: usize>(
        &mut self,
        tree: &crate::ExpressionTree<'_, MAX_NODES>,
        root: crate::ExprId,
    ) -> Result<(), CodegenError> {
        self.emit_slice_return_at(tree, root, 0)
    }

    fn emit_slice_return_at<const MAX_NODES: usize>(
        &mut self,
        tree: &crate::ExpressionTree<'_, MAX_NODES>,
        root: crate::ExprId,
        depth: usize,
    ) -> Result<(), CodegenError> {
        if depth == 64 {
            return Err(self.error(CodegenErrorKind::Lowering(
                IrErrorKind::NestingLimitExceeded,
            )));
        }
        if matches!(
            tree.expression(root).map(|expression| expression.kind),
            Some(ExprKind::Call { .. })
        ) && runtime_expression_type_with_locals(
            self.function,
            self.resolver,
            &self.locals[..self.saved_locals],
            tree,
            root,
            depth + 1,
        )
        .is_ok_and(runtime_type_is_fat_reference)
        {
            self.emit_expression(tree, root, depth + 1)?;
            if self.abi == X86_64Abi::Windows {
                self.emit(&[0x49, 0x89, 0xd0, 0x48, 0x89, 0xc1])?;
                let local_slots = self.local_stack_slots()?;
                let hidden_pointer_slot = self
                    .saved_parameter_slots
                    .checked_sub(1)
                    .and_then(|slot| slot.checked_add(self.evaluation_depth))
                    .and_then(|slot| slot.checked_add(local_slots))
                    .ok_or(self.error(CodegenErrorKind::OutputTooSmall))?;
                self.emit_stack_slot(hidden_pointer_slot)?;
                self.emit(&[0x48, 0x89, 0x08, 0x4c, 0x89, 0x40, 0x08])?;
            }
            return self.emit_epilogue();
        }
        if let Some(
            ExprKind::If {
                condition,
                then_branch,
                else_branch,
            }
            | ExprKind::LoopBreakIf {
                condition,
                then_branch,
                else_branch,
            },
        ) = tree.expression(root).map(|expression| expression.kind)
        {
            self.emit_expression(tree, condition, depth + 1)?;
            self.emit(&[0x48, 0x85, 0xc0])?;
            let else_patch = self.emit_forward_branch(0x84)?;
            self.emit_slice_return_at(tree, then_branch, depth + 1)?;
            self.patch_forward_branch(else_patch)?;
            return self.emit_slice_return_at(tree, else_branch, depth + 1);
        }
        if let Some(
            ExprKind::LoopBreak { operand }
            | ExprKind::Return { operand }
            | ExprKind::InlineConst { operand },
        ) = tree.expression(root).map(|expression| expression.kind)
        {
            return self.emit_slice_return_at(tree, operand, depth + 1);
        }
        if let Some(ExprKind::Sequence { first, then }) =
            tree.expression(root).map(|expression| expression.kind)
        {
            self.emit_expression(tree, first, depth + 1)?;
            return self.emit_slice_return_at(tree, then, depth + 1);
        }
        let stacked = if matches!(
            tree.expression(root).map(|expression| expression.kind),
            Some(ExprKind::String(_) | ExprKind::ByteString(_) | ExprKind::CStrToBytes { .. })
        ) {
            self.emit_slice_value_to_stack(tree, root, depth + 1)?;
            true
        } else {
            self.emit_range_slice_to_stack(tree, root, depth + 1)?
        };
        if stacked {
            self.emit_stack_slot(1)?;
            self.emit(&[0x48, 0x89, 0xc1])?;
            self.emit_stack_slot(0)?;
        } else {
            let source = reference_source_name(tree, root)
                .ok_or(self.error(CodegenErrorKind::RuntimeExpressionUnsupported))?;
            self.emit_expression(tree, root, 0)?;
            self.emit(&[0x48, 0x89, 0xc1])?;
            self.emit_slice_length(source)?;
        }
        match self.abi {
            X86_64Abi::SystemV => {
                self.emit(&[0x48, 0x89, 0xc2, 0x48, 0x89, 0xc8])?;
            }
            X86_64Abi::Windows => {
                self.emit(&[0x49, 0x89, 0xc0])?;
                let local_slots = self.local_stack_slots()?;
                let pointer_slot = usize::from(stacked)
                    .checked_mul(2)
                    .and_then(|slots| slots.checked_add(self.evaluation_depth))
                    .and_then(|slots| slots.checked_add(local_slots))
                    .and_then(|slots| slots.checked_add(self.saved_parameter_slots - 1))
                    .ok_or(self.error(CodegenErrorKind::OutputTooSmall))?;
                self.emit_stack_slot(pointer_slot)?;
                self.emit(&[0x48, 0x89, 0x08, 0x4c, 0x89, 0x40, 0x08])?;
            }
        }
        if stacked {
            self.emit_stack_cleanup_bytes(16)?;
        }
        self.emit_epilogue()
    }

    fn emit_pack_array_word(
        &mut self,
        _element: RuntimeArrayElementType,
        count: usize,
        element_bytes: usize,
        word: usize,
    ) -> Result<(), CodegenError> {
        self.emit(&[0x31, 0xd2])?;
        for index in 0..count {
            let byte_offset = index * element_bytes;
            if byte_offset / 8 != word {
                continue;
            }
            self.emit_stack_slot(index)?;
            match element_bytes {
                1 => self.emit(&[0x0f, 0xb6, 0xc0])?,
                2 => self.emit(&[0x0f, 0xb7, 0xc0])?,
                4 => self.emit(&[0x89, 0xc0])?,
                8 => {}
                _ => return Err(self.error(CodegenErrorKind::UnsupportedReturnType)),
            }
            let shift = ((byte_offset % 8) * 8) as u8;
            if shift != 0 {
                self.emit(&[0x48, 0xc1, 0xe0, shift])?;
            }
            self.emit(&[0x48, 0x09, 0xc2])?;
        }
        self.emit(&[0x48, 0x89, 0xd0])
    }

    fn emit_conditional_return_else<const MAX_EXPRESSION_NODES: usize>(
        &mut self,
        conditional: &crate::ConditionalReturnElse<'_>,
        expected_type: RuntimeExpressionType,
        body_start: usize,
    ) -> Result<(), CodegenError> {
        for branch in conditional.branches().iter().flatten() {
            let condition_tree =
                branch
                    .parse_condition::<MAX_EXPRESSION_NODES>()
                    .map_err(|error| CodegenError {
                        kind: CodegenErrorKind::Expression(error.kind),
                        span: translate_span(body_start + branch.condition_span.start, error.span),
                    })?;
            let condition_type = runtime_expression_type_with_locals(
                self.function,
                self.resolver,
                &self.locals[..self.saved_locals],
                &condition_tree,
                condition_tree.root(),
                0,
            )
            .map_err(|kind| CodegenError {
                kind,
                span: translate_span(body_start, branch.condition_span),
            })?;
            if condition_type != RuntimeExpressionType::Bool {
                return Err(CodegenError {
                    kind: CodegenErrorKind::RuntimeTypeMismatch,
                    span: translate_span(body_start, branch.condition_span),
                });
            }
            let value_tree = branch
                .parse_value::<MAX_EXPRESSION_NODES>()
                .map_err(|error| CodegenError {
                    kind: CodegenErrorKind::Expression(error.kind),
                    span: translate_span(body_start + branch.value_span.start, error.span),
                })?;
            let value_type = runtime_expression_type_with_locals(
                self.function,
                self.resolver,
                &self.locals[..self.saved_locals],
                &value_tree,
                value_tree.root(),
                0,
            )
            .map_err(|kind| CodegenError {
                kind,
                span: translate_span(body_start, branch.value_span),
            })?;
            if !runtime_types_compatible(value_type, expected_type) {
                return Err(CodegenError {
                    kind: CodegenErrorKind::RuntimeTypeMismatch,
                    span: translate_span(body_start, branch.value_span),
                });
            }
            self.emit_expression(&condition_tree, condition_tree.root(), 0)?;
            self.emit(&[0x48, 0x85, 0xc0])?;
            let next_branch = self.emit_forward_branch(0x84)?;
            self.emit_typed_return(&value_tree, value_tree.root(), expected_type)?;
            self.patch_forward_branch(next_branch)?;
        }
        let Some(else_value) = conditional.else_value.as_ref() else {
            return Ok(());
        };
        let else_tree = else_value
            .parse_value::<MAX_EXPRESSION_NODES>()
            .map_err(|error| CodegenError {
                kind: CodegenErrorKind::Expression(error.kind),
                span: translate_span(body_start + else_value.value_span.start, error.span),
            })?;
        let else_type = runtime_expression_type_with_locals(
            self.function,
            self.resolver,
            &self.locals[..self.saved_locals],
            &else_tree,
            else_tree.root(),
            0,
        )
        .map_err(|kind| CodegenError {
            kind,
            span: translate_span(body_start, else_value.value_span),
        })?;
        if !runtime_types_compatible(else_type, expected_type) {
            return Err(CodegenError {
                kind: CodegenErrorKind::RuntimeTypeMismatch,
                span: translate_span(body_start, else_value.value_span),
            });
        }
        self.emit_typed_return(&else_tree, else_tree.root(), expected_type)
    }

    fn emit_normalize(&mut self) -> Result<(), CodegenError> {
        self.emit_normalize_width(self.width)
    }

    fn emit_normalize_width(&mut self, width: RuntimeWidth) -> Result<(), CodegenError> {
        match (width.signed, width.bits) {
            (false, 8) => self.emit(&[0x0f, 0xb6, 0xc0]),
            (false, 16) => self.emit(&[0x0f, 0xb7, 0xc0]),
            (false, 32) => self.emit(&[0x89, 0xc0]),
            (true, 8) => self.emit(&[0x48, 0x0f, 0xbe, 0xc0]),
            (true, 16) => self.emit(&[0x48, 0x0f, 0xbf, 0xc0]),
            (true, 32) => self.emit(&[0x48, 0x63, 0xc0]),
            (_, 64) => Ok(()),
            _ => Err(self.error(CodegenErrorKind::UnsupportedRuntimeType)),
        }
    }

    fn emit_range_check(&mut self) -> Result<(), CodegenError> {
        if self.width.bits == 64 {
            return Ok(());
        }
        self.emit(&[0x48, 0xba])?;
        self.emit(&self.width.maximum.to_le_bytes())?;
        self.emit(&[0x48, 0x39, 0xd0])?;
        self.emit_trap_branch(if self.width.signed { 0x8f } else { 0x87 })?;
        if self.width.signed {
            self.emit(&[0x48, 0xba])?;
            self.emit(&(self.width.minimum as u64).to_le_bytes())?;
            self.emit(&[0x48, 0x39, 0xd0])?;
            self.emit_trap_branch(0x8c)?;
        }
        Ok(())
    }

    fn emit_ascii_predicate(
        &mut self,
        predicate: crate::expression::AsciiPredicate,
    ) -> Result<(), CodegenError> {
        use crate::expression::AsciiPredicate;
        let ranges: &[(u8, u8)] = match predicate {
            AsciiPredicate::Ascii => &[(0x00, 0x7f)],
            AsciiPredicate::Alphabetic => &[(b'A', b'Z'), (b'a', b'z')],
            AsciiPredicate::Uppercase => &[(b'A', b'Z')],
            AsciiPredicate::Lowercase => &[(b'a', b'z')],
            AsciiPredicate::Alphanumeric => &[(b'0', b'9'), (b'A', b'Z'), (b'a', b'z')],
            AsciiPredicate::Digit => &[(b'0', b'9')],
            AsciiPredicate::HexDigit => &[(b'0', b'9'), (b'A', b'F'), (b'a', b'f')],
            AsciiPredicate::Punctuation => {
                &[(0x21, 0x2f), (0x3a, 0x40), (0x5b, 0x60), (0x7b, 0x7e)]
            }
            AsciiPredicate::Graphic => &[(0x21, 0x7e)],
            AsciiPredicate::Whitespace => &[
                (b'\t', b'\t'),
                (b'\n', b'\n'),
                (0x0c, 0x0c),
                (b'\r', b'\r'),
                (b' ', b' '),
            ],
            AsciiPredicate::Control => &[(0x00, 0x1f), (0x7f, 0x7f)],
        };
        let mut matches = [None; 5];
        for (index, &(low, high)) in ranges.iter().enumerate() {
            self.emit(&[0x48, 0x83, 0xf8, low])?;
            let below = self.emit_forward_branch(0x82)?;
            self.emit(&[0x48, 0x83, 0xf8, high])?;
            matches[index] = Some(self.emit_forward_branch(0x86)?);
            self.patch_forward_branch(below)?;
        }
        self.emit(&[0x31, 0xc0])?;
        let end = self.emit_unconditional_forward_branch()?;
        for matched in matches[..ranges.len()].iter().flatten().copied() {
            self.patch_forward_branch(matched)?;
        }
        self.emit(&[0xb8, 1, 0, 0, 0])?;
        self.patch_forward_branch(end)
    }

    fn emit_saturating_arithmetic(
        &mut self,
        operator: crate::BinaryOperator,
    ) -> Result<(), CodegenError> {
        use crate::BinaryOperator::{Add, Divide, Multiply, Subtract};
        if operator == Divide {
            return self.emit_saturating_division();
        }
        if operator == Multiply {
            return self.emit_saturating_multiplication();
        }
        if operator == Add {
            self.emit(&[0x48, 0x01, 0xc8])?;
        } else {
            self.emit(&[0x48, 0x89, 0xc2, 0x48, 0x89, 0xc8, 0x48, 0x29, 0xd0])?;
        }
        debug_assert!(matches!(operator, Add | Subtract | Multiply | Divide));

        if !self.width.signed && operator == Subtract {
            let no_borrow = self.emit_forward_branch(0x83)?;
            self.emit(&[0x31, 0xc0])?;
            self.patch_forward_branch(no_borrow)?;
        } else if !self.width.signed && self.width.bits == 64 {
            let no_carry = self.emit_forward_branch(0x83)?;
            self.emit(&[0x48, 0xb8])?;
            self.emit(&u64::MAX.to_le_bytes())?;
            self.patch_forward_branch(no_carry)?;
        } else if !self.width.signed {
            self.emit(&[0x48, 0xba])?;
            self.emit(&self.width.maximum.to_le_bytes())?;
            self.emit(&[0x48, 0x39, 0xd0])?;
            let in_range = self.emit_forward_branch(0x86)?;
            self.emit(&[0x48, 0x89, 0xd0])?;
            self.patch_forward_branch(in_range)?;
        } else if self.width.bits == 64 {
            let no_overflow = self.emit_forward_branch(0x81)?;
            self.emit(&[0x48, 0x85, 0xc9])?;
            let negative = self.emit_forward_branch(0x88)?;
            self.emit(&[0x48, 0xb8])?;
            self.emit(&self.width.maximum.to_le_bytes())?;
            let end = self.emit_unconditional_forward_branch()?;
            self.patch_forward_branch(negative)?;
            self.emit(&[0x48, 0xb8])?;
            self.emit(&(self.width.minimum as u64).to_le_bytes())?;
            self.patch_forward_branch(end)?;
            self.patch_forward_branch(no_overflow)?;
        } else {
            self.emit(&[0x48, 0xba])?;
            self.emit(&self.width.maximum.to_le_bytes())?;
            self.emit(&[0x48, 0x39, 0xd0])?;
            let not_above = self.emit_forward_branch(0x8e)?;
            self.emit(&[0x48, 0x89, 0xd0])?;
            let end = self.emit_unconditional_forward_branch()?;
            self.patch_forward_branch(not_above)?;
            self.emit(&[0x48, 0xba])?;
            self.emit(&(self.width.minimum as u64).to_le_bytes())?;
            self.emit(&[0x48, 0x39, 0xd0])?;
            let in_range = self.emit_forward_branch(0x8d)?;
            self.emit(&[0x48, 0x89, 0xd0])?;
            self.patch_forward_branch(in_range)?;
            self.patch_forward_branch(end)?;
        }
        self.emit_normalize()
    }

    fn emit_saturating_mixed_arithmetic(
        &mut self,
        operator: crate::BinaryOperator,
    ) -> Result<(), CodegenError> {
        use crate::BinaryOperator::{Add, Subtract};
        if self.width.signed {
            match operator {
                Add => {
                    self.emit(&[0x48, 0xba])?;
                    self.emit(&self.width.maximum.to_le_bytes())?;
                    self.emit(&[0x48, 0x29, 0xca])?;
                }
                Subtract => {
                    self.emit(&[0x48, 0x89, 0xca, 0x49, 0xb8])?;
                    self.emit(&(self.width.minimum as u64).to_le_bytes())?;
                    self.emit(&[0x4c, 0x29, 0xc2])?;
                }
                _ => return Err(self.error(CodegenErrorKind::UnsupportedRuntimeOperator)),
            }
            self.emit(&[0x48, 0x39, 0xd0])?;
            let in_range = self.emit_forward_branch(0x86)?;
            self.emit(&[0x48, 0xb8])?;
            let clamp = if operator == Add {
                self.width.maximum
            } else {
                self.width.minimum as u64
            };
            self.emit(&clamp.to_le_bytes())?;
            let end = self.emit_unconditional_forward_branch()?;
            self.patch_forward_branch(in_range)?;
            match operator {
                Add => self.emit(&[0x48, 0x01, 0xc8])?,
                Subtract => self.emit(&[0x48, 0x29, 0xc1, 0x48, 0x89, 0xc8])?,
                _ => unreachable!(),
            }
            self.patch_forward_branch(end)?;
            return self.emit_normalize();
        }

        if self.width.bits < 64 {
            match operator {
                Add => self.emit(&[0x48, 0x01, 0xc8])?,
                Subtract => self.emit(&[0x48, 0x29, 0xc1, 0x48, 0x89, 0xc8])?,
                _ => return Err(self.error(CodegenErrorKind::UnsupportedRuntimeOperator)),
            }
            self.emit(&[0x48, 0x85, 0xc0])?;
            let nonnegative = self.emit_forward_branch(0x89)?;
            self.emit(&[0x31, 0xc0])?;
            let end = self.emit_unconditional_forward_branch()?;
            self.patch_forward_branch(nonnegative)?;
            self.emit(&[0x48, 0xba])?;
            self.emit(&self.width.maximum.to_le_bytes())?;
            self.emit(&[0x48, 0x39, 0xd0])?;
            let in_range = self.emit_forward_branch(0x86)?;
            self.emit(&[0x48, 0x89, 0xd0])?;
            self.patch_forward_branch(in_range)?;
            self.patch_forward_branch(end)?;
            return self.emit_normalize();
        }

        self.emit(&[0x48, 0x85, 0xc0])?;
        let nonnegative = self.emit_forward_branch(0x89)?;
        self.emit(&[0x48, 0xf7, 0xd8])?;
        match operator {
            Add => self.emit(&[0x48, 0x29, 0xc1])?,
            Subtract => self.emit(&[0x48, 0x01, 0xc1])?,
            _ => return Err(self.error(CodegenErrorKind::UnsupportedRuntimeOperator)),
        }
        let negative_in_range = self.emit_forward_branch(0x83)?;
        if operator == Add {
            self.emit(&[0x31, 0xc0])?;
        } else {
            self.emit(&[0x48, 0xb8])?;
            self.emit(&u64::MAX.to_le_bytes())?;
        }
        let negative_end = self.emit_unconditional_forward_branch()?;
        self.patch_forward_branch(negative_in_range)?;
        self.emit(&[0x48, 0x89, 0xc8])?;
        let negative_result_end = self.emit_unconditional_forward_branch()?;

        self.patch_forward_branch(nonnegative)?;
        match operator {
            Add => self.emit(&[0x48, 0x01, 0xc1])?,
            Subtract => self.emit(&[0x48, 0x29, 0xc1])?,
            _ => unreachable!(),
        }
        let positive_in_range = self.emit_forward_branch(0x83)?;
        if operator == Add {
            self.emit(&[0x48, 0xb8])?;
            self.emit(&u64::MAX.to_le_bytes())?;
        } else {
            self.emit(&[0x31, 0xc0])?;
        }
        let positive_end = self.emit_unconditional_forward_branch()?;
        self.patch_forward_branch(positive_in_range)?;
        self.emit(&[0x48, 0x89, 0xc8])?;
        self.patch_forward_branch(negative_end)?;
        self.patch_forward_branch(negative_result_end)?;
        self.patch_forward_branch(positive_end)
    }

    fn emit_saturating_multiplication(&mut self) -> Result<(), CodegenError> {
        if !self.width.signed && self.width.bits == 64 {
            self.emit(&[0x48, 0xf7, 0xe1, 0x48, 0x85, 0xd2])?;
            let in_range = self.emit_forward_branch(0x84)?;
            self.emit(&[0x48, 0xb8])?;
            self.emit(&u64::MAX.to_le_bytes())?;
            self.patch_forward_branch(in_range)?;
        } else if self.width.signed && self.width.bits == 64 {
            self.emit(&[0x48, 0x89, 0xc2, 0x48, 0x0f, 0xaf, 0xc1])?;
            let in_range = self.emit_forward_branch(0x81)?;
            self.emit(&[0x48, 0x31, 0xca, 0x48, 0x85, 0xd2])?;
            let negative = self.emit_forward_branch(0x88)?;
            self.emit(&[0x48, 0xb8])?;
            self.emit(&self.width.maximum.to_le_bytes())?;
            let end = self.emit_unconditional_forward_branch()?;
            self.patch_forward_branch(negative)?;
            self.emit(&[0x48, 0xb8])?;
            self.emit(&(self.width.minimum as u64).to_le_bytes())?;
            self.patch_forward_branch(end)?;
            self.patch_forward_branch(in_range)?;
        } else {
            self.emit(&[0x48, 0x0f, 0xaf, 0xc1])?;
            self.emit(&[0x48, 0xba])?;
            self.emit(&self.width.maximum.to_le_bytes())?;
            self.emit(&[0x48, 0x39, 0xd0])?;
            let not_above =
                self.emit_forward_branch(if self.width.signed { 0x8e } else { 0x86 })?;
            self.emit(&[0x48, 0x89, 0xd0])?;
            let end = self.emit_unconditional_forward_branch()?;
            self.patch_forward_branch(not_above)?;
            if self.width.signed {
                self.emit(&[0x48, 0xba])?;
                self.emit(&(self.width.minimum as u64).to_le_bytes())?;
                self.emit(&[0x48, 0x39, 0xd0])?;
                let in_range = self.emit_forward_branch(0x8d)?;
                self.emit(&[0x48, 0x89, 0xd0])?;
                self.patch_forward_branch(in_range)?;
            }
            self.patch_forward_branch(end)?;
        }
        self.emit_normalize()
    }

    fn emit_saturating_division(&mut self) -> Result<(), CodegenError> {
        self.emit(&[0x48, 0x87, 0xc1, 0x48, 0x85, 0xc9])?;
        self.emit_trap_branch(0x84)?;
        if self.width.signed {
            self.emit(&[0x48, 0x83, 0xf9, 0xff])?;
            let ordinary_divisor = self.emit_forward_branch(0x85)?;
            self.emit(&[0x48, 0xba])?;
            self.emit(&(self.width.minimum as u64).to_le_bytes())?;
            self.emit(&[0x48, 0x39, 0xd0])?;
            let ordinary_dividend = self.emit_forward_branch(0x85)?;
            self.emit(&[0x48, 0xb8])?;
            self.emit(&self.width.maximum.to_le_bytes())?;
            let end = self.emit_unconditional_forward_branch()?;
            self.patch_forward_branch(ordinary_divisor)?;
            self.patch_forward_branch(ordinary_dividend)?;
            self.emit(&[0x48, 0x99, 0x48, 0xf7, 0xf9])?;
            self.patch_forward_branch(end)?;
        } else {
            self.emit(&[0x48, 0x31, 0xd2, 0x48, 0xf7, 0xf1])?;
        }
        self.emit_normalize()
    }

    fn emit_euclidean_division(
        &mut self,
        operator: crate::BinaryOperator,
        wrapping: bool,
    ) -> Result<(), CodegenError> {
        use crate::BinaryOperator::{Divide, Remainder};
        debug_assert!(matches!(operator, Divide | Remainder));
        self.emit(&[0x48, 0x87, 0xc1, 0x48, 0x85, 0xc9])?;
        self.emit_trap_branch(0x84)?;
        if !self.width.signed {
            self.emit(&[0x48, 0x31, 0xd2, 0x48, 0xf7, 0xf1])?;
            if operator == Remainder {
                self.emit(&[0x48, 0x89, 0xd0])?;
            }
            return self.emit_normalize();
        }
        self.emit(&[0x48, 0x83, 0xf9, 0xff])?;
        let ordinary_divisor = self.emit_forward_branch(0x85)?;
        self.emit(&[0x49, 0xb9])?;
        self.emit(&(self.width.minimum as u64).to_le_bytes())?;
        self.emit(&[0x4c, 0x39, 0xc8])?;
        if wrapping {
            let ordinary_dividend = self.emit_forward_branch(0x85)?;
            if operator == Remainder {
                self.emit(&[0x31, 0xc0])?;
            }
            let wrapped = self.emit_unconditional_forward_branch()?;
            self.patch_forward_branch(ordinary_dividend)?;
            self.patch_forward_branch(ordinary_divisor)?;
            self.emit(&[0x48, 0x99, 0x48, 0xf7, 0xf9, 0x48, 0x85, 0xd2])?;
            let nonnegative = self.emit_forward_branch(0x89)?;
            self.emit_euclidean_adjustment(operator)?;
            self.patch_forward_branch(nonnegative)?;
            if operator == Remainder {
                self.emit(&[0x48, 0x89, 0xd0])?;
            }
            self.patch_forward_branch(wrapped)?;
            return self.emit_normalize();
        }
        self.emit_trap_branch(0x84)?;
        self.patch_forward_branch(ordinary_divisor)?;
        self.emit(&[0x48, 0x99, 0x48, 0xf7, 0xf9, 0x48, 0x85, 0xd2])?;
        let nonnegative = self.emit_forward_branch(0x89)?;
        self.emit_euclidean_adjustment(operator)?;
        self.patch_forward_branch(nonnegative)?;
        if operator == Remainder {
            self.emit(&[0x48, 0x89, 0xd0])?;
        }
        self.emit_normalize()
    }

    fn emit_euclidean_adjustment(
        &mut self,
        operator: crate::BinaryOperator,
    ) -> Result<(), CodegenError> {
        use crate::BinaryOperator::Divide;
        self.emit(&[0x48, 0x85, 0xc9])?;
        let negative_divisor = self.emit_forward_branch(0x88)?;
        if operator == Divide {
            self.emit(&[0x48, 0xff, 0xc8])?;
        } else {
            self.emit(&[0x48, 0x01, 0xca])?;
        }
        let adjusted = self.emit_unconditional_forward_branch()?;
        self.patch_forward_branch(negative_divisor)?;
        if operator == Divide {
            self.emit(&[0x48, 0xff, 0xc0])?;
        } else {
            self.emit(&[0x48, 0x29, 0xca])?;
        }
        self.patch_forward_branch(adjusted)?;
        Ok(())
    }

    fn emit_wrapping_division(
        &mut self,
        operator: crate::BinaryOperator,
    ) -> Result<(), CodegenError> {
        use crate::BinaryOperator::{Divide, Remainder};
        self.emit(&[0x48, 0x87, 0xc1, 0x48, 0x85, 0xc9])?;
        self.emit_trap_branch(0x84)?;
        if self.width.signed {
            self.emit(&[0x48, 0x83, 0xf9, 0xff])?;
            let ordinary_divisor = self.emit_forward_branch(0x85)?;
            self.emit(&[0x48, 0xba])?;
            self.emit(&(self.width.minimum as u64).to_le_bytes())?;
            self.emit(&[0x48, 0x39, 0xd0])?;
            let ordinary_dividend = self.emit_forward_branch(0x85)?;
            if operator == Remainder {
                self.emit(&[0x31, 0xc0])?;
            }
            let end = self.emit_unconditional_forward_branch()?;
            self.patch_forward_branch(ordinary_divisor)?;
            self.patch_forward_branch(ordinary_dividend)?;
            self.emit(&[0x48, 0x99, 0x48, 0xf7, 0xf9])?;
            if operator == Remainder {
                self.emit(&[0x48, 0x89, 0xd0])?;
            }
            self.patch_forward_branch(end)?;
        } else {
            self.emit(&[0x48, 0x31, 0xd2, 0x48, 0xf7, 0xf1])?;
            if operator == Remainder {
                self.emit(&[0x48, 0x89, 0xd0])?;
            }
        }
        debug_assert!(matches!(operator, Divide | Remainder));
        self.emit_normalize()
    }

    fn emit_integer_square_root(&mut self, width: RuntimeWidth) -> Result<(), CodegenError> {
        self.emit(&[0x45, 0x31, 0xc0, 0x49, 0xb9])?;
        self.emit(&(1_u64 << (width.bits - 2)).to_le_bytes())?;
        let align = self.length;
        self.emit(&[0x4c, 0x39, 0xc8])?;
        let aligned = self.emit_forward_branch(0x83)?;
        self.emit(&[0x49, 0xc1, 0xe9, 2])?;
        self.emit_backward_branch(align)?;
        self.patch_forward_branch(aligned)?;
        let root = self.length;
        self.emit(&[0x4d, 0x85, 0xc9])?;
        let done = self.emit_forward_branch(0x84)?;
        self.emit(&[0x4d, 0x89, 0xc2, 0x4d, 0x01, 0xca])?;
        self.emit(&[0x4c, 0x39, 0xd0])?;
        let below = self.emit_forward_branch(0x82)?;
        self.emit(&[0x4c, 0x29, 0xd0, 0x49, 0xd1, 0xe8, 0x4d, 0x01, 0xc8])?;
        let shifted = self.emit_unconditional_forward_branch()?;
        self.patch_forward_branch(below)?;
        self.emit(&[0x49, 0xd1, 0xe8])?;
        self.patch_forward_branch(shifted)?;
        self.emit(&[0x49, 0xc1, 0xe9, 2])?;
        self.emit_backward_branch(root)?;
        self.patch_forward_branch(done)?;
        self.emit(&[0x4c, 0x89, 0xc0])
    }

    fn emit_checked_multiply_branches(
        &mut self,
        width: RuntimeWidth,
    ) -> Result<(Option<usize>, Option<usize>), CodegenError> {
        if width.bits == 64 {
            if width.signed {
                self.emit(&[0x48, 0x0f, 0xaf, 0xc1])?;
                return Ok((Some(self.emit_forward_branch(0x80)?), None));
            }
            self.emit(&[0x48, 0xf7, 0xe1, 0x48, 0x85, 0xd2])?;
            return Ok((Some(self.emit_forward_branch(0x85)?), None));
        }
        self.emit(&[0x48, 0x0f, 0xaf, 0xc1])?;
        let below_minimum = if width.signed {
            self.emit(&[0x48, 0xba])?;
            self.emit(&(width.minimum as u64).to_le_bytes())?;
            self.emit(&[0x48, 0x39, 0xd0])?;
            Some(self.emit_forward_branch(0x8c)?)
        } else {
            None
        };
        self.emit(&[0x48, 0xba])?;
        self.emit(&width.maximum.to_le_bytes())?;
        self.emit(&[0x48, 0x39, 0xd0])?;
        let above_maximum = self.emit_forward_branch(if width.signed { 0x8f } else { 0x87 })?;
        self.emit_normalize()?;
        Ok((below_minimum, Some(above_maximum)))
    }

    fn emit_checked_integer_option<const MAX_NODES: usize>(
        &mut self,
        tree: &crate::ExpressionTree<'_, MAX_NODES>,
        option: crate::ExprId,
        depth: usize,
    ) -> Result<(RuntimeWidth, RuntimeWidth), CodegenError> {
        let option_id = option;
        let option = tree
            .expression(option)
            .ok_or(self.error(CodegenErrorKind::RuntimeExpressionUnsupported))?;
        if let ExprKind::IntegerOptionMap {
            option: producer,
            closure,
        } = option.kind
        {
            let input_type = checked_option_integer_type(
                self.function,
                self.resolver,
                &self.locals[..self.saved_locals],
                tree,
                producer,
                depth + 1,
            )
            .map_err(|kind| self.error(kind))?;
            let output_type = checked_option_integer_type(
                self.function,
                self.resolver,
                &self.locals[..self.saved_locals],
                tree,
                option_id,
                depth + 1,
            )
            .map_err(|kind| self.error(kind))?;
            let closure_expression = tree
                .expression(closure)
                .ok_or(self.error(CodegenErrorKind::RuntimeExpressionUnsupported))?;
            let ExprKind::Closure {
                parameter: Some(parameter),
                body,
            } = closure_expression.kind
            else {
                return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
            };
            let mut closure_tree = *tree;
            closure_tree
                .bind_closure_parameter(parameter, input_type)
                .map_err(|kind| self.error(CodegenErrorKind::Expression(kind)))?;
            let (_, previous_width) =
                self.emit_checked_integer_option(tree, producer, depth + 1)?;
            self.emit(&[0x4d, 0x85, 0xc0])?;
            let none = self.emit_forward_branch(0x84)?;
            self.emit(&[0x50])?;
            self.evaluation_depth += 1;
            self.width = runtime_width(output_type.name())
                .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
            self.emit_expression(&closure_tree, body, depth + 1)?;
            self.emit(&[0x48, 0x83, 0xc4, 0x08, 0x41, 0xb8, 1, 0, 0, 0])?;
            self.evaluation_depth -= 1;
            self.patch_forward_branch(none)?;
            let output_width = self.width;
            return Ok((output_width, previous_width));
        }
        if let ExprKind::IntegerOptionAndThen {
            option: producer,
            closure,
        } = option.kind
        {
            let input_type = checked_option_integer_type(
                self.function,
                self.resolver,
                &self.locals[..self.saved_locals],
                tree,
                producer,
                depth + 1,
            )
            .map_err(|kind| self.error(kind))?;
            let closure_expression = tree
                .expression(closure)
                .ok_or(self.error(CodegenErrorKind::RuntimeExpressionUnsupported))?;
            let ExprKind::Closure {
                parameter: Some(parameter),
                body,
            } = closure_expression.kind
            else {
                return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
            };
            let mut closure_tree = *tree;
            closure_tree
                .bind_closure_parameter(parameter, input_type)
                .map_err(|kind| self.error(CodegenErrorKind::Expression(kind)))?;
            let (_, previous_width) =
                self.emit_checked_integer_option(tree, producer, depth + 1)?;
            self.emit(&[0x4d, 0x85, 0xc0])?;
            let none = self.emit_forward_branch(0x84)?;
            self.emit(&[0x50])?;
            self.evaluation_depth += 1;
            let (output_width, _) =
                self.emit_checked_integer_option(&closure_tree, body, depth + 1)?;
            self.emit(&[0x48, 0x83, 0xc4, 0x08])?;
            self.evaluation_depth -= 1;
            self.patch_forward_branch(none)?;
            self.width = output_width;
            return Ok((output_width, previous_width));
        }
        if let ExprKind::IntegerOptionOrElse {
            option: producer,
            closure,
        } = option.kind
        {
            let input_type = checked_option_integer_type(
                self.function,
                self.resolver,
                &self.locals[..self.saved_locals],
                tree,
                producer,
                depth + 1,
            )
            .map_err(|kind| self.error(kind))?;
            let closure_expression = tree
                .expression(closure)
                .ok_or(self.error(CodegenErrorKind::RuntimeExpressionUnsupported))?;
            let ExprKind::Closure {
                parameter: None,
                body,
            } = closure_expression.kind
            else {
                return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
            };
            let (input_width, previous_width) =
                self.emit_checked_integer_option(tree, producer, depth + 1)?;
            self.emit(&[0x4d, 0x85, 0xc0])?;
            let some = self.emit_forward_branch(0x85)?;
            let (output_width, _) = self.emit_checked_integer_option(tree, body, depth + 1)?;
            if output_width != input_width
                || runtime_width(input_type.name())
                    .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?
                    != input_width
            {
                return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
            }
            self.patch_forward_branch(some)?;
            self.width = input_width;
            return Ok((input_width, previous_width));
        }
        if let ExprKind::IntegerOptionOr {
            option: producer,
            alternative,
        } = option.kind
        {
            let input_type = checked_option_integer_type(
                self.function,
                self.resolver,
                &self.locals[..self.saved_locals],
                tree,
                producer,
                depth + 1,
            )
            .map_err(|kind| self.error(kind))?;
            let (input_width, previous_width) =
                self.emit_checked_integer_option(tree, producer, depth + 1)?;
            self.emit(&[0x50, 0x41, 0x50])?;
            self.evaluation_depth += 2;
            let (alternative_width, _) =
                self.emit_checked_integer_option(tree, alternative, depth + 1)?;
            if alternative_width != input_width
                || runtime_width(input_type.name())
                    .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?
                    != input_width
            {
                return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
            }
            self.emit(&[0x48, 0x83, 0x3c, 0x24, 0])?;
            let original_none = self.emit_forward_branch(0x84)?;
            self.emit(&[0x48, 0x8b, 0x44, 0x24, 0x08, 0x41, 0xb8, 1, 0, 0, 0])?;
            self.patch_forward_branch(original_none)?;
            self.emit(&[0x48, 0x83, 0xc4, 0x10])?;
            self.evaluation_depth -= 2;
            self.width = input_width;
            return Ok((input_width, previous_width));
        }
        if let ExprKind::IntegerOptionXor {
            option: producer,
            alternative,
        } = option.kind
        {
            let input_type = checked_option_integer_type(
                self.function,
                self.resolver,
                &self.locals[..self.saved_locals],
                tree,
                producer,
                depth + 1,
            )
            .map_err(|kind| self.error(kind))?;
            let (input_width, previous_width) =
                self.emit_checked_integer_option(tree, producer, depth + 1)?;
            self.emit(&[0x50, 0x41, 0x50])?;
            self.evaluation_depth += 2;
            let (alternative_width, _) =
                self.emit_checked_integer_option(tree, alternative, depth + 1)?;
            if alternative_width != input_width
                || runtime_width(input_type.name())
                    .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?
                    != input_width
            {
                return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
            }
            self.emit(&[0x48, 0x83, 0x3c, 0x24, 0])?;
            let original_none = self.emit_forward_branch(0x84)?;
            self.emit(&[0x4d, 0x85, 0xc0])?;
            let alternative_none = self.emit_forward_branch(0x84)?;
            self.emit(&[0x45, 0x31, 0xc0])?;
            let selected = self.emit_unconditional_forward_branch()?;
            self.patch_forward_branch(alternative_none)?;
            self.emit(&[0x48, 0x8b, 0x44, 0x24, 0x08, 0x41, 0xb8, 1, 0, 0, 0])?;
            self.patch_forward_branch(selected)?;
            self.patch_forward_branch(original_none)?;
            self.emit(&[0x48, 0x83, 0xc4, 0x10])?;
            self.evaluation_depth -= 2;
            self.width = input_width;
            return Ok((input_width, previous_width));
        }
        if let ExprKind::IntegerOptionAnd {
            option: producer,
            alternative,
        } = option.kind
        {
            checked_option_integer_type(
                self.function,
                self.resolver,
                &self.locals[..self.saved_locals],
                tree,
                producer,
                depth + 1,
            )
            .map_err(|kind| self.error(kind))?;
            let (_, previous_width) =
                self.emit_checked_integer_option(tree, producer, depth + 1)?;
            self.emit(&[0x41, 0x50])?;
            self.evaluation_depth += 1;
            let (output_width, _) =
                self.emit_checked_integer_option(tree, alternative, depth + 1)?;
            self.emit(&[0x48, 0x83, 0x3c, 0x24, 0])?;
            let original_some = self.emit_forward_branch(0x85)?;
            self.emit(&[0x45, 0x31, 0xc0])?;
            self.patch_forward_branch(original_some)?;
            self.emit(&[0x48, 0x83, 0xc4, 0x08])?;
            self.evaluation_depth -= 1;
            self.width = output_width;
            return Ok((output_width, previous_width));
        }
        if let ExprKind::IntegerOptionThenSome { condition, value } = option.kind {
            let output_type = checked_option_integer_type(
                self.function,
                self.resolver,
                &self.locals[..self.saved_locals],
                tree,
                option_id,
                depth + 1,
            )
            .map_err(|kind| self.error(kind))?;
            let output_width = runtime_width(output_type.name())
                .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
            let previous_width = self.width;
            self.width =
                runtime_width("u8").ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
            self.emit_expression(tree, condition, depth + 1)?;
            self.emit(&[0x50])?;
            self.evaluation_depth += 1;
            self.width = output_width;
            self.emit_expression(tree, value, depth + 1)?;
            self.emit(&[0x48, 0x83, 0x3c, 0x24, 0])?;
            self.emit(&[0x41, 0x0f, 0x95, 0xc0, 0x4d, 0x0f, 0xb6, 0xc0])?;
            self.emit(&[0x48, 0x83, 0xc4, 0x08])?;
            self.evaluation_depth -= 1;
            self.width = output_width;
            return Ok((output_width, previous_width));
        }
        if let ExprKind::IntegerOptionThen { condition, closure } = option.kind {
            let output_type = checked_option_integer_type(
                self.function,
                self.resolver,
                &self.locals[..self.saved_locals],
                tree,
                option_id,
                depth + 1,
            )
            .map_err(|kind| self.error(kind))?;
            let output_width = runtime_width(output_type.name())
                .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
            let closure_expression = tree
                .expression(closure)
                .ok_or(self.error(CodegenErrorKind::RuntimeExpressionUnsupported))?;
            let ExprKind::Closure {
                parameter: None,
                body,
            } = closure_expression.kind
            else {
                return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
            };
            let previous_width = self.width;
            self.width =
                runtime_width("u8").ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
            self.emit_expression(tree, condition, depth + 1)?;
            self.emit(&[0x48, 0x85, 0xc0])?;
            let absent = self.emit_forward_branch(0x84)?;
            self.width = output_width;
            self.emit_expression(tree, body, depth + 1)?;
            self.emit(&[0x41, 0xb8, 1, 0, 0, 0])?;
            let done = self.emit_unconditional_forward_branch()?;
            self.patch_forward_branch(absent)?;
            self.emit(&[0x31, 0xc0, 0x45, 0x31, 0xc0])?;
            self.patch_forward_branch(done)?;
            self.width = output_width;
            return Ok((output_width, previous_width));
        }
        if let ExprKind::IntegerOptionInspect {
            option: producer,
            closure,
        } = option.kind
        {
            let input_type = checked_option_integer_type(
                self.function,
                self.resolver,
                &self.locals[..self.saved_locals],
                tree,
                option_id,
                depth + 1,
            )
            .map_err(|kind| self.error(kind))?;
            let closure_expression = tree
                .expression(closure)
                .ok_or(self.error(CodegenErrorKind::RuntimeExpressionUnsupported))?;
            let ExprKind::Closure {
                parameter: Some(parameter),
                body,
            } = closure_expression.kind
            else {
                return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
            };
            let mut closure_tree = *tree;
            closure_tree
                .bind_closure_reference_parameter(parameter, input_type)
                .map_err(|kind| self.error(CodegenErrorKind::Expression(kind)))?;
            let widths = self.emit_checked_integer_option(tree, producer, depth + 1)?;
            let input_width = self.width;
            self.emit(&[0x4d, 0x85, 0xc0])?;
            let none = self.emit_forward_branch(0x84)?;
            self.emit(&[0x50])?;
            self.evaluation_depth += 1;
            self.emit_expression(&closure_tree, body, depth + 1)?;
            self.emit(&[0x58, 0x41, 0xb8, 1, 0, 0, 0])?;
            self.evaluation_depth -= 1;
            self.patch_forward_branch(none)?;
            self.width = input_width;
            return Ok(widths);
        }
        if let ExprKind::IntegerOptionFilter {
            option: producer,
            closure,
        } = option.kind
        {
            let result_type = checked_option_integer_type(
                self.function,
                self.resolver,
                &self.locals[..self.saved_locals],
                tree,
                producer,
                depth + 1,
            )
            .map_err(|kind| self.error(kind))?;
            let closure_expression = tree
                .expression(closure)
                .ok_or(self.error(CodegenErrorKind::RuntimeExpressionUnsupported))?;
            let ExprKind::Closure {
                parameter: Some(parameter),
                body,
            } = closure_expression.kind
            else {
                return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
            };
            let mut closure_tree = *tree;
            closure_tree
                .bind_closure_reference_parameter(parameter, result_type)
                .map_err(|kind| self.error(CodegenErrorKind::Expression(kind)))?;
            let widths = self.emit_checked_integer_option(tree, producer, depth + 1)?;
            let result_width = self.width;
            self.emit(&[0x4d, 0x85, 0xc0])?;
            let none = self.emit_forward_branch(0x84)?;
            self.emit(&[0x50])?;
            self.evaluation_depth += 1;
            self.emit_expression(&closure_tree, body, depth + 1)?;
            self.emit(&[0x49, 0x89, 0xc1, 0x58, 0x4d, 0x89, 0xc8])?;
            self.evaluation_depth -= 1;
            self.patch_forward_branch(none)?;
            self.width = result_width;
            return Ok(widths);
        }
        let ExprKind::CheckedIntegerOption {
            base,
            argument,
            operation,
        } = option.kind
        else {
            return Err(self.error(CodegenErrorKind::RuntimeExpressionUnsupported));
        };
        let base_type = runtime_expression_type_with_locals(
            self.function,
            self.resolver,
            &self.locals[..self.saved_locals],
            tree,
            base,
            depth + 1,
        )
        .map_err(|kind| self.error(kind))?;
        let source_width = runtime_expression_width(base_type)
            .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
        let previous_width = self.width;
        self.width = source_width;
        self.emit_expression(tree, base, depth + 1)?;
        let cast_target = match operation {
            crate::expression::CheckedIntegerOptionOperation::Cast(target) => Some(target),
            crate::expression::CheckedIntegerOptionOperation::Truncate(target) => {
                let RuntimeExpressionType::Integer(Some(source)) = base_type else {
                    return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
                };
                if !source
                    .supports_width_cast(target, crate::expression::IntegerWidthCastMode::Truncate)
                {
                    return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
                }
                Some(target)
            }
            crate::expression::CheckedIntegerOptionOperation::SignCast { signed } => {
                let RuntimeExpressionType::Integer(Some(source)) = base_type else {
                    return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
                };
                if source.is_signed() == signed {
                    return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
                }
                Some(
                    if signed {
                        source.signed_counterpart()
                    } else {
                        source.unsigned_counterpart()
                    }
                    .ok_or(self.error(CodegenErrorKind::RuntimeTypeMismatch))?,
                )
            }
            crate::expression::CheckedIntegerOptionOperation::ExactDivision => None,
            crate::expression::CheckedIntegerOptionOperation::Division { .. } => None,
            crate::expression::CheckedIntegerOptionOperation::Arithmetic(_) => None,
            crate::expression::CheckedIntegerOptionOperation::SignedUnary { .. } => None,
            crate::expression::CheckedIntegerOptionOperation::Shift { .. } => None,
            crate::expression::CheckedIntegerOptionOperation::Power => None,
            crate::expression::CheckedIntegerOptionOperation::NextPowerOfTwo => None,
            crate::expression::CheckedIntegerOptionOperation::Logarithm { .. } => None,
            crate::expression::CheckedIntegerOptionOperation::NextMultiple => None,
            crate::expression::CheckedIntegerOptionOperation::UnsignedMixedArithmetic {
                ..
            } => None,
            crate::expression::CheckedIntegerOptionOperation::SignedMixedArithmetic { .. } => None,
            crate::expression::CheckedIntegerOptionOperation::SquareRoot => None,
            crate::expression::CheckedIntegerOptionOperation::SignedDifference => None,
        };
        if let Some(target) = cast_target {
            if argument.is_some() {
                return Err(self.error(CodegenErrorKind::RuntimeExpressionUnsupported));
            }
            let target_width = runtime_width(target.name())
                .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
            self.emit(&[0x45, 0x31, 0xc0])?;
            let check_minimum = source_width.signed
                && (!target_width.signed || target_width.bits < source_width.bits);
            let check_maximum = if source_width.signed {
                target_width.bits < source_width.bits
            } else if target_width.signed {
                target_width.bits <= source_width.bits
            } else {
                target_width.bits < source_width.bits
            };
            let mut below_minimum = None;
            if check_minimum {
                let minimum = if target_width.signed {
                    target_width.minimum as u64
                } else {
                    0
                };
                self.emit(&[0x48, 0xba])?;
                self.emit(&minimum.to_le_bytes())?;
                self.emit(&[0x48, 0x39, 0xd0])?;
                below_minimum = Some(self.emit_forward_branch(0x8c)?);
            }
            let mut above_maximum = None;
            if check_maximum {
                self.emit(&[0x48, 0xba])?;
                self.emit(&target_width.maximum.to_le_bytes())?;
                self.emit(&[0x48, 0x39, 0xd0])?;
                above_maximum = Some(self.emit_forward_branch(if source_width.signed {
                    0x8f
                } else {
                    0x87
                })?);
            }
            self.emit(&[0x41, 0xb8, 1, 0, 0, 0])?;
            if let Some(branch) = below_minimum {
                self.patch_forward_branch(branch)?;
            }
            if let Some(branch) = above_maximum {
                self.patch_forward_branch(branch)?;
            }
            self.width = target_width;
            self.emit_normalize()?;
            return Ok((target_width, previous_width));
        }
        if let crate::expression::CheckedIntegerOptionOperation::Arithmetic(operator) = operation {
            let argument =
                argument.ok_or(self.error(CodegenErrorKind::RuntimeExpressionUnsupported))?;
            self.emit(&[0x50])?;
            self.evaluation_depth += 1;
            self.emit_expression(tree, argument, depth + 1)?;
            self.emit(&[0x59])?;
            self.evaluation_depth -= 1;
            match operator {
                crate::BinaryOperator::Add => self.emit(&[0x48, 0x01, 0xc8])?,
                crate::BinaryOperator::Subtract => {
                    self.emit(&[0x48, 0x87, 0xc1, 0x48, 0x29, 0xc8])?;
                }
                crate::BinaryOperator::Multiply => {
                    if source_width.signed {
                        self.emit(&[0x48, 0x0f, 0xaf, 0xc1])?;
                    } else {
                        self.emit(&[0x48, 0x87, 0xc1, 0x48, 0xf7, 0xe1])?;
                    }
                }
                _ => return Err(self.error(CodegenErrorKind::RuntimeExpressionUnsupported)),
            }
            if source_width.bits == 64 {
                self.emit(if source_width.signed {
                    &[0x41, 0x0f, 0x91, 0xc0]
                } else {
                    &[0x41, 0x0f, 0x93, 0xc0]
                })?;
            } else {
                self.emit(&[0x45, 0x31, 0xc0])?;
                let mut below_minimum = None;
                if source_width.signed {
                    self.emit(&[0x48, 0xba])?;
                    self.emit(&(source_width.minimum as u64).to_le_bytes())?;
                    self.emit(&[0x48, 0x39, 0xd0])?;
                    below_minimum = Some(self.emit_forward_branch(0x8c)?);
                }
                self.emit(&[0x48, 0xba])?;
                self.emit(&source_width.maximum.to_le_bytes())?;
                self.emit(&[0x48, 0x39, 0xd0])?;
                let above_maximum =
                    self.emit_forward_branch(if source_width.signed { 0x8f } else { 0x87 })?;
                self.emit(&[0x41, 0xb8, 1, 0, 0, 0])?;
                if let Some(below_minimum) = below_minimum {
                    self.patch_forward_branch(below_minimum)?;
                }
                self.patch_forward_branch(above_maximum)?;
            }
            self.emit_normalize()?;
            return Ok((source_width, previous_width));
        }
        if let crate::expression::CheckedIntegerOptionOperation::UnsignedMixedArithmetic {
            subtract,
        } = operation
        {
            if source_width.signed {
                return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
            }
            let argument =
                argument.ok_or(self.error(CodegenErrorKind::RuntimeExpressionUnsupported))?;
            self.emit(&[0x50])?;
            self.evaluation_depth += 1;
            self.emit_expression(tree, argument, depth + 1)?;
            self.emit(&[0x59])?;
            self.evaluation_depth -= 1;
            if source_width.bits < 64 {
                if subtract {
                    self.emit(&[0x48, 0x29, 0xc1, 0x48, 0x89, 0xc8])?;
                } else {
                    self.emit(&[0x48, 0x01, 0xc8])?;
                }
                self.emit(&[0x45, 0x31, 0xc0, 0x48, 0xba])?;
                self.emit(&source_width.maximum.to_le_bytes())?;
                self.emit(&[0x48, 0x39, 0xd0])?;
                let invalid = self.emit_forward_branch(0x87)?;
                self.emit(&[0x41, 0xb8, 1, 0, 0, 0])?;
                self.patch_forward_branch(invalid)?;
            } else {
                self.emit(&[0x48, 0x85, 0xc0])?;
                let negative = self.emit_forward_branch(0x88)?;
                if subtract {
                    self.emit(&[
                        0x48, 0x39, 0xc1, 0x41, 0x0f, 0x93, 0xc0, 0x48, 0x29, 0xc1, 0x48, 0x89,
                        0xc8,
                    ])?;
                } else {
                    self.emit(&[0x48, 0x01, 0xc8, 0x41, 0x0f, 0x93, 0xc0])?;
                }
                let end = self.emit_unconditional_forward_branch()?;
                self.patch_forward_branch(negative)?;
                self.emit(&[0x48, 0xf7, 0xd8])?;
                if subtract {
                    self.emit(&[0x48, 0x01, 0xc8, 0x41, 0x0f, 0x93, 0xc0])?;
                } else {
                    self.emit(&[
                        0x48, 0x39, 0xc1, 0x41, 0x0f, 0x93, 0xc0, 0x48, 0x29, 0xc1, 0x48, 0x89,
                        0xc8,
                    ])?;
                }
                self.patch_forward_branch(end)?;
            }
            self.emit_normalize()?;
            return Ok((source_width, previous_width));
        }
        if let crate::expression::CheckedIntegerOptionOperation::SignedMixedArithmetic {
            subtract,
        } = operation
        {
            if !source_width.signed {
                return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
            }
            let argument =
                argument.ok_or(self.error(CodegenErrorKind::RuntimeExpressionUnsupported))?;
            self.emit(&[0x50])?;
            self.evaluation_depth += 1;
            self.emit_expression(tree, argument, depth + 1)?;
            self.emit(&[0x59, 0x45, 0x31, 0xc0])?;
            self.evaluation_depth -= 1;
            if subtract {
                self.emit(&[0x48, 0x89, 0xca, 0x49, 0xba])?;
                self.emit(&(source_width.minimum as u64).to_le_bytes())?;
                self.emit(&[0x4c, 0x29, 0xd2])?;
            } else {
                self.emit(&[0x48, 0xba])?;
                self.emit(&source_width.maximum.to_le_bytes())?;
                self.emit(&[0x48, 0x29, 0xca])?;
            }
            self.emit(&[0x48, 0x39, 0xd0])?;
            let invalid = self.emit_forward_branch(0x87)?;
            if subtract {
                self.emit(&[0x48, 0x29, 0xc1, 0x48, 0x89, 0xc8])?;
            } else {
                self.emit(&[0x48, 0x01, 0xc8])?;
            }
            self.emit(&[0x41, 0xb8, 1, 0, 0, 0])?;
            self.patch_forward_branch(invalid)?;
            self.emit_normalize()?;
            return Ok((source_width, previous_width));
        }
        if operation == crate::expression::CheckedIntegerOptionOperation::SignedDifference {
            if source_width.signed {
                return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
            }
            let argument =
                argument.ok_or(self.error(CodegenErrorKind::RuntimeExpressionUnsupported))?;
            let RuntimeExpressionType::Integer(Some(source)) = base_type else {
                return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
            };
            let target = source
                .signed_counterpart()
                .ok_or(self.error(CodegenErrorKind::RuntimeTypeMismatch))?;
            let result_width = runtime_width(target.name())
                .ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
            self.emit(&[0x50])?;
            self.evaluation_depth += 1;
            self.emit_expression(tree, argument, depth + 1)?;
            self.emit(&[
                0x59, 0x48, 0x39, 0xc1, 0x41, 0x0f, 0x93, 0xc1, 0x48, 0x29, 0xc1, 0x48, 0x89, 0xc8,
            ])?;
            self.evaluation_depth -= 1;
            self.emit_normalize_width(result_width)?;
            self.emit(&[
                0x48, 0x85, 0xc0, 0x41, 0x0f, 0x99, 0xc2, 0x45, 0x38, 0xd1, 0x41, 0x0f, 0x94, 0xc0,
            ])?;
            self.width = result_width;
            return Ok((result_width, previous_width));
        }
        if operation == crate::expression::CheckedIntegerOptionOperation::NextMultiple {
            let divisor =
                argument.ok_or(self.error(CodegenErrorKind::RuntimeExpressionUnsupported))?;
            self.emit(&[0x50])?;
            self.evaluation_depth += 1;
            self.emit_expression(tree, divisor, depth + 1)?;
            self.emit(&[
                0x59, 0x48, 0x87, 0xc1, 0x49, 0x89, 0xc2, 0x45, 0x31, 0xc0, 0x48, 0x85, 0xc9,
            ])?;
            self.evaluation_depth -= 1;
            let zero_divisor = self.emit_forward_branch(0x84)?;
            let negative_one = if source_width.signed {
                self.emit(&[0x48, 0x83, 0xf9, 0xff])?;
                Some(self.emit_forward_branch(0x84)?)
            } else {
                None
            };
            if source_width.signed {
                self.emit(&[
                    0x49, 0x89, 0xc1, 0x49, 0x31, 0xc9, 0x48, 0x99, 0x48, 0xf7, 0xf9,
                ])?;
            } else {
                self.emit(&[0x48, 0x31, 0xd2, 0x48, 0xf7, 0xf1])?;
            }
            self.emit(&[0x48, 0x85, 0xd2])?;
            let exact = self.emit_forward_branch(0x84)?;
            if source_width.signed {
                self.emit(&[0x4d, 0x85, 0xc9])?;
                let same_sign = self.emit_forward_branch(0x89)?;
                self.emit(&[0x48, 0x01, 0xca])?;
                self.patch_forward_branch(same_sign)?;
            }
            self.emit(&[0x48, 0x29, 0xd1, 0x4c, 0x89, 0xd0, 0x48, 0x01, 0xc8])?;
            if source_width.bits == 64 {
                self.emit(if source_width.signed {
                    &[0x41, 0x0f, 0x91, 0xc0]
                } else {
                    &[0x41, 0x0f, 0x93, 0xc0]
                })?;
            } else {
                let mut below_minimum = None;
                if source_width.signed {
                    self.emit(&[0x48, 0xba])?;
                    self.emit(&(source_width.minimum as u64).to_le_bytes())?;
                    self.emit(&[0x48, 0x39, 0xd0])?;
                    below_minimum = Some(self.emit_forward_branch(0x8c)?);
                }
                self.emit(&[0x48, 0xba])?;
                self.emit(&source_width.maximum.to_le_bytes())?;
                self.emit(&[0x48, 0x39, 0xd0])?;
                let above_maximum =
                    self.emit_forward_branch(if source_width.signed { 0x8f } else { 0x87 })?;
                self.emit(&[0x41, 0xb8, 1, 0, 0, 0])?;
                if let Some(below_minimum) = below_minimum {
                    self.patch_forward_branch(below_minimum)?;
                }
                self.patch_forward_branch(above_maximum)?;
            }
            let end = self.emit_unconditional_forward_branch()?;
            self.patch_forward_branch(exact)?;
            if let Some(negative_one) = negative_one {
                self.patch_forward_branch(negative_one)?;
            }
            self.emit(&[0x4c, 0x89, 0xd0, 0x41, 0xb8, 1, 0, 0, 0])?;
            self.patch_forward_branch(end)?;
            self.patch_forward_branch(zero_divisor)?;
            self.emit_normalize()?;
            return Ok((source_width, previous_width));
        }
        if let crate::expression::CheckedIntegerOptionOperation::SignedUnary { absolute } =
            operation
        {
            if argument.is_some() || (absolute && !source_width.signed) {
                return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
            }
            if source_width.signed {
                self.emit(&[0x48, 0xba])?;
                self.emit(&(source_width.minimum as u64).to_le_bytes())?;
                self.emit(&[0x48, 0x39, 0xd0, 0x41, 0x0f, 0x95, 0xc0])?;
            } else {
                self.emit(&[0x48, 0x85, 0xc0, 0x41, 0x0f, 0x94, 0xc0])?;
            }
            if absolute {
                self.emit(&[0x48, 0x85, 0xc0])?;
                let nonnegative = self.emit_forward_branch(0x89)?;
                self.emit(&[0x48, 0xf7, 0xd8])?;
                self.patch_forward_branch(nonnegative)?;
            } else {
                self.emit(&[0x48, 0xf7, 0xd8])?;
            }
            self.emit_normalize()?;
            return Ok((source_width, previous_width));
        }
        if operation == crate::expression::CheckedIntegerOptionOperation::SquareRoot {
            if argument.is_some() || !source_width.signed {
                return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
            }
            self.emit(&[0x45, 0x31, 0xc0, 0x48, 0x85, 0xc0])?;
            let negative = self.emit_forward_branch(0x88)?;
            self.emit_integer_square_root(source_width)?;
            self.emit(&[0x41, 0xb8, 1, 0, 0, 0])?;
            self.patch_forward_branch(negative)?;
            self.emit_normalize()?;
            return Ok((source_width, previous_width));
        }
        if let crate::expression::CheckedIntegerOptionOperation::Shift { left } = operation {
            let argument =
                argument.ok_or(self.error(CodegenErrorKind::RuntimeExpressionUnsupported))?;
            self.emit(&[0x50])?;
            self.evaluation_depth += 1;
            self.emit_expression(tree, argument, depth + 1)?;
            self.emit(&[0x48, 0x83, 0xf8, source_width.bits])?;
            self.emit(&[0x41, 0x0f, 0x92, 0xc0, 0x48, 0x89, 0xc1, 0x58])?;
            self.evaluation_depth -= 1;
            self.emit(if left {
                &[0x48, 0xd3, 0xe0]
            } else if source_width.signed {
                &[0x48, 0xd3, 0xf8]
            } else {
                &[0x48, 0xd3, 0xe8]
            })?;
            self.emit_normalize()?;
            return Ok((source_width, previous_width));
        }
        if operation == crate::expression::CheckedIntegerOptionOperation::Power {
            let exponent =
                argument.ok_or(self.error(CodegenErrorKind::RuntimeExpressionUnsupported))?;
            self.emit(&[0x50])?;
            self.evaluation_depth += 1;
            self.width =
                runtime_width("u32").ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
            self.emit_expression(tree, exponent, depth + 1)?;
            self.width = source_width;
            self.emit(&[
                0x49, 0x89, 0xc1, 0x59, 0xb8, 1, 0, 0, 0, 0x41, 0xb8, 1, 0, 0, 0,
            ])?;
            self.evaluation_depth -= 1;
            let loop_start = self.length;
            self.emit(&[0x4d, 0x85, 0xc9])?;
            let done = self.emit_forward_branch(0x84)?;
            self.emit(&[0x41, 0xf6, 0xc1, 1])?;
            let even = self.emit_forward_branch(0x84)?;
            let mut overflow_patches = [None; 4];
            let mut overflow_count = 0usize;
            let multiply_patches = self.emit_checked_multiply_branches(source_width)?;
            for patch in [multiply_patches.0, multiply_patches.1]
                .into_iter()
                .flatten()
            {
                overflow_patches[overflow_count] = Some(patch);
                overflow_count += 1;
            }
            self.patch_forward_branch(even)?;
            self.emit(&[0x49, 0xd1, 0xe9, 0x4d, 0x85, 0xc9])?;
            let finished = self.emit_forward_branch(0x84)?;
            self.emit(&[0x49, 0x89, 0xc2, 0x48, 0x89, 0xc8])?;
            let square_patches = self.emit_checked_multiply_branches(source_width)?;
            for patch in [square_patches.0, square_patches.1].into_iter().flatten() {
                overflow_patches[overflow_count] = Some(patch);
                overflow_count += 1;
            }
            self.emit(&[0x48, 0x89, 0xc1, 0x4c, 0x89, 0xd0])?;
            self.emit_backward_branch(loop_start)?;
            for patch in overflow_patches[..overflow_count].iter().flatten().copied() {
                self.patch_forward_branch(patch)?;
            }
            self.emit(&[0x45, 0x31, 0xc0])?;
            let end = self.emit_unconditional_forward_branch()?;
            self.patch_forward_branch(done)?;
            self.patch_forward_branch(finished)?;
            self.patch_forward_branch(end)?;
            self.emit_normalize()?;
            return Ok((source_width, previous_width));
        }
        if operation == crate::expression::CheckedIntegerOptionOperation::NextPowerOfTwo {
            if argument.is_some() || source_width.signed {
                return Err(self.error(CodegenErrorKind::RuntimeTypeMismatch));
            }
            self.emit(&[0x45, 0x31, 0xc0, 0x48, 0xba])?;
            let maximum_power = 1u64 << (source_width.bits - 1);
            self.emit(&maximum_power.to_le_bytes())?;
            self.emit(&[0x48, 0x39, 0xd0])?;
            let overflow = self.emit_forward_branch(0x87)?;
            self.emit(&[0x48, 0x83, 0xf8, 1])?;
            let zero_or_one = self.emit_forward_branch(0x86)?;
            self.emit(&[
                0x48, 0xff, 0xc8, 0x48, 0x0f, 0xbd, 0xc8, 0x48, 0xff, 0xc1, 0xb8, 1, 0, 0, 0, 0x48,
                0xd3, 0xe0,
            ])?;
            let valid = self.emit_unconditional_forward_branch()?;
            self.patch_forward_branch(zero_or_one)?;
            self.emit(&[0xb8, 1, 0, 0, 0])?;
            self.patch_forward_branch(valid)?;
            self.emit(&[0x41, 0xb8, 1, 0, 0, 0])?;
            self.patch_forward_branch(overflow)?;
            self.emit_normalize()?;
            return Ok((source_width, previous_width));
        }
        if let crate::expression::CheckedIntegerOptionOperation::Logarithm { binary } = operation {
            if let Some(radix) = argument {
                self.emit(&[0x50])?;
                self.evaluation_depth += 1;
                self.emit_expression(tree, radix, depth + 1)?;
                self.emit(&[0x49, 0x89, 0xc1, 0x58])?;
                self.evaluation_depth -= 1;
            } else {
                self.emit(&[0x49, 0xc7, 0xc1])?;
                self.emit(&(if binary { 2_u32 } else { 10_u32 }).to_le_bytes())?;
            }
            self.emit(&[0x45, 0x31, 0xc0, 0x48, 0x85, 0xc0])?;
            let invalid_base =
                self.emit_forward_branch(if source_width.signed { 0x8e } else { 0x84 })?;
            let invalid_radix = if argument.is_some() {
                self.emit(&[0x49, 0x83, 0xf9, 2])?;
                Some(self.emit_forward_branch(if source_width.signed { 0x8c } else { 0x82 })?)
            } else {
                None
            };
            self.emit(&[0x41, 0xb8, 1, 0, 0, 0, 0x45, 0x31, 0xd2])?;
            let loop_start = self.length;
            self.emit(&[0x4c, 0x39, 0xc8])?;
            let done = self.emit_forward_branch(0x82)?;
            self.emit(&[0x48, 0x31, 0xd2, 0x49, 0xf7, 0xf1, 0x41, 0xff, 0xc2])?;
            self.emit_backward_branch(loop_start)?;
            self.patch_forward_branch(done)?;
            self.emit(&[0x44, 0x89, 0xd0])?;
            self.patch_forward_branch(invalid_base)?;
            if let Some(invalid_radix) = invalid_radix {
                self.patch_forward_branch(invalid_radix)?;
            }
            let result_width =
                runtime_width("u32").ok_or(self.error(CodegenErrorKind::UnsupportedRuntimeType))?;
            self.width = result_width;
            return Ok((result_width, previous_width));
        }
        let exact = operation == crate::expression::CheckedIntegerOptionOperation::ExactDivision;
        let remainder_result = matches!(
            operation,
            crate::expression::CheckedIntegerOptionOperation::Division {
                remainder: true,
                ..
            }
        );
        let euclidean = matches!(
            operation,
            crate::expression::CheckedIntegerOptionOperation::Division {
                euclidean: true,
                ..
            }
        );
        if !exact
            && !matches!(
                operation,
                crate::expression::CheckedIntegerOptionOperation::Division { .. }
            )
        {
            return Err(self.error(CodegenErrorKind::RuntimeExpressionUnsupported));
        }
        let argument =
            argument.ok_or(self.error(CodegenErrorKind::RuntimeExpressionUnsupported))?;
        self.emit(&[0x50])?;
        self.evaluation_depth += 1;
        self.emit_expression(tree, argument, depth + 1)?;
        self.emit(&[0x59, 0x45, 0x31, 0xc0, 0x48, 0x85, 0xc0])?;
        self.evaluation_depth -= 1;
        let zero_divisor = self.emit_forward_branch(0x84)?;
        let mut signed_overflow = None;
        if source_width.signed {
            self.emit(&[0x48, 0x83, 0xf8, 0xff])?;
            let ordinary_divisor = self.emit_forward_branch(0x85)?;
            self.emit(&[0x48, 0xba])?;
            self.emit(&(source_width.minimum as u64).to_le_bytes())?;
            self.emit(&[0x48, 0x39, 0xd1])?;
            signed_overflow = Some(self.emit_forward_branch(0x84)?);
            self.patch_forward_branch(ordinary_divisor)?;
        }
        self.emit(&[0x48, 0x87, 0xc1])?;
        if source_width.signed {
            self.emit(&[0x48, 0x99, 0x48, 0xf7, 0xf9])?;
        } else {
            self.emit(&[0x48, 0x31, 0xd2, 0x48, 0xf7, 0xf1])?;
        }
        if euclidean && source_width.signed {
            self.emit(&[0x48, 0x85, 0xd2])?;
            let nonnegative_remainder = self.emit_forward_branch(0x89)?;
            self.emit(&[0x48, 0x85, 0xc9])?;
            let negative_divisor = self.emit_forward_branch(0x88)?;
            if remainder_result {
                self.emit(&[0x48, 0x01, 0xca])?;
            } else {
                self.emit(&[0x48, 0xff, 0xc8])?;
            }
            let adjusted = self.emit_unconditional_forward_branch()?;
            self.patch_forward_branch(negative_divisor)?;
            if remainder_result {
                self.emit(&[0x48, 0x29, 0xca])?;
            } else {
                self.emit(&[0x48, 0xff, 0xc0])?;
            }
            self.patch_forward_branch(adjusted)?;
            self.patch_forward_branch(nonnegative_remainder)?;
        }
        let inexact = if exact {
            self.emit(&[0x48, 0x85, 0xd2])?;
            Some(self.emit_forward_branch(0x85)?)
        } else {
            None
        };
        if remainder_result {
            self.emit(&[0x48, 0x89, 0xd0])?;
        }
        self.emit(&[0x41, 0xb8, 1, 0, 0, 0])?;
        self.patch_forward_branch(zero_divisor)?;
        if let Some(signed_overflow) = signed_overflow {
            self.patch_forward_branch(signed_overflow)?;
        }
        if let Some(inexact) = inexact {
            self.patch_forward_branch(inexact)?;
        }
        Ok((source_width, previous_width))
    }

    fn emit_binary(&mut self, operator: crate::BinaryOperator) -> Result<(), CodegenError> {
        use crate::BinaryOperator::*;
        match operator {
            Add => {
                self.emit(&[0x48, 0x01, 0xc8])?;
                if self.overflow_checks {
                    if self.width.bits == 64 {
                        self.emit_trap_branch(if self.width.signed { 0x80 } else { 0x82 })
                    } else {
                        self.emit_range_check()
                    }
                } else {
                    self.emit_normalize()
                }
            }
            Subtract => {
                self.emit(&[0x48, 0x29, 0xc1])?;
                if self.overflow_checks && self.width.bits == 64 {
                    self.emit_trap_branch(if self.width.signed { 0x80 } else { 0x82 })?;
                }
                self.emit(&[0x48, 0x89, 0xc8])?;
                if self.overflow_checks && self.width.bits < 64 {
                    self.emit_range_check()
                } else {
                    self.emit_normalize()
                }
            }
            Multiply => {
                self.emit(&[0x48, 0x87, 0xc1])?;
                if self.width.signed {
                    self.emit(&[0x48, 0x0f, 0xaf, 0xc1])?;
                } else {
                    self.emit(&[0x48, 0xf7, 0xe1, 0x48, 0x85, 0xd2])?;
                }
                if self.overflow_checks && self.width.bits == 64 {
                    self.emit_trap_branch(if self.width.signed { 0x80 } else { 0x85 })
                } else if self.overflow_checks {
                    self.emit_range_check()
                } else {
                    self.emit_normalize()
                }
            }
            Divide | Remainder => {
                self.emit(&[0x48, 0x87, 0xc1, 0x48, 0x85, 0xc9])?;
                self.emit_trap_branch(0x84)?;
                if self.width.signed {
                    // Rust traps for MIN / -1 and MIN % -1 in every overflow
                    // mode. Skip the second comparison unless the divisor is -1.
                    self.emit(&[0x48, 0x83, 0xf9, 0xff, 0x75, 19])?;
                    self.emit(&[0x48, 0xba])?;
                    self.emit(&(self.width.minimum as u64).to_le_bytes())?;
                    self.emit(&[0x48, 0x39, 0xd0])?;
                    self.emit_trap_branch(0x84)?;
                    self.emit(&[0x48, 0x99, 0x48, 0xf7, 0xf9])?;
                } else {
                    self.emit(&[0x48, 0x31, 0xd2, 0x48, 0xf7, 0xf1])?;
                }
                if operator == Remainder {
                    self.emit(&[0x48, 0x89, 0xd0])?;
                }
                self.emit_normalize()
            }
            BitAnd => self.emit(&[0x48, 0x21, 0xc8]),
            BitOr => self.emit(&[0x48, 0x09, 0xc8]),
            BitXor => self.emit(&[0x48, 0x31, 0xc8]),
            ShiftLeft | ShiftRight => {
                self.emit(&[0x48, 0x87, 0xc1])?;
                if self.overflow_checks {
                    self.emit(&[0x48, 0x83, 0xf9, self.width.bits])?;
                    self.emit_trap_branch(0x83)?;
                } else {
                    self.emit(&[0x83, 0xe1, self.width.bits - 1])?;
                }
                self.emit(if operator == ShiftLeft {
                    &[0x48, 0xd3, 0xe0]
                } else if self.width.signed {
                    &[0x48, 0xd3, 0xf8]
                } else {
                    &[0x48, 0xd3, 0xe8]
                })?;
                self.emit_normalize()
            }
            Equal | NotEqual | Less | LessEqual | Greater | GreaterEqual => {
                let condition = match (self.width.signed, operator) {
                    (_, Equal) => 0x94,
                    (_, NotEqual) => 0x95,
                    (false, Less) => 0x92,
                    (false, LessEqual) => 0x96,
                    (false, Greater) => 0x97,
                    (false, GreaterEqual) => 0x93,
                    (true, Less) => 0x9c,
                    (true, LessEqual) => 0x9e,
                    (true, Greater) => 0x9f,
                    (true, GreaterEqual) => 0x9d,
                    _ => unreachable!(),
                };
                self.emit(&[0x48, 0x39, 0xc1, 0x0f, condition, 0xc0, 0x0f, 0xb6, 0xc0])
            }
            LogicalAnd | LogicalOr => Err(self.error(CodegenErrorKind::UnsupportedRuntimeOperator)),
        }
    }

    fn emit_strict_mixed_arithmetic(
        &mut self,
        operator: crate::BinaryOperator,
    ) -> Result<(), CodegenError> {
        use crate::BinaryOperator::{Add, Subtract};
        if self.width.signed {
            match operator {
                Add => {
                    self.emit(&[0x48, 0xba])?;
                    self.emit(&self.width.maximum.to_le_bytes())?;
                    self.emit(&[0x48, 0x29, 0xca])?;
                }
                Subtract => {
                    self.emit(&[0x48, 0x89, 0xca, 0x49, 0xb8])?;
                    self.emit(&(self.width.minimum as u64).to_le_bytes())?;
                    self.emit(&[0x4c, 0x29, 0xc2])?;
                }
                _ => return Err(self.error(CodegenErrorKind::UnsupportedRuntimeOperator)),
            }
            self.emit(&[0x48, 0x39, 0xd0])?;
            self.emit_trap_branch(0x87)?;
            match operator {
                Add => self.emit(&[0x48, 0x01, 0xc8])?,
                Subtract => self.emit(&[0x48, 0x29, 0xc1, 0x48, 0x89, 0xc8])?,
                _ => unreachable!(),
            }
            self.emit_normalize()
        } else if self.width.bits < 64 {
            let previous_overflow_checks = self.overflow_checks;
            self.overflow_checks = true;
            let result = self.emit_binary(operator);
            self.overflow_checks = previous_overflow_checks;
            result
        } else {
            self.emit(&[0x48, 0x85, 0xc0, 0x79, 0x11, 0x48, 0xf7, 0xd8])?;
            match operator {
                Add => self.emit(&[0x48, 0x29, 0xc1])?,
                Subtract => self.emit(&[0x48, 0x01, 0xc1])?,
                _ => return Err(self.error(CodegenErrorKind::UnsupportedRuntimeOperator)),
            }
            self.emit_trap_branch(0x82)?;
            self.emit(&[0x48, 0x89, 0xc8, 0xeb, 0x0c])?;
            match operator {
                Add => self.emit(&[0x48, 0x01, 0xc1])?,
                Subtract => self.emit(&[0x48, 0x29, 0xc1])?,
                _ => unreachable!(),
            }
            self.emit_trap_branch(0x82)?;
            self.emit(&[0x48, 0x89, 0xc8])
        }
    }
}

fn parameter_push_encoding(abi: X86_64Abi, index: usize) -> Option<&'static [u8]> {
    const RCX: &[u8] = &[0x51];
    const RDX: &[u8] = &[0x52];
    const RDI: &[u8] = &[0x57];
    const RSI: &[u8] = &[0x56];
    const R8: &[u8] = &[0x41, 0x50];
    const R9: &[u8] = &[0x41, 0x51];
    match (abi, index) {
        (X86_64Abi::Windows, 0) | (X86_64Abi::SystemV, 3) => Some(RCX),
        (X86_64Abi::Windows, 1) | (X86_64Abi::SystemV, 2) => Some(RDX),
        (X86_64Abi::Windows, 2) | (X86_64Abi::SystemV, 4) => Some(R8),
        (X86_64Abi::Windows, 3) | (X86_64Abi::SystemV, 5) => Some(R9),
        (X86_64Abi::SystemV, 0) => Some(RDI),
        (X86_64Abi::SystemV, 1) => Some(RSI),
        _ => None,
    }
}

fn assignment_binary_operator(
    operator: crate::AssignmentOperator,
) -> Option<crate::BinaryOperator> {
    use crate::{AssignmentOperator as Assignment, BinaryOperator as Binary};
    Some(match operator {
        Assignment::Assign => return None,
        Assignment::Add => Binary::Add,
        Assignment::Subtract => Binary::Subtract,
        Assignment::Multiply => Binary::Multiply,
        Assignment::Divide => Binary::Divide,
        Assignment::Remainder => Binary::Remainder,
        Assignment::BitAnd => Binary::BitAnd,
        Assignment::BitOr => Binary::BitOr,
        Assignment::BitXor => Binary::BitXor,
        Assignment::ShiftLeft => Binary::ShiftLeft,
        Assignment::ShiftRight => Binary::ShiftRight,
    })
}

fn translate_span(base: usize, relative: Span) -> Span {
    Span {
        start: base + relative.start,
        end: base + relative.end,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RuntimeWidth {
    bits: u8,
    signed: bool,
    minimum: i64,
    maximum: u64,
}

fn runtime_width(ty: &str) -> Option<RuntimeWidth> {
    Some(match ty {
        "u8" => RuntimeWidth {
            bits: 8,
            signed: false,
            minimum: 0,
            maximum: u64::from(u8::MAX),
        },
        "u16" => RuntimeWidth {
            bits: 16,
            signed: false,
            minimum: 0,
            maximum: u64::from(u16::MAX),
        },
        "u32" | "char" => RuntimeWidth {
            bits: 32,
            signed: false,
            minimum: 0,
            maximum: u64::from(u32::MAX),
        },
        "u64" | "usize" => RuntimeWidth {
            bits: 64,
            signed: false,
            minimum: 0,
            maximum: u64::MAX,
        },
        "i8" => RuntimeWidth {
            bits: 8,
            signed: true,
            minimum: i64::from(i8::MIN),
            maximum: i8::MAX as u64,
        },
        "i16" => RuntimeWidth {
            bits: 16,
            signed: true,
            minimum: i64::from(i16::MIN),
            maximum: i16::MAX as u64,
        },
        "i32" => RuntimeWidth {
            bits: 32,
            signed: true,
            minimum: i64::from(i32::MIN),
            maximum: i32::MAX as u64,
        },
        "i64" | "isize" => RuntimeWidth {
            bits: 64,
            signed: true,
            minimum: i64::MIN,
            maximum: i64::MAX as u64,
        },
        _ => return None,
    })
}
