#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CallArrayElement, Item, NoConstants, Parser, RuntimeCallParameter, RuntimeCallTarget,
        ScalarType, TargetLayout, analyze_constants,
    };

    struct FatCallResolver;

    struct ByteCallResolver;

    struct TupleCallResolver;

    struct MutableReferenceCallResolver;

    impl ConstantResolver for MutableReferenceCallResolver {
        fn resolve(&self, _: &str) -> Option<u128> {
            None
        }

        fn resolve_runtime_call<const MAX_PARAMETERS: usize>(
            &self,
            name: &str,
            argument_count: usize,
        ) -> Option<RuntimeCallTarget<'_, MAX_PARAMETERS>> {
            if MAX_PARAMETERS == 0 {
                return None;
            }
            let reference = ScalarType::Reference {
                target: crate::PointerPointee::Integer(crate::IntegerType::U16),
                mutable: true,
            };
            let shared_reference = ScalarType::Reference {
                target: crate::PointerPointee::Integer(crate::IntegerType::U16),
                mutable: false,
            };
            let array_reference = ScalarType::ArrayReference {
                element: crate::CallArrayElement::Integer(crate::IntegerType::U16),
                count: 2,
                mutable: true,
            };
            let slice_reference = ScalarType::SliceReference {
                element: crate::CallArrayElement::Integer(crate::IntegerType::U16),
                mutable: true,
            };
            let shared_slice_reference = ScalarType::SliceReference {
                element: crate::CallArrayElement::Integer(crate::IntegerType::U16),
                mutable: false,
            };
            let mut parameters = [None; MAX_PARAMETERS];
            match (name, argument_count) {
                ("shared_identity", 1) => {
                    parameters[0] = Some(RuntimeCallParameter {
                        name: "value",
                        ty: shared_reference,
                    });
                    Some(RuntimeCallTarget {
                        name: "shared_identity",
                        parameters,
                        parameter_count: 1,
                        return_type: shared_reference,
                        return_type_name: "&u16",
                        body_expression: "value",
                    })
                }
                ("array_element", 1) => {
                    parameters[0] = Some(RuntimeCallParameter {
                        name: "values",
                        ty: array_reference,
                    });
                    Some(RuntimeCallTarget {
                        name: "array_element",
                        parameters,
                        parameter_count: 1,
                        return_type: reference,
                        return_type_name: "&mut u16",
                        body_expression: "&mut values[0]",
                    })
                }
                ("slice_element", 1) => {
                    parameters[0] = Some(RuntimeCallParameter {
                        name: "values",
                        ty: slice_reference,
                    });
                    Some(RuntimeCallTarget {
                        name: "slice_element",
                        parameters,
                        parameter_count: 1,
                        return_type: reference,
                        return_type_name: "&mut u16",
                        body_expression: "&mut values[0]",
                    })
                }
                ("array_subslice_element", 1) => {
                    parameters[0] = Some(RuntimeCallParameter {
                        name: "values",
                        ty: array_reference,
                    });
                    Some(RuntimeCallTarget {
                        name: "array_subslice_element",
                        parameters,
                        parameter_count: 1,
                        return_type: reference,
                        return_type_name: "&mut u16",
                        body_expression: "&mut values[1..][0]",
                    })
                }
                ("slice_subslice_element", 1) => {
                    parameters[0] = Some(RuntimeCallParameter {
                        name: "values",
                        ty: slice_reference,
                    });
                    Some(RuntimeCallTarget {
                        name: "slice_subslice_element",
                        parameters,
                        parameter_count: 1,
                        return_type: reference,
                        return_type_name: "&mut u16",
                        body_expression: "&mut values[1..][0]",
                    })
                }
                ("slice_repeated_subslice_element", 1) => {
                    parameters[0] = Some(RuntimeCallParameter {
                        name: "values",
                        ty: slice_reference,
                    });
                    Some(RuntimeCallTarget {
                        name: "slice_repeated_subslice_element",
                        parameters,
                        parameter_count: 1,
                        return_type: reference,
                        return_type_name: "&mut u16",
                        body_expression: "&mut values[0..][1..][0]",
                    })
                }
                ("array_repeated_subslice_element", 1) => {
                    parameters[0] = Some(RuntimeCallParameter {
                        name: "values",
                        ty: array_reference,
                    });
                    Some(RuntimeCallTarget {
                        name: "array_repeated_subslice_element",
                        parameters,
                        parameter_count: 1,
                        return_type: reference,
                        return_type_name: "&mut u16",
                        body_expression: "&mut values[0..][1..][0]",
                    })
                }
                ("slice_repeated_subslice_element_alias", 1) => {
                    parameters[0] = Some(RuntimeCallParameter {
                        name: "values",
                        ty: slice_reference,
                    });
                    Some(RuntimeCallTarget {
                        name: "slice_repeated_subslice_element_alias",
                        parameters,
                        parameter_count: 1,
                        return_type: reference,
                        return_type_name: "&mut u16",
                        body_expression: concat!(
                            "let alias: &mut u16 = &mut values[0..][1..][0]; ",
                            "alias"
                        ),
                    })
                }
                ("slice_nested_subslice_element", 1) => {
                    parameters[0] = Some(RuntimeCallParameter {
                        name: "values",
                        ty: slice_reference,
                    });
                    Some(RuntimeCallTarget {
                        name: "slice_nested_subslice_element",
                        parameters,
                        parameter_count: 1,
                        return_type: reference,
                        return_type_name: "&mut u16",
                        body_expression: "&mut values[0..][0..][1..][0]",
                    })
                }
                ("array_subslice", 1) => {
                    parameters[0] = Some(RuntimeCallParameter {
                        name: "values",
                        ty: array_reference,
                    });
                    Some(RuntimeCallTarget {
                        name: "array_subslice",
                        parameters,
                        parameter_count: 1,
                        return_type: slice_reference,
                        return_type_name: "&mut [u16]",
                        body_expression: "&mut values[1..]",
                    })
                }
                ("slice_subslice", 1) => {
                    parameters[0] = Some(RuntimeCallParameter {
                        name: "values",
                        ty: slice_reference,
                    });
                    Some(RuntimeCallTarget {
                        name: "slice_subslice",
                        parameters,
                        parameter_count: 1,
                        return_type: slice_reference,
                        return_type_name: "&mut [u16]",
                        body_expression: "&mut values[1..]",
                    })
                }
                ("array_repeated_subslice", 1) => {
                    parameters[0] = Some(RuntimeCallParameter {
                        name: "values",
                        ty: array_reference,
                    });
                    Some(RuntimeCallTarget {
                        name: "array_repeated_subslice",
                        parameters,
                        parameter_count: 1,
                        return_type: slice_reference,
                        return_type_name: "&mut [u16]",
                        body_expression: "&mut values[0..][1..]",
                    })
                }
                ("slice_repeated_subslice", 1) => {
                    parameters[0] = Some(RuntimeCallParameter {
                        name: "values",
                        ty: slice_reference,
                    });
                    Some(RuntimeCallTarget {
                        name: "slice_repeated_subslice",
                        parameters,
                        parameter_count: 1,
                        return_type: slice_reference,
                        return_type_name: "&mut [u16]",
                        body_expression: "&mut values[0..][1..]",
                    })
                }
                ("slice_repeated_subslice_alias", 1) => {
                    parameters[0] = Some(RuntimeCallParameter {
                        name: "values",
                        ty: slice_reference,
                    });
                    Some(RuntimeCallTarget {
                        name: "slice_repeated_subslice_alias",
                        parameters,
                        parameter_count: 1,
                        return_type: slice_reference,
                        return_type_name: "&mut [u16]",
                        body_expression: concat!(
                            "let alias: &mut [u16] = &mut values[0..][1..]; ",
                            "alias"
                        ),
                    })
                }
                ("slice_repeated_subslice_alias_chain", 1) => {
                    parameters[0] = Some(RuntimeCallParameter {
                        name: "values",
                        ty: slice_reference,
                    });
                    Some(RuntimeCallTarget {
                        name: "slice_repeated_subslice_alias_chain",
                        parameters,
                        parameter_count: 1,
                        return_type: slice_reference,
                        return_type_name: "&mut [u16]",
                        body_expression: concat!(
                            "let first: &mut [u16] = &mut values[0..][1..]; ",
                            "let second: &mut [u16] = first; second"
                        ),
                    })
                }
                ("slice_conditional_repeated_subslice", 2) if MAX_PARAMETERS >= 2 => {
                    parameters[0] = Some(RuntimeCallParameter {
                        name: "values",
                        ty: slice_reference,
                    });
                    parameters[1] = Some(RuntimeCallParameter {
                        name: "first",
                        ty: ScalarType::Bool,
                    });
                    Some(RuntimeCallTarget {
                        name: "slice_conditional_repeated_subslice",
                        parameters,
                        parameter_count: 2,
                        return_type: slice_reference,
                        return_type_name: "&mut [u16]",
                        body_expression: concat!(
                            "if first { &mut values[0..][1..] } ",
                            "else { &mut values[1..][1..] }"
                        ),
                    })
                }
                ("shared_slice_conditional_repeated_subslice", 2)
                    if MAX_PARAMETERS >= 2 =>
                {
                    parameters[0] = Some(RuntimeCallParameter {
                        name: "values",
                        ty: slice_reference,
                    });
                    parameters[1] = Some(RuntimeCallParameter {
                        name: "first",
                        ty: ScalarType::Bool,
                    });
                    Some(RuntimeCallTarget {
                        name: "shared_slice_conditional_repeated_subslice",
                        parameters,
                        parameter_count: 2,
                        return_type: shared_slice_reference,
                        return_type_name: "&[u16]",
                        body_expression: concat!(
                            "if first { &values[0..][1..] } ",
                            "else { &values[1..][1..] }"
                        ),
                    })
                }
                ("slice_explicit_repeated_subslice", 2) if MAX_PARAMETERS >= 2 => {
                    parameters[0] = Some(RuntimeCallParameter {
                        name: "values",
                        ty: slice_reference,
                    });
                    parameters[1] = Some(RuntimeCallParameter {
                        name: "first",
                        ty: ScalarType::Bool,
                    });
                    Some(RuntimeCallTarget {
                        name: "slice_explicit_repeated_subslice",
                        parameters,
                        parameter_count: 2,
                        return_type: slice_reference,
                        return_type_name: "&mut [u16]",
                        body_expression: concat!(
                            "if first { return &mut values[0..][1..]; } ",
                            "&mut values[1..][1..]"
                        ),
                    })
                }
                ("shared_slice_explicit_repeated_subslice", 2) if MAX_PARAMETERS >= 2 => {
                    parameters[0] = Some(RuntimeCallParameter {
                        name: "values",
                        ty: slice_reference,
                    });
                    parameters[1] = Some(RuntimeCallParameter {
                        name: "first",
                        ty: ScalarType::Bool,
                    });
                    Some(RuntimeCallTarget {
                        name: "shared_slice_explicit_repeated_subslice",
                        parameters,
                        parameter_count: 2,
                        return_type: shared_slice_reference,
                        return_type_name: "&[u16]",
                        body_expression: concat!(
                            "if first { return &values[0..][1..]; } ",
                            "&values[1..][1..]"
                        ),
                    })
                }
                ("array_element_alias", 1) => {
                    parameters[0] = Some(RuntimeCallParameter {
                        name: "values",
                        ty: array_reference,
                    });
                    Some(RuntimeCallTarget {
                        name: "array_element_alias",
                        parameters,
                        parameter_count: 1,
                        return_type: reference,
                        return_type_name: "&mut u16",
                        body_expression: "let alias: &mut u16 = &mut values[0]; alias",
                    })
                }
                ("shared_array_element_alias", 1) => {
                    parameters[0] = Some(RuntimeCallParameter {
                        name: "values",
                        ty: array_reference,
                    });
                    Some(RuntimeCallTarget {
                        name: "shared_array_element_alias",
                        parameters,
                        parameter_count: 1,
                        return_type: shared_reference,
                        return_type_name: "&u16",
                        body_expression: "let alias: &mut u16 = &mut values[0]; alias",
                    })
                }
                ("slice_subslice_alias", 1) => {
                    parameters[0] = Some(RuntimeCallParameter {
                        name: "values",
                        ty: slice_reference,
                    });
                    Some(RuntimeCallTarget {
                        name: "slice_subslice_alias",
                        parameters,
                        parameter_count: 1,
                        return_type: slice_reference,
                        return_type_name: "&mut [u16]",
                        body_expression: "let alias: &mut [u16] = &mut values[1..]; alias",
                    })
                }
                ("shared_slice_subslice_alias", 1) => {
                    parameters[0] = Some(RuntimeCallParameter {
                        name: "values",
                        ty: slice_reference,
                    });
                    Some(RuntimeCallTarget {
                        name: "shared_slice_subslice_alias",
                        parameters,
                        parameter_count: 1,
                        return_type: shared_slice_reference,
                        return_type_name: "&[u16]",
                        body_expression: concat!(
                            "let mutable: &mut [u16] = &mut values[1..]; ",
                            "let shared: &[u16] = mutable; shared"
                        ),
                    })
                }
                ("shared_slice_repeated_subslice", 1) => {
                    parameters[0] = Some(RuntimeCallParameter {
                        name: "values",
                        ty: shared_slice_reference,
                    });
                    Some(RuntimeCallTarget {
                        name: "shared_slice_repeated_subslice",
                        parameters,
                        parameter_count: 1,
                        return_type: shared_slice_reference,
                        return_type_name: "&[u16]",
                        body_expression: "&values[0..][1..]",
                    })
                }
                ("shared_slice_repeated_subslice_alias", 1) => {
                    parameters[0] = Some(RuntimeCallParameter {
                        name: "values",
                        ty: slice_reference,
                    });
                    Some(RuntimeCallTarget {
                        name: "shared_slice_repeated_subslice_alias",
                        parameters,
                        parameter_count: 1,
                        return_type: shared_slice_reference,
                        return_type_name: "&[u16]",
                        body_expression: concat!(
                            "let mutable: &mut [u16] = &mut values[0..][1..]; ",
                            "let shared: &[u16] = mutable; shared"
                        ),
                    })
                }
                ("shared_slice_repeated_subslice_alias_chain", 1) => {
                    parameters[0] = Some(RuntimeCallParameter {
                        name: "values",
                        ty: slice_reference,
                    });
                    Some(RuntimeCallTarget {
                        name: "shared_slice_repeated_subslice_alias_chain",
                        parameters,
                        parameter_count: 1,
                        return_type: shared_slice_reference,
                        return_type_name: "&[u16]",
                        body_expression: concat!(
                            "let first: &mut [u16] = &mut values[0..][1..]; ",
                            "let second: &mut [u16] = first; ",
                            "let shared: &[u16] = second; shared"
                        ),
                    })
                }
                ("shared_slice_reassigned_repeated_subslice", 1) => {
                    parameters[0] = Some(RuntimeCallParameter {
                        name: "values",
                        ty: slice_reference,
                    });
                    Some(RuntimeCallTarget {
                        name: "shared_slice_reassigned_repeated_subslice",
                        parameters,
                        parameter_count: 1,
                        return_type: shared_slice_reference,
                        return_type_name: "&[u16]",
                        body_expression: concat!(
                            "let mut selected: &mut [u16] = &mut values[0..][1..]; ",
                            "selected = &mut values[1..][1..]; ",
                            "let shared: &[u16] = selected; shared"
                        ),
                    })
                }
                ("identity", 1) => {
                    parameters[0] = Some(RuntimeCallParameter {
                        name: "value",
                        ty: reference,
                    });
                    Some(RuntimeCallTarget {
                        name: "identity",
                        parameters,
                        parameter_count: 1,
                        return_type: reference,
                        return_type_name: "&mut u16",
                        body_expression: "value",
                    })
                }
                ("forward", 1) => {
                    parameters[0] = Some(RuntimeCallParameter {
                        name: "value",
                        ty: reference,
                    });
                    Some(RuntimeCallTarget {
                        name: "forward",
                        parameters,
                        parameter_count: 1,
                        return_type: reference,
                        return_type_name: "&mut u16",
                        body_expression: "let alias: &mut u16 = value; alias",
                    })
                }
                ("reassign_forward", 1) => {
                    parameters[0] = Some(RuntimeCallParameter {
                        name: "value",
                        ty: reference,
                    });
                    Some(RuntimeCallTarget {
                        name: "reassign_forward",
                        parameters,
                        parameter_count: 1,
                        return_type: reference,
                        return_type_name: "&mut u16",
                        body_expression: concat!(
                            "let mut alias: &mut u16 = value; ",
                            "alias = &mut *alias; alias"
                        ),
                    })
                }
                ("tuple_field_assign", 2) if MAX_PARAMETERS >= 3 => {
                    parameters[0] = Some(RuntimeCallParameter {
                        name: "first",
                        ty: reference,
                    });
                    parameters[1] = Some(RuntimeCallParameter {
                        name: "second",
                        ty: reference,
                    });
                    Some(RuntimeCallTarget {
                        name: "tuple_field_assign",
                        parameters,
                        parameter_count: 2,
                        return_type: reference,
                        return_type_name: "&mut u16",
                        body_expression: concat!(
                            "let mut pair: (&mut u16,) = (first,); ",
                            "pair.0 = second; pair.0"
                        ),
                    })
                }
                ("tuple_field_initialize", 1) if MAX_PARAMETERS >= 2 => {
                    parameters[0] = Some(RuntimeCallParameter {
                        name: "value",
                        ty: reference,
                    });
                    Some(RuntimeCallTarget {
                        name: "tuple_field_initialize",
                        parameters,
                        parameter_count: 1,
                        return_type: reference,
                        return_type_name: "&mut u16",
                        body_expression: "let pair: (&mut u16,) = (value,); pair.0",
                    })
                }
                ("tuple_field_move", 1) if MAX_PARAMETERS >= 4 => {
                    parameters[0] = Some(RuntimeCallParameter {
                        name: "value",
                        ty: reference,
                    });
                    Some(RuntimeCallTarget {
                        name: "tuple_field_move",
                        parameters,
                        parameter_count: 1,
                        return_type: reference,
                        return_type_name: "&mut u16",
                        body_expression: concat!(
                            "let pair: (&mut u16,) = (value,); ",
                            "let alias: &mut u16 = pair.0; ",
                            "let result: &mut u16 = alias; result"
                        ),
                    })
                }
                ("tuple_field_assign_alias", 2) if MAX_PARAMETERS >= 4 => {
                    parameters[0] = Some(RuntimeCallParameter {
                        name: "first",
                        ty: reference,
                    });
                    parameters[1] = Some(RuntimeCallParameter {
                        name: "second",
                        ty: reference,
                    });
                    Some(RuntimeCallTarget {
                        name: "tuple_field_assign_alias",
                        parameters,
                        parameter_count: 2,
                        return_type: reference,
                        return_type_name: "&mut u16",
                        body_expression: concat!(
                            "let pair: (&mut u16,) = (second,); ",
                            "let mut alias: &mut u16 = first; ",
                            "alias = pair.0; alias"
                        ),
                    })
                }
                ("branch_tuple_field_assign_alias", 3) if MAX_PARAMETERS >= 4 => {
                    parameters[0] = Some(RuntimeCallParameter {
                        name: "first",
                        ty: reference,
                    });
                    parameters[1] = Some(RuntimeCallParameter {
                        name: "second",
                        ty: reference,
                    });
                    parameters[2] = Some(RuntimeCallParameter {
                        name: "choose",
                        ty: ScalarType::Bool,
                    });
                    Some(RuntimeCallTarget {
                        name: "branch_tuple_field_assign_alias",
                        parameters,
                        parameter_count: 3,
                        return_type: reference,
                        return_type_name: "&mut u16",
                        body_expression: concat!(
                            "let pair: (&mut u16,) = (second,); ",
                            "let mut alias: &mut u16 = first; ",
                            "if choose { alias = pair.0; } ",
                            "else { alias = pair.0; } alias"
                        ),
                    })
                }
                ("branch_local_tuple_assign_alias", 3) if MAX_PARAMETERS >= 4 => {
                    parameters[0] = Some(RuntimeCallParameter {
                        name: "first",
                        ty: reference,
                    });
                    parameters[1] = Some(RuntimeCallParameter {
                        name: "second",
                        ty: reference,
                    });
                    parameters[2] = Some(RuntimeCallParameter {
                        name: "choose",
                        ty: ScalarType::Bool,
                    });
                    Some(RuntimeCallTarget {
                        name: "branch_local_tuple_assign_alias",
                        parameters,
                        parameter_count: 3,
                        return_type: reference,
                        return_type_name: "&mut u16",
                        body_expression: concat!(
                            "let mut alias: &mut u16 = first; ",
                            "if choose { let pair: (&mut u16,) = (second,); alias = pair.0; } ",
                            "else { let pair: (&mut u16,) = (second,); alias = pair.0; } alias"
                        ),
                    })
                }
                ("loop_tuple_field_assign_alias", 3) if MAX_PARAMETERS >= 4 => {
                    parameters[0] = Some(RuntimeCallParameter {
                        name: "first",
                        ty: reference,
                    });
                    parameters[1] = Some(RuntimeCallParameter {
                        name: "second",
                        ty: reference,
                    });
                    parameters[2] = Some(RuntimeCallParameter {
                        name: "repeat",
                        ty: ScalarType::Bool,
                    });
                    Some(RuntimeCallTarget {
                        name: "loop_tuple_field_assign_alias",
                        parameters,
                        parameter_count: 3,
                        return_type: reference,
                        return_type_name: "&mut u16",
                        body_expression: concat!(
                            "let pair: (&mut u16,) = (second,); ",
                            "let mut alias: &mut u16 = &mut *pair.0; ",
                            "while repeat { alias = &mut *pair.0; } alias"
                        ),
                    })
                }
                ("loop_local_tuple_assign_alias", 2) if MAX_PARAMETERS >= 3 => {
                    parameters[0] = Some(RuntimeCallParameter {
                        name: "value",
                        ty: reference,
                    });
                    parameters[1] = Some(RuntimeCallParameter {
                        name: "repeat",
                        ty: ScalarType::Bool,
                    });
                    Some(RuntimeCallTarget {
                        name: "loop_local_tuple_assign_alias",
                        parameters,
                        parameter_count: 2,
                        return_type: reference,
                        return_type_name: "&mut u16",
                        body_expression: concat!(
                            "let mut alias: &mut u16 = value; ",
                            "while repeat { let pair: (&mut u16,) = (&mut *alias,); ",
                            "alias = pair.0; } alias"
                        ),
                    })
                }
                ("tuple_field_initialize_conditional", 3) if MAX_PARAMETERS >= 4 => {
                    parameters[0] = Some(RuntimeCallParameter {
                        name: "first",
                        ty: reference,
                    });
                    parameters[1] = Some(RuntimeCallParameter {
                        name: "second",
                        ty: reference,
                    });
                    parameters[2] = Some(RuntimeCallParameter {
                        name: "choose",
                        ty: ScalarType::Bool,
                    });
                    Some(RuntimeCallTarget {
                        name: "tuple_field_initialize_conditional",
                        parameters,
                        parameter_count: 3,
                        return_type: reference,
                        return_type_name: "&mut u16",
                        body_expression: concat!(
                            "let pair: (&mut u16, &mut u16) = ",
                            "(first, if choose { second } else { second }); ",
                            "let alias: &mut u16 = pair.1; alias"
                        ),
                    })
                }
                ("branch_tuple_field_assign", 3) if MAX_PARAMETERS >= 4 => {
                    parameters[0] = Some(RuntimeCallParameter {
                        name: "first",
                        ty: reference,
                    });
                    parameters[1] = Some(RuntimeCallParameter {
                        name: "second",
                        ty: reference,
                    });
                    parameters[2] = Some(RuntimeCallParameter {
                        name: "choose",
                        ty: ScalarType::Bool,
                    });
                    Some(RuntimeCallTarget {
                        name: "branch_tuple_field_assign",
                        parameters,
                        parameter_count: 3,
                        return_type: reference,
                        return_type_name: "&mut u16",
                        body_expression: concat!(
                            "let mut pair: (&mut u16,) = (first,); ",
                            "if choose { pair.0 = second; } ",
                            "else { pair.0 = second; } ",
                            "let alias: &mut u16 = pair.0; alias"
                        ),
                    })
                }
                ("loop_tuple_field_assign", 3) if MAX_PARAMETERS >= 4 => {
                    parameters[0] = Some(RuntimeCallParameter {
                        name: "first",
                        ty: reference,
                    });
                    parameters[1] = Some(RuntimeCallParameter {
                        name: "second",
                        ty: reference,
                    });
                    parameters[2] = Some(RuntimeCallParameter {
                        name: "repeat",
                        ty: ScalarType::Bool,
                    });
                    Some(RuntimeCallTarget {
                        name: "loop_tuple_field_assign",
                        parameters,
                        parameter_count: 3,
                        return_type: reference,
                        return_type_name: "&mut u16",
                        body_expression: concat!(
                            "let mut pair: (&mut u16,) = (second,); ",
                            "while repeat { pair.0 = &mut *pair.0; } ",
                            "let alias: &mut u16 = pair.0; alias"
                        ),
                    })
                }
                ("branch_forward", 2) if MAX_PARAMETERS >= 2 => {
                    parameters[0] = Some(RuntimeCallParameter {
                        name: "value",
                        ty: reference,
                    });
                    parameters[1] = Some(RuntimeCallParameter {
                        name: "first",
                        ty: ScalarType::Bool,
                    });
                    Some(RuntimeCallTarget {
                        name: "branch_forward",
                        parameters,
                        parameter_count: 2,
                        return_type: reference,
                        return_type_name: "&mut u16",
                        body_expression: concat!(
                            "let mut alias: &mut u16 = value; ",
                            "if first { alias = &mut *alias; } ",
                            "else { alias = &mut *alias; } alias"
                        ),
                    })
                }
                ("loop_forward", 2) if MAX_PARAMETERS >= 2 => {
                    parameters[0] = Some(RuntimeCallParameter {
                        name: "value",
                        ty: reference,
                    });
                    parameters[1] = Some(RuntimeCallParameter {
                        name: "repeat",
                        ty: ScalarType::Bool,
                    });
                    Some(RuntimeCallTarget {
                        name: "loop_forward",
                        parameters,
                        parameter_count: 2,
                        return_type: reference,
                        return_type_name: "&mut u16",
                        body_expression: concat!(
                            "let mut alias: &mut u16 = value; ",
                            "while repeat { alias = &mut *alias; } alias"
                        ),
                    })
                }
                ("branch_local_forward", 2) if MAX_PARAMETERS >= 2 => {
                    parameters[0] = Some(RuntimeCallParameter {
                        name: "value",
                        ty: reference,
                    });
                    parameters[1] = Some(RuntimeCallParameter {
                        name: "first",
                        ty: ScalarType::Bool,
                    });
                    Some(RuntimeCallTarget {
                        name: "branch_local_forward",
                        parameters,
                        parameter_count: 2,
                        return_type: reference,
                        return_type_name: "&mut u16",
                        body_expression: concat!(
                            "let mut result: &mut u16 = value; ",
                            "if first { let branch: &mut u16 = &mut *result; result = branch; } ",
                            "else { let branch: &mut u16 = &mut *result; result = branch; } result"
                        ),
                    })
                }
                ("branch_local_return", 2) if MAX_PARAMETERS >= 2 => {
                    parameters[0] = Some(RuntimeCallParameter {
                        name: "value",
                        ty: reference,
                    });
                    parameters[1] = Some(RuntimeCallParameter {
                        name: "first",
                        ty: ScalarType::Bool,
                    });
                    Some(RuntimeCallTarget {
                        name: "branch_local_return",
                        parameters,
                        parameter_count: 2,
                        return_type: reference,
                        return_type_name: "&mut u16",
                        body_expression: concat!(
                            "if first { let branch: &mut u16 = &mut *value; return branch; } ",
                            "let tail: &mut u16 = &mut *value; tail"
                        ),
                    })
                }
                ("loop_local_forward", 2) if MAX_PARAMETERS >= 2 => {
                    parameters[0] = Some(RuntimeCallParameter {
                        name: "value",
                        ty: reference,
                    });
                    parameters[1] = Some(RuntimeCallParameter {
                        name: "repeat",
                        ty: ScalarType::Bool,
                    });
                    Some(RuntimeCallTarget {
                        name: "loop_local_forward",
                        parameters,
                        parameter_count: 2,
                        return_type: reference,
                        return_type_name: "&mut u16",
                        body_expression: concat!(
                            "let mut result: &mut u16 = value; while repeat { ",
                            "let iteration: &mut u16 = &mut *result; result = iteration; } result"
                        ),
                    })
                }
                ("loop_branch_local_return", 3) if MAX_PARAMETERS >= 3 => {
                    parameters[0] = Some(RuntimeCallParameter {
                        name: "value",
                        ty: reference,
                    });
                    parameters[1] = Some(RuntimeCallParameter {
                        name: "repeat",
                        ty: ScalarType::Bool,
                    });
                    parameters[2] = Some(RuntimeCallParameter {
                        name: "first",
                        ty: ScalarType::Bool,
                    });
                    Some(RuntimeCallTarget {
                        name: "loop_branch_local_return",
                        parameters,
                        parameter_count: 3,
                        return_type: reference,
                        return_type_name: "&mut u16",
                        body_expression: concat!(
                            "while repeat { if first { let branch: &mut u16 = &mut *value; ",
                            "return branch; } else { return value; } } value"
                        ),
                    })
                }
                ("loop_branch_tuple_assign_return", 3) if MAX_PARAMETERS >= 3 => {
                    parameters[0] = Some(RuntimeCallParameter {
                        name: "value",
                        ty: reference,
                    });
                    parameters[1] = Some(RuntimeCallParameter {
                        name: "repeat",
                        ty: ScalarType::Bool,
                    });
                    parameters[2] = Some(RuntimeCallParameter {
                        name: "first",
                        ty: ScalarType::Bool,
                    });
                    Some(RuntimeCallTarget {
                        name: "loop_branch_tuple_assign_return",
                        parameters,
                        parameter_count: 3,
                        return_type: reference,
                        return_type_name: "&mut u16",
                        body_expression: concat!(
                            "while repeat { if first { let mut alias: &mut u16 = value; ",
                            "let pair: (&mut u16,) = (&mut *alias,); alias = pair.0; return alias; } ",
                            "else { return value; } } value"
                        ),
                    })
                }
                ("loop_branch_fallthrough", 3) if MAX_PARAMETERS >= 4 => {
                    parameters[0] = Some(RuntimeCallParameter {
                        name: "value",
                        ty: reference,
                    });
                    parameters[1] = Some(RuntimeCallParameter {
                        name: "repeat",
                        ty: ScalarType::Bool,
                    });
                    parameters[2] = Some(RuntimeCallParameter {
                        name: "first",
                        ty: ScalarType::Bool,
                    });
                    Some(RuntimeCallTarget {
                        name: "loop_branch_fallthrough",
                        parameters,
                        parameter_count: 3,
                        return_type: reference,
                        return_type_name: "&mut u16",
                        body_expression: concat!(
                            "let mut alias: &mut u16 = value; while repeat { ",
                            "if first { alias = &mut *alias; } ",
                            "else { alias = &mut *alias; } } alias"
                        ),
                    })
                }
                ("touch", 1) => {
                    parameters[0] = Some(RuntimeCallParameter {
                        name: "value",
                        ty: reference,
                    });
                    Some(RuntimeCallTarget {
                        name: "touch",
                        parameters,
                        parameter_count: 1,
                        return_type: ScalarType::Unit,
                        return_type_name: "()",
                        body_expression: "*value += 1",
                    })
                }
                ("read", 1) => {
                    parameters[0] = Some(RuntimeCallParameter {
                        name: "value",
                        ty: shared_reference,
                    });
                    Some(RuntimeCallTarget {
                        name: "read",
                        parameters,
                        parameter_count: 1,
                        return_type: ScalarType::Integer(crate::IntegerType::U16),
                        return_type_name: "u16",
                        body_expression: "*value",
                    })
                }
                ("choose", 2) if MAX_PARAMETERS >= 2 => {
                    parameters[0] = Some(RuntimeCallParameter {
                        name: "value",
                        ty: reference,
                    });
                    parameters[1] = Some(RuntimeCallParameter {
                        name: "first",
                        ty: ScalarType::Bool,
                    });
                    Some(RuntimeCallTarget {
                        name: "choose",
                        parameters,
                        parameter_count: 2,
                        return_type: reference,
                        return_type_name: "&mut u16",
                        body_expression: "if first { return value; } value",
                    })
                }
                ("loop_choose", 2) if MAX_PARAMETERS >= 2 => {
                    parameters[0] = Some(RuntimeCallParameter {
                        name: "value",
                        ty: reference,
                    });
                    parameters[1] = Some(RuntimeCallParameter {
                        name: "first",
                        ty: ScalarType::Bool,
                    });
                    Some(RuntimeCallTarget {
                        name: "loop_choose",
                        parameters,
                        parameter_count: 2,
                        return_type: reference,
                        return_type_name: "&mut u16",
                        body_expression: "while first { return value; } value",
                    })
                }
                ("loop_branch", 2) if MAX_PARAMETERS >= 2 => {
                    parameters[0] = Some(RuntimeCallParameter {
                        name: "value",
                        ty: reference,
                    });
                    parameters[1] = Some(RuntimeCallParameter {
                        name: "first",
                        ty: ScalarType::Bool,
                    });
                    Some(RuntimeCallTarget {
                        name: "loop_branch",
                        parameters,
                        parameter_count: 2,
                        return_type: reference,
                        return_type_name: "&mut u16",
                        body_expression: "loop { if first { return value; } else { return value; } }",
                    })
                }
                ("nested_loop", 2) if MAX_PARAMETERS >= 2 => {
                    parameters[0] = Some(RuntimeCallParameter {
                        name: "value",
                        ty: reference,
                    });
                    parameters[1] = Some(RuntimeCallParameter {
                        name: "first",
                        ty: ScalarType::Bool,
                    });
                    Some(RuntimeCallTarget {
                        name: "nested_loop",
                        parameters,
                        parameter_count: 2,
                        return_type: reference,
                        return_type_name: "&mut u16",
                        body_expression: concat!(
                            "loop { loop { let branch: &mut u16 = &mut *value; ",
                            "if first { return branch; } } }"
                        ),
                    })
                }
                ("nested_loop_tuple_assign", 2) if MAX_PARAMETERS >= 2 => {
                    parameters[0] = Some(RuntimeCallParameter {
                        name: "value",
                        ty: reference,
                    });
                    parameters[1] = Some(RuntimeCallParameter {
                        name: "first",
                        ty: ScalarType::Bool,
                    });
                    Some(RuntimeCallTarget {
                        name: "nested_loop_tuple_assign",
                        parameters,
                        parameter_count: 2,
                        return_type: reference,
                        return_type_name: "&mut u16",
                        body_expression: concat!(
                            "loop { loop { let mut alias: &mut u16 = value; ",
                            "let pair: (&mut u16,) = (&mut *alias,); alias = pair.0; ",
                            "if first { return alias; } } }"
                        ),
                    })
                }
                _ => None,
            }
        }
    }

    impl ConstantResolver for TupleCallResolver {
        fn resolve(&self, _: &str) -> Option<u128> {
            None
        }

        fn resolve_runtime_call<const MAX_PARAMETERS: usize>(
            &self,
            name: &str,
            argument_count: usize,
        ) -> Option<RuntimeCallTarget<'_, MAX_PARAMETERS>> {
            let element = CallArrayElement::Integer(crate::IntegerType::Usize);
            let mut tuple_elements = [None; 4];
            tuple_elements[0] = Some(element);
            tuple_elements[1] = Some(element);
            let tuple = ScalarType::Tuple {
                elements: tuple_elements,
                element_count: 2,
            };
            let mut parameters = [None; MAX_PARAMETERS];
            match (name, argument_count) {
                ("make_tuple", 2) if MAX_PARAMETERS >= 2 => {
                    parameters[0] = Some(RuntimeCallParameter {
                        name: "first",
                        ty: ScalarType::Integer(crate::IntegerType::Usize),
                    });
                    parameters[1] = Some(RuntimeCallParameter {
                        name: "second",
                        ty: ScalarType::Integer(crate::IntegerType::Usize),
                    });
                    Some(RuntimeCallTarget {
                        name: "make_tuple",
                        parameters,
                        parameter_count: 2,
                        return_type: tuple,
                        return_type_name: "(usize, usize)",
                        body_expression: "(first, second)",
                    })
                }
                ("consume_tuple", 2) if MAX_PARAMETERS >= 2 => {
                    parameters[0] = Some(RuntimeCallParameter {
                        name: "pair",
                        ty: tuple,
                    });
                    parameters[1] = Some(RuntimeCallParameter {
                        name: "bias",
                        ty: ScalarType::Integer(crate::IntegerType::Usize),
                    });
                    Some(RuntimeCallTarget {
                        name: "consume_tuple",
                        parameters,
                        parameter_count: 2,
                        return_type: ScalarType::Integer(crate::IntegerType::Usize),
                        return_type_name: "usize",
                        body_expression: "pair.0 + pair.1 + bias",
                    })
                }
                _ => None,
            }
        }
    }

    impl ConstantResolver for ByteCallResolver {
        fn resolve(&self, _: &str) -> Option<u128> {
            None
        }

        fn resolve_runtime_call<const MAX_PARAMETERS: usize>(
            &self,
            name: &str,
            argument_count: usize,
        ) -> Option<RuntimeCallTarget<'_, MAX_PARAMETERS>> {
            if name != "choose_bytes" || argument_count != 2 || MAX_PARAMETERS < 2 {
                return None;
            }
            let element = CallArrayElement::Integer(crate::IntegerType::U8);
            let slice = ScalarType::SliceReference {
                element,
                mutable: false,
            };
            let mut parameters = [None; MAX_PARAMETERS];
            parameters[0] = Some(RuntimeCallParameter {
                name: "values",
                ty: ScalarType::Array { element, count: 8 },
            });
            parameters[1] = Some(RuntimeCallParameter {
                name: "bias",
                ty: ScalarType::Integer(crate::IntegerType::Usize),
            });
            Some(RuntimeCallTarget {
                name: "choose_bytes",
                parameters,
                parameter_count: 2,
                return_type: slice,
                return_type_name: "&[u8]",
                body_expression: "{ if bias == 0 { &values[..] } else { &values[1..] } }",
            })
        }
    }

    impl ConstantResolver for FatCallResolver {
        fn resolve(&self, _: &str) -> Option<u128> {
            None
        }

        fn resolve_runtime_call<const MAX_PARAMETERS: usize>(
            &self,
            name: &str,
            argument_count: usize,
        ) -> Option<RuntimeCallTarget<'_, MAX_PARAMETERS>> {
            if name == "make_array" && argument_count == 3 && MAX_PARAMETERS >= 3 {
                let element = CallArrayElement::Integer(crate::IntegerType::Usize);
                let mut parameters = [None; MAX_PARAMETERS];
                for (index, parameter_name) in ["first", "second", "third"].iter().enumerate() {
                    parameters[index] = Some(RuntimeCallParameter {
                        name: parameter_name,
                        ty: ScalarType::Integer(crate::IntegerType::Usize),
                    });
                }
                return Some(RuntimeCallTarget {
                    name: "make_array",
                    parameters,
                    parameter_count: 3,
                    return_type: ScalarType::Array { element, count: 3 },
                    return_type_name: "[usize; 3]",
                    body_expression: "[first, second, third]",
                });
            }
            let slice = ScalarType::SliceReference {
                element: CallArrayElement::Integer(crate::IntegerType::Usize),
                mutable: false,
            };
            if matches!(
                name,
                "choose_aggregate" | "choose_literal" | "choose_conditional" | "choose_wrapped"
            ) && argument_count == 3
                && MAX_PARAMETERS >= 3
            {
                let element = CallArrayElement::Integer(crate::IntegerType::Usize);
                let mut tuple_elements = [None; 4];
                tuple_elements[0] = Some(element);
                tuple_elements[1] = Some(element);
                let mut parameters = [None; MAX_PARAMETERS];
                parameters[0] = Some(RuntimeCallParameter {
                    name: "values",
                    ty: ScalarType::Array { element, count: 3 },
                });
                parameters[1] = Some(RuntimeCallParameter {
                    name: "pair",
                    ty: ScalarType::Tuple {
                        elements: tuple_elements,
                        element_count: 2,
                    },
                });
                parameters[2] = Some(RuntimeCallParameter {
                    name: "bias",
                    ty: ScalarType::Integer(crate::IntegerType::Usize),
                });
                return Some(RuntimeCallTarget {
                    name: match name {
                        "choose_aggregate" => "choose_aggregate",
                        "choose_literal" => "choose_literal",
                        "choose_conditional" => "choose_conditional",
                        _ => "choose_wrapped",
                    },
                    parameters,
                    parameter_count: 3,
                    return_type: slice,
                    return_type_name: "&[usize]",
                    body_expression: "{ pair.0; if bias == 0 { &values[..] } else { &values[1..] } }",
                });
            }
            if name != "choose" || argument_count != 4 || MAX_PARAMETERS < 4 {
                return None;
            }
            let mut parameters = [None; MAX_PARAMETERS];
            parameters[0] = Some(RuntimeCallParameter {
                name: "values",
                ty: slice,
            });
            for (index, name) in ["start", "end", "bias"].iter().enumerate() {
                parameters[index + 1] = Some(RuntimeCallParameter {
                    name,
                    ty: ScalarType::Integer(crate::IntegerType::Usize),
                });
            }
            Some(RuntimeCallTarget {
                name: "choose",
                parameters,
                parameter_count: 4,
                return_type: slice,
                return_type_name: "&[usize]",
                body_expression: "{ if bias == 0 { &values[start..end] } else { values } }",
            })
        }
    }

    #[test]
    fn emits_validated_fixed_inline_assembly() {
        let compile = |source| {
            let module = Parser::new(source).parse_module::<1, 2>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            compile_x86_64_function::<_, 256, 2, 8>(&function, &NoConstants, X86_64Abi::SystemV)
        };
        let baseline =
            compile("#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer() -> u64 { 42 }")
                .unwrap();
        let delayed = compile(
            "#[unsafe(no_mangle)] pub extern \"C\" fn answer() -> u64 { let value: u64; value = 42; value }",
        )
        .unwrap();
        assert!(delayed.bytes().contains(&0xc3));
        for source in [
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer() -> u64 { asm!(\"nop\"); 42 }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn answer() -> u64 { unsafe { asm!(\"nop\"); } 42 }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer() -> u64 { asm!(\"nop\", clobber_abi(\"C\")); 42 }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer() -> u64 { asm!(\"nop\", options(nomem, nostack, preserves_flags)); 42 }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer() -> u64 { asm!(\"nop\", options(preserves_flags, nomem)); 42 }",
        ] {
            let code = compile(source).unwrap();
            assert_eq!(code.len(), baseline.len() + 1);
            let insertion = (0..code.len())
                .find(|index| {
                    code.bytes()[*index] == 0x90
                        && code.bytes()[..*index] == baseline.bytes()[..*index]
                        && code.bytes()[*index + 1..] == baseline.bytes()[*index..]
                })
                .expect("one inline nop must be inserted into ordinary lowering");
            assert!(insertion < code.len());
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn trap() -> ! { unsafe { asm!(\"int3\", options(noreturn, nostack)); } }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn trap() -> ! { asm!(\"int3\", options(nostack, noreturn)); }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn trap() -> u64 { unsafe { asm!(\"int3\", options(noreturn, nostack)); } }",
        ] {
            let code = compile(source).unwrap();
            assert_eq!(code.bytes().last(), Some(&0xcc), "{source}");
            assert!(!code.bytes().contains(&0xc3), "{source}");
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn halt() -> ! { unsafe { asm!(\"cli\", \"2:\", \"hlt\", \"jmp 2b\", options(noreturn, nomem, nostack)); } }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn halt() -> ! { asm!(\"cli\", \"2:\", \"hlt\", \"jmp 2b\", options(nostack, nomem, noreturn)); }",
        ] {
            let code = compile(source).unwrap();
            assert_eq!(
                code.bytes().get(code.len() - 4..),
                Some(&[0xfa, 0xf4, 0xeb, 0xfd][..])
            );
            assert!(!code.bytes().contains(&0xc3), "{source}");
        }

        for source in [
            concat!(
                "#[unsafe(no_mangle)] pub extern \"C\" fn terminate(operation: u64) -> ! { unsafe { ",
                "asm!(\"int 0x80\", in(\"rax\") operation, in(\"rdi\") 0u64, ",
                "in(\"rsi\") 0u64, in(\"rdx\") 0u64, in(\"r10\") 0u64, ",
                "in(\"r8\") 0u64, in(\"r9\") 0u64, options(noreturn, nostack)); } }"
            ),
            concat!(
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn terminate(operation: u64) -> ! { ",
                "asm!(\"int 0x80\", in(\"rax\") operation, in(\"rdi\") 0u64, ",
                "in(\"rsi\") 0u64, in(\"rdx\") 0u64, in(\"r10\") 0u64, ",
                "in(\"r8\") 0u64, in(\"r9\") 0u64, options(nostack, noreturn)); }"
            ),
        ] {
            let code = compile(source).unwrap();
            assert_eq!(
                code.bytes().get(code.len() - 12..),
                Some(
                    &[
                        0x41, 0x59, 0x41, 0x58, 0x41, 0x5a, 0x5a, 0x5e, 0x5f, 0x58, 0xcd, 0x80,
                    ][..]
                )
            );
            assert!(!code.bytes().contains(&0xc3), "{source}");
        }

        let returning_syscall = compile(concat!(
            "#[unsafe(no_mangle)] pub extern \"C\" fn answer(operation: u64) -> u64 { ",
            "let mut status: u64 = operation; let state: u64; unsafe { ",
            "asm!(\"int 0x80\", inlateout(\"rax\") status, in(\"rdi\") 1u64, ",
            "in(\"rsi\") 2u64, inlateout(\"rdx\") 0u64 => state, ",
            "inlateout(\"r10\") 0u64 => _, inlateout(\"r8\") 0u64 => _, ",
            "inlateout(\"r9\") 0u64 => _, options(nostack)); } status + state }"
        ))
        .unwrap();
        assert!(
            returning_syscall
                .bytes()
                .windows(2)
                .any(|bytes| bytes == [0xcd, 0x80])
        );
        assert!(returning_syscall.bytes().contains(&0xc3));

        for source in [
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer() -> u64 { asm!(\"pause\"); 42 }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn answer() -> u64 { unsafe { asm!(\"pause\"); } 42 }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer() -> u64 { asm!(\"pause\", options(nomem, nostack, preserves_flags)); 42 }",
        ] {
            let code = compile(source).unwrap();
            assert_eq!(code.len(), baseline.len() + 2);
            let insertion = (0..code.len() - 1)
                .find(|index| {
                    code.bytes()[*index..*index + 2] == [0xf3, 0x90]
                        && code.bytes()[..*index] == baseline.bytes()[..*index]
                        && code.bytes()[*index + 2..] == baseline.bytes()[*index..]
                })
                .expect("one inline pause must be inserted into ordinary lowering");
            assert!(insertion < code.len());
        }

        let compare = compile(concat!(
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer(value: u64) -> u64 { ",
            "asm!(\"cmp rax, rax\", in(\"rax\") value, options(nomem, nostack)); value }"
        ))
        .unwrap();
        assert!(
            compare
                .bytes()
                .windows(3)
                .any(|bytes| bytes == [0x48, 0x39, 0xc0])
        );
        let compare_rcx = compile(concat!(
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer(value: u64) -> u64 { ",
            "asm!(\"cmp rcx, rcx\", in(\"rcx\") value, options(nomem, nostack)); value }"
        ))
        .unwrap();
        assert!(
            compare_rcx
                .bytes()
                .windows(6)
                .any(|bytes| bytes == [0x48, 0x89, 0xc1, 0x48, 0x39, 0xc9])
        );
        let compare_rdx = compile(concat!(
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer(value: u64) -> u64 { ",
            "asm!(\"cmp rdx, rdx\", in(\"rdx\") value, options(nomem, nostack)); value }"
        ))
        .unwrap();
        assert!(
            compare_rdx
                .bytes()
                .windows(6)
                .any(|bytes| bytes == [0x48, 0x89, 0xc2, 0x48, 0x39, 0xd2])
        );
        for (source, expected) in [
            (
                concat!(
                    "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer(value: u64) -> u64 { ",
                    "asm!(\"cmp rsi, rsi\", in(\"rsi\") value); value }"
                ),
                [0x48, 0x89, 0xc6, 0x48, 0x39, 0xf6],
            ),
            (
                concat!(
                    "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer(value: u64) -> u64 { ",
                    "asm!(\"cmp r15, r15\", in(\"r15\") value); value }"
                ),
                [0x49, 0x89, 0xc7, 0x4d, 0x39, 0xff],
            ),
        ] {
            let code = compile(source).unwrap();
            assert!(code.bytes().windows(6).any(|bytes| bytes == expected));
        }
        for source in [
            concat!(
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer() -> u64 { ",
                "let mut value: u64 = 0; asm!(\"mov rax, 7\", lateout(\"rax\") value); value }"
            ),
            concat!(
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer() -> u64 { ",
                "let mut value: u64 = 0; asm!(\"mov rax, 7\", lateout(\"rax\") value, ",
                "options(nomem, nostack, preserves_flags)); value }"
            ),
        ] {
            let code = compile(source).unwrap();
            assert!(
                code.bytes()
                    .windows(7)
                    .any(|bytes| bytes == [0x48, 0xc7, 0xc0, 0x07, 0, 0, 0])
            );
        }
        let r15_output = compile(concat!(
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer() -> u64 { ",
            "let mut value: u64 = 0; asm!(\"mov r15, 7\", lateout(\"r15\") value); value }"
        ))
        .unwrap();
        assert!(
            r15_output
                .bytes()
                .windows(10)
                .any(|bytes| bytes == [0x49, 0xc7, 0xc7, 0x07, 0, 0, 0, 0x4c, 0x89, 0xf8])
        );
        for source in [
            concat!(
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer() -> u64 { ",
                "let mut value: u64 = 0; asm!(\"mov rdx, 7\", lateout(\"rdx\") value); value }"
            ),
            concat!(
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer() -> u64 { ",
                "asm!(\"mov rdx, 7\", lateout(\"rdx\") _); 42 }"
            ),
            concat!(
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer() -> u64 { ",
                "let mut values: (u64, u64) = (0, 1); ",
                "asm!(\"mov rdx, 7\", lateout(\"rdx\") values.1); values.1 }"
            ),
        ] {
            let code = compile(source).unwrap();
            assert!(
                code.bytes()
                    .windows(7)
                    .any(|bytes| bytes == [0x48, 0xc7, 0xc2, 0x07, 0, 0, 0])
            );
        }
        let r15_inout = compile(concat!(
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer(input: u64) -> u64 { ",
            "let mut output: u64 = 0; ",
            "asm!(\"inc r15\", inout(\"r15\") input => output); output }"
        ))
        .unwrap();
        assert!(
            r15_inout
                .bytes()
                .windows(9)
                .any(|bytes| bytes == [0x49, 0x89, 0xc7, 0x49, 0xff, 0xc7, 0x4c, 0x89, 0xf8])
        );
        let discarded_output = compile(concat!(
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer() -> u64 { ",
            "asm!(\"mov rax, 7\", lateout(\"rax\") _); 42 }"
        ))
        .unwrap();
        assert!(
            discarded_output
                .bytes()
                .windows(7)
                .any(|bytes| bytes == [0x48, 0xc7, 0xc0, 0x07, 0, 0, 0])
        );
        for source in [
            concat!(
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer() -> u64 { ",
                "let mut value: u64 = 0; asm!(\"mov rcx, 7\", lateout(\"rcx\") value); value }"
            ),
            concat!(
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer() -> u64 { ",
                "asm!(\"mov rcx, 7\", lateout(\"rcx\") _); 42 }"
            ),
        ] {
            let code = compile(source).unwrap();
            assert!(
                code.bytes()
                    .windows(7)
                    .any(|bytes| bytes == [0x48, 0xc7, 0xc1, 0x07, 0, 0, 0])
            );
        }
        for source in [
            concat!(
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer() -> u64 { ",
                "let mut value: u64 = 6; asm!(\"inc rdx\", inout(\"rdx\") value); value }"
            ),
            concat!(
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer(input: u64) -> u64 { ",
                "let mut output: u64 = 0; ",
                "asm!(\"inc rdx\", inout(\"rdx\") input => output); output }"
            ),
            concat!(
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer(input: u64) -> u64 { ",
                "let mut values: (u64, u64) = (0, 1); ",
                "asm!(\"inc rdx\", inout(\"rdx\") input => values.1); values.1 }"
            ),
        ] {
            let code = compile(source).unwrap();
            assert!(
                code.bytes()
                    .windows(9)
                    .any(|bytes| bytes == [0x48, 0x89, 0xc2, 0x48, 0xff, 0xc2, 0x48, 0x89, 0xd0])
            );
        }
        let projected_output = compile(concat!(
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer() -> u64 { ",
            "let mut values: (u64, u64) = (1, 2); ",
            "asm!(\"mov rax, 7\", lateout(\"rax\") values.1); values.1 }"
        ))
        .unwrap();
        assert!(
            projected_output
                .bytes()
                .windows(7)
                .any(|bytes| bytes == [0x48, 0xc7, 0xc0, 0x07, 0, 0, 0])
        );
        let projected_inout = compile(concat!(
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer() -> u64 { ",
            "let mut values: (u64, u64) = (1, 2); ",
            "asm!(\"inc rax\", inout(\"rax\") values.1); values.1 }"
        ))
        .unwrap();
        assert!(
            projected_inout
                .bytes()
                .windows(3)
                .any(|bytes| bytes == [0x48, 0xff, 0xc0])
        );
        for source in [
            concat!(
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer() -> u64 { ",
                "let mut value: u64 = 6; asm!(\"inc rax\", inout(\"rax\") value); value }"
            ),
            concat!(
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer() -> u64 { ",
                "let mut value: u64 = 6; asm!(\"inc rax\", inout(\"rax\") value, ",
                "options(nomem, nostack)); value }"
            ),
        ] {
            let code = compile(source).unwrap();
            assert!(
                code.bytes()
                    .windows(3)
                    .any(|bytes| bytes == [0x48, 0xff, 0xc0])
            );
        }
        let split_inout = compile(concat!(
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer(input: u64) -> u64 { ",
            "let mut output: u64 = 0; asm!(\"inc rax\", inout(\"rax\") input => output, ",
            "options(nomem, nostack)); output }"
        ))
        .unwrap();
        assert!(
            split_inout
                .bytes()
                .windows(3)
                .any(|bytes| bytes == [0x48, 0xff, 0xc0])
        );
        let projected_split_inout = compile(concat!(
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer(input: u64) -> u64 { ",
            "let mut values: (u64, u64) = (0, 1); ",
            "asm!(\"inc rax\", inout(\"rax\") input => values.1); values.1 }"
        ))
        .unwrap();
        assert!(
            projected_split_inout
                .bytes()
                .windows(3)
                .any(|bytes| bytes == [0x48, 0xff, 0xc0])
        );
        for source in [
            concat!(
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer() -> u64 { ",
                "let mut value: u64 = 6; asm!(\"inc rcx\", inout(\"rcx\") value); value }"
            ),
            concat!(
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer(input: u64) -> u64 { ",
                "let mut output: u64 = 0; ",
                "asm!(\"inc rcx\", inout(\"rcx\") input => output); output }"
            ),
            concat!(
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer(input: u64) -> u64 { ",
                "let mut values: (u64, u64) = (0, 1); ",
                "asm!(\"inc rcx\", inout(\"rcx\") input => values.1); values.1 }"
            ),
        ] {
            let code = compile(source).unwrap();
            assert!(
                code.bytes()
                    .windows(9)
                    .any(|bytes| bytes == [0x48, 0x89, 0xc1, 0x48, 0xff, 0xc1, 0x48, 0x89, 0xc8])
            );
        }
        for source in [
            concat!(
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer() -> u64 { ",
                "let mut values: [u64; 2] = [1, 2]; ",
                "asm!(\"mov rax, 7\", lateout(\"rax\") values[1]); values[1] }"
            ),
            concat!(
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer() -> u64 { ",
                "let mut values: [u64; 2] = [1, 2]; ",
                "asm!(\"inc rax\", inout(\"rax\") values[1]); values[1] }"
            ),
            concat!(
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer(input: u64) -> u64 { ",
                "let mut values: [u64; 2] = [1, 2]; ",
                "asm!(\"inc rax\", inout(\"rax\") input => values[1]); values[1] }"
            ),
        ] {
            let code = compile(source).unwrap();
            assert!(
                code.bytes()
                    .windows(3)
                    .any(|bytes| { bytes == [0x48, 0xff, 0xc0] || bytes == [0x48, 0xc7, 0xc0] })
            );
        }
        for source in [
            concat!(
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer(target: &mut u64) { ",
                "asm!(\"mov rax, 7\", lateout(\"rax\") *target); }"
            ),
            concat!(
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer(target: &mut u64) { ",
                "asm!(\"inc rax\", inout(\"rax\") *target); }"
            ),
            concat!(
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer(target: &mut u64) { ",
                "asm!(\"inc rax\", inout(\"rax\") 6u64 => *target); }"
            ),
        ] {
            let code = compile(source).unwrap();
            assert!(
                code.bytes()
                    .windows(3)
                    .any(|bytes| bytes == [0x48, 0x89, 0x08])
            );
        }
        for source in [
            concat!(
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer(index: usize) -> u64 { ",
                "let mut values: [u64; 2] = [1, 2]; ",
                "asm!(\"mov rax, 7\", lateout(\"rax\") values[index % 2]); values[0] }"
            ),
            concat!(
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer(index: usize) -> u64 { ",
                "let mut values: [u64; 2] = [1, 2]; ",
                "asm!(\"inc rax\", inout(\"rax\") values[(index + 1) % 2]); values[0] }"
            ),
            concat!(
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer(index: usize) -> u64 { ",
                "let mut values: [u64; 2] = [1, 2]; ",
                "asm!(\"inc rax\", inout(\"rax\") 6u64 => values[index]); values[0] }"
            ),
        ] {
            let code = compile(source).unwrap_or_else(|error| panic!("{source}: {error:?}"));
            assert!(
                code.bytes()
                    .windows(4)
                    .any(|bytes| bytes == [0x48, 0x83, 0xf8, 0x02])
            );
        }
        for source in [
            concat!(
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer(values: &mut [u64; 2]) -> u64 { ",
                "let index: usize = 1; asm!(\"mov rax, 7\", lateout(\"rax\") values[index % 2]); values[0] }"
            ),
            concat!(
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer(values: &mut [u64; 2]) -> u64 { ",
                "let index: usize = 1; asm!(\"inc rax\", inout(\"rax\") values[index]); values[0] }"
            ),
            concat!(
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer(values: &mut [u64; 2]) -> u64 { ",
                "let index: usize = 1; asm!(\"inc rax\", inout(\"rax\") 6u64 => values[index]); values[0] }"
            ),
            concat!(
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer(values: &mut [u64; 2]) -> u64 { ",
                "let mut target: &mut [u64; 2] = values; ",
                "asm!(\"inc rax\", inout(\"rax\") target[1]); target[0] }"
            ),
        ] {
            let code = compile(source).unwrap_or_else(|error| panic!("{source}: {error:?}"));
            assert!(
                code.bytes()
                    .windows(4)
                    .any(|bytes| bytes == [0x48, 0x83, 0xf8, 0x02])
            );
        }
        for source in [
            concat!(
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer(values: &mut [u64]) -> u64 { ",
                "let index: usize = 1; asm!(\"mov rax, 7\", lateout(\"rax\") values[index % 2]); values[0] }"
            ),
            concat!(
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer(values: &mut [u64]) -> u64 { ",
                "let index: usize = 1; asm!(\"inc rax\", inout(\"rax\") values[index]); values[0] }"
            ),
            concat!(
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer(values: &mut [u64]) -> u64 { ",
                "let index: usize = 1; asm!(\"inc rax\", inout(\"rax\") 6u64 => values[index]); values[0] }"
            ),
            concat!(
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer(values: &mut [u64]) -> u64 { ",
                "let mut target: &mut [u64] = values; ",
                "asm!(\"inc rax\", inout(\"rax\") target[1]); target[0] }"
            ),
        ] {
            let code = compile(source).unwrap_or_else(|error| panic!("{source}: {error:?}"));
            assert!(
                code.bytes()
                    .windows(4)
                    .any(|bytes| bytes == [0x48, 0x39, 0x04, 0x24])
            );
        }
        for source in [
            concat!(
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer() -> u64 { ",
                "let mut value: u64 = 6; asm!(\"inc {value}\", value = inout(reg) value); value }"
            ),
            concat!(
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer(input: u64) -> u64 { ",
                "let mut output: u64 = 0; asm!(\"inc {slot}\", slot = inout(reg) input => output, ",
                "options(nomem, nostack)); output }"
            ),
            concat!(
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer() -> u64 { ",
                "let mut value: u64 = 6; asm!(\"inc {value}\", value = inout(reg) value, ",
                "options(pure, nomem)); value }"
            ),
            concat!(
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer() -> u64 { ",
                "let mut value: u64 = 6; asm!(\"inc {value}\", value = inout(reg) value, ",
                "options(pure, readonly)); value }"
            ),
            concat!(
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer() -> u64 { ",
                "let mut value: u64 = 6; asm!(\"inc {value}\", value = inout(reg) value, ",
                "options(readonly)); value }"
            ),
        ] {
            let code = compile(source).unwrap();
            assert!(
                code.bytes()
                    .windows(3)
                    .any(|bytes| bytes == [0x48, 0xff, 0xc0])
            );
        }
        let two_registers = compile(concat!(
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer(right: u64) -> u64 { ",
            "let mut left: u64 = 6; asm!(\"add {left}, {right}\", ",
            "left = inout(reg) left, right = in(reg) right, options(pure, nomem)); left }"
        ))
        .unwrap();
        assert!(
            two_registers
                .bytes()
                .windows(3)
                .any(|bytes| bytes == [0x48, 0x89, 0xc1])
        );
        assert!(
            two_registers
                .bytes()
                .windows(3)
                .any(|bytes| bytes == [0x48, 0x01, 0xc8])
        );

        for (source, expected) in [
            (
                "#[unsafe(no_mangle)] pub extern \"C\" fn answer() -> u64 { asm!(\"nop\"); 42 }",
                CodegenErrorKind::InlineAssemblyRequiresUnsafe,
            ),
            (
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer() -> u64 { asm!(\"ret\"); 42 }",
                CodegenErrorKind::InvalidInlineAssembly,
            ),
            (
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer() -> u64 { asm!(\"nop\", options(nomem, nomem)); 42 }",
                CodegenErrorKind::InvalidInlineAssembly,
            ),
            (
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer() -> u64 { asm!(\"nop\", options(readonly)); 42 }",
                CodegenErrorKind::InvalidInlineAssembly,
            ),
            (
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer() -> u64 { asm!(\"nop\", clobber_abi(\"MRML\")); 42 }",
                CodegenErrorKind::InvalidInlineAssembly,
            ),
            (
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer() -> u64 { let mut value: u64 = 0; asm!(\"mov {}, 7\", out(reg) value, clobber_abi(\"C\")); value }",
                CodegenErrorKind::InvalidInlineAssembly,
            ),
            (
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer() -> u64 { asm!(\"nop\", in(\"rax\") 1); 42 }",
                CodegenErrorKind::InvalidInlineAssembly,
            ),
            (
                "#[unsafe(no_mangle)] pub extern \"C\" fn answer() -> u64 { asm!(\"pause\"); 42 }",
                CodegenErrorKind::InlineAssemblyRequiresUnsafe,
            ),
            (
                "#[unsafe(no_mangle)] pub extern \"C\" fn answer() -> u64 { unsafe { 42; } asm!(\"pause\"); 42 }",
                CodegenErrorKind::InlineAssemblyRequiresUnsafe,
            ),
            (
                "#[unsafe(no_mangle)] pub extern \"C\" fn trap() -> ! { asm!(\"int3\", options(noreturn, nostack)); }",
                CodegenErrorKind::InlineAssemblyRequiresUnsafe,
            ),
            (
                "#[unsafe(no_mangle)] pub extern \"C\" fn trap() -> u64 { unsafe { asm!(\"int3\", options(noreturn, nostack)); } 42 }",
                CodegenErrorKind::InvalidInlineAssembly,
            ),
            (
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn trap() -> ! { asm!(\"int3\", options(noreturn)); }",
                CodegenErrorKind::InvalidInlineAssembly,
            ),
            (
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn trap() -> ! { asm!(\"int3\"); }",
                CodegenErrorKind::InvalidInlineAssembly,
            ),
            (
                "#[unsafe(no_mangle)] pub extern \"C\" fn halt() -> ! { asm!(\"cli\", \"2:\", \"hlt\", \"jmp 2b\", options(noreturn, nomem, nostack)); }",
                CodegenErrorKind::InlineAssemblyRequiresUnsafe,
            ),
            (
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn halt() -> ! { asm!(\"cli\", \"hlt\", \"jmp 2b\", options(noreturn, nomem, nostack)); }",
                CodegenErrorKind::InvalidInlineAssembly,
            ),
            (
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn halt() -> u64 { asm!(\"cli\", \"2:\", \"hlt\", \"jmp 2b\", options(noreturn, nomem, nostack)); 42 }",
                CodegenErrorKind::InvalidInlineAssembly,
            ),
            (
                "#[unsafe(no_mangle)] pub extern \"C\" fn answer() -> u64 { let value: u64; unsafe { asm!(\"nop\"); } value }",
                CodegenErrorKind::RuntimeUseAfterMove,
            ),
            (
                "#[unsafe(no_mangle)] pub extern \"C\" fn answer() -> u64 { let value: u64; value = 41; value = 42; value }",
                CodegenErrorKind::ImmutableAssignment,
            ),
            (
                concat!(
                    "#[unsafe(no_mangle)] pub extern \"C\" fn terminate(operation: u64) -> ! { ",
                    "asm!(\"int 0x80\", in(\"rax\") operation, in(\"rdi\") 0u64, ",
                    "in(\"rsi\") 0u64, in(\"rdx\") 0u64, in(\"r10\") 0u64, ",
                    "in(\"r8\") 0u64, in(\"r9\") 0u64, options(noreturn, nostack)); }"
                ),
                CodegenErrorKind::InlineAssemblyRequiresUnsafe,
            ),
            (
                concat!(
                    "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn terminate(operation: u64) -> u64 { ",
                    "asm!(\"int 0x80\", in(\"rax\") operation, in(\"rdi\") 0u64, ",
                    "in(\"rsi\") 0u64, in(\"rdx\") 0u64, in(\"r10\") 0u64, ",
                    "in(\"r8\") 0u64, in(\"r9\") 0u64, options(noreturn, nostack)); 42 }"
                ),
                CodegenErrorKind::InvalidInlineAssembly,
            ),
            (
                concat!(
                    "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn terminate(operation: u64) -> ! { ",
                    "asm!(\"int 0x80\", in(\"rdi\") operation, in(\"rax\") 0u64, ",
                    "in(\"rsi\") 0u64, in(\"rdx\") 0u64, in(\"r10\") 0u64, ",
                    "in(\"r8\") 0u64, in(\"r9\") 0u64, options(noreturn, nostack)); }"
                ),
                CodegenErrorKind::InvalidInlineAssembly,
            ),
            (
                concat!(
                    "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer(operation: u64) -> u64 { ",
                    "asm!(\"int 0x80\", in(\"rax\") operation, in(\"rdi\") 0u64, ",
                    "in(\"rsi\") 0u64, in(\"rdx\") 0u64, in(\"r10\") 0u64, ",
                    "in(\"r8\") 0u64, in(\"r9\") 0u64, options(nostack)); operation }"
                ),
                CodegenErrorKind::InvalidInlineAssembly,
            ),
            (
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer() -> u64 { asm!(\"pause\", clobber_abi(\"C\")); 42 }",
                CodegenErrorKind::InvalidInlineAssembly,
            ),
            (
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer() -> u64 { asm!(\"pause\", in(\"rax\") 1); 42 }",
                CodegenErrorKind::InvalidInlineAssembly,
            ),
            (
                "#[unsafe(no_mangle)] pub extern \"C\" fn answer(value: u64) -> u64 { asm!(\"cmp rax, rax\", in(\"rax\") value); value }",
                CodegenErrorKind::InlineAssemblyRequiresUnsafe,
            ),
            (
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer(value: u32) -> u32 { asm!(\"cmp rax, rax\", in(\"rax\") value); value }",
                CodegenErrorKind::RuntimeTypeMismatch,
            ),
            (
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer(value: u64) -> u64 { asm!(\"cmp rax, rax\", in(\"rax\") value, options(preserves_flags)); value }",
                CodegenErrorKind::InvalidInlineAssembly,
            ),
            (
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer(value: u64) -> u64 { asm!(\"cmp rcx, rcx\", in(\"rax\") value); value }",
                CodegenErrorKind::InvalidInlineAssembly,
            ),
            (
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer(value: u64) -> u64 { asm!(\"cmp rdx, rdx\", in(\"rcx\") value); value }",
                CodegenErrorKind::InvalidInlineAssembly,
            ),
            (
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer(value: u64) -> u64 { asm!(\"cmp rbx, rbx\", in(\"rbx\") value); value }",
                CodegenErrorKind::InvalidInlineAssembly,
            ),
            (
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer(value: u64) -> u64 { asm!(\"cmp rsp, rsp\", in(\"rsp\") value); value }",
                CodegenErrorKind::InvalidInlineAssembly,
            ),
            (
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer(value: u64) -> u64 { asm!(\"cmp rbp, rbp\", in(\"rbp\") value); value }",
                CodegenErrorKind::InvalidInlineAssembly,
            ),
            (
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer() -> u64 { let mut value: u64 = 0; asm!(\"mov rdx, 7\", lateout(\"rcx\") value); value }",
                CodegenErrorKind::InvalidInlineAssembly,
            ),
            (
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer() -> u64 { asm!(\"cmp rax, rax\", in(\"rax\")); 42 }",
                CodegenErrorKind::InvalidInlineAssembly,
            ),
            (
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer() -> u64 { let value: u64 = 0; asm!(\"mov rax, 7\", lateout(\"rax\") value); value }",
                CodegenErrorKind::ImmutableAssignment,
            ),
            (
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer() -> u32 { let mut value: u32 = 0; asm!(\"mov rax, 7\", lateout(\"rax\") value); value }",
                CodegenErrorKind::RuntimeTypeMismatch,
            ),
            (
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer(value: u64) -> u64 { asm!(\"mov rax, 7\", lateout(\"rax\") value); value }",
                CodegenErrorKind::ImmutableAssignment,
            ),
            (
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer() -> u64 { asm!(\"mov rax, 7\", lateout(\"rax\") missing); 42 }",
                CodegenErrorKind::UnknownRuntimeName,
            ),
            (
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer() -> u64 { let mut value: u64 = 0; asm!(\"mov rax, 7\", lateout(\"rcx\") value); value }",
                CodegenErrorKind::InvalidInlineAssembly,
            ),
            (
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer() -> u64 { let values: (u64, u64) = (1, 2); asm!(\"mov rax, 7\", lateout(\"rax\") values.1); values.1 }",
                CodegenErrorKind::ImmutableAssignment,
            ),
            (
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer() -> u64 { let mut values: (u64, u64) = (1, 2); asm!(\"mov rax, 7\", lateout(\"rax\") values.2); values.1 }",
                CodegenErrorKind::ValueOutOfRange,
            ),
            (
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer() -> u64 { let mut values: (u64, bool) = (1, false); asm!(\"mov rax, 7\", lateout(\"rax\") values.1); values.0 }",
                CodegenErrorKind::RuntimeTypeMismatch,
            ),
            (
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer() -> u64 { let values: (u64, u64) = (1, 2); asm!(\"inc rax\", inout(\"rax\") values.1); values.1 }",
                CodegenErrorKind::ImmutableAssignment,
            ),
            (
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer() -> u64 { let mut values: (u64, bool) = (1, false); asm!(\"inc rax\", inout(\"rax\") values.1); values.0 }",
                CodegenErrorKind::RuntimeTypeMismatch,
            ),
            (
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer() -> u64 { let value: u64 = 6; asm!(\"inc rax\", inout(\"rax\") value); value }",
                CodegenErrorKind::ImmutableAssignment,
            ),
            (
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer() -> u32 { let mut value: u32 = 6; asm!(\"inc rax\", inout(\"rax\") value); value }",
                CodegenErrorKind::RuntimeTypeMismatch,
            ),
            (
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer() -> u64 { let mut value: u64 = 6; asm!(\"inc rax\", inout(\"rax\") value, options(preserves_flags)); value }",
                CodegenErrorKind::InvalidInlineAssembly,
            ),
            (
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer() -> u64 { let mut value: u64 = 6; asm!(\"inc rax\", inout(\"rcx\") value); value }",
                CodegenErrorKind::InvalidInlineAssembly,
            ),
            (
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer() -> u64 { let mut value: u64 = 6; asm!(\"inc rcx\", inout(\"rax\") value); value }",
                CodegenErrorKind::InvalidInlineAssembly,
            ),
            (
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer() -> u64 { let mut value: u64 = 6; asm!(\"inc rdx\", inout(\"rcx\") value); value }",
                CodegenErrorKind::InvalidInlineAssembly,
            ),
            (
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer(input: u32) -> u64 { let mut output: u64 = 0; asm!(\"inc rax\", inout(\"rax\") input => output); output }",
                CodegenErrorKind::RuntimeTypeMismatch,
            ),
            (
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer(input: u64) -> u64 { let output: u64 = 0; asm!(\"inc rax\", inout(\"rax\") input => output); output }",
                CodegenErrorKind::ImmutableAssignment,
            ),
            (
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer(input: u64) -> u64 { let values: (u64, u64) = (0, 1); asm!(\"inc rax\", inout(\"rax\") input => values.1); values.1 }",
                CodegenErrorKind::ImmutableAssignment,
            ),
            (
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer() -> u64 { let values: [u64; 2] = [1, 2]; asm!(\"mov rax, 7\", lateout(\"rax\") values[1]); values[1] }",
                CodegenErrorKind::ImmutableAssignment,
            ),
            (
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer() -> u64 { let mut values: [u64; 2] = [1, 2]; asm!(\"inc rax\", inout(\"rax\") values[2]); values[1] }",
                CodegenErrorKind::ValueOutOfRange,
            ),
            (
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer() -> bool { let mut values: [bool; 2] = [false, true]; asm!(\"inc rax\", inout(\"rax\") values[1]); values[1] }",
                CodegenErrorKind::RuntimeTypeMismatch,
            ),
            (
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer(values: &[u64; 2]) { asm!(\"inc rax\", inout(\"rax\") values[1]); }",
                CodegenErrorKind::ImmutableAssignment,
            ),
            (
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer(values: &mut [u32; 2]) { asm!(\"inc rax\", inout(\"rax\") values[1]); }",
                CodegenErrorKind::RuntimeTypeMismatch,
            ),
            (
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer(values: &[u64]) { asm!(\"inc rax\", inout(\"rax\") values[1]); }",
                CodegenErrorKind::ImmutableAssignment,
            ),
            (
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer(values: &mut [u32]) { asm!(\"inc rax\", inout(\"rax\") values[1]); }",
                CodegenErrorKind::RuntimeTypeMismatch,
            ),
            (
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer(target: &u64) { asm!(\"mov rax, 7\", lateout(\"rax\") *target); }",
                CodegenErrorKind::RuntimeTypeMismatch,
            ),
            (
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer(target: &mut bool) { asm!(\"inc rax\", inout(\"rax\") *target); }",
                CodegenErrorKind::RuntimeTypeMismatch,
            ),
            (
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer(index: u64) -> u64 { let mut values: [u64; 2] = [1, 2]; asm!(\"inc rax\", inout(\"rax\") values[index]); values[0] }",
                CodegenErrorKind::RuntimeTypeMismatch,
            ),
            (
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer(index: bool) -> u64 { let mut values: [u64; 2] = [1, 2]; asm!(\"inc rax\", inout(\"rax\") values[index]); values[0] }",
                CodegenErrorKind::RuntimeTypeMismatch,
            ),
            (
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer(input: u64) -> u64 { let mut output: u64 = 0; asm!(\"inc rax\", inout(\"rax\") input =>); output }",
                CodegenErrorKind::InvalidInlineAssembly,
            ),
            (
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer(input: u64) -> u64 { let mut output: u64 = 0; asm!(\"inc rax\", inout(\"rax\") input => output => output); output }",
                CodegenErrorKind::InvalidInlineAssembly,
            ),
            (
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer() -> u64 { let mut value: u64 = 6; asm!(\"inc {value}\", other = inout(reg) value); value }",
                CodegenErrorKind::InvalidInlineAssembly,
            ),
            (
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer() -> u64 { let mut value: u64 = 6; asm!(\"inc {value}\", value = inout(reg_byte) value); value }",
                CodegenErrorKind::InvalidInlineAssembly,
            ),
            (
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer() -> u64 { let mut value: u64 = 6; asm!(\"inc {}\", inout(reg) value); value }",
                CodegenErrorKind::InvalidInlineAssembly,
            ),
            (
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer() -> u64 { let mut value: u64 = 6; asm!(\"inc {value} {value}\", value = inout(reg) value); value }",
                CodegenErrorKind::InvalidInlineAssembly,
            ),
            (
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer() -> u64 { let mut value: u64 = 6; asm!(\"inc {value}\", value = inout(reg) value, options(pure)); value }",
                CodegenErrorKind::InvalidInlineAssembly,
            ),
            (
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer(value: u64) -> u64 { asm!(\"cmp rax, rax\", in(\"rax\") value, options(pure, nomem)); value }",
                CodegenErrorKind::InvalidInlineAssembly,
            ),
            (
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer() -> u64 { let mut value: u64 = 6; asm!(\"inc {value}\", value = inout(reg) value, options(pure, nomem, readonly)); value }",
                CodegenErrorKind::InvalidInlineAssembly,
            ),
            (
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer(right: u64) -> u64 { let left: u64 = 6; asm!(\"add {left}, {right}\", left = inout(reg) left, right = in(reg) right); left }",
                CodegenErrorKind::ImmutableAssignment,
            ),
            (
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer(right: u32) -> u64 { let mut left: u64 = 6; asm!(\"add {left}, {right}\", left = inout(reg) left, right = in(reg) right); left }",
                CodegenErrorKind::RuntimeTypeMismatch,
            ),
            (
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer(right: u64) -> u64 { let mut left: u64 = 6; asm!(\"add {left}, {right}\", right = inout(reg) left, left = in(reg) right); left }",
                CodegenErrorKind::InvalidInlineAssembly,
            ),
            (
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer(right: u64) -> u64 { let mut left: u64 = 6; asm!(\"add {left}, {left}\", left = inout(reg) left, right = in(reg) right); left }",
                CodegenErrorKind::InvalidInlineAssembly,
            ),
            (
                "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn answer(right: u64) -> u64 { let mut left: u64 = 6; asm!(\"add {left}, {right}\", left = inout(reg) left, right = in(reg) right, extra = in(reg) right); left }",
                CodegenErrorKind::InvalidInlineAssembly,
            ),
        ] {
            assert_eq!(compile(source).unwrap_err().kind, expected);
        }
    }

    #[test]
    fn emits_restricted_naked_functions_without_a_prologue_or_epilogue() {
        let module = Parser::new(concat!(
            "#[unsafe(naked)] pub unsafe extern \"C\" fn entry() ",
            "{ naked_asm!(\"push -1\", \"push -129\", ",
            "\"mov r10, -0x8000000000000000\", \"mov r11, [r12 + r9 * 4 - 16]\", ",
            "\"mov [rbp + rcx * 2 + 0x1234], r11\", \"lgdt [r13 - 128]\", ",
            "\"swapgs\", \"jmp [rax + r12 * 8]\"); }"
        ))
        .parse_module::<1, 1>()
        .unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        for instruction in [
            "pushq $-1",
            "pushq %r12",
            "movabsq $-0x8000000000000000, %r10",
            "movq -16(%r12,%r9,4), %r11",
            "movq %r11, 0x1234(%rbp,%rcx,2)",
            "lgdt -128(%r13)",
            "swapgs",
            "jmp *(%rax,%r12,8)",
        ] {
            assert!(
                encode_x86_64_naked_att_instruction(instruction).is_some(),
                "unsupported AT&T instruction: {instruction}"
            );
        }
        let code =
            compile_x86_64_function::<_, 48, 1, 8>(&function, &NoConstants, X86_64Abi::SystemV)
                .unwrap();
        assert_eq!(
            code.bytes(),
            &[
                0x6a, 0xff, 0x68, 0x7f, 0xff, 0xff, 0xff, 0x49, 0xba, 0, 0, 0, 0, 0, 0, 0, 0x80,
                0x4f, 0x8b, 0x5c, 0x8c, 0xf0, 0x4c, 0x89, 0x9c, 0x4d, 0x34, 0x12, 0, 0, 0x41, 0x0f,
                0x01, 0x55, 0x80, 0x0f, 0x01, 0xf8, 0x42, 0xff, 0x24, 0xe0,
            ]
        );

        let module = Parser::new(concat!(
            "#[unsafe(naked)] unsafe extern \"C\" fn external() { ",
            "naked_asm!(\"nop\", \"jmp external_target\"); }"
        ))
        .parse_module::<1, 1>()
        .unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let output = compile_x86_64_naked_relocatable::<16, 1>(&function).unwrap();
        assert_eq!(output.code.bytes(), &[0x90, 0xe9, 0, 0, 0, 0]);
        assert_eq!(
            output.relocations(),
            &[X86_64ExternalRelocation {
                offset: 2,
                symbol: "external_target",
                kind: X86_64ExternalRelocationKind::Branch,
            }]
        );
        assert_eq!(
            compile_x86_64_function::<_, 16, 1, 8>(&function, &NoConstants, X86_64Abi::SystemV,)
                .unwrap_err()
                .kind,
            CodegenErrorKind::InvalidNakedAssembly
        );

        for source in [
            concat!(
                "#[unsafe(naked)] unsafe extern \"C\" fn external_memory() { ",
                "naked_asm!(\"mov r10, [rip + external_data]\", \"ret\"); }"
            ),
            concat!(
                "#[unsafe(naked)] unsafe extern \"C\" fn external_memory() { ",
                "naked_asm!(\"movq external_data(%rip), %r10\", \"ret\", ",
                "options(att_syntax)); }"
            ),
        ] {
            let module = Parser::new(source).parse_module::<1, 1>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            let output = compile_x86_64_naked_relocatable::<16, 1>(&function).unwrap();
            assert_eq!(output.code.bytes(), &[0x4c, 0x8b, 0x15, 0, 0, 0, 0, 0xc3]);
            assert_eq!(
                output.relocations(),
                &[X86_64ExternalRelocation {
                    offset: 3,
                    symbol: "external_data",
                    kind: X86_64ExternalRelocationKind::RipRelativeMemory,
                }]
            );
        }

        for (instruction, expected) in [
            ("mov [rip + data], r11", &[0x4c, 0x89, 0x1d][..]),
            ("jmp [rip + target]", &[0xff, 0x25][..]),
            ("lgdt [rip + table]", &[0x0f, 0x01, 0x15][..]),
            ("movq %r11, data(%rip)", &[0x4c, 0x89, 0x1d][..]),
            ("jmp *target(%rip)", &[0xff, 0x25][..]),
            ("lgdt table(%rip)", &[0x0f, 0x01, 0x15][..]),
        ] {
            let external =
                x86_64_naked_external_memory_instruction(instruction, instruction.contains('%'))
                    .unwrap();
            assert_eq!(&external.encoding[..external.relocation_offset], expected);
            assert_eq!(external.length, external.relocation_offset + 4);
        }

        let module = Parser::new(concat!(
            "#[unsafe(naked)] unsafe extern \"C\" fn multiple() { naked_asm!(",
            "\"mov rax, [rip + first]\", \"mov [rip + second], r10\", ",
            "\"jmp third\"); }"
        ))
        .parse_module::<1, 1>()
        .unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let output = compile_x86_64_naked_relocatable::<32, 1>(&function).unwrap();
        assert_eq!(
            output.relocations(),
            &[
                X86_64ExternalRelocation {
                    offset: 3,
                    symbol: "first",
                    kind: X86_64ExternalRelocationKind::RipRelativeMemory,
                },
                X86_64ExternalRelocation {
                    offset: 10,
                    symbol: "second",
                    kind: X86_64ExternalRelocationKind::RipRelativeMemory,
                },
                X86_64ExternalRelocation {
                    offset: 15,
                    symbol: "third",
                    kind: X86_64ExternalRelocationKind::Branch,
                },
            ]
        );

        let module = Parser::new(concat!(
            "#[unsafe(naked)] unsafe extern \"C\" fn labels() { ",
            "naked_asm!(\"2:\", \"nop\", \"jmp 3f\", \"int3\", \"3:\", \"jmp 2b\", ",
            "options(raw)); }"
        ))
        .parse_module::<1, 1>()
        .unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let code =
            compile_x86_64_function::<_, 16, 1, 8>(&function, &NoConstants, X86_64Abi::SystemV)
                .unwrap();
        assert_eq!(
            code.bytes(),
            &[0x90, 0xe9, 1, 0, 0, 0, 0xcc, 0xe9, 0xf4, 0xff, 0xff, 0xff]
        );

        let module = Parser::new(concat!(
            "#[unsafe(naked)] unsafe extern \"C\" fn att() { naked_asm!(",
            "\"pushq $-1\", \"pushq %r12\", \"movabsq $-0x8000000000000000, %r10\", ",
            "\"movq -16(%r12,%r9,4), %r11\", \"movq %r11, 0x1234(%rbp,%rcx,2)\", ",
            "\"lgdt -128(%r13)\", \"swapgs\", \"jmp *(%rax,%r12,8)\", ",
            "options(raw, att_syntax)); }"
        ))
        .parse_module::<1, 1>()
        .unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let code =
            compile_x86_64_function::<_, 48, 1, 8>(&function, &NoConstants, X86_64Abi::SystemV)
                .unwrap();
        assert_eq!(
            code.bytes(),
            &[
                0x6a, 0xff, 0x41, 0x54, 0x49, 0xba, 0, 0, 0, 0, 0, 0, 0, 0x80, 0x4f, 0x8b, 0x5c,
                0x8c, 0xf0, 0x4c, 0x89, 0x9c, 0x4d, 0x34, 0x12, 0, 0, 0x41, 0x0f, 0x01, 0x55, 0x80,
                0x0f, 0x01, 0xf8, 0x42, 0xff, 0x24, 0xe0,
            ]
        );

        for source in [
            concat!(
                "#[unsafe(naked)] unsafe extern \"C\" fn absolute() { naked_asm!(",
                "\"mov r10, [0x12345678]\", \"mov [r9 * 4 - 16], r11\", ",
                "\"jmp [0x1234]\"); }"
            ),
            concat!(
                "#[unsafe(naked)] unsafe extern \"C\" fn absolute() { naked_asm!(",
                "\"movq 0x12345678, %r10\", \"movq %r11, -16(,%r9,4)\", ",
                "\"jmp *0x1234\", options(att_syntax)); }"
            ),
        ] {
            let module = Parser::new(source).parse_module::<1, 1>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            let code =
                compile_x86_64_function::<_, 24, 1, 8>(&function, &NoConstants, X86_64Abi::SystemV)
                    .unwrap();
            assert_eq!(
                code.bytes(),
                &[
                    0x4c, 0x8b, 0x14, 0x25, 0x78, 0x56, 0x34, 0x12, 0x4e, 0x89, 0x1c, 0x8d, 0xf0,
                    0xff, 0xff, 0xff, 0xff, 0x24, 0x25, 0x34, 0x12, 0, 0,
                ]
            );
        }

        for (source, expected) in [
            (
                "#[unsafe(naked)] extern \"C\" fn f() { naked_asm!(\"ret\"); }",
                CodegenErrorKind::NakedFunctionMustBeUnsafe,
            ),
            (
                "#[unsafe(naked)] unsafe fn f() { naked_asm!(\"ret\"); }",
                CodegenErrorKind::NakedFunctionRequiresCAbi,
            ),
            (
                "#[unsafe(naked)] unsafe extern \"C\" fn f(x: u64) { naked_asm!(\"ret\"); }",
                CodegenErrorKind::NakedFunctionParametersUnsupported,
            ),
            (
                "#[unsafe(naked)] unsafe extern \"C\" fn f() -> u64 { naked_asm!(\"ret\"); }",
                CodegenErrorKind::NakedFunctionReturnUnsupported,
            ),
            (
                "#[unsafe(naked)] unsafe extern \"C\" fn f() { naked_asm!(\"add rax, rbx\", \"ret\"); }",
                CodegenErrorKind::InvalidNakedAssembly,
            ),
            (
                "#[unsafe(naked)] unsafe extern \"C\" fn f() { naked_asm!(\"push eax\", \"ret\"); }",
                CodegenErrorKind::InvalidNakedAssembly,
            ),
            (
                "#[unsafe(naked)] unsafe extern \"C\" fn f() { naked_asm!(\"push 0x80000000\", \"ret\"); }",
                CodegenErrorKind::InvalidNakedAssembly,
            ),
            (
                "#[unsafe(naked)] unsafe extern \"C\" fn f() { naked_asm!(\"push -0x80000001\", \"ret\"); }",
                CodegenErrorKind::InvalidNakedAssembly,
            ),
            (
                "#[unsafe(naked)] unsafe extern \"C\" fn f() { naked_asm!(\"mov rax, -0x8000000000000001\", \"ret\"); }",
                CodegenErrorKind::InvalidNakedAssembly,
            ),
            (
                "#[unsafe(naked)] unsafe extern \"C\" fn f() { naked_asm!(\"mov rax, 1__0\", \"ret\"); }",
                CodegenErrorKind::InvalidNakedAssembly,
            ),
            (
                "#[unsafe(naked)] unsafe extern \"C\" fn f() { naked_asm!(\"mov rax, [rip]\", \"ret\"); }",
                CodegenErrorKind::InvalidNakedAssembly,
            ),
            (
                "#[unsafe(naked)] unsafe extern \"C\" fn f() { naked_asm!(\"mov rax, [rip + bad.symbol]\", \"ret\"); }",
                CodegenErrorKind::InvalidNakedAssembly,
            ),
            (
                "#[unsafe(naked)] unsafe extern \"C\" fn f() { naked_asm!(\"mov [rax + rsp * 2], rbx\", \"ret\"); }",
                CodegenErrorKind::InvalidNakedAssembly,
            ),
            (
                "#[unsafe(naked)] unsafe extern \"C\" fn f() { naked_asm!(\"mov [rax + rcx * 3], rbx\", \"ret\"); }",
                CodegenErrorKind::InvalidNakedAssembly,
            ),
            (
                "#[unsafe(naked)] unsafe extern \"C\" fn f() { naked_asm!(\"mov [rax + 0x80000000], rbx\", \"ret\"); }",
                CodegenErrorKind::InvalidNakedAssembly,
            ),
            (
                "#[unsafe(naked)] unsafe extern \"C\" fn f() { naked_asm!(\"mov rax, [0x80000000]\", \"ret\"); }",
                CodegenErrorKind::InvalidNakedAssembly,
            ),
            (
                "#[unsafe(naked)] unsafe extern \"C\" fn f() { naked_asm!(\"mov [rsp * 2], rbx\", \"ret\"); }",
                CodegenErrorKind::InvalidNakedAssembly,
            ),
            (
                "#[unsafe(naked)] unsafe extern \"C\" fn f() { naked_asm!(\"2:\", \"2:\", \"ret\"); }",
                CodegenErrorKind::InvalidNakedAssembly,
            ),
            (
                "#[unsafe(naked)] unsafe extern \"C\" fn f() { naked_asm!(\"jmp 2f\"); }",
                CodegenErrorKind::InvalidNakedAssembly,
            ),
            (
                "#[unsafe(naked)] unsafe extern \"C\" fn f() { naked_asm!(\"2:\", \"jmp 2f\"); }",
                CodegenErrorKind::InvalidNakedAssembly,
            ),
            (
                "#[unsafe(naked)] unsafe extern \"C\" fn f() { naked_asm!(\"jmp 2b\", \"2:\"); }",
                CodegenErrorKind::InvalidNakedAssembly,
            ),
            (
                "#[unsafe(naked)] unsafe extern \"C\" fn f() { naked_asm!(\"jmp first\", \"jmp second\"); }",
                CodegenErrorKind::InvalidNakedAssembly,
            ),
            (
                "#[unsafe(naked)] unsafe extern \"C\" fn f() { naked_asm!(\"jmp external.target\"); }",
                CodegenErrorKind::InvalidNakedAssembly,
            ),
            (
                "#[unsafe(naked)] unsafe extern \"C\" fn f() { naked_asm!(\"mov rax, rbx\", \"ret\", options(att_syntax)); }",
                CodegenErrorKind::InvalidNakedAssembly,
            ),
            (
                "#[unsafe(naked)] unsafe extern \"C\" fn f() { naked_asm!(\"movq (%rax,%rsp,2), %rbx\", \"ret\", options(att_syntax)); }",
                CodegenErrorKind::InvalidNakedAssembly,
            ),
            (
                "#[unsafe(naked)] unsafe extern \"C\" fn f() { naked_asm!(\"movq 0x80000000, %rax\", \"ret\", options(att_syntax)); }",
                CodegenErrorKind::InvalidNakedAssembly,
            ),
            (
                "#[unsafe(naked)] unsafe extern \"C\" fn f() { naked_asm!(\"movq %rbx, (,%rsp,2)\", \"ret\", options(att_syntax)); }",
                CodegenErrorKind::InvalidNakedAssembly,
            ),
            (
                "#[unsafe(naked)] unsafe extern \"C\" fn f() { naked_asm!(options(raw)); }",
                CodegenErrorKind::InvalidNakedAssembly,
            ),
            (
                "#[unsafe(naked)] unsafe extern \"C\" fn f() { naked_asm!(\"nop\"); }",
                CodegenErrorKind::InvalidNakedAssembly,
            ),
        ] {
            let module = Parser::new(source).parse_module::<1, 1>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert_eq!(
                compile_x86_64_function::<_, 16, 1, 8>(
                    &function,
                    &NoConstants,
                    X86_64Abi::SystemV,
                )
                .unwrap_err()
                .kind,
                expected
            );
        }
    }

    #[test]
    fn runtime_place_ids_survive_shadowing_and_scope_cleanup() {
        let module = Parser::new("fn value(parameter: u64) -> u64 { parameter }")
            .parse_module::<1, 4>()
            .unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let resolver = NoConstants;
        let mut body_facts = RuntimeBodyFacts::EMPTY;
        body_facts
            .push_initialized_parameter(
                0,
                RuntimeExpressionType::Integer(Some(crate::IntegerType::U64)),
                Some(function.parameters()[0].unwrap().span),
            )
            .unwrap();
        body_facts.current_ownership_event_location =
            RuntimeOwnershipEventLocation::EmissionExpansion;
        let mut emitter = RuntimeEmitter::<_, 64, 4> {
            bytes: [0; 64],
            length: 0,
            readonly_data: [0; MAX_X86_64_READONLY_DATA_BYTES],
            readonly_data_length: 0,
            readonly_relocations: [X86_64ReadonlyDataRelocation {
                offset: 0,
                data_offset: 0,
            }; MAX_X86_64_READONLY_RELOCATIONS],
            readonly_relocation_count: 0,
            trap_patches: [0; 64],
            trap_count: 0,
            function: &function,
            resolver: &resolver,
            abi: X86_64Abi::Windows,
            width: runtime_width("u64").unwrap(),
            overflow_checks: true,
            uses_sret: false,
            saved_parameter_slots: 0,
            locals: [None; 4],
            saved_locals: 0,
            body_facts: &mut body_facts,
            preanalyzed_local_count: 0,
            preanalyzed_local_cursor: 0,
            preanalyzed_assignment_access_cursor: 0,
            preanalyzed_assignment_read_cursor: 0,
            evaluation_depth: 0,
            runtime_call_depth: 0,
            runtime_call_names: [None; 8],
            runtime_call_local_floor: None,
        };
        emitter
            .push_runtime_local(
                "value",
                RuntimeExpressionType::Integer(Some(crate::IntegerType::U64)),
                true,
                true,
                1,
                None,
            )
            .unwrap();
        emitter
            .push_runtime_local(
                "value",
                RuntimeExpressionType::Integer(Some(crate::IntegerType::U64)),
                true,
                true,
                1,
                None,
            )
            .unwrap();
        let assignment = crate::Assignment {
            name: "value",
            name_span: Span { start: 0, end: 5 },
            projection: None,
            operator: crate::AssignmentOperator::Assign,
            value: "1",
            value_span: Span { start: 8, end: 9 },
        };
        let first_place = emitter.resolve_assignment_place(&assignment).unwrap();
        emitter
            .body_facts
            .push_assignment_access(RuntimePlaceAccessFact {
                base: RuntimePlaceIdentity::Local(RuntimeLocalId(1)),
                projections: RuntimePlaceProjections::EMPTY,
                ty: first_place.ty,
                access: first_place.access,
                span: assignment.name_span,
            })
            .unwrap();
        emitter
            .record_place_access::<16>(first_place, &assignment)
            .unwrap();
        assert_eq!(emitter.preanalyzed_assignment_access_cursor, 1);
        emitter
            .body_facts
            .push_assignment_read(
                RuntimePlaceAccessFact {
                    base: RuntimePlaceIdentity::Local(RuntimeLocalId(1)),
                    projections: RuntimePlaceProjections::EMPTY,
                    ty: first_place.ty,
                    access: RuntimePlaceAccess::Read,
                    span: Span { start: 10, end: 15 },
                },
                RuntimeReadEffectContext::Value,
            )
            .unwrap();
        emitter
            .record_identifier_read(
                "value",
                RuntimePlaceProjections::EMPTY,
                Span { start: 10, end: 15 },
            )
            .unwrap();
        assert_eq!(emitter.preanalyzed_assignment_read_cursor, 1);
        assert_eq!(first_place.access, RuntimePlaceAccess::Write);
        assert_eq!(
            first_place.base,
            RuntimePlaceBase::Local {
                id: RuntimeLocalId(1),
                index: 1,
            }
        );
        emitter.truncate_scoped_locals(1).unwrap();
        emitter
            .push_runtime_local(
                "value",
                RuntimeExpressionType::Integer(Some(crate::IntegerType::U64)),
                true,
                true,
                1,
                None,
            )
            .unwrap();
        let compound = crate::Assignment {
            operator: crate::AssignmentOperator::Add,
            ..assignment
        };
        let compound_place = emitter.resolve_assignment_place(&compound).unwrap();
        emitter
            .record_place_access::<16>(compound_place, &compound)
            .unwrap();
        assert_eq!(compound_place.access, RuntimePlaceAccess::ReadModifyWrite);
        let final_place = emitter.resolve_assignment_place(&assignment).unwrap();
        emitter
            .record_identifier_read(
                "value",
                RuntimePlaceProjections::EMPTY,
                Span { start: 20, end: 25 },
            )
            .unwrap();
        emitter
            .record_identifier_read(
                "parameter",
                RuntimePlaceProjections::EMPTY,
                Span { start: 28, end: 37 },
            )
            .unwrap();
        assert_eq!(
            final_place.base,
            RuntimePlaceBase::Local {
                id: RuntimeLocalId(2),
                index: 1,
            }
        );
        assert_eq!(emitter.body_facts.local_count, 3);
        assert_eq!(emitter.body_facts.locals[0].unwrap().id, RuntimeLocalId(0));
        assert_eq!(emitter.body_facts.locals[1].unwrap().id, RuntimeLocalId(1));
        assert_eq!(emitter.body_facts.locals[2].unwrap().id, RuntimeLocalId(2));
        assert_eq!(emitter.body_facts.access_count, 5);
        assert_eq!(
            emitter.body_facts.accesses[0].unwrap().base,
            RuntimePlaceIdentity::Local(RuntimeLocalId(1))
        );
        assert_eq!(
            emitter.body_facts.accesses[1].unwrap().base,
            RuntimePlaceIdentity::Local(RuntimeLocalId(1))
        );
        assert_eq!(
            emitter.body_facts.accesses[1].unwrap().access,
            RuntimePlaceAccess::Read
        );
        assert_eq!(
            emitter.body_facts.accesses[2].unwrap().base,
            RuntimePlaceIdentity::Local(RuntimeLocalId(2))
        );
        assert_eq!(
            emitter.body_facts.accesses[3].unwrap().base,
            RuntimePlaceIdentity::Local(RuntimeLocalId(2))
        );
        assert_eq!(
            emitter.body_facts.accesses[4].unwrap().base,
            RuntimePlaceIdentity::Parameter(0)
        );
        let tuple_type = RuntimeExpressionType::Tuple {
            elements: [
                Some(RuntimeTupleElementType::Scalar(
                    RuntimeArrayElementType::Integer(Some(crate::IntegerType::U64)),
                )),
                Some(RuntimeTupleElementType::Scalar(
                    RuntimeArrayElementType::Bool,
                )),
                None,
                None,
            ],
            element_count: 2,
        };
        assert!(runtime_place_projections_valid(
            tuple_type,
            RuntimePlaceProjections::single(RuntimePlaceProjection::TupleField(1))
        ));
        assert!(!runtime_place_projections_valid(
            tuple_type,
            RuntimePlaceProjections::single(RuntimePlaceProjection::TupleField(2))
        ));
        let array_type = RuntimeExpressionType::Array {
            element: RuntimeArrayElementType::Integer(Some(crate::IntegerType::U64)),
            count: 2,
        };
        assert!(runtime_place_projections_valid(
            array_type,
            RuntimePlaceProjections::single(RuntimePlaceProjection::Index)
        ));
        let mut malformed = RuntimePlaceProjections::EMPTY;
        malformed.items[1] = Some(RuntimePlaceProjection::Index);
        assert!(!runtime_place_projections_valid(array_type, malformed));
        let mut bounded = RuntimePlaceProjections::EMPTY;
        for _ in 0..MAX_RUNTIME_PLACE_PROJECTIONS {
            bounded.push(RuntimePlaceProjection::Dereference).unwrap();
        }
        assert_eq!(
            bounded
                .push(RuntimePlaceProjection::Dereference)
                .unwrap_err(),
            CodegenErrorKind::TooManyRuntimePlaceProjections
        );
        emitter.validate_runtime_place_facts().unwrap();

        let valid_assignment_fact = emitter.body_facts.assignment_accesses[0].unwrap();
        emitter.body_facts.assignment_accesses[0] = Some(RuntimePlaceAccessFact {
            base: RuntimePlaceIdentity::Local(RuntimeLocalId(3)),
            ..valid_assignment_fact
        });
        assert_eq!(
            emitter.validate_runtime_place_facts().unwrap_err().kind,
            CodegenErrorKind::InvalidRuntimePlaceFacts
        );
        emitter.body_facts.assignment_accesses[0] = Some(valid_assignment_fact);

        let valid_assignment_read = emitter.body_facts.assignment_reads[0].unwrap();
        emitter.body_facts.assignment_reads[0] = Some(RuntimePlaceAccessFact {
            access: RuntimePlaceAccess::Write,
            ..valid_assignment_read
        });
        assert_eq!(
            emitter.validate_runtime_place_facts().unwrap_err().kind,
            CodegenErrorKind::InvalidRuntimePlaceFacts
        );
        emitter.body_facts.assignment_reads[0] = Some(valid_assignment_read);

        let valid_fact = emitter.body_facts.accesses[2].unwrap();
        emitter.body_facts.accesses[2] = Some(RuntimePlaceAccessFact {
            base: RuntimePlaceIdentity::Local(RuntimeLocalId(3)),
            ..valid_fact
        });
        assert_eq!(
            emitter.validate_runtime_place_facts().unwrap_err().kind,
            CodegenErrorKind::InvalidRuntimePlaceFacts
        );
        emitter.body_facts.accesses[2] = Some(valid_fact);
        for _ in emitter.body_facts.access_count..MAX_RUNTIME_PLACE_ACCESS_FACTS {
            emitter
                .record_place_access::<16>(final_place, &assignment)
                .unwrap();
        }
        assert_eq!(
            emitter
                .record_place_access::<16>(final_place, &assignment)
                .unwrap_err()
                .kind,
            CodegenErrorKind::TooManyRuntimePlaceAccessFacts
        );

        emitter.truncate_scoped_locals(0).unwrap();
        for _ in emitter.body_facts.local_count..MAX_RUNTIME_LOCAL_FACTS {
            emitter
                .push_runtime_local(
                    "bounded",
                    RuntimeExpressionType::Integer(Some(crate::IntegerType::U64)),
                    true,
                    true,
                    1,
                    None,
                )
                .unwrap();
            emitter.truncate_scoped_locals(0).unwrap();
        }
        assert_eq!(
            emitter
                .push_runtime_local(
                    "overflow",
                    RuntimeExpressionType::Integer(Some(crate::IntegerType::U64)),
                    true,
                    true,
                    1,
                    None,
                )
                .unwrap_err()
                .kind,
            CodegenErrorKind::TooManyRuntimeLocalFacts
        );
    }

    #[test]
    fn runtime_places_distinguish_constant_and_runtime_array_elements() {
        let source = "fn value(index: usize) -> u16 { let mut values: [u16; 2] = [1, 2]; values[1] = 3; values[index] = 4; values[1] }";
        let module = Parser::new(source).parse_module::<1, 4>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<4>().unwrap();
        let mut facts = RuntimeBodyFacts::EMPTY;
        assert_eq!(
            preanalyze_runtime_body_declarations::<_, 4, 32>(
                &function,
                &NoConstants,
                &body,
                "u16",
                function.body_expression_span.start,
                &mut facts,
            )
            .unwrap(),
            1
        );
        assert_eq!(facts.assignment_access_count, 2);
        assert_eq!(
            facts.assignment_accesses[0].unwrap().projections,
            RuntimePlaceProjections::single(RuntimePlaceProjection::ArrayElement(1))
        );
        assert_eq!(
            facts.assignment_accesses[1].unwrap().projections,
            RuntimePlaceProjections::single(RuntimePlaceProjection::Index)
        );
        assert!(
            facts.assignment_reads[..facts.assignment_read_count]
                .iter()
                .flatten()
                .any(|read| {
                    read.projections
                        == RuntimePlaceProjections::single(RuntimePlaceProjection::ArrayElement(1))
                })
        );
        let array = RuntimeExpressionType::Array {
            element: RuntimeArrayElementType::Integer(Some(crate::IntegerType::U16)),
            count: 2,
        };
        assert!(runtime_place_projections_valid(
            array,
            RuntimePlaceProjections::single(RuntimePlaceProjection::ArrayElement(1))
        ));
        assert!(!runtime_place_projections_valid(
            array,
            RuntimePlaceProjections::single(RuntimePlaceProjection::ArrayElement(2))
        ));
    }

    #[test]
    fn runtime_body_facts_preanalyze_typed_straight_line_locals() {
        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u16) -> u16 { let first: u16 = input; let second = first + 1; second }";
        let module = Parser::new(source).parse_module::<1, 4>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<4>().unwrap();
        let resolver = NoConstants;
        let mut facts = RuntimeBodyFacts::EMPTY;
        let count = preanalyze_runtime_body_declarations::<_, 4, 16>(
            &function,
            &resolver,
            &body,
            "u16",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();

        assert_eq!(count, 2);
        assert_eq!(facts.local_count, 2);
        assert_eq!(
            facts.locals[0],
            Some(RuntimeLocalFact {
                id: RuntimeLocalId(0),
                name: "first",
                ty: RuntimeExpressionType::Integer(Some(crate::IntegerType::U16)),
                mutable: false,
                initialized: true,
                declaration_span: Some(translate_span(
                    function.body_expression_span.start,
                    body.locals()[0].unwrap().name_span,
                )),
            })
        );
        assert_eq!(
            facts.locals[1],
            Some(RuntimeLocalFact {
                id: RuntimeLocalId(1),
                name: "second",
                ty: RuntimeExpressionType::Integer(Some(crate::IntegerType::U16)),
                mutable: false,
                initialized: true,
                declaration_span: Some(translate_span(
                    function.body_expression_span.start,
                    body.locals()[1].unwrap().name_span,
                )),
            })
        );
        assert_eq!(facts.access_count, 0);
        assert_eq!(facts.move_path_count, 3);
        assert_eq!(facts.initialization_count, 3);
        assert_eq!(
            facts.move_paths[0],
            Some(RuntimeMovePathFact {
                id: RuntimeMovePathId(0),
                parent: None,
                base: RuntimePlaceIdentity::Parameter(0),
                projections: RuntimePlaceProjections::EMPTY,
                ty: RuntimeExpressionType::Integer(Some(crate::IntegerType::U16)),
            })
        );
        for (index, local) in [RuntimeLocalId(0), RuntimeLocalId(1)].iter().enumerate() {
            let path_index = index + 1;
            assert_eq!(
                facts.move_paths[path_index].unwrap().base,
                RuntimePlaceIdentity::Local(*local)
            );
            assert_eq!(
                facts.initializations[path_index].unwrap().origin,
                RuntimeInitializationOrigin::LocalDeclaration
            );
        }
        assert_eq!(
            facts.initializations[0],
            Some(RuntimeInitializationFact {
                path: RuntimeMovePathId(0),
                origin: RuntimeInitializationOrigin::Parameter,
                span: Some(function.parameters()[0].unwrap().span),
                event: RuntimeOwnershipEventId(0),
                location: RuntimeOwnershipEventLocation::ParameterEntry,
                expression_path: RuntimeOwnershipExpressionPath::ROOT,
                expression_conditional: None,
                expression_point: None,
            })
        );

        let mut emitter = RuntimeEmitter::<_, 64, 4> {
            bytes: [0; 64],
            length: 0,
            readonly_data: [0; MAX_X86_64_READONLY_DATA_BYTES],
            readonly_data_length: 0,
            readonly_relocations: [X86_64ReadonlyDataRelocation {
                offset: 0,
                data_offset: 0,
            }; MAX_X86_64_READONLY_RELOCATIONS],
            readonly_relocation_count: 0,
            trap_patches: [0; 64],
            trap_count: 0,
            function: &function,
            resolver: &resolver,
            abi: X86_64Abi::Windows,
            width: runtime_width("u16").unwrap(),
            overflow_checks: true,
            uses_sret: false,
            saved_parameter_slots: 0,
            locals: [None; 4],
            saved_locals: 0,
            body_facts: &mut facts,
            preanalyzed_local_count: count,
            preanalyzed_local_cursor: 0,
            preanalyzed_assignment_access_cursor: 0,
            preanalyzed_assignment_read_cursor: 0,
            evaluation_depth: 0,
            runtime_call_depth: 0,
            runtime_call_names: [None; 8],
            runtime_call_local_floor: None,
        };
        emitter
            .push_runtime_local(
                "second",
                RuntimeExpressionType::Integer(Some(crate::IntegerType::U16)),
                false,
                true,
                1,
                Some(translate_span(
                    function.body_expression_span.start,
                    body.locals()[0].unwrap().name_span,
                )),
            )
            .unwrap();
        assert_eq!(
            emitter.validate_runtime_place_facts().unwrap_err().kind,
            CodegenErrorKind::InvalidRuntimePlaceFacts
        );

        let mut event_capacity = RuntimeBodyFacts::EMPTY;
        event_capacity.ownership_event_count = MAX_RUNTIME_OWNERSHIP_EVENT_FACTS;
        assert_eq!(
            event_capacity
                .push_initialized_parameter(0, runtime_type_from_text("&mut u16").unwrap(), None,)
                .unwrap_err(),
            CodegenErrorKind::TooManyRuntimeOwnershipEventFacts
        );
        assert_eq!(event_capacity.move_path_count, 0);
        assert_eq!(event_capacity.initialization_count, 0);
    }

    #[test]
    fn runtime_move_path_foundation_fails_closed_on_corruption_and_capacity() {
        let source = "fn value(input: u16) -> u16 { input }";
        let module = Parser::new(source).parse_module::<1, 1>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<1>().unwrap();
        let mut facts = RuntimeBodyFacts::EMPTY;
        let local_count = preanalyze_runtime_body_declarations::<_, 1, 8>(
            &function,
            &NoConstants,
            &body,
            "u16",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();
        let assignment_access_count = facts.assignment_access_count;
        let assignment_read_count = facts.assignment_read_count;
        let emitter = RuntimeEmitter::<_, 64, 1> {
            bytes: [0; 64],
            length: 0,
            readonly_data: [0; MAX_X86_64_READONLY_DATA_BYTES],
            readonly_data_length: 0,
            readonly_relocations: [X86_64ReadonlyDataRelocation {
                offset: 0,
                data_offset: 0,
            }; MAX_X86_64_READONLY_RELOCATIONS],
            readonly_relocation_count: 0,
            trap_patches: [0; 64],
            trap_count: 0,
            function: &function,
            resolver: &NoConstants,
            abi: X86_64Abi::SystemV,
            width: runtime_width("u16").unwrap(),
            overflow_checks: true,
            uses_sret: false,
            saved_parameter_slots: 1,
            locals: [None; 1],
            saved_locals: 0,
            body_facts: &mut facts,
            preanalyzed_local_count: local_count,
            preanalyzed_local_cursor: local_count,
            preanalyzed_assignment_access_cursor: assignment_access_count,
            preanalyzed_assignment_read_cursor: assignment_read_count,
            evaluation_depth: 0,
            runtime_call_depth: 0,
            runtime_call_names: [None; 8],
            runtime_call_local_floor: None,
        };
        emitter.validate_runtime_place_facts().unwrap();

        let valid_path = emitter.body_facts.move_paths[0].unwrap();
        emitter.body_facts.move_paths[0] = Some(RuntimeMovePathFact {
            parent: Some(RuntimeMovePathId(0)),
            ..valid_path
        });
        assert_eq!(
            emitter.validate_runtime_place_facts().unwrap_err().kind,
            CodegenErrorKind::InvalidRuntimePlaceFacts
        );
        emitter.body_facts.move_paths[0] = Some(valid_path);

        let valid_initialization = emitter.body_facts.initializations[0].unwrap();
        emitter.body_facts.initializations[0] = Some(RuntimeInitializationFact {
            origin: RuntimeInitializationOrigin::LocalDeclaration,
            ..valid_initialization
        });
        assert_eq!(
            emitter.validate_runtime_place_facts().unwrap_err().kind,
            CodegenErrorKind::InvalidRuntimePlaceFacts
        );
        emitter.body_facts.initializations[0] = Some(valid_initialization);
        emitter.body_facts.move_path_count = 0;
        emitter.body_facts.initialization_count = 0;
        assert_eq!(
            emitter.validate_runtime_place_facts().unwrap_err().kind,
            CodegenErrorKind::InvalidRuntimePlaceFacts
        );
        let mut capacity = RuntimeBodyFacts::EMPTY;
        capacity.move_path_count = MAX_RUNTIME_MOVE_PATH_FACTS;
        assert_eq!(
            capacity
                .push_initialized_parameter(
                    0,
                    RuntimeExpressionType::Integer(Some(crate::IntegerType::U16)),
                    None,
                )
                .unwrap_err(),
            CodegenErrorKind::TooManyRuntimeMovePathFacts
        );
        capacity.move_path_count = 0;
        capacity.initialization_count = MAX_RUNTIME_INITIALIZATION_FACTS;
        assert_eq!(
            capacity
                .push_initialized_parameter(
                    0,
                    RuntimeExpressionType::Integer(Some(crate::IntegerType::U16)),
                    None,
                )
                .unwrap_err(),
            CodegenErrorKind::TooManyRuntimeInitializationFacts
        );
    }

    #[test]
    fn runtime_move_paths_expand_owned_tuple_fields_and_reject_corruption() {
        let source = "fn value(first: u16, flag: bool, letter: char) -> u16 { let local: (u16, bool, char) = (first, flag, letter); local.0 }";
        let module = Parser::new(source).parse_module::<1, 4>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<4>().unwrap();
        let mut facts = RuntimeBodyFacts::EMPTY;
        let local_count = preanalyze_runtime_body_declarations::<_, 4, 16>(
            &function,
            &NoConstants,
            &body,
            "u16",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();
        assert_eq!(local_count, 1);
        assert_eq!(facts.move_path_count, 7);
        assert_eq!(facts.initialization_count, 4);
        for parameter in 0..3 {
            assert_eq!(
                facts.move_paths[parameter].unwrap().base,
                RuntimePlaceIdentity::Parameter(parameter)
            );
        }
        let root = RuntimeMovePathId(3);
        let base = RuntimePlaceIdentity::Local(RuntimeLocalId(0));
        assert_eq!(facts.move_paths[root.0].unwrap().base, base);
        for field in 0..3 {
            let child = facts.move_paths[root.0 + field + 1].unwrap();
            assert_eq!(child.parent, Some(root));
            assert_eq!(child.base, base);
            assert_eq!(
                child.projections,
                RuntimePlaceProjections::single(RuntimePlaceProjection::TupleField(field))
            );
        }
        assert_eq!(facts.initializations[0].unwrap().path, RuntimeMovePathId(0));
        assert_eq!(facts.initializations[3].unwrap().path, root);

        let assignment_access_count = facts.assignment_access_count;
        let assignment_read_count = facts.assignment_read_count;
        let emitter = RuntimeEmitter::<_, 64, 4> {
            bytes: [0; 64],
            length: 0,
            readonly_data: [0; MAX_X86_64_READONLY_DATA_BYTES],
            readonly_data_length: 0,
            readonly_relocations: [X86_64ReadonlyDataRelocation {
                offset: 0,
                data_offset: 0,
            }; MAX_X86_64_READONLY_RELOCATIONS],
            readonly_relocation_count: 0,
            trap_patches: [0; 64],
            trap_count: 0,
            function: &function,
            resolver: &NoConstants,
            abi: X86_64Abi::SystemV,
            width: runtime_width("u16").unwrap(),
            overflow_checks: true,
            uses_sret: false,
            saved_parameter_slots: 3,
            locals: [None; 4],
            saved_locals: 0,
            body_facts: &mut facts,
            preanalyzed_local_count: local_count,
            preanalyzed_local_cursor: local_count,
            preanalyzed_assignment_access_cursor: assignment_access_count,
            preanalyzed_assignment_read_cursor: assignment_read_count,
            evaluation_depth: 0,
            runtime_call_depth: 0,
            runtime_call_names: [None; 8],
            runtime_call_local_floor: None,
        };
        emitter.validate_runtime_place_facts().unwrap();
        let valid_child = emitter.body_facts.move_paths[5].unwrap();
        emitter.body_facts.move_paths[5] = Some(RuntimeMovePathFact {
            parent: Some(RuntimeMovePathId(0)),
            ..valid_child
        });
        assert_eq!(
            emitter.validate_runtime_place_facts().unwrap_err().kind,
            CodegenErrorKind::InvalidRuntimePlaceFacts
        );

        let tuple_type = runtime_type_from_text("(u16, bool, char)").unwrap();
        let mut capacity = RuntimeBodyFacts::EMPTY;
        capacity.move_path_count = MAX_RUNTIME_MOVE_PATH_FACTS - 2;
        assert_eq!(
            capacity
                .push_initialized_move_path_root(
                    RuntimePlaceIdentity::Parameter(0),
                    tuple_type,
                    RuntimeInitializationOrigin::Parameter,
                    None,
                )
                .unwrap_err(),
            CodegenErrorKind::TooManyRuntimeMovePathFacts
        );
        assert_eq!(capacity.move_path_count, MAX_RUNTIME_MOVE_PATH_FACTS - 2);
        assert_eq!(capacity.initialization_count, 0);
    }

    #[test]
    fn runtime_place_effects_classify_direct_moves_and_precise_writes() {
        let source = "fn value(input: &mut u16) -> u16 { let moved: &mut u16 = input; let mut pair: (u16, bool) = (1, false); pair.0 += 1; pair.1 = true; *moved + pair.0 }";
        let module = Parser::new(source).parse_module::<1, 4>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<4>().unwrap();
        let mut facts = RuntimeBodyFacts::EMPTY;
        let local_count = preanalyze_runtime_body_declarations::<_, 4, 16>(
            &function,
            &NoConstants,
            &body,
            "u16",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();
        assert_eq!(local_count, 2);
        assert_eq!(facts.effect_count, 5);
        assert_eq!(facts.effects[0].unwrap().path, RuntimeMovePathId(0));
        assert_eq!(
            facts.effects[0].unwrap().kind,
            RuntimePlaceEffectKind::MutableBorrow
        );
        let pair_root = facts
            .find_move_path(
                RuntimePlaceIdentity::Local(RuntimeLocalId(1)),
                RuntimePlaceProjections::EMPTY,
            )
            .unwrap();
        assert_eq!(
            facts.effects[1].unwrap().path,
            RuntimeMovePathId(pair_root.0 + 1)
        );
        assert_eq!(
            facts.effects[1].unwrap().kind,
            RuntimePlaceEffectKind::ReadModifyWrite
        );
        assert_eq!(
            facts.effects[2].unwrap().path,
            RuntimeMovePathId(pair_root.0 + 2)
        );
        assert_eq!(
            facts.effects[2].unwrap().kind,
            RuntimePlaceEffectKind::Write
        );
        assert_eq!(facts.effects[3].unwrap().path, RuntimeMovePathId(1));
        assert_eq!(
            facts.effects[3].unwrap().kind,
            RuntimePlaceEffectKind::LoanUse
        );
        assert_eq!(
            facts.effects[4].unwrap().path,
            RuntimeMovePathId(pair_root.0 + 1)
        );
        assert_eq!(facts.effects[4].unwrap().kind, RuntimePlaceEffectKind::Copy);

        let assignment_access_count = facts.assignment_access_count;
        let assignment_read_count = facts.assignment_read_count;
        let emitter = RuntimeEmitter::<_, 64, 4> {
            bytes: [0; 64],
            length: 0,
            readonly_data: [0; MAX_X86_64_READONLY_DATA_BYTES],
            readonly_data_length: 0,
            readonly_relocations: [X86_64ReadonlyDataRelocation {
                offset: 0,
                data_offset: 0,
            }; MAX_X86_64_READONLY_RELOCATIONS],
            readonly_relocation_count: 0,
            trap_patches: [0; 64],
            trap_count: 0,
            function: &function,
            resolver: &NoConstants,
            abi: X86_64Abi::SystemV,
            width: runtime_width("u16").unwrap(),
            overflow_checks: true,
            uses_sret: false,
            saved_parameter_slots: 1,
            locals: [None; 4],
            saved_locals: 0,
            body_facts: &mut facts,
            preanalyzed_local_count: local_count,
            preanalyzed_local_cursor: local_count,
            preanalyzed_assignment_access_cursor: assignment_access_count,
            preanalyzed_assignment_read_cursor: assignment_read_count,
            evaluation_depth: 0,
            runtime_call_depth: 0,
            runtime_call_names: [None; 8],
            runtime_call_local_floor: None,
        };
        emitter.validate_runtime_place_facts().unwrap();
        let valid_copy = emitter.body_facts.effects[4].unwrap();
        emitter.body_facts.effects[4] = Some(RuntimePlaceEffectFact {
            path: RuntimeMovePathId(0),
            ..valid_copy
        });
        assert_eq!(
            emitter.validate_runtime_place_facts().unwrap_err().kind,
            CodegenErrorKind::InvalidRuntimePlaceFacts
        );
        emitter.body_facts.effects[4] = Some(valid_copy);
        let valid_move = emitter.body_facts.effects[0].unwrap();
        emitter.body_facts.effects[0] = Some(RuntimePlaceEffectFact {
            path: RuntimeMovePathId(MAX_RUNTIME_MOVE_PATH_FACTS),
            ..valid_move
        });
        assert_eq!(
            emitter.validate_runtime_place_facts().unwrap_err().kind,
            CodegenErrorKind::InvalidRuntimePlaceFacts
        );
        emitter.body_facts.effects[0] = Some(valid_move);
        emitter.body_facts.effect_count = MAX_RUNTIME_PLACE_EFFECT_FACTS + 1;
        assert_eq!(
            emitter.validate_runtime_place_facts().unwrap_err().kind,
            CodegenErrorKind::InvalidRuntimePlaceFacts
        );

        let mut capacity = RuntimeBodyFacts::EMPTY;
        capacity
            .push_initialized_parameter(
                0,
                RuntimeExpressionType::Integer(Some(crate::IntegerType::U16)),
                None,
            )
            .unwrap();
        capacity.effect_count = MAX_RUNTIME_PLACE_EFFECT_FACTS;
        assert_eq!(
            capacity
                .push_place_effect(valid_move.path, valid_move.kind, valid_move.span)
                .unwrap_err(),
            CodegenErrorKind::TooManyRuntimePlaceEffectFacts
        );
        assert_eq!(
            capacity
                .push_assignment_read(
                    RuntimePlaceAccessFact {
                        base: RuntimePlaceIdentity::Parameter(0),
                        projections: RuntimePlaceProjections::EMPTY,
                        ty: RuntimeExpressionType::Integer(Some(crate::IntegerType::U16)),
                        access: RuntimePlaceAccess::Read,
                        span: Span { start: 0, end: 1 },
                    },
                    RuntimeReadEffectContext::Value
                )
                .unwrap_err(),
            CodegenErrorKind::TooManyRuntimePlaceEffectFacts
        );
        assert_eq!(capacity.assignment_read_count, 0);
    }

    #[test]
    fn runtime_place_effects_distinguish_value_reads_and_borrows() {
        let source = "fn value(input: u16, reference: &mut u16) -> u16 { let mut first = input; let mut second = input; let shared: &u16 = &first; let mutable: &mut u16 = &mut second; let reborrowed: &mut u16 = &mut *reference; *shared + *mutable + *reborrowed }";
        let module = Parser::new(source).parse_module::<1, 8>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<8>().unwrap();
        let mut facts = RuntimeBodyFacts::EMPTY;
        let local_count = preanalyze_runtime_body_declarations::<_, 8, 32>(
            &function,
            &NoConstants,
            &body,
            "u16",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();

        assert_eq!(local_count, 5);
        assert_eq!(facts.effect_count, 8);
        assert_eq!(facts.effects[0].unwrap().kind, RuntimePlaceEffectKind::Copy);
        assert_eq!(facts.effects[0].unwrap().path, RuntimeMovePathId(0));
        assert_eq!(facts.effects[1].unwrap().kind, RuntimePlaceEffectKind::Copy);
        assert_eq!(facts.effects[1].unwrap().path, RuntimeMovePathId(0));
        assert_eq!(
            facts.effects[2].unwrap().kind,
            RuntimePlaceEffectKind::SharedBorrow
        );
        assert_eq!(facts.effects[2].unwrap().path, RuntimeMovePathId(2));
        assert_eq!(
            facts.effects[3].unwrap().kind,
            RuntimePlaceEffectKind::MutableBorrow
        );
        assert_eq!(facts.effects[3].unwrap().path, RuntimeMovePathId(3));
        assert_eq!(
            facts.effects[4].unwrap().kind,
            RuntimePlaceEffectKind::MutableBorrow
        );
        assert_eq!(facts.effects[4].unwrap().path, RuntimeMovePathId(1));
        for (effect_index, path) in [(5, 4), (6, 5), (7, 6)] {
            assert_eq!(
                facts.effects[effect_index].unwrap().kind,
                RuntimePlaceEffectKind::LoanUse
            );
            assert_eq!(
                facts.effects[effect_index].unwrap().path,
                RuntimeMovePathId(path)
            );
        }
        assert_eq!(
            facts.direct_loan_fact(4),
            Some(RuntimeLoanFact {
                id: RuntimeLoanId(4),
                borrower: RuntimeLocalId(2),
                borrowed_path: RuntimeMovePathId(2),
                kind: RuntimePlaceEffectKind::SharedBorrow,
                issue_effect: 2,
                generation_event: facts.initializations[4].unwrap().event,
            })
        );
        assert_eq!(
            facts.direct_loan_fact(5),
            Some(RuntimeLoanFact {
                id: RuntimeLoanId(5),
                borrower: RuntimeLocalId(3),
                borrowed_path: RuntimeMovePathId(3),
                kind: RuntimePlaceEffectKind::MutableBorrow,
                issue_effect: 3,
                generation_event: facts.initializations[5].unwrap().event,
            })
        );
        assert_eq!(
            facts.direct_loan_fact(6),
            Some(RuntimeLoanFact {
                id: RuntimeLoanId(6),
                borrower: RuntimeLocalId(4),
                borrowed_path: RuntimeMovePathId(1),
                kind: RuntimePlaceEffectKind::MutableBorrow,
                issue_effect: 4,
                generation_event: facts.initializations[6].unwrap().event,
            })
        );

        let assignment_access_count = facts.assignment_access_count;
        let assignment_read_count = facts.assignment_read_count;
        let emitter = RuntimeEmitter::<_, 128, 8> {
            bytes: [0; 128],
            length: 0,
            readonly_data: [0; MAX_X86_64_READONLY_DATA_BYTES],
            readonly_data_length: 0,
            readonly_relocations: [X86_64ReadonlyDataRelocation {
                offset: 0,
                data_offset: 0,
            }; MAX_X86_64_READONLY_RELOCATIONS],
            readonly_relocation_count: 0,
            trap_patches: [0; 128],
            trap_count: 0,
            function: &function,
            resolver: &NoConstants,
            abi: X86_64Abi::SystemV,
            width: runtime_width("u16").unwrap(),
            overflow_checks: true,
            uses_sret: false,
            saved_parameter_slots: 2,
            locals: [None; 8],
            saved_locals: 0,
            body_facts: &mut facts,
            preanalyzed_local_count: local_count,
            preanalyzed_local_cursor: local_count,
            preanalyzed_assignment_access_cursor: assignment_access_count,
            preanalyzed_assignment_read_cursor: assignment_read_count,
            evaluation_depth: 0,
            runtime_call_depth: 0,
            runtime_call_names: [None; 8],
            runtime_call_local_floor: None,
        };
        emitter.validate_runtime_place_facts().unwrap();

        let valid_borrow = emitter.body_facts.effects[2].unwrap();
        emitter.body_facts.effects[2] = Some(RuntimePlaceEffectFact {
            path: RuntimeMovePathId(MAX_RUNTIME_MOVE_PATH_FACTS),
            ..valid_borrow
        });
        assert_eq!(
            emitter.validate_runtime_place_facts().unwrap_err().kind,
            CodegenErrorKind::InvalidRuntimePlaceFacts
        );
        emitter.body_facts.effects[2] = Some(valid_borrow);
        let valid_loan_use = emitter.body_facts.effects[5].unwrap();
        emitter.body_facts.effects[5] = Some(RuntimePlaceEffectFact {
            path: RuntimeMovePathId(1),
            ..valid_loan_use
        });
        assert_eq!(
            emitter.validate_runtime_place_facts().unwrap_err().kind,
            CodegenErrorKind::InvalidRuntimePlaceFacts
        );
        emitter.body_facts.effects[5] = Some(valid_loan_use);
        assert_eq!(emitter.body_facts.direct_loan_fact(0), None);
    }

    #[test]
    fn runtime_shared_loan_liveness_rejects_only_use_after_mutable_borrow() {
        let rejected = "fn value(input: u16) -> u16 { let mut slot = input; let shared: &u16 = &slot; let mutable: &mut u16 = &mut slot; *mutable += 1; *shared + *mutable }";
        let module = Parser::new(rejected).parse_module::<1, 8>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<8>().unwrap();
        let mut facts = RuntimeBodyFacts::EMPTY;
        assert_eq!(
            preanalyze_runtime_body_declarations::<_, 8, 32>(
                &function,
                &NoConstants,
                &body,
                "u16",
                function.body_expression_span.start,
                &mut facts,
            )
            .unwrap_err()
            .kind,
            CodegenErrorKind::RuntimeBorrowConflict
        );

        let accepted = "fn value(input: u16) -> u16 { let mut slot = input; let shared: &u16 = &slot; let copied = *shared; let mutable: &mut u16 = &mut slot; *mutable += 1; copied + *mutable }";
        let module = Parser::new(accepted).parse_module::<1, 8>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<8>().unwrap();
        let mut facts = RuntimeBodyFacts::EMPTY;
        preanalyze_runtime_body_declarations::<_, 8, 32>(
            &function,
            &NoConstants,
            &body,
            "u16",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();
        assert!(
            facts.effects[..facts.effect_count]
                .iter()
                .flatten()
                .any(|effect| {
                    effect.kind == RuntimePlaceEffectKind::LoanUse
                        && effect.path == RuntimeMovePathId(2)
                })
        );
    }

    #[test]
    fn runtime_shared_loan_liveness_rejects_only_use_after_owner_mutation() {
        fn analyze(source: &str) -> Result<usize, CodegenError> {
            let module = Parser::new(source).parse_module::<1, 8>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            let body = function.parse_body::<8>().unwrap();
            let mut facts = RuntimeBodyFacts::EMPTY;
            preanalyze_runtime_body_declarations::<_, 8, 32>(
                &function,
                &NoConstants,
                &body,
                "u16",
                function.body_expression_span.start,
                &mut facts,
            )
        }

        let rejected = "fn value(input: u16) -> u16 { let mut slot = input; let shared: &u16 = &slot; slot += 1; *shared }";
        assert_eq!(
            analyze(rejected).unwrap_err().kind,
            CodegenErrorKind::RuntimeBorrowConflict
        );

        let accepted = "fn value(input: u16) -> u16 { let mut slot = input; let shared: &u16 = &slot; let copied = *shared; slot += 1; copied + slot }";
        analyze(accepted).unwrap();
    }

    #[test]
    fn runtime_shared_loan_liveness_rejects_only_use_after_owner_move() {
        fn analyze(source: &str) -> Result<usize, CodegenError> {
            let module = Parser::new(source).parse_module::<1, 8>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            let body = function.parse_body::<8>().unwrap();
            let mut facts = RuntimeBodyFacts::EMPTY;
            preanalyze_runtime_body_declarations::<_, 8, 32>(
                &function,
                &NoConstants,
                &body,
                "u16",
                function.body_expression_span.start,
                &mut facts,
            )
        }

        let rejected = "fn value(input: &mut u16) -> u16 { let shared: &u16 = &*input; let moved = input; *shared + *moved }";
        assert_eq!(
            analyze(rejected).unwrap_err().kind,
            CodegenErrorKind::RuntimeBorrowConflict
        );

        let accepted = "fn value(input: &mut u16) -> u16 { let shared: &u16 = &*input; let copied = *shared; let moved = input; copied + *moved }";
        analyze(accepted).unwrap();
    }

    #[test]
    fn runtime_shared_loan_liveness_follows_conditional_cfg_edges() {
        let rejected = "fn value(input: u16, change: bool) -> u16 { let mut slot = input; let shared: &u16 = &slot; if change { let mutable: &mut u16 = &mut slot; *mutable += 1; } *shared }";
        let module = Parser::new(rejected).parse_module::<1, 8>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<8>().unwrap();
        let mut facts = RuntimeBodyFacts::EMPTY;
        assert_eq!(
            preanalyze_runtime_body_declarations::<_, 8, 32>(
                &function,
                &NoConstants,
                &body,
                "u16",
                function.body_expression_span.start,
                &mut facts,
            )
            .unwrap_err()
            .kind,
            CodegenErrorKind::RuntimeBorrowConflict
        );

        let accepted = "fn value(input: u16, change: bool) -> u16 { let mut slot = input; let shared: &u16 = &slot; let copied = *shared; if change { let mutable: &mut u16 = &mut slot; *mutable += 1; } copied }";
        let module = Parser::new(accepted).parse_module::<1, 8>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<8>().unwrap();
        let mut facts = RuntimeBodyFacts::EMPTY;
        preanalyze_runtime_body_declarations::<_, 8, 32>(
            &function,
            &NoConstants,
            &body,
            "u16",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();
    }

    #[test]
    fn runtime_mutable_loan_invalidation_rejects_only_later_borrower_use() {
        let rejected = "fn value(input: u16) -> u16 { let mut slot = input; let mutable: &mut u16 = &mut slot; let shared: &u16 = &slot; *mutable += 1; *shared + *mutable }";
        let module = Parser::new(rejected).parse_module::<1, 8>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<8>().unwrap();
        let mut facts = RuntimeBodyFacts::EMPTY;
        assert_eq!(
            preanalyze_runtime_body_declarations::<_, 8, 32>(
                &function,
                &NoConstants,
                &body,
                "u16",
                function.body_expression_span.start,
                &mut facts,
            )
            .unwrap_err()
            .kind,
            CodegenErrorKind::RuntimeBorrowConflict
        );

        let accepted = "fn value(input: u16) -> u16 { let mut slot = input; let mutable: &mut u16 = &mut slot; *mutable += 1; let shared: &u16 = &slot; *shared }";
        let module = Parser::new(accepted).parse_module::<1, 8>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<8>().unwrap();
        let mut facts = RuntimeBodyFacts::EMPTY;
        preanalyze_runtime_body_declarations::<_, 8, 32>(
            &function,
            &NoConstants,
            &body,
            "u16",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();
    }

    #[test]
    fn runtime_mutable_reborrow_temporarily_suspends_its_parent() {
        let rejected = "fn value(input: u16) -> u16 { let mut slot = input; let parent: &mut u16 = &mut slot; let child: &mut u16 = &mut *parent; let parent_value = *parent; let child_value = *child; parent_value + child_value }";
        let module = Parser::new(rejected).parse_module::<1, 8>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<8>().unwrap();
        let mut facts = RuntimeBodyFacts::EMPTY;
        assert_eq!(
            preanalyze_runtime_body_declarations::<_, 8, 32>(
                &function,
                &NoConstants,
                &body,
                "u16",
                function.body_expression_span.start,
                &mut facts,
            )
            .unwrap_err()
            .kind,
            CodegenErrorKind::RuntimeBorrowConflict
        );

        let accepted = "fn value(input: u16) -> u16 { let mut slot = input; let parent: &mut u16 = &mut slot; let child: &mut u16 = &mut *parent; let child_value = *child; let parent_value = *parent; parent_value + child_value }";
        let module = Parser::new(accepted).parse_module::<1, 8>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<8>().unwrap();
        let mut facts = RuntimeBodyFacts::EMPTY;
        preanalyze_runtime_body_declarations::<_, 8, 32>(
            &function,
            &NoConstants,
            &body,
            "u16",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();

        let rejected_root = "fn value(input: u16) -> u16 { let mut slot = input; let parent: &mut u16 = &mut slot; let child: &mut u16 = &mut *parent; slot += 1; *child }";
        let module = Parser::new(rejected_root).parse_module::<1, 8>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<8>().unwrap();
        let mut facts = RuntimeBodyFacts::EMPTY;
        assert_eq!(
            preanalyze_runtime_body_declarations::<_, 8, 32>(
                &function,
                &NoConstants,
                &body,
                "u16",
                function.body_expression_span.start,
                &mut facts,
            )
            .unwrap_err()
            .kind,
            CodegenErrorKind::RuntimeBorrowConflict
        );

        let accepted_root = "fn value(input: u16) -> u16 { let mut slot = input; let parent: &mut u16 = &mut slot; let child: &mut u16 = &mut *parent; let copied = *child; slot += 1; copied + slot }";
        let module = Parser::new(accepted_root).parse_module::<1, 8>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<8>().unwrap();
        let mut facts = RuntimeBodyFacts::EMPTY;
        preanalyze_runtime_body_declarations::<_, 8, 32>(
            &function,
            &NoConstants,
            &body,
            "u16",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();

        let shared = "fn value(input: u16) -> u16 { let slot = input; let parent: &u16 = &slot; let child: &u16 = &*parent; let parent_value = *parent; let child_value = *child; parent_value + child_value }";
        let module = Parser::new(shared).parse_module::<1, 8>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<8>().unwrap();
        let mut facts = RuntimeBodyFacts::EMPTY;
        preanalyze_runtime_body_declarations::<_, 8, 32>(
            &function,
            &NoConstants,
            &body,
            "u16",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();
    }

    #[test]
    fn runtime_nested_reborrows_suspend_every_mutable_ancestor() {
        fn analyze(source: &str) -> Result<usize, CodegenError> {
            let module = Parser::new(source).parse_module::<1, 8>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            let body = function.parse_body::<8>().unwrap();
            let mut facts = RuntimeBodyFacts::EMPTY;
            preanalyze_runtime_body_declarations::<_, 8, 32>(
                &function,
                &NoConstants,
                &body,
                "u16",
                function.body_expression_span.start,
                &mut facts,
            )
        }

        for rejected in [
            "fn value(input: u16) -> u16 { let mut slot = input; let first: &mut u16 = &mut slot; let second: &mut u16 = &mut *first; let third: &mut u16 = &mut *second; *first += 1; *third }",
            "fn value(input: u16) -> u16 { let mut slot = input; let first: &mut u16 = &mut slot; let second: &mut u16 = &mut *first; let third: &u16 = &*second; *first += 1; *third }",
            "fn value(input: &mut u16) -> u16 { let first: &mut u16 = &mut *input; let second: &mut u16 = &mut *first; let third: &u16 = &*second; *input += 1; *third }",
        ] {
            assert_eq!(
                analyze(rejected).unwrap_err().kind,
                CodegenErrorKind::RuntimeBorrowConflict
            );
        }

        for accepted in [
            "fn value(input: u16) -> u16 { let mut slot = input; let first: &mut u16 = &mut slot; let second: &mut u16 = &mut *first; let third: &mut u16 = &mut *second; let copied = *third; *first += 1; copied + *first }",
            "fn value(input: u16) -> u16 { let mut slot = input; let first: &mut u16 = &mut slot; let second: &mut u16 = &mut *first; let third: &u16 = &*second; let copied = *third; *first += 1; copied + *first }",
            "fn value(input: &mut u16) -> u16 { let first: &mut u16 = &mut *input; let second: &mut u16 = &mut *first; let third: &u16 = &*second; let copied = *third; *input += 1; copied + *input }",
        ] {
            analyze(accepted).unwrap();
        }
    }

    #[test]
    fn runtime_call_reborrows_suspend_live_shared_children_of_local_ancestors() {
        fn analyze(source: &str) -> Result<usize, CodegenError> {
            let module = Parser::new(source).parse_module::<1, 8>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            let body = function.parse_body::<8>().unwrap();
            let mut facts = RuntimeBodyFacts::EMPTY;
            preanalyze_runtime_body_declarations::<_, 8, 32>(
                &function,
                &MutableReferenceCallResolver,
                &body,
                "u16",
                function.body_expression_span.start,
                &mut facts,
            )
        }

        for rejected in [
            "fn value(input: u16) -> u16 { let mut slot = input; let parent: &mut u16 = &mut slot; let child: &u16 = &*parent; touch(parent); *child }",
            "fn value(input: u16) -> u16 { let mut slot = input; let holder = (&mut slot,); let child: &u16 = &*holder.0; touch(holder.0); *child }",
        ] {
            assert_eq!(
                analyze(rejected).unwrap_err().kind,
                CodegenErrorKind::RuntimeBorrowConflict,
                "{rejected}",
            );
        }

        for accepted in [
            "fn value(input: u16) -> u16 { let mut slot = input; let parent: &mut u16 = &mut slot; let child: &u16 = &*parent; let copied = *child; touch(parent); copied + *parent }",
            "fn value(input: u16) -> u16 { let mut slot = input; let holder = (&mut slot,); let child: &u16 = &*holder.0; let copied = *child; touch(holder.0); copied + slot }",
        ] {
            analyze(accepted).unwrap_or_else(|error| panic!("{accepted}: {error:?}"));
        }
    }

    #[test]
    fn runtime_shared_call_reborrows_suspend_live_mutable_children_of_local_ancestors() {
        fn analyze(source: &str) -> Result<usize, CodegenError> {
            let module = Parser::new(source).parse_module::<1, 8>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            let body = function.parse_body::<8>().unwrap();
            let mut facts = RuntimeBodyFacts::EMPTY;
            preanalyze_runtime_body_declarations::<_, 8, 32>(
                &function,
                &MutableReferenceCallResolver,
                &body,
                "u16",
                function.body_expression_span.start,
                &mut facts,
            )
        }

        let rejected = "fn value(input: u16) -> u16 { let mut slot = input; let parent: &mut u16 = &mut slot; let child: &mut u16 = &mut *parent; let observed = read(parent); observed + *child }";
        assert_eq!(
            analyze(rejected).unwrap_err().kind,
            CodegenErrorKind::RuntimeBorrowConflict
        );

        let accepted = "fn value(input: u16) -> u16 { let mut slot = input; let parent: &mut u16 = &mut slot; let child: &mut u16 = &mut *parent; let copied = *child; let observed = read(parent); copied + observed }";
        analyze(accepted).unwrap();
    }

    #[test]
    fn runtime_owner_moves_suspend_live_children_of_local_reference_ancestors() {
        fn analyze(source: &str) -> Result<usize, CodegenError> {
            let module = Parser::new(source).parse_module::<1, 8>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            let body = function.parse_body::<8>().unwrap();
            let mut facts = RuntimeBodyFacts::EMPTY;
            preanalyze_runtime_body_declarations::<_, 8, 32>(
                &function,
                &NoConstants,
                &body,
                "u16",
                function.body_expression_span.start,
                &mut facts,
            )
        }

        for rejected in [
            "fn value(input: u16) -> u16 { let mut slot = input; let parent: &mut u16 = &mut slot; let child: &u16 = &*parent; let moved = parent; *child + *moved }",
            "fn value(input: u16) -> u16 { let mut slot = input; let parent: &mut u16 = &mut slot; let child: &mut u16 = &mut *parent; let moved = parent; *child + *moved }",
        ] {
            assert_eq!(
                analyze(rejected).unwrap_err().kind,
                CodegenErrorKind::RuntimeBorrowConflict
            );
        }

        for accepted in [
            "fn value(input: u16) -> u16 { let mut slot = input; let parent: &mut u16 = &mut slot; let child: &u16 = &*parent; let copied = *child; let moved = parent; copied + *moved }",
            "fn value(input: u16) -> u16 { let mut slot = input; let parent: &mut u16 = &mut slot; let child: &mut u16 = &mut *parent; let copied = *child; let moved = parent; copied + *moved }",
        ] {
            analyze(accepted).unwrap();
        }
    }

    #[test]
    fn runtime_owner_moves_include_projected_reference_path_ancestors() {
        fn analyze(source: &str) -> Result<usize, CodegenError> {
            let module = Parser::new(source).parse_module::<1, 8>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            let body = function.parse_body::<8>().unwrap();
            let mut facts = RuntimeBodyFacts::EMPTY;
            preanalyze_runtime_body_declarations::<_, 8, 32>(
                &function,
                &NoConstants,
                &body,
                "u16",
                function.body_expression_span.start,
                &mut facts,
            )
        }

        for rejected in [
            "fn value(input: u16) -> u16 { let mut slot = input; let holder = (&mut slot,); let child: &u16 = &*holder.0; let moved = holder; *child + *moved.0 }",
            "fn value(input: u16) -> u16 { let mut slot = input; let holder = (&mut slot,); let child: &mut u16 = &mut *holder.0; let moved = holder; *child + *moved.0 }",
        ] {
            assert_eq!(
                analyze(rejected).unwrap_err().kind,
                CodegenErrorKind::RuntimeBorrowConflict
            );
        }

        for accepted in [
            "fn value(input: u16) -> u16 { let mut slot = input; let holder = (&mut slot,); let child: &u16 = &*holder.0; let copied = *child; let moved = holder; copied + *moved.0 }",
            "fn value(input: u16) -> u16 { let mut first = input; let mut second = input + 1; let holder = (&mut first, &mut second); let child: &u16 = &*holder.0; let moved = holder.1; *child + *moved }",
            "fn value(input: u16) -> u16 { let mut first = input; let mut second = input + 1; let mut holder = (&mut first,); let replacement = (&mut second,); let child: &u16 = &*holder.0; holder = replacement; *child + *holder.0 }",
        ] {
            analyze(accepted).unwrap();
        }

        let mut corrupt = RuntimeBodyFacts::EMPTY;
        corrupt.move_path_count = 1;
        corrupt.move_paths[0] = Some(RuntimeMovePathFact {
            id: RuntimeMovePathId(0),
            parent: Some(RuntimeMovePathId(0)),
            base: RuntimePlaceIdentity::Local(RuntimeLocalId(0)),
            projections: RuntimePlaceProjections::EMPTY,
            ty: RuntimeExpressionType::Integer(Some(crate::IntegerType::U16)),
        });
        assert_eq!(
            runtime_move_path_is_ancestor_or_same(
                &corrupt,
                RuntimeMovePathId(1),
                RuntimeMovePathId(0)
            ),
            None
        );
        assert_eq!(
            runtime_move_path_is_ancestor_or_same(
                &corrupt,
                RuntimeMovePathId(0),
                RuntimeMovePathId(1)
            ),
            None
        );
    }

    #[test]
    fn runtime_reference_moves_propagate_direct_loan_identity() {
        fn analyze(source: &str) -> Result<usize, CodegenError> {
            let module = Parser::new(source).parse_module::<1, 8>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            let body = function.parse_body::<8>().unwrap();
            let mut facts = RuntimeBodyFacts::EMPTY;
            preanalyze_runtime_body_declarations::<_, 8, 32>(
                &function,
                &NoConstants,
                &body,
                "u16",
                function.body_expression_span.start,
                &mut facts,
            )
        }

        for rejected in [
            "fn value(input: u16) -> u16 { let mut slot = input; let parent: &mut u16 = &mut slot; let moved = parent; let child: &u16 = &*moved; slot += 1; *child }",
            "fn value(input: u16) -> u16 { let mut slot = input; let parent: &mut u16 = &mut slot; let moved = parent; let child: &mut u16 = &mut *moved; slot += 1; *child }",
            "fn value(input: u16) -> u16 { let mut slot = input; let parent: &mut u16 = &mut slot; let first = parent; let second = first; let child: &u16 = &*second; slot += 1; *child }",
            "fn value(input: u16) -> u16 { let mut first = input; let mut second = input + 1; let mut parent: &mut u16 = &mut first; parent = &mut second; let moved = parent; let child: &u16 = &*moved; second += 1; *child }",
        ] {
            assert_eq!(
                analyze(rejected).unwrap_err().kind,
                CodegenErrorKind::RuntimeBorrowConflict
            );
        }

        for accepted in [
            "fn value(input: u16) -> u16 { let mut slot = input; let parent: &mut u16 = &mut slot; let moved = parent; let child: &u16 = &*moved; let copied = *child; slot += 1; copied + slot }",
            "fn value(input: u16) -> u16 { let mut slot = input; let parent: &mut u16 = &mut slot; let moved = parent; *moved += 1; *moved }",
            "fn value(input: u16) -> u16 { let mut slot = input; let parent: &mut u16 = &mut slot; let first = parent; let second = first; let child: &u16 = &*second; let copied = *child; slot += 1; copied + slot }",
            "fn value(input: u16) -> u16 { let mut first = input; let mut second = input + 1; let mut parent: &mut u16 = &mut first; parent = &mut second; let moved = parent; let child: &u16 = &*moved; first += 1; *child + first }",
        ] {
            analyze(accepted).unwrap();
        }
    }

    #[test]
    fn runtime_projected_reference_value_moves_propagate_tuple_field_loans() {
        fn analyze(source: &str) -> Result<usize, CodegenError> {
            let module = Parser::new(source).parse_module::<1, 8>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            let body = function.parse_body::<8>().unwrap();
            let mut facts = RuntimeBodyFacts::EMPTY;
            preanalyze_runtime_body_declarations::<_, 8, 32>(
                &function,
                &NoConstants,
                &body,
                "u16",
                function.body_expression_span.start,
                &mut facts,
            )
        }

        for rejected in [
            "fn value(input: u16) -> u16 { let mut slot = input; let holder = (&mut slot,); let moved = holder.0; let child: &u16 = &*moved; slot += 1; *child }",
            "fn value(input: u16) -> u16 { let mut slot = input; let holder = (&mut slot,); let moved = holder.0; let child: &mut u16 = &mut *moved; slot += 1; *child }",
            "fn value(input: u16) -> u16 { let mut first = input; let mut second = input + 1; let holder = (&mut first, &mut second); let moved = holder.1; let child: &u16 = &*moved; second += 1; *child }",
        ] {
            assert_eq!(
                analyze(rejected).unwrap_err().kind,
                CodegenErrorKind::RuntimeBorrowConflict
            );
        }

        for accepted in [
            "fn value(input: u16) -> u16 { let mut slot = input; let holder = (&mut slot,); let moved = holder.0; let child: &u16 = &*moved; let copied = *child; slot += 1; copied + slot }",
            "fn value(input: u16) -> u16 { let mut first = input; let mut second = input + 1; let holder = (&mut first, &mut second); let moved = holder.1; let child: &u16 = &*moved; first += 1; *child + first }",
        ] {
            analyze(accepted).unwrap();
        }
    }

    #[test]
    fn runtime_projected_reference_value_move_chains_preserve_tuple_field_loans() {
        fn analyze(source: &str) -> Result<usize, CodegenError> {
            let module = Parser::new(source).parse_module::<1, 12>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            let body = function.parse_body::<12>().unwrap();
            let mut facts = RuntimeBodyFacts::EMPTY;
            preanalyze_runtime_body_declarations::<_, 12, 48>(
                &function,
                &NoConstants,
                &body,
                "u16",
                function.body_expression_span.start,
                &mut facts,
            )
        }

        for rejected in [
            "fn value(input: u16) -> u16 { let mut slot = input; let holder = (&mut slot,); let first = holder.0; let second = first; let child: &u16 = &*second; slot += 1; *child }",
            "fn value(input: u16) -> u16 { let mut slot = input; let holder = (&mut slot,); let first = holder.0; let second = first; let third = second; let child: &mut u16 = &mut *third; slot += 1; *child }",
            "fn value(input: u16) -> u16 { let mut first = input; let mut second = input + 1; let holder = (&mut first, &mut second); let moved = holder.1; let again = moved; let child: &u16 = &*again; second += 1; *child }",
            "fn value(input: u16) -> u16 { let mut slot = input; let first_holder = (&mut slot,); let first = first_holder.0; let second_holder = (first,); let moved = second_holder.0; let child: &u16 = &*moved; slot += 1; *child }",
            "fn value(input: u16) -> u16 { let mut slot = input; let first_holder = (&mut slot,); let first = first_holder.0; let second_holder = (first,); let moved = second_holder.0; let child: &mut u16 = &mut *moved; slot += 1; *child }",
            "fn value(input: u16) -> u16 { let mut first = input; let mut second = input + 1; let mut holder = (&mut first,); holder.0 = &mut second; let moved = holder.0; let child: &u16 = &*moved; second += 1; *child }",
            "fn value(input: u16) -> u16 { let mut first = input; let mut second = input + 1; let mut holder = (&mut first,); holder.0 = &mut second; let moved = holder.0; let child: &mut u16 = &mut *moved; second += 1; *child }",
            "fn value(input: u16, choose: bool) -> u16 { let mut first = input; let mut second = input + 1; let mut third = input + 2; let mut holder = (&mut first,); holder.0 = if choose { &mut second } else { &mut third }; let moved = holder.0; let child: &u16 = &*moved; second += 1; *child }",
            "fn value(input: u16, choose: bool) -> u16 { let mut first = input; let mut second = input + 1; let mut third = input + 2; let mut holder = (&mut first,); holder.0 = if choose { &mut second } else { &mut third }; let moved = holder.0; let child: &u16 = &*moved; third += 1; *child }",
            "fn value(input: u16, choose: bool) -> u16 { let mut first = input; let mut second = input + 1; let mut third = input + 2; let mut holder = (&mut first,); holder.0 = if choose { &mut second } else { &mut third }; let moved = holder.0; let child: &u16 = &*moved; first += 1; *child }",
            "fn value(input: u16) -> u16 { let mut first = input; let mut second = input + 1; let mut third = input + 2; let mut holder = (&mut first,); holder.0 = &mut second; holder.0 = &mut third; let moved = holder.0; let child: &u16 = &*moved; first += 1; *child }",
            "fn value(input: u16) -> u16 { let mut first = input; let mut second = input + 1; let mut third = input + 2; let mut holder = (&mut first,); holder.0 = &mut second; holder.0 = &mut third; let moved = holder.0; let child: &u16 = &*moved; second += 1; *child }",
            "fn value(input: u16) -> u16 { let mut first = input; let mut second = input + 1; let mut third = input + 2; let mut holder = (&mut first,); holder.0 = &mut second; holder.0 = &mut third; let moved = holder.0; let child: &u16 = &*moved; third += 1; *child }",
        ] {
            match analyze(rejected) {
                Err(error) => assert_eq!(error.kind, CodegenErrorKind::RuntimeBorrowConflict),
                Ok(_) => panic!("expected borrow conflict: {rejected}"),
            }
        }

        for accepted in [
            "fn value(input: u16) -> u16 { let mut slot = input; let holder = (&mut slot,); let first = holder.0; let second = first; let child: &u16 = &*second; let copied = *child; slot += 1; copied + slot }",
            "fn value(input: u16) -> u16 { let mut first = input; let mut second = input + 1; let holder = (&mut first, &mut second); let moved = holder.1; let again = moved; let child: &u16 = &*again; first += 1; *child + first }",
            "fn value(input: u16) -> u16 { let mut first = input; let mut second = input + 1; let holder = (&mut first,); let mut moved = holder.0; moved = &mut second; let again = moved; let child: &u16 = &*again; first += 1; *child + first }",
            "fn value(input: u16) -> u16 { let mut slot = input; let first_holder = (&mut slot,); let first = first_holder.0; let second_holder = (first,); let moved = second_holder.0; let child: &u16 = &*moved; let copied = *child; slot += 1; copied + slot }",
            "fn value(input: u16) -> u16 { let mut first = input; let mut second = input + 1; let mut unrelated = input + 2; let mut holder = (&mut first,); holder.0 = &mut second; let moved = holder.0; let child: &u16 = &*moved; unrelated += 1; *child + unrelated }",
            "fn value(input: u16) -> u16 { let mut first = input; let mut second = input + 1; let mut holder = (&mut first,); holder.0 = &mut second; let moved = holder.0; let child: &u16 = &*moved; let copied = *child; second += 1; copied + second }",
            "fn value(input: u16, choose: bool) -> u16 { let mut first = input; let mut second = input + 1; let mut third = input + 2; let mut unrelated = input + 3; let mut holder = (&mut first,); holder.0 = if choose { &mut second } else { &mut third }; let moved = holder.0; let child: &u16 = &*moved; unrelated += 1; *child + unrelated }",
            "fn value(input: u16, choose: bool) -> u16 { let mut first = input; let mut second = input + 1; let mut third = input + 2; let mut holder = (&mut first,); holder.0 = if choose { &mut second } else { &mut third }; let moved = holder.0; let child: &u16 = &*moved; let copied = *child; second += 1; third += 1; copied + second + third }",
            "fn value(input: u16) -> u16 { let mut first = input; let mut second = input + 1; let mut third = input + 2; let mut unrelated = input + 3; let mut holder = (&mut first,); holder.0 = &mut second; holder.0 = &mut third; let moved = holder.0; let child: &u16 = &*moved; unrelated += 1; *child + unrelated }",
            "fn value(input: u16) -> u16 { let mut first = input; let mut second = input + 1; let mut third = input + 2; let mut holder = (&mut first,); holder.0 = &mut second; holder.0 = &mut third; let moved = holder.0; let child: &u16 = &*moved; let copied = *child; first += 1; second += 1; third += 1; copied + first + second + third }",
        ] {
            analyze(accepted).unwrap();
        }
    }

    #[test]
    fn runtime_function_return_references_outlive_local_storage() {
        fn analyze(source: &str) -> Result<usize, CodegenError> {
            let module = Parser::new(source).parse_module::<1, 8>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            let body = function.parse_body::<8>().unwrap();
            let mut facts = RuntimeBodyFacts::EMPTY;
            preanalyze_runtime_body_declarations::<_, 8, 32>(
                &function,
                &NoConstants,
                &body,
                "&u16",
                function.body_expression_span.start,
                &mut facts,
            )
        }

        for rejected in [
            "fn value(input: &u16) -> &u16 { let local = *input; &local }",
            "fn value(input: &u16) -> &u16 { let local = *input; return &local; }",
            "fn value(input: &u16, choose: bool) -> &u16 { let local = *input; if choose { return &local; } input }",
            "fn value(input: &u16, choose: bool) -> &u16 { let local = *input; let mut selected: &u16 = &local; if choose { selected = input; } selected }",
            "fn value(input: &u16) -> &u16 { let local = *input; let source: &u16 = &local; let returned = source; returned }",
            "fn value(input: &u16) -> &u16 { let local = *input; let holder = (&local,); holder.0 }",
            "fn value(input: &u16, choose: bool) -> &u16 { let local = *input; let mut holder = (input,); holder.0 = if choose { input } else { &local }; holder.0 }",
            "fn value(input: &u16, choose: bool) -> &u16 { let local = *input; let holder = (if choose { input } else { &local },); holder.0 }",
            "fn value(input: &u16, first: bool, second: bool) -> &u16 { let local = *input; let holder = (if first { input } else if second { &local } else { input },); holder.0 }",
            "fn value(input: &u16, choose: bool) -> &u16 { let local = *input; let mut holder = (input,); if choose { holder.0 = &local; } else { holder.0 = input; } holder.0 }",
            "fn value(input: &u16) -> &u16 { let local = *input; let mut holder = (input,); holder.0 = input; holder.0 = &local; holder.0 }",
            "fn value(input: &u16) -> &u16 { let local = *input; let mut holder = (&local,); holder.0 = input; holder.0 }",
            "fn value(input: &u16, choose: bool) -> &u16 { let local = *input; let mut holder = (&local,); holder.0 = if choose { input } else { &*input }; holder.0 }",
            "fn value(input: &u16, repeat: bool) -> &u16 { let local = *input; let mut holder = (input,); while repeat { holder.0 = &local; break; } holder.0 }",
            "fn value(input: &u16, repeat: bool) -> &u16 { let local = *input; let mut holder = (input,); while repeat { holder.0 = &local; holder.0 = input; break; } holder.0 }",
            "fn value(input: &u16) -> &u16 { let local = *input; let holder = (&local,); let moved = holder.0; moved }",
            "fn value(input: &u16, choose: bool) -> &u16 { let local = *input; let holder = (if choose { input } else { &local },); let moved = holder.0; moved }",
            "fn value(input: &u16, choose: bool) -> &u16 { let local = *input; let mut holder = (input,); if choose { holder.0 = &local; } else { holder.0 = input; } let moved = holder.0; moved }",
        ] {
            match analyze(rejected) {
                Err(error) => assert_eq!(
                    error.kind,
                    CodegenErrorKind::RuntimeReferenceOutlivesFunction,
                    "{rejected}"
                ),
                Ok(_) => panic!("expected outlives failure: {rejected}"),
            }
        }

        for accepted in [
            "fn value(input: &u16) -> &u16 { input }",
            "fn value(input: &u16) -> &u16 { let returned: &u16 = &*input; returned }",
            "fn value(input: &u16) -> &u16 { let local = *input; let mut selected: &u16 = &local; selected = input; selected }",
            "fn value(input: &mut u16) -> &u16 { let moved = input; let returned: &u16 = &*moved; returned }",
            "fn value(input: &u16) -> &u16 { let returned = input; returned }",
            "fn value(input: &u16) -> &u16 { let first = input; let second = first; second }",
            "fn value(input: &u16) -> &u16 { let holder = (input,); holder.0 }",
            "fn value(input: &u16, choose: bool) -> &u16 { let mut holder = (input,); holder.0 = if choose { input } else { &*input }; holder.0 }",
            "fn value(input: &u16, choose: bool) -> &u16 { let holder = (if choose { input } else { &*input },); holder.0 }",
            "fn value(input: &u16, choose: bool) -> &u16 { let local = *input; let holder = (if choose { input } else { &*input }, &local); holder.0 }",
            "fn value(input: &u16, choose: bool) -> &u16 { let local = *input; let holder = (&local, if choose { input } else { &*input }); holder.1 }",
            "fn value(input: &u16, first: bool, second: bool) -> &u16 { let holder = (if first { input } else if second { &*input } else { input },); holder.0 }",
            "fn value(input: &u16, choose: bool) -> &u16 { let mut holder = (input,); if choose { holder.0 = &*input; } else { holder.0 = input; } holder.0 }",
            "fn value(input: &u16) -> &u16 { let mut holder = (input,); holder.0 = &*input; holder.0 = input; holder.0 }",
            "fn value(input: &u16, repeat: bool) -> &u16 { let mut holder = (input,); while repeat { holder.0 = &*input; break; } holder.0 }",
            "fn value(input: &u16, repeat: bool) -> &u16 { let local = *input; let mut holder = (input,); while repeat { break; holder.0 = &local; } holder.0 }",
            "fn value(input: &u16) -> &u16 { let holder = (input,); let moved = holder.0; moved }",
            "fn value(input: &u16, choose: bool) -> &u16 { let holder = (if choose { input } else { &*input },); let moved = holder.0; moved }",
            "fn value(input: &u16, choose: bool) -> &u16 { let mut holder = (input,); if choose { holder.0 = &*input; } else { holder.0 = input; } let moved = holder.0; moved }",
            "fn value(input: &u16, repeat: bool) -> &u16 { let local = *input; let mut holder = (input,); while repeat { break; holder.0 = &local; } let moved = holder.0; moved }",
        ] {
            analyze(accepted).unwrap_or_else(|error| panic!("{accepted}: {error:?}"));
        }
    }

    #[test]
    fn runtime_function_return_outlives_follow_identity_call_arguments() {
        fn analyze(source: &str) -> Result<usize, CodegenError> {
            let module = Parser::new(source).parse_module::<1, 8>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            let body = function.parse_body::<8>().unwrap();
            let mut facts = RuntimeBodyFacts::EMPTY;
            preanalyze_runtime_body_declarations::<_, 8, 32>(
                &function,
                &MutableReferenceCallResolver,
                &body,
                "&mut u16",
                function.body_expression_span.start,
                &mut facts,
            )
        }

        for rejected in [
            "fn value(input: &mut u16, choose: bool) -> &mut u16 { let mut local = *input; if choose { return identity(&mut local); } input }",
            "fn value(input: &mut u16, choose: bool) -> &mut u16 { let mut local = *input; if choose { let returned = identity(&mut local); return returned; } input }",
            "fn value(input: &mut u16, choose: bool) -> &mut u16 { let mut local = *input; let holder = (if choose { &mut *input } else { &mut local },); identity(holder.0) }",
            "fn value(input: &mut u16, choose: bool) -> &mut u16 { let mut local = *input; let holder = (if choose { &mut *input } else { &mut local },); let returned = identity(holder.0); returned }",
        ] {
            assert_eq!(
                analyze(rejected).unwrap_err().kind,
                CodegenErrorKind::RuntimeReferenceOutlivesFunction
            );
        }
        for accepted in [
            "fn value(input: &mut u16) -> &mut u16 { identity(input) }",
            "fn value(input: &mut u16) -> &mut u16 { let returned = identity(input); returned }",
            "fn value(input: &mut u16, choose: bool) -> &mut u16 { let holder = (if choose { &mut *input } else { &mut *input },); identity(holder.0) }",
            "fn value(input: &mut u16, choose: bool) -> &mut u16 { let holder = (if choose { &mut *input } else { &mut *input },); let returned = identity(holder.0); returned }",
        ] {
            analyze(accepted).unwrap();
        }
    }

    #[test]
    fn runtime_function_return_outlives_follow_shared_call_arguments() {
        fn analyze(source: &str) -> Result<usize, CodegenError> {
            let module = Parser::new(source).parse_module::<1, 8>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            let body = function.parse_body::<8>().unwrap();
            let mut facts = RuntimeBodyFacts::EMPTY;
            preanalyze_runtime_body_declarations::<_, 8, 24>(
                &function,
                &MutableReferenceCallResolver,
                &body,
                "&u16",
                function.body_expression_span.start,
                &mut facts,
            )
        }

        analyze("fn value(input: &u16) -> &u16 { shared_identity(input) }").unwrap();
        analyze("fn value(first: &u16, second: &u16, choose: bool) -> &u16 { shared_identity(if choose { first } else { second }) }").unwrap();
        assert_eq!(
            analyze(
                "fn value(input: &u16) -> &u16 { let local = *input; shared_identity(&local) }"
            )
            .unwrap_err()
            .kind,
            CodegenErrorKind::RuntimeReferenceOutlivesFunction
        );
        assert_eq!(
            analyze("fn value(input: &u16, choose: bool) -> &u16 { let local = *input; shared_identity(if choose { input } else { &local }) }")
                .unwrap_err()
                .kind,
            CodegenErrorKind::RuntimeReferenceOutlivesFunction
        );
    }

    #[test]
    fn runtime_function_return_outlives_follow_shared_children_of_call_results() {
        fn analyze(source: &str) -> Result<usize, CodegenError> {
            let module = Parser::new(source).parse_module::<1, 8>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            let body = function.parse_body::<8>().unwrap();
            let mut facts = RuntimeBodyFacts::EMPTY;
            preanalyze_runtime_body_declarations::<_, 8, 40>(
                &function,
                &MutableReferenceCallResolver,
                &body,
                "&u16",
                function.body_expression_span.start,
                &mut facts,
            )
        }

        for source in [
            "fn value(input: &mut u16) -> &u16 { let returned: &mut u16 = identity(input); let child: &u16 = &*returned; child }",
            "fn value(input: &mut u16, choose: bool) -> &u16 { let returned: &mut u16 = choose(input, choose); let child: &u16 = &*returned; child }",
            "fn value(first: &mut u16, second: &mut u16, choose: bool) -> &u16 { let returned: &mut u16 = forward(if choose { first } else { second }); let child: &u16 = &*returned; child }",
            "fn value(input: &mut u16) -> &u16 { let returned: &mut u16 = identity(input); let child: &u16 = &*returned; return child; }",
            "fn value(input: &mut u16, choose: bool) -> &u16 { let returned: &mut u16 = choose(input, choose); let child: &u16 = &*returned; if choose { return child; } child }",
            "fn value(input: &mut u16) -> &u16 { loop { let returned: &mut u16 = identity(input); let child: &u16 = &*returned; return child; } }",
            "fn value(input: &mut u16, choose: bool) -> &u16 { loop { let returned: &mut u16 = choose(input, choose); let child: &u16 = &*returned; if choose { return child; } return child; } }",
            "fn value(first: &mut u16, second: &mut u16) -> &u16 { let returned: &mut u16 = tuple_field_assign(first, second); let child: &u16 = &*returned; child }",
            "fn value(first: &mut u16, second: &mut u16, choose: bool) -> &u16 { let returned: &mut u16 = branch_tuple_field_assign(first, second, choose); let child: &u16 = &*returned; child }",
            "fn value(first: &mut u16, second: &mut u16) -> &u16 { let returned: &mut u16 = tuple_field_assign(first, second); let child: &u16 = &*returned; return child; }",
            "fn value(first: &mut u16, second: &mut u16, choose: bool) -> &u16 { let returned: &mut u16 = branch_tuple_field_assign(first, second, choose); let child: &u16 = &*returned; if choose { return child; } child }",
            "fn value(first: &mut u16, second: &mut u16) -> &u16 { loop { let returned: &mut u16 = tuple_field_assign(first, second); let child: &u16 = &*returned; return child; } }",
            "fn value(first: &mut u16, second: &mut u16, choose: bool) -> &u16 { loop { let returned: &mut u16 = branch_tuple_field_assign(first, second, choose); let child: &u16 = &*returned; if choose { return child; } return child; } }",
            "fn value(first: &mut u16, second: &mut u16) -> &u16 { loop { loop { let returned: &mut u16 = tuple_field_assign(first, second); let child: &u16 = &*returned; return child; } } }",
            "fn value(first: &mut u16, second: &mut u16, choose: bool) -> &u16 { loop { loop { let returned: &mut u16 = branch_tuple_field_assign(first, second, choose); let child: &u16 = &*returned; if choose { return child; } return child; } } }",
        ] {
            analyze(source).unwrap();
        }
        for source in [
            "fn value(input: &mut u16) -> &u16 { let mut local = *input; let returned: &mut u16 = identity(&mut local); let child: &u16 = &*returned; child }",
            "fn value(input: &mut u16, choose: bool) -> &u16 { let mut local = *input; let returned: &mut u16 = choose(&mut local, choose); let child: &u16 = &*returned; child }",
            "fn value(input: &mut u16, choose: bool) -> &u16 { let mut local = *input; let returned: &mut u16 = forward(if choose { input } else { &mut local }); let child: &u16 = &*returned; child }",
            "fn value(input: &mut u16) -> &u16 { let mut local = *input; let returned: &mut u16 = identity(&mut local); let child: &u16 = &*returned; return child; }",
            "fn value(input: &mut u16, choose: bool) -> &u16 { let mut local = *input; let returned: &mut u16 = choose(&mut local, choose); let child: &u16 = &*returned; if choose { return child; } child }",
            "fn value(input: &mut u16) -> &u16 { loop { let mut local = *input; let returned: &mut u16 = identity(&mut local); let child: &u16 = &*returned; return child; } }",
            "fn value(input: &mut u16, choose: bool) -> &u16 { loop { let mut local = *input; let returned: &mut u16 = choose(&mut local, choose); let child: &u16 = &*returned; if choose { return child; } return child; } }",
            "fn value(first: &mut u16, second: &mut u16) -> &u16 { let mut local = *second; let returned: &mut u16 = tuple_field_assign(first, &mut local); let child: &u16 = &*returned; child }",
            "fn value(first: &mut u16, second: &mut u16) -> &u16 { let mut local = *first; let returned: &mut u16 = tuple_field_assign(&mut local, second); let child: &u16 = &*returned; child }",
            "fn value(first: &mut u16, second: &mut u16, choose: bool) -> &u16 { let mut local = *second; let returned: &mut u16 = branch_tuple_field_assign(first, &mut local, choose); let child: &u16 = &*returned; child }",
            "fn value(first: &mut u16, second: &mut u16) -> &u16 { let mut local = *second; let returned: &mut u16 = tuple_field_assign(first, &mut local); let child: &u16 = &*returned; return child; }",
            "fn value(first: &mut u16, second: &mut u16, choose: bool) -> &u16 { let mut local = *second; let returned: &mut u16 = branch_tuple_field_assign(first, &mut local, choose); let child: &u16 = &*returned; if choose { return child; } child }",
            "fn value(first: &mut u16, second: &mut u16) -> &u16 { loop { let mut local = *second; let returned: &mut u16 = tuple_field_assign(first, &mut local); let child: &u16 = &*returned; return child; } }",
            "fn value(first: &mut u16, second: &mut u16, choose: bool) -> &u16 { loop { let mut local = *second; let returned: &mut u16 = branch_tuple_field_assign(first, &mut local, choose); let child: &u16 = &*returned; if choose { return child; } return child; } }",
            "fn value(first: &mut u16, second: &mut u16) -> &u16 { loop { loop { let mut local = *second; let returned: &mut u16 = tuple_field_assign(first, &mut local); let child: &u16 = &*returned; return child; } } }",
            "fn value(first: &mut u16, second: &mut u16, choose: bool) -> &u16 { loop { loop { let mut local = *second; let returned: &mut u16 = branch_tuple_field_assign(first, &mut local, choose); let child: &u16 = &*returned; if choose { return child; } return child; } } }",
        ] {
            assert_eq!(
                analyze(source).unwrap_err().kind,
                CodegenErrorKind::RuntimeReferenceOutlivesFunction
            );
        }
        analyze("fn value(first: &mut u16, second: &mut u16, choose: bool) -> &u16 { loop { loop { let returned: &mut u16 = branch_tuple_field_assign(first, second, choose); let child: &u16 = &*returned; if choose { return child; } } } }")
            .unwrap();
    }

    #[test]
    fn runtime_function_return_outlives_follow_loop_conditional_terminals() {
        fn analyze(source: &str) -> Result<usize, CodegenError> {
            let module = Parser::new(source).parse_module::<1, 8>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            let body = function.parse_body::<8>().unwrap();
            let mut facts = RuntimeBodyFacts::EMPTY;
            preanalyze_runtime_body_declarations::<_, 8, 48>(
                &function,
                &MutableReferenceCallResolver,
                &body,
                "&mut u16",
                function.body_expression_span.start,
                &mut facts,
            )
        }

        assert_eq!(
            analyze("fn value(input: &mut u16, choose: bool) -> &mut u16 { loop { if choose { let mut local = *input; return identity(&mut local); } else { return input; } } }")
                .unwrap_err()
                .kind,
            CodegenErrorKind::RuntimeReferenceOutlivesFunction
        );
        analyze("fn value(input: &mut u16, choose: bool) -> &mut u16 { loop { if choose { return identity(input); } else { return input; } } }").unwrap();
    }

    #[test]
    fn runtime_function_return_outlives_follow_nested_loop_returns() {
        fn analyze(source: &str) -> Result<usize, CodegenError> {
            let module = Parser::new(source).parse_module::<1, 8>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            let body = function.parse_body::<8>().unwrap();
            let mut facts = RuntimeBodyFacts::EMPTY;
            preanalyze_runtime_body_declarations::<_, 8, 48>(
                &function,
                &MutableReferenceCallResolver,
                &body,
                "&mut u16",
                function.body_expression_span.start,
                &mut facts,
            )
        }

        for rejected in [
            "fn value(input: &mut u16, choose: bool) -> &mut u16 { loop { loop { let mut local = *input; return identity(&mut local); } } }",
            "fn value(input: &mut u16, choose: bool) -> &mut u16 { loop { loop { let mut local = *input; if choose { return identity(&mut local); } } } }",
        ] {
            assert_eq!(
                analyze(rejected).unwrap_err().kind,
                CodegenErrorKind::RuntimeReferenceOutlivesFunction
            );
        }
        for accepted in [
            "fn value(input: &mut u16) -> &mut u16 { loop { loop { return identity(input); } } }",
            "fn value(input: &mut u16, choose: bool) -> &mut u16 { loop { loop { if choose { return identity(input); } } } }",
        ] {
            analyze(accepted).unwrap_or_else(|error| panic!("{accepted}: {error:?}"));
        }
    }

    #[test]
    fn runtime_reference_moves_preserve_conditional_loan_origins() {
        fn analyze(source: &str) -> Result<usize, CodegenError> {
            let module = Parser::new(source).parse_module::<1, 8>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            let body = function.parse_body::<8>().unwrap();
            let mut facts = RuntimeBodyFacts::EMPTY;
            preanalyze_runtime_body_declarations::<_, 8, 32>(
                &function,
                &NoConstants,
                &body,
                "u16",
                function.body_expression_span.start,
                &mut facts,
            )
        }

        for rejected in [
            "fn value(first: &mut u16, second: &mut u16, choose: bool) -> u16 { let parent: &mut u16 = if choose { &mut *first } else { &mut *second }; let moved = parent; let child: &u16 = &*moved; let changed: &mut u16 = &mut *first; *changed += 1; *child }",
            "fn value(first: &mut u16, second: &mut u16, choose: bool) -> u16 { let parent: &mut u16 = if choose { &mut *first } else { &mut *second }; let moved = parent; let child: &mut u16 = &mut *moved; let changed: &mut u16 = &mut *second; *changed += 1; *child }",
        ] {
            assert_eq!(
                analyze(rejected).unwrap_err().kind,
                CodegenErrorKind::RuntimeBorrowConflict
            );
        }

        for accepted in [
            "fn value(first: &mut u16, second: &mut u16, third: &mut u16, choose: bool) -> u16 { let parent: &mut u16 = if choose { &mut *first } else { &mut *second }; let moved = parent; let child: &u16 = &*moved; let changed: &mut u16 = &mut *third; *changed += 1; *child }",
            "fn value(first: &mut u16, second: &mut u16, choose: bool) -> u16 { let parent: &mut u16 = if choose { &mut *first } else { &mut *second }; let moved = parent; let child: &u16 = &*moved; let copied = *child; let changed: &mut u16 = &mut *first; *changed += 1; copied + *changed }",
        ] {
            analyze(accepted).unwrap();
        }
    }

    #[test]
    fn runtime_reference_move_chains_preserve_conditional_loan_origins() {
        fn analyze(source: &str) -> Result<usize, CodegenError> {
            let module = Parser::new(source).parse_module::<1, 8>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            let body = function.parse_body::<8>().unwrap();
            let mut facts = RuntimeBodyFacts::EMPTY;
            preanalyze_runtime_body_declarations::<_, 8, 32>(
                &function,
                &NoConstants,
                &body,
                "u16",
                function.body_expression_span.start,
                &mut facts,
            )
        }

        for rejected in [
            "fn value(first: &mut u16, second: &mut u16, choose: bool) -> u16 { let parent: &mut u16 = if choose { &mut *first } else { &mut *second }; let first_move = parent; let second_move = first_move; let child: &u16 = &*second_move; let changed: &mut u16 = &mut *first; *changed += 1; *child }",
            "fn value(first: &mut u16, second: &mut u16, choose: bool) -> u16 { let parent: &mut u16 = if choose { &mut *first } else { &mut *second }; let first_move = parent; let second_move = first_move; let third_move = second_move; let child: &mut u16 = &mut *third_move; let changed: &mut u16 = &mut *second; *changed += 1; *child }",
        ] {
            assert_eq!(
                analyze(rejected).unwrap_err().kind,
                CodegenErrorKind::RuntimeBorrowConflict
            );
        }

        for accepted in [
            "fn value(first: &mut u16, second: &mut u16, third: &mut u16, choose: bool) -> u16 { let parent: &mut u16 = if choose { &mut *first } else { &mut *second }; let first_move = parent; let second_move = first_move; let child: &u16 = &*second_move; let changed: &mut u16 = &mut *third; *changed += 1; *child }",
            "fn value(first: &mut u16, second: &mut u16, choose: bool) -> u16 { let parent: &mut u16 = if choose { &mut *first } else { &mut *second }; let first_move = parent; let second_move = first_move; let child: &u16 = &*second_move; let copied = *child; let changed: &mut u16 = &mut *first; *changed += 1; copied + *changed }",
        ] {
            analyze(accepted).unwrap();
        }
    }

    #[test]
    fn runtime_expected_mutable_reference_binding_is_an_implicit_reborrow() {
        let rejected = "fn value(input: u16) -> u16 { let mut slot = input; let parent: &mut u16 = &mut slot; let child: &mut u16 = parent; let parent_value = *parent; let child_value = *child; parent_value + child_value }";
        let module = Parser::new(rejected).parse_module::<1, 8>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<8>().unwrap();
        let mut facts = RuntimeBodyFacts::EMPTY;
        assert_eq!(
            preanalyze_runtime_body_declarations::<_, 8, 32>(
                &function,
                &NoConstants,
                &body,
                "u16",
                function.body_expression_span.start,
                &mut facts,
            )
            .unwrap_err()
            .kind,
            CodegenErrorKind::RuntimeBorrowConflict
        );

        let accepted = "fn value(input: u16) -> u16 { let mut slot = input; let parent: &mut u16 = &mut slot; let child: &mut u16 = parent; let child_value = *child; let parent_value = *parent; parent_value + child_value }";
        let module = Parser::new(accepted).parse_module::<1, 8>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<8>().unwrap();
        let mut facts = RuntimeBodyFacts::EMPTY;
        preanalyze_runtime_body_declarations::<_, 8, 32>(
            &function,
            &NoConstants,
            &body,
            "u16",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();

        let moved = "fn value(input: u16) -> u16 { let mut slot = input; let parent: &mut u16 = &mut slot; let child = parent; let parent_value = *parent; *child + parent_value }";
        let module = Parser::new(moved).parse_module::<1, 8>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<8>().unwrap();
        let mut facts = RuntimeBodyFacts::EMPTY;
        assert_eq!(
            preanalyze_runtime_body_declarations::<_, 8, 32>(
                &function,
                &NoConstants,
                &body,
                "u16",
                function.body_expression_span.start,
                &mut facts,
            )
            .unwrap_err()
            .kind,
            CodegenErrorKind::RuntimeUseAfterMove
        );
    }

    #[test]
    fn runtime_shared_child_blocks_only_live_parent_mutation() {
        let rejected = "fn value(input: u16) -> u16 { let mut slot = input; let parent: &mut u16 = &mut slot; let child: &u16 = &*parent; *parent += 1; *child }";
        let module = Parser::new(rejected).parse_module::<1, 8>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<8>().unwrap();
        let mut facts = RuntimeBodyFacts::EMPTY;
        assert_eq!(
            preanalyze_runtime_body_declarations::<_, 8, 32>(
                &function,
                &NoConstants,
                &body,
                "u16",
                function.body_expression_span.start,
                &mut facts,
            )
            .unwrap_err()
            .kind,
            CodegenErrorKind::RuntimeBorrowConflict
        );

        for accepted in [
            "fn value(input: u16) -> u16 { let mut slot = input; let parent: &mut u16 = &mut slot; let child: &u16 = &*parent; let copied = *child; *parent += 1; copied + *parent }",
            "fn value(input: u16) -> u16 { let mut slot = input; let parent: &mut u16 = &mut slot; let child: &u16 = &*parent; let parent_value = *parent; let child_value = *child; parent_value + child_value }",
        ] {
            let module = Parser::new(accepted).parse_module::<1, 8>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            let body = function.parse_body::<8>().unwrap();
            let mut facts = RuntimeBodyFacts::EMPTY;
            preanalyze_runtime_body_declarations::<_, 8, 32>(
                &function,
                &NoConstants,
                &body,
                "u16",
                function.body_expression_span.start,
                &mut facts,
            )
            .unwrap();
        }
    }

    #[test]
    fn runtime_reference_reassignment_replaces_the_active_loan_generation() {
        for accepted in [
            "fn value(first: &mut u16, second: &mut u16) -> u16 { let mut parent: &mut u16 = &mut *first; let old = *parent; parent = &mut *second; *parent += 1; old + *parent }",
            "fn value(first: &mut u16, second: &mut u16) -> u16 { let mut parent: &mut u16 = &mut *first; let child: &u16 = &*parent; parent = &mut *second; *child }",
        ] {
            let module = Parser::new(accepted).parse_module::<1, 8>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            let body = function.parse_body::<8>().unwrap();
            let mut facts = RuntimeBodyFacts::EMPTY;
            preanalyze_runtime_body_declarations::<_, 8, 32>(
                &function,
                &NoConstants,
                &body,
                "u16",
                function.body_expression_span.start,
                &mut facts,
            )
            .unwrap();
            assert!(
                (0..facts.effect_count)
                    .filter_map(|index| facts.direct_assigned_loan_fact(index))
                    .any(|loan| loan.borrower == RuntimeLocalId(0))
            );
        }

        let rejected = "fn value(first: &mut u16, second: &mut u16) -> u16 { let mut parent: &mut u16 = &mut *first; parent = &mut *second; let child: &u16 = &*parent; *parent += 1; *child }";
        let module = Parser::new(rejected).parse_module::<1, 8>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<8>().unwrap();
        let mut facts = RuntimeBodyFacts::EMPTY;
        assert_eq!(
            preanalyze_runtime_body_declarations::<_, 8, 32>(
                &function,
                &NoConstants,
                &body,
                "u16",
                function.body_expression_span.start,
                &mut facts,
            )
            .unwrap_err()
            .kind,
            CodegenErrorKind::RuntimeBorrowConflict
        );
    }

    #[test]
    fn runtime_expected_reference_assignment_is_an_implicit_reborrow() {
        let accepted = "fn value(first: &mut u16, second: &mut u16) -> u16 { let parent: &mut u16 = &mut *first; let mut child: &mut u16 = &mut *second; child = parent; *child += 1; *parent }";
        let module = Parser::new(accepted).parse_module::<1, 8>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<8>().unwrap();
        let mut facts = RuntimeBodyFacts::EMPTY;
        preanalyze_runtime_body_declarations::<_, 8, 32>(
            &function,
            &NoConstants,
            &body,
            "u16",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();
        assert!(
            facts.effects[..facts.effect_count]
                .iter()
                .flatten()
                .any(|effect| effect.kind == RuntimePlaceEffectKind::MutableBorrow)
        );

        let rejected = "fn value(first: &mut u16, second: &mut u16) -> u16 { let parent: &mut u16 = &mut *first; let mut child: &mut u16 = &mut *second; child = parent; let before = *parent; *child += 1; before }";
        let module = Parser::new(rejected).parse_module::<1, 8>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<8>().unwrap();
        let mut facts = RuntimeBodyFacts::EMPTY;
        assert_eq!(
            preanalyze_runtime_body_declarations::<_, 8, 32>(
                &function,
                &NoConstants,
                &body,
                "u16",
                function.body_expression_span.start,
                &mut facts,
            )
            .unwrap_err()
            .kind,
            CodegenErrorKind::RuntimeBorrowConflict
        );
    }

    #[test]
    fn runtime_conditional_reference_generations_join_by_reaching_definition() {
        let rejected = "fn value(first: &mut u16, second: &mut u16, choose: bool) -> u16 { let mut parent: &mut u16 = &mut *first; if choose { parent = &mut *second; } let changed: &mut u16 = &mut *first; *changed += 1; *parent }";
        let module = Parser::new(rejected).parse_module::<1, 8>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<8>().unwrap();
        let mut facts = RuntimeBodyFacts::EMPTY;
        assert_eq!(
            preanalyze_runtime_body_declarations::<_, 8, 32>(
                &function,
                &NoConstants,
                &body,
                "u16",
                function.body_expression_span.start,
                &mut facts,
            )
            .unwrap_err()
            .kind,
            CodegenErrorKind::RuntimeBorrowConflict
        );

        let accepted = "fn value(first: &mut u16, second: &mut u16, third: &mut u16, choose: bool) -> u16 { let mut parent: &mut u16 = &mut *first; if choose { parent = &mut *second; } else { parent = &mut *third; } let changed: &mut u16 = &mut *first; *changed += 1; *parent }";
        let module = Parser::new(accepted).parse_module::<1, 8>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<8>().unwrap();
        let mut facts = RuntimeBodyFacts::EMPTY;
        preanalyze_runtime_body_declarations::<_, 8, 32>(
            &function,
            &NoConstants,
            &body,
            "u16",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();

        let ambiguous_child = "fn value(first: &mut u16, second: &mut u16, choose: bool) -> u16 { let mut parent: &mut u16 = &mut *first; if choose { parent = &mut *second; } let child: &u16 = &*parent; *child }";
        let module = Parser::new(ambiguous_child).parse_module::<1, 8>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<8>().unwrap();
        let mut facts = RuntimeBodyFacts::EMPTY;
        preanalyze_runtime_body_declarations::<_, 8, 32>(
            &function,
            &NoConstants,
            &body,
            "u16",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();

        let child_conflict = "fn value(first: &mut u16, second: &mut u16, choose: bool) -> u16 { let mut parent: &mut u16 = &mut *first; if choose { parent = &mut *second; } let child: &u16 = &*parent; let changed: &mut u16 = &mut *first; *changed += 1; *child }";
        let module = Parser::new(child_conflict).parse_module::<1, 8>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<8>().unwrap();
        let mut facts = RuntimeBodyFacts::EMPTY;
        assert_eq!(
            preanalyze_runtime_body_declarations::<_, 8, 32>(
                &function,
                &NoConstants,
                &body,
                "u16",
                function.body_expression_span.start,
                &mut facts,
            )
            .unwrap_err()
            .kind,
            CodegenErrorKind::RuntimeBorrowConflict
        );
    }

    #[test]
    fn runtime_loop_exit_reference_generations_follow_cfg_paths() {
        let rejected = "fn value(first: &mut u16, second: &mut u16, choose: bool) -> u16 { let mut parent: &mut u16 = &mut *first; while choose { parent = &mut *second; break; } let changed: &mut u16 = &mut *first; *changed += 1; *parent }";
        let module = Parser::new(rejected).parse_module::<1, 8>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<8>().unwrap();
        let mut facts = RuntimeBodyFacts::EMPTY;
        assert_eq!(
            preanalyze_runtime_body_declarations::<_, 8, 32>(
                &function,
                &NoConstants,
                &body,
                "u16",
                function.body_expression_span.start,
                &mut facts,
            )
            .unwrap_err()
            .kind,
            CodegenErrorKind::RuntimeBorrowConflict
        );

        let accepted = "fn value(first: &mut u16, second: &mut u16) -> u16 { let mut parent: &mut u16 = &mut *first; loop { parent = &mut *second; break; } let changed: &mut u16 = &mut *first; *changed += 1; *parent }";
        let module = Parser::new(accepted).parse_module::<1, 8>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<8>().unwrap();
        let mut facts = RuntimeBodyFacts::EMPTY;
        preanalyze_runtime_body_declarations::<_, 8, 32>(
            &function,
            &NoConstants,
            &body,
            "u16",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();

        let repeated_rejected = "fn value(first: &mut u16, second: &mut u16, limit: u16) -> u16 { let mut parent: &mut u16 = &mut *first; let mut index: u16 = 0; while index < limit { parent = &mut *second; index += 1; } let changed: &mut u16 = &mut *first; *changed += 1; *parent }";
        let module = Parser::new(repeated_rejected)
            .parse_module::<1, 8>()
            .unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<8>().unwrap();
        let mut facts = RuntimeBodyFacts::EMPTY;
        assert_eq!(
            preanalyze_runtime_body_declarations::<_, 8, 32>(
                &function,
                &NoConstants,
                &body,
                "u16",
                function.body_expression_span.start,
                &mut facts,
            )
            .unwrap_err()
            .kind,
            CodegenErrorKind::RuntimeBorrowConflict
        );

        let repeated_accepted = "fn value(first: &mut u16, second: &mut u16, stop: bool) -> u16 { let mut parent: &mut u16 = &mut *first; loop { parent = &mut *second; if stop { break; } } let changed: &mut u16 = &mut *first; *changed += 1; *parent }";
        let module = Parser::new(repeated_accepted)
            .parse_module::<1, 8>()
            .unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<8>().unwrap();
        let mut facts = RuntimeBodyFacts::EMPTY;
        preanalyze_runtime_body_declarations::<_, 8, 32>(
            &function,
            &NoConstants,
            &body,
            "u16",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();
    }

    #[test]
    fn runtime_expression_conditional_reference_generations_follow_cfg_paths() {
        fn analyze(source: &str) -> Result<usize, CodegenError> {
            let module = Parser::new(source).parse_module::<1, 8>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            let body = function.parse_body::<8>().unwrap();
            let mut facts = RuntimeBodyFacts::EMPTY;
            preanalyze_runtime_body_declarations::<_, 8, 32>(
                &function,
                &MutableReferenceCallResolver,
                &body,
                "u16",
                function.body_expression_span.start,
                &mut facts,
            )
        }

        for source in [
            "fn value(first: &mut u16, second: &mut u16, choose: bool) -> u16 { let parent: &mut u16 = if choose { &mut *first } else { &mut *second }; let changed: &mut u16 = &mut *first; *changed += 1; *parent }",
            "fn value(first: &mut u16, second: &mut u16, choose: bool) -> u16 { let mut parent: &mut u16 = &mut *second; parent = if choose { &mut *first } else { &mut *second }; let changed: &mut u16 = &mut *first; *changed += 1; *parent }",
            "fn value(first: &mut u16, second: &mut u16, third: &mut u16, outer: bool, inner: bool) -> u16 { let parent: &mut u16 = if outer { if inner { &mut *first } else { &mut *second } } else { &mut *third }; let changed: &mut u16 = &mut *first; *changed += 1; *parent }",
        ] {
            assert_eq!(
                analyze(source).unwrap_err().kind,
                CodegenErrorKind::RuntimeBorrowConflict
            );
        }

        for source in [
            "fn value(first: &mut u16, second: &mut u16, third: &mut u16, choose: bool) -> u16 { let parent: &mut u16 = if choose { &mut *second } else { &mut *third }; let changed: &mut u16 = &mut *first; *changed += 1; *parent }",
            "fn value(first: &mut u16, second: &mut u16, third: &mut u16, choose: bool) -> u16 { let mut parent: &mut u16 = &mut *first; parent = if choose { &mut *second } else { &mut *third }; let changed: &mut u16 = &mut *first; *changed += 1; *parent }",
            "fn value(first: &mut u16, second: &mut u16, third: &mut u16, choose: bool) -> u16 { let parent: &mut u16 = if choose { &mut *first; &mut *second } else { &mut *first; &mut *third }; let changed: &mut u16 = &mut *first; *changed += 1; *parent }",
        ] {
            analyze(source).unwrap();
        }

        let projected_grandchild_live = "fn value(first: &mut u16, second: &mut u16) -> u16 { let pair = (&mut *first,); let child: &mut u16 = pair.0; let grandchild: &mut u16 = &mut *child; let competing: &mut u16 = &mut *first; *competing += 1; *grandchild }";
        assert_eq!(
            analyze(projected_grandchild_live).unwrap_err().kind,
            CodegenErrorKind::RuntimeBorrowConflict
        );
        analyze("fn value(first: &mut u16, second: &mut u16) -> u16 { let pair = (&mut *first,); let child: &mut u16 = pair.0; let grandchild: &mut u16 = &mut *child; *grandchild += 1; let restored: &mut u16 = &mut *first; *restored }").unwrap();

        let projected_call_assignment_live = "fn value(first: &mut u16, second: &mut u16) -> u16 { let pair = (&mut *first,); let mut child: &mut u16 = second; child = identity(pair.0); let competing: &mut u16 = &mut *first; *competing += 1; *child }";
        assert_eq!(
            analyze(projected_call_assignment_live).unwrap_err().kind,
            CodegenErrorKind::RuntimeBorrowConflict
        );
        analyze("fn value(first: &mut u16, second: &mut u16) -> u16 { let pair = (&mut *first,); let mut child: &mut u16 = second; child = identity(pair.0); *child += 1; let restored: &mut u16 = &mut *first; *restored }").unwrap();

        for source in [
            "fn value(first: &mut u16, second: &mut u16, third: &mut u16, choose: bool) -> u16 { let pair = (&mut *first, &mut *second); let mut child: &mut u16 = third; child = identity(if choose { pair.0 } else { pair.1 }); let competing: &mut u16 = &mut *first; *competing += 1; *child }",
            "fn value(first: &mut u16, second: &mut u16, third: &mut u16, choose: bool) -> u16 { let pair = (&mut *first, &mut *second); let mut child: &mut u16 = third; child = identity(if choose { pair.0 } else { pair.1 }); let competing: &mut u16 = &mut *second; *competing += 1; *child }",
        ] {
            assert_eq!(
                analyze(source).unwrap_err().kind,
                CodegenErrorKind::RuntimeBorrowConflict
            );
        }
        for source in [
            "fn value(first: &mut u16, second: &mut u16, third: &mut u16, choose: bool) -> u16 { let pair = (&mut *first, &mut *second); let mut child: &mut u16 = third; child = identity(if choose { pair.0 } else { pair.1 }); *child += 1; let restored: &mut u16 = &mut *first; *restored }",
            "fn value(first: &mut u16, second: &mut u16, third: &mut u16, choose: bool) -> u16 { let pair = (&mut *first, &mut *second); let mut child: &mut u16 = third; child = identity(if choose { pair.0 } else { pair.1 }); *child += 1; let restored: &mut u16 = &mut *second; *restored }",
        ] {
            analyze(source).unwrap();
        }

        let projected_shared_call_live = "fn value(first: &mut u16) -> u16 { let pair = (&mut *first,); let child: &mut u16 = &mut *pair.0; let observed = read(pair.0); observed + *child }";
        assert_eq!(
            analyze(projected_shared_call_live).unwrap_err().kind,
            CodegenErrorKind::RuntimeBorrowConflict
        );
        analyze("fn value(first: &mut u16) -> u16 { let pair = (&mut *first,); let child: &mut u16 = &mut *pair.0; let copied = *child; let observed = read(pair.0); copied + observed }").unwrap();

        let projected_mutable_call_live = "fn value(first: &mut u16) -> u16 { let pair = (&mut *first,); let child: &u16 = &*pair.0; touch(pair.0); *child }";
        assert_eq!(
            analyze(projected_mutable_call_live).unwrap_err().kind,
            CodegenErrorKind::RuntimeBorrowConflict
        );
        analyze("fn value(first: &mut u16) -> u16 { let pair = (&mut *first,); let child: &u16 = &*pair.0; let copied = *child; touch(pair.0); copied + *pair.0 }").unwrap();

        for source in [
            "fn value(first: &mut u16, second: &mut u16) -> u16 { let mut child: &u16 = &*second; child = first; let competing: &mut u16 = &mut *first; *competing += 1; *child }",
            "fn value(first: &mut u16, second: &mut u16) -> u16 { let pair = (&mut *first,); let mut child: &u16 = &*second; child = pair.0; let competing: &mut u16 = &mut *first; *competing += 1; *child }",
            "fn value(first: &mut u16, second: &mut u16) -> u16 { let mut child: &u16 = &*second; child = first; *first += 1; *child }",
            "fn value(first: &mut u16, second: &mut u16) -> u16 { let pair = (&mut *first,); let mut child: &u16 = &*second; child = pair.0; *first += 1; *child }",
        ] {
            assert_eq!(
                analyze(source).unwrap_err().kind,
                CodegenErrorKind::RuntimeBorrowConflict
            );
        }
        analyze("fn value(first: &mut u16, second: &mut u16) -> u16 { let pair = (&mut *first,); let mut child: &u16 = &*second; child = pair.0; let copied = *child; *first += 1; copied + *first }").unwrap();

        for source in [
            "fn value(first: &mut u16, second: &mut u16, third: &mut u16, choose: bool) -> u16 { let pair = (&mut *first, &mut *second); let mut child: &u16 = &*third; child = if choose { pair.0 } else { pair.1 }; let competing: &mut u16 = &mut *first; *competing += 1; *child }",
            "fn value(first: &mut u16, second: &mut u16, third: &mut u16, choose: bool) -> u16 { let pair = (&mut *first, &mut *second); let mut child: &u16 = &*third; child = if choose { pair.0 } else { pair.1 }; let competing: &mut u16 = &mut *second; *competing += 1; *child }",
            "fn value(first: &mut u16, second: &mut u16, third: &mut u16, choose: bool) -> u16 { let pair = (&mut *first, &mut *second); let mut child: &u16 = &*third; child = if choose { pair.0 } else { pair.1 }; *first += 1; *child }",
            "fn value(first: &mut u16, second: &mut u16, third: &mut u16, choose: bool) -> u16 { let pair = (&mut *first, &mut *second); let mut child: &u16 = &*third; child = if choose { pair.0 } else { pair.1 }; *second += 1; *child }",
        ] {
            assert_eq!(
                analyze(source).unwrap_err().kind,
                CodegenErrorKind::RuntimeBorrowConflict
            );
        }
        for source in [
            "fn value(first: &mut u16, second: &mut u16, third: &mut u16, choose: bool) -> u16 { let pair = (&mut *first, &mut *second); let mut child: &u16 = &*third; child = if choose { pair.0 } else { pair.1 }; let copied = *child; *first += 1; copied + *first }",
            "fn value(first: &mut u16, second: &mut u16, third: &mut u16, choose: bool) -> u16 { let pair = (&mut *first, &mut *second); let mut child: &u16 = &*third; child = if choose { pair.0 } else { pair.1 }; let copied = *child; *second += 1; copied + *second }",
        ] {
            analyze(source).unwrap();
        }

        for source in [
            "fn value(first: &mut u16, second: &mut u16, choose: bool) -> u16 { let mut parent: &mut u16 = &mut *first; if choose { parent = &mut *second; } let child: &u16 = &*parent; *first += 1; *child }",
            "fn value(first: &mut u16, second: &mut u16, choose: bool) -> u16 { let mut parent: &mut u16 = &mut *first; if choose { parent = &mut *second; } let child: &u16 = &*parent; *second += 1; *child }",
        ] {
            assert_eq!(
                analyze(source).unwrap_err().kind,
                CodegenErrorKind::RuntimeBorrowConflict
            );
        }
        for source in [
            "fn value(first: &mut u16, second: &mut u16, choose: bool) -> u16 { let mut parent: &mut u16 = &mut *first; if choose { parent = &mut *second; } let child: &u16 = &*parent; let copied = *child; *first += 1; copied + *first }",
            "fn value(first: &mut u16, second: &mut u16, choose: bool) -> u16 { let mut parent: &mut u16 = &mut *first; if choose { parent = &mut *second; } let child: &u16 = &*parent; let copied = *child; *second += 1; copied + *second }",
        ] {
            analyze(source).unwrap();
        }

        for source in [
            "fn value(first: &mut u16, second: &mut u16, choose: bool) -> u16 { let mut parent: &mut u16 = &mut *first; while choose { parent = &mut *second; break; } let child: &u16 = &*parent; *first += 1; *child }",
            "fn value(first: &mut u16, second: &mut u16, choose: bool) -> u16 { let mut parent: &mut u16 = &mut *first; while choose { parent = &mut *second; break; } let child: &u16 = &*parent; *second += 1; *child }",
        ] {
            assert_eq!(
                analyze(source).unwrap_err().kind,
                CodegenErrorKind::RuntimeBorrowConflict
            );
        }
        analyze("fn value(first: &mut u16, second: &mut u16, choose: bool) -> u16 { let mut parent: &mut u16 = &mut *first; while choose { parent = &mut *second; break; } let child: &u16 = &*parent; let copied = *child; *first += 1; *second += 1; copied + *first + *second }").unwrap();
    }

    #[test]
    fn runtime_conditional_reference_identifiers_use_expected_reborrow_context() {
        fn analyze(source: &str) -> Result<usize, CodegenError> {
            let module = Parser::new(source).parse_module::<1, 8>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            let body = function.parse_body::<8>().unwrap();
            let mut facts = RuntimeBodyFacts::EMPTY;
            preanalyze_runtime_body_declarations::<_, 8, 32>(
                &function,
                &NoConstants,
                &body,
                "u16",
                function.body_expression_span.start,
                &mut facts,
            )
        }

        for source in [
            "fn value(first: &mut u16, second: &mut u16, choose: bool) -> u16 { let first_parent: &mut u16 = &mut *first; let second_parent: &mut u16 = &mut *second; let child: &mut u16 = if choose { first_parent } else { second_parent }; let changed: &mut u16 = &mut *first; *changed += 1; *child }",
            "fn value(first: &mut u16, second: &mut u16, third: &mut u16, choose: bool) -> u16 { let first_parent: &mut u16 = &mut *first; let second_parent: &mut u16 = &mut *second; let mut child: &mut u16 = &mut *third; child = if choose { first_parent } else { second_parent }; let changed: &mut u16 = &mut *first; *changed += 1; *child }",
        ] {
            assert_eq!(
                analyze(source).unwrap_err().kind,
                CodegenErrorKind::RuntimeBorrowConflict
            );
        }

        for source in [
            "fn value(first: &mut u16, second: &mut u16, choose: bool) -> u16 { let parent: &mut u16 = &mut *first; let child: &mut u16 = if choose { parent } else { &mut *second }; *child += 1; *parent }",
            "fn value(first: &mut u16, second: &mut u16, choose: bool) -> u16 { let parent: &mut u16 = &mut *first; let mut child: &mut u16 = &mut *second; child = if choose { parent } else { &mut *second }; *child += 1; *parent }",
        ] {
            analyze(source).unwrap();
        }
    }

    #[test]
    fn runtime_projected_reference_places_use_expected_reborrow_context() {
        fn analyze(source: &str) -> Result<usize, CodegenError> {
            let module = Parser::new(source).parse_module::<1, 8>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            let body = function.parse_body::<8>().unwrap();
            let mut facts = RuntimeBodyFacts::EMPTY;
            preanalyze_runtime_body_declarations::<_, 8, 32>(
                &function,
                &NoConstants,
                &body,
                "u16",
                function.body_expression_span.start,
                &mut facts,
            )
        }

        for source in [
            "fn value(first: &mut u16, second: &mut u16) -> u16 { let pair = (first, second); let child: &mut u16 = pair.0; let competing: &mut u16 = pair.0; *competing += 1; *child }",
            "fn value(first: &mut u16, second: &mut u16, third: &mut u16) -> u16 { let pair = (first, second); let mut child: &mut u16 = third; child = pair.0; let competing: &mut u16 = pair.0; *competing += 1; *child }",
        ] {
            assert_eq!(
                analyze(source).unwrap_err().kind,
                CodegenErrorKind::RuntimeBorrowConflict
            );
        }

        for source in [
            "fn value(first: &mut u16, second: &mut u16) -> u16 { let pair = (first, second); let child: &mut u16 = pair.0; *child += 1; let next: &mut u16 = pair.0; *next }",
            "fn value(first: &mut u16, second: &mut u16, third: &mut u16) -> u16 { let pair = (first, second); let mut child: &mut u16 = third; child = pair.0; *child += 1; let next: &mut u16 = pair.0; *next }",
        ] {
            analyze(source).unwrap();
        }

        for source in [
            "fn value(first: &mut u16, second: &mut u16, third: &mut u16, choose: bool) -> u16 { let pair = (&mut *first, &mut *second); let mut child: &mut u16 = third; child = if choose { pair.0 } else { pair.1 }; let competing: &mut u16 = &mut *first; *competing += 1; *child }",
            "fn value(first: &mut u16, second: &mut u16, third: &mut u16, choose: bool) -> u16 { let pair = (&mut *first, &mut *second); let mut child: &mut u16 = third; child = if choose { pair.0 } else { pair.1 }; let competing: &mut u16 = &mut *second; *competing += 1; *child }",
        ] {
            assert_eq!(
                analyze(source).unwrap_err().kind,
                CodegenErrorKind::RuntimeBorrowConflict
            );
        }

        for source in [
            "fn value(first: &mut u16, second: &mut u16, third: &mut u16, choose: bool) -> u16 { let pair = (&mut *first, &mut *second); let mut child: &mut u16 = third; child = if choose { pair.0 } else { pair.1 }; *child += 1; let restored: &mut u16 = &mut *first; *restored }",
            "fn value(first: &mut u16, second: &mut u16, third: &mut u16, choose: bool) -> u16 { let pair = (&mut *first, &mut *second); let mut child: &mut u16 = third; child = if choose { pair.0 } else { pair.1 }; *child += 1; let restored: &mut u16 = &mut *second; *restored }",
        ] {
            analyze(source).unwrap();
        }

        for source in [
            "fn value(first: &mut u16, second: &mut u16) -> u16 { let mut pair = (&mut *first,); pair.0 = &mut *second; let child: &mut u16 = pair.0; let competing: &mut u16 = &mut *first; *competing += 1; *child }",
            "fn value(first: &mut u16, second: &mut u16) -> u16 { let mut pair = (&mut *first,); pair.0 = &mut *second; let child: &mut u16 = pair.0; let competing: &mut u16 = &mut *second; *competing += 1; *child }",
        ] {
            assert_eq!(
                analyze(source).unwrap_err().kind,
                CodegenErrorKind::RuntimeBorrowConflict
            );
        }
        for source in [
            "fn value(first: &mut u16, second: &mut u16) -> u16 { let mut pair = (&mut *first,); pair.0 = &mut *second; let child: &mut u16 = pair.0; *child += 1; let restored: &mut u16 = &mut *first; *restored }",
            "fn value(first: &mut u16, second: &mut u16) -> u16 { let mut pair = (&mut *first,); pair.0 = &mut *second; let child: &mut u16 = pair.0; *child += 1; let restored: &mut u16 = &mut *second; *restored }",
        ] {
            analyze(source).unwrap();
        }
    }

    #[test]
    fn runtime_non_reference_call_results_reborrow_reference_arguments() {
        fn analyze(source: &str) -> Result<usize, CodegenError> {
            let module = Parser::new(source).parse_module::<1, 8>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            let body = function.parse_body::<8>().unwrap();
            let mut facts = RuntimeBodyFacts::EMPTY;
            preanalyze_runtime_body_declarations::<_, 8, 32>(
                &function,
                &MutableReferenceCallResolver,
                &body,
                "u16",
                function.body_expression_span.start,
                &mut facts,
            )
        }

        for source in [
            "fn value(input: &mut u16) -> u16 { let child: &mut u16 = &mut *input; touch(input); *child }",
            "fn value(first: &mut u16, second: &mut u16, choose: bool) -> u16 { let child: &mut u16 = &mut *first; touch(if choose { first } else { second }); *child }",
        ] {
            assert_eq!(
                analyze(source).unwrap_err().kind,
                CodegenErrorKind::RuntimeBorrowConflict
            );
        }

        for source in [
            "fn value(input: &mut u16) -> u16 { touch(input); *input }",
            "fn value(first: &mut u16, second: &mut u16, choose: bool) -> u16 { touch(if choose { first } else { second }); *first + *second }",
        ] {
            analyze(source).unwrap();
        }
    }

    #[test]
    fn runtime_place_effects_reborrow_reference_values_at_return_coercion_sites() {
        let source = "fn value(input: &mut u16) -> &mut u16 { let returned: &mut u16 = identity(input); returned }";
        let module = Parser::new(source).parse_module::<1, 4>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<4>().unwrap();
        let mut facts = RuntimeBodyFacts::EMPTY;
        let local_count = preanalyze_runtime_body_declarations::<_, 4, 16>(
            &function,
            &MutableReferenceCallResolver,
            &body,
            "&mut u16",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();

        assert_eq!(local_count, 1);
        assert_eq!(facts.effect_count, 2);
        assert_eq!(facts.initialization_count, 2);
        assert_eq!(facts.ownership_event_count, 4);
        assert_eq!(facts.ownership_statement_count, 1);
        assert!(facts.ownership_has_tail);
        assert_eq!(
            facts.initializations[0].unwrap().event,
            RuntimeOwnershipEventId(0)
        );
        assert_eq!(
            facts.initializations[0].unwrap().location,
            RuntimeOwnershipEventLocation::ParameterEntry
        );
        assert_eq!(facts.effects[0].unwrap().event, RuntimeOwnershipEventId(1));
        assert_eq!(
            facts.effects[0].unwrap().location,
            RuntimeOwnershipEventLocation::TopLevelStatement(0)
        );
        assert_eq!(
            facts.initializations[1].unwrap().event,
            RuntimeOwnershipEventId(2)
        );
        assert_eq!(
            facts.initializations[1].unwrap().location,
            RuntimeOwnershipEventLocation::TopLevelStatement(0)
        );
        assert_eq!(facts.effects[1].unwrap().event, RuntimeOwnershipEventId(3));
        assert_eq!(
            facts.effects[1].unwrap().location,
            RuntimeOwnershipEventLocation::Tail
        );
        assert_eq!(
            facts.effects[0].unwrap().kind,
            RuntimePlaceEffectKind::MutableBorrow
        );
        assert_eq!(facts.effects[0].unwrap().path, RuntimeMovePathId(0));
        assert_eq!(
            facts.effects[1].unwrap().kind,
            RuntimePlaceEffectKind::MutableBorrow
        );
        assert_eq!(facts.effects[1].unwrap().path, RuntimeMovePathId(1));

        let assignment_access_count = facts.assignment_access_count;
        let assignment_read_count = facts.assignment_read_count;
        let emitter = RuntimeEmitter::<_, 64, 4> {
            bytes: [0; 64],
            length: 0,
            readonly_data: [0; MAX_X86_64_READONLY_DATA_BYTES],
            readonly_data_length: 0,
            readonly_relocations: [X86_64ReadonlyDataRelocation {
                offset: 0,
                data_offset: 0,
            }; MAX_X86_64_READONLY_RELOCATIONS],
            readonly_relocation_count: 0,
            trap_patches: [0; 64],
            trap_count: 0,
            function: &function,
            resolver: &MutableReferenceCallResolver,
            abi: X86_64Abi::SystemV,
            width: runtime_width("u16").unwrap(),
            overflow_checks: true,
            uses_sret: false,
            saved_parameter_slots: 1,
            locals: [None; 4],
            saved_locals: 0,
            body_facts: &mut facts,
            preanalyzed_local_count: local_count,
            preanalyzed_local_cursor: local_count,
            preanalyzed_assignment_access_cursor: assignment_access_count,
            preanalyzed_assignment_read_cursor: assignment_read_count,
            evaluation_depth: 0,
            runtime_call_depth: 0,
            runtime_call_names: [None; 8],
            runtime_call_local_floor: None,
        };
        emitter.validate_runtime_place_facts().unwrap();

        let valid_move = emitter.body_facts.effects[1].unwrap();
        emitter.body_facts.effects[1] = Some(RuntimePlaceEffectFact {
            path: RuntimeMovePathId(0),
            kind: RuntimePlaceEffectKind::Copy,
            ..valid_move
        });
        assert_eq!(
            emitter.validate_runtime_place_facts().unwrap_err().kind,
            CodegenErrorKind::InvalidRuntimePlaceFacts
        );
        emitter.body_facts.effects[1] = Some(RuntimePlaceEffectFact {
            event: RuntimeOwnershipEventId(2),
            ..valid_move
        });
        assert_eq!(
            emitter.validate_runtime_place_facts().unwrap_err().kind,
            CodegenErrorKind::InvalidRuntimePlaceFacts
        );
        emitter.body_facts.effects[1] = Some(RuntimePlaceEffectFact {
            location: RuntimeOwnershipEventLocation::Unassigned,
            ..valid_move
        });
        assert_eq!(
            emitter.validate_runtime_place_facts().unwrap_err().kind,
            CodegenErrorKind::InvalidRuntimePlaceFacts
        );
        emitter.body_facts.effects[1] = Some(RuntimePlaceEffectFact {
            location: RuntimeOwnershipEventLocation::TopLevelStatement(1),
            ..valid_move
        });
        assert_eq!(
            emitter.validate_runtime_place_facts().unwrap_err().kind,
            CodegenErrorKind::InvalidRuntimePlaceFacts
        );
    }

    #[test]
    fn runtime_identity_call_results_reject_a_competing_reborrow() {
        let source = "fn value(input: &mut u16) -> u16 { let first: &mut u16 = identity(input); let second: &mut u16 = identity(input); *first + *second }";
        let module = Parser::new(source).parse_module::<1, 4>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<4>().unwrap();
        let mut facts = RuntimeBodyFacts::EMPTY;
        assert_eq!(
            preanalyze_runtime_body_declarations::<_, 4, 16>(
                &function,
                &MutableReferenceCallResolver,
                &body,
                "u16",
                function.body_expression_span.start,
                &mut facts,
            )
            .unwrap_err()
            .kind,
            CodegenErrorKind::RuntimeBorrowConflict
        );
    }

    #[test]
    fn runtime_identity_call_results_retain_argument_loan_origins() {
        fn analyze(source: &str) -> Result<usize, CodegenError> {
            let module = Parser::new(source).parse_module::<1, 8>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            let body = function.parse_body::<8>().unwrap();
            let mut facts = RuntimeBodyFacts::EMPTY;
            preanalyze_runtime_body_declarations::<_, 8, 32>(
                &function,
                &MutableReferenceCallResolver,
                &body,
                "u16",
                function.body_expression_span.start,
                &mut facts,
            )
        }

        for source in [
            "fn value(input: &mut u16) -> u16 { let returned: &mut u16 = identity(input); let competing: &mut u16 = &mut *input; *competing += 1; *returned }",
            "fn value(first: &mut u16, second: &mut u16) -> u16 { let mut returned: &mut u16 = second; returned = identity(first); let competing: &mut u16 = &mut *first; *competing += 1; *returned }",
            "fn value(input: &mut u16) -> u16 { let returned: &mut u16 = identity(input); let child: &u16 = &*returned; *input += 1; *child }",
        ] {
            assert_eq!(
                analyze(source).unwrap_err().kind,
                CodegenErrorKind::RuntimeBorrowConflict
            );
        }

        for source in [
            "fn value(input: &mut u16) -> u16 { let returned: &mut u16 = identity(input); *returned += 1; let restored: &mut u16 = &mut *input; *restored }",
            "fn value(first: &mut u16, second: &mut u16) -> u16 { let mut returned: &mut u16 = second; returned = identity(first); *returned += 1; let restored: &mut u16 = &mut *first; *restored }",
            "fn value(input: &mut u16) -> u16 { let returned: &mut u16 = identity(input); let child: &u16 = &*returned; let copied = *child; *input += 1; copied + *input }",
        ] {
            analyze(source).unwrap();
        }
    }

    #[test]
    fn runtime_conditional_return_call_results_retain_argument_origins() {
        fn analyze(source: &str) -> Result<usize, CodegenError> {
            let module = Parser::new(source).parse_module::<1, 8>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            let body = function.parse_body::<8>().unwrap();
            let mut facts = RuntimeBodyFacts::EMPTY;
            preanalyze_runtime_body_declarations::<_, 8, 40>(
                &function,
                &MutableReferenceCallResolver,
                &body,
                "u16",
                function.body_expression_span.start,
                &mut facts,
            )
        }

        for source in [
            "fn value(input: &mut u16, first: bool) -> u16 { let returned: &mut u16 = choose(input, first); let competing: &mut u16 = &mut *input; *competing += 1; *returned }",
            "fn value(input: &mut u16, alternate: &mut u16, first: bool) -> u16 { let mut returned: &mut u16 = alternate; returned = choose(input, first); let competing: &mut u16 = &mut *input; *competing += 1; *returned }",
            "fn value(input: &mut u16, first: bool) -> u16 { let returned: &mut u16 = choose(input, first); let child: &u16 = &*returned; *input += 1; *child }",
        ] {
            assert_eq!(
                analyze(source).unwrap_err().kind,
                CodegenErrorKind::RuntimeBorrowConflict
            );
        }

        for source in [
            "fn value(input: &mut u16, first: bool) -> u16 { let returned: &mut u16 = choose(input, first); *returned += 1; let restored: &mut u16 = &mut *input; *restored }",
            "fn value(input: &mut u16, alternate: &mut u16, first: bool) -> u16 { let mut returned: &mut u16 = alternate; returned = choose(input, first); *returned += 1; let restored: &mut u16 = &mut *input; *restored }",
            "fn value(input: &mut u16, first: bool) -> u16 { let returned: &mut u16 = choose(input, first); let child: &u16 = &*returned; let copied = *child; *input += 1; copied + *input }",
        ] {
            analyze(source).unwrap();
        }
    }

    #[test]
    fn runtime_local_alias_call_results_retain_argument_origins() {
        fn analyze(source: &str) -> Result<usize, CodegenError> {
            let module = Parser::new(source).parse_module::<1, 8>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            let body = function.parse_body::<8>().unwrap();
            let mut facts = RuntimeBodyFacts::EMPTY;
            preanalyze_runtime_body_declarations::<_, 8, 32>(
                &function,
                &MutableReferenceCallResolver,
                &body,
                "u16",
                function.body_expression_span.start,
                &mut facts,
            )
        }

        for source in [
            "fn value(input: &mut u16) -> u16 { let shared: &u16 = &*input; let returned: &u16 = shared_identity(shared); let competing: &mut u16 = &mut *input; *competing += 1; *returned }",
            "fn value(first: &mut u16, second: &mut u16, choose: bool) -> u16 { let returned: &u16 = shared_identity(if choose { &*first } else { &*second }); let competing: &mut u16 = &mut *first; *competing += 1; *returned }",
            "fn value(first: &mut u16, second: &mut u16, choose: bool) -> u16 { let returned: &u16 = shared_identity(if choose { &*first } else { &*second }); let competing: &mut u16 = &mut *second; *competing += 1; *returned }",
            "fn value(input: &mut u16, repeat: bool) -> u16 { while repeat { let returned: &u16 = shared_identity(&*input); *input += 1; if *returned == 0 { return *input; } } *input }",
            "fn value(first: &mut u16, second: &mut u16, choose: bool, repeat: bool) -> u16 { while repeat { let returned: &u16 = shared_identity(if choose { &*first } else { &*second }); *first += 1; if *returned == 0 { return *second; } } *first }",
            "fn value(first: &mut u16, second: &mut u16, choose: bool, repeat: bool) -> u16 { while repeat { let returned: &u16 = shared_identity(if choose { &*first } else { &*second }); *second += 1; if *returned == 0 { return *first; } } *second }",
            "fn value(first: &mut u16, second: &mut u16, choose: bool, outer: bool, inner: bool) -> u16 { while outer { while inner { let returned: &u16 = shared_identity(if choose { &*first } else { &*second }); *first += 1; if *returned == 0 { return *second; } } } *first }",
            "fn value(input: &mut u16, repeat: bool) -> u16 { while repeat { let returned: &mut u16 = forward(input); *input += 1; if *returned == 0 { return *input; } } *input }",
            "fn value(input: &mut u16) -> u16 { let returned: &mut u16 = forward(input); let competing: &mut u16 = &mut *input; *competing += 1; *returned }",
            "fn value(input: &mut u16, choose: bool) -> u16 { let returned: &mut u16 = forward(if choose { input } else { input }); let competing: &mut u16 = &mut *input; *competing += 1; *returned }",
            "fn value(first: &mut u16, second: &mut u16, choose: bool) -> u16 { let returned: &mut u16 = forward(if choose { first } else { second }); let competing: &mut u16 = &mut *first; *competing += 1; *returned }",
            "fn value(first: &mut u16, second: &mut u16, choose: bool) -> u16 { let returned: &mut u16 = forward(if choose { first } else { second }); let competing: &mut u16 = &mut *second; *competing += 1; *returned }",
            "fn value(first: &mut u16, second: &mut u16) -> u16 { let mut returned: &mut u16 = second; returned = forward(first); let competing: &mut u16 = &mut *first; *competing += 1; *returned }",
            "fn value(input: &mut u16) -> u16 { let returned: &mut u16 = reassign_forward(input); let competing: &mut u16 = &mut *input; *competing += 1; *returned }",
            "fn value(input: &mut u16, first: bool) -> u16 { let returned: &mut u16 = branch_forward(input, first); let competing: &mut u16 = &mut *input; *competing += 1; *returned }",
            "fn value(input: &mut u16, repeat: bool) -> u16 { let returned: &mut u16 = loop_forward(input, repeat); let competing: &mut u16 = &mut *input; *competing += 1; *returned }",
            "fn value(input: &mut u16, first: bool) -> u16 { let returned: &mut u16 = branch_local_forward(input, first); let competing: &mut u16 = &mut *input; *competing += 1; *returned }",
            "fn value(input: &mut u16, first: bool) -> u16 { let returned: &mut u16 = branch_local_return(input, first); let competing: &mut u16 = &mut *input; *competing += 1; *returned }",
            "fn value(input: &mut u16, repeat: bool) -> u16 { let returned: &mut u16 = loop_local_forward(input, repeat); let competing: &mut u16 = &mut *input; *competing += 1; *returned }",
            "fn value(input: &mut u16, repeat: bool, first: bool) -> u16 { let returned: &mut u16 = loop_branch_local_return(input, repeat, first); let competing: &mut u16 = &mut *input; *competing += 1; *returned }",
            "fn value(input: &mut u16, repeat: bool, first: bool) -> u16 { let returned: &mut u16 = loop_branch_tuple_assign_return(input, repeat, first); let competing: &mut u16 = &mut *input; *competing += 1; *returned }",
            "fn value(input: &mut u16, repeat: bool, first: bool) -> u16 { let returned: &mut u16 = loop_branch_fallthrough(input, repeat, first); let competing: &mut u16 = &mut *input; *competing += 1; *returned }",
            "fn value(first: &mut u16, second: &mut u16) -> u16 { let returned: &mut u16 = tuple_field_assign(first, second); let competing: &mut u16 = &mut *second; *competing += 1; *returned }",
            "fn value(first: &mut u16, second: &mut u16) -> u16 { let returned: &mut u16 = tuple_field_assign(first, second); let competing: &mut u16 = &mut *first; *competing += 1; *returned }",
            "fn value(input: &mut u16) -> u16 { let returned: &mut u16 = tuple_field_initialize(input); let competing: &mut u16 = &mut *input; *competing += 1; *returned }",
            "fn value(input: &mut u16) -> u16 { let returned: &mut u16 = tuple_field_move(input); let competing: &mut u16 = &mut *input; *competing += 1; *returned }",
            "fn value(first: &mut u16, second: &mut u16) -> u16 { let returned: &mut u16 = tuple_field_assign_alias(first, second); let competing: &mut u16 = &mut *second; *competing += 1; *returned }",
            "fn value(first: &mut u16, second: &mut u16, choose: bool) -> u16 { let returned: &mut u16 = branch_tuple_field_assign_alias(first, second, choose); let competing: &mut u16 = &mut *second; *competing += 1; *returned }",
            "fn value(first: &mut u16, second: &mut u16, choose: bool) -> u16 { let returned: &mut u16 = branch_local_tuple_assign_alias(first, second, choose); let competing: &mut u16 = &mut *second; *competing += 1; *returned }",
            "fn value(first: &mut u16, second: &mut u16, repeat: bool) -> u16 { let returned: &mut u16 = loop_tuple_field_assign_alias(first, second, repeat); let competing: &mut u16 = &mut *second; *competing += 1; *returned }",
            "fn value(input: &mut u16, repeat: bool) -> u16 { let returned: &mut u16 = loop_local_tuple_assign_alias(input, repeat); let competing: &mut u16 = &mut *input; *competing += 1; *returned }",
            "fn value(first: &mut u16, second: &mut u16, choose: bool) -> u16 { let returned: &mut u16 = tuple_field_initialize_conditional(first, second, choose); let competing: &mut u16 = &mut *second; *competing += 1; *returned }",
            "fn value(first: &mut u16, second: &mut u16, choose: bool) -> u16 { let returned: &mut u16 = branch_tuple_field_assign(first, second, choose); let competing: &mut u16 = &mut *second; *competing += 1; *returned }",
            "fn value(first: &mut u16, second: &mut u16, repeat: bool) -> u16 { let returned: &mut u16 = loop_tuple_field_assign(first, second, repeat); let competing: &mut u16 = &mut *second; *competing += 1; *returned }",
        ] {
            assert_eq!(
                analyze(source).unwrap_err().kind,
                CodegenErrorKind::RuntimeBorrowConflict
            );
        }

        for source in [
            "fn value(input: &mut u16) -> u16 { let shared: &u16 = &*input; let returned: &u16 = shared_identity(shared); let copied = *returned; *input += 1; copied + *input }",
            "fn value(first: &mut u16, second: &mut u16, choose: bool) -> u16 { let returned: &u16 = shared_identity(if choose { &*first } else { &*second }); let copied = *returned; *first += 1; *second += 1; copied + *first + *second }",
            "fn value(input: &mut u16, repeat: bool) -> u16 { while repeat { let returned: &u16 = shared_identity(&*input); let copied = *returned; *input += 1; if copied == 0 { return *input; } } *input }",
            "fn value(first: &mut u16, second: &mut u16, choose: bool, repeat: bool) -> u16 { while repeat { let returned: &u16 = shared_identity(if choose { &*first } else { &*second }); let copied = *returned; *first += 1; *second += 1; if copied == 0 { return *second; } } *first }",
            "fn value(first: &mut u16, second: &mut u16, choose: bool, outer: bool, inner: bool) -> u16 { while outer { while inner { let returned: &u16 = shared_identity(if choose { &*first } else { &*second }); let copied = *returned; *first += 1; *second += 1; if copied == 0 { return *second; } } } *first }",
            "fn value(input: &mut u16, repeat: bool) -> u16 { while repeat { let returned: &mut u16 = forward(input); let copied = *returned; *input += 1; if copied == 0 { return *input; } } *input }",
            "fn value(input: &mut u16) -> u16 { let returned: &mut u16 = forward(input); *returned += 1; let restored: &mut u16 = &mut *input; *restored }",
            "fn value(input: &mut u16, choose: bool) -> u16 { let returned: &mut u16 = forward(if choose { input } else { input }); let copied = *returned; *input += 1; copied + *input }",
            "fn value(first: &mut u16, second: &mut u16, choose: bool) -> u16 { let returned: &mut u16 = forward(if choose { first } else { second }); let copied = *returned; *first += 1; *second += 1; copied + *first + *second }",
            "fn value(first: &mut u16, second: &mut u16) -> u16 { let mut returned: &mut u16 = second; returned = forward(first); *returned += 1; let restored: &mut u16 = &mut *first; *restored }",
            "fn value(input: &mut u16) -> u16 { let returned: &mut u16 = reassign_forward(input); *returned += 1; let restored: &mut u16 = &mut *input; *restored }",
            "fn value(input: &mut u16, first: bool) -> u16 { let returned: &mut u16 = branch_forward(input, first); *returned += 1; let restored: &mut u16 = &mut *input; *restored }",
            "fn value(input: &mut u16, repeat: bool) -> u16 { let returned: &mut u16 = loop_forward(input, repeat); *returned += 1; let restored: &mut u16 = &mut *input; *restored }",
            "fn value(input: &mut u16, first: bool) -> u16 { let returned: &mut u16 = branch_local_forward(input, first); *returned += 1; let restored: &mut u16 = &mut *input; *restored }",
            "fn value(input: &mut u16, first: bool) -> u16 { let returned: &mut u16 = branch_local_return(input, first); *returned += 1; let restored: &mut u16 = &mut *input; *restored }",
            "fn value(input: &mut u16, repeat: bool) -> u16 { let returned: &mut u16 = loop_local_forward(input, repeat); *returned += 1; let restored: &mut u16 = &mut *input; *restored }",
            "fn value(input: &mut u16, repeat: bool, first: bool) -> u16 { let returned: &mut u16 = loop_branch_local_return(input, repeat, first); *returned += 1; let restored: &mut u16 = &mut *input; *restored }",
            "fn value(input: &mut u16, repeat: bool, first: bool) -> u16 { let returned: &mut u16 = loop_branch_tuple_assign_return(input, repeat, first); *returned += 1; let restored: &mut u16 = &mut *input; *restored }",
            "fn value(input: &mut u16, repeat: bool, first: bool) -> u16 { let returned: &mut u16 = loop_branch_fallthrough(input, repeat, first); *returned += 1; let restored: &mut u16 = &mut *input; *restored }",
            "fn value(first: &mut u16, second: &mut u16) -> u16 { let returned: &mut u16 = tuple_field_assign(first, second); *returned += 1; let restored: &mut u16 = &mut *second; *restored }",
            "fn value(first: &mut u16, second: &mut u16) -> u16 { let mut local = *first; let returned: &mut u16 = tuple_field_assign(&mut local, second); let copied = *returned; local += 1; copied + local }",
            "fn value(input: &mut u16) -> u16 { let returned: &mut u16 = tuple_field_initialize(input); *returned += 1; let restored: &mut u16 = &mut *input; *restored }",
            "fn value(input: &mut u16) -> u16 { let returned: &mut u16 = tuple_field_move(input); *returned += 1; let restored: &mut u16 = &mut *input; *restored }",
            "fn value(first: &mut u16, second: &mut u16) -> u16 { let returned: &mut u16 = tuple_field_assign_alias(first, second); *returned += 1; let restored: &mut u16 = &mut *second; *restored }",
            "fn value(first: &mut u16, second: &mut u16, choose: bool) -> u16 { let returned: &mut u16 = branch_tuple_field_assign_alias(first, second, choose); *returned += 1; let restored: &mut u16 = &mut *second; *restored }",
            "fn value(first: &mut u16, second: &mut u16, choose: bool) -> u16 { let returned: &mut u16 = branch_local_tuple_assign_alias(first, second, choose); *returned += 1; let restored: &mut u16 = &mut *second; *restored }",
            "fn value(first: &mut u16, second: &mut u16, repeat: bool) -> u16 { let returned: &mut u16 = loop_tuple_field_assign_alias(first, second, repeat); *returned += 1; let restored: &mut u16 = &mut *second; *restored }",
            "fn value(input: &mut u16, repeat: bool) -> u16 { let returned: &mut u16 = loop_local_tuple_assign_alias(input, repeat); *returned += 1; let restored: &mut u16 = &mut *input; *restored }",
            "fn value(first: &mut u16, second: &mut u16, choose: bool) -> u16 { let returned: &mut u16 = tuple_field_initialize_conditional(first, second, choose); *returned += 1; let restored: &mut u16 = &mut *second; *restored }",
            "fn value(first: &mut u16, second: &mut u16, choose: bool) -> u16 { let returned: &mut u16 = branch_tuple_field_assign(first, second, choose); *returned += 1; let restored: &mut u16 = &mut *second; *restored }",
            "fn value(first: &mut u16, second: &mut u16, repeat: bool) -> u16 { let returned: &mut u16 = loop_tuple_field_assign(first, second, repeat); *returned += 1; let restored: &mut u16 = &mut *second; *restored }",
        ] {
            analyze(source).unwrap();
        }

        let forward = MutableReferenceCallResolver
            .resolve_runtime_call::<2>("forward", 1)
            .unwrap();
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 16>(forward),
            Some(0)
        );
        let reassign_forward = MutableReferenceCallResolver
            .resolve_runtime_call::<2>("reassign_forward", 1)
            .unwrap();
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 16>(reassign_forward),
            Some(0)
        );
        let tuple_field_assign = MutableReferenceCallResolver
            .resolve_runtime_call::<3>("tuple_field_assign", 2)
            .unwrap();
        assert_eq!(
            runtime_reference_call_origin_parameter::<3, 32>(tuple_field_assign),
            Some(1)
        );
        let tuple_field_initialize = MutableReferenceCallResolver
            .resolve_runtime_call::<2>("tuple_field_initialize", 1)
            .unwrap();
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 16>(tuple_field_initialize),
            Some(0)
        );
        let tuple_field_move = MutableReferenceCallResolver
            .resolve_runtime_call::<4>("tuple_field_move", 1)
            .unwrap();
        assert_eq!(
            runtime_reference_call_origin_parameter::<4, 32>(tuple_field_move),
            Some(0)
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<4, 32>(RuntimeCallTarget {
                body_expression: concat!(
                    "let mut local_value: u16 = 1; ",
                    "let pair: (&mut u16,) = (&mut local_value,); ",
                    "let alias: &mut u16 = pair.0; ",
                    "let result: &mut u16 = alias; result"
                ),
                ..tuple_field_move
            }),
            None
        );
        let tuple_field_assign_alias = MutableReferenceCallResolver
            .resolve_runtime_call::<4>("tuple_field_assign_alias", 2)
            .unwrap();
        assert_eq!(
            runtime_reference_call_origin_parameter::<4, 32>(tuple_field_assign_alias),
            Some(1)
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<4, 32>(RuntimeCallTarget {
                body_expression: concat!(
                    "let mut local_value: u16 = 1; ",
                    "let pair: (&mut u16,) = (&mut local_value,); ",
                    "let mut alias = pair.0; alias = second; alias"
                ),
                ..tuple_field_assign_alias
            }),
            Some(1)
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<4, 32>(RuntimeCallTarget {
                body_expression: concat!(
                    "let mut local_value: u16 = 1; ",
                    "let pair: (&mut u16,) = (&mut local_value,); ",
                    "let mut alias: &mut u16 = first; alias = pair.0; alias"
                ),
                ..tuple_field_assign_alias
            }),
            None
        );
        let branch_tuple_field_assign_alias = MutableReferenceCallResolver
            .resolve_runtime_call::<4>("branch_tuple_field_assign_alias", 3)
            .unwrap();
        assert_eq!(
            runtime_reference_call_origin_parameter::<4, 32>(branch_tuple_field_assign_alias),
            Some(1)
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<4, 32>(RuntimeCallTarget {
                body_expression: concat!(
                    "let pair: (&mut u16,) = (second,); ",
                    "let mut alias: &mut u16 = first; ",
                    "if choose { alias = pair.0; } alias"
                ),
                ..branch_tuple_field_assign_alias
            }),
            None
        );
        let branch_local_tuple_assign_alias = MutableReferenceCallResolver
            .resolve_runtime_call::<4>("branch_local_tuple_assign_alias", 3)
            .unwrap();
        assert_eq!(
            runtime_reference_call_origin_parameter::<4, 32>(branch_local_tuple_assign_alias),
            Some(1)
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<4, 48>(RuntimeCallTarget {
                body_expression: concat!(
                    "let mut local_value: u16 = 1; ",
                    "let mut alias: &mut u16 = first; ",
                    "if choose { let pair: (&mut u16,) = (second,); alias = pair.0; } ",
                    "else { let pair: (&mut u16,) = (second,); alias = pair.0; } ",
                    "let replacement: (&mut u16,) = (&mut local_value,); replacement.0"
                ),
                ..branch_local_tuple_assign_alias
            }),
            None
        );
        let loop_tuple_field_assign_alias = MutableReferenceCallResolver
            .resolve_runtime_call::<4>("loop_tuple_field_assign_alias", 3)
            .unwrap();
        assert_eq!(
            runtime_reference_call_origin_parameter::<4, 32>(loop_tuple_field_assign_alias),
            Some(1)
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<4, 32>(RuntimeCallTarget {
                body_expression: concat!(
                    "let pair: (&mut u16,) = (second,); ",
                    "let mut alias: &mut u16 = first; ",
                    "while repeat { alias = &mut *pair.0; } alias"
                ),
                ..loop_tuple_field_assign_alias
            }),
            None
        );
        let loop_local_tuple_assign_alias = MutableReferenceCallResolver
            .resolve_runtime_call::<3>("loop_local_tuple_assign_alias", 2)
            .unwrap();
        assert_eq!(
            runtime_reference_call_origin_parameter::<3, 32>(loop_local_tuple_assign_alias),
            Some(0)
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<3, 40>(RuntimeCallTarget {
                body_expression: concat!(
                    "let mut local_value: u16 = 1; ",
                    "let mut alias: &mut u16 = value; ",
                    "while repeat { let pair: (&mut u16,) = (&mut local_value,); ",
                    "alias = pair.0; } alias"
                ),
                ..loop_local_tuple_assign_alias
            }),
            None
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 16>(RuntimeCallTarget {
                body_expression: concat!(
                    "let mut local_value: u16 = 1; ",
                    "let pair: (&mut u16,) = (&mut local_value,); pair.0"
                ),
                ..tuple_field_initialize
            }),
            None
        );
        let tuple_field_initialize_conditional = MutableReferenceCallResolver
            .resolve_runtime_call::<4>("tuple_field_initialize_conditional", 3)
            .unwrap();
        assert_eq!(
            runtime_reference_call_origin_parameter::<4, 32>(tuple_field_initialize_conditional),
            Some(1)
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<4, 32>(RuntimeCallTarget {
                body_expression: concat!(
                    "let pair: (&mut u16, &mut u16) = ",
                    "(first, if choose { first } else { second }); pair.1"
                ),
                ..tuple_field_initialize_conditional
            }),
            None
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<3, 32>(RuntimeCallTarget {
                body_expression: concat!(
                    "let mut local_value: u16 = 1; ",
                    "let mut pair: (&mut u16,) = (first,); ",
                    "pair.0 = &mut local_value; pair.0"
                ),
                ..tuple_field_assign
            }),
            None
        );
        let branch_tuple_field_assign = MutableReferenceCallResolver
            .resolve_runtime_call::<4>("branch_tuple_field_assign", 3)
            .unwrap();
        assert_eq!(
            runtime_reference_call_origin_parameter::<4, 32>(branch_tuple_field_assign),
            Some(1)
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<4, 32>(RuntimeCallTarget {
                body_expression: concat!(
                    "let mut pair: (&mut u16,) = (first,); ",
                    "if choose { pair.0 = second; } pair.0"
                ),
                ..branch_tuple_field_assign
            }),
            None
        );
        let loop_tuple_field_assign = MutableReferenceCallResolver
            .resolve_runtime_call::<4>("loop_tuple_field_assign", 3)
            .unwrap();
        assert_eq!(
            runtime_reference_call_origin_parameter::<4, 32>(loop_tuple_field_assign),
            Some(1)
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<4, 32>(RuntimeCallTarget {
                body_expression: concat!(
                    "let mut pair: (&mut u16,) = (first,); ",
                    "while repeat { pair.0 = &mut *pair.0; } pair.0"
                ),
                ..loop_tuple_field_assign
            }),
            Some(0)
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<3, 32>(RuntimeCallTarget {
                body_expression: concat!(
                    "let mut pair: (&mut u16,) = (first,); ",
                    "pair.1 = second; pair.1"
                ),
                ..tuple_field_assign
            }),
            None
        );
        let branch_forward = MutableReferenceCallResolver
            .resolve_runtime_call::<3>("branch_forward", 2)
            .unwrap();
        assert_eq!(
            runtime_reference_call_origin_parameter::<3, 32>(branch_forward),
            Some(0)
        );
        let loop_forward = MutableReferenceCallResolver
            .resolve_runtime_call::<3>("loop_forward", 2)
            .unwrap();
        assert_eq!(
            runtime_reference_call_origin_parameter::<3, 32>(loop_forward),
            Some(0)
        );
        let branch_local_forward = MutableReferenceCallResolver
            .resolve_runtime_call::<3>("branch_local_forward", 2)
            .unwrap();
        assert_eq!(
            runtime_reference_call_origin_parameter::<3, 32>(branch_local_forward),
            Some(0)
        );
        let branch_local_return = MutableReferenceCallResolver
            .resolve_runtime_call::<3>("branch_local_return", 2)
            .unwrap();
        assert_eq!(
            runtime_reference_call_origin_parameter::<3, 32>(branch_local_return),
            Some(0)
        );
        let loop_local_forward = MutableReferenceCallResolver
            .resolve_runtime_call::<3>("loop_local_forward", 2)
            .unwrap();
        assert_eq!(
            runtime_reference_call_origin_parameter::<3, 32>(loop_local_forward),
            Some(0)
        );
        let loop_branch_local_return = MutableReferenceCallResolver
            .resolve_runtime_call::<3>("loop_branch_local_return", 3)
            .unwrap();
        assert_eq!(
            runtime_reference_call_origin_parameter::<3, 32>(loop_branch_local_return),
            Some(0)
        );
        let loop_branch_tuple_assign_return = MutableReferenceCallResolver
            .resolve_runtime_call::<3>("loop_branch_tuple_assign_return", 3)
            .unwrap();
        assert_eq!(
            runtime_reference_call_origin_parameter::<3, 48>(loop_branch_tuple_assign_return),
            Some(0)
        );
        let loop_branch_fallthrough = MutableReferenceCallResolver
            .resolve_runtime_call::<4>("loop_branch_fallthrough", 3)
            .unwrap();
        assert_eq!(
            runtime_reference_call_origin_parameter::<4, 32>(loop_branch_fallthrough),
            Some(0)
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<4, 32>(RuntimeCallTarget {
                body_expression: concat!(
                    "let mut alias: &mut u16 = value; while repeat { ",
                    "if first { return alias; } else { alias = &mut *alias; } } alias"
                ),
                ..loop_branch_fallthrough
            }),
            Some(0)
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<4, 40>(RuntimeCallTarget {
                body_expression: concat!(
                    "let mut local: u16 = 1; let mut alias: &mut u16 = value; ",
                    "while repeat { if first { alias = &mut local; } } alias"
                ),
                ..loop_branch_fallthrough
            }),
            None
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<4, 40>(RuntimeCallTarget {
                body_expression: concat!(
                    "let mut local: u16 = 1; let mut alias: &mut u16 = value; ",
                    "while repeat { if first { return alias; } ",
                    "else { alias = &mut local; } } alias"
                ),
                ..loop_branch_fallthrough
            }),
            None
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<3, 48>(RuntimeCallTarget {
                body_expression: concat!(
                    "let mut local: u16 = 1; while repeat { if first { ",
                    "let mut alias: &mut u16 = value; let pair: (&mut u16,) = (&mut local,); ",
                    "alias = pair.0; return alias; } ",
                    "else { return value; } } value"
                ),
                ..loop_branch_tuple_assign_return
            }),
            None
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<3, 32>(RuntimeCallTarget {
                body_expression: concat!(
                    "while repeat { if first { let mut local: u16 = 1; ",
                    "let branch: &mut u16 = &mut local; return branch; } } value"
                ),
                ..loop_branch_local_return
            }),
            None
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<3, 32>(RuntimeCallTarget {
                body_expression: concat!(
                    "if first { let mut local: u16 = 1; return &mut local; } value"
                ),
                ..branch_local_return
            }),
            None
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<3, 32>(RuntimeCallTarget {
                body_expression: concat!(
                    "let mut local: u16 = 1; let mut result: &mut u16 = value; ",
                    "if first { let branch: &mut u16 = &mut local; result = branch; } result"
                ),
                ..branch_local_forward
            }),
            None
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<3, 32>(RuntimeCallTarget {
                body_expression: concat!(
                    "let mut alias: &mut u16 = value; ",
                    "if first { alias = &mut *alias; } alias"
                ),
                ..branch_forward
            }),
            Some(0)
        );
        let reference = branch_forward.parameters[0].unwrap().ty;
        let mut ambiguous_parameters = branch_forward.parameters;
        ambiguous_parameters[1] = Some(RuntimeCallParameter {
            name: "alternate",
            ty: reference,
        });
        ambiguous_parameters[2] = Some(RuntimeCallParameter {
            name: "first",
            ty: ScalarType::Bool,
        });
        assert_eq!(
            runtime_reference_call_origin_parameter::<3, 32>(RuntimeCallTarget {
                name: "ambiguous_branch_forward",
                parameters: ambiguous_parameters,
                parameter_count: 3,
                body_expression: concat!(
                    "let mut alias: &mut u16 = value; ",
                    "if first { alias = value; } else { alias = alternate; } alias"
                ),
                ..branch_forward
            }),
            None
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 16>(RuntimeCallTarget {
                body_expression: "let value: u16 = 1; value",
                ..forward
            }),
            None
        );
        for body_expression in [
            "let alias: &mut u16 = value; alias = &mut *alias; alias",
            "let mut local: u16 = 1; let mut alias: &mut u16 = value; alias = &mut local; alias",
            "let mut alias: &mut u16 = value; *alias += 1; alias",
        ] {
            assert_eq!(
                runtime_reference_call_origin_parameter::<2, 16>(RuntimeCallTarget {
                    body_expression,
                    ..reassign_forward
                }),
                None
            );
        }
    }

    #[test]
    fn runtime_array_element_call_results_retain_argument_origins() {
        fn analyze(source: &str) -> Result<usize, CodegenError> {
            let module = Parser::new(source).parse_module::<1, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            let body = function.parse_body::<4>().unwrap();
            let mut facts = RuntimeBodyFacts::EMPTY;
            preanalyze_runtime_body_declarations::<_, 4, 32>(
                &function,
                &MutableReferenceCallResolver,
                &body,
                "u16",
                function.body_expression_span.start,
                &mut facts,
            )
        }

        assert_eq!(
            analyze(concat!(
                "fn value(input: &mut [u16; 2]) -> u16 { ",
                "let returned: &mut u16 = array_element(input); ",
                "let competing: &mut u16 = &mut input[0]; ",
                "*competing += 1; *returned }"
            ))
            .unwrap_err()
            .kind,
            CodegenErrorKind::RuntimeBorrowConflict
        );
        analyze(concat!(
            "fn value(input: &mut [u16; 2]) -> u16 { ",
            "let returned: &mut u16 = array_element(input); *returned += 1; ",
            "let restored: &mut u16 = &mut input[0]; *restored }"
        ))
        .unwrap();
        assert_eq!(
            analyze(concat!(
                "fn value(input: &mut [u16; 2]) -> u16 { ",
                "let returned: &mut u16 = array_element_alias(input); ",
                "let competing: &mut u16 = &mut input[0]; ",
                "*competing += 1; *returned }"
            ))
            .unwrap_err()
            .kind,
            CodegenErrorKind::RuntimeBorrowConflict
        );
        analyze(concat!(
            "fn value(input: &mut [u16; 2]) -> u16 { ",
            "let returned: &mut u16 = array_element_alias(input); *returned += 1; ",
            "let restored: &mut u16 = &mut input[0]; *restored }"
        ))
        .unwrap();
        assert_eq!(
            analyze(concat!(
                "fn value(input: &mut [u16; 2]) -> u16 { ",
                "let returned: &u16 = shared_array_element_alias(input); ",
                "let competing: &mut u16 = &mut input[0]; ",
                "*competing += 1; *returned }"
            ))
            .unwrap_err()
            .kind,
            CodegenErrorKind::RuntimeBorrowConflict
        );
        analyze(concat!(
            "fn value(input: &mut [u16; 2]) -> u16 { ",
            "let returned: &u16 = shared_array_element_alias(input); let value = *returned; ",
            "let restored: &mut u16 = &mut input[0]; *restored += value; *restored }"
        ))
        .unwrap();
        assert_eq!(
            analyze(concat!(
                "fn value(input: &mut [u16]) -> u16 { ",
                "let returned: &mut u16 = slice_element(input); ",
                "let competing: &mut u16 = &mut input[0]; ",
                "*competing += 1; *returned }"
            ))
            .unwrap_err()
            .kind,
            CodegenErrorKind::RuntimeBorrowConflict
        );
        analyze(concat!(
            "fn value(input: &mut [u16]) -> u16 { ",
            "let returned: &mut u16 = slice_element(input); *returned += 1; ",
            "let restored: &mut u16 = &mut input[0]; *restored }"
        ))
        .unwrap();
        for rejected in [
            "fn value(input: &mut [u16; 2]) -> u16 { let returned: &mut u16 = array_subslice_element(input); let competing: &mut u16 = &mut input[1]; *competing += 1; *returned }",
            "fn value(input: &mut [u16]) -> u16 { let returned: &mut u16 = slice_subslice_element(input); let competing: &mut u16 = &mut input[1]; *competing += 1; *returned }",
            "fn value(input: &mut [u16]) -> u16 { let returned: &mut u16 = slice_repeated_subslice_element(input); let competing: &mut u16 = &mut input[1]; *competing += 1; *returned }",
            "fn value(input: &mut [u16; 2]) -> u16 { let returned: &mut u16 = array_repeated_subslice_element(input); let competing: &mut u16 = &mut input[1]; *competing += 1; *returned }",
            "fn value(input: &mut [u16]) -> u16 { let returned: &mut u16 = slice_repeated_subslice_element_alias(input); let competing: &mut u16 = &mut input[1]; *competing += 1; *returned }",
            "fn value(input: &mut [u16]) -> u16 { let returned: &mut u16 = slice_nested_subslice_element(input); let competing: &mut u16 = &mut input[1]; *competing += 1; *returned }",
        ] {
            assert_eq!(
                analyze(rejected).unwrap_err().kind,
                CodegenErrorKind::RuntimeBorrowConflict
            );
        }
        for accepted in [
            "fn value(input: &mut [u16; 2]) -> u16 { let returned: &mut u16 = array_subslice_element(input); *returned += 1; let restored: &mut u16 = &mut input[1]; *restored }",
            "fn value(input: &mut [u16]) -> u16 { let returned: &mut u16 = slice_subslice_element(input); *returned += 1; let restored: &mut u16 = &mut input[1]; *restored }",
            "fn value(input: &mut [u16]) -> u16 { let returned: &mut u16 = slice_repeated_subslice_element(input); *returned += 1; let restored: &mut u16 = &mut input[1]; *restored }",
            "fn value(input: &mut [u16; 2]) -> u16 { let returned: &mut u16 = array_repeated_subslice_element(input); *returned += 1; let restored: &mut u16 = &mut input[1]; *restored }",
            "fn value(input: &mut [u16]) -> u16 { let returned: &mut u16 = slice_repeated_subslice_element_alias(input); *returned += 1; let restored: &mut u16 = &mut input[1]; *restored }",
            "fn value(input: &mut [u16]) -> u16 { let returned: &mut u16 = slice_nested_subslice_element(input); *returned += 1; let restored: &mut u16 = &mut input[1]; *restored }",
        ] {
            analyze(accepted).unwrap();
        }
        for rejected in [
            concat!(
                "fn value(input: &mut [u16; 2]) -> u16 { ",
                "let returned: &mut [u16] = array_subslice(input); ",
                "let competing: &mut u16 = &mut input[1]; ",
                "*competing += 1; returned[0] }"
            ),
            concat!(
                "fn value(input: &mut [u16]) -> u16 { ",
                "let returned: &mut [u16] = slice_subslice(input); ",
                "let competing: &mut u16 = &mut input[1]; ",
                "*competing += 1; returned[0] }"
            ),
            concat!(
                "fn value(input: &mut [u16; 2]) -> u16 { ",
                "let returned: &mut [u16] = array_repeated_subslice(input); ",
                "let competing: &mut u16 = &mut input[1]; ",
                "*competing += 1; returned[0] }"
            ),
            concat!(
                "fn value(input: &mut [u16]) -> u16 { ",
                "let returned: &mut [u16] = slice_repeated_subslice(input); ",
                "let competing: &mut u16 = &mut input[1]; ",
                "*competing += 1; returned[0] }"
            ),
            concat!(
                "fn value(input: &mut [u16]) -> u16 { ",
                "let returned: &mut [u16] = slice_repeated_subslice_alias(input); ",
                "let competing: &mut u16 = &mut input[1]; ",
                "*competing += 1; returned[0] }"
            ),
            concat!(
                "fn value(input: &mut [u16]) -> u16 { ",
                "let returned: &mut [u16] = slice_repeated_subslice_alias_chain(input); ",
                "let competing: &mut u16 = &mut input[1]; ",
                "*competing += 1; returned[0] }"
            ),
            concat!(
                "fn value(input: &mut [u16]) -> u16 { ",
                "let returned: &mut [u16] = slice_conditional_repeated_subslice(input, true); ",
                "let competing: &mut u16 = &mut input[1]; ",
                "*competing += 1; returned[0] }"
            ),
            concat!(
                "fn value(input: &mut [u16]) -> u16 { ",
                "let returned: &[u16] = shared_slice_conditional_repeated_subslice(input, true); ",
                "let competing: &mut u16 = &mut input[1]; ",
                "*competing += 1; returned[0] }"
            ),
            concat!(
                "fn value(input: &mut [u16]) -> u16 { ",
                "let returned: &mut [u16] = slice_explicit_repeated_subslice(input, true); ",
                "let competing: &mut u16 = &mut input[1]; ",
                "*competing += 1; returned[0] }"
            ),
            concat!(
                "fn value(input: &mut [u16]) -> u16 { ",
                "let returned: &[u16] = shared_slice_explicit_repeated_subslice(input, true); ",
                "let competing: &mut u16 = &mut input[1]; ",
                "*competing += 1; returned[0] }"
            ),
            concat!(
                "fn value(input: &mut [u16]) -> u16 { ",
                "let returned: &mut [u16] = slice_subslice_alias(input); ",
                "let competing: &mut u16 = &mut input[1]; ",
                "*competing += 1; returned[0] }"
            ),
            concat!(
                "fn value(input: &mut [u16]) -> u16 { ",
                "let returned: &[u16] = shared_slice_subslice_alias(input); ",
                "let competing: &mut u16 = &mut input[1]; ",
                "*competing += 1; returned[0] }"
            ),
            concat!(
                "fn value(input: &mut [u16]) -> u16 { ",
                "let returned: &[u16] = shared_slice_repeated_subslice(input); ",
                "let competing: &mut u16 = &mut input[1]; ",
                "*competing += 1; returned[0] }"
            ),
            concat!(
                "fn value(input: &mut [u16]) -> u16 { ",
                "let returned: &[u16] = shared_slice_repeated_subslice_alias(input); ",
                "let competing: &mut u16 = &mut input[1]; ",
                "*competing += 1; returned[0] }"
            ),
            concat!(
                "fn value(input: &mut [u16]) -> u16 { ",
                "let returned: &[u16] = shared_slice_repeated_subslice_alias_chain(input); ",
                "let competing: &mut u16 = &mut input[1]; ",
                "*competing += 1; returned[0] }"
            ),
            concat!(
                "fn value(input: &mut [u16]) -> u16 { ",
                "let returned: &[u16] = shared_slice_reassigned_repeated_subslice(input); ",
                "let competing: &mut u16 = &mut input[1]; ",
                "*competing += 1; returned[0] }"
            ),
        ] {
            assert_eq!(
                analyze(rejected).unwrap_err().kind,
                CodegenErrorKind::RuntimeBorrowConflict
            );
        }
        for accepted in [
            concat!(
                "fn value(input: &mut [u16; 2]) -> u16 { ",
                "let returned: &mut [u16] = array_subslice(input); returned[0] += 1; ",
                "let restored: &mut u16 = &mut input[1]; *restored }"
            ),
            concat!(
                "fn value(input: &mut [u16]) -> u16 { ",
                "let returned: &mut [u16] = slice_subslice(input); returned[0] += 1; ",
                "let restored: &mut u16 = &mut input[1]; *restored }"
            ),
            concat!(
                "fn value(input: &mut [u16; 2]) -> u16 { ",
                "let returned: &mut [u16] = array_repeated_subslice(input); returned[0] += 1; ",
                "let restored: &mut u16 = &mut input[1]; *restored }"
            ),
            concat!(
                "fn value(input: &mut [u16]) -> u16 { ",
                "let returned: &mut [u16] = slice_repeated_subslice(input); returned[0] += 1; ",
                "let restored: &mut u16 = &mut input[1]; *restored }"
            ),
            concat!(
                "fn value(input: &mut [u16]) -> u16 { ",
                "let returned: &mut [u16] = slice_repeated_subslice_alias(input); returned[0] += 1; ",
                "let restored: &mut u16 = &mut input[1]; *restored }"
            ),
            concat!(
                "fn value(input: &mut [u16]) -> u16 { ",
                "let returned: &mut [u16] = slice_repeated_subslice_alias_chain(input); returned[0] += 1; ",
                "let restored: &mut u16 = &mut input[1]; *restored }"
            ),
            concat!(
                "fn value(input: &mut [u16]) -> u16 { ",
                "let returned: &mut [u16] = slice_conditional_repeated_subslice(input, true); returned[0] += 1; ",
                "let restored: &mut u16 = &mut input[1]; *restored }"
            ),
            concat!(
                "fn value(input: &mut [u16]) -> u16 { ",
                "let returned: &[u16] = shared_slice_conditional_repeated_subslice(input, true); ",
                "let value = returned[0]; ",
                "let restored: &mut u16 = &mut input[1]; *restored += value; *restored }"
            ),
            concat!(
                "fn value(input: &mut [u16]) -> u16 { ",
                "let returned: &mut [u16] = slice_explicit_repeated_subslice(input, true); returned[0] += 1; ",
                "let restored: &mut u16 = &mut input[1]; *restored }"
            ),
            concat!(
                "fn value(input: &mut [u16]) -> u16 { ",
                "let returned: &[u16] = shared_slice_explicit_repeated_subslice(input, true); ",
                "let value = returned[0]; ",
                "let restored: &mut u16 = &mut input[1]; *restored += value; *restored }"
            ),
            concat!(
                "fn value(input: &mut [u16]) -> u16 { ",
                "let returned: &mut [u16] = slice_subslice_alias(input); returned[0] += 1; ",
                "let restored: &mut u16 = &mut input[1]; *restored }"
            ),
            concat!(
                "fn value(input: &mut [u16]) -> u16 { ",
                "let returned: &[u16] = shared_slice_subslice_alias(input); ",
                "let value = returned[0]; ",
                "let restored: &mut u16 = &mut input[1]; *restored += value; *restored }"
            ),
            concat!(
                "fn value(input: &mut [u16]) -> u16 { ",
                "let returned: &[u16] = shared_slice_repeated_subslice(input); ",
                "let value = returned[0]; ",
                "let restored: &mut u16 = &mut input[1]; *restored += value; *restored }"
            ),
            concat!(
                "fn value(input: &mut [u16]) -> u16 { ",
                "let returned: &[u16] = shared_slice_repeated_subslice_alias(input); ",
                "let value = returned[0]; ",
                "let restored: &mut u16 = &mut input[1]; *restored += value; *restored }"
            ),
            concat!(
                "fn value(input: &mut [u16]) -> u16 { ",
                "let returned: &[u16] = shared_slice_repeated_subslice_alias_chain(input); ",
                "let value = returned[0]; ",
                "let restored: &mut u16 = &mut input[1]; *restored += value; *restored }"
            ),
            concat!(
                "fn value(input: &mut [u16]) -> u16 { ",
                "let returned: &[u16] = shared_slice_reassigned_repeated_subslice(input); ",
                "let value = returned[0]; ",
                "let restored: &mut u16 = &mut input[1]; *restored += value; *restored }"
            ),
        ] {
            analyze(accepted).unwrap();
        }

        let target = MutableReferenceCallResolver
            .resolve_runtime_call::<2>("array_element", 1)
            .unwrap();
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 16>(target),
            Some(0)
        );
        let slice_target = MutableReferenceCallResolver
            .resolve_runtime_call::<2>("slice_element", 1)
            .unwrap();
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 16>(slice_target),
            Some(0)
        );
        let array_subslice_element = MutableReferenceCallResolver
            .resolve_runtime_call::<2>("array_subslice_element", 1)
            .unwrap();
        let slice_subslice_element = MutableReferenceCallResolver
            .resolve_runtime_call::<2>("slice_subslice_element", 1)
            .unwrap();
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 16>(array_subslice_element),
            Some(0)
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 16>(slice_subslice_element),
            Some(0)
        );
        let slice_repeated_subslice_element = MutableReferenceCallResolver
            .resolve_runtime_call::<2>("slice_repeated_subslice_element", 1)
            .unwrap();
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 16>(slice_repeated_subslice_element),
            Some(0)
        );
        let array_repeated_subslice_element = MutableReferenceCallResolver
            .resolve_runtime_call::<2>("array_repeated_subslice_element", 1)
            .unwrap();
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 16>(array_repeated_subslice_element),
            Some(0)
        );
        let slice_repeated_subslice_element_alias = MutableReferenceCallResolver
            .resolve_runtime_call::<2>("slice_repeated_subslice_element_alias", 1)
            .unwrap();
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 16>(
                slice_repeated_subslice_element_alias
            ),
            Some(0)
        );
        let slice_nested_subslice_element = MutableReferenceCallResolver
            .resolve_runtime_call::<2>("slice_nested_subslice_element", 1)
            .unwrap();
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 16>(slice_nested_subslice_element),
            Some(0)
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 16>(RuntimeCallTarget {
                body_expression: "&mut values[0..][0][0..][0]",
                ..slice_nested_subslice_element
            }),
            None
        );
        let array_subslice = MutableReferenceCallResolver
            .resolve_runtime_call::<2>("array_subslice", 1)
            .unwrap();
        let slice_subslice = MutableReferenceCallResolver
            .resolve_runtime_call::<2>("slice_subslice", 1)
            .unwrap();
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 16>(array_subslice),
            Some(0)
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 16>(slice_subslice),
            Some(0)
        );
        let array_repeated_subslice = MutableReferenceCallResolver
            .resolve_runtime_call::<2>("array_repeated_subslice", 1)
            .unwrap();
        let slice_repeated_subslice = MutableReferenceCallResolver
            .resolve_runtime_call::<2>("slice_repeated_subslice", 1)
            .unwrap();
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 16>(array_repeated_subslice),
            Some(0)
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 16>(slice_repeated_subslice),
            Some(0)
        );
        let slice_repeated_subslice_alias = MutableReferenceCallResolver
            .resolve_runtime_call::<2>("slice_repeated_subslice_alias", 1)
            .unwrap();
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 16>(slice_repeated_subslice_alias),
            Some(0)
        );
        let slice_repeated_subslice_alias_chain = MutableReferenceCallResolver
            .resolve_runtime_call::<2>("slice_repeated_subslice_alias_chain", 1)
            .unwrap();
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 16>(
                slice_repeated_subslice_alias_chain
            ),
            Some(0)
        );
        let slice_conditional_repeated_subslice = MutableReferenceCallResolver
            .resolve_runtime_call::<2>("slice_conditional_repeated_subslice", 2)
            .unwrap();
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 16>(
                slice_conditional_repeated_subslice
            ),
            Some(0)
        );
        let shared_slice_conditional_repeated_subslice = MutableReferenceCallResolver
            .resolve_runtime_call::<2>("shared_slice_conditional_repeated_subslice", 2)
            .unwrap();
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 16>(
                shared_slice_conditional_repeated_subslice
            ),
            Some(0)
        );
        let slice_explicit_repeated_subslice = MutableReferenceCallResolver
            .resolve_runtime_call::<2>("slice_explicit_repeated_subslice", 2)
            .unwrap();
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 16>(slice_explicit_repeated_subslice),
            Some(0)
        );
        let shared_slice_explicit_repeated_subslice = MutableReferenceCallResolver
            .resolve_runtime_call::<2>("shared_slice_explicit_repeated_subslice", 2)
            .unwrap();
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 16>(
                shared_slice_explicit_repeated_subslice
            ),
            Some(0)
        );
        let array_element_alias = MutableReferenceCallResolver
            .resolve_runtime_call::<2>("array_element_alias", 1)
            .unwrap();
        let shared_array_element_alias = MutableReferenceCallResolver
            .resolve_runtime_call::<2>("shared_array_element_alias", 1)
            .unwrap();
        let slice_subslice_alias = MutableReferenceCallResolver
            .resolve_runtime_call::<2>("slice_subslice_alias", 1)
            .unwrap();
        let shared_slice_subslice_alias = MutableReferenceCallResolver
            .resolve_runtime_call::<2>("shared_slice_subslice_alias", 1)
            .unwrap();
        let shared_slice_repeated_subslice = MutableReferenceCallResolver
            .resolve_runtime_call::<2>("shared_slice_repeated_subslice", 1)
            .unwrap();
        let shared_slice_repeated_subslice_alias = MutableReferenceCallResolver
            .resolve_runtime_call::<2>("shared_slice_repeated_subslice_alias", 1)
            .unwrap();
        let shared_slice_repeated_subslice_alias_chain = MutableReferenceCallResolver
            .resolve_runtime_call::<4>("shared_slice_repeated_subslice_alias_chain", 1)
            .unwrap();
        let shared_slice_reassigned_repeated_subslice = MutableReferenceCallResolver
            .resolve_runtime_call::<4>("shared_slice_reassigned_repeated_subslice", 1)
            .unwrap();
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 16>(array_element_alias),
            Some(0)
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 16>(shared_array_element_alias),
            Some(0)
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 24>(RuntimeCallTarget {
                body_expression: concat!(
                    "let mut alias: &u16 = &mut values[0]; ",
                    "alias = &mut values[1]; alias"
                ),
                ..shared_array_element_alias
            }),
            Some(0)
        );
        let mut shared_assignment_parameters = shared_array_element_alias.parameters;
        shared_assignment_parameters[1] = Some(RuntimeCallParameter {
            name: "alternate",
            ty: shared_array_element_alias.return_type,
        });
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 24>(RuntimeCallTarget {
                parameters: shared_assignment_parameters,
                parameter_count: 2,
                body_expression: concat!(
                    "let mut alias: &mut u16 = &mut values[0]; ",
                    "alias = alternate; alias"
                ),
                ..shared_array_element_alias
            }),
            None
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 24>(RuntimeCallTarget {
                body_expression: concat!(
                    "let mut alias = &mut values[0]; ",
                    "alias = &mut values[1]; alias"
                ),
                ..array_element_alias
            }),
            Some(0)
        );
        for body_expression in [
            concat!(
                "let mut storage: u16 = 1; let mut alias = &mut storage; ",
                "alias = &mut values[0]; alias"
            ),
            concat!(
                "let mut storage: u16 = 1; let mut alias = &mut storage; ",
                "if true { alias = &mut values[0]; } else { alias = &mut values[1]; } alias"
            ),
        ] {
            assert_eq!(
                runtime_reference_call_origin_parameter::<2, 32>(RuntimeCallTarget {
                    body_expression,
                    ..array_element_alias
                }),
                Some(0)
            );
        }
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 16>(slice_subslice_alias),
            Some(0)
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 24>(shared_slice_subslice_alias),
            Some(0)
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 24>(
                shared_slice_repeated_subslice
            ),
            Some(0)
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 24>(
                shared_slice_repeated_subslice_alias
            ),
            Some(0)
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<4, 32>(
                shared_slice_repeated_subslice_alias_chain
            ),
            Some(0)
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<4, 32>(
                shared_slice_reassigned_repeated_subslice
            ),
            Some(0)
        );
        let mut cross_origin_parameters = shared_slice_reassigned_repeated_subslice.parameters;
        cross_origin_parameters[1] = Some(RuntimeCallParameter {
            name: "alternate",
            ty: shared_slice_reassigned_repeated_subslice.parameters[0]
                .unwrap()
                .ty,
        });
        assert_eq!(
            runtime_reference_call_origin_parameter::<4, 32>(RuntimeCallTarget {
                parameters: cross_origin_parameters,
                parameter_count: 2,
                body_expression: concat!(
                    "let mut selected: &mut [u16] = &mut values[0..][1..]; ",
                    "selected = &mut alternate[1..][1..]; ",
                    "let shared: &[u16] = selected; shared"
                ),
                ..shared_slice_reassigned_repeated_subslice
            }),
            Some(1)
        );
        cross_origin_parameters[2] = Some(RuntimeCallParameter {
            name: "choose_alternate",
            ty: ScalarType::Bool,
        });
        assert_eq!(
            runtime_reference_call_origin_parameter::<4, 40>(RuntimeCallTarget {
                parameters: cross_origin_parameters,
                parameter_count: 3,
                body_expression: concat!(
                    "let mut selected: &mut [u16] = &mut values[0..][1..]; ",
                    "if choose_alternate { selected = &mut alternate[1..][1..]; } ",
                    "let shared: &[u16] = selected; shared"
                ),
                ..shared_slice_reassigned_repeated_subslice
            }),
            None
        );
        let mutable_slice_reference = shared_slice_repeated_subslice_alias.parameters[0]
            .unwrap()
            .ty;
        let shared_slice_reference = shared_slice_repeated_subslice_alias.return_type;
        let mut shared_parameter = shared_slice_repeated_subslice_alias.parameters;
        shared_parameter[0] = Some(RuntimeCallParameter {
            name: "values",
            ty: shared_slice_reference,
        });
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 24>(RuntimeCallTarget {
                parameters: shared_parameter,
                return_type: mutable_slice_reference,
                return_type_name: "&mut [u16]",
                body_expression: "&mut values[0..][1..]",
                ..shared_slice_repeated_subslice_alias
            }),
            None
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 16>(RuntimeCallTarget {
                body_expression: "let alias: &mut [u16] = &mut values[0]; alias",
                ..array_element_alias
            }),
            None
        );
        for body_expression in [
            concat!(
                "let mut alias: &mut [u16] = &mut values[1..]; ",
                "alias = &mut values[0]; alias"
            ),
            concat!(
                "let mut alias: &mut [u16] = &mut values[1..]; ",
                "if true { alias = &mut values[0]; } else { alias = &mut values[1]; } alias"
            ),
            concat!(
                "let mut alias = &mut values[1..]; ",
                "alias = &mut values[0]; alias"
            ),
            concat!(
                "let mut alias = &mut values[1..]; ",
                "if true { alias = &mut values[0]; } else { alias = &mut values[1]; } alias"
            ),
            concat!(
                "let mut alias: &mut u16 = &mut values[1..]; ",
                "alias = &mut values[0]; alias"
            ),
            concat!(
                "let mut alias: &mut u16 = &mut values[1..]; ",
                "if true { alias = &mut values[0]; } else { alias = &mut values[1]; } alias"
            ),
        ] {
            assert_eq!(
                runtime_reference_call_origin_parameter::<2, 32>(RuntimeCallTarget {
                    body_expression,
                    ..array_element_alias
                }),
                None
            );
        }
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 16>(RuntimeCallTarget {
                body_expression: "&mut values[0]",
                ..array_subslice
            }),
            None
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 16>(RuntimeCallTarget {
                body_expression: "&mut (*values)[1]",
                ..target
            }),
            Some(0)
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 16>(RuntimeCallTarget {
                body_expression: "&mut values",
                ..target
            }),
            None
        );
        let mut shared_parameters = target.parameters;
        shared_parameters[0] = Some(RuntimeCallParameter {
            ty: ScalarType::ArrayReference {
                element: crate::CallArrayElement::Integer(crate::IntegerType::U16),
                count: 2,
                mutable: false,
            },
            ..shared_parameters[0].unwrap()
        });
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 16>(RuntimeCallTarget {
                parameters: shared_parameters,
                ..target
            }),
            None
        );
    }

    #[test]
    fn runtime_direct_loop_return_call_results_retain_argument_origins() {
        fn analyze(source: &str) -> Result<usize, CodegenError> {
            let module = Parser::new(source).parse_module::<1, 8>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            let body = function.parse_body::<8>().unwrap();
            let mut facts = RuntimeBodyFacts::EMPTY;
            preanalyze_runtime_body_declarations::<_, 8, 40>(
                &function,
                &MutableReferenceCallResolver,
                &body,
                "u16",
                function.body_expression_span.start,
                &mut facts,
            )
        }

        for source in [
            "fn value(input: &mut u16, first: bool) -> u16 { let returned: &mut u16 = loop_choose(input, first); let competing: &mut u16 = &mut *input; *competing += 1; *returned }",
            "fn value(input: &mut u16, alternate: &mut u16, first: bool) -> u16 { let mut returned: &mut u16 = alternate; returned = loop_choose(input, first); let competing: &mut u16 = &mut *input; *competing += 1; *returned }",
        ] {
            assert_eq!(
                analyze(source).unwrap_err().kind,
                CodegenErrorKind::RuntimeBorrowConflict
            );
        }

        for source in [
            "fn value(input: &mut u16, first: bool) -> u16 { let returned: &mut u16 = loop_choose(input, first); *returned += 1; let restored: &mut u16 = &mut *input; *restored }",
            "fn value(input: &mut u16, alternate: &mut u16, first: bool) -> u16 { let mut returned: &mut u16 = alternate; returned = loop_choose(input, first); *returned += 1; let restored: &mut u16 = &mut *input; *restored }",
        ] {
            analyze(source).unwrap();
        }

        let loop_choose = MutableReferenceCallResolver
            .resolve_runtime_call::<2>("loop_choose", 2)
            .unwrap();
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 24>(loop_choose),
            Some(0)
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 24>(RuntimeCallTarget {
                body_expression: "while first { return value; } let value: u16 = 1; value",
                ..loop_choose
            }),
            None
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 24>(RuntimeCallTarget {
                body_expression: concat!(
                    "loop { let mut changed: &mut u16 = value; ",
                    "changed = &mut *changed; if first { return changed; } }"
                ),
                ..loop_choose
            }),
            Some(0)
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 32>(RuntimeCallTarget {
                body_expression: concat!(
                    "let mut local: u16 = 1; loop { ",
                    "let mut changed: &mut u16 = value; changed = &mut local; ",
                    "if first { return changed; } }"
                ),
                ..loop_choose
            }),
            None
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 24>(RuntimeCallTarget {
                body_expression: concat!(
                    "loop { let mut changed: &mut u16 = value; ",
                    "changed = &mut *changed; return changed; ",
                    "changed = value; }"
                ),
                ..loop_choose
            }),
            Some(0)
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 32>(RuntimeCallTarget {
                body_expression: concat!(
                    "let mut local: u16 = 1; loop { ",
                    "let mut changed: &mut u16 = value; changed = &mut local; ",
                    "return changed; changed = value; }"
                ),
                ..loop_choose
            }),
            None
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 32>(RuntimeCallTarget {
                body_expression: concat!(
                    "let mut local: u16 = 1; let mut changed: &mut u16 = &mut local; ",
                    "while first { changed = value; break; } changed"
                ),
                ..loop_choose
            }),
            None
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 32>(RuntimeCallTarget {
                body_expression: concat!(
                    "let mut local: u16 = 1; let mut changed: &mut u16 = &mut local; ",
                    "loop { changed = value; break; } changed"
                ),
                ..loop_choose
            }),
            Some(0)
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 32>(RuntimeCallTarget {
                body_expression: concat!(
                    "loop { let mut changed: &mut u16 = value; ",
                    "changed = &mut *changed; loop { ",
                    "if first { return changed; } } }"
                ),
                ..loop_choose
            }),
            Some(0)
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 40>(RuntimeCallTarget {
                body_expression: concat!(
                    "let mut local: u16 = 1; loop { ",
                    "let mut changed: &mut u16 = value; changed = &mut local; ",
                    "loop { if first { return changed; } } }"
                ),
                ..loop_choose
            }),
            None
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 40>(RuntimeCallTarget {
                body_expression: concat!(
                    "let mut local: u16 = 1; let mut changed: &mut u16 = &mut local; ",
                    "loop { changed = value; if first { break; } ",
                    "changed = &mut local; } changed"
                ),
                ..loop_choose
            }),
            Some(0)
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 40>(RuntimeCallTarget {
                body_expression: concat!(
                    "let mut local: u16 = 1; let mut changed: &mut u16 = value; ",
                    "loop { changed = &mut local; if first { break; } ",
                    "changed = value; } changed"
                ),
                ..loop_choose
            }),
            None
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 40>(RuntimeCallTarget {
                body_expression: concat!(
                    "let mut local: u16 = 1; let mut changed: &mut u16 = value; ",
                    "loop { changed = value; if first { return changed; } ",
                    "continue; changed = &mut local; }"
                ),
                ..loop_choose
            }),
            Some(0)
        );
        let conditional_continue = RuntimeCallTarget {
            name: loop_choose.name,
            parameters: [
                loop_choose.parameters[0],
                loop_choose.parameters[1],
                Some(RuntimeCallParameter {
                    name: "second",
                    ty: ScalarType::Bool,
                }),
            ],
            parameter_count: 3,
            return_type: loop_choose.return_type,
            return_type_name: loop_choose.return_type_name,
            body_expression: concat!(
                "let mut local: u16 = 1; let mut changed: &mut u16 = value; loop { ",
                "if first { return changed; } changed = value; ",
                "if second { continue; } changed = &mut local; changed = value; }"
            ),
        };
        assert_eq!(
            runtime_reference_call_origin_parameter::<3, 48>(conditional_continue),
            Some(0)
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<3, 48>(RuntimeCallTarget {
                body_expression: concat!(
                    "let mut local: u16 = 1; let mut changed: &mut u16 = value; ",
                    "while first { changed = value; if second { continue; } ",
                    "changed = &mut local; } changed"
                ),
                ..conditional_continue
            }),
            None
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 40>(RuntimeCallTarget {
                body_expression: concat!(
                    "let mut local: u16 = 1; let mut changed: &mut u16 = &mut local; ",
                    "loop { if first { changed = value; break; } ",
                    "else { changed = value; break; } } changed"
                ),
                ..loop_choose
            }),
            Some(0)
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 40>(RuntimeCallTarget {
                body_expression: concat!(
                    "let mut local: u16 = 1; let mut changed: &mut u16 = value; ",
                    "loop { if first { changed = value; break; } ",
                    "else { changed = &mut local; break; } } changed"
                ),
                ..loop_choose
            }),
            None
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 40>(RuntimeCallTarget {
                body_expression: concat!(
                    "let mut changed: &mut u16 = value; loop { ",
                    "if first { changed = value; continue; } ",
                    "else { changed = value; } return changed; }"
                ),
                ..loop_choose
            }),
            Some(0)
        );
    }

    #[test]
    fn runtime_conditional_loop_block_call_results_retain_argument_origins() {
        fn analyze(source: &str) -> Result<usize, CodegenError> {
            let module = Parser::new(source).parse_module::<1, 8>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            let body = function.parse_body::<8>().unwrap();
            let mut facts = RuntimeBodyFacts::EMPTY;
            preanalyze_runtime_body_declarations::<_, 8, 40>(
                &function,
                &MutableReferenceCallResolver,
                &body,
                "u16",
                function.body_expression_span.start,
                &mut facts,
            )
        }

        for source in [
            "fn value(input: &mut u16, first: bool) -> u16 { let returned: &mut u16 = loop_branch(input, first); let competing: &mut u16 = &mut *input; *competing += 1; *returned }",
            "fn value(input: &mut u16, alternate: &mut u16, first: bool) -> u16 { let mut returned: &mut u16 = alternate; returned = loop_branch(input, first); let competing: &mut u16 = &mut *input; *competing += 1; *returned }",
        ] {
            assert_eq!(
                analyze(source).unwrap_err().kind,
                CodegenErrorKind::RuntimeBorrowConflict
            );
        }

        for source in [
            "fn value(input: &mut u16, first: bool) -> u16 { let returned: &mut u16 = loop_branch(input, first); *returned += 1; let restored: &mut u16 = &mut *input; *restored }",
            "fn value(input: &mut u16, alternate: &mut u16, first: bool) -> u16 { let mut returned: &mut u16 = alternate; returned = loop_branch(input, first); *returned += 1; let restored: &mut u16 = &mut *input; *restored }",
        ] {
            analyze(source).unwrap();
        }

        let loop_branch = MutableReferenceCallResolver
            .resolve_runtime_call::<2>("loop_branch", 2)
            .unwrap();
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 24>(loop_branch),
            Some(0)
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 24>(RuntimeCallTarget {
                body_expression: "loop { if first { let changed: &mut u16 = value; return changed; } else { return value; } }",
                ..loop_branch
            }),
            Some(0)
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 24>(RuntimeCallTarget {
                body_expression: concat!(
                    "loop { if first { let mut changed: &mut u16 = value; ",
                    "changed = &mut *changed; return changed; } else { return value; } }"
                ),
                ..loop_branch
            }),
            Some(0)
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 32>(RuntimeCallTarget {
                body_expression: concat!(
                    "let mut local: u16 = 1; loop { if first { ",
                    "let mut changed: &mut u16 = value; changed = &mut local; ",
                    "return changed; } else { return value; } }"
                ),
                ..loop_branch
            }),
            None
        );
    }

    #[test]
    fn runtime_nested_loop_call_results_retain_argument_origins() {
        fn analyze(source: &str) -> Result<usize, CodegenError> {
            let module = Parser::new(source).parse_module::<1, 8>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            let body = function.parse_body::<8>().unwrap();
            let mut facts = RuntimeBodyFacts::EMPTY;
            preanalyze_runtime_body_declarations::<_, 8, 40>(
                &function,
                &MutableReferenceCallResolver,
                &body,
                "u16",
                function.body_expression_span.start,
                &mut facts,
            )
        }

        for source in [
            "fn value(input: &mut u16, first: bool) -> u16 { let returned: &mut u16 = nested_loop(input, first); let competing: &mut u16 = &mut *input; *competing += 1; *returned }",
            "fn value(input: &mut u16, alternate: &mut u16, first: bool) -> u16 { let mut returned: &mut u16 = alternate; returned = nested_loop(input, first); let competing: &mut u16 = &mut *input; *competing += 1; *returned }",
            "fn value(input: &mut u16, first: bool) -> u16 { let returned: &mut u16 = nested_loop_tuple_assign(input, first); let competing: &mut u16 = &mut *input; *competing += 1; *returned }",
        ] {
            assert_eq!(
                analyze(source).unwrap_err().kind,
                CodegenErrorKind::RuntimeBorrowConflict
            );
        }

        for source in [
            "fn value(input: &mut u16, first: bool) -> u16 { let returned: &mut u16 = nested_loop(input, first); *returned += 1; let restored: &mut u16 = &mut *input; *restored }",
            "fn value(input: &mut u16, alternate: &mut u16, first: bool) -> u16 { let mut returned: &mut u16 = alternate; returned = nested_loop(input, first); *returned += 1; let restored: &mut u16 = &mut *input; *restored }",
            "fn value(input: &mut u16, first: bool) -> u16 { let returned: &mut u16 = nested_loop_tuple_assign(input, first); *returned += 1; let restored: &mut u16 = &mut *input; *restored }",
        ] {
            analyze(source).unwrap();
        }

        let nested_loop = MutableReferenceCallResolver
            .resolve_runtime_call::<2>("nested_loop", 2)
            .unwrap();
        let nested_continue = RuntimeCallTarget {
            name: nested_loop.name,
            parameters: [
                nested_loop.parameters[0],
                nested_loop.parameters[1],
                Some(RuntimeCallParameter {
                    name: "second",
                    ty: ScalarType::Bool,
                }),
            ],
            parameter_count: 3,
            return_type: nested_loop.return_type,
            return_type_name: nested_loop.return_type_name,
            body_expression: "",
        };
        let nested_multi_backedge = RuntimeCallTarget {
            name: nested_loop.name,
            parameters: [
                nested_loop.parameters[0],
                nested_loop.parameters[1],
                nested_continue.parameters[2],
                Some(RuntimeCallParameter {
                    name: "third",
                    ty: ScalarType::Bool,
                }),
            ],
            parameter_count: 4,
            return_type: nested_loop.return_type,
            return_type_name: nested_loop.return_type_name,
            body_expression: "",
        };
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 24>(nested_loop),
            Some(0)
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 32>(RuntimeCallTarget {
                body_expression: concat!(
                    "loop { loop { if first { ",
                    "let changed: &mut u16 = &mut *value; return changed; } } }"
                ),
                ..nested_loop
            }),
            Some(0)
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 32>(RuntimeCallTarget {
                body_expression: concat!(
                    "loop { loop { if first { let mut local: u16 = 1; ",
                    "let changed: &mut u16 = &mut local; return changed; } } }"
                ),
                ..nested_loop
            }),
            None
        );
        let nested_loop_tuple_assign = MutableReferenceCallResolver
            .resolve_runtime_call::<2>("nested_loop_tuple_assign", 2)
            .unwrap();
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 32>(nested_loop_tuple_assign),
            Some(0)
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 40>(RuntimeCallTarget {
                body_expression: concat!(
                    "let mut local: u16 = 1; loop { loop { ",
                    "let mut alias: &mut u16 = value; ",
                    "let pair: (&mut u16,) = (&mut local,); alias = pair.0; ",
                    "if first { return alias; } } }"
                ),
                ..nested_loop_tuple_assign
            }),
            None
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 24>(RuntimeCallTarget {
                body_expression: "loop { loop { let changed: &mut u16 = value; if first { return changed; } } }",
                ..nested_loop
            }),
            Some(0)
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 24>(RuntimeCallTarget {
                body_expression: concat!(
                    "loop { loop { let mut changed: &mut u16 = value; ",
                    "changed = &mut *changed; if first { return changed; } } }"
                ),
                ..nested_loop
            }),
            Some(0)
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 40>(RuntimeCallTarget {
                body_expression: concat!(
                    "let mut local: u16 = 1; let mut changed: &mut u16 = &mut local; ",
                    "loop { loop { if first { return changed; } ",
                    "changed = value; return changed; } }"
                ),
                ..nested_loop
            }),
            None
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 40>(RuntimeCallTarget {
                body_expression: concat!(
                    "let mut local: u16 = 1; let mut changed: &mut u16 = value; ",
                    "loop { loop { if first { return changed; } ",
                    "changed = &mut local; changed = value; return changed; } }"
                ),
                ..nested_loop
            }),
            Some(0)
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 40>(RuntimeCallTarget {
                body_expression: concat!(
                    "let mut local: u16 = 1; let mut changed: &mut u16 = value; ",
                    "loop { loop { if first { return changed; } ",
                    "changed = &mut local; } }"
                ),
                ..nested_loop
            }),
            None
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 40>(RuntimeCallTarget {
                body_expression: concat!(
                    "let mut local: u16 = 1; let mut changed: &mut u16 = value; ",
                    "loop { loop { if first { return changed; } ",
                    "changed = &mut local; changed = value; } }"
                ),
                ..nested_loop
            }),
            Some(0)
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 24>(RuntimeCallTarget {
                body_expression: concat!(
                    "loop { loop { let mut local: u16 = 1; ",
                    "let changed: &mut u16 = &mut local; if first { return changed; } } }"
                ),
                ..nested_loop
            }),
            None
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 40>(RuntimeCallTarget {
                body_expression: concat!(
                    "let mut local: u16 = 1; let mut changed: &mut u16 = &mut local; ",
                    "loop { loop { changed = value; break; } return changed; }"
                ),
                ..nested_loop
            }),
            Some(0)
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 40>(RuntimeCallTarget {
                body_expression: concat!(
                    "let mut local: u16 = 1; let mut changed: &mut u16 = value; ",
                    "loop { loop { changed = &mut local; break; } return changed; }"
                ),
                ..nested_loop
            }),
            None
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 40>(RuntimeCallTarget {
                body_expression: concat!(
                    "let mut local: u16 = 1; let mut changed: &mut u16 = &mut local; ",
                    "loop { while first { changed = value; break; } return changed; }"
                ),
                ..nested_loop
            }),
            None
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 40>(RuntimeCallTarget {
                body_expression: concat!(
                    "let mut local: u16 = 1; let mut changed: &mut u16 = &mut local; ",
                    "'outer: loop { loop { changed = value; break 'outer; } } changed"
                ),
                ..nested_loop
            }),
            Some(0)
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 40>(RuntimeCallTarget {
                body_expression: concat!(
                    "let mut local: u16 = 1; let mut changed: &mut u16 = value; ",
                    "'outer: loop { loop { changed = &mut local; break 'outer; } } changed"
                ),
                ..nested_loop
            }),
            None
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 40>(RuntimeCallTarget {
                body_expression: concat!(
                    "let mut changed: &mut u16 = &mut *value; 'outer: while first { ",
                    "loop { changed = &mut *value; continue 'outer; } } changed"
                ),
                ..nested_loop
            }),
            Some(0)
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 40>(RuntimeCallTarget {
                body_expression: concat!(
                    "let mut local: u16 = 1; let mut changed: &mut u16 = &mut *value; ",
                    "'outer: while first { loop { changed = &mut local; ",
                    "continue 'outer; } } changed"
                ),
                ..nested_loop
            }),
            None
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 48>(RuntimeCallTarget {
                body_expression: concat!(
                    "let mut local: u16 = 1; let mut changed: &mut u16 = &mut local; ",
                    "'outer: loop { loop { changed = value; ",
                    "if first { break 'outer; } break; } return changed; } changed"
                ),
                ..nested_loop
            }),
            Some(0)
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 48>(RuntimeCallTarget {
                body_expression: concat!(
                    "let mut local: u16 = 1; let mut changed: &mut u16 = value; ",
                    "'outer: loop { loop { changed = &mut local; ",
                    "if first { break 'outer; } changed = value; break; } ",
                    "return changed; } changed"
                ),
                ..nested_loop
            }),
            None
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 48>(RuntimeCallTarget {
                body_expression: concat!(
                    "let mut changed: &mut u16 = &mut *value; 'outer: while first { ",
                    "loop { changed = &mut *value; if first { continue 'outer; } ",
                    "break; } break 'outer; } changed"
                ),
                ..nested_loop
            }),
            Some(0)
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 48>(RuntimeCallTarget {
                body_expression: concat!(
                    "let mut local: u16 = 1; let mut changed: &mut u16 = &mut *value; ",
                    "'outer: while first { loop { changed = &mut *value; ",
                    "if first { continue 'outer; } changed = &mut local; break; } ",
                    "break 'outer; } changed"
                ),
                ..nested_loop
            }),
            None
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 40>(RuntimeCallTarget {
                body_expression: concat!(
                    "let mut local: u16 = 1; let mut changed: &mut u16 = &mut local; ",
                    "loop { loop { changed = value; if first { break; } } ",
                    "return changed; }"
                ),
                ..nested_loop
            }),
            Some(0)
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 40>(RuntimeCallTarget {
                body_expression: concat!(
                    "let mut local: u16 = 1; let mut changed: &mut u16 = &mut local; ",
                    "loop { loop { if first { break; } changed = value; } ",
                    "return changed; }"
                ),
                ..nested_loop
            }),
            None
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<3, 48>(RuntimeCallTarget {
                body_expression: concat!(
                    "let mut local: u16 = 1; let mut changed: &mut u16 = &mut local; ",
                    "loop { loop { changed = value; if first { continue; } ",
                    "if second { break; } } return changed; }"
                ),
                ..nested_continue
            }),
            Some(0)
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<3, 48>(RuntimeCallTarget {
                body_expression: concat!(
                    "let mut local: u16 = 1; let mut changed: &mut u16 = &mut local; ",
                    "loop { loop { if first { continue; } if second { break; } ",
                    "changed = value; } return changed; }"
                ),
                ..nested_continue
            }),
            None
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 40>(RuntimeCallTarget {
                body_expression: concat!(
                    "let mut local: u16 = 1; let mut changed: &mut u16 = &mut local; ",
                    "loop { loop { changed = value; if first { return changed; } ",
                    "continue; changed = &mut local; } }"
                ),
                ..nested_loop
            }),
            Some(0)
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<2, 40>(RuntimeCallTarget {
                body_expression: concat!(
                    "let mut local: u16 = 1; let mut changed: &mut u16 = &mut local; ",
                    "loop { loop { if first { return changed; } changed = value; ",
                    "continue; } }"
                ),
                ..nested_loop
            }),
            None
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<4, 64>(RuntimeCallTarget {
                body_expression: concat!(
                    "let mut local: u16 = 1; let mut changed: &mut u16 = &mut local; ",
                    "loop { loop { changed = value; if first { continue; } ",
                    "changed = &mut local; if second { continue; } changed = value; ",
                    "if third { break; } } return changed; }"
                ),
                ..nested_multi_backedge
            }),
            Some(0)
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<4, 64>(RuntimeCallTarget {
                body_expression: concat!(
                    "let mut local: u16 = 1; let mut changed: &mut u16 = &mut local; ",
                    "loop { loop { if third { break; } changed = value; ",
                    "if first { continue; } changed = &mut local; ",
                    "if second { continue; } changed = value; } return changed; }"
                ),
                ..nested_multi_backedge
            }),
            None
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<4, 64>(RuntimeCallTarget {
                body_expression: concat!(
                    "let mut local: u16 = 1; let mut changed: &mut u16 = &mut local; ",
                    "loop { loop { changed = value; if first { continue; } ",
                    "changed = &mut local; if second { continue; } changed = value; ",
                    "break; changed = &mut local; } return changed; }"
                ),
                ..nested_multi_backedge
            }),
            Some(0)
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<4, 64>(RuntimeCallTarget {
                body_expression: concat!(
                    "let mut local: u16 = 1; let mut changed: &mut u16 = &mut local; ",
                    "loop { loop { if third { break; } changed = value; ",
                    "if first { continue; } changed = &mut local; ",
                    "if second { continue; } changed = value; break; } ",
                    "return changed; }"
                ),
                ..nested_multi_backedge
            }),
            None
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<4, 64>(RuntimeCallTarget {
                body_expression: concat!(
                    "let mut local: u16 = 1; let mut changed: &mut u16 = &mut local; ",
                    "loop { loop { changed = value; if first { return changed; } ",
                    "if second { continue; } changed = &mut local; ",
                    "if third { continue; } changed = value; continue; ",
                    "changed = &mut local; } }"
                ),
                ..nested_multi_backedge
            }),
            Some(0)
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<4, 64>(RuntimeCallTarget {
                body_expression: concat!(
                    "let mut local: u16 = 1; let mut changed: &mut u16 = &mut local; ",
                    "loop { loop { if first { return changed; } changed = value; ",
                    "if second { continue; } changed = &mut local; ",
                    "if third { continue; } changed = value; continue; } }"
                ),
                ..nested_multi_backedge
            }),
            None
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<3, 80>(RuntimeCallTarget {
                body_expression: concat!(
                    "let mut local: u16 = 1; let mut a: &mut u16 = &mut *value; ",
                    "let mut b: &mut u16 = &mut *value; loop { loop { ",
                    "a = &mut *b; b = &mut local; ",
                    "if first { continue; } a = &mut *value; ",
                    "if second { break; } } return a; }"
                ),
                ..nested_continue
            }),
            Some(0)
        );
        assert_eq!(
            runtime_reference_call_origin_parameter::<3, 80>(RuntimeCallTarget {
                body_expression: concat!(
                    "let mut local: u16 = 1; let mut a: &mut u16 = &mut *value; ",
                    "let mut b: &mut u16 = &mut *value; loop { loop { ",
                    "a = &mut *b; b = &mut local; ",
                    "if second { break; } a = &mut *value; ",
                    "if first { continue; } } return a; }"
                ),
                ..nested_continue
            }),
            None
        );
    }

    #[test]
    fn runtime_single_block_initializedness_accepts_exact_write_reinitialization() {
        let source = "fn value(input: &mut u16) -> &mut u16 { let mut slot: &mut u16 = input; let moved: &mut u16 = slot; slot = &mut *moved; slot }";
        let module = Parser::new(source).parse_module::<1, 4>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<4>().unwrap();
        let mut facts = RuntimeBodyFacts::EMPTY;
        assert_eq!(
            preanalyze_runtime_body_declarations::<_, 4, 16>(
                &function,
                &NoConstants,
                &body,
                "&mut u16",
                function.body_expression_span.start,
                &mut facts,
            )
            .unwrap(),
            2
        );
        assert!(
            facts.effects[..facts.effect_count]
                .iter()
                .flatten()
                .any(|effect| effect.kind == RuntimePlaceEffectKind::Write)
        );
    }

    #[test]
    fn runtime_tuple_field_initializedness_tracks_partial_moves_and_writes() {
        let rejected = "fn value(first: &mut u16, second: &mut u16) -> &mut u16 { let pair = (first, second); let moved = pair.0; let repeated = pair.0; repeated }";
        let module = Parser::new(rejected).parse_module::<2, 4>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<4>().unwrap();
        let mut facts = RuntimeBodyFacts::EMPTY;
        assert_eq!(
            preanalyze_runtime_body_declarations::<_, 4, 24>(
                &function,
                &NoConstants,
                &body,
                "&mut u16",
                function.body_expression_span.start,
                &mut facts,
            )
            .unwrap_err()
            .kind,
            CodegenErrorKind::RuntimeUseAfterMove
        );

        let partial = "fn value(first: &mut u16, second: &mut u16) -> &mut u16 { let pair = (first, second); let moved = pair.0; pair.1 }";
        let module = Parser::new(partial).parse_module::<2, 4>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<4>().unwrap();
        let mut facts = RuntimeBodyFacts::EMPTY;
        assert_eq!(
            preanalyze_runtime_body_declarations::<_, 4, 24>(
                &function,
                &NoConstants,
                &body,
                "&mut u16",
                function.body_expression_span.start,
                &mut facts,
            )
            .unwrap(),
            2
        );

        let whole = "fn value(first: &mut u16, second: &mut u16) -> &mut u16 { let pair = (first, second); let moved = pair.0; let consumed = pair; consumed.1 }";
        let module = Parser::new(whole).parse_module::<2, 4>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<4>().unwrap();
        let mut facts = RuntimeBodyFacts::EMPTY;
        assert_eq!(
            preanalyze_runtime_body_declarations::<_, 4, 24>(
                &function,
                &NoConstants,
                &body,
                "&mut u16",
                function.body_expression_span.start,
                &mut facts,
            )
            .unwrap_err()
            .kind,
            CodegenErrorKind::RuntimeUseAfterMove
        );

        let accepted = "fn value(first: &mut u16, second: &mut u16) -> &mut u16 { let mut pair = (first, second); let moved = pair.0; pair.0 = &mut *moved; pair.0 }";
        let module = Parser::new(accepted).parse_module::<2, 4>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<4>().unwrap();
        let mut facts = RuntimeBodyFacts::EMPTY;
        assert_eq!(
            preanalyze_runtime_body_declarations::<_, 4, 24>(
                &function,
                &NoConstants,
                &body,
                "&mut u16",
                function.body_expression_span.start,
                &mut facts,
            )
            .unwrap(),
            2
        );
        let tuple_path = facts.move_paths[..facts.move_path_count]
            .iter()
            .flatten()
            .find(|path| {
                path.projections
                    == RuntimePlaceProjections::single(RuntimePlaceProjection::TupleField(0))
                    && !runtime_type_is_copy(path.ty)
            })
            .unwrap()
            .id;
        assert!(
            facts.effects[..facts.effect_count]
                .iter()
                .flatten()
                .any(|effect| {
                    effect.path == tuple_path && effect.kind == RuntimePlaceEffectKind::Move
                })
        );
        assert!(
            facts.effects[..facts.effect_count]
                .iter()
                .flatten()
                .any(|effect| {
                    effect.path == tuple_path && effect.kind == RuntimePlaceEffectKind::Write
                })
        );
    }

    #[test]
    fn runtime_multiblock_initializedness_preserves_early_return_paths() {
        let source = "fn value(input: &mut u16, choose: bool) -> &mut u16 { if choose { return identity(input); } input }";
        let module = Parser::new(source).parse_module::<2, 4>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<4>().unwrap();
        let mut facts = RuntimeBodyFacts::EMPTY;
        preanalyze_runtime_body_declarations::<_, 4, 16>(
            &function,
            &MutableReferenceCallResolver,
            &body,
            "&mut u16",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();
        assert!(facts.basic_block_count > 1);
        assert_eq!(
            facts.effects[..facts.effect_count]
                .iter()
                .flatten()
                .filter(|effect| effect.kind == RuntimePlaceEffectKind::Move)
                .count(),
            0
        );
        assert!(
            facts.effects[..facts.effect_count]
                .iter()
                .flatten()
                .any(
                    |effect| effect.kind == RuntimePlaceEffectKind::MutableBorrow
                        && effect.location == RuntimeOwnershipEventLocation::Tail
                )
        );
        assert!(
            facts.effects[..facts.effect_count]
                .iter()
                .flatten()
                .any(|effect| {
                    effect.kind == RuntimePlaceEffectKind::Copy
                        && effect.location
                            == (RuntimeOwnershipEventLocation::ConditionalReturnCondition {
                                statement_index: 0,
                                branch_index: 0,
                            })
                })
        );
        assert!(
            facts.effects[..facts.effect_count]
                .iter()
                .flatten()
                .any(|effect| {
                    effect.kind == RuntimePlaceEffectKind::MutableBorrow
                        && effect.location
                            == (RuntimeOwnershipEventLocation::ConditionalReturnValue {
                                statement_index: 0,
                                branch_index: 0,
                            })
                })
        );
        assert_eq!(
            facts.ownership_control_point(
                RuntimeOwnershipEventLocation::ConditionalReturnCondition {
                    statement_index: 0,
                    branch_index: 0,
                }
            ),
            Some(RuntimeOwnershipControlPoint::Block(RuntimeBasicBlockId(0)))
        );
        assert_eq!(
            facts.ownership_control_point(RuntimeOwnershipEventLocation::ConditionalReturnValue {
                statement_index: 0,
                branch_index: 0,
            }),
            Some(RuntimeOwnershipControlPoint::Edge(0))
        );

        let conditional_tail = "fn value(input: &mut u16, choose: bool) -> &mut u16 { if choose { input } else { &mut *input } }";
        let module = Parser::new(conditional_tail)
            .parse_module::<2, 2>()
            .unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<2>().unwrap();
        let mut facts = RuntimeBodyFacts::EMPTY;
        preanalyze_runtime_body_declarations::<_, 2, 16>(
            &function,
            &NoConstants,
            &body,
            "&mut u16",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();
        assert_eq!(facts.basic_block_count, 1);
        assert!(!facts.ownership_events_single_path);
        assert!(
            facts.effects[..facts.effect_count]
                .iter()
                .flatten()
                .any(
                    |effect| effect.kind == RuntimePlaceEffectKind::MutableBorrow
                        && effect.expression_path
                            == RuntimeOwnershipExpressionPath {
                                else_bits: 0,
                                depth: 1,
                            }
                )
        );
        assert!(
            facts.effects[..facts.effect_count]
                .iter()
                .flatten()
                .any(
                    |effect| effect.kind == RuntimePlaceEffectKind::MutableBorrow
                        && effect.expression_path
                            == RuntimeOwnershipExpressionPath {
                                else_bits: 1,
                                depth: 1,
                            }
                )
        );

        let nested = "fn value(input: &mut u16, first: bool, second: bool) -> &mut u16 { if first { if second { input } else { &mut *input } } else { &mut *input } }";
        let module = Parser::new(nested).parse_module::<1, 4>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<4>().unwrap();
        let mut facts = RuntimeBodyFacts::EMPTY;
        preanalyze_runtime_body_declarations::<_, 4, 24>(
            &function,
            &NoConstants,
            &body,
            "&mut u16",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();
        assert_eq!(facts.conditional_expression_count, 2);
        let outer = facts.conditional_expressions[0].unwrap();
        let inner = facts.conditional_expressions[1].unwrap();
        assert_eq!(outer.id, RuntimeConditionalExpressionId(0));
        assert_eq!(outer.location, RuntimeOwnershipEventLocation::Tail);
        assert_eq!(outer.parent, None);
        assert_eq!(outer.parent_path, RuntimeOwnershipExpressionPath::ROOT);
        assert_eq!(inner.id, RuntimeConditionalExpressionId(1));
        assert_eq!(inner.location, RuntimeOwnershipEventLocation::Tail);
        assert_eq!(inner.parent, Some(RuntimeConditionalExpressionId(0)));
        assert_eq!(
            inner.parent_path,
            RuntimeOwnershipExpressionPath {
                else_bits: 0,
                depth: 1,
            }
        );
        assert_eq!(outer.entry, RuntimeExpressionProgramPointId(0));
        assert_eq!(outer.condition, RuntimeExpressionProgramPointId(1));
        assert_eq!(outer.then_branch, RuntimeExpressionProgramPointId(2));
        assert_eq!(outer.else_branch, RuntimeExpressionProgramPointId(3));
        assert_eq!(outer.join, RuntimeExpressionProgramPointId(4));
        assert_eq!(outer.then_exit, Some(inner.join));
        assert_eq!(outer.else_exit, Some(outer.else_branch));
        assert_eq!(inner.entry, outer.then_branch);
        assert_eq!(inner.then_exit, Some(inner.then_branch));
        assert_eq!(inner.else_exit, Some(inner.else_branch));
        for (point, kind) in [
            (
                outer.condition,
                RuntimeExpressionProgramPointKind::Condition(outer.id),
            ),
            (
                outer.then_branch,
                RuntimeExpressionProgramPointKind::Then(outer.id),
            ),
            (
                outer.else_branch,
                RuntimeExpressionProgramPointKind::Else(outer.id),
            ),
            (
                outer.join,
                RuntimeExpressionProgramPointKind::Join(outer.id),
            ),
            (
                inner.condition,
                RuntimeExpressionProgramPointKind::Condition(inner.id),
            ),
            (
                inner.then_branch,
                RuntimeExpressionProgramPointKind::Then(inner.id),
            ),
            (
                inner.else_branch,
                RuntimeExpressionProgramPointKind::Else(inner.id),
            ),
            (
                inner.join,
                RuntimeExpressionProgramPointKind::Join(inner.id),
            ),
        ] {
            assert_eq!(facts.expression_program_points[point.0].unwrap().kind, kind);
        }
        assert_eq!(facts.expression_control_flow_edge_count, 10);
        assert_eq!(
            &facts.expression_control_flow_edges[..10],
            &[
                Some(RuntimeExpressionControlFlowEdgeFact {
                    from: outer.entry,
                    to: outer.condition,
                }),
                Some(RuntimeExpressionControlFlowEdgeFact {
                    from: outer.condition,
                    to: outer.then_branch,
                }),
                Some(RuntimeExpressionControlFlowEdgeFact {
                    from: outer.condition,
                    to: outer.else_branch,
                }),
                Some(RuntimeExpressionControlFlowEdgeFact {
                    from: inner.join,
                    to: outer.join,
                }),
                Some(RuntimeExpressionControlFlowEdgeFact {
                    from: outer.else_branch,
                    to: outer.join,
                }),
                Some(RuntimeExpressionControlFlowEdgeFact {
                    from: inner.entry,
                    to: inner.condition,
                }),
                Some(RuntimeExpressionControlFlowEdgeFact {
                    from: inner.condition,
                    to: inner.then_branch,
                }),
                Some(RuntimeExpressionControlFlowEdgeFact {
                    from: inner.condition,
                    to: inner.else_branch,
                }),
                Some(RuntimeExpressionControlFlowEdgeFact {
                    from: inner.then_branch,
                    to: inner.join,
                }),
                Some(RuntimeExpressionControlFlowEdgeFact {
                    from: inner.else_branch,
                    to: inner.join,
                }),
            ]
        );
        for (kind, expression_path) in [
            (
                RuntimePlaceEffectKind::MutableBorrow,
                RuntimeOwnershipExpressionPath {
                    else_bits: 0,
                    depth: 2,
                },
            ),
            (
                RuntimePlaceEffectKind::MutableBorrow,
                RuntimeOwnershipExpressionPath {
                    else_bits: 2,
                    depth: 2,
                },
            ),
            (
                RuntimePlaceEffectKind::MutableBorrow,
                RuntimeOwnershipExpressionPath {
                    else_bits: 1,
                    depth: 1,
                },
            ),
        ] {
            assert!(
                facts.effects[..facts.effect_count]
                    .iter()
                    .flatten()
                    .any(|effect| effect.kind == kind && effect.expression_path == expression_path)
            );
        }
        assert!(
            facts.effects[..facts.effect_count]
                .iter()
                .flatten()
                .any(
                    |effect| effect.kind == RuntimePlaceEffectKind::MutableBorrow
                        && effect.expression_conditional == Some(RuntimeConditionalExpressionId(1))
                )
        );
        assert!(
            facts.effects[..facts.effect_count]
                .iter()
                .flatten()
                .any(
                    |effect| effect.kind == RuntimePlaceEffectKind::MutableBorrow
                        && effect.expression_path
                            == RuntimeOwnershipExpressionPath {
                                else_bits: 1,
                                depth: 1,
                            }
                        && effect.expression_conditional == Some(RuntimeConditionalExpressionId(0))
                )
        );
        assert!(!facts.expression_origin_is_valid(
            RuntimeOwnershipEventLocation::Tail,
            RuntimeOwnershipExpressionPath {
                else_bits: 0,
                depth: 1,
            },
            Some(RuntimeConditionalExpressionId(2)),
        ));

        let mut capacity = RuntimeBodyFacts::EMPTY;
        capacity.current_ownership_event_location = RuntimeOwnershipEventLocation::Tail;
        capacity.conditional_expression_count = MAX_RUNTIME_OWNERSHIP_EVENT_FACTS;
        assert_eq!(
            capacity.push_conditional_expression(Span { start: 0, end: 1 }),
            Err(CodegenErrorKind::TooManyRuntimeOwnershipEventFacts)
        );
        let mut point_capacity = RuntimeBodyFacts::EMPTY;
        point_capacity.current_ownership_event_location = RuntimeOwnershipEventLocation::Tail;
        point_capacity.expression_program_point_count =
            MAX_RUNTIME_EXPRESSION_PROGRAM_POINT_FACTS - 4;
        assert_eq!(
            point_capacity.push_conditional_expression(Span { start: 0, end: 1 }),
            Err(CodegenErrorKind::TooManyRuntimeOwnershipEventFacts)
        );
        assert_eq!(
            point_capacity.expression_program_point_count,
            MAX_RUNTIME_EXPRESSION_PROGRAM_POINT_FACTS - 4
        );
        assert_eq!(point_capacity.conditional_expression_count, 0);
        let mut edge_capacity = RuntimeBodyFacts::EMPTY;
        edge_capacity.expression_control_flow_edge_count =
            MAX_RUNTIME_EXPRESSION_CONTROL_FLOW_EDGE_FACTS;
        assert_eq!(
            edge_capacity.push_expression_control_flow_edge(RuntimeExpressionControlFlowEdgeFact {
                from: RuntimeExpressionProgramPointId(0),
                to: RuntimeExpressionProgramPointId(1),
            }),
            Err(CodegenErrorKind::TooManyRuntimeControlFlowEdgeFacts)
        );

        let sequential = "fn value(input: &mut u16, first: bool, second: bool) -> &mut u16 { { if first { *input } else { *input }; if second { input } else { &mut *input } } }";
        let module = Parser::new(sequential).parse_module::<1, 4>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<4>().unwrap();
        let mut facts = RuntimeBodyFacts::EMPTY;
        preanalyze_runtime_body_declarations::<_, 4, 32>(
            &function,
            &NoConstants,
            &body,
            "&mut u16",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();
        assert_eq!(facts.conditional_expression_count, 2);
        let first = facts.conditional_expressions[0].unwrap();
        let second = facts.conditional_expressions[1].unwrap();
        assert_eq!(first.parent, None);
        assert_eq!(second.parent, None);
        assert_eq!(first.parent_path, RuntimeOwnershipExpressionPath::ROOT);
        assert_eq!(second.parent_path, RuntimeOwnershipExpressionPath::ROOT);
        assert_ne!(first.id, second.id);
        assert_ne!(first.span, second.span);
        assert_eq!(second.entry, first.join);
        assert_eq!(first.then_exit, Some(first.then_branch));
        assert_eq!(first.else_exit, Some(first.else_branch));
        assert_eq!(second.then_exit, Some(second.then_branch));
        assert_eq!(second.else_exit, Some(second.else_branch));

        let assignment_access_count = facts.assignment_access_count;
        let assignment_read_count = facts.assignment_read_count;
        let effect_with_point = facts.effects[..facts.effect_count]
            .iter()
            .position(|effect| effect.is_some_and(|effect| effect.expression_point.is_some()))
            .unwrap();
        let emitter = RuntimeEmitter::<_, 64, 4> {
            bytes: [0; 64],
            length: 0,
            readonly_data: [0; MAX_X86_64_READONLY_DATA_BYTES],
            readonly_data_length: 0,
            readonly_relocations: [X86_64ReadonlyDataRelocation {
                offset: 0,
                data_offset: 0,
            }; MAX_X86_64_READONLY_RELOCATIONS],
            readonly_relocation_count: 0,
            trap_patches: [0; 64],
            trap_count: 0,
            function: &function,
            resolver: &NoConstants,
            abi: X86_64Abi::SystemV,
            width: runtime_width("u16").unwrap(),
            overflow_checks: true,
            uses_sret: false,
            saved_parameter_slots: 3,
            locals: [None; 4],
            saved_locals: 0,
            body_facts: &mut facts,
            preanalyzed_local_count: 0,
            preanalyzed_local_cursor: 0,
            preanalyzed_assignment_access_cursor: assignment_access_count,
            preanalyzed_assignment_read_cursor: assignment_read_count,
            evaluation_depth: 0,
            runtime_call_depth: 0,
            runtime_call_names: [None; 8],
            runtime_call_local_floor: None,
        };
        emitter.validate_runtime_place_facts().unwrap();
        let valid_condition =
            emitter.body_facts.expression_program_points[second.condition.0].unwrap();
        emitter.body_facts.expression_program_points[second.condition.0] =
            Some(RuntimeExpressionProgramPointFact {
                kind: RuntimeExpressionProgramPointKind::Then(first.id),
                ..valid_condition
            });
        assert_eq!(
            emitter.validate_runtime_place_facts().unwrap_err().kind,
            CodegenErrorKind::InvalidRuntimePlaceFacts
        );
        emitter.body_facts.expression_program_points[second.condition.0] = Some(valid_condition);
        let valid_effect = emitter.body_facts.effects[effect_with_point].unwrap();
        emitter.body_facts.effects[effect_with_point] = Some(RuntimePlaceEffectFact {
            expression_point: Some(RuntimeExpressionProgramPointId(
                emitter.body_facts.expression_program_point_count,
            )),
            ..valid_effect
        });
        assert_eq!(
            emitter.validate_runtime_place_facts().unwrap_err().kind,
            CodegenErrorKind::InvalidRuntimePlaceFacts
        );
        emitter.body_facts.effects[effect_with_point] = Some(valid_effect);
        let valid_edge = emitter.body_facts.expression_control_flow_edges[0].unwrap();
        emitter.body_facts.expression_control_flow_edges[0] =
            Some(RuntimeExpressionControlFlowEdgeFact {
                to: RuntimeExpressionProgramPointId(
                    emitter.body_facts.expression_program_point_count,
                ),
                ..valid_edge
            });
        assert_eq!(
            emitter.validate_runtime_place_facts().unwrap_err().kind,
            CodegenErrorKind::InvalidRuntimeControlFlowFacts
        );
    }

    #[test]
    fn runtime_cfg_reborrow_ends_when_conditional_result_is_unused() {
        let source = "fn identity(value: &mut u16) -> &mut u16 { value } fn value(first: &mut u16, second: &mut u16, choose: bool) -> &mut u16 { let mut output: &mut u16 = first; if choose { output = identity(second); } second }";
        let module = Parser::new(source).parse_module::<3, 4>().unwrap();
        let Some(Item::Function(function)) = module.items()[1] else {
            panic!("expected function")
        };
        let body = function.parse_body::<4>().unwrap();
        let mut facts = RuntimeBodyFacts::EMPTY;
        let result = preanalyze_runtime_body_declarations::<_, 4, 16>(
            &function,
            &MutableReferenceCallResolver,
            &body,
            "&mut u16",
            function.body_expression_span.start,
            &mut facts,
        );
        result.unwrap();
    }

    #[test]
    fn runtime_expression_initializedness_preserves_conditional_reborrows() {
        let reborrowed = "fn value(input: &mut u16, choose: bool) -> &mut u16 { let moved: &mut u16 = if choose { input } else { &mut *input }; input }";
        let module = Parser::new(reborrowed).parse_module::<2, 4>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<4>().unwrap();
        let mut facts = RuntimeBodyFacts::EMPTY;
        let result = preanalyze_runtime_body_declarations::<_, 4, 24>(
            &function,
            &NoConstants,
            &body,
            "&mut u16",
            function.body_expression_span.start,
            &mut facts,
        );
        assert!(runtime_expression_initializedness_is_supported(&facts));
        result.unwrap();
        let edge = facts.expression_control_flow_edges[0].unwrap();
        let target = facts.expression_program_points[edge.to.0].unwrap();
        facts.expression_program_points[edge.to.0] = Some(RuntimeExpressionProgramPointFact {
            location: RuntimeOwnershipEventLocation::Tail,
            ..target
        });
        assert!(!runtime_expression_initializedness_is_supported(&facts));
        assert_eq!(
            validate_runtime_initializedness(&facts, function.body_expression_span)
                .unwrap_err()
                .kind,
            CodegenErrorKind::RuntimeExpressionUnsupported
        );

        let retained = "fn value(input: &mut u16, choose: bool) -> &mut u16 { let selected: &mut u16 = if choose { &mut *input } else { &mut *input }; input }";
        let module = Parser::new(retained).parse_module::<2, 4>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<4>().unwrap();
        let mut facts = RuntimeBodyFacts::EMPTY;
        preanalyze_runtime_body_declarations::<_, 4, 32>(
            &function,
            &NoConstants,
            &body,
            "&mut u16",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();
        assert!(!facts.ownership_events_single_path);
        assert!(runtime_expression_initializedness_is_supported(&facts));
    }

    #[test]
    fn runtime_cfg_reborrow_ends_before_a_loop_exit_when_result_is_unused() {
        let source = "fn identity(value: &mut u16) -> &mut u16 { value } fn value(input: &mut u16) -> &mut u16 { loop { let moved: &mut u16 = identity(input); break; } input }";
        let module = Parser::new(source).parse_module::<2, 4>().unwrap();
        let Some(Item::Function(function)) = module.items()[1] else {
            panic!("expected function")
        };
        let body = function.parse_body::<4>().unwrap();
        let mut facts = RuntimeBodyFacts::EMPTY;
        preanalyze_runtime_body_declarations::<_, 4, 16>(
            &function,
            &MutableReferenceCallResolver,
            &body,
            "&mut u16",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();
    }

    #[test]
    fn runtime_assignment_rhs_reborrows_precede_destination_writes() {
        let source = "fn value(first: &mut u16, second: &mut u16) -> &mut u16 { let mut slot: &mut u16 = first; let mut source: &mut u16 = second; slot = source; source = &mut *slot; source }";
        let module = Parser::new(source).parse_module::<2, 4>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<4>().unwrap();
        let mut facts = RuntimeBodyFacts::EMPTY;
        assert_eq!(
            preanalyze_runtime_body_declarations::<_, 4, 16>(
                &function,
                &NoConstants,
                &body,
                "&mut u16",
                function.body_expression_span.start,
                &mut facts,
            )
            .unwrap(),
            2
        );
        let source_path = facts
            .find_move_path(
                RuntimePlaceIdentity::Local(RuntimeLocalId(1)),
                RuntimePlaceProjections::EMPTY,
            )
            .unwrap();
        let slot_path = facts
            .find_move_path(
                RuntimePlaceIdentity::Local(RuntimeLocalId(0)),
                RuntimePlaceProjections::EMPTY,
            )
            .unwrap();
        let rhs_reborrow = facts.effects[..facts.effect_count]
            .iter()
            .flatten()
            .find(|effect| {
                effect.path == source_path
                    && effect.kind == RuntimePlaceEffectKind::MutableBorrow
                    && effect.location == RuntimeOwnershipEventLocation::TopLevelStatement(2)
            })
            .unwrap();
        let destination_write = facts.effects[..facts.effect_count]
            .iter()
            .flatten()
            .find(|effect| {
                effect.path == slot_path
                    && effect.kind == RuntimePlaceEffectKind::Write
                    && effect.location == RuntimeOwnershipEventLocation::TopLevelStatement(2)
            })
            .unwrap();
        assert!(rhs_reborrow.event.0 < destination_write.event.0);
    }

    #[test]
    fn runtime_loop_return_origins_map_conditions_and_values_to_cfg() {
        let source = "fn value(input: &mut u16, stop: bool) -> &mut u16 { loop { if stop { return input; } return &mut *input; } }";
        let module = Parser::new(source).parse_module::<2, 2>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<2>().unwrap();
        let mut facts = RuntimeBodyFacts::EMPTY;
        preanalyze_runtime_body_declarations::<_, 2, 16>(
            &function,
            &NoConstants,
            &body,
            "&mut u16",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();

        for (location, point) in [
            (
                RuntimeOwnershipEventLocation::LoopConditionalReturnCondition {
                    statement_index: 0,
                    operation_index: 0,
                },
                RuntimeOwnershipControlPoint::Block(RuntimeBasicBlockId(1)),
            ),
            (
                RuntimeOwnershipEventLocation::LoopConditionalReturnValue {
                    statement_index: 0,
                    operation_index: 0,
                },
                RuntimeOwnershipControlPoint::Edge(1),
            ),
            (
                RuntimeOwnershipEventLocation::LoopReturnValue {
                    statement_index: 0,
                    operation_index: 1,
                },
                RuntimeOwnershipControlPoint::Edge(3),
            ),
        ] {
            assert!(
                facts.effects[..facts.effect_count]
                    .iter()
                    .flatten()
                    .any(|effect| effect.location == location),
                "missing {location:?}"
            );
            assert_eq!(facts.ownership_control_point(location), Some(point));
        }
    }

    #[test]
    fn runtime_ownership_origins_distinguish_conditional_assignment_program_points() {
        let source = "fn value(input: u16, choose: bool) -> u16 { let mut output: u16 = input; if choose { output += input; } else { output = input; } output }";
        let module = Parser::new(source).parse_module::<2, 4>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<4>().unwrap();
        let mut facts = RuntimeBodyFacts::EMPTY;
        preanalyze_runtime_body_declarations::<_, 4, 16>(
            &function,
            &NoConstants,
            &body,
            "u16",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();

        let condition = RuntimeOwnershipEventLocation::ConditionalAssignmentCondition {
            statement_index: 1,
            branch_index: 0,
        };
        let branch_action = RuntimeOwnershipEventLocation::ConditionalAssignmentAction {
            statement_index: 1,
            branch_index: Some(0),
            action_index: 0,
        };
        let else_action = RuntimeOwnershipEventLocation::ConditionalAssignmentAction {
            statement_index: 1,
            branch_index: None,
            action_index: 0,
        };
        let branch_block = facts
            .block_with_source(RuntimeBasicBlockSource::ConditionalAssignmentActions {
                statement_index: 1,
                branch_index: 0,
            })
            .unwrap();
        let else_block = facts
            .block_with_source(RuntimeBasicBlockSource::ConditionalAssignmentElseActions {
                statement_index: 1,
            })
            .unwrap();
        assert_eq!(
            facts.ownership_control_point(condition),
            Some(RuntimeOwnershipControlPoint::Block(RuntimeBasicBlockId(0)))
        );
        assert_eq!(
            facts.ownership_control_point(branch_action),
            Some(RuntimeOwnershipControlPoint::Block(branch_block))
        );
        assert_eq!(
            facts.ownership_control_point(else_action),
            Some(RuntimeOwnershipControlPoint::Block(else_block))
        );
        assert!(
            facts.effects[..facts.effect_count]
                .iter()
                .flatten()
                .any(|effect| effect.location == condition)
        );
        assert!(
            facts.effects[..facts.effect_count]
                .iter()
                .flatten()
                .any(|effect| {
                    effect.location == branch_action
                        && effect.kind == RuntimePlaceEffectKind::ReadModifyWrite
                })
        );
        assert!(
            facts.effects[..facts.effect_count]
                .iter()
                .flatten()
                .any(|effect| {
                    effect.location == else_action && effect.kind == RuntimePlaceEffectKind::Write
                })
        );
        let condition_effect = facts.effects[..facts.effect_count]
            .iter()
            .position(|effect| effect.is_some_and(|effect| effect.location == condition))
            .unwrap();
        let assignment_access_count = facts.assignment_access_count;
        let assignment_read_count = facts.assignment_read_count;
        let local_count = facts.local_count;
        let emitter = RuntimeEmitter::<_, 64, 4> {
            bytes: [0; 64],
            length: 0,
            readonly_data: [0; MAX_X86_64_READONLY_DATA_BYTES],
            readonly_data_length: 0,
            readonly_relocations: [X86_64ReadonlyDataRelocation {
                offset: 0,
                data_offset: 0,
            }; MAX_X86_64_READONLY_RELOCATIONS],
            readonly_relocation_count: 0,
            trap_patches: [0; 64],
            trap_count: 0,
            function: &function,
            resolver: &NoConstants,
            abi: X86_64Abi::SystemV,
            width: runtime_width("u16").unwrap(),
            overflow_checks: true,
            uses_sret: false,
            saved_parameter_slots: 2,
            locals: [None; 4],
            saved_locals: 0,
            body_facts: &mut facts,
            preanalyzed_local_count: local_count,
            preanalyzed_local_cursor: local_count,
            preanalyzed_assignment_access_cursor: assignment_access_count,
            preanalyzed_assignment_read_cursor: assignment_read_count,
            evaluation_depth: 0,
            runtime_call_depth: 0,
            runtime_call_names: [None; 8],
            runtime_call_local_floor: None,
        };
        emitter.validate_runtime_place_facts().unwrap();
        let valid_branch_block = emitter.body_facts.basic_blocks[branch_block.0].unwrap();
        emitter.body_facts.basic_blocks[branch_block.0] = Some(RuntimeBasicBlockFact {
            source: RuntimeBasicBlockSource::TopLevel,
            ..valid_branch_block
        });
        assert_eq!(
            emitter.body_facts.ownership_control_point(branch_action),
            None
        );
        assert_eq!(
            emitter.validate_runtime_place_facts().unwrap_err().kind,
            CodegenErrorKind::InvalidRuntimePlaceFacts
        );
        emitter.body_facts.basic_blocks[branch_block.0] = Some(valid_branch_block);
        let valid_condition = emitter.body_facts.effects[condition_effect].unwrap();
        emitter.body_facts.effects[condition_effect] = Some(RuntimePlaceEffectFact {
            expression_path: RuntimeOwnershipExpressionPath {
                else_bits: 2,
                depth: 1,
            },
            ..valid_condition
        });
        assert_eq!(
            emitter.validate_runtime_place_facts().unwrap_err().kind,
            CodegenErrorKind::InvalidRuntimePlaceFacts
        );
        emitter.body_facts.effects[condition_effect] = Some(RuntimePlaceEffectFact {
            location: RuntimeOwnershipEventLocation::ConditionalAssignmentCondition {
                statement_index: 1,
                branch_index: 1,
            },
            ..valid_condition
        });
        assert_eq!(
            emitter.validate_runtime_place_facts().unwrap_err().kind,
            CodegenErrorKind::InvalidRuntimePlaceFacts
        );
        emitter.body_facts.effects[condition_effect] = Some(RuntimePlaceEffectFact {
            location: RuntimeOwnershipEventLocation::ConditionalAssignmentAction {
                statement_index: 1,
                branch_index: Some(0),
                action_index: 1,
            },
            ..valid_condition
        });
        assert_eq!(
            emitter.validate_runtime_place_facts().unwrap_err().kind,
            CodegenErrorKind::InvalidRuntimePlaceFacts
        );
    }

    #[test]
    fn runtime_body_facts_build_initial_conditional_return_cfg() {
        let source = "fn value(input: usize, stop: bool) -> usize { let first = input + 1; if stop { return first; } let second = first + 1; second }";
        let module = Parser::new(source).parse_module::<1, 4>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<4>().unwrap();
        let mut facts = RuntimeBodyFacts::EMPTY;
        preanalyze_runtime_body_declarations::<_, 4, 32>(
            &function,
            &NoConstants,
            &body,
            "usize",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();

        assert!(facts.control_flow_complete);
        assert_eq!(facts.basic_block_count, 2);
        assert_eq!(
            facts.basic_blocks[..2],
            [
                Some(RuntimeBasicBlockFact {
                    id: RuntimeBasicBlockId(0),
                    source: RuntimeBasicBlockSource::TopLevel,
                    first_statement: 0,
                    statement_count: 2,
                    reachable: true,
                }),
                Some(RuntimeBasicBlockFact {
                    id: RuntimeBasicBlockId(1),
                    source: RuntimeBasicBlockSource::TopLevel,
                    first_statement: 2,
                    statement_count: 1,
                    reachable: true,
                }),
            ]
        );
        assert_eq!(facts.control_flow_edge_count, 3);
        assert_eq!(
            facts.control_flow_edges[..3],
            [
                Some(RuntimeControlFlowEdgeFact {
                    from: RuntimeBasicBlockId(0),
                    target: RuntimeControlFlowTarget::Return,
                    kind: RuntimeControlFlowEdgeKind::True,
                }),
                Some(RuntimeControlFlowEdgeFact {
                    from: RuntimeBasicBlockId(0),
                    target: RuntimeControlFlowTarget::Block(RuntimeBasicBlockId(1)),
                    kind: RuntimeControlFlowEdgeKind::False,
                }),
                Some(RuntimeControlFlowEdgeFact {
                    from: RuntimeBasicBlockId(1),
                    target: RuntimeControlFlowTarget::Return,
                    kind: RuntimeControlFlowEdgeKind::Unconditional,
                }),
            ]
        );
    }

    #[test]
    fn runtime_body_cfg_bounds_fact_capacity() {
        let mut capacity = RuntimeBodyFacts::EMPTY;
        for index in 0..MAX_RUNTIME_BASIC_BLOCK_FACTS {
            assert_eq!(
                capacity.push_basic_block(index, true),
                Ok(RuntimeBasicBlockId(index))
            );
        }
        assert_eq!(
            capacity.push_basic_block(MAX_RUNTIME_BASIC_BLOCK_FACTS, true),
            Err(CodegenErrorKind::TooManyRuntimeBasicBlockFacts)
        );
        for _ in 0..MAX_RUNTIME_CONTROL_FLOW_EDGE_FACTS {
            capacity
                .push_control_flow_edge(RuntimeControlFlowEdgeFact {
                    from: RuntimeBasicBlockId(0),
                    target: RuntimeControlFlowTarget::Return,
                    kind: RuntimeControlFlowEdgeKind::Unconditional,
                })
                .unwrap();
        }
        assert_eq!(
            capacity.push_control_flow_edge(RuntimeControlFlowEdgeFact {
                from: RuntimeBasicBlockId(0),
                target: RuntimeControlFlowTarget::Return,
                kind: RuntimeControlFlowEdgeKind::Unconditional,
            }),
            Err(CodegenErrorKind::TooManyRuntimeControlFlowEdgeFacts)
        );
    }

    #[test]
    fn runtime_body_facts_build_initial_while_cfg() {
        let source = "fn value(limit: u8, stop: u8) -> u8 { let mut index: u8 = 0; while index < limit { index += 1; if index == stop { break; } } index }";
        let module = Parser::new(source).parse_module::<1, 4>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<4>().unwrap();
        let mut facts = RuntimeBodyFacts::EMPTY;
        preanalyze_runtime_body_declarations::<_, 4, 32>(
            &function,
            &NoConstants,
            &body,
            "u8",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();

        assert!(facts.control_flow_complete);
        assert_eq!(facts.basic_block_count, 4);
        assert_eq!(facts.basic_blocks[0].unwrap().statement_count, 2);
        assert_eq!(
            facts.basic_blocks[1].unwrap().source,
            RuntimeBasicBlockSource::TopLevel
        );
        assert_eq!(
            facts.basic_blocks[2].unwrap().source,
            RuntimeBasicBlockSource::LoopBody {
                statement_index: 1,
                first_operation: 0,
                operation_count: 2,
            }
        );
        assert_eq!(
            facts.basic_blocks[3].unwrap().source,
            RuntimeBasicBlockSource::LoopBody {
                statement_index: 1,
                first_operation: 2,
                operation_count: 0,
            }
        );
        assert_eq!(facts.control_flow_edge_count, 6);
        assert_eq!(
            facts.control_flow_edges[..6],
            [
                Some(RuntimeControlFlowEdgeFact {
                    from: RuntimeBasicBlockId(0),
                    target: RuntimeControlFlowTarget::Block(RuntimeBasicBlockId(2)),
                    kind: RuntimeControlFlowEdgeKind::True,
                }),
                Some(RuntimeControlFlowEdgeFact {
                    from: RuntimeBasicBlockId(0),
                    target: RuntimeControlFlowTarget::Block(RuntimeBasicBlockId(1)),
                    kind: RuntimeControlFlowEdgeKind::False,
                }),
                Some(RuntimeControlFlowEdgeFact {
                    from: RuntimeBasicBlockId(2),
                    target: RuntimeControlFlowTarget::Block(RuntimeBasicBlockId(1)),
                    kind: RuntimeControlFlowEdgeKind::True,
                }),
                Some(RuntimeControlFlowEdgeFact {
                    from: RuntimeBasicBlockId(2),
                    target: RuntimeControlFlowTarget::Block(RuntimeBasicBlockId(3)),
                    kind: RuntimeControlFlowEdgeKind::False,
                }),
                Some(RuntimeControlFlowEdgeFact {
                    from: RuntimeBasicBlockId(3),
                    target: RuntimeControlFlowTarget::Block(RuntimeBasicBlockId(0)),
                    kind: RuntimeControlFlowEdgeKind::Unconditional,
                }),
                Some(RuntimeControlFlowEdgeFact {
                    from: RuntimeBasicBlockId(1),
                    target: RuntimeControlFlowTarget::Return,
                    kind: RuntimeControlFlowEdgeKind::Unconditional,
                }),
            ]
        );
    }

    #[test]
    fn runtime_body_facts_model_loop_continue_and_post_terminal_operations() {
        let source = "fn value(limit: u8) -> u8 { let mut index: u8 = 0; loop { index += 1; if index < limit { continue; } break; } index }";
        let module = Parser::new(source).parse_module::<1, 4>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<4>().unwrap();
        let mut facts = RuntimeBodyFacts::EMPTY;
        preanalyze_runtime_body_declarations::<_, 4, 32>(
            &function,
            &NoConstants,
            &body,
            "u8",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();
        assert!(facts.control_flow_complete);
        assert_eq!(facts.basic_block_count, 4);
        assert_eq!(facts.control_flow_edge_count, 5);
        assert_eq!(
            facts.control_flow_edges[1],
            Some(RuntimeControlFlowEdgeFact {
                from: RuntimeBasicBlockId(2),
                target: RuntimeControlFlowTarget::Block(RuntimeBasicBlockId(0)),
                kind: RuntimeControlFlowEdgeKind::True,
            })
        );

        let post_terminal =
            "fn value() -> u8 { loop { continue; let unreachable: u8 = 1; unreachable; } }";
        let module = Parser::new(post_terminal).parse_module::<1, 4>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<4>().unwrap();
        let mut facts = RuntimeBodyFacts::EMPTY;
        preanalyze_runtime_body_declarations::<_, 4, 32>(
            &function,
            &NoConstants,
            &body,
            "u8",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();
        assert!(facts.control_flow_complete);
        assert!(
            facts.basic_blocks[..facts.basic_block_count]
                .iter()
                .flatten()
                .any(|block| !block.reachable)
        );
    }

    #[test]
    fn runtime_body_facts_build_exhaustive_conditional_loop_block_cfg() {
        let source = "fn value(mode: u8) -> u8 { let mut value: u8 = 0; loop { if mode == 0 { value += 1; continue; } else if mode == 1 { value += 2; break; } else { return value; } } value }";
        let module = Parser::new(source).parse_module::<1, 4>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<4>().unwrap();
        let mut facts = RuntimeBodyFacts::EMPTY;
        preanalyze_runtime_body_declarations::<_, 4, 32>(
            &function,
            &NoConstants,
            &body,
            "u8",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();

        assert!(facts.control_flow_complete);
        assert_eq!(facts.basic_block_count, 7);
        assert_eq!(
            facts.basic_blocks[2].unwrap().source,
            RuntimeBasicBlockSource::LoopBody {
                statement_index: 1,
                first_operation: 0,
                operation_count: 1,
            }
        );
        assert_eq!(
            facts.basic_blocks[3].unwrap().source,
            RuntimeBasicBlockSource::LoopConditionalActions {
                statement_index: 1,
                operation_index: 0,
                arm_index: 0,
                action_count: 1,
            }
        );
        assert_eq!(
            facts.basic_blocks[4].unwrap().source,
            RuntimeBasicBlockSource::LoopConditionalCondition {
                statement_index: 1,
                operation_index: 0,
                arm_index: 1,
            }
        );
        assert_eq!(
            facts.basic_blocks[6].unwrap().source,
            RuntimeBasicBlockSource::LoopConditionalActions {
                statement_index: 1,
                operation_index: 0,
                arm_index: 2,
                action_count: 0,
            }
        );
        assert_eq!(facts.control_flow_edge_count, 9);
        assert_eq!(
            facts.control_flow_edges[..9],
            [
                Some(RuntimeControlFlowEdgeFact {
                    from: RuntimeBasicBlockId(0),
                    target: RuntimeControlFlowTarget::Block(RuntimeBasicBlockId(2)),
                    kind: RuntimeControlFlowEdgeKind::Unconditional,
                }),
                Some(RuntimeControlFlowEdgeFact {
                    from: RuntimeBasicBlockId(2),
                    target: RuntimeControlFlowTarget::Block(RuntimeBasicBlockId(3)),
                    kind: RuntimeControlFlowEdgeKind::True,
                }),
                Some(RuntimeControlFlowEdgeFact {
                    from: RuntimeBasicBlockId(3),
                    target: RuntimeControlFlowTarget::Block(RuntimeBasicBlockId(0)),
                    kind: RuntimeControlFlowEdgeKind::Unconditional,
                }),
                Some(RuntimeControlFlowEdgeFact {
                    from: RuntimeBasicBlockId(2),
                    target: RuntimeControlFlowTarget::Block(RuntimeBasicBlockId(4)),
                    kind: RuntimeControlFlowEdgeKind::False,
                }),
                Some(RuntimeControlFlowEdgeFact {
                    from: RuntimeBasicBlockId(4),
                    target: RuntimeControlFlowTarget::Block(RuntimeBasicBlockId(5)),
                    kind: RuntimeControlFlowEdgeKind::True,
                }),
                Some(RuntimeControlFlowEdgeFact {
                    from: RuntimeBasicBlockId(5),
                    target: RuntimeControlFlowTarget::Block(RuntimeBasicBlockId(1)),
                    kind: RuntimeControlFlowEdgeKind::Unconditional,
                }),
                Some(RuntimeControlFlowEdgeFact {
                    from: RuntimeBasicBlockId(4),
                    target: RuntimeControlFlowTarget::Block(RuntimeBasicBlockId(6)),
                    kind: RuntimeControlFlowEdgeKind::False,
                }),
                Some(RuntimeControlFlowEdgeFact {
                    from: RuntimeBasicBlockId(6),
                    target: RuntimeControlFlowTarget::Return,
                    kind: RuntimeControlFlowEdgeKind::Unconditional,
                }),
                Some(RuntimeControlFlowEdgeFact {
                    from: RuntimeBasicBlockId(1),
                    target: RuntimeControlFlowTarget::Return,
                    kind: RuntimeControlFlowEdgeKind::Unconditional,
                }),
            ]
        );
        for (location, point) in [
            (
                RuntimeOwnershipEventLocation::LoopConditionalCondition {
                    statement_index: 1,
                    operation_index: 0,
                    arm_index: 0,
                },
                RuntimeOwnershipControlPoint::Block(RuntimeBasicBlockId(2)),
            ),
            (
                RuntimeOwnershipEventLocation::LoopConditionalAction {
                    statement_index: 1,
                    operation_index: 0,
                    arm_index: 0,
                    action_index: 0,
                },
                RuntimeOwnershipControlPoint::Block(RuntimeBasicBlockId(3)),
            ),
            (
                RuntimeOwnershipEventLocation::LoopConditionalCondition {
                    statement_index: 1,
                    operation_index: 0,
                    arm_index: 1,
                },
                RuntimeOwnershipControlPoint::Block(RuntimeBasicBlockId(4)),
            ),
            (
                RuntimeOwnershipEventLocation::LoopConditionalAction {
                    statement_index: 1,
                    operation_index: 0,
                    arm_index: 1,
                    action_index: 0,
                },
                RuntimeOwnershipControlPoint::Block(RuntimeBasicBlockId(5)),
            ),
            (
                RuntimeOwnershipEventLocation::LoopConditionalTerminal {
                    statement_index: 1,
                    operation_index: 0,
                    arm_index: 2,
                },
                RuntimeOwnershipControlPoint::Edge(7),
            ),
        ] {
            assert!(
                facts.effects[..facts.effect_count]
                    .iter()
                    .flatten()
                    .any(|effect| effect.location == location),
                "missing {location:?}"
            );
            assert_eq!(facts.ownership_control_point(location), Some(point));
        }
        assert_eq!(
            facts.ownership_control_point(RuntimeOwnershipEventLocation::LoopConditionalAction {
                statement_index: 1,
                operation_index: 0,
                arm_index: 0,
                action_index: 1,
            }),
            None
        );

        let unreachable_suffix = "fn value(mode: bool) -> u8 { loop { if mode { return 1; } else { return 2; } let unreachable: u8 = 3; unreachable; } }";
        let module = Parser::new(unreachable_suffix)
            .parse_module::<1, 4>()
            .unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<4>().unwrap();
        let mut facts = RuntimeBodyFacts::EMPTY;
        preanalyze_runtime_body_declarations::<_, 4, 32>(
            &function,
            &NoConstants,
            &body,
            "u8",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();
        assert!(facts.control_flow_complete);
        assert!(
            facts.basic_blocks[..facts.basic_block_count]
                .iter()
                .flatten()
                .any(|block| !block.reachable)
        );
    }

    #[test]
    fn runtime_body_facts_join_fallthrough_conditional_loop_arms() {
        let source = "fn value(limit: u8, mode: bool) -> u8 { let mut index: u8 = 0; let mut value: u8 = 0; while index < limit { if mode { value += 1; } else { value += 2; } index += 1; } value }";
        let module = Parser::new(source).parse_module::<1, 4>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<4>().unwrap();
        let mut facts = RuntimeBodyFacts::EMPTY;
        preanalyze_runtime_body_declarations::<_, 4, 32>(
            &function,
            &NoConstants,
            &body,
            "u8",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();

        assert!(facts.control_flow_complete);
        assert_eq!(facts.basic_block_count, 6);
        assert_eq!(facts.control_flow_edge_count, 8);
        assert_eq!(
            facts.basic_blocks[3].unwrap().source,
            RuntimeBasicBlockSource::LoopBody {
                statement_index: 2,
                first_operation: 1,
                operation_count: 1,
            }
        );
        assert_eq!(
            facts.control_flow_edges[3],
            Some(RuntimeControlFlowEdgeFact {
                from: RuntimeBasicBlockId(4),
                target: RuntimeControlFlowTarget::Block(RuntimeBasicBlockId(3)),
                kind: RuntimeControlFlowEdgeKind::Unconditional,
            })
        );
        assert_eq!(
            facts.control_flow_edges[5],
            Some(RuntimeControlFlowEdgeFact {
                from: RuntimeBasicBlockId(5),
                target: RuntimeControlFlowTarget::Block(RuntimeBasicBlockId(3)),
                kind: RuntimeControlFlowEdgeKind::Unconditional,
            })
        );
        assert_eq!(
            facts.control_flow_edges[6],
            Some(RuntimeControlFlowEdgeFact {
                from: RuntimeBasicBlockId(3),
                target: RuntimeControlFlowTarget::Block(RuntimeBasicBlockId(0)),
                kind: RuntimeControlFlowEdgeKind::Unconditional,
            })
        );
    }

    #[test]
    fn runtime_body_facts_build_nested_loop_target_cfg() {
        let source = "fn value(enter: bool, stop: bool) -> u8 { let mut value: u8 = 0; while enter { 'inner: loop { value += 1; if value == 1 { continue 'inner; } if stop { break 'inner; } break 'inner; } break; } value }";
        let module = Parser::new(source).parse_module::<1, 4>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<4>().unwrap();
        let mut facts = RuntimeBodyFacts::EMPTY;
        preanalyze_runtime_body_declarations::<_, 4, 32>(
            &function,
            &NoConstants,
            &body,
            "u8",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();

        assert!(facts.control_flow_complete);
        assert_eq!(facts.basic_block_count, 9);
        assert_eq!(facts.control_flow_edge_count, 12);
        assert_eq!(
            facts.basic_blocks[4].unwrap().source,
            RuntimeBasicBlockSource::NestedLoopHeader {
                statement_index: 1,
                operation_index: 0,
            }
        );
        assert_eq!(
            facts.basic_blocks[5].unwrap().source,
            RuntimeBasicBlockSource::NestedLoopAction {
                statement_index: 1,
                operation_index: 0,
                action_index: 0,
            }
        );
        for (block_index, control_order) in [(6, 0), (7, 1), (8, 2)] {
            assert_eq!(
                facts.basic_blocks[block_index].unwrap().source,
                RuntimeBasicBlockSource::NestedLoopControl {
                    statement_index: 1,
                    operation_index: 0,
                    action_index: 1,
                    control_order,
                }
            );
        }
        assert_eq!(
            facts.control_flow_edges[5],
            Some(RuntimeControlFlowEdgeFact {
                from: RuntimeBasicBlockId(6),
                target: RuntimeControlFlowTarget::Block(RuntimeBasicBlockId(4)),
                kind: RuntimeControlFlowEdgeKind::True,
            })
        );
        assert_eq!(
            facts.control_flow_edges[7],
            Some(RuntimeControlFlowEdgeFact {
                from: RuntimeBasicBlockId(7),
                target: RuntimeControlFlowTarget::Block(RuntimeBasicBlockId(3)),
                kind: RuntimeControlFlowEdgeKind::True,
            })
        );
        assert_eq!(
            facts.control_flow_edges[10],
            Some(RuntimeControlFlowEdgeFact {
                from: RuntimeBasicBlockId(3),
                target: RuntimeControlFlowTarget::Block(RuntimeBasicBlockId(1)),
                kind: RuntimeControlFlowEdgeKind::Unconditional,
            })
        );
        for (location, block) in [
            (
                RuntimeOwnershipEventLocation::LoopHeader { statement_index: 1 },
                RuntimeBasicBlockId(0),
            ),
            (
                RuntimeOwnershipEventLocation::NestedLoopAction {
                    statement_index: 1,
                    operation_index: 0,
                    action_index: 0,
                },
                RuntimeBasicBlockId(5),
            ),
            (
                RuntimeOwnershipEventLocation::NestedLoopControlCondition {
                    statement_index: 1,
                    operation_index: 0,
                    action_index: 1,
                    control_order: 0,
                },
                RuntimeBasicBlockId(6),
            ),
            (
                RuntimeOwnershipEventLocation::NestedLoopControlCondition {
                    statement_index: 1,
                    operation_index: 0,
                    action_index: 1,
                    control_order: 1,
                },
                RuntimeBasicBlockId(7),
            ),
        ] {
            assert!(
                facts.effects[..facts.effect_count]
                    .iter()
                    .flatten()
                    .any(|effect| effect.location == location),
                "missing {location:?}"
            );
            assert_eq!(
                facts.ownership_control_point(location),
                Some(RuntimeOwnershipControlPoint::Block(block))
            );
        }
    }

    #[test]
    fn runtime_nested_loop_branch_actions_build_cfg_and_admit_return_origin_branches() {
        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn value(stop: u64) -> u64 { loop { loop { if stop != 0 { stop; return stop; } } } }";
        let module = Parser::new(source).parse_module::<2, 2>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<2>().unwrap();
        let outer = body.while_loops()[0].unwrap();
        let Some(crate::LoopOperation::NestedBlock(index)) = outer.operations()[0] else {
            panic!("expected nested loop block")
        };
        let inner = outer.nested_blocks()[index].unwrap();
        assert!(nested_loop_has_supported_control_flow(&inner).unwrap());
        let mut facts = RuntimeBodyFacts::EMPTY;
        preanalyze_runtime_body_declarations::<_, 2, 16>(
            &function,
            &NoConstants,
            &body,
            "u64",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();
        for source in [
            RuntimeBasicBlockSource::NestedLoopBranchCondition {
                statement_index: 0,
                operation_index: 0,
                branch_index: 0,
            },
            RuntimeBasicBlockSource::NestedLoopBranchActions {
                statement_index: 0,
                operation_index: 0,
                branch_index: 0,
                action_count: 1,
            },
        ] {
            assert!(
                facts.block_with_source(source).is_some(),
                "missing {source:?}"
            );
        }
        for location in [
            RuntimeOwnershipEventLocation::NestedLoopBranchCondition {
                statement_index: 0,
                operation_index: 0,
                branch_index: 0,
            },
            RuntimeOwnershipEventLocation::NestedLoopBranchAction {
                statement_index: 0,
                operation_index: 0,
                branch_index: 0,
                action_index: 0,
            },
            RuntimeOwnershipEventLocation::NestedLoopBranchValue {
                statement_index: 0,
                operation_index: 0,
                branch_index: 0,
            },
        ] {
            assert!(
                facts.ownership_control_point(location).is_some(),
                "missing control point for {location:?}"
            );
        }
        assert!(
            compile_x86_64_function::<_, 256, 2, 16>(&function, &NoConstants, X86_64Abi::SystemV,)
                .unwrap()
                .len()
                > 11
        );

        let reference_source = "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &mut u64, stop: bool) -> &mut u64 { loop { loop { if stop { *input += 1; return input; } } } }";
        let module = Parser::new(reference_source)
            .parse_module::<2, 2>()
            .unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        assert!(
            compile_x86_64_function::<_, 256, 2, 16>(&function, &NoConstants, X86_64Abi::SystemV,)
                .is_ok()
        );

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &mut u64, stop: bool) -> &mut u64 { loop { loop { if stop { let alias: &mut u64 = &mut *input; break; } break; } return input; } }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &mut u64, stop: bool) -> &mut u64 { loop { loop { if stop { let alias: &mut u64 = &mut *input; continue; } return input; } } }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &mut u64, stop: bool) -> &mut u64 { let mut alias: &mut u64 = input; loop { loop { if stop { alias = &mut *alias; continue; } return alias; } } }",
        ] {
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            let compiled = compile_x86_64_function::<_, 256, 2, 16>(
                &function,
                &NoConstants,
                X86_64Abi::SystemV,
            );
            assert!(compiled.is_ok(), "failed to compile {source}: {compiled:?}");
        }

        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u64, stop: bool) -> u64 { loop { loop { if stop { let result: u64 = input + 1; return result; } else { let fallback: u64 = input + 2; return fallback; } } } }";
        let module = Parser::new(source).parse_module::<2, 2>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<2>().unwrap();
        let mut facts = RuntimeBodyFacts::EMPTY;
        preanalyze_runtime_body_declarations::<_, 2, 16>(
            &function,
            &NoConstants,
            &body,
            "u64",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();
        assert!(
            facts
                .block_with_source(RuntimeBasicBlockSource::NestedLoopBranchElseActions {
                    statement_index: 0,
                    operation_index: 0,
                    branch_index: 0,
                    alternative_index: 0,
                    action_count: 1,
                })
                .is_some()
        );
        for location in [
            RuntimeOwnershipEventLocation::NestedLoopBranchElseAction {
                statement_index: 0,
                operation_index: 0,
                branch_index: 0,
                alternative_index: 0,
                action_index: 0,
            },
            RuntimeOwnershipEventLocation::NestedLoopBranchElseValue {
                statement_index: 0,
                operation_index: 0,
                branch_index: 0,
                alternative_index: 0,
            },
        ] {
            assert!(
                facts.ownership_control_point(location).is_some(),
                "missing control point for {location:?}",
            );
        }
        assert!(
            compile_x86_64_function::<_, 256, 2, 16>(&function, &NoConstants, X86_64Abi::SystemV,)
                .unwrap()
                .len()
                > 11,
        );

        let reference_else = "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &mut u64, stop: bool) -> &mut u64 { loop { loop { if stop { return input; } else { *input += 1; return input; } } } }";
        let module = Parser::new(reference_else).parse_module::<2, 2>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        assert!(
            compile_x86_64_function::<_, 256, 2, 16>(&function, &NoConstants, X86_64Abi::SystemV,)
                .is_ok(),
        );

        let local_else = "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &mut u64, stop: bool) -> &mut u64 { loop { loop { if stop { return input; } else { let mut local: u64 = 1; return &mut local; } } } }";
        let module = Parser::new(local_else).parse_module::<2, 2>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(
            compile_x86_64_function::<_, 256, 2, 16>(&function, &NoConstants, X86_64Abi::SystemV,)
                .unwrap_err()
                .kind,
            CodegenErrorKind::RuntimeReferenceOutlivesFunction,
        );

        let else_if = "#[unsafe(no_mangle)] pub extern \"C\" fn value(limit: u64, stop: u64) -> u64 { let mut outer: u64 = 0; let mut inner: u64 = 0; while outer < limit { loop { if inner == stop { outer + inner; return outer + inner; } else if inner < limit { inner += 1; continue; } } } outer }";
        let module = Parser::new(else_if).parse_module::<2, 2>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<2>().unwrap();
        let mut facts = RuntimeBodyFacts::EMPTY;
        preanalyze_runtime_body_declarations::<_, 2, 16>(
            &function,
            &NoConstants,
            &body,
            "u64",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();
        assert!(
            facts
                .block_with_source(RuntimeBasicBlockSource::NestedLoopBranchElseCondition {
                    statement_index: 2,
                    operation_index: 0,
                    branch_index: 0,
                    alternative_index: 0,
                })
                .is_some()
        );
        for location in [
            RuntimeOwnershipEventLocation::NestedLoopBranchElseCondition {
                statement_index: 2,
                operation_index: 0,
                branch_index: 0,
                alternative_index: 0,
            },
            RuntimeOwnershipEventLocation::NestedLoopBranchElseAction {
                statement_index: 2,
                operation_index: 0,
                branch_index: 0,
                alternative_index: 0,
                action_index: 0,
            },
        ] {
            assert!(
                facts.ownership_control_point(location).is_some(),
                "missing control point for {location:?}",
            );
        }
        assert!(
            compile_x86_64_function::<_, 256, 2, 16>(&function, &NoConstants, X86_64Abi::SystemV,)
                .unwrap()
                .len()
                > 11,
        );

        let chain_source = "#[unsafe(no_mangle)] pub extern \"C\" fn value(primary: bool, first: bool, second: bool) -> u64 { loop { loop { if primary { return 40; } else if first { return 50; } else if second { return 60; } else { return 70; } } } }";
        let module = Parser::new(chain_source).parse_module::<1, 4>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<4>().unwrap();
        let mut facts = RuntimeBodyFacts::EMPTY;
        preanalyze_runtime_body_declarations::<_, 4, 16>(
            &function,
            &NoConstants,
            &body,
            "u64",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();
        for alternative_index in 0..3 {
            assert!(
                facts
                    .block_with_source_matching(|source| matches!(
                        source,
                        RuntimeBasicBlockSource::NestedLoopBranchElseActions {
                            statement_index: 0,
                            operation_index: 0,
                            branch_index: 0,
                            alternative_index: stored_alternative,
                            ..
                        } if stored_alternative == alternative_index
                    ))
                    .is_some(),
                "missing alternative {alternative_index} actions",
            );
            assert!(
                facts
                    .ownership_control_point(
                        RuntimeOwnershipEventLocation::NestedLoopBranchElseValue {
                            statement_index: 0,
                            operation_index: 0,
                            branch_index: 0,
                            alternative_index,
                        },
                    )
                    .is_some()
            );
        }
        for alternative_index in 0..2 {
            assert!(
                facts
                    .ownership_control_point(
                        RuntimeOwnershipEventLocation::NestedLoopBranchElseCondition {
                            statement_index: 0,
                            operation_index: 0,
                            branch_index: 0,
                            alternative_index,
                        },
                    )
                    .is_some()
            );
        }
        assert!(
            compile_x86_64_function::<_, 256, 4, 16>(&function, &NoConstants, X86_64Abi::SystemV,)
                .unwrap()
                .len()
                > 11,
        );

        let reference_chain = "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &mut u64, primary: bool, first: bool, second: bool) -> &mut u64 { loop { loop { if primary { return input; } else if first { *input += 1; return input; } else if second { return input; } else { return input; } } } }";
        let module = Parser::new(reference_chain).parse_module::<1, 4>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        assert!(
            compile_x86_64_function::<_, 384, 4, 24>(&function, &NoConstants, X86_64Abi::SystemV,)
                .is_ok(),
        );

        let local_chain = "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &mut u64, primary: bool, first: bool) -> &mut u64 { loop { loop { if primary { return input; } else if first { let mut local: u64 = 40; return &mut local; } else { return input; } } } }";
        let module = Parser::new(local_chain).parse_module::<1, 4>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(
            compile_x86_64_function::<_, 384, 4, 24>(&function, &NoConstants, X86_64Abi::SystemV,)
                .unwrap_err()
                .kind,
            CodegenErrorKind::RuntimeReferenceOutlivesFunction,
        );
    }

    #[test]
    fn runtime_nested_loop_validation_covers_every_alternative_and_requires_complete_cfg() {
        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn value(primary: bool, first: bool, second: bool) -> u64 { loop { loop { if primary { return 40; } else if first { let selected: u64 = 50; return selected; } else if second { let selected: u64 = 60; return selected; } else { return 70; } } } }";
        let module = Parser::new(source).parse_module::<2, 4>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<4>().unwrap();
        let outer = body.while_loops()[0].unwrap();
        let Some(crate::LoopOperation::NestedBlock(index)) = outer.operations()[0] else {
            panic!("expected nested loop block")
        };
        let inner = outer.nested_blocks()[index].unwrap();
        let branch = inner.conditional_blocks()[0].unwrap();
        assert_eq!(branch.else_arm_count(), 3);
        validate_nested_loop_conditional_branch(branch).unwrap();
        assert!(nested_loop_has_supported_control_flow(&inner).unwrap());
        assert_eq!(
            validate_runtime_body_for_emission(&body, &RuntimeBodyFacts::EMPTY),
            Err(CodegenErrorKind::UnsupportedRuntimeControlFlow)
        );

        let mut facts = RuntimeBodyFacts::EMPTY;
        preanalyze_runtime_body_declarations::<_, 4, 32>(
            &function,
            &NoConstants,
            &body,
            "u64",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();
        assert_eq!(
            validate_runtime_body_for_emission(&body, &facts),
            Ok(ValidatedRuntimeBody)
        );
        for alternative_index in 0..3 {
            assert!(
                facts
                    .block_with_source(RuntimeBasicBlockSource::NestedLoopBranchElseActions {
                        statement_index: 0,
                        operation_index: 0,
                        branch_index: 0,
                        alternative_index,
                        action_count: usize::from(alternative_index < 2),
                    })
                    .is_some(),
                "missing alternative {alternative_index}"
            );
        }
    }

    #[test]
    fn runtime_body_facts_target_outer_loop_and_isolate_nested_terminal_suffix() {
        let source = "fn value(enter: bool, stop: bool) -> u8 { 'outer: while enter { 'inner: loop { if stop { break 'outer; } continue 'inner; } } 42 }";
        let module = Parser::new(source).parse_module::<1, 4>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<4>().unwrap();
        let mut facts = RuntimeBodyFacts::EMPTY;
        preanalyze_runtime_body_declarations::<_, 4, 32>(
            &function,
            &NoConstants,
            &body,
            "u8",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();
        assert!(facts.control_flow_complete);
        assert!(
            facts.control_flow_edges[..facts.control_flow_edge_count]
                .iter()
                .flatten()
                .any(|edge| edge.target == RuntimeControlFlowTarget::Block(RuntimeBasicBlockId(1)))
        );

        let suffix = "fn value() -> u8 { loop { 'inner: loop { continue 'inner; let unreachable: u8 = 1; unreachable; } } }";
        let module = Parser::new(suffix).parse_module::<1, 4>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<4>().unwrap();
        let mut facts = RuntimeBodyFacts::EMPTY;
        preanalyze_runtime_body_declarations::<_, 4, 32>(
            &function,
            &NoConstants,
            &body,
            "u8",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();
        assert!(facts.control_flow_complete);
        assert_eq!(facts.basic_block_count, 6);
        assert_eq!(facts.control_flow_edge_count, 6);
        assert!(!facts.basic_blocks[4].unwrap().reachable);
        assert!(!facts.basic_blocks[5].unwrap().reachable);
        assert_eq!(
            facts.basic_blocks[4].unwrap().source,
            RuntimeBasicBlockSource::NestedLoopAction {
                statement_index: 0,
                operation_index: 0,
                action_index: 0,
            }
        );
        assert!(
            !facts.control_flow_edges[..facts.control_flow_edge_count]
                .iter()
                .flatten()
                .any(|edge| edge.target == RuntimeControlFlowTarget::Block(RuntimeBasicBlockId(4)))
        );
    }

    #[test]
    fn runtime_body_facts_treat_unit_break_loop_as_a_completed_operation() {
        let source = "fn value(enter: bool) -> u8 { let mut value: u8 = 0; while enter { loop { break; } value += 1; break; } value }";
        let module = Parser::new(source).parse_module::<1, 4>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<4>().unwrap();
        let loop_statement = body.while_loops()[0].unwrap();
        assert_eq!(
            loop_statement.operations()[0],
            Some(crate::LoopOperation::NestedUnitLoop)
        );
        let mut facts = RuntimeBodyFacts::EMPTY;
        preanalyze_runtime_body_declarations::<_, 4, 32>(
            &function,
            &NoConstants,
            &body,
            "u8",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();

        assert!(facts.control_flow_complete);
        assert_eq!(facts.basic_block_count, 3);
        assert_eq!(facts.control_flow_edge_count, 4);
        assert_eq!(
            facts.basic_blocks[2].unwrap().source,
            RuntimeBasicBlockSource::LoopBody {
                statement_index: 1,
                first_operation: 0,
                operation_count: 3,
            }
        );
    }

    #[test]
    fn runtime_body_facts_isolate_post_terminal_loop_operations() {
        let source = "fn value() -> u8 { loop { continue; let unreachable: u8 = 1; if unreachable == 1 { break; } } 42 }";
        let module = Parser::new(source).parse_module::<1, 4>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<4>().unwrap();
        let mut facts = RuntimeBodyFacts::EMPTY;
        preanalyze_runtime_body_declarations::<_, 4, 32>(
            &function,
            &NoConstants,
            &body,
            "u8",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();

        assert!(facts.control_flow_complete);
        assert_eq!(facts.basic_block_count, 5);
        assert_eq!(facts.control_flow_edge_count, 6);
        assert!(!facts.basic_blocks[1].unwrap().reachable);
        assert!(!facts.basic_blocks[3].unwrap().reachable);
        assert!(!facts.basic_blocks[4].unwrap().reachable);
        assert_eq!(
            facts.basic_blocks[3].unwrap().source,
            RuntimeBasicBlockSource::LoopBody {
                statement_index: 0,
                first_operation: 1,
                operation_count: 2,
            }
        );
        assert!(
            !facts.control_flow_edges[..facts.control_flow_edge_count]
                .iter()
                .flatten()
                .any(|edge| edge.target == RuntimeControlFlowTarget::Block(RuntimeBasicBlockId(3)))
        );
        assert_eq!(
            facts.control_flow_edges[2],
            Some(RuntimeControlFlowEdgeFact {
                from: RuntimeBasicBlockId(3),
                target: RuntimeControlFlowTarget::Block(RuntimeBasicBlockId(1)),
                kind: RuntimeControlFlowEdgeKind::True,
            })
        );
    }

    #[test]
    fn runtime_body_facts_build_exhaustive_conditional_return_cfg() {
        let source = "fn value(input: u8) -> u8 { if input == 0 { return 10; } else if input == 1 { return 20; } else if input == 2 { return 30; } else { return 40; } }";
        let module = Parser::new(source).parse_module::<1, 2>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<2>().unwrap();
        let mut facts = RuntimeBodyFacts::EMPTY;
        preanalyze_runtime_body_declarations::<_, 2, 32>(
            &function,
            &NoConstants,
            &body,
            "u8",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();

        assert!(facts.control_flow_complete);
        assert_eq!(facts.basic_block_count, 3);
        assert_eq!(facts.basic_blocks[0].unwrap().statement_count, 1);
        for branch_index in 1..3 {
            let block = facts.basic_blocks[branch_index].unwrap();
            assert_eq!(block.id, RuntimeBasicBlockId(branch_index));
            assert_eq!(
                block.source,
                RuntimeBasicBlockSource::ConditionalReturnBranch {
                    statement_index: 0,
                    branch_index,
                }
            );
            assert_eq!(block.first_statement, 0);
            assert_eq!(block.statement_count, 0);
            assert!(block.reachable);
        }
        assert_eq!(facts.control_flow_edge_count, 6);
        for block in 0..3 {
            assert_eq!(
                facts.control_flow_edges[block * 2],
                Some(RuntimeControlFlowEdgeFact {
                    from: RuntimeBasicBlockId(block),
                    target: RuntimeControlFlowTarget::Return,
                    kind: RuntimeControlFlowEdgeKind::True,
                })
            );
            assert_eq!(
                facts.control_flow_edges[block * 2 + 1],
                Some(RuntimeControlFlowEdgeFact {
                    from: RuntimeBasicBlockId(block),
                    target: if block == 2 {
                        RuntimeControlFlowTarget::Return
                    } else {
                        RuntimeControlFlowTarget::Block(RuntimeBasicBlockId(block + 1))
                    },
                    kind: RuntimeControlFlowEdgeKind::False,
                })
            );
        }
    }

    #[test]
    fn runtime_body_facts_build_fallthrough_conditional_return_cfg() {
        let source = "fn value(input: u8) -> u8 { if input == 0 { return 10; } else if input == 1 { return 20; } input + 1 }";
        let module = Parser::new(source).parse_module::<1, 2>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<2>().unwrap();
        let mut facts = RuntimeBodyFacts::EMPTY;
        preanalyze_runtime_body_declarations::<_, 2, 32>(
            &function,
            &NoConstants,
            &body,
            "u8",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();

        assert!(facts.control_flow_complete);
        assert_eq!(facts.basic_block_count, 3);
        assert_eq!(
            facts.basic_blocks[0].unwrap().source,
            RuntimeBasicBlockSource::TopLevel
        );
        assert_eq!(
            facts.basic_blocks[1].unwrap().source,
            RuntimeBasicBlockSource::ConditionalReturnBranch {
                statement_index: 0,
                branch_index: 1,
            }
        );
        assert_eq!(
            facts.basic_blocks[2].unwrap().source,
            RuntimeBasicBlockSource::TopLevel
        );
        assert_eq!(facts.basic_blocks[2].unwrap().first_statement, 1);
        assert_eq!(facts.control_flow_edge_count, 5);
        assert_eq!(
            facts.control_flow_edges[3],
            Some(RuntimeControlFlowEdgeFact {
                from: RuntimeBasicBlockId(1),
                target: RuntimeControlFlowTarget::Block(RuntimeBasicBlockId(2)),
                kind: RuntimeControlFlowEdgeKind::False,
            })
        );
        assert_eq!(
            facts.control_flow_edges[4],
            Some(RuntimeControlFlowEdgeFact {
                from: RuntimeBasicBlockId(2),
                target: RuntimeControlFlowTarget::Return,
                kind: RuntimeControlFlowEdgeKind::Unconditional,
            })
        );
    }

    #[test]
    fn runtime_body_facts_build_conditional_action_cfg() {
        let source = "fn value(input: u8, mode: u8) -> u8 { let mut result: u8 = input; if mode == 0 { result += 1; } else if mode == 1 { result += 2; } else { result += 3; } result }";
        let module = Parser::new(source).parse_module::<1, 4>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<4>().unwrap();
        let mut facts = RuntimeBodyFacts::EMPTY;
        preanalyze_runtime_body_declarations::<_, 4, 32>(
            &function,
            &NoConstants,
            &body,
            "u8",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();

        assert!(facts.control_flow_complete);
        assert_eq!(facts.basic_block_count, 6);
        assert_eq!(facts.basic_blocks[0].unwrap().statement_count, 2);
        assert_eq!(
            facts.basic_blocks[1].unwrap().source,
            RuntimeBasicBlockSource::TopLevel
        );
        assert_eq!(facts.basic_blocks[1].unwrap().first_statement, 2);
        assert_eq!(
            facts.basic_blocks[2].unwrap().source,
            RuntimeBasicBlockSource::ConditionalAssignmentActions {
                statement_index: 1,
                branch_index: 0,
            }
        );
        assert_eq!(
            facts.basic_blocks[3].unwrap().source,
            RuntimeBasicBlockSource::ConditionalAssignmentCondition {
                statement_index: 1,
                branch_index: 1,
            }
        );
        assert_eq!(
            facts.basic_blocks[4].unwrap().source,
            RuntimeBasicBlockSource::ConditionalAssignmentActions {
                statement_index: 1,
                branch_index: 1,
            }
        );
        assert_eq!(
            facts.basic_blocks[5].unwrap().source,
            RuntimeBasicBlockSource::ConditionalAssignmentElseActions { statement_index: 1 }
        );
        assert_eq!(facts.control_flow_edge_count, 8);
        assert_eq!(
            facts.control_flow_edges[..8],
            [
                Some(RuntimeControlFlowEdgeFact {
                    from: RuntimeBasicBlockId(0),
                    target: RuntimeControlFlowTarget::Block(RuntimeBasicBlockId(2)),
                    kind: RuntimeControlFlowEdgeKind::True,
                }),
                Some(RuntimeControlFlowEdgeFact {
                    from: RuntimeBasicBlockId(2),
                    target: RuntimeControlFlowTarget::Block(RuntimeBasicBlockId(1)),
                    kind: RuntimeControlFlowEdgeKind::Unconditional,
                }),
                Some(RuntimeControlFlowEdgeFact {
                    from: RuntimeBasicBlockId(0),
                    target: RuntimeControlFlowTarget::Block(RuntimeBasicBlockId(3)),
                    kind: RuntimeControlFlowEdgeKind::False,
                }),
                Some(RuntimeControlFlowEdgeFact {
                    from: RuntimeBasicBlockId(3),
                    target: RuntimeControlFlowTarget::Block(RuntimeBasicBlockId(4)),
                    kind: RuntimeControlFlowEdgeKind::True,
                }),
                Some(RuntimeControlFlowEdgeFact {
                    from: RuntimeBasicBlockId(4),
                    target: RuntimeControlFlowTarget::Block(RuntimeBasicBlockId(1)),
                    kind: RuntimeControlFlowEdgeKind::Unconditional,
                }),
                Some(RuntimeControlFlowEdgeFact {
                    from: RuntimeBasicBlockId(5),
                    target: RuntimeControlFlowTarget::Block(RuntimeBasicBlockId(1)),
                    kind: RuntimeControlFlowEdgeKind::Unconditional,
                }),
                Some(RuntimeControlFlowEdgeFact {
                    from: RuntimeBasicBlockId(3),
                    target: RuntimeControlFlowTarget::Block(RuntimeBasicBlockId(5)),
                    kind: RuntimeControlFlowEdgeKind::False,
                }),
                Some(RuntimeControlFlowEdgeFact {
                    from: RuntimeBasicBlockId(1),
                    target: RuntimeControlFlowTarget::Return,
                    kind: RuntimeControlFlowEdgeKind::Unconditional,
                }),
            ]
        );
    }

    #[test]
    fn runtime_body_facts_model_terminating_and_post_return_actions() {
        let terminating = "fn value(mode: bool) -> u8 { if mode { let first: u8 = 1; return first; } else { let second: u8 = 2; return second; } let unreachable: u8 = 3; unreachable }";
        let module = Parser::new(terminating).parse_module::<1, 4>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<4>().unwrap();
        let mut facts = RuntimeBodyFacts::EMPTY;
        preanalyze_runtime_body_declarations::<_, 4, 32>(
            &function,
            &NoConstants,
            &body,
            "u8",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();
        assert!(facts.control_flow_complete);
        assert_eq!(facts.basic_block_count, 4);
        assert!(!facts.basic_blocks[3].unwrap().reachable);
        assert_eq!(facts.basic_blocks[3].unwrap().first_statement, 1);

        let post_return = "fn value(mode: bool) -> u8 { let mut result: u8 = 0; if mode { result = 1; return 1; result = 2; } result }";
        let module = Parser::new(post_return).parse_module::<1, 4>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<4>().unwrap();
        let mut facts = RuntimeBodyFacts::EMPTY;
        preanalyze_runtime_body_declarations::<_, 4, 32>(
            &function,
            &NoConstants,
            &body,
            "u8",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();
        assert!(facts.control_flow_complete);
        let unreachable_block = facts.basic_blocks[..facts.basic_block_count]
            .iter()
            .position(|block| {
                block.is_some_and(|block| {
                    block.source
                        == RuntimeBasicBlockSource::ConditionalAssignmentUnreachableActions {
                            statement_index: 1,
                            branch_index: Some(0),
                            first_action: 2,
                            action_count: 1,
                        }
                })
            })
            .unwrap();
        assert!(!facts.basic_blocks[unreachable_block].unwrap().reachable);
        assert!(
            !facts.control_flow_edges[..facts.control_flow_edge_count]
                .iter()
                .flatten()
                .any(|edge| {
                    edge.target
                        == RuntimeControlFlowTarget::Block(RuntimeBasicBlockId(unreachable_block))
                })
        );
        assert!(
            facts.control_flow_edges[..facts.control_flow_edge_count]
                .iter()
                .flatten()
                .any(|edge| {
                    edge.from == RuntimeBasicBlockId(unreachable_block)
                        && edge.target == RuntimeControlFlowTarget::Block(RuntimeBasicBlockId(1))
                        && edge.kind == RuntimeControlFlowEdgeKind::Unconditional
                })
        );
    }

    #[test]
    fn runtime_body_facts_assign_distinct_conditional_branch_local_ids() {
        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u16, mode: u16) -> u16 { let mut result: u16 = input; if mode == 0 { let branch: u16 = result + 1; result = branch; } else if mode == 1 { let branch: u16 = result + 2; result = branch; } else { let branch: u16 = result + 3; result = branch; } result }";
        let module = Parser::new(source).parse_module::<1, 4>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<4>().unwrap();
        let resolver = NoConstants;
        let mut facts = RuntimeBodyFacts::EMPTY;
        let count = preanalyze_runtime_body_declarations::<_, 4, 32>(
            &function,
            &resolver,
            &body,
            "u16",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();

        assert_eq!(count, 4);
        assert_eq!(facts.locals[0].unwrap().name, "result");
        for (index, fact) in facts.locals[1..4].iter().enumerate() {
            let fact = fact.unwrap();
            assert_eq!(fact.id, RuntimeLocalId(index + 1));
            assert_eq!(fact.name, "branch");
            assert_eq!(
                fact.ty,
                RuntimeExpressionType::Integer(Some(crate::IntegerType::U16))
            );
            assert_ne!(
                fact.declaration_span,
                facts.locals[(index + 1) % 3 + 1].unwrap().declaration_span
            );
        }

        for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
            compile_x86_64_function::<_, 1024, 4, 32>(&function, &resolver, abi).unwrap();
        }
    }

    #[test]
    fn runtime_body_facts_continue_across_statements_and_conditionals() {
        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u16, mode: u16) -> u16 { let mut result: u16 = input; result += 1; if mode == 0 { let branch: u16 = result + 1; result = branch; } else { let branch: u16 = result + 2; result = branch; } result += 3; let after: u16 = result; if mode == 2 { let second: u16 = after + 4; result = second; } else { let second: u16 = after + 5; result = second; } let tail: u16 = result; tail }";
        let module = Parser::new(source).parse_module::<1, 8>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<8>().unwrap();
        let resolver = NoConstants;
        let mut facts = RuntimeBodyFacts::EMPTY;
        let count = preanalyze_runtime_body_declarations::<_, 8, 64>(
            &function,
            &resolver,
            &body,
            "u16",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();

        assert_eq!(count, 7);
        for (id, (fact, name)) in facts.locals[..count]
            .iter()
            .zip([
                "result", "branch", "branch", "after", "second", "second", "tail",
            ])
            .enumerate()
        {
            assert_eq!(fact.unwrap().name, name);
            assert_eq!(fact.unwrap().id, RuntimeLocalId(id));
        }
        assert_ne!(
            facts.locals[1].unwrap().declaration_span,
            facts.locals[2].unwrap().declaration_span
        );
        assert_ne!(
            facts.locals[4].unwrap().declaration_span,
            facts.locals[5].unwrap().declaration_span
        );
        assert_eq!(facts.assignment_access_count, 6);
        for fact in facts.assignment_accesses[..6].iter().flatten() {
            assert_eq!(fact.base, RuntimePlaceIdentity::Local(RuntimeLocalId(0)));
        }
        assert_eq!(
            facts.assignment_accesses[0].unwrap().access,
            RuntimePlaceAccess::ReadModifyWrite
        );
        assert_eq!(
            facts.assignment_accesses[3].unwrap().access,
            RuntimePlaceAccess::ReadModifyWrite
        );
        assert_eq!(facts.assignment_read_count, 14);
        for (fact, id) in facts.assignment_reads[..14].iter().zip([
            RuntimePlaceIdentity::Parameter(0),
            RuntimePlaceIdentity::Parameter(1),
            RuntimePlaceIdentity::Local(RuntimeLocalId(0)),
            RuntimePlaceIdentity::Local(RuntimeLocalId(1)),
            RuntimePlaceIdentity::Local(RuntimeLocalId(0)),
            RuntimePlaceIdentity::Local(RuntimeLocalId(2)),
            RuntimePlaceIdentity::Local(RuntimeLocalId(0)),
            RuntimePlaceIdentity::Parameter(1),
            RuntimePlaceIdentity::Local(RuntimeLocalId(3)),
            RuntimePlaceIdentity::Local(RuntimeLocalId(4)),
            RuntimePlaceIdentity::Local(RuntimeLocalId(3)),
            RuntimePlaceIdentity::Local(RuntimeLocalId(5)),
            RuntimePlaceIdentity::Local(RuntimeLocalId(0)),
            RuntimePlaceIdentity::Local(RuntimeLocalId(6)),
        ]) {
            assert_eq!(fact.unwrap().base, id);
        }

        for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
            compile_x86_64_function::<_, 2048, 8, 64>(&function, &resolver, abi).unwrap();
        }
    }

    #[test]
    fn runtime_body_facts_order_nested_assignment_expression_reads() {
        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn value(seed: u16, left: u16, right: u16, choose: bool) -> u16 { let mut result: u16 = seed; let pair: (u16, bool) = (right, choose); result = left + pair.0 * right; result = if choose { right } else { left }; result }";
        let module = Parser::new(source).parse_module::<1, 8>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<8>().unwrap();
        let resolver = NoConstants;
        let mut facts = RuntimeBodyFacts::EMPTY;
        let count = preanalyze_runtime_body_declarations::<_, 8, 64>(
            &function,
            &resolver,
            &body,
            "u16",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();

        assert_eq!(count, 2);
        assert_eq!(facts.assignment_access_count, 2);
        assert_eq!(facts.assignment_read_count, 10);
        for (fact, identity) in facts.assignment_reads[..10].iter().zip([
            RuntimePlaceIdentity::Parameter(0),
            RuntimePlaceIdentity::Parameter(2),
            RuntimePlaceIdentity::Parameter(3),
            RuntimePlaceIdentity::Parameter(1),
            RuntimePlaceIdentity::Local(RuntimeLocalId(1)),
            RuntimePlaceIdentity::Parameter(2),
            RuntimePlaceIdentity::Parameter(3),
            RuntimePlaceIdentity::Parameter(2),
            RuntimePlaceIdentity::Parameter(1),
            RuntimePlaceIdentity::Local(RuntimeLocalId(0)),
        ]) {
            assert_eq!(fact.unwrap().base, identity);
            assert_eq!(fact.unwrap().access, RuntimePlaceAccess::Read);
        }
        assert_eq!(
            facts.assignment_reads[4].unwrap().projections,
            RuntimePlaceProjections::single(RuntimePlaceProjection::TupleField(0))
        );
        for index in [0, 1, 2, 3, 5, 6, 7, 8, 9] {
            assert_eq!(
                facts.assignment_reads[index].unwrap().projections,
                RuntimePlaceProjections::EMPTY
            );
        }

        for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
            compile_x86_64_function::<_, 4096, 8, 64>(&function, &resolver, abi).unwrap();
        }
    }

    #[test]
    fn runtime_body_facts_mirror_typed_nested_index_lowering() {
        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn value(seed: u16, values: &[u16; 2], index: usize, left: u16, right: u16) -> u16 { let mut result: u16 = seed; let local: [u16; 2] = [left, right]; result = values[index] + local[index]; result = local[1] + left; result }";
        let module = Parser::new(source).parse_module::<1, 8>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<8>().unwrap();
        let resolver = NoConstants;
        let mut facts = RuntimeBodyFacts::EMPTY;
        let count = preanalyze_runtime_body_declarations::<_, 8, 64>(
            &function,
            &resolver,
            &body,
            "u16",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();

        assert_eq!(count, 2);
        assert_eq!(facts.assignment_access_count, 2);
        assert_eq!(facts.assignment_read_count, 11);
        for (fact, (identity, projections)) in facts.assignment_reads[..11].iter().zip([
            (
                RuntimePlaceIdentity::Parameter(0),
                RuntimePlaceProjections::EMPTY,
            ),
            (
                RuntimePlaceIdentity::Parameter(3),
                RuntimePlaceProjections::EMPTY,
            ),
            (
                RuntimePlaceIdentity::Parameter(4),
                RuntimePlaceProjections::EMPTY,
            ),
            (
                RuntimePlaceIdentity::Parameter(1),
                RuntimePlaceProjections::EMPTY,
            ),
            (
                RuntimePlaceIdentity::Parameter(2),
                RuntimePlaceProjections::EMPTY,
            ),
            (
                RuntimePlaceIdentity::Local(RuntimeLocalId(1)),
                RuntimePlaceProjections::single(RuntimePlaceProjection::Index),
            ),
            (
                RuntimePlaceIdentity::Local(RuntimeLocalId(1)),
                RuntimePlaceProjections::single(RuntimePlaceProjection::Index),
            ),
            (
                RuntimePlaceIdentity::Parameter(2),
                RuntimePlaceProjections::EMPTY,
            ),
            (
                RuntimePlaceIdentity::Local(RuntimeLocalId(1)),
                RuntimePlaceProjections::single(RuntimePlaceProjection::ArrayElement(1)),
            ),
            (
                RuntimePlaceIdentity::Parameter(3),
                RuntimePlaceProjections::EMPTY,
            ),
            (
                RuntimePlaceIdentity::Local(RuntimeLocalId(0)),
                RuntimePlaceProjections::EMPTY,
            ),
        ]) {
            assert_eq!(fact.unwrap().base, identity);
            assert_eq!(fact.unwrap().projections, projections);
        }

        for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
            compile_x86_64_function::<_, 4096, 8, 64>(&function, &resolver, abi).unwrap();
        }
    }

    #[test]
    fn runtime_body_facts_preanalyze_scalar_initializer_reads_before_shadowing() {
        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u16, left: u16, right: u16, choose: bool) -> u16 { let first: u16 = input + left; let first: u16 = first + right; let selected: u16 = if choose { first + left } else { input + right }; selected }";
        let module = Parser::new(source).parse_module::<1, 8>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<8>().unwrap();
        let resolver = NoConstants;
        let mut facts = RuntimeBodyFacts::EMPTY;
        let count = preanalyze_runtime_body_declarations::<_, 8, 64>(
            &function,
            &resolver,
            &body,
            "u16",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();

        assert_eq!(count, 3);
        assert_eq!(facts.assignment_access_count, 0);
        assert_eq!(facts.assignment_read_count, 10);
        for (fact, identity) in facts.assignment_reads[..10].iter().zip([
            RuntimePlaceIdentity::Parameter(0),
            RuntimePlaceIdentity::Parameter(1),
            RuntimePlaceIdentity::Local(RuntimeLocalId(0)),
            RuntimePlaceIdentity::Parameter(2),
            RuntimePlaceIdentity::Parameter(3),
            RuntimePlaceIdentity::Local(RuntimeLocalId(1)),
            RuntimePlaceIdentity::Parameter(1),
            RuntimePlaceIdentity::Parameter(0),
            RuntimePlaceIdentity::Parameter(2),
            RuntimePlaceIdentity::Local(RuntimeLocalId(2)),
        ]) {
            assert_eq!(fact.unwrap().base, identity);
            assert_eq!(fact.unwrap().projections, RuntimePlaceProjections::EMPTY);
        }

        for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
            compile_x86_64_function::<_, 3072, 8, 64>(&function, &resolver, abi).unwrap();
        }
    }

    #[test]
    fn runtime_body_facts_preanalyze_scoped_expression_statement_reads() {
        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u16, left: u16, right: u16, choose: bool) -> u16 { let first: u16 = input + left; if choose { let branch: u16 = first + right; branch + left; } else { first + input; } while choose { first + right; break; } first + left; first }";
        let module = Parser::new(source).parse_module::<1, 8>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<8>().unwrap();
        let resolver = NoConstants;
        let mut facts = RuntimeBodyFacts::EMPTY;
        let count = preanalyze_runtime_body_declarations::<_, 8, 64>(
            &function,
            &resolver,
            &body,
            "u16",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();

        assert_eq!(count, 2);
        assert_eq!(facts.assignment_access_count, 0);
        assert_eq!(facts.assignment_read_count, 15);
        for (fact, identity) in facts.assignment_reads[..15].iter().zip([
            RuntimePlaceIdentity::Parameter(0),
            RuntimePlaceIdentity::Parameter(1),
            RuntimePlaceIdentity::Parameter(3),
            RuntimePlaceIdentity::Local(RuntimeLocalId(0)),
            RuntimePlaceIdentity::Parameter(2),
            RuntimePlaceIdentity::Local(RuntimeLocalId(1)),
            RuntimePlaceIdentity::Parameter(1),
            RuntimePlaceIdentity::Local(RuntimeLocalId(0)),
            RuntimePlaceIdentity::Parameter(0),
            RuntimePlaceIdentity::Parameter(3),
            RuntimePlaceIdentity::Local(RuntimeLocalId(0)),
            RuntimePlaceIdentity::Parameter(2),
            RuntimePlaceIdentity::Local(RuntimeLocalId(0)),
            RuntimePlaceIdentity::Parameter(1),
            RuntimePlaceIdentity::Local(RuntimeLocalId(0)),
        ]) {
            assert_eq!(fact.unwrap().base, identity);
            assert_eq!(fact.unwrap().projections, RuntimePlaceProjections::EMPTY);
        }

        for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
            compile_x86_64_function::<_, 4096, 8, 64>(&function, &resolver, abi).unwrap();
        }
    }

    #[test]
    fn runtime_body_facts_preanalyze_conditions_returns_and_scalar_tail() {
        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u16, choose: bool, limit: u16) -> u16 { let first: u16 = input + 1; if choose { return first + input; } while first < limit { if first == input { let returned: u16 = first + limit; return returned + input; } break; } first + limit }";
        let module = Parser::new(source).parse_module::<1, 8>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<8>().unwrap();
        let resolver = NoConstants;
        let mut facts = RuntimeBodyFacts::EMPTY;
        let count = preanalyze_runtime_body_declarations::<_, 8, 64>(
            &function,
            &resolver,
            &body,
            "u16",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();

        assert_eq!(count, 2);
        assert_eq!(facts.assignment_access_count, 0);
        assert_eq!(facts.assignment_read_count, 14);
        for (fact, identity) in facts.assignment_reads[..14].iter().zip([
            RuntimePlaceIdentity::Parameter(0),
            RuntimePlaceIdentity::Parameter(1),
            RuntimePlaceIdentity::Local(RuntimeLocalId(0)),
            RuntimePlaceIdentity::Parameter(0),
            RuntimePlaceIdentity::Local(RuntimeLocalId(0)),
            RuntimePlaceIdentity::Parameter(2),
            RuntimePlaceIdentity::Local(RuntimeLocalId(0)),
            RuntimePlaceIdentity::Parameter(0),
            RuntimePlaceIdentity::Local(RuntimeLocalId(0)),
            RuntimePlaceIdentity::Parameter(2),
            RuntimePlaceIdentity::Local(RuntimeLocalId(1)),
            RuntimePlaceIdentity::Parameter(0),
            RuntimePlaceIdentity::Local(RuntimeLocalId(0)),
            RuntimePlaceIdentity::Parameter(2),
        ]) {
            assert_eq!(fact.unwrap().base, identity);
            assert_eq!(fact.unwrap().projections, RuntimePlaceProjections::EMPTY);
        }

        for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
            compile_x86_64_function::<_, 4096, 8, 64>(&function, &resolver, abi).unwrap();
        }
    }

    #[test]
    fn runtime_body_facts_follow_loop_scope_emission_order() {
        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn value(limit: u16) -> u16 { let mut index: u16 = 0; let mut total: u16 = 0; while index < limit { let current: u16 = index + 1; loop { let nested: u16 = current; total += nested; break; } if current % 2 == 0 { let branch: u16 = current + 1; total += branch; } else { let branch: u16 = current + 2; total += branch; } index = current; } let after: u16 = total; after }";
        let module = Parser::new(source).parse_module::<1, 8>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<8>().unwrap();
        let resolver = NoConstants;
        let mut facts = RuntimeBodyFacts::EMPTY;
        let count = preanalyze_runtime_body_declarations::<_, 8, 64>(
            &function,
            &resolver,
            &body,
            "u16",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();

        assert_eq!(count, 7);
        for (id, (fact, name)) in facts.locals[..count]
            .iter()
            .zip([
                "index", "total", "current", "nested", "branch", "branch", "after",
            ])
            .enumerate()
        {
            assert_eq!(fact.unwrap().name, name);
            assert_eq!(fact.unwrap().id, RuntimeLocalId(id));
        }
        assert_ne!(
            facts.locals[4].unwrap().declaration_span,
            facts.locals[5].unwrap().declaration_span
        );
        assert_eq!(facts.assignment_access_count, 4);
        for (fact, id) in facts.assignment_accesses[..4].iter().zip([
            RuntimeLocalId(1),
            RuntimeLocalId(1),
            RuntimeLocalId(1),
            RuntimeLocalId(0),
        ]) {
            assert_eq!(fact.unwrap().base, RuntimePlaceIdentity::Local(id));
        }
        assert_eq!(
            facts.assignment_accesses[0].unwrap().access,
            RuntimePlaceAccess::ReadModifyWrite
        );
        assert_eq!(
            facts.assignment_accesses[3].unwrap().access,
            RuntimePlaceAccess::Write
        );
        assert_eq!(facts.assignment_read_count, 13);
        for (fact, identity) in facts.assignment_reads[..13].iter().zip([
            RuntimePlaceIdentity::Local(RuntimeLocalId(0)),
            RuntimePlaceIdentity::Parameter(0),
            RuntimePlaceIdentity::Local(RuntimeLocalId(0)),
            RuntimePlaceIdentity::Local(RuntimeLocalId(2)),
            RuntimePlaceIdentity::Local(RuntimeLocalId(3)),
            RuntimePlaceIdentity::Local(RuntimeLocalId(2)),
            RuntimePlaceIdentity::Local(RuntimeLocalId(2)),
            RuntimePlaceIdentity::Local(RuntimeLocalId(4)),
            RuntimePlaceIdentity::Local(RuntimeLocalId(2)),
            RuntimePlaceIdentity::Local(RuntimeLocalId(5)),
            RuntimePlaceIdentity::Local(RuntimeLocalId(2)),
            RuntimePlaceIdentity::Local(RuntimeLocalId(1)),
            RuntimePlaceIdentity::Local(RuntimeLocalId(6)),
        ]) {
            assert_eq!(fact.unwrap().base, identity);
        }
        for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
            compile_x86_64_function::<_, 4096, 8, 64>(&function, &resolver, abi).unwrap();
        }
    }

    #[test]
    fn runtime_body_facts_follow_interleaved_nested_loop_control_order() {
        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn value(limit: u16, gate: bool, stop: u16) -> u16 { let mut outer: u16 = 0; while outer < limit { outer += 1; let seed: u16 = outer + limit; while seed < stop { if gate && seed == outer { continue; } let inner: u16 = seed + outer; if inner == stop { break; } if gate && inner == limit { return inner + outer; } outer += inner; break; } } outer }";
        let module = Parser::new(source).parse_module::<1, 8>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<8>().unwrap();
        let resolver = NoConstants;
        let mut facts = RuntimeBodyFacts::EMPTY;
        let count = preanalyze_runtime_body_declarations::<_, 8, 64>(
            &function,
            &resolver,
            &body,
            "u16",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();

        assert_eq!(count, 3);
        assert_eq!(facts.assignment_access_count, 2);
        assert_eq!(facts.assignment_read_count, 20);
        for (fact, identity) in facts.assignment_reads[..20].iter().zip([
            RuntimePlaceIdentity::Local(RuntimeLocalId(0)),
            RuntimePlaceIdentity::Parameter(0),
            RuntimePlaceIdentity::Local(RuntimeLocalId(0)),
            RuntimePlaceIdentity::Parameter(0),
            RuntimePlaceIdentity::Local(RuntimeLocalId(1)),
            RuntimePlaceIdentity::Parameter(2),
            RuntimePlaceIdentity::Parameter(1),
            RuntimePlaceIdentity::Local(RuntimeLocalId(1)),
            RuntimePlaceIdentity::Local(RuntimeLocalId(0)),
            RuntimePlaceIdentity::Local(RuntimeLocalId(1)),
            RuntimePlaceIdentity::Local(RuntimeLocalId(0)),
            RuntimePlaceIdentity::Local(RuntimeLocalId(2)),
            RuntimePlaceIdentity::Parameter(2),
            RuntimePlaceIdentity::Parameter(1),
            RuntimePlaceIdentity::Local(RuntimeLocalId(2)),
            RuntimePlaceIdentity::Parameter(0),
            RuntimePlaceIdentity::Local(RuntimeLocalId(2)),
            RuntimePlaceIdentity::Local(RuntimeLocalId(0)),
            RuntimePlaceIdentity::Local(RuntimeLocalId(2)),
            RuntimePlaceIdentity::Local(RuntimeLocalId(0)),
        ]) {
            assert_eq!(fact.unwrap().base, identity);
            assert_eq!(fact.unwrap().projections, RuntimePlaceProjections::EMPTY);
        }

        let mut saw_header = false;
        let mut saw_action = false;
        let mut saw_condition = false;
        let mut saw_value = false;
        for effect in facts.effects[..facts.effect_count].iter().flatten() {
            match effect.location {
                RuntimeOwnershipEventLocation::NestedLoopHeader { .. } => saw_header = true,
                RuntimeOwnershipEventLocation::NestedLoopAction { .. } => saw_action = true,
                RuntimeOwnershipEventLocation::NestedLoopControlCondition { .. } => {
                    saw_condition = true;
                }
                RuntimeOwnershipEventLocation::NestedLoopControlValue { .. } => saw_value = true,
                _ => continue,
            }
            assert!(facts.ownership_control_point(effect.location).is_some());
        }
        assert!(saw_header && saw_action && saw_condition && saw_value);

        for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
            compile_x86_64_function::<_, 4096, 8, 64>(&function, &resolver, abi).unwrap();
        }
    }

    #[test]
    fn runtime_body_facts_preanalyze_literal_aggregate_materialization_order() {
        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn value(first: u16, second: u16, index: usize, choose: bool) -> u16 { let repeated: [u16; 3] = [first + second; 3]; let values: [u16; 3] = [first, repeated[index], if choose { second } else { first }]; let pair: (u16, u16) = (values[0], second + first); pair.0 }";
        let module = Parser::new(source).parse_module::<1, 8>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<8>().unwrap();
        let resolver = NoConstants;
        let mut facts = RuntimeBodyFacts::EMPTY;
        let count = preanalyze_runtime_body_declarations::<_, 8, 64>(
            &function,
            &resolver,
            &body,
            "u16",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();

        assert_eq!(count, 3);
        assert_eq!(facts.assignment_access_count, 0);
        assert_eq!(facts.assignment_read_count, 14);
        for (fact, identity) in facts.assignment_reads[..14].iter().zip([
            RuntimePlaceIdentity::Parameter(0),
            RuntimePlaceIdentity::Parameter(1),
            RuntimePlaceIdentity::Parameter(0),
            RuntimePlaceIdentity::Local(RuntimeLocalId(0)),
            RuntimePlaceIdentity::Local(RuntimeLocalId(0)),
            RuntimePlaceIdentity::Local(RuntimeLocalId(0)),
            RuntimePlaceIdentity::Parameter(2),
            RuntimePlaceIdentity::Parameter(3),
            RuntimePlaceIdentity::Parameter(1),
            RuntimePlaceIdentity::Parameter(0),
            RuntimePlaceIdentity::Local(RuntimeLocalId(1)),
            RuntimePlaceIdentity::Parameter(1),
            RuntimePlaceIdentity::Parameter(0),
            RuntimePlaceIdentity::Local(RuntimeLocalId(2)),
        ]) {
            assert_eq!(fact.unwrap().base, identity);
        }

        for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
            compile_x86_64_function::<_, 4096, 8, 64>(&function, &resolver, abi).unwrap();
        }
    }

    #[test]
    fn runtime_body_facts_preanalyze_aggregate_copy_projections() {
        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn value(values: [u16; 3], first: u16, second: u16) -> u16 { let copied: [u16; 3] = values; let pair: (u16, u16) = (first, second); let pair_copy: (u16, u16) = pair; pair_copy.1 }";
        let module = Parser::new(source).parse_module::<1, 8>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<8>().unwrap();
        let resolver = NoConstants;
        let mut facts = RuntimeBodyFacts::EMPTY;
        let count = preanalyze_runtime_body_declarations::<_, 8, 64>(
            &function,
            &resolver,
            &body,
            "u16",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();

        assert_eq!(count, 3);
        assert_eq!(facts.assignment_read_count, 8);
        for index in 0..3 {
            let fact = facts.assignment_reads[index].unwrap();
            assert_eq!(fact.base, RuntimePlaceIdentity::Parameter(0));
            assert_eq!(
                fact.projections,
                RuntimePlaceProjections::single(RuntimePlaceProjection::Index)
            );
        }
        assert_eq!(
            facts.assignment_reads[3].unwrap().base,
            RuntimePlaceIdentity::Parameter(1)
        );
        assert_eq!(
            facts.assignment_reads[4].unwrap().base,
            RuntimePlaceIdentity::Parameter(2)
        );
        for (index, field) in [(5, 0), (6, 1)] {
            let fact = facts.assignment_reads[index].unwrap();
            assert_eq!(fact.base, RuntimePlaceIdentity::Local(RuntimeLocalId(1)));
            assert_eq!(
                fact.projections,
                RuntimePlaceProjections::single(RuntimePlaceProjection::TupleField(field))
            );
        }
        assert_eq!(
            facts.assignment_reads[7].unwrap().base,
            RuntimePlaceIdentity::Local(RuntimeLocalId(2))
        );

        for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
            compile_x86_64_function::<_, 4096, 8, 64>(&function, &resolver, abi).unwrap();
        }
    }

    #[test]
    fn runtime_body_facts_preanalyze_conditional_tuple_literals_once() {
        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn value(first: u16, second: u16, choose: bool) -> u16 { let selected: (u16, u16) = if choose { (first + 1, second) } else { (second + 2, first) }; selected.0 }";
        let module = Parser::new(source).parse_module::<1, 8>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<8>().unwrap();
        let resolver = NoConstants;
        let mut facts = RuntimeBodyFacts::EMPTY;
        let count = preanalyze_runtime_body_declarations::<_, 8, 64>(
            &function,
            &resolver,
            &body,
            "u16",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();

        assert_eq!(count, 1);
        assert_eq!(facts.assignment_read_count, 6);
        for (fact, identity) in facts.assignment_reads[..6].iter().zip([
            RuntimePlaceIdentity::Parameter(2),
            RuntimePlaceIdentity::Parameter(0),
            RuntimePlaceIdentity::Parameter(1),
            RuntimePlaceIdentity::Parameter(1),
            RuntimePlaceIdentity::Parameter(0),
            RuntimePlaceIdentity::Local(RuntimeLocalId(0)),
        ]) {
            assert_eq!(fact.unwrap().base, identity);
        }

        for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
            compile_x86_64_function::<_, 4096, 8, 64>(&function, &resolver, abi).unwrap();
        }
    }

    #[test]
    fn runtime_body_facts_preanalyze_conditional_array_literals_once_per_branch() {
        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn value(first: u16, second: u16, left: u16, right: u16, choose: bool) -> u16 { let selected: [u16; 2] = if choose { [first + left, second] } else { [right, first + second] }; selected[0] }";
        let module = Parser::new(source).parse_module::<1, 8>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<8>().unwrap();
        let resolver = NoConstants;
        let mut facts = RuntimeBodyFacts::EMPTY;
        let count = preanalyze_runtime_body_declarations::<_, 8, 64>(
            &function,
            &resolver,
            &body,
            "u16",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();

        assert_eq!(count, 1);
        assert_eq!(facts.assignment_read_count, 8);
        for (fact, identity) in facts.assignment_reads[..8].iter().zip([
            RuntimePlaceIdentity::Parameter(4),
            RuntimePlaceIdentity::Parameter(0),
            RuntimePlaceIdentity::Parameter(2),
            RuntimePlaceIdentity::Parameter(1),
            RuntimePlaceIdentity::Parameter(3),
            RuntimePlaceIdentity::Parameter(0),
            RuntimePlaceIdentity::Parameter(1),
            RuntimePlaceIdentity::Local(RuntimeLocalId(0)),
        ]) {
            assert_eq!(fact.unwrap().base, identity);
        }

        for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
            compile_x86_64_function::<_, 4096, 8, 64>(&function, &resolver, abi).unwrap();
        }
    }

    #[test]
    fn runtime_body_facts_preanalyze_sequence_wrapped_aggregates_exactly() {
        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn value(first: u16, second: u16, left: u16, right: u16, prefix: u16) -> u16 { let pair: (u16, u16) = { prefix + first; (left, right) }; let values: [u16; 2] = { prefix + second; [first, left] }; pair.0 + values[1] }";
        let module = Parser::new(source).parse_module::<1, 8>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<8>().unwrap();
        let resolver = NoConstants;
        let mut facts = RuntimeBodyFacts::EMPTY;
        let count = preanalyze_runtime_body_declarations::<_, 8, 64>(
            &function,
            &resolver,
            &body,
            "u16",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();

        assert_eq!(count, 2);
        assert_eq!(facts.assignment_read_count, 10);
        for (fact, identity) in facts.assignment_reads[..10].iter().zip([
            RuntimePlaceIdentity::Parameter(4),
            RuntimePlaceIdentity::Parameter(0),
            RuntimePlaceIdentity::Parameter(2),
            RuntimePlaceIdentity::Parameter(3),
            RuntimePlaceIdentity::Parameter(4),
            RuntimePlaceIdentity::Parameter(1),
            RuntimePlaceIdentity::Parameter(0),
            RuntimePlaceIdentity::Parameter(2),
            RuntimePlaceIdentity::Local(RuntimeLocalId(0)),
            RuntimePlaceIdentity::Local(RuntimeLocalId(1)),
        ]) {
            assert_eq!(fact.unwrap().base, identity);
        }

        for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
            compile_x86_64_function::<_, 4096, 8, 64>(&function, &resolver, abi).unwrap();
        }
    }

    #[test]
    fn runtime_body_facts_preanalyze_simple_fat_reference_initializers() {
        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &[u16], alternate: &[u16], text: &str, choose: bool, prefix: usize) -> usize { let direct: &[u16] = input; let selected: &[u16] = if choose { direct } else { alternate }; let copied_text: &str = { prefix; text }; selected.len() + copied_text.len() }";
        let module = Parser::new(source).parse_module::<1, 8>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<8>().unwrap();
        let resolver = NoConstants;
        let mut facts = RuntimeBodyFacts::EMPTY;
        let count = preanalyze_runtime_body_declarations::<_, 8, 64>(
            &function,
            &resolver,
            &body,
            "usize",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();

        assert_eq!(count, 3);
        assert_eq!(facts.assignment_read_count, 6);
        for (fact, identity) in facts.assignment_reads[..6].iter().zip([
            RuntimePlaceIdentity::Parameter(0),
            RuntimePlaceIdentity::Parameter(3),
            RuntimePlaceIdentity::Local(RuntimeLocalId(0)),
            RuntimePlaceIdentity::Parameter(1),
            RuntimePlaceIdentity::Parameter(4),
            RuntimePlaceIdentity::Parameter(2),
        ]) {
            assert_eq!(fact.unwrap().base, identity);
            assert_eq!(fact.unwrap().projections, RuntimePlaceProjections::EMPTY);
        }

        for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
            compile_x86_64_function::<_, 4096, 8, 64>(&function, &resolver, abi).unwrap();
        }
    }

    #[test]
    fn runtime_body_facts_preanalyze_call_derived_fat_reference_initializers() {
        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &[usize], prefix: usize, start: usize, end: usize, bias: usize) -> usize { let selected: &[usize] = { prefix; choose(input, start, end, bias) }; selected.len() }";
        let module = Parser::new(source).parse_module::<1, 8>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<8>().unwrap();
        let resolver = FatCallResolver;
        let mut facts = RuntimeBodyFacts::EMPTY;
        let count = preanalyze_runtime_body_declarations::<_, 8, 64>(
            &function,
            &resolver,
            &body,
            "usize",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();

        assert_eq!(count, 1);
        assert_eq!(facts.assignment_read_count, 5);
        for (fact, identity) in facts.assignment_reads[..5].iter().zip([
            RuntimePlaceIdentity::Parameter(1),
            RuntimePlaceIdentity::Parameter(0),
            RuntimePlaceIdentity::Parameter(2),
            RuntimePlaceIdentity::Parameter(3),
            RuntimePlaceIdentity::Parameter(4),
        ]) {
            assert_eq!(fact.unwrap().base, identity);
            assert_eq!(fact.unwrap().projections, RuntimePlaceProjections::EMPTY);
        }

        for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
            compile_x86_64_function::<_, 4096, 8, 64>(&function, &resolver, abi).unwrap();
        }
    }

    #[test]
    fn runtime_body_facts_preanalyze_identifier_aggregate_call_arguments() {
        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn value(first: usize, second: usize, third: usize, left: usize, right: usize, prefix: usize, bias: usize) -> usize { let values = [first, second, third]; let pair = (left, right); let selected: &[usize] = { prefix; choose_aggregate(values, pair, bias) }; selected.len() }";
        let module = Parser::new(source).parse_module::<1, 8>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<8>().unwrap();
        let resolver = FatCallResolver;
        let mut facts = RuntimeBodyFacts::EMPTY;
        let count = preanalyze_runtime_body_declarations::<_, 8, 64>(
            &function,
            &resolver,
            &body,
            "usize",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();

        assert_eq!(count, 3);
        assert_eq!(facts.assignment_read_count, 12);
        for (index, fact) in facts.assignment_reads[..12].iter().enumerate() {
            let fact = fact.unwrap();
            let (base, projections) = match index {
                0..=4 => (
                    RuntimePlaceIdentity::Parameter(index),
                    RuntimePlaceProjections::EMPTY,
                ),
                5 => (
                    RuntimePlaceIdentity::Parameter(5),
                    RuntimePlaceProjections::EMPTY,
                ),
                6..=8 => (
                    RuntimePlaceIdentity::Local(RuntimeLocalId(0)),
                    RuntimePlaceProjections::single(RuntimePlaceProjection::Index),
                ),
                9 | 10 => (
                    RuntimePlaceIdentity::Local(RuntimeLocalId(1)),
                    RuntimePlaceProjections::single(RuntimePlaceProjection::TupleField(index - 9)),
                ),
                11 => (
                    RuntimePlaceIdentity::Parameter(6),
                    RuntimePlaceProjections::EMPTY,
                ),
                _ => unreachable!(),
            };
            assert_eq!(fact.base, base);
            assert_eq!(fact.projections, projections);
        }

        for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
            compile_x86_64_function::<_, 4096, 8, 64>(&function, &resolver, abi).unwrap();
        }
    }

    #[test]
    fn runtime_body_facts_preanalyze_literal_aggregate_call_arguments() {
        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn value(first: usize, second: usize, third: usize, left: usize, right: usize, prefix: usize, bias: usize, choose: bool) -> usize { let selected: &[usize] = { prefix; choose_literal([first, second, third], if choose { (left, right) } else { (right, left) }, bias) }; let repeated: &[usize] = choose_literal([first; 3], (left, right), bias); selected.len() + repeated.len() }";
        let module = Parser::new(source).parse_module::<1, 8>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<8>().unwrap();
        let resolver = FatCallResolver;
        let mut facts = RuntimeBodyFacts::EMPTY;
        let count = preanalyze_runtime_body_declarations::<_, 8, 64>(
            &function,
            &resolver,
            &body,
            "usize",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();

        assert_eq!(count, 2);
        assert_eq!(facts.assignment_read_count, 14);
        for (fact, identity) in facts.assignment_reads[..14].iter().zip([
            RuntimePlaceIdentity::Parameter(5),
            RuntimePlaceIdentity::Parameter(0),
            RuntimePlaceIdentity::Parameter(1),
            RuntimePlaceIdentity::Parameter(2),
            RuntimePlaceIdentity::Parameter(7),
            RuntimePlaceIdentity::Parameter(3),
            RuntimePlaceIdentity::Parameter(4),
            RuntimePlaceIdentity::Parameter(4),
            RuntimePlaceIdentity::Parameter(3),
            RuntimePlaceIdentity::Parameter(6),
            RuntimePlaceIdentity::Parameter(0),
            RuntimePlaceIdentity::Parameter(3),
            RuntimePlaceIdentity::Parameter(4),
            RuntimePlaceIdentity::Parameter(6),
        ]) {
            assert_eq!(fact.unwrap().base, identity);
            assert_eq!(fact.unwrap().projections, RuntimePlaceProjections::EMPTY);
        }

        for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
            compile_x86_64_function::<_, 4096, 8, 64>(&function, &resolver, abi).unwrap();
        }
    }

    #[test]
    fn runtime_body_facts_preanalyze_conditional_array_call_arguments() {
        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn value(first: usize, second: usize, third: usize, left: usize, right: usize, prefix: usize, bias: usize, choose: bool) -> usize { let selected: &[usize] = { prefix; choose_conditional(if choose { [first, second, third] } else { [third, second, first] }, (left, right), bias) }; selected.len() }";
        let module = Parser::new(source).parse_module::<1, 8>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<8>().unwrap();
        let resolver = FatCallResolver;
        let mut facts = RuntimeBodyFacts::EMPTY;
        let count = preanalyze_runtime_body_declarations::<_, 8, 64>(
            &function,
            &resolver,
            &body,
            "usize",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();

        assert_eq!(count, 1);
        assert_eq!(facts.assignment_read_count, 11);
        for (fact, identity) in facts.assignment_reads[..11].iter().zip([
            RuntimePlaceIdentity::Parameter(5),
            RuntimePlaceIdentity::Parameter(7),
            RuntimePlaceIdentity::Parameter(0),
            RuntimePlaceIdentity::Parameter(1),
            RuntimePlaceIdentity::Parameter(2),
            RuntimePlaceIdentity::Parameter(2),
            RuntimePlaceIdentity::Parameter(1),
            RuntimePlaceIdentity::Parameter(0),
            RuntimePlaceIdentity::Parameter(3),
            RuntimePlaceIdentity::Parameter(4),
            RuntimePlaceIdentity::Parameter(6),
        ]) {
            assert_eq!(fact.unwrap().base, identity);
            assert_eq!(fact.unwrap().projections, RuntimePlaceProjections::EMPTY);
        }

        for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
            compile_x86_64_function::<_, 4096, 8, 64>(&function, &resolver, abi).unwrap();
        }
    }

    #[test]
    fn runtime_body_facts_preanalyze_sequence_wrapped_array_call_arguments() {
        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn value(first: usize, second: usize, third: usize, left: usize, right: usize, prefix: usize, bias: usize, choose: bool) -> usize { let selected: &[usize] = choose_wrapped({ prefix; if choose { [first, second, third] } else { [third, second, first] } }, (left, right), bias); selected.len() }";
        let module = Parser::new(source).parse_module::<1, 8>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<8>().unwrap();
        let resolver = FatCallResolver;
        let mut facts = RuntimeBodyFacts::EMPTY;
        let count = preanalyze_runtime_body_declarations::<_, 8, 64>(
            &function,
            &resolver,
            &body,
            "usize",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();

        assert_eq!(count, 1);
        assert_eq!(facts.assignment_read_count, 11);
        for (fact, identity) in facts.assignment_reads[..11].iter().zip([
            RuntimePlaceIdentity::Parameter(5),
            RuntimePlaceIdentity::Parameter(7),
            RuntimePlaceIdentity::Parameter(0),
            RuntimePlaceIdentity::Parameter(1),
            RuntimePlaceIdentity::Parameter(2),
            RuntimePlaceIdentity::Parameter(2),
            RuntimePlaceIdentity::Parameter(1),
            RuntimePlaceIdentity::Parameter(0),
            RuntimePlaceIdentity::Parameter(3),
            RuntimePlaceIdentity::Parameter(4),
            RuntimePlaceIdentity::Parameter(6),
        ]) {
            assert_eq!(fact.unwrap().base, identity);
            assert_eq!(fact.unwrap().projections, RuntimePlaceProjections::EMPTY);
        }

        for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
            compile_x86_64_function::<_, 4096, 8, 64>(&function, &resolver, abi).unwrap();
        }
    }

    #[test]
    fn runtime_body_facts_preanalyze_sequence_wrapped_identifier_array_call_arguments() {
        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn value(first: usize, second: usize, third: usize, left: usize, right: usize, prefix: usize, bias: usize) -> usize { let values = [first, second, third]; let selected: &[usize] = choose_wrapped({ prefix; values }, (left, right), bias); selected.len() }";
        let module = Parser::new(source).parse_module::<1, 8>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<8>().unwrap();
        let resolver = FatCallResolver;
        let mut facts = RuntimeBodyFacts::EMPTY;
        let count = preanalyze_runtime_body_declarations::<_, 8, 64>(
            &function,
            &resolver,
            &body,
            "usize",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();

        assert_eq!(count, 2);
        assert_eq!(facts.assignment_read_count, 10);
        for (index, fact) in facts.assignment_reads[..10].iter().enumerate() {
            let fact = fact.unwrap();
            let (base, projections) = match index {
                0..=2 => (
                    RuntimePlaceIdentity::Parameter(index),
                    RuntimePlaceProjections::EMPTY,
                ),
                3 => (
                    RuntimePlaceIdentity::Parameter(5),
                    RuntimePlaceProjections::EMPTY,
                ),
                4..=6 => (
                    RuntimePlaceIdentity::Local(RuntimeLocalId(0)),
                    RuntimePlaceProjections::single(RuntimePlaceProjection::Index),
                ),
                7 | 8 => (
                    RuntimePlaceIdentity::Parameter(index - 4),
                    RuntimePlaceProjections::EMPTY,
                ),
                9 => (
                    RuntimePlaceIdentity::Parameter(6),
                    RuntimePlaceProjections::EMPTY,
                ),
                _ => unreachable!(),
            };
            assert_eq!(fact.base, base);
            assert_eq!(fact.projections, projections);
        }

        for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
            compile_x86_64_function::<_, 4096, 8, 64>(&function, &resolver, abi).unwrap();
        }
    }

    #[test]
    fn runtime_body_facts_preanalyze_sequence_wrapped_default_array_call_arguments() {
        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: usize, right: usize, prefix: usize, bias: usize) -> usize { let selected: &[usize] = choose_wrapped({ prefix; Default::default() }, (left, right), bias); selected.len() }";
        let module = Parser::new(source).parse_module::<1, 8>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<8>().unwrap();
        let resolver = FatCallResolver;
        let mut facts = RuntimeBodyFacts::EMPTY;
        let count = preanalyze_runtime_body_declarations::<_, 8, 64>(
            &function,
            &resolver,
            &body,
            "usize",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();

        assert_eq!(count, 1);
        assert_eq!(facts.assignment_read_count, 4);
        for (fact, identity) in facts.assignment_reads[..4].iter().zip([
            RuntimePlaceIdentity::Parameter(2),
            RuntimePlaceIdentity::Parameter(0),
            RuntimePlaceIdentity::Parameter(1),
            RuntimePlaceIdentity::Parameter(3),
        ]) {
            assert_eq!(fact.unwrap().base, identity);
            assert_eq!(fact.unwrap().projections, RuntimePlaceProjections::EMPTY);
        }

        for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
            compile_x86_64_function::<_, 4096, 8, 64>(&function, &resolver, abi).unwrap();
        }
    }

    #[test]
    fn runtime_body_facts_preanalyze_nested_wrapped_array_call_arguments() {
        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn value(first: usize, second: usize, third: usize, left: usize, right: usize, outer: usize, bias: usize, choose: bool) -> usize { let values = [first, second, third]; let selected: &[usize] = choose_wrapped({ outer; if choose { { left; values } } else { { right; [third, second, first] } } }, (left, right), bias); selected.len() }";
        let module = Parser::new(source).parse_module::<1, 8>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<8>().unwrap();
        let resolver = FatCallResolver;
        let mut facts = RuntimeBodyFacts::EMPTY;
        let count = preanalyze_runtime_body_declarations::<_, 8, 64>(
            &function,
            &resolver,
            &body,
            "usize",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();

        assert_eq!(count, 2);
        assert_eq!(facts.assignment_read_count, 16);
        for (index, fact) in facts.assignment_reads[..16].iter().enumerate() {
            let fact = fact.unwrap();
            let (base, projections) = match index {
                0..=2 => (
                    RuntimePlaceIdentity::Parameter(index),
                    RuntimePlaceProjections::EMPTY,
                ),
                3 => (
                    RuntimePlaceIdentity::Parameter(5),
                    RuntimePlaceProjections::EMPTY,
                ),
                4 => (
                    RuntimePlaceIdentity::Parameter(7),
                    RuntimePlaceProjections::EMPTY,
                ),
                5 => (
                    RuntimePlaceIdentity::Parameter(3),
                    RuntimePlaceProjections::EMPTY,
                ),
                6..=8 => (
                    RuntimePlaceIdentity::Local(RuntimeLocalId(0)),
                    RuntimePlaceProjections::single(RuntimePlaceProjection::Index),
                ),
                9 => (
                    RuntimePlaceIdentity::Parameter(4),
                    RuntimePlaceProjections::EMPTY,
                ),
                10 => (
                    RuntimePlaceIdentity::Parameter(2),
                    RuntimePlaceProjections::EMPTY,
                ),
                11 => (
                    RuntimePlaceIdentity::Parameter(1),
                    RuntimePlaceProjections::EMPTY,
                ),
                12 => (
                    RuntimePlaceIdentity::Parameter(0),
                    RuntimePlaceProjections::EMPTY,
                ),
                13 | 14 => (
                    RuntimePlaceIdentity::Parameter(index - 10),
                    RuntimePlaceProjections::EMPTY,
                ),
                15 => (
                    RuntimePlaceIdentity::Parameter(6),
                    RuntimePlaceProjections::EMPTY,
                ),
                _ => unreachable!(),
            };
            assert_eq!(fact.base, base);
            assert_eq!(fact.projections, projections);
        }

        for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
            compile_x86_64_function::<_, 8192, 8, 64>(&function, &resolver, abi).unwrap();
        }
    }

    #[test]
    fn runtime_body_facts_preanalyze_integer_byte_array_call_arguments() {
        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u64, prefix: u64, bias: usize) -> usize { let selected: &[u8] = choose_bytes(({ prefix; input }).to_le_bytes(), bias); selected.len() }";
        let module = Parser::new(source).parse_module::<1, 4>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<4>().unwrap();
        let resolver = ByteCallResolver;
        let mut facts = RuntimeBodyFacts::EMPTY;
        let count = preanalyze_runtime_body_declarations::<_, 4, 64>(
            &function,
            &resolver,
            &body,
            "usize",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();

        assert_eq!(count, 1);
        assert_eq!(facts.assignment_read_count, 3);
        for (index, fact) in facts.assignment_reads[..3].iter().enumerate() {
            let fact = fact.unwrap();
            let expected = if index == 2 {
                RuntimePlaceIdentity::Parameter(2)
            } else {
                RuntimePlaceIdentity::Parameter(1 - index)
            };
            assert_eq!(fact.base, expected);
            assert_eq!(fact.projections, RuntimePlaceProjections::EMPTY);
        }
        for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
            compile_x86_64_function::<_, 8192, 4, 64>(&function, &resolver, abi).unwrap();
        }
    }

    #[test]
    fn runtime_body_facts_preanalyze_array_producing_call_arguments() {
        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn value(first: usize, second: usize, third: usize, left: usize, right: usize, prefix: usize, bias: usize, choose: bool) -> usize { let direct: &[usize] = choose_wrapped(make_array(first, second, third), (left, right), bias); let wrapped: &[usize] = choose_wrapped({ prefix; if choose { make_array(first, second, third) } else { make_array(third, second, first) } }, (left, right), bias); direct.len() + wrapped.len() }";
        let module = Parser::new(source).parse_module::<1, 8>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<8>().unwrap();
        let resolver = FatCallResolver;
        let mut facts = RuntimeBodyFacts::EMPTY;
        let count = preanalyze_runtime_body_declarations::<_, 8, 64>(
            &function,
            &resolver,
            &body,
            "usize",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();

        assert_eq!(count, 2);
        assert_eq!(facts.assignment_read_count, 17);
        let expected = [0, 1, 2, 3, 4, 6, 5, 7, 0, 1, 2, 2, 1, 0, 3, 4, 6];
        for (fact, parameter) in facts.assignment_reads[..17].iter().zip(expected) {
            let fact = fact.unwrap();
            assert_eq!(fact.base, RuntimePlaceIdentity::Parameter(parameter));
            assert_eq!(fact.projections, RuntimePlaceProjections::EMPTY);
        }

        for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
            compile_x86_64_function::<_, 16384, 8, 64>(&function, &resolver, abi).unwrap();
        }
    }

    #[test]
    fn runtime_body_facts_preanalyze_tuple_producing_call_arguments_once() {
        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn value(first: usize, second: usize, prefix: usize, bias: usize, choose: bool) -> usize { let direct = consume_tuple(make_tuple(first, second), bias); let wrapped = consume_tuple({ prefix; if choose { make_tuple(first, second) } else { make_tuple(second, first) } }, bias); direct + wrapped }";
        let module = Parser::new(source).parse_module::<1, 6>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<6>().unwrap();
        let resolver = TupleCallResolver;
        let mut facts = RuntimeBodyFacts::EMPTY;
        let count = preanalyze_runtime_body_declarations::<_, 6, 64>(
            &function,
            &resolver,
            &body,
            "usize",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();

        assert_eq!(count, 2);
        assert_eq!(facts.assignment_read_count, 12);
        for (fact, parameter) in facts.assignment_reads[..10]
            .iter()
            .zip([0, 1, 3, 2, 4, 0, 1, 1, 0, 3])
        {
            let fact = fact.unwrap();
            assert_eq!(fact.base, RuntimePlaceIdentity::Parameter(parameter));
            assert_eq!(fact.projections, RuntimePlaceProjections::EMPTY);
        }
        for (fact, local) in facts.assignment_reads[10..12]
            .iter()
            .zip([RuntimeLocalId(0), RuntimeLocalId(1)])
        {
            let fact = fact.unwrap();
            assert_eq!(fact.base, RuntimePlaceIdentity::Local(local));
            assert_eq!(fact.projections, RuntimePlaceProjections::EMPTY);
        }

        for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
            compile_x86_64_function::<_, 16384, 6, 64>(&function, &resolver, abi).unwrap();
        }
    }

    #[test]
    fn runtime_body_facts_preanalyze_tuple_value_returns_and_tails() {
        let source = "fn value(first: usize, second: usize, prefix: usize, choose: bool) -> (usize, usize) { let pair = (first, second); if choose { return { prefix; pair }; } { prefix; if choose { make_tuple(first, second) } else { (second, first) } } }";
        let module = Parser::new(source).parse_module::<1, 4>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<4>().unwrap();
        let resolver = TupleCallResolver;
        let mut facts = RuntimeBodyFacts::EMPTY;
        let count = preanalyze_runtime_body_declarations::<_, 4, 64>(
            &function,
            &resolver,
            &body,
            "(usize, usize)",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();

        assert_eq!(count, 1);
        assert_eq!(facts.assignment_read_count, 12);
        for (fact, parameter) in facts.assignment_reads[..4].iter().zip([0, 1, 3, 2]) {
            let fact = fact.unwrap();
            assert_eq!(fact.base, RuntimePlaceIdentity::Parameter(parameter));
            assert_eq!(fact.projections, RuntimePlaceProjections::EMPTY);
        }
        for (fact, field) in facts.assignment_reads[4..6].iter().zip([0, 1]) {
            let fact = fact.unwrap();
            assert_eq!(fact.base, RuntimePlaceIdentity::Local(RuntimeLocalId(0)));
            assert_eq!(
                fact.projections,
                RuntimePlaceProjections::single(RuntimePlaceProjection::TupleField(field))
            );
        }
        for (fact, parameter) in facts.assignment_reads[6..].iter().zip([2, 3, 0, 1, 1, 0]) {
            let fact = fact.unwrap();
            assert_eq!(fact.base, RuntimePlaceIdentity::Parameter(parameter));
            assert_eq!(fact.projections, RuntimePlaceProjections::EMPTY);
        }
    }

    #[test]
    fn runtime_body_facts_mirror_tuple_loop_break_field_materialization() {
        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn value(first: usize, second: usize, prefix: usize, bias: usize) -> usize { let wrapped = consume_tuple(loop { break { prefix; make_tuple(first, second) }; }, bias); wrapped }";
        let module = Parser::new(source).parse_module::<1, 5>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<5>().unwrap();
        let resolver = TupleCallResolver;
        let mut facts = RuntimeBodyFacts::EMPTY;
        let count = preanalyze_runtime_body_declarations::<_, 5, 64>(
            &function,
            &resolver,
            &body,
            "usize",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();

        assert_eq!(count, 1);
        assert_eq!(facts.assignment_read_count, 8);
        for (fact, parameter) in facts.assignment_reads[..7]
            .iter()
            .zip([2, 0, 1, 2, 0, 1, 3])
        {
            let fact = fact.unwrap();
            assert_eq!(fact.base, RuntimePlaceIdentity::Parameter(parameter));
            assert_eq!(fact.projections, RuntimePlaceProjections::EMPTY);
        }
        let tail = facts.assignment_reads[7].unwrap();
        assert_eq!(tail.base, RuntimePlaceIdentity::Local(RuntimeLocalId(0)));
        assert_eq!(tail.projections, RuntimePlaceProjections::EMPTY);

        for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
            compile_x86_64_function::<_, 16384, 5, 64>(&function, &resolver, abi).unwrap();
        }
    }

    #[test]
    fn runtime_body_facts_preanalyze_direct_array_call_returns_and_tails() {
        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn value(first: usize, second: usize, third: usize, prefix: usize, bias: usize) -> [usize; 3] { prefix; if bias == 0 { return make_array(first, second, third); } make_array(third, second, first) }";
        let module = Parser::new(source).parse_module::<1, 6>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<6>().unwrap();
        let resolver = FatCallResolver;
        let mut facts = RuntimeBodyFacts::EMPTY;
        let count = preanalyze_runtime_body_declarations::<_, 6, 64>(
            &function,
            &resolver,
            &body,
            "[usize; 3]",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();

        assert_eq!(count, 0);
        assert_eq!(facts.assignment_read_count, 8);
        for (fact, parameter) in facts.assignment_reads[..8]
            .iter()
            .zip([3, 4, 0, 1, 2, 2, 1, 0])
        {
            let fact = fact.unwrap();
            assert_eq!(fact.base, RuntimePlaceIdentity::Parameter(parameter));
            assert_eq!(fact.projections, RuntimePlaceProjections::EMPTY);
        }

        for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
            compile_x86_64_function::<_, 16384, 6, 64>(&function, &resolver, abi).unwrap();
        }
    }

    #[test]
    fn runtime_body_facts_preanalyze_compound_array_index_bases() {
        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn value(first: usize, second: usize, third: usize, prefix: usize, index: usize) -> usize { let selected = ({ prefix; if index == 0 { make_array(first, second, third) } else { [third, second, first] } })[index]; selected }";
        let module = Parser::new(source).parse_module::<1, 5>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<5>().unwrap();
        let resolver = FatCallResolver;
        let mut facts = RuntimeBodyFacts::EMPTY;
        let count = preanalyze_runtime_body_declarations::<_, 5, 64>(
            &function,
            &resolver,
            &body,
            "usize",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();

        assert_eq!(count, 1);
        assert_eq!(facts.assignment_read_count, 10);
        for (fact, parameter) in facts.assignment_reads[..9]
            .iter()
            .zip([3, 4, 0, 1, 2, 2, 1, 0, 4])
        {
            let fact = fact.unwrap();
            assert_eq!(fact.base, RuntimePlaceIdentity::Parameter(parameter));
            assert_eq!(fact.projections, RuntimePlaceProjections::EMPTY);
        }
        let tail = facts.assignment_reads[9].unwrap();
        assert_eq!(tail.base, RuntimePlaceIdentity::Local(RuntimeLocalId(0)));
        assert_eq!(tail.projections, RuntimePlaceProjections::EMPTY);

        for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
            compile_x86_64_function::<_, 16384, 5, 64>(&function, &resolver, abi).unwrap();
        }
    }

    #[test]
    fn runtime_body_facts_preanalyze_direct_array_value_returns_and_tails() {
        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn value(first: usize, second: usize, third: usize, prefix: usize, bias: usize) -> [usize; 3] { prefix; if bias == 0 { return [first, second, third]; } [third; 3] }";
        let module = Parser::new(source).parse_module::<1, 6>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<6>().unwrap();
        let resolver = NoConstants;
        let mut facts = RuntimeBodyFacts::EMPTY;
        let count = preanalyze_runtime_body_declarations::<_, 6, 64>(
            &function,
            &resolver,
            &body,
            "[usize; 3]",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();

        assert_eq!(count, 0);
        assert_eq!(facts.assignment_read_count, 6);
        for (fact, parameter) in facts.assignment_reads[..6].iter().zip([3, 4, 0, 1, 2, 2]) {
            let fact = fact.unwrap();
            assert_eq!(fact.base, RuntimePlaceIdentity::Parameter(parameter));
            assert_eq!(fact.projections, RuntimePlaceProjections::EMPTY);
        }

        for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
            compile_x86_64_function::<_, 16384, 6, 64>(&function, &resolver, abi).unwrap();
        }
    }

    #[test]
    fn runtime_body_facts_preanalyze_direct_array_identifier_returns_per_index() {
        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn value(values: [u16; 3], choose: bool) -> [u16; 3] { if choose { return values; } values }";
        let module = Parser::new(source).parse_module::<1, 2>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<2>().unwrap();
        let resolver = NoConstants;
        let mut facts = RuntimeBodyFacts::EMPTY;
        let count = preanalyze_runtime_body_declarations::<_, 2, 32>(
            &function,
            &resolver,
            &body,
            "[u16; 3]",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();

        assert_eq!(count, 0);
        assert_eq!(facts.assignment_read_count, 7);
        let condition = facts.assignment_reads[0].unwrap();
        assert_eq!(condition.base, RuntimePlaceIdentity::Parameter(1));
        assert_eq!(condition.projections, RuntimePlaceProjections::EMPTY);
        for fact in facts.assignment_reads[1..7].iter().flatten() {
            assert_eq!(fact.base, RuntimePlaceIdentity::Parameter(0));
            assert_eq!(
                fact.projections,
                RuntimePlaceProjections::single(RuntimePlaceProjection::Index)
            );
        }

        for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
            compile_x86_64_function::<_, 16384, 2, 32>(&function, &resolver, abi).unwrap();
        }
    }

    #[test]
    fn runtime_body_facts_preanalyze_conditional_array_returns_once_per_branch() {
        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn value(first: usize, second: usize, third: usize, fourth: usize, prefix: usize, bias: usize, choose: bool) -> [usize; 2] { prefix; if bias == 0 { return if choose { [first, second] } else { [third, fourth] }; } if choose { [fourth, third] } else { [second, first] } }";
        let module = Parser::new(source).parse_module::<1, 7>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<7>().unwrap();
        let resolver = NoConstants;
        let mut facts = RuntimeBodyFacts::EMPTY;
        let count = preanalyze_runtime_body_declarations::<_, 7, 64>(
            &function,
            &resolver,
            &body,
            "[usize; 2]",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();

        assert_eq!(count, 0);
        assert_eq!(facts.assignment_read_count, 12);
        for (fact, parameter) in facts.assignment_reads[..12]
            .iter()
            .zip([4, 5, 6, 0, 1, 2, 3, 6, 3, 2, 1, 0])
        {
            let fact = fact.unwrap();
            assert_eq!(fact.base, RuntimePlaceIdentity::Parameter(parameter));
            assert_eq!(fact.projections, RuntimePlaceProjections::EMPTY);
        }

        for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
            compile_x86_64_function::<_, 16384, 7, 64>(&function, &resolver, abi).unwrap();
        }
    }

    #[test]
    fn runtime_body_facts_preanalyze_packed_conditional_identifiers_once_per_branch() {
        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: [u16; 3], right: [u16; 3], prefix: usize, bias: bool, choose: bool) -> [u16; 3] { prefix; if bias { return if choose { left } else { right }; } if choose { right } else { left } }";
        let module = Parser::new(source).parse_module::<1, 5>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<5>().unwrap();
        let resolver = NoConstants;
        let mut facts = RuntimeBodyFacts::EMPTY;
        let count = preanalyze_runtime_body_declarations::<_, 5, 64>(
            &function,
            &resolver,
            &body,
            "[u16; 3]",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();

        assert_eq!(count, 0);
        assert_eq!(facts.assignment_read_count, 16);
        for (index, (fact, parameter)) in facts.assignment_reads[..16]
            .iter()
            .zip([2, 3, 4, 0, 0, 0, 1, 1, 1, 4, 1, 1, 1, 0, 0, 0])
            .enumerate()
        {
            let fact = fact.unwrap();
            assert_eq!(fact.base, RuntimePlaceIdentity::Parameter(parameter));
            let projected = !matches!(index, 0 | 1 | 2 | 9);
            assert_eq!(
                fact.projections,
                if projected {
                    RuntimePlaceProjections::single(RuntimePlaceProjection::Index)
                } else {
                    RuntimePlaceProjections::EMPTY
                }
            );
        }

        for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
            compile_x86_64_function::<_, 16384, 5, 64>(&function, &resolver, abi).unwrap();
        }
    }

    #[test]
    fn runtime_body_facts_evaluate_sequence_prefixes_once_per_returned_array() {
        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn value(first: usize, second: usize, prefix: usize, suffix: usize, bias: bool) -> [usize; 2] { if bias { return { prefix; [first, second] }; } { suffix; [second, first] } }";
        let module = Parser::new(source).parse_module::<1, 5>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<5>().unwrap();
        let resolver = NoConstants;
        let mut facts = RuntimeBodyFacts::EMPTY;
        let count = preanalyze_runtime_body_declarations::<_, 5, 64>(
            &function,
            &resolver,
            &body,
            "[usize; 2]",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();

        assert_eq!(count, 0);
        assert_eq!(facts.assignment_read_count, 7);
        for (fact, parameter) in facts.assignment_reads[..7]
            .iter()
            .zip([4, 2, 0, 1, 3, 1, 0])
        {
            let fact = fact.unwrap();
            assert_eq!(fact.base, RuntimePlaceIdentity::Parameter(parameter));
            assert_eq!(fact.projections, RuntimePlaceProjections::EMPTY);
        }

        for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
            compile_x86_64_function::<_, 16384, 5, 64>(&function, &resolver, abi).unwrap();
        }
    }

    #[test]
    fn runtime_body_facts_evaluate_wrapped_array_calls_once() {
        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn value(first: usize, second: usize, third: usize, prefix: usize, bias: usize, wrapper: usize, suffix: usize) -> [usize; 3] { prefix; if bias == 0 { return { wrapper; make_array(first, second, third) }; } { suffix; make_array(third, second, first) } }";
        let module = Parser::new(source).parse_module::<1, 7>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<7>().unwrap();
        let resolver = FatCallResolver;
        let mut facts = RuntimeBodyFacts::EMPTY;
        let count = preanalyze_runtime_body_declarations::<_, 7, 64>(
            &function,
            &resolver,
            &body,
            "[usize; 3]",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();

        assert_eq!(count, 0);
        assert_eq!(facts.assignment_read_count, 10);
        for (fact, parameter) in facts.assignment_reads[..10]
            .iter()
            .zip([3, 4, 5, 0, 1, 2, 6, 2, 1, 0])
        {
            let fact = fact.unwrap();
            assert_eq!(fact.base, RuntimePlaceIdentity::Parameter(parameter));
            assert_eq!(fact.projections, RuntimePlaceProjections::EMPTY);
        }

        for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
            compile_x86_64_function::<_, 16384, 7, 64>(&function, &resolver, abi).unwrap();
        }
    }

    #[test]
    fn runtime_body_facts_preanalyze_range_derived_fat_reference_initializers() {
        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &[usize], start: usize, end: usize, left: usize) -> usize { let local = [10usize, 20usize, 30usize, 40usize]; let from_local: &[usize] = &local[start..end]; let from_input: &[usize] = &input[left..]; from_local.len() + from_input.len() }";
        let module = Parser::new(source).parse_module::<1, 8>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<8>().unwrap();
        let resolver = NoConstants;
        let mut facts = RuntimeBodyFacts::EMPTY;
        let count = preanalyze_runtime_body_declarations::<_, 8, 64>(
            &function,
            &resolver,
            &body,
            "usize",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();

        assert_eq!(count, 3);
        assert_eq!(facts.assignment_read_count, 5);
        for (index, (fact, identity)) in facts.assignment_reads[..5]
            .iter()
            .zip([
                RuntimePlaceIdentity::Parameter(1),
                RuntimePlaceIdentity::Parameter(2),
                RuntimePlaceIdentity::Local(RuntimeLocalId(0)),
                RuntimePlaceIdentity::Parameter(3),
                RuntimePlaceIdentity::Parameter(0),
            ])
            .enumerate()
        {
            let fact = fact.unwrap();
            assert_eq!(fact.base, identity);
            assert_eq!(
                fact.projections,
                if index == 2 {
                    RuntimePlaceProjections::single(RuntimePlaceProjection::Subslice)
                } else {
                    RuntimePlaceProjections::EMPTY
                }
            );
        }

        for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
            compile_x86_64_function::<_, 4096, 8, 64>(&function, &resolver, abi).unwrap();
        }
    }

    #[test]
    fn runtime_body_facts_preanalyze_conditional_wrapped_fat_reference_initializers() {
        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &[usize], choose: bool, prefix: usize, start: usize, end: usize, left: usize) -> usize { let local = [10usize, 20usize, 30usize, 40usize]; let selected: &[usize] = if choose { { prefix; &local[start..end] } } else { &input[left..] }; selected.len() }";
        let module = Parser::new(source).parse_module::<1, 8>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<8>().unwrap();
        let resolver = NoConstants;
        let mut facts = RuntimeBodyFacts::EMPTY;
        let count = preanalyze_runtime_body_declarations::<_, 8, 64>(
            &function,
            &resolver,
            &body,
            "usize",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();

        assert_eq!(count, 2);
        assert_eq!(facts.assignment_read_count, 7);
        for (index, (fact, identity)) in facts.assignment_reads[..7]
            .iter()
            .zip([
                RuntimePlaceIdentity::Parameter(1),
                RuntimePlaceIdentity::Parameter(2),
                RuntimePlaceIdentity::Parameter(3),
                RuntimePlaceIdentity::Parameter(4),
                RuntimePlaceIdentity::Local(RuntimeLocalId(0)),
                RuntimePlaceIdentity::Parameter(5),
                RuntimePlaceIdentity::Parameter(0),
            ])
            .enumerate()
        {
            let fact = fact.unwrap();
            assert_eq!(fact.base, identity);
            assert_eq!(
                fact.projections,
                if index == 4 {
                    RuntimePlaceProjections::single(RuntimePlaceProjection::Subslice)
                } else {
                    RuntimePlaceProjections::EMPTY
                }
            );
        }

        for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
            compile_x86_64_function::<_, 4096, 8, 64>(&function, &resolver, abi).unwrap();
        }
    }

    #[test]
    fn runtime_body_facts_retain_direct_subslice_index_borrows() {
        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &mut [u32; 4], start: usize, index: usize) -> u32 { let selected: &mut u32 = &mut input[start..][index]; *selected += 7; *selected }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &mut [u32], start: usize, index: usize) -> u32 { let selected: &mut u32 = &mut input[start..][index]; *selected += 7; *selected }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &mut [u32; 4], start: usize, end: usize, index: usize) -> u32 { let selected: &mut u32 = &mut input[start..end][index]; *selected += 7; *selected }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &mut [u32], start: usize, end: usize, index: usize) -> u32 { let selected: &mut u32 = &mut input[start..end][index]; *selected += 7; *selected }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &mut [u32; 4], start: usize, end: usize, index: usize) -> u32 { let selected: &mut u32 = &mut input[start..=end][index]; *selected += 7; *selected }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &mut [u32], start: usize, end: usize, index: usize) -> u32 { let selected: &mut u32 = &mut input[start..=end][index]; *selected += 7; *selected }",
        ] {
            let module = Parser::new(source).parse_module::<1, 5>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            let body = function.parse_body::<5>().unwrap();
            let resolver = NoConstants;
            let mut facts = RuntimeBodyFacts::EMPTY;
            preanalyze_runtime_body_declarations::<_, 5, 64>(
                &function,
                &resolver,
                &body,
                "u32",
                function.body_expression_span.start,
                &mut facts,
            )
            .unwrap();

            let mut nested = RuntimePlaceProjections::single(RuntimePlaceProjection::Subslice);
            nested.push(RuntimePlaceProjection::Index).unwrap();
            let matching = facts.assignment_reads[..facts.assignment_read_count]
                .iter()
                .flatten()
                .filter(|fact| {
                    fact.base == RuntimePlaceIdentity::Parameter(0) && fact.projections == nested
                })
                .count();
            assert_eq!(matching, 1);

            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                compile_x86_64_function::<_, 8192, 5, 64>(&function, &resolver, abi).unwrap();
            }
        }
    }

    #[test]
    fn runtime_body_facts_retain_two_ordered_subslices_before_index() {
        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &mut [u32], first: usize, second: usize, index: usize) -> u32 { let selected: &mut u32 = &mut input[first..][second..][index]; 0 }";
        let module = Parser::new(source).parse_module::<1, 5>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<5>().unwrap();
        let resolver = NoConstants;
        let mut facts = RuntimeBodyFacts::EMPTY;
        preanalyze_runtime_body_declarations::<_, 5, 64>(
            &function,
            &resolver,
            &body,
            "u32",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();

        let mut nested = RuntimePlaceProjections::single(RuntimePlaceProjection::Subslice);
        nested.push(RuntimePlaceProjection::Subslice).unwrap();
        nested.push(RuntimePlaceProjection::Index).unwrap();
        let expected = [
            (
                RuntimePlaceIdentity::Parameter(1),
                RuntimePlaceProjections::EMPTY,
            ),
            (
                RuntimePlaceIdentity::Parameter(2),
                RuntimePlaceProjections::EMPTY,
            ),
            (RuntimePlaceIdentity::Parameter(0), nested),
            (
                RuntimePlaceIdentity::Parameter(3),
                RuntimePlaceProjections::EMPTY,
            ),
        ];
        assert_eq!(facts.assignment_read_count, expected.len());
        for (fact, (base, projections)) in facts.assignment_reads[..expected.len()]
            .iter()
            .flatten()
            .zip(expected)
        {
            assert_eq!((fact.base, fact.projections), (base, projections));
        }

        for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
            compile_x86_64_function::<_, 8192, 5, 64>(&function, &resolver, abi).unwrap();
        }
    }

    #[test]
    fn runtime_body_facts_preanalyze_fat_reference_explicit_and_tail_returns() {
        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &[usize], choose: bool, start: usize, end: usize, left: usize) -> &[usize] { if choose { return &input[start..end]; } &input[left..] }";
        let module = Parser::new(source).parse_module::<1, 8>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<8>().unwrap();
        let resolver = NoConstants;
        let mut facts = RuntimeBodyFacts::EMPTY;
        let count = preanalyze_runtime_body_declarations::<_, 8, 64>(
            &function,
            &resolver,
            &body,
            "usize",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();

        assert_eq!(count, 0);
        assert_eq!(facts.assignment_read_count, 6);
        for (fact, identity) in facts.assignment_reads[..6].iter().zip([
            RuntimePlaceIdentity::Parameter(1),
            RuntimePlaceIdentity::Parameter(2),
            RuntimePlaceIdentity::Parameter(3),
            RuntimePlaceIdentity::Parameter(0),
            RuntimePlaceIdentity::Parameter(4),
            RuntimePlaceIdentity::Parameter(0),
        ]) {
            let fact = fact.unwrap();
            assert_eq!(fact.base, identity);
            assert_eq!(fact.projections, RuntimePlaceProjections::EMPTY);
        }

        for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
            compile_x86_64_function::<_, 4096, 8, 64>(&function, &resolver, abi).unwrap();
        }
    }

    #[test]
    fn runtime_body_facts_preanalyze_wrapped_fat_reference_returns() {
        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &[usize], choose: bool, alternate: bool, prefix: usize, suffix: usize, start: usize, end: usize, left: usize) -> &[usize] { if choose { return { prefix; if alternate { &input[start..end] } else { &input[left..] } }; } { suffix; &input[start..] } }";
        let module = Parser::new(source).parse_module::<1, 8>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<8>().unwrap();
        let resolver = NoConstants;
        let mut facts = RuntimeBodyFacts::EMPTY;
        let count = preanalyze_runtime_body_declarations::<_, 8, 64>(
            &function,
            &resolver,
            &body,
            "&[usize]",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();

        assert_eq!(count, 0);
        assert_eq!(facts.assignment_read_count, 11);
        for (fact, parameter) in facts.assignment_reads[..11]
            .iter()
            .zip([1, 3, 2, 5, 6, 0, 7, 0, 4, 5, 0])
        {
            let fact = fact.unwrap();
            assert_eq!(fact.base, RuntimePlaceIdentity::Parameter(parameter));
            assert_eq!(fact.projections, RuntimePlaceProjections::EMPTY);
        }

        for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
            compile_x86_64_function::<_, 8192, 8, 64>(&function, &resolver, abi).unwrap();
        }
    }

    #[test]
    fn runtime_body_facts_preanalyze_call_derived_fat_reference_returns() {
        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &[usize], choose_call: bool, start: usize, end: usize, bias: usize, prefix: usize) -> &[usize] { if choose_call { return choose(input, start, end, bias); } { prefix; choose(input, start, end, bias) } }";
        let module = Parser::new(source).parse_module::<1, 6>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<6>().unwrap();
        let resolver = FatCallResolver;
        let mut facts = RuntimeBodyFacts::EMPTY;
        let count = preanalyze_runtime_body_declarations::<_, 6, 64>(
            &function,
            &resolver,
            &body,
            "&[usize]",
            function.body_expression_span.start,
            &mut facts,
        )
        .unwrap();

        assert_eq!(count, 0);
        assert_eq!(facts.assignment_read_count, 10);
        for (fact, parameter) in facts.assignment_reads[..10]
            .iter()
            .zip([1, 0, 2, 3, 4, 5, 0, 2, 3, 4])
        {
            let fact = fact.unwrap();
            assert_eq!(fact.base, RuntimePlaceIdentity::Parameter(parameter));
            assert_eq!(fact.projections, RuntimePlaceProjections::EMPTY);
        }

        for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
            compile_x86_64_function::<_, 16384, 6, 64>(&function, &resolver, abi).unwrap();
        }
    }

    #[test]
    fn direct_dereference_read_retains_the_base_identity_and_projection() {
        let module = Parser::new("fn value(parameter: &u64) -> u64 { *parameter }")
            .parse_module::<1, 2>()
            .unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let resolver = NoConstants;
        let mut body_facts = RuntimeBodyFacts::EMPTY;
        body_facts
            .push_initialized_parameter(
                0,
                runtime_reference_type("&u64").unwrap(),
                Some(function.parameters()[0].unwrap().span),
            )
            .unwrap();
        let mut emitter = RuntimeEmitter::<_, 64, 2> {
            bytes: [0; 64],
            length: 0,
            readonly_data: [0; MAX_X86_64_READONLY_DATA_BYTES],
            readonly_data_length: 0,
            readonly_relocations: [X86_64ReadonlyDataRelocation {
                offset: 0,
                data_offset: 0,
            }; MAX_X86_64_READONLY_RELOCATIONS],
            readonly_relocation_count: 0,
            trap_patches: [0; 64],
            trap_count: 0,
            function: &function,
            resolver: &resolver,
            abi: X86_64Abi::Windows,
            width: runtime_width("u64").unwrap(),
            overflow_checks: true,
            uses_sret: false,
            saved_parameter_slots: 0,
            locals: [None; 2],
            saved_locals: 0,
            body_facts: &mut body_facts,
            preanalyzed_local_count: 0,
            preanalyzed_local_cursor: 0,
            preanalyzed_assignment_access_cursor: 0,
            preanalyzed_assignment_read_cursor: 0,
            evaluation_depth: 0,
            runtime_call_depth: 0,
            runtime_call_names: [None; 8],
            runtime_call_local_floor: None,
        };
        let tree = function.parse_body_expression::<4>().unwrap();
        emitter.emit_expression(&tree, tree.root(), 0).unwrap();

        assert_eq!(emitter.body_facts.access_count, 1);
        let fact = emitter.body_facts.accesses[0].unwrap();
        assert_eq!(fact.base, RuntimePlaceIdentity::Parameter(0));
        assert_eq!(fact.access, RuntimePlaceAccess::Read);
        assert_eq!(
            fact.projections,
            RuntimePlaceProjections::single(RuntimePlaceProjection::Dereference)
        );
        assert_eq!(fact.span, Span { start: 1, end: 10 });
        emitter.validate_runtime_place_facts().unwrap();
    }

    #[test]
    fn runtime_read_place_discovery_orders_nested_projections_and_is_bounded() {
        let module = Parser::new("fn value(values: &[(u64,)]) -> u64 { (*values)[1].0 }")
            .parse_module::<1, 2>()
            .unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let tree = function.parse_body_expression::<16>().unwrap();
        let place = discover_runtime_read_place(&tree, tree.root())
            .unwrap()
            .unwrap();
        assert_eq!(place.name, "values");
        assert_eq!(place.span, Span { start: 2, end: 8 });
        let mut expected = RuntimePlaceProjections::EMPTY;
        expected.push(RuntimePlaceProjection::Dereference).unwrap();
        expected.push(RuntimePlaceProjection::Index).unwrap();
        expected
            .push(RuntimePlaceProjection::TupleField(0))
            .unwrap();
        assert_eq!(place.projections, expected);

        let overflow = Parser::new("fn value(value: &&&&&u64) -> u64 { *****value }")
            .parse_module::<1, 2>()
            .unwrap();
        let Some(Item::Function(function)) = overflow.items()[0] else {
            panic!("expected function")
        };
        let tree = function.parse_body_expression::<16>().unwrap();
        assert_eq!(
            discover_runtime_read_place(&tree, tree.root()).unwrap_err(),
            CodegenErrorKind::TooManyRuntimePlaceProjections
        );
    }

    #[test]
    fn bounded_callee_projected_origins_validate_generations_and_joins() {
        let mut elements = [None; crate::expression::MAX_TUPLE_ELEMENTS];
        elements[0] = Some(RuntimeTupleElementType::Reference {
            pointee: RuntimeArrayElementType::Integer(Some(crate::IntegerType::U16)),
            mutable: true,
        });
        elements[1] = elements[0];
        let tuple = RuntimeExpressionType::Tuple {
            elements,
            element_count: 2,
        };
        let first = RuntimePlaceProjections::single(RuntimePlaceProjection::TupleField(0));
        let second = RuntimePlaceProjections::single(RuntimePlaceProjection::TupleField(1));
        let invalid = RuntimePlaceProjections::single(RuntimePlaceProjection::TupleField(2));

        let mut state = RuntimeCalleeProjectedOrigins::<1>::EMPTY;
        assert_eq!(state.set(0, tuple, RuntimePlaceProjections::EMPTY, 2), None);
        assert_eq!(state.set(0, tuple, invalid, 2), None);
        state.set(0, tuple, first, 2).unwrap();
        assert_eq!(state.get(0, first).unwrap().generation, 0);
        state.set(0, tuple, first, 3).unwrap();
        assert_eq!(state.get(0, first).unwrap().origin, 3);
        assert_eq!(state.get(0, first).unwrap().generation, 1);
        assert_eq!(state.set(0, tuple, second, 4), None);

        let mut same = RuntimeCalleeProjectedOrigins::<1>::EMPTY;
        same.set(0, tuple, first, 3).unwrap();
        let joined = state.intersect(same);
        assert_eq!(joined.count, 1);
        assert_eq!(joined.get(0, first).unwrap().origin, 3);
        assert_eq!(joined.get(0, first).unwrap().generation, 1);

        let mut different = RuntimeCalleeProjectedOrigins::<1>::EMPTY;
        different.set(0, tuple, first, 4).unwrap();
        assert_eq!(state.intersect(different).count, 0);

        let mut scoped = RuntimeCalleeProjectedOrigins::<2>::EMPTY;
        scoped.set(0, tuple, first, 2).unwrap();
        scoped.set(1, tuple, second, 3).unwrap();
        let retained = scoped.retain_local_prefix(1);
        assert_eq!(retained.count, 1);
        assert_eq!(retained.get(0, first).unwrap().origin, 2);
        assert_eq!(retained.get(1, second), None);
    }

    #[test]
    fn emits_a_windows_and_system_v_compatible_integer_return() {
        let source = "const PAGE: u64 = 4096; #[unsafe(no_mangle)] pub extern \"C\" fn arena_bytes() -> u64 { PAGE * 8 + 16 }";
        let module = Parser::new(source).parse_module::<4, 2>().unwrap();
        let constants = analyze_constants::<4, 16, 4, 2>(&module, TargetLayout::X86_64).unwrap();
        let Some(Item::Function(function)) = module.items()[1] else {
            panic!("expected function")
        };
        let code = compile_x86_64_constant_function::<_, 11, 2, 16>(&function, &constants).unwrap();
        assert_eq!(
            code.bytes(),
            &[
                0x48, 0xb8, 0x10, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc3
            ]
        );
    }

    #[test]
    fn emits_typed_negative_module_constants() {
        let source = "const OFFSET: i32 = -2; #[unsafe(no_mangle)] pub extern \"C\" fn value(input: i32) -> i32 { input + OFFSET }";
        let module = Parser::new(source).parse_module::<4, 2>().unwrap();
        let constants = analyze_constants::<4, 16, 4, 2>(&module, TargetLayout::X86_64).unwrap();
        let Some(Item::Function(function)) = module.items()[1] else {
            panic!("expected function")
        };
        for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
            let code =
                compile_x86_64_function::<_, 128, 2, 16>(&function, &constants, abi).unwrap();
            assert!(code.bytes().windows(10).any(|bytes| {
                bytes == [0x48, 0xb8, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
            }));
        }
    }

    #[test]
    fn reports_source_relative_expression_errors() {
        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn broken() -> u64 { 1 + }";
        let module = Parser::new(source).parse_module::<2, 2>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let error =
            compile_x86_64_constant_function::<_, 16, 2, 8>(&function, &NoConstants).unwrap_err();
        assert_eq!(
            error.kind,
            CodegenErrorKind::Expression(ExpressionErrorKind::ExpectedExpression)
        );
        assert_eq!(error.span.start, function.body_expression_span.end);
    }

    #[test]
    fn rejects_unsupported_signatures_and_overflow() {
        let parameters = Parser::new(
            "#[unsafe(no_mangle)] pub extern \"C\" fn identity(value: u64) -> u64 { value }",
        )
        .parse_module::<2, 2>()
        .unwrap();
        let Some(Item::Function(function)) = parameters.items()[0] else {
            panic!("expected function")
        };
        let error =
            compile_x86_64_constant_function::<_, 16, 2, 8>(&function, &NoConstants).unwrap_err();
        assert_eq!(error.kind, CodegenErrorKind::ParametersUnsupported);

        let overflow = Parser::new("#[unsafe(no_mangle)] pub extern \"C\" fn byte() -> u8 { 256 }")
            .parse_module::<2, 2>()
            .unwrap();
        let Some(Item::Function(function)) = overflow.items()[0] else {
            panic!("expected function")
        };
        let error =
            compile_x86_64_constant_function::<_, 16, 2, 8>(&function, &NoConstants).unwrap_err();
        assert_eq!(error.kind, CodegenErrorKind::ValueOutOfRange);
    }

    #[test]
    fn enforces_output_capacity_without_partial_artifacts() {
        let module = Parser::new("#[unsafe(no_mangle)] pub extern \"C\" fn answer() -> u64 { 42 }")
            .parse_module::<2, 2>()
            .unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let error =
            compile_x86_64_constant_function::<_, 10, 2, 8>(&function, &NoConstants).unwrap_err();
        assert_eq!(error.kind, CodegenErrorKind::OutputTooSmall);
    }

    #[test]
    fn refuses_to_export_an_unstable_rust_abi_symbol() {
        let module = Parser::new("pub fn answer() -> u64 { 42 }")
            .parse_module::<2, 2>()
            .unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let error =
            compile_x86_64_constant_function::<_, 16, 2, 8>(&function, &NoConstants).unwrap_err();
        assert_eq!(error.kind, CodegenErrorKind::StableExportRequired);
    }

    #[test]
    fn emits_abi_specific_parameter_returns() {
        let module = Parser::new(
            "#[unsafe(no_mangle)] pub extern \"C\" fn identity(value: u64) -> u64 { value }",
        )
        .parse_module::<2, 2>()
        .unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let windows =
            compile_x86_64_function::<_, 16, 2, 8>(&function, &NoConstants, X86_64Abi::Windows)
                .unwrap();
        assert_eq!(
            windows.bytes(),
            &[0x51, 0x48, 0x8b, 0x44, 0x24, 0, 0x48, 0x83, 0xc4, 8, 0xc3]
        );
        let system_v =
            compile_x86_64_function::<_, 16, 2, 8>(&function, &NoConstants, X86_64Abi::SystemV)
                .unwrap();
        assert_eq!(system_v.bytes()[0], 0x57);
        assert_eq!(&system_v.bytes()[1..], &windows.bytes()[1..]);
    }

    #[test]
    fn emits_one_word_mrml_v1_exports_through_the_planned_locations() {
        let module = Parser::new(
            "#[mrml_abi::export(version = 1)] pub fn identity(value: u64) -> u64 { value }",
        )
        .parse_module::<2, 2>()
        .unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let windows =
            compile_x86_64_function::<_, 16, 2, 8>(&function, &NoConstants, X86_64Abi::Windows)
                .unwrap();
        let system_v =
            compile_x86_64_function::<_, 16, 2, 8>(&function, &NoConstants, X86_64Abi::SystemV)
                .unwrap();
        assert_eq!(windows.bytes()[0], 0x51);
        assert_eq!(system_v.bytes()[0], 0x57);
        assert_eq!(&windows.bytes()[1..], &system_v.bytes()[1..]);
    }

    #[test]
    fn mrml_v1_codegen_narrows_two_word_integer_parameters() {
        let source =
            "#[mrml_abi::export(version = 1)] pub fn first(input: u128) -> u8 { input as u8 }";
        let module = Parser::new(source).parse_module::<2, 2>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let system_v = compile_x86_64_function::<_, 128, 2, 16>(
            &function,
            &NoConstants,
            X86_64Abi::SystemV,
        )
        .unwrap();
        let windows = compile_x86_64_function::<_, 128, 2, 16>(
            &function,
            &NoConstants,
            X86_64Abi::Windows,
        )
        .unwrap();
        assert_eq!(&system_v.bytes()[..2], &[0x57, 0x56]);
        assert_eq!(&windows.bytes()[..2], &[0x51, 0x52]);
    }

    #[test]
    fn runtime_stack_model_reserves_two_words_for_128_bit_integers() {
        for integer in [crate::IntegerType::U128, crate::IntegerType::I128] {
            assert_eq!(
                runtime_type_stack_slots(RuntimeExpressionType::Integer(Some(integer))),
                2
            );
        }
        for integer in [crate::IntegerType::U64, crate::IntegerType::I64] {
            assert_eq!(
                runtime_type_stack_slots(RuntimeExpressionType::Integer(Some(integer))),
                1
            );
        }
        assert_eq!(runtime_parameter_stack_slots("u128"), 2);
        assert_eq!(runtime_parameter_stack_slots("i128"), 2);
        assert_eq!(runtime_parameter_stack_slots("u64"), 1);
        assert_eq!(runtime_parameter_stack_slots("&[u8]"), 2);
    }

    #[test]
    fn runtime_integer_layout_preserves_exact_128_bit_bounds() {
        assert_eq!(
            runtime_integer_layout("u128"),
            Some(RuntimeIntegerLayout {
                bits: 128,
                signed: false,
                minimum: 0,
                maximum: u128::MAX,
                words: 2,
            })
        );
        assert_eq!(
            runtime_integer_layout("i128"),
            Some(RuntimeIntegerLayout {
                bits: 128,
                signed: true,
                minimum: i128::MIN,
                maximum: i128::MAX as u128,
                words: 2,
            })
        );
        assert_eq!(runtime_width("u128"), None);
        assert_eq!(runtime_width("i128"), None);
    }

    #[test]
    fn runtime_integer_literal_bounds_cover_both_128_bit_extremes() {
        let unsigned = runtime_integer_layout("u128").unwrap();
        assert!(runtime_integer_literal_fits(unsigned, u128::MAX, false));
        assert!(!runtime_integer_literal_fits(unsigned, 1, true));

        let signed = runtime_integer_layout("i128").unwrap();
        assert!(runtime_integer_literal_fits(
            signed,
            i128::MAX as u128,
            false
        ));
        assert!(runtime_integer_literal_fits(
            signed,
            i128::MIN.unsigned_abs(),
            true
        ));
        assert!(!runtime_integer_literal_fits(
            signed,
            i128::MIN.unsigned_abs(),
            false
        ));
    }

    #[test]
    fn mrml_v1_codegen_returns_two_word_integer_parameters() {
        let source =
            "#[mrml_abi::export(version = 1)] pub fn value(input: u128) -> u128 { input }";
        let module = Parser::new(source).parse_module::<2, 2>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        for abi in [X86_64Abi::SystemV, X86_64Abi::Windows] {
            let code = compile_x86_64_function::<_, 256, 2, 16>(
                &function,
                &NoConstants,
                abi,
            )
            .unwrap();
            assert!(code.bytes().windows(3).any(|bytes| bytes == [0x48, 0x89, 0xc2]));
        }
    }

    #[test]
    fn mrml_v1_codegen_preserves_two_word_integer_cast_bits() {
        for source in [
            "#[mrml_abi::export(version = 1)] pub fn value(input: u128) -> i128 { input as i128 }",
            "#[mrml_abi::export(version = 1)] pub fn value(input: i128) -> u128 { input as u128 }",
        ] {
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::SystemV, X86_64Abi::Windows] {
                compile_x86_64_function::<_, 256, 2, 16>(&function, &NoConstants, abi).unwrap();
            }
        }
    }

    #[test]
    fn mrml_v1_codegen_inverts_both_two_word_integer_halves() {
        for source in [
            "#[mrml_abi::export(version = 1)] pub fn value(input: u128) -> u128 { !input }",
            "#[mrml_abi::export(version = 1)] pub fn value(input: i128) -> i128 { !input }",
        ] {
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::SystemV, X86_64Abi::Windows] {
                let code =
                    compile_x86_64_function::<_, 256, 2, 16>(&function, &NoConstants, abi)
                        .unwrap();
                assert!(code.bytes().windows(6).any(|bytes| {
                    bytes == [0x48, 0xf7, 0xd0, 0x48, 0xf7, 0xd2]
                }));
            }
        }
    }

    #[test]
    fn mrml_v1_codegen_checked_negates_two_word_signed_integers() {
        let source =
            "#[mrml_abi::export(version = 1)] pub fn value(input: i128) -> i128 { -input }";
        let module = Parser::new(source).parse_module::<2, 2>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        for abi in [X86_64Abi::SystemV, X86_64Abi::Windows] {
            let code =
                compile_x86_64_function::<_, 256, 2, 16>(&function, &NoConstants, abi).unwrap();
            assert!(code.bytes().windows(10).any(|bytes| {
                bytes
                    == [
                        0x48, 0xf7, 0xd8, 0x48, 0x83, 0xd2, 0x00, 0x48, 0xf7, 0xda,
                    ]
            }));
            assert!(code.bytes().ends_with(&[0x0f, 0x0b]));
        }
    }

    #[test]
    fn mrml_v1_codegen_combines_both_two_word_bitwise_halves() {
        for source in [
            "#[mrml_abi::export(version = 1)] pub fn value(input: u128) -> u128 { input & 1512366075204170947332355369683137040 }",
            "#[mrml_abi::export(version = 1)] pub fn value(input: u128) -> u128 { input | 1512366075204170947332355369683137040 }",
            "#[mrml_abi::export(version = 1)] pub fn value(input: u128) -> u128 { input ^ 1512366075204170947332355369683137040 }",
        ] {
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::SystemV, X86_64Abi::Windows] {
                compile_x86_64_function::<_, 320, 2, 16>(&function, &NoConstants, abi).unwrap();
            }
        }
    }

    #[test]
    fn mrml_v1_codegen_checked_adds_two_word_integers() {
        for source in [
            "#[mrml_abi::export(version = 1)] pub fn value(input: u128) -> u128 { input + 17 }",
            "#[mrml_abi::export(version = 1)] pub fn value(input: i128) -> i128 { input + 17 }",
        ] {
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::SystemV, X86_64Abi::Windows] {
                let code =
                    compile_x86_64_function::<_, 320, 2, 16>(&function, &NoConstants, abi)
                        .unwrap();
                assert!(code
                    .bytes()
                    .windows(6)
                    .any(|bytes| bytes == [0x4c, 0x01, 0xc0, 0x48, 0x11, 0xca]));
                assert!(code.bytes().ends_with(&[0x0f, 0x0b]));
            }
        }
    }

    #[test]
    fn mrml_v1_codegen_checked_subtracts_two_word_integers() {
        for source in [
            "#[mrml_abi::export(version = 1)] pub fn value(input: u128) -> u128 { input - 17 }",
            "#[mrml_abi::export(version = 1)] pub fn value(input: i128) -> i128 { input - 17 }",
        ] {
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::SystemV, X86_64Abi::Windows] {
                let code =
                    compile_x86_64_function::<_, 320, 2, 16>(&function, &NoConstants, abi)
                        .unwrap();
                assert!(code
                    .bytes()
                    .windows(6)
                    .any(|bytes| bytes == [0x49, 0x29, 0xc0, 0x48, 0x19, 0xd1]));
                assert!(code.bytes().ends_with(&[0x0f, 0x0b]));
            }
        }
    }

    #[test]
    fn mrml_v1_codegen_compares_two_word_integer_equality() {
        for source in [
            "#[mrml_abi::export(version = 1)] pub fn value(input: u128) -> u64 { (input == 1512366075204170947332355369683137040) as u64 }",
            "#[mrml_abi::export(version = 1)] pub fn value(input: i128) -> u64 { (input != -1512366075204170947332355369683137040) as u64 }",
        ] {
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::SystemV, X86_64Abi::Windows] {
                let code =
                    compile_x86_64_function::<_, 320, 2, 16>(&function, &NoConstants, abi)
                        .unwrap();
                assert!(code
                    .bytes()
                    .windows(9)
                    .any(|bytes| bytes == [0x4c, 0x31, 0xc0, 0x48, 0x31, 0xca, 0x48, 0x09, 0xd0]));
            }
        }
    }

    #[test]
    fn mrml_v1_codegen_widens_one_word_integers_for_two_word_returns() {
        for source in [
            "#[mrml_abi::export(version = 1)] pub fn value(input: u8) -> u128 { input as u128 }",
            "#[mrml_abi::export(version = 1)] pub fn value(input: u8) -> i128 { input as i128 }",
            "#[mrml_abi::export(version = 1)] pub fn value(input: u16) -> u128 { input as u128 }",
            "#[mrml_abi::export(version = 1)] pub fn value(input: u16) -> i128 { input as i128 }",
            "#[mrml_abi::export(version = 1)] pub fn value(input: u32) -> u128 { input as u128 }",
            "#[mrml_abi::export(version = 1)] pub fn value(input: u32) -> i128 { input as i128 }",
            "#[mrml_abi::export(version = 1)] pub fn value(input: u64) -> u128 { input as u128 }",
            "#[mrml_abi::export(version = 1)] pub fn value(input: u64) -> i128 { input as i128 }",
            "#[mrml_abi::export(version = 1)] pub fn value(input: i8) -> u128 { input as u128 }",
            "#[mrml_abi::export(version = 1)] pub fn value(input: i8) -> i128 { input as i128 }",
            "#[mrml_abi::export(version = 1)] pub fn value(input: i16) -> u128 { input as u128 }",
            "#[mrml_abi::export(version = 1)] pub fn value(input: i16) -> i128 { input as i128 }",
            "#[mrml_abi::export(version = 1)] pub fn value(input: i32) -> u128 { input as u128 }",
            "#[mrml_abi::export(version = 1)] pub fn value(input: i32) -> i128 { input as i128 }",
            "#[mrml_abi::export(version = 1)] pub fn value(input: i64) -> u128 { input as u128 }",
            "#[mrml_abi::export(version = 1)] pub fn value(input: i64) -> i128 { input as i128 }",
        ] {
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::SystemV, X86_64Abi::Windows] {
                compile_x86_64_function::<_, 256, 2, 16>(&function, &NoConstants, abi).unwrap();
            }
        }
    }

    #[test]
    fn mrml_v1_codegen_returns_bounded_two_word_integer_literals() {
        for source in [
            "#[mrml_abi::export(version = 1)] pub fn value() -> u128 { 340282366920938463463374607431768211455 }",
            "#[mrml_abi::export(version = 1)] pub fn value() -> i128 { 170141183460469231731687303715884105727 }",
            "#[mrml_abi::export(version = 1)] pub fn value() -> i128 { -170141183460469231731687303715884105728 }",
        ] {
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::SystemV, X86_64Abi::Windows] {
                compile_x86_64_function::<_, 256, 2, 16>(&function, &NoConstants, abi).unwrap();
            }
        }
    }

    #[test]
    fn mrml_v1_codegen_rejects_out_of_range_two_word_integer_literals() {
        for source in [
            "#[mrml_abi::export(version = 1)] pub fn value() -> i128 { 170141183460469231731687303715884105728 }",
            "#[mrml_abi::export(version = 1)] pub fn value() -> i128 { -170141183460469231731687303715884105729 }",
        ] {
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            let error = compile_x86_64_function::<_, 256, 2, 16>(
                &function,
                &NoConstants,
                X86_64Abi::SystemV,
            )
            .unwrap_err();
            assert_eq!(error.kind, CodegenErrorKind::ValueOutOfRange);
        }
    }

    #[test]
    fn mrml_v1_codegen_rejects_other_wide_returns() {
        let source = "#[mrml_abi::export(version = 1)] pub fn value(input: u128) -> u128 { input * 2 }";
        let module = Parser::new(source).parse_module::<2, 2>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let error = compile_x86_64_function::<_, 256, 2, 16>(
            &function,
            &NoConstants,
            X86_64Abi::SystemV,
        )
        .unwrap_err();
        assert_eq!(error.kind, CodegenErrorKind::RuntimeExpressionUnsupported);
    }

    #[test]
    fn mrml_v1_codegen_rejects_zero_word_parameters_at_the_type_span() {
        let source = "#[mrml_abi::export(version = 1)] pub fn consume(input: ()) { }";
        let module = Parser::new(source).parse_module::<2, 2>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let error = compile_x86_64_function::<_, 128, 2, 8>(
            &function,
            &NoConstants,
            X86_64Abi::Windows,
        )
        .unwrap_err();
        assert_eq!(error.kind, CodegenErrorKind::MrmlV1MultiwordValueUnsupported);
        assert_eq!(&source[error.span.start..error.span.end], "()");
    }

    #[test]
    fn saves_and_reads_stack_passed_parameters_for_both_abis() {
        let windows_module = Parser::new(
            "#[unsafe(no_mangle)] pub extern \"C\" fn fifth(a: u64, b: u64, c: u64, d: u64, value: u64) -> u64 { value }",
        )
        .parse_module::<2, 8>()
        .unwrap();
        let Some(Item::Function(windows_function)) = windows_module.items()[0] else {
            panic!("expected function")
        };
        let windows = compile_x86_64_function::<_, 96, 8, 8>(
            &windows_function,
            &NoConstants,
            X86_64Abi::Windows,
        )
        .unwrap();
        assert!(
            windows
                .bytes()
                .windows(6)
                .any(|bytes| bytes == [0x48, 0x8b, 0x44, 0x24, 72, 0x50])
        );

        let system_v_module = Parser::new(
            "#[unsafe(no_mangle)] pub extern \"C\" fn seventh(a: u64, b: u64, c: u64, d: u64, e: u64, f: u64, value: u64) -> u64 { value }",
        )
        .parse_module::<2, 8>()
        .unwrap();
        let Some(Item::Function(system_v_function)) = system_v_module.items()[0] else {
            panic!("expected function")
        };
        let system_v = compile_x86_64_function::<_, 128, 8, 8>(
            &system_v_function,
            &NoConstants,
            X86_64Abi::SystemV,
        )
        .unwrap();
        assert!(
            system_v
                .bytes()
                .windows(6)
                .any(|bytes| bytes == [0x48, 0x8b, 0x44, 0x24, 56, 0x50])
        );
    }

    #[test]
    fn uses_wide_displacements_for_deep_array_stack_slots() {
        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn deep(values: [u64; 8], after: u64) -> u64 { let copied = values; copied[7] + values[0] + after }";
        let module = Parser::new(source).parse_module::<2, 4>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
            let code =
                compile_x86_64_function::<_, 2048, 4, 64>(&function, &NoConstants, abi).unwrap();
            assert!(
                code.bytes()
                    .windows(4)
                    .any(|bytes| bytes == [0x48, 0x8b, 0x84, 0x24])
            );
        }

        let packed_source = "#[unsafe(no_mangle)] pub extern \"C\" fn packed(values: [u8; 4], after: u8) -> u8 { values[0] + after }";
        let packed_module = Parser::new(packed_source).parse_module::<2, 4>().unwrap();
        let Some(Item::Function(packed_function)) = packed_module.items()[0] else {
            panic!("expected function")
        };
        for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
            assert!(
                compile_x86_64_function::<_, 512, 4, 32>(&packed_function, &NoConstants, abi,)
                    .is_ok()
            );
        }
    }

    #[test]
    fn bounds_abi_parameters_and_uses_wide_stack_cleanup() {
        let sixteen = Parser::new(
            "#[unsafe(no_mangle)] pub extern \"C\" fn last(a: u64, b: u64, c: u64, d: u64, e: u64, f: u64, g: u64, h: u64, i: u64, j: u64, k: u64, l: u64, m: u64, n: u64, o: u64, value: u64) -> u64 { value }",
        )
        .parse_module::<2, 17>()
        .unwrap();
        let Some(Item::Function(function)) = sixteen.items()[0] else {
            panic!("expected function")
        };
        let code =
            compile_x86_64_function::<_, 256, 17, 8>(&function, &NoConstants, X86_64Abi::Windows)
                .unwrap();
        assert!(
            code.bytes()
                .windows(7)
                .any(|bytes| bytes == [0x48, 0x81, 0xc4, 128, 0, 0, 0])
        );

        let seventeen = Parser::new(
            "#[unsafe(no_mangle)] pub extern \"C\" fn excess(a: u64, b: u64, c: u64, d: u64, e: u64, f: u64, g: u64, h: u64, i: u64, j: u64, k: u64, l: u64, m: u64, n: u64, o: u64, p: u64, value: u64) -> u64 { value }",
        )
        .parse_module::<2, 17>()
        .unwrap();
        let Some(Item::Function(function)) = seventeen.items()[0] else {
            panic!("expected function")
        };
        let error =
            compile_x86_64_function::<_, 256, 17, 8>(&function, &NoConstants, X86_64Abi::Windows)
                .unwrap_err();
        assert_eq!(error.kind, CodegenErrorKind::TooManyAbiParameters);
    }

    #[test]
    fn emits_checked_runtime_arithmetic_and_a_shared_trap() {
        let module = Parser::new(
            "#[unsafe(no_mangle)] pub extern \"C\" fn increment(value: u64) -> u64 { value + 1 }",
        )
        .parse_module::<2, 2>()
        .unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let code =
            compile_x86_64_function::<_, 64, 2, 8>(&function, &NoConstants, X86_64Abi::SystemV)
                .unwrap();
        assert!(
            code.bytes()
                .windows(3)
                .any(|bytes| bytes == [0x48, 0x01, 0xc8])
        );
        assert!(code.bytes().windows(2).any(|bytes| bytes == [0x0f, 0x82]));
        assert_eq!(&code.bytes()[code.len() - 2..], &[0x0f, 0x0b]);
    }

    #[test]
    fn emits_width_normalization_and_narrow_overflow_checks() {
        let module = Parser::new(
            "#[unsafe(no_mangle)] pub extern \"C\" fn increment(value: u8) -> u8 { value + 1 }",
        )
        .parse_module::<2, 2>()
        .unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let code =
            compile_x86_64_function::<_, 96, 2, 8>(&function, &NoConstants, X86_64Abi::Windows)
                .unwrap();
        assert!(
            code.bytes()
                .windows(3)
                .any(|bytes| bytes == [0x0f, 0xb6, 0xc0])
        );
        assert!(
            code.bytes()
                .windows(8)
                .any(|bytes| bytes == u64::from(u8::MAX).to_le_bytes())
        );
        assert!(code.bytes().windows(2).any(|bytes| bytes == [0x0f, 0x87]));

        let wrapping = compile_x86_64_function_with_options::<_, 96, 2, 8>(
            &function,
            &NoConstants,
            X86_64Abi::Windows,
            CodegenOptions::WRAPPING,
        )
        .unwrap();
        assert!(
            !wrapping
                .bytes()
                .windows(2)
                .any(|bytes| bytes == [0x0f, 0x82])
        );
        assert!(
            !wrapping
                .bytes()
                .windows(2)
                .any(|bytes| bytes == [0x0f, 0x87])
        );
        assert_eq!(wrapping.bytes()[wrapping.len() - 1], 0xc3);
    }

    #[test]
    fn types_unsigned_comparisons_as_bool() {
        let module = Parser::new(
            "#[unsafe(no_mangle)] pub extern \"C\" fn less(left: u8, right: u8) -> bool { left < right }",
        )
        .parse_module::<2, 2>()
        .unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let code =
            compile_x86_64_function::<_, 96, 2, 8>(&function, &NoConstants, X86_64Abi::Windows)
                .unwrap();
        assert!(
            code.bytes()
                .windows(3)
                .any(|bytes| bytes == [0x0f, 0x92, 0xc0])
        );

        let invalid = Parser::new(
            "#[unsafe(no_mangle)] pub extern \"C\" fn less(left: u8, right: u8) -> u8 { left < right }",
        )
        .parse_module::<2, 2>()
        .unwrap();
        let Some(Item::Function(function)) = invalid.items()[0] else {
            panic!("expected function")
        };
        let error =
            compile_x86_64_function::<_, 96, 2, 8>(&function, &NoConstants, X86_64Abi::Windows)
                .unwrap_err();
        assert_eq!(error.kind, CodegenErrorKind::RuntimeTypeMismatch);
    }

    #[test]
    fn emits_signed_division_negation_and_comparisons() {
        let module = Parser::new(
            "#[unsafe(no_mangle)] pub extern \"C\" fn quotient(left: i8, right: i8) -> i8 { -left / right }",
        )
        .parse_module::<2, 2>()
        .unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let code =
            compile_x86_64_function::<_, 256, 2, 16>(&function, &NoConstants, X86_64Abi::Windows)
                .unwrap();
        assert!(
            code.bytes()
                .windows(4)
                .any(|bytes| bytes == [0x48, 0x0f, 0xbe, 0xc0])
        );
        assert!(
            code.bytes()
                .windows(3)
                .any(|bytes| bytes == [0x48, 0xf7, 0xf9])
        );
        assert!(
            code.bytes()
                .windows(3)
                .any(|bytes| bytes == [0x48, 0xf7, 0xd8])
        );

        let comparison = Parser::new(
            "#[unsafe(no_mangle)] pub extern \"C\" fn less(left: i32, right: i32) -> bool { left < right }",
        )
        .parse_module::<2, 2>()
        .unwrap();
        let Some(Item::Function(function)) = comparison.items()[0] else {
            panic!("expected function")
        };
        let code =
            compile_x86_64_function::<_, 128, 2, 8>(&function, &NoConstants, X86_64Abi::SystemV)
                .unwrap();
        assert!(
            code.bytes()
                .windows(3)
                .any(|bytes| bytes == [0x0f, 0x9c, 0xc0])
        );

        let minimum =
            Parser::new("#[unsafe(no_mangle)] pub extern \"C\" fn minimum() -> i8 { -128i8 }")
                .parse_module::<2, 2>()
                .unwrap();
        let Some(Item::Function(function)) = minimum.items()[0] else {
            panic!("expected function")
        };
        let code =
            compile_x86_64_function::<_, 64, 2, 8>(&function, &NoConstants, X86_64Abi::Windows)
                .unwrap();
        assert_eq!(&code.bytes()[2..10], &(-128i64 as u64).to_le_bytes());
    }

    #[test]
    fn emits_typed_boolean_not_and_short_circuit_branches() {
        let module = Parser::new(
            "#[unsafe(no_mangle)] pub extern \"C\" fn logic(left: bool, right: bool) -> bool { left && !right }",
        )
        .parse_module::<2, 2>()
        .unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let code =
            compile_x86_64_function::<_, 128, 2, 16>(&function, &NoConstants, X86_64Abi::Windows)
                .unwrap();
        assert!(code.bytes().windows(2).any(|bytes| bytes == [0x0f, 0x84]));
        assert!(
            code.bytes()
                .windows(3)
                .any(|bytes| bytes == [0x0f, 0x94, 0xc0])
        );

        let invalid = Parser::new(
            "#[unsafe(no_mangle)] pub extern \"C\" fn logic(left: u8, right: u8) -> bool { left && right }",
        )
        .parse_module::<2, 2>()
        .unwrap();
        let Some(Item::Function(function)) = invalid.items()[0] else {
            panic!("expected function")
        };
        let error =
            compile_x86_64_function::<_, 128, 2, 16>(&function, &NoConstants, X86_64Abi::Windows)
                .unwrap_err();
        assert_eq!(error.kind, CodegenErrorKind::RuntimeTypeMismatch);

        let literals = Parser::new(
            "#[unsafe(no_mangle)] pub extern \"C\" fn constant_guard() -> bool { true || (1 / 0 > 0) }",
        )
        .parse_module::<2, 2>()
        .unwrap();
        let Some(Item::Function(function)) = literals.items()[0] else {
            panic!("expected function")
        };
        let code =
            compile_x86_64_function::<_, 160, 2, 16>(&function, &NoConstants, X86_64Abi::SystemV)
                .unwrap();
        assert!(code.bytes().windows(2).any(|bytes| bytes == [0x0f, 0x85]));
    }

    #[test]
    fn emits_integer_cast_normalization_for_shift_distances() {
        let module = Parser::new(
            "#[unsafe(no_mangle)] pub extern \"C\" fn shifted(value: u8, distance: u8) -> u8 { value >> distance as usize }",
        )
        .parse_module::<2, 2>()
        .unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let code =
            compile_x86_64_function::<_, 128, 2, 16>(&function, &NoConstants, X86_64Abi::SystemV)
                .unwrap();
        assert!(
            code.bytes()
                .windows(3)
                .any(|bytes| bytes == [0x48, 0xd3, 0xe8])
        );
    }

    #[test]
    fn rejects_cast_results_that_do_not_match_the_return_type() {
        let module =
            Parser::new("#[unsafe(no_mangle)] pub extern \"C\" fn mismatch() -> u8 { 1 as u64 }")
                .parse_module::<2, 1>()
                .unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let error =
            compile_x86_64_function::<_, 64, 1, 8>(&function, &NoConstants, X86_64Abi::Windows)
                .unwrap_err();
        assert_eq!(error.kind, CodegenErrorKind::RuntimeTypeMismatch);
    }

    #[test]
    fn folds_typed_locals_in_declaration_order() {
        let module = Parser::new(
            "#[unsafe(no_mangle)] pub extern \"C\" fn local_math() -> isize { let x: isize = 15; let y: isize = 4; x / y + x % y }",
        )
        .parse_module::<2, 2>()
        .unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let code =
            compile_x86_64_function::<_, 64, 2, 16>(&function, &NoConstants, X86_64Abi::Windows)
                .unwrap();
        assert_eq!(&code.bytes()[2..10], &6u64.to_le_bytes());

        let shadowed = Parser::new(
            "#[unsafe(no_mangle)] pub extern \"C\" fn shadowed() -> usize { let x: usize = 1; let x: usize = x + 1; x }",
        )
        .parse_module::<2, 2>()
        .unwrap();
        let Some(Item::Function(function)) = shadowed.items()[0] else {
            panic!("expected function")
        };
        let code =
            compile_x86_64_function::<_, 64, 2, 16>(&function, &NoConstants, X86_64Abi::Windows)
                .unwrap();
        assert_eq!(&code.bytes()[2..10], &2u64.to_le_bytes());
    }

    #[test]
    fn shadows_parameters_and_mutable_scalar_locals_in_source_order() {
        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(value: u8) -> u64 { let value: u16 = value as u16 + 1; let value: u64 = value as u64 * 2; value }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u64) -> u64 { let mut value: u64 = 1; let mut value: u64 = 10; value += input; value }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result = compile_x86_64_function::<_, 512, 4, 64>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn value() -> u64 { let mut value: u64 = 1; let value: u64 = 2; value += 1; value }";
        let module = Parser::new(source).parse_module::<2, 4>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(
            compile_x86_64_function::<_, 512, 4, 64>(&function, &NoConstants, X86_64Abi::SystemV,)
                .unwrap_err()
                .kind,
            CodegenErrorKind::ImmutableAssignment
        );
    }

    #[test]
    fn evaluates_wildcard_let_initializers_without_binding_them() {
        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u64) -> u64 { let _: u64 = input + 1; input + 2 }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u64) -> u64 { let _: [u64; 2] = [input, input + 1]; input + 2 }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(values: &[u8]) -> usize { let _: &[u8] = &values[..]; values.len() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u64, flag: bool) -> u64 { let first: u64 = input; let second: u64 = input + 1; if flag { let _: u64 = input + 2; } first + second }",
        ] {
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 1024, 2, 96>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        let constant = Parser::new(
            "#[unsafe(no_mangle)] pub extern \"C\" fn value() -> u64 { let _: u64 = 1; 42 }",
        )
        .parse_module::<2, 2>()
        .unwrap();
        let Some(Item::Function(function)) = constant.items()[0] else {
            panic!("expected function")
        };
        let code =
            compile_x86_64_function::<_, 64, 2, 16>(&function, &NoConstants, X86_64Abi::Windows)
                .unwrap();
        assert_eq!(&code.bytes()[2..10], &42u64.to_le_bytes());

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value() -> u64 { let mut _ = 1u64; 0 }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value() -> u64 { let _: bool = 1u8; 0 }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value() -> u64 { let _: u64 = 1; _ }",
        ] {
            let module = Parser::new(source).parse_module::<2, 2>();
            if let Ok(module) = module {
                let Some(Item::Function(function)) = module.items()[0] else {
                    panic!("expected function")
                };
                assert!(
                    compile_x86_64_function::<_, 256, 2, 32>(
                        &function,
                        &NoConstants,
                        X86_64Abi::SystemV,
                    )
                    .is_err(),
                    "{source}"
                );
            }
        }
    }

    #[test]
    fn evaluates_underscore_assignments_without_a_target() {
        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u64) -> u64 { _ = input + 1; input + 2 }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u64) -> u64 { _ = [input, input + 1]; input + 2 }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(values: &[u8]) -> usize { _ = &values[..]; values.len() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u64, flag: bool) -> u64 { let first: u64 = input; let second: u64 = input + 1; if flag { _ = input + 2; } first + second }",
        ] {
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 1024, 2, 96>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value() -> u64 { _ += 1u64; 0 }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value() -> u64 { _[0] = 1u64; 0 }",
        ] {
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert!(
                compile_x86_64_function::<_, 256, 2, 32>(
                    &function,
                    &NoConstants,
                    X86_64Abi::SystemV,
                )
                .is_err(),
                "{source}"
            );
        }
    }

    #[test]
    fn emits_parameterized_integer_and_boolean_locals() {
        let arithmetic = Parser::new(
            "#[unsafe(no_mangle)] pub extern \"C\" fn local_runtime(value: u64) -> u64 { let doubled: u64 = value * 2; let adjusted: u64 = doubled + 1; adjusted + value }",
        )
        .parse_module::<2, 4>()
        .unwrap();
        let Some(Item::Function(function)) = arithmetic.items()[0] else {
            panic!("expected function")
        };
        let code =
            compile_x86_64_function::<_, 256, 4, 32>(&function, &NoConstants, X86_64Abi::Windows)
                .unwrap();
        assert!(code.bytes().iter().filter(|byte| **byte == 0x50).count() >= 4);
        assert!(
            code.bytes()
                .windows(4)
                .any(|bytes| bytes == [0x48, 0x83, 0xc4, 24])
        );

        let boolean = Parser::new(
            "#[unsafe(no_mangle)] pub extern \"C\" fn local_guard(value: u64, enabled: bool) -> bool { let positive: bool = value > 0; enabled && positive }",
        )
        .parse_module::<2, 4>()
        .unwrap();
        let Some(Item::Function(function)) = boolean.items()[0] else {
            panic!("expected function")
        };
        assert!(
            compile_x86_64_function::<_, 256, 4, 32>(&function, &NoConstants, X86_64Abi::SystemV,)
                .is_ok()
        );
    }

    #[test]
    fn evaluates_and_emits_mutable_local_assignments() {
        let constant = Parser::new(
            "#[unsafe(no_mangle)] pub extern \"C\" fn swap() -> isize { let mut a: isize = 1; let mut b: isize = 2; a ^= b; b ^= a; a = a ^ b; a | b }",
        )
        .parse_module::<2, 4>()
        .unwrap();
        let Some(Item::Function(function)) = constant.items()[0] else {
            panic!("expected function")
        };
        let code =
            compile_x86_64_function::<_, 256, 4, 32>(&function, &NoConstants, X86_64Abi::Windows)
                .unwrap();
        assert!(code.bytes().len() > X86_64_RETURN_CONSTANT_BYTES);

        let runtime = Parser::new(
            "#[unsafe(no_mangle)] pub extern \"C\" fn mutate(value: u64) -> u64 { let mut x: u64 = value; x ^= 255; x += 1; x }",
        )
        .parse_module::<2, 4>()
        .unwrap();
        let Some(Item::Function(function)) = runtime.items()[0] else {
            panic!("expected function")
        };
        let code =
            compile_x86_64_function::<_, 256, 4, 32>(&function, &NoConstants, X86_64Abi::SystemV)
                .unwrap();
        assert!(
            code.bytes()
                .windows(5)
                .any(|bytes| bytes == [0x48, 0x89, 0x44, 0x24, 0])
        );

        let immutable = Parser::new(
            "#[unsafe(no_mangle)] pub extern \"C\" fn invalid(value: u64) -> u64 { let x: u64 = value; x = 1; x }",
        )
        .parse_module::<2, 2>()
        .unwrap();
        let Some(Item::Function(function)) = immutable.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(
            compile_x86_64_function::<_, 128, 2, 16>(&function, &NoConstants, X86_64Abi::Windows,)
                .unwrap_err()
                .kind,
            CodegenErrorKind::ImmutableAssignment
        );
    }

    #[test]
    fn infers_local_integer_types_from_context_and_suffixes() {
        let inferred = Parser::new(
            "#[unsafe(no_mangle)] pub extern \"C\" fn inferred() -> i32 { let mut x = 0; x += 42; x }",
        )
        .parse_module::<2, 2>()
        .unwrap();
        let Some(Item::Function(function)) = inferred.items()[0] else {
            panic!("expected function")
        };
        assert!(
            compile_x86_64_function::<_, 256, 2, 16>(&function, &NoConstants, X86_64Abi::Windows,)
                .is_ok()
        );

        let mismatch = Parser::new(
            "#[unsafe(no_mangle)] pub extern \"C\" fn mismatch(value: u64) -> u64 { let x = 1u32; x + value }",
        )
        .parse_module::<2, 2>()
        .unwrap();
        let Some(Item::Function(function)) = mismatch.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(
            compile_x86_64_function::<_, 256, 2, 16>(&function, &NoConstants, X86_64Abi::SystemV,)
                .unwrap_err()
                .kind,
            CodegenErrorKind::RuntimeTypeMismatch
        );
    }

    #[test]
    fn emits_typed_lazy_if_expressions() {
        let module = Parser::new(
            "#[unsafe(no_mangle)] pub extern \"C\" fn choose(value: u64, guard: bool) -> u64 { if guard { value } else { 10 / value } }",
        )
        .parse_module::<2, 2>()
        .unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let code =
            compile_x86_64_function::<_, 512, 2, 32>(&function, &NoConstants, X86_64Abi::SystemV)
                .unwrap();
        assert!(code.bytes().windows(2).any(|bytes| bytes == [0x0f, 0x84]));
        assert!(code.bytes().contains(&0xe9));

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn bad() -> u64 { if 1 { 2 } else { 3 } }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn bad(flag: bool) -> u64 { if flag { 2 } else { false } }",
        ] {
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert_eq!(
                compile_x86_64_function::<_, 512, 2, 32>(
                    &function,
                    &NoConstants,
                    X86_64Abi::Windows,
                )
                .unwrap_err()
                .kind,
                CodegenErrorKind::RuntimeTypeMismatch
            );
        }
    }

    #[test]
    fn emits_explicit_tail_return_values() {
        let module = Parser::new(
            "#[unsafe(no_mangle)] pub extern \"C\" fn identity(value: usize) -> usize { return value; }",
        )
        .parse_module::<2, 2>()
        .unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        assert!(
            compile_x86_64_function::<_, 128, 2, 16>(&function, &NoConstants, X86_64Abi::Windows,)
                .is_ok()
        );
        assert!(
            compile_x86_64_function::<_, 128, 2, 16>(&function, &NoConstants, X86_64Abi::SystemV,)
                .is_ok()
        );
    }

    #[test]
    fn emits_conditional_returns_with_local_frame_cleanup() {
        let module = Parser::new(
            "#[unsafe(no_mangle)] pub extern \"C\" fn early(value: u64, stop: bool) -> u64 { let adjusted: u64 = value + 1; if stop { return adjusted; } adjusted + 1 }",
        )
        .parse_module::<2, 4>()
        .unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
            let code =
                compile_x86_64_function::<_, 512, 4, 32>(&function, &NoConstants, abi).unwrap();
            assert!(code.bytes().iter().filter(|byte| **byte == 0xc3).count() >= 2);
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn bad(value: u64) -> u64 { if value { return 1; } value }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn bad(value: u64, stop: bool) -> u64 { if stop { return false; } value }",
        ] {
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert_eq!(
                compile_x86_64_function::<_, 512, 2, 32>(
                    &function,
                    &NoConstants,
                    X86_64Abi::Windows,
                )
                .unwrap_err()
                .kind,
                CodegenErrorKind::RuntimeTypeMismatch
            );
        }
    }

    #[test]
    fn emits_exhaustive_conditional_returns_with_lazy_branches() {
        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn choose(value: u64, select: bool) -> u64 { let adjusted = value + 1; if select { return adjusted; } else { return value / value; } }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn choose_chain(value: u64) -> u64 { if value == 0 { return 42; } else if value == 1 { return value + 41; } else if value == 2 { return 84 / value; } else { return 126 / value; } }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn choose_unit(select: bool) { if select { return; } else { return (); } }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                assert!(
                    compile_x86_64_function::<_, 512, 4, 32>(&function, &NoConstants, abi,).is_ok()
                );
            }
        }

        let mismatch = Parser::new(
            "#[unsafe(no_mangle)] pub extern \"C\" fn bad(select: bool) -> u64 { if select { return 1; } else { return false; } }",
        )
        .parse_module::<2, 2>()
        .unwrap();
        let Some(Item::Function(function)) = mismatch.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(
            compile_x86_64_function::<_, 512, 2, 32>(&function, &NoConstants, X86_64Abi::Windows,)
                .unwrap_err()
                .kind,
            CodegenErrorKind::RuntimeTypeMismatch
        );
    }

    #[test]
    fn emits_non_exhaustive_return_chains_with_fallthrough() {
        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn choose(value: u64) -> u64 { if value == 0 { return 42; } else if value == 1 { return 42 / value; } 84 / value }";
        let module = Parser::new(source).parse_module::<2, 2>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
            assert!(compile_x86_64_function::<_, 512, 2, 32>(&function, &NoConstants, abi).is_ok());
        }
    }

    #[test]
    fn emits_lazy_conditional_assignments() {
        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn choose(value: u64) -> u64 { let mut result = value; if value == 0 { result = 40; value + 1; result += 2; return result; } else if value == 1 { result = 40; 84 / value; result += 2; return result; } else if value == 2 { result = 40; 42 / value; result += 2; return result; } else { result = 40; value + 10; result += 2; return result; } 1 / value }";
        let module = Parser::new(source).parse_module::<2, 4>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
            assert!(
                compile_x86_64_function::<_, 1024, 4, 48>(&function, &NoConstants, abi).is_ok()
            );
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn bad(value: u64, select: bool) -> u64 { let result = value; if select { result = 1; } result }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn bad(value: u64) -> u64 { let mut result = value; if value { result = 1; } result }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn bad(value: u64, select: bool) -> u64 { let mut result = value; if select { result = false; } result }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn bad(value: u64, select: bool) -> u64 { let mut result = value; if select { result += 1; return false; } result }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert!(
                compile_x86_64_function::<_, 1024, 4, 48>(
                    &function,
                    &NoConstants,
                    X86_64Abi::Windows,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn emits_scoped_locals_in_conditional_action_blocks() {
        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn choose(value: u64, select: bool) -> u64 { let mut result = value; if select { let mut result: u64 = 40; result += 2; return result; } else { let selected: u64 = 84 / value; selected + 1; result = selected; } result }";
        let module = Parser::new(source).parse_module::<2, 4>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
            assert!(
                compile_x86_64_function::<_, 1024, 4, 48>(&function, &NoConstants, abi,).is_ok()
            );
        }

        let leaking = Parser::new(
            "#[unsafe(no_mangle)] pub extern \"C\" fn bad(select: bool) -> u64 { let mut result: u64 = 0; if select { let scoped: u64 = 42; result = scoped; } scoped }",
        )
        .parse_module::<2, 4>()
        .unwrap();
        let Some(Item::Function(function)) = leaking.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(
            compile_x86_64_function::<_, 1024, 4, 48>(&function, &NoConstants, X86_64Abi::Windows,)
                .unwrap_err()
                .kind,
            CodegenErrorKind::UnknownRuntimeName
        );

        let crowded = Parser::new(
            "#[unsafe(no_mangle)] pub extern \"C\" fn crowded(select: bool) -> u64 { let one: u64 = 1; let two: u64 = 2; let three: u64 = 3; let four: u64 = 4; if select { let fifth: u64 = 5; return fifth; } one + two + three + four }",
        )
        .parse_module::<2, 4>()
        .unwrap();
        let Some(Item::Function(function)) = crowded.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(
            compile_x86_64_function::<_, 1024, 4, 48>(&function, &NoConstants, X86_64Abi::Windows,)
                .unwrap_err()
                .kind,
            CodegenErrorKind::TooManyRuntimeLocals
        );
    }

    #[test]
    fn emits_bounded_scalar_while_loop_backedges() {
        let module = Parser::new(
            "#[unsafe(no_mangle)] pub extern \"C\" fn count(limit: u64) -> u64 { let mut i: u64 = 0; let mut sum: u64 = 0; while i < limit { sum += i; i += 1; if i == 10 { break; } } sum }",
        )
        .parse_module::<2, 4>()
        .unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
            let code =
                compile_x86_64_function::<_, 512, 4, 32>(&function, &NoConstants, abi).unwrap();
            assert!(code.bytes().contains(&0xe9));
            assert!(code.bytes().windows(2).any(|bytes| bytes == [0x0f, 0x84]));
        }

        let immutable = Parser::new(
            "#[unsafe(no_mangle)] pub extern \"C\" fn bad(limit: u64) -> u64 { let i: u64 = 0; while i < limit { i += 1; } i }",
        )
        .parse_module::<2, 4>()
        .unwrap();
        let Some(Item::Function(function)) = immutable.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(
            compile_x86_64_function::<_, 512, 4, 32>(&function, &NoConstants, X86_64Abi::Windows,)
                .unwrap_err()
                .kind,
            CodegenErrorKind::ImmutableAssignment
        );

        let invalid_break = Parser::new(
            "#[unsafe(no_mangle)] pub extern \"C\" fn bad(limit: u64) -> u64 { let mut i: u64 = 0; while i < limit { i += 1; if i { break; } } i }",
        )
        .parse_module::<2, 4>()
        .unwrap();
        let Some(Item::Function(function)) = invalid_break.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(
            compile_x86_64_function::<_, 512, 4, 32>(&function, &NoConstants, X86_64Abi::Windows,)
                .unwrap_err()
                .kind,
            CodegenErrorKind::RuntimeTypeMismatch
        );
    }

    #[test]
    fn emits_scoped_loop_locals_across_control_edges() {
        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn count(limit: u64, stop: u64) -> u64 { let mut i: u64 = 0; let mut total: u64 = 0; while i < limit { loop { break; } let current: u64 = i + 1; current + 10; i = current; if i % 3 == 0 { let selected: u64 = current; total += selected; } else if i % 2 == 0 { let even: u64 = 2; total += even; } else { let fallback: u64 = 1; total += fallback; } if i % 2 == 0 { let skipped: u64 = current; skipped + 10; continue; } if i == stop { let selected: u64 = current; selected + 20; break; } total + current; } total }";
        let module = Parser::new(source).parse_module::<2, 4>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
            let result = compile_x86_64_function::<_, 4096, 4, 64>(&function, &NoConstants, abi);
            assert!(result.is_ok(), "{:#?}", result.err());
        }
        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn count(limit: u64) -> u64 { let mut i: u64 = 0; while i < limit { let current: u64 = i + 1; i = current; continue; } i }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn once() -> u64 { loop { let selected: u64 = 42; selected + 1; break; } 42 }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn return_local() -> u64 { loop { let selected: u64 = 42; return selected; } }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn conditional_return(value: u64) -> u64 { loop { if value == 0 { let selected: u64 = 42; selected + 1; return selected; } return value; } }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn nested_unit_return(limit: u64, enter: bool) { let mut i: u64 = 0; while i < limit { while enter { let selected: u64 = i + 1; selected + 10; return; } i += 1; } }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn nested_conditional_unit_return(limit: u64, stop: u64) { let mut outer: u64 = 0; let mut inner: u64 = 0; while outer < limit { while inner < 3 { inner += 1; if inner == stop { return; } } outer += 1; inner = 0; } }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn nested_conditional_return(limit: u64, stop: u64) -> u64 { let mut outer: u64 = 0; let mut inner: u64 = 0; while outer < limit { while inner < 3 { inner += 1; if inner == stop { return outer + 40; } } outer += 1; inner = 0; } outer }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn nested_ordered_returns(limit: u64, first: u64, second: u64) -> u64 { let mut outer: u64 = 0; let mut inner: u64 = 0; while outer < limit { while inner < 3 { inner += 1; if inner == first { return outer + 40; } if inner == second { return outer + 50; } } outer += 1; inner = 0; } outer }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn nested_continue_then_return(limit: u64, skip: u64, stop: u64) -> u64 { let mut outer: u64 = 0; let mut inner: u64 = 0; while outer < limit { while inner < 3 { inner += 1; if inner == skip { continue; } if inner == stop { return outer + 40; } } outer += 1; inner = 0; } outer }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn nested_multiple_continues(limit: u64, first: u64, second: u64) -> u64 { let mut outer: u64 = 0; let mut inner: u64 = 0; let mut total: u64 = 0; while outer < limit { while inner < 5 { inner += 1; if inner == first { continue; } if inner == second { continue; } total += inner; } outer += 1; inner = 0; } total }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn nested_multiple_breaks(limit: u64, first: u64, second: u64) -> u64 { let mut outer: u64 = 0; let mut inner: u64 = 0; let mut total: u64 = 0; while outer < limit { while inner < 5 { inner += 1; if inner == first { break; } total += inner; if inner == second { break; } } outer += 1; inner = 0; } total }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn nested_unconditional_continue(limit: u64) -> u64 { let mut outer: u64 = 0; let mut inner: u64 = 0; while outer < limit { while inner < 3 { let selected: u64 = inner + 1; inner = selected; continue; let unreachable: u64 = 10 / 0; unreachable; } outer += 1; inner = 0; } outer }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn nested_conditional_only_loop(enter: bool, stop: u64) -> u64 { let mut inner: u64 = 0; while enter { loop { inner += 1; if inner < stop { continue; } if inner == stop { return inner; } } } 0 }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn nested_empty_loop(enter: bool) -> u64 { while enter { loop {} } 42 }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn nested_action_only_loop(enter: bool) -> u64 { while enter { loop { 1; } } 42 }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                assert!(
                    compile_x86_64_function::<_, 1536, 4, 48>(&function, &NoConstants, abi,)
                        .is_ok()
                );
            }
        }

        let unreachable_type_error = Parser::new(
            "#[unsafe(no_mangle)] pub extern \"C\" fn bad(limit: u64) -> u64 { let mut outer: u64 = 0; let mut inner: u64 = 0; while outer < limit { while inner < 3 { inner += 1; continue; let invalid: bool = 1; invalid; } outer += 1; inner = 0; } outer }",
        )
        .parse_module::<2, 4>()
        .unwrap();
        let Some(Item::Function(function)) = unreachable_type_error.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(
            compile_x86_64_function::<_, 1536, 4, 48>(&function, &NoConstants, X86_64Abi::Windows,)
                .unwrap_err()
                .kind,
            CodegenErrorKind::RuntimeTypeMismatch
        );

        let empty_inner_loop = Parser::new(
            "#[unsafe(no_mangle)] pub extern \"C\" fn spin(enter: bool) -> u64 { while enter { loop {} } 42 }",
        )
        .parse_module::<2, 2>()
        .unwrap();
        let Some(Item::Function(function)) = empty_inner_loop.items()[0] else {
            panic!("expected function")
        };
        let machine =
            compile_x86_64_function::<_, 512, 2, 32>(&function, &NoConstants, X86_64Abi::Windows)
                .unwrap();
        assert!(machine.bytes().windows(5).any(|instruction| {
            instruction[0] == 0xe9
                && i32::from_le_bytes([
                    instruction[1],
                    instruction[2],
                    instruction[3],
                    instruction[4],
                ]) < 0
        }));

        let leaking = Parser::new(
            "#[unsafe(no_mangle)] pub extern \"C\" fn bad(limit: u64) -> u64 { let mut i: u64 = 0; while i < limit { let scoped: u64 = i; i += 1; } scoped }",
        )
        .parse_module::<2, 4>()
        .unwrap();
        let Some(Item::Function(function)) = leaking.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(
            compile_x86_64_function::<_, 1024, 4, 48>(&function, &NoConstants, X86_64Abi::Windows,)
                .unwrap_err()
                .kind,
            CodegenErrorKind::UnknownRuntimeName
        );

        let crowded = Parser::new(
            "#[unsafe(no_mangle)] pub extern \"C\" fn crowded(limit: u64) -> u64 { let mut i: u64 = 0; let one: u64 = 1; let two: u64 = 2; let three: u64 = 3; while i < limit { let fifth: u64 = i; i += fifth; } one + two + three }",
        )
        .parse_module::<2, 4>()
        .unwrap();
        let Some(Item::Function(function)) = crowded.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(
            compile_x86_64_function::<_, 1024, 4, 48>(&function, &NoConstants, X86_64Abi::Windows,)
                .unwrap_err()
                .kind,
            CodegenErrorKind::TooManyRuntimeLocals
        );
    }

    #[test]
    fn emits_empty_while_and_top_level_diverging_loop_backedges() {
        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn probe(enter: bool) -> u64 { while enter {} 42 }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn spin() -> u64 { loop {} }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn spin() -> u64 { loop { 1; } }",
        ] {
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let machine =
                    compile_x86_64_function::<_, 512, 2, 32>(&function, &NoConstants, abi).unwrap();
                assert!(machine.bytes().windows(5).any(|instruction| {
                    instruction[0] == 0xe9
                        && i32::from_le_bytes([
                            instruction[1],
                            instruction[2],
                            instruction[3],
                            instruction[4],
                        ]) < 0
                }));
            }
        }
    }

    #[test]
    fn emits_matching_labels_on_statement_loop_controls() {
        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(limit: u64, stop: u64) -> u64 { let mut i: u64 = 0; let mut total: u64 = 0; 'count: while i < limit { i += 1; if i % 2 == 0 { continue 'count; } else if i == stop { break 'count; } total += i; } 'once: loop { break 'once; } total }";
        let module = Parser::new(source).parse_module::<2, 4>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
            assert!(
                compile_x86_64_function::<_, 2048, 4, 64>(&function, &NoConstants, abi).is_ok()
            );
        }
    }

    #[test]
    fn emits_labeled_controls_targeting_inner_and_outer_loops() {
        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn probe(limit: u64, stop: u64) -> u64 { let mut outer: u64 = 0; let mut total: u64 = 0; 'outer: while outer < limit { outer += 1; 'inner: loop { let selected: u64 = outer; if selected == 0 { continue 'inner; } if selected % 2 == 0 { continue 'outer; } if selected == stop { break 'outer; } break 'inner; } total += outer; } total }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn probe(limit: u64) -> u64 { let mut outer: u64 = 0; 'outer: while outer < limit { outer += 1; 'inner: loop { continue 'outer; } } outer }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn probe(enter: bool) -> u64 { let mut outer: u64 = 0; 'outer: while enter { outer += 1; 'inner: loop { break 'outer; } } outer }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                assert!(
                    compile_x86_64_function::<_, 3072, 4, 96>(&function, &NoConstants, abi,)
                        .is_ok()
                );
            }
        }
    }

    #[test]
    fn emits_bounded_unconditional_loops_and_explicit_continue() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn once() -> u64 { let mut value: u64 = 0; loop { value += 1; if value == 1 { break; } } value }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn count(limit: u64) -> u64 { let mut value: u64 = 0; while value < limit { value += 1; continue; } value }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn immediate() -> u64 { loop { break; } 42 }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn classify(limit: usize) -> usize { let mut i: usize = 0; let mut is_even: bool = false; loop { if i == limit { break; } is_even = false; i += 1; if i % 2 != 0 { continue; } is_even = true; } if is_even { i } else { 0 } }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                assert!(
                    compile_x86_64_function::<_, 512, 4, 32>(&function, &NoConstants, abi,).is_ok()
                );
            }
        }

        let endless = Parser::new(
            "#[unsafe(no_mangle)] pub extern \"C\" fn endless() -> u64 { let mut value: u64 = 0; loop { value += 1; continue; } value }",
        )
        .parse_module::<2, 4>()
        .unwrap();
        let Some(Item::Function(function)) = endless.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<4>().unwrap();
        assert_eq!(body.tail_expression, "value");
        for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
            assert!(compile_x86_64_function::<_, 512, 4, 32>(&function, &NoConstants, abi).is_ok());
        }
    }

    #[test]
    fn emits_typed_returns_inside_loops() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn find(limit: u64) -> u64 { let mut value: u64 = 0; while value < limit { if value == 42 { return value; } value += 1; } limit }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn divisible(value: u32) -> bool { let mut divisor: u32 = 2; loop { if value % divisor == 0 { return true; } divisor += 1; } false }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn immediate(value: u64) -> u64 { loop { return value + 1; } }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn immediate(value: bool) -> bool { loop { return !value; } }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let code =
                    compile_x86_64_function::<_, 768, 4, 48>(&function, &NoConstants, abi).unwrap();
                assert!(code.bytes().contains(&0xc3));
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn bad(value: u64) -> u64 { loop { if value { return value; } } 0 }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn bad(value: u64) -> u64 { loop { if value == 0 { return false; } } 0 }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn bad() -> u64 { loop { return false; } }",
        ] {
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert_eq!(
                compile_x86_64_function::<_, 512, 2, 32>(
                    &function,
                    &NoConstants,
                    X86_64Abi::Windows,
                )
                .unwrap_err()
                .kind,
                CodegenErrorKind::RuntimeTypeMismatch
            );
        }
    }

    #[test]
    fn emits_typed_immediate_break_loop_values() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u64) -> u64 { let result: u64 = loop { break input + 1; }; result }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: bool) -> bool { let result: bool = loop { break input; }; result }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value() -> u64 { let result: u64 = loop { break 13; }; result }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(choose_first: bool, input: u64) -> u64 { let result: u64 = loop { if choose_first { break input + 1; } break 84 / input; }; result }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value() -> u64 { let first: () = loop { break (); break; }; first; let second: () = loop { break; break (); }; second; 42 }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value() -> u64 { let first: () = loop { if true { break; } else { break break Default::default(); } }; first; let second: () = loop { if true { break Default::default(); } else { break; } }; second; let third: () = loop { break if true { Default::default() } else { break; }; }; third; 42 }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value() -> u64 { let integer: u64 = Default::default(); let boolean: bool = Default::default(); integer; if boolean { 1 / 0 } else { integer + 42 } }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result = compile_x86_64_function::<_, 512, 4, 32>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        let mismatch = Parser::new(
            "#[unsafe(no_mangle)] pub extern \"C\" fn bad() -> u64 { let result: u64 = loop { break false; }; result }",
        )
        .parse_module::<2, 4>()
        .unwrap();
        let Some(Item::Function(function)) = mismatch.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(
            compile_x86_64_function::<_, 512, 4, 32>(&function, &NoConstants, X86_64Abi::Windows,)
                .unwrap_err()
                .kind,
            CodegenErrorKind::RuntimeTypeMismatch
        );

        let branch_mismatch = Parser::new(
            "#[unsafe(no_mangle)] pub extern \"C\" fn bad(flag: bool) -> u64 { let result = loop { if flag { break 1; } break false; }; result }",
        )
        .parse_module::<2, 4>()
        .unwrap();
        let Some(Item::Function(function)) = branch_mismatch.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(
            compile_x86_64_function::<_, 512, 4, 32>(&function, &NoConstants, X86_64Abi::Windows,)
                .unwrap_err()
                .kind,
            CodegenErrorKind::RuntimeTypeMismatch
        );

        let unreachable_mismatch = Parser::new(
            "#[unsafe(no_mangle)] pub extern \"C\" fn bad() -> u64 { let result = loop { break 1; break false; }; result }",
        )
        .parse_module::<2, 4>()
        .unwrap();
        let Some(Item::Function(function)) = unreachable_mismatch.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(
            compile_x86_64_function::<_, 512, 4, 32>(&function, &NoConstants, X86_64Abi::Windows,)
                .unwrap_err()
                .kind,
            CodegenErrorKind::RuntimeTypeMismatch
        );

        let unconstrained_default = Parser::new(
            "#[unsafe(no_mangle)] pub extern \"C\" fn bad() -> u64 { let result = Default::default(); result }",
        )
        .parse_module::<2, 4>()
        .unwrap();
        let Some(Item::Function(function)) = unconstrained_default.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(
            compile_x86_64_function::<_, 512, 4, 32>(&function, &NoConstants, X86_64Abi::Windows,)
                .unwrap_err()
                .kind,
            CodegenErrorKind::RuntimeTypeMismatch
        );
    }

    #[test]
    fn emits_bounded_scalar_array_literal_indexes() {
        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value() -> u64 { [13u64, 42, 99][1] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value() -> u32 { [1u32, 3, 5][2] }",
        ] {
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                assert!(
                    compile_x86_64_function::<_, 128, 2, 24>(&function, &NoConstants, abi).is_ok()
                );
            }
        }

        let mixed = Parser::new(
            "#[unsafe(no_mangle)] pub extern \"C\" fn bad() -> u64 { [1u64, false][0] }",
        )
        .parse_module::<2, 2>()
        .unwrap();
        let Some(Item::Function(function)) = mixed.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(
            compile_x86_64_function::<_, 128, 2, 24>(&function, &NoConstants, X86_64Abi::Windows)
                .unwrap_err()
                .kind,
            CodegenErrorKind::RuntimeTypeMismatch
        );
    }

    #[test]
    fn emits_contextual_array_defaults_from_loop_breaks() {
        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn value() -> u64 { (loop { break if true { break Default::default() } else { break [13u64, 14] }; })[0] + (loop { if false { break [1 / 0, 14] } else { break Default::default() } })[1] + (loop { break if false { break Default::default() } else { [42, 43] }; })[1] }";
        let module = Parser::new(source).parse_module::<2, 2>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
            assert!(compile_x86_64_function::<_, 256, 2, 64>(&function, &NoConstants, abi).is_ok());
        }
    }

    #[test]
    fn stores_fixed_array_locals_for_scalar_indexes_and_assignment() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value() -> u64 { let values: [u64; 3] = [13, 42, 99]; values[1] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u64) -> u64 { let before: u64 = input; let values = [13u64, 42, 99]; let after: u64 = 1; before + values[1] + after }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value() -> u64 { let values: [u64; 2] = Default::default(); values[0] + values[1] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u64) -> u64 { let values = [input + 1; 3]; values[0] + values[1] + values[2] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(select: bool) -> bool { let values = [select; 2usize]; values[0] & values[1] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u64, divisor: u64) -> u64 { let values: [u64; 0] = [input / divisor; 0]; 42 }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(select: bool) -> u64 { let values: [u64; 2] = loop { break if select { break [13, 14] } else { break Default::default() }; }; values[0] + values[1] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(select: bool) -> u64 { let choice: bool = select; let values = if choice { [13u64, 14] } else { [20, 22] }; values[0] + values[1] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value() -> u64 { let mut values = [13u64, 14]; values = [20, 22]; values[0] + values[1] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value() -> u64 { let mut values = [13u64, 42]; values = [values[1], values[0]]; values[0] * 100 + values[1] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(select: bool) -> u64 { let mut values = [1u64, 2]; if select { values = [20, 22]; } else { values = [13, 14]; } values[0] + values[1] }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result = compile_x86_64_function::<_, 512, 4, 64>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        let compound = Parser::new(
            "#[unsafe(no_mangle)] pub extern \"C\" fn bad() -> u64 { let mut values: [u64; 2] = [1, 2]; values += [3, 4]; values[0] }",
        )
        .parse_module::<2, 2>()
        .unwrap();
        let Some(Item::Function(function)) = compound.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(
            compile_x86_64_function::<_, 128, 2, 32>(&function, &NoConstants, X86_64Abi::Windows)
                .unwrap_err()
                .kind,
            CodegenErrorKind::UnsupportedRuntimeOperator
        );
    }

    #[test]
    fn emits_bounded_runtime_array_indexes() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(index: usize) -> usize { [13usize, 42, 99][index] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(index: usize) -> usize { let values = [13usize, 42, 99]; values[index] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(index: usize, divisor: usize) -> usize { [84 / divisor, 42][index] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(select: bool, index: usize, divisor: usize) -> usize { (if select { [84 / divisor, 42] } else { [13, 14] })[index] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(index: usize) -> bool { let values = [false, true]; values[index] }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let code = compile_x86_64_function::<_, 1024, 4, 64>(&function, &NoConstants, abi)
                    .unwrap();
                assert!(code.bytes().windows(2).any(|bytes| bytes == [0x0f, 0x0b]));
            }
        }

        let wrong_index = Parser::new(
            "#[unsafe(no_mangle)] pub extern \"C\" fn bad(index: u64) -> u64 { [13u64, 42][index] }",
        )
        .parse_module::<2, 2>()
        .unwrap();
        let Some(Item::Function(function)) = wrong_index.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(
            compile_x86_64_function::<_, 256, 2, 32>(&function, &NoConstants, X86_64Abi::Windows)
                .unwrap_err()
                .kind,
            CodegenErrorKind::RuntimeTypeMismatch
        );
    }

    #[test]
    fn stores_fixed_array_elements_through_constant_and_runtime_indexes() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value() -> u64 { let mut values = [13u64, 42, 99]; values[1] = 20; values[0] + values[1] + values[2] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(index: usize) -> usize { let mut values = [13usize, 42, 99]; let after = 1usize; values[index] += after; values[index] + after }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(index: usize) -> bool { let mut values = [false, true]; values[index] ^= true; values[index] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value() -> char { let mut values = ['a', 'b']; values[0] = 'z'; values[0] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(index: usize) { let mut values = [(), ()]; values[index] = (); values[index] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(select: bool, index: usize) -> usize { let mut values = [1usize, 2]; if select { values[index] = 20; } else { values[index] = 13; } values[index] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value() -> usize { let mut values = [1usize, 2]; let mut index = 0usize; while index < 2 { values[index] += 1; index += 1; } values[0] + values[1] }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 1536, 4, 64>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        let invalid = [
            (
                "#[unsafe(no_mangle)] pub extern \"C\" fn value() -> u64 { let values = [1u64, 2]; values[0] = 3; values[0] }",
                CodegenErrorKind::ImmutableAssignment,
            ),
            (
                "#[unsafe(no_mangle)] pub extern \"C\" fn value() -> u64 { let mut value = 1u64; value[0] = 3; value }",
                CodegenErrorKind::RuntimeTypeMismatch,
            ),
            (
                "#[unsafe(no_mangle)] pub extern \"C\" fn value(index: u64) -> u64 { let mut values = [1u64, 2]; values[index] = 3; values[0] }",
                CodegenErrorKind::RuntimeTypeMismatch,
            ),
            (
                "#[unsafe(no_mangle)] pub extern \"C\" fn value() -> u64 { let mut values = [1u64, 2]; values[2] = 3; values[0] }",
                CodegenErrorKind::Execution(ExecutionError::Arithmetic(
                    crate::ConstEvalError::ArrayIndexOutOfBounds,
                )),
            ),
            (
                "#[unsafe(no_mangle)] pub extern \"C\" fn value() -> char { let mut values = ['a', 'b']; values[0] += 'c'; values[0] }",
                CodegenErrorKind::UnsupportedRuntimeOperator,
            ),
        ];
        for (source, expected) in invalid {
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert_eq!(
                compile_x86_64_function::<_, 512, 2, 64>(
                    &function,
                    &NoConstants,
                    X86_64Abi::Windows,
                )
                .unwrap_err()
                .kind,
                expected,
                "{source}",
            );
        }
    }

    #[test]
    fn loads_one_word_fixed_array_parameters() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(values: [u64; 1], after: u64) -> u64 { values[0] + after }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(values: [u64; 1]) -> u64 { let copied = values; copied[0] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(values: [bool; 1]) -> bool { values[0] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(values: [char; 1]) -> char { values[0] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(values: [u64; 2], after: u64) -> u64 { values[0] + values[1] + after }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(before: u64, values: [u64; 3], after: u64) -> u64 { before + values[0] + values[1] + values[2] + after }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u64, b: u64, c: u64, d: u64, e: u64, values: [u64; 2], after: u64) -> u64 { a + b + c + d + e + values[0] + values[1] + after }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(values: [u8; 4]) -> u8 { values[0] + values[1] + values[2] + values[3] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(values: [u16; 5]) -> u16 { values[0] + values[4] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(values: [u32; 2]) -> u32 { values[0] + values[1] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(values: [i16; 3]) -> i16 { values[0] + values[2] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(values: [char; 2]) -> char { values[1] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(values: [bool; 3]) -> bool { values[0] ^ values[2] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(values: [u32; 2]) -> u64 { values[0] as u64 }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u64, empty: [u8; 0], b: u64, c: u64) -> u64 { a + b + c }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u64, units: [(); 3], b: u64, c: u64) -> u64 { a + b + c }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 8>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result = compile_x86_64_function::<_, 768, 8, 64>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }
    }

    #[test]
    fn loads_immutable_scalar_reference_parameters() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(before: u64, input: &u64, after: u64) -> u64 { let copied = input; before + *copied + after }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &i16) -> i16 { *input }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &bool) -> bool { *input }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &char) -> char { *input }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result = compile_x86_64_function::<_, 512, 4, 48>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }
    }

    #[test]
    fn returns_thin_references() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &u16) -> &u16 { input }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &mut i32) -> &mut i32 { input }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &[u8; 4]) -> &[u8; 4] { input }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &u16) -> &u16 { let copied: &u16 = input; copied }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &u16) -> &u16 { &*input }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &mut u16) -> &mut u16 { &mut *input }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &mut u16) -> &u16 { input }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result = compile_x86_64_function::<_, 768, 4, 96>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        let source =
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &u16) -> &mut u16 { input }";
        let module = Parser::new(source).parse_module::<2, 2>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(
            compile_x86_64_function::<_, 512, 2, 64>(&function, &NoConstants, X86_64Abi::Windows,)
                .unwrap_err()
                .kind,
            CodegenErrorKind::RuntimeTypeMismatch,
        );
    }

    #[test]
    fn returns_slice_references() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &[u16]) -> &[u16] { input }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &mut [i32]) -> &mut [i32] { input }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &[u8]) -> &[u8] { let copied: &[u8] = input; copied }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &[u16]) -> &[u16] { &input[..] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &[u16], start: usize, end: usize) -> &[u16] { &input[start..end] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &mut [u16], start: usize, end: usize) -> &mut [u16] { &mut input[start..end] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &mut [u16]) -> &[u16] { input }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 2048, 4, 160>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }
    }

    #[test]
    fn creates_and_returns_indexed_element_references() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &[u16], index: usize) -> &u16 { &input[index] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &mut [i32], index: usize) -> &mut i32 { &mut input[index] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &[u8; 4], index: usize) -> &u8 { &input[index] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &mut [u16; 4], index: usize) -> &mut u16 { &mut input[index] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u16, index: usize) -> u16 { let mut values = [input, 40u16]; let selected: &mut u16 = &mut values[index]; *selected += 2; values[index] }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 2048, 4, 160>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &[u16], index: usize) -> &mut u16 { &mut input[index] }";
        let module = Parser::new(source).parse_module::<2, 2>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(
            compile_x86_64_function::<_, 512, 2, 64>(&function, &NoConstants, X86_64Abi::Windows,)
                .unwrap_err()
                .kind,
            CodegenErrorKind::ImmutableAssignment,
        );

        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &[u16]) -> &u16 { &input[true] }";
        let module = Parser::new(source).parse_module::<2, 2>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(
            compile_x86_64_function::<_, 512, 2, 64>(&function, &NoConstants, X86_64Abi::Windows,)
                .unwrap_err()
                .kind,
            CodegenErrorKind::RuntimeTypeMismatch,
        );
    }

    #[test]
    fn returns_conditional_slice_references() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &[u16], select: bool) -> &[u16] { if select { &input[..1] } else { &input[1..] } }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &mut [u16], select: bool) -> &mut [u16] { if select { &mut input[..1] } else { &mut input[1..] } }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &mut [u16], select: bool) -> &[u16] { if select { input } else { &input[1..] } }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 3072, 4, 192>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }
    }

    #[test]
    fn stores_conditional_slice_references_in_locals() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &[u16], select: bool) -> &[u16] { let selected: &[u16] = if select { &input[..1] } else { &input[1..] }; selected }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &mut [u16], select: bool) -> u16 { let selected: &mut [u16] = if select { &mut input[..1] } else { &mut input[1..] }; selected[0] += 2; selected[0] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &[u16], select: bool) -> usize { let selected = if select { &input[..1] } else { &input[1..] }; selected.len() }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 4096, 4, 224>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }
    }

    #[test]
    fn replaces_slice_reference_locals() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &[u16], select: bool) -> &[u16] { let mut selected: &[u16] = &input[..1]; if select { selected = &input[1..]; } selected }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &mut [u16], select: bool) -> u16 { let mut selected: &mut [u16] = &mut input[..1]; if select { selected = &mut input[1..]; } selected[0] += 2; selected[0] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &mut [u16]) -> usize { let mut selected: &[u16] = input; selected = &input[1..]; selected.len() }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 4096, 4, 224>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }
    }

    #[test]
    fn supports_string_slice_references() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &str) -> usize { input.len() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &str) -> bool { input.is_empty() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &str) -> &str { input }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &str, select: bool) -> &str { let selected: &str = if select { input } else { input }; selected }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &mut str) -> &str { input }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 2048, 4, 160>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        let source =
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &str) -> u8 { input[0] }";
        let module = Parser::new(source).parse_module::<2, 2>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(
            compile_x86_64_function::<_, 512, 2, 64>(&function, &NoConstants, X86_64Abi::Windows,)
                .unwrap_err()
                .kind,
            CodegenErrorKind::RuntimeTypeMismatch,
        );
    }

    #[test]
    fn creates_utf8_checked_string_ranges() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &str, start: usize, end: usize) -> &str { &input[start..end] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &str, end: usize) -> &str { &input[..end] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &str, start: usize) -> &str { &input[start..] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &str) -> &str { &input[..] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &str, start: usize, end: usize) -> &str { &input[start..=end] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &mut str, start: usize, end: usize) -> &mut str { &mut input[start..end] }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 3072, 4, 192>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }
    }

    #[test]
    fn converts_string_slices_to_bytes() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &str) -> &[u8] { input.as_bytes() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &str, index: usize) -> u8 { let bytes: &[u8] = input.as_bytes(); bytes[index] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &str) -> usize { input.as_bytes().len() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &mut str) -> &[u8] { input.as_bytes() }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 2048, 4, 160>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &mut str) -> u8 { let bytes: &mut [u8] = input.as_bytes(); bytes[0] }";
        let module = Parser::new(source).parse_module::<2, 2>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(
            compile_x86_64_function::<_, 512, 2, 64>(&function, &NoConstants, X86_64Abi::Windows,)
                .unwrap_err()
                .kind,
            CodegenErrorKind::RuntimeTypeMismatch,
        );
    }

    #[test]
    fn checks_string_character_boundaries() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &str, index: usize) -> bool { input.is_char_boundary(index) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &str) -> bool { input.is_char_boundary(0) && input.is_char_boundary(input.len()) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &str, index: usize) -> bool { let copied: &str = input; copied.is_char_boundary(index) }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 2048, 4, 160>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &[u8], index: usize) -> bool { input.is_char_boundary(index) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &str) -> bool { input.is_char_boundary(true) }",
        ] {
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert_eq!(
                compile_x86_64_function::<_, 768, 2, 80>(
                    &function,
                    &NoConstants,
                    X86_64Abi::Windows,
                )
                .unwrap_err()
                .kind,
                CodegenErrorKind::RuntimeTypeMismatch,
            );
        }
    }

    #[test]
    fn exposes_reference_data_pointers() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &[u16]) -> *const u16 { input.as_ptr() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &mut [u16]) -> *mut u16 { input.as_mut_ptr() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &str) -> *const u8 { input.as_ptr() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: *mut u16) -> *const u16 { let copied: *const u16 = input; copied }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 2048, 4, 160>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for (source, expected) in [
            (
                "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &[u16]) -> *mut u16 { input.as_mut_ptr() }",
                CodegenErrorKind::ImmutableAssignment,
            ),
            (
                "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: *const u16) -> *mut u16 { input }",
                CodegenErrorKind::RuntimeTypeMismatch,
            ),
        ] {
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert_eq!(
                compile_x86_64_function::<_, 768, 2, 80>(
                    &function,
                    &NoConstants,
                    X86_64Abi::Windows,
                )
                .unwrap_err()
                .kind,
                expected,
            );
        }
    }

    #[test]
    fn dereferences_scalar_raw_pointers() {
        let sources = [
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(input: *const u16) -> u16 { *input }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(input: *const u32) -> u32 { input.read() }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(input: *const u32) -> u32 { input.read_unaligned() }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(input: *mut u32) -> u32 { input.read_volatile() }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(input: *mut u16) -> u16 { *input = 42; *input }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(input: *mut i16) -> i16 { *input += 2; *input }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 2048, 4, 160>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        let source = "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(input: *const u16) { *input = 42; }";
        let module = Parser::new(source).parse_module::<2, 2>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(
            compile_x86_64_function::<_, 768, 2, 80>(&function, &NoConstants, X86_64Abi::Windows,)
                .unwrap_err()
                .kind,
            CodegenErrorKind::ImmutableAssignment,
        );

        let source = "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(input: usize) -> usize { input.read() }";
        let module = Parser::new(source).parse_module::<2, 2>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(
            compile_x86_64_function::<_, 768, 2, 80>(&function, &NoConstants, X86_64Abi::Windows,)
                .unwrap_err()
                .kind,
            CodegenErrorKind::RuntimeTypeMismatch,
        );
    }

    #[test]
    fn converts_scalar_raw_pointers_to_unchecked_references() {
        let sources = [
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(input: *const u32) -> u32 { *input.as_ref_unchecked() }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(input: *mut i16) -> i16 { *input.as_ref_unchecked() }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(input: *mut i16) -> i16 { let reference: &mut i16 = input.as_mut_unchecked(); *reference += 2; *reference }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(input: *mut bool) -> bool { let reference: &mut bool = input.as_mut_unchecked(); *reference ^= true; *reference }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 2048, 4, 160>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(input: *const u32) -> u32 { *input.as_mut_unchecked() }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(input: usize) -> usize { *input.as_ref_unchecked() }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert_eq!(
                compile_x86_64_function::<_, 1024, 4, 96>(
                    &function,
                    &NoConstants,
                    X86_64Abi::Windows,
                )
                .unwrap_err()
                .kind,
                CodegenErrorKind::RuntimeTypeMismatch,
            );
        }
    }

    #[test]
    fn writes_scalar_raw_pointers() {
        let sources = [
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(input: *mut u32, value: u32) { input.write(value) }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(input: *mut u32, value: u32) { input.write_unaligned(value) }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(input: *mut u32, value: u32) { input.write_volatile(value) }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(input: *mut bool, value: bool) { input.write(value) }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(input: *mut char, value: char) { input.write(value) }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 2048, 4, 160>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(input: *const u32) { input.write(42) }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(input: *mut u32, value: bool) { input.write(value) }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(input: usize) { input.write(42) }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert_eq!(
                compile_x86_64_function::<_, 1024, 4, 96>(
                    &function,
                    &NoConstants,
                    X86_64Abi::Windows,
                )
                .unwrap_err()
                .kind,
                CodegenErrorKind::RuntimeTypeMismatch,
            );
        }
    }

    #[test]
    fn fills_bytes_through_scalar_raw_pointers() {
        let sources = [
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(input: *mut u8, value: u8, count: usize) { input.write_bytes(value, count) }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(input: *mut u16, value: u8, count: usize) { input.write_bytes(value, count) }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(input: *mut u32, value: u8, count: usize) { input.write_bytes(value, count) }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(input: *mut u64, value: u8, count: usize) { input.write_bytes(value, count) }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 2048, 4, 160>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(input: *const u32, value: u8, count: usize) { input.write_bytes(value, count) }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(input: *mut u32, value: u16, count: usize) { input.write_bytes(value, count) }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(input: *mut u32, value: u8, count: u32) { input.write_bytes(value, count) }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(input: usize, value: u8, count: usize) { input.write_bytes(value, count) }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert_eq!(
                compile_x86_64_function::<_, 1024, 4, 96>(
                    &function,
                    &NoConstants,
                    X86_64Abi::Windows,
                )
                .unwrap_err()
                .kind,
                CodegenErrorKind::RuntimeTypeMismatch,
            );
        }
    }

    #[test]
    fn copies_between_scalar_raw_pointers() {
        let sources = [
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(source: *const u8, destination: *mut u8, count: usize) { source.copy_to(destination, count) }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(source: *mut u16, destination: *mut u16, count: usize) { source.copy_to(destination, count) }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(source: *const u32, destination: *mut u32, count: usize) { source.copy_to_nonoverlapping(destination, count) }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(source: *const u64, destination: *mut u64, count: usize) { source.copy_to_nonoverlapping(destination, count) }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(source: *const u8, destination: *mut u8, count: usize) { destination.copy_from(source, count) }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(source: *const u32, destination: *mut u32, count: usize) { destination.copy_from_nonoverlapping(source, count) }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 3072, 4, 192>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(source: *const u32, destination: *const u32, count: usize) { source.copy_to(destination, count) }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(source: *const u32, destination: *mut u16, count: usize) { source.copy_to(destination, count) }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(source: *const u32, destination: *mut u32, count: u32) { source.copy_to(destination, count) }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(source: usize, destination: *mut u32, count: usize) { source.copy_to(destination, count) }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(source: *const u32, destination: *const u32, count: usize) { destination.copy_from(source, count) }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert_eq!(
                compile_x86_64_function::<_, 1536, 4, 128>(
                    &function,
                    &NoConstants,
                    X86_64Abi::Windows,
                )
                .unwrap_err()
                .kind,
                CodegenErrorKind::RuntimeTypeMismatch,
            );
        }
    }

    #[test]
    fn replaces_scalar_raw_pointer_values() {
        let sources = [
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(input: *mut u32, value: u32) -> u32 { input.replace(value) }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(input: *mut i16, value: i16) -> i16 { input.replace(value) }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(input: *mut bool, value: bool) -> bool { input.replace(value) }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(input: *mut char, value: char) -> char { input.replace(value) }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 2048, 4, 160>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(input: *const u32) -> u32 { input.replace(42) }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(input: *mut u32, value: bool) -> u32 { input.replace(value) }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert_eq!(
                compile_x86_64_function::<_, 1024, 4, 96>(
                    &function,
                    &NoConstants,
                    X86_64Abi::Windows,
                )
                .unwrap_err()
                .kind,
                CodegenErrorKind::RuntimeTypeMismatch,
            );
        }
    }

    #[test]
    fn swaps_scalar_raw_pointer_values() {
        let sources = [
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(left: *mut u32, right: *mut u32) { left.swap(right) }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(left: *mut i16, right: *mut i16) { left.swap(right) }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(left: *mut bool, right: *mut bool) { left.swap(right) }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(left: *mut char, right: *mut char) { left.swap(right) }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 2048, 4, 160>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(left: *const u32, right: *mut u32) { left.swap(right) }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(left: *mut u32, right: *mut u16) { left.swap(right) }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(left: *mut u32, right: *const u32) { left.swap(right) }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert_eq!(
                compile_x86_64_function::<_, 1024, 4, 96>(
                    &function,
                    &NoConstants,
                    X86_64Abi::Windows,
                )
                .unwrap_err()
                .kind,
                CodegenErrorKind::RuntimeTypeMismatch,
            );
        }
    }

    #[test]
    fn compares_scalar_raw_pointers() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: *const u16, right: *const u16) -> bool { left == right }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: *const u16, right: *const u16) -> bool { left < right }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: *mut u16, right: *const u16) -> bool { left != right }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 1024, 4, 96>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: *const u16, right: *const u8) -> bool { left == right }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: *const u16, right: *const u16) -> u16 { left + right }",
        ] {
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert_eq!(
                compile_x86_64_function::<_, 768, 2, 80>(
                    &function,
                    &NoConstants,
                    X86_64Abi::Windows,
                )
                .unwrap_err()
                .kind,
                CodegenErrorKind::RuntimeTypeMismatch,
            );
        }
    }

    #[test]
    fn casts_scalar_raw_pointers_and_integers() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: *const u16) -> usize { input as usize }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: usize) -> *const u8 { input as *const u8 }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: *mut u16) -> *const u8 { input as *const u8 }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: *const u16) -> *mut u16 { input as *mut u16 }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: *const u16) -> u8 { input as u8 }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 1024, 4, 96>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: bool) -> *const u8 { input as *const u8 }";
        let module = Parser::new(source).parse_module::<2, 2>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(
            compile_x86_64_function::<_, 768, 2, 80>(&function, &NoConstants, X86_64Abi::Windows,)
                .unwrap_err()
                .kind,
            CodegenErrorKind::RuntimeTypeMismatch,
        );
    }

    #[test]
    fn offsets_scalar_raw_pointers_by_elements() {
        let sources = [
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(input: *const u16, offset: usize) -> *const u16 { input.add(offset) }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(input: *mut i32, offset: usize) -> *mut i32 { input.sub(offset) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: *const u8, offset: usize) -> *const u8 { input.wrapping_add(offset) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: *const char, offset: usize) -> *const char { input.wrapping_sub(offset) }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(input: *const u64, forward: usize, back: usize) -> *const u64 { input.add(forward).sub(back) }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(input: *const u32, offset: isize) -> *const u32 { input.offset(offset) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: *mut u64, offset: isize) -> *mut u64 { input.wrapping_offset(offset) }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 1536, 4, 128>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(input: *const u16, offset: u16) -> *const u16 { input.add(offset) }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(input: *const u16, offset: usize) -> *const u16 { input.offset(offset) }",
        ] {
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert_eq!(
                compile_x86_64_function::<_, 768, 2, 80>(
                    &function,
                    &NoConstants,
                    X86_64Abi::Windows,
                )
                .unwrap_err()
                .kind,
                CodegenErrorKind::RuntimeTypeMismatch,
            );
        }
    }

    #[test]
    fn measures_scalar_raw_pointer_element_distances() {
        let sources = [
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(pointer: *const u16, origin: *const u16) -> isize { pointer.offset_from(origin) }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(pointer: *mut u64, origin: *const u64) -> isize { pointer.offset_from(origin) }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(pointer: *const char, origin: *mut char) -> isize { pointer.offset_from(origin) }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 1024, 4, 96>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(pointer: *const u16, origin: *const u8) -> isize { pointer.offset_from(origin) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(pointer: usize, origin: usize) -> isize { pointer.offset_from(origin) }",
        ] {
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert_eq!(
                compile_x86_64_function::<_, 768, 2, 80>(
                    &function,
                    &NoConstants,
                    X86_64Abi::Windows,
                )
                .unwrap_err()
                .kind,
                CodegenErrorKind::RuntimeTypeMismatch,
            );
        }
    }

    #[test]
    fn measures_unsigned_raw_pointer_distances() {
        let sources = [
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(pointer: *const u16, origin: *const u16) -> usize { pointer.offset_from_unsigned(origin) }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(pointer: *mut u64, origin: *const u64) -> usize { pointer.offset_from_unsigned(origin) }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(pointer: *const u32, origin: *const u32) -> usize { pointer.byte_offset_from_unsigned(origin) }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 1024, 4, 96>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        let source = "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(pointer: *const u16, origin: *const u8) -> usize { pointer.offset_from_unsigned(origin) }";
        let module = Parser::new(source).parse_module::<2, 4>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(
            compile_x86_64_function::<_, 1024, 4, 96>(&function, &NoConstants, X86_64Abi::Windows,)
                .unwrap_err()
                .kind,
            CodegenErrorKind::RuntimeTypeMismatch,
        );
    }

    #[test]
    fn computes_scalar_raw_pointer_alignment_offsets() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(pointer: *const u8, alignment: usize) -> usize { pointer.align_offset(alignment) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(pointer: *const u16, alignment: usize) -> usize { pointer.align_offset(alignment) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(pointer: *mut u32, alignment: usize) -> usize { pointer.align_offset(alignment) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(pointer: *const u64, alignment: usize) -> usize { pointer.align_offset(alignment) }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 2048, 4, 160>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(pointer: usize, alignment: usize) -> usize { pointer.align_offset(alignment) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(pointer: *const u32, alignment: u32) -> usize { pointer.align_offset(alignment) }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert_eq!(
                compile_x86_64_function::<_, 1024, 4, 96>(
                    &function,
                    &NoConstants,
                    X86_64Abi::Windows,
                )
                .unwrap_err()
                .kind,
                CodegenErrorKind::RuntimeTypeMismatch,
            );
        }
    }

    #[test]
    fn checks_scalar_raw_pointer_alignment() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(pointer: *const u8) -> bool { pointer.is_aligned() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(pointer: *const u16) -> bool { pointer.is_aligned() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(pointer: *mut u32) -> bool { pointer.is_aligned() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(pointer: *const u64) -> bool { pointer.is_aligned() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(pointer: *mut char) -> bool { pointer.is_aligned() }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 1024, 4, 96>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn value(pointer: usize) -> bool { pointer.is_aligned() }";
        let module = Parser::new(source).parse_module::<2, 4>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(
            compile_x86_64_function::<_, 1024, 4, 96>(&function, &NoConstants, X86_64Abi::Windows,)
                .unwrap_err()
                .kind,
            CodegenErrorKind::RuntimeTypeMismatch,
        );
    }

    #[test]
    fn masks_and_checks_scalar_raw_pointer_alignment() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: *const u32, mask: usize) -> *const u32 { input.mask(mask) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: *mut i16, mask: usize) -> *mut i16 { input.mask(mask) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: *const u32, alignment: usize) -> bool { input.is_aligned_to(alignment) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: *mut char, alignment: usize) -> bool { input.is_aligned_to(alignment) }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 2048, 4, 160>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: usize, mask: usize) -> usize { input.mask(mask) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: *const u32, mask: u32) -> *const u32 { input.mask(mask) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: *const u32, alignment: u32) -> bool { input.is_aligned_to(alignment) }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert_eq!(
                compile_x86_64_function::<_, 1024, 4, 96>(
                    &function,
                    &NoConstants,
                    X86_64Abi::Windows,
                )
                .unwrap_err()
                .kind,
                CodegenErrorKind::RuntimeTypeMismatch,
            );
        }
    }

    #[test]
    fn drops_scalar_raw_pointer_values_in_place() {
        let sources = [
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(input: *mut u32) { input.drop_in_place() }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(input: *mut bool) { input.drop_in_place() }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(input: *mut char) { input.drop_in_place() }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 1024, 4, 96>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(input: *const u32) { input.drop_in_place() }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(input: usize) { input.drop_in_place() }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert_eq!(
                compile_x86_64_function::<_, 1024, 4, 96>(
                    &function,
                    &NoConstants,
                    X86_64Abi::Windows,
                )
                .unwrap_err()
                .kind,
                CodegenErrorKind::RuntimeTypeMismatch,
            );
        }
    }

    #[test]
    fn offsets_and_measures_raw_pointers_by_bytes() {
        let sources = [
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(input: *const u32, offset: usize) -> *const u32 { input.byte_add(offset) }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(input: *mut u64, offset: usize) -> *mut u64 { input.byte_sub(offset) }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(input: *const u16, offset: isize) -> *const u16 { input.byte_offset(offset) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: *const u32, offset: usize) -> *const u32 { input.wrapping_byte_add(offset) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: *const u64, offset: usize) -> *const u64 { input.wrapping_byte_sub(offset) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: *mut u16, offset: isize) -> *mut u16 { input.wrapping_byte_offset(offset) }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(pointer: *const u32, origin: *const u32) -> isize { pointer.byte_offset_from(origin) }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 1024, 4, 96>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }
    }

    #[test]
    fn checks_raw_pointers_for_null() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: *const u16) -> bool { input.is_null() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: *mut char) -> bool { input.is_null() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value() -> bool { (0usize as *const u8).is_null() }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 1024, 4, 96>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: usize) -> bool { input.is_null() }";
        let module = Parser::new(source).parse_module::<2, 2>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(
            compile_x86_64_function::<_, 768, 2, 80>(&function, &NoConstants, X86_64Abi::Windows,)
                .unwrap_err()
                .kind,
            CodegenErrorKind::RuntimeTypeMismatch,
        );
    }

    #[test]
    fn extracts_and_replaces_raw_pointer_addresses() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: *const u16) -> usize { input.addr() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: *mut char) -> usize { input.addr() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: *const u32) -> usize { input.expose_provenance() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: *mut u64) -> usize { input.expose_provenance() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: *const u32, address: usize) -> *const u32 { input.with_addr(address) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: *mut u64, address: usize) -> *mut u64 { input.with_addr(address) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: *const u8, address: usize) -> usize { input.with_addr(address).addr() }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 1024, 4, 96>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: usize) -> usize { input.addr() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: usize) -> usize { input.expose_provenance() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: *const u16, address: u64) -> *const u16 { input.with_addr(address) }",
        ] {
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert_eq!(
                compile_x86_64_function::<_, 768, 2, 80>(
                    &function,
                    &NoConstants,
                    X86_64Abi::Windows,
                )
                .unwrap_err()
                .kind,
                CodegenErrorKind::RuntimeTypeMismatch,
            );
        }
    }

    #[test]
    fn replaces_scalar_raw_pointer_metadata() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: *const u8, metadata: *const u32) -> *const u32 { input.with_metadata_of(metadata) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: *mut u8, metadata: *const i16) -> *mut i16 { input.with_metadata_of(metadata) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: *mut bool, metadata: *mut char) -> *mut char { input.with_metadata_of(metadata) }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 1536, 4, 128>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: usize, metadata: *const u32) -> *const u32 { input.with_metadata_of(metadata) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: *const u8, metadata: usize) -> *const u32 { input.with_metadata_of(metadata) }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert_eq!(
                compile_x86_64_function::<_, 1024, 4, 96>(
                    &function,
                    &NoConstants,
                    X86_64Abi::Windows,
                )
                .unwrap_err()
                .kind,
                CodegenErrorKind::RuntimeTypeMismatch,
            );
        }
    }

    #[test]
    fn converts_raw_pointer_mutability() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: *const u16) -> *mut u16 { input.cast_mut() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: *mut char) -> *const char { input.cast_const() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: *const u8) -> *const u8 { input.cast_mut().cast_const() }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 1024, 4, 96>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: usize) -> usize { input.cast_mut() }";
        let module = Parser::new(source).parse_module::<2, 4>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(
            compile_x86_64_function::<_, 1024, 4, 96>(&function, &NoConstants, X86_64Abi::Windows,)
                .unwrap_err()
                .kind,
            CodegenErrorKind::RuntimeTypeMismatch
        );
    }

    #[test]
    fn casts_raw_pointer_pointee_types() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: *const u32) -> *const u8 { input.cast::<u8>() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: *mut u32) -> *mut i16 { input.cast::<i16>() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: *const bool) -> *const char { input.cast::<char>() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: *mut char) -> *mut bool { input.cast::<bool>() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: *const u64) -> *mut u16 { input.cast::<u16>().cast_mut() }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 1024, 4, 96>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: usize) -> usize { input.cast::<u8>() as usize }";
        let module = Parser::new(source).parse_module::<2, 4>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(
            compile_x86_64_function::<_, 1024, 4, 96>(&function, &NoConstants, X86_64Abi::Windows,)
                .unwrap_err()
                .kind,
            CodegenErrorKind::RuntimeTypeMismatch,
        );
    }

    #[test]
    fn preserves_typed_and_mutable_scalar_reference_pointers() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &u64) -> u64 { let copied: &u64 = input; *copied }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &mut u64) -> u64 { let copied: &mut u64 = input; *copied }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result = compile_x86_64_function::<_, 512, 4, 48>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }
    }

    #[test]
    fn mutates_scalar_reference_pointees() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &mut u64) -> u64 { *input = 40; *input += 2; *input }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &mut i16) -> i16 { let copied: &mut i16 = input; *copied += 2; *copied }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &mut bool) -> bool { *input ^= true; *input }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &mut char) -> char { *input = 'z'; *input }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result = compile_x86_64_function::<_, 512, 4, 48>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        let module = Parser::new(
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &u64) -> u64 { *input = 42; *input }",
        )
        .parse_module::<2, 2>()
        .unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(
            compile_x86_64_function::<_, 256, 2, 32>(&function, &NoConstants, X86_64Abi::Windows,)
                .unwrap_err()
                .kind,
            CodegenErrorKind::ImmutableAssignment,
        );
    }

    #[test]
    fn creates_and_reborrows_scalar_references() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u64) -> u64 { let reference: &u64 = &input; *reference }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i16) -> i16 { let mut local = input; let reference: &mut i16 = &mut local; *reference += 2; local }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &mut u64) -> u64 { let reference: &mut u64 = &mut *input; *reference += 2; *input }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: &u64) -> u64 { let reference: &u64 = &*input; *reference }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result = compile_x86_64_function::<_, 512, 4, 48>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        let module = Parser::new(
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u64) -> u64 { let reference: &mut u64 = &mut input; *reference }",
        )
        .parse_module::<2, 2>()
        .unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(
            compile_x86_64_function::<_, 256, 2, 32>(&function, &NoConstants, X86_64Abi::Windows,)
                .unwrap_err()
                .kind,
            CodegenErrorKind::ImmutableAssignment,
        );
    }

    #[test]
    fn indexes_and_mutates_fixed_array_references() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(values: &[usize; 4], index: usize) -> usize { let copied: &[usize; 4] = values; copied[index] + copied[0] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(values: &mut [usize; 4], index: usize) -> usize { let copied: &mut [usize; 4] = &mut *values; copied[index] += 2; values[index] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(values: &mut [i16; 3]) -> i16 { values[1] = -12; values[1] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(values: &mut [bool; 3]) -> bool { values[2] ^= true; values[2] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(values: &mut [char; 2]) -> char { values[1] = 'z'; values[1] }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result = compile_x86_64_function::<_, 768, 4, 64>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        let module = Parser::new(
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(values: &[u64; 2]) -> u64 { values[0] = 42; values[0] }",
        )
        .parse_module::<2, 2>()
        .unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(
            compile_x86_64_function::<_, 256, 2, 32>(&function, &NoConstants, X86_64Abi::Windows,)
                .unwrap_err()
                .kind,
            CodegenErrorKind::ImmutableAssignment,
        );
    }

    #[test]
    fn takes_references_to_expanded_fixed_array_locals() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: usize, index: usize) -> usize { let values = [input, 10, 20, 30]; let reference: &[usize; 4] = &values; reference[index] + reference[0] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: usize, index: usize) -> usize { let mut values = [input, 10, 20, 30]; let reference: &mut [usize; 4] = &mut values; let copied: &mut [usize; 4] = &mut *reference; copied[index] += 2; copied[index] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i16) -> i16 { let mut values = [input, 0, 0]; let reference: &mut [i16; 3] = &mut values; reference[1] = -12; reference[1] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: bool) -> bool { let mut values = [input, false, true]; let reference: &mut [bool; 3] = &mut values; reference[1] ^= true; reference[1] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: char) -> char { let mut values = [input, 'a']; let reference: &mut [char; 2] = &mut values; reference[1] = 'z'; reference[1] }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 8>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 1024, 8, 96>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }
    }

    #[test]
    fn indexes_and_mutates_slice_references() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(values: &[usize], index: usize) -> usize { let copied: &[usize] = values; copied[index] + copied[0] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(values: &mut [usize], index: usize) -> usize { let copied: &mut [usize] = &mut *values; copied[index] += 2; values[index] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(values: &[usize]) -> usize { values.len() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(values: &mut [usize]) -> usize { let copied: &mut [usize] = &mut *values; copied.len() + values.len() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(values: &[usize]) -> bool { values.is_empty() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(values: &mut [usize]) -> bool { let copied: &mut [usize] = &mut *values; copied.is_empty() || values.is_empty() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(values: &mut [i16]) -> i16 { values[1] = -12; values[1] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(values: &mut [bool]) -> bool { values[2] ^= true; values[2] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(values: &mut [char]) -> char { values[1] = 'z'; values[1] }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 1024, 4, 96>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        let module = Parser::new(
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(values: &[u64]) -> u64 { values[0] = 42; values[0] }",
        )
        .parse_module::<2, 2>()
        .unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(
            compile_x86_64_function::<_, 384, 2, 48>(&function, &NoConstants, X86_64Abi::Windows,)
                .unwrap_err()
                .kind,
            CodegenErrorKind::ImmutableAssignment,
        );
    }

    #[test]
    fn creates_slices_from_fixed_array_reference_ranges() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(values: &[usize; 4]) -> usize { let slice: &[usize] = &values[1..3]; slice.len() + slice[0] + slice[1] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(values: &mut [usize; 4]) -> usize { let slice: &mut [usize] = &mut values[1..=2]; slice[1] += 2; values[2] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(values: &[usize; 4]) -> usize { let slice: &[usize] = &values[..2]; slice.len() + slice[1] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(values: &[usize; 4]) -> usize { let slice: &[usize] = &values[2..]; slice.len() + slice[0] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(values: &[usize; 4]) -> usize { let slice: &[usize] = &values[..]; slice.len() + slice[3] }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 1024, 4, 128>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(values: &[usize; 4]) -> usize { let slice: &[usize] = &values[3..2]; slice.len() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(values: &[usize; 4]) -> usize { let slice: &[usize] = &values[..5]; slice.len() }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert_eq!(
                compile_x86_64_function::<_, 512, 4, 96>(
                    &function,
                    &NoConstants,
                    X86_64Abi::Windows,
                )
                .unwrap_err()
                .kind,
                CodegenErrorKind::ValueOutOfRange,
            );
        }

        let module = Parser::new(
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(values: &[usize; 4]) -> usize { let slice: &mut [usize] = &mut values[1..3]; slice.len() }",
        )
        .parse_module::<2, 4>()
        .unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(
            compile_x86_64_function::<_, 512, 4, 96>(&function, &NoConstants, X86_64Abi::Windows,)
                .unwrap_err()
                .kind,
            CodegenErrorKind::ImmutableAssignment,
        );
    }

    #[test]
    fn creates_slices_from_runtime_fixed_array_ranges() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(values: &mut [usize; 4], start: usize, end: usize) -> usize { let slice: &mut [usize] = &mut values[start..end]; slice[0] += 2; slice.len() + slice[0] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(values: &[usize; 4], start: usize, end: usize) -> usize { let slice: &[usize] = &values[start..=end]; slice.len() + slice[0] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(values: &[usize; 4], end: usize) -> usize { let slice: &[usize] = &values[..end]; slice.len() + slice[0] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(values: &[usize; 4], start: usize) -> usize { let slice: &[usize] = &values[start..]; slice.len() + slice[0] }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 1536, 4, 128>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }
    }

    #[test]
    fn creates_subslices_from_slice_ranges() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(values: &mut [u16], start: usize, end: usize) -> u16 { let slice: &mut [u16] = &mut values[start..end]; slice[0] += 2; slice[0] + slice[1] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(values: &[usize], start: usize, end: usize) -> usize { let slice: &[usize] = &values[start..=end]; slice.len() + slice[0] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(values: &[usize], end: usize) -> usize { let slice: &[usize] = &values[..end]; slice.len() + slice[0] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(values: &[usize], start: usize) -> usize { let slice: &[usize] = &values[start..]; slice.len() + slice[0] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(values: &[usize]) -> usize { let slice: &[usize] = &values[..]; slice.len() + slice[0] }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 2048, 4, 160>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }
    }

    #[test]
    fn creates_slices_from_contiguous_fixed_array_locals() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: usize, start: usize, end: usize) -> usize { let values = [input, 10, 20, 30]; let slice: &[usize] = &values[start..end]; slice.len() + slice[0] + values[2] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: usize, start: usize, end: usize) -> usize { let mut values = [input, 10, 20, 30]; let slice: &mut [usize] = &mut values[start..=end]; slice[1] += 2; values[2] + slice.len() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i64) -> i64 { let values = [input, 10, 20, 30]; let slice: &[i64] = &values[1..3]; slice[0] + slice[1] }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 8>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 2048, 8, 160>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }
    }

    #[test]
    fn creates_slices_from_packed_fixed_array_locals() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u8) -> u8 { let mut values = [input, 10, 20, 30]; let slice: &mut [u8] = &mut values[1..=2]; slice[1] += 2; values[2] + slice[0] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u16) -> u16 { let mut values = [input, 1000, 2000, 3000, 4000]; let slice: &mut [u16] = &mut values[1..4]; slice[1] += 2; values[2] + slice[0] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u32) -> u32 { let mut values = [input, 100000, 200000]; values = [input, values[1], values[2]]; let slice: &[u32] = &values[..2]; slice[0] + slice[1] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: bool) -> bool { let mut values = [input, false, true]; let slice: &mut [bool] = &mut values[1..]; slice[0] ^= true; values[1] && slice[1] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: char) -> char { let mut values = [input, 'x', 'y']; let slice: &mut [char] = &mut values[1..3]; slice[0] = 'z'; values[1] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(start: usize, end: usize) -> u8 { let mut values = [7u8, 10, 20, 30]; let slice: &mut [u8] = &mut values[start..end]; slice[0] += 2; values[start] + slice[1] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(start: usize) -> u8 { let end: usize = start + 2; let mut values = [7u8, 10, 20, 30]; let slice: &mut [u8] = &mut values[start..end]; slice[0] += 2; values[start] + slice[1] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(start: usize) -> u8 { let end = start + 2; if end == 3 { 42u8 } else { 1 } }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(start: usize) -> u8 { let end: usize = start + 2; if end == 3 { 42u8 } else { 1 } }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 8>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 3072, 8, 192>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }
    }

    #[test]
    fn keeps_auxiliary_usize_parameters_out_of_narrow_arithmetic() {
        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u8, index: usize) -> u8 { input + index }";
        let module = Parser::new(source).parse_module::<2, 2>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(
            compile_x86_64_function::<_, 512, 2, 64>(&function, &NoConstants, X86_64Abi::Windows,)
                .unwrap_err()
                .kind,
            CodegenErrorKind::RuntimeTypeMismatch,
        );
    }

    #[test]
    fn supports_independent_scalar_integer_widths() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u8, wide: u64, signed: i16) -> u8 { let adjusted = wide + 2; let negative: i16 = signed + 2; if adjusted == 258 && negative == -1 { input + 1 } else { input } }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u8) -> u8 { let wide: u64 = 256; let signed: i16 = -3; if wide + 2 == 258 && signed + 2 == -1 { input + 1 } else { input } }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u8) -> u8 { let values: [u16; 3] = [256, 257, 258]; if values[1] == 257 { input + 1 } else { input } }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u8) -> u8 { let mut wide: u64 = 256; wide += 2; let mut signed: i16 = -3; signed += 2; let mut values: [u16; 3] = [256, 257, 258]; values[1] += 1; if wide == 258 && signed == -1 && values[1] == 258 { input + 1 } else { input } }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 1536, 4, 128>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }
    }

    #[test]
    fn checks_unsigned_integer_multiples_and_powers_of_two() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u8) -> bool { input.is_power_of_two() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u64, divisor: u64) -> bool { input.is_multiple_of(divisor) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: usize) -> bool { input.is_multiple_of(0) }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 2048, 4, 160>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i32) -> bool { input.is_power_of_two() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u32, divisor: u16) -> bool { input.is_multiple_of(divisor) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: bool) -> bool { input.is_power_of_two() }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert_eq!(
                compile_x86_64_function::<_, 1024, 4, 96>(
                    &function,
                    &NoConstants,
                    X86_64Abi::Windows,
                )
                .unwrap_err()
                .kind,
                CodegenErrorKind::RuntimeTypeMismatch,
            );
        }
    }

    #[test]
    fn wraps_primitive_integer_arithmetic() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u8, rhs: u8) -> u8 { input.wrapping_add(rhs) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i16, rhs: i16) -> i16 { input.wrapping_sub(rhs) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u32, rhs: u32) -> u32 { input.wrapping_mul(rhs) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i64, rhs: i64) -> i64 { input.wrapping_mul(rhs) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: usize, rhs: usize) -> usize { input.wrapping_add(rhs) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i8, rhs: i8) -> i8 { input.wrapping_div(rhs) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u16, rhs: u16) -> u16 { input.wrapping_rem(rhs) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i64, rhs: i64) -> i64 { input.wrapping_rem(rhs) }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 1024, 4, 96>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u8, rhs: u16) -> u8 { input.wrapping_add(rhs) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: bool, rhs: bool) -> bool { input.wrapping_mul(rhs) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: *const u8, rhs: usize) -> *const u8 { input.wrapping_mul(rhs) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i8, rhs: i16) -> i8 { input.wrapping_div(rhs) }",
        ] {
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert_eq!(
                compile_x86_64_function::<_, 768, 2, 80>(
                    &function,
                    &NoConstants,
                    X86_64Abi::Windows,
                )
                .unwrap_err()
                .kind,
                CodegenErrorKind::RuntimeTypeMismatch,
            );
        }
    }

    #[test]
    fn wraps_mixed_signedness_integer_arithmetic() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: i8, right: u8) -> i8 { left.wrapping_add_unsigned(right) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: i64, right: u64) -> i64 { left.wrapping_sub_unsigned(right) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: u16, right: i16) -> u16 { left.wrapping_add_signed(right) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: u64, right: i64) -> u64 { left.wrapping_sub_signed(right) }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 1024, 4, 96>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: u8, right: u8) -> u8 { left.wrapping_add_signed(right) }";
        let module = Parser::new(source).parse_module::<2, 4>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(
            compile_x86_64_function::<_, 1024, 4, 96>(&function, &NoConstants, X86_64Abi::Windows,)
                .unwrap_err()
                .kind,
            CodegenErrorKind::RuntimeTypeMismatch,
        );
    }

    #[test]
    fn checks_strict_primitive_integer_arithmetic() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: u8, right: u8) -> u8 { left.strict_add(right) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: i16, right: i16) -> i16 { left.strict_sub(right) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: u32, right: u32) -> u32 { left.strict_mul(right) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: i64, right: i64) -> i64 { left.strict_add(right) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: u64, right: u64) -> u64 { left.strict_sub(right) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: i8, right: i8) -> i8 { left.strict_mul(right) }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                for options in [CodegenOptions::CHECKED, CodegenOptions::WRAPPING] {
                    let result = compile_x86_64_function_with_options::<_, 1024, 4, 96>(
                        &function,
                        &NoConstants,
                        abi,
                        options,
                    );
                    assert!(result.is_ok(), "{source}: {result:?}");
                }
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: u8, right: u16) -> u8 { left.strict_add(right) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: bool, right: bool) -> bool { left.strict_mul(right) }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert_eq!(
                compile_x86_64_function::<_, 1024, 4, 96>(
                    &function,
                    &NoConstants,
                    X86_64Abi::Windows,
                )
                .unwrap_err()
                .kind,
                CodegenErrorKind::RuntimeTypeMismatch,
            );
        }
    }

    #[test]
    fn checks_strict_mixed_signedness_integer_arithmetic() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: i8, right: u8) -> i8 { left.strict_add_unsigned(right) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: i64, right: u64) -> i64 { left.strict_sub_unsigned(right) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: u16, right: i16) -> u16 { left.strict_add_signed(right) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: u64, right: i64) -> u64 { left.strict_sub_signed(right) }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                for options in [CodegenOptions::CHECKED, CodegenOptions::WRAPPING] {
                    let result = compile_x86_64_function_with_options::<_, 1536, 4, 128>(
                        &function,
                        &NoConstants,
                        abi,
                        options,
                    );
                    assert!(result.is_ok(), "{source}: {result:?}");
                }
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: i8, right: i8) -> i8 { left.strict_add_unsigned(right) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: u32, right: u32) -> u32 { left.strict_sub_signed(right) }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert_eq!(
                compile_x86_64_function::<_, 1024, 4, 96>(
                    &function,
                    &NoConstants,
                    X86_64Abi::Windows,
                )
                .unwrap_err()
                .kind,
                CodegenErrorKind::RuntimeTypeMismatch,
            );
        }
    }

    #[test]
    fn checks_strict_primitive_integer_division() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: u8, right: u8) -> u8 { left.strict_div(right) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: i16, right: i16) -> i16 { left.strict_rem(right) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: i64, right: i64) -> i64 { left.strict_div_euclid(right) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: i16, right: i16) -> i16 { left.strict_rem_euclid(right) }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                for options in [CodegenOptions::CHECKED, CodegenOptions::WRAPPING] {
                    let result = compile_x86_64_function_with_options::<_, 1024, 4, 96>(
                        &function,
                        &NoConstants,
                        abi,
                        options,
                    );
                    assert!(result.is_ok(), "{source}: {result:?}");
                }
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: u8, right: u16) -> u8 { left.strict_div(right) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: bool, right: bool) -> bool { left.strict_rem(right) }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert_eq!(
                compile_x86_64_function::<_, 1024, 4, 96>(
                    &function,
                    &NoConstants,
                    X86_64Abi::Windows,
                )
                .unwrap_err()
                .kind,
                CodegenErrorKind::RuntimeTypeMismatch,
            );
        }
    }

    #[test]
    fn checks_strict_primitive_integer_negation() {
        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u8) -> u8 { input.strict_neg() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i16) -> i16 { input.strict_neg() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i64) -> i64 { input.strict_neg() }",
        ] {
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                for options in [CodegenOptions::CHECKED, CodegenOptions::WRAPPING] {
                    let result = compile_x86_64_function_with_options::<_, 1024, 2, 96>(
                        &function,
                        &NoConstants,
                        abi,
                        options,
                    );
                    assert!(result.is_ok(), "{source}: {result:?}");
                }
            }
        }

        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: bool) -> bool { input.strict_neg() }";
        let module = Parser::new(source).parse_module::<2, 2>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(
            compile_x86_64_function::<_, 1024, 2, 96>(&function, &NoConstants, X86_64Abi::Windows,)
                .unwrap_err()
                .kind,
            CodegenErrorKind::RuntimeTypeMismatch,
        );
    }

    #[test]
    fn checks_strict_primitive_integer_shifts() {
        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u8, distance: u32) -> u8 { input.strict_shl(distance) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i16, distance: u32) -> i16 { input.strict_shr(distance) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u64, distance: u32) -> u64 { input.strict_shl(distance) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i64, distance: u32) -> i64 { input.strict_shr(distance) }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                for options in [CodegenOptions::CHECKED, CodegenOptions::WRAPPING] {
                    let result = compile_x86_64_function_with_options::<_, 1024, 4, 96>(
                        &function,
                        &NoConstants,
                        abi,
                        options,
                    );
                    assert!(result.is_ok(), "{source}: {result:?}");
                }
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u8, distance: u16) -> u8 { input.strict_shl(distance) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: bool, distance: u32) -> bool { input.strict_shr(distance) }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert_eq!(
                compile_x86_64_function::<_, 1024, 4, 96>(
                    &function,
                    &NoConstants,
                    X86_64Abi::Windows,
                )
                .unwrap_err()
                .kind,
                CodegenErrorKind::RuntimeTypeMismatch,
            );
        }
    }

    #[test]
    fn checks_strict_primitive_integer_powers() {
        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u8, exponent: u32) -> u8 { input.strict_pow(exponent) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i16, exponent: u32) -> i16 { input.strict_pow(exponent) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u64, exponent: u32) -> u64 { input.strict_pow(exponent) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i64, exponent: u32) -> i64 { input.strict_pow(exponent) }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                for options in [CodegenOptions::CHECKED, CodegenOptions::WRAPPING] {
                    let result = compile_x86_64_function_with_options::<_, 2048, 4, 96>(
                        &function,
                        &NoConstants,
                        abi,
                        options,
                    );
                    assert!(result.is_ok(), "{source}: {result:?}");
                }
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u8, exponent: u16) -> u8 { input.strict_pow(exponent) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: bool, exponent: u32) -> bool { input.strict_pow(exponent) }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert_eq!(
                compile_x86_64_function::<_, 2048, 4, 96>(
                    &function,
                    &NoConstants,
                    X86_64Abi::Windows,
                )
                .unwrap_err()
                .kind,
                CodegenErrorKind::RuntimeTypeMismatch,
            );
        }
    }

    #[test]
    fn computes_strict_signed_integer_absolute_values() {
        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i8) -> i8 { input.strict_abs() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i16) -> i16 { input.strict_abs() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i64) -> i64 { input.strict_abs() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: isize) -> isize { input.strict_abs() }",
        ] {
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                for options in [CodegenOptions::CHECKED, CodegenOptions::WRAPPING] {
                    let result = compile_x86_64_function_with_options::<_, 1024, 2, 96>(
                        &function,
                        &NoConstants,
                        abi,
                        options,
                    );
                    assert!(result.is_ok(), "{source}: {result:?}");
                }
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u8) -> u8 { input.strict_abs() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: bool) -> bool { input.strict_abs() }",
        ] {
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert_eq!(
                compile_x86_64_function::<_, 1024, 2, 96>(
                    &function,
                    &NoConstants,
                    X86_64Abi::Windows,
                )
                .unwrap_err()
                .kind,
                CodegenErrorKind::RuntimeTypeMismatch,
            );
        }
    }

    #[test]
    fn divides_primitive_integers_euclideanly() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u8, rhs: u8) -> u8 { input.div_euclid(rhs) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i16, rhs: i16) -> i16 { input.rem_euclid(rhs) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u32, rhs: u32) -> u32 { input.rem_euclid(rhs) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i64, rhs: i64) -> i64 { input.div_euclid(rhs) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i8, rhs: i8) -> i8 { input.wrapping_div_euclid(rhs) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i64, rhs: i64) -> i64 { input.wrapping_rem_euclid(rhs) }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 2048, 4, 96>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u8, rhs: u16) -> u8 { input.div_euclid(rhs) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: bool, rhs: bool) -> bool { input.rem_euclid(rhs) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i8, rhs: i16) -> i8 { input.wrapping_div_euclid(rhs) }",
        ] {
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert_eq!(
                compile_x86_64_function::<_, 1024, 2, 80>(
                    &function,
                    &NoConstants,
                    X86_64Abi::Windows,
                )
                .unwrap_err()
                .kind,
                CodegenErrorKind::RuntimeTypeMismatch,
            );
        }
    }

    #[test]
    fn wraps_signed_integer_negation_and_absolute_value() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i8) -> i8 { input.wrapping_neg() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i16) -> i16 { input.wrapping_abs() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i32) -> i32 { input.wrapping_neg() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i64) -> i64 { input.wrapping_abs() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: isize) -> isize { input.wrapping_neg() }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 1024, 2, 96>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u8) -> u8 { input.wrapping_neg() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u64) -> u64 { input.wrapping_abs() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: bool) -> bool { input.wrapping_neg() }",
        ] {
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert_eq!(
                compile_x86_64_function::<_, 768, 2, 80>(
                    &function,
                    &NoConstants,
                    X86_64Abi::Windows,
                )
                .unwrap_err()
                .kind,
                CodegenErrorKind::RuntimeTypeMismatch,
            );
        }
    }

    #[test]
    fn saturates_primitive_integer_arithmetic() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u8, rhs: u8) -> u8 { input.saturating_add(rhs) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i16, rhs: i16) -> i16 { input.saturating_sub(rhs) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u32, rhs: u32) -> u32 { input.saturating_sub(rhs) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i64, rhs: i64) -> i64 { input.saturating_add(rhs) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: usize, rhs: usize) -> usize { input.saturating_add(rhs) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u64, rhs: u64) -> u64 { input.saturating_mul(rhs) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i32, rhs: i32) -> i32 { input.saturating_mul(rhs) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i64, rhs: i64) -> i64 { input.saturating_mul(rhs) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u32, rhs: u32) -> u32 { input.saturating_div(rhs) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i64, rhs: i64) -> i64 { input.saturating_div(rhs) }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 1280, 2, 96>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u8, rhs: u16) -> u8 { input.saturating_add(rhs) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: bool, rhs: bool) -> bool { input.saturating_sub(rhs) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u8, rhs: u16) -> u8 { input.saturating_mul(rhs) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i8, rhs: i16) -> i8 { input.saturating_div(rhs) }",
        ] {
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert_eq!(
                compile_x86_64_function::<_, 896, 2, 80>(
                    &function,
                    &NoConstants,
                    X86_64Abi::Windows,
                )
                .unwrap_err()
                .kind,
                CodegenErrorKind::RuntimeTypeMismatch,
            );
        }
    }

    #[test]
    fn saturates_mixed_signedness_integer_arithmetic() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: i8, right: u8) -> i8 { left.saturating_add_unsigned(right) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: i64, right: u64) -> i64 { left.saturating_sub_unsigned(right) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: u16, right: i16) -> u16 { left.saturating_add_signed(right) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: u64, right: i64) -> u64 { left.saturating_sub_signed(right) }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 1536, 4, 128>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: i8, right: i8) -> i8 { left.saturating_add_unsigned(right) }";
        let module = Parser::new(source).parse_module::<2, 4>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(
            compile_x86_64_function::<_, 1024, 4, 96>(&function, &NoConstants, X86_64Abi::Windows,)
                .unwrap_err()
                .kind,
            CodegenErrorKind::RuntimeTypeMismatch,
        );
    }

    #[test]
    fn saturates_signed_integer_negation_and_absolute_value() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i8) -> i8 { input.saturating_neg() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i16) -> i16 { input.saturating_abs() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i32) -> i32 { input.saturating_neg() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i64) -> i64 { input.saturating_abs() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: isize) -> isize { input.saturating_neg() }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 1280, 2, 96>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u8) -> u8 { input.saturating_neg() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u64) -> u64 { input.saturating_abs() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: bool) -> bool { input.saturating_neg() }",
        ] {
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert_eq!(
                compile_x86_64_function::<_, 896, 2, 80>(
                    &function,
                    &NoConstants,
                    X86_64Abi::Windows,
                )
                .unwrap_err()
                .kind,
                CodegenErrorKind::RuntimeTypeMismatch,
            );
        }
    }

    #[test]
    fn classifies_signed_integer_signs() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i8) -> i8 { input.signum() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i16) -> bool { input.is_positive() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i32) -> bool { input.is_negative() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i64) -> i64 { input.signum() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: isize) -> bool { input.is_negative() }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 1024, 2, 96>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u8) -> u8 { input.signum() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u32) -> bool { input.is_positive() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: bool) -> bool { input.is_negative() }",
        ] {
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert_eq!(
                compile_x86_64_function::<_, 768, 2, 80>(
                    &function,
                    &NoConstants,
                    X86_64Abi::Windows,
                )
                .unwrap_err()
                .kind,
                CodegenErrorKind::RuntimeTypeMismatch,
            );
        }
    }

    #[test]
    fn checks_signed_absolute_overflow_mode() {
        let source =
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i64) -> i64 { input.abs() }";
        let module = Parser::new(source).parse_module::<2, 2>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let checked = compile_x86_64_function_with_options::<_, 1024, 2, 64>(
            &function,
            &NoConstants,
            X86_64Abi::Windows,
            CodegenOptions::CHECKED,
        )
        .unwrap();
        assert!(
            checked
                .bytes()
                .windows(2)
                .any(|bytes| bytes == [0x0f, 0x80])
        );
        let wrapping = compile_x86_64_function_with_options::<_, 1024, 2, 64>(
            &function,
            &NoConstants,
            X86_64Abi::Windows,
            CodegenOptions::WRAPPING,
        )
        .unwrap();
        assert!(
            !wrapping
                .bytes()
                .windows(2)
                .any(|bytes| bytes == [0x0f, 0x80])
        );

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i8) -> i8 { input.abs() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i16) -> i16 { input.abs() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i32) -> i32 { input.abs() }",
        ] {
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert!(
                compile_x86_64_function::<_, 1024, 2, 64>(
                    &function,
                    &NoConstants,
                    X86_64Abi::SystemV,
                )
                .is_ok()
            );
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u8) -> u8 { input.abs() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: bool) -> bool { input.abs() }",
        ] {
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert_eq!(
                compile_x86_64_function::<_, 768, 2, 64>(
                    &function,
                    &NoConstants,
                    X86_64Abi::Windows,
                )
                .unwrap_err()
                .kind,
                CodegenErrorKind::RuntimeTypeMismatch,
            );
        }
    }

    #[test]
    fn computes_unsigned_absolute_values() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i8) -> u8 { input.unsigned_abs() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i16) -> u16 { input.unsigned_abs() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i32) -> u32 { input.unsigned_abs() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i64) -> u64 { input.unsigned_abs() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: isize) -> usize { input.unsigned_abs() }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 1024, 2, 96>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i8) -> i8 { input.unsigned_abs() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u32) -> u32 { input.unsigned_abs() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: bool) -> bool { input.unsigned_abs() }",
        ] {
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert_eq!(
                compile_x86_64_function::<_, 768, 2, 80>(
                    &function,
                    &NoConstants,
                    X86_64Abi::Windows,
                )
                .unwrap_err()
                .kind,
                CodegenErrorKind::RuntimeTypeMismatch,
            );
        }
    }

    #[test]
    fn computes_integer_absolute_differences() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: i8, right: i8) -> u8 { left.abs_diff(right) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: u16, right: u16) -> u16 { left.abs_diff(right) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: i32, right: i32) -> u32 { left.abs_diff(right) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: u64, right: u64) -> u64 { left.abs_diff(right) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: isize, right: isize) -> usize { left.abs_diff(right) }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 1280, 4, 96>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: i8, right: i8) -> i8 { left.abs_diff(right) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: u8, right: u16) -> u8 { left.abs_diff(right) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: bool, right: bool) -> bool { left.abs_diff(right) }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert_eq!(
                compile_x86_64_function::<_, 896, 4, 80>(
                    &function,
                    &NoConstants,
                    X86_64Abi::Windows,
                )
                .unwrap_err()
                .kind,
                CodegenErrorKind::RuntimeTypeMismatch,
            );
        }
    }

    #[test]
    fn computes_primitive_integer_midpoints() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: i8, right: i8) -> i8 { left.midpoint(right) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: u16, right: u16) -> u16 { left.midpoint(right) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: i32, right: i32) -> i32 { left.midpoint(right) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: u64, right: u64) -> u64 { left.midpoint(right) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: isize, right: isize) -> isize { left.midpoint(right) }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 1024, 4, 96>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: u8, right: u16) -> u8 { left.midpoint(right) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: bool, right: bool) -> bool { left.midpoint(right) }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert_eq!(
                compile_x86_64_function::<_, 1024, 4, 96>(
                    &function,
                    &NoConstants,
                    X86_64Abi::Windows,
                )
                .unwrap_err()
                .kind,
                CodegenErrorKind::RuntimeTypeMismatch,
            );
        }
    }

    #[test]
    fn orders_and_clamps_primitive_integers() {
        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: u8, right: u8) -> u8 { left.min(right) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: i16, right: i16) -> i16 { left.max(right) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u32, low: u32, high: u32) -> u32 { input.clamp(low, high) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i64, low: i64, high: i64) -> i64 { input.clamp(low, high) }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 1536, 4, 96>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u32, low: u16, high: u32) -> u32 { input.clamp(low, high) }";
        let module = Parser::new(source).parse_module::<2, 4>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(
            compile_x86_64_function::<_, 1536, 4, 96>(&function, &NoConstants, X86_64Abi::Windows,)
                .unwrap_err()
                .kind,
            CodegenErrorKind::RuntimeTypeMismatch,
        );
    }

    #[test]
    fn divides_integers_toward_positive_infinity() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: u8, right: u8) -> u8 { left.div_ceil(right) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: u16, right: u16) -> u16 { left.div_ceil(right) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: u64, right: u64) -> u64 { left.div_ceil(right) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: usize, right: usize) -> usize { left.div_ceil(right) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: i8, right: i8) -> i8 { left.div_ceil(right) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: i64, right: i64) -> i64 { left.div_ceil(right) }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 1024, 4, 96>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: u8, right: u16) -> u8 { left.div_ceil(right) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: bool, right: bool) -> bool { left.div_ceil(right) }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert_eq!(
                compile_x86_64_function::<_, 1024, 4, 96>(
                    &function,
                    &NoConstants,
                    X86_64Abi::Windows,
                )
                .unwrap_err()
                .kind,
                CodegenErrorKind::RuntimeTypeMismatch,
            );
        }
    }

    #[test]
    fn divides_integers_toward_negative_infinity() {
        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: u8, right: u8) -> u8 { left.div_floor(right) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: u64, right: u64) -> u64 { left.div_floor(right) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: i8, right: i8) -> i8 { left.div_floor(right) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: i64, right: i64) -> i64 { left.div_floor(right) }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 1024, 4, 96>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: u8, right: u16) -> u8 { left.div_floor(right) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: bool, right: bool) -> bool { left.div_floor(right) }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert_eq!(
                compile_x86_64_function::<_, 1024, 4, 96>(
                    &function,
                    &NoConstants,
                    X86_64Abi::Windows,
                )
                .unwrap_err()
                .kind,
                CodegenErrorKind::RuntimeTypeMismatch,
            );
        }
    }

    #[test]
    fn rounds_integers_to_next_multiples() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: u8, right: u8) -> u8 { left.next_multiple_of(right) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: u16, right: u16) -> u16 { left.next_multiple_of(right) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: u64, right: u64) -> u64 { left.next_multiple_of(right) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: usize, right: usize) -> usize { left.next_multiple_of(right) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: i8, right: i8) -> i8 { left.next_multiple_of(right) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: i64, right: i64) -> i64 { left.next_multiple_of(right) }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                for options in [CodegenOptions::CHECKED, CodegenOptions::WRAPPING] {
                    let result = compile_x86_64_function_with_options::<_, 1024, 4, 96>(
                        &function,
                        &NoConstants,
                        abi,
                        options,
                    );
                    assert!(result.is_ok(), "{source}: {result:?}");
                }
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: u8, right: u16) -> u8 { left.next_multiple_of(right) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: bool, right: bool) -> bool { left.next_multiple_of(right) }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert_eq!(
                compile_x86_64_function::<_, 1024, 4, 96>(
                    &function,
                    &NoConstants,
                    X86_64Abi::Windows,
                )
                .unwrap_err()
                .kind,
                CodegenErrorKind::RuntimeTypeMismatch,
            );
        }
    }

    #[test]
    fn rotates_primitive_integer_bits() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u8, distance: u32) -> u8 { input.rotate_left(distance) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i16, distance: u32) -> i16 { input.rotate_right(distance) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u32, distance: u32) -> u32 { input.rotate_left(distance) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i64, distance: u32) -> i64 { input.rotate_right(distance) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: usize, distance: u32) -> usize { input.rotate_left(distance) }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 1024, 4, 96>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u8, distance: u16) -> u8 { input.rotate_left(distance) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: bool, distance: u32) -> bool { input.rotate_right(distance) }",
        ] {
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert_eq!(
                compile_x86_64_function::<_, 768, 2, 80>(
                    &function,
                    &NoConstants,
                    X86_64Abi::Windows,
                )
                .unwrap_err()
                .kind,
                CodegenErrorKind::RuntimeTypeMismatch,
            );
        }
    }

    #[test]
    fn funnels_unsigned_integer_bits() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8, n: u32) -> u8 { a.funnel_shl(b, n) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u16, b: u16, n: u32) -> u16 { a.funnel_shr(b, n) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u64, b: u64, n: u32) -> u64 { a.funnel_shl(b, n) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: usize, b: usize, n: u32) -> usize { a.funnel_shr(b, n) }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<4, 8>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                assert!(
                    compile_x86_64_function::<_, 1024, 8, 96>(&function, &NoConstants, abi).is_ok()
                );
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: i8, b: i8, n: u32) -> i8 { a.funnel_shl(b, n) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u16, n: u32) -> u8 { a.funnel_shr(b, n) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8, n: u16) -> u8 { a.funnel_shl(b, n) }",
        ] {
            let module = Parser::new(source).parse_module::<4, 8>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert!(
                compile_x86_64_function::<_, 1024, 8, 96>(
                    &function,
                    &NoConstants,
                    X86_64Abi::Windows
                )
                .is_err()
            );
        }
    }

    #[test]
    fn converts_integer_signedness_at_the_same_width() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u8) -> i8 { input.cast_signed() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i16) -> u16 { input.cast_unsigned() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u32) -> i32 { input.saturating_cast_signed() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i64) -> u64 { input.saturating_cast_unsigned() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: usize) -> isize { input.strict_cast_signed() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: isize) -> usize { input.strict_cast_unsigned() }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                assert!(
                    compile_x86_64_function::<_, 1024, 4, 96>(&function, &NoConstants, abi).is_ok()
                );
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u8) -> i8 { input.cast_unsigned() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i8) -> u8 { input.cast_signed() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: bool) -> u8 { input.cast_unsigned() }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert!(
                compile_x86_64_function::<_, 1024, 4, 96>(
                    &function,
                    &NoConstants,
                    X86_64Abi::Windows
                )
                .is_err()
            );
        }
    }

    #[test]
    fn widens_and_truncates_primitive_integers() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u32) -> u8 { input.truncate::<u8>() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i64) -> i16 { input.saturating_truncate::<i16>() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u8) -> u64 { input.widen::<u64>() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i8) -> i64 { input.widen::<i64>() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u16) -> usize { input.widen::<usize>() }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                assert!(
                    compile_x86_64_function::<_, 1024, 4, 96>(&function, &NoConstants, abi).is_ok(),
                    "{source}"
                );
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u8) -> u16 { input.truncate::<u16>() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i16) -> i8 { input.widen::<i8>() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u8) -> i16 { input.widen::<i16>() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u32) -> usize { input.widen::<usize>() }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert_eq!(
                compile_x86_64_function::<_, 1024, 4, 96>(
                    &function,
                    &NoConstants,
                    X86_64Abi::Windows,
                )
                .unwrap_err()
                .kind,
                CodegenErrorKind::RuntimeTypeMismatch,
                "{source}"
            );
        }
    }

    #[test]
    fn casts_between_all_primitive_integer_types() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i64) -> u8 { input.saturating_cast::<u8>() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u64) -> i8 { input.saturating_cast::<i8>() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i8) -> u64 { input.wrapping_cast::<u64>() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u64) -> i16 { input.wrapping_cast::<i16>() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i64) -> usize { input.strict_cast::<usize>() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: usize) -> i8 { input.strict_cast::<i8>() }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(input: i64) -> u8 { input.unchecked_cast::<u8>() }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(input: u8) -> i64 { input.unchecked_cast::<i64>() }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                assert!(
                    compile_x86_64_function::<_, 1024, 4, 96>(&function, &NoConstants, abi).is_ok(),
                    "{source}"
                );
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: bool) -> u8 { input.wrapping_cast::<u8>() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u8) -> bool { input.saturating_cast::<u8>() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u8) -> u16 { input.unchecked_cast::<u16>() }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert!(
                compile_x86_64_function::<_, 1024, 4, 96>(
                    &function,
                    &NoConstants,
                    X86_64Abi::Windows,
                )
                .is_err(),
                "{source}"
            );
        }
    }

    #[test]
    fn emits_unchecked_integer_operations_only_in_unsafe_contexts() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8) -> u8 { unsafe { a.unchecked_add(b) } }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, n: u32) -> u8 { unsafe { let value = a; value.unchecked_shl(n) } }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u64, b: u64) -> u64 { unsafe { unsafe { a.unchecked_disjoint_bitor(b) } } }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(a: u8, b: u8) -> u8 { a.unchecked_add(b) }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(a: i16, b: i16) -> i16 { a.unchecked_sub(b) }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(a: u32, b: u32) -> u32 { a.unchecked_mul(b) }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(a: u32, b: u32) -> u32 { a.unchecked_div_exact(b) }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(a: i64, b: i64) -> i64 { a.unchecked_div_exact(b) }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(a: i64) -> i64 { a.unchecked_neg() }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(a: u8, n: u32) -> u8 { a.unchecked_shl(n) }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(a: i64, n: u32) -> i64 { a.unchecked_shr(n) }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(a: u16, n: u32) -> u16 { a.unchecked_shl_exact(n) }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(a: i32, n: u32) -> i32 { a.unchecked_shr_exact(n) }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(a: u8, b: u8, n: u32) -> u8 { a.unchecked_funnel_shl(b, n) }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(a: u64, b: u64, n: u32) -> u64 { a.unchecked_funnel_shr(b, n) }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(a: u64, b: u64) -> u64 { a.unchecked_disjoint_bitor(b) }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 1024, 4, 96>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8) -> u8 { a.unchecked_add(b) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8) -> u8 { (unsafe { a }).unchecked_add(b) }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(a: u8) -> u8 { a.unchecked_add() }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(a: u8, b: u8) -> u8 { a.unchecked_div_exact() }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(a: u8, b: u16) -> u8 { a.unchecked_div_exact(b) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8) -> u8 { a.unchecked_div_exact(b) }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(a: i8) -> i8 { a.unchecked_neg(1) }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(a: u8) -> u8 { a.unchecked_neg() }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(a: i8, b: i8) -> i8 { a.unchecked_disjoint_bitor(b) }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(a: u8, n: u16) -> u8 { a.unchecked_shl(n) }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(a: i8, b: i8, n: u32) -> i8 { a.unchecked_funnel_shl(b, n) }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(a: u8, b: u16, n: u32) -> u8 { a.unchecked_funnel_shr(b, n) }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(a: u8, b: u8, n: u16) -> u8 { a.unchecked_funnel_shr(b, n) }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(a: u8, n: u32) -> u8 { a.unchecked_funnel_shr(n) }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert!(
                compile_x86_64_function::<_, 1024, 4, 96>(
                    &function,
                    &NoConstants,
                    X86_64Abi::Windows,
                )
                .is_err(),
                "{source}"
            );
        }
    }

    #[test]
    fn consumes_checked_exact_division_options_with_unwrap_or() {
        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u32, b: u32, fallback: u32) -> u32 { a.checked_div_exact(b).unwrap_or(fallback) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: i64, b: i64, fallback: i64) -> i64 { a.checked_div_exact(b).unwrap_or(fallback) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u16, b: u16) -> u16 { a.checked_div_exact(b).unwrap_or_default() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u64, b: u64) -> bool { a.checked_div_exact(b).is_some() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: i32, b: i32) -> bool { a.checked_div_exact(b).is_none() }",
        ] {
            let module = Parser::new(source).parse_module::<4, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 1024, 4, 96>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u16) -> u8 { a.checked_div_exact(b).unwrap_or(0) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8) -> u8 { a.checked_div_exact(b) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8) -> bool { a.checked_div_exact(b).unwrap_or(0) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u16) -> bool { a.checked_div_exact(b).is_some() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8) -> u8 { a.checked_div_exact(b).is_none() }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert!(
                compile_x86_64_function::<_, 1024, 4, 96>(
                    &function,
                    &NoConstants,
                    X86_64Abi::SystemV,
                )
                .is_err(),
                "{source}"
            );
        }
    }

    #[test]
    fn consumes_checked_arithmetic_options() {
        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8, fallback: u8) -> u8 { a.checked_add(b).unwrap_or(fallback) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: i16, b: i16) -> i16 { a.checked_sub(b).unwrap_or_default() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u32, b: u32) -> bool { a.checked_mul(b).is_some() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: i64, b: i64) -> bool { a.checked_mul(b).is_none() }",
        ] {
            let module = Parser::new(source).parse_module::<4, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 1024, 4, 96>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u16) -> u8 { a.checked_add(b).unwrap_or_default() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: i32, b: i32, fallback: u32) -> i32 { a.checked_sub(b).unwrap_or(fallback) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u64, b: u64) -> u64 { a.checked_mul(b) }",
        ] {
            let module = Parser::new(source).parse_module::<3, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert!(
                compile_x86_64_function::<_, 1024, 4, 96>(
                    &function,
                    &NoConstants,
                    X86_64Abi::SystemV,
                )
                .is_err(),
                "{source}"
            );
        }
    }

    #[test]
    fn consumes_checked_unsigned_mixed_arithmetic_options() {
        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: i8, fallback: u8) -> u8 { a.checked_add_signed(b).unwrap_or(fallback) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u64, b: i64) -> u64 { a.checked_sub_signed(b).unwrap_or_default() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: usize, b: isize) -> bool { a.checked_add_signed(b).is_some() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u16, b: i16) -> bool { a.checked_sub_signed(b).is_none() }",
        ] {
            let module = Parser::new(source).parse_module::<4, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 1024, 4, 96>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: i16) -> u8 { a.checked_add_signed(b).unwrap_or_default() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: i32, b: u32) -> bool { a.checked_sub_signed(b).is_some() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u64, b: i64) -> u64 { a.checked_add_signed(b) }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert!(
                compile_x86_64_function::<_, 1024, 4, 96>(
                    &function,
                    &NoConstants,
                    X86_64Abi::SystemV,
                )
                .is_err(),
                "{source}"
            );
        }
    }

    #[test]
    fn consumes_checked_signed_difference_options() {
        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8, fallback: i8) -> i8 { a.checked_signed_diff(b).unwrap_or(fallback) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u64, b: u64) -> i64 { a.checked_signed_diff(b).unwrap_or_default() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: usize, b: usize) -> bool { a.checked_signed_diff(b).is_some() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u16, b: u16) -> bool { a.checked_signed_diff(b).is_none() }",
        ] {
            let module = Parser::new(source).parse_module::<4, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 1024, 4, 96>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u16) -> i8 { a.checked_signed_diff(b).unwrap_or_default() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: i32, b: i32) -> i32 { a.checked_signed_diff(b).unwrap_or_default() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u64, b: u64) -> i64 { a.checked_signed_diff(b) }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert!(
                compile_x86_64_function::<_, 1024, 4, 96>(
                    &function,
                    &NoConstants,
                    X86_64Abi::SystemV,
                )
                .is_err(),
                "{source}"
            );
        }
    }

    #[test]
    fn consumes_checked_signed_mixed_arithmetic_options() {
        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: i8, b: u8, fallback: i8) -> i8 { a.checked_add_unsigned(b).unwrap_or(fallback) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: i64, b: u64) -> i64 { a.checked_sub_unsigned(b).unwrap_or_default() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: isize, b: usize) -> bool { a.checked_add_unsigned(b).is_some() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: i16, b: u16) -> bool { a.checked_sub_unsigned(b).is_none() }",
        ] {
            let module = Parser::new(source).parse_module::<4, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 1024, 4, 96>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: i8, b: u16) -> i8 { a.checked_add_unsigned(b).unwrap_or_default() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u32, b: i32) -> bool { a.checked_sub_unsigned(b).is_some() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: i64, b: u64) -> i64 { a.checked_add_unsigned(b) }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert!(
                compile_x86_64_function::<_, 1024, 4, 96>(
                    &function,
                    &NoConstants,
                    X86_64Abi::SystemV,
                )
                .is_err(),
                "{source}"
            );
        }
    }

    #[test]
    fn consumes_checked_division_and_remainder_options() {
        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u32, b: u32, fallback: u32) -> u32 { a.checked_div(b).unwrap_or(fallback) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: i64, b: i64) -> i64 { a.checked_rem(b).unwrap_or_default() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: i16, b: i16) -> bool { a.checked_div(b).is_some() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8) -> bool { a.checked_rem(b).is_none() }",
        ] {
            let module = Parser::new(source).parse_module::<4, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 1024, 4, 96>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u16) -> u8 { a.checked_div(b).unwrap_or_default() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: i32, b: i32, fallback: u32) -> i32 { a.checked_rem(b).unwrap_or(fallback) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u64, b: u64) -> u64 { a.checked_div(b) }",
        ] {
            let module = Parser::new(source).parse_module::<3, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert!(
                compile_x86_64_function::<_, 1024, 4, 96>(
                    &function,
                    &NoConstants,
                    X86_64Abi::SystemV,
                )
                .is_err(),
                "{source}"
            );
        }
    }

    #[test]
    fn consumes_checked_euclidean_division_options() {
        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: i64, b: i64, fallback: i64) -> i64 { a.checked_div_euclid(b).unwrap_or(fallback) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: i16, b: i16) -> i16 { a.checked_rem_euclid(b).unwrap_or_default() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u32, b: u32) -> bool { a.checked_div_euclid(b).is_some() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8) -> bool { a.checked_rem_euclid(b).is_none() }",
        ] {
            let module = Parser::new(source).parse_module::<4, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 1024, 4, 96>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u16) -> u8 { a.checked_div_euclid(b).unwrap_or_default() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: i32, b: i32, fallback: u32) -> i32 { a.checked_rem_euclid(b).unwrap_or(fallback) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u64, b: u64) -> u64 { a.checked_div_euclid(b) }",
        ] {
            let module = Parser::new(source).parse_module::<3, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert!(
                compile_x86_64_function::<_, 1024, 4, 96>(
                    &function,
                    &NoConstants,
                    X86_64Abi::SystemV,
                )
                .is_err(),
                "{source}"
            );
        }
    }

    #[test]
    fn consumes_checked_signed_unary_options() {
        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: i8, fallback: i8) -> i8 { a.checked_neg().unwrap_or(fallback) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: i64) -> i64 { a.checked_abs().unwrap_or_default() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: isize) -> bool { a.checked_neg().is_some() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: i16) -> bool { a.checked_abs().is_none() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, fallback: u8) -> u8 { a.checked_neg().unwrap_or(fallback) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u64) -> bool { a.checked_neg().is_some() }",
        ] {
            let module = Parser::new(source).parse_module::<3, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 1024, 4, 96>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u32) -> bool { a.checked_abs().is_some() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: i64) -> i64 { a.checked_neg() }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert!(
                compile_x86_64_function::<_, 1024, 4, 96>(
                    &function,
                    &NoConstants,
                    X86_64Abi::SystemV,
                )
                .is_err(),
                "{source}"
            );
        }
    }

    #[test]
    fn consumes_checked_shift_options() {
        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, n: u32, fallback: u8) -> u8 { a.checked_shl(n).unwrap_or(fallback) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: i64, n: u32) -> i64 { a.checked_shr(n).unwrap_or_default() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: i16, n: u32) -> bool { a.checked_shl(n).is_some() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u32, n: u32) -> bool { a.checked_shr(n).is_none() }",
        ] {
            let module = Parser::new(source).parse_module::<4, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 1024, 4, 96>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, n: u16) -> u8 { a.checked_shl(n).unwrap_or_default() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: i32, n: i32) -> bool { a.checked_shr(n).is_some() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u64, n: u32) -> u64 { a.checked_shl(n) }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert!(
                compile_x86_64_function::<_, 1024, 4, 96>(
                    &function,
                    &NoConstants,
                    X86_64Abi::SystemV,
                )
                .is_err(),
                "{source}"
            );
        }
    }

    #[test]
    fn consumes_checked_power_options() {
        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, n: u32, fallback: u8) -> u8 { a.checked_pow(n).unwrap_or(fallback) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: i64, n: u32) -> i64 { a.checked_pow(n).unwrap_or_default() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: i16, n: u32) -> bool { a.checked_pow(n).is_some() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u32, n: u32) -> bool { a.checked_pow(n).is_none() }",
        ] {
            let module = Parser::new(source).parse_module::<4, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 2048, 4, 96>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, n: u16) -> u8 { a.checked_pow(n).unwrap_or_default() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: i32, n: i32) -> bool { a.checked_pow(n).is_some() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u64, n: u32) -> u64 { a.checked_pow(n) }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert!(
                compile_x86_64_function::<_, 2048, 4, 96>(
                    &function,
                    &NoConstants,
                    X86_64Abi::SystemV,
                )
                .is_err(),
                "{source}"
            );
        }
    }

    #[test]
    fn consumes_checked_next_power_of_two_options() {
        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, fallback: u8) -> u8 { a.checked_next_power_of_two().unwrap_or(fallback) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u64) -> u64 { a.checked_next_power_of_two().unwrap_or_default() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: usize) -> bool { a.checked_next_power_of_two().is_some() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u16) -> bool { a.checked_next_power_of_two().is_none() }",
        ] {
            let module = Parser::new(source).parse_module::<3, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 1024, 4, 96>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: i8) -> i8 { a.checked_next_power_of_two().unwrap_or_default() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: i64) -> bool { a.checked_next_power_of_two().is_some() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u64) -> u64 { a.checked_next_power_of_two() }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert!(
                compile_x86_64_function::<_, 1024, 4, 96>(
                    &function,
                    &NoConstants,
                    X86_64Abi::SystemV,
                )
                .is_err(),
                "{source}"
            );
        }
    }

    #[test]
    fn consumes_checked_integer_square_root_options() {
        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: i8, fallback: i8) -> i8 { a.checked_isqrt().unwrap_or(fallback) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: i64) -> i64 { a.checked_isqrt().unwrap_or_default() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: isize) -> bool { a.checked_isqrt().is_some() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: i16) -> bool { a.checked_isqrt().is_none() }",
        ] {
            let module = Parser::new(source).parse_module::<3, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 2048, 4, 96>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8) -> u8 { a.checked_isqrt().unwrap_or_default() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u64) -> bool { a.checked_isqrt().is_some() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: i64) -> i64 { a.checked_isqrt() }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert!(
                compile_x86_64_function::<_, 2048, 4, 96>(
                    &function,
                    &NoConstants,
                    X86_64Abi::SystemV,
                )
                .is_err(),
                "{source}"
            );
        }
    }

    #[test]
    fn consumes_checked_next_multiple_options() {
        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8, fallback: u8) -> u8 { a.checked_next_multiple_of(b).unwrap_or(fallback) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: i64, b: i64) -> i64 { a.checked_next_multiple_of(b).unwrap_or_default() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: i16, b: i16) -> bool { a.checked_next_multiple_of(b).is_some() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u32, b: u32) -> bool { a.checked_next_multiple_of(b).is_none() }",
        ] {
            let module = Parser::new(source).parse_module::<4, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 1536, 4, 96>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u16) -> u8 { a.checked_next_multiple_of(b).unwrap_or_default() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: i32, b: i32, fallback: u32) -> i32 { a.checked_next_multiple_of(b).unwrap_or(fallback) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u64, b: u64) -> u64 { a.checked_next_multiple_of(b) }",
        ] {
            let module = Parser::new(source).parse_module::<3, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert!(
                compile_x86_64_function::<_, 1536, 4, 96>(
                    &function,
                    &NoConstants,
                    X86_64Abi::SystemV,
                )
                .is_err(),
                "{source}"
            );
        }
    }

    #[test]
    fn consumes_checked_logarithm_options() {
        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u64, radix: u64, fallback: u32) -> u32 { a.checked_ilog(radix).unwrap_or(fallback) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: i16) -> u32 { a.checked_ilog2().unwrap_or_default() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8) -> bool { a.checked_ilog10().is_some() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: i64, radix: i64) -> bool { a.checked_ilog(radix).is_none() }",
        ] {
            let module = Parser::new(source).parse_module::<4, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 1024, 4, 96>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, radix: u16) -> u32 { a.checked_ilog(radix).unwrap_or_default() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u64, fallback: u64) -> u32 { a.checked_ilog2().unwrap_or(fallback) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: i64) -> u32 { a.checked_ilog10() }",
        ] {
            let module = Parser::new(source).parse_module::<3, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert!(
                compile_x86_64_function::<_, 1024, 4, 96>(
                    &function,
                    &NoConstants,
                    X86_64Abi::SystemV,
                )
                .is_err(),
                "{source}"
            );
        }
    }

    #[test]
    fn consumes_generic_checked_cast_options() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u16, fallback: u8) -> u8 { input.checked_cast::<u8>().unwrap_or(fallback) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i64) -> u32 { input.checked_cast::<u32>().unwrap_or_default() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u64) -> bool { input.checked_cast::<i32>().is_some() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i8) -> bool { input.checked_cast::<u64>().is_none() }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<3, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 1024, 4, 96>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u16, fallback: u16) -> u8 { input.checked_cast::<u8>().unwrap_or(fallback) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u16) -> u8 { input.checked_cast::<u8>() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: bool) -> bool { input.checked_cast::<u8>().is_some() }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert!(
                compile_x86_64_function::<_, 1024, 4, 96>(
                    &function,
                    &NoConstants,
                    X86_64Abi::SystemV,
                )
                .is_err(),
                "{source}"
            );
        }
    }

    #[test]
    fn consumes_generic_checked_truncation_options() {
        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u32, fallback: u8) -> u8 { input.checked_truncate::<u8>().unwrap_or(fallback) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i64) -> i16 { input.checked_truncate::<i16>().unwrap_or_default() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u64) -> bool { input.checked_truncate::<u32>().is_some() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i16) -> bool { input.checked_truncate::<i8>().is_none() }",
        ] {
            let module = Parser::new(source).parse_module::<3, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 1024, 4, 96>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u16) -> i8 { input.checked_truncate::<i8>().unwrap_or_default() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u8) -> u16 { input.checked_truncate::<u16>().unwrap_or_default() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i64, fallback: i32) -> i16 { input.checked_truncate::<i16>().unwrap_or(fallback) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u64) -> u32 { input.checked_truncate::<u32>() }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert!(
                compile_x86_64_function::<_, 1024, 4, 96>(
                    &function,
                    &NoConstants,
                    X86_64Abi::SystemV
                )
                .is_err(),
                "{source}"
            );
        }
    }

    #[test]
    fn unwraps_checked_integer_options_or_traps() {
        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8) -> u8 { a.checked_add(b).unwrap() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: i64, b: i64) -> i64 { a.checked_div(b).unwrap() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u64, b: u64) -> i64 { a.checked_signed_diff(b).unwrap() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i64) -> i16 { input.checked_truncate::<i16>().unwrap() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u64) -> u32 { input.checked_ilog2().unwrap() }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 1024, 4, 96>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8) -> u8 { a.unwrap() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8) -> bool { a.checked_add(b).unwrap() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8) -> u8 { a.checked_add(b) }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert!(
                compile_x86_64_function::<_, 1024, 4, 96>(
                    &function,
                    &NoConstants,
                    X86_64Abi::SystemV,
                )
                .is_err(),
                "{source}"
            );
        }
    }

    #[test]
    fn expects_checked_integer_options_or_traps() {
        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8) -> u8 { a.checked_add(b).expect(\"checked addition overflowed\") }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8, message: &str) -> u8 { a.checked_add(b).expect(message) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u64, b: u64, message: &str) -> i64 { a.checked_signed_diff(b).expect(message) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i64, message: &mut str) -> i16 { input.checked_truncate::<i16>().expect(message) }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 1024, 4, 96>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8) -> u8 { a.checked_add(b).expect() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8, message: u8) -> u8 { a.checked_add(b).expect(message) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, message: &str) -> u8 { a.expect(message) }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert!(
                compile_x86_64_function::<_, 1024, 4, 96>(
                    &function,
                    &NoConstants,
                    X86_64Abi::SystemV,
                )
                .is_err(),
                "{source}"
            );
        }
    }

    #[test]
    fn unwraps_checked_integer_options_unchecked_in_unsafe_functions() {
        for source in [
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(a: u8, b: u8) -> u8 { a.checked_add(b).unwrap_unchecked() }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(a: u64, b: u64) -> i64 { a.checked_signed_diff(b).unwrap_unchecked() }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(input: i64) -> i16 { input.checked_truncate::<i16>().unwrap_unchecked() }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 1024, 4, 96>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8) -> u8 { a.checked_add(b).unwrap_unchecked() }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(a: u8, b: u8) -> bool { a.checked_add(b).unwrap_unchecked() }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(a: u8) -> u8 { a.unwrap_unchecked() }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert!(
                compile_x86_64_function::<_, 1024, 4, 96>(
                    &function,
                    &NoConstants,
                    X86_64Abi::SystemV,
                )
                .is_err(),
                "{source}"
            );
        }
    }

    #[test]
    fn lazily_unwraps_checked_integer_options_with_zero_argument_closures() {
        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8, fallback: u8) -> u8 { a.checked_add(b).unwrap_or_else(|| fallback) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: i64, b: i64) -> i64 { a.checked_div(b).unwrap_or_else(|| -1) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i64, fallback: i16) -> i16 { input.checked_truncate::<i16>().unwrap_or_else(|| fallback) }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 1024, 4, 96>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8, fallback: u8) -> u8 { a.checked_add(b).unwrap_or_else(fallback) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8) -> u8 { a.checked_add(b).unwrap_or_else(|| true) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(fallback: u8) -> u8 { || fallback }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert!(
                compile_x86_64_function::<_, 1024, 4, 96>(
                    &function,
                    &NoConstants,
                    X86_64Abi::SystemV,
                )
                .is_err(),
                "{source}"
            );
        }
    }

    #[test]
    fn predicates_checked_integer_options_with_one_argument_closures() {
        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8, threshold: u8) -> bool { a.checked_add(b).is_some_and(|value| value > threshold) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i64, expected: i16) -> bool { input.checked_truncate::<i16>().is_some_and(|value| value == expected) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u64, b: u64) -> bool { a.checked_signed_diff(b).is_none_or(|value| value >= -10) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u64) -> bool { input.checked_ilog2().is_some_and(|value| value < 64) }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 2048, 4, 128>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8) -> bool { a.checked_add(b).is_some_and(|| true) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8, predicate: bool) -> bool { a.checked_add(b).is_some_and(predicate) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8) -> bool { a.checked_add(b).is_none_or(|value| value) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u8) -> bool { |value| value == input }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert!(
                compile_x86_64_function::<_, 2048, 4, 128>(
                    &function,
                    &NoConstants,
                    X86_64Abi::SystemV,
                )
                .is_err(),
                "{source}"
            );
        }
    }

    #[test]
    fn filters_checked_integer_options_with_borrowed_predicates() {
        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8, threshold: u8) -> bool { a.checked_add(b).filter(|value| *value > threshold).is_some() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i64, expected: i16) -> bool { input.checked_truncate::<i16>().filter(|value| *value == expected).is_none() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u64, b: u64) -> bool { a.checked_signed_diff(b).filter(|value| *value >= -10).is_some() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u64) -> bool { input.checked_ilog2().filter(|value| *value < 64).is_none() }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 3072, 4, 176>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8) -> bool { a.checked_add(b).filter(|value| value > 0).is_some() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8) -> bool { a.checked_add(b).filter(|| true).is_some() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8) -> bool { a.checked_add(b).filter(|value| *value).is_some() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8, predicate: bool) -> bool { a.checked_add(b).filter(predicate).is_some() }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert!(
                compile_x86_64_function::<_, 3072, 4, 176>(
                    &function,
                    &NoConstants,
                    X86_64Abi::SystemV,
                )
                .is_err(),
                "{source}"
            );
        }
    }

    #[test]
    fn consumes_filtered_checked_integer_options() {
        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8, threshold: u8) -> u8 { a.checked_add(b).filter(|value| *value > threshold).unwrap_or_default() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i64, expected: i16, fallback: i16) -> i16 { input.checked_truncate::<i16>().filter(|value| *value == expected).unwrap_or(fallback) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u64, b: u64, fallback: i64) -> i64 { a.checked_signed_diff(b).filter(|value| *value >= -10).unwrap_or_else(|| fallback) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u64) -> u32 { input.checked_ilog2().filter(|value| *value < 64).unwrap() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8) -> u8 { a.checked_add(b).filter(|value| *value > 0).expect(\"positive\") }",
            "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn value(a: u8, b: u8) -> u8 { a.checked_add(b).filter(|value| *value > 0).unwrap_unchecked() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8, threshold: u8) -> bool { a.checked_add(b).filter(|value| *value > threshold).is_some_and(|value| value < 200) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8, threshold: u8, fallback: u32) -> u32 { a.checked_add(b).filter(|value| *value > threshold).map_or(fallback, |value| value as u32 * 2) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8, threshold: u8, fallback: u32) -> u32 { a.checked_add(b).filter(|value| *value > threshold).map_or_else(|| fallback, |value| value as u32 * 2) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8, low: u8, high: u8) -> u32 { a.checked_add(b).filter(|value| *value > low).filter(|value| *value < high).map_or_default(|value| value as u32) }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 4096, 4, 224>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }
    }

    #[test]
    fn composes_mapped_checked_integer_options() {
        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8, offset: u32) -> u32 { a.checked_add(b).map(|value| value as u32 + offset).unwrap_or_default() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i64, fallback: u16) -> u16 { input.checked_truncate::<i16>().map(|value| value as u16).unwrap_or(fallback) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8, low: u32) -> u64 { a.checked_add(b).map(|value| value as u32 * 2).filter(|value| *value > low).map(|value| value as u64 + 1).map_or_default(|value| value) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8) -> bool { a.checked_add(b).map(|value| value as u64 + 1).is_some_and(|value| value < 200) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8, fallback: i64) -> i64 { a.checked_add(b).map(|value| value as i64 - 20).map_or_else(|| fallback, |value| value * 2) }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 4096, 4, 224>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8) -> u8 { a.checked_add(b).map(|value| value > 0).unwrap_or_default() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8) -> u32 { a.checked_add(b).map(|| 1u32).unwrap_or_default() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8) -> u32 { a.checked_add(b).map(|value| value as u32).unwrap_or(1u8) }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert_eq!(
                compile_x86_64_function::<_, 4096, 4, 224>(
                    &function,
                    &NoConstants,
                    X86_64Abi::Windows,
                )
                .unwrap_err()
                .kind,
                CodegenErrorKind::RuntimeTypeMismatch,
                "{source}"
            );
        }
    }

    #[test]
    fn inspects_checked_integer_options_without_changing_them() {
        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8) -> u8 { a.checked_add(b).inspect(|value| ()).unwrap_or_default() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8, threshold: u32) -> u64 { a.checked_add(b).map(|value| value as u32 * 2).inspect(|value| if *value > threshold { () } else { () }).filter(|value| *value > threshold).map(|value| value as u64 + 1).unwrap_or_default() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i64) -> bool { input.checked_truncate::<i16>().inspect(|value| ()).is_some_and(|value| value >= 0) }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 4096, 4, 224>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8) -> u8 { a.checked_add(b).inspect(|value| *value).unwrap_or_default() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8) -> u8 { a.checked_add(b).inspect(|| ()).unwrap_or_default() }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert_eq!(
                compile_x86_64_function::<_, 4096, 4, 224>(
                    &function,
                    &NoConstants,
                    X86_64Abi::Windows,
                )
                .unwrap_err()
                .kind,
                CodegenErrorKind::RuntimeTypeMismatch,
                "{source}"
            );
        }
    }

    #[test]
    fn chains_checked_integer_options_lazily() {
        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8, limit: u8) -> u16 { a.checked_add(b).and_then(|sum| sum.checked_mul(limit)).map(|value| value as u16).unwrap_or_default() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u64, b: u64) -> bool { a.checked_signed_diff(b).and_then(|difference| difference.checked_abs()).is_some() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i64, divisor: i16, fallback: i16) -> i16 { input.checked_truncate::<i16>().and_then(|value| value.checked_div(divisor)).unwrap_or(fallback) }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 4096, 4, 192>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8) -> u8 { a.checked_add(b).and_then(|value| value + 1).unwrap_or_default() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8) -> u8 { a.checked_add(b).and_then(|| a.checked_add(b)).unwrap_or_default() }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert!(
                compile_x86_64_function::<_, 4096, 4, 192>(
                    &function,
                    &NoConstants,
                    X86_64Abi::SystemV,
                )
                .is_err(),
                "{source}"
            );
        }
    }

    #[test]
    fn recovers_checked_integer_options_lazily() {
        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8, fallback: u8) -> u8 { a.checked_add(b).or_else(|| fallback.checked_add(1)).unwrap_or_default() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u64, b: u64, fallback: i64) -> bool { a.checked_signed_diff(b).or_else(|| fallback.checked_abs()).is_some() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8) -> u8 { a.checked_add(b).or_else(|| 1u8.checked_div(0)).unwrap_or_default() }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 4096, 4, 192>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8, fallback: u16) -> u8 { a.checked_add(b).or_else(|| fallback.checked_add(1)).unwrap_or_default() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8) -> u8 { a.checked_add(b).or_else(|value| value.checked_add(1)).unwrap_or_default() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8) -> u8 { a.checked_add(b).or_else(|| 1u8).unwrap_or_default() }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert!(
                compile_x86_64_function::<_, 4096, 4, 192>(
                    &function,
                    &NoConstants,
                    X86_64Abi::SystemV,
                )
                .is_err(),
                "{source}"
            );
        }
    }

    #[test]
    fn selects_the_first_checked_integer_option_eagerly() {
        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8, fallback: u8) -> u8 { a.checked_add(b).or(fallback.checked_add(1)).unwrap_or_default() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: i64, b: i64, fallback: i64) -> i64 { a.checked_mul(b).or(fallback.checked_abs()).map(|value| value + 1).unwrap_or_default() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u64, b: u64, fallback: i64) -> bool { a.checked_signed_diff(b).or(fallback.checked_abs()).is_none() }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 4096, 4, 192>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8, fallback: u16) -> u8 { a.checked_add(b).or(fallback.checked_add(1)).unwrap_or_default() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8) -> u8 { a.checked_add(b).or(1u8).unwrap_or_default() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8) -> u8 { a.checked_add(b).or().unwrap_or_default() }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert!(
                compile_x86_64_function::<_, 4096, 4, 192>(
                    &function,
                    &NoConstants,
                    X86_64Abi::SystemV,
                )
                .is_err(),
                "{source}"
            );
        }
    }

    #[test]
    fn selects_exactly_one_checked_integer_option_eagerly() {
        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8, fallback: u8) -> u8 { a.checked_add(b).xor(fallback.checked_add(1)).unwrap_or_default() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: i64, b: i64, fallback: i64) -> i64 { a.checked_mul(b).xor(fallback.checked_abs()).map(|value| value + 1).unwrap_or_default() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u64, b: u64, fallback: i64) -> bool { a.checked_signed_diff(b).xor(fallback.checked_abs()).is_none() }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let code = compile_x86_64_function::<_, 4096, 4, 192>(&function, &NoConstants, abi)
                    .unwrap_or_else(|error| panic!("{source}: {error:?}"));
                assert!(
                    code.bytes()
                        .windows(4)
                        .any(|bytes| bytes == [0x45, 0x31, 0xc0, 0xe9]),
                    "both-Some must clear validity and skip left-only selection: {source}"
                );
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8, fallback: u16) -> u8 { a.checked_add(b).xor(fallback.checked_add(1)).unwrap_or_default() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8) -> u8 { a.checked_add(b).xor(1u8).unwrap_or_default() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8) -> u8 { a.checked_add(b).xor().unwrap_or_default() }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert!(
                compile_x86_64_function::<_, 4096, 4, 192>(
                    &function,
                    &NoConstants,
                    X86_64Abi::SystemV,
                )
                .is_err(),
                "{source}"
            );
        }
    }

    #[test]
    fn sequences_checked_integer_options_eagerly() {
        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8, fallback: u16) -> u16 { a.checked_add(b).and(fallback.checked_mul(1000)).unwrap_or_default() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: i8, b: i8, fallback: i64) -> i64 { a.checked_mul(b).and(fallback.checked_abs()).map(|value| value + 1).unwrap_or_default() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u64, b: u64, fallback: i16) -> bool { a.checked_signed_diff(b).and(fallback.checked_abs()).is_some_and(|value| value > 10) }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 4096, 4, 192>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8) -> u8 { a.checked_add(b).and(1u8).unwrap_or_default() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8) -> u8 { a.checked_add(b).and().unwrap_or_default() }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert!(
                compile_x86_64_function::<_, 4096, 4, 192>(
                    &function,
                    &NoConstants,
                    X86_64Abi::SystemV,
                )
                .is_err(),
                "{source}"
            );
        }
    }

    #[test]
    fn constructs_integer_options_from_booleans() {
        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(flag: bool, value: u16, fallback: u16) -> u16 { flag.then_some(value).unwrap_or(fallback) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(flag: bool, numerator: i64, divisor: i64) -> i64 { flag.then(|| numerator / divisor).unwrap_or_default() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(flag: bool, value: u8) -> u32 { flag.then_some(value).map(|present| present as u32 + 1).unwrap_or_default() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(flag: bool, value: i16) -> bool { flag.then(|| value).is_some_and(|present| present > 10) }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 4096, 4, 192>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(flag: u8, value: u8) -> u8 { flag.then_some(value).unwrap_or_default() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(flag: bool) -> bool { flag.then_some(true).unwrap_or_default() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(flag: bool, value: u8) -> u8 { flag.then(|ignored| value).unwrap_or_default() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(flag: bool, value: u8) -> u8 { flag.then(value).unwrap_or_default() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(flag: bool) -> u8 { flag.then_some().unwrap_or_default() }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert!(
                compile_x86_64_function::<_, 4096, 4, 192>(
                    &function,
                    &NoConstants,
                    X86_64Abi::SystemV,
                )
                .is_err(),
                "{source}"
            );
        }
    }

    #[test]
    fn maps_checked_integer_options_with_eager_defaults_and_lazy_closures() {
        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8, offset: u32) -> u32 { a.checked_add(b).map_or(99u32, |value| value as u32 + offset) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u64, b: u64, threshold: i64) -> bool { a.checked_signed_diff(b).map_or(false, |value| value < threshold) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i64, fallback: i64) -> i64 { input.checked_truncate::<i16>().map_or(fallback, |value| value as i64 * 2) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u64) -> char { input.checked_ilog2().map_or('x', |value| if value > 3 { 'y' } else { 'z' }) }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 3072, 4, 160>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8) -> u32 { a.checked_add(b).map_or(0u32, || 1u32) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8) -> u32 { a.checked_add(b).map_or(0u32, |value| value > 0) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8) -> u32 { a.checked_add(b).map_or(0u32) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8, mapper: u32) -> u32 { a.checked_add(b).map_or(0u32, mapper) }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert!(
                compile_x86_64_function::<_, 3072, 4, 160>(
                    &function,
                    &NoConstants,
                    X86_64Abi::SystemV,
                )
                .is_err(),
                "{source}"
            );
        }
    }

    #[test]
    fn maps_checked_integer_options_with_two_lazy_closures() {
        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8, fallback: u32, offset: u32) -> u32 { a.checked_add(b).map_or_else(|| fallback, |value| value as u32 + offset) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u64, b: u64, fallback: bool, threshold: i64) -> bool { a.checked_signed_diff(b).map_or_else(|| fallback, |value| value < threshold) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i64, fallback: i64) -> i64 { input.checked_truncate::<i16>().map_or_else(|| fallback, |value| value as i64 * 2) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u64) -> char { input.checked_ilog2().map_or_else(|| 'x', |value| if value > 3 { 'y' } else { 'z' }) }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 3584, 4, 192>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8) -> u32 { a.checked_add(b).map_or_else(|value| value as u32, |value| value as u32) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8) -> u32 { a.checked_add(b).map_or_else(|| 0u32, || 1u32) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8) -> u32 { a.checked_add(b).map_or_else(|| false, |value| value as u32) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8) -> u32 { a.checked_add(b).map_or_else(|| 0u32) }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert!(
                compile_x86_64_function::<_, 3584, 4, 192>(
                    &function,
                    &NoConstants,
                    X86_64Abi::SystemV,
                )
                .is_err(),
                "{source}"
            );
        }
    }

    #[test]
    fn maps_checked_integer_options_with_default_results() {
        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8, offset: u32) -> u32 { a.checked_add(b).map_or_default(|value| value as u32 + offset) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u64, b: u64, threshold: i64) -> bool { a.checked_signed_diff(b).map_or_default(|value| value < threshold) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i64) -> i64 { input.checked_truncate::<i16>().map_or_default(|value| value as i64 * 2) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u64) -> char { input.checked_ilog2().map_or_default(|value| if value > 3 { 'y' } else { 'z' }) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u64) -> *const u8 { input.checked_ilog2().map_or_default(|value| value as usize as *const u8) }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 3072, 4, 176>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8) -> u32 { a.checked_add(b).map_or_default(|| 1u32) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8, mapper: u32) -> u32 { a.checked_add(b).map_or_default(mapper) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8, fallback: u32) -> &u32 { a.checked_add(b).map_or_default(|_| &fallback) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(a: u8, b: u8) -> u32 { a.checked_add(b).map_or_default() }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert!(
                compile_x86_64_function::<_, 3072, 4, 176>(
                    &function,
                    &NoConstants,
                    X86_64Abi::SystemV,
                )
                .is_err(),
                "{source}"
            );
        }
    }

    #[test]
    fn consumes_checked_same_width_sign_cast_options() {
        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u32, fallback: i32) -> i32 { input.checked_cast_signed().unwrap_or(fallback) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i64) -> u64 { input.checked_cast_unsigned().unwrap_or_default() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u16) -> bool { input.checked_cast_signed().is_some() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i8) -> bool { input.checked_cast_unsigned().is_none() }",
        ] {
            let module = Parser::new(source).parse_module::<3, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                assert!(
                    compile_x86_64_function::<_, 1024, 4, 96>(&function, &NoConstants, abi,)
                        .is_ok(),
                    "{source}"
                );
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i32) -> bool { input.checked_cast_signed().is_some() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u32) -> bool { input.checked_cast_unsigned().is_some() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u32, fallback: u32) -> i32 { input.checked_cast_signed().unwrap_or(fallback) }",
        ] {
            let module = Parser::new(source).parse_module::<3, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert!(
                compile_x86_64_function::<_, 1024, 4, 96>(
                    &function,
                    &NoConstants,
                    X86_64Abi::SystemV,
                )
                .is_err(),
                "{source}"
            );
        }
    }

    #[test]
    fn clamps_signed_integer_magnitudes() {
        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i8, limit: u8) -> i8 { input.clamp_magnitude(limit) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i16, limit: u16) -> i16 { input.clamp_magnitude(limit) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i64, limit: u64) -> i64 { input.clamp_magnitude(limit) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: isize, limit: usize) -> isize { input.clamp_magnitude(limit) }",
        ] {
            let module = Parser::new(source).parse_module::<3, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 1024, 4, 96>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u8, limit: u8) -> u8 { input.clamp_magnitude(limit) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i8, limit: i8) -> i8 { input.clamp_magnitude(limit) }",
        ] {
            let module = Parser::new(source).parse_module::<3, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert!(
                compile_x86_64_function::<_, 1024, 4, 96>(
                    &function,
                    &NoConstants,
                    X86_64Abi::Windows
                )
                .is_err()
            );
        }
    }

    #[test]
    fn wraps_primitive_integer_shifts() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u8, distance: u32) -> u8 { input.wrapping_shl(distance) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i16, distance: u32) -> i16 { input.wrapping_shr(distance) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u32, distance: u32) -> u32 { input.wrapping_shr(distance) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i64, distance: u32) -> i64 { input.wrapping_shl(distance) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: usize, distance: u32) -> usize { input.wrapping_shr(distance) }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 1024, 4, 96>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u8, distance: u16) -> u8 { input.wrapping_shl(distance) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: bool, distance: u32) -> bool { input.wrapping_shr(distance) }",
        ] {
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert_eq!(
                compile_x86_64_function::<_, 768, 2, 80>(
                    &function,
                    &NoConstants,
                    X86_64Abi::Windows,
                )
                .unwrap_err()
                .kind,
                CodegenErrorKind::RuntimeTypeMismatch,
            );
        }
    }

    #[test]
    fn shifts_primitive_integers_without_bounds() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u8, distance: u32) -> u8 { input.unbounded_shl(distance) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i16, distance: u32) -> i16 { input.unbounded_shr(distance) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u32, distance: u32) -> u32 { input.unbounded_shr(distance) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i64, distance: u32) -> i64 { input.unbounded_shl(distance) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: usize, distance: u32) -> usize { input.unbounded_shr(distance) }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 1536, 4, 96>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u8, distance: u16) -> u8 { input.unbounded_shl(distance) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: bool, distance: u32) -> bool { input.unbounded_shr(distance) }",
        ] {
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert_eq!(
                compile_x86_64_function::<_, 1024, 2, 80>(
                    &function,
                    &NoConstants,
                    X86_64Abi::Windows,
                )
                .unwrap_err()
                .kind,
                CodegenErrorKind::RuntimeTypeMismatch,
            );
        }
    }

    #[test]
    fn wraps_primitive_integer_powers() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u8, exponent: u32) -> u8 { input.wrapping_pow(exponent) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i16, exponent: u32) -> i16 { input.wrapping_pow(exponent) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u32, exponent: u32) -> u32 { input.wrapping_pow(exponent) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i64, exponent: u32) -> i64 { input.wrapping_pow(exponent) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: usize, exponent: u32) -> usize { input.wrapping_pow(exponent) }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 1536, 4, 96>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u8, exponent: u16) -> u8 { input.wrapping_pow(exponent) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: bool, exponent: u32) -> bool { input.wrapping_pow(exponent) }",
        ] {
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert_eq!(
                compile_x86_64_function::<_, 1024, 2, 80>(
                    &function,
                    &NoConstants,
                    X86_64Abi::Windows,
                )
                .unwrap_err()
                .kind,
                CodegenErrorKind::RuntimeTypeMismatch,
            );
        }
    }

    #[test]
    fn saturates_primitive_integer_powers() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u8, exponent: u32) -> u8 { input.saturating_pow(exponent) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i16, exponent: u32) -> i16 { input.saturating_pow(exponent) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u32, exponent: u32) -> u32 { input.saturating_pow(exponent) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i64, exponent: u32) -> i64 { input.saturating_pow(exponent) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: usize, exponent: u32) -> usize { input.saturating_pow(exponent) }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 3072, 4, 96>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u8, exponent: u16) -> u8 { input.saturating_pow(exponent) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: bool, exponent: u32) -> bool { input.saturating_pow(exponent) }",
        ] {
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert_eq!(
                compile_x86_64_function::<_, 2048, 2, 80>(
                    &function,
                    &NoConstants,
                    X86_64Abi::Windows,
                )
                .unwrap_err()
                .kind,
                CodegenErrorKind::RuntimeTypeMismatch,
            );
        }
    }

    #[test]
    fn checks_primitive_integer_powers() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u8, exponent: u32) -> u8 { input.pow(exponent) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i16, exponent: u32) -> i16 { input.pow(exponent) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u64, exponent: u32) -> u64 { input.pow(exponent) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i64, exponent: u32) -> i64 { input.pow(exponent) }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                for options in [CodegenOptions::CHECKED, CodegenOptions::WRAPPING] {
                    let result = compile_x86_64_function_with_options::<_, 3072, 4, 96>(
                        &function,
                        &NoConstants,
                        abi,
                        options,
                    );
                    assert!(result.is_ok(), "{source}: {result:?}");
                }
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u8, exponent: u16) -> u8 { input.pow(exponent) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: bool, exponent: u32) -> bool { input.pow(exponent) }",
        ] {
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert_eq!(
                compile_x86_64_function::<_, 2048, 2, 80>(
                    &function,
                    &NoConstants,
                    X86_64Abi::Windows,
                )
                .unwrap_err()
                .kind,
                CodegenErrorKind::RuntimeTypeMismatch,
            );
        }
    }

    #[test]
    fn reorders_primitive_integer_bits_and_bytes() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u8) -> u8 { input.reverse_bits() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i16) -> i16 { input.swap_bytes() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u32) -> u32 { input.reverse_bits() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i64) -> i64 { input.to_be() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: usize) -> usize { input.to_le() }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 1536, 2, 96>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: bool) -> bool { input.reverse_bits() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: char) -> char { input.swap_bytes() }",
        ] {
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert_eq!(
                compile_x86_64_function::<_, 768, 2, 80>(
                    &function,
                    &NoConstants,
                    X86_64Abi::Windows,
                )
                .unwrap_err()
                .kind,
                CodegenErrorKind::RuntimeTypeMismatch,
            );
        }
    }

    #[test]
    fn converts_integers_from_explicit_endianness() {
        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u8) -> u8 { u8::from_be(input) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i16) -> i16 { i16::from_le(input) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u32) -> u32 { u32::from_be(input) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i64) -> i64 { i64::from_le(input) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: usize) -> usize { usize::from_be(input) }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 1024, 4, 96>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u16) -> u32 { u32::from_be(input) }";
        let module = Parser::new(source).parse_module::<2, 4>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        assert!(
            compile_x86_64_function::<_, 1024, 4, 96>(&function, &NoConstants, X86_64Abi::Windows)
                .is_err()
        );
    }

    #[test]
    fn constructs_integers_from_byte_arrays() {
        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(bytes: [u8; 1]) -> u8 { u8::from_be_bytes(bytes) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(bytes: [u8; 2]) -> i16 { i16::from_le_bytes(bytes) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(bytes: [u8; 4]) -> u32 { u32::from_be_bytes(bytes) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(bytes: [u8; 8]) -> i64 { i64::from_ne_bytes(bytes) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(bytes: [u8; 8]) -> usize { usize::from_le_bytes(bytes) }",
        ] {
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 1536, 2, 96>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(bytes: [u8; 3]) -> u32 { u32::from_be_bytes(bytes) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(bytes: [u16; 2]) -> u32 { u32::from_le_bytes(bytes) }",
        ] {
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert_eq!(
                compile_x86_64_function::<_, 1536, 2, 96>(
                    &function,
                    &NoConstants,
                    X86_64Abi::Windows,
                )
                .unwrap_err()
                .kind,
                CodegenErrorKind::RuntimeTypeMismatch,
            );
        }
    }

    #[test]
    fn converts_integers_to_byte_arrays() {
        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u8) -> [u8; 1] { input.to_be_bytes() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i16) -> [u8; 2] { input.to_le_bytes() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u32) -> [u8; 4] { input.to_be_bytes() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i64) -> [u8; 8] { input.to_ne_bytes() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: usize) -> u8 { input.to_be_bytes()[0] }",
        ] {
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 2048, 2, 112>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: bool) -> [u8; 1] { input.to_ne_bytes() }";
        let module = Parser::new(source).parse_module::<2, 2>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        assert!(
            compile_x86_64_function::<_, 1024, 2, 80>(&function, &NoConstants, X86_64Abi::Windows,)
                .is_err()
        );
    }

    #[test]
    fn emits_primitive_integer_associated_constants() {
        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value() -> u8 { u8::MIN }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value() -> i16 { i16::MIN }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value() -> u32 { u32::MAX }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value() -> i64 { i64::MAX }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value() -> usize { usize::MAX }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value() -> u32 { isize::BITS }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value() -> i32 { i32::min_value() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value() -> u64 { u64::max_value() }",
        ] {
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result = compile_x86_64_function::<_, 768, 2, 80>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn value() -> u16 { u8::MAX }";
        let module = Parser::new(source).parse_module::<2, 2>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(
            compile_x86_64_function::<_, 768, 2, 80>(&function, &NoConstants, X86_64Abi::Windows,)
                .unwrap_err()
                .kind,
            CodegenErrorKind::RuntimeTypeMismatch,
        );

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value() -> u8 { u8::min_value(1) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value() -> u8 { u8::max_value }",
        ] {
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert!(
                compile_x86_64_function::<_, 768, 2, 80>(
                    &function,
                    &NoConstants,
                    X86_64Abi::Windows,
                )
                .is_err(),
                "{source}"
            );
        }
    }

    #[test]
    fn counts_primitive_integer_bits() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u8) -> u32 { input.count_ones() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i16) -> u32 { input.count_zeros() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u32) -> u32 { input.leading_zeros() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i64) -> u32 { input.trailing_zeros() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i8) -> u32 { input.leading_ones() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u64) -> u32 { input.trailing_ones() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: usize) -> u32 { input.count_ones() }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 2048, 2, 96>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: bool) -> u32 { input.count_ones() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u8) -> u8 { input.leading_zeros() }",
        ] {
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert_eq!(
                compile_x86_64_function::<_, 768, 2, 80>(
                    &function,
                    &NoConstants,
                    X86_64Abi::Windows,
                )
                .unwrap_err()
                .kind,
                CodegenErrorKind::RuntimeTypeMismatch,
            );
        }
    }

    #[test]
    fn isolates_integer_bits_and_measures_unsigned_widths() {
        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u8) -> u32 { input.bit_width() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u64) -> u32 { input.bit_width() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u8) -> u8 { input.isolate_highest_one() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u64) -> u64 { input.isolate_lowest_one() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i8) -> i8 { input.isolate_highest_one() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i64) -> i64 { input.isolate_lowest_one() }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 1024, 4, 96>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i8) -> u32 { input.bit_width() }";
        let module = Parser::new(source).parse_module::<2, 4>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(
            compile_x86_64_function::<_, 1024, 4, 96>(&function, &NoConstants, X86_64Abi::Windows,)
                .unwrap_err()
                .kind,
            CodegenErrorKind::RuntimeTypeMismatch,
        );
    }

    #[test]
    fn multiplies_and_gathers_unsigned_integer_bits() {
        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: u8, right: u8) -> u8 { left.carryless_mul(right) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(value: u64, mask: u64) -> u64 { value.carryless_mul(mask) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(value: u8, mask: u8) -> u8 { value.extract_bits(mask) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(value: u64, mask: u64) -> u64 { value.deposit_bits(mask) }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 1024, 4, 96>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(left: i8, right: i8) -> i8 { left.carryless_mul(right) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(value: i8, mask: i8) -> i8 { value.extract_bits(mask) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(value: i8, mask: i8) -> i8 { value.deposit_bits(mask) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(value: u8, mask: u16) -> u8 { value.extract_bits(mask) }",
        ] {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert_eq!(
                compile_x86_64_function::<_, 1024, 4, 96>(
                    &function,
                    &NoConstants,
                    X86_64Abi::Windows,
                )
                .unwrap_err()
                .kind,
                CodegenErrorKind::RuntimeTypeMismatch,
            );
        }
    }

    #[test]
    fn rounds_unsigned_integers_to_powers_of_two() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u8) -> u8 { input.next_power_of_two() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u16) -> u16 { input.wrapping_next_power_of_two() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u32) -> u32 { input.next_power_of_two() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u64) -> u64 { input.wrapping_next_power_of_two() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: usize) -> usize { input.next_power_of_two() }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                for options in [CodegenOptions::CHECKED, CodegenOptions::WRAPPING] {
                    let result = compile_x86_64_function_with_options::<_, 2048, 2, 96>(
                        &function,
                        &NoConstants,
                        abi,
                        options,
                    );
                    assert!(result.is_ok(), "{source}: {result:?}");
                }
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i8) -> i8 { input.next_power_of_two() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: bool) -> bool { input.wrapping_next_power_of_two() }",
        ] {
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert_eq!(
                compile_x86_64_function::<_, 1024, 2, 80>(
                    &function,
                    &NoConstants,
                    X86_64Abi::Windows,
                )
                .unwrap_err()
                .kind,
                CodegenErrorKind::RuntimeTypeMismatch,
            );
        }
    }

    #[test]
    fn computes_primitive_integer_logarithms() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u8) -> u32 { input.ilog2() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i16) -> u32 { input.ilog10() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u32, radix: u32) -> u32 { input.ilog(radix) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i64, radix: i64) -> u32 { input.ilog(radix) }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 2048, 4, 96>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u8, radix: u16) -> u32 { input.ilog(radix) }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: bool) -> u32 { input.ilog2() }",
        ] {
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert_eq!(
                compile_x86_64_function::<_, 1024, 2, 80>(
                    &function,
                    &NoConstants,
                    X86_64Abi::Windows,
                )
                .unwrap_err()
                .kind,
                CodegenErrorKind::RuntimeTypeMismatch,
            );
        }
    }

    #[test]
    fn computes_primitive_integer_square_roots() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u8) -> u8 { input.isqrt() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i16) -> i16 { input.isqrt() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u32) -> u32 { input.isqrt() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i64) -> i64 { input.isqrt() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: usize) -> usize { input.isqrt() }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 2048, 2, 96>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        let source =
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: bool) -> bool { input.isqrt() }";
        let module = Parser::new(source).parse_module::<2, 2>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(
            compile_x86_64_function::<_, 2048, 2, 96>(&function, &NoConstants, X86_64Abi::Windows,)
                .unwrap_err()
                .kind,
            CodegenErrorKind::RuntimeTypeMismatch,
        );
    }

    #[test]
    fn classifies_ascii_bytes() {
        let methods = [
            "is_ascii",
            "is_ascii_alphabetic",
            "is_ascii_uppercase",
            "is_ascii_lowercase",
            "is_ascii_alphanumeric",
            "is_ascii_digit",
            "is_ascii_hexdigit",
            "is_ascii_punctuation",
            "is_ascii_graphic",
            "is_ascii_whitespace",
            "is_ascii_control",
        ];
        for method in methods {
            let mut source = [0u8; 160];
            let prefix =
                "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u8) -> bool { input.";
            let suffix = "() }";
            let length = prefix.len() + method.len() + suffix.len();
            source[..prefix.len()].copy_from_slice(prefix.as_bytes());
            source[prefix.len()..prefix.len() + method.len()].copy_from_slice(method.as_bytes());
            source[prefix.len() + method.len()..length].copy_from_slice(suffix.as_bytes());
            let source = core::str::from_utf8(&source[..length]).unwrap();
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 1024, 2, 96>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }

        for source in [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u16) -> bool { input.is_ascii() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i8) -> bool { input.is_ascii_digit() }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: bool) -> bool { input.is_ascii_control() }",
        ] {
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert_eq!(
                compile_x86_64_function::<_, 768, 2, 80>(
                    &function,
                    &NoConstants,
                    X86_64Abi::Windows,
                )
                .unwrap_err()
                .kind,
                CodegenErrorKind::RuntimeTypeMismatch,
            );
        }
    }

    #[test]
    fn supports_independent_aggregate_parameter_widths() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u8, values: [u16; 3]) -> u8 { if values[1] == 257 { input + 1 } else { input } }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u8, values: &[u16; 3], slice: &[i32]) -> u8 { if values[1] == 257 && slice[0] == -3 { input + 1 } else { input } }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u8, flag: &bool, character: &char) -> u8 { if *flag && *character == 'z' { input + 1 } else { input } }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u8, wide: &mut u64, values: &mut [u16; 3], slice: &mut [i16]) -> u8 { *wide += 2; values[1] += 1; slice[0] += 2; if *wide == 258 && values[1] == 258 && slice[0] == -1 { input + 1 } else { input } }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 1536, 4, 128>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }
    }

    #[test]
    fn returns_fixed_arrays_through_x86_64_abi_classes() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u64) -> [u64; 1] { [input + 1] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: bool) -> [bool; 1] { [input] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: char) -> [char; 1] { [input] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u64) -> [u64; 2] { [input, input + 1] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u64, after: u64) -> [u64; 3] { [input, 42, after] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u64) -> [u64; 3] { let values = [input, input + 1, input + 2]; return values; }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(select: bool) -> [u64; 3] { if select { return [13u64, 42, 99]; } [1, 2, 3] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(select: bool) -> [u64; 2] { if select { return [13u64, 42]; } else { return [1, 2]; } }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u8) -> [u8; 4] { [input, input + 1, input + 2, input + 3] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u16) -> [u16; 5] { [input, 1, 2, 3, input + 4] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u32) -> [u32; 2] { [input, input + 1] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: i16) -> [i16; 3] { [input, -2, input + 1] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: char) -> [char; 2] { [input, 'z'] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: bool) -> [bool; 3] { [input, false, true] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u8) -> [u8; 0] { [] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u8) -> [(); 3] { [(); 3] }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u16) -> [u16; 5] { if input == 0 { Default::default() } else { [input, 0, 0, 0, input] } }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result = compile_x86_64_function::<_, 768, 4, 64>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }
    }

    #[test]
    fn supports_sixteen_element_fixed_arrays() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(values: [u8; 16]) -> [u8; 16] { let mut copied = values; copied[15] += 1; copied }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn value(input: u64) -> u64 { let mut values = [input; 16]; values[15] += 1; values[15] }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                let result =
                    compile_x86_64_function::<_, 4096, 4, 96>(&function, &NoConstants, abi);
                assert!(result.is_ok(), "{source}: {result:?}");
            }
        }
    }

    #[test]
    fn emits_unit_returning_functions() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn unit() -> () { () }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn implicit_unit() {}",
            "#[unsafe(no_mangle)] pub extern \"C\" fn early_unit(value: u64) { let adjusted = value + 1; return; let unreachable = adjusted + 1; unreachable; }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn conditional_unit(stop: bool) { if stop { return; } () }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn loop_return_unit(stop: bool) { loop { if stop { return; } } }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn loop_unit() -> () { loop { break; } }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn loop_value_unit() -> () { let value: () = loop { break (); }; value }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                assert!(
                    compile_x86_64_function::<_, 512, 4, 32>(&function, &NoConstants, abi,).is_ok()
                );
            }
        }

        let mismatch = Parser::new("#[unsafe(no_mangle)] pub extern \"C\" fn bad() -> () { 42 }")
            .parse_module::<2, 4>()
            .unwrap();
        let Some(Item::Function(function)) = mismatch.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(
            compile_x86_64_function::<_, 512, 4, 32>(&function, &NoConstants, X86_64Abi::Windows,)
                .unwrap_err()
                .kind,
            CodegenErrorKind::RuntimeTypeMismatch
        );

        let mismatch =
            Parser::new("#[unsafe(no_mangle)] pub extern \"C\" fn bad() -> u64 { return; }")
                .parse_module::<2, 4>()
                .unwrap();
        let Some(Item::Function(function)) = mismatch.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<4>().unwrap();
        assert_eq!(body.returns()[0].unwrap().value, "()");
        assert!(body.tail_diverges);
        assert_eq!(
            compile_x86_64_function::<_, 512, 4, 32>(&function, &NoConstants, X86_64Abi::Windows,)
                .unwrap_err()
                .kind,
            CodegenErrorKind::RuntimeTypeMismatch
        );
    }

    #[test]
    fn emits_boolean_and_unit_comparisons_and_boolean_bitwise_ops() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn equal(left: bool, right: bool) -> bool { left == right }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn different(left: bool, right: bool) -> bool { left != right }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn unit_equal() -> bool { () == () }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn ordered(left: bool, right: bool) -> bool { left < right }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn unit_ordered() -> bool { () <= () }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn bitwise(left: bool, right: bool) -> bool { (left & right) | (left ^ right) }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                assert!(
                    compile_x86_64_function::<_, 512, 4, 32>(&function, &NoConstants, abi,).is_ok()
                );
            }
        }

        let mixed = Parser::new(
            "#[unsafe(no_mangle)] pub extern \"C\" fn bad(left: bool) -> bool { left == 1 }",
        )
        .parse_module::<2, 4>()
        .unwrap();
        let Some(Item::Function(function)) = mixed.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(
            compile_x86_64_function::<_, 512, 4, 32>(&function, &NoConstants, X86_64Abi::Windows,)
                .unwrap_err()
                .kind,
            CodegenErrorKind::RuntimeTypeMismatch
        );
    }

    #[test]
    fn emits_boolean_compound_assignments() {
        let sources = [
            "#[unsafe(no_mangle)] pub extern \"C\" fn mutate(left: bool, right: bool) -> bool { let mut value: bool = left; value &= right; value ^= true; value |= left; value }",
            "#[unsafe(no_mangle)] pub extern \"C\" fn parity(limit: u64) -> bool { let mut i: u64 = 0; let mut value: bool = false; while i < limit { value ^= true; i += 1; } value }",
        ];
        for source in sources {
            let module = Parser::new(source).parse_module::<2, 4>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            for abi in [X86_64Abi::Windows, X86_64Abi::SystemV] {
                assert!(
                    compile_x86_64_function::<_, 768, 4, 64>(&function, &NoConstants, abi,).is_ok()
                );
            }
        }

        let arithmetic = Parser::new(
            "#[unsafe(no_mangle)] pub extern \"C\" fn bad() -> bool { let mut value: bool = false; value += true; value }",
        )
        .parse_module::<2, 4>()
        .unwrap();
        let Some(Item::Function(function)) = arithmetic.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(
            compile_x86_64_function::<_, 512, 4, 32>(&function, &NoConstants, X86_64Abi::Windows,)
                .unwrap_err()
                .kind,
            CodegenErrorKind::RuntimeTypeMismatch
        );
    }
}
