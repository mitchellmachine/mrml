//! Bounded, deterministic x86-64 static-link planning and relocation.
//!
//! The passes deliberately have no shared mutable work between inputs until the
//! final copy/relocation pass. A hosted driver can therefore parallelize input
//! validation and relocation scanning later without changing link semantics.

pub const MAX_LINK_INPUTS: usize = 32;
pub const MAX_LINK_RELOCATIONS: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinkerError {
    EmptyInput,
    EmptySymbol,
    SymbolContainsNul,
    TooManyInputs,
    TooManyRelocations,
    DuplicateSymbol,
    UndefinedSymbol,
    InvalidRelocationOffset,
    OffsetOverflow,
    RelocationOverflow,
    OutputTooSmall,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkRelocation<'a> {
    /// Offset of the four-byte x86-64 PC-relative field in this input's text.
    pub offset: usize,
    pub symbol: &'a str,
    /// Explicit object-format addend. A call/jump rel32 normally uses `-4`.
    pub addend: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkInput<'a> {
    pub symbol: &'a str,
    pub text: &'a [u8],
    pub readonly_data: &'a [u8],
    pub relocations: &'a [LinkRelocation<'a>],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkedImage<const MAX_BYTES: usize> {
    bytes: [u8; MAX_BYTES],
    length: usize,
    readonly_offset: usize,
    entry_offset: usize,
}

impl<const MAX_BYTES: usize> LinkedImage<MAX_BYTES> {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.length]
    }

    pub const fn readonly_offset(&self) -> usize {
        self.readonly_offset
    }

    pub const fn entry_offset(&self) -> usize {
        self.entry_offset
    }
}

#[derive(Clone, Copy)]
struct InputLayout {
    text: usize,
    readonly: usize,
}

/// Links already-decoded MRML x86-64 fragments into one position-independent
/// image. Input order is significant and makes the result reproducible.
pub fn link_x86_64_static<const MAX_BYTES: usize>(
    inputs: &[LinkInput<'_>],
    entry_symbol: &str,
) -> Result<LinkedImage<MAX_BYTES>, LinkerError> {
    if inputs.is_empty() {
        return Err(LinkerError::EmptyInput);
    }
    if inputs.len() > MAX_LINK_INPUTS {
        return Err(LinkerError::TooManyInputs);
    }
    validate_symbol(entry_symbol)?;

    // Pass 1: validate independent inputs and construct the global symbol set.
    let mut relocation_count = 0usize;
    for (index, input) in inputs.iter().enumerate() {
        validate_symbol(input.symbol)?;
        relocation_count = relocation_count
            .checked_add(input.relocations.len())
            .ok_or(LinkerError::OffsetOverflow)?;
        if relocation_count > MAX_LINK_RELOCATIONS {
            return Err(LinkerError::TooManyRelocations);
        }
        for earlier in &inputs[..index] {
            if earlier.symbol == input.symbol {
                return Err(LinkerError::DuplicateSymbol);
            }
        }
        for relocation in input.relocations {
            validate_symbol(relocation.symbol)?;
            relocation
                .offset
                .checked_add(4)
                .filter(|end| *end <= input.text.len())
                .ok_or(LinkerError::InvalidRelocationOffset)?;
        }
    }

    // Pass 2: freeze layout before copying bytes, following a text-first,
    // read-only-data-second policy. The fixed arrays keep all bounds explicit.
    let mut layouts = [InputLayout {
        text: 0,
        readonly: 0,
    }; MAX_LINK_INPUTS];
    let mut cursor = 0usize;
    for (layout, input) in layouts.iter_mut().zip(inputs) {
        cursor = align(cursor, 16)?;
        layout.text = cursor;
        cursor = cursor
            .checked_add(input.text.len())
            .ok_or(LinkerError::OffsetOverflow)?;
    }
    let readonly_offset = align(cursor, 16)?;
    cursor = readonly_offset;
    for (layout, input) in layouts.iter_mut().zip(inputs) {
        cursor = align(cursor, 16)?;
        layout.readonly = cursor;
        cursor = cursor
            .checked_add(input.readonly_data.len())
            .ok_or(LinkerError::OffsetOverflow)?;
    }
    if cursor > MAX_BYTES {
        return Err(LinkerError::OutputTooSmall);
    }

    let entry_offset = resolve_symbol(inputs, &layouts, entry_symbol)?;
    let mut output = [0u8; MAX_BYTES];

    // Pass 3: disjoint copies are independently executable once layout is fixed.
    for (input, layout) in inputs.iter().zip(layouts.iter()) {
        copy_at(&mut output, layout.text, input.text)?;
        copy_at(&mut output, layout.readonly, input.readonly_data)?;
    }

    // Pass 4: each relocation patches a disjoint field validated above.
    for (input, layout) in inputs.iter().zip(layouts.iter()) {
        for relocation in input.relocations {
            let place = layout
                .text
                .checked_add(relocation.offset)
                .ok_or(LinkerError::OffsetOverflow)?;
            let target = resolve_symbol(inputs, &layouts, relocation.symbol)?;
            let displacement = i64::try_from(target)
                .map_err(|_| LinkerError::OffsetOverflow)?
                .checked_add(relocation.addend)
                .and_then(|value| value.checked_sub(i64::try_from(place).ok()?))
                .ok_or(LinkerError::OffsetOverflow)?;
            let displacement =
                i32::try_from(displacement).map_err(|_| LinkerError::RelocationOverflow)?;
            output[place..place + 4].copy_from_slice(&displacement.to_le_bytes());
        }
    }

    Ok(LinkedImage {
        bytes: output,
        length: cursor,
        readonly_offset,
        entry_offset,
    })
}

fn validate_symbol(symbol: &str) -> Result<(), LinkerError> {
    if symbol.is_empty() {
        Err(LinkerError::EmptySymbol)
    } else if symbol.as_bytes().contains(&0) {
        Err(LinkerError::SymbolContainsNul)
    } else {
        Ok(())
    }
}

fn resolve_symbol(
    inputs: &[LinkInput<'_>],
    layouts: &[InputLayout; MAX_LINK_INPUTS],
    symbol: &str,
) -> Result<usize, LinkerError> {
    inputs
        .iter()
        .zip(layouts.iter())
        .find_map(|(input, layout)| (input.symbol == symbol).then_some(layout.text))
        .ok_or(LinkerError::UndefinedSymbol)
}

fn align(value: usize, alignment: usize) -> Result<usize, LinkerError> {
    value
        .checked_add(alignment - 1)
        .map(|value| value & !(alignment - 1))
        .ok_or(LinkerError::OffsetOverflow)
}

fn copy_at<const MAX_BYTES: usize>(
    output: &mut [u8; MAX_BYTES],
    offset: usize,
    input: &[u8],
) -> Result<(), LinkerError> {
    let end = offset
        .checked_add(input.len())
        .ok_or(LinkerError::OffsetOverflow)?;
    output
        .get_mut(offset..end)
        .ok_or(LinkerError::OutputTooSmall)?
        .copy_from_slice(input);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn links_forward_and_backward_calls_after_freezing_layout() {
        let to_helper = LinkRelocation {
            offset: 1,
            symbol: "helper",
            addend: -4,
        };
        let to_entry = LinkRelocation {
            offset: 1,
            symbol: "entry",
            addend: -4,
        };
        let inputs = [
            LinkInput {
                symbol: "entry",
                text: &[0xe8, 0, 0, 0, 0, 0xc3],
                readonly_data: b"A",
                relocations: &[to_helper],
            },
            LinkInput {
                symbol: "helper",
                text: &[0xe8, 0, 0, 0, 0, 0xc3],
                readonly_data: b"B",
                relocations: &[to_entry],
            },
        ];
        let image = link_x86_64_static::<128>(&inputs, "entry").unwrap();
        assert_eq!(image.entry_offset(), 0);
        assert_eq!(image.readonly_offset(), 32);
        assert_eq!(
            i32::from_le_bytes(image.bytes()[1..5].try_into().unwrap()),
            11
        );
        assert_eq!(
            i32::from_le_bytes(image.bytes()[17..21].try_into().unwrap()),
            -21
        );
        assert_eq!(image.bytes()[32], b'A');
        assert_eq!(image.bytes()[48], b'B');
        assert_eq!(image, link_x86_64_static::<128>(&inputs, "entry").unwrap());
    }

    #[test]
    fn rejects_ambiguous_missing_and_out_of_bounds_inputs() {
        let plain = LinkInput {
            symbol: "same",
            text: &[0xc3],
            readonly_data: &[],
            relocations: &[],
        };
        assert_eq!(
            link_x86_64_static::<32>(&[plain, plain], "same"),
            Err(LinkerError::DuplicateSymbol)
        );
        assert_eq!(
            link_x86_64_static::<32>(&[plain], "missing"),
            Err(LinkerError::UndefinedSymbol)
        );
        let bad = LinkRelocation {
            offset: 0,
            symbol: "same",
            addend: 0,
        };
        let invalid = LinkInput {
            relocations: &[bad],
            ..plain
        };
        assert_eq!(
            link_x86_64_static::<32>(&[invalid], "same"),
            Err(LinkerError::InvalidRelocationOffset)
        );
        assert_eq!(
            link_x86_64_static::<0>(&[plain], "same"),
            Err(LinkerError::OutputTooSmall)
        );
    }
}
