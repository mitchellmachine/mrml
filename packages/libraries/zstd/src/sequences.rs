use crate::bits::{ReverseBitWriter, ReverseBits};
use crate::fse::{
    CompressionPath, Entry, State as FseState, Table, parse_table, serialize_probabilities,
};
use crate::{Error, Result};
use mrml_runtime::Vector;

#[derive(Clone, Copy)]
pub(crate) struct Sequence {
    literals: u32,
    length: u32,
    offset: u32,
}

impl Sequence {
    #[allow(dead_code)] // Used by the block match finder after this staged codec gate.
    pub(crate) const fn new(literals: u32, length: u32, offset: u32) -> Self {
        Self {
            literals,
            length,
            offset,
        }
    }
}

pub(crate) struct State {
    literal_table: Option<Table>,
    offset_table: Option<Table>,
    match_table: Option<Table>,
    offsets: [u32; 3],
}

impl State {
    pub(crate) const fn new() -> Self {
        Self {
            literal_table: None,
            offset_table: None,
            match_table: None,
            offsets: [1, 4, 8],
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct EncoderState {
    literal_table: Option<Table>,
    offset_table: Option<Table>,
    match_table: Option<Table>,
}

impl EncoderState {
    pub(crate) const fn new() -> Self {
        Self {
            literal_table: None,
            offset_table: None,
            match_table: None,
        }
    }
}

#[derive(Clone, Copy)]
enum Kind {
    Literals,
    Offset,
    Match,
}

pub(crate) fn decode(bytes: &[u8], state: &mut State) -> Result<Vector<Sequence>> {
    let (count, count_bytes) = sequence_count(bytes)?;
    let mut output = Vector::with_capacity(count as usize).map_err(|_| Error::Allocation)?;
    if count == 0 {
        return Ok(output);
    }
    let modes = *bytes
        .get(count_bytes)
        .ok_or(Error::InvalidSequencesSection)?;
    if modes & 3 != 0 {
        return Err(Error::InvalidSequencesSection);
    }
    let mut cursor = count_bytes + 1;
    let literal_table = resolve(
        (modes >> 6) & 3,
        bytes,
        &mut cursor,
        &mut state.literal_table,
        Kind::Literals,
    )?;
    let offset_table = resolve(
        (modes >> 4) & 3,
        bytes,
        &mut cursor,
        &mut state.offset_table,
        Kind::Offset,
    )?;
    let match_table = resolve(
        (modes >> 2) & 3,
        bytes,
        &mut cursor,
        &mut state.match_table,
        Kind::Match,
    )?;
    let mut bits = ReverseBits::new(bytes.get(cursor..).ok_or(Error::InvalidSequencesSection)?)?;
    let mut literal_state = FseState::new(&literal_table, &mut bits)?;
    let mut offset_state = FseState::new(&offset_table, &mut bits)?;
    let mut match_state = FseState::new(&match_table, &mut bits)?;
    for index in 0..count {
        let literal_entry = literal_state.entry(&literal_table);
        let offset_entry = offset_state.entry(&offset_table);
        let match_entry = match_state.entry(&match_table);
        let (literal_base, literal_bits) = *LITERAL_LENGTHS
            .get(literal_entry.symbol as usize)
            .ok_or(Error::InvalidSequencesSection)?;
        let (match_base, match_bits) = *MATCH_LENGTHS
            .get(match_entry.symbol as usize)
            .ok_or(Error::InvalidSequencesSection)?;
        let offset_code = offset_entry.symbol as u8;
        if offset_code >= 32 {
            return Err(Error::InvalidSequencesSection);
        }
        let offset_value = (1u32 << offset_code) + bits.read(offset_code)?;
        let match_length = match_base + bits.read(match_bits)?;
        let literal_length = literal_base + bits.read(literal_bits)?;
        let offset = resolve_offset(offset_value, literal_length, &mut state.offsets)?;
        output.push(Sequence {
            literals: literal_length,
            length: match_length,
            offset,
        });
        if index + 1 != count {
            advance(&mut literal_state, literal_entry, &literal_table, &mut bits)?;
            advance(&mut match_state, match_entry, &match_table, &mut bits)?;
            advance(&mut offset_state, offset_entry, &offset_table, &mut bits)?;
        }
    }
    state.literal_table = Some(literal_table);
    state.offset_table = Some(offset_table);
    state.match_table = Some(match_table);
    Ok(output)
}

fn advance(
    state: &mut FseState,
    entry: Entry,
    table: &Table,
    bits: &mut ReverseBits<'_>,
) -> Result<()> {
    let value = entry.baseline as u32 + bits.read(entry.bits)?;
    if value as usize >= table.entries.len() {
        return Err(Error::InvalidFseState);
    }
    *state = FseState::from_value(value as u16);
    Ok(())
}

fn sequence_count(bytes: &[u8]) -> Result<(u32, usize)> {
    let first = *bytes.first().ok_or(Error::InvalidSequencesSection)?;
    if first < 128 {
        Ok((first as u32, 1))
    } else if first < 255 {
        Ok((
            ((first as u32 - 128) << 8)
                | *bytes.get(1).ok_or(Error::InvalidSequencesSection)? as u32,
            2,
        ))
    } else {
        Ok((
            0x7f00
                + *bytes.get(1).ok_or(Error::InvalidSequencesSection)? as u32
                + ((*bytes.get(2).ok_or(Error::InvalidSequencesSection)? as u32) << 8),
            3,
        ))
    }
}

fn resolve(
    mode: u8,
    bytes: &[u8],
    cursor: &mut usize,
    previous: &mut Option<Table>,
    kind: Kind,
) -> Result<Table> {
    match mode {
        0 => predefined(kind),
        1 => {
            let symbol = *bytes.get(*cursor).ok_or(Error::InvalidSequencesSection)? as u16;
            *cursor += 1;
            let mut entries = Vector::with_capacity(1).map_err(|_| Error::Allocation)?;
            entries.push(Entry {
                symbol,
                bits: 0,
                baseline: 0,
            });
            Ok(Table {
                accuracy: 0,
                entries,
            })
        }
        2 => {
            let (accuracy, maximum) = match kind {
                Kind::Literals => (9, 35),
                Kind::Offset => (8, 31),
                Kind::Match => (9, 52),
            };
            let (table, consumed) = parse_table(
                bytes.get(*cursor..).ok_or(Error::InvalidSequencesSection)?,
                accuracy,
                maximum,
            )?;
            *cursor += consumed;
            Ok(table)
        }
        3 => previous.clone().ok_or(Error::InvalidSequencesSection),
        _ => Err(Error::InvalidSequencesSection),
    }
}

fn predefined(kind: Kind) -> Result<Table> {
    match kind {
        Kind::Literals => Table::from_probabilities(
            &[
                4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1,
                1, 1, 1, 1, -1, -1, -1, -1,
            ],
            6,
        ),
        Kind::Offset => Table::from_probabilities(
            &[
                1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1,
                -1, -1,
            ],
            5,
        ),
        Kind::Match => Table::from_probabilities(
            &[
                1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1,
            ],
            6,
        ),
    }
}

pub(crate) fn encode(sequences: &[Sequence], state: &mut EncoderState) -> Result<Vector<u8>> {
    if sequences.is_empty() {
        let mut output = Vector::new();
        output.try_push(0).map_err(|_| Error::Allocation)?;
        return Ok(output);
    }
    let mut literal_symbols =
        Vector::with_capacity(sequences.len()).map_err(|_| Error::Allocation)?;
    let mut offset_symbols =
        Vector::with_capacity(sequences.len()).map_err(|_| Error::Allocation)?;
    let mut match_symbols =
        Vector::with_capacity(sequences.len()).map_err(|_| Error::Allocation)?;
    let mut literal_extras =
        Vector::with_capacity(sequences.len()).map_err(|_| Error::Allocation)?;
    let mut offset_extras =
        Vector::with_capacity(sequences.len()).map_err(|_| Error::Allocation)?;
    let mut match_extras = Vector::with_capacity(sequences.len()).map_err(|_| Error::Allocation)?;
    for sequence in sequences {
        let (literal_symbol, literal_extra) = encode_length(sequence.literals, &LITERAL_LENGTHS)?;
        let (match_symbol, match_extra) = encode_length(sequence.length, &MATCH_LENGTHS)?;
        if sequence.offset == 0 {
            return Err(Error::InvalidOffset);
        }
        // Values above three are explicit offsets and therefore do not depend
        // on the repeat-offset history at a block boundary.
        let offset_value = sequence.offset.checked_add(3).ok_or(Error::InvalidOffset)?;
        let offset_symbol = (31 - offset_value.leading_zeros()) as u16;
        if offset_symbol >= 29 {
            return Err(Error::InvalidOffset);
        }
        literal_symbols.push(literal_symbol);
        offset_symbols.push(offset_symbol);
        match_symbols.push(match_symbol);
        literal_extras.push(literal_extra);
        offset_extras.push(offset_value - (1u32 << offset_symbol));
        match_extras.push(match_extra);
    }

    let (literal_mode, literal_table, literal_description) = selected_table(
        &literal_symbols,
        Kind::Literals,
        state.literal_table.as_ref(),
    )?;
    let (offset_mode, offset_table, offset_description) =
        selected_table(&offset_symbols, Kind::Offset, state.offset_table.as_ref())?;
    let (match_mode, match_table, match_description) =
        selected_table(&match_symbols, Kind::Match, state.match_table.as_ref())?;
    let mut output = Vector::new();
    write_sequence_count(sequences.len(), &mut output)?;
    output
        .try_push((literal_mode << 6) | (offset_mode << 4) | (match_mode << 2))
        .map_err(|_| Error::Allocation)?;
    for description in [
        &literal_description,
        &offset_description,
        &match_description,
    ] {
        output
            .try_extend_from_slice(description)
            .map_err(|_| Error::Allocation)?;
    }
    let literal_path = CompressionPath::for_symbols(&literal_table, &literal_symbols)?;
    let offset_path = CompressionPath::for_symbols(&offset_table, &offset_symbols)?;
    let match_path = CompressionPath::for_symbols(&match_table, &match_symbols)?;
    let maximum_bits = sequences
        .len()
        .checked_mul(80)
        .and_then(|bits| bits.checked_add(32))
        .ok_or(Error::BlockTooLarge)?;
    let mut writer = ReverseBitWriter::new(maximum_bits);
    writer.write(literal_path.initial() as u32, literal_table.accuracy)?;
    writer.write(offset_path.initial() as u32, offset_table.accuracy)?;
    writer.write(match_path.initial() as u32, match_table.accuracy)?;
    for index in 0..sequences.len() {
        writer.write(offset_extras[index], offset_symbols[index] as u8)?;
        let match_entry = MATCH_LENGTHS[match_symbols[index] as usize];
        writer.write(match_extras[index], match_entry.1)?;
        let literal_entry = LITERAL_LENGTHS[literal_symbols[index] as usize];
        writer.write(literal_extras[index], literal_entry.1)?;
        if index + 1 != sequences.len() {
            for (path, table) in [
                (&literal_path, &literal_table),
                (&match_path, &match_table),
                (&offset_path, &offset_table),
            ] {
                let (value, bits) = path.transition(table, index)?;
                writer.write(value, bits)?;
            }
        }
    }
    output
        .try_extend_from_slice(&writer.finish()?)
        .map_err(|_| Error::Allocation)?;
    state.literal_table = Some(literal_table);
    state.offset_table = Some(offset_table);
    state.match_table = Some(match_table);
    Ok(output)
}

fn selected_table(
    symbols: &[u16],
    kind: Kind,
    previous: Option<&Table>,
) -> Result<(u8, Table, Vector<u8>)> {
    let first = *symbols.first().ok_or(Error::InvalidSequencesSection)?;
    if symbols.iter().all(|symbol| *symbol == first) {
        let maximum = match kind {
            Kind::Literals => 35,
            Kind::Offset => 31,
            Kind::Match => 52,
        };
        if first > maximum {
            return Err(Error::InvalidSequencesSection);
        }
        let mut entries = Vector::with_capacity(1).map_err(|_| Error::Allocation)?;
        entries.push(Entry {
            symbol: first,
            bits: 0,
            baseline: 0,
        });
        let mut description = Vector::new();
        description
            .try_push(first as u8)
            .map_err(|_| Error::Allocation)?;
        return Ok((
            1,
            Table {
                accuracy: 0,
                entries,
            },
            description,
        ));
    }
    let predefined = predefined(kind)?;
    let predefined_bits = path_bits(&predefined, symbols)?;
    let maximum_accuracy = match kind {
        Kind::Offset => 8,
        Kind::Literals | Kind::Match => 9,
    };
    let mut selected_mode = 0;
    let mut selected_table = predefined;
    let mut selected_description = Vector::new();
    let mut selected_bits = predefined_bits;
    if let Ok((probabilities, accuracy)) = normalize_counts(symbols, maximum_accuracy) {
        let compressed = Table::from_probabilities(&probabilities, accuracy)?;
        let description = serialize_probabilities(&probabilities, accuracy)?;
        let compressed_bits = path_bits(&compressed, symbols)?
            .checked_add(
                description
                    .len()
                    .checked_mul(8)
                    .ok_or(Error::BlockTooLarge)?,
            )
            .ok_or(Error::BlockTooLarge)?;
        if compressed_bits < predefined_bits {
            selected_mode = 2;
            selected_table = compressed;
            selected_description = description;
            selected_bits = compressed_bits;
        }
    }
    if let Some(previous) = previous {
        if let Ok(repeat_bits) = path_bits(previous, symbols) {
            if repeat_bits < selected_bits {
                return Ok((3, previous.clone(), Vector::new()));
            }
        }
    }
    Ok((selected_mode, selected_table, selected_description))
}

fn path_bits(table: &Table, symbols: &[u16]) -> Result<usize> {
    let path = CompressionPath::for_symbols(table, symbols)?;
    let mut bits = table.accuracy as usize;
    for index in 0..symbols.len() - 1 {
        bits = bits
            .checked_add(path.transition(table, index)?.1 as usize)
            .ok_or(Error::BlockTooLarge)?;
    }
    Ok(bits)
}

fn normalize_counts(symbols: &[u16], maximum_accuracy: u8) -> Result<(Vector<i16>, u8)> {
    let maximum_symbol = *symbols.iter().max().ok_or(Error::InvalidFseTable)? as usize;
    let mut counts = Vector::with_capacity(maximum_symbol + 1).map_err(|_| Error::Allocation)?;
    counts.resize(maximum_symbol + 1, 0u32);
    for symbol in symbols {
        counts[*symbol as usize] = counts[*symbol as usize]
            .checked_add(1)
            .ok_or(Error::BlockTooLarge)?;
    }
    let distinct = counts.iter().filter(|count| **count != 0).count();
    let mut accuracy = 5u8;
    while accuracy < maximum_accuracy && (1usize << accuracy) < distinct.saturating_mul(2) {
        accuracy += 1;
    }
    if distinct > 1usize << accuracy {
        return Err(Error::InvalidFseTable);
    }
    let size = 1u32 << accuracy;
    let total = symbols.len() as u32;
    let mut probabilities = Vector::with_capacity(counts.len()).map_err(|_| Error::Allocation)?;
    probabilities.resize(counts.len(), 0i16);
    let mut assigned = 0u32;
    for (index, count) in counts.iter().enumerate() {
        if *count != 0 {
            let probability = ((*count as u64 * size as u64) / total as u64).max(1) as u32;
            probabilities[index] = probability as i16;
            assigned += probability;
        }
    }
    while assigned < size {
        let index = counts
            .iter()
            .enumerate()
            .filter(|(_, count)| **count != 0)
            .max_by_key(|(index, count)| {
                (
                    (**count as u64 * size as u64) % total as u64,
                    **count,
                    usize::MAX - *index,
                )
            })
            .map(|(index, _)| index)
            .ok_or(Error::InvalidFseTable)?;
        probabilities[index] += 1;
        assigned += 1;
    }
    while assigned > size {
        let index = probabilities
            .iter()
            .enumerate()
            .filter(|(_, probability)| **probability > 1)
            .max_by_key(|(index, probability)| (**probability, counts[*index], usize::MAX - *index))
            .map(|(index, _)| index)
            .ok_or(Error::InvalidFseTable)?;
        probabilities[index] -= 1;
        assigned -= 1;
    }
    for probability in &mut probabilities {
        if *probability == 1 {
            *probability = -1;
        }
    }
    Ok((probabilities, accuracy))
}

fn encode_length(value: u32, table: &[(u32, u8)]) -> Result<(u16, u32)> {
    for (symbol, (base, bits)) in table.iter().enumerate().rev() {
        if value >= *base {
            let extra = value - *base;
            if extra < 1u32 << bits {
                return Ok((symbol as u16, extra));
            }
            break;
        }
    }
    Err(Error::InvalidSequencesSection)
}

fn write_sequence_count(count: usize, output: &mut Vector<u8>) -> Result<()> {
    if count < 128 {
        output
            .try_push(count as u8)
            .map_err(|_| Error::Allocation)?;
    } else if count < 0x7f00 {
        output
            .try_extend_from_slice(&[((count >> 8) as u8) + 128, count as u8])
            .map_err(|_| Error::Allocation)?;
    } else if count <= 0x17eff {
        let adjusted = count - 0x7f00;
        output
            .try_extend_from_slice(&[255, adjusted as u8, (adjusted >> 8) as u8])
            .map_err(|_| Error::Allocation)?;
    } else {
        return Err(Error::BlockTooLarge);
    }
    Ok(())
}

fn resolve_offset(value: u32, literals: u32, previous: &mut [u32; 3]) -> Result<u32> {
    let offset;
    if value > 3 {
        offset = value - 3;
        previous[2] = previous[1];
        previous[1] = previous[0];
        previous[0] = offset;
    } else if literals == 0 {
        offset = match value {
            1 => previous[1],
            2 => previous[2],
            3 => previous[0].checked_sub(1).ok_or(Error::InvalidOffset)?,
            _ => return Err(Error::InvalidOffset),
        };
        match value {
            1 => previous.swap(0, 1),
            2 => {
                let old = previous[2];
                previous[2] = previous[1];
                previous[1] = previous[0];
                previous[0] = old;
            }
            3 => {
                previous[2] = previous[1];
                previous[1] = previous[0];
                previous[0] = offset;
            }
            _ => {}
        }
    } else {
        offset = previous[(value - 1) as usize];
        if value == 2 {
            previous.swap(0, 1);
        } else if value == 3 {
            let old = previous[2];
            previous[2] = previous[1];
            previous[1] = previous[0];
            previous[0] = old;
        }
    }
    if offset == 0 {
        return Err(Error::InvalidOffset);
    }
    Ok(offset)
}

pub(crate) fn execute(
    sequences: &[Sequence],
    literals: &[u8],
    output: &mut Vector<u8>,
) -> Result<()> {
    let before = output.len();
    let mut literal = 0usize;
    for sequence in sequences {
        let count = sequence.literals as usize;
        let end = literal
            .checked_add(count)
            .ok_or(Error::InvalidSequencesSection)?;
        output
            .try_extend_from_slice(
                literals
                    .get(literal..end)
                    .ok_or(Error::InvalidSequencesSection)?,
            )
            .map_err(|_| Error::Allocation)?;
        literal = end;
        let offset = sequence.offset as usize;
        if offset == 0 || offset > output.len() {
            return Err(Error::InvalidOffset);
        }
        for _ in 0..sequence.length {
            let byte = output[output.len() - offset];
            output.push(byte);
        }
        if output.len() - before > 128 * 1024 {
            return Err(Error::BlockTooLarge);
        }
    }
    output
        .try_extend_from_slice(
            literals
                .get(literal..)
                .ok_or(Error::InvalidSequencesSection)?,
        )
        .map_err(|_| Error::Allocation)?;
    if output.len() - before > 128 * 1024 {
        return Err(Error::BlockTooLarge);
    }
    Ok(())
}

const LITERAL_LENGTHS: [(u32, u8); 36] = [
    (0, 0),
    (1, 0),
    (2, 0),
    (3, 0),
    (4, 0),
    (5, 0),
    (6, 0),
    (7, 0),
    (8, 0),
    (9, 0),
    (10, 0),
    (11, 0),
    (12, 0),
    (13, 0),
    (14, 0),
    (15, 0),
    (16, 1),
    (18, 1),
    (20, 1),
    (22, 1),
    (24, 2),
    (28, 2),
    (32, 3),
    (40, 3),
    (48, 4),
    (64, 6),
    (128, 7),
    (256, 8),
    (512, 9),
    (1024, 10),
    (2048, 11),
    (4096, 12),
    (8192, 13),
    (16384, 14),
    (32768, 15),
    (65536, 16),
];
const MATCH_LENGTHS: [(u32, u8); 53] = [
    (3, 0),
    (4, 0),
    (5, 0),
    (6, 0),
    (7, 0),
    (8, 0),
    (9, 0),
    (10, 0),
    (11, 0),
    (12, 0),
    (13, 0),
    (14, 0),
    (15, 0),
    (16, 0),
    (17, 0),
    (18, 0),
    (19, 0),
    (20, 0),
    (21, 0),
    (22, 0),
    (23, 0),
    (24, 0),
    (25, 0),
    (26, 0),
    (27, 0),
    (28, 0),
    (29, 0),
    (30, 0),
    (31, 0),
    (32, 0),
    (33, 0),
    (34, 0),
    (35, 1),
    (37, 1),
    (39, 1),
    (41, 1),
    (43, 2),
    (47, 2),
    (51, 3),
    (59, 3),
    (67, 4),
    (83, 4),
    (99, 5),
    (131, 7),
    (259, 8),
    (515, 9),
    (1027, 10),
    (2051, 11),
    (4099, 12),
    (8195, 13),
    (16387, 14),
    (32771, 15),
    (65539, 16),
];

#[cfg(test)]
mod encode_tests {
    use super::*;

    #[test]
    fn predefined_sequence_section_round_trips_and_executes() {
        let expected = [Sequence::new(3, 3, 3), Sequence::new(0, 3, 6)];
        let encoded = encode(&expected, &mut EncoderState::new()).unwrap();
        assert_eq!(encoded[1] & 0x0c, 0x04);
        let decoded = decode(&encoded, &mut State::new()).unwrap();
        assert_eq!(decoded.len(), expected.len());
        for (actual, expected) in decoded.iter().zip(expected) {
            assert_eq!(actual.literals, expected.literals);
            assert_eq!(actual.length, expected.length);
            assert_eq!(actual.offset, expected.offset);
        }
        let mut output = Vector::new();
        execute(&decoded, b"abc", &mut output).unwrap();
        assert_eq!(&output[..], b"abcabcabc");
    }

    #[test]
    fn uniform_code_streams_select_rle_tables() {
        let encoded = encode(&[Sequence::new(3, 7, 3)], &mut EncoderState::new()).unwrap();
        assert_eq!(encoded[1], 0x54);
        let decoded = decode(&encoded, &mut State::new()).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].literals, 3);
        assert_eq!(decoded[0].length, 7);
        assert_eq!(decoded[0].offset, 3);
    }

    #[test]
    fn skewed_code_stream_selects_fse_compressed_table() {
        let mut symbols = Vector::new();
        for index in 0..1024 {
            symbols.push(if index % 31 == 0 {
                2
            } else if index % 7 == 0 {
                1
            } else {
                0
            });
        }
        let (mode, table, description) = selected_table(&symbols, Kind::Literals, None).unwrap();
        assert_eq!(mode, 2);
        assert!(!description.is_empty());
        let (parsed, consumed) = parse_table(&description, 9, 35).unwrap();
        assert_eq!(consumed, description.len());
        assert_eq!(parsed.entries, table.entries);
        let (repeat_mode, repeat_table, repeat_description) =
            selected_table(&symbols, Kind::Literals, Some(&table)).unwrap();
        assert_eq!(repeat_mode, 3);
        assert!(repeat_description.is_empty());
        assert_eq!(repeat_table.entries, table.entries);
    }

    #[test]
    fn predefined_sequence_section_rejects_invalid_values() {
        assert!(matches!(
            encode(&[Sequence::new(0, 2, 1)], &mut EncoderState::new()),
            Err(Error::InvalidSequencesSection)
        ));
        assert!(matches!(
            encode(&[Sequence::new(0, 3, 0)], &mut EncoderState::new()),
            Err(Error::InvalidOffset)
        ));
    }
}
