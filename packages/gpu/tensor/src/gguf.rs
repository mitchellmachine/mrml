use crate::error::{Result, anyhow};
use crate::types::{DType, Shape};
use mrml_runtime::{File, OrderedMap, Text, Vector};

pub const GGUF_MAGIC: u32 = 0x46554747; // "GGUF" in little endian
const MAX_GGUF_BYTES: u64 = 1 << 40;
const MAX_TENSORS: usize = 1_000_000;
const MAX_METADATA: usize = 1_000_000;
const MAX_STRING_BYTES: usize = 64 * 1024 * 1024;
const MAX_ARRAY_ITEMS: usize = 4_000_000;
const MAX_VALUE_DEPTH: usize = 8;
const MAX_METADATA_ALLOCATION: usize = 1024 * 1024 * 1024;
const MAX_ALIGNMENT: u64 = 1024 * 1024;

struct ParseBudget {
    file_bytes: u64,
    allocation_left: usize,
    array_items_left: usize,
}

impl ParseBudget {
    fn new(file_bytes: u64) -> Result<Self> {
        if file_bytes > MAX_GGUF_BYTES {
            return Err(anyhow!("GGUF file exceeds parser byte budget"));
        }
        Ok(Self {
            file_bytes,
            allocation_left: MAX_METADATA_ALLOCATION,
            array_items_left: MAX_ARRAY_ITEMS,
        })
    }

    fn count(value: u64, maximum: usize, name: &str) -> Result<usize> {
        let value = usize::try_from(value).map_err(|_| anyhow!("GGUF {name} count overflow"))?;
        if value > maximum {
            return Err(anyhow!("GGUF {name} count exceeds parser budget"));
        }
        Ok(value)
    }

    fn allocate(&mut self, bytes: usize) -> Result<()> {
        self.allocation_left = self
            .allocation_left
            .checked_sub(bytes)
            .ok_or_else(|| anyhow!("GGUF metadata allocation budget exceeded"))?;
        Ok(())
    }

    fn array(&mut self, items: usize) -> Result<()> {
        self.array_items_left = self
            .array_items_left
            .checked_sub(items)
            .ok_or_else(|| anyhow!("GGUF array item budget exceeded"))?;
        self.allocate(
            items
                .checked_mul(core::mem::size_of::<GgufValue>())
                .ok_or_else(|| anyhow!("GGUF array allocation overflow"))?,
        )
    }

    fn check_position(&self, position: u64) -> Result<()> {
        if position > self.file_bytes {
            return Err(anyhow!("GGUF parser position exceeds file"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub enum GgufValue {
    Uint8(u8),
    Int8(i8),
    Uint16(u16),
    Int16(i16),
    Uint32(u32),
    Int32(i32),
    Float32(f32),
    Bool(bool),
    String(Text),
    Array(Vector<GgufValue>),
    Uint64(u64),
    Int64(i64),
    Float64(f64),
}

impl GgufValue {
    pub fn as_u32(&self) -> Option<u32> {
        match self {
            GgufValue::Uint32(v) => Some(*v),
            GgufValue::Int32(v) if *v >= 0 => Some(*v as u32),
            GgufValue::Uint64(v) => u32::try_from(*v).ok(),
            GgufValue::Int64(v) => u32::try_from(*v).ok(),
            GgufValue::Uint16(v) => Some(*v as u32),
            GgufValue::Uint8(v) => Some(*v as u32),
            _ => None,
        }
    }

    pub fn as_f32(&self) -> Option<f32> {
        match self {
            GgufValue::Float32(v) => Some(*v),
            GgufValue::Float64(v) => Some(*v as f32),
            GgufValue::Uint32(v) => Some(*v as f32),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            GgufValue::String(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[GgufValue]> {
        match self {
            GgufValue::Array(arr) => Some(arr),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct GgufTensorInfo {
    pub name: Text,
    pub shape: Shape,
    pub dtype: DType,
    pub offset: u64,
    pub size_bytes: usize,
}

pub struct GgufFile {
    pub version: u32,
    pub metadata: OrderedMap<Text, GgufValue>,
    pub tensors: OrderedMap<Text, GgufTensorInfo>,
    pub data_offset: u64,
    pub path: Text,
    file_bytes: u64,
}

impl GgufFile {
    pub fn open(path: &str) -> Result<Self> {
        let stored_path = Text::from(path);
        let mut file = File::open(path)?;
        let file_bytes = file.len()?;
        let mut budget = ParseBudget::new(file_bytes)?;

        let magic = read_u32_le(&mut file)?;
        if magic != GGUF_MAGIC {
            return Err(anyhow!("Invalid GGUF magic number: 0x{:08X}", magic));
        }

        let version = read_u32_le(&mut file)?;
        if version < 2 || version > 3 {
            return Err(anyhow!("Unsupported GGUF version: {}", version));
        }

        let tensor_count = ParseBudget::count(read_u64_le(&mut file)?, MAX_TENSORS, "tensor")?;
        let kv_count = ParseBudget::count(read_u64_le(&mut file)?, MAX_METADATA, "metadata")?;
        budget.allocate(
            tensor_count
                .checked_mul(core::mem::size_of::<(Text, GgufTensorInfo)>())
                .and_then(|value| {
                    value.checked_add(
                        kv_count.checked_mul(core::mem::size_of::<(Text, GgufValue)>())?,
                    )
                })
                .ok_or_else(|| anyhow!("GGUF table allocation overflow"))?,
        )?;

        let mut metadata = OrderedMap::with_capacity(kv_count)
            .map_err(|_| anyhow!("GGUF metadata allocation failed"))?;
        for _ in 0..kv_count {
            let key = read_gguf_string(&mut file, &mut budget)?;
            let val_type = read_u32_le(&mut file)?;
            let value = read_gguf_value(&mut file, val_type, &mut budget, 0)?;
            if metadata
                .try_insert(key, value)
                .map_err(|_| anyhow!("GGUF metadata allocation failed"))?
                .is_some()
            {
                return Err(anyhow!("GGUF contains duplicate metadata key"));
            }
        }

        let mut tensors = OrderedMap::with_capacity(tensor_count)
            .map_err(|_| anyhow!("GGUF tensor table allocation failed"))?;
        for _ in 0..tensor_count {
            let name = read_gguf_string(&mut file, &mut budget)?;
            let n_dims = read_u32_le(&mut file)? as usize;
            if !(1..=4).contains(&n_dims) {
                return Err(anyhow!("GGUF tensor dimension count must be 1 through 4"));
            }

            let mut dims = [1; 4];
            let mut numel = 1usize;
            for dimension in dims.iter_mut().take(n_dims) {
                *dimension = usize::try_from(read_u64_le(&mut file)?)
                    .map_err(|_| anyhow!("GGUF tensor dimension overflow"))?;
                if *dimension == 0 {
                    return Err(anyhow!("GGUF tensor dimensions must be nonzero"));
                }
                numel = numel
                    .checked_mul(*dimension)
                    .ok_or_else(|| anyhow!("GGUF tensor shape multiplication overflow"))?;
            }

            let type_id = read_u32_le(&mut file)?;
            let dtype = match type_id {
                0 => DType::F32,
                1 => DType::F16,
                2 => DType::Q4_0,
                3 => DType::Q4_1,
                8 => DType::Q8_0,
                12 => DType::Q4_K,
                13 => DType::Q5_K,
                14 => DType::Q6_K,
                16 => DType::IQ4_XS,
                30 => DType::BF16,
                _ => return Err(anyhow!("Unsupported GGUF dtype ID: {}", type_id)),
            };

            let offset = read_u64_le(&mut file)?;
            let shape = Shape { dims, n_dims };
            if numel % dtype.block_size() != 0 {
                return Err(anyhow!(
                    "GGUF tensor element count is not quantization-block divisible"
                ));
            }
            let size_bytes = (numel / dtype.block_size())
                .checked_mul(dtype.type_size())
                .ok_or_else(|| anyhow!("GGUF tensor byte size overflow"))?;

            if tensors
                .try_insert(
                    name.clone(),
                    GgufTensorInfo {
                        name,
                        shape,
                        dtype,
                        offset,
                        size_bytes,
                    },
                )
                .map_err(|_| anyhow!("GGUF tensor table allocation failed"))?
                .is_some()
            {
                return Err(anyhow!("GGUF contains duplicate tensor name"));
            }
        }

        let alignment = metadata
            .get("general.alignment")
            .and_then(|v| v.as_u32())
            .unwrap_or(32) as u64;
        if alignment == 0 || !alignment.is_power_of_two() || alignment > MAX_ALIGNMENT {
            return Err(anyhow!(
                "GGUF alignment must be a bounded nonzero power of two"
            ));
        }

        let cur_pos = file.position();
        let data_offset = cur_pos
            .checked_add(alignment - 1)
            .map(|value| value & !(alignment - 1))
            .ok_or_else(|| anyhow!("GGUF data alignment overflow"))?;
        budget.check_position(data_offset)?;
        let mut ranges = Vector::with_capacity(tensor_count)
            .map_err(|_| anyhow!("GGUF range table allocation failed"))?;
        for (_, tensor) in &tensors {
            let start = data_offset
                .checked_add(tensor.offset)
                .ok_or_else(|| anyhow!("GGUF tensor offset overflow"))?;
            let length = u64::try_from(tensor.size_bytes)
                .map_err(|_| anyhow!("GGUF tensor length conversion overflow"))?;
            let end = start
                .checked_add(length)
                .ok_or_else(|| anyhow!("GGUF tensor range overflow"))?;
            if end > file_bytes {
                return Err(anyhow!("GGUF tensor range exceeds file"));
            }
            ranges
                .try_push((start, end))
                .map_err(|_| anyhow!("GGUF range allocation failed"))?;
        }
        ranges.sort_unstable_by_key(|range| range.0);
        if ranges.windows(2).any(|pair| pair[0].1 > pair[1].0) {
            return Err(anyhow!("GGUF tensor ranges overlap"));
        }

        Ok(Self {
            version,
            metadata,
            tensors,
            data_offset,
            path: stored_path,
            file_bytes,
        })
    }

    /// Read raw tensor bytes directly from file on-demand
    pub fn read_tensor_bytes(&self, tensor: &GgufTensorInfo) -> Result<Vector<u8>> {
        let mut file = File::open(&self.path)?;
        let start = self
            .data_offset
            .checked_add(tensor.offset)
            .ok_or_else(|| anyhow!("GGUF tensor offset overflow"))?;
        let end = start
            .checked_add(
                u64::try_from(tensor.size_bytes)
                    .map_err(|_| anyhow!("GGUF tensor length overflow"))?,
            )
            .ok_or_else(|| anyhow!("GGUF tensor range overflow"))?;
        if end > self.file_bytes {
            return Err(anyhow!("GGUF tensor range exceeds file"));
        }
        file.seek(start)?;
        let mut buf = Vector::with_capacity(tensor.size_bytes).expect("MRML allocation failed");
        buf.resize(tensor.size_bytes, 0);
        file.read_exact(&mut buf)?;
        Ok(buf)
    }

    pub fn get_meta(&self, key: &str) -> Option<&GgufValue> {
        self.metadata.get(key)
    }
}

fn read_gguf_string(reader: &mut File, budget: &mut ParseBudget) -> Result<Text> {
    let len = ParseBudget::count(read_u64_le(reader)?, MAX_STRING_BYTES, "string byte")?;
    budget.allocate(len)?;
    let mut buf =
        Vector::with_capacity(len).map_err(|_| anyhow!("GGUF string allocation failed"))?;
    buf.resize(len, 0);
    reader.read_exact(&mut buf)?;
    let value = core::str::from_utf8(&buf)
        .map_err(|_| crate::error::Error::msg("GGUF string is not valid UTF-8"))?;
    Ok(Text::from(value))
}

fn read_gguf_value(
    reader: &mut File,
    val_type: u32,
    budget: &mut ParseBudget,
    depth: usize,
) -> Result<GgufValue> {
    if depth > MAX_VALUE_DEPTH {
        return Err(anyhow!("GGUF value nesting exceeds parser budget"));
    }
    match val_type {
        0 => Ok(GgufValue::Uint8(read_u8(reader)?)),
        1 => Ok(GgufValue::Int8(read_i8(reader)?)),
        2 => Ok(GgufValue::Uint16(read_u16_le(reader)?)),
        3 => Ok(GgufValue::Int16(read_i16_le(reader)?)),
        4 => Ok(GgufValue::Uint32(read_u32_le(reader)?)),
        5 => Ok(GgufValue::Int32(read_i32_le(reader)?)),
        6 => Ok(GgufValue::Float32(read_f32_le(reader)?)),
        7 => match read_u8(reader)? {
            0 => Ok(GgufValue::Bool(false)),
            1 => Ok(GgufValue::Bool(true)),
            _ => Err(anyhow!("GGUF boolean is not canonical")),
        },
        8 => Ok(GgufValue::String(read_gguf_string(reader, budget)?)),
        9 => {
            let item_type = read_u32_le(reader)?;
            let len = ParseBudget::count(read_u64_le(reader)?, MAX_ARRAY_ITEMS, "array")?;
            budget.array(len)?;
            let mut arr =
                Vector::with_capacity(len).map_err(|_| anyhow!("GGUF array allocation failed"))?;
            for _ in 0..len {
                arr.try_push(read_gguf_value(reader, item_type, budget, depth + 1)?)
                    .map_err(|_| anyhow!("GGUF array allocation failed"))?;
            }
            Ok(GgufValue::Array(arr))
        }
        10 => Ok(GgufValue::Uint64(read_u64_le(reader)?)),
        11 => Ok(GgufValue::Int64(read_i64_le(reader)?)),
        12 => Ok(GgufValue::Float64(read_f64_le(reader)?)),
        _ => Err(anyhow!("Unknown GGUF value type ID: {}", val_type)),
    }
}

fn read_u8(reader: &mut File) -> Result<u8> {
    let mut b = [0u8; 1];
    reader.read_exact(&mut b)?;
    Ok(b[0])
}

fn read_i8(reader: &mut File) -> Result<i8> {
    let mut b = [0u8; 1];
    reader.read_exact(&mut b)?;
    Ok(b[0] as i8)
}

fn read_u16_le(reader: &mut File) -> Result<u16> {
    let mut b = [0u8; 2];
    reader.read_exact(&mut b)?;
    Ok(u16::from_le_bytes(b))
}

fn read_i16_le(reader: &mut File) -> Result<i16> {
    let mut b = [0u8; 2];
    reader.read_exact(&mut b)?;
    Ok(i16::from_le_bytes(b))
}

fn read_u32_le(reader: &mut File) -> Result<u32> {
    let mut b = [0u8; 4];
    reader.read_exact(&mut b)?;
    Ok(u32::from_le_bytes(b))
}

fn read_i32_le(reader: &mut File) -> Result<i32> {
    let mut b = [0u8; 4];
    reader.read_exact(&mut b)?;
    Ok(i32::from_le_bytes(b))
}

fn read_f32_le(reader: &mut File) -> Result<f32> {
    let mut b = [0u8; 4];
    reader.read_exact(&mut b)?;
    Ok(f32::from_le_bytes(b))
}

fn read_u64_le(reader: &mut File) -> Result<u64> {
    let mut b = [0u8; 8];
    reader.read_exact(&mut b)?;
    Ok(u64::from_le_bytes(b))
}

fn read_i64_le(reader: &mut File) -> Result<i64> {
    let mut b = [0u8; 8];
    reader.read_exact(&mut b)?;
    Ok(i64::from_le_bytes(b))
}

fn read_f64_le(reader: &mut File) -> Result<f64> {
    let mut b = [0u8; 8];
    reader.read_exact(&mut b)?;
    Ok(f64::from_le_bytes(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    trait TestExtend {
        fn extend_from_slice(&mut self, values: &[u8]);
    }

    impl TestExtend for Vector<u8> {
        fn extend_from_slice(&mut self, values: &[u8]) {
            self.try_extend_from_slice(values).unwrap();
        }
    }

    fn header(tensors: u64, metadata: u64) -> Vector<u8> {
        let mut bytes = Vector::new();
        bytes.extend_from_slice(&GGUF_MAGIC.to_le_bytes());
        bytes.extend_from_slice(&3u32.to_le_bytes());
        bytes.extend_from_slice(&tensors.to_le_bytes());
        bytes.extend_from_slice(&metadata.to_le_bytes());
        bytes
    }

    fn string(bytes: &mut Vector<u8>, value: &[u8]) {
        bytes.extend_from_slice(&(value.len() as u64).to_le_bytes());
        bytes.extend_from_slice(value);
    }

    fn tensor(bytes: &mut Vector<u8>, name: &[u8], dimensions: &[u64], kind: u32, offset: u64) {
        string(bytes, name);
        bytes.extend_from_slice(&(dimensions.len() as u32).to_le_bytes());
        for dimension in dimensions {
            bytes.extend_from_slice(&dimension.to_le_bytes());
        }
        bytes.extend_from_slice(&kind.to_le_bytes());
        bytes.extend_from_slice(&offset.to_le_bytes());
    }

    fn parse(bytes: &[u8], name: &str) -> Result<GgufFile> {
        let path = mrml_runtime::join_path(
            &mrml_runtime::temporary_directory(),
            &mrml_runtime::mrml_format!("gguf-budget-{name}-{}", mrml_runtime::process_id()),
        );
        if mrml_runtime::path_exists(&path) {
            mrml_runtime::remove_file(&path).unwrap();
        }
        mrml_runtime::write_file(&path, bytes).unwrap();
        let result = GgufFile::open(&path);
        mrml_runtime::remove_file(&path).unwrap();
        result
    }

    fn pad_data(bytes: &mut Vector<u8>) {
        while bytes.len() % 32 != 0 {
            bytes.push(0);
        }
    }

    #[test]
    fn parses_one_bounded_quantized_tensor() {
        let mut bytes = header(1, 0);
        tensor(&mut bytes, b"w", &[32], 2, 0);
        pad_data(&mut bytes);
        bytes.extend_from_slice(&[0; 18]);
        let file = parse(&bytes, "valid").unwrap();
        assert_eq!(file.tensors.get("w").unwrap().size_bytes, 18);
    }

    #[test]
    fn rejects_counts_strings_arrays_and_nesting_over_budget() {
        assert!(parse(&header((MAX_TENSORS + 1) as u64, 0), "tensor-count").is_err());
        let mut huge_string = header(0, 1);
        huge_string.extend_from_slice(&((MAX_STRING_BYTES + 1) as u64).to_le_bytes());
        assert!(parse(&huge_string, "string").is_err());
        let mut nested = header(0, 1);
        string(&mut nested, b"x");
        nested.extend_from_slice(&9u32.to_le_bytes());
        for _ in 0..=MAX_VALUE_DEPTH {
            nested.extend_from_slice(&9u32.to_le_bytes());
            nested.extend_from_slice(&1u64.to_le_bytes());
        }
        assert!(parse(&nested, "nesting").is_err());
    }

    #[test]
    fn rejects_dimensions_shape_overflow_and_quantization_remainders() {
        let mut too_many = header(1, 0);
        tensor(&mut too_many, b"w", &[1, 1, 1, 1, 1], 0, 0);
        assert!(parse(&too_many, "dimensions").is_err());
        let mut overflow = header(1, 0);
        tensor(&mut overflow, b"w", &[usize::MAX as u64, 2], 0, 0);
        assert!(parse(&overflow, "shape-overflow").is_err());
        let mut remainder = header(1, 0);
        tensor(&mut remainder, b"w", &[31], 2, 0);
        assert!(parse(&remainder, "quant-remainder").is_err());
    }

    #[test]
    fn rejects_invalid_alignment_and_out_of_file_or_overlapping_ranges() {
        let mut alignment = header(0, 1);
        string(&mut alignment, b"general.alignment");
        alignment.extend_from_slice(&4u32.to_le_bytes());
        alignment.extend_from_slice(&0u32.to_le_bytes());
        assert!(parse(&alignment, "alignment").is_err());

        let mut outside = header(1, 0);
        tensor(&mut outside, b"w", &[1], 0, 0);
        pad_data(&mut outside);
        assert!(parse(&outside, "outside").is_err());

        let mut overlap = header(2, 0);
        tensor(&mut overlap, b"a", &[1], 0, 0);
        tensor(&mut overlap, b"b", &[1], 0, 0);
        pad_data(&mut overlap);
        overlap.extend_from_slice(&[0; 4]);
        assert!(parse(&overlap, "overlap").is_err());
    }
}
