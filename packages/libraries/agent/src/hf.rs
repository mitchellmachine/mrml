//! Hugging Face cache acquisition.
//!
//! Relative-name validation prevents server-selected traversal, and staging
//! files reject final-component links. Until the runtime exposes fully
//! descriptor-relative directory traversal on both hosts, the cache root and
//! its existing intermediate directories must remain owner-controlled; a
//! writable shared cache is not a supported security boundary.

use mrml_crypto::Sha3_512;
use mrml_error::{Result, anyhow};
use mrml_runtime::{
    Text, Vector, mrml_format as format, mrml_println as println, parent_path, rename_file,
};

const MAX_MODEL_FILES: usize = 256;
const MAX_MODEL_FILE_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const MAX_MODEL_TOTAL_BYTES: u64 = 256 * 1024 * 1024 * 1024;

fn digest_hex(digest: &[u8; 64]) -> Text {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = Text::new();
    for byte in digest {
        text.push(HEX[(byte >> 4) as usize] as char);
        text.push(HEX[(byte & 15) as usize] as char);
    }
    text
}

fn hash_file_state(path: &str) -> Result<(Sha3_512, u64)> {
    let mut file = mrml_runtime::File::open_regular(path)?;
    let mut hash = Sha3_512::new();
    let mut length = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
        length = length
            .checked_add(read as u64)
            .filter(|length| *length <= MAX_MODEL_FILE_BYTES)
            .ok_or_else(|| anyhow!("model file exceeds the per-file byte limit"))?;
    }
    Ok((hash, length))
}
fn hash_file(path: &str) -> Result<([u8; 64], u64)> {
    let (hash, length) = hash_file_state(path)?;
    Ok((hash.finalize(), length))
}

fn digest_matches(path: &str, sidecar: &str) -> bool {
    let Ok(mut file) = mrml_runtime::File::open_regular(sidecar) else {
        return false;
    };
    let Ok(length) = file.len().and_then(|length| {
        usize::try_from(length).map_err(|_| mrml_runtime::FileError::ReadFailed)
    }) else {
        return false;
    };
    if length > 129 {
        return false;
    }
    let mut bytes = [0u8; 129];
    if file.read_exact(&mut bytes[..length]).is_err() {
        return false;
    }
    let Ok(expected) = core::str::from_utf8(&bytes[..length]) else {
        return false;
    };
    let expected = expected.trim();
    if expected.len() != 128 {
        return false;
    }
    hash_file(path).is_ok_and(|(digest, _)| digest_hex(&digest).eq_ignore_ascii_case(expected))
}

fn write_digest(path: &str, digest: &[u8; 64]) -> Result<()> {
    if mrml_runtime::path_exists(path) {
        mrml_runtime::remove_file(path)?;
    }
    mrml_runtime::write_new_file(path, digest_hex(digest).as_bytes())?;
    Ok(())
}

fn native_file_len(path: &str) -> Option<u64> {
    mrml_runtime::File::open_regular(path).ok()?.len().ok()
}

#[derive(Default)]
struct DownloadBudget {
    total: u64,
}

impl DownloadBudget {
    fn add_file(&mut self, bytes: u64) -> Result<()> {
        if bytes > MAX_MODEL_FILE_BYTES {
            return Err(anyhow!("model file exceeds the per-file byte limit"));
        }
        self.total = self
            .total
            .checked_add(bytes)
            .filter(|total| *total <= MAX_MODEL_TOTAL_BYTES)
            .ok_or_else(|| anyhow!("model download exceeds the total byte limit"))?;
        Ok(())
    }

    fn add_chunk(&mut self, file_bytes: &mut u64, bytes: usize) -> Result<()> {
        let bytes = u64::try_from(bytes).map_err(|_| anyhow!("download byte count overflow"))?;
        let next_file = file_bytes
            .checked_add(bytes)
            .filter(|total| *total <= MAX_MODEL_FILE_BYTES)
            .ok_or_else(|| anyhow!("model file exceeds the per-file byte limit"))?;
        let next_total = self
            .total
            .checked_add(bytes)
            .filter(|total| *total <= MAX_MODEL_TOTAL_BYTES)
            .ok_or_else(|| anyhow!("model download exceeds the total byte limit"))?;
        *file_bytes = next_file;
        self.total = next_total;
        Ok(())
    }
}

fn path_file_name(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

fn safe_relative_hf_filename(filename: &str) -> Result<&str> {
    if filename.is_empty() || filename.len() > 1024 || filename.starts_with('/') {
        return Err(anyhow!("unsafe Hugging Face filename"));
    }
    for segment in filename.split('/') {
        if segment.is_empty()
            || segment.len() > 255
            || matches!(segment, "." | "..")
            || segment.ends_with(['.', ' '])
            || !segment
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
            || windows_reserved_name(segment)
        {
            return Err(anyhow!("unsafe Hugging Face filename"));
        }
    }
    Ok(filename)
}

fn windows_reserved_name(segment: &str) -> bool {
    let stem = segment.split('.').next().unwrap_or(segment);
    stem.eq_ignore_ascii_case("con")
        || stem.eq_ignore_ascii_case("prn")
        || stem.eq_ignore_ascii_case("aux")
        || stem.eq_ignore_ascii_case("nul")
        || (stem.len() == 4
            && (stem[..3].eq_ignore_ascii_case("com") || stem[..3].eq_ignore_ascii_case("lpt"))
            && matches!(stem.as_bytes()[3], b'1'..=b'9'))
}

fn safe_repo_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && !matches!(value, "." | "..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HfModelSpec {
    pub repo_id: Text,
    pub user: Text,
    pub model: Text,
    pub quant: Text,
}

#[derive(Debug, Clone)]
pub struct HfModelFiles {
    pub primary_entry_file: Text,
    pub shard_files: Vector<Text>,
    pub mmproj_file: Option<Text>,
    pub speedup_draft_file: Option<Text>,
}

impl HfModelSpec {
    pub fn parse(input: &str) -> Result<Self> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(anyhow!("Empty HuggingFace model specification"));
        }

        let (repo_part, quant_part) = if let Some(idx) = trimmed.find(':') {
            (&trimmed[..idx], &trimmed[idx + 1..])
        } else {
            (trimmed, "Q4_0")
        };

        let parts: Vector<&str> = repo_part.split('/').collect();
        let (user, model) = match parts.len() {
            1 => ("ggml-org", parts[0]),
            2 => (parts[0], parts[1]),
            _ => {
                return Err(anyhow!(
                    "Invalid HuggingFace repo format. Expected 'user/model' or 'user/model:quant'"
                ));
            }
        };

        if !safe_repo_component(user)
            || !safe_repo_component(model)
            || (!quant_part.is_empty() && !safe_repo_component(quant_part))
        {
            return Err(anyhow!(
                "Invalid HuggingFace repository or quantization name"
            ));
        }

        let repo_id = format!("{}/{}", user, model);
        let quant = if quant_part.is_empty() {
            Text::from("Q4_0")
        } else {
            Text::from(quant_part).to_ascii_uppercase()
        };

        Ok(Self {
            repo_id: repo_id.as_str().into(),
            user: user.into(),
            model: model.into(),
            quant,
        })
    }

    pub fn default_gemma_4_26b() -> Self {
        Self {
            repo_id: "ggml-org/gemma-4-26B-A4B-it-GGUF".into(),
            user: "ggml-org".into(),
            model: "gemma-4-26B-A4B-it-GGUF".into(),
            quant: "Q4_0".into(),
        }
    }

    pub fn cache_dir() -> Text {
        if let Some(path) = mrml_runtime::environment_variable("HF_HUB_CACHE") {
            return path;
        }
        if let Some(hf_home) = mrml_runtime::environment_variable("HF_HOME") {
            return mrml_runtime::join_path(&hf_home, "hub");
        }
        if let Some(mrml_cache) = mrml_runtime::environment_variable("MRML_CACHE") {
            return mrml_cache;
        }

        #[cfg(windows)]
        {
            if let Some(local_appdata) = mrml_runtime::environment_variable("LOCALAPPDATA") {
                let p = mrml_runtime::join_path(
                    &mrml_runtime::join_path(&local_appdata, "huggingface"),
                    "hub",
                );
                return p;
            }
        }

        if let Some(home) = crate::platform::home_dir() {
            return mrml_runtime::join_path(
                &mrml_runtime::join_path(&mrml_runtime::join_path(&home, ".cache"), "huggingface"),
                "hub",
            );
        }

        mrml_runtime::join_path(&mrml_runtime::join_path(".cache", "huggingface"), "hub")
    }

    pub fn get_model_dir(&self) -> Text {
        let repo_slug = format!("models--{}--{}", self.user, self.model);
        mrml_runtime::join_path(&Self::cache_dir(), &repo_slug)
    }

    pub fn is_cached(&self) -> bool {
        let model_dir = self.get_model_dir();
        if !mrml_runtime::path_is_directory(&model_dir) {
            return false;
        }

        let target_quant_lower = self.quant.to_ascii_lowercase();
        for path in crate::fs_walk::paths(&model_dir) {
            let name = Text::from(path_file_name(&path)).to_ascii_lowercase();
            if name.ends_with(".gguf")
                && name.contains(target_quant_lower.as_str())
                && !name.ends_with(".part")
                && !name.contains("mmproj")
                && !name.contains("mtp")
            {
                if mrml_runtime::File::open(&path)
                    .and_then(|file| file.len())
                    .is_ok_and(|length| length > 10 * 1024 * 1024)
                {
                    // > 10MB
                    return true;
                }
            }
        }
        false
    }
}

pub fn render_progress_bar(percent: f32, width: usize) -> Text {
    let filled = ((percent.clamp(0.0, 1.0) * width as f32 + 0.5) as usize).min(width);
    let empty = width.saturating_sub(filled);
    let mut output = Text::with_capacity(2 + width * 3).expect("MRML allocation failed");
    output.push('[');
    for _ in 0..filled {
        output.push('█');
    }
    for _ in 0..empty {
        output.push('░');
    }
    output.push(']');
    output
}

pub async fn query_hf_api_siblings(spec: &HfModelSpec) -> Result<Vector<Text>> {
    let api_url = format!(
        "https://huggingface.co/api/models/{}/{}",
        spec.user, spec.model
    );

    let client = mrml_http::Client::new();
    let token =
        mrml_runtime::environment_variable("HF_TOKEN").map(|value| format!("Bearer {}", value));
    let mut response = if let Some(ref authorization) = token {
        client.get_follow(&api_url, &[("Authorization", authorization)], 8)
    } else {
        client.get_follow(&api_url, &[], 8)
    }
    .map_err(|error| anyhow!("Hugging Face HTTPS query failed: {}", error))?;
    if !(200..300).contains(&response.status) {
        return Err(anyhow!("Failed to query Hugging Face API at {}", api_url));
    }
    let bytes = response
        .read_to_end(32 * 1024 * 1024)
        .map_err(|error| anyhow!("Hugging Face API response failed: {}", error))?;
    let body = Text::from_utf8_lossy(&bytes);
    let val: serde_json::Value = serde_json::from_str(&body)?;

    let mut filenames = Vector::new();
    if let Some(siblings) = val.get("siblings").and_then(|s| s.as_array()) {
        for item in siblings {
            if let Some(rfilename) = item.get("rfilename").and_then(|r| r.as_str()) {
                if rfilename.ends_with(".gguf") {
                    if filenames.len() == MAX_MODEL_FILES {
                        return Err(anyhow!("Hugging Face model file count exceeds the limit"));
                    }
                    filenames.push(safe_relative_hf_filename(rfilename)?.into());
                }
            }
        }
    }

    Ok(filenames)
}

pub async fn resolve_or_fetch_hf_model<F>(
    spec: &HfModelSpec,
    mut progress_cb: F,
) -> Result<HfModelFiles>
where
    F: FnMut(&str, f32, usize, usize) + Send + 'static,
{
    // 1. First check if model already exists in HF hub cache (~/.cache/huggingface/hub/) or local cache
    if let Some(existing_primary) =
        crate::client::find_model_file(&format!("{}:{}", spec.repo_id, spec.quant))
            .or_else(|| crate::client::find_model_file(&spec.model))
    {
        progress_cb(
            &format!(
                "✓ Found local cached weights at {}",
                path_file_name(&existing_primary)
            ),
            1.0,
            1,
            1,
        );
        return Ok(HfModelFiles {
            primary_entry_file: existing_primary.clone(),
            shard_files: [existing_primary].into_iter().collect(),
            mmproj_file: None,
            speedup_draft_file: None,
        });
    }

    let model_dir = spec.get_model_dir();
    mrml_runtime::create_dir_all(&model_dir)?;

    progress_cb(
        &format!(
            "Querying Hugging Face for model shards, mmproj & MTP speedup in {}...",
            spec.repo_id
        ),
        0.05,
        0,
        1,
    );

    let siblings = query_hf_api_siblings(spec).await.unwrap_or_default();

    let target_quant_lower = spec.quant.to_ascii_lowercase();
    let mut matching_shards = Vector::new();
    let mut mmproj_file_opt = None;
    let mut speedup_file_opt = None;

    for fname in &siblings {
        let fname_lower = fname.to_ascii_lowercase();
        if fname_lower.contains("mmproj") {
            if mmproj_file_opt.is_none() || fname_lower.contains(target_quant_lower.as_str()) {
                mmproj_file_opt = Some(fname.clone());
            }
        } else if fname_lower.contains("mtp") || fname_lower.contains("dflash") {
            if speedup_file_opt.is_none() || fname_lower.contains(target_quant_lower.as_str()) {
                speedup_file_opt = Some(fname.clone());
            }
        } else if fname_lower.contains(target_quant_lower.as_str()) {
            matching_shards.push(fname.clone());
        }
    }

    matching_shards[..].sort_unstable();

    // Fallbacks if not found via API
    if matching_shards.is_empty() {
        if spec.quant.eq_ignore_ascii_case("Q8_0") {
            for shard_idx in 1..=4 {
                matching_shards.push(
                    format!(
                        "{}-{}-{:05}-of-00004.gguf",
                        spec.model.to_ascii_lowercase(),
                        spec.quant.to_ascii_lowercase(),
                        shard_idx
                    )
                    .as_str()
                    .into(),
                );
            }
        } else {
            matching_shards.push(
                format!(
                    "{}-{}.gguf",
                    spec.model.to_ascii_lowercase(),
                    spec.quant.to_ascii_lowercase()
                )
                .as_str()
                .into(),
            );
        }
    }

    let mut download_queue = matching_shards.clone();
    if let Some(ref mmproj) = mmproj_file_opt {
        if !download_queue.contains(mmproj) {
            download_queue.push(mmproj.clone());
        }
    }
    if let Some(ref speedup) = speedup_file_opt {
        if !download_queue.contains(speedup) {
            download_queue.push(speedup.clone());
        }
    }

    let total_files = download_queue.len();
    if total_files == 0 || total_files > MAX_MODEL_FILES {
        return Err(anyhow!("Hugging Face model file count exceeds the limit"));
    }
    let mut budget = DownloadBudget::default();
    let mut downloaded_shard_paths = Vector::new();
    let mut resolved_mmproj_path = None;
    let mut resolved_speedup_path = None;

    for (idx, filename) in download_queue.iter().enumerate() {
        safe_relative_hf_filename(filename)?;
        let file_num = idx + 1;
        let dest_path = mrml_runtime::join_path(&model_dir, filename);
        let destination_directory =
            parent_path(&dest_path).ok_or_else(|| anyhow!("model destination has no parent"))?;
        mrml_runtime::create_dir_all(destination_directory)?;
        let part_path = mrml_runtime::join_path(&model_dir, &format!("{}.part", filename));
        let digest_path = format!("{}.sha3-512", dest_path);
        let part_digest_path = format!("{}.sha3-512", part_path);

        if let Some(cached_length) =
            native_file_len(&dest_path).filter(|length| *length > 10 * 1024 * 1024)
        {
            if cached_length > MAX_MODEL_FILE_BYTES {
                return Err(anyhow!("cached model file exceeds the per-file byte limit"));
            }
            if mrml_runtime::path_is_file(&digest_path) {
                if !digest_matches(&dest_path, &digest_path) {
                    mrml_runtime::remove_file(&dest_path)?;
                    mrml_runtime::remove_file(&digest_path)?;
                } else {
                    let msg = format!(
                        "✓ [File {}/{}] {} (cached; local SHA3-512 integrity matched, not publisher-authenticated)",
                        file_num, total_files, filename
                    );
                    println!("{}", msg);
                    progress_cb(
                        &msg,
                        file_num as f32 / total_files as f32,
                        file_num,
                        total_files,
                    );
                    budget.add_file(cached_length)?;
                    if filename.contains("mmproj") {
                        resolved_mmproj_path = Some(dest_path);
                    } else if filename.contains("mtp") || filename.contains("dflash") {
                        resolved_speedup_path = Some(dest_path);
                    } else {
                        downloaded_shard_paths.push(dest_path);
                    }
                    continue;
                }
            } else {
                let (digest, _) = hash_file(&dest_path)?;
                write_digest(&digest_path, &digest)?;
            }
            if mrml_runtime::path_is_file(&dest_path) {
                let msg = format!(
                    "✓ [File {}/{}] {} (cached; local SHA3-512 recorded, not publisher-authenticated)",
                    file_num, total_files, filename
                );
                println!("{}", msg);
                progress_cb(
                    &msg,
                    file_num as f32 / total_files as f32,
                    file_num,
                    total_files,
                );

                budget.add_file(cached_length)?;
                if filename.contains("mmproj") {
                    resolved_mmproj_path = Some(dest_path);
                } else if filename.contains("mtp") || filename.contains("dflash") {
                    resolved_speedup_path = Some(dest_path);
                } else {
                    downloaded_shard_paths.push(dest_path);
                }
                continue;
            }
        }

        let download_url = format!(
            "https://huggingface.co/{}/{}/resolve/main/{}",
            spec.user, spec.model, filename
        );

        if mrml_runtime::path_exists(&part_path) {
            mrml_runtime::remove_file(&part_path)?;
        }
        if mrml_runtime::path_exists(&part_digest_path) {
            mrml_runtime::remove_file(&part_digest_path)?;
        }
        println!(
            "⬇️ [File {}/{}] Downloading {}...",
            file_num, total_files, filename
        );

        let client = mrml_http::Client::new();
        let authorization =
            mrml_runtime::environment_variable("HF_TOKEN").map(|value| format!("Bearer {}", value));
        let mut response = match authorization.as_ref() {
            Some(auth) => client.get_follow(&download_url, &[("Authorization", auth)], 8),
            None => client.get_follow(&download_url, &[], 8),
        }
        .map_err(|error| anyhow!("HTTPS download failed for {}: {}", filename, error))?;
        if response.status != 200 {
            return Err(anyhow!(
                "Download of {} returned HTTP {}",
                filename,
                response.status
            ));
        }
        if let Some(content_length) = response.header("content-length") {
            let content_length = content_length
                .parse::<u64>()
                .map_err(|_| anyhow!("invalid model Content-Length"))?;
            if content_length > MAX_MODEL_FILE_BYTES
                || budget
                    .total
                    .checked_add(content_length)
                    .is_none_or(|total| total > MAX_MODEL_TOTAL_BYTES)
            {
                return Err(anyhow!("model download Content-Length exceeds byte limits"));
            }
        }
        let mut hash = Sha3_512::new();
        let mut downloaded = 0u64;
        let mut output = mrml_runtime::File::create_new(&part_path)?;
        let mut buffer = [0u8; 64 * 1024];
        let mut next_checkpoint = downloaded.saturating_add(64 * 1024 * 1024);
        loop {
            let read = response
                .read(&mut buffer)
                .map_err(|error| anyhow!("HTTPS body failed for {}: {}", filename, error))?;
            if read == 0 {
                break;
            }
            output.write_all(&buffer[..read])?;
            hash.update(&buffer[..read]);
            budget.add_chunk(&mut downloaded, read)?;
            if downloaded >= next_checkpoint {
                write_digest(&part_digest_path, &hash.clone().finalize())?;
                next_checkpoint = downloaded.saturating_add(64 * 1024 * 1024);
                let mb = downloaded as f64 / (1024.0 * 1024.0);
                let msg = format!(
                    "⬇️ [File {}/{}] {} ({:.1} MB downloaded, SHA3-512 checkpointed)...",
                    file_num, total_files, filename, mb
                );
                let file_pct = (mb / 4000.0).clamp(0.05, 0.95) as f32;
                progress_cb(
                    &msg,
                    ((file_num as f32 - 1.0) + file_pct) / total_files as f32,
                    file_num,
                    total_files,
                );
            }
        }
        let digest = hash.finalize();
        output.sync()?;
        drop(output);
        write_digest(&part_digest_path, &digest)?;

        // The staging file was exclusively created without following a final
        // link, fully written, and synchronized before its atomic promotion.
        if mrml_runtime::path_is_file(&part_path) {
            rename_file(&part_path, &dest_path)?;
            write_digest(&digest_path, &digest)?;
            if mrml_runtime::path_is_file(&part_digest_path) {
                mrml_runtime::remove_file(&part_digest_path)?;
            }
        }

        let done_msg = format!(
            "✓ [File {}/{}] {} (downloaded over TLS; local SHA3-512 recorded, not publisher-authenticated)",
            file_num, total_files, filename
        );
        println!("{}", done_msg);
        progress_cb(
            &done_msg,
            file_num as f32 / total_files as f32,
            file_num,
            total_files,
        );

        if filename.contains("mmproj") {
            resolved_mmproj_path = Some(dest_path);
        } else if filename.contains("mtp") || filename.contains("dflash") {
            resolved_speedup_path = Some(dest_path);
        } else {
            downloaded_shard_paths.push(dest_path);
        }
    }

    let primary_entry_file = downloaded_shard_paths.first().cloned().unwrap_or_else(|| {
        mrml_runtime::join_path(
            &model_dir,
            &format!(
                "{}-{}.gguf",
                spec.model.to_ascii_lowercase(),
                spec.quant.to_ascii_lowercase()
            ),
        )
    });

    let complete_msg = format!(
        "✨ All {} model weights ready in {}",
        total_files, model_dir
    );
    println!("{}", complete_msg);
    progress_cb(&complete_msg, 1.0, total_files, total_files);

    Ok(HfModelFiles {
        primary_entry_file,
        shard_files: downloaded_shard_paths.into_iter().collect(),
        mmproj_file: resolved_mmproj_path,
        speedup_draft_file: resolved_speedup_path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hf_spec_full() {
        let spec = HfModelSpec::parse("ggml-org/gemma-4-26B-A4B-it-GGUF:Q4_0").unwrap();
        assert_eq!(spec.user, "ggml-org");
        assert_eq!(spec.model, "gemma-4-26B-A4B-it-GGUF");
        assert_eq!(spec.quant, "Q4_0");
    }

    #[test]
    fn test_parse_hf_spec_sharded_q8() {
        let spec = HfModelSpec::parse("ggml-org/gemma-4-26B-A4B-it-GGUF:Q8_0").unwrap();
        assert_eq!(spec.user, "ggml-org");
        assert_eq!(spec.model, "gemma-4-26B-A4B-it-GGUF");
        assert_eq!(spec.quant, "Q8_0");
    }

    #[test]
    fn test_render_progress_bar() {
        let bar_half = render_progress_bar(0.5, 10);
        assert_eq!(bar_half, "[█████░░░░░]");
        let bar_full = render_progress_bar(1.0, 10);
        assert_eq!(bar_full, "[██████████]");
    }

    #[test]
    fn accepts_only_contained_portable_hugging_face_filenames() {
        assert_eq!(
            safe_relative_hf_filename("weights/model-Q4_0-00001-of-00002.gguf").unwrap(),
            "weights/model-Q4_0-00001-of-00002.gguf"
        );
        for hostile in [
            "",
            "/absolute.gguf",
            "../escape.gguf",
            "weights/../../escape.gguf",
            "weights\\escape.gguf",
            "C:escape.gguf",
            "model.gguf?download=1",
            "model.gguf#fragment",
            "NUL.gguf",
            "aux/model.gguf",
            "trailing./model.gguf",
            "double//model.gguf",
        ] {
            assert!(safe_relative_hf_filename(hostile).is_err(), "{hostile}");
        }
    }

    #[test]
    fn rejects_repository_components_that_can_change_urls_or_paths() {
        for hostile in [
            "../model:Q4_0",
            "owner/../model:Q4_0",
            "owner/model:../../Q4_0",
            "owner/model:Q4_0?revision=evil",
        ] {
            assert!(HfModelSpec::parse(hostile).is_err(), "{hostile}");
        }
    }

    #[test]
    fn model_download_budget_rejects_file_total_and_arithmetic_overflow() {
        let mut budget = DownloadBudget::default();
        budget.add_file(MAX_MODEL_FILE_BYTES).unwrap();
        assert!(budget.add_file(MAX_MODEL_TOTAL_BYTES).is_err());

        let mut file_bytes = MAX_MODEL_FILE_BYTES;
        assert!(budget.add_chunk(&mut file_bytes, 1).is_err());
        assert_eq!(file_bytes, MAX_MODEL_FILE_BYTES);

        let mut overflow = DownloadBudget { total: u64::MAX };
        let mut empty_file = 0;
        assert!(overflow.add_chunk(&mut empty_file, 1).is_err());
    }

    #[test]
    fn sha3_sidecar_detects_model_tampering() {
        let directory = mrml_runtime::temporary_directory();
        let path = mrml_runtime::join_path(&directory, "mrml-hash-test.bin");
        let sidecar = format!("{}.sha3-512", path);
        mrml_runtime::write_file(&path, b"authenticated model bytes").unwrap();
        let (digest, _) = hash_file(&path).unwrap();
        write_digest(&sidecar, &digest).unwrap();
        assert!(digest_matches(&path, &sidecar));
        mrml_runtime::write_file(&path, b"tampered model bytes").unwrap();
        assert!(!digest_matches(&path, &sidecar));
        let _ = mrml_runtime::remove_file(&path);
        let _ = mrml_runtime::remove_file(&sidecar);
    }

    #[test]
    fn live_hf_query_when_configured() {
        if mrml_runtime::environment_variable("MRML_HF_LIVE_TEST").is_none() {
            return;
        }
        let spec = HfModelSpec::parse("ggml-org/gemma-4-26B-A4B-it-GGUF:Q4_0").unwrap();
        let files = mrml_tools::block_on(query_hf_api_siblings(&spec)).unwrap();
        assert!(!files.is_empty());
    }
}
