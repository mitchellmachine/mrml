use std::collections::BTreeMap;
use std::fs;
use std::path::{Component, Path, PathBuf};

use super::Workspace;

const STATUS_PATH: &str = "docs/STATUS.md";
const UNSAFE_INVENTORY_PATH: &str = "docs/UNSAFE_INVENTORY.md";
const UNSAFE_POLICY_PATH: &str = "tools/ci/unsafe-policy.tsv";
const MAX_ASSURANCE_FILES: usize = 20_000;
const MAX_ASSURANCE_FILE_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct UnsafeCounts {
    blocks: usize,
    functions: usize,
    implementations: usize,
    externs: usize,
    traits: usize,
    undocumented_blocks: usize,
}

impl UnsafeCounts {
    const fn any(self) -> bool {
        self.blocks != 0
            || self.functions != 0
            || self.implementations != 0
            || self.externs != 0
            || self.traits != 0
    }

    fn add(&mut self, other: Self) -> Result<(), String> {
        self.blocks = self
            .blocks
            .checked_add(other.blocks)
            .ok_or("AssuranceUnsafeCountOverflow")?;
        self.functions = self
            .functions
            .checked_add(other.functions)
            .ok_or("AssuranceUnsafeCountOverflow")?;
        self.implementations = self
            .implementations
            .checked_add(other.implementations)
            .ok_or("AssuranceUnsafeCountOverflow")?;
        self.externs = self
            .externs
            .checked_add(other.externs)
            .ok_or("AssuranceUnsafeCountOverflow")?;
        self.traits = self
            .traits
            .checked_add(other.traits)
            .ok_or("AssuranceUnsafeCountOverflow")?;
        self.undocumented_blocks = self
            .undocumented_blocks
            .checked_add(other.undocumented_blocks)
            .ok_or("AssuranceUnsafeCountOverflow")?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct UnsafeBudget {
    counts: UnsafeCounts,
    reason: String,
}

#[derive(Clone, Debug)]
struct SourceInventory {
    rust_files: usize,
    rust_lines: usize,
    tests: usize,
    largest_path: String,
    largest_bytes: u64,
    unsafe_by_path: BTreeMap<String, UnsafeCounts>,
    unsafe_total: UnsafeCounts,
}

#[derive(Clone, Copy, Debug, Default)]
struct ManifestInventory {
    manifests: usize,
    artifacts: usize,
    features: usize,
    build_inputs: usize,
    declared_tests: usize,
    examples: usize,
    benchmarks: usize,
    binaries: usize,
}

#[derive(Clone, Copy, Debug, Default)]
struct GraphInventory {
    compile_edges: usize,
    build_tool_edges: usize,
    runtime_interface_edges: usize,
    package_edges: usize,
    system_release_edges: usize,
}

#[derive(Clone, Copy, Debug, Default)]
struct WorkflowInventory {
    audit: bool,
    assurance: bool,
    linux_full_tests: bool,
    windows_full_tests: bool,
    cuda_profile: bool,
    cuda_target: bool,
    stage_zero_clippy: bool,
    full_asan_tests: bool,
}

pub(super) fn command(workspace: &Workspace, args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str).unwrap_or("check") {
        "check" if args.len() == 1 || args.is_empty() => check(workspace),
        "generate" if args.len() == 1 => generate(workspace),
        other => Err(format!(
            "AssuranceUsage {{ command: {other}, usage: mrml assurance <check|generate> }}"
        )),
    }
}

fn check(workspace: &Workspace) -> Result<(), String> {
    let source = source_inventory(&workspace.root)?;
    let policy = unsafe_policy(&workspace.root)?;
    validate_unsafe_policy(&workspace.root, &source.unsafe_by_path, &policy)?;
    let manifests = manifest_inventory(workspace)?;
    let graph = graph_inventory(&workspace.root)?;
    let workflows = workflow_inventory(&workspace.root)?;
    validate_workflows(workflows)?;
    check_generated(
        &workspace.root,
        STATUS_PATH,
        &render_status(workspace, &source, manifests, graph, workflows),
    )?;
    check_generated(
        &workspace.root,
        UNSAFE_INVENTORY_PATH,
        &render_unsafe_inventory(&source, &policy),
    )?;
    check_markdown_links(&workspace.root)?;
    println!(
        "assurance|status=PASS|packages={}|rust_files={}|unsafe_files={}|links=PASS|generated=PASS|workflows=PASS",
        workspace.components.len(),
        source.rust_files,
        source.unsafe_by_path.len()
    );
    Ok(())
}

fn generate(workspace: &Workspace) -> Result<(), String> {
    let source = source_inventory(&workspace.root)?;
    let policy = unsafe_policy(&workspace.root)?;
    validate_unsafe_policy(&workspace.root, &source.unsafe_by_path, &policy)?;
    let manifests = manifest_inventory(workspace)?;
    let graph = graph_inventory(&workspace.root)?;
    let workflows = workflow_inventory(&workspace.root)?;
    validate_workflows(workflows)?;
    write_generated(
        &workspace.root,
        STATUS_PATH,
        &render_status(workspace, &source, manifests, graph, workflows),
    )?;
    write_generated(
        &workspace.root,
        UNSAFE_INVENTORY_PATH,
        &render_unsafe_inventory(&source, &policy),
    )?;
    println!(
        "assurance-generate|status=PASS|status_file={STATUS_PATH}|unsafe_file={UNSAFE_INVENTORY_PATH}"
    );
    Ok(())
}

fn source_inventory(root: &Path) -> Result<SourceInventory, String> {
    let mut rust_files = rust_files(root)?;
    rust_files.sort();
    let mut inventory = SourceInventory {
        rust_files: 0,
        rust_lines: 0,
        tests: 0,
        largest_path: String::new(),
        largest_bytes: 0,
        unsafe_by_path: BTreeMap::new(),
        unsafe_total: UnsafeCounts::default(),
    };
    for path in rust_files {
        let metadata = fs::metadata(&path).map_err(|error| {
            format!(
                "AssuranceMetadata {{ path: {}, detail: {error} }}",
                path.display()
            )
        })?;
        if metadata.len() > MAX_ASSURANCE_FILE_BYTES {
            return Err(format!(
                "AssuranceSourceTooLarge {{ path: {}, bytes: {}, limit: {MAX_ASSURANCE_FILE_BYTES} }}",
                path.display(),
                metadata.len()
            ));
        }
        let text = fs::read_to_string(&path).map_err(|error| {
            format!(
                "AssuranceRead {{ path: {}, detail: {error} }}",
                path.display()
            )
        })?;
        let relative = relative_path(root, &path)?;
        inventory.rust_files = inventory
            .rust_files
            .checked_add(1)
            .ok_or("AssuranceSourceCountOverflow")?;
        inventory.rust_lines = inventory
            .rust_lines
            .checked_add(text.lines().count())
            .ok_or("AssuranceSourceCountOverflow")?;
        inventory.tests = inventory
            .tests
            .checked_add(text.matches("#[test]").count())
            .ok_or("AssuranceSourceCountOverflow")?;
        if metadata.len() > inventory.largest_bytes {
            inventory.largest_bytes = metadata.len();
            inventory.largest_path = relative.clone();
        }
        let counts = unsafe_counts(&text, &relative)?;
        inventory.unsafe_total.add(counts)?;
        if counts.any() {
            inventory.unsafe_by_path.insert(relative, counts);
        }
    }
    Ok(inventory)
}

fn rust_files(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    let mut visited = 0_usize;
    while let Some(directory) = pending.pop() {
        visited = visited.checked_add(1).ok_or("AssurancePathCountOverflow")?;
        if visited > MAX_ASSURANCE_FILES {
            return Err("AssurancePathLimit".into());
        }
        let mut entries = fs::read_dir(&directory)
            .map_err(|error| {
                format!(
                    "AssuranceReadDirectory {{ path: {}, detail: {error} }}",
                    directory.display()
                )
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                format!(
                    "AssuranceReadDirectory {{ path: {}, detail: {error} }}",
                    directory.display()
                )
            })?;
        entries.sort_by_key(fs::DirEntry::file_name);
        for entry in entries {
            let path = entry.path();
            let file_type = entry.file_type().map_err(|error| {
                format!(
                    "AssuranceFileType {{ path: {}, detail: {error} }}",
                    path.display()
                )
            })?;
            if file_type.is_symlink() {
                return Err(format!(
                    "AssuranceSymlinkRejected {{ path: {} }}",
                    path.display()
                ));
            }
            if file_type.is_dir() {
                let name = entry.file_name();
                if name != ".git" && name != "target" {
                    pending.push(path);
                }
            } else if path.extension().and_then(|value| value.to_str()) == Some("rs") {
                files.push(path);
            }
        }
    }
    Ok(files)
}

fn manifest_inventory(workspace: &Workspace) -> Result<ManifestInventory, String> {
    let mut inventory = ManifestInventory::default();
    for component in &workspace.components {
        let path = workspace.root.join(&component.path).join("mrml.toml");
        let text = fs::read_to_string(&path).map_err(|error| {
            format!(
                "AssuranceManifestRead {{ path: {}, detail: {error} }}",
                path.display()
            )
        })?;
        inventory.manifests += 1;
        for line in text.lines().map(str::trim) {
            match line {
                "[[artifact]]" => inventory.artifacts += 1,
                "[[feature]]" => inventory.features += 1,
                "[[build_input]]" => inventory.build_inputs += 1,
                "[[test]]" => inventory.declared_tests += 1,
                "[[example]]" => inventory.examples += 1,
                "[[benchmark]]" => inventory.benchmarks += 1,
                "[[binary]]" => inventory.binaries += 1,
                _ => {}
            }
        }
    }
    Ok(inventory)
}

fn graph_inventory(root: &Path) -> Result<GraphInventory, String> {
    let text = fs::read_to_string(root.join("mrml.lock"))
        .map_err(|error| format!("AssuranceLockRead {{ detail: {error} }}"))?;
    let mut graph = GraphInventory::default();
    let mut in_graphs = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_graphs = line == "[graphs]";
            continue;
        }
        if !in_graphs || line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once('=') else {
            continue;
        };
        let value = value
            .trim()
            .parse::<usize>()
            .map_err(|_| format!("AssuranceLockGraphInvalid {{ field: {} }}", name.trim()))?;
        match name.trim() {
            "compile_edges" => graph.compile_edges = value,
            "build_tool_edges" => graph.build_tool_edges = value,
            "runtime_interface_edges" => graph.runtime_interface_edges = value,
            "package_edges" => graph.package_edges = value,
            "system_release_edges" => graph.system_release_edges = value,
            _ => {}
        }
    }
    Ok(graph)
}

fn workflow_inventory(root: &Path) -> Result<WorkflowInventory, String> {
    let ci = fs::read_to_string(root.join(".gitea/workflows/ci.yml")).map_err(|error| {
        format!("AssuranceWorkflowRead {{ workflow: ci.yml, detail: {error} }}")
    })?;
    let sanitizers =
        fs::read_to_string(root.join(".gitea/workflows/sanitizers.yml")).map_err(|error| {
            format!("AssuranceWorkflowRead {{ workflow: sanitizers.yml, detail: {error} }}")
        })?;
    let ci_commands = workflow_commands(&ci);
    let sanitizer_commands = workflow_commands(&sanitizers);
    Ok(WorkflowInventory {
        audit: has_mrml_command(
            &ci_commands,
            &[
                "audit",
                "--all",
                "--target",
                "native",
                "--output",
                "structured",
            ],
        ),
        assurance: has_mrml_command(&ci_commands, &["assurance", "check"]),
        linux_full_tests: has_mrml_command(
            &ci_commands,
            &["test", "--all", "--target", "linux", "--release"],
        ),
        windows_full_tests: has_mrml_command(
            &ci_commands,
            &["test", "--all", "--target", "windows", "--release"],
        ),
        cuda_profile: has_mrml_command(
            &ci_commands,
            &[
                "build",
                "org.mrml.library.tensor",
                "--target",
                "linux",
                "--feature-profile",
                "cuda",
            ],
        ) && has_mrml_command(
            &ci_commands,
            &[
                "build",
                "org.mrml.library.tensor",
                "--target",
                "windows",
                "--feature-profile",
                "cuda",
            ],
        ),
        cuda_target: count_mrml_commands(
            &ci_commands,
            &[
                "build",
                "org.mrml.library.tensor",
                "--target",
                "cuda-nvidia",
            ],
        ) >= 2,
        stage_zero_clippy: has_cargo_command(
            &ci_commands,
            &[
                "clippy",
                "--locked",
                "--all-targets",
                "--",
                "-D",
                "warnings",
            ],
        ),
        full_asan_tests: has_mrml_command(
            &sanitizer_commands,
            &[
                "test",
                "--all",
                "--target",
                "linux",
                "--sanitizer",
                "address",
            ],
        ),
    })
}

fn workflow_commands(source: &str) -> Vec<String> {
    let mut commands = Vec::new();
    let mut block_parent_indent = None;
    for original in source.lines() {
        let trimmed = original.trim_start();
        let indent = original.len().saturating_sub(trimmed.len());
        if let Some(parent_indent) = block_parent_indent {
            if trimmed.is_empty() {
                continue;
            }
            if indent > parent_indent {
                let command = yaml_value_without_comment(trimmed);
                if !command.is_empty() {
                    commands.push(command.to_owned());
                }
                continue;
            }
            block_parent_indent = None;
        }
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let statement = trimmed.strip_prefix("- ").unwrap_or(trimmed).trim_start();
        let Some(value) = statement.strip_prefix("run:") else {
            continue;
        };
        let value = yaml_value_without_comment(value.trim_start());
        if matches!(value, "|" | "|-" | "|+" | ">" | ">-" | ">+") {
            block_parent_indent = Some(indent);
        } else if !value.is_empty() {
            commands.push(value.to_owned());
        }
    }
    commands
}

fn has_mrml_command(commands: &[String], expected: &[&str]) -> bool {
    count_mrml_commands(commands, expected) != 0
}

fn count_mrml_commands(commands: &[String], expected: &[&str]) -> usize {
    commands
        .iter()
        .filter(|command| {
            let tokens = command_tokens(command);
            let Some((program, arguments)) = tokens.split_first() else {
                return false;
            };
            let program = program.replace('\\', "/");
            (program.ends_with("/mrml") || program.ends_with("/mrml.exe"))
                && token_subsequence(arguments, expected)
        })
        .count()
}

fn has_cargo_command(commands: &[String], expected: &[&str]) -> bool {
    commands.iter().any(|command| {
        let tokens = command_tokens(command);
        let Some((program, arguments)) = tokens.split_first() else {
            return false;
        };
        let program = program.replace('\\', "/");
        let cargo =
            program == "cargo" || program.ends_with("/cargo") || program.ends_with("/cargo.exe");
        cargo && token_subsequence(arguments, expected)
    })
}

fn command_tokens(command: &str) -> Vec<&str> {
    command
        .split_ascii_whitespace()
        .map(|token| token.trim_matches(['\'', '"']))
        .collect()
}

fn token_subsequence(actual: &[&str], expected: &[&str]) -> bool {
    !expected.is_empty()
        && actual
            .windows(expected.len())
            .any(|window| window == expected)
}

fn yaml_value_without_comment(value: &str) -> &str {
    let mut single_quoted = false;
    let mut double_quoted = false;
    let mut escaped = false;
    let mut previous = None;
    for (index, character) in value.char_indices() {
        if double_quoted {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                double_quoted = false;
            }
        } else if single_quoted {
            if character == '\'' {
                single_quoted = false;
            }
        } else if character == '"' {
            double_quoted = true;
        } else if character == '\'' {
            single_quoted = true;
        } else if character == '#' && previous.is_none_or(char::is_whitespace) {
            return value[..index].trim_end();
        }
        previous = Some(character);
    }
    value.trim_end()
}

fn validate_workflows(workflows: WorkflowInventory) -> Result<(), String> {
    let checks = [
        ("native-audit", workflows.audit),
        ("repository-assurance", workflows.assurance),
        ("linux-full-tests", workflows.linux_full_tests),
        ("windows-full-tests", workflows.windows_full_tests),
        ("cuda-feature-profile", workflows.cuda_profile),
        ("cuda-ptx-target", workflows.cuda_target),
        ("stage-zero-clippy", workflows.stage_zero_clippy),
        ("full-address-sanitizer", workflows.full_asan_tests),
    ];
    for (name, present) in checks {
        if !present {
            return Err(format!("AssuranceWorkflowGateMissing {{ gate: {name} }}"));
        }
    }
    Ok(())
}

fn unsafe_policy(root: &Path) -> Result<BTreeMap<String, UnsafeBudget>, String> {
    let path = root.join(UNSAFE_POLICY_PATH);
    let text = fs::read_to_string(&path).map_err(|error| {
        format!("AssuranceUnsafePolicyRead {{ path: {UNSAFE_POLICY_PATH}, detail: {error} }}")
    })?;
    let mut policy = BTreeMap::new();
    for (index, line) in text.lines().enumerate() {
        let line_number = index + 1;
        let line = line.trim_end();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.len() != 8 {
            return Err(format!(
                "AssuranceUnsafePolicyFormat {{ line: {line_number}, fields: {} }}",
                fields.len()
            ));
        }
        let path = fields[0];
        if !safe_relative_path(path) || !path.ends_with(".rs") {
            return Err(format!(
                "AssuranceUnsafePolicyPath {{ line: {line_number}, path: {path} }}"
            ));
        }
        let parse = |field: &str, name: &str| {
            field.parse::<usize>().map_err(|_| {
                format!("AssuranceUnsafePolicyCount {{ line: {line_number}, field: {name} }}")
            })
        };
        let budget = UnsafeBudget {
            counts: UnsafeCounts {
                blocks: parse(fields[1], "blocks")?,
                functions: parse(fields[2], "functions")?,
                implementations: parse(fields[3], "implementations")?,
                externs: parse(fields[4], "externs")?,
                traits: parse(fields[5], "traits")?,
                undocumented_blocks: parse(fields[6], "undocumented-blocks")?,
            },
            reason: fields[7].trim().to_owned(),
        };
        if budget.reason.len() < 24 {
            return Err(format!(
                "AssuranceUnsafePolicyReason {{ line: {line_number}, path: {path} }}"
            ));
        }
        if policy.insert(path.to_owned(), budget).is_some() {
            return Err(format!("AssuranceUnsafePolicyDuplicate {{ path: {path} }}"));
        }
    }
    Ok(policy)
}

fn validate_unsafe_policy(
    root: &Path,
    actual: &BTreeMap<String, UnsafeCounts>,
    policy: &BTreeMap<String, UnsafeBudget>,
) -> Result<(), String> {
    for (path, counts) in actual {
        let budget = policy
            .get(path)
            .ok_or_else(|| format!("UnsafeBoundaryUnadmitted {{ path: {path} }}"))?;
        let checks = [
            ("blocks", counts.blocks, budget.counts.blocks),
            ("functions", counts.functions, budget.counts.functions),
            (
                "implementations",
                counts.implementations,
                budget.counts.implementations,
            ),
            ("externs", counts.externs, budget.counts.externs),
            ("traits", counts.traits, budget.counts.traits),
            (
                "undocumented-blocks",
                counts.undocumented_blocks,
                budget.counts.undocumented_blocks,
            ),
        ];
        for (kind, observed, admitted) in checks {
            if observed > admitted {
                return Err(format!(
                    "UnsafeBoundaryGrowth {{ path: {path}, kind: {kind}, observed: {observed}, admitted: {admitted} }}"
                ));
            }
        }
    }
    for path in policy.keys() {
        if !root.join(path).is_file() {
            return Err(format!("UnsafeBoundaryPathMissing {{ path: {path} }}"));
        }
    }
    Ok(())
}

fn unsafe_counts(source: &str, path: &str) -> Result<UnsafeCounts, String> {
    let stripped = strip_non_code(source, path)?;
    let tokens = simple_tokens(&stripped);
    let lines = source.lines().collect::<Vec<_>>();
    let mut counts = UnsafeCounts::default();
    for (index, token) in tokens.iter().enumerate() {
        if token.text != "unsafe" {
            continue;
        }
        let Some(next) = tokens.get(index + 1) else {
            continue;
        };
        match next.text.as_str() {
            "{" => {
                counts.blocks += 1;
                if !has_safety_comment(&lines, token.line) {
                    counts.undocumented_blocks += 1;
                }
            }
            "fn" => counts.functions += 1,
            "impl" => counts.implementations += 1,
            "extern" => counts.externs += 1,
            "trait" => counts.traits += 1,
            _ => {}
        }
    }
    Ok(counts)
}

#[derive(Clone, Debug)]
struct SimpleToken {
    text: String,
    line: usize,
}

fn simple_tokens(source: &str) -> Vec<SimpleToken> {
    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0_usize;
    let mut line = 1_usize;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'\n' {
            line += 1;
            index += 1;
        } else if byte.is_ascii_whitespace() {
            index += 1;
        } else if byte.is_ascii_alphabetic() || byte == b'_' {
            let start = index;
            index += 1;
            while index < bytes.len()
                && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
            {
                index += 1;
            }
            tokens.push(SimpleToken {
                text: source[start..index].to_owned(),
                line,
            });
        } else {
            tokens.push(SimpleToken {
                text: char::from(byte).to_string(),
                line,
            });
            index += 1;
        }
    }
    tokens
}

fn strip_non_code(source: &str, path: &str) -> Result<String, String> {
    let bytes = source.as_bytes();
    let mut output = bytes.to_vec();
    let mut index = 0_usize;
    while index < bytes.len() {
        if bytes.get(index..index + 2) == Some(&b"//"[..]) {
            let start = index;
            index += 2;
            while index < bytes.len() && bytes[index] != b'\n' {
                index += 1;
            }
            blank(&mut output, start, index);
            continue;
        }
        if bytes.get(index..index + 2) == Some(&b"/*"[..]) {
            let start = index;
            index += 2;
            let mut depth = 1_usize;
            while index < bytes.len() && depth != 0 {
                if bytes.get(index..index + 2) == Some(&b"/*"[..]) {
                    depth += 1;
                    index += 2;
                } else if bytes.get(index..index + 2) == Some(&b"*/"[..]) {
                    depth -= 1;
                    index += 2;
                } else {
                    index += 1;
                }
            }
            if depth != 0 {
                return Err(format!(
                    "AssuranceUnterminatedComment {{ path: {path}, byte: {start} }}"
                ));
            }
            blank(&mut output, start, index);
            continue;
        }
        if raw_string_start(bytes, index) {
            let end = raw_string_end(bytes, index)?.ok_or_else(|| {
                format!("AssuranceRawStringInvalid {{ path: {path}, byte: {index} }}")
            })?;
            blank(&mut output, index, end);
            index = end;
            continue;
        }
        if normal_string_start(bytes, index) {
            let end = normal_string_end(bytes, index).ok_or_else(|| {
                format!("AssuranceUnterminatedString {{ path: {path}, byte: {index} }}")
            })?;
            blank(&mut output, index, end);
            index = end;
            continue;
        }
        if let Some(end) = character_literal_end(bytes, index) {
            blank(&mut output, index, end);
            index = end;
            continue;
        }
        index += 1;
    }
    String::from_utf8(output).map_err(|_| format!("AssuranceSourceEncoding {{ path: {path} }}"))
}

fn blank(output: &mut [u8], start: usize, end: usize) {
    for byte in &mut output[start..end] {
        if *byte != b'\n' && *byte != b'\r' {
            *byte = b' ';
        }
    }
}

fn raw_string_start(bytes: &[u8], start: usize) -> bool {
    let previous_is_identifier =
        start != 0 && (bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'_');
    if previous_is_identifier {
        return false;
    }
    let mut index = start;
    if bytes.get(index..index + 2) == Some(&b"br"[..])
        || bytes.get(index..index + 2) == Some(&b"cr"[..])
    {
        index += 2;
    } else if bytes.get(index) == Some(&b'r') {
        index += 1;
    } else {
        return false;
    }
    while bytes.get(index) == Some(&b'#') {
        index += 1;
    }
    bytes.get(index) == Some(&b'"')
}

fn raw_string_end(bytes: &[u8], start: usize) -> Result<Option<usize>, String> {
    if !raw_string_start(bytes, start) {
        return Ok(None);
    }
    let mut index = start;
    if bytes.get(index..index + 2) == Some(&b"br"[..])
        || bytes.get(index..index + 2) == Some(&b"cr"[..])
    {
        index += 2;
    } else {
        index += 1;
    }
    let mut hashes = 0_usize;
    while bytes.get(index) == Some(&b'#') {
        hashes += 1;
        index += 1;
    }
    index += 1;
    while index < bytes.len() {
        if bytes[index] == b'"'
            && (0..hashes).all(|offset| bytes.get(index + 1 + offset) == Some(&b'#'))
        {
            return Ok(Some(index + 1 + hashes));
        }
        index += 1;
    }
    Err(format!(
        "AssuranceUnterminatedRawString {{ byte: {start} }}"
    ))
}

fn normal_string_start(bytes: &[u8], start: usize) -> bool {
    if bytes.get(start) == Some(&b'"') {
        return true;
    }
    (bytes.get(start) == Some(&b'b') || bytes.get(start) == Some(&b'c'))
        && bytes.get(start + 1) == Some(&b'"')
        && (start == 0 || !(bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'_'))
}

fn normal_string_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut quote = start;
    if bytes.get(start) == Some(&b'b') || bytes.get(start) == Some(&b'c') {
        quote += 1;
    }
    if bytes.get(quote) != Some(&b'"') {
        return None;
    }
    let mut index = quote + 1;
    let mut escaped = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if escaped {
            escaped = false;
        } else if byte == b'\\' {
            escaped = true;
        } else if byte == b'"' {
            return Some(index + 1);
        }
        index += 1;
    }
    None
}

fn character_literal_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut quote = start;
    if bytes.get(start) == Some(&b'b') && bytes.get(start + 1) == Some(&b'\'') {
        let previous_is_identifier =
            start != 0 && (bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'_');
        if previous_is_identifier {
            return None;
        }
        quote += 1;
    }
    if bytes.get(quote) != Some(&b'\'') {
        return None;
    }
    let mut index = quote + 1;
    let byte = *bytes.get(index)?;
    if matches!(byte, b'\n' | b'\r' | b'\'') {
        return None;
    }
    if byte == b'\\' {
        index += 1;
        match *bytes.get(index)? {
            b'u' if bytes.get(index + 1) == Some(&b'{') => {
                index += 2;
                while bytes.get(index).copied() != Some(b'}') {
                    if matches!(bytes.get(index).copied(), None | Some(b'\n' | b'\r')) {
                        return None;
                    }
                    index += 1;
                }
                index += 1;
            }
            b'x' => index = index.checked_add(3)?,
            _ => index += 1,
        }
    } else {
        let width = utf8_scalar_width(byte)?;
        index = index.checked_add(width)?;
    }
    (bytes.get(index) == Some(&b'\'')).then_some(index + 1)
}

const fn utf8_scalar_width(first: u8) -> Option<usize> {
    if first < 0x80 {
        Some(1)
    } else if first & 0xe0 == 0xc0 {
        Some(2)
    } else if first & 0xf0 == 0xe0 {
        Some(3)
    } else if first & 0xf8 == 0xf0 {
        Some(4)
    } else {
        None
    }
}

fn has_safety_comment(lines: &[&str], line: usize) -> bool {
    let start = line.saturating_sub(4);
    let end = line.saturating_add(2).min(lines.len());
    lines
        .get(start..end)
        .is_some_and(|window| window.iter().any(|value| value.contains("SAFETY:")))
}

fn render_status(
    workspace: &Workspace,
    source: &SourceInventory,
    manifests: ManifestInventory,
    graph: GraphInventory,
    workflows: WorkflowInventory,
) -> String {
    let mut output = String::new();
    output.push_str("# MRML generated workspace status\n\n");
    output.push_str("> Generated by `mrml assurance generate`. Do not edit package counts or evidence claims by hand. This is an inventory and verification-scope record, not a production-readiness claim.\n\n");
    output.push_str("## Machine-readable graph\n\n");
    output.push_str("| Measure | Current value |\n| --- | ---: |\n");
    output.push_str(&format!(
        "| Workspace packages | {} |\n",
        workspace.components.len()
    ));
    output.push_str(&format!(
        "| Package manifests | {} |\n",
        manifests.manifests
    ));
    output.push_str(&format!("| Compile edges | {} |\n", graph.compile_edges));
    output.push_str(&format!("| Package edges | {} |\n", graph.package_edges));
    output.push_str(&format!(
        "| Runtime-interface edges | {} |\n",
        graph.runtime_interface_edges
    ));
    output.push_str(&format!(
        "| Build-tool edges | {} |\n",
        graph.build_tool_edges
    ));
    output.push_str(&format!(
        "| System-release edges | {} |\n",
        graph.system_release_edges
    ));
    output.push_str(&format!(
        "| Feature declarations | {} |\n",
        manifests.features
    ));
    output.push_str(&format!(
        "| Artifact declarations | {} |\n",
        manifests.artifacts
    ));
    output.push_str(&format!(
        "| Exact build-input declarations | {} |\n",
        manifests.build_inputs
    ));
    output.push_str(&format!(
        "| Declared integration tests | {} |\n",
        manifests.declared_tests
    ));
    output.push_str(&format!("| Declared examples | {} |\n", manifests.examples));
    output.push_str(&format!(
        "| Declared benchmarks | {} |\n",
        manifests.benchmarks
    ));
    output.push_str(&format!("| Declared binaries | {} |\n", manifests.binaries));

    output.push_str("\n## Source and test inventory\n\n");
    output.push_str("| Measure | Current value |\n| --- | ---: |\n");
    output.push_str(&format!("| Rust source files | {} |\n", source.rust_files));
    output.push_str(&format!("| Rust source lines | {} |\n", source.rust_lines));
    output.push_str(&format!(
        "| Static `#[test]` annotations | {} |\n",
        source.tests
    ));
    output.push_str(&format!(
        "| Largest Rust source | `{}` ({} bytes) |\n",
        source.largest_path, source.largest_bytes
    ));
    output.push_str(&format!(
        "| Files containing admitted unsafe boundaries | {} |\n",
        source.unsafe_by_path.len()
    ));
    output.push_str(&format!(
        "| Unsafe blocks | {} |\n",
        source.unsafe_total.blocks
    ));
    output.push_str(&format!(
        "| Unsafe functions | {} |\n",
        source.unsafe_total.functions
    ));
    output.push_str(&format!(
        "| Unsafe implementations | {} |\n",
        source.unsafe_total.implementations
    ));
    output.push_str(&format!(
        "| Unsafe extern blocks | {} |\n",
        source.unsafe_total.externs
    ));
    output.push_str(&format!(
        "| Unsafe traits | {} |\n",
        source.unsafe_total.traits
    ));
    output.push_str(&format!(
        "| Unsafe blocks without a nearby `SAFETY:` note | {} |\n",
        source.unsafe_total.undocumented_blocks
    ));

    output.push_str("\n## Enforced repository gates\n\n");
    output.push_str("- Build inputs are admitted by stable ID plus kind, repository path, and line-independent token fingerprint. Count-preserving substitution, stale declarations, duplicate identities, comments, strings, and multiline expressions have dedicated audit tests.\n");
    output.push_str("- Audited Rust source files are limited to 2 MiB; the compiler code generator is split into phase-oriented include units below that ceiling.\n");
    output.push_str("- Unsafe growth is fail-closed against `tools/ci/unsafe-policy.tsv`; reductions pass without increasing a budget. The detailed generated inventory is in [UNSAFE_INVENTORY.md](UNSAFE_INVENTORY.md).\n");
    output.push_str("- CI checks canonical manifests and lock state, the exact-site audit, generated-document drift, local Markdown links, full native Linux and Windows tests, the host CUDA feature profile, the CUDA PTX target, stage-zero Clippy, and full Linux AddressSanitizer tests.\n");

    output.push_str("\n## CI configuration evidence\n\n");
    output.push_str("| Gate | Configured | Evidence level |\n| --- | --- | --- |\n");
    let configured = |value: bool| if value { "yes" } else { "no" };
    output.push_str(&format!("| Exact native audit | {} | workflow configuration; execution is established only by the CI result |\n", configured(workflows.audit)));
    output.push_str(&format!("| Generated status, unsafe policy, and links | {} | workflow configuration; execution is established only by the CI result |\n", configured(workflows.assurance)));
    output.push_str(&format!("| Full Linux native tests | {} | workflow configuration; execution is established only by the CI result |\n", configured(workflows.linux_full_tests)));
    output.push_str(&format!("| Full Windows native tests | {} | workflow configuration; execution is established only by the CI result |\n", configured(workflows.windows_full_tests)));
    output.push_str(&format!("| Host CUDA feature-profile build | {} | compile-only workflow configuration; no device authority |\n", configured(workflows.cuda_profile)));
    output.push_str(&format!("| CUDA PTX target build | {} | compile-only workflow configuration; no device authority |\n", configured(workflows.cuda_target)));
    output.push_str(&format!("| Stage-zero Clippy | {} | Cargo frontend only; native packages are built directly with `rustc` |\n", configured(workflows.stage_zero_clippy)));
    output.push_str(&format!("| Full Linux AddressSanitizer tests | {} | Linux-compatible native graph selected by `mrml`; execution is established only by the CI result |\n", configured(workflows.full_asan_tests)));

    output.push_str("\n## Evidence boundaries and explicit gaps\n\n");
    output.push_str("- A checked-in workflow is not evidence that a particular revision passed. Use the corresponding GitHub Actions result and retained artifacts for that claim.\n");
    output.push_str("- QEMU, KVM, WHP, model, parser, and service probes are narrower than production deployment. Physical-device, IOMMU, firmware, power-loss, accessibility-user, and independent-security-audit evidence must be recorded separately.\n");
    output.push_str("- Zstandard compressed-block support, complete Opus mode coverage, NVIDIA AV1 hardware execution, and GUI-probe application IPC integration remain explicitly incomplete in their owning source modules.\n");
    output.push_str("- MRML remains experimental research: this inventory does not claim a complete Rust compiler, production codec conformance, production-secure networking, or a production operating system.\n");
    output
}

fn render_unsafe_inventory(
    source: &SourceInventory,
    policy: &BTreeMap<String, UnsafeBudget>,
) -> String {
    let mut output = String::new();
    output.push_str("# Generated unsafe-boundary inventory\n\n");
    output.push_str("> Generated by `mrml assurance generate` from Rust tokens and `tools/ci/unsafe-policy.tsv`. Reductions are accepted; new files or growth beyond a checked-in baseline budget fail `mrml assurance check`.\n\n");
    output.push_str(&format!("Unsafe-bearing files: **{}**. Unsafe blocks: **{}**. Unsafe functions: **{}**. Unsafe implementations: **{}**. Unsafe extern blocks: **{}**. Unsafe traits: **{}**. Blocks without a nearby `SAFETY:` note: **{}**.\n\n", source.unsafe_by_path.len(), source.unsafe_total.blocks, source.unsafe_total.functions, source.unsafe_total.implementations, source.unsafe_total.externs, source.unsafe_total.traits, source.unsafe_total.undocumented_blocks));
    output.push_str("| Path | Blocks | Functions | Impls | Externs | Traits | Undocumented blocks | Admission rationale |\n");
    output.push_str("| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |\n");
    for (path, counts) in &source.unsafe_by_path {
        let reason = policy
            .get(path)
            .map(|entry| entry.reason.as_str())
            .unwrap_or("UNADMITTED");
        output.push_str(&format!(
            "| `{path}` | {} | {} | {} | {} | {} | {} | {} |\n",
            counts.blocks,
            counts.functions,
            counts.implementations,
            counts.externs,
            counts.traits,
            counts.undocumented_blocks,
            escape_markdown(reason)
        ));
    }
    output
}

fn check_generated(root: &Path, relative: &str, expected: &str) -> Result<(), String> {
    let path = root.join(relative);
    let actual = fs::read_to_string(&path).map_err(|error| {
        format!("AssuranceGeneratedMissing {{ path: {relative}, detail: {error} }}")
    })?;
    if normalize_newlines(&actual) != normalize_newlines(expected) {
        return Err(format!(
            "AssuranceGeneratedDrift {{ path: {relative}, repair: mrml assurance generate }}"
        ));
    }
    Ok(())
}

fn write_generated(root: &Path, relative: &str, text: &str) -> Result<(), String> {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            format!(
                "AssuranceGeneratedDirectory {{ path: {}, detail: {error} }}",
                parent.display()
            )
        })?;
    }
    fs::write(&path, text)
        .map_err(|error| format!("AssuranceGeneratedWrite {{ path: {relative}, detail: {error} }}"))
}

fn normalize_newlines(value: &str) -> String {
    value.replace("\r\n", "\n")
}

fn check_markdown_links(root: &Path) -> Result<(), String> {
    let mut markdown = files_with_extension(root, "md")?;
    markdown.sort();
    let mut failures = Vec::new();
    for file in markdown {
        let text = fs::read_to_string(&file).map_err(|error| {
            format!(
                "AssuranceMarkdownRead {{ path: {}, detail: {error} }}",
                file.display()
            )
        })?;
        let relative = relative_path(root, &file)?;
        for (line, target) in markdown_targets(&text) {
            if external_target(&target) {
                continue;
            }
            let without_anchor = target.split(['#', '?']).next().unwrap_or("");
            let target = without_anchor.trim_matches(['<', '>']);
            if target.is_empty() {
                continue;
            }
            let decoded = target.replace("%20", " ");
            let candidate = file.parent().unwrap_or(root).join(decoded);
            let normalized = normalize_path(&candidate);
            if !normalized.starts_with(root) || !normalized.exists() {
                failures.push(format!("{relative}:{line}:{target}"));
            }
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        failures.truncate(32);
        Err(format!(
            "AssuranceMarkdownLinkBroken {{ links: {} }}",
            failures.join(",")
        ))
    }
}

fn markdown_targets(text: &str) -> Vec<(usize, String)> {
    let mut targets = Vec::new();
    let mut fenced = false;
    for (index, original) in text.lines().enumerate() {
        let line_number = index + 1;
        let trimmed = original.trim_start();
        if trimmed.starts_with("```") || trimmed.starts_with("~~~") {
            fenced = !fenced;
            continue;
        }
        if fenced {
            continue;
        }
        let line = strip_inline_code(original);
        let bytes = line.as_bytes();
        let mut cursor = 0_usize;
        while cursor + 2 < bytes.len() {
            let Some(relative_close) = line[cursor..].find("](") else {
                break;
            };
            let open = cursor + relative_close + 2;
            let Some(relative_end) = line[open..].find(')') else {
                break;
            };
            let end = open + relative_end;
            let raw = line[open..end].trim();
            let target = markdown_destination(raw);
            if !target.is_empty() {
                targets.push((line_number, target.to_owned()));
            }
            cursor = end + 1;
        }
        let trimmed = line.trim();
        if trimmed.starts_with('[')
            && let Some((_, destination)) = trimmed
                .split_once("]: ")
                .or_else(|| trimmed.split_once("]:"))
        {
            let target = markdown_destination(destination.trim());
            if !target.is_empty() {
                targets.push((line_number, target.to_owned()));
            }
        }
    }
    targets
}

fn markdown_destination(value: &str) -> &str {
    if value.starts_with('<') {
        return value.find('>').map_or(value, |end| &value[..=end]);
    }
    value.split_ascii_whitespace().next().unwrap_or("")
}

fn strip_inline_code(line: &str) -> String {
    let mut output = String::with_capacity(line.len());
    let mut in_code = false;
    for character in line.chars() {
        if character == '`' {
            in_code = !in_code;
            output.push(' ');
        } else if in_code {
            output.push(if character == '\t' { '\t' } else { ' ' });
        } else {
            output.push(character);
        }
    }
    output
}

fn external_target(target: &str) -> bool {
    let lower = target.to_ascii_lowercase();
    lower.starts_with('#')
        || lower.starts_with("http://")
        || lower.starts_with("https://")
        || lower.starts_with("mailto:")
        || lower.starts_with("data:")
        || lower.starts_with("javascript:")
}

fn files_with_extension(root: &Path, extension: &str) -> Result<Vec<PathBuf>, String> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    let mut visited = 0_usize;
    while let Some(directory) = pending.pop() {
        visited += 1;
        if visited > MAX_ASSURANCE_FILES {
            return Err("AssurancePathLimit".into());
        }
        let mut entries = fs::read_dir(&directory)
            .map_err(|error| {
                format!(
                    "AssuranceReadDirectory {{ path: {}, detail: {error} }}",
                    directory.display()
                )
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                format!(
                    "AssuranceReadDirectory {{ path: {}, detail: {error} }}",
                    directory.display()
                )
            })?;
        entries.sort_by_key(fs::DirEntry::file_name);
        for entry in entries {
            let path = entry.path();
            let file_type = entry.file_type().map_err(|error| {
                format!(
                    "AssuranceFileType {{ path: {}, detail: {error} }}",
                    path.display()
                )
            })?;
            if file_type.is_symlink() {
                return Err(format!(
                    "AssuranceSymlinkRejected {{ path: {} }}",
                    path.display()
                ));
            }
            if file_type.is_dir() {
                let name = entry.file_name();
                if name != ".git" && name != "target" {
                    pending.push(path);
                }
            } else if path.extension().and_then(|value| value.to_str()) == Some(extension) {
                files.push(path);
            }
        }
    }
    Ok(files)
}

fn safe_relative_path(value: &str) -> bool {
    let path = Path::new(value);
    !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn relative_path(root: &Path, path: &Path) -> Result<String, String> {
    path.strip_prefix(root)
        .map(|relative| relative.display().to_string().replace('\\', "/"))
        .map_err(|_| {
            format!(
                "AssurancePathOutsideWorkspace {{ path: {} }}",
                path.display()
            )
        })
}

fn normalize_path(path: &Path) -> PathBuf {
    let mut output = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                output.pop();
            }
            other => output.push(other.as_os_str()),
        }
    }
    output
}

fn escape_markdown(value: &str) -> String {
    value.replace('|', "\\|").replace('\n', " ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsafe_scanner_ignores_comments_and_literals() {
        let source = r###"
// unsafe { fake(); }
const TEXT: &str = "unsafe fn fake() {}";
const RAW: &str = r#"unsafe impl Fake {}"#;
fn real() {
    // SAFETY: the fixture establishes the test invariant.
    unsafe { operation(); }
}
"###;
        let counts = unsafe_counts(source, "fixture.rs").expect("scan");
        assert_eq!(counts.blocks, 1);
        assert_eq!(counts.functions, 0);
        assert_eq!(counts.implementations, 0);
        assert_eq!(counts.undocumented_blocks, 0);
    }

    #[test]
    fn unsafe_scanner_preserves_lifetimes() {
        let source =
            "unsafe fn borrow<'a, 'b>(left: &'a str, right: &'b str) { let _ = (left, right); }";
        let counts = unsafe_counts(source, "fixture.rs").expect("scan");
        assert_eq!(counts.functions, 1);
    }

    #[test]
    fn unsafe_scanner_classifies_boundaries() {
        let source = "unsafe fn a() {}\nunsafe impl X for Y {}\nunsafe extern \"C\" {}\nunsafe trait Z {}\nunsafe { call(); }";
        let counts = unsafe_counts(source, "fixture.rs").expect("scan");
        assert_eq!(counts.blocks, 1);
        assert_eq!(counts.functions, 1);
        assert_eq!(counts.implementations, 1);
        assert_eq!(counts.externs, 1);
        assert_eq!(counts.traits, 1);
        assert_eq!(counts.undocumented_blocks, 1);
    }

    #[test]
    fn markdown_parser_ignores_fenced_and_inline_code() {
        let targets = markdown_targets(
            "[real](docs/REAL.md)\n`[inline](missing.md)`\n```\n[fenced](missing.md)\n```\n",
        );
        assert_eq!(targets, vec![(1, "docs/REAL.md".to_owned())]);
    }

    #[test]
    fn workflow_parser_ignores_names_and_comments() {
        let source = r#"
- name: mrml assurance check
  # run: ./target/debug/mrml audit --all --target native --output structured
  run: echo active # ./target/debug/mrml assurance check
"#;
        let commands = workflow_commands(source);
        assert_eq!(commands, vec!["echo active"]);
        assert!(!has_mrml_command(&commands, &["assurance", "check"]));
    }

    #[test]
    fn workflow_parser_collects_single_and_block_run_commands() {
        let source = r#"
- run: cargo test --locked
- shell: pwsh
  run: |-
    rustup set default-host x86_64-pc-windows-gnullvm
    # ignored block comment
    .\target\debug\mrml.exe test --all --target windows --release
- run: 'echo # retained in quotes'
"#;
        let commands = workflow_commands(source);
        assert!(
            commands
                .iter()
                .any(|command| command == "cargo test --locked")
        );
        assert!(
            commands
                .iter()
                .any(|command| command == "rustup set default-host x86_64-pc-windows-gnullvm")
        );
        assert!(has_mrml_command(
            &commands,
            &["test", "--all", "--target", "windows", "--release"],
        ));
        assert!(
            commands
                .iter()
                .any(|command| command == "'echo # retained in quotes'")
        );
        assert!(
            !commands
                .iter()
                .any(|command| command.contains("ignored block comment"))
        );
    }

    #[test]
    fn workflow_gate_detection_rejects_echoed_gate_text() {
        let commands = workflow_commands(
            "- run: echo ./target/debug/mrml assurance check\n- run: ./target/debug/mrml doctor\n",
        );
        assert!(!has_mrml_command(&commands, &["assurance", "check"]));
        assert!(has_mrml_command(&commands, &["doctor"]));
    }
}
