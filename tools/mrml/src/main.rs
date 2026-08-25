use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Component as PathComponent, Path, PathBuf};
use std::process::{Command, ExitCode};

const MAX_WORKSPACE_BYTES: u64 = 1024 * 1024;
const MAX_COMPONENTS: usize = 256;
const PINNED_NIGHTLY: &str = "nightly-2026-08-24";
const TARGET_FAMILIES: [&str; 5] = ["WINDOWS", "LINUX", "MRML_NATIVE", "UEFI", "CUDA"];

#[derive(Clone, Debug)]
struct Component {
    id: String,
    path: String,
    cargo_package: String,
    class: String,
    targets: Vec<String>,
    default: bool,
    dependencies: Vec<String>,
    features: Vec<String>,
    outputs: Vec<String>,
    input_policy: InputCounts,
    rust_action: Option<RustAction>,
}

#[derive(Clone, Debug)]
struct RustAction {
    crate_name: String,
    crate_type: String,
    source: String,
    externs: Vec<RustExtern>,
}

#[derive(Clone, Debug)]
struct RustExtern {
    package: String,
    crate_name: String,
    targets: Vec<String>,
}

#[derive(Debug)]
struct Workspace {
    root: PathBuf,
    components: Vec<Component>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OutputMode {
    Human,
    Structured,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() || matches!(args[0].as_str(), "help" | "--help" | "-h") {
        print_help();
        return Ok(());
    }
    let workspace = load_workspace()?;
    match args[0].as_str() {
        "list" => list(&workspace, &args[1..]),
        "build" | "test" => build_or_test(&workspace, &args),
        "doctor" => doctor(&workspace, &args[1..]),
        "audit" => audit(&workspace, &args[1..]),
        command @ ("package" | "release" | "image" | "publish") => Err(format!(
            "UnsupportedOperation {{ command: {command}, status: PLANNED }}"
        )),
        command => Err(format!("UnknownCommand {{ command: {command} }}")),
    }
}

fn print_help() {
    println!("mrml - canonical MRML repository build frontend (native migration stage)");
    println!("usage: mrml <list|doctor|audit|build|test> [component] [options]");
    println!("  --all                 select every host-compatible component");
    println!("  --target <family>     native|windows|linux|uefi-x86_64|cuda-nvidia");
    println!("  --gpu-arch <name>     required metadata for CUDA target");
    println!("  --release             use release profile");
    println!("  --output structured   emit stable key=value records");
}

fn find_root() -> Result<PathBuf, String> {
    let mut current =
        env::current_dir().map_err(|e| format!("CurrentDirectoryError {{ detail: {e} }}"))?;
    loop {
        if current.join("MRML.workspace").is_file() {
            return Ok(current);
        }
        if !current.pop() {
            return Err("WorkspaceNotFound { file: MRML.workspace }".into());
        }
    }
}

fn load_workspace() -> Result<Workspace, String> {
    let root = find_root()?;
    let workspace_path = root.join("MRML.workspace");
    let bytes = fs::metadata(&workspace_path)
        .map_err(|e| format!("WorkspaceMetadataError {{ detail: {e} }}"))?
        .len();
    if bytes > MAX_WORKSPACE_BYTES {
        return Err(format!(
            "WorkspaceSizeLimit {{ bytes: {bytes}, limit: {MAX_WORKSPACE_BYTES} }}"
        ));
    }
    let text = fs::read_to_string(workspace_path)
        .map_err(|e| format!("WorkspaceReadError {{ detail: {e} }}"))?;
    let mut version = None;
    let mut components = Vec::new();
    let mut rust_actions = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split('|').collect();
        match fields.as_slice() {
            ["version", value] => version = Some(*value),
            [
                "component",
                id,
                path,
                cargo,
                class,
                targets,
                default,
                dependencies,
                features,
                outputs,
                input_policy,
            ] => {
                if components.len() >= MAX_COMPONENTS {
                    return Err(format!("ComponentCountLimit {{ limit: {MAX_COMPONENTS} }}"));
                }
                if components.iter().any(|item: &Component| {
                    item.id == *id || item.path == *path || item.cargo_package == *cargo
                }) {
                    return Err(format!(
                        "DuplicateComponent {{ line: {}, id: {id} }}",
                        index + 1
                    ));
                }
                if !safe_relative_path(path) || !root.join(path).join("Cargo.toml").is_file() {
                    return Err(format!(
                        "ComponentPathMissing {{ line: {}, path: {path} }}",
                        index + 1
                    ));
                }
                components.push(Component {
                    id: (*id).into(),
                    path: (*path).into(),
                    cargo_package: (*cargo).into(),
                    class: (*class).into(),
                    targets: targets.split(',').map(str::to_owned).collect(),
                    default: *default == "true",
                    dependencies: split_declaration(dependencies),
                    features: split_declaration(features),
                    outputs: split_declaration(outputs),
                    input_policy: parse_input_policy(input_policy, index + 1)?,
                    rust_action: None,
                });
            }
            [
                "rust-action",
                component,
                crate_name,
                crate_type,
                source,
                externs,
            ] => {
                if rust_actions.iter().any(
                    |(existing, _, _, _, _): &(String, String, String, String, String)| {
                        existing == component
                    },
                ) {
                    return Err(format!(
                        "DuplicateRustAction {{ line: {}, component: {component} }}",
                        index + 1
                    ));
                }
                rust_actions.push((
                    (*component).into(),
                    (*crate_name).into(),
                    (*crate_type).into(),
                    (*source).into(),
                    (*externs).into(),
                ));
            }
            _ => return Err(format!("WorkspaceSyntaxError {{ line: {} }}", index + 1)),
        }
    }
    if version != Some("3") {
        return Err("UnsupportedWorkspaceVersion".into());
    }
    if components.is_empty() {
        return Err("EmptyWorkspace".into());
    }
    for (component_id, crate_name, crate_type, source, externs) in rust_actions {
        let component = components
            .iter_mut()
            .find(|component| component.id == component_id)
            .ok_or_else(|| format!("RustActionComponentMissing {{ component: {component_id} }}"))?;
        if crate_type != "lib" {
            return Err(format!(
                "UnsupportedRustActionType {{ component: {component_id}, crate_type: {crate_type} }}"
            ));
        }
        if !rust_identifier(&crate_name) {
            return Err(format!(
                "RustActionCrateNameInvalid {{ component: {component_id}, crate_name: {crate_name} }}"
            ));
        }
        let externs = parse_rust_externs(&externs)?;
        let mut extern_packages: Vec<_> = externs
            .iter()
            .map(|external| external.package.clone())
            .collect();
        extern_packages.sort();
        if component.dependencies != extern_packages {
            return Err(format!(
                "RustActionExternDrift {{ component: {component_id}, dependencies: {}, externs: {} }}",
                component.dependencies.join(","),
                extern_packages.join(",")
            ));
        }
        let component_root = root.join(&component.path);
        let source_path = root.join(&source);
        if !safe_relative_path(&source)
            || !source_path.is_file()
            || !source_path.starts_with(&component_root)
        {
            return Err(format!(
                "RustActionSourceInvalid {{ component: {component_id}, source: {source} }}"
            ));
        }
        component.rust_action = Some(RustAction {
            crate_name,
            crate_type,
            source,
            externs,
        });
    }
    Ok(Workspace { root, components })
}

fn safe_relative_path(value: &str) -> bool {
    !value.is_empty()
        && Path::new(value)
            .components()
            .all(|component| matches!(component, PathComponent::Normal(_)))
}

fn rust_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z' | b'A'..=b'Z' | b'_'))
        && bytes.all(|byte| matches!(byte, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_'))
}

fn parse_rust_externs(value: &str) -> Result<Vec<RustExtern>, String> {
    if value.is_empty() {
        return Ok(Vec::new());
    }
    let mut result = Vec::new();
    for declaration in value.split(';') {
        let (binding, targets) = declaration
            .split_once('@')
            .ok_or_else(|| format!("RustExternSyntaxError {{ declaration: {declaration} }}"))?;
        let (package, crate_name) = binding
            .split_once('=')
            .ok_or_else(|| format!("RustExternSyntaxError {{ declaration: {declaration} }}"))?;
        if package.is_empty() || !rust_identifier(crate_name) {
            return Err(format!(
                "RustExternIdentityInvalid {{ declaration: {declaration} }}"
            ));
        }
        let targets = if targets == "*" {
            TARGET_FAMILIES
                .iter()
                .map(|target| (*target).into())
                .collect()
        } else {
            split_declaration(targets)
        };
        if targets.is_empty()
            || targets
                .iter()
                .any(|target| !TARGET_FAMILIES.contains(&target.as_str()))
        {
            return Err(format!(
                "RustExternTargetInvalid {{ declaration: {declaration} }}"
            ));
        }
        if result.iter().any(|external: &RustExtern| {
            external.package == package || external.crate_name == crate_name
        }) {
            return Err(format!(
                "RustExternDuplicate {{ declaration: {declaration} }}"
            ));
        }
        result.push(RustExtern {
            package: package.into(),
            crate_name: crate_name.into(),
            targets,
        });
    }
    result.sort_by(|left, right| left.package.cmp(&right.package));
    Ok(result)
}

fn parse_input_policy(value: &str, line: usize) -> Result<InputCounts, String> {
    let mut counts = InputCounts::default();
    let mut seen = [false; 6];
    for field in value.split(',') {
        let (name, raw_count) = field
            .split_once(':')
            .ok_or_else(|| format!("InputPolicySyntaxError {{ line: {line} }}"))?;
        let count = raw_count
            .parse::<usize>()
            .map_err(|_| format!("InputPolicyCountError {{ line: {line}, kind: {name} }}"))?;
        let (slot, destination) = match name {
            "build-script" => (0, &mut counts.build_scripts),
            "proc-macro" => (1, &mut counts.proc_macros),
            "native-link" => (2, &mut counts.native_links),
            "compile-env" => (3, &mut counts.compile_env),
            "included-file" => (4, &mut counts.included_files),
            "external-command" => (5, &mut counts.external_commands),
            _ => {
                return Err(format!(
                    "InputPolicyUnknownKind {{ line: {line}, kind: {name} }}"
                ));
            }
        };
        if seen[slot] {
            return Err(format!(
                "InputPolicyDuplicateKind {{ line: {line}, kind: {name} }}"
            ));
        }
        seen[slot] = true;
        *destination = count;
    }
    if !seen.iter().all(|value| *value) {
        return Err(format!("InputPolicyMissingKind {{ line: {line} }}"));
    }
    Ok(counts)
}

fn split_declaration(value: &str) -> Vec<String> {
    let mut values: Vec<_> = value
        .split(',')
        .filter(|entry| !entry.is_empty())
        .map(str::to_owned)
        .collect();
    values.sort();
    values.dedup();
    values
}

fn output_mode(args: &[String]) -> OutputMode {
    args.windows(2)
        .find(|pair| pair[0] == "--output")
        .map(|pair| pair[1].as_str())
        .filter(|value| *value == "structured")
        .map(|_| OutputMode::Structured)
        .unwrap_or(OutputMode::Human)
}

fn list(workspace: &Workspace, args: &[String]) -> Result<(), String> {
    let mode = output_mode(args);
    for component in &workspace.components {
        if mode == OutputMode::Structured {
            println!(
                "component|id={}|path={}|class={}|targets={}|dependencies={}|features={}|outputs={}|inputs={}|builder={}",
                component.id,
                component.path,
                component.class,
                component.targets.join(","),
                component.dependencies.join(","),
                component.features.join(","),
                component.outputs.join(","),
                component.input_policy.structured(),
                if component.rust_action.is_some() {
                    "native-rustc"
                } else {
                    "cargo-transition"
                }
            );
        } else {
            println!(
                "{:<48} {:<18} {}",
                component.id, component.class, component.path
            );
        }
    }
    Ok(())
}

fn host_family() -> Result<&'static str, String> {
    match env::consts::OS {
        "windows" => Ok("WINDOWS"),
        "linux" => Ok("LINUX"),
        other => Err(format!(
            "UnsupportedHost {{ host: {other}, supported: [windows,linux] }}"
        )),
    }
}

fn requested_target(args: &[String]) -> Result<String, String> {
    let value = args
        .windows(2)
        .find(|pair| pair[0] == "--target")
        .map(|pair| pair[1].as_str());
    Ok(match value {
        None | Some("host") => host_family()?.into(),
        Some("native") => "MRML_NATIVE".into(),
        Some("windows") => "WINDOWS".into(),
        Some("linux") => "LINUX".into(),
        Some("uefi-x86_64") => "UEFI".into(),
        Some("cuda-nvidia") => "CUDA".into(),
        Some(other) => return Err(format!("UnsupportedTarget {{ target: {other} }}")),
    })
}

fn selector(args: &[String]) -> Option<&str> {
    args.get(1)
        .filter(|arg| !arg.starts_with('-'))
        .map(String::as_str)
}

fn build_or_test(workspace: &Workspace, args: &[String]) -> Result<(), String> {
    let operation = args[0].as_str();
    let mode = output_mode(args);
    let target = requested_target(args)?;
    let host = host_family()?;
    if matches!(target.as_str(), "WINDOWS" | "LINUX") && target != host {
        return Err(format!(
            "ToolchainUnavailable {{ target: {target}, required_component: cross_host_rust_target }}"
        ));
    }
    let all = args.iter().any(|arg| arg == "--all");
    let selected = selector(args);
    let release = args.iter().any(|arg| arg == "--release");
    let mut components: Vec<&Component> = workspace
        .components
        .iter()
        .filter(|component| {
            if let Some(value) = selected {
                (component.id == value
                    || component.path == value
                    || component.cargo_package == value)
                    && component.targets.contains(&target)
            } else if all {
                component.targets.contains(&target)
            } else {
                component.default && component.targets.contains(&target)
            }
        })
        .collect();

    if selected.is_none() && target == "WINDOWS" {
        add_component(workspace, &mut components, "mrml-whp-run");
    }
    if selected.is_none() && target == "LINUX" {
        add_component(workspace, &mut components, "mrml-kvm-run");
    }
    if target == "UEFI" {
        components = vec![find_component(workspace, "mrml-kernel-image")?];
    }
    if target == "CUDA" {
        components = vec![find_component(workspace, "mrml-tensor")?];
        check_cuda(args)?;
    }
    if components.is_empty() {
        return Err(format!("NoMatchingComponents {{ target: {target} }}"));
    }

    for component in components {
        if target == "CUDA" && mode == OutputMode::Structured {
            let gpu_arch = args
                .windows(2)
                .find(|pair| pair[0] == "--gpu-arch")
                .map(|pair| pair[1].as_str())
                .unwrap_or("missing");
            println!(
                "metadata|target=CUDA|gpu_arch={gpu_arch}|artifact=PTX|toolchain=upstream-rustc-nvptx|runtime_authority=none"
            );
        }
        let builder = if component.rust_action.is_some() {
            "native-rustc"
        } else {
            "cargo-transition"
        };
        emit(mode, operation, component, &target, builder, "START");
        if component.rust_action.is_some() {
            run_rust_action(workspace, component, operation, &target, release)?;
        } else {
            run_cargo_transition(workspace, component, operation, &target, release)?;
        }
        emit(mode, operation, component, &target, builder, "PASS");
    }
    Ok(())
}

fn run_cargo_transition(
    workspace: &Workspace,
    component: &Component,
    operation: &str,
    target: &str,
    release: bool,
) -> Result<(), String> {
    let cargo = pinned_tool("cargo")?;
    let mut command = Command::new(cargo);
    command
        .current_dir(&workspace.root)
        .arg(operation)
        .arg("--locked")
        .arg("-p")
        .arg(&component.cargo_package);
    if release {
        command.arg("--release");
    }
    if component.cargo_package == "mrml-whp-run" {
        command.arg("--no-default-features");
    }
    if target == "MRML_NATIVE" {
        command.args(["--target", "x86_64-unknown-none"]);
    } else if target == "UEFI" {
        command.args([
            "--target",
            "x86_64-unknown-uefi",
            "--features",
            "kernel-image",
        ]);
    } else if target == "CUDA" {
        command.args(["--features", "cuda"]);
    }
    let status = command.status().map_err(|error| {
        format!(
            "ToolchainUnavailable {{ target: {target}, required_component: cargo, detail: {error} }}"
        )
    })?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "BuildFailed {{ component: {}, target: {target}, builder: cargo-transition, status: {:?} }}",
            component.id,
            status.code()
        ))
    }
}

fn run_rust_action(
    workspace: &Workspace,
    component: &Component,
    operation: &str,
    target: &str,
    release: bool,
) -> Result<(), String> {
    let mut built = BTreeSet::new();
    compile_rust_component(
        workspace,
        component,
        target,
        release,
        operation == "test",
        &mut built,
    )
}

fn compile_rust_component(
    workspace: &Workspace,
    component: &Component,
    target: &str,
    release: bool,
    test: bool,
    built: &mut BTreeSet<String>,
) -> Result<(), String> {
    if !test && built.contains(&component.id) {
        return Ok(());
    }
    let action = component.rust_action.as_ref().ok_or_else(|| {
        format!(
            "NativeDependencyActionMissing {{ component: {} }}",
            component.id
        )
    })?;
    for external in action
        .externs
        .iter()
        .filter(|external| external.targets.iter().any(|family| family == target))
    {
        let dependency = workspace
            .components
            .iter()
            .find(|candidate| candidate.cargo_package == external.package)
            .ok_or_else(|| {
                format!(
                    "NativeDependencyMissing {{ component: {}, dependency: {} }}",
                    component.id, external.package
                )
            })?;
        if !dependency.targets.iter().any(|family| family == target) {
            return Err(format!(
                "NativeDependencyTargetMismatch {{ component: {}, dependency: {}, target: {target} }}",
                component.id, dependency.id
            ));
        }
        compile_rust_component(workspace, dependency, target, release, false, built)?;
    }

    let profile = if release { "release" } else { "debug" };
    let output_dir = workspace
        .root
        .join("target")
        .join("mrml")
        .join(target.to_ascii_lowercase())
        .join(profile);
    fs::create_dir_all(&output_dir)
        .map_err(|error| format!("ArtifactDirectoryError {{ detail: {error} }}"))?;
    let extension = if test && target == "WINDOWS" {
        ".exe"
    } else {
        ""
    };
    let output = if test {
        output_dir.join(format!("{}_tests{extension}", action.crate_name))
    } else {
        native_artifact(workspace, action, target, release)
    };
    let rustc = pinned_tool("rustc")?;
    let mut command = Command::new(rustc);
    command
        .current_dir(&workspace.root)
        .args(["--crate-name", &action.crate_name])
        .args(["--edition", "2024"])
        .arg(&action.source)
        .args(["--crate-type", &action.crate_type])
        .args(["-C", "panic=abort"])
        .arg("-o")
        .arg(&output);
    for external in action
        .externs
        .iter()
        .filter(|external| external.targets.iter().any(|family| family == target))
    {
        let dependency = workspace
            .components
            .iter()
            .find(|candidate| candidate.cargo_package == external.package)
            .ok_or("NativeDependencyDisappeared")?;
        let dependency_action = dependency
            .rust_action
            .as_ref()
            .ok_or("NativeDependencyActionDisappeared")?;
        command.arg("--extern").arg(format!(
            "{}={}",
            external.crate_name,
            native_artifact(workspace, dependency_action, target, release).display()
        ));
    }
    if test {
        command.arg("--test").arg("-Zpanic-abort-tests");
    }
    if target == "WINDOWS" {
        command.args(["-C", "linker=rust-lld", "-C", "target-feature=+crt-static"]);
    } else if target == "LINUX" {
        command.args(["--target", "x86_64-unknown-linux-gnu"]);
    } else {
        return Err(format!(
            "RustActionTargetUnsupported {{ component: {}, target: {target} }}",
            component.id
        ));
    }
    if release {
        command.args([
            "-C",
            "opt-level=3",
            "-C",
            "lto=thin",
            "-C",
            "codegen-units=1",
            "-C",
            "strip=symbols",
        ]);
    }
    let status = command.status().map_err(|error| {
        format!(
            "ToolchainUnavailable {{ target: {target}, required_component: rustc, detail: {error} }}"
        )
    })?;
    if !status.success() {
        return Err(format!(
            "BuildFailed {{ component: {}, target: {target}, builder: native-rustc, status: {:?} }}",
            component.id,
            status.code()
        ));
    }
    if test {
        let status = Command::new(&output)
            .status()
            .map_err(|error| format!("TestExecutionUnavailable {{ detail: {error} }}"))?;
        if !status.success() {
            return Err(format!(
                "TestFailed {{ component: {}, status: {:?} }}",
                component.id,
                status.code()
            ));
        }
    } else {
        built.insert(component.id.clone());
    }
    Ok(())
}

fn native_artifact(
    workspace: &Workspace,
    action: &RustAction,
    target: &str,
    release: bool,
) -> PathBuf {
    workspace
        .root
        .join("target")
        .join("mrml")
        .join(target.to_ascii_lowercase())
        .join(if release { "release" } else { "debug" })
        .join(format!("lib{}.rlib", action.crate_name))
}

fn find_component<'a>(workspace: &'a Workspace, cargo: &str) -> Result<&'a Component, String> {
    workspace
        .components
        .iter()
        .find(|item| item.cargo_package == cargo)
        .ok_or_else(|| format!("ComponentNotFound {{ cargo_package: {cargo} }}"))
}

fn add_component<'a>(workspace: &'a Workspace, selected: &mut Vec<&'a Component>, cargo: &str) {
    if let Some(item) = workspace
        .components
        .iter()
        .find(|item| item.cargo_package == cargo)
        && !selected.iter().any(|existing| existing.id == item.id)
    {
        selected.push(item);
    }
}

fn check_cuda(args: &[String]) -> Result<(), String> {
    let gpu_arch = args
        .windows(2)
        .find(|pair| pair[0] == "--gpu-arch")
        .map(|pair| pair[1].as_str())
        .ok_or("MissingTargetMetadata { target: CUDA, required: gpu_arch }")?;
    let rustc = pinned_tool("rustc")?;
    let output = Command::new(rustc)
        .args(["--print", "target-list"])
        .output()
        .map_err(|e| {
            format!(
                "ToolchainUnavailable {{ target: CUDA, required_component: rustc, detail: {e} }}"
            )
        })?;
    let targets = String::from_utf8_lossy(&output.stdout);
    if !output.status.success() || !targets.lines().any(|line| line == "nvptx64-nvidia-cuda") {
        return Err(
            "ToolchainUnavailable { target: CUDA, required_component: nvptx64-nvidia-cuda }".into(),
        );
    }
    if !gpu_arch.starts_with("sm_") && !gpu_arch.starts_with("compute_") {
        return Err(format!("InvalidGpuArchitecture {{ value: {gpu_arch} }}"));
    }
    Ok(())
}

fn emit(
    mode: OutputMode,
    operation: &str,
    component: &Component,
    target: &str,
    builder: &str,
    status: &str,
) {
    if mode == OutputMode::Structured {
        println!(
            "result|operation={operation}|component={}|target={target}|compiler=upstream-rustc|builder={builder}|status={status}",
            component.id
        );
    } else {
        println!("mrml {operation}: {} [{target}] {status}", component.id);
    }
}

fn doctor(workspace: &Workspace, args: &[String]) -> Result<(), String> {
    let mode = output_mode(args);
    let host = host_family()?;
    let rustc_path = pinned_tool("rustc")?;
    let rustc = tool_version(&rustc_path, "rustc")?;
    let graph = verify_native_graph(workspace)?;
    if mode == OutputMode::Structured {
        println!(
            "doctor|host={host}|workspace_version=3|components={}|dependencies={}|resolver=native|rustc={}",
            workspace.components.len(),
            graph.dependency_count,
            clean(&rustc)
        );
    } else {
        println!(
            "host: {host}\nworkspace: v3 ({} components; {} native dependency edges verified)\nresolver: native\nrustc: {}",
            workspace.components.len(),
            graph.dependency_count,
            rustc.trim()
        );
    }
    Ok(())
}

#[derive(Debug, Eq, PartialEq)]
struct NativeGraph {
    dependency_count: usize,
    order: Vec<usize>,
}

fn verify_native_graph(workspace: &Workspace) -> Result<NativeGraph, String> {
    let mut packages = BTreeMap::new();
    for (index, component) in workspace.components.iter().enumerate() {
        if component.targets.is_empty()
            || component
                .targets
                .iter()
                .any(|target| !TARGET_FAMILIES.contains(&target.as_str()))
        {
            return Err(format!(
                "InvalidComponentTarget {{ component: {}, targets: {} }}",
                component.id,
                component.targets.join(",")
            ));
        }
        if component.outputs.is_empty() {
            return Err(format!(
                "MissingComponentOutput {{ component: {} }}",
                component.id
            ));
        }
        if packages
            .insert(component.cargo_package.as_str(), index)
            .is_some()
        {
            return Err(format!(
                "DuplicatePackageIdentity {{ package: {} }}",
                component.cargo_package
            ));
        }
    }

    let mut dependency_count = 0_usize;
    let mut edges = Vec::with_capacity(workspace.components.len());
    for component in &workspace.components {
        let mut component_edges = Vec::with_capacity(component.dependencies.len());
        for dependency in &component.dependencies {
            let index = *packages.get(dependency.as_str()).ok_or_else(|| {
                format!(
                    "MissingDependency {{ component: {}, dependency: {dependency} }}",
                    component.id
                )
            })?;
            if workspace.components[index].id == component.id {
                return Err(format!("SelfDependency {{ component: {} }}", component.id));
            }
            component_edges.push(index);
            dependency_count = dependency_count
                .checked_add(1)
                .ok_or("DependencyCountOverflow")?;
        }
        edges.push(component_edges);
    }

    let mut states = vec![0_u8; workspace.components.len()];
    let mut stack = Vec::new();
    let mut order = Vec::with_capacity(workspace.components.len());
    for index in 0..workspace.components.len() {
        visit_component(
            index,
            workspace,
            &edges,
            &mut states,
            &mut stack,
            &mut order,
        )?;
    }
    Ok(NativeGraph {
        dependency_count,
        order,
    })
}

fn visit_component(
    index: usize,
    workspace: &Workspace,
    edges: &[Vec<usize>],
    states: &mut [u8],
    stack: &mut Vec<usize>,
    order: &mut Vec<usize>,
) -> Result<(), String> {
    if stack.len() >= MAX_COMPONENTS {
        return Err(format!(
            "DependencyDepthLimit {{ limit: {MAX_COMPONENTS} }}"
        ));
    }
    match states[index] {
        2 => return Ok(()),
        1 => {
            let start = stack.iter().position(|item| *item == index).unwrap_or(0);
            let mut cycle: Vec<_> = stack[start..]
                .iter()
                .map(|item| workspace.components[*item].id.as_str())
                .collect();
            cycle.push(workspace.components[index].id.as_str());
            return Err(format!(
                "DependencyCycle {{ path: {} }}",
                cycle.join(" -> ")
            ));
        }
        _ => {}
    }
    states[index] = 1;
    stack.push(index);
    for dependency in &edges[index] {
        visit_component(*dependency, workspace, edges, states, stack, order)?;
    }
    stack.pop();
    states[index] = 2;
    order.push(index);
    Ok(())
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct InputCounts {
    build_scripts: usize,
    proc_macros: usize,
    native_links: usize,
    compile_env: usize,
    included_files: usize,
    external_commands: usize,
}

impl InputCounts {
    fn structured(self) -> String {
        format!(
            "build-script:{},proc-macro:{},native-link:{},compile-env:{},included-file:{},external-command:{}",
            self.build_scripts,
            self.proc_macros,
            self.native_links,
            self.compile_env,
            self.included_files,
            self.external_commands
        )
    }

    fn add(&mut self, other: Self) -> Result<(), String> {
        self.build_scripts = self
            .build_scripts
            .checked_add(other.build_scripts)
            .ok_or("AuditCountOverflow")?;
        self.proc_macros = self
            .proc_macros
            .checked_add(other.proc_macros)
            .ok_or("AuditCountOverflow")?;
        self.native_links = self
            .native_links
            .checked_add(other.native_links)
            .ok_or("AuditCountOverflow")?;
        self.compile_env = self
            .compile_env
            .checked_add(other.compile_env)
            .ok_or("AuditCountOverflow")?;
        self.included_files = self
            .included_files
            .checked_add(other.included_files)
            .ok_or("AuditCountOverflow")?;
        self.external_commands = self
            .external_commands
            .checked_add(other.external_commands)
            .ok_or("AuditCountOverflow")?;
        Ok(())
    }
}

fn audit(workspace: &Workspace, args: &[String]) -> Result<(), String> {
    let mode = output_mode(args);
    let graph = verify_native_graph(workspace)?;
    let dependency_count = graph.dependency_count;
    let mut feature_count = 0_usize;
    let mut target_count = 0_usize;
    let mut counts = InputCounts::default();
    for index in &graph.order {
        let component = &workspace.components[*index];
        feature_count = feature_count
            .checked_add(component.features.len())
            .ok_or("AuditCountOverflow")?;
        target_count = target_count
            .checked_add(component.outputs.len())
            .ok_or("AuditCountOverflow")?;
        for output in &component.outputs {
            if mode == OutputMode::Structured {
                println!(
                    "native-output|component={}|declaration={}",
                    clean(&component.id),
                    clean(output)
                );
            }
        }
        if mode == OutputMode::Structured {
            println!(
                "native-component|id={}|dependencies={}|features={}",
                clean(&component.id),
                component.dependencies.join(","),
                component.features.join(",")
            );
        }
    }
    for component in &workspace.components {
        let mut component_counts = InputCounts {
            build_scripts: component
                .outputs
                .iter()
                .filter(|output| output.ends_with(":custom-build"))
                .count(),
            proc_macros: component
                .outputs
                .iter()
                .filter(|output| output.ends_with(":proc-macro"))
                .count(),
            ..InputCounts::default()
        };
        scan_component(workspace, component, mode, &mut component_counts)?;
        if component.input_policy != component_counts {
            return Err(format!(
                "InputPolicyDrift {{ component: {}, declared: {}, actual: {} }}",
                component.id,
                component.input_policy.structured(),
                component_counts.structured()
            ));
        }
        counts.add(component_counts)?;
    }
    if mode == OutputMode::Structured {
        println!(
            "audit|status=PASS|resolver=native|components={}|dependencies={dependency_count}|features={feature_count}|outputs={target_count}|build_scripts={}|proc_macros={}|native_links={}|compile_env={}|included_files={}|external_commands={}",
            workspace.components.len(),
            counts.build_scripts,
            counts.proc_macros,
            counts.native_links,
            counts.compile_env,
            counts.included_files,
            counts.external_commands
        );
    } else {
        println!(
            "audit PASS (native resolver): {} components, {dependency_count} dependency records, {feature_count} features, {target_count} outputs\ninputs: {} build scripts, {} proc macros, {} native links, {} compile-time environment reads, {} included files, {} external command sites",
            workspace.components.len(),
            counts.build_scripts,
            counts.proc_macros,
            counts.native_links,
            counts.compile_env,
            counts.included_files,
            counts.external_commands
        );
    }
    Ok(())
}

fn scan_component(
    workspace: &Workspace,
    component: &Component,
    mode: OutputMode,
    counts: &mut InputCounts,
) -> Result<(), String> {
    let mut pending = vec![workspace.root.join(&component.path)];
    let mut visited = 0_usize;
    while let Some(path) = pending.pop() {
        visited = visited.checked_add(1).ok_or("AuditPathCountOverflow")?;
        if visited > 20_000 {
            return Err(format!("AuditPathLimit {{ component: {} }}", component.id));
        }
        let mut entries: Vec<_> = fs::read_dir(&path)
            .map_err(|error| {
                format!(
                    "AuditReadDirectory {{ path: {}, detail: {error} }}",
                    clean(&path.display().to_string())
                )
            })?
            .collect::<Result<_, _>>()
            .map_err(|error| {
                format!(
                    "AuditReadDirectory {{ path: {}, detail: {error} }}",
                    clean(&path.display().to_string())
                )
            })?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let entry_path = entry.path();
            let file_type = entry
                .file_type()
                .map_err(|error| format!("AuditFileType {{ detail: {error} }}"))?;
            if file_type.is_symlink() {
                return Err(format!(
                    "AuditSymlinkRejected {{ path: {} }}",
                    clean(&entry_path.display().to_string())
                ));
            }
            if file_type.is_dir() {
                pending.push(entry_path);
            } else if entry_path.extension().and_then(|value| value.to_str()) == Some("rs") {
                scan_rust_file(workspace, component, &entry_path, mode, counts)?;
            }
        }
    }
    Ok(())
}

fn scan_rust_file(
    workspace: &Workspace,
    component: &Component,
    path: &std::path::Path,
    mode: OutputMode,
    counts: &mut InputCounts,
) -> Result<(), String> {
    let metadata =
        fs::metadata(path).map_err(|error| format!("AuditFileMetadata {{ detail: {error} }}"))?;
    if metadata.len() > 2 * 1024 * 1024 {
        return Err(format!(
            "AuditSourceTooLarge {{ path: {}, bytes: {} }}",
            clean(&path.display().to_string()),
            metadata.len()
        ));
    }
    let text = fs::read_to_string(path)
        .map_err(|error| format!("AuditSourceRead {{ detail: {error} }}"))?;
    let relative = path
        .strip_prefix(&workspace.root)
        .map_err(|_| "AuditPathOutsideWorkspace")?
        .display()
        .to_string()
        .replace('\\', "/");
    for (index, line) in text.lines().enumerate() {
        let line_number = index + 1;
        if line.contains(concat!("#[", "link(")) || line.contains(concat!("link", "(name")) {
            record_input(
                mode,
                component,
                &relative,
                line_number,
                "native-link",
                &mut counts.native_links,
            )?;
        }
        if line.contains(concat!("env", "!(")) {
            record_input(
                mode,
                component,
                &relative,
                line_number,
                "compile-env",
                &mut counts.compile_env,
            )?;
        }
        if line.contains(concat!("include_", "bytes!("))
            || line.contains(concat!("include_", "str!("))
        {
            record_input(
                mode,
                component,
                &relative,
                line_number,
                "included-file",
                &mut counts.included_files,
            )?;
        }
        if line.contains(concat!("Command", "::new(")) {
            record_input(
                mode,
                component,
                &relative,
                line_number,
                "external-command",
                &mut counts.external_commands,
            )?;
        }
    }
    Ok(())
}

fn record_input(
    mode: OutputMode,
    component: &Component,
    relative: &str,
    line: usize,
    kind: &str,
    count: &mut usize,
) -> Result<(), String> {
    *count = count.checked_add(1).ok_or("AuditCountOverflow")?;
    if mode == OutputMode::Structured {
        println!(
            "input|component={}|kind={kind}|path={}|line={line}",
            component.id,
            clean(relative)
        );
    }
    Ok(())
}

fn pinned_tool(tool: &str) -> Result<PathBuf, String> {
    let host = host_family()?;
    let toolchain = match host {
        "WINDOWS" => format!("{PINNED_NIGHTLY}-x86_64-pc-windows-gnullvm"),
        "LINUX" => format!("{PINNED_NIGHTLY}-x86_64-unknown-linux-gnu"),
        _ => unreachable!(),
    };
    let output = Command::new("rustup")
        .args(["which", "--toolchain", &toolchain, tool])
        .output()
        .map_err(|error| {
            format!(
                "ToolchainUnavailable {{ required_component: rustup, toolchain: {toolchain}, detail: {error} }}"
            )
        })?;
    if !output.status.success() {
        return Err(format!(
            "ToolchainUnavailable {{ required_component: {tool}, toolchain: {toolchain} }}"
        ));
    }
    let path =
        String::from_utf8(output.stdout).map_err(|_| "ToolchainPathInvalidUtf8".to_owned())?;
    let path = PathBuf::from(path.trim());
    if !path.is_file() {
        return Err(format!(
            "ToolchainPathMissing {{ required_component: {tool}, toolchain: {toolchain} }}"
        ));
    }
    Ok(path)
}

fn tool_version(tool: &Path, name: &str) -> Result<String, String> {
    let output = Command::new(tool).arg("--version").output().map_err(|e| {
        format!("ToolchainUnavailable {{ required_component: {name}, detail: {e} }}")
    })?;
    if !output.status.success() {
        return Err(format!("ToolchainFailed {{ tool: {name} }}"));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn clean(value: &str) -> String {
    value.trim().replace(['|', '='], "_")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn component(package: &str, dependencies: &[&str]) -> Component {
        Component {
            id: format!("org.mrml.{package}"),
            path: package.into(),
            cargo_package: package.into(),
            class: "TEST".into(),
            targets: vec!["WINDOWS".into(), "LINUX".into()],
            default: false,
            dependencies: dependencies.iter().map(|value| (*value).into()).collect(),
            features: Vec::new(),
            outputs: vec![format!("{package}:lib")],
            input_policy: InputCounts::default(),
            rust_action: None,
        }
    }

    fn workspace(components: Vec<Component>) -> Workspace {
        Workspace {
            root: PathBuf::new(),
            components,
        }
    }

    #[test]
    fn output_mode_is_explicit() {
        assert_eq!(
            output_mode(&["--output".into(), "structured".into()]),
            OutputMode::Structured
        );
        assert_eq!(output_mode(&[]), OutputMode::Human);
    }
    #[test]
    fn selector_ignores_option_values() {
        let args = vec![
            "build".into(),
            "org.mrml.compiler.core".into(),
            "--output".into(),
            "structured".into(),
        ];
        assert_eq!(selector(&args), Some("org.mrml.compiler.core"));
    }
    #[test]
    fn structured_cleaning_is_bounded_to_delimiters() {
        assert_eq!(clean("a|b=c\n"), "a_b_c");
    }
    #[test]
    fn native_declarations_are_canonicalized() {
        assert_eq!(split_declaration("z,a,z"), ["a", "z"]);
        assert!(split_declaration("").is_empty());
    }
    #[test]
    fn rust_actions_reject_escaping_paths_and_invalid_crate_names() {
        assert!(safe_relative_path("packages/libraries/math/src/lib.rs"));
        assert!(!safe_relative_path(
            "packages/libraries/math/../crypto/src/lib.rs"
        ));
        assert!(!safe_relative_path("C:/outside.rs"));
        assert!(rust_identifier("mrml_math"));
        assert!(!rust_identifier("../mrml-math"));
    }
    #[test]
    fn rust_externs_are_target_scoped_and_unique() {
        let externs =
            parse_rust_externs("mrml-linux=mrml_linux@LINUX;mrml-windows=mrml_windows@WINDOWS")
                .unwrap();
        assert_eq!(externs.len(), 2);
        assert_eq!(externs[0].package, "mrml-linux");
        assert_eq!(externs[0].targets, ["LINUX"]);
        assert!(parse_rust_externs("mrml-runtime=bad-name@*").is_err());
        assert!(
            parse_rust_externs(
                "mrml-runtime=mrml_runtime@WINDOWS;mrml-runtime=runtime_again@LINUX"
            )
            .is_err()
        );
    }
    #[test]
    fn input_policy_requires_every_unique_kind() {
        let policy = parse_input_policy(
            "build-script:1,proc-macro:0,native-link:2,compile-env:3,included-file:4,external-command:5",
            7,
        )
        .unwrap();
        assert_eq!(policy.build_scripts, 1);
        assert_eq!(policy.external_commands, 5);
        assert!(parse_input_policy("build-script:0", 7).is_err());
        assert!(parse_input_policy(
            "build-script:0,build-script:0,proc-macro:0,native-link:0,compile-env:0,included-file:0,external-command:0",
            7
        )
        .is_err());
    }

    #[test]
    fn native_graph_orders_dependencies_before_consumers() {
        let workspace = workspace(vec![
            component("application", &["service", "library"]),
            component("service", &["library"]),
            component("library", &[]),
        ]);
        let graph = verify_native_graph(&workspace).unwrap();
        let order: Vec<_> = graph
            .order
            .iter()
            .map(|index| workspace.components[*index].cargo_package.as_str())
            .collect();
        assert_eq!(graph.dependency_count, 3);
        assert_eq!(order, ["library", "service", "application"]);
    }

    #[test]
    fn native_graph_rejects_missing_dependencies() {
        let error = verify_native_graph(&workspace(vec![component("application", &["missing"])]))
            .unwrap_err();
        assert!(error.contains("MissingDependency"));
        assert!(error.contains("missing"));
    }

    #[test]
    fn native_graph_reports_the_cycle_path() {
        let error = verify_native_graph(&workspace(vec![
            component("alpha", &["beta"]),
            component("beta", &["alpha"]),
        ]))
        .unwrap_err();
        assert_eq!(
            error,
            "DependencyCycle { path: org.mrml.alpha -> org.mrml.beta -> org.mrml.alpha }"
        );
    }

    #[test]
    fn native_graph_rejects_unknown_targets_and_empty_outputs() {
        let mut invalid_target = component("invalid-target", &[]);
        invalid_target.targets = vec!["PLAN9".into()];
        assert!(
            verify_native_graph(&workspace(vec![invalid_target]))
                .unwrap_err()
                .contains("InvalidComponentTarget")
        );

        let mut missing_output = component("missing-output", &[]);
        missing_output.outputs.clear();
        assert!(
            verify_native_graph(&workspace(vec![missing_output]))
                .unwrap_err()
                .contains("MissingComponentOutput")
        );
    }
}
