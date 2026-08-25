use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, ExitCode};

#[derive(Clone, Debug)]
struct Component {
    id: String,
    path: String,
    cargo_package: String,
    class: String,
    targets: Vec<String>,
    default: bool,
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
        command @ ("package" | "release" | "image" | "publish") => Err(format!(
            "UnsupportedOperation {{ command: {command}, status: PLANNED }}"
        )),
        command => Err(format!("UnknownCommand {{ command: {command} }}")),
    }
}

fn print_help() {
    println!("mrml - canonical MRML repository build frontend (Cargo bridge stage)");
    println!("usage: mrml <list|doctor|build|test> [component] [options]");
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
    let text = fs::read_to_string(root.join("MRML.workspace"))
        .map_err(|e| format!("WorkspaceReadError {{ detail: {e} }}"))?;
    let mut version = None;
    let mut components = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split('|').collect();
        match fields.as_slice() {
            ["version", value] => version = Some(*value),
            ["component", id, path, cargo, class, targets, default] => {
                if components
                    .iter()
                    .any(|item: &Component| item.id == *id || item.path == *path)
                {
                    return Err(format!(
                        "DuplicateComponent {{ line: {}, id: {id} }}",
                        index + 1
                    ));
                }
                if !root.join(path).join("Cargo.toml").is_file() {
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
                });
            }
            _ => return Err(format!("WorkspaceSyntaxError {{ line: {} }}", index + 1)),
        }
    }
    if version != Some("1") {
        return Err("UnsupportedWorkspaceVersion".into());
    }
    if components.is_empty() {
        return Err("EmptyWorkspace".into());
    }
    Ok(Workspace { root, components })
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
                "component|id={}|path={}|class={}|targets={}|bridge=cargo",
                component.id,
                component.path,
                component.class,
                component.targets.join(",")
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
        let mut command = Command::new("cargo");
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
        }
        if target == "UEFI" {
            command.args([
                "--target",
                "x86_64-unknown-uefi",
                "--features",
                "kernel-image",
            ]);
        }
        if target == "CUDA" {
            command.args(["--features", "cuda"]);
        }
        emit(mode, operation, component, &target, "START");
        let status = command.status().map_err(|e| format!("ToolchainUnavailable {{ target: {target}, required_component: cargo, detail: {e} }}"))?;
        if !status.success() {
            return Err(format!(
                "BuildFailed {{ component: {}, target: {target}, status: {:?} }}",
                component.id,
                status.code()
            ));
        }
        emit(mode, operation, component, &target, "PASS");
    }
    Ok(())
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
    let output = Command::new("rustc")
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

fn emit(mode: OutputMode, operation: &str, component: &Component, target: &str, status: &str) {
    if mode == OutputMode::Structured {
        println!(
            "result|operation={operation}|component={}|target={target}|compiler=upstream-rustc|bridge=cargo|status={status}",
            component.id
        );
    } else {
        println!("mrml {operation}: {} [{target}] {status}", component.id);
    }
}

fn doctor(workspace: &Workspace, args: &[String]) -> Result<(), String> {
    let mode = output_mode(args);
    let host = host_family()?;
    let cargo = tool_version("cargo")?;
    let rustc = tool_version("rustc")?;
    if mode == OutputMode::Structured {
        println!(
            "doctor|host={host}|workspace_version=1|components={}|cargo={}|rustc={}",
            workspace.components.len(),
            clean(&cargo),
            clean(&rustc)
        );
    } else {
        println!(
            "host: {host}\nworkspace: v1 ({} components)\ncargo: {}\nrustc: {}",
            workspace.components.len(),
            cargo.trim(),
            rustc.trim()
        );
    }
    Ok(())
}

fn tool_version(tool: &str) -> Result<String, String> {
    let output = Command::new(tool).arg("--version").output().map_err(|e| {
        format!("ToolchainUnavailable {{ required_component: {tool}, detail: {e} }}")
    })?;
    if !output.status.success() {
        return Err(format!("ToolchainFailed {{ tool: {tool} }}"));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn clean(value: &str) -> String {
    value.trim().replace(['|', '='], "_")
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
