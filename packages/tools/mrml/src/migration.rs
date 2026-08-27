use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::path::Path;

const MAX_V1_BYTES: u64 = 1024 * 1024;
const MAX_V1_RECORDS: usize = 4096;

#[derive(Clone, Debug)]
struct Record {
    line: usize,
    kind: String,
    fields: Vec<String>,
}

#[derive(Clone, Debug)]
struct LegacyPackage {
    id: String,
    path: String,
    name: String,
    class: String,
    targets: Vec<String>,
    default: bool,
    dependencies: Vec<String>,
    features: Vec<String>,
    artifacts: Vec<String>,
    input_counts: BTreeMap<String, usize>,
    records: Vec<Record>,
}

pub fn migrate(input: &Path, output: &Path) -> Result<usize, String> {
    let size = fs::metadata(input)
        .map_err(|error| format!("LegacyManifestMetadataError {{ detail: {error} }}"))?
        .len();
    if size == 0 || size > MAX_V1_BYTES {
        return Err(format!(
            "LegacyManifestSize {{ bytes: {size}, limit: {MAX_V1_BYTES} }}"
        ));
    }
    let text = fs::read_to_string(input)
        .map_err(|error| format!("LegacyManifestReadError {{ detail: {error} }}"))?;
    let packages = parse(&text)?;
    fs::create_dir(output)
        .map_err(|error| format!("MigrationOutputCreateError {{ detail: {error} }}"))?;
    let mut root =
        String::from("[manifest]\nformat = \"mrml\"\nversion = 2\n\n[workspace]\nmembers = [\n");
    for package in &packages {
        root.push_str(&format!("  \"{}\",\n", package.path));
        let directory = output.join(&package.path);
        fs::create_dir_all(&directory).map_err(|error| {
            format!(
                "MigrationPackageDirectoryError {{ package: {}, detail: {error} }}",
                package.id
            )
        })?;
        write_new(&directory.join("mrml.toml"), render(package, &packages)?)?;
    }
    root.push_str("]\n");
    write_new(&output.join("mrml.toml"), root)?;
    Ok(packages.len())
}

fn write_new(path: &Path, text: String) -> Result<(), String> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            format!(
                "MigrationOutputWriteError {{ file: {}, detail: {error} }}",
                path.display()
            )
        })?;
    file.write_all(text.as_bytes())
        .and_then(|_| file.sync_all())
        .map_err(|error| {
            format!(
                "MigrationOutputWriteError {{ file: {}, detail: {error} }}",
                path.display()
            )
        })
}

fn split_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .filter(|item| !item.is_empty())
        .map(str::to_owned)
        .collect()
}

fn parse(text: &str) -> Result<Vec<LegacyPackage>, String> {
    let mut version = None;
    let mut records = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if records.len() >= MAX_V1_RECORDS {
            return Err("LegacyRecordLimit".into());
        }
        let fields = line.split('|').map(str::to_owned).collect::<Vec<_>>();
        if fields.first().map(String::as_str) == Some("version") {
            if fields.len() != 2 || version.replace(fields[1].clone()).is_some() {
                return Err(format!("LegacyVersionInvalid {{ line: {} }}", index + 1));
            }
        } else {
            records.push(Record {
                line: index + 1,
                kind: fields[0].clone(),
                fields,
            });
        }
    }
    if version.as_deref() != Some("3") {
        return Err("LegacyVersionUnsupported".into());
    }
    let mut packages = Vec::new();
    let mut ids = BTreeSet::new();
    for record in records.iter().filter(|record| record.kind == "component") {
        if record.fields.len() != 11 {
            return Err(format!("LegacyComponentSyntax {{ line: {} }}", record.line));
        }
        if !ids.insert(record.fields[1].clone()) {
            return Err(format!(
                "LegacyComponentDuplicate {{ line: {} }}",
                record.line
            ));
        }
        let default = record.fields[6]
            .parse::<bool>()
            .map_err(|_| format!("LegacyBooleanInvalid {{ line: {} }}", record.line))?;
        let mut input_counts = BTreeMap::new();
        for encoded in split_list(&record.fields[10]) {
            let (kind, count) = encoded
                .split_once(':')
                .ok_or_else(|| format!("LegacyInputInvalid {{ line: {} }}", record.line))?;
            let count = count
                .parse::<usize>()
                .map_err(|_| format!("LegacyInputInvalid {{ line: {} }}", record.line))?;
            if input_counts.insert(kind.into(), count).is_some() {
                return Err(format!("LegacyInputDuplicate {{ line: {} }}", record.line));
            }
        }
        packages.push(LegacyPackage {
            id: record.fields[1].clone(),
            path: record.fields[2].clone(),
            name: record.fields[3].clone(),
            class: record.fields[4].clone(),
            targets: split_list(&record.fields[5]),
            default,
            dependencies: split_list(&record.fields[7]),
            features: split_list(&record.fields[8]),
            artifacts: split_list(&record.fields[9]),
            input_counts,
            records: Vec::new(),
        });
    }
    if packages.is_empty() {
        return Err("LegacyWorkspaceEmpty".into());
    }
    for record in records
        .into_iter()
        .filter(|record| record.kind != "component")
    {
        let component = record
            .fields
            .get(1)
            .ok_or_else(|| format!("LegacyRecordSyntax {{ line: {} }}", record.line))?;
        packages
            .iter_mut()
            .find(|package| &package.id == component)
            .ok_or_else(|| {
                format!(
                    "LegacyRecordPackageMissing {{ line: {}, package: {component} }}",
                    record.line
                )
            })?
            .records
            .push(record);
    }
    Ok(packages)
}

fn quote(value: &str) -> Result<String, String> {
    if value
        .bytes()
        .any(|byte| byte < 0x20 || matches!(byte, b'"' | b'\\' | b'|'))
    {
        return Err("LegacyValueNotRepresentable".into());
    }
    Ok(format!("\"{value}\""))
}

fn class(class: &str) -> Result<(&'static str, &'static str), String> {
    match class {
        "BOOTSTRAP_ONLY" => Ok(("bootstrap-tool", "host-tool")),
        "COMPILER" => Ok(("compiler", "compiler")),
        "MRML_NATIVE" => Ok(("service", "system-service")),
        "UEFI" => Ok(("bootloader", "uefi")),
        "GPU" => Ok(("library", "gpu-kernel")),
        "TEST" => Ok(("test", "test")),
        "SHARED" => Ok(("library", "library")),
        "HOST_WINDOWS_LINUX" => Ok(("tool", "host-tool")),
        "EXPERIMENT" => Ok(("experiment", "host-tool")),
        _ => Err(format!("LegacyClassUnsupported {{ class: {class} }}")),
    }
}

fn target(value: &str) -> Result<(&'static str, &'static str), String> {
    match value {
        "WINDOWS" => Ok(("windows", "x86_64")),
        "LINUX" => Ok(("linux", "x86_64")),
        "MRML_NATIVE" => Ok(("mrml", "x86_64")),
        "UEFI" => Ok(("uefi", "x86_64")),
        "CUDA" => Ok(("gpu", "cuda")),
        _ => Err(format!("LegacyTargetUnsupported {{ target: {value} }}")),
    }
}

fn render(package: &LegacyPackage, packages: &[LegacyPackage]) -> Result<String, String> {
    let (kind, profile) = class(&package.class)?;
    let action = package
        .records
        .iter()
        .find(|record| record.kind == "rust-action")
        .ok_or_else(|| format!("LegacyRustActionMissing {{ package: {} }}", package.id))?;
    if action.fields.len() != 6 {
        return Err(format!(
            "LegacyRustActionSyntax {{ line: {} }}",
            action.line
        ));
    }
    let mut out = format!(
        "[manifest]\nformat = \"mrml\"\nversion = 2\n\n[package]\ndefault = {}\nid = {}\nkind = {}\nname = {}\nprofile = {}\n",
        package.default,
        quote(&package.id)?,
        quote(kind)?,
        quote(&package.name)?,
        quote(profile)?
    );
    for value in &package.targets {
        let (environment, arch) = target(value)?;
        out.push_str(&format!(
            "\n[[target]]\narch = {}\nenvironment = {}\n",
            quote(arch)?,
            quote(environment)?
        ));
        if value == "CUDA" {
            out.push_str("toolchain = \"cuda-nvidia\"\n");
        }
    }
    for artifact in &package.artifacts {
        let (name, kind) = artifact.split_once(':').ok_or("LegacyArtifactInvalid")?;
        out.push_str(&format!(
            "\n[[artifact]]\nkind = {}\nname = {}\n",
            quote(kind)?,
            quote(name)?
        ));
    }
    out.push_str(&format!(
        "\n[rust]\ncrate_name = {}\ncrate_type = {}\nsource = {}\n",
        quote(&action.fields[2])?,
        quote(&action.fields[3])?,
        quote(&action.fields[4])?
    ));
    render_dependencies(&mut out, package, packages, &action.fields[5])?;
    render_records(&mut out, package)?;
    if package.input_counts.values().any(|count| *count != 0) {
        return Err(format!(
            "LegacyBuildInputIdentityRequired {{ package: {} }}",
            package.id
        ));
    }
    Ok(out)
}

fn render_dependencies(
    out: &mut String,
    package: &LegacyPackage,
    packages: &[LegacyPackage],
    encoded: &str,
) -> Result<(), String> {
    let mut seen = BTreeSet::new();
    for external in encoded.split(';').filter(|value| !value.is_empty()) {
        let (compile_name, rest) = external.split_once('=').ok_or("LegacyExternInvalid")?;
        let alias_end = rest.find(['@', '?', '#', '!']).unwrap_or(rest.len());
        let alias = &rest[..alias_end];
        if !seen.insert(compile_name) {
            return Err("LegacyExternDuplicate".into());
        }
        let provider = packages
            .iter()
            .find(|candidate| candidate.name == compile_name)
            .ok_or_else(|| {
                format!(
                    "LegacyDependencyMissing {{ package: {}, dependency: {compile_name} }}",
                    package.id
                )
            })?;
        out.push_str(&format!(
            "\n[[dependency]]\nalias = {}\ncompile_name = {}\npackage = {}\nscope = \"compile\"\n",
            quote(alias)?,
            quote(compile_name)?,
            quote(&provider.id)?
        ));
        if let Some(at) = rest.find('@') {
            let end = rest[at + 1..]
                .find(['?', '#', '!'])
                .map(|index| at + 1 + index)
                .unwrap_or(rest.len());
            let targets = &rest[at + 1..end];
            if targets != "*" && !targets.is_empty() {
                out.push_str(&format!(
                    "targets = [{}]\n",
                    targets
                        .split(',')
                        .map(quote)
                        .collect::<Result<Vec<_>, _>>()?
                        .join(", ")
                ));
            }
        }
        if let Some(question) = rest.find('?') {
            let end = rest[question + 1..]
                .find(['#', '!'])
                .map(|index| question + 1 + index)
                .unwrap_or(rest.len());
            out.push_str(&format!("feature = {}\n", quote(&rest[question + 1..end])?));
        }
        if let Some(hash) = rest.find('#') {
            let end = rest[hash + 1..]
                .find('!')
                .map(|index| hash + 1 + index)
                .unwrap_or(rest.len());
            out.push_str(&format!(
                "provider_profile = {}\n",
                quote(&rest[hash + 1..end])?
            ));
        }
        if rest.ends_with("!test") {
            out.push_str("test_only = true\n");
        }
    }
    let mut extern_names = seen.into_iter().map(str::to_owned).collect::<Vec<_>>();
    extern_names.sort();
    let mut declared = package.dependencies.clone();
    declared.sort();
    if declared != extern_names {
        return Err(format!(
            "LegacyDependencySemanticLoss {{ package: {} }}",
            package.id
        ));
    }
    Ok(())
}

fn render_records(out: &mut String, package: &LegacyPackage) -> Result<(), String> {
    for record in package
        .records
        .iter()
        .filter(|record| record.kind != "rust-action")
    {
        let fields = &record.fields;
        match (record.kind.as_str(), fields.len()) {
            ("rust-test", 5) | ("rust-benchmark", 5) => {
                let section = if record.kind == "rust-test" { "test" } else { "benchmark" };
                out.push_str(&format!("\n[[{section}]]\nname = {}\nself_extern = {}\nsource = {}\n", quote(&fields[2])?, fields[4], quote(&fields[3])?));
            }
            ("rust-example", 4) | ("rust-example", 6) => {
                out.push_str(&format!("\n[[example]]\nname = {}\nsource = {}\n", quote(&fields[2])?, quote(&fields[3])?));
                if fields.len() == 6 { render_targets_feature(out, &fields[4], &fields[5])?; }
            }
            ("rust-binary", 6) | ("rust-binary", 8) => {
                out.push_str(&format!("\n[[binary]]\ncrate_name = {}\noutput = {}\nself_extern = {}\nsource = {}\n", quote(&fields[3])?, quote(&fields[2])?, fields[5], quote(&fields[4])?));
                if fields.len() == 8 { render_targets_feature(out, &fields[6], &fields[7])?; }
            }
            ("rust-feature-set", 3) | ("rust-feature-set", 4) => {
                let (targets, features) = if fields.len() == 3 { ("*", fields[2].as_str()) } else { (fields[2].as_str(), fields[3].as_str()) };
                out.push_str("\n[[feature_set]]\n"); render_string_array(out, "targets", targets)?; render_string_array(out, "features", features)?;
            }
            ("rust-feature-profile", 5) => {
                out.push_str(&format!("\n[[feature_profile]]\nname = {}\n", quote(&fields[2])?));
                render_string_array(out, "targets", &fields[3])?; render_string_array(out, "features", &fields[4])?;
            }
            ("rust-compile-env", 4) | ("rust-compile-env", 5) => out.push_str(&format!("\n[[compile_env]]\nname = {}\nvalue = {}\n", quote(&fields[2])?, quote(&fields[3])?)),
            ("rust-compile-env-absent", 3) => out.push_str(&format!("\n[[absent_compile_env]]\nname = {}\n", quote(&fields[2])?)),
            ("rust-host-builds", 3) | ("rust-projected-builds", 3) | ("rust-host-tests", 3) => {
                let section = match record.kind.as_str() { "rust-host-builds" => "host_build", "rust-projected-builds" => "projected_build", _ => "host_test" };
                out.push_str(&format!("\n[[{section}]]\n")); render_string_array(out, "targets", &fields[2])?;
            }
            ("rust-test-policy", 3) => out.push_str(&format!("\n[test_policy]\nstack_bytes = {}\n", fields[2])),
            ("rust-target-triple", 4) => out.push_str(&format!("\n[[target_triple]]\ntarget = {}\ntriple = {}\n", quote(&fields[2])?, quote(&fields[3])?)),
            ("rust-extern-profile", 5) => out.push_str(&format!("\n[[extern_profile]]\ncompile_name = {}\nconsumer = {}\nprovider = {}\n", quote(&fields[2])?, quote(&fields[3])?, quote(&fields[4])?)),
            ("rust-ptx", 7) => out.push_str(&format!("\n[[generated]]\ncompile_env = {}\ndefault_arch = {}\nfeature = {}\noutput = {}\nsource = {}\n", quote(&fields[5])?, quote(&fields[6])?, quote(&fields[4])?, quote(&fields[2])?, quote(&fields[3])?)),
            _ => return Err(format!("LegacyRecordUnsupported {{ line: {}, kind: {} }}", record.line, record.kind)),
        }
    }
    for feature in &package.features {
        out.push_str(&format!("\n[[feature]]\nname = {}\n", quote(feature)?));
    }
    Ok(())
}

fn render_targets_feature(out: &mut String, targets: &str, feature: &str) -> Result<(), String> {
    if targets != "*" && !targets.is_empty() {
        render_string_array(out, "targets", targets)?;
    }
    if !feature.is_empty() {
        out.push_str(&format!("feature = {}\n", quote(feature)?));
    }
    Ok(())
}

fn render_string_array(out: &mut String, name: &str, values: &str) -> Result<(), String> {
    let values = split_list(values)
        .iter()
        .map(|value| quote(value))
        .collect::<Result<Vec<_>, _>>()?;
    out.push_str(&format!("{name} = [{}]\n", values.join(", ")));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::Document;

    const FIXTURE: &str = r#"version|3
component|org.mrml.library.base|packages/base|mrml-base|SHARED|WINDOWS,LINUX|false|||mrml_base:lib|build-script:0,proc-macro:0,native-link:0,compile-env:0,included-file:0,external-command:0
component|org.mrml.app.demo|packages/demo|mrml-demo|HOST_WINDOWS_LINUX|WINDOWS,LINUX|true|mrml-base|fast|mrml-demo:bin,demo_test:test,demo_example:example,demo_bench:bench|build-script:0,proc-macro:0,native-link:0,compile-env:0,included-file:0,external-command:0
rust-action|org.mrml.library.base|mrml_base|lib|packages/base/src/lib.rs|
rust-action|org.mrml.app.demo|mrml_demo|lib|packages/demo/src/lib.rs|mrml-base=mrml_base@*
rust-test|org.mrml.app.demo|demo_test|packages/demo/tests/demo.rs|true
rust-example|org.mrml.app.demo|demo_example|packages/demo/examples/demo.rs
rust-benchmark|org.mrml.app.demo|demo_bench|packages/demo/benches/demo.rs|true
rust-binary|org.mrml.app.demo|mrml-demo|mrml_demo|packages/demo/src/main.rs|true
rust-feature-set|org.mrml.app.demo|WINDOWS,LINUX|fast
"#;

    #[test]
    fn v1_fixture_converts_to_structured_v2_without_graph_loss() {
        let packages = parse(FIXTURE).expect("parse v1 fixture");
        assert_eq!(packages.len(), 2);
        let converted = render(&packages[1], &packages).expect("convert fixture");
        assert!(!converted.contains("component|"));
        let document = Document::parse(converted.as_bytes()).expect("parse converted v2");
        let package = document.section("package").expect("package section");
        assert_eq!(package.string("id"), Ok("org.mrml.app.demo"));
        let dependencies = document.array_sections("dependency").collect::<Vec<_>>();
        assert_eq!(dependencies.len(), 1);
        assert_eq!(
            dependencies[0].string("package"),
            Ok("org.mrml.library.base")
        );
        assert_eq!(document.array_sections("test").count(), 1);
        assert_eq!(document.array_sections("example").count(), 1);
        assert_eq!(document.array_sections("benchmark").count(), 1);
        assert_eq!(document.array_sections("binary").count(), 1);
        assert_eq!(document.array_sections("feature").count(), 1);
        assert_eq!(document.array_sections("artifact").count(), 4);
        assert_eq!(document.array_sections("target").count(), 2);
        assert_eq!(document.array_sections("build_input").count(), 0);
    }

    #[test]
    fn v1_migration_requires_manual_identity_for_sensitive_inputs() {
        let fixture = FIXTURE.replacen(
            "mrml-demo:bin,demo_test:test,demo_example:example,demo_bench:bench|build-script:0,proc-macro:0,native-link:0,compile-env:0,included-file:0,external-command:0",
            "mrml-demo:bin,demo_test:test,demo_example:example,demo_bench:bench|build-script:0,proc-macro:0,native-link:0,compile-env:0,included-file:0,external-command:1",
            1,
        );
        let packages = parse(&fixture).expect("parse v1 input-policy fixture");
        assert!(
            render(&packages[1], &packages)
                .unwrap_err()
                .starts_with("LegacyBuildInputIdentityRequired")
        );
    }

    #[test]
    fn v1_parser_rejects_unknown_component_records_and_dependency_loss() {
        let unknown = format!("{FIXTURE}rust-test|org.mrml.missing|x|x.rs|false\n");
        assert!(parse(&unknown).is_err());
        let packages = parse(&FIXTURE.replace("|mrml-base|fast|", "||fast|"))
            .expect("syntactically valid fixture");
        assert!(render(&packages[1], &packages).is_err());
    }
}
