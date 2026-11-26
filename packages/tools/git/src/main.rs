#![no_std]
#![cfg_attr(not(test), no_main)]
#![cfg_attr(test, allow(dead_code))]

use mrml_error::{Context, Result, anyhow};
use mrml_git::{
    Cli, GitSignatureFormat, HttpsCredentialError, HttpsCredentialProvider, HttpsCredentialScope,
    HttpsRemote, HttpsTransport, MergeOutcome, NativeChangeKind, ObjectFormat,
    OpenPgpDigestAlgorithm, OpenPgpFingerprint, OpenPgpPublicKey, OpenPgpSigningKey,
    OpenPgpVerificationPolicy, RebaseOutcome, Repository, ScopedBearerCredential, check_ssh,
    fetch_https, fetch_https_authenticated, fetch_ssh, inspect_ssh, parse_public_key_ascii,
    parse_tree_with_format, push_ssh, sign_git_payload_via_interface, validate_positional,
    verify_detached_ascii,
};
#[cfg(target_os = "linux")]
use mrml_git::{
    AuthorizedHybridPair, CapabilityVerifiedProofSigner, CredentialAgentCapability,
    CredentialAgentPeer, HistoryVerificationLimits, LinuxDurableTrustPolicyStore,
    ProtectedSignerCapability, ProtectedSignerPeer, UnixHttpsCredentialProvider,
    UnixProtectedCommitSigningProvider, push_https_protected_authenticated,
};
use mrml_interface_detached_signing_v1::{
    OpenPgpDigestAlgorithm as InterfaceOpenPgpDigestAlgorithm, OpenPgpGitSigningPurpose,
};
use mrml_runtime::{
    File, Text, Vector, join_path, mrml_format as format, mrml_println as println, path_is_file,
    read_file_bounded, read_file_text_bounded, read_stdin_secret_bounded,
};
use mrml_ssh::{
    RsaPrivateKey, SshRemote, encode_rsa_public_key, parse_rsa_private_pem, parse_rsa_public_line,
};
use mrml_terminal_style::Colorize;

const MRML_OPENPGP_FINGERPRINT: &str = "6EE75495B0427A4F3F97BA1C14D70434990F1CA9";
const MRML_OPENPGP_PUBLIC_KEY: &str = "docs/keys/mrml-commit-signing-key.asc";
const MRML_OPENPGP_KEY_NOT_AFTER: u64 = 1_851_111_680;
const MAX_HTTPS_PACK_BYTES: u64 = 1024 * 1024 * 1024;

struct StandardInputBearerProvider {
    token: Vector<u8>,
}

impl StandardInputBearerProvider {
    fn read() -> Result<Self> {
        let mut token = read_stdin_secret_bounded(66)
            .map_err(|_| anyhow!("cannot read bounded HTTPS credential from standard input"))?;
        if token.last() == Some(&b'\n') {
            token.pop();
        }
        if token.last() == Some(&b'\r') {
            token.pop();
        }
        if token.len() != 64 {
            erase_secret(&mut token);
            return Err(anyhow!("HTTPS credential from standard input is invalid"));
        }
        Ok(Self { token })
    }
}

impl HttpsCredentialProvider for StandardInputBearerProvider {
    fn credential(
        &mut self,
        scope: &HttpsCredentialScope,
    ) -> core::result::Result<ScopedBearerCredential, HttpsCredentialError> {
        ScopedBearerCredential::from_provider_token(scope.clone(), &self.token)
    }
}

impl Drop for StandardInputBearerProvider {
    fn drop(&mut self) {
        erase_secret(&mut self.token);
    }
}

fn native_repository(repository: Option<&str>) -> Result<Repository> {
    Repository::discover(repository.unwrap_or(".")).map_err(|error| anyhow!("{}", error))
}

fn native_dashboard(repository: Option<&str>) -> Result<()> {
    let repository = native_repository(repository)?;
    let branch = repository
        .current_branch()
        .map_err(|error| anyhow!("{}", error))?
        .unwrap_or_else(|| "detached HEAD".into());
    let head = repository.head().map_err(|error| anyhow!("{}", error))?;
    let changes = repository.changes().map_err(|error| anyhow!("{}", error))?;
    println!("{}", "MRML GIT · NATIVE STATUS".bright_cyan().bold());
    println!("  {}   {}", "root".dimmed(), repository.worktree);
    println!("  {} {}", "branch".dimmed(), branch.magenta().bold());
    if let Some(id) = head {
        println!("  {}   {}", "head".dimmed(), id);
    } else {
        println!("  {}   no commits yet", "head".dimmed());
    }
    if let Some((upstream, ahead, behind)) = repository
        .upstream_status()
        .map_err(|error| anyhow!("{}", error))?
    {
        println!(
            "  {} {}  {} ahead  {} behind",
            "track".dimmed(),
            upstream,
            ahead,
            behind
        );
    } else {
        println!("  {} {}", "track".dimmed(), "no upstream".yellow());
    }
    if changes.is_empty() {
        println!("  {}", "clean — index matches working tree".green());
    }
    for change in changes {
        let label = match change.kind {
            NativeChangeKind::Modified => "modified".yellow(),
            NativeChangeKind::Deleted => "deleted".red(),
            NativeChangeKind::Untracked => "untracked".bright_cyan(),
        };
        let lane = match (change.staged, change.unstaged) {
            (true, true) => "staged+worktree",
            (true, false) => "staged",
            (false, true) => "worktree",
            (false, false) => "",
        };
        println!("  {:9} {:15} {}", label, lane.dimmed(), change.path);
    }
    Ok(())
}

fn help() {
    println!("{}\n", "MRML GIT".bright_cyan().bold());
    for usage in [
        "[-C PATH] [status]",
        "[-C PATH] doctor",
        "[-C PATH] init [path]",
        "[-C PATH] clone <url> [path]",
        "[-C PATH] log [count]",
        "[-C PATH] diff [--staged] [path]...",
        "[-C PATH] diff-ref <revision> [path]...",
        "[-C PATH] show [revision]",
        "[-C PATH] history <path>",
        "[-C PATH] blame <path>",
        "[-C PATH] conflicts",
        "[-C PATH] branch [new-name]",
        "[-C PATH] branch-delete <name>",
        "[-C PATH] switch <name>",
        "[-C PATH] upstream <remote/branch>",
        "[-C PATH] publish <remote> <branch>",
        "[-C PATH] merge <branch>",
        "[-C PATH] rebase <branch>",
        "[-C PATH] cherry-pick <revision>",
        "[-C PATH] operation-abort <merge|rebase|cherry-pick>",
        "[-C PATH] stage <path>...",
        "[-C PATH] unstage <path>...",
        "[-C PATH] restore <path>...",
        "[-C PATH] commit [--sign] <message>",
        "[-C PATH] fetch [remote]",
        "[-C PATH] pull [remote] [branch]",
        "[-C PATH] push [remote] [branch]",
        "[-C PATH] remote",
        "[-C PATH] ssh <add|set|auth|info|check> ...",
        "[-C PATH] signing configure-openpgp <seed> [public-key [primary-fingerprint [sha256|sha384|sha512]]]",
        "[-C PATH] signing <configure|auto|status|off|verify|verify-tag> ...",
        "[-C PATH] tag [name]",
        "[-C PATH] tag-sign <name> <message>",
        "[-C PATH] stash [list|push [message]|pop]",
    ] {
        println!("  mrml-git {}", usage);
    }
    println!(
        "\nPulls are fast-forward only. Native SSH is experimental and disabled unless MRML_GIT_EXPERIMENTAL_SSH=1; HTTPS is the production transport. Private-key files are disabled by default and accepted only by the explicit development provider with MRML_GIT_DEVELOPMENT_KEY_FILES=1; production uses narrow signer and credential providers. Capability-authorized isolated service routing remains planned. Fetch and clone install advertised branch references only; tag references are not installed. No command invokes host Git, GnuPG, or OpenSSH."
    );
}

fn require_arguments<'a>(command: &str, arguments: &'a [Text]) -> Result<&'a [Text]> {
    if arguments.is_empty() {
        Err(anyhow!("{} requires at least one argument", command))
    } else {
        Ok(arguments)
    }
}

fn join_words(words: &[Text]) -> Text {
    let mut output = Text::new();
    for (index, word) in words.iter().enumerate() {
        if index > 0 {
            output.push(' ');
        }
        output.push_str(word);
    }
    output
}

fn checked_positionals(values: &[Text]) -> Result<&[Text]> {
    validate_positional(values).map_err(|error| anyhow!("{}", error))?;
    Ok(values)
}

fn experimental_ssh_enabled(value: Option<&str>) -> bool {
    value == Some("1")
}

fn require_experimental_ssh() -> Result<()> {
    if experimental_ssh_enabled(
        mrml_runtime::environment_variable("MRML_GIT_EXPERIMENTAL_SSH").as_deref(),
    ) {
        Ok(())
    } else {
        Err(anyhow!(
            "SSH is experimental and disabled; use HTTPS or explicitly set MRML_GIT_EXPERIMENTAL_SSH=1"
        ))
    }
}

fn parse_pull_arguments(arguments: &[Text]) -> Result<(&str, Option<&str>)> {
    let positionals = if arguments.first().is_some_and(|value| value == "--ff-only") {
        &arguments[1..]
    } else {
        arguments
    };
    if positionals.len() > 2 {
        return Err(anyhow!("pull accepts only [--ff-only] [remote] [branch]"));
    }
    checked_positionals(positionals)?;
    Ok((
        positionals.first().map(Text::as_str).unwrap_or("origin"),
        positionals.get(1).map(Text::as_str),
    ))
}

fn ssh_remote(repository: Option<&str>, name: &str) -> Result<(Text, SshRemote)> {
    require_experimental_ssh()?;
    let url = native_repository(repository)?
        .remotes()
        .map_err(|error| anyhow!("{}", error))?
        .into_iter()
        .find(|(remote, _)| remote == name)
        .map(|(_, url)| url)
        .ok_or_else(|| anyhow!("remote '{}' does not exist", name))?;
    let parsed =
        SshRemote::parse(&url).map_err(|error| anyhow!("invalid SSH remote: {}", error))?;
    Ok((url, parsed))
}

fn remote_url(repository: &Repository, name: &str) -> Result<Text> {
    repository
        .remotes()
        .map_err(|error| anyhow!("{}", error))?
        .into_iter()
        .find(|(remote, _)| remote == name)
        .map(|(_, url)| url)
        .ok_or_else(|| anyhow!("remote '{}' does not exist", name))
}

fn parse_https_transport(value: Option<&str>) -> Result<HttpsTransport> {
    match value {
        None | Some("h2") => Ok(HttpsTransport::Http2),
        Some("h3-v2") => Ok(HttpsTransport::Http3V2),
        Some(_) => Err(anyhow!("unsupported native HTTPS transport")),
    }
}

fn repository_https_transport(repository: &Repository) -> Result<HttpsTransport> {
    let configured = repository
        .config_value("http", "transport")
        .map_err(|error| anyhow!("{}", error))?;
    parse_https_transport(configured.as_deref())
}

fn repository_https_provider(repository: &Repository) -> Result<Option<Text>> {
    let provider = repository
        .config_value("http", "credentialProvider")
        .map_err(|error| anyhow!("{}", error))?;
    match provider.as_deref() {
        None => Ok(None),
        Some("standard-input" | "unix-v1") => Ok(provider),
        Some(_) => Err(anyhow!("HTTPS credential provider is unavailable")),
    }
}

#[cfg(target_os = "linux")]
fn credential_agent(repository: &Repository) -> Result<UnixHttpsCredentialProvider> {
    let required = |name: &str| {
        repository
            .config_value("http", name)
            .map_err(|error| anyhow!("{}", error))?
            .ok_or_else(|| anyhow!("HTTPS credential agent configuration is incomplete"))
    };
    let socket = required("credentialSocket")?;
    let capability_path = required("credentialCapabilityFile")?;
    let uid = required("credentialUid")?
        .parse()
        .ok()
        .filter(|value| *value != 0)
        .ok_or_else(|| anyhow!("HTTPS credential agent UID is invalid"))?;
    let gid = required("credentialGid")?
        .parse()
        .ok()
        .filter(|value| *value != 0)
        .ok_or_else(|| anyhow!("HTTPS credential agent GID is invalid"))?;
    let generation = required("credentialGeneration")?
        .parse()
        .ok()
        .filter(|value| *value != 0)
        .ok_or_else(|| anyhow!("HTTPS credential generation is invalid"))?;
    let mut bytes = load_protected_secret(&capability_path, 32)?;
    let mut capability = [0; 32];
    capability.copy_from_slice(&bytes);
    erase_secret(&mut bytes);
    let provider = UnixHttpsCredentialProvider::new(
        &socket,
        CredentialAgentPeer { uid, gid },
        CredentialAgentCapability::new(capability)
            .map_err(|_| anyhow!("HTTPS credential agent capability is invalid"))?,
        generation,
    )
    .map_err(|_| anyhow!("HTTPS credential agent configuration is invalid"));
    erase_secret(&mut capability);
    provider
}

#[cfg(target_os = "linux")]
fn protected_push_signer(
    repository: &Repository,
) -> Result<Option<(
    UnixProtectedCommitSigningProvider,
    mrml_git::HybridTrustPolicy,
    mrml_openpgp::PublicKeyV6,
    [u8; mrml_crypto::ML_DSA_65_PUBLIC_KEY_BYTES],
)>> {
    let provider = repository
        .config_value("gpg.protected", "signerProvider")
        .map_err(|error| anyhow!("{}", error))?;
    let Some(provider) = provider else { return Ok(None) };
    if provider != "unix-v1" {
        return Err(anyhow!("protected signer provider is unavailable"));
    }
    let required = |name: &str| {
        repository
            .config_value("gpg.protected", name)
            .map_err(|error| anyhow!("{}", error))?
            .ok_or_else(|| anyhow!("protected signer configuration is incomplete"))
    };
    let socket = required("signerSocket")?;
    let capability_path = required("signerCapabilityFile")?;
    let signer_uid: u32 = required("signerUid")?
        .parse()
        .ok()
        .filter(|value| *value != 0)
        .ok_or_else(|| anyhow!("protected signer UID is invalid"))?;
    let signer_gid: u32 = required("signerGid")?
        .parse()
        .ok()
        .filter(|value| *value != 0)
        .ok_or_else(|| anyhow!("protected signer GID is invalid"))?;
    let mut capability_bytes = load_protected_secret(&capability_path, 32)?;
    let mut capability = [0; 32];
    capability.copy_from_slice(&capability_bytes);
    erase_secret(&mut capability_bytes);
    let transport = UnixProtectedCommitSigningProvider::new(
        &socket,
        ProtectedSignerPeer { uid: signer_uid, gid: signer_gid },
        ProtectedSignerCapability::new(capability)
            .map_err(|_| anyhow!("protected signer capability is invalid"))?,
    )
    .map_err(|_| anyhow!("protected signer transport configuration is invalid"))?;
    erase_secret(&mut capability);

    let policy_dir = required("trustPolicyDirectory")?;
    let state = LinuxDurableTrustPolicyStore::open(&policy_dir)
        .and_then(|store| store.load())
        .map_err(|_| anyhow!("protected trust policy is unavailable"))?;
    let openpgp_path = required("openpgpPublicKeyFile")?;
    let openpgp_bytes = read_file_bounded(&openpgp_path, mrml_openpgp::MAX_OPENPGP_PUBLIC_KEY_BYTES)
        .map_err(|_| anyhow!("protected OpenPGP public key is unavailable"))?;
    let mut openpgp_scratch = [0; mrml_openpgp::MAX_OPENPGP_PUBLIC_KEY_BYTES];
    let openpgp = mrml_openpgp::parse_public_key_v6_ascii(&openpgp_bytes, &mut openpgp_scratch)
        .map_err(|_| anyhow!("protected OpenPGP public key is invalid"))?;
    let ml_dsa_path = required("mlDsaPublicKeyFile")?;
    let ml_dsa_bytes = read_file_bounded(&ml_dsa_path, mrml_crypto::ML_DSA_65_PUBLIC_KEY_BYTES)
        .map_err(|_| anyhow!("protected ML-DSA public key is unavailable"))?;
    let ml_dsa: [u8; mrml_crypto::ML_DSA_65_PUBLIC_KEY_BYTES] = (&*ml_dsa_bytes)
        .try_into()
        .map_err(|_| anyhow!("protected ML-DSA public key is invalid"))?;
    let pair = AuthorizedHybridPair::bind(&openpgp, &ml_dsa);
    let now = mrml_runtime::unix_time_seconds()
        .ok_or_else(|| anyhow!("trusted signing time is unavailable"))?;
    let policy = state
        .active_verification_policy_at(pair, now, true)
        .map_err(|_| anyhow!("protected signing pair is not currently authorized"))?;
    Ok(Some((transport, policy, openpgp, ml_dsa)))
}

#[cfg(target_os = "linux")]
fn load_protected_secret(path: &str, exact: usize) -> Result<Vector<u8>> {
    let mut file = File::open_regular(path)
        .map_err(|_| anyhow!("cannot open protected signer capability"))?;
    if !file.is_owner_only_secret()
        || file.len().map_err(|_| anyhow!("cannot inspect protected signer capability"))?
            != exact as u64
    {
        return Err(anyhow!("protected signer capability file is insecure"));
    }
    let mut bytes = Vector::with_capacity(exact).map_err(|_| anyhow!("allocation failed"))?;
    bytes.resize(exact, 0);
    if file.read_exact(&mut bytes).is_err() {
        erase_secret(&mut bytes);
        return Err(anyhow!("cannot read protected signer capability"));
    }
    Ok(bytes)
}

fn fetch_configured_https(
    repository: &Repository,
    remote_name: &str,
    remote: &HttpsRemote,
) -> Result<mrml_git::FetchResult> {
    match repository_https_provider(repository)?.as_deref() {
        None => fetch_https(repository, remote_name, remote, MAX_HTTPS_PACK_BYTES)
            .map_err(|error| anyhow!("{}", error)),
        Some("standard-input") => {
            let mut provider = StandardInputBearerProvider::read()?;
            fetch_https_authenticated(
                repository,
                remote_name,
                remote,
                MAX_HTTPS_PACK_BYTES,
                &mut provider,
            )
            .map_err(|error| anyhow!("{}", error))
        }
        #[cfg(target_os = "linux")]
        Some("unix-v1") => {
            let mut provider = credential_agent(repository)?;
            fetch_https_authenticated(
                repository,
                remote_name,
                remote,
                MAX_HTTPS_PACK_BYTES,
                &mut provider,
            )
            .map_err(|error| anyhow!("{}", error))
        }
        Some(_) => Err(anyhow!("HTTPS credential provider is unavailable")),
    }
}

fn print_ssh_remote(name: &str, url: &str, remote: &SshRemote) {
    println!("{} {}", "remote".green().bold(), name);
    println!("{} {}", "url".green().bold(), url);
    println!("{} {}", "destination".green().bold(), remote.destination());
    println!("{} {}", "path".green().bold(), remote.path);
    println!(
        "{} {}",
        "port".green().bold(),
        remote
            .port
            .map(|value| format!("{}", value))
            .unwrap_or_else(|| "default".into())
    );
}

fn ssh_credentials_paths(
    private_path: &str,
    host_path: &str,
) -> Result<(RsaPrivateKey, Vector<u8>)> {
    let private = load_development_rsa_key(private_path)?;
    let host = read_file_text_bounded(host_path, 64 * 1024)
        .map_err(|_| anyhow!("cannot read pinned SSH host key"))?;
    let host = parse_rsa_public_line(&host)
        .and_then(|key| encode_rsa_public_key(&key))
        .map_err(|error| anyhow!("invalid SSH host key: {}", error))?;
    Ok((private, host))
}

fn development_key_files_enabled() -> bool {
    mrml_runtime::environment_variable("MRML_GIT_DEVELOPMENT_KEY_FILES").as_deref() == Some("1")
}

#[inline(never)]
fn erase_secret(bytes: &mut [u8]) {
    mrml_crypto::erase_secret_bytes(bytes);
}

fn load_development_secret(path: &str, maximum: usize) -> Result<Vector<u8>> {
    if !development_key_files_enabled() {
        return Err(anyhow!(
            "key-file providers are disabled; use a signer or credential provider"
        ));
    }
    let mut file =
        File::open_regular(path).map_err(|_| anyhow!("cannot open development SSH private key"))?;
    if !file.is_owner_only_secret() {
        return Err(anyhow!(
            "development key must be owned by this user with mode 0400 or 0600"
        ));
    }
    let length = usize::try_from(
        file.len()
            .map_err(|_| anyhow!("cannot inspect development key"))?,
    )
    .ok()
    .filter(|length| *length != 0 && *length <= maximum)
    .ok_or_else(|| anyhow!("development SSH private key has an invalid size"))?;
    let mut bytes =
        Vector::with_capacity(length).map_err(|_| anyhow!("cannot allocate key buffer"))?;
    bytes.resize(length, 0);
    if file.read_exact(&mut bytes).is_err() {
        erase_secret(&mut bytes);
        return Err(anyhow!("cannot read development SSH private key"));
    }
    Ok(bytes)
}

fn load_development_rsa_key(path: &str) -> Result<RsaPrivateKey> {
    require_experimental_ssh()?;
    let mut bytes = load_development_secret(path, 64 * 1024)?;
    let parsed = core::str::from_utf8(&bytes)
        .map_err(|_| anyhow!("development SSH private key is not text"))
        .and_then(|text| {
            parse_rsa_private_pem(text)
                .map_err(|error| anyhow!("invalid development SSH private key: {}", error))
        });
    erase_secret(&mut bytes);
    parsed
}

fn ssh_credentials(repository: &Repository) -> Result<(RsaPrivateKey, Vector<u8>)> {
    let provider = repository
        .config_value("ssh", "credentialProvider")
        .map_err(|error| anyhow!("{}", error))?;
    if provider.as_deref() != Some("development-key-file") {
        return Err(anyhow!("SSH credential provider is unavailable"));
    }
    let private = repository
        .config_value("ssh", "developmentPrivateKeyFile")
        .map_err(|error| anyhow!("{}", error))?
        .ok_or_else(|| anyhow!("development SSH credential is incomplete"))?;
    let host = repository
        .config_value("ssh", "hostKey")
        .map_err(|error| anyhow!("{}", error))?
        .ok_or_else(|| anyhow!("run ssh auth <private-key.pem> <host-public-key> first"))?;
    ssh_credentials_paths(&private, &host)
}
fn repository_ssh_signing_key(repository: &Repository) -> Result<RsaPrivateKey> {
    let provider = repository
        .config_value("gpg.ssh", "signerProvider")
        .map_err(|error| anyhow!("{}", error))?;
    if provider.as_deref() != Some("development-key-file") {
        return Err(anyhow!("SSH signer provider is unavailable"));
    }
    let path = repository
        .config_value("gpg.ssh", "developmentPrivateKeyFile")
        .map_err(|error| anyhow!("{}", error))?
        .ok_or_else(|| anyhow!("development SSH signer is incomplete"))?;
    load_development_rsa_key(&path)
}
fn repository_ssh_verification_key(repository: &Repository) -> Result<mrml_ssh::RsaPublicKey> {
    require_experimental_ssh()?;
    let path = repository
        .config_value("gpg.ssh", "allowedSignersFile")
        .map_err(|error| anyhow!("{}", error))?
        .ok_or_else(|| anyhow!("signing verification requires an allowed signer file"))?;
    let text = read_file_text_bounded(&path, 64 * 1024)
        .map_err(|_| anyhow!("cannot read allowed signer"))?;
    parse_rsa_public_line(&text).map_err(|error| anyhow!("invalid allowed signer: {}", error))
}

fn repository_signature_format(repository: &Repository) -> Result<GitSignatureFormat> {
    let configured = repository
        .config_value("gpg", "format")
        .map_err(|error| anyhow!("{}", error))?;
    match configured.as_deref() {
        None => {
            let user_key = repository
                .config_value("user", "signingkey")
                .map_err(|error| anyhow!("{}", error))?;
            let ssh_provider = repository
                .config_value("gpg.ssh", "signerProvider")
                .map_err(|error| anyhow!("{}", error))?;
            let ssh_allowed = repository
                .config_value("gpg.ssh", "allowedSignersFile")
                .map_err(|error| anyhow!("{}", error))?;
            if user_key.is_none() && (ssh_provider.is_some() || ssh_allowed.is_some()) {
                Ok(GitSignatureFormat::Ssh)
            } else {
                Ok(GitSignatureFormat::OpenPgp)
            }
        }
        Some(value)
            if value.eq_ignore_ascii_case("openpgp") || value.eq_ignore_ascii_case("gpg") =>
        {
            Ok(GitSignatureFormat::OpenPgp)
        }
        Some(value) if value.eq_ignore_ascii_case("ssh") => Ok(GitSignatureFormat::Ssh),
        Some(value) => Err(anyhow!("unsupported Git signature format '{}'", value)),
    }
}

fn repository_openpgp_public_key(repository: &Repository) -> Result<Text> {
    let configured = repository
        .config_value("gpg.openpgp", "publicKeyFile")
        .map_err(|error| anyhow!("{}", error))?;
    let path = configured.unwrap_or_else(|| MRML_OPENPGP_PUBLIC_KEY.into());
    let path = if mrml_runtime::path_is_absolute(&path) {
        path
    } else {
        join_path(&repository.worktree, &path)
    };
    if !path_is_file(&path) {
        return Err(anyhow!(
            "OpenPGP verification key '{}' is unavailable; configure gpg.openpgp.publicKeyFile",
            path
        ));
    }
    Ok(path)
}

fn repository_openpgp_seed(repository: &Repository) -> Result<Text> {
    let provider = repository
        .config_value("gpg.openpgp", "signerProvider")
        .map_err(|error| anyhow!("{}", error))?;
    if provider.as_deref() != Some("development-key-file") {
        return Err(anyhow!("OpenPGP signer provider is unavailable"));
    }
    let configured = repository
        .config_value("gpg.openpgp", "privateSeedFile")
        .map_err(|error| anyhow!("{}", error))?
        .ok_or_else(|| {
            anyhow!(
                "OpenPGP signing requires gpg.openpgp.privateSeedFile; run signing configure-openpgp"
            )
        })?;
    let path = if mrml_runtime::path_is_absolute(&configured) {
        configured
    } else {
        join_path(&repository.worktree, &configured)
    };
    if !path_is_file(&path) {
        return Err(anyhow!("configured OpenPGP private seed is unavailable"));
    }
    Ok(path)
}

fn repository_openpgp_fingerprint_text(repository: &Repository) -> Result<Text> {
    repository
        .config_value("gpg.openpgp", "allowedFingerprint")
        .map_err(|error| anyhow!("{}", error))
        .map(|value| value.unwrap_or_else(|| MRML_OPENPGP_FINGERPRINT.into()))
}

fn repository_openpgp_fingerprint(repository: &Repository) -> Result<OpenPgpFingerprint> {
    let value = repository_openpgp_fingerprint_text(repository)?;
    OpenPgpFingerprint::parse_hex(&value)
        .map_err(|error| anyhow!("invalid primary fingerprint: {}", error))
}

fn openpgp_fingerprint_text(fingerprint: OpenPgpFingerprint) -> Text {
    let mut encoded = [0u8; 40];
    fingerprint
        .write_hex(&mut encoded)
        .expect("fixed OpenPGP fingerprint buffer");
    core::str::from_utf8(&encoded)
        .expect("hexadecimal OpenPGP fingerprint")
        .into()
}

fn repository_openpgp_revoked(repository: &Repository) -> Result<bool> {
    let configured = repository
        .config_value("gpg.openpgp", "revoked")
        .map_err(|error| anyhow!("{}", error))?;
    match configured.as_deref() {
        None | Some("false") => Ok(false),
        Some("true") => Ok(true),
        Some(_) => Err(anyhow!("invalid gpg.openpgp.revoked value")),
    }
}

fn repository_openpgp_key_not_after(
    repository: &Repository,
    fingerprint: OpenPgpFingerprint,
) -> Result<Option<u64>> {
    let configured = repository
        .config_value("gpg.openpgp", "keyNotAfter")
        .map_err(|error| anyhow!("{}", error))?;
    match configured.as_deref() {
        Some(value) if value.eq_ignore_ascii_case("none") => Ok(None),
        Some(value) => value
            .parse::<u64>()
            .ok()
            .filter(|value| *value != 0)
            .map(Some)
            .ok_or_else(|| anyhow!("invalid gpg.openpgp.keyNotAfter value")),
        None if fingerprint
            == OpenPgpFingerprint::parse_hex(MRML_OPENPGP_FINGERPRINT)
                .expect("checked MRML fingerprint") =>
        {
            Ok(Some(MRML_OPENPGP_KEY_NOT_AFTER))
        }
        None => Ok(None),
    }
}

fn repository_openpgp_digest(repository: &Repository) -> Result<OpenPgpDigestAlgorithm> {
    let configured = repository
        .config_value("gpg.openpgp", "digestAlgorithm")
        .map_err(|error| anyhow!("{}", error))?;
    match configured.as_deref() {
        None => Ok(OpenPgpDigestAlgorithm::Sha512),
        Some(value) if value.eq_ignore_ascii_case("sha256") => Ok(OpenPgpDigestAlgorithm::Sha256),
        Some(value) if value.eq_ignore_ascii_case("sha384") => Ok(OpenPgpDigestAlgorithm::Sha384),
        Some(value) if value.eq_ignore_ascii_case("sha512") => Ok(OpenPgpDigestAlgorithm::Sha512),
        Some(value) => Err(anyhow!(
            "unsupported OpenPGP digest '{}'; use sha256, sha384, or sha512",
            value
        )),
    }
}

const fn openpgp_digest_name(digest: OpenPgpDigestAlgorithm) -> &'static str {
    match digest {
        OpenPgpDigestAlgorithm::Sha256 => "sha256",
        OpenPgpDigestAlgorithm::Sha384 => "sha384",
        OpenPgpDigestAlgorithm::Sha512 => "sha512",
    }
}

const fn signing_interface_digest(
    digest: OpenPgpDigestAlgorithm,
) -> InterfaceOpenPgpDigestAlgorithm {
    match digest {
        OpenPgpDigestAlgorithm::Sha256 => InterfaceOpenPgpDigestAlgorithm::Sha256,
        OpenPgpDigestAlgorithm::Sha384 => InterfaceOpenPgpDigestAlgorithm::Sha384,
        OpenPgpDigestAlgorithm::Sha512 => InterfaceOpenPgpDigestAlgorithm::Sha512,
    }
}

fn load_openpgp_public_key(repository: &Repository) -> Result<OpenPgpPublicKey> {
    let path = repository_openpgp_public_key(repository)?;
    let public = read_file_bounded(&path, mrml_openpgp::MAX_OPENPGP_PUBLIC_KEY_BYTES)
        .map_err(|_| anyhow!("cannot read OpenPGP public key"))?;
    let mut scratch = [0u8; mrml_openpgp::MAX_OPENPGP_PUBLIC_KEY_BYTES];
    let key = parse_public_key_ascii(&public, &mut scratch)
        .map_err(|error| anyhow!("invalid OpenPGP public key: {}", error))?;
    if key.fingerprint() != repository_openpgp_fingerprint(repository)? {
        return Err(anyhow!(
            "OpenPGP public key fingerprint does not match owner policy"
        ));
    }
    Ok(key)
}

fn load_openpgp_signing_key(repository: &Repository) -> Result<OpenPgpSigningKey> {
    let public = load_openpgp_public_key(repository)?;
    let path = repository_openpgp_seed(repository)?;
    let mut bytes = load_development_secret(&path, 32)?;
    if bytes.len() != 32 {
        erase_secret(&mut bytes);
        return Err(anyhow!("development OpenPGP seed must be exactly 32 bytes"));
    }
    let result = OpenPgpSigningKey::from_seed_bytes_and_public_key(&mut bytes, public)
        .map_err(|error| anyhow!("invalid OpenPGP private seed: {}", error));
    erase_secret(&mut bytes);
    result
}

fn sign_openpgp(
    repository: &Repository,
    payload: &[u8],
    purpose: OpenPgpGitSigningPurpose,
) -> Result<Text> {
    let digest_algorithm = repository_openpgp_digest(repository)?;
    let interface_digest = signing_interface_digest(digest_algorithm);
    if InterfaceOpenPgpDigestAlgorithm::from_wire(interface_digest.wire()).is_none() {
        return Err(anyhow!(
            "OpenPGP digest is unavailable through the signing interface"
        ));
    }
    let key = load_openpgp_signing_key(repository)?;
    let fingerprint = repository_openpgp_fingerprint(repository)?;
    let not_after = repository_openpgp_key_not_after(repository, fingerprint)?;
    let revoked = repository_openpgp_revoked(repository)?;
    let public_key = key.public_key();
    let armor = sign_git_payload_via_interface(
        key,
        purpose,
        interface_digest,
        not_after,
        revoked,
        payload,
        mrml_runtime::unix_time_seconds,
    )
    .map_err(|error| anyhow!("OpenPGP signing failed: {}", error))?;
    let validation_time = mrml_runtime::unix_time_seconds()
        .ok_or_else(|| anyhow!("system time is unavailable for OpenPGP policy"))?;
    let mut scratch = [0u8; mrml_openpgp::MAX_OPENPGP_SIGNATURE_BYTES];
    verify_detached_ascii(
        &public_key,
        payload,
        &armor,
        &OpenPgpVerificationPolicy {
            expected_primary_fingerprint: fingerprint,
            validation_time: Some(validation_time),
            key_not_after: not_after,
            key_revoked: revoked,
            enforce_signature_expiration: true,
        },
        &mut scratch,
    )
    .map_err(|error| anyhow!("OpenPGP signing self-check failed: {}", error))?;
    let armor = core::str::from_utf8(&armor)
        .map_err(|_| anyhow!("OpenPGP library returned non-UTF-8 ASCII armor"))?;
    Ok(armor.into())
}

fn verify_openpgp(repository: &Repository, payload: &[u8], armor: &str) -> Result<()> {
    let public_key = load_openpgp_public_key(repository)?;
    let fingerprint = repository_openpgp_fingerprint(repository)?;
    let not_after = repository_openpgp_key_not_after(repository, fingerprint)?;
    let revoked = repository_openpgp_revoked(repository)?;
    let now = mrml_runtime::unix_time_seconds()
        .ok_or_else(|| anyhow!("system time is unavailable for OpenPGP policy"))?;
    let mut scratch = [0u8; mrml_openpgp::MAX_OPENPGP_SIGNATURE_BYTES];
    verify_detached_ascii(
        &public_key,
        payload,
        armor.as_bytes(),
        &OpenPgpVerificationPolicy {
            expected_primary_fingerprint: fingerprint,
            validation_time: Some(now),
            key_not_after: not_after,
            key_revoked: revoked,
            enforce_signature_expiration: true,
        },
        &mut scratch,
    )
    .map_err(|error| anyhow!("OpenPGP verification failed: {}", error))?;
    Ok(())
}

fn repository_identity(repository: &Repository) -> Result<(Text, Text)> {
    let name = mrml_runtime::environment_variable("MRML_GIT_AUTHOR_NAME")
        .or_else(|| mrml_runtime::environment_variable("GIT_AUTHOR_NAME"))
        .or_else(|| repository.config_value("user", "name").ok().flatten())
        .unwrap_or_else(|| "MRML User".into());
    let email = mrml_runtime::environment_variable("MRML_GIT_AUTHOR_EMAIL")
        .or_else(|| mrml_runtime::environment_variable("GIT_AUTHOR_EMAIL"))
        .or_else(|| repository.config_value("user", "email").ok().flatten())
        .unwrap_or_else(|| "mrml@localhost".into());
    Ok((name, email))
}

fn repository_signed_commit(
    repository: &Repository,
    message: &str,
    name: &str,
    email: &str,
    timestamp: u64,
) -> Result<mrml_git::ObjectId> {
    match repository_signature_format(repository)? {
        GitSignatureFormat::Ssh => {
            let key = repository_ssh_signing_key(repository)?;
            repository
                .commit_signed(message, name, email, timestamp, &key)
                .map_err(|error| anyhow!("{}", error))
        }
        GitSignatureFormat::OpenPgp => {
            let mut signing_error = None;
            let result = repository.commit_signed_with(
                message,
                name,
                email,
                timestamp,
                GitSignatureFormat::OpenPgp,
                |payload| match sign_openpgp(
                    repository,
                    payload,
                    OpenPgpGitSigningPurpose::GitCommit,
                ) {
                    Ok(signature) => Ok(signature),
                    Err(error) => {
                        signing_error = Some(format!("{}", error));
                        Err(mrml_git::RepositoryError::Signing)
                    }
                },
                |payload, armor| {
                    verify_openpgp(repository, payload, armor)
                        .map_err(|_| mrml_git::RepositoryError::Signing)
                },
            );
            repository_result_with_detail(result, signing_error)
        }
    }
}

fn repository_signed_tag(
    repository: &Repository,
    tag: &str,
    message: &str,
    name: &str,
    email: &str,
    timestamp: u64,
) -> Result<mrml_git::ObjectId> {
    match repository_signature_format(repository)? {
        GitSignatureFormat::Ssh => {
            let key = repository_ssh_signing_key(repository)?;
            repository
                .create_signed_tag(tag, message, name, email, timestamp, &key)
                .map_err(|error| anyhow!("{}", error))
        }
        GitSignatureFormat::OpenPgp => {
            let mut signing_error = None;
            let result = repository.create_signed_tag_with(
                tag,
                message,
                name,
                email,
                timestamp,
                GitSignatureFormat::OpenPgp,
                |payload| match sign_openpgp(
                    repository,
                    payload,
                    OpenPgpGitSigningPurpose::GitAnnotatedTag,
                ) {
                    Ok(signature) => Ok(signature),
                    Err(error) => {
                        signing_error = Some(format!("{}", error));
                        Err(mrml_git::RepositoryError::Signing)
                    }
                },
                |payload, armor| {
                    verify_openpgp(repository, payload, armor)
                        .map_err(|_| mrml_git::RepositoryError::Signing)
                },
            );
            repository_result_with_detail(result, signing_error)
        }
    }
}

fn repository_verify_commit(repository: &Repository, id: mrml_git::ObjectId) -> Result<Text> {
    match repository_signature_format(repository)? {
        GitSignatureFormat::Ssh => {
            let key = repository_ssh_verification_key(repository)?;
            repository
                .verify_commit_signature(id, &key)
                .map_err(|error| anyhow!("{}", error))?;
            Ok("SSH".into())
        }
        GitSignatureFormat::OpenPgp => {
            let mut verification_error = None;
            let result = repository.verify_commit_signature_with(
                id,
                GitSignatureFormat::OpenPgp,
                |payload, armor| match verify_openpgp(repository, payload, armor) {
                    Ok(()) => Ok(()),
                    Err(error) => {
                        verification_error = Some(format!("{}", error));
                        Err(mrml_git::RepositoryError::Signing)
                    }
                },
            );
            repository_result_with_detail(result, verification_error)?;
            Ok("OpenPGP".into())
        }
    }
}

fn repository_verify_tag(repository: &Repository, id: mrml_git::ObjectId) -> Result<Text> {
    match repository_signature_format(repository)? {
        GitSignatureFormat::Ssh => {
            let key = repository_ssh_verification_key(repository)?;
            repository
                .verify_tag_signature(id, &key)
                .map_err(|error| anyhow!("{}", error))?;
            Ok("SSH".into())
        }
        GitSignatureFormat::OpenPgp => {
            let mut verification_error = None;
            let result = repository.verify_tag_signature_with(
                id,
                GitSignatureFormat::OpenPgp,
                |payload, armor| match verify_openpgp(repository, payload, armor) {
                    Ok(()) => Ok(()),
                    Err(error) => {
                        verification_error = Some(format!("{}", error));
                        Err(mrml_git::RepositoryError::Signing)
                    }
                },
            );
            repository_result_with_detail(result, verification_error)?;
            Ok("OpenPGP".into())
        }
    }
}

fn repository_result_with_detail<T>(
    result: core::result::Result<T, mrml_git::RepositoryError>,
    detail: Option<Text>,
) -> Result<T> {
    match (result, detail) {
        (Ok(value), _) => Ok(value),
        (Err(_), Some(detail)) => Err(anyhow!("{}", detail)),
        (Err(error), None) => Err(anyhow!("{}", error)),
    }
}

fn native_fetch(repository: Option<&str>, name: &str) -> Result<()> {
    let repo = native_repository(repository)?;
    let url = remote_url(&repo, name)?;
    let result = if url.starts_with("https://") {
        let remote = HttpsRemote::parse(&url, repository_https_transport(&repo)?)
            .map_err(|error| anyhow!("invalid HTTPS remote: {}", error))?;
        fetch_configured_https(&repo, name, &remote)?
    } else {
        require_experimental_ssh()?;
        let remote =
            SshRemote::parse(&url).map_err(|error| anyhow!("invalid SSH remote: {}", error))?;
        let (key, host) = ssh_credentials(&repo)?;
        fetch_ssh(&repo, name, &remote, &key, &host).map_err(|error| anyhow!("{}", error))?
    };
    println!(
        "Fetched {} object(s) and {} branch ref(s) from {}",
        result.objects.len(),
        result.branches.len(),
        name
    );
    Ok(())
}

fn finish_clone(
    repo: &Repository,
    url: &str,
    target: &str,
    result: &mrml_git::FetchResult,
) -> Result<()> {
    let branch = result
        .default_branch
        .as_ref()
        .and_then(|name| result.branches.iter().find(|(branch, _)| branch == name))
        .or_else(|| result.branches.iter().find(|(branch, _)| branch == "main"))
        .or_else(|| {
            result
                .branches
                .iter()
                .find(|(branch, _)| branch == "master")
        })
        .or_else(|| result.branches.first());
    if let Some(branch) = branch {
        repo.checkout_branch_at(&branch.0, branch.1)
            .map_err(|error| anyhow!("{}", error))?;
        repo.set_upstream(&mrml_runtime::mrml_format!("origin/{}", branch.0))
            .map_err(|error| anyhow!("{}", error))?;
        println!("Cloned {} into {} on branch {}", url, target, branch.0);
    } else {
        println!("Cloned empty repository {} into {}", url, target);
    }
    Ok(())
}

fn native_clone(url: &str, explicit_target: Option<&str>) -> Result<()> {
    if url.starts_with("https://") {
        let transport_setting = mrml_runtime::environment_variable("MRML_GIT_HTTPS_TRANSPORT");
        let transport = parse_https_transport(transport_setting.as_deref())?;
        let remote = HttpsRemote::parse(url, transport)
            .map_err(|error| anyhow!("invalid HTTPS remote: {}", error))?;
        let target: Text = explicit_target.map(Into::into).unwrap_or_else(|| {
            remote
                .repository_path
                .rsplit('/')
                .next()
                .unwrap_or("repository.git")
                .trim_end_matches(".git")
                .into()
        });
        let provider = mrml_runtime::environment_variable("MRML_GIT_CREDENTIAL_PROVIDER");
        if provider.as_deref().is_some_and(|value| {
            value != "standard-input" && value != "unix-v1"
        })
        {
            return Err(anyhow!("HTTPS credential provider is unavailable"));
        }
        let repo = Repository::init_with_format(&target, ObjectFormat::Sha256)
            .map_err(|error| anyhow!("{}", error))?;
        repo.set_remote("origin", url, false)
            .map_err(|error| anyhow!("{}", error))?;
        repo.set_config_value(
            "http",
            "transport",
            match transport {
                HttpsTransport::Http2 => "h2",
                HttpsTransport::Http3V2 => "h3-v2",
            },
        )
        .map_err(|error| anyhow!("{}", error))?;
        if provider.as_deref() == Some("standard-input") {
            repo.set_config_value("http", "credentialProvider", "standard-input")
                .map_err(|error| anyhow!("{}", error))?;
        }
        #[cfg(target_os = "linux")]
        if provider.as_deref() == Some("unix-v1") {
            for (key, environment) in [
                ("credentialSocket", "MRML_GIT_CREDENTIAL_SOCKET"),
                ("credentialCapabilityFile", "MRML_GIT_CREDENTIAL_CAPABILITY_FILE"),
                ("credentialUid", "MRML_GIT_CREDENTIAL_UID"),
                ("credentialGid", "MRML_GIT_CREDENTIAL_GID"),
                ("credentialGeneration", "MRML_GIT_CREDENTIAL_GENERATION"),
            ] {
                let value = mrml_runtime::environment_variable(environment)
                    .ok_or_else(|| anyhow!("HTTPS credential agent configuration is incomplete"))?;
                repo.set_config_value("http", key, &value)
                    .map_err(|error| anyhow!("{}", error))?;
            }
            repo.set_config_value("http", "credentialProvider", "unix-v1")
                .map_err(|error| anyhow!("{}", error))?;
        }
        let result = fetch_configured_https(&repo, "origin", &remote)?;
        return finish_clone(&repo, url, &target, &result);
    }

    require_experimental_ssh()?;
    let remote = SshRemote::parse(url).map_err(|error| anyhow!("invalid SSH remote: {}", error))?;
    let target: Text = explicit_target.map(Into::into).unwrap_or_else(|| {
        remote
            .path
            .rsplit('/')
            .next()
            .unwrap_or("repository")
            .trim_end_matches(".git")
            .into()
    });
    let private_path = mrml_runtime::environment_variable("MRML_GIT_SSH_KEY")
        .ok_or_else(|| anyhow!("clone requires MRML_GIT_SSH_KEY"))?;
    let host_path = mrml_runtime::environment_variable("MRML_GIT_SSH_HOST_KEY")
        .ok_or_else(|| anyhow!("clone requires MRML_GIT_SSH_HOST_KEY"))?;
    let (key, host) = ssh_credentials_paths(&private_path, &host_path)?;
    let remote_info = inspect_ssh(&remote, &key, &host).map_err(|error| anyhow!("{}", error))?;
    let repo = Repository::init_with_format(&target, remote_info.object_format)
        .map_err(|error| anyhow!("{}", error))?;
    repo.set_remote("origin", url, false)
        .map_err(|error| anyhow!("{}", error))?;
    repo.set_config_value("ssh", "credentialProvider", "development-key-file")
        .map_err(|error| anyhow!("{}", error))?;
    repo.set_config_value("ssh", "developmentPrivateKeyFile", &private_path)
        .map_err(|error| anyhow!("{}", error))?;
    repo.set_config_value("ssh", "hostKey", &host_path)
        .map_err(|error| anyhow!("{}", error))?;
    let result =
        fetch_ssh(&repo, "origin", &remote, &key, &host).map_err(|error| anyhow!("{}", error))?;
    finish_clone(&repo, url, &target, &result)
}

fn native_push(repository: Option<&str>, name: &str, branch: Option<&str>) -> Result<()> {
    let repo = native_repository(repository)?;
    let branch = branch
        .map(Into::into)
        .or_else(|| repo.current_branch().ok().flatten())
        .ok_or_else(|| anyhow!("push requires a branch for detached HEAD"))?;
    let url = remote_url(&repo, name)?;
    let result = if url.starts_with("https://") {
        let remote = HttpsRemote::parse(&url, repository_https_transport(&repo)?)
            .map_err(|error| anyhow!("invalid HTTPS remote: {}", error))?;
        match repository_https_provider(&repo)?.as_deref() {
            Some("standard-input") => {
                let mut provider = StandardInputBearerProvider::read()?;
                #[cfg(target_os = "linux")]
                if let Some((transport, policy, openpgp, ml_dsa)) = protected_push_signer(&repo)? {
                    let mut scratch = [0; mrml_openpgp::MAX_OPENPGP_SIGNATURE_BYTES];
                    let mut signer = CapabilityVerifiedProofSigner::new(
                        transport, policy, &openpgp, &ml_dsa, &mut scratch,
                    )
                    .map_err(|_| anyhow!("protected signer policy is invalid"))?;
                    push_https_protected_authenticated(
                        &repo,
                        name,
                        &branch,
                        &remote,
                        &mut provider,
                        &mut signer,
                        HistoryVerificationLimits::default(),
                    )
                    .map_err(|error| anyhow!("{}", error))?
                } else {
                    mrml_git::push_https_authenticated(&repo, name, &branch, &remote, &mut provider)
                        .map_err(|error| anyhow!("{}", error))?
                }
                #[cfg(not(target_os = "linux"))]
                mrml_git::push_https_authenticated(&repo, name, &branch, &remote, &mut provider)
                    .map_err(|error| anyhow!("{}", error))?
            }
            #[cfg(target_os = "linux")]
            Some("unix-v1") => {
                let mut provider = credential_agent(&repo)?;
                if let Some((transport, policy, openpgp, ml_dsa)) = protected_push_signer(&repo)? {
                    let mut scratch = [0; mrml_openpgp::MAX_OPENPGP_SIGNATURE_BYTES];
                    let mut signer = CapabilityVerifiedProofSigner::new(
                        transport, policy, &openpgp, &ml_dsa, &mut scratch,
                    )
                    .map_err(|_| anyhow!("protected signer policy is invalid"))?;
                    push_https_protected_authenticated(
                        &repo, name, &branch, &remote, &mut provider, &mut signer,
                        HistoryVerificationLimits::default(),
                    )
                    .map_err(|error| anyhow!("{}", error))?
                } else {
                    mrml_git::push_https_authenticated(&repo, name, &branch, &remote, &mut provider)
                        .map_err(|error| anyhow!("{}", error))?
                }
            }
            _ => {
                return Err(anyhow!(
                    "protected HTTPS push requires http.credentialProvider=standard-input"
                ));
            }
        }
    } else {
        require_experimental_ssh()?;
        let remote =
            SshRemote::parse(&url).map_err(|error| anyhow!("invalid SSH remote: {}", error))?;
        let (key, host) = ssh_credentials(&repo)?;
        push_ssh(&repo, name, &branch, &remote, &key, &host)
            .map_err(|error| anyhow!("{}", error))?
    };
    if result.old == result.new {
        println!("Everything up to date.");
    } else {
        println!(
            "Pushed {} to {}/{}",
            &result.new.to_hex()[..12],
            name,
            branch
        );
    }
    Ok(())
}

fn config_value(repository: Option<&str>, key: &str) -> Option<Text> {
    let (section, name) = key.rsplit_once('.')?;
    native_repository(repository)
        .ok()?
        .config_value(section, name)
        .ok()
        .flatten()
}

fn print_signing_status(repository: Option<&str>) -> Result<()> {
    let repo = native_repository(repository)?;
    let signature_format = repository_signature_format(&repo)?;
    println!(
        "{} {}",
        "object format".green().bold(),
        repo.object_format()
    );
    println!(
        "{} {}",
        "signature format".green().bold(),
        match signature_format {
            GitSignatureFormat::OpenPgp => "openpgp",
            GitSignatureFormat::Ssh => "ssh",
        }
    );
    for (label, key) in [
        ("key selector", "user.signingkey"),
        ("commit auto-sign", "commit.gpgsign"),
        ("tag auto-sign", "tag.gpgsign"),
    ] {
        println!(
            "{} {}",
            label.green().bold(),
            config_value(repository, key).unwrap_or_else(|| "not configured".into())
        );
    }
    match signature_format {
        GitSignatureFormat::OpenPgp => {
            match repository_openpgp_public_key(&repo) {
                Ok(path) => println!("{} {}", "public key".green().bold(), path),
                Err(error) => println!("{} {}", "public key".yellow().bold(), error),
            }
            println!(
                "{} {}",
                "private seed".green().bold(),
                if repository_openpgp_seed(&repo).is_ok() {
                    "configured"
                } else {
                    "not configured"
                }
            );
            println!(
                "{} {}",
                "primary fingerprint".green().bold(),
                repository_openpgp_fingerprint_text(&repo)?
            );
            let digest = repository_openpgp_digest(&repo)?;
            println!(
                "{} {} (interface {})",
                "signature digest".green().bold(),
                openpgp_digest_name(digest),
                signing_interface_digest(digest).wire()
            );
            let fingerprint = repository_openpgp_fingerprint(&repo)?;
            println!(
                "{} {}",
                "key not after".green().bold(),
                repository_openpgp_key_not_after(&repo, fingerprint)?
                    .map(|value| format!("{}", value))
                    .unwrap_or_else(|| "not configured".into())
            );
            println!(
                "{} {}",
                "owner revocation".green().bold(),
                if repository_openpgp_revoked(&repo)? {
                    "revoked"
                } else {
                    "not revoked"
                }
            );
        }
        GitSignatureFormat::Ssh => println!(
            "{} {}",
            "allowed signers".green().bold(),
            config_value(repository, "gpg.ssh.allowedSignersFile")
                .unwrap_or_else(|| "not configured".into())
        ),
    }
    Ok(())
}

fn dispatch(cli: &Cli) -> Result<()> {
    let repository = cli.repository.as_deref();
    let tail: &[Text] = &cli.arguments;
    match cli.command.as_str() {
        "status" | "pulse" if tail.is_empty() => native_dashboard(repository),
        "help" | "--help" | "-h" if tail.is_empty() => {
            help();
            Ok(())
        }
        "--version" | "-V" if tail.is_empty() => {
            println!("{}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        "doctor" if tail.is_empty() => {
            println!(
                "{} built-in object IDs, index, repository and status",
                "native".green().bold()
            );
            match native_repository(repository) {
                Ok(repo) => println!("{} {}", "repository".green().bold(), repo.worktree),
                Err(_) => println!("{} not inside a repository", "repository".yellow().bold()),
            }
            Ok(())
        }
        "init" if tail.len() <= 1 => {
            checked_positionals(tail)?;
            let path = tail.first().map(Text::as_str).or(repository).unwrap_or(".");
            let initialized = Repository::init_with_format(path, ObjectFormat::Sha256)
                .map_err(|error| anyhow!("{}", error))?;
            println!(
                "Initialized empty MRML Git repository in {}",
                initialized.git_dir
            );
            Ok(())
        }
        "clone" if matches!(tail.len(), 1 | 2) => {
            checked_positionals(tail)?;
            native_clone(&tail[0], tail.get(1).map(Text::as_str))
        }
        "log" => {
            let count = tail.first().map(Text::as_str).unwrap_or("12");
            if tail.len() > 1 || count.parse::<usize>().is_err() {
                return Err(anyhow!("log accepts one numeric count"));
            }
            let limit = count
                .parse::<usize>()
                .map_err(|_| anyhow!("invalid log count"))?;
            let repository = native_repository(repository)?;
            let head = repository
                .head()
                .map_err(|error| anyhow!("{}", error))?
                .ok_or_else(|| anyhow!("no commits yet"))?;
            for (id, commit) in repository
                .history(head, limit)
                .map_err(|error| anyhow!("{}", error))?
            {
                println!(
                    "{} {}",
                    (&id.to_hex()[..12]).bright_yellow(),
                    commit.message.lines().next().unwrap_or("")
                );
                println!("  {}", commit.author.dimmed());
            }
            Ok(())
        }
        "diff" => {
            let staged = tail.first().is_some_and(|argument| argument == "--staged");
            let paths = if staged { &tail[1..] } else { tail };
            checked_positionals(paths)?;
            let diffs = native_repository(repository)?
                .diff(staged, paths)
                .map_err(|error| anyhow!("{}", error))?;
            for diff in diffs {
                println!("{}", diff.unified());
            }
            Ok(())
        }
        "diff-ref" if !tail.is_empty() => {
            checked_positionals(tail)?;
            let diffs = native_repository(repository)?
                .diff_revision(&tail[0], &tail[1..])
                .map_err(|error| anyhow!("{}", error))?;
            for diff in diffs {
                println!("{}", diff.unified());
            }
            Ok(())
        }
        "show" if tail.len() <= 1 => {
            checked_positionals(tail)?;
            let repository = native_repository(repository)?;
            let id = repository
                .resolve_revision(tail.first().map(Text::as_str).unwrap_or("HEAD"))
                .map_err(|error| anyhow!("{}", error))?;
            let commit = repository
                .read_commit(id)
                .map_err(|error| anyhow!("{}", error))?;
            println!("{} {}", "commit".yellow(), id);
            println!("{} {}", "Author:".dimmed(), commit.author);
            println!("{} {}", "Tree:".dimmed(), commit.tree);
            for parent in commit.parents {
                println!("{} {}", "Parent:".dimmed(), parent);
            }
            println!("\n{}", commit.message);
            Ok(())
        }
        "history" if tail.len() == 1 => {
            checked_positionals(tail)?;
            for (id, commit) in native_repository(repository)?
                .file_history(&tail[0], 256)
                .map_err(|error| anyhow!("{}", error))?
            {
                println!(
                    "{} {}",
                    &id.to_hex()[..12],
                    commit.message.lines().next().unwrap_or("")
                );
            }
            Ok(())
        }
        "blame" if tail.len() == 1 => {
            checked_positionals(tail)?;
            for line in native_repository(repository)?
                .blame(&tail[0])
                .map_err(|error| anyhow!("{}", error))?
            {
                println!(
                    "{} {:4} ({}) {}",
                    &line.commit.to_hex()[..12],
                    line.line_number,
                    line.author,
                    line.text.trim_end_matches('\n')
                );
            }
            Ok(())
        }
        "conflicts" if tail.is_empty() => {
            let paths = native_repository(repository)?
                .conflicted_paths()
                .map_err(|error| anyhow!("{}", error))?;
            if paths.is_empty() {
                println!("{}", "no unresolved conflicts".green());
            } else {
                for path in paths {
                    println!("{} {}", "conflict".red().bold(), path);
                }
            }
            Ok(())
        }
        "branch" if tail.is_empty() => {
            let repository = native_repository(repository)?;
            let current = repository
                .current_branch()
                .map_err(|error| anyhow!("{}", error))?;
            for (name, id) in repository
                .branches()
                .map_err(|error| anyhow!("{}", error))?
            {
                if current.as_deref() == Some(&name) {
                    println!("{} {} {}", "*".green(), name, &id.to_hex()[..12]);
                } else {
                    println!("  {} {}", name, &id.to_hex()[..12]);
                }
            }
            Ok(())
        }
        "branch" if tail.len() == 1 => {
            checked_positionals(tail)?;
            let id = native_repository(repository)?
                .create_branch(&tail[0], false)
                .map_err(|error| anyhow!("{}", error))?;
            println!("Created branch '{}' at {}", tail[0], &id.to_hex()[..12]);
            Ok(())
        }
        "branch" if tail.len() == 2 && tail[0] == "-d" => {
            checked_positionals(&tail[1..])?;
            native_repository(repository)?
                .delete_branch(&tail[1])
                .map_err(|error| anyhow!("{}", error))?;
            println!("Deleted branch {}", tail[1]);
            Ok(())
        }
        "branch-delete" if tail.len() == 1 => {
            checked_positionals(tail)?;
            native_repository(repository)?
                .delete_branch(&tail[0])
                .map_err(|error| anyhow!("{}", error))?;
            println!("Deleted branch {}", tail[0]);
            Ok(())
        }
        "switch" if tail.len() == 1 => {
            checked_positionals(tail)?;
            let id = native_repository(repository)?
                .switch_branch(&tail[0])
                .map_err(|error| anyhow!("{}", error))?;
            println!("Switched to branch '{}' at {}", tail[0], &id.to_hex()[..12]);
            Ok(())
        }
        "switch" if tail.len() == 2 && tail[0] == "-c" => {
            checked_positionals(&tail[1..])?;
            let id = native_repository(repository)?
                .create_branch(&tail[1], true)
                .map_err(|error| anyhow!("{}", error))?;
            println!(
                "Switched to a new branch '{}' at {}",
                tail[1],
                &id.to_hex()[..12]
            );
            Ok(())
        }
        "checkout" if tail.len() == 1 => {
            checked_positionals(tail)?;
            let id = native_repository(repository)?
                .switch_branch(&tail[0])
                .map_err(|error| anyhow!("{}", error))?;
            println!("Switched to branch '{}' at {}", tail[0], &id.to_hex()[..12]);
            Ok(())
        }
        "checkout" if tail.len() == 2 && tail[0] == "-b" => {
            checked_positionals(&tail[1..])?;
            let id = native_repository(repository)?
                .create_branch(&tail[1], true)
                .map_err(|error| anyhow!("{}", error))?;
            println!(
                "Switched to a new branch '{}' at {}",
                tail[1],
                &id.to_hex()[..12]
            );
            Ok(())
        }
        "upstream" if tail.len() == 1 => {
            checked_positionals(tail)?;
            native_repository(repository)?
                .set_upstream(&tail[0])
                .map_err(|error| anyhow!("{}", error))?;
            println!("Branch now tracks {}", tail[0]);
            Ok(())
        }
        "publish" if tail.len() == 2 => {
            checked_positionals(tail)?;
            native_push(repository, &tail[0], Some(&tail[1]))?;
            native_repository(repository)?
                .set_upstream(&format!("{}/{}", tail[0], tail[1]))
                .map_err(|error| anyhow!("{}", error))?;
            Ok(())
        }
        "merge" if tail.len() == 1 => {
            checked_positionals(tail)?;
            let name = mrml_runtime::environment_variable("MRML_GIT_AUTHOR_NAME")
                .or_else(|| mrml_runtime::environment_variable("GIT_AUTHOR_NAME"))
                .unwrap_or_else(|| "MRML User".into());
            let email = mrml_runtime::environment_variable("MRML_GIT_AUTHOR_EMAIL")
                .or_else(|| mrml_runtime::environment_variable("GIT_AUTHOR_EMAIL"))
                .unwrap_or_else(|| "mrml@localhost".into());
            let timestamp = mrml_runtime::unix_time_seconds()
                .ok_or_else(|| anyhow!("system time is unavailable"))?;
            match native_repository(repository)?
                .merge(&tail[0], &name, &email, timestamp)
                .map_err(|error| anyhow!("{}", error))?
            {
                MergeOutcome::UpToDate => println!("Already up to date."),
                MergeOutcome::FastForward(id) => println!("Fast-forward to {}", &id.to_hex()[..12]),
                MergeOutcome::Merged(id) => println!("Merge made commit {}", &id.to_hex()[..12]),
                MergeOutcome::Conflicts(count) => {
                    println!("Merge has {} conflict(s); resolve and commit", count)
                }
            }
            Ok(())
        }
        "rebase" if tail.len() == 1 => {
            checked_positionals(tail)?;
            let name = mrml_runtime::environment_variable("MRML_GIT_AUTHOR_NAME")
                .or_else(|| mrml_runtime::environment_variable("GIT_AUTHOR_NAME"))
                .unwrap_or_else(|| "MRML User".into());
            let email = mrml_runtime::environment_variable("MRML_GIT_AUTHOR_EMAIL")
                .or_else(|| mrml_runtime::environment_variable("GIT_AUTHOR_EMAIL"))
                .unwrap_or_else(|| "mrml@localhost".into());
            let timestamp = mrml_runtime::unix_time_seconds()
                .ok_or_else(|| anyhow!("system time is unavailable"))?;
            match native_repository(repository)?
                .rebase(&tail[0], &name, &email, timestamp)
                .map_err(|error| anyhow!("{}", error))?
            {
                RebaseOutcome::UpToDate => println!("Current branch is up to date."),
                RebaseOutcome::Rebased { count, head } => println!(
                    "Rebased {} commit(s); HEAD is {}",
                    count,
                    &head.to_hex()[..12]
                ),
                RebaseOutcome::Conflicts(count) => {
                    println!("Rebase stopped with {} conflict(s)", count)
                }
            }
            Ok(())
        }
        "cherry-pick" if tail.len() == 1 => {
            checked_positionals(tail)?;
            let name = mrml_runtime::environment_variable("MRML_GIT_AUTHOR_NAME")
                .or_else(|| mrml_runtime::environment_variable("GIT_AUTHOR_NAME"))
                .unwrap_or_else(|| "MRML User".into());
            let email = mrml_runtime::environment_variable("MRML_GIT_AUTHOR_EMAIL")
                .or_else(|| mrml_runtime::environment_variable("GIT_AUTHOR_EMAIL"))
                .unwrap_or_else(|| "mrml@localhost".into());
            let timestamp = mrml_runtime::unix_time_seconds()
                .ok_or_else(|| anyhow!("system time is unavailable"))?;
            match native_repository(repository)?
                .cherry_pick(&tail[0], &name, &email, timestamp)
                .map_err(|error| anyhow!("{}", error))?
            {
                MergeOutcome::Merged(id) => {
                    println!("Cherry-picked {} as {}", tail[0], &id.to_hex()[..12])
                }
                MergeOutcome::Conflicts(count) => {
                    println!("Cherry-pick has {} conflict(s); resolve and commit", count)
                }
                _ => return Err(anyhow!("unexpected cherry-pick outcome")),
            }
            Ok(())
        }
        "operation-abort" if tail.len() == 1 && tail[0] == "merge" => {
            let id = native_repository(repository)?
                .abort_merge()
                .map_err(|error| anyhow!("{}", error))?;
            println!("Aborted merge; restored {}", &id.to_hex()[..12]);
            Ok(())
        }
        "operation-abort" if tail.len() == 1 && tail[0] == "rebase" => {
            let id = native_repository(repository)?
                .abort_rebase()
                .map_err(|error| anyhow!("{}", error))?;
            println!("Aborted rebase; restored {}", &id.to_hex()[..12]);
            Ok(())
        }
        "operation-abort" if tail.len() == 1 && tail[0] == "cherry-pick" => {
            let id = native_repository(repository)?
                .abort_cherry_pick()
                .map_err(|error| anyhow!("{}", error))?;
            println!("Aborted cherry-pick; restored {}", &id.to_hex()[..12]);
            Ok(())
        }
        "stage" | "add" => {
            checked_positionals(require_arguments("stage", tail)?)?;
            native_repository(repository)?
                .stage(tail)
                .map_err(|error| anyhow!("{}", error))?;
            native_dashboard(repository)
        }
        "rm" => {
            checked_positionals(require_arguments("rm", tail)?)?;
            native_repository(repository)?
                .remove_paths(tail)
                .map_err(|error| anyhow!("{}", error))?;
            native_dashboard(repository)
        }
        "mv" if tail.len() == 2 => {
            checked_positionals(tail)?;
            native_repository(repository)?
                .move_path(&tail[0], &tail[1])
                .map_err(|error| anyhow!("{}", error))?;
            native_dashboard(repository)
        }
        "unstage" => {
            checked_positionals(require_arguments("unstage", tail)?)?;
            native_repository(repository)?
                .unstage(tail)
                .map_err(|error| anyhow!("{}", error))?;
            native_dashboard(repository)
        }
        "reset" if tail.is_empty() => {
            native_repository(repository)?
                .unstage_all()
                .map_err(|error| anyhow!("{}", error))?;
            native_dashboard(repository)
        }
        "reset" => {
            checked_positionals(tail)?;
            native_repository(repository)?
                .unstage(tail)
                .map_err(|error| anyhow!("{}", error))?;
            native_dashboard(repository)
        }
        "restore" => {
            checked_positionals(require_arguments("restore", tail)?)?;
            native_repository(repository)?
                .restore(tail)
                .map_err(|error| anyhow!("{}", error))?;
            native_dashboard(repository)
        }
        "commit" => {
            let mut sign = false;
            let mut message = None;
            let mut legacy_words = Vector::new();
            let mut index = 0usize;
            while index < tail.len() {
                match tail[index].as_str() {
                    "-S" | "--gpg-sign" | "--sign" => sign = true,
                    "-m" | "--message" => {
                        index += 1;
                        let value = tail
                            .get(index)
                            .ok_or_else(|| anyhow!("commit -m requires a message"))?;
                        if message.replace(value.clone()).is_some() {
                            return Err(anyhow!("commit accepts one message"));
                        }
                    }
                    value if value.starts_with('-') => {
                        return Err(anyhow!("unsupported commit option '{}'", value));
                    }
                    _ => legacy_words.push(tail[index].clone()),
                }
                index += 1;
            }
            if message.is_some() && !legacy_words.is_empty() {
                return Err(anyhow!("commit message cannot mix -m and positional words"));
            }
            let message = message.unwrap_or_else(|| join_words(&legacy_words));
            if message.is_empty() {
                return Err(anyhow!("commit requires a message"));
            }
            let timestamp = mrml_runtime::unix_time_seconds()
                .ok_or_else(|| anyhow!("system time is unavailable"))?;
            let repo = native_repository(repository)?;
            let (name, email) = repository_identity(&repo)?;
            let sign = sign
                || repo
                    .config_value("commit", "gpgsign")
                    .ok()
                    .flatten()
                    .is_some_and(|value| value.eq_ignore_ascii_case("true"));
            let id = if sign {
                repository_signed_commit(&repo, &message, &name, &email, timestamp)?
            } else {
                repo.commit(&message, &name, &email, timestamp)
                    .map_err(|error| anyhow!("{}", error))?
            };
            println!("[{}] {}", (&id.to_hex()[..12]).bright_green(), message);
            Ok(())
        }
        "fetch" if tail.len() <= 1 => {
            checked_positionals(tail)?;
            native_fetch(
                repository,
                tail.first().map(Text::as_str).unwrap_or("origin"),
            )
        }
        "pull" => {
            let (remote, requested_branch) = parse_pull_arguments(tail)?;
            native_fetch(repository, remote)?;
            let repo = native_repository(repository)?;
            let branch = requested_branch
                .map(Into::into)
                .or_else(|| repo.current_branch().ok().flatten())
                .ok_or_else(|| anyhow!("pull requires a branch for detached HEAD"))?;
            let revision = format!("refs/remotes/{remote}/{branch}");
            match repo
                .fast_forward(&revision)
                .map_err(|error| anyhow!("fast-forward pull failed: {}", error))?
            {
                MergeOutcome::UpToDate => println!("Already up to date."),
                MergeOutcome::FastForward(id) => println!("Fast-forward to {}", &id.to_hex()[..12]),
                _ => return Err(anyhow!("unexpected pull outcome")),
            }
            Ok(())
        }
        "push" if tail.len() <= 2 => {
            checked_positionals(tail)?;
            native_push(
                repository,
                tail.first().map(Text::as_str).unwrap_or("origin"),
                tail.get(1).map(Text::as_str),
            )
        }
        "remote" if tail.is_empty() => {
            for (name, url) in native_repository(repository)?
                .remotes()
                .map_err(|error| anyhow!("{}", error))?
            {
                println!("{}\t{}", name, url);
            }
            Ok(())
        }
        "remote" if tail.len() == 3 && tail[0] == "add" => {
            checked_positionals(&tail[1..])?;
            native_repository(repository)?
                .set_remote(&tail[1], &tail[2], false)
                .map_err(|error| anyhow!("{}", error))
        }
        "remote" if tail.len() == 3 && tail[0] == "set-url" => {
            checked_positionals(&tail[1..])?;
            native_repository(repository)?
                .set_remote(&tail[1], &tail[2], true)
                .map_err(|error| anyhow!("{}", error))
        }
        "ssh" if tail.len() == 3 && tail[0] == "add" => {
            checked_positionals(&tail[1..2])?;
            SshRemote::parse(&tail[2]).map_err(|error| anyhow!("invalid SSH remote: {}", error))?;
            native_repository(repository)?
                .set_remote(&tail[1], &tail[2], false)
                .map_err(|error| anyhow!("{}", error))?;
            Ok(())
        }
        "ssh" if tail.len() == 3 && tail[0] == "set" => {
            checked_positionals(&tail[1..2])?;
            SshRemote::parse(&tail[2]).map_err(|error| anyhow!("invalid SSH remote: {}", error))?;
            native_repository(repository)?
                .set_remote(&tail[1], &tail[2], true)
                .map_err(|error| anyhow!("{}", error))?;
            Ok(())
        }
        "ssh" if tail.len() == 3 && tail[0] == "auth" => {
            checked_positionals(&tail[1..])?;
            let repo = native_repository(repository)?;
            let _private = load_development_rsa_key(&tail[1])?;
            let host = read_file_text_bounded(&tail[2], 64 * 1024)
                .map_err(|_| anyhow!("cannot read SSH host key"))?;
            parse_rsa_public_line(&host)
                .map_err(|error| anyhow!("invalid SSH host key: {}", error))?;
            repo.set_config_value("ssh", "credentialProvider", "development-key-file")
                .map_err(|error| anyhow!("{}", error))?;
            repo.set_config_value("ssh", "developmentPrivateKeyFile", &tail[1])
                .map_err(|error| anyhow!("{}", error))?;
            repo.set_config_value("ssh", "hostKey", &tail[2])
                .map_err(|error| anyhow!("{}", error))?;
            println!(
                "{} repository-local SSH credentials configured",
                "native".green().bold()
            );
            Ok(())
        }
        "ssh" if matches!(tail.len(), 1 | 2) && tail[0] == "info" => {
            let name = tail.get(1).map(Text::as_str).unwrap_or("origin");
            checked_positionals(&tail[1..])?;
            let (url, parsed) = ssh_remote(repository, name)?;
            print_ssh_remote(name, &url, &parsed);
            Ok(())
        }
        "ssh" if matches!(tail.len(), 1 | 2) && tail[0] == "check" => {
            let name = tail.get(1).map(Text::as_str).unwrap_or("origin");
            checked_positionals(&tail[1..])?;
            let (url, parsed) = ssh_remote(repository, name)?;
            print_ssh_remote(name, &url, &parsed);
            println!("{}", "checking read-only SSH access...".dimmed());
            let repo = native_repository(repository)?;
            let (key, host) = ssh_credentials(&repo)?;
            let refs = check_ssh(&parsed, &key, &host).map_err(|error| anyhow!("{}", error))?;
            println!(
                "{} authenticated; {} reference(s) advertised",
                "SSH access valid".green().bold(),
                refs
            );
            Ok(())
        }
        "signing" if tail.len() == 2 && tail[0] == "configure" => {
            checked_positionals(&tail[1..])?;
            let repo = native_repository(repository)?;
            let _private = load_development_rsa_key(&tail[1])?;
            repo.set_config_value("gpg", "format", "ssh")
                .map_err(|error| anyhow!("{}", error))?;
            repo.set_config_value("user", "signingkey", "development-provider")
                .map_err(|error| anyhow!("{}", error))?;
            repo.set_config_value("gpg.ssh", "signerProvider", "development-key-file")
                .map_err(|error| anyhow!("{}", error))?;
            repo.set_config_value("gpg.ssh", "developmentPrivateKeyFile", &tail[1])
                .map_err(|error| anyhow!("{}", error))?;
            print_signing_status(repository)
        }
        "signing" if tail.len() == 3 && tail[0] == "configure" => {
            checked_positionals(&tail[1..])?;
            let repo = native_repository(repository)?;
            let _private = load_development_rsa_key(&tail[1])?;
            let allowed = read_file_text_bounded(&tail[2], 64 * 1024)
                .map_err(|_| anyhow!("cannot read allowed signer"))?;
            parse_rsa_public_line(&allowed)
                .map_err(|error| anyhow!("invalid allowed signer: {}", error))?;
            repo.set_config_value("gpg", "format", "ssh")
                .map_err(|error| anyhow!("{}", error))?;
            repo.set_config_value("user", "signingkey", "development-provider")
                .map_err(|error| anyhow!("{}", error))?;
            repo.set_config_value("gpg.ssh", "signerProvider", "development-key-file")
                .map_err(|error| anyhow!("{}", error))?;
            repo.set_config_value("gpg.ssh", "developmentPrivateKeyFile", &tail[1])
                .map_err(|error| anyhow!("{}", error))?;
            repo.set_config_value("gpg.ssh", "allowedSignersFile", &tail[2])
                .map_err(|error| anyhow!("{}", error))?;
            print_signing_status(repository)
        }
        "signing" if (2..=5).contains(&tail.len()) && tail[0] == "configure-openpgp" => {
            checked_positionals(&tail[1..])?;
            let repo = native_repository(repository)?;
            let seed_path = tail[1].as_str();
            let public_key = tail
                .get(2)
                .map(Text::as_str)
                .unwrap_or(MRML_OPENPGP_PUBLIC_KEY);
            let fingerprint = tail
                .get(3)
                .map(Text::as_str)
                .unwrap_or(MRML_OPENPGP_FINGERPRINT);
            let digest = tail.get(4).map(Text::as_str).unwrap_or("sha512");
            let expected = OpenPgpFingerprint::parse_hex(fingerprint)
                .map_err(|error| anyhow!("invalid primary fingerprint: {}", error))?;
            let canonical_fingerprint = openpgp_fingerprint_text(expected);
            let digest = match digest {
                value if value.eq_ignore_ascii_case("sha256") => "sha256",
                value if value.eq_ignore_ascii_case("sha384") => "sha384",
                value if value.eq_ignore_ascii_case("sha512") => "sha512",
                value => {
                    return Err(anyhow!(
                        "unsupported OpenPGP digest '{}'; use sha256, sha384, or sha512",
                        value
                    ));
                }
            };
            let checked_public_path = if mrml_runtime::path_is_absolute(public_key) {
                public_key.into()
            } else {
                join_path(&repo.worktree, public_key)
            };
            let public = read_file_bounded(
                &checked_public_path,
                mrml_openpgp::MAX_OPENPGP_PUBLIC_KEY_BYTES,
            )
            .map_err(|_| anyhow!("cannot read OpenPGP public key"))?;
            let mut public_scratch = [0u8; mrml_openpgp::MAX_OPENPGP_PUBLIC_KEY_BYTES];
            let parsed_public = parse_public_key_ascii(&public, &mut public_scratch)
                .map_err(|error| anyhow!("invalid OpenPGP public key: {}", error))?;
            if parsed_public.fingerprint() != expected {
                return Err(anyhow!(
                    "OpenPGP public key fingerprint does not match requested fingerprint"
                ));
            }
            let checked_seed_path = if mrml_runtime::path_is_absolute(seed_path) {
                seed_path.into()
            } else {
                join_path(&repo.worktree, seed_path)
            };
            let mut seed_bytes = load_development_secret(&checked_seed_path, 32)?;
            if seed_bytes.len() != 32 {
                erase_secret(&mut seed_bytes);
                return Err(anyhow!("development OpenPGP seed must be exactly 32 bytes"));
            }
            let key =
                OpenPgpSigningKey::from_seed_bytes_and_public_key(&mut seed_bytes, parsed_public)
                    .map_err(|error| anyhow!("invalid OpenPGP private seed: {}", error));
            erase_secret(&mut seed_bytes);
            let _key = key?;
            repo.set_config_value("gpg", "format", "openpgp")
                .map_err(|error| anyhow!("{}", error))?;
            repo.set_config_value("user", "signingkey", &canonical_fingerprint)
                .map_err(|error| anyhow!("{}", error))?;
            repo.set_config_value("gpg.openpgp", "privateSeedFile", seed_path)
                .map_err(|error| anyhow!("{}", error))?;
            repo.set_config_value("gpg.openpgp", "signerProvider", "development-key-file")
                .map_err(|error| anyhow!("{}", error))?;
            repo.set_config_value("gpg.openpgp", "publicKeyFile", public_key)
                .map_err(|error| anyhow!("{}", error))?;
            repo.set_config_value("gpg.openpgp", "allowedFingerprint", &canonical_fingerprint)
                .map_err(|error| anyhow!("{}", error))?;
            repo.set_config_value("gpg.openpgp", "digestAlgorithm", digest)
                .map_err(|error| anyhow!("{}", error))?;
            repo.set_config_value(
                "gpg.openpgp",
                "keyNotAfter",
                if expected
                    == OpenPgpFingerprint::parse_hex(MRML_OPENPGP_FINGERPRINT)
                        .expect("checked MRML fingerprint")
                {
                    "1851111680"
                } else {
                    "none"
                },
            )
            .map_err(|error| anyhow!("{}", error))?;
            print_signing_status(repository)
        }
        "signing" if tail.len() == 1 && tail[0] == "auto" => {
            let repo = native_repository(repository)?;
            match repository_signature_format(&repo)? {
                GitSignatureFormat::Ssh => {
                    repository_ssh_signing_key(&repo)?;
                }
                GitSignatureFormat::OpenPgp => {
                    let _key = load_openpgp_signing_key(&repo)?;
                }
            }
            repo.set_config_value("commit", "gpgsign", "true")
                .map_err(|error| anyhow!("{}", error))?;
            repo.set_config_value("tag", "gpgsign", "true")
                .map_err(|error| anyhow!("{}", error))?;
            print_signing_status(repository)
        }
        "signing" if tail.len() == 1 && tail[0] == "status" => print_signing_status(repository),
        "signing" if tail.len() == 1 && tail[0] == "off" => {
            let repo = native_repository(repository)?;
            repo.set_config_value("commit", "gpgsign", "false")
                .map_err(|error| anyhow!("{}", error))?;
            repo.set_config_value("tag", "gpgsign", "false")
                .map_err(|error| anyhow!("{}", error))?;
            print_signing_status(repository)
        }
        "signing" if tail.len() == 2 && tail[0] == "verify" => {
            checked_positionals(&tail[1..])?;
            let repo = native_repository(repository)?;
            let id = repo
                .resolve_revision(&tail[1])
                .map_err(|error| anyhow!("{}", error))?;
            let format = repository_verify_commit(&repo, id)?;
            println!(
                "{} commit {}",
                format!("valid {} signature", format).green().bold(),
                &id.to_hex()[..12]
            );
            Ok(())
        }
        "verify-commit" if tail.len() == 1 => {
            checked_positionals(tail)?;
            let repo = native_repository(repository)?;
            let id = repo
                .resolve_revision(&tail[0])
                .map_err(|error| anyhow!("{}", error))?;
            let format = repository_verify_commit(&repo, id)?;
            println!("valid {} signature for commit {}", format, id);
            Ok(())
        }
        "signing" if tail.len() == 2 && tail[0] == "verify-tag" => {
            checked_positionals(&tail[1..])?;
            let repo = native_repository(repository)?;
            let id = repo
                .resolve_revision(&tail[1])
                .map_err(|error| anyhow!("{}", error))?;
            let format = repository_verify_tag(&repo, id)?;
            println!(
                "{} tag {}",
                format!("valid {} signature", format).green().bold(),
                tail[1]
            );
            Ok(())
        }
        "verify-tag" if tail.len() == 1 => {
            checked_positionals(tail)?;
            let repo = native_repository(repository)?;
            let id = repo
                .resolve_revision(&tail[0])
                .map_err(|error| anyhow!("{}", error))?;
            let format = repository_verify_tag(&repo, id)?;
            println!("valid {} signature for tag {}", format, tail[0]);
            Ok(())
        }
        "tag" if tail.is_empty() => {
            for (name, _) in native_repository(repository)?
                .tags()
                .map_err(|error| anyhow!("{}", error))?
            {
                println!("{}", name);
            }
            Ok(())
        }
        "tag" if tail.len() == 1 => {
            checked_positionals(tail)?;
            let repo = native_repository(repository)?;
            let auto = repo
                .config_value("tag", "gpgsign")
                .ok()
                .flatten()
                .is_some_and(|value| value.eq_ignore_ascii_case("true"));
            let id = if auto {
                let (name, email) = repository_identity(&repo)?;
                let timestamp = mrml_runtime::unix_time_seconds()
                    .ok_or_else(|| anyhow!("system time is unavailable"))?;
                repository_signed_tag(&repo, &tail[0], &tail[0], &name, &email, timestamp)?
            } else {
                repo.create_tag(&tail[0])
                    .map_err(|error| anyhow!("{}", error))?
            };
            if auto {
                println!("Signed tag {} at {}", tail[0], &id.to_hex()[..12]);
            } else {
                println!("Tagged {} at {}", tail[0], &id.to_hex()[..12]);
            }
            Ok(())
        }
        "tag" if tail.len() == 4 && tail[0] == "-s" && (tail[1] == "-m" || tail[2] == "-m") => {
            let (tag, message) = if tail[1] == "-m" {
                (&tail[3], &tail[2])
            } else {
                (&tail[1], &tail[3])
            };
            checked_positionals(core::slice::from_ref(tag))?;
            if message.is_empty() || message.starts_with('-') {
                return Err(anyhow!("tag -s requires a nonempty -m message"));
            }
            let repo = native_repository(repository)?;
            let (name, email) = repository_identity(&repo)?;
            let timestamp = mrml_runtime::unix_time_seconds()
                .ok_or_else(|| anyhow!("system time is unavailable"))?;
            let id = repository_signed_tag(&repo, tag, message, &name, &email, timestamp)?;
            println!("Signed tag {} at {}", tag, &id.to_hex()[..12]);
            Ok(())
        }
        "tag-sign" if tail.len() >= 2 => {
            checked_positionals(&tail[..1])?;
            let message = join_words(&tail[1..]);
            let repo = native_repository(repository)?;
            let (name, email) = repository_identity(&repo)?;
            let timestamp = mrml_runtime::unix_time_seconds()
                .ok_or_else(|| anyhow!("system time is unavailable"))?;
            let id = repository_signed_tag(&repo, &tail[0], &message, &name, &email, timestamp)?;
            println!("Signed tag {} at {}", tail[0], &id.to_hex()[..12]);
            Ok(())
        }
        "rev-parse" if tail.len() == 1 => {
            checked_positionals(tail)?;
            let id = native_repository(repository)?
                .resolve_revision(&tail[0])
                .map_err(|error| anyhow!("{}", error))?;
            println!("{}", id);
            Ok(())
        }
        "ls-tree" if tail.len() == 1 => {
            checked_positionals(tail)?;
            let repo = native_repository(repository)?;
            let id = repo
                .resolve_revision(&tail[0])
                .map_err(|error| anyhow!("{}", error))?;
            let object = repo.read_object(id).map_err(|error| anyhow!("{}", error))?;
            let (tree, format) = match object.kind {
                mrml_git::ObjectKind::Tree => (id, repo.object_format()),
                mrml_git::ObjectKind::Commit => (
                    repo.read_commit(id)
                        .map_err(|error| anyhow!("{}", error))?
                        .tree,
                    repo.object_format(),
                ),
                _ => return Err(anyhow!("ls-tree requires a tree or commit")),
            };
            let object = repo
                .read_object(tree)
                .map_err(|error| anyhow!("{}", error))?;
            for entry in parse_tree_with_format(&object.contents, format)
                .map_err(|error| anyhow!("{}", error))?
            {
                let kind = repo
                    .read_object(entry.id)
                    .map_err(|error| anyhow!("{}", error))?
                    .kind;
                println!(
                    "{:06o} {} {}\t{}",
                    entry.mode,
                    kind.name(),
                    entry.id,
                    entry.name
                );
            }
            Ok(())
        }
        "cat-file" if tail.len() == 2 => {
            let repo = native_repository(repository)?;
            let id = repo
                .resolve_revision(&tail[1])
                .map_err(|error| anyhow!("{}", error))?;
            let object = repo.read_object(id).map_err(|error| anyhow!("{}", error))?;
            match tail[0].as_str() {
                "-t" => println!("{}", object.kind.name()),
                "-s" => println!("{}", object.contents.len()),
                "-p" => match object.kind {
                    mrml_git::ObjectKind::Tree => {
                        for entry in parse_tree_with_format(&object.contents, repo.object_format())
                            .map_err(|error| anyhow!("{}", error))?
                        {
                            let kind = repo
                                .read_object(entry.id)
                                .map_err(|error| anyhow!("{}", error))?
                                .kind;
                            println!(
                                "{:06o} {} {}\t{}",
                                entry.mode,
                                kind.name(),
                                entry.id,
                                entry.name
                            );
                        }
                    }
                    _ => {
                        let text = core::str::from_utf8(&object.contents)
                            .map_err(|_| anyhow!("cat-file -p cannot emit a binary object"))?;
                        mrml_runtime::mrml_print!("{}", text);
                    }
                },
                option => return Err(anyhow!("unsupported cat-file option '{}'", option)),
            }
            Ok(())
        }
        "show-ref" if tail.is_empty() => {
            let repo = native_repository(repository)?;
            for (name, id) in repo.branches().map_err(|error| anyhow!("{}", error))? {
                println!("{} refs/heads/{}", id, name);
            }
            for (name, id) in repo.tags().map_err(|error| anyhow!("{}", error))? {
                println!("{} refs/tags/{}", id, name);
            }
            Ok(())
        }
        "fsck" if tail.is_empty() => {
            let count = native_repository(repository)?
                .validate_reachable_refs()
                .map_err(|error| anyhow!("{}", error))?;
            println!("validated {} reachable reference tip(s)", count);
            Ok(())
        }
        "gc" | "repack" if tail.is_empty() => {
            let result = native_repository(repository)?
                .repack_local()
                .map_err(|error| anyhow!("{}", error))?;
            println!(
                "packed {} reachable object(s) as {}",
                result.object_count, result.pack_checksum
            );
            Ok(())
        }
        "gc" | "repack" => Err(anyhow!(
            "{} accepts no options or positional arguments",
            cli.command
        )),
        "stash" if tail.is_empty() || (tail.len() == 1 && tail[0] == "list") => {
            for (index, (id, commit)) in native_repository(repository)?
                .stash_list(256)
                .map_err(|error| anyhow!("{}", error))?
                .into_iter()
                .enumerate()
            {
                println!(
                    "stash@{{{}}}: {} {}",
                    index,
                    &id.to_hex()[..12],
                    commit.message.trim()
                );
            }
            Ok(())
        }
        "stash" if tail.len() == 1 && tail[0] == "pop" => {
            let id = native_repository(repository)?
                .stash_pop()
                .map_err(|error| anyhow!("{}", error))?;
            println!("Applied stash {}", &id.to_hex()[..12]);
            Ok(())
        }
        "stash" if !tail.is_empty() && tail[0] == "push" => {
            let message = join_words(&tail[1..]);
            let name = mrml_runtime::environment_variable("MRML_GIT_AUTHOR_NAME")
                .or_else(|| mrml_runtime::environment_variable("GIT_AUTHOR_NAME"))
                .unwrap_or_else(|| "MRML User".into());
            let email = mrml_runtime::environment_variable("MRML_GIT_AUTHOR_EMAIL")
                .or_else(|| mrml_runtime::environment_variable("GIT_AUTHOR_EMAIL"))
                .unwrap_or_else(|| "mrml@localhost".into());
            let timestamp = mrml_runtime::unix_time_seconds()
                .ok_or_else(|| anyhow!("system time is unavailable"))?;
            let id = native_repository(repository)?
                .stash_push(&message, &name, &email, timestamp)
                .map_err(|error| anyhow!("{}", error))?;
            println!("Saved stash {}", &id.to_hex()[..12]);
            Ok(())
        }
        command => Err(anyhow!(
            "invalid arguments for '{}'; run mrml-git help",
            command
        )),
    }
}

fn application_main() -> Result<()> {
    let cli =
        Cli::parse(mrml_runtime::command_arguments()).map_err(|error| anyhow!("{}", error))?;
    dispatch(&cli).context("mrml-git")
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrml_runtime::{join_path, process_id, remove_dir_all, temporary_directory, write_file};

    fn invoke(repository: &str, command: &str, arguments: &[&str]) {
        dispatch(&Cli {
            repository: Some(repository.into()),
            command: command.into(),
            arguments: arguments
                .iter()
                .map(|argument| (*argument).into())
                .collect(),
        })
        .unwrap();
    }

    #[test]
    fn pull_accepts_only_the_exact_fast_forward_spelling() {
        let values = |parts: &[&str]| {
            parts
                .iter()
                .map(|part| Text::from(*part))
                .collect::<Vector<_>>()
        };
        let empty = values(&[]);
        assert_eq!(parse_pull_arguments(&empty).unwrap(), ("origin", None));
        let flag = values(&["--ff-only"]);
        assert_eq!(parse_pull_arguments(&flag).unwrap(), ("origin", None));
        let exact = values(&["--ff-only", "upstream", "main"]);
        assert_eq!(
            parse_pull_arguments(&exact).unwrap(),
            ("upstream", Some("main"))
        );
        assert!(parse_pull_arguments(&values(&["--rebase"])).is_err());
        assert!(parse_pull_arguments(&values(&["origin", "main", "extra"])).is_err());
    }

    #[test]
    fn ssh_requires_the_exact_experimental_switch() {
        assert!(!experimental_ssh_enabled(None));
        assert!(!experimental_ssh_enabled(Some("0")));
        assert!(!experimental_ssh_enabled(Some("true")));
        assert!(!experimental_ssh_enabled(Some("01")));
        assert!(experimental_ssh_enabled(Some("1")));
    }

    #[test]
    fn legacy_private_key_paths_are_not_automatic_credentials_or_signers() {
        let path = join_path(
            &temporary_directory(),
            &mrml_runtime::mrml_format!("mrml-git-private-path-{}", process_id()),
        );
        let repository = Repository::init(&path).unwrap();
        repository
            .set_config_value("ssh", "privateKey", "/secret/legacy.pem")
            .unwrap();
        repository
            .set_config_value("ssh", "hostKey", "/secret/host.pub")
            .unwrap();
        repository
            .set_config_value("user", "signingkey", "/secret/signing.pem")
            .unwrap();
        repository
            .set_config_value("gpg.openpgp", "privateSeedFile", "/secret/seed")
            .unwrap();

        for error in [
            ssh_credentials(&repository).unwrap_err(),
            repository_ssh_signing_key(&repository).unwrap_err(),
            repository_openpgp_seed(&repository).unwrap_err(),
        ] {
            let rendered = format!("{}", error);
            assert!(!rendered.contains("/secret/"));
            assert!(rendered.contains("provider"));
        }
        remove_dir_all(&path).unwrap();
    }

    #[test]
    fn https_transport_and_provider_selection_are_exact_and_tokenless() {
        assert_eq!(parse_https_transport(None).unwrap(), HttpsTransport::Http2);
        assert_eq!(
            parse_https_transport(Some("h3-v2")).unwrap(),
            HttpsTransport::Http3V2
        );
        assert!(parse_https_transport(Some("HTTP/3")).is_err());
        let path = join_path(
            &temporary_directory(),
            &mrml_runtime::mrml_format!("mrml-git-https-provider-{}", process_id()),
        );
        let repository = Repository::init_with_format(&path, ObjectFormat::Sha256).unwrap();
        repository
            .set_config_value("http", "token", &"a".repeat(64))
            .unwrap();
        assert_eq!(repository_https_provider(&repository).unwrap(), None);
        repository
            .set_config_value("http", "credentialProvider", "standard-input")
            .unwrap();
        assert_eq!(
            repository_https_provider(&repository).unwrap().as_deref(),
            Some("standard-input")
        );
        repository
            .set_config_value("http", "credentialProvider", "unix-v1")
            .unwrap();
        assert_eq!(
            repository_https_provider(&repository).unwrap().as_deref(),
            Some("unix-v1")
        );
        repository
            .set_config_value("http", "credentialProvider", "raw-token-file")
            .unwrap();
        let rendered = format!("{}", repository_https_provider(&repository).unwrap_err());
        assert!(!rendered.contains(&"a".repeat(64)));
        assert!(rendered.contains("provider"));
        remove_dir_all(&path).unwrap();
    }

    #[test]
    fn advertised_local_porcelain_dispatches_without_host_tools() {
        let path = join_path(
            &temporary_directory(),
            &mrml_runtime::mrml_format!("mrml-git-cli-{}", process_id()),
        );
        let repository = Repository::init(&path).unwrap();
        repository
            .set_config_value("commit", "gpgsign", "false")
            .unwrap();
        repository
            .set_config_value("tag", "gpgsign", "false")
            .unwrap();
        repository.set_config_value("gpg", "format", "ssh").unwrap();
        invoke(&path, "status", &[]);
        let tracked = join_path(&path, "tracked.txt");
        write_file(&tracked, b"base\n").unwrap();
        invoke(&path, "add", &["tracked.txt"]);
        invoke(&path, "commit", &["-m", "base"]);
        for (command, arguments) in [
            ("log", &["2"][..]),
            ("show", &["HEAD"][..]),
            ("history", &["tracked.txt"][..]),
            ("blame", &["tracked.txt"][..]),
            ("diff-ref", &["HEAD", "tracked.txt"][..]),
            ("conflicts", &[][..]),
            ("remote", &[][..]),
            ("signing", &["status"][..]),
            ("stash", &["list"][..]),
            ("rev-parse", &["HEAD"][..]),
            ("ls-tree", &["HEAD"][..]),
            ("cat-file", &["-t", "HEAD"][..]),
            ("cat-file", &["-s", "HEAD"][..]),
            ("cat-file", &["-p", "HEAD"][..]),
            ("show-ref", &[][..]),
            ("fsck", &[][..]),
        ] {
            invoke(&path, command, arguments);
        }
        write_file(&tracked, b"changed\n").unwrap();
        invoke(&path, "stage", &["tracked.txt"]);
        invoke(&path, "reset", &[]);
        invoke(&path, "restore", &["tracked.txt"]);
        invoke(&path, "branch", &["feature"]);
        invoke(&path, "checkout", &["main"]);
        invoke(&path, "branch", &["-d", "feature"]);
        invoke(&path, "switch", &["-c", "switch-created"]);
        invoke(&path, "switch", &["main"]);
        invoke(&path, "branch", &["-d", "switch-created"]);
        invoke(&path, "checkout", &["-b", "checkout-created"]);
        invoke(&path, "checkout", &["main"]);
        invoke(&path, "branch", &["-d", "checkout-created"]);
        invoke(&path, "remote", &["add", "backup", "host:repository.git"]);
        invoke(&path, "remote", &["set-url", "backup", "host:updated.git"]);
        invoke(&path, "tag", &["v1"]);
        invoke(&path, "tag", &[]);
        write_file(&tracked, b"stashed\n").unwrap();
        invoke(&path, "stash", &["push", "checkpoint"]);
        invoke(&path, "stash", &["pop"]);
        invoke(&path, "mv", &["tracked.txt", "renamed.txt"]);
        invoke(&path, "rm", &["renamed.txt"]);
        for command in ["gc", "repack"] {
            let result = dispatch(&Cli {
                repository: Some(path.clone()),
                command: command.into(),
                arguments: Vector::new(),
            });
            #[cfg(unix)]
            assert!(result.is_ok());
            #[cfg(windows)]
            assert!(result.is_err());
            let rejected = dispatch(&Cli {
                repository: Some(path.clone()),
                command: command.into(),
                arguments: Vector::from([Text::from("--all")]),
            })
            .unwrap_err();
            assert_eq!(
                format!("{}", rejected),
                format!("{} accepts no options or positional arguments", command)
            );
        }
        remove_dir_all(&path).unwrap();
    }
}

mrml_runtime::mrml_entrypoint!(application_main);
