/// A trusted ambient path and a retained Linux directory are distinct
/// storage authorities. Windows never interprets a path as the latter.
pub(crate) enum GitFileRoot {
    Ambient,
    #[cfg(target_os = "linux")]
    Retained(mrml_runtime::DirectoryCapability),
}

impl GitFileRoot {
    #[cfg(target_os = "linux")]
    pub(crate) fn as_ref(&self) -> Option<&mrml_runtime::DirectoryCapability> {
        match self {
            Self::Ambient => None,
            Self::Retained(root) => Some(root),
        }
    }
}
