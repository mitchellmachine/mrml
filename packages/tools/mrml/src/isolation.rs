use crate::manifest::Document;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum IsolationPlacement {
    InProcess,
    NativeProcess,
    NativeService,
    Microvm,
    Platform,
}

impl IsolationPlacement {
    pub const fn token(self) -> &'static str {
        match self {
            Self::InProcess => "in-process",
            Self::NativeProcess => "native-process",
            Self::NativeService => "native-service",
            Self::Microvm => "microvm",
            Self::Platform => "platform",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "in-process" => Some(Self::InProcess),
            "native-process" => Some(Self::NativeProcess),
            "native-service" => Some(Self::NativeService),
            "microvm" => Some(Self::Microvm),
            "platform" => Some(Self::Platform),
            _ => None,
        }
    }

    const fn rank(self) -> Option<u8> {
        match self {
            Self::InProcess => Some(0),
            Self::NativeProcess | Self::NativeService => Some(1),
            Self::Microvm => Some(2),
            Self::Platform => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IsolationPolicy {
    preferred: IsolationPlacement,
    minimum: IsolationPlacement,
    maximum: IsolationPlacement,
    supported: Vec<IsolationPlacement>,
    runtime: Option<RuntimeClassification>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeClass {
    MicrovmEligible,
    HostSubstrateRequired,
    BootOnly,
    RecoveryOnly,
    UnsupportedBlocker,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeClassification {
    class: RuntimeClass,
    must_run: bool,
    reason: String,
}

impl RuntimeClassification {
    pub const fn class(&self) -> RuntimeClass {
        self.class
    }

    pub const fn must_run(&self) -> bool {
        self.must_run
    }

    pub fn reason(&self) -> &str {
        &self.reason
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlacementRequest {
    PackageDefault,
    Owner(IsolationPlacement),
    TotalMicrovm,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlacementSource {
    PackageDefault,
    Owner,
    TotalMicrovm,
    TotalMicrovmException,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EffectivePlacement {
    placement: IsolationPlacement,
    source: PlacementSource,
}

impl EffectivePlacement {
    pub const fn placement(self) -> IsolationPlacement {
        self.placement
    }
    pub const fn source(self) -> PlacementSource {
        self.source
    }
}

impl IsolationPolicy {
    pub fn parse(document: &Document, kind: &str, package: &str) -> Result<Self, String> {
        let Some(section) = document
            .sections
            .iter()
            .find(|section| !section.array && section.name == "isolation")
        else {
            return Ok(Self::default_for_kind(kind));
        };
        if section.fields.keys().any(|key| {
            !matches!(
                key.as_str(),
                "default"
                    | "minimum"
                    | "maximum"
                    | "supported"
                    | "runtime_class"
                    | "must_run"
                    | "reason"
            )
        }) {
            return Err(format!("IsolationFieldInvalid {{ package: {package} }}"));
        }
        let parse_field = |field: &str| {
            section
                .string(field)
                .ok()
                .and_then(IsolationPlacement::parse)
                .ok_or_else(|| {
                    format!("IsolationPlacementInvalid {{ package: {package}, field: {field} }}")
                })
        };
        let preferred = parse_field("default")?;
        let minimum = parse_field("minimum")?;
        let mut supported = Vec::new();
        for value in section
            .strings("supported")
            .map_err(|_| format!("IsolationSupportedMissing {{ package: {package} }}"))?
        {
            let placement = IsolationPlacement::parse(value).ok_or_else(|| {
                format!("IsolationPlacementInvalid {{ package: {package}, field: supported }}")
            })?;
            if supported.contains(&placement) {
                return Err(format!(
                    "IsolationSupportedDuplicate {{ package: {package} }}"
                ));
            }
            supported.push(placement);
        }
        let maximum = match section
            .optional_string("maximum")
            .map_err(|_| format!("IsolationMaximumInvalid {{ package: {package} }}"))?
        {
            Some(value) => IsolationPlacement::parse(value)
                .ok_or_else(|| format!("IsolationMaximumInvalid {{ package: {package} }}"))?,
            None => supported
                .iter()
                .copied()
                .max_by_key(|placement| placement.rank())
                .ok_or_else(|| format!("IsolationSupportedMissing {{ package: {package} }}"))?,
        };
        if !supported.contains(&preferred)
            || !supported.contains(&minimum)
            || !supported.contains(&maximum)
            || !allowed_for_kind(kind, &supported)
        {
            return Err(format!(
                "IsolationPolicyContradiction {{ package: {package} }}"
            ));
        }
        if minimum == IsolationPlacement::Platform {
            if supported != [IsolationPlacement::Platform]
                || section
                    .optional_string("reason")
                    .ok()
                    .flatten()
                    .is_none_or(str::is_empty)
            {
                return Err(format!(
                    "IsolationPlatformReasonMissing {{ package: {package} }}"
                ));
            }
        } else if minimum.rank() > preferred.rank() || preferred.rank() > maximum.rank() {
            return Err(format!("IsolationBoundsInvalid {{ package: {package} }}"));
        }
        let runtime_class = section
            .optional_string("runtime_class")
            .map_err(|_| format!("IsolationRuntimeClassInvalid {{ package: {package} }}"))?;
        let must_run = section
            .optional_boolean("must_run")
            .map_err(|_| format!("IsolationMustRunInvalid {{ package: {package} }}"))?;
        let reason = section
            .optional_string("reason")
            .map_err(|_| format!("IsolationReasonInvalid {{ package: {package} }}"))?;
        let runtime = match (runtime_class, must_run) {
            (None, None) => None,
            (Some(class), Some(must_run)) => {
                let class = match class {
                    "microvm-eligible" => RuntimeClass::MicrovmEligible,
                    "host-substrate-required" => RuntimeClass::HostSubstrateRequired,
                    "boot-only" => RuntimeClass::BootOnly,
                    "recovery-only" => RuntimeClass::RecoveryOnly,
                    "unsupported-blocker" => RuntimeClass::UnsupportedBlocker,
                    _ => {
                        return Err(format!(
                            "IsolationRuntimeClassInvalid {{ package: {package} }}"
                        ));
                    }
                };
                let reason = reason.unwrap_or("");
                if (class == RuntimeClass::MicrovmEligible
                    && (!supported.contains(&IsolationPlacement::Microvm) || !reason.is_empty()))
                    || (class != RuntimeClass::MicrovmEligible && reason.is_empty())
                {
                    return Err(format!(
                        "IsolationRuntimeClassificationInvalid {{ package: {package} }}"
                    ));
                }
                Some(RuntimeClassification {
                    class,
                    must_run,
                    reason: reason.into(),
                })
            }
            _ => {
                return Err(format!(
                    "IsolationRuntimeClassificationIncomplete {{ package: {package} }}"
                ));
            }
        };
        Ok(Self {
            preferred,
            minimum,
            maximum,
            supported,
            runtime,
        })
    }

    pub fn default_for_kind(kind: &str) -> Self {
        let placement = match kind {
            "application" | "tool" | "compiler" | "test" | "experiment" => {
                IsolationPlacement::NativeProcess
            }
            "service" => IsolationPlacement::NativeService,
            "library" => IsolationPlacement::InProcess,
            _ => IsolationPlacement::Platform,
        };
        Self {
            preferred: placement,
            minimum: placement,
            maximum: placement,
            supported: vec![placement],
            runtime: None,
        }
    }

    pub const fn preferred(&self) -> IsolationPlacement {
        self.preferred
    }
    pub const fn minimum(&self) -> IsolationPlacement {
        self.minimum
    }
    pub const fn maximum(&self) -> IsolationPlacement {
        self.maximum
    }
    pub fn supported(&self) -> &[IsolationPlacement] {
        &self.supported
    }

    pub const fn runtime(&self) -> Option<&RuntimeClassification> {
        self.runtime.as_ref()
    }

    pub fn resolve(&self, request: PlacementRequest) -> Result<EffectivePlacement, String> {
        let (placement, source) = match request {
            PlacementRequest::PackageDefault => (self.preferred, PlacementSource::PackageDefault),
            PlacementRequest::Owner(placement) => (placement, PlacementSource::Owner),
            PlacementRequest::TotalMicrovm
                if self.supported.contains(&IsolationPlacement::Microvm) =>
            {
                (IsolationPlacement::Microvm, PlacementSource::TotalMicrovm)
            }
            PlacementRequest::TotalMicrovm => {
                (self.preferred, PlacementSource::TotalMicrovmException)
            }
        };
        if !self.supported.contains(&placement) {
            return Err("IsolationPlacementUnsupported".into());
        }
        if placement != IsolationPlacement::Platform
            && (placement.rank() < self.minimum.rank() || placement.rank() > self.maximum.rank())
        {
            return Err("IsolationPlacementOutsideBounds".into());
        }
        Ok(EffectivePlacement { placement, source })
    }
}

fn allowed_for_kind(kind: &str, values: &[IsolationPlacement]) -> bool {
    if values == [IsolationPlacement::Platform] {
        return true;
    }
    values.iter().all(|placement| match kind {
        "application" => matches!(
            placement,
            IsolationPlacement::NativeProcess | IsolationPlacement::Microvm
        ),
        "service" => matches!(
            placement,
            IsolationPlacement::NativeService | IsolationPlacement::Microvm
        ),
        "library" => matches!(
            placement,
            IsolationPlacement::InProcess
                | IsolationPlacement::NativeService
                | IsolationPlacement::Microvm
        ),
        "tool" | "compiler" | "test" | "experiment" => {
            *placement == IsolationPlacement::NativeProcess
        }
        _ => *placement == IsolationPlacement::Platform,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(isolation: &str) -> Document {
        Document::parse(
            format!(
                "[manifest]\nformat = \"mrml\"\nversion = 2\n\n[package]\nid = \"org.mrml.app.test\"\n{isolation}"
            )
            .as_bytes(),
        )
        .unwrap()
    }

    #[test]
    fn application_policy_separates_preference_floor_and_ceiling() {
        let document = manifest(
            "\n[isolation]\ndefault = \"microvm\"\nminimum = \"native-process\"\nmaximum = \"microvm\"\nsupported = [\"native-process\", \"microvm\"]\n",
        );
        let policy = IsolationPolicy::parse(&document, "application", "org.mrml.app.test").unwrap();
        assert_eq!(policy.preferred(), IsolationPlacement::Microvm);
        assert_eq!(policy.minimum(), IsolationPlacement::NativeProcess);
        assert_eq!(policy.maximum(), IsolationPlacement::Microvm);
    }

    #[test]
    fn contradictions_unknowns_and_cross_class_placements_fail_closed() {
        for isolation in [
            "\n[isolation]\ndefault = \"microvm\"\nminimum = \"microvm\"\nsupported = [\"native-process\"]\n",
            "\n[isolation]\ndefault = \"native-service\"\nminimum = \"native-service\"\nsupported = [\"native-service\"]\n",
            "\n[isolation]\ndefault = \"magic\"\nminimum = \"native-process\"\nsupported = [\"native-process\"]\n",
            "\n[isolation]\ndefault = \"native-process\"\nminimum = \"native-process\"\nsupported = [\"native-process\"]\nunknown = \"x\"\n",
        ] {
            assert!(
                IsolationPolicy::parse(&manifest(isolation), "application", "org.mrml.app.test")
                    .is_err()
            );
        }
    }

    #[test]
    fn platform_is_fixed_and_requires_a_reason() {
        let good = manifest(
            "\n[isolation]\ndefault = \"platform\"\nminimum = \"platform\"\nsupported = [\"platform\"]\nreason = \"required before VM substrate exists\"\n",
        );
        assert!(IsolationPolicy::parse(&good, "kernel", "org.mrml.system.kernel").is_ok());
        let bad = manifest(
            "\n[isolation]\ndefault = \"platform\"\nminimum = \"platform\"\nsupported = [\"platform\"]\n",
        );
        assert!(IsolationPolicy::parse(&bad, "kernel", "org.mrml.system.kernel").is_err());
    }

    #[test]
    fn owner_and_total_requests_respect_bounds_and_report_exceptions() {
        let document = manifest(
            "\n[isolation]\ndefault = \"microvm\"\nminimum = \"native-process\"\nmaximum = \"microvm\"\nsupported = [\"native-process\", \"microvm\"]\n",
        );
        let policy = IsolationPolicy::parse(&document, "application", "org.mrml.app.test").unwrap();
        assert_eq!(
            policy
                .resolve(PlacementRequest::Owner(IsolationPlacement::NativeProcess))
                .unwrap(),
            EffectivePlacement {
                placement: IsolationPlacement::NativeProcess,
                source: PlacementSource::Owner,
            }
        );
        assert_eq!(
            policy
                .resolve(PlacementRequest::TotalMicrovm)
                .unwrap()
                .placement(),
            IsolationPlacement::Microvm
        );
        let native = IsolationPolicy::default_for_kind("application");
        assert_eq!(
            native
                .resolve(PlacementRequest::TotalMicrovm)
                .unwrap()
                .source(),
            PlacementSource::TotalMicrovmException
        );
        assert!(
            native
                .resolve(PlacementRequest::Owner(IsolationPlacement::Microvm))
                .is_err()
        );
    }

    #[test]
    fn runtime_classification_is_explicit_complete_and_reasoned() {
        let eligible = manifest(
            "\n[isolation]\ndefault = \"native-process\"\nminimum = \"native-process\"\nmaximum = \"microvm\"\nsupported = [\"native-process\", \"microvm\"]\nruntime_class = \"microvm-eligible\"\nmust_run = true\n",
        );
        let policy = IsolationPolicy::parse(&eligible, "application", "org.mrml.app.test").unwrap();
        let runtime = policy.runtime().unwrap();
        assert_eq!(runtime.class(), RuntimeClass::MicrovmEligible);
        assert!(runtime.must_run());
        assert_eq!(runtime.reason(), "");

        let boot = manifest(
            "\n[isolation]\ndefault = \"platform\"\nminimum = \"platform\"\nsupported = [\"platform\"]\nruntime_class = \"boot-only\"\nmust_run = true\nreason = \"required before VM substrate exists\"\n",
        );
        let policy = IsolationPolicy::parse(&boot, "kernel", "org.mrml.system.kernel").unwrap();
        assert_eq!(policy.runtime().unwrap().class(), RuntimeClass::BootOnly);

        for invalid in [
            "\n[isolation]\ndefault = \"native-process\"\nminimum = \"native-process\"\nsupported = [\"native-process\", \"microvm\"]\nruntime_class = \"microvm-eligible\"\n",
            "\n[isolation]\ndefault = \"native-process\"\nminimum = \"native-process\"\nsupported = [\"native-process\"]\nruntime_class = \"microvm-eligible\"\nmust_run = true\n",
            "\n[isolation]\ndefault = \"native-process\"\nminimum = \"native-process\"\nsupported = [\"native-process\"]\nruntime_class = \"unsupported-blocker\"\nmust_run = false\n",
        ] {
            assert!(
                IsolationPolicy::parse(&manifest(invalid), "application", "org.mrml.app.test")
                    .is_err()
            );
        }
    }
}
