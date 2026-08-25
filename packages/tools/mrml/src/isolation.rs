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
                "default" | "minimum" | "maximum" | "supported" | "reason"
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
        Ok(Self {
            preferred,
            minimum,
            maximum,
            supported,
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
}

fn allowed_for_kind(kind: &str, values: &[IsolationPlacement]) -> bool {
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
}
