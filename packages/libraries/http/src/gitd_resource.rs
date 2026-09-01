use mrml_runtime::Vector;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitdPressureMode {
    Normal,
    Pressure,
    Siege,
    Recovery,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitdWorkClass {
    CachedPage,
    OpenConnection,
    Handshake,
    LightweightRequest,
    Render,
    Zstd,
    GitRead,
    GitPush,
    LargeDiff,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GitdResourceSnapshot {
    pub free_disk_bytes: u64,
    pub memory_used_bytes: u64,
    pub memory_limit_bytes: u64,
    pub queued_work: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceIdentity {
    address: [u8; 16],
    prefix_bits: u8,
}

impl SourceIdentity {
    pub const fn ipv4(address: [u8; 4]) -> Self {
        let mut mapped = [0; 16];
        mapped[10] = 0xff;
        mapped[11] = 0xff;
        mapped[12] = address[0];
        mapped[13] = address[1];
        mapped[14] = address[2];
        mapped[15] = address[3];
        Self {
            address: mapped,
            prefix_bits: 128,
        }
    }

    pub const fn ipv6_64(mut address: [u8; 16]) -> Self {
        address[8] = 0;
        address[9] = 0;
        address[10] = 0;
        address[11] = 0;
        address[12] = 0;
        address[13] = 0;
        address[14] = 0;
        address[15] = 0;
        Self {
            address,
            prefix_bits: 64,
        }
    }
}

struct SourceBucket {
    source: SourceIdentity,
    tokens: u32,
    last_tick: u64,
}

pub struct GitdResourceController {
    mode: GitdPressureMode,
    sources: Vector<SourceBucket>,
    maximum_sources: usize,
    bucket_capacity: u32,
    refill_per_tick: u32,
    active: [u32; 9],
    limits: [u32; 9],
    recovery_observations: u8,
}

impl GitdResourceController {
    pub fn new(maximum_sources: usize) -> Option<Self> {
        if maximum_sources == 0 || maximum_sources > 65_536 {
            return None;
        }
        Some(Self {
            mode: GitdPressureMode::Normal,
            sources: Vector::new(),
            maximum_sources,
            bucket_capacity: 64,
            refill_per_tick: 8,
            active: [0; 9],
            limits: [64, 8_000, 128, 1_000, 8, 4, 64, 16, 4],
            recovery_observations: 0,
        })
    }

    pub fn mode(&self) -> GitdPressureMode {
        self.mode
    }

    pub fn active_count(&self, class: GitdWorkClass) -> u32 {
        self.active[class as usize]
    }

    pub fn observe(&mut self, snapshot: GitdResourceSnapshot) {
        const DISK_RESERVE: u64 = 40 * 1024 * 1024 * 1024;
        let siege = snapshot.free_disk_bytes < DISK_RESERVE
            || snapshot.memory_used_bytes.saturating_mul(100)
                >= snapshot.memory_limit_bytes.saturating_mul(95)
            || snapshot.queued_work >= 900;
        let pressure = snapshot.free_disk_bytes < DISK_RESERVE + 10 * 1024 * 1024 * 1024
            || snapshot.memory_used_bytes.saturating_mul(100)
                >= snapshot.memory_limit_bytes.saturating_mul(80)
            || snapshot.queued_work >= 700;
        if siege {
            self.mode = GitdPressureMode::Siege;
            self.recovery_observations = 0;
        } else if pressure {
            self.mode = GitdPressureMode::Pressure;
            self.recovery_observations = 0;
        } else if self.mode != GitdPressureMode::Normal {
            self.mode = GitdPressureMode::Recovery;
            self.recovery_observations = self.recovery_observations.saturating_add(1);
            if self.recovery_observations >= 3 {
                self.mode = GitdPressureMode::Normal;
                self.recovery_observations = 0;
            }
        }
    }

    pub fn admit(&mut self, source: SourceIdentity, class: GitdWorkClass, tick: u64) -> bool {
        let index = class as usize;
        if self.active[index] >= self.limits[index] || !self.mode_allows(class) {
            return false;
        }
        let bucket =
            if let Some(index) = self.sources.iter().position(|entry| entry.source == source) {
                &mut self.sources[index]
            } else {
                if self.sources.len() >= self.maximum_sources {
                    return false;
                }
                if self
                    .sources
                    .try_push(SourceBucket {
                        source,
                        tokens: self.bucket_capacity,
                        last_tick: tick,
                    })
                    .is_err()
                {
                    return false;
                }
                let index = self.sources.len() - 1;
                &mut self.sources[index]
            };
        let elapsed = tick.saturating_sub(bucket.last_tick);
        let refill = elapsed
            .saturating_mul(self.refill_per_tick as u64)
            .min(u32::MAX as u64) as u32;
        bucket.tokens = bucket
            .tokens
            .saturating_add(refill)
            .min(self.bucket_capacity);
        bucket.last_tick = tick;
        if bucket.tokens == 0 {
            return false;
        }
        bucket.tokens -= 1;
        self.active[index] += 1;
        true
    }

    pub fn complete(&mut self, class: GitdWorkClass) {
        let active = &mut self.active[class as usize];
        *active = active.saturating_sub(1);
    }

    fn mode_allows(&self, class: GitdWorkClass) -> bool {
        match self.mode {
            GitdPressureMode::Normal => true,
            GitdPressureMode::Pressure | GitdPressureMode::Recovery => {
                !matches!(class, GitdWorkClass::LargeDiff)
            }
            GitdPressureMode::Siege => {
                matches!(class, GitdWorkClass::CachedPage | GitdWorkClass::GitRead)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_source_table_ipv6_prefix_and_work_limits_fail_closed() {
        let mut controller = GitdResourceController::new(2).unwrap();
        assert!(controller.admit(
            SourceIdentity::ipv4([192, 0, 2, 1]),
            GitdWorkClass::Render,
            0
        ));
        for _ in 1..8 {
            assert!(controller.admit(
                SourceIdentity::ipv4([192, 0, 2, 1]),
                GitdWorkClass::Render,
                0
            ));
        }
        assert!(!controller.admit(
            SourceIdentity::ipv4([192, 0, 2, 1]),
            GitdWorkClass::Render,
            0
        ));
        let a = SourceIdentity::ipv6_64([0x20, 1, 0x0d, 0xb8, 0, 0, 0, 1, 1, 2, 3, 4, 5, 6, 7, 8]);
        let b = SourceIdentity::ipv6_64([0x20, 1, 0x0d, 0xb8, 0, 0, 0, 1, 9, 9, 9, 9, 9, 9, 9, 9]);
        assert_eq!(a, b);
        assert!(controller.admit(a, GitdWorkClass::CachedPage, 0));
        assert!(!controller.admit(
            SourceIdentity::ipv4([198, 51, 100, 1]),
            GitdWorkClass::CachedPage,
            0
        ));
    }

    #[test]
    fn pressure_siege_and_recovery_are_hysteretic() {
        let mut controller = GitdResourceController::new(8).unwrap();
        let source = SourceIdentity::ipv4([203, 0, 113, 9]);
        controller.observe(GitdResourceSnapshot {
            free_disk_bytes: 39 << 30,
            memory_used_bytes: 1,
            memory_limit_bytes: 10,
            queued_work: 0,
        });
        assert_eq!(controller.mode(), GitdPressureMode::Siege);
        assert!(!controller.admit(source, GitdWorkClass::GitPush, 0));
        assert!(controller.admit(source, GitdWorkClass::CachedPage, 0));
        let healthy = GitdResourceSnapshot {
            free_disk_bytes: 60 << 30,
            memory_used_bytes: 5,
            memory_limit_bytes: 10,
            queued_work: 0,
        };
        controller.observe(healthy);
        controller.observe(healthy);
        assert_eq!(controller.mode(), GitdPressureMode::Recovery);
        controller.observe(healthy);
        assert_eq!(controller.mode(), GitdPressureMode::Normal);
    }

    #[test]
    fn configured_concurrency_envelope_is_exact_and_fail_closed() {
        fn fill(class: GitdWorkClass, expected: usize) {
            let mut controller = GitdResourceController::new(expected + 1).unwrap();
            for index in 0..expected {
                let source = SourceIdentity::ipv4([
                    10,
                    ((index >> 8) & 0xff) as u8,
                    (index & 0xff) as u8,
                    1,
                ]);
                assert!(controller.admit(source, class, 0), "rejected slot {index}");
            }
            assert!(!controller.admit(SourceIdentity::ipv4([198, 51, 100, 254]), class, 0));
            for _ in 0..expected {
                controller.complete(class);
            }
            assert!(controller.admit(SourceIdentity::ipv4([198, 51, 100, 254]), class, 1));
        }

        fill(GitdWorkClass::OpenConnection, 8_000);
        fill(GitdWorkClass::Handshake, 128);
        fill(GitdWorkClass::LightweightRequest, 1_000);
        fill(GitdWorkClass::CachedPage, 64);
        fill(GitdWorkClass::Render, 8);
        fill(GitdWorkClass::Zstd, 4);
        fill(GitdWorkClass::GitRead, 64);
        fill(GitdWorkClass::GitPush, 16);
    }
}
