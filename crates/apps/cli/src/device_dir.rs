//! A device directory: the software keys of a device that registers with a factory, and what
//! the factory gave it. Development only: the keys are files readable by their owner and the
//! device is unattested (CLI-007).
//!
//! Layout: `sign.key` and `agree.key` (the key-file format of `keys generate --purpose
//! sign|agree`), `tenancy` (64 hex digits, written when the request is built) and
//! `tenancy.certificate` (the factory's certificate, written by `registration wait`).

use std::path::{Path, PathBuf};

use fieldseal_adapters_memory::registration::SoftwareDevice;
use fieldseal_trust::ports::RandomSource;

use crate::device_keys::{DeviceKey, DevicePurpose};

/// A device directory.
pub struct DeviceDir {
    dir: PathBuf,
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    std::fs::write(path, bytes).map_err(|e| format!("{}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|e| format!("{}: {e}", path.display()))?;
    }
    Ok(())
}

impl DeviceDir {
    /// The device directory at `dir` (created when keys are first generated).
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// The directory.
    pub fn path(&self) -> &Path {
        &self.dir
    }

    fn read_key(&self, name: &str) -> Option<DeviceKey> {
        std::fs::read_to_string(self.dir.join(name)).ok().and_then(|t| DeviceKey::from_file(&t).ok())
    }

    /// The signing and agreement keys, if the directory holds both.
    pub fn keys(&self) -> Option<(DeviceKey, DeviceKey)> {
        Some((self.read_key("sign.key")?, self.read_key("agree.key")?))
    }

    /// The keys, generating them (from `random`) if the directory has none. The flag says
    /// whether they were created now.
    pub fn keys_or_create(&self, random: &dyn RandomSource) -> Result<((DeviceKey, DeviceKey), bool), String> {
        if let Some(k) = self.keys() {
            return Ok((k, false));
        }
        std::fs::create_dir_all(&self.dir).map_err(|e| format!("{}: {e}", self.dir.display()))?;
        let (sign, agree) = (DeviceKey::generate(DevicePurpose::Sign, random), DeviceKey::generate(DevicePurpose::Agree, random));
        write_private(&self.dir.join("sign.key"), sign.to_file().as_bytes())?;
        write_private(&self.dir.join("agree.key"), agree.to_file().as_bytes())?;
        Ok(((sign, agree), true))
    }

    /// The registration-side device built from the stored keys.
    pub fn software_device(&self) -> Option<SoftwareDevice> {
        let (sign, agree) = self.keys()?;
        Some(SoftwareDevice::from_keys(sign.signing()?, agree.agreement()?))
    }

    /// The tenancy (64 hex digits) the keys registered, if known.
    pub fn tenancy(&self) -> Option<String> {
        std::fs::read_to_string(self.dir.join("tenancy")).ok().map(|t| t.trim().to_owned()).filter(|t| t.len() == 64)
    }

    /// Records the tenancy.
    pub fn save_tenancy(&self, hex: &str) -> Result<(), String> {
        std::fs::create_dir_all(&self.dir).map_err(|e| format!("{}: {e}", self.dir.display()))?;
        write_private(&self.dir.join("tenancy"), format!("{hex}\n").as_bytes())
    }

    /// The factory's certificate (CBOR), if it was fetched.
    pub fn certificate(&self) -> Option<Vec<u8>> {
        std::fs::read(self.dir.join("tenancy.certificate")).ok()
    }

    /// Stores the factory's certificate.
    pub fn save_certificate(&self, bytes: &[u8]) -> Result<(), String> {
        write_private(&self.dir.join("tenancy.certificate"), bytes)
    }
}
