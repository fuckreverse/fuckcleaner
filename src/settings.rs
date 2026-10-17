use std::collections::HashSet;
#[cfg(test)]
use std::fs;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::rules::{CleanupAction, Rule, SafetyContext};
use serde::{Deserialize, Serialize};

pub const SETTINGS_VERSION: u32 = 1;
fn interval_default() -> u64 {
    60
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub version: u32,
    pub rules: Vec<Rule>,
    #[serde(default)]
    pub whitelist: Vec<PathBuf>,
    #[serde(default)]
    pub default_action: CleanupAction,
    #[serde(default)]
    pub automation_enabled: bool,
    #[serde(default = "interval_default")]
    pub automation_interval_minutes: u64,
    #[serde(default)]
    pub agent: crate::agent::AgentConfig,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            version: SETTINGS_VERSION,
            rules: crate::rules::built_in_rules(),
            whitelist: vec![],
            default_action: CleanupAction::Trash,
            automation_enabled: false,
            automation_interval_minutes: interval_default(),
            agent: crate::agent::AgentConfig::default(),
        }
    }
}
impl Settings {
    pub fn load() -> Result<Self, String> {
        Self::load_from(&state_path("settings.json")?)
    }
    pub fn save(&self) -> Result<(), String> {
        self.save_to(&state_path("settings.json")?)
    }
    pub fn validate(&self) -> Result<(), String> {
        self.validate_in(&SafetyContext::current()?)
    }

    pub(crate) fn validate_in(&self, ctx: &SafetyContext) -> Result<(), String> {
        if self.version != SETTINGS_VERSION {
            return Err(format!(
                "Unsupported settings version {}; expected {SETTINGS_VERSION}",
                self.version
            ));
        }
        if self.automation_interval_minutes < 1 || self.automation_interval_minutes > 10080 {
            return Err("Automation interval must be between 1 minute and 7 days".into());
        }
        let mut ids = HashSet::new();
        for rule in &self.rules {
            if !ids.insert(&rule.id) {
                return Err(format!("Duplicate rule id: {}", rule.id));
            }
            rule.validate_in(ctx)
                .map_err(|e| format!("Rule {}: {e}", rule.id))?;
        }
        for entry in &self.whitelist {
            ctx.expand(entry)
                .map_err(|e| format!("Invalid whitelist path: {e}"))?;
        }
        self.agent.validate()?;
        // Credentials belong in the agent's Keychain integration, never this JSON file.
        reject_secrets(&serde_json::to_value(&self.agent).map_err(|e| e.to_string())?)?;
        Ok(())
    }

    pub fn load_from(path: &Path) -> Result<Self, String> {
        let ctx = SafetyContext::current()?;
        Self::load_in(path, &ctx)
    }
    pub fn save_to(&self, path: &Path) -> Result<(), String> {
        self.save_in(path, &SafetyContext::current()?)
    }
    fn load_in(path: &Path, ctx: &SafetyContext) -> Result<Self, String> {
        let parent = path.parent().ok_or("Settings path has no parent")?;
        let dir = match private_dir(parent, false) {
            Ok(dir) => dir,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let settings = Self {
                    rules: crate::rules::built_in_rules(),
                    ..Self::default()
                };
                settings.validate_in(ctx)?;
                return Ok(settings);
            }
            Err(e) => return Err(e.to_string()),
        };
        let name = path.file_name().ok_or("Settings path has no filename")?;
        let mut file = match open_private_at(&dir, name, false, false) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let settings = Self::default();
                settings.validate_in(ctx)?;
                return Ok(settings);
            }
            Err(e) => return Err(e.to_string()),
        };
        let mut bytes = Vec::new();
        (&mut file)
            .take(4 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        if bytes.len() > 4 * 1024 * 1024 {
            return Err("Settings exceed the size limit".into());
        }
        let settings: Self = serde_json::from_slice(&bytes)
            .map_err(|e| format!("Invalid settings; original file left intact: {e}"))?;
        settings.validate_in(ctx)?;
        Ok(settings)
    }
    fn save_in(&self, path: &Path, ctx: &SafetyContext) -> Result<(), String> {
        self.validate_in(ctx)?;
        let parent = path.parent().ok_or("Settings path has no parent")?;
        let name = path.file_name().ok_or("Settings path has no filename")?;
        let dir = private_dir(parent, true).map_err(|e| e.to_string())?;
        // Refuse to overwrite a symlink, shared file, or another user's configuration.
        match open_private_at(&dir, name, false, false) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.to_string()),
        }
        let temporary = unique_name(".settings-");
        let mut file =
            open_private_at(&dir, temporary.as_ref(), true, true).map_err(|e| e.to_string())?;
        let result = (|| {
            let bytes = serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?;
            file.write_all(&bytes)
                .and_then(|_| file.sync_all())
                .map_err(|e| e.to_string())?;
            rename_at(&dir, temporary.as_ref(), &dir, name, false).map_err(|e| e.to_string())?;
            dir.sync_all().map_err(|e| e.to_string())
        })();
        if result.is_err() {
            let _ = unlink_at(&dir, temporary.as_ref(), false);
        }
        result
    }
}

fn reject_secrets(value: &serde_json::Value) -> Result<(), String> {
    match value {
        serde_json::Value::Object(fields) => {
            for (key, value) in fields {
                let normalized = key.to_ascii_lowercase().replace(['_', '-'], "");
                if [
                    "apikey",
                    "password",
                    "secret",
                    "clientsecret",
                    "accesstoken",
                    "authorization",
                    "bearertoken",
                ]
                .contains(&normalized.as_str())
                    && !value.is_null()
                    && value.as_str() != Some("")
                {
                    return Err("Agent credentials must be stored in Keychain, not settings".into());
                }
                reject_secrets(value)?;
            }
        }
        serde_json::Value::Array(values) => {
            for v in values {
                reject_secrets(v)?;
            }
        }
        serde_json::Value::String(s) => {
            // A URL with userinfo or an embedded credential is also a secret.
            let lower = s.to_ascii_lowercase();
            if (s.contains("://")
                && s.split("://")
                    .nth(1)
                    .unwrap_or("")
                    .split('/')
                    .next()
                    .unwrap_or("")
                    .contains('@'))
                || ["api_key=", "apikey=", "access_token=", "token=", "key="]
                    .iter()
                    .any(|needle| lower.contains(needle))
            {
                return Err("Agent URLs must not embed credentials".into());
            }
        }
        _ => {}
    }
    Ok(())
}

pub(crate) fn state_path(name: &str) -> Result<PathBuf, String> {
    crate::onboarding::state_dir()
        .map(|dir| dir.join(name))
        .ok_or_else(|| "Cannot determine Petal state directory".into())
}

pub(crate) fn c_name(name: &std::ffi::OsStr) -> std::io::Result<std::ffi::CString> {
    if name.is_empty() || name.as_bytes().contains(&b'/') || name == "." || name == ".." {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Expected a single filename",
        ));
    }
    std::ffi::CString::new(name.as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in filename"))
}

// Descriptor-based traversal: no symlink may redirect private state reads or writes.
pub(crate) fn private_dir(path: &Path, create: bool) -> std::io::Result<File> {
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "State directory must be absolute without traversal",
        ));
    }
    let mut dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")?;
    let mut current_path = PathBuf::from("/");
    for component in path.components() {
        let Component::Normal(part) = component else {
            continue;
        };
        current_path.push(part);
        let name = c_name(part)?;
        let mut fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0
            && create
            && std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound
        {
            if unsafe { libc::mkdirat(dir.as_raw_fd(), name.as_ptr(), 0o700) } < 0
                && std::io::Error::last_os_error().kind() != std::io::ErrorKind::AlreadyExists
            {
                return Err(std::io::Error::last_os_error());
            }
            fd = unsafe {
                libc::openat(
                    dir.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
        }
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        dir = unsafe { File::from_raw_fd(fd) };
        let meta = dir.metadata()?;
        if !crate::rules::trusted_ancestor(
            &current_path,
            &meta,
            unsafe { libc::geteuid() },
            Some(&dir),
        ) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "Untrusted state directory ancestor",
            ));
        }
    }
    let meta = dir.metadata()?;
    if meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
        // Tighten our own existing state directory through its pinned descriptor.
        if meta.uid() != unsafe { libc::geteuid() }
            || unsafe { libc::fchmod(dir.as_raw_fd(), 0o700) } < 0
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "State directory is not private and owned by the current user",
            ));
        }
    }
    Ok(dir)
}

pub(crate) fn open_private_at(
    dir: &File,
    name: &std::ffi::OsStr,
    write: bool,
    exclusive: bool,
) -> std::io::Result<File> {
    let name = c_name(name)?;
    let mut flags = libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;
    flags |= if write {
        libc::O_WRONLY | libc::O_CREAT | libc::O_APPEND
    } else {
        libc::O_RDONLY
    };
    if exclusive {
        flags |= libc::O_EXCL;
    }
    let fd = unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), flags, 0o600) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let meta = file.metadata()?;
    if !meta.is_file()
        || meta.nlink() != 1
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.mode() & 0o077 != 0
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "State file must be a private 0600 ordinary single-link file",
        ));
    }
    Ok(file)
}

pub(crate) fn unique_name(prefix: &str) -> std::ffi::OsString {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!(
        "{prefix}{}-{time}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )
    .into()
}

pub(crate) fn rename_at(
    from: &File,
    source: &std::ffi::OsStr,
    to: &File,
    target: &std::ffi::OsStr,
    exclusive: bool,
) -> std::io::Result<()> {
    let source = c_name(source)?;
    let target = c_name(target)?;
    #[cfg(target_os = "macos")]
    let status = unsafe {
        libc::renameatx_np(
            from.as_raw_fd(),
            source.as_ptr(),
            to.as_raw_fd(),
            target.as_ptr(),
            if exclusive { libc::RENAME_EXCL } else { 0 },
        )
    };
    #[cfg(not(target_os = "macos"))]
    let status = if exclusive {
        // No portable no-replace rename; fail closed rather than emulate it unsafely.
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "Exclusive rename requires macOS",
        ));
    } else {
        unsafe {
            libc::renameat(
                from.as_raw_fd(),
                source.as_ptr(),
                to.as_raw_fd(),
                target.as_ptr(),
            )
        }
    };
    if status < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}
pub(crate) fn unlink_at(
    dir: &File,
    name: &std::ffi::OsStr,
    directory: bool,
) -> std::io::Result<()> {
    let name = c_name(name)?;
    if unsafe {
        libc::unlinkat(
            dir.as_raw_fd(),
            name.as_ptr(),
            if directory { libc::AT_REMOVEDIR } else { 0 },
        )
    } < 0
    {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::fixtures::Fixture;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn private_atomic_round_trip_and_corruption_is_not_reset() {
        let f = Fixture::new();
        let path = f.dir.join("state/settings.json");
        let s = f.settings();
        s.save_in(&path, &f.ctx).unwrap();
        let loaded = Settings::load_in(&path, &f.ctx).unwrap();
        assert_eq!(loaded.version, SETTINGS_VERSION);
        assert_eq!(loaded.rules.len(), s.rules.len());
        assert_eq!(
            fs::metadata(path.parent().unwrap()).unwrap().mode() & 0o777,
            0o700
        );
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        fs::write(&path, b"broken").unwrap();
        assert!(Settings::load_in(&path, &f.ctx).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"broken");
    }
    #[test]
    fn rejects_unknown_version_duplicates_empty_whitelist_and_secrets() {
        let f = Fixture::new();
        let mut s = f.settings();
        s.version = 99;
        assert!(s.validate_in(&f.ctx).is_err());
        s.version = SETTINGS_VERSION;
        s.rules.push(s.rules[0].clone());
        assert!(s.validate_in(&f.ctx).is_err());
        s.rules.pop();
        s.whitelist.push(PathBuf::new());
        assert!(s.validate_in(&f.ctx).is_err());
        assert!(reject_secrets(&serde_json::json!({"api_key":"not-a-key"})).is_err());
        assert!(
            reject_secrets(&serde_json::json!({"endpoint":"https://user:pass@example.com/v1"}))
                .is_err()
        );
        assert!(reject_secrets(&serde_json::json!({"endpoint":"https://example.com/v1", "keychain_service":"petal"})).is_ok());
    }
    #[test]
    fn config_round_trip_allows_symlinked_and_offline_scopes_but_not_static_escape() {
        let f = Fixture::new();
        let mut config = f.settings();
        std::os::unix::fs::symlink(f.dir.join("outside-home"), f.ctx.home.join("Downloads"))
            .unwrap();
        let path = f.dir.join("state/settings.json");
        config.save_in(&path, &f.ctx).unwrap();
        let loaded = Settings::load_in(&path, &f.ctx).unwrap();
        assert!(
            loaded
                .rules
                .iter()
                .find(|r| r.id == "download-installers")
                .unwrap()
                .validate_active_in(&f.ctx)
                .is_err()
        );
        config.rules[0].enabled = false;
        config.rules[0].roots = vec![f.ctx.home.join("offline")];
        config.save_in(&path, &f.ctx).unwrap();
        config.rules[0].roots = vec![PathBuf::from("/")];
        assert!(config.save_in(&path, &f.ctx).is_err());
        config.rules[0].roots = vec![f.ctx.home.clone()];
        assert!(config.save_in(&path, &f.ctx).is_err());
        config.rules[0].roots = vec![f.dir.join("outside-home")];
        assert!(config.save_in(&path, &f.ctx).is_err());
    }

    #[test]
    fn state_symlinks_hardlinks_and_shared_files_are_rejected() {
        let f = Fixture::new();
        let s = f.settings();
        let path = f.dir.join("state/settings.json");
        s.save_in(&path, &f.ctx).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Settings::load_in(&path, &f.ctx).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::hard_link(&path, f.dir.join("alias")).unwrap();
        assert!(s.save_in(&path, &f.ctx).is_err());
        fs::remove_file(f.dir.join("alias")).unwrap();
        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(f.dir.join("elsewhere"), &path).unwrap();
        assert!(s.save_in(&path, &f.ctx).is_err());
        let alias = f.dir.join("state-alias");
        std::os::unix::fs::symlink(path.parent().unwrap(), &alias).unwrap();
        assert!(private_dir(&alias, true).is_err());
    }
}
