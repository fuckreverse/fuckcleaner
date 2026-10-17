use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::rules::{self, CleanupAction, RuleMatch, SafetyContext};
use crate::settings::{self, Settings};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default)]
pub struct ExecutionReport {
    pub completed: Vec<PathBuf>,
    pub failed: Vec<(PathBuf, String)>,
    pub log_error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub path: PathBuf,
    pub action: CleanupAction,
    pub status: String,
    pub time: u64,
    pub rule_id: String,
    pub automatic: bool,
    pub operation_id: String,
    pub detail: Option<String>,
    /// Original location is `path`. On Trash success this is the preserved staging
    /// location for Finder Put Back, NOT the final Trash destination. Manually move
    /// from recovery_path to path afterward; the fallback may not support Put Back.
    pub recovery_path: Option<PathBuf>,
}

static EXECUTION_LOCK: Mutex<()> = Mutex::new(());
const HISTORY_LIMIT: u64 = 32 * 1024 * 1024;

/// Calling with automatic=false is the caller's explicit confirmation boundary.
/// The UI must confirm the selected paths AND each Permanent action before calling.
/// No timer or AI callback may use that boundary as implicit authorization.
/// Cooperative cancellation: completed backend calls cannot be undone. Cancellation
/// before removal restores an isolated file and refuses all subsequent files.
pub fn execute_cancellable(
    items: &[RuleMatch],
    settings: &Settings,
    automatic: bool,
    cancel: &AtomicBool,
) -> ExecutionReport {
    if cancel.load(Ordering::Acquire) {
        return fail_all(items, "cancelled".into(), None);
    }
    let ctx = match SafetyContext::current() {
        Ok(ctx) => ctx,
        Err(e) => return fail_all(items, e, None),
    };
    let path = match settings::state_path("cleanup-history.jsonl") {
        Ok(path) => path,
        Err(e) => return fail_all(items, "Audit history is unavailable".into(), Some(e)),
    };
    execute_controlled(
        items,
        settings,
        automatic,
        &ctx,
        &path,
        &|path| crate::trashing::move_to_trash(&[path.to_path_buf()]),
        cancel,
        &Settings::load,
    )
}

fn fail_all(items: &[RuleMatch], error: String, log_error: Option<String>) -> ExecutionReport {
    ExecutionReport {
        completed: vec![],
        failed: items
            .iter()
            .map(|i| (i.path.clone(), error.clone()))
            .collect(),
        log_error,
    }
}

#[cfg(test)]
fn execute_in(
    items: &[RuleMatch],
    config: &Settings,
    automatic: bool,
    ctx: &SafetyContext,
    history_path: &Path,
    trash: &dyn Fn(&Path) -> Result<(), String>,
) -> ExecutionReport {
    execute_controlled(
        items,
        config,
        automatic,
        ctx,
        history_path,
        trash,
        &AtomicBool::new(false),
        &|| Ok(config.clone()),
    )
}

#[allow(clippy::too_many_arguments)]
fn execute_controlled(
    items: &[RuleMatch],
    config: &Settings,
    automatic: bool,
    ctx: &SafetyContext,
    history_path: &Path,
    trash: &dyn Fn(&Path) -> Result<(), String>,
    cancel: &AtomicBool,
    load_config: &dyn Fn() -> Result<Settings, String>,
) -> ExecutionReport {
    if cancel.load(Ordering::Acquire) {
        return fail_all(items, "cancelled".into(), None);
    }
    let _guard = match EXECUTION_LOCK.lock() {
        Ok(g) => g,
        Err(_) => return fail_all(items, "Execution lock is poisoned".into(), None),
    };
    if let Err(e) = config.validate_in(ctx) {
        return fail_all(items, e, None);
    }
    if automatic && !config.automation_enabled {
        return fail_all(
            items,
            "Global automation authorization is disabled".into(),
            None,
        );
    }
    if items.is_empty() {
        return ExecutionReport::default();
    }
    let mut log = match AuditLog::open(history_path) {
        Ok(log) => log,
        Err(e) => {
            return fail_all(
                items,
                "Cleanup refused: cannot establish a durable private audit log".into(),
                Some(e),
            );
        }
    };
    if automatic
        && log.last_automatic.is_some_and(|t| {
            timestamp().saturating_sub(t) < config.automation_interval_minutes.saturating_mul(60)
        })
    {
        return fail_all(
            items,
            "Automatic cleanup interval has not elapsed".into(),
            None,
        );
    }
    let mut report = ExecutionReport::default();
    let mut seen = HashSet::new();
    let mut audit_failed = false;
    let mut stopped: Option<String> = None;
    for item in items {
        if cancel.load(Ordering::Acquire) {
            stopped = Some("cancelled".into());
        }
        if let Some(reason) = &stopped {
            report.failed.push((item.path.clone(), reason.clone()));
            continue;
        }
        let current = match current_authorization(config, automatic, ctx, cancel, load_config) {
            Ok(current) => current,
            Err(e) => {
                report.failed.push((item.path.clone(), e.clone()));
                stopped = Some(e);
                continue;
            }
        };
        if audit_failed {
            report.failed.push((
                item.path.clone(),
                "Cleanup stopped after audit failure".into(),
            ));
            continue;
        }
        let operation_id = settings::unique_name("operation-")
            .to_string_lossy()
            .into_owned();
        let stage_name = settings::unique_name(".petal-cleanup-");
        let recovery_path = item
            .path
            .parent()
            .zip(item.path.file_name())
            .map(|(p, name)| p.join(&stage_name).join(name));
        let mut entry = HistoryEntry {
            path: item.path.clone(),
            action: item.action,
            status: "intent".into(),
            time: timestamp(),
            rule_id: item.rule_id.clone(),
            automatic,
            operation_id,
            detail: None,
            recovery_path,
        };
        // Intent is synced BEFORE any filesystem mutation, including isolation renames.
        if let Err(e) = log.append(&entry) {
            report.log_error = Some(e);
            audit_failed = true;
            report.failed.push((
                item.path.clone(),
                "Cleanup refused: audit intent could not be persisted".into(),
            ));
            continue;
        }
        let result = (|| {
            if !seen.insert((item.fingerprint.device, item.fingerprint.inode)) {
                return Err("Duplicate file in execution request".into());
            }
            revalidate(item, &current, automatic, ctx)?;
            if file_in_use(&item.path)? {
                return Err("File is open in a running application".into());
            }
            if let Err(e) = current_authorization(config, automatic, ctx, cancel, load_config) {
                stopped = Some(e.clone());
                return Err(e);
            }
            let mut staged =
                StagedFile::isolate_named_cancellable(item, ctx, stage_name.clone(), cancel)?;
            entry.status = "isolated".into();
            entry.recovery_path = Some(staged.path.clone());
            entry.time = timestamp();
            if let Err(e) = log.append(&entry) {
                report.log_error = Some(e);
                audit_failed = true;
                let recovery = staged.restore();
                return Err(format!("Audit isolation record failed; {recovery}"));
            }
            // Check original path-level policies again after isolation. Do not re-run the
            // positive matcher on the private staging name (it is deliberately protected).
            if rules::protected(&item.path, ctx)
                || rules::parent_identities(&item.path, ctx).ok().as_ref()
                    != Some(&item.fingerprint.parents)
            {
                let recovery = staged.restore();
                return Err(format!("Original parent path changed; {recovery}"));
            }
            if let Err(e) = staged.check(item) {
                let recovery = staged.restore();
                return Err(format!("{e}; {recovery}"));
            }
            // Isolation closes our read descriptor. Recheck active references on the
            // new name immediately before removal; uncertainty is fail-closed.
            match file_in_use(&staged.path) {
                Ok(false) => {}
                result => {
                    let recovery = staged.restore();
                    return Err(format!(
                        "File became active or active state is uncertain: {result:?}; {recovery}"
                    ));
                }
            }
            if let Err(e) = current_authorization(config, automatic, ctx, cancel, load_config) {
                stopped = Some(e.clone());
                let recovery = staged.restore();
                return Err(format!("{e}; {recovery}"));
            }
            // Query first: our retained fd would itself appear in the active list.
            // After the query, pin/lock and recheck immediately before removal.
            let _final_file = match staged.final_check(item, ctx) {
                Ok(file) => file,
                Err(e) => {
                    let recovery = staged.restore();
                    return Err(format!("{e}; {recovery}"));
                }
            };
            if cancel.load(Ordering::Acquire) {
                stopped = Some("cancelled".into());
                let recovery = staged.restore();
                return Err(format!("cancelled; {recovery}"));
            }
            staged.preserve_directory = item.action == CleanupAction::Trash;
            let removal = match item.action {
                CleanupAction::Trash => trash(&staged.path),
                CleanupAction::Permanent => {
                    // Only an isolated, identity-checked ordinary file; never a directory.
                    // unlinkat pins the parent even if the original directory path changes.
                    settings::unlink_at(&staged.dir, &staged.original_name, false)
                        .map_err(|e| e.to_string())
                }
            };
            match removal {
                Ok(()) => match fs::symlink_metadata(&staged.path) {
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                    Ok(_) => {
                        let recovery = staged.restore();
                        Err(format!(
                            "Removal returned success but the file is still present; {recovery}"
                        ))
                    }
                    Err(e) => Err(format!(
                        "Cannot verify removal: {e}; inspect {}",
                        staged.path.display()
                    )),
                },
                Err(e) => {
                    // A Trash implementation can complete before reporting an error. Do
                    // not report failure or restore a nonexistent file in that case.
                    if matches!(fs::symlink_metadata(&staged.path), Err(ref io) if io.kind() == std::io::ErrorKind::NotFound)
                    {
                        entry.detail = Some(format!("Removal completed with backend warning: {e}"));
                        Ok(())
                    } else {
                        let recovery = staged.restore();
                        Err(format!("{e}; {recovery}"))
                    }
                }
            }
        })();
        entry.time = timestamp();
        match result {
            Ok(()) => {
                report.completed.push(item.path.clone());
                entry.status = "completed".into();
                if item.action == CleanupAction::Permanent {
                    entry.recovery_path = None;
                } else {
                    let warning = entry.detail.take().unwrap_or_default();
                    entry.detail = Some(format!(
                        "{warning} Trash preserves the basename. Finder Put Back, if available, restores to recovery_path in the retained staging directory, not the original path; manually move it to path. The fallback may not support Put Back."
                    ));
                }
            }
            Err(e) => {
                report.failed.push((item.path.clone(), e.clone()));
                entry.status = if e.starts_with("cancelled") {
                    "cancelled"
                } else {
                    "failed"
                }
                .into();
                entry.detail = Some(e);
            }
        }
        if !audit_failed {
            if let Err(e) = log.append(&entry) {
                // A completed filesystem operation cannot be rolled back after the fact.
                // Its durable intent/isolation records remain; stop all subsequent items.
                report.log_error = Some(e);
                audit_failed = true;
            }
        }
    }
    report
}

fn current_authorization(
    snapshot: &Settings,
    automatic: bool,
    ctx: &SafetyContext,
    cancel: &AtomicBool,
    load_config: &dyn Fn() -> Result<Settings, String>,
) -> Result<Settings, String> {
    if cancel.load(Ordering::Acquire) {
        return Err("cancelled".into());
    }
    let current = if automatic {
        load_config()
            .map_err(|e| format!("Automatic cleanup stopped: cannot load current settings: {e}"))?
    } else {
        snapshot.clone()
    };
    if cancel.load(Ordering::Acquire) {
        return Err("cancelled".into());
    }
    current.validate_in(ctx)?;
    if automatic {
        if !current.automation_enabled {
            return Err("Automatic cleanup stopped: global authorization disabled".into());
        }
        // No counter or relaxed policy inheritance: any persisted settings change
        // invalidates the batch, including source, revisions and whitelist.
        let before = serde_json::to_value(snapshot).map_err(|e| e.to_string())?;
        let after = serde_json::to_value(&current).map_err(|e| e.to_string())?;
        if before != after {
            return Err(
                "Automatic cleanup stopped: settings changed since confirmation/preview".into(),
            );
        }
    }
    Ok(current)
}

fn revalidate(
    item: &RuleMatch,
    config: &Settings,
    automatic: bool,
    ctx: &SafetyContext,
) -> Result<(), String> {
    let current = rules::match_path(&item.path, config, ctx, SystemTime::now())?
        .ok_or("File no longer matches an enabled rule")?;
    if current.rule_id != item.rule_id
        || current.action != item.action
        || current.source != item.source
        || current.rule_revision != item.rule_revision
        || current.matched_rule_ids != item.matched_rule_ids
        || current.fingerprint != item.fingerprint
    {
        return Err("Rule, overlapping policies, file identity, modification time, or parent path changed since preview".into());
    }
    if automatic
        && (!item.auto_clean
            || !current.auto_clean
            || !ctx.auto_root(&item.path)
            || current.action != CleanupAction::Trash)
    {
        return Err("Automatic cleanup requires current global and per-rule authorization, local low-risk scope and Trash".into());
    }
    Ok(())
}

fn timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

struct AuditLog {
    file: File,
    dir: File,
    name: std::ffi::OsString,
    last_automatic: Option<u64>,
}
impl AuditLog {
    fn open(path: &Path) -> Result<Self, String> {
        let dir = settings::private_dir(path.parent().ok_or("History has no parent")?, true)
            .map_err(|e| e.to_string())?;
        let name = path.file_name().ok_or("History has no filename")?;
        let file = settings::open_private_at(&dir, name, true, false).map_err(|e| e.to_string())?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } < 0 {
            return Err("History is locked by another cleanup process".into());
        }
        // Validate the existing JSONL while the append descriptor holds the lock.
        let reader =
            settings::open_private_at(&dir, name, false, false).map_err(|e| e.to_string())?;
        if !same_identity(&file, &reader)? {
            return Err("History was replaced while opening".into());
        }
        let entries = read_entries(reader)?;
        let last_automatic = entries.iter().filter(|e| e.automatic).map(|e| e.time).max();
        dir.sync_all().map_err(|e| e.to_string())?;
        Ok(Self {
            file,
            dir,
            name: name.to_os_string(),
            last_automatic,
        })
    }
    fn append(&mut self, entry: &HistoryEntry) -> Result<(), String> {
        let current = settings::open_private_at(&self.dir, &self.name, false, false)
            .map_err(|e| e.to_string())?;
        if !same_identity(&self.file, &current)? {
            return Err("Audit log path was replaced".into());
        }
        let mut bytes = serde_json::to_vec(entry).map_err(|e| e.to_string())?;
        bytes.push(b'\n');
        if self
            .file
            .metadata()
            .map_err(|e| e.to_string())?
            .len()
            .saturating_add(bytes.len() as u64)
            > HISTORY_LIMIT
        {
            return Err("History is full; archive it before further cleanup".into());
        }
        self.file
            .write_all(&bytes)
            .and_then(|_| self.file.sync_all())
            .map_err(|e| e.to_string())
    }
}
impl Drop for AuditLog {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

fn same_identity(a: &File, b: &File) -> Result<bool, String> {
    use std::os::unix::fs::MetadataExt;
    let a = a.metadata().map_err(|e| e.to_string())?;
    let b = b.metadata().map_err(|e| e.to_string())?;
    Ok(a.dev() == b.dev() && a.ino() == b.ino())
}

fn read_entries(file: File) -> Result<Vec<HistoryEntry>, String> {
    if file.metadata().map_err(|e| e.to_string())?.len() > HISTORY_LIMIT {
        return Err("History exceeds the size limit".into());
    }
    let mut reader = BufReader::new(file.take(HISTORY_LIMIT + 1));
    let mut entries = Vec::new();
    let mut line = Vec::new();
    let mut total = 0;
    loop {
        line.clear();
        let n = reader
            .read_until(b'\n', &mut line)
            .map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > HISTORY_LIMIT || line.last() != Some(&b'\n') {
            return Err("History contains an incomplete record; cleanup refused".into());
        }
        entries.push(
            serde_json::from_slice(&line).map_err(|e| format!("Invalid history record: {e}"))?,
        );
    }
    Ok(entries)
}

pub fn history() -> Result<Vec<HistoryEntry>, String> {
    history_from(&settings::state_path("cleanup-history.jsonl")?)
}

pub fn history_from(path: &Path) -> Result<Vec<HistoryEntry>, String> {
    let dir = match settings::private_dir(path.parent().ok_or("History has no parent")?, false) {
        Ok(dir) => dir,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => return Err(e.to_string()),
    };
    let file = match settings::open_private_at(
        &dir,
        path.file_name().ok_or("History has no filename")?,
        false,
        false,
    ) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => return Err(e.to_string()),
    };
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) } < 0 {
        return Err("History is being updated; retry later".into());
    }
    read_entries(file)
}

struct StagedFile {
    parent: File,
    dir: File,
    stage_name: std::ffi::OsString,
    original_name: std::ffi::OsString,
    path: PathBuf,
    preserve_directory: bool,
    isolated_fingerprint: Option<rules::FileFingerprint>,
}
impl StagedFile {
    #[cfg(test)]
    fn isolate(item: &RuleMatch, ctx: &SafetyContext) -> Result<Self, String> {
        Self::isolate_named(item, ctx, settings::unique_name(".petal-cleanup-"))
    }
    #[cfg(test)]
    fn isolate_named(
        item: &RuleMatch,
        ctx: &SafetyContext,
        stage_name: std::ffi::OsString,
    ) -> Result<Self, String> {
        Self::isolate_named_cancellable(item, ctx, stage_name, &AtomicBool::new(false))
    }
    fn isolate_named_cancellable(
        item: &RuleMatch,
        ctx: &SafetyContext,
        stage_name: std::ffi::OsString,
        cancel: &AtomicBool,
    ) -> Result<Self, String> {
        if cancel.load(Ordering::Acquire) {
            return Err("cancelled".into());
        }
        if rules::parent_identities(&item.path, ctx)? != item.fingerprint.parents {
            return Err("Parent identity changed".into());
        }
        let parent_path = item.path.parent().ok_or("File has no parent")?;
        // Each ancestor is opened relative to a pinned descriptor, never through a symlink.
        let mut parent = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open("/")
            .map_err(|e| e.to_string())?;
        for component in parent_path.components() {
            if let std::path::Component::Normal(part) = component {
                let name = settings::c_name(part).map_err(|e| e.to_string())?;
                let fd = unsafe {
                    libc::openat(
                        parent.as_raw_fd(),
                        name.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if fd < 0 {
                    return Err(std::io::Error::last_os_error().to_string());
                }
                parent = unsafe { File::from_raw_fd(fd) };
            }
        }
        use std::os::unix::fs::MetadataExt;
        let meta = parent.metadata().map_err(|e| e.to_string())?;
        let expected = item
            .fingerprint
            .parents
            .last()
            .ok_or("Missing parent fingerprint")?;
        if meta.dev() != expected.device || meta.ino() != expected.inode {
            return Err("Pinned parent does not match preview".into());
        }
        let original_name = item
            .path
            .file_name()
            .ok_or("Missing filename")?
            .to_os_string();
        let original = open_regular_at(&parent, &original_name)?;
        if !item
            .fingerprint
            .same_file(&original.metadata().map_err(|e| e.to_string())?)
        {
            return Err("File changed while opening".into());
        }
        // Advisory lock supplements the native open-file check; it is not mistaken for
        // proof that other applications cooperate with file locks.
        if unsafe { libc::flock(original.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } < 0 {
            return Err("File is locked by an application".into());
        }
        let name = settings::c_name(&stage_name).map_err(|e| e.to_string())?;
        if cancel.load(Ordering::Acquire) {
            return Err("cancelled".into());
        }
        if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            let _ = settings::unlink_at(&parent, &stage_name, true);
            return Err(std::io::Error::last_os_error().to_string());
        }
        let dir = unsafe { File::from_raw_fd(fd) };
        let mut staged = Self {
            parent,
            dir,
            stage_name: stage_name.clone(),
            path: parent_path.join(stage_name).join(&original_name),
            original_name,
            preserve_directory: false,
            isolated_fingerprint: None,
        };
        if rules::parent_identities(&item.path, ctx)? != item.fingerprint.parents {
            return Err("Parent replaced before isolation".into());
        }
        if cancel.load(Ordering::Acquire) {
            return Err("cancelled".into());
        }
        settings::rename_at(
            &staged.parent,
            &staged.original_name,
            &staged.dir,
            &staged.original_name,
            true,
        )
        .map_err(|e| e.to_string())?;
        if let Err(e) = staged.check(item) {
            let recovery = staged.restore();
            return Err(format!("{e}; {recovery}"));
        }
        let captured = (|| {
            let isolated = open_regular_at(&staged.dir, &staged.original_name)?;
            let meta = isolated.metadata().map_err(|e| e.to_string())?;
            if !item.fingerprint.same_after_rename(&meta) {
                return Err("File changed while capturing isolated fingerprint".to_string());
            }
            Ok(rules::FileFingerprint::from_metadata(
                &meta,
                item.fingerprint.parents.clone(),
            ))
        })();
        match captured {
            Ok(fingerprint) => staged.isolated_fingerprint = Some(fingerprint),
            Err(e) => {
                let recovery = staged.restore();
                return Err(format!("{e}; {recovery}"));
            }
        }
        // Persist the isolation rename on both directories before handing off to Trash.
        if let Err(e) = staged.parent.sync_all().and_then(|_| staged.dir.sync_all()) {
            let recovery = staged.restore();
            return Err(format!("Isolation sync failed: {e}; {recovery}"));
        }
        Ok(staged)
    }
    fn check(&self, item: &RuleMatch) -> Result<(), String> {
        let file = open_regular_at(&self.dir, &self.original_name)?;
        let meta = file.metadata().map_err(|e| e.to_string())?;
        if !item.fingerprint.same_after_rename(&meta)
            || self
                .isolated_fingerprint
                .as_ref()
                .is_some_and(|fp| !fp.same_file(&meta))
        {
            return Err("Isolated file identity or modification time changed".into());
        }
        // The pathname used by the existing Trash API must still identify our pinned dir.
        let path_dir = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(self.path.parent().ok_or("Missing staging parent")?)
            .map_err(|e| e.to_string())?;
        if !same_identity(&self.dir, &path_dir)? {
            return Err("Staging path was replaced".into());
        }
        Ok(())
    }
    fn final_check(&self, item: &RuleMatch, ctx: &SafetyContext) -> Result<File, String> {
        if rules::protected(&item.path, ctx)
            || rules::parent_identities(&item.path, ctx)? != item.fingerprint.parents
        {
            return Err("Original parent or path protection changed before removal".into());
        }
        let file = open_regular_at(&self.dir, &self.original_name)?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } < 0 {
            return Err("Isolated file became locked".into());
        }
        let meta = file.metadata().map_err(|e| e.to_string())?;
        let expected = self
            .isolated_fingerprint
            .as_ref()
            .ok_or("Missing isolated fingerprint")?;
        if !expected.same_file(&meta) {
            return Err("Final fingerprint mismatch before removal".into());
        }
        self.check(item)?;
        if rules::parent_identities(&item.path, ctx)? != item.fingerprint.parents {
            return Err("Original parent changed during final check".into());
        }
        if !expected.same_file(&file.metadata().map_err(|e| e.to_string())?) {
            return Err("File changed during final check".into());
        }
        Ok(file) // Keep this descriptor and its advisory lock across unlinkat/Trash.
    }
    fn restore(&mut self) -> String {
        match settings::rename_at(
            &self.dir,
            &self.original_name,
            &self.parent,
            &self.original_name,
            true,
        ) {
            Ok(()) => {
                self.preserve_directory = false;
                let _ = self.parent.sync_all();
                "file restored to its original name; refresh preview before retrying".into()
            }
            Err(e) => format!(
                "file preserved at {} for manual recovery (restore: {e})",
                self.path.display()
            ),
        }
    }
}
impl Drop for StagedFile {
    fn drop(&mut self) {
        // Never recursively remove staging data. rmdir succeeds only when empty.
        if !self.preserve_directory {
            let _ = settings::unlink_at(&self.parent, &self.stage_name, true);
        }
    }
}

fn open_regular_at(dir: &File, name: &std::ffi::OsStr) -> Result<File, String> {
    let name = settings::c_name(name).map_err(|e| e.to_string())?;
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let file = unsafe { File::from_raw_fd(fd) };
    if !file.metadata().map_err(|e| e.to_string())?.is_file() {
        return Err("Not a regular file".into());
    }
    Ok(file)
}

#[cfg(target_os = "macos")]
fn file_in_use(path: &Path) -> Result<bool, String> {
    // Native libproc query; no shell, sudo, arbitrary commands, or external dependency.
    #[link(name = "proc")]
    unsafe extern "C" {
        fn proc_listpidspath(
            kind: u32,
            typeinfo: u32,
            path: *const libc::c_char,
            flags: u32,
            buffer: *mut libc::c_void,
            size: libc::c_int,
        ) -> libc::c_int;
    }
    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| "NUL in path")?;
    let mut pids = vec![0u32; 65536];
    let bytes = unsafe {
        proc_listpidspath(
            1,
            0,
            path.as_ptr(),
            0,
            pids.as_mut_ptr().cast(),
            (pids.len() * 4) as libc::c_int,
        )
    };
    if bytes < 0 || bytes as usize >= pids.len() * 4 {
        return Err("Cannot establish whether the file is in use".into());
    }
    Ok(pids[..bytes as usize / 4].iter().any(|&pid| pid != 0))
}
#[cfg(not(target_os = "macos"))]
fn file_in_use(_path: &Path) -> Result<bool, String> {
    Err("Safe cleanup execution is supported only on macOS".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::fixtures::Fixture;
    fn preview(f: &Fixture, path: &Path, s: &Settings) -> RuleMatch {
        rules::match_path(path, s, &f.ctx, SystemTime::now())
            .unwrap()
            .unwrap()
    }
    #[test]
    fn pre_cancelled_batch_never_reads_config_or_touches_files() {
        let f = Fixture::new();
        let path = f.file("Library/Caches/a/old", 8);
        let config = f.settings();
        let item = preview(&f, &path, &config);
        let history = f.dir.join("state/history.jsonl");
        let cancel = AtomicBool::new(true);
        let report = execute_controlled(
            &[item],
            &config,
            false,
            &f.ctx,
            &history,
            &|_| panic!("cancelled backend"),
            &cancel,
            &|| panic!("cancelled loader"),
        );
        assert_eq!(report.failed[0].1, "cancelled");
        assert!(path.exists());
        assert!(!history.exists());
    }

    #[test]
    fn latest_global_rule_whitelist_and_load_failure_invalidate_auto_batch() {
        let f = Fixture::new();
        let path = f.file("Library/Caches/a/old", 8);
        let mut config = f.settings();
        config.automation_enabled = true;
        config.rules[0].auto_clean = true;
        let item = preview(&f, &path, &config);
        let cancel = AtomicBool::new(false);
        for change in 0..5 {
            let mut current = config.clone();
            match change {
                0 => current.automation_enabled = false,
                1 => current.rules[0].enabled = false,
                2 => current.whitelist.push(path.clone()),
                3 => current.rules[0].priority += 1,
                _ => {}
            }
            let history = f.dir.join(format!("state-{change}/history.jsonl"));
            let report = execute_controlled(
                &[item.clone()],
                &config,
                true,
                &f.ctx,
                &history,
                &|_| panic!("stale authorization backend"),
                &cancel,
                &|| {
                    if change == 4 {
                        Err("fixture corrupt config".into())
                    } else {
                        Ok(current.clone())
                    }
                },
            );
            assert_eq!(report.failed.len(), 1);
            assert!(report.completed.is_empty());
            assert!(path.exists());
            assert!(!fs::read_dir(path.parent().unwrap()).unwrap().any(|e| {
                e.unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".petal-cleanup-")
            }));
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn cancelled_between_files_keeps_completed_result_and_refuses_remaining() {
        let f = Fixture::new();
        let first = f.file("Library/Caches/a/old", 8);
        let second = f.file("Library/Caches/b/old", 8);
        let config = f.settings();
        let items = [preview(&f, &first, &config), preview(&f, &second, &config)];
        let cancel = AtomicBool::new(false);
        let fake_trash = f.dir.join("fake-trash");
        fs::create_dir(&fake_trash).unwrap();
        let report = execute_controlled(
            &items,
            &config,
            false,
            &f.ctx,
            &f.dir.join("state/history.jsonl"),
            &|path| {
                fs::rename(path, fake_trash.join(path.file_name().unwrap()))
                    .map_err(|e| e.to_string())?;
                cancel.store(true, Ordering::Release);
                Ok(())
            },
            &cancel,
            &|| panic!("manual cleanup must not load production config"),
        );
        assert_eq!(report.completed, vec![first]);
        assert_eq!(report.failed, vec![(second.clone(), "cancelled".into())]);
        assert!(second.exists());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn cancellation_after_isolation_restores_and_marks_history_cancelled() {
        use std::cell::Cell;
        let f = Fixture::new();
        let path = f.file("Library/Caches/a/old", 8);
        let later = f.file("Library/Caches/b/old", 8);
        let mut config = f.settings();
        config.automation_enabled = true;
        config.rules[0].auto_clean = true;
        let items = [preview(&f, &path, &config), preview(&f, &later, &config)];
        let history = f.dir.join("state/history.jsonl");
        let cancel = AtomicBool::new(false);
        let calls = Cell::new(0);
        let report = execute_controlled(
            &items,
            &config,
            true,
            &f.ctx,
            &history,
            &|_| panic!("cancelled before removal"),
            &cancel,
            &|| {
                calls.set(calls.get() + 1);
                if calls.get() == 3 {
                    cancel.store(true, Ordering::Release);
                }
                Ok(config.clone())
            },
        );
        assert!(report.completed.is_empty());
        assert_eq!(report.failed.len(), 2);
        assert!(
            report
                .failed
                .iter()
                .all(|(_, e)| e.starts_with("cancelled"))
        );
        assert!(path.exists());
        assert!(later.exists());
        assert!(
            history_from(&history)
                .unwrap()
                .iter()
                .any(|e| e.status == "isolated")
        );
        assert!(
            history_from(&history)
                .unwrap()
                .iter()
                .any(|e| e.status == "cancelled")
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn current_settings_reload_between_files_stops_batch_and_load_error_after_stage_restores() {
        use std::cell::{Cell, RefCell};
        let f = Fixture::new();
        let first = f.file("Library/Caches/a/old", 8);
        let second = f.file("Library/Caches/b/old", 8);
        let mut config = f.settings();
        config.automation_enabled = true;
        config.rules[0].auto_clean = true;
        let items = [preview(&f, &first, &config), preview(&f, &second, &config)];
        let latest = RefCell::new(config.clone());
        let cancel = AtomicBool::new(false);
        let fake_trash = f.dir.join("fake-trash");
        fs::create_dir(&fake_trash).unwrap();
        let report = execute_controlled(
            &items,
            &config,
            true,
            &f.ctx,
            &f.dir.join("state/history.jsonl"),
            &|path| {
                fs::rename(path, fake_trash.join(path.file_name().unwrap()))
                    .map_err(|e| e.to_string())?;
                latest.borrow_mut().automation_enabled = false;
                Ok(())
            },
            &cancel,
            &|| Ok(latest.borrow().clone()),
        );
        assert_eq!(report.completed, vec![first]);
        assert_eq!(report.failed.len(), 1);
        assert!(second.exists());
        let item = preview(&f, &second, &config);
        let calls = Cell::new(0);
        let history = f.dir.join("another-state/history.jsonl");
        let report = execute_controlled(
            &[item],
            &config,
            true,
            &f.ctx,
            &history,
            &|_| panic!("load failure before removal"),
            &cancel,
            &|| {
                calls.set(calls.get() + 1);
                if calls.get() == 3 {
                    Err("fixture config unreadable".into())
                } else {
                    Ok(config.clone())
                }
            },
        );
        assert!(report.completed.is_empty());
        assert_eq!(report.failed.len(), 1);
        assert!(second.exists());
        assert!(
            history_from(&history)
                .unwrap()
                .iter()
                .any(|e| e.status == "isolated")
        );
    }

    #[test]
    fn execution_rechecks_rule_fingerprint_whitelist_and_authorization() {
        let f = Fixture::new();
        let path = f.file("Library/Caches/app/old", 8);
        let mut s = f.settings();
        let item = preview(&f, &path, &s);
        assert!(revalidate(&item, &s, true, &f.ctx).is_err());
        s.rules[0].auto_clean = true;
        let item = preview(&f, &path, &s);
        assert!(revalidate(&item, &s, true, &f.ctx).is_ok());
        s.rules[0].older_than_days = Some(9);
        assert!(revalidate(&item, &s, false, &f.ctx).is_err());
        s.rules[0].older_than_days = Some(7);
        s.whitelist.push(path.clone());
        assert!(revalidate(&item, &s, false, &f.ctx).is_err());
        s.whitelist.clear();
        fs::write(&path, b"changed").unwrap();
        assert!(revalidate(&item, &s, false, &f.ctx).is_err());
    }
    #[test]
    fn audit_failure_is_closed_without_touching_files() {
        let f = Fixture::new();
        let path = f.file("Library/Caches/app/old", 8);
        let s = f.settings();
        let item = preview(&f, &path, &s);
        let history = f.dir.join("history");
        fs::create_dir(&history).unwrap();
        let report = execute_in(&[item], &s, false, &f.ctx, &history, &|_| {
            panic!("Trash must not run")
        });
        assert_eq!(report.failed.len(), 1);
        assert!(report.log_error.is_some());
        assert!(path.exists());
    }
    #[test]
    fn history_round_trip_and_partial_record_refusal() {
        let f = Fixture::new();
        let path = f.dir.join("state/history.jsonl");
        let entry = HistoryEntry {
            path: f.ctx.home.join("example"),
            action: CleanupAction::Trash,
            status: "intent".into(),
            time: 1,
            rule_id: "a".into(),
            automatic: false,
            operation_id: "x".into(),
            detail: None,
            recovery_path: None,
        };
        {
            let mut log = AuditLog::open(&path).unwrap();
            log.append(&entry).unwrap();
        }
        assert_eq!(history_from(&path).unwrap().len(), 1);
        fs::write(&path, b"{\"broken\":").unwrap();
        assert!(AuditLog::open(&path).is_err());
        assert!(history_from(&path).is_err());
    }
    #[test]
    fn parent_symlink_and_parent_replacement_refused() {
        let f = Fixture::new();
        let path = f.file("Library/Caches/app/old", 8);
        let s = f.settings();
        let item = preview(&f, &path, &s);
        let parent = path.parent().unwrap();
        let moved = parent.with_file_name("moved");
        fs::rename(parent, &moved).unwrap();
        std::os::unix::fs::symlink(&moved, parent).unwrap();
        assert!(revalidate(&item, &s, false, &f.ctx).is_err());
        fs::remove_file(parent).unwrap();
        fs::create_dir(parent).unwrap();
        fs::write(&path, b"fixture data").unwrap();
        assert!(revalidate(&item, &s, false, &f.ctx).is_err());
    }
    #[test]
    fn effective_trash_rule_is_revalidated_without_permanent_upgrade() {
        let f = Fixture::new();
        let path = f.file("Library/Caches/a/old", 8);
        let mut config = f.settings();
        config.rules.retain(|r| r.id == "app-caches");
        let mut permanent = config.rules[0].clone();
        permanent.id = "permanent".into();
        permanent.action = CleanupAction::Permanent;
        permanent.priority = 100;
        config.rules.push(permanent);
        let item = preview(&f, &path, &config);
        assert_eq!(item.action, CleanupAction::Trash);
        assert!(revalidate(&item, &config, false, &f.ctx).is_ok());
        config.rules[0].enabled = false;
        assert!(revalidate(&item, &config, false, &f.ctx).is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn final_check_catches_changes_after_query_and_pins_file() {
        let f = Fixture::new();
        let path = f.file("Library/Caches/a/cache.bin", 8);
        let config = f.settings();
        let item = preview(&f, &path, &config);
        let mut staged = StagedFile::isolate(&item, &f.ctx).unwrap();
        assert_eq!(staged.path.file_name(), path.file_name());
        staged.check(&item).unwrap();
        assert!(!file_in_use(&staged.path).unwrap());
        {
            let pinned = staged.final_check(&item, &f.ctx).unwrap();
            assert!(
                same_identity(
                    &pinned,
                    &open_regular_at(&staged.dir, &staged.original_name).unwrap()
                )
                .unwrap()
            );
        }
        fs::write(&staged.path, b"modified after query").unwrap();
        assert!(staged.final_check(&item, &f.ctx).is_err());
        assert!(staged.path.exists());
        assert!(staged.restore().contains("restored"));
        assert_eq!(fs::read(&path).unwrap(), b"modified after query");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn final_check_rejects_same_size_and_mtime_replacement() {
        let f = Fixture::new();
        let path = f.file("Library/Caches/a/cache.bin", 8);
        let config = f.settings();
        let item = preview(&f, &path, &config);
        let staged = StagedFile::isolate(&item, &f.ctx).unwrap();
        let time = fs::metadata(&staged.path).unwrap().modified().unwrap();
        let replacement = staged.path.with_file_name("replacement");
        fs::write(&replacement, b"fixture data").unwrap();
        File::options()
            .write(true)
            .open(&replacement)
            .unwrap()
            .set_times(fs::FileTimes::new().set_modified(time))
            .unwrap();
        let retained = staged.path.with_file_name("retained-original");
        fs::rename(&staged.path, &retained).unwrap();
        fs::rename(&replacement, &staged.path).unwrap();
        assert!(staged.final_check(&item, &f.ctx).is_err());
        assert!(retained.exists());
        assert!(staged.path.exists());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn final_check_catches_parent_replacement() {
        let f = Fixture::new();
        let path = f.file("Library/Caches/a/cache.bin", 8);
        let config = f.settings();
        let item = preview(&f, &path, &config);
        let mut staged = StagedFile::isolate(&item, &f.ctx).unwrap();
        let parent = path.parent().unwrap();
        let moved = parent.with_file_name("moved");
        fs::rename(parent, &moved).unwrap();
        fs::create_dir(parent).unwrap();
        assert!(staged.final_check(&item, &f.ctx).is_err());
        assert!(staged.restore().contains("restored"));
        assert!(moved.join("cache.bin").exists());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn partial_success_trash_failure_restores_and_permanent_is_individual() {
        let f = Fixture::new();
        let first = f.file("Library/Caches/a/old", 8);
        let second = f.file("Library/Caches/b/old", 8);
        let s = f.settings();
        let items = vec![preview(&f, &first, &s), preview(&f, &second, &s)];
        let history = f.dir.join("state/history.jsonl");
        let fake_trash = f.dir.join("fake-trash");
        fs::create_dir(&fake_trash).unwrap();
        let report = execute_in(&items, &s, false, &f.ctx, &history, &|path| {
            assert_eq!(path.file_name(), Some(std::ffi::OsStr::new("old")));
            if path.to_string_lossy().contains("/a/") {
                fs::rename(path, fake_trash.join(path.file_name().unwrap()))
                    .map_err(|e| e.to_string())
            } else {
                Err("fixture backend failure".into())
            }
        });
        assert_eq!(report.completed, vec![first.clone()]);
        assert_eq!(report.failed.len(), 1);
        assert!(!first.exists());
        assert!(second.exists());
        assert_eq!(
            history_from(&history)
                .unwrap()
                .iter()
                .filter(|e| e.status == "completed")
                .count(),
            1
        );
        let records = history_from(&history).unwrap();
        let success = records.iter().find(|e| e.status == "completed").unwrap();
        assert_eq!(success.path, first);
        let recovery = success.recovery_path.as_ref().unwrap();
        assert_eq!(recovery.file_name(), first.file_name());
        assert!(recovery.parent().unwrap().is_dir());
        assert!(success.detail.as_ref().unwrap().contains("manually move"));
        // Simulate Put Back without Finder or a real Trash: the retained directory
        // exists and the original basename round-trips via the recorded mapping.
        fs::rename(fake_trash.join("old"), recovery).unwrap();
        fs::rename(recovery, &first).unwrap();
        let mut s = s;
        s.rules[0].action = CleanupAction::Permanent;
        let item = preview(&f, &second, &s);
        let report = execute_in(&[item], &s, false, &f.ctx, &history, &|_| {
            panic!("Permanent must not call Trash")
        });
        assert_eq!(report.completed, vec![second.clone()]);
        assert!(!second.exists());
        assert!(second.parent().unwrap().exists());
        let records = history_from(&history).unwrap();
        let permanent = records
            .iter()
            .rev()
            .find(|e| e.status == "completed")
            .unwrap();
        assert_eq!(permanent.action, CleanupAction::Permanent);
        assert!(permanent.recovery_path.is_none());
        let isolation = records
            .iter()
            .rev()
            .find(|e| e.status == "isolated")
            .unwrap();
        assert!(
            !isolation
                .recovery_path
                .as_ref()
                .unwrap()
                .parent()
                .unwrap()
                .exists()
        );
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn open_file_is_refused_and_dual_auto_authorization_required() {
        let f = Fixture::new();
        let path = f.file("Library/Caches/a/old", 8);
        let mut s = f.settings();
        s.rules[0].auto_clean = true;
        let item = preview(&f, &path, &s);
        let history = f.dir.join("state/history.jsonl");
        let report = execute_in(&[item.clone()], &s, true, &f.ctx, &history, &|_| {
            panic!("Not authorized")
        });
        assert_eq!(report.failed.len(), 1);
        assert!(!history.exists());
        s.automation_enabled = true;
        let file = File::open(&path).unwrap();
        assert!(file_in_use(&path).unwrap());
        let report = execute_in(&[item], &s, true, &f.ctx, &history, &|_| {
            panic!("File is in use")
        });
        assert_eq!(report.failed.len(), 1);
        assert!(path.exists());
        drop(file);
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn isolation_restore_never_overwrites_new_original_name() {
        let f = Fixture::new();
        let path = f.file("Library/Caches/a/old", 8);
        let s = f.settings();
        let item = preview(&f, &path, &s);
        let mut staged = StagedFile::isolate(&item, &f.ctx).unwrap();
        fs::write(&path, b"new original").unwrap();
        assert!(staged.restore().contains("preserved"));
        assert_eq!(fs::read(&path).unwrap(), b"new original");
        assert!(staged.path.exists());
    }
}
