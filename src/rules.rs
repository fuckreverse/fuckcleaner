use std::collections::{HashMap, HashSet};
use std::fs;
#[cfg(target_os = "macos")]
use std::os::macos::fs::MetadataExt as _;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::SystemTime;
#[cfg(test)]
use std::time::UNIX_EPOCH;

use globset::{GlobBuilder, GlobMatcher};
use serde::{Deserialize, Serialize};

use crate::scan::{Kind, Tree};
use crate::settings::Settings;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CleanupCategory {
    Temporary,
    Cache,
    Build,
    Logs,
    Downloads,
    Backup,
    Other,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CleanupAction {
    #[default]
    Trash,
    Permanent,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleSource {
    BuiltIn,
    #[default]
    User,
    Ai,
}

fn enabled_default() -> bool {
    true
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub category: CleanupCategory,
    pub roots: Vec<PathBuf>,
    pub pattern: String,
    #[serde(default)]
    pub exclude: Vec<String>,
    #[serde(default)]
    pub min_size: u64,
    #[serde(default)]
    pub older_than_days: Option<u64>,
    #[serde(default)]
    pub priority: i32,
    #[serde(default = "enabled_default")]
    pub enabled: bool,
    #[serde(default)]
    pub auto_clean: bool,
    #[serde(default)]
    pub action: CleanupAction,
    #[serde(default)]
    pub source: RuleSource,
}

impl Rule {
    pub fn validate(&self) -> Result<(), String> {
        self.validate_in(&SafetyContext::current()?)
    }

    pub(crate) fn validate_in(&self, ctx: &SafetyContext) -> Result<(), String> {
        if self.id.trim().is_empty() || self.name.trim().is_empty() {
            return Err("Rule id and name must not be empty".into());
        }
        if self.roots.is_empty() {
            return Err("A rule needs at least one concrete directory".into());
        }
        compile_glob(&self.pattern)?;
        for pattern in &self.exclude {
            compile_glob(pattern)?;
        }
        if self
            .older_than_days
            .is_some_and(|d| d.checked_mul(86400).is_none())
        {
            return Err("Rule age is too large".into());
        }
        for root in &self.roots {
            let root = ctx.expand(root)?;
            if root == Path::new("/")
                || equivalent(&root) == equivalent(&ctx.home)
                || !ctx.in_scope(&root)
            {
                return Err(format!(
                    "Scope must be a concrete directory within the current user's home or temporary directory: {}",
                    root.display()
                ));
            }
            // Static validation deliberately does not touch the filesystem. Offline,
            // disabled or symlinked defaults remain loadable; execution fails closed.
            if self.auto_clean && !ctx.auto_root(&root) {
                return Err("Automatic rules require a locally approved cache or log scope".into());
            }
        }
        if self.source == RuleSource::Ai
            && (self.auto_clean || self.action == CleanupAction::Permanent)
        {
            return Err("AI drafts cannot authorize automation or permanent deletion".into());
        }
        if self.auto_clean
            && (self.action != CleanupAction::Trash || self.older_than_days.unwrap_or(0) < 7)
        {
            return Err(
                "Automatic rules require Trash and at least seven days of retention".into(),
            );
        }
        Ok(())
    }

    pub(crate) fn validate_active_in(&self, ctx: &SafetyContext) -> Result<(), String> {
        self.validate_in(ctx)?;
        self.validate_scope_in(ctx)
    }

    fn validate_scope_in(&self, ctx: &SafetyContext) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        for root in &self.roots {
            let root = ctx.expand(root)?;
            let meta =
                fs::symlink_metadata(&root).map_err(|e| format!("{}: {e}", root.display()))?;
            if !meta.is_dir() || meta.file_type().is_symlink() {
                return Err(format!("Scope is not a real directory: {}", root.display()));
            }
            parent_identities(&root.join(".scope-check"), ctx)?;
            let real = fs::canonicalize(&root).map_err(|e| e.to_string())?;
            if !ctx.in_scope(&real) || equivalent(&real) == equivalent(&ctx.home) {
                return Err("Canonical scope escapes the user boundary".into());
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathIdentity {
    pub path: PathBuf,
    pub device: u64,
    pub inode: u64,
    pub uid: u32,
    pub mode: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileFingerprint {
    pub device: u64,
    pub inode: u64,
    pub size: u64,
    pub mtime_secs: i64,
    pub mtime_nanos: i64,
    pub ctime_secs: i64,
    pub ctime_nanos: i64,
    pub uid: u32,
    pub links: u64,
    pub mode: u32,
    pub flags: u32,
    pub parents: Vec<PathIdentity>,
}
impl FileFingerprint {
    pub(crate) fn from_metadata(meta: &fs::Metadata, parents: Vec<PathIdentity>) -> Self {
        Self {
            device: meta.dev(),
            inode: meta.ino(),
            size: meta.len(),
            mtime_secs: meta.mtime(),
            mtime_nanos: meta.mtime_nsec(),
            ctime_secs: meta.ctime(),
            ctime_nanos: meta.ctime_nsec(),
            uid: meta.uid(),
            links: meta.nlink(),
            mode: meta.mode(),
            flags: file_flags(meta),
            parents,
        }
    }
    pub(crate) fn same_file(&self, meta: &fs::Metadata) -> bool {
        let other = Self::from_metadata(meta, self.parents.clone());
        *self == other
    }
    // A rename changes ctime. Only this narrowly scoped comparison is used after our own rename.
    pub(crate) fn same_after_rename(&self, meta: &fs::Metadata) -> bool {
        meta.is_file()
            && self.device == meta.dev()
            && self.inode == meta.ino()
            && self.size == meta.len()
            && self.mtime_secs == meta.mtime()
            && self.mtime_nanos == meta.mtime_nsec()
            && self.uid == meta.uid()
            && self.links == meta.nlink()
            && self.mode == meta.mode()
            && self.flags == file_flags(meta)
    }
}

fn file_flags(meta: &fs::Metadata) -> u32 {
    #[cfg(target_os = "macos")]
    {
        meta.st_flags()
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = meta;
        0
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct RuleMatch {
    pub path: PathBuf,
    pub rule_id: String,
    pub rule_name: String,
    pub category: CleanupCategory,
    pub priority: i32,
    pub action: CleanupAction,
    pub size: u64,
    pub reason: String,
    pub auto_clean: bool,
    pub fingerprint: FileFingerprint,
    pub source: RuleSource,
    /// All overlapping rules must authorize automatic cleanup, not just the priority winner.
    pub matched_rule_ids: Vec<String>,
    /// Snapshot of the complete selected rule, including exclusions and retention.
    pub rule_revision: String,
}

#[derive(Clone, Default)]
pub struct Plan {
    pub items: Vec<RuleMatch>,
    pub blocked: Vec<String>,
    pub errors: Vec<String>,
    pub blocked_total: u64,
    pub skipped_total: u64,
    #[cfg(test)]
    pub(crate) metadata_reads: u64,
    #[cfg(test)]
    pub(crate) visited_edges: u64,
    #[cfg(test)]
    pub(crate) rule_compilations: u64,
    #[cfg(test)]
    pub(crate) parent_cache_misses: u64,
}

pub(crate) struct SafetyContext {
    pub home: PathBuf,
    pub temp: Option<PathBuf>,
    pub uid: u32,
}
impl SafetyContext {
    pub(crate) fn current() -> Result<Self, String> {
        let uid = unsafe { libc::geteuid() };
        if uid == 0 {
            return Err("Cleanup is disabled when running as root".into());
        }
        // Do not let HOME/TMPDIR environment variables redefine the production safety boundary.
        let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result = std::ptr::null_mut();
        let mut buffer = vec![0u8; 16384];
        let status = unsafe {
            libc::getpwuid_r(
                uid,
                &mut entry,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        if status != 0 || result.is_null() || entry.pw_dir.is_null() {
            return Err("Cannot resolve the current user's home".into());
        }
        use std::os::unix::ffi::OsStrExt;
        let home = PathBuf::from(std::ffi::OsStr::from_bytes(
            unsafe { std::ffi::CStr::from_ptr(entry.pw_dir) }.to_bytes(),
        ));
        let home = fs::canonicalize(home).map_err(|e| e.to_string())?;
        Ok(Self {
            home,
            temp: user_temp_dir(),
            uid,
        })
    }
    pub(crate) fn expand(&self, path: &Path) -> Result<PathBuf, String> {
        if path.as_os_str().is_empty()
            || path
                .components()
                .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
        {
            return Err("Empty paths and traversal components are forbidden".into());
        }
        let mut parts = path.components();
        let expanded = if parts.next().is_some_and(|c| c.as_os_str() == "~") {
            self.home.join(parts.as_path())
        } else {
            path.to_path_buf()
        };
        if !expanded.is_absolute()
            || expanded
                .to_string_lossy()
                .contains(['*', '?', '[', ']', '{', '}'])
        {
            return Err("Paths must be absolute concrete paths (or ~/...)".into());
        }
        Ok(expanded)
    }
    pub(crate) fn in_scope(&self, path: &Path) -> bool {
        let path = equivalent(path);
        path.starts_with(equivalent(&self.home))
            || self
                .temp
                .as_ref()
                .is_some_and(|t| path.starts_with(equivalent(t)))
    }
    fn auto_roots(&self) -> Vec<PathBuf> {
        // Path-based local policy, never category labels or rule source claims.
        ["Library/Caches", "Library/Logs", ".npm/_cacache"]
            .iter()
            .map(|p| self.home.join(p))
            .collect()
    }
    pub(crate) fn auto_root(&self, path: &Path) -> bool {
        let path = equivalent(path);
        self.auto_roots()
            .iter()
            .any(|r| path.starts_with(equivalent(r)))
    }
}

fn user_temp_dir() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        let mut buf = vec![0 as libc::c_char; 4096];
        let len =
            unsafe { libc::confstr(libc::_CS_DARWIN_USER_TEMP_DIR, buf.as_mut_ptr(), buf.len()) };
        if len == 0 || len > buf.len() {
            return None;
        }
        let path = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) }.to_bytes();
        use std::os::unix::ffi::OsStrExt;
        fs::canonicalize(Path::new(std::ffi::OsStr::from_bytes(path))).ok()
    }
    #[cfg(not(target_os = "macos"))]
    {
        None
    }
}

pub(crate) fn equivalent(path: &Path) -> PathBuf {
    path.strip_prefix("/System/Volumes/Data")
        .ok()
        .map(|p| Path::new("/").join(p))
        .unwrap_or_else(|| path.to_path_buf())
}

fn compile_glob(pattern: &str) -> Result<GlobMatcher, String> {
    if pattern.trim().is_empty()
        || Path::new(pattern).is_absolute()
        || pattern.split('/').any(|c| c == ".." || c == ".")
    {
        return Err("Glob must be nonempty and relative, without traversal".into());
    }
    GlobBuilder::new(pattern)
        .literal_separator(true)
        .case_insensitive(true)
        .backslash_escape(false)
        .build()
        .map(|g| g.compile_matcher())
        .map_err(|e| e.to_string())
}

pub(crate) fn parent_identities(
    path: &Path,
    ctx: &SafetyContext,
) -> Result<Vec<PathIdentity>, String> {
    let parent = path.parent().ok_or("Missing parent")?;
    let mut ids = Vec::new();
    let mut current = PathBuf::from("/");
    for component in parent.components() {
        if let Component::Normal(part) = component {
            current.push(part);
        }
        let meta =
            fs::symlink_metadata(&current).map_err(|e| format!("{}: {e}", current.display()))?;
        if !meta.is_dir() || meta.file_type().is_symlink() {
            return Err("Symlink or non-directory ancestor".into());
        }
        // Root-owned sticky OS temp ancestors are permitted; the user's concrete
        // scope and every other ancestor must not be shared-writable.
        if !trusted_ancestor(&current, &meta, ctx.uid, None) {
            return Err(format!(
                "Untrusted or shared writable ancestor: {}",
                current.display()
            ));
        }
        ids.push(PathIdentity {
            path: current.clone(),
            device: meta.dev(),
            inode: meta.ino(),
            uid: meta.uid(),
            mode: meta.mode(),
        });
    }
    Ok(ids)
}

// The APFS Data mount itself is commonly root:admin (gid 80) or root:wheel
// (gid 0), mode 0775. These are macOS system group IDs, not arbitrary groups.
// This is NOT a
// general root-owned group-writable exception: require its exact path, owner,
// group, mode and verified native APFS mount identity.
fn ancestor_policy(
    path: &Path,
    uid: u32,
    gid: u32,
    mode: u32,
    current_uid: u32,
    verified_data_mount: bool,
) -> bool {
    if uid != 0 && uid != current_uid {
        return false;
    }
    if mode & 0o022 == 0 || (uid == 0 && mode & 0o1000 != 0) {
        return true;
    }
    path == Path::new("/System/Volumes/Data")
        && uid == 0
        && matches!(gid, 0 | 80) // wheel or macOS admin; exact verified mount only
        && mode & 0o7777 == 0o775
        && verified_data_mount
}

pub(crate) fn trusted_ancestor(
    path: &Path,
    meta: &fs::Metadata,
    uid: u32,
    pinned: Option<&fs::File>,
) -> bool {
    let needs_mount = path == Path::new("/System/Volumes/Data")
        && meta.uid() == 0
        && matches!(meta.gid(), 0 | 80)
        && meta.mode() & 0o7777 == 0o775;
    let verified = needs_mount && verified_data_mount(path, meta, pinned);
    ancestor_policy(path, meta.uid(), meta.gid(), meta.mode(), uid, verified)
}

fn verified_data_mount(path: &Path, meta: &fs::Metadata, pinned: Option<&fs::File>) -> bool {
    #[cfg(target_os = "macos")]
    {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::OpenOptionsExt;
        let opened;
        let file = if let Some(file) = pinned {
            file
        } else {
            opened = match fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(path)
            {
                Ok(file) => file,
                Err(_) => return false,
            };
            &opened
        };
        let current = match file.metadata() {
            Ok(m) => m,
            Err(_) => return false,
        };
        if current.dev() != meta.dev() || current.ino() != meta.ino() {
            return false;
        }
        let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatfs(file.as_raw_fd(), &mut stat) } != 0 {
            return false;
        }
        let field = |chars: &[libc::c_char]| {
            chars
                .iter()
                .take_while(|&&c| c != 0)
                .map(|&c| c as u8)
                .collect::<Vec<_>>()
        };
        field(&stat.f_fstypename) == b"apfs" && field(&stat.f_mntonname) == b"/System/Volumes/Data"
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (path, meta, pinned);
        false
    }
}

pub(crate) fn protected(path: &Path, ctx: &SafetyContext) -> bool {
    let path = equivalent(path);
    if !ctx.in_scope(&path) {
        return true;
    }
    // macOS usually uses a case-insensitive filesystem. Protection must not depend
    // on the spelling supplied by a user rule or a scan alias.
    let policy_path = PathBuf::from(path.to_string_lossy().to_ascii_lowercase());
    let lower_path = |p: &Path| PathBuf::from(equivalent(p).to_string_lossy().to_ascii_lowercase());
    let parts: Vec<String> = path
        .components()
        .map(|c| c.as_os_str().to_string_lossy().to_ascii_lowercase())
        .collect();
    const COMPONENTS: &[&str] = &[
        ".git",
        ".ssh",
        ".gnupg",
        ".aws",
        ".azure",
        ".kube",
        ".config",
        ".trash",
        "keychains",
        "credentials",
        "secrets",
        "documents",
        "desktop",
        "pictures",
        "movies",
        "music",
        "applications",
    ];
    const BUNDLES: &[&str] = &[
        "app",
        "appex",
        "framework",
        "bundle",
        "plugin",
        "xpc",
        "kext",
        "systemextension",
        "dext",
        "qlgenerator",
        "mdimporter",
        "prefpane",
        "saver",
        "component",
        "vst",
        "vst3",
        "aaxplugin",
        "driver",
        "xcarchive",
        "photoslibrary",
        "musiclibrary",
        "fcpbundle",
    ];
    if parts.iter().any(|p| {
        COMPONENTS.contains(&p.as_str())
            || p.starts_with(".env")
            || p.contains("credential")
            || p.contains("token")
            || p.contains("secret")
            || p == ".npmrc"
            || p == ".netrc"
            || p == ".gitconfig"
            || p == "id_rsa"
            || p == "id_ed25519"
            || p.starts_with(".petal-cleanup-")
            || p.rsplit_once('.')
                .is_some_and(|(_, ext)| BUNDLES.contains(&ext))
    }) {
        return true;
    }
    let name = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_ascii_lowercase();
    if [
        "db", "sqlite", "sqlite3", "mdb", "realm", "pem", "key", "p12", "pfx", "doc", "docx",
        "xls", "xlsx", "ppt", "pptx", "pdf", "pages", "numbers", "keynote", "jpg", "jpeg", "png",
        "heic", "mp4", "mov",
    ]
    .iter()
    .any(|ext| name.ends_with(&format!(".{ext}")))
        || name.ends_with("-wal")
        || name.ends_with("-shm")
    {
        return true;
    }
    for category in crate::findings::CATALOG {
        if category.safety == crate::findings::Safety::ManageInApp
            || matches!(
                category.fix,
                crate::findings::Fix::Command(_)
                    | crate::findings::Fix::InApp
                    | crate::findings::Fix::GitGc
            )
        {
            let base = match category.base {
                crate::findings::Base::Home => Some(&ctx.home),
                crate::findings::Base::UserTemp => ctx.temp.as_ref(),
            };
            if base.is_some_and(|b| policy_path.starts_with(lower_path(&b.join(category.path)))) {
                return true;
            }
        }
    }
    [
        "Library/Application Support",
        "Library/Containers",
        "Library/Group Containers",
        "Library/Mail",
        "Library/Messages",
        "Library/Safari",
        "Library/CloudStorage",
        "Library/Mobile Documents",
        ".ollama",
        ".lmstudio",
        ".cache/huggingface",
        ".claude",
        ".codex",
    ]
    .iter()
    .any(|p| policy_path.starts_with(lower_path(&ctx.home.join(p))))
}

fn relative_to(path: &Path, root: &Path) -> Option<PathBuf> {
    let path = equivalent(path);
    let root = equivalent(root);
    path.strip_prefix(root)
        .ok()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
}

fn excluded(path: &Path, settings: &Settings, ctx: &SafetyContext) -> Result<bool, String> {
    for entry in &settings.whitelist {
        let entry = ctx.expand(entry)?;
        let real = if entry.exists() {
            fs::canonicalize(&entry).map_err(|e| e.to_string())?
        } else {
            entry.clone()
        };
        let lower = |p: &Path| PathBuf::from(equivalent(p).to_string_lossy().to_ascii_lowercase());
        if lower(path).starts_with(lower(&entry)) || lower(path).starts_with(lower(&real)) {
            return Ok(true);
        }
    }
    // An exclusion in ANY active overlapping scope wins globally, even if that rule's
    // positive pattern or age doesn't match. Ancestors are checked for directory globs.
    for rule in settings.rules.iter().filter(|r| r.enabled) {
        for root in &rule.roots {
            let root = ctx.expand(root)?;
            // Lexical exclusions also apply to invalid scopes; never follow their symlinks.
            let root = equivalent(&root);
            if let Some(relative) = relative_to(path, &root) {
                for pattern in &rule.exclude {
                    let matcher = compile_glob(pattern)?;
                    if relative
                        .ancestors()
                        .filter(|p| !p.as_os_str().is_empty())
                        .any(|p| matcher.is_match(p))
                    {
                        return Ok(true);
                    }
                }
            }
        }
    }
    Ok(false)
}

pub(crate) fn match_path(
    path: &Path,
    settings: &Settings,
    ctx: &SafetyContext,
    now: SystemTime,
) -> Result<Option<RuleMatch>, String> {
    if protected(path, ctx) || excluded(path, settings, ctx)? {
        return Err("Protected path or global exclusion".into());
    }
    let parents = parent_identities(path, ctx)?;
    let meta = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !meta.is_file()
        || meta.file_type().is_symlink()
        || meta.uid() != ctx.uid
        || meta.nlink() != 1
    {
        return Err("Only current-user regular, single-link files are eligible".into());
    }
    #[cfg(target_os = "macos")]
    if meta.st_flags() & (0x40000000 | 0x2 | 0x4 | 0x20000 | 0x40000) != 0 {
        return Err("Cloud-only, immutable or append-only file".into());
    }
    let age = now
        .duration_since(meta.modified().map_err(|e| e.to_string())?)
        .map_err(|_| "Future modification time")?;
    let mut matches = Vec::new();
    for rule in settings.rules.iter().filter(|r| r.enabled) {
        if let Err(error) = rule.validate_active_in(ctx) {
            // An invalid overlapping rule cannot disappear and weaken another rule.
            if rule.roots.iter().any(|r| {
                ctx.expand(r)
                    .ok()
                    .is_some_and(|r| relative_to(path, &r).is_some())
            }) {
                return Err(format!(
                    "Rule {} has an invalid active scope: {error}",
                    rule.id
                ));
            }
            continue;
        }
        if meta.len() < rule.min_size
            || rule
                .older_than_days
                .is_some_and(|d| age.as_secs() < d.saturating_mul(86400))
        {
            continue;
        }
        let pattern = compile_glob(&rule.pattern)?;
        for root in &rule.roots {
            let root = ctx.expand(root)?;
            let real = match fs::canonicalize(&root) {
                Ok(p) => p,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e.to_string()),
            };
            if let Some(relative) = relative_to(path, &real) {
                if pattern.is_match(relative) {
                    matches.push(rule);
                    break;
                }
            }
        }
    }
    make_match(path, ctx, &meta, parents, age.as_secs(), matches)
}

fn make_match(
    path: &Path,
    ctx: &SafetyContext,
    meta: &fs::Metadata,
    parents: Vec<PathIdentity>,
    age_secs: u64,
    mut matches: Vec<&Rule>,
) -> Result<Option<RuleMatch>, String> {
    matches.sort_by(|a, b| b.priority.cmp(&a.priority).then(a.id.cmp(&b.id)));
    let Some(priority_winner) = matches.first() else {
        return Ok(None);
    };
    let rule = matches
        .iter()
        .find(|r| r.action == CleanupAction::Trash)
        .unwrap_or(priority_winner);
    let action_conflict =
        priority_winner.action == CleanupAction::Permanent && rule.action == CleanupAction::Trash;
    let auto_clean = ctx.auto_root(path)
        && matches.iter().all(|r| {
            r.auto_clean
                && r.source != RuleSource::Ai
                && r.action == CleanupAction::Trash
                && r.older_than_days.unwrap_or(0) >= 7
        });
    Ok(Some(RuleMatch {
        path: path.to_path_buf(),
        rule_id: rule.id.clone(),
        rule_name: rule.name.clone(),
        category: rule.category,
        priority: rule.priority,
        action: rule.action,
        size: meta.len(),
        reason: format!(
            "{}{}; modified {} days ago; {}",
            rule.name,
            if action_conflict {
                "; conflicting Permanent rule overridden by overlapping Trash constraint"
            } else {
                ""
            },
            age_secs / 86400,
            if auto_clean {
                "locally authorized low-risk scope"
            } else {
                "confirmation required"
            }
        ),
        auto_clean,
        fingerprint: FileFingerprint::from_metadata(meta, parents),
        source: rule.source,
        matched_rule_ids: matches.iter().map(|r| r.id.clone()).collect(),
        rule_revision: serde_json::to_string(rule).map_err(|e| e.to_string())?,
    }))
}

const DIAGNOSTIC_LIMIT: usize = 200;
impl Plan {
    fn block(&mut self, message: impl FnOnce() -> String) {
        self.blocked_total = self.blocked_total.saturating_add(1);
        if self.blocked.len() < DIAGNOSTIC_LIMIT {
            self.blocked.push(message());
        }
    }
    fn finish(&mut self) {
        if self.blocked_total > self.blocked.len() as u64 {
            let sampled = self.blocked.len().saturating_sub(1);
            self.blocked.truncate(sampled);
            self.blocked.push(format!(
                "Diagnostics truncated: {sampled} samples of {} blocked entries/scopes",
                self.blocked_total
            ));
        }
    }
    fn cancelled(&mut self) {
        self.items.clear(); // Never return executable partial work after cancellation.
        self.errors
            .push("cancelled: rule evaluation did not complete".into());
        self.finish();
    }
}

struct CompiledRule<'a> {
    rule: &'a Rule,
    roots: Vec<PathBuf>,
    pattern: GlobMatcher,
    exclude: Vec<GlobMatcher>,
    invalid: Option<String>,
}
struct PreviewPolicy<'a> {
    rules: Vec<CompiledRule<'a>>,
    whitelist: Vec<PathBuf>,
    unreadable: Vec<PathBuf>,
    parents: HashMap<PathBuf, Result<Vec<PathIdentity>, String>>,
}
impl<'a> PreviewPolicy<'a> {
    fn compile(
        settings: &'a Settings,
        tree: &Tree,
        ctx: &SafetyContext,
        cancel: &AtomicBool,
        plan: &mut Plan,
    ) -> Result<Self, String> {
        if cancel.load(Ordering::Acquire) {
            return Err("cancelled".into());
        }
        settings.validate_in(ctx)?;
        let mut rules = Vec::new();
        for rule in settings.rules.iter().filter(|r| r.enabled) {
            if cancel.load(Ordering::Acquire) {
                return Err("cancelled".into());
            }
            // Settings already passed static schema validation above.
            let mut invalid = rule.validate_scope_in(ctx).err();
            if let Some(error) = &invalid {
                // Missing optional scopes and invalid active scopes are local diagnostics,
                // not global scan errors. Overlap still vetoes the affected path below.
                plan.block(|| format!("Rule {} unavailable: {error}", rule.id));
            }
            let mut roots = Vec::new();
            for root in &rule.roots {
                if cancel.load(Ordering::Acquire) {
                    return Err("cancelled".into());
                }
                let root = ctx.expand(root)?;
                roots.push(equivalent(&root));
                if invalid.is_none() {
                    match fs::canonicalize(&root) {
                        Ok(real) => {
                            let real = equivalent(&real);
                            if !roots.contains(&real) {
                                roots.push(real);
                            }
                        }
                        Err(e) => {
                            invalid = Some(format!("Scope changed during preparation: {e}"));
                            plan.block(|| format!("Rule {} unavailable: {e}", rule.id));
                        }
                    }
                }
            }
            #[cfg(test)]
            {
                plan.rule_compilations += 1;
            }
            rules.push(CompiledRule {
                rule,
                roots,
                pattern: compile_glob(&rule.pattern)?,
                exclude: rule
                    .exclude
                    .iter()
                    .map(|p| compile_glob(p))
                    .collect::<Result<_, _>>()?,
                invalid,
            });
        }
        let mut whitelist = Vec::new();
        for entry in &settings.whitelist {
            if cancel.load(Ordering::Acquire) {
                return Err("cancelled".into());
            }
            let entry = ctx.expand(entry)?;
            whitelist.push(lower_policy_path(&entry));
            match fs::canonicalize(&entry) {
                Ok(real) => whitelist.push(lower_policy_path(&real)),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(format!("Cannot resolve global whitelist: {e}")),
            }
        }
        Ok(Self {
            rules,
            whitelist,
            unreadable: tree
                .unreadable
                .iter()
                .map(|u| equivalent(&u.path))
                .collect(),
            parents: HashMap::new(),
        })
    }

    fn match_file(
        &mut self,
        path: &Path,
        ctx: &SafetyContext,
        now: SystemTime,
        plan: &mut Plan,
    ) -> Result<Option<RuleMatch>, String> {
        // No stat, canonicalize, protection walk or glob compilation for out-of-scope files.
        let operation_path = path;
        let path = equivalent(path);
        let candidates: Vec<_> = self
            .rules
            .iter()
            .enumerate()
            .filter(|(_, r)| {
                r.roots
                    .iter()
                    .any(|root| path.starts_with(root) && path != *root)
            })
            .map(|(ix, _)| ix)
            .collect();
        if candidates.is_empty() {
            return Ok(None);
        }
        if protected(&path, ctx)
            || self
                .whitelist
                .iter()
                .any(|p| lower_policy_path(&path).starts_with(p))
            || self.unreadable.iter().any(|p| path.starts_with(p))
        {
            return Err("Protected, whitelisted or unreadable path".into());
        }
        for &index in &candidates {
            let compiled = &self.rules[index];
            if let Some(error) = &compiled.invalid {
                return Err(format!(
                    "Invalid overlapping rule {}: {error}",
                    compiled.rule.id
                ));
            }
            for root in &compiled.roots {
                if let Ok(relative) = path.strip_prefix(root) {
                    if compiled.exclude.iter().any(|glob| {
                        relative
                            .ancestors()
                            .filter(|p| !p.as_os_str().is_empty())
                            .any(|p| glob.is_match(p))
                    }) {
                        return Err("Global overlapping exclusion".into());
                    }
                }
            }
        }
        // Keep operation paths as scanned, not their equivalent policy aliases.
        // The caller passes the original path to the filesystem phase below.
        self.match_metadata(operation_path, ctx, now, &candidates, plan)
    }

    fn match_metadata(
        &mut self,
        path: &Path,
        ctx: &SafetyContext,
        now: SystemTime,
        candidate_indices: &[usize],
        plan: &mut Plan,
    ) -> Result<Option<RuleMatch>, String> {
        let parent = path.parent().ok_or("Missing parent")?.to_path_buf();
        #[cfg(test)]
        {
            if !self.parents.contains_key(&parent) {
                plan.parent_cache_misses += 1;
            }
        }
        let parents = self
            .parents
            .entry(parent)
            .or_insert_with(|| parent_identities(path, ctx))
            .clone()?;
        #[cfg(test)]
        {
            plan.metadata_reads += 1;
        }
        #[cfg(not(test))]
        let _ = plan;
        let meta = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
        if !meta.is_file()
            || meta.file_type().is_symlink()
            || meta.uid() != ctx.uid
            || meta.nlink() != 1
        {
            return Err("Only current-user ordinary single-link files are eligible".into());
        }
        if file_flags(&meta) & (0x40000000 | 0x2 | 0x4 | 0x20000 | 0x40000) != 0 {
            return Err("Cloud-only or protected file flags".into());
        }
        let age = now
            .duration_since(meta.modified().map_err(|e| e.to_string())?)
            .map_err(|_| "Future modification time")?
            .as_secs();
        let policy_path = equivalent(path);
        let matches = candidate_indices
            .iter()
            .map(|&ix| &self.rules[ix])
            .filter(|r| {
                meta.len() >= r.rule.min_size
                    && r.rule
                        .older_than_days
                        .is_none_or(|d| age >= d.saturating_mul(86400))
                    && r.roots.iter().any(|root| {
                        policy_path
                            .strip_prefix(root)
                            .ok()
                            .is_some_and(|relative| r.pattern.is_match(relative))
                    })
            })
            .map(|r| r.rule)
            .collect();
        make_match(path, ctx, &meta, parents, age, matches)
    }
}
fn lower_policy_path(path: &Path) -> PathBuf {
    PathBuf::from(equivalent(path).to_string_lossy().to_ascii_lowercase())
}

pub fn evaluate_cancellable(tree: &Tree, settings: &Settings, cancel: &AtomicBool) -> Plan {
    if cancel.load(Ordering::Acquire) {
        let mut plan = Plan::default();
        plan.cancelled();
        return plan;
    }
    let ctx = match SafetyContext::current() {
        Ok(ctx) => ctx,
        Err(e) => {
            return Plan {
                errors: vec![e],
                ..Plan::default()
            };
        }
    };
    evaluate_controlled(tree, settings, &ctx, cancel)
}
#[cfg(test)]
fn evaluate_in(tree: &Tree, settings: &Settings, ctx: &SafetyContext) -> Plan {
    evaluate_controlled(tree, settings, ctx, &AtomicBool::new(false))
}
fn evaluate_controlled(
    tree: &Tree,
    settings: &Settings,
    ctx: &SafetyContext,
    cancel: &AtomicBool,
) -> Plan {
    evaluate_with_checkpoint(tree, settings, ctx, cancel, &mut || {})
}
fn evaluate_with_checkpoint(
    tree: &Tree,
    settings: &Settings,
    ctx: &SafetyContext,
    cancel: &AtomicBool,
    checkpoint: &mut dyn FnMut(),
) -> Plan {
    let mut plan = Plan::default();
    if cancel.load(Ordering::Acquire) {
        plan.cancelled();
        return plan;
    }
    let mut policy = match PreviewPolicy::compile(settings, tree, ctx, cancel, &mut plan) {
        Ok(policy) => policy,
        Err(e) => {
            if cancel.load(Ordering::Acquire) {
                plan.cancelled();
            } else {
                plan.errors.push(e);
            }
            return plan;
        }
    };
    if tree.errors > 0 {
        plan.errors.push(format!(
            "Scan has {} errors; automatic cleanup disabled",
            tree.errors
        ));
    }
    if tree.cloud_only > 0 {
        plan.errors.push(format!(
            "Scan skipped {} cloud-only entries; automatic cleanup disabled",
            tree.cloud_only
        ));
    }
    let now = SystemTime::now();
    let mut visited = vec![false; tree.nodes.len()];
    let mut identities = HashSet::new();
    // One path stack and one child cursor per depth: no full-tree path allocation,
    // no per-file siblings.contains(), no recursive Rust call-stack growth.
    let mut path = tree.root_path.clone();
    let mut stack = Vec::new();
    if let Some(root) = tree.nodes.first() {
        if root.kind == Kind::Dir && root.parent.is_none() {
            visited[0] = true;
            stack.push((0usize, 0usize));
        } else if root.kind == Kind::File && root.parent.is_none() {
            visited[0] = true;
            preview_file(
                &path,
                &mut policy,
                ctx,
                now,
                tree,
                &mut identities,
                &mut plan,
            );
        }
    }
    while let Some((ix, next)) = stack.last_mut() {
        checkpoint();
        if cancel.load(Ordering::Acquire) {
            plan.cancelled();
            return plan;
        }
        let node = &tree.nodes[*ix];
        if *next == node.children.len() {
            stack.pop();
            if !stack.is_empty() {
                path.pop();
            }
            continue;
        }
        let child_ix = node.children[*next];
        *next += 1;
        #[cfg(test)]
        {
            plan.visited_edges += 1;
        }
        let Some(child) = tree.nodes.get(child_ix) else {
            plan.block(|| format!("Invalid child index {child_ix}"));
            continue;
        };
        if visited[child_ix] || child.parent != Some(*ix) {
            plan.block(|| format!("Detached/cyclic child {child_ix}"));
            continue;
        }
        let name = Path::new(child.name.as_ref());
        if name.components().count() != 1
            || !matches!(name.components().next(), Some(Component::Normal(_)))
        {
            plan.block(|| format!("Invalid scan name at {child_ix}"));
            continue;
        }
        visited[child_ix] = true;
        path.push(name);
        match child.kind {
            Kind::Dir => stack.push((child_ix, 0)),
            Kind::File => {
                preview_file(
                    &path,
                    &mut policy,
                    ctx,
                    now,
                    tree,
                    &mut identities,
                    &mut plan,
                );
                path.pop();
            }
            Kind::Other => {
                plan.skipped_total += 1;
                path.pop();
            }
        }
    }
    for (ix, node) in tree.nodes.iter().enumerate() {
        if cancel.load(Ordering::Acquire) {
            plan.cancelled();
            return plan;
        }
        if !visited[ix] && node.kind == Kind::File {
            plan.block(|| format!("Detached or synthetic scan node: {ix}"));
        }
    }
    if cancel.load(Ordering::Acquire) {
        plan.cancelled();
        return plan;
    }
    plan.items
        .sort_by(|a, b| b.priority.cmp(&a.priority).then(a.path.cmp(&b.path)));
    if cancel.load(Ordering::Acquire) {
        plan.cancelled();
        return plan;
    }
    plan.finish();
    plan
}
fn preview_file(
    path: &Path,
    policy: &mut PreviewPolicy<'_>,
    ctx: &SafetyContext,
    now: SystemTime,
    tree: &Tree,
    identities: &mut HashSet<(u64, u64)>,
    plan: &mut Plan,
) {
    match policy.match_file(path, ctx, now, plan) {
        Ok(Some(mut item)) => {
            if tree.errors > 0 || tree.cloud_only > 0 {
                item.auto_clean = false;
            }
            if identities.insert((item.fingerprint.device, item.fingerprint.inode)) {
                plan.items.push(item);
            } else {
                plan.skipped_total += 1;
            }
        }
        Ok(None) => plan.skipped_total += 1,
        Err(error) => plan.block(|| format!("{}: {error}", path.display())),
    }
}

pub fn built_in_rules() -> Vec<Rule> {
    let Ok(ctx) = SafetyContext::current() else {
        return Vec::new();
    };
    built_ins_in(&ctx)
}

fn built_ins_in(ctx: &SafetyContext) -> Vec<Rule> {
    let definitions = [
        (
            "app-caches",
            "Old app cache files",
            CleanupCategory::Cache,
            "Library/Caches",
            "**/*",
            7,
        ),
        (
            "app-logs",
            "Old application logs",
            CleanupCategory::Logs,
            "Library/Logs",
            "**/*.log",
            7,
        ),
        (
            "xcode-derived",
            "Xcode derived build files",
            CleanupCategory::Build,
            "Library/Developer/Xcode/DerivedData",
            "**/*",
            30,
        ),
        (
            "download-installers",
            "Old downloaded installers (review)",
            CleanupCategory::Downloads,
            "Downloads",
            "*.{dmg,pkg,mpkg}",
            30,
        ),
        (
            "npm-cache",
            "npm content cache",
            CleanupCategory::Cache,
            ".npm/_cacache",
            "**/*",
            7,
        ),
        (
            "old-log-backups",
            "Rotated log backups (review)",
            CleanupCategory::Backup,
            "Library/Logs",
            "**/*.{gz,bak,old}",
            30,
        ),
    ];
    let mut rules: Vec<Rule> = definitions.into_iter().map(|(id, name, category, root, pattern, days)| Rule {
        id: id.into(), name: name.into(), description: "Individual ordinary files only; review before moving to Trash. Size is not a promise of freed space.".into(),
        category, roots: vec![ctx.home.join(root)], pattern: pattern.into(), exclude: vec![], min_size: 0, older_than_days: Some(days), priority: 0,
        enabled: true, auto_clean: false, action: CleanupAction::Trash, source: RuleSource::BuiltIn,
    }).collect();
    if let Some(temp) = &ctx.temp {
        rules.push(Rule {
            id: "user-temp".into(),
            name: "Old user temporary files (review)".into(),
            description: "Actual Darwin per-user temporary scope, never /tmp; ordinary files only"
                .into(),
            category: CleanupCategory::Temporary,
            roots: vec![temp.clone()],
            pattern: "**/*".into(),
            exclude: vec![],
            min_size: 0,
            older_than_days: Some(7),
            priority: 0,
            enabled: true,
            auto_clean: false,
            action: CleanupAction::Trash,
            source: RuleSource::BuiltIn,
        });
    }
    rules
}

#[cfg(test)]
pub(crate) mod fixtures {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    pub struct Fixture {
        pub dir: PathBuf,
        pub ctx: SafetyContext,
    }
    impl Fixture {
        pub fn new() -> Self {
            use std::os::unix::fs::PermissionsExt;
            // Canonicalizing the OS temporary base avoids /var symlink aliases. No global env changes.
            let base = fs::canonicalize(std::env::temp_dir()).unwrap();
            let dir = base.join(format!(
                "petal-rules-{}-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&dir).unwrap();
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
            let home = dir.join("home");
            fs::create_dir(&home).unwrap();
            let ctx = SafetyContext {
                home,
                temp: None,
                uid: unsafe { libc::geteuid() },
            };
            Self { dir, ctx }
        }
        pub fn file(&self, relative: &str, age_days: u64) -> PathBuf {
            let path = self.ctx.home.join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, b"fixture data").unwrap();
            let file = fs::File::options().write(true).open(&path).unwrap();
            let time = SystemTime::now() - std::time::Duration::from_secs(age_days * 86400 + 10);
            file.set_times(fs::FileTimes::new().set_modified(time))
                .unwrap();
            path
        }
        pub fn settings(&self) -> Settings {
            Settings {
                version: crate::settings::SETTINGS_VERSION,
                rules: built_ins_in(&self.ctx),
                whitelist: vec![],
                default_action: CleanupAction::Trash,
                automation_enabled: false,
                automation_interval_minutes: 60,
                agent: crate::agent::AgentConfig::default(),
                language: None,
            }
        }
        pub fn tree(&self, path: &Path) -> Tree {
            use crate::scan::Node;
            let relative = path.strip_prefix(&self.ctx.home).unwrap();
            let mut nodes = vec![Node {
                name: "home".into(),
                size: 0,
                kind: Kind::Dir,
                parent: None,
                children: vec![],
                items: 0,
            }];
            let count = relative.components().count();
            for (i, part) in relative.components().enumerate() {
                nodes[i].children.push(i + 1);
                nodes.push(Node {
                    name: part.as_os_str().to_string_lossy().into_owned().into(),
                    size: 12,
                    kind: if i + 1 == count {
                        Kind::File
                    } else {
                        Kind::Dir
                    },
                    parent: Some(i),
                    children: vec![],
                    items: 1,
                });
            }
            Tree {
                root_path: self.ctx.home.clone(),
                nodes,
                ..Tree::default()
            }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fixtures::Fixture;
    #[test]
    fn validation_rejects_dangerous_scopes_and_globs() {
        let f = Fixture::new();
        let mut rule = f.settings().rules.remove(0);
        for path in [
            PathBuf::from("/"),
            f.ctx.home.clone(),
            f.ctx.home.join("Library/../Caches"),
            PathBuf::from("relative"),
        ] {
            rule.roots = vec![path];
            assert!(rule.validate_in(&f.ctx).is_err());
        }
        rule.roots = vec![PathBuf::from("~/Library/Caches")];
        for pattern in ["", "[", "../*", "/**"] {
            rule.pattern = pattern.into();
            assert!(rule.validate_in(&f.ctx).is_err());
        }
        rule.pattern = "**/*".into();
        assert!(rule.validate_in(&f.ctx).is_ok());
    }
    #[test]
    fn automation_is_local_policy_not_category_or_source() {
        let f = Fixture::new();
        let mut rule = f.settings().rules.remove(0);
        rule.auto_clean = true;
        assert!(rule.validate_in(&f.ctx).is_ok());
        rule.source = RuleSource::Ai;
        assert!(rule.validate_in(&f.ctx).is_err());
        rule.source = RuleSource::User;
        rule.action = CleanupAction::Permanent;
        assert!(rule.validate_in(&f.ctx).is_err());
        rule.action = CleanupAction::Trash;
        rule.older_than_days = Some(6);
        assert!(rule.validate_in(&f.ctx).is_err());
        rule.older_than_days = Some(7);
        rule.roots = vec![f.ctx.home.join("Downloads")];
        assert!(rule.validate_in(&f.ctx).is_err());
    }
    #[test]
    fn priority_never_overrides_review_or_global_exclusions() {
        let f = Fixture::new();
        let path = f.file("Library/Caches/app/old", 8);
        let mut s = f.settings();
        let mut auto = s.rules[0].clone();
        auto.id = "auto".into();
        auto.auto_clean = true;
        auto.priority = 100;
        s.rules.push(auto);
        let plan = evaluate_in(&f.tree(&path), &s, &f.ctx);
        assert_eq!(plan.items.len(), 1);
        assert_eq!(plan.items[0].rule_id, "auto");
        assert!(!plan.items[0].auto_clean);
        s.rules[0].exclude.push("app".into());
        assert!(evaluate_in(&f.tree(&path), &s, &f.ctx).items.is_empty());
        s.rules[0].exclude.clear();
        s.whitelist.push(path.parent().unwrap().to_path_buf());
        assert!(evaluate_in(&f.tree(&path), &s, &f.ctx).items.is_empty());
    }
    #[test]
    fn protects_credentials_databases_bundles_and_personal_data() {
        let f = Fixture::new();
        for relative in [
            "Library/Caches/a/.git/data",
            "Library/Caches/a/key.pem",
            "Library/Caches/a/db.sqlite",
            "Library/Caches/a/db.sqlite-wal",
            "Library/Caches/a/Thing.app/data",
            "Documents/data",
            ".codex/sessions/data",
            "Library/Caches/Homebrew/data",
            "Library/Caches/homebrew/data",
            "library/application support/private/data",
            "Library/Caches/a/token",
            "Library/Caches/a/image.png",
        ] {
            assert!(protected(&f.ctx.home.join(relative), &f.ctx), "{relative}");
        }
    }
    #[test]
    fn metadata_age_symlinks_hardlinks_and_detached_nodes() {
        let f = Fixture::new();
        let path = f.file("Library/Caches/app/old", 8);
        let s = f.settings();
        assert_eq!(evaluate_in(&f.tree(&path), &s, &f.ctx).items.len(), 1);
        let fresh = f.file("Library/Caches/app/new", 0);
        assert!(evaluate_in(&f.tree(&fresh), &s, &f.ctx).items.is_empty());
        let link = path.with_file_name("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(evaluate_in(&f.tree(&link), &s, &f.ctx).items.is_empty());
        fs::hard_link(&path, path.with_file_name("hard")).unwrap();
        assert!(evaluate_in(&f.tree(&path), &s, &f.ctx).items.is_empty());
        fs::remove_file(path.with_file_name("hard")).unwrap();
        let mut tree = f.tree(&path);
        let last = tree.nodes.len() - 1;
        tree.nodes[last].parent = None;
        assert!(evaluate_in(&tree, &s, &f.ctx).items.is_empty());
    }
    #[test]
    fn scan_errors_disable_auto_and_data_volume_paths_match() {
        let f = Fixture::new();
        let path = f.file("Library/Caches/app/old", 8);
        let mut s = f.settings();
        s.rules[0].auto_clean = true;
        let mut tree = f.tree(&path);
        assert!(evaluate_in(&tree, &s, &f.ctx).items[0].auto_clean);
        tree.errors = 1;
        assert!(!evaluate_in(&tree, &s, &f.ctx).items[0].auto_clean);
        tree.errors = 0;
        tree.unreadable.push(crate::scan::Unreadable {
            path: path.parent().unwrap().into(),
            whole: false,
            errors: 1,
        });
        assert!(evaluate_in(&tree, &s, &f.ctx).items.is_empty());
        assert_eq!(
            relative_to(
                Path::new("/System/Volumes/Data/Users/a/Library/Caches/x"),
                Path::new("/Users/a/Library/Caches")
            ),
            Some(PathBuf::from("x"))
        );
    }
    #[test]
    fn data_mount_exception_is_exact_and_requires_verified_identity() {
        let path = Path::new("/System/Volumes/Data");
        assert!(ancestor_policy(
            path,
            0,
            0,
            u32::from(libc::S_IFDIR) | 0o775,
            501,
            true
        ));
        assert!(ancestor_policy(
            path,
            0,
            80,
            u32::from(libc::S_IFDIR) | 0o775,
            501,
            true
        ));
        assert!(!ancestor_policy(path, 0, 80, 0o775, 501, false));
        assert!(!ancestor_policy(
            Path::new("/System/Volumes/Data/Users"),
            0,
            80,
            0o775,
            501,
            true
        ));
        for (p, uid, gid, mode, verified) in [
            (path, 0, 0, 0o775, false),
            (Path::new("/System/Volumes/Data/Users"), 0, 0, 0o775, true),
            (Path::new("/somewhere/Data"), 0, 0, 0o775, true),
            (path, 501, 0, 0o775, true),
            (path, 0, 20, 0o775, true),
            (path, 0, 0, 0o777, true),
        ] {
            assert!(!ancestor_policy(p, uid, gid, mode, 501, verified));
        }
        assert_eq!(
            equivalent(&path.join("Users/test/Library/Caches")),
            PathBuf::from("/Users/test/Library/Caches")
        );
    }

    #[test]
    fn disabled_symlink_loads_and_active_invalid_scope_does_not_block_unrelated_rule() {
        let f = Fixture::new();
        let path = f.file("Library/Caches/app/old", 8);
        let mut settings = f.settings();
        settings
            .rules
            .retain(|r| r.id == "app-caches" || r.id == "download-installers");
        let downloads = f.ctx.home.join("Downloads");
        std::os::unix::fs::symlink(f.dir.join("outside-home"), &downloads).unwrap();
        settings.rules[1].enabled = false;
        assert!(settings.validate_in(&f.ctx).is_ok());
        let plan = evaluate_in(&f.tree(&path), &settings, &f.ctx);
        assert!(plan.errors.is_empty());
        assert_eq!(plan.items.len(), 1);
        settings.rules[1].enabled = true;
        assert!(settings.validate_in(&f.ctx).is_ok());
        let plan = evaluate_in(&f.tree(&path), &settings, &f.ctx);
        assert!(plan.errors.is_empty());
        assert!(
            plan.blocked
                .iter()
                .any(|e| e.contains("download-installers"))
        );
        assert_eq!(plan.items.len(), 1);
        assert!(settings.rules[1].validate_active_in(&f.ctx).is_err());
        // A broken scope overlapping an otherwise good cache rule remains a veto.
        let mut broken = settings.rules[0].clone();
        broken.id = "broken-overlap".into();
        broken.roots.push(f.ctx.home.join("missing-root"));
        settings.rules.push(broken);
        let plan = evaluate_in(&f.tree(&path), &settings, &f.ctx);
        assert!(plan.items.is_empty());
        assert!(plan.errors.is_empty());
        assert!(plan.blocked.iter().any(|e| e.contains("broken-overlap")));
        settings.rules.pop();
        settings.rules[1].roots = vec![f.ctx.home.join("not-created")];
        settings.rules[1].enabled = false;
        assert!(settings.validate_in(&f.ctx).is_ok());
        settings.rules[1].roots = vec![f.ctx.home.clone()];
        assert!(settings.validate_in(&f.ctx).is_err());
    }

    fn flat_tree(root: PathBuf, count: usize) -> Tree {
        use crate::scan::Node;
        let mut nodes = Vec::with_capacity(count + 1);
        nodes.push(Node {
            name: "root".into(),
            kind: Kind::Dir,
            size: 0,
            items: count as u64,
            parent: None,
            children: (1..=count).collect(),
        });
        for ix in 1..=count {
            nodes.push(Node {
                name: format!("file-{ix}").into(),
                kind: Kind::File,
                size: 1,
                items: 1,
                parent: Some(0),
                children: vec![],
            });
        }
        Tree {
            root_path: root,
            nodes,
            ..Tree::default()
        }
    }

    #[test]
    fn flat_30000_out_of_scope_is_linear_and_has_zero_file_io() {
        let f = Fixture::new();
        let settings = f.settings();
        let tree = flat_tree(f.ctx.home.join("unrelated-not-created"), 30000);
        let plan = evaluate_in(&tree, &settings, &f.ctx);
        assert!(plan.errors.is_empty());
        assert!(plan.items.is_empty());
        assert_eq!(plan.visited_edges, 30000);
        assert_eq!(plan.metadata_reads, 0);
        assert_eq!(plan.parent_cache_misses, 0);
        assert_eq!(plan.skipped_total, 30000);
        assert_eq!(
            plan.rule_compilations,
            settings.rules.iter().filter(|r| r.enabled).count() as u64
        );
        assert!(plan.blocked.len() <= DIAGNOSTIC_LIMIT);
    }

    #[test]
    fn diagnostics_bounded_and_parent_identity_cached_once_per_directory() {
        let f = Fixture::new();
        let path = f.file("Library/Caches/app/old", 8);
        let mut settings = f.settings();
        settings.rules.retain(|r| r.id == "app-caches");
        let tree = flat_tree(path.parent().unwrap().to_path_buf(), 30000);
        let plan = evaluate_in(&tree, &settings, &f.ctx);
        assert!(plan.errors.is_empty());
        assert_eq!(plan.visited_edges, 30000);
        assert_eq!(plan.metadata_reads, 30000);
        assert_eq!(plan.parent_cache_misses, 1);
        assert_eq!(plan.rule_compilations, 1);
        assert_eq!(plan.blocked_total, 30000);
        assert_eq!(plan.blocked.len(), DIAGNOSTIC_LIMIT);
        assert!(plan.blocked.last().unwrap().contains("truncated"));
    }

    #[test]
    fn missing_default_scopes_are_local_and_do_not_disable_unrelated_auto() {
        let f = Fixture::new();
        let path = f.file("Library/Caches/app/old", 8);
        let mut settings = f.settings();
        settings.rules[0].auto_clean = true;
        let plan = evaluate_in(&f.tree(&path), &settings, &f.ctx);
        assert!(plan.errors.is_empty());
        assert_eq!(plan.items.len(), 1);
        assert!(plan.items[0].auto_clean);
        assert!(plan.blocked.iter().any(|e| e.contains("npm-cache")));
        assert!(plan.blocked.iter().any(|e| e.contains("xcode-derived")));
        // Fast preview and independent execution matcher must agree on identity/policy.
        let current = match_path(&path, &settings, &f.ctx, SystemTime::now())
            .unwrap()
            .unwrap();
        assert_eq!(plan.items[0].fingerprint, current.fingerprint);
        assert_eq!(plan.items[0].rule_revision, current.rule_revision);
    }

    #[test]
    fn evaluation_cancels_during_flat_walk_without_partial_items_or_io() {
        let f = Fixture::new();
        let tree = flat_tree(f.ctx.home.join("unrelated"), 30000);
        let settings = f.settings();
        let cancel = AtomicBool::new(false);
        let mut checkpoints = 0;
        let plan = evaluate_with_checkpoint(&tree, &settings, &f.ctx, &cancel, &mut || {
            checkpoints += 1;
            if checkpoints == 25 {
                cancel.store(true, Ordering::Release);
            }
        });
        assert!(plan.items.is_empty());
        assert!(plan.errors.iter().any(|e| e.contains("cancelled")));
        assert!(plan.visited_edges < 25);
        assert_eq!(plan.metadata_reads, 0);
        let plan = evaluate_controlled(&tree, &settings, &f.ctx, &cancel);
        assert_eq!(plan.rule_compilations, 0);
        assert_eq!(plan.visited_edges, 0);
    }

    #[test]
    fn overlap_permanent_priority_never_upgrades_trash_constraint() {
        let f = Fixture::new();
        let path = f.file("Library/Caches/app/old", 8);
        let mut settings = f.settings();
        settings.rules.retain(|r| r.id == "app-caches");
        let mut permanent = settings.rules[0].clone();
        permanent.id = "permanent".into();
        permanent.action = CleanupAction::Permanent;
        permanent.priority = 100;
        settings.rules.push(permanent);
        let item = match_path(&path, &settings, &f.ctx, SystemTime::now())
            .unwrap()
            .unwrap();
        assert_eq!(item.action, CleanupAction::Trash);
        assert_eq!(item.rule_id, "app-caches");
        assert!(item.reason.contains("conflicting Permanent"));
        assert_eq!(item.matched_rule_ids, vec!["permanent", "app-caches"]);
        assert_eq!(
            item.rule_revision,
            serde_json::to_string(&settings.rules[0]).unwrap()
        );
        settings.rules[0].enabled = false;
        let item = match_path(&path, &settings, &f.ctx, SystemTime::now())
            .unwrap()
            .unwrap();
        assert_eq!(item.action, CleanupAction::Permanent);
    }

    #[test]
    fn fingerprints_detect_replacement_and_modification() {
        let f = Fixture::new();
        let path = f.file("Library/Caches/app/old", 8);
        let s = f.settings();
        let item = match_path(&path, &s, &f.ctx, SystemTime::now())
            .unwrap()
            .unwrap();
        fs::write(&path, b"changed").unwrap();
        assert!(
            !item
                .fingerprint
                .same_file(&fs::symlink_metadata(&path).unwrap())
        );
    }
}
