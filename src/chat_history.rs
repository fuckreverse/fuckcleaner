//! Local, display-only conversation history. Never automatically upload this archive.
//! User-entered text may be sensitive: storage uses private directories and 0600 files.
//! No agent context, scan authorization, configuration or credentials are persisted.
//! The parent owns mutations and must serialize asynchronous saves of cloned snapshots;
//! after a load error it must not save until the user explicitly resolves the error.

use std::collections::HashSet;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::settings::{
    open_private_at, private_dir, rename_at, state_path, unique_name, unlink_at,
};

pub const ARCHIVE_VERSION: u32 = 1;
pub const MAX_SESSIONS: usize = 100;
pub const MAX_ENTRIES: usize = 200;
pub const MAX_TEXT_BYTES: usize = 64 * 1024;
pub const MAX_FILE_BYTES: usize = 8 * 1024 * 1024;
const MAX_TITLE_BYTES: usize = 256;
const MAX_ID_BYTES: usize = 128;
pub(crate) const MAX_PROPOSALS: usize = 20;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChatStatus {
    Pending,
    Complete,
    Failed,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProposalDecision {
    Pending,
    Adopted,
    Rejected,
    Expired,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredProposal {
    pub rule: crate::rules::Rule,
    pub decision: ProposalDecision,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChatEntry {
    pub id: String,
    pub role: crate::agent::ChatRole,
    pub content: String,
    pub status: ChatStatus,
    pub detail: String,
    pub proposals: Vec<StoredProposal>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChatSession {
    pub id: String,
    pub title: String,
    pub created_at: u64,
    pub updated_at: u64,
    pub messages: Vec<ChatEntry>,
}

impl ChatSession {
    /// Creates an empty session with a trimmed, single-line, bounded display title.
    /// Explicit field edits and deserialized titles are validated, not silently fixed.
    pub fn new(title: String) -> Self {
        let mut title: String = title
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .chars()
            .filter(|c| !c.is_control())
            .collect();
        while title.len() > MAX_TITLE_BYTES {
            title.pop();
        }
        let title = title.trim().to_owned();
        let now = timestamp();
        Self {
            id: new_id(),
            title: if title.is_empty() {
                "New conversation".into()
            } else {
                title
            },
            created_at: now,
            updated_at: now,
            messages: Vec::new(),
        }
    }

    /// Local Unicode-lowercase substring search over title, content, detail and proposals.
    /// Empty/whitespace queries match every session. No network or filesystem access.
    pub fn matches_query(&self, query: &str) -> bool {
        let query = query.trim().to_lowercase();
        self.title.to_lowercase().contains(&query)
            || self.messages.iter().any(|entry| {
                entry.content.to_lowercase().contains(&query)
                    || entry.detail.to_lowercase().contains(&query)
                    || entry.proposals.iter().any(|proposal| {
                        let rule = &proposal.rule;
                        [&rule.id, &rule.name, &rule.description, &rule.pattern]
                            .iter()
                            .any(|text| text.to_lowercase().contains(&query))
                            || rule
                                .exclude
                                .iter()
                                .any(|text| text.to_lowercase().contains(&query))
                            || rule
                                .roots
                                .iter()
                                .any(|path| path.to_string_lossy().to_lowercase().contains(&query))
                    })
            })
    }
}

pub fn timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn new_id() -> String {
    // unique_name uses process ID, nanoseconds and an atomic counter, without I/O.
    unique_name("chat-").to_string_lossy().into_owned()
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChatArchive {
    pub version: u32,
    pub sessions: Vec<ChatSession>,
}

impl Default for ChatArchive {
    fn default() -> Self {
        Self {
            version: ARCHIVE_VERSION,
            sessions: Vec::new(),
        }
    }
}

impl ChatArchive {
    pub fn load() -> Result<Self, String> {
        Self::load_from(&state_path("ai-conversations.json")?)
    }

    pub fn save(&self) -> Result<(), String> {
        self.save_to(&state_path("ai-conversations.json")?)
    }

    /// Strict validation; unlike saving, does not evict sessions to satisfy limits.
    pub fn validate(&self) -> Result<(), String> {
        self.validate_fields()?;
        if self.sessions.len() > MAX_SESSIONS {
            return Err("History exceeds 100 sessions".into());
        }
        bounded_json(self, MAX_FILE_BYTES)?;
        Ok(())
    }

    fn validate_fields(&self) -> Result<(), String> {
        if self.version != ARCHIVE_VERSION {
            return Err(format!(
                "Unsupported history version {}; expected {ARCHIVE_VERSION}",
                self.version
            ));
        }
        let mut ids = HashSet::new();
        for session in &self.sessions {
            validate_id(&session.id, &mut ids)?;
            if session.title.trim().is_empty()
                || session.title.len() > MAX_TITLE_BYTES
                || session.title.chars().any(char::is_control)
            {
                return Err(
                    "History title must be nonempty, single-line and at most 256 bytes".into(),
                );
            }
            if session.updated_at < session.created_at {
                return Err("History update time precedes creation time".into());
            }
            if session.messages.len() > MAX_ENTRIES {
                return Err(
                    "History session exceeds 200 entries; no messages were truncated".into(),
                );
            }
            for entry in &session.messages {
                validate_id(&entry.id, &mut ids)?;
                if entry.content.len().saturating_add(entry.detail.len()) > MAX_TEXT_BYTES {
                    return Err(
                        "History entry text exceeds 64 KiB; no message was truncated".into(),
                    );
                }
                if entry.proposals.len() > MAX_PROPOSALS {
                    return Err("History entry exceeds 20 proposals".into());
                }
                // Bound all rule strings, paths and collections together, without probing
                // their paths or calling Rule::validate / SafetyContext::current.
                bounded_json(&entry.proposals, MAX_TEXT_BYTES)?;
            }
        }
        Ok(())
    }

    /// Evicts oldest whole sessions, keeping the selected session and reserving serialized
    /// space for its next turn. Failure leaves the archive unchanged; text is never truncated.
    pub fn retain(
        &mut self,
        keep_session: Option<&str>,
        reserve_bytes: usize,
    ) -> Result<bool, String> {
        let (indices, _) = self.retained_json(keep_session, reserve_bytes)?;
        let retained: HashSet<usize> = indices.into_iter().collect();
        let changed = retained.len() != self.sessions.len();
        let mut index = 0;
        self.sessions.retain(|_| {
            let keep = retained.contains(&index);
            index += 1;
            keep
        });
        Ok(changed)
    }

    // Serialize borrowed sessions, not a deep clone of a potentially oversized archive.
    // The same algorithm serves mutable UI retention and immutable disk snapshots.
    fn retained_json(
        &self,
        keep_session: Option<&str>,
        reserve_bytes: usize,
    ) -> Result<(Vec<usize>, Vec<u8>), String> {
        self.validate_fields()?;
        if keep_session.is_some_and(|id| !self.sessions.iter().any(|s| s.id == id)) {
            return Err("Selected history session is missing".into());
        }
        let limit = MAX_FILE_BYTES
            .checked_sub(reserve_bytes)
            .ok_or("History reserve exceeds 8 MiB")?;
        let mut oldest: Vec<usize> = (0..self.sessions.len()).collect();
        oldest.sort_by_key(|&i| {
            let s = &self.sessions[i];
            (s.updated_at, s.created_at, &s.id)
        });
        let mut retained = vec![true; self.sessions.len()];
        let mut count = self.sessions.len();
        let mut candidates = oldest
            .into_iter()
            .filter(|&i| Some(self.sessions[i].id.as_str()) != keep_session);
        loop {
            let mut indices: Vec<usize> =
                (0..self.sessions.len()).filter(|&i| retained[i]).collect();
            indices.sort_by_key(|&i| {
                let s = &self.sessions[i];
                (s.updated_at, s.created_at, &s.id)
            });
            if count <= MAX_SESSIONS {
                let view = ArchiveView {
                    version: self.version,
                    sessions: indices.iter().map(|&i| &self.sessions[i]).collect(),
                };
                if let Ok(bytes) = bounded_json(&view, limit) {
                    return Ok((indices, bytes));
                }
            }
            if count <= 1 {
                return Err("Current conversation exceeds the 8 MiB history budget; start a new conversation".into());
            }
            let index = candidates
                .next()
                .ok_or("No historical session can be evicted")?;
            retained[index] = false;
            count -= 1;
        }
    }

    /// Recovery is display-only and idempotent; never rebuilds an actionable proposal.
    pub fn normalize_for_display(&mut self) {
        for session in &mut self.sessions {
            for entry in &mut session.messages {
                if entry.status == ChatStatus::Pending {
                    entry.status = ChatStatus::Cancelled;
                }
                for proposal in &mut entry.proposals {
                    if proposal.decision == ProposalDecision::Pending {
                        proposal.decision = ProposalDecision::Expired;
                    }
                    proposal.rule.enabled = false;
                    proposal.rule.auto_clean = false;
                    proposal.rule.action = crate::rules::CleanupAction::Trash;
                }
            }
        }
    }

    pub fn load_from(path: &Path) -> Result<Self, String> {
        let parent = path.parent().ok_or("History path has no parent")?;
        let name = path.file_name().ok_or("History path has no filename")?;
        // Validate the filename even when the parent is missing.
        crate::settings::c_name(name).map_err(|e| e.to_string())?;
        let dir = match private_dir(parent, false) {
            Ok(dir) => dir,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(e.to_string()),
        };
        let Some((mut archive, _, _)) = read_existing(&dir, name)? else {
            return Ok(Self::default());
        };
        archive.normalize_for_display();
        archive.retain(None, 0)?;
        Ok(archive)
    }

    /// Saves a snapshot, leaving self unchanged. Invalid entries always fail before I/O.
    /// Evicts whole sessions in ascending (updated_at, created_at, id) order until both
    /// count and compact-JSON limits fit; never drops the last session or truncates text.
    /// UI callers must retain their mutable archive before snapshotting to stay in sync.
    /// Concurrent writers are not supported.
    pub fn save_to(&self, path: &Path) -> Result<(), String> {
        let (_, bytes) = self.retained_json(None, 0)?;
        let parent = path.parent().ok_or("History path has no parent")?;
        let name = path.file_name().ok_or("History path has no filename")?;
        crate::settings::c_name(name).map_err(|e| e.to_string())?;
        let dir = private_dir(parent, true).map_err(|e| e.to_string())?;
        // Corruption, oversize, symlinks, hardlinks and shared files all fail closed.
        let existing = read_existing(&dir, name)?;
        let temporary = unique_name(".ai-conversations-");
        let mut file =
            open_private_at(&dir, temporary.as_ref(), true, true).map_err(|e| e.to_string())?;
        let result = (|| {
            // Ensure exactly 0600 even under a restrictive umask.
            if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } < 0 {
                return Err(std::io::Error::last_os_error().to_string());
            }
            file.write_all(&bytes)
                .and_then(|_| file.sync_all())
                .map_err(|e| e.to_string())?;
            let current = read_existing(&dir, name)?;
            let unchanged = match (&existing, &current) {
                (None, None) => true,
                (Some((_, before, identity)), Some((_, after, current_identity))) => {
                    identity == current_identity && before == after
                }
                _ => false,
            };
            if !unchanged {
                return Err("History target changed during save; refusing overwrite".into());
            }
            // A previously absent destination must not replace a newly created file.
            // Existing replacements rely on the pinned private directory and the
            // parent's single-writer contract; this is not a cross-process lock.
            rename_at(&dir, temporary.as_ref(), &dir, name, existing.is_none())
                .map_err(|e| e.to_string())?;
            dir.sync_all().map_err(|e| e.to_string())
        })();
        if result.is_err() {
            let _ = unlink_at(&dir, temporary.as_ref(), false);
        }
        result
    }
}

fn validate_id<'a>(id: &'a str, ids: &mut HashSet<&'a str>) -> Result<(), String> {
    if id.trim().is_empty() || id.len() > MAX_ID_BYTES || id.chars().any(char::is_control) {
        return Err("History IDs must be nonempty and at most 128 bytes without controls".into());
    }
    if !ids.insert(id) {
        return Err("Duplicate history ID".into());
    }
    Ok(())
}

#[derive(Serialize)]
struct ArchiveView<'a> {
    version: u32,
    sessions: Vec<&'a ChatSession>,
}

/// Measure the prospective turn with JSON escaping, without cloning existing messages.
/// Extra envelope allowance includes archive delimiters and timestamp growth.
pub(crate) fn turn_fits(session: &ChatSession, entries: &[ChatEntry], reserve: usize) -> bool {
    bounded_json(session, MAX_FILE_BYTES)
        .and_then(|session| {
            let entries = bounded_json(&entries, MAX_FILE_BYTES)?;
            if session
                .len()
                .saturating_add(entries.len())
                .saturating_add(reserve)
                .saturating_add(128)
                <= MAX_FILE_BYTES
            {
                Ok(())
            } else {
                Err("Conversation capacity reached".into())
            }
        })
        .is_ok()
}

pub(crate) fn proposals_fit(rules: &[crate::rules::Rule]) -> bool {
    #[derive(Serialize)]
    struct ProposalView<'a> {
        rule: &'a crate::rules::Rule,
        decision: ProposalDecision,
    }
    rules.len() <= MAX_PROPOSALS
        && bounded_json(
            &rules
                .iter()
                .map(|rule| ProposalView {
                    rule,
                    // Longest decision representation also covers subsequent decisions.
                    decision: ProposalDecision::Rejected,
                })
                .collect::<Vec<_>>(),
            MAX_TEXT_BYTES,
        )
        .is_ok()
}

// Bounded output prevents JSON escaping / proposal metadata from bypassing byte limits.
struct BoundedBuffer {
    bytes: Vec<u8>,
    limit: usize,
}
impl Write for BoundedBuffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(std::io::Error::other(
                "History exceeds its serialized byte limit",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
pub(crate) fn bounded_json(value: &impl Serialize, limit: usize) -> Result<Vec<u8>, String> {
    let mut buffer = BoundedBuffer {
        bytes: Vec::new(),
        limit,
    };
    serde_json::to_writer(&mut buffer, value).map_err(|e| e.to_string())?;
    Ok(buffer.bytes)
}

type Existing = (ChatArchive, Vec<u8>, (u64, u64));
fn read_existing(dir: &File, name: &std::ffi::OsStr) -> Result<Option<Existing>, String> {
    let mut file = match open_private_at(dir, name, false, false) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    if metadata.len() > MAX_FILE_BYTES as u64 {
        return Err("History exceeds 8 MiB; original file left intact".into());
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_FILE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > MAX_FILE_BYTES {
        return Err("History exceeds 8 MiB; original file left intact".into());
    }
    let archive: ChatArchive = serde_json::from_slice(&bytes)
        .map_err(|e| format!("Invalid history; original file left intact: {e}"))?;
    archive.validate()?;
    Ok(Some((archive, bytes, (metadata.dev(), metadata.ino()))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::fixtures::Fixture;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn entry(content: &str) -> ChatEntry {
        ChatEntry {
            id: new_id(),
            role: crate::agent::ChatRole::User,
            content: content.into(),
            status: ChatStatus::Complete,
            detail: "Local diagnostic detail".into(),
            proposals: Vec::new(),
        }
    }
    fn archive() -> ChatArchive {
        let mut session = ChatSession::new("  Disk history  ".into());
        session.messages.push(entry("Hello 世界"));
        ChatArchive {
            sessions: vec![session],
            ..ChatArchive::default()
        }
    }
    fn write_private(path: &Path, bytes: &[u8]) {
        let dir = private_dir(path.parent().unwrap(), true).unwrap();
        let mut file = open_private_at(&dir, path.file_name().unwrap(), true, true).unwrap();
        file.write_all(bytes).unwrap();
    }
    fn assert_no_temporary_files(path: &Path) {
        assert!(fs::read_dir(path.parent().unwrap()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".ai-conversations-")
        }));
    }

    #[test]
    fn roundtrip_missing_permissions_and_search() {
        let f = Fixture::new();
        let path = f.dir.join("state/ai-conversations.json");
        assert!(ChatArchive::load_from(&path).unwrap().sessions.is_empty());
        assert!(!path.parent().unwrap().exists());
        let original = archive();
        original.save_to(&path).unwrap();
        let restored = ChatArchive::load_from(&path).unwrap();
        assert_eq!(
            bounded_json(&original, MAX_FILE_BYTES).unwrap(),
            bounded_json(&restored, MAX_FILE_BYTES).unwrap()
        );
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        assert_eq!(
            fs::metadata(path.parent().unwrap()).unwrap().mode() & 0o777,
            0o700
        );
        let session = &restored.sessions[0];
        for query in ["DISK", "hello", "世界", "DIAGNOSTIC", "  "] {
            assert!(session.matches_query(query));
        }
        assert!(!session.matches_query("not present"));
        original.save_to(&path).unwrap();
        assert_no_temporary_files(&path);
    }

    #[test]
    fn recovery_expires_proposals_cancels_pending_and_disables_all_rules() {
        let f = Fixture::new();
        let path = f.dir.join("state/ai-conversations.json");
        let mut original = archive();
        let message = &mut original.sessions[0].messages[0];
        message.status = ChatStatus::Pending;
        let mut rule = f.settings().rules.remove(0);
        rule.enabled = true;
        rule.auto_clean = true;
        rule.action = crate::rules::CleanupAction::Permanent;
        rule.description = "Searchable proposal evidence".into();
        for decision in [
            ProposalDecision::Pending,
            ProposalDecision::Adopted,
            ProposalDecision::Rejected,
            ProposalDecision::Expired,
        ] {
            message.proposals.push(StoredProposal {
                rule: rule.clone(),
                decision,
            });
        }
        original.save_to(&path).unwrap();
        let before = fs::read(&path).unwrap();
        let mut restored = ChatArchive::load_from(&path).unwrap();
        assert_eq!(fs::read(&path).unwrap(), before);
        let message = &restored.sessions[0].messages[0];
        assert_eq!(message.status, ChatStatus::Cancelled);
        assert_eq!(message.proposals[0].decision, ProposalDecision::Expired);
        assert_eq!(message.proposals[1].decision, ProposalDecision::Adopted);
        assert_eq!(message.proposals[2].decision, ProposalDecision::Rejected);
        for proposal in &message.proposals {
            assert!(!proposal.rule.enabled && !proposal.rule.auto_clean);
            assert_eq!(proposal.rule.action, crate::rules::CleanupAction::Trash);
        }
        assert!(restored.sessions[0].matches_query("PROPOSAL EVIDENCE"));
        let once = bounded_json(&restored, MAX_FILE_BYTES).unwrap();
        restored.normalize_for_display();
        assert_eq!(once, bounded_json(&restored, MAX_FILE_BYTES).unwrap());
        assert_eq!(original.sessions[0].messages[0].status, ChatStatus::Pending);
    }

    #[test]
    fn corrupt_unknown_version_and_unknown_fields_preserve_target() {
        let f = Fixture::new();
        for (index, bytes) in [
            b"broken".as_slice(),
            br#"{"version":99,"sessions":[]}"#,
            br#"{"version":1,"sessions":[],"agent_context":{}}"#,
        ]
        .into_iter()
        .enumerate()
        {
            let path = f.dir.join(format!("state/history-{index}.json"));
            write_private(&path, bytes);
            assert!(ChatArchive::load_from(&path).is_err());
            assert!(archive().save_to(&path).is_err());
            assert_eq!(fs::read(&path).unwrap(), bytes);
            assert_no_temporary_files(&path);
        }
    }

    #[test]
    fn rejects_invalid_fields_and_never_truncates_messages() {
        let f = Fixture::new();
        let path = f.dir.join("state/ai-conversations.json");
        let original = archive();
        original.save_to(&path).unwrap();
        let before = fs::read(&path).unwrap();
        let mut invalid = Vec::new();
        let mut a = original.clone();
        a.version = 0;
        invalid.push(a);
        let mut a = original.clone();
        a.sessions.push(a.sessions[0].clone());
        invalid.push(a);
        let mut a = original.clone();
        let duplicate = a.sessions[0].messages[0].clone();
        a.sessions[0].messages.push(duplicate);
        invalid.push(a);
        for title in ["", " \t", "bad\ntitle", &"x".repeat(MAX_TITLE_BYTES + 1)] {
            let mut a = original.clone();
            a.sessions[0].title = title.into();
            invalid.push(a);
        }
        let mut a = original.clone();
        a.sessions[0].messages[0].id.clear();
        invalid.push(a);
        let mut a = original.clone();
        a.sessions[0].updated_at = a.sessions[0].created_at.saturating_sub(1);
        invalid.push(a);
        let mut a = original.clone();
        a.sessions[0].messages[0].content = "x".repeat(MAX_TEXT_BYTES + 1);
        invalid.push(a);
        let mut a = original.clone();
        a.sessions[0].messages = (0..=MAX_ENTRIES).map(|_| entry("message")).collect();
        invalid.push(a);
        let mut a = original.clone();
        let mut rule = f.settings().rules.remove(0);
        rule.description = "x".repeat(MAX_TEXT_BYTES + 1);
        a.sessions[0].messages[0].proposals.push(StoredProposal {
            rule,
            decision: ProposalDecision::Pending,
        });
        invalid.push(a);
        for a in invalid {
            assert!(a.validate().is_err());
            assert!(a.save_to(&path).is_err());
            assert_eq!(fs::read(&path).unwrap(), before);
        }
        assert_no_temporary_files(&path);
    }

    #[test]
    fn memory_retention_keeps_selected_and_counts_json_escapes() {
        let mut a = ChatArchive::default();
        for index in 0..103 {
            let mut session = ChatSession::new(format!("Session {index}"));
            session.created_at = 0;
            session.updated_at = index;
            a.sessions.push(session);
        }
        let selected = a.sessions[0].id.clone();
        assert!(a.retain(Some(&selected), 0).unwrap());
        assert_eq!(a.sessions.len(), MAX_SESSIONS);
        assert_eq!(a.sessions[0].id, selected);
        assert!(!a.sessions.iter().any(|s| s.title == "Session 1"));
        assert!(!a.retain(Some(&selected), 0).unwrap());

        a.sessions.truncate(1);
        let selected = a.sessions[0].id.clone();
        for index in 0..4 {
            let mut session = ChatSession::new(format!("escaped {index}"));
            session.created_at = 0;
            session.updated_at = index + 1;
            session.messages = (0..10)
                .map(|_| {
                    let mut message = entry(&"\u{0001}".repeat(60 * 1024));
                    message.detail.clear();
                    message
                })
                .collect();
            a.sessions.push(session);
        }
        assert!(a.retain(Some(&selected), 512 * 1024).unwrap());
        assert_eq!(a.sessions[0].id, selected);
        assert!(!a.sessions.iter().any(|s| s.title == "escaped 0"));
        assert!(a.sessions.iter().skip(1).all(|s| s.messages.len() == 10));
        let bytes = bounded_json(&a, MAX_FILE_BYTES).unwrap();
        assert!(bytes.len() + 512 * 1024 <= MAX_FILE_BYTES);
        let (_, disk_bytes) = a.retained_json(None, 0).unwrap();
        let disk: ChatArchive = serde_json::from_slice(&disk_bytes).unwrap();
        let memory_ids: HashSet<_> = a.sessions.iter().map(|s| &s.id).collect();
        let disk_ids: HashSet<_> = disk.sessions.iter().map(|s| &s.id).collect();
        assert_eq!(memory_ids, disk_ids);
    }

    #[test]
    fn memory_retention_failure_is_atomic_and_turn_budget_is_escaped() {
        let mut a = archive();
        let selected = a.sessions[0].id.clone();
        a.sessions[0].messages = (0..22)
            .map(|_| {
                let mut message = entry(&"\u{0001}".repeat(60 * 1024));
                message.detail.clear();
                message
            })
            .collect();
        let before_ids: Vec<_> = a.sessions[0]
            .messages
            .iter()
            .map(|m| m.id.clone())
            .collect();
        assert!(a.retain(Some(&selected), 512 * 1024).is_err());
        assert_eq!(
            a.sessions[0]
                .messages
                .iter()
                .map(|m| m.id.clone())
                .collect::<Vec<_>>(),
            before_ids
        );
        assert_eq!(a.sessions[0].id, selected);
        assert!(!turn_fits(&a.sessions[0], &[entry("new")], 512 * 1024));
        a.sessions[0].messages.truncate(1);
        assert!(turn_fits(&a.sessions[0], &[entry("new")], 512 * 1024));
        assert!(a.retain(Some("missing"), 0).is_err());
        assert!(a.retain(Some(&selected), MAX_FILE_BYTES + 1).is_err());
    }

    #[test]
    fn retention_is_deterministic_and_whole_session_only() {
        let f = Fixture::new();
        let path = f.dir.join("state/ai-conversations.json");
        let mut a = ChatArchive::default();
        for index in (0..105).rev() {
            let mut session = ChatSession::new(format!("Session {index}"));
            session.created_at = 1;
            session.updated_at = index + 1;
            a.sessions.push(session);
        }
        assert!(a.validate().is_err());
        a.save_to(&path).unwrap();
        let restored = ChatArchive::load_from(&path).unwrap();
        assert_eq!(restored.sessions.len(), MAX_SESSIONS);
        assert_eq!(restored.sessions[0].title, "Session 5");
        assert_eq!(a.sessions.len(), 105);
        let first = fs::read(&path).unwrap();
        a.sessions.reverse();
        a.save_to(&path).unwrap();
        assert_eq!(fs::read(&path).unwrap(), first);

        let mut large = ChatArchive::default();
        for index in 0..3 {
            let mut session = ChatSession::new(format!("Large {index}"));
            session.created_at = 0;
            session.updated_at = index;
            session.messages = (0..50)
                .map(|_| {
                    let mut message = entry(&"x".repeat(MAX_TEXT_BYTES));
                    message.detail.clear();
                    message
                })
                .collect();
            large.sessions.push(session);
        }
        assert!(large.validate().is_err());
        large.save_to(&path).unwrap();
        let restored = ChatArchive::load_from(&path).unwrap();
        assert_eq!(restored.sessions.len(), 2);
        assert_eq!(restored.sessions[0].title, "Large 1");
        assert!(restored.sessions.iter().all(|s| s.messages.len() == 50));
        assert!(fs::metadata(&path).unwrap().len() <= MAX_FILE_BYTES as u64);
        assert_no_temporary_files(&path);
    }

    #[test]
    fn oversized_file_and_single_session_are_rejected_without_replacement() {
        let f = Fixture::new();
        let path = f.dir.join("state/ai-conversations.json");
        write_private(&path, b"{}");
        File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(MAX_FILE_BYTES as u64 + 1)
            .unwrap();
        assert!(ChatArchive::load_from(&path).is_err());
        assert!(archive().save_to(&path).is_err());
        assert_eq!(
            fs::metadata(&path).unwrap().len(),
            MAX_FILE_BYTES as u64 + 1
        );
        fs::remove_file(&path).unwrap();
        let mut a = archive();
        a.sessions[0].messages = (0..MAX_ENTRIES)
            .map(|_| {
                let mut message = entry(&"x".repeat(MAX_TEXT_BYTES));
                message.detail.clear();
                message
            })
            .collect();
        assert!(a.save_to(&path).is_err());
        assert!(!path.exists());
        assert_no_temporary_files(&path);
    }

    #[test]
    fn rejects_symlinks_hardlinks_shared_files_and_cleans_fixture() {
        let fixture_dir;
        {
            let f = Fixture::new();
            fixture_dir = f.dir.clone();
            let path = f.dir.join("state/ai-conversations.json");
            archive().save_to(&path).unwrap();
            let alias = f.dir.join("alias");
            fs::hard_link(&path, &alias).unwrap();
            let before = fs::read(&alias).unwrap();
            assert!(ChatArchive::load_from(&path).is_err());
            assert!(archive().save_to(&path).is_err());
            assert_eq!(fs::read(&alias).unwrap(), before);
            fs::remove_file(&alias).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(ChatArchive::load_from(&path).is_err());
            assert!(archive().save_to(&path).is_err());
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            fs::rename(&path, &alias).unwrap();
            symlink(&alias, &path).unwrap();
            assert!(ChatArchive::load_from(&path).is_err());
            assert!(archive().save_to(&path).is_err());
            assert_eq!(fs::read(&alias).unwrap(), before);
            fs::remove_file(&path).unwrap();
            symlink(f.dir.join("absent"), &path).unwrap();
            assert!(ChatArchive::load_from(&path).is_err());
            assert!(archive().save_to(&path).is_err());
            let dir_alias = f.dir.join("state-alias");
            symlink(path.parent().unwrap(), &dir_alias).unwrap();
            assert!(ChatArchive::load_from(&dir_alias.join("history.json")).is_err());
            assert!(archive().save_to(&dir_alias.join("history.json")).is_err());
            assert_no_temporary_files(&path);
        }
        assert!(!fixture_dir.exists());
    }

    #[test]
    fn constructors_and_terminal_statuses() {
        assert_ne!(new_id(), new_id());
        assert!(timestamp() > 0);
        let title = ChatSession::new(" \n 测试\t title \r ".into());
        assert_eq!(title.title, "测试 title");
        assert_eq!(title.created_at, title.updated_at);
        assert!(ChatSession::new("世界".repeat(200)).title.len() <= MAX_TITLE_BYTES);
        assert!(!ChatSession::new(" \n ".into()).title.is_empty());
        let mut a = archive();
        a.sessions[0].messages = [
            ChatStatus::Complete,
            ChatStatus::Failed,
            ChatStatus::Cancelled,
        ]
        .into_iter()
        .map(|status| {
            let mut m = entry("retained");
            m.status = status;
            m
        })
        .collect();
        let before = bounded_json(&a, MAX_FILE_BYTES).unwrap();
        a.normalize_for_display();
        assert_eq!(bounded_json(&a, MAX_FILE_BYTES).unwrap(), before);
        assert_eq!(
            serde_json::to_string(&ChatStatus::Pending).unwrap(),
            "\"pending\""
        );
        assert_eq!(
            serde_json::to_string(&ProposalDecision::Expired).unwrap(),
            "\"expired\""
        );
    }
}
