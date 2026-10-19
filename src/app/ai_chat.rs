use super::*;
use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;
use std::task::{Context as TaskContext, Poll, Waker};

// Owns newest snapshots and progresses without any view/App updates.
#[derive(Clone, Default)]
struct ChatSaveQueue(Arc<Mutex<ChatSaveState>>);

#[derive(Default)]
struct ChatSaveState {
    latest: Option<ChatArchive>,
    running: bool,
    error: Option<String>,
    waiters: Vec<Waker>,
}

impl ChatSaveQueue {
    fn enqueue(&self, snapshot: ChatArchive) -> bool {
        let mut state = self.0.lock().unwrap();
        state.latest = Some(snapshot);
        if state.running || state.error.is_some() {
            return false;
        }
        state.running = true;
        true
    }

    fn error(&self) -> Option<String> {
        self.0.lock().unwrap().error.clone()
    }

    fn retry(&self) {
        self.0.lock().unwrap().error = None;
    }

    fn run(&self, mut write: impl FnMut(&ChatArchive) -> Result<(), String>) {
        loop {
            let snapshot = {
                let mut state = self.0.lock().unwrap();
                match state.latest.take() {
                    Some(snapshot) => snapshot,
                    None => {
                        state.running = false;
                        let waiters = std::mem::take(&mut state.waiters);
                        drop(state);
                        for waker in waiters {
                            waker.wake();
                        }
                        return;
                    }
                }
            };
            if let Err(error) = write(&snapshot) {
                let mut state = self.0.lock().unwrap();
                // A failed old write must not replace a newer deletion/reply.
                if state.latest.is_none() {
                    state.latest = Some(snapshot);
                }
                state.error = Some(error);
                state.running = false;
                let waiters = std::mem::take(&mut state.waiters);
                drop(state);
                for waker in waiters {
                    waker.wake();
                }
                return;
            }
        }
    }

    fn wait(&self) -> ChatSaveWait {
        ChatSaveWait(self.clone())
    }

    async fn drain(
        &self,
        executor: gpui::BackgroundExecutor,
        timeout: Duration,
    ) -> Result<(), String> {
        let mut wait = self.wait();
        let mut timer = Box::pin(executor.timer(timeout));
        std::future::poll_fn(move |cx| {
            if let Poll::Ready(result) = Pin::new(&mut wait).poll(cx) { return Poll::Ready(result); }
            if timer.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Err("Chat history save timed out; latest changes remain in memory. / 会话历史保存超时；最新更改仍仅在内存中。".into()));
            }
            Poll::Pending
        }).await
    }
}

struct ChatSaveWait(ChatSaveQueue);

impl Future for ChatSaveWait {
    type Output = Result<(), String>;

    fn poll(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Self::Output> {
        let mut state = self.0.0.lock().unwrap();
        if let Some(error) = &state.error {
            return Poll::Ready(Err(error.clone()));
        }
        if !state.running && state.latest.is_none() {
            return Poll::Ready(Ok(()));
        }
        if !state.waiters.iter().any(|w| w.will_wake(cx.waker())) {
            state.waiters.push(cx.waker().clone());
        }
        Poll::Pending
    }
}

use crate::agent::{AgentContext, ChatMessage, ChatRole};
use crate::app::ai_markdown::MarkdownDocument;
use crate::chat_history::{
    self, ChatArchive, ChatEntry, ChatSession, ChatStatus, ProposalDecision, StoredProposal,
};

// Worst-case escaped 64 KiB answer (6x), 64 KiB encoded proposals and bounded
// status/detail growth fit within 512 KiB. Small idle slack covers decision changes.
const TURN_RESERVE_BYTES: usize = 512 * 1024;
const RETENTION_SLACK_BYTES: usize = 4096;

pub(super) struct LiveChat {
    pub session_id: String,
    pub context: AgentContext,
    pub request: AgentRequest,
    pub token: Token,
    pub transcript: Vec<ChatMessage>,
}

pub(super) struct ChatState {
    pub archive: ChatArchive,
    pub selected: Option<String>,
    pub live: Option<LiveChat>,
    pub next_input: Option<(String, u64)>,
    pub composer: Entity<TextInput>,
    search: Entity<TextInput>,
    scroll: gpui::ScrollHandle,
    history_scroll: gpui::ScrollHandle,
    pending_page: usize,
    pending_scroll: gpui::ScrollHandle,
    pub persistence: bool,
    loaded: bool,
    loading: bool,
    load_error: Option<String>,
    save_error: Option<String>,
    dirty: bool,
    saves: ChatSaveQueue,
    closing: bool,
    pending_entry: Option<String>,
    pending_wire: Option<String>,
    pending_input: Option<(String, u64)>,
    proposals: HashMap<(String, String), (Token, Rule)>,
    markdown: RefCell<HashMap<String, MarkdownDocument>>,
}

pub(super) fn bounded_detail(detail: String, content_bytes: usize) -> String {
    let limit = chat_history::MAX_TEXT_BYTES
        .saturating_sub(content_bytes)
        .min(4096);
    if detail.len() <= limit {
        return detail;
    }
    let replacement = t!(Tr::CpChatDetailBounded);
    if replacement.len() <= limit {
        replacement.into()
    } else {
        String::new()
    }
}

// One-use capability created ONLY from current in-memory validated proposals.
// It must never be persisted or reconstructed from display-only archive rules.
struct OwnAdoption {
    before: Token,
    session_id: String,
    adopted: (String, String),
    remaining: Vec<((String, String), Rule)>,
}

fn entry(role: ChatRole, content: String, status: ChatStatus) -> ChatEntry {
    ChatEntry {
        id: chat_history::new_id(),
        role,
        content,
        status,
        detail: String::new(),
        proposals: vec![],
    }
}

// Only completed in-memory pairs are authority. Never derive this from the archive.
pub(super) fn response_current(sequence: u64, active: u64, busy: bool) -> bool {
    sequence == active && busy
}

fn wire_messages(transcript: &[ChatMessage], input: String) -> Vec<ChatMessage> {
    let mut start = transcript.len().saturating_sub(38);
    start += start % 2;
    while start < transcript.len()
        && transcript[start..]
            .iter()
            .map(|m| m.content.len())
            .sum::<usize>()
            > 48 * 1024
    {
        start += 2;
    }
    let mut messages = transcript[start..].to_vec();
    messages.push(ChatMessage {
        role: ChatRole::User,
        content: input,
    });
    messages
}

impl ChatState {
    pub(super) fn new(cx: &mut Context<Petal>) -> Self {
        let composer = input("", t!(Tr::CpChatInput), false, cx);
        let search = input("", t!(Tr::CpChatSearch), false, cx);
        for entity in [&composer, &search] {
            cx.observe(entity, |_, _, cx| cx.notify()).detach();
        }
        Self {
            archive: ChatArchive::default(),
            selected: None,
            live: None,
            next_input: None,
            composer,
            search,
            scroll: gpui::ScrollHandle::new(),
            history_scroll: gpui::ScrollHandle::new(),
            pending_page: 0,
            pending_scroll: gpui::ScrollHandle::new(),
            persistence: false,
            loaded: false,
            loading: false,
            load_error: None,
            save_error: None,
            dirty: false,
            saves: ChatSaveQueue::default(),
            closing: false,
            pending_entry: None,
            pending_wire: None,
            pending_input: None,
            proposals: HashMap::new(),
            markdown: RefCell::new(HashMap::new()),
        }
    }

    fn retain_archive(&mut self, reserve: usize) -> Result<(), String> {
        if self.archive.retain(self.selected.as_deref(), reserve)? {
            self.dirty = true;
            let entries: HashSet<&str> = self
                .archive
                .sessions
                .iter()
                .flat_map(|session| session.messages.iter().map(|entry| entry.id.as_str()))
                .collect();
            self.markdown
                .borrow_mut()
                .retain(|id, _| entries.contains(id.as_str()));
            self.proposals
                .retain(|(id, _), _| entries.contains(id.as_str()));
        }
        Ok(())
    }

    fn retention_reserve(&self) -> usize {
        if let Some(id) = &self.pending_entry {
            let used = self
                .archive
                .sessions
                .iter()
                .flat_map(|s| &s.messages)
                .find(|entry| &entry.id == id)
                .and_then(|entry| chat_history::bounded_json(entry, TURN_RESERVE_BYTES).ok())
                .map_or(0, |bytes| bytes.len());
            TURN_RESERVE_BYTES.saturating_sub(used)
        } else {
            // Existing display-only sessions can legitimately occupy the full disk budget.
            // New completions already reserve decision slack before they become idle.
            0
        }
    }

    fn merge_archive(&mut self, mut archive: ChatArchive) -> Result<(), String> {
        // Loading is display-only. Local requests and their authority always win.
        archive.sessions.retain(|disk| {
            !self
                .archive
                .sessions
                .iter()
                .any(|local| local.id == disk.id)
        });
        self.archive.sessions.append(&mut archive.sessions);
        self.retain_archive(self.retention_reserve())
    }

    fn take_save_snapshot(&mut self) -> Option<ChatArchive> {
        if !self.persistence
            || !self.loaded
            || self.load_error.is_some()
            || self.save_error.is_some()
            || !self.dirty
        {
            return None;
        }
        if let Err(error) = self.retain_archive(self.retention_reserve()) {
            self.save_error = Some(error);
            self.dirty = true;
            return None;
        }
        self.dirty = false;
        Some(self.archive.clone())
    }

    fn finish_save(&mut self, result: Result<(), String>) {
        if let Err(error) = result {
            self.save_error = Some(error);
            self.dirty = true;
        }
    }

    pub(super) fn has_history(&self) -> bool {
        self.selected.is_some() || !self.archive.sessions.is_empty()
    }

    fn selected_mut(&mut self) -> Option<&mut ChatSession> {
        let id = self.selected.as_ref()?;
        self.archive.sessions.iter_mut().find(|s| &s.id == id)
    }

    fn capture_own_adoption(
        &self,
        adopted: &(String, String),
        current: Token,
        ready: bool,
    ) -> Option<OwnAdoption> {
        if !ready || self.pending_entry.is_some() {
            return None;
        }
        let session_id = self.selected.as_ref()?;
        let session = self
            .archive
            .sessions
            .iter()
            .find(|session| &session.id == session_id)?;
        if !self.proposals.contains_key(adopted) {
            return None;
        }
        // Fail closed if ANY authority is stale, not just the clicked rule.
        if !self.proposals.iter().all(|(key, (token, _))| {
            *token == current
                && session.messages.iter().any(|entry| {
                    entry.id == key.0
                        && entry.proposals.iter().any(|proposal| {
                            proposal.rule.id == key.1
                                && proposal.decision == ProposalDecision::Pending
                        })
                })
        }) {
            return None;
        }
        Some(OwnAdoption {
            before: current,
            session_id: session_id.clone(),
            adopted: adopted.clone(),
            remaining: self
                .proposals
                .iter()
                .filter(|(key, _)| *key != adopted)
                .map(|(key, (_, rule))| (key.clone(), rule.clone()))
                .collect(),
        })
    }

    fn restore_after_own_adoption(
        &mut self,
        captured: OwnAdoption,
        current: Token,
        ready: bool,
    ) -> bool {
        // Exactly the synchronous save_panel_settings transition is allowed.
        // A scan refresh, additional settings write, switch or active turn cannot rebase.
        let expected = Token {
            scan: captured.before.scan,
            revision: captured.before.revision.wrapping_add(1),
            generation: captured.before.generation.wrapping_add(1),
        };
        if !ready
            || current != expected
            || self.selected.as_ref() != Some(&captured.session_id)
            || self.live.is_some()
            || self.pending_entry.is_some()
            || !self.proposals.is_empty()
        {
            return false;
        }
        let Some(session) = self
            .archive
            .sessions
            .iter_mut()
            .find(|session| session.id == captured.session_id)
        else {
            return false;
        };
        let find = |key: &(String, String)| {
            session
                .messages
                .iter()
                .find(|entry| entry.id == key.0)
                .and_then(|entry| {
                    entry
                        .proposals
                        .iter()
                        .find(|proposal| proposal.rule.id == key.1)
                })
                .is_some_and(|proposal| proposal.decision == ProposalDecision::Expired)
        };
        if !find(&captured.adopted) || !captured.remaining.iter().all(|(key, _)| find(key)) {
            return false;
        }
        for entry in &mut session.messages {
            for proposal in &mut entry.proposals {
                let key = (entry.id.clone(), proposal.rule.id.clone());
                if key == captured.adopted {
                    proposal.decision = ProposalDecision::Adopted;
                } else if let Some((_, rule)) = captured
                    .remaining
                    .iter()
                    .find(|(candidate, _)| *candidate == key)
                {
                    proposal.decision = ProposalDecision::Pending;
                    // Restore captured validated Rule, NEVER the archive copy.
                    self.proposals.insert(key, (current, rule.clone()));
                }
            }
        }
        self.dirty = true;
        true
    }

    pub(super) fn expire_proposals(&mut self) {
        self.proposals.clear();
        for session in &mut self.archive.sessions {
            for entry in &mut session.messages {
                for proposal in &mut entry.proposals {
                    if proposal.decision == ProposalDecision::Pending {
                        proposal.decision = ProposalDecision::Expired;
                        self.dirty = true;
                    }
                }
            }
        }
    }

    pub(super) fn begin(
        &mut self,
        label: String,
        wire: String,
        manual: Option<(String, u64)>,
        fresh: bool,
    ) -> bool {
        if !fresh
            && self
                .selected_mut()
                .is_none_or(|session| session.messages.len() + 2 > chat_history::MAX_ENTRIES)
        {
            return false;
        }
        if label.len() > chat_history::MAX_TEXT_BYTES {
            return false;
        }
        let new_session = fresh.then(|| ChatSession::new(label.clone()));
        let additions = [
            entry(ChatRole::User, label, ChatStatus::Complete),
            entry(ChatRole::Assistant, String::new(), ChatStatus::Pending),
        ];
        let current = new_session.as_ref().or_else(|| {
            self.archive
                .sessions
                .iter()
                .find(|s| Some(&s.id) == self.selected.as_ref())
        });
        if current.is_none_or(|s| {
            !chat_history::turn_fits(s, &additions, TURN_RESERVE_BYTES + RETENTION_SLACK_BYTES)
        }) {
            // No append, no invalidation of existing proposals, no transcript changes.
            return false;
        }
        self.expire_proposals();
        if let Some(session) = new_session {
            self.scroll = gpui::ScrollHandle::new();
            self.live = None;
            self.selected = Some(session.id.clone());
            self.archive.sessions.insert(0, session);
            self.markdown.borrow_mut().clear();
        }
        let id = additions[1].id.clone();
        let session = self.selected_mut().expect("preflight selected a session");
        session.messages.extend(additions);
        session.updated_at = chat_history::timestamp().max(session.created_at);
        self.pending_entry = Some(id);
        self.pending_wire = Some(wire);
        self.pending_input = manual;
        // GPUI applies this flag using the NEW content height during prepaint.
        self.scroll.scroll_to_bottom();
        self.dirty = true;
        // Only this small turn was added before pruning; never accumulate oversized archives.
        if let Err(error) = self.retain_archive(TURN_RESERVE_BYTES) {
            self.save_error = Some(error);
        }
        true
    }

    pub(super) fn set_phase(&mut self, phase: AiPhase, detail: String) {
        let Some(id) = self.pending_entry.clone() else {
            return;
        };
        if let Some(session) = self.selected_mut() {
            if let Some(entry) = session.messages.iter_mut().find(|e| e.id == id) {
                entry.detail = bounded_detail(detail, entry.content.len());
                entry.status = match phase {
                    AiPhase::Complete => ChatStatus::Complete,
                    AiPhase::Failed => ChatStatus::Failed,
                    AiPhase::Cancelled => ChatStatus::Cancelled,
                    _ => ChatStatus::Pending,
                };
                self.dirty = true;
            }
        }
        if matches!(phase, AiPhase::Failed | AiPhase::Cancelled) {
            self.pending_entry = None;
            self.pending_wire = None;
            self.pending_input = None;
        }
    }

    pub(super) fn seal(&mut self, context: AgentContext, request: AgentRequest, token: Token) {
        if let Some(session_id) = self.selected.clone() {
            self.live = Some(LiveChat {
                session_id,
                context,
                request,
                token,
                transcript: vec![],
            });
        }
    }

    pub(super) fn pending_messages(&self) -> Vec<ChatMessage> {
        wire_messages(
            self.live
                .as_ref()
                .map(|live| live.transcript.as_slice())
                .unwrap_or(&[]),
            self.pending_wire.clone().unwrap_or_default(),
        )
    }

    #[cfg(test)]
    pub(super) fn complete(
        &mut self,
        response: &AgentResponse,
        token: Token,
        actionable: bool,
        cx: &mut Context<Petal>,
    ) {
        self.complete_with_detail(response, token, actionable, None, cx);
    }

    pub(super) fn complete_with_detail(
        &mut self,
        response: &AgentResponse,
        token: Token,
        actionable: bool,
        detail: Option<&str>,
        cx: &mut Context<Petal>,
    ) {
        // Backend validation normally guarantees this. Fail closed without truncating
        // an oversized answer or letting it poison memory/persistence if that changes.
        if response.explanation.len() > chat_history::MAX_TEXT_BYTES {
            self.set_phase(AiPhase::Failed, t!(Tr::CpChatLimit).into());
            return;
        }
        let proposals_fit = chat_history::proposals_fit(&response.proposals);
        let actionable = actionable && proposals_fit;
        let Some(id) = self.pending_entry.take() else {
            return;
        };
        let follow_bottom = self.scroll.max_offset().y + self.scroll.offset().y <= px(2.);
        let wire = self.pending_wire.take().unwrap_or_default();
        if let Some(live) = &mut self.live {
            live.transcript = wire_messages(&live.transcript, wire);
            live.transcript.push(ChatMessage {
                role: ChatRole::Assistant,
                content: response.explanation.clone(),
            });
        }
        if let Some(session) = self.selected_mut() {
            if let Some(entry) = session.messages.iter_mut().find(|e| e.id == id) {
                entry.content = response.explanation.clone();
                entry.status = ChatStatus::Complete;
                entry.detail = if !proposals_fit {
                    t!(Tr::CpChatProposalLimit)
                } else if let Some(detail) = detail {
                    detail
                } else if actionable || response.proposals.is_empty() {
                    t!(Tr::CpAiSnapshotNotice)
                } else {
                    t!(Tr::CpAiDraftsExpired)
                }
                .into();
                entry.detail =
                    bounded_detail(std::mem::take(&mut entry.detail), entry.content.len());
                entry.proposals = response
                    .proposals
                    .iter()
                    .filter(|_| proposals_fit)
                    .cloned()
                    .map(|rule| StoredProposal {
                        rule,
                        decision: if actionable {
                            ProposalDecision::Pending
                        } else {
                            ProposalDecision::Expired
                        },
                    })
                    .collect();
            }
            session.updated_at = chat_history::timestamp().max(session.created_at);
        }
        if actionable {
            for rule in &response.proposals {
                self.proposals
                    .insert((id.clone(), rule.id.clone()), (token, rule.clone()));
            }
        }
        if let Some((submitted, revision)) = self.pending_input.take() {
            let input = self.composer.read(cx);
            if input.text() == submitted
                && input.edit_revision() == revision
                && !input.is_composing()
            {
                self.composer.update(cx, |input, cx| input.set_text("", cx));
            }
        }
        if follow_bottom {
            self.scroll.scroll_to_bottom();
        }
        self.dirty = true;
        if let Err(error) = self.retain_archive(RETENTION_SLACK_BYTES) {
            self.save_error = Some(error);
        }
    }

    fn choose(&mut self, id: String) {
        if !self.archive.sessions.iter().any(|session| session.id == id) {
            return;
        }
        // Switching away irrevocably ends outbound authority, even when switching back.
        if self.selected.as_ref() != Some(&id) {
            self.expire_proposals();
            self.live = None;
            self.selected = Some(id);
            self.scroll = gpui::ScrollHandle::new();
        }
    }
}

impl Petal {
    pub(in crate::app) fn install_chat_shutdown(
        &self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let view = cx.weak_entity();
        window.on_window_should_close(cx, move |window, cx| {
            // With no root entity there is nothing left to snapshot.
            view.update(cx, |this, cx| this.request_chat_close(false, window, cx))
                .is_err()
        });
        let view = cx.weak_entity();
        let saves = self.cleanup_panel.chat.saves.clone();
        // App-level registration intentionally outlives the view. GPUI destroys
        // windows BEFORE polling quit futures and only gives them 200 ms.
        gpui::App::on_app_quit(cx, move |cx| {
            view.update(cx, |this, cx| this.queue_chat_save(cx)).ok();
            let saves = saves.clone();
            async move {
                let _ = saves.wait().await;
            }
        })
        .detach();
    }

    pub(crate) fn request_chat_close(
        &mut self,
        quit: bool,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if !quit && self.menu_bar_enabled() {
            // Keep the root entity, ongoing scans and persistence alive while the
            // menu bar monitor runs. Cmd-Q still uses the existing drain gate.
            self.queue_chat_save(cx);
            cx.hide();
            return;
        }
        if self.cleanup_panel.chat.closing {
            return;
        }
        self.cleanup_panel.chat.closing = true;
        let handle = window.window_handle();
        cx.spawn(async move |this, cx| {
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            loop {
                let prepared = this.update(cx, |this, cx| {
                    this.queue_chat_save(cx);
                    let chat = &this.cleanup_panel.chat;
                    let error = chat.load_error.clone().or_else(|| chat.save_error.clone())
                        .or_else(|| chat.saves.error())
                        .or_else(|| (chat.persistence && (chat.loading || !chat.loaded)).then(||
                            "Chat history is still loading; please wait before closing. / 会话历史仍在加载，请稍后关闭。".into()));
                    (chat.saves.clone(), error)
                });
                let Ok((saves, error)) = prepared else { return; };
                let result = match error {
                    Some(error) => Err(error),
                    None => saves.drain(cx.background_executor().clone(), deadline.saturating_duration_since(std::time::Instant::now())).await,
                };
                if let Err(error) = result {
                    // Keep the view and all memory-only sessions alive. Never retry
                    // automatically or override an archive that failed to load.
                    let answer = handle.update(cx, |_, window, cx| {
                        cx.activate(true);
                        window.activate();
                        this.update(cx, |this, cx| {
                            this.panel_message(tf!(Tr::CpChatSaveFailed, "e" => &error), cx);
                        }).ok();
                        window.prompt(gpui::PromptLevel::Warning,
                            t!(Tr::CpChatRetrySave),
                            Some(&format!("{}\nUnsaved changes will be lost if you exit. / 退出将丢失未保存的更改。",
                                tf!(Tr::CpChatSaveFailed, "e" => &error))),
                            &[t!(Tr::Cancel), t!(Tr::MenuQuit)], cx)
                    });
                    let discard = match answer {
                        Ok(answer) => answer.await == Ok(1),
                        Err(_) => false,
                    };
                    handle.update(cx, |_, window, cx| {
                        this.update(cx, |this, _| this.cleanup_panel.chat.closing = false).ok();
                        if discard {
                            if quit { cx.quit(); } else { window.remove_window(); }
                        }
                    }).ok();
                    return;
                }
                let done = handle.update(cx, |_, window, cx| {
                    this.update(cx, |this, cx| {
                        // A reply may have arrived while drain was awaiting. Capture
                        // it and check idle in the SAME UI transaction as close.
                        this.queue_chat_save(cx);
                        let chat = &this.cleanup_panel.chat;
                        let state = chat.saves.0.lock().unwrap();
                        if state.running || state.latest.is_some() || state.error.is_some() {
                            return false;
                        }
                        if chat.dirty && chat.persistence { return false; }
                        drop(state); // Never hold the queue lock across platform quit.
                        if quit { cx.quit(); } else { window.remove_window(); }
                        true
                    }).unwrap_or(true)
                }).unwrap_or(true);
                if done { return; }
            }
        }).detach();
    }

    pub(super) fn load_chat_archive(&mut self, cx: &mut Context<Self>) {
        let chat = &mut self.cleanup_panel.chat;
        if !chat.persistence || chat.loaded || chat.loading {
            return;
        }
        chat.loading = true;
        cx.spawn(async move |this, cx| {
            let result = cx.background_spawn(async { ChatArchive::load() }).await;
            this.update(cx, |this, cx| {
                let chat = &mut this.cleanup_panel.chat;
                chat.loading = false;
                chat.loaded = true;
                match result {
                    Ok(archive) => {
                        if let Err(error) = chat.merge_archive(archive) {
                            chat.load_error = Some(error);
                        }
                    }
                    Err(error) => chat.load_error = Some(error),
                }
                this.queue_chat_save(cx);
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    pub(super) fn queue_chat_save(&mut self, cx: &mut Context<Self>) {
        if let Some(error) = self.cleanup_panel.chat.saves.error() {
            self.cleanup_panel.chat.save_error = Some(error);
            return;
        }
        let Some(snapshot) = self.cleanup_panel.chat.take_save_snapshot() else {
            return;
        };
        let saves = self.cleanup_panel.chat.saves.clone();
        if !saves.enqueue(snapshot) {
            return;
        }
        let worker = saves.clone();
        // Spawn before the view-bound notification task. The detached worker owns
        // every queued snapshot and never awaits an App/WeakEntity update.
        let task = cx.background_executor().spawn(async move {
            worker.run(ChatArchive::save);
        });
        task.detach();
        cx.spawn(async move |this, cx| {
            let result = saves.wait().await;
            this.update(cx, |this, cx| {
                // A user may already have retried before this notification runs.
                // Do not resurrect an obsolete failure from the previous writer.
                if result.is_err() {
                    if let Some(error) = this.cleanup_panel.chat.saves.error() {
                        this.cleanup_panel.chat.finish_save(Err(error));
                    }
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn send_chat(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.cleanup_panel.ai_busy {
            return;
        }
        let input = self.cleanup_panel.chat.composer.read(cx);
        if input.is_composing() {
            self.panel_message(t!(Tr::CpChatConfirmComposition), cx);
            return;
        }
        let submitted = input.text().to_owned();
        let revision = input.edit_revision();
        if submitted.trim().is_empty() || submitted.len() > agent::MAX_CHAT_INPUT_BYTES {
            self.panel_message(t!(Tr::CpChatInputLimit), cx);
            return;
        }
        if !self.ai_ready() {
            self.panel_message(t!(Tr::CpAiNotReady), cx);
            return;
        }
        let Ok(settings) = self.cleanup_panel.settings.clone() else {
            return;
        };
        if !settings.agent.enabled {
            self.panel_message(t!(Tr::CpAiNotEnabled), cx);
            return;
        }
        if text(&self.cleanup_panel.url, cx) != settings.agent.base_url
            || text(&self.cleanup_panel.model, cx) != settings.agent.model
        {
            self.panel_message(t!(Tr::CpAiServiceHint), cx);
            return;
        }
        let continuing = self.cleanup_panel.chat.live.as_ref().is_some_and(|live| {
            self.cleanup_panel.chat.selected.as_ref() == Some(&live.session_id)
                && self.ai_current(live.token)
                && settings.agent.has_privacy_consent()
        });
        if !continuing {
            self.cleanup_panel.chat.next_input = Some((submitted, revision));
            self.request_panel_ai(AgentRequest::Analyze, None, window, cx);
            return;
        }
        if !self.cleanup_panel.chat.begin(
            submitted.clone(),
            submitted.clone(),
            Some((submitted.clone(), revision)),
            false,
        ) {
            self.panel_message(t!(Tr::CpChatLimit), cx);
            return;
        }
        let live = self.cleanup_panel.chat.live.as_ref().unwrap();
        let token = live.token;
        let context = live.context.clone();
        let request = live.request.clone();
        let messages = self.cleanup_panel.chat.pending_messages();
        self.cleanup_panel.ai_turn = Some(AiTurn::new(submitted));
        self.cleanup_panel.response = None;
        self.cleanup_panel.ai_busy = true;
        self.cleanup_panel.ai_sequence = self.cleanup_panel.ai_sequence.wrapping_add(1);
        let sequence = self.cleanup_panel.ai_sequence;
        self.set_ai_phase(AiPhase::Waiting, t!(Tr::CpAiWaitingResponse), cx);
        cx.spawn(async move |this, cx| {
            let result = cx
                .background_spawn(async move {
                    agent::run_conversation(&settings.agent, context, request, messages)
                })
                .await;
            this.update(cx, |this, cx| {
                if !response_current(
                    sequence,
                    this.cleanup_panel.ai_sequence,
                    this.cleanup_panel.ai_busy,
                ) {
                    return;
                }
                this.cleanup_panel.ai_busy = false;
                if !this.ai_current(token) {
                    this.set_ai_phase(AiPhase::Cancelled, t!(Tr::CpAiRequestChanged), cx);
                    return;
                }
                match result {
                    Ok(response) => {
                        let actionable = this.cleanup_current(token) && this.cleanup_ready();
                        let detail = this.ai_response_detail(&response, token, actionable, cx);
                        this.cleanup_panel
                            .chat
                            .complete_with_detail(&response, token, actionable, Some(&detail), cx);
                        if let Some(turn) = &mut this.cleanup_panel.ai_turn {
                            turn.answer = Some(response.explanation.clone());
                        }
                        if actionable {
                            this.cleanup_panel.response = Some((token, response));
                        }
                        this.set_ai_phase(AiPhase::Complete, detail, cx);
                    }
                    Err(error) => this.set_ai_phase(AiPhase::Failed, error, cx),
                }
            })
            .ok();
        })
        .detach();
    }

    // Both response paths queue nominations before completing the chat and store
    // local feedback directly on that completed entry. Never infer execution.
    pub(super) fn ai_response_detail(
        &mut self,
        response: &AgentResponse,
        token: Token,
        actionable: bool,
        cx: &mut Context<Self>,
    ) -> String {
        let had_actions = !response.proposals.is_empty() || !response.pending_deletions.is_empty();
        if !response.pending_deletions.is_empty() {
            if !actionable {
                return t!(Tr::CpAiPendingExpired).into();
            }
            return self.queue_ai_deletions(&response.pending_deletions, token, cx);
        }
        if !actionable && had_actions {
            t!(Tr::CpAiDraftsExpired).into()
        } else {
            t!(Tr::CpAiSnapshotNotice).into()
        }
    }

    fn chat_pending_ready(&self) -> bool {
        !self.cleanup_panel.ai_busy && !self.cleanup_panel.cleanup_busy && self.cleanup_ready()
    }

    fn chat_pending_guard(&mut self, scan: u64, version: u64, cx: &mut Context<Self>) -> bool {
        if !self.chat_pending_ready() {
            self.panel_message(t!(Tr::CpAiPendingExpired), cx);
            return false;
        }
        if !matches!(&self.screen, Screen::Results(r) if r.id == scan && r.collector_version == version) {
            self.panel_message(t!(Tr::CpAiPendingChanged), cx);
            return false;
        }
        true
    }

    fn remove_chat_pending(&mut self, scan: u64, version: u64, ix: Option<usize>, cx: &mut Context<Self>) {
        if !self.chat_pending_guard(scan, version, cx) {
            return;
        }
        if let Screen::Results(r) = &mut self.screen {
            if let Some(ix) = ix {
                r.collector.retain(|&item| item != ix);
                r.ai_collector.remove(&ix);
            } else {
                r.collector.clear();
                r.ai_collector.clear();
            }
        }
        self.collector_changed(cx);
        cx.notify();
    }

    pub(super) fn render_chat_pending(&self, cx: &mut Context<Self>) -> gpui::Stateful<gpui::Div> {
        const PAGE_SIZE: usize = 50;
        let mut panel = div().id("chat-pending").debug_selector(|| "chat-pending".into())
            .flex().flex_col().flex_shrink_0().min_w_0().gap_1().p_2()
            .border_1().border_color(rgb(BORDER)).rounded_lg();
        let title = || div().text_xs().font_weight(FontWeight::SEMIBOLD)
            .child(t!(Tr::CpAiPendingTitle));
        let empty = row().min_w_0().child(title())
            .child(div().text_xs().text_color(rgb(MUTED)).child(t!(Tr::CpAiPendingEmpty)));
        let Screen::Results(r) = &self.screen else {
            return panel.child(empty);
        };
        let n = r.collector.len();
        if n == 0 {
            return panel.child(empty);
        }
        panel = panel.child(title())
            .child(div().text_xs().text_color(rgb(MUTED)).child(t!(Tr::CpAiPendingHint)));
        let scan = r.id;
        let version = r.collector_version;
        let ready = self.chat_pending_ready();
        let pages = n.div_ceil(PAGE_SIZE);
        let page = self.cleanup_panel.chat.pending_page.min(pages - 1);
        let mut list = div().id("chat-pending-list").max_h(px(120.)).overflow_y_scroll()
            .track_scroll(&self.cleanup_panel.chat.pending_scroll).flex().flex_col().gap_1();
        for (position, &ix) in r.collector.iter().enumerate().skip(page * PAGE_SIZE).take(PAGE_SIZE) {
            let Some(node) = r.tree.nodes.get(ix) else { continue };
            let path = r.tree.path_of(ix);
            let reveal = path.clone();
            list = list.child(div().flex().flex_shrink_0().items_center().min_w_0().gap_2()
                .child(div().flex_1().min_w_0().flex().flex_col()
                    .child(div().id(("chat-pending-path", ix))
                        .debug_selector(move || format!("chat-pending-path-{position}"))
                        .overflow_x_scroll().text_xs()
                        .child(path.to_string_lossy().into_owned()))
                    .child(div().text_xs().text_color(rgb(MUTED))
                        .child(tf!(Tr::CpAiPendingSize, "size" => format_size(node.size)))))
                .child(button(("chat-pending-reveal", ix), t!(Tr::RevealInFinder)).text_xs()
                    .when(!ready, |d| d.opacity(0.45))
                    .when(ready, |d| d.on_click(cx.listener(move |this, _, _, cx| {
                        if this.chat_pending_guard(scan, version, cx) {
                            cx.reveal_path(&reveal);
                        }
                    }))))
                .child(button(("chat-pending-remove", ix), "×")
                    .tooltip(tooltip(t!(Tr::RemoveFromCollector)))
                    .when(!ready, |d| d.opacity(0.45))
                    .when(ready, |d| d.on_click(cx.listener(move |this, _, _, cx| {
                        this.remove_chat_pending(scan, version, Some(ix), cx);
                    })))));
        }
        panel = panel.child(list);
        if pages > 1 {
            panel = panel.child(row()
                .child(div().text_xs().child(tf!(Tr::CpAiPendingPage,
                    "page" => page + 1, "pages" => pages, "n" => n)))
                .child(button("chat-pending-prev", t!(Tr::CpAiPendingPrevious))
                    .when(page == 0, |d| d.opacity(0.45))
                    .when(page > 0, |d| d.on_click(cx.listener(move |this, _, _, cx| {
                        this.cleanup_panel.chat.pending_page = page - 1;
                        this.cleanup_panel.chat.pending_scroll.set_offset(gpui::point(px(0.), px(0.)));
                        cx.notify();
                    }))))
                .child(button("chat-pending-next", t!(Tr::CpAiPendingNext))
                    .when(page + 1 == pages, |d| d.opacity(0.45))
                    .when(page + 1 < pages, |d| d.on_click(cx.listener(move |this, _, _, cx| {
                        this.cleanup_panel.chat.pending_page = page + 1;
                        this.cleanup_panel.chat.pending_scroll.set_offset(gpui::point(px(0.), px(0.)));
                        cx.notify();
                    })))));
        }
        panel.child(row()
            .child(button("chat-pending-clear", t!(Tr::Clear))
                .when(!ready, |d| d.opacity(0.45))
                .when(ready, |d| d.on_click(cx.listener(move |this, _, _, cx| {
                    this.remove_chat_pending(scan, version, None, cx);
                }))))
            .child(button("chat-pending-confirm", tf!(Tr::CpAiPendingConfirm, "n" => n))
                .debug_selector(|| "chat-pending-confirm".into())
                .when(!ready, |d| d.opacity(0.45))
                .when(ready, |d| d.on_click(cx.listener(move |this, _, window, cx| {
                    if this.chat_pending_guard(scan, version, cx) {
                        this.trash_collected(window, cx);
                    }
                })))))
    }

    fn decide_chat_proposal(
        &mut self,
        entry_id: String,
        rule_id: String,
        adopt: bool,
        cx: &mut Context<Self>,
    ) {
        if self.cleanup_panel.ai_busy {
            return;
        }
        let key = (entry_id.clone(), rule_id.clone());
        let Some((token, mut rule)) = self.cleanup_panel.chat.proposals.get(&key).cloned() else {
            return;
        };
        if !self.cleanup_current(token) || !self.cleanup_ready() {
            self.panel_message(t!(Tr::CpAiDraftsExpired), cx);
            return;
        }
        if adopt {
            let Some(captured) =
                self.cleanup_panel
                    .chat
                    .capture_own_adoption(&key, token, self.cleanup_ready())
            else {
                self.panel_message(t!(Tr::CpAiDraftsExpired), cx);
                return;
            };
            let Ok(mut next) = self.cleanup_panel.settings.clone() else {
                return;
            };
            rule.enabled = true;
            rule.auto_clean = false;
            rule.action = CleanupAction::Trash;
            rule.source = RuleSource::Ai;
            next.rules.push(rule);
            // The click is explicit authorization. Persistence must succeed before Adopted.
            if !self.save_panel_settings(next, cx) {
                return;
            }
            // Only this call site may restore capabilities after its own safe-rule save.
            // save_panel_settings remains unchanged and invalidates all other jobs/live chat.
            if let Some(current) = self.cleanup_token() {
                let ready = self.cleanup_ready();
                self.cleanup_panel
                    .chat
                    .restore_after_own_adoption(captured, current, ready);
            }
        }
        for session in &mut self.cleanup_panel.chat.archive.sessions {
            if let Some(entry) = session.messages.iter_mut().find(|e| e.id == entry_id) {
                if let Some(proposal) = entry.proposals.iter_mut().find(|p| p.rule.id == rule_id) {
                    proposal.decision = if adopt {
                        ProposalDecision::Adopted
                    } else {
                        ProposalDecision::Rejected
                    };
                }
            }
        }
        self.cleanup_panel.chat.proposals.remove(&key);
        self.cleanup_panel.chat.dirty = true;
        self.queue_chat_save(cx);
        cx.notify();
    }

    fn delete_chat(&mut self, id: String, window: &mut Window, cx: &mut Context<Self>) {
        if self.cleanup_panel.ai_busy {
            return;
        }
        let answer = window.prompt(
            PromptLevel::Warning,
            t!(Tr::CpChatDeleteConfirm),
            Some(t!(Tr::CpChatReadOnly)),
            &[t!(Tr::CpChatDelete), t!(Tr::Cancel)],
            cx,
        );
        cx.spawn(async move |this, cx| {
            if answer.await != Ok(0) {
                return;
            }
            this.update(cx, |this, cx| {
                if this.cleanup_panel.ai_busy {
                    return;
                }
                let chat = &mut this.cleanup_panel.chat;
                chat.archive.sessions.retain(|s| s.id != id);
                if chat.selected.as_ref() == Some(&id) {
                    chat.expire_proposals();
                    chat.selected = None;
                    chat.live = None;
                    this.cleanup_panel.ai_turn = None;
                }
                chat.markdown.borrow_mut().clear();
                chat.dirty = true;
                this.queue_chat_save(cx);
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    pub(super) fn render_chat_controls(&self, can_send: bool, cx: &mut Context<Self>) -> gpui::Div {
        let p = &self.cleanup_panel;
        let chat = &p.chat;
        let mut controls = div()
            .flex()
            .flex_col()
            .gap_1()
            .min_w_0()
            .child(
                row().min_w_0().child(
                    button("chat-new", t!(Tr::CpChatNew))
                        .when(!p.ai_busy, |d| {
                            d.on_click(cx.listener(|this, _, _, cx| {
                                let chat = &mut this.cleanup_panel.chat;
                                chat.expire_proposals();
                                chat.live = None;
                                chat.selected = None;
                                this.cleanup_panel.ai_turn = None;
                                this.cleanup_panel.response = None;
                                this.queue_chat_save(cx);
                                cx.notify();
                            }))
                        })
                        .when(p.ai_busy, |d| d.opacity(0.45)),
                ).child(
                    div().id("chat-privacy-summary").flex_1().min_w_0().text_xs().text_color(rgb(MUTED))
                        .tooltip(tooltip(t!(Tr::CpChatPrivacy)))
                        .child(t!(Tr::CpChatPrivacySummary)),
                ),
            )
            .child(
                row()
                    .items_center()
                    .debug_selector(|| "chat-composer".into())
                    .child(div().flex_1().min_w_0().child(chat.composer.clone()))
                    .child(
                        button("chat-send", t!(Tr::CpChatSend))
                            .when(!can_send, |d| d.opacity(0.45))
                            .when(can_send, |d| {
                                d.on_click(
                                    cx.listener(|this, _, window, cx| this.send_chat(window, cx)),
                                )
                            }),
                    ),
            );
        if chat
            .live
            .as_ref()
            .is_none_or(|live| !self.ai_current(live.token))
        {
            controls = controls.child(
                div().id("chat-history-readonly")
                    .min_w_0().truncate()
                    .text_xs()
                    .text_color(rgb(MUTED))
                    .tooltip(tooltip(t!(Tr::CpChatReadOnly)))
                    .child(t!(Tr::CpChatReadOnly)),
            );
        }
        if chat.loading {
            controls = controls.child(t!(Tr::CpChatLoading));
        }
        if let Some(error) = &chat.load_error {
            controls = controls.child(
                div()
                    .text_color(rgb(WARNING))
                    .child(tf!(Tr::CpChatLoadFailed, "e" => error)),
            );
        }
        if let Some(error) = &chat.save_error {
            controls =
                controls
                    .child(
                        div()
                            .text_color(rgb(WARNING))
                            .child(tf!(Tr::CpChatSaveFailed, "e" => error)),
                    )
                    .child(button("chat-retry-save", t!(Tr::CpChatRetrySave)).on_click(
                        cx.listener(|this, _, _, cx| {
                            this.cleanup_panel.chat.save_error = None;
                            this.cleanup_panel.chat.saves.retry();
                            this.cleanup_panel.chat.dirty = true;
                            this.queue_chat_save(cx);
                        }),
                    ));
        }
        controls.flex_shrink_0()
    }

    pub(super) fn render_chat_workspace(
        &self,
        can_send: bool,
        narrow: bool,
        cx: &mut Context<Self>,
    ) -> gpui::Div {
        let p = &self.cleanup_panel;
        let chat = &p.chat;
        let query = chat.search.read(cx).text();
        let mut sessions: Vec<_> = chat
            .archive
            .sessions
            .iter()
            .filter(|s| s.matches_query(query))
            .collect();
        sessions.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
        let mut history = div()
            .flex()
            .flex_col()
            .gap_2()
            .min_w_0()
            .when(narrow, |d| d.flex_row().items_start())
            .child(
                div().flex().flex_col().gap_1().min_w_0()
                    .when(narrow, |d| d.w(px(140.)).flex_shrink_0())
                    .child(div().id("chat-history-label").min_w_0().truncate().text_xs().text_color(rgb(MUTED)).tooltip(tooltip(t!(Tr::CpChatHistory))).child(t!(Tr::CpChatHistory)))
                    .child(chat.search.clone()),
            );
        let mut list = div()
            .id("chat-history-list")
            .min_w_0()
            .when(narrow, |d| d.flex_1())
            .max_h(px(if narrow { 70. } else { 240. }))
            .overflow_y_scroll()
            .track_scroll(&chat.history_scroll)
            .flex()
            .flex_col()
            .gap_1();
        for session in sessions {
            let id = session.id.clone();
            let remove = id.clone();
            list = list.child(
                div()
                    .flex()
                    .items_center()
                    .min_w_0()
                    .gap_1()
                    .child(
                        button(
                            SharedString::from(format!("chat-session-{}", session.id)),
                            format!("{} · {}", session.title, session.messages.len() / 2),
                        )
                        .flex_1()
                        .min_w_0()
                        .truncate()
                        .when(chat.selected.as_ref() == Some(&session.id), |d| {
                            d.bg(rgb(ACCENT))
                        })
                        .when(!p.ai_busy, |d| {
                            d.on_click(cx.listener(move |this, _, _, cx| {
                                this.cleanup_panel.chat.choose(id.clone());
                                this.cleanup_panel.ai_turn = None;
                                this.cleanup_panel.response = None;
                                this.queue_chat_save(cx);
                                cx.notify();
                            }))
                        })
                        .when(p.ai_busy, |d| d.opacity(0.45)),
                    )
                    .child(
                        button(
                            SharedString::from(format!("chat-delete-{}", session.id)),
                            "×",
                        )
                        .tooltip(tooltip(t!(Tr::CpChatDelete)))
                        .when(!p.ai_busy, |d| {
                            d.on_click(cx.listener(move |this, _, window, cx| {
                                this.delete_chat(remove.clone(), window, cx)
                            }))
                        }),
                    ),
            );
        }
        history = history.child(list);
        let mut messages = div()
            .id("chat-messages")
            .debug_selector(|| "chat-messages".into())
            .flex_1()
            .min_h_0()
            .min_w_0()
            .overflow_y_scroll()
            .track_scroll(&chat.scroll)
            .flex()
            .flex_col()
            .gap_3()
            .p_2()
            // Keep nominations reachable without reserving space above the composer.
            // Put them first so scroll-to-bottom still reveals the latest chat turn.
            .child(self.render_chat_pending(cx));
        if let Some(session) = chat
            .archive
            .sessions
            .iter()
            .find(|s| Some(&s.id) == chat.selected.as_ref())
        {
            for entry in &session.messages {
                let mut message = div()
                    .id(SharedString::from(format!("chat-entry-{}", entry.id)))
                    .debug_selector({
                        let id = entry.id.clone();
                        move || format!("chat-entry-{id}")
                    })
                    .flex()
                    .flex_col()
                    .flex_shrink_0()
                    .min_w_0()
                    .gap_2()
                    .p_3()
                    .rounded_lg()
                    .bg(rgb(PANEL))
                    .child(div().text_xs().text_color(rgb(ACCENT)).child(
                        if entry.role == ChatRole::User {
                            t!(Tr::CpAiYou)
                        } else {
                            t!(Tr::CpTabAi)
                        },
                    ));
                if entry.role == ChatRole::User {
                    message = message.child(div().min_w_0().child(entry.content.clone()));
                } else if !entry.content.is_empty() {
                    let mut cache = chat.markdown.borrow_mut();
                    let document = cache
                        .entry(entry.id.clone())
                        .or_insert_with(|| MarkdownDocument::parse(&entry.content));
                    message = message.child(document.render());
                }
                if !entry.detail.is_empty() {
                    message = message.child(
                        div()
                            .text_xs()
                            .text_color(rgb(
                                if matches!(
                                    entry.status,
                                    ChatStatus::Failed | ChatStatus::Cancelled
                                ) {
                                    WARNING
                                } else {
                                    MUTED
                                },
                            ))
                            .child(entry.detail.clone()),
                    );
                }
                for proposal in &entry.proposals {
                    let decision = match proposal.decision {
                        ProposalDecision::Pending => t!(Tr::CpChatPending),
                        ProposalDecision::Adopted => t!(Tr::CpChatAdopted),
                        ProposalDecision::Rejected => t!(Tr::CpChatRejected),
                        ProposalDecision::Expired => t!(Tr::CpChatExpired),
                    };
                    let key = (entry.id.clone(), proposal.rule.id.clone());
                    let actionable = proposal.decision == ProposalDecision::Pending
                        && !p.ai_busy
                        && self.cleanup_ready()
                        && chat
                            .proposals
                            .get(&key)
                            .is_some_and(|(token, _)| self.cleanup_current(*token));
                    let edit_rule = proposal.rule.clone();
                    let edit_id = proposal.rule.id.clone();
                    let edit_key = key.clone();
                    let (adopt_entry, adopt_rule) = key.clone();
                    let (reject_entry, reject_rule) = key;
                    message =
                        message.child(
                            div()
                                .flex()
                                .flex_col()
                                .gap_2()
                                .min_w_0()
                                .p_3()
                                .border_1()
                                .border_color(rgb(BORDER))
                                .rounded_lg()
                                .child(
                                    row()
                                        .child(proposal.rule.name.clone())
                                        .child(ai_badge(decision, MUTED)),
                                )
                                .child(proposal.rule.description.clone())
                                .child(path_list(&proposal.rule.roots))
                                .child(proposal.rule.pattern.clone())
                                .child(
                                    div()
                                        .text_xs()
                                        .text_color(rgb(WARNING))
                                        .child(t!(Tr::CpAiDraftSafety)),
                                )
                                .when(actionable, |d| {
                                    d.child(
                                        row()
                                            .child(
                                                button(
                                                    SharedString::from(format!(
                                                        "chat-adopt-{}:{}",
                                                        entry.id, proposal.rule.id
                                                    )),
                                                    t!(Tr::CpAdoptEnable),
                                                )
                                                .on_click(cx.listener(move |this, _, _, cx| {
                                                    this.decide_chat_proposal(
                                                        adopt_entry.clone(),
                                                        adopt_rule.clone(),
                                                        true,
                                                        cx,
                                                    )
                                                })),
                                            )
                                            .child(
                                                button(
                                                    SharedString::from(format!(
                                                        "chat-edit-{}:{}",
                                                        entry.id, proposal.rule.id
                                                    )),
                                                    t!(Tr::CpEditAsUserRule),
                                                )
                                                .on_click(cx.listener(
                                                    move |this, _, window, cx| {
                                                        if this
                                                            .cleanup_panel
                                                            .chat
                                                            .proposals
                                                            .get(&edit_key)
                                                            .is_some_and(|(token, _)| {
                                                                this.cleanup_current(*token)
                                                            })
                                                            && !this.cleanup_panel.ai_busy
                                                        {
                                                            this.edit_panel_rule(
                                                                edit_rule.clone(),
                                                                Some(edit_id.clone()),
                                                                window,
                                                                cx,
                                                            );
                                                        }
                                                    },
                                                )),
                                            )
                                            .child(
                                                button(
                                                    SharedString::from(format!(
                                                        "chat-reject-{}:{}",
                                                        entry.id, proposal.rule.id
                                                    )),
                                                    t!(Tr::CpReject),
                                                )
                                                .on_click(cx.listener(move |this, _, _, cx| {
                                                    this.decide_chat_proposal(
                                                        reject_entry.clone(),
                                                        reject_rule.clone(),
                                                        false,
                                                        cx,
                                                    )
                                                })),
                                            ),
                                    )
                                }),
                        );
                }
                messages = messages.child(message);
            }
        }
        let mut current = div().flex_1().min_w_0().min_h_0().flex().flex_col().gap_2();
        if let Some(live) = chat
            .live
            .as_ref()
            .filter(|live| chat.selected.as_ref() == Some(&live.session_id))
        {
            let entries = live.context.wire["entries"].as_array();
            let count = entries.map_or(0, Vec::len);
            let typed = entries.map_or(0, |entries| {
                entries
                    .iter()
                    .filter(|entry| entry["file_type_hint"].is_string())
                    .count()
            });
            let markers = entries.map_or(0, |entries| {
                entries
                    .iter()
                    .map(|entry| {
                        entry["directory_evidence"]["recognized_markers"]
                            .as_array()
                            .map_or(0, Vec::len)
                    })
                    .sum::<usize>()
            });
            current = current.child(
                div().id("chat-snapshot-evidence").flex_shrink_0().text_xs().text_color(rgb(MUTED))
                    .tooltip(tooltip(t!(Tr::CpChatEvidenceHint)))
                    .child(tf!(Tr::CpChatEvidence, "entries" => count, "typed" => typed, "markers" => markers)),
            );
        }
        if let Some(turn) = &p.ai_turn {
            let label = match turn.phase {
                AiPhase::Consent => t!(Tr::CpAiPhaseConsent),
                AiPhase::Preparing => t!(Tr::CpAiPhasePreparing),
                AiPhase::Waiting => t!(Tr::CpAiPhaseWaiting),
                AiPhase::Complete => t!(Tr::CpAiPhaseComplete),
                AiPhase::Failed => t!(Tr::CpAiPhaseFailed),
                AiPhase::Cancelled => t!(Tr::CpAiPhaseCancelled),
            };
            current = current.child(
                row().flex_shrink_0()
                    .child(ai_badge(
                        label,
                        if matches!(turn.phase, AiPhase::Failed | AiPhase::Cancelled) {
                            WARNING
                        } else {
                            ACCENT
                        },
                    ))
                    .when(!turn.detail.is_empty(), |d| {
                        d.child(
                            div()
                                .flex_1()
                                .min_w_0()
                                .text_xs()
                                .child(turn.detail.clone()),
                        )
                    })
                    .when(p.ai_busy, |d| {
                        d.child(button("chat-cancel", t!(Tr::CpCancelDiscard)).on_click(
                            cx.listener(|this, _, _, cx| {
                                this.cleanup_panel.ai_sequence =
                                    this.cleanup_panel.ai_sequence.wrapping_add(1);
                                this.cleanup_panel.ai_busy = false;
                                this.set_ai_phase(
                                    AiPhase::Cancelled,
                                    t!(Tr::CpResultCancelled),
                                    cx,
                                );
                            }),
                        ))
                    }),
            );
        }
        current = current
            .child(messages)
            .child(self.render_chat_controls(can_send, cx));
        div()
            .flex()
            .gap_2()
            .min_w_0()
            .flex_1()
            .min_h_0()
            .overflow_hidden()
            .when(narrow, |d| d.flex_col())
            .child(
                div()
                    .min_w_0()
                    .flex_shrink_0()
                    .when(!narrow, |d| d.w(px(220.)))
                    .child(history),
            )
            .child(current)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "snapshot")]
    fn pending_fixture(cx: &mut Context<Petal>) -> Petal {
        let node = |name: &str, kind, parent, children| crate::scan::Node {
            name: name.into(), size: 100, kind, parent, children, items: 1,
        };
        // Synthetic scan only: never create or delete anything in the user's home.
        let home = crate::rules::SafetyContext::current().unwrap().home;
        let tree = Tree {
            root_path: home.clone(),
            nodes: vec![
                node("home", Kind::Dir, None, vec![1, 6]),
                node("Downloads", Kind::Dir, Some(0), vec![2, 3, 5, 7, 9]),
                node("archive.zip", Kind::File, Some(1), vec![]),
                node("package", Kind::Dir, Some(1), vec![4]),
                node("payload.bin", Kind::File, Some(3), vec![]),
                node("credentials.json", Kind::File, Some(1), vec![]),
                node(".ssh", Kind::Dir, Some(0), vec![]),
                node("unsafe-package", Kind::Dir, Some(1), vec![8]),
                node("credentials.json", Kind::File, Some(7), vec![]),
                node("opaque", Kind::Other, Some(1), vec![]),
                node("detached.zip", Kind::File, None, vec![]),
            ],
            ..Tree::default()
        };
        Petal {
            screen: Screen::Results(Results::new(tree, vec![], Duration::ZERO,
                home, ColorBy::Folder, ChartType::Sunburst)),
            cleanup_panel: PanelState::with_settings(Ok(Settings::default()), cx),
            menu_bar: crate::menubar::Monitor::new(),
            focus_handle: cx.focus_handle(),
            error: None, notice: None, notice_warning: false, notice_version: 0,
            access: Access::Dismissed, _access_watch: None,
            color_by: ColorBy::Folder, chart: ChartType::Sunburst,
        }
    }

    #[cfg(feature = "snapshot")]
    fn whitelist_pending_fixture(cx: &mut Context<Petal>) -> Petal {
        let mut petal = pending_fixture(cx);
        // Unique, nonexistent Downloads paths; never write to the user's home.
        let r = petal.results().unwrap();
        r.tree.nodes[3].name = format!(
            "petal-whitelist-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ).into();
        petal
    }

    #[cfg(feature = "snapshot")]
    #[gpui::test]
    fn pending_whitelist_tilde_exact_ancestor_and_descendant_skip_package(cx: &mut gpui::TestAppContext) {
        for relation in ["exact-file", "exact-directory", "ancestor", "descendant", "unscanned-descendant"] {
            let view = cx.new(whitelist_pending_fixture);
            view.update(cx, |this, cx| {
                let token = this.cleanup_token().unwrap();
                let r = this.results().unwrap();
                let package = r.tree.path_of(3);
                let file = r.tree.path_of(4);
                assert_eq!(std::fs::canonicalize(&file).unwrap_err().kind(), std::io::ErrorKind::NotFound);
                assert_eq!(r.ai_deletion_node(&package, &mut 20_000), Some(3));
                let protected = match relation {
                    "exact-file" | "descendant" => file.clone(),
                    "exact-directory" => package.clone(),
                    "ancestor" => package.parent().unwrap().to_path_buf(),
                    _ => package.join("not-in-scan/keep.bin"),
                };
                let home = crate::rules::SafetyContext::current().unwrap().home;
                let tilde = PathBuf::from("~").join(protected.strip_prefix(home).unwrap());
                this.cleanup_panel.settings.as_mut().unwrap().whitelist = vec![tilde];
                let candidate = if relation == "exact-file" { file } else { package };
                let version = this.results().unwrap().collector_version;
                assert_eq!(this.queue_ai_deletions(&[candidate], token, cx),
                    tf!(Tr::CpAiQueued, "added" => 0, "skipped" => 1), "{relation}");
                let r = this.results().unwrap();
                assert!(r.collector.is_empty(), "{relation}");
                assert!(r.ai_collector.is_empty(), "{relation}");
                assert_eq!(r.collector_version, version);
                assert!(!r.trashing);
            });
        }
    }

    #[cfg(feature = "snapshot")]
    #[gpui::test]
    fn pending_whitelist_missing_mixed_case_data_alias_blocks_both_tree_spellings(cx: &mut gpui::TestAppContext) {
        for physical_tree in [false, true] {
            for relation in ["exact", "ancestor", "descendant"] {
                let view = cx.new(whitelist_pending_fixture);
                view.update(cx, |this, cx| {
                    let token = this.cleanup_token().unwrap();
                    let r = this.results().unwrap();
                    let logical = r.tree.path_of(3);
                    let protected = match relation {
                        "ancestor" => logical.clone(),
                        "descendant" => logical.join("not-in-scan/keep.bin"),
                        _ => logical.clone(),
                    };
                    let mixed_alias = PathBuf::from(format!("/sYsTeM/vOlUmEs/dAtA{}",
                        protected.to_string_lossy().to_ascii_uppercase()));
                    assert_eq!(std::fs::canonicalize(&mixed_alias).unwrap_err().kind(), std::io::ErrorKind::NotFound);
                    if physical_tree {
                        r.tree.root_path = std::path::Path::new("/System/Volumes/Data")
                            .join(r.tree.root_path.strip_prefix("/").unwrap());
                    }
                    let candidate_ix = if relation == "ancestor" { 4 } else { 3 };
                    let candidate = r.tree.path_of(candidate_ix);
                    assert_eq!(r.ai_deletion_node(&candidate, &mut 20_000), Some(candidate_ix));
                    this.cleanup_panel.settings.as_mut().unwrap().whitelist = vec![mixed_alias];
                    assert_eq!(this.queue_ai_deletions(&[candidate], token, cx),
                        tf!(Tr::CpAiQueued, "added" => 0, "skipped" => 1),
                        "physical={physical_tree}, relation={relation}");
                    let r = this.results().unwrap();
                    assert!(r.collector.is_empty());
                    assert!(r.ai_collector.is_empty());
                    assert!(!r.trashing);
                });
            }
        }
    }

    #[cfg(feature = "snapshot")]
    #[gpui::test]
    fn pending_whitelist_sibling_string_prefix_does_not_block(cx: &mut gpui::TestAppContext) {
        for shorter_whitelist in [false, true] {
            let view = cx.new(whitelist_pending_fixture);
            view.update(cx, |this, cx| {
                let token = this.cleanup_token().unwrap();
                let r = this.results().unwrap();
                let package = r.tree.path_of(3);
                let sibling = if shorter_whitelist {
                    r.tree.nodes[3].name = format!("{}-sibling", r.tree.nodes[3].name).into();
                    package
                } else {
                    package.with_file_name(format!("{}-sibling", r.tree.nodes[3].name))
                };
                let candidate = r.tree.path_of(3);
                this.cleanup_panel.settings.as_mut().unwrap().whitelist = vec![sibling];
                assert_eq!(this.queue_ai_deletions(&[candidate], token, cx),
                    tf!(Tr::CpAiQueued, "added" => 1, "skipped" => 0));
                let r = this.results().unwrap();
                assert_eq!(r.collector, vec![3]);
                assert_eq!(r.ai_collector, HashSet::from([3]));
                assert!(!r.trashing);
            });
        }
    }

    #[cfg(feature = "snapshot")]
    #[gpui::test]
    fn pending_whitelist_relative_configuration_fails_closed(cx: &mut gpui::TestAppContext) {
        let view = cx.new(whitelist_pending_fixture);
        view.update(cx, |this, cx| {
            let token = this.cleanup_token().unwrap();
            let package = this.results().unwrap().tree.path_of(3);
            // Replace only in-memory settings, never validate/save a disk configuration.
            this.cleanup_panel.settings.as_mut().unwrap().whitelist = vec![PathBuf::from("Downloads/keep")];
            let version = this.results().unwrap().collector_version;
            assert_eq!(this.queue_ai_deletions(&[package], token, cx), t!(Tr::CpAiPendingExpired));
            let r = this.results().unwrap();
            assert!(r.collector.is_empty());
            assert!(r.ai_collector.is_empty());
            assert_eq!(r.collector_version, version);
            assert!(!r.trashing);
        });
    }

    #[cfg(all(feature = "snapshot", target_os = "macos"))]
    #[gpui::test]
    fn pending_whitelist_real_root_symlink_cannot_hide_protected_ancestor_or_descendant(cx: &mut gpui::TestAppContext) {
        let fixture = crate::rules::fixtures::Fixture::new();
        let real_file = fixture.file("Downloads/package/payload.bin", 0);
        let real_root = fixture.ctx.home.join("Downloads");
        let alias = fixture.dir.join("Downloads");
        std::os::unix::fs::symlink(&real_root, &alias).unwrap();
        let safety = crate::rules::SafetyContext::current().unwrap();
        assert!(safety.in_scope(&alias), "fixture must be inside the approved OS temp scope");
        assert_eq!(std::fs::canonicalize(&alias).unwrap(), real_root);
        for relation in ["ancestor", "descendant", "whitelist-alias"] {
            let view = cx.new(|cx| {
                let mut petal = pending_fixture(cx);
                let node = |name: &str, kind, parent, children| crate::scan::Node {
                    name: name.into(), size: 12, kind, parent, children, items: 1,
                };
                let r = petal.results().unwrap();
                r.tree = Tree {
                    root_path: alias.clone(),
                    nodes: vec![
                        node("Downloads", Kind::Dir, None, vec![1]),
                        node("package", Kind::Dir, Some(0), vec![2]),
                        node("payload.bin", Kind::File, Some(1), vec![]),
                    ],
                    ..Tree::default()
                };
                r.requested_root = alias.clone();
                petal
            });
            view.update(cx, |this, cx| {
                let token = this.cleanup_token().unwrap();
                let candidate = this.results().unwrap().tree.path_of(1);
                // Positive control proves the alias is eligible without a whitelist.
                this.cleanup_panel.settings.as_mut().unwrap().whitelist.clear();
                assert_eq!(this.queue_ai_deletions(&[candidate.clone()], token, cx),
                    tf!(Tr::CpAiQueued, "added" => 1, "skipped" => 0));
                this.results().unwrap().revoke_ai_collector();
                let protected = match relation {
                    "ancestor" => real_root.clone(),
                    "descendant" => real_file.clone(),
                    _ => {
                        let second_alias = fixture.dir.join("keep-alias");
                        std::os::unix::fs::symlink(&real_root, &second_alias).unwrap();
                        second_alias
                    }
                };
                this.cleanup_panel.settings.as_mut().unwrap().whitelist = vec![protected];
                let version = this.results().unwrap().collector_version;
                assert_eq!(this.queue_ai_deletions(&[candidate], token, cx),
                    tf!(Tr::CpAiQueued, "added" => 0, "skipped" => 1), "{relation}");
                let r = this.results().unwrap();
                assert!(r.collector.is_empty());
                assert!(r.ai_collector.is_empty());
                assert_eq!(r.collector_version, version);
                assert!(!r.trashing);
            });
        }
        // Fixture::drop removes only this private OS-temp directory, including aliases.
    }

    #[cfg(feature = "snapshot")]
    #[gpui::test]
    fn pending_queue_checks_tokens_live_safety_duplicates_and_never_trashes(cx: &mut gpui::TestAppContext) {
        let view = cx.new(pending_fixture);
        view.update(cx, |this, cx| {
            let token = this.cleanup_token().unwrap();
            let Screen::Results(r) = &this.screen else { panic!("results") };
            let file = r.tree.path_of(2);
            let directory = r.tree.path_of(3);
            let unsafe_paths = vec![r.tree.path_of(0), r.tree.path_of(5), r.tree.path_of(6),
                r.tree.path_of(7), r.tree.path_of(9), r.tree.root_path.join("Downloads/missing.zip")];
            for old in [Token { scan: token.scan + 1, ..token },
                Token { revision: token.revision + 1, ..token },
                Token { generation: token.generation + 1, ..token }] {
                assert_eq!(this.queue_ai_deletions(&[file.clone()], old, cx), t!(Tr::CpAiPendingExpired));
                assert!(this.results().unwrap().collector.is_empty());
            }
            assert_eq!(this.queue_ai_deletions(&unsafe_paths, token, cx),
                tf!(Tr::CpAiQueued, "added" => 0, "skipped" => unsafe_paths.len()));
            assert!(this.results().unwrap().collector.is_empty());
            // A stale scan index cannot restore a detached item.
            this.results().unwrap().tree.nodes[1].children.push(10);
            let detached = this.results().unwrap().tree.root_path.join("Downloads/detached.zip");
            assert_eq!(this.queue_ai_deletions(&[detached], token, cx),
                tf!(Tr::CpAiQueued, "added" => 0, "skipped" => 1));
            this.results().unwrap().tree.nodes[1].children.retain(|&ix| ix != 10);
            assert_eq!(this.queue_ai_deletions(&[file.clone(), directory.clone(), file.clone()], token, cx),
                tf!(Tr::CpAiQueued, "added" => 2, "skipped" => 1));
            let r = this.results().unwrap();
            assert_eq!(r.collector.iter().copied().collect::<HashSet<_>>(), HashSet::from([2, 3]));
            assert_eq!(r.ai_collector, HashSet::from([2, 3]));
            assert!(!r.trashing, "queueing is not execution authorization");
            let version = r.collector_version;
            assert_eq!(this.queue_ai_deletions(&[file.clone(), directory], token, cx),
                tf!(Tr::CpAiQueued, "added" => 0, "skipped" => 2));
            assert!(!this.results().unwrap().trashing);
            // A refreshed row must not remove a newly updated shared selection.
            assert!(!this.chat_pending_guard(token.scan, version.wrapping_sub(1), cx));
            assert_eq!(this.cleanup_panel.message, t!(Tr::CpAiPendingChanged));
            let count = this.results().unwrap().collector.len();
            this.remove_chat_pending(token.scan, version.wrapping_sub(1), Some(2), cx);
            assert_eq!(this.results().unwrap().collector.len(), count);
            // Configuration invalidation must remove AI-only nominations (app.rs contract).
            this.invalidate_cleanup_jobs();
            assert!(this.results().unwrap().ai_collector.is_empty());
            assert!(this.results().unwrap().collector.is_empty());
            assert_eq!(this.queue_ai_deletions(&[file], token, cx), t!(Tr::CpAiPendingExpired));
        });
    }

    #[cfg(feature = "snapshot")]
    #[gpui::test]
    fn pending_queue_and_row_actions_reject_busy_and_unready_states(cx: &mut gpui::TestAppContext) {
        let view = cx.new(pending_fixture);
        view.update(cx, |this, cx| {
            let token = this.cleanup_token().unwrap();
            let file = this.results().unwrap().tree.path_of(2);
            for busy in 0..7 {
                this.cleanup_panel.ai_busy = busy == 0;
                this.cleanup_panel.cleanup_busy = busy == 1;
                let r = this.results().unwrap();
                r.trashing = busy == 2;
                r.refreshing = busy == 3;
                r.out_of_date = busy == 4;
                r.admin = if busy == 5 { AdminRead::Reading } else { AdminRead::Done };
                r.deleting_snapshots = busy == 6;
                let version = r.collector_version;
                assert!(!this.chat_pending_ready());
                assert!(!this.chat_pending_guard(token.scan, version, cx));
                assert_eq!(this.queue_ai_deletions(&[file.clone()], token, cx), t!(Tr::CpAiPendingExpired));
                assert!(this.results().unwrap().collector.is_empty());
            }
            this.results().unwrap().deleting_snapshots = false;
            assert!(this.chat_pending_ready());
            this.queue_ai_deletions(&[file], token, cx);
            let version = this.results().unwrap().collector_version;
            for ai_busy in [true, false] {
                this.cleanup_panel.ai_busy = ai_busy;
                this.cleanup_panel.cleanup_busy = !ai_busy;
                this.remove_chat_pending(token.scan, version, Some(2), cx);
                this.remove_chat_pending(token.scan, version, None, cx);
                assert_eq!(this.results().unwrap().collector, vec![2]);
                assert!(!this.results().unwrap().trashing);
            }
            this.cleanup_panel.cleanup_busy = false;
            this.remove_chat_pending(token.scan, version, Some(2), cx);
            assert!(this.results().unwrap().collector.is_empty());
            assert!(this.results().unwrap().ai_collector.is_empty());
        });
    }

    #[cfg(feature = "snapshot")]
    #[gpui::test]
    fn pending_response_feedback_is_saved_after_completion_and_stale_candidates_are_not_queued(cx: &mut gpui::TestAppContext) {
        let view = cx.new(pending_fixture);
        view.update(cx, |this, cx| {
            let token = this.cleanup_token().unwrap();
            let response = AgentResponse {
                explanation: "Review only".into(), proposals: vec![],
                pending_deletions: vec![this.results().unwrap().tree.path_of(2)],
            };
            for actionable in [false, true] {
                this.cleanup_panel.chat.begin("analyze".into(), "analyze".into(), None, true);
                this.cleanup_panel.ai_turn = Some(AiTurn::new("analyze".into()));
                let detail = this.ai_response_detail(&response, token, actionable, cx);
                if !actionable {
                    assert_eq!(detail, t!(Tr::CpAiPendingExpired));
                    assert!(this.results().unwrap().collector.is_empty());
                } else {
                    assert_eq!(detail, tf!(Tr::CpAiQueued, "added" => 1, "skipped" => 0));
                }
                this.cleanup_panel.chat.complete_with_detail(&response, token, actionable, Some(&detail), cx);
                this.set_ai_phase(AiPhase::Complete, detail.clone(), cx);
                let chat = &this.cleanup_panel.chat;
                let session = chat.archive.sessions.iter().find(|s| Some(&s.id) == chat.selected.as_ref()).unwrap();
                assert_eq!(session.messages.last().unwrap().detail, detail);
                assert!(!this.results().unwrap().trashing);
            }
            let empty = AgentResponse { explanation: "Advice".into(), proposals: vec![], pending_deletions: vec![] };
            assert_eq!(this.ai_response_detail(&empty, token, false, cx), t!(Tr::CpAiSnapshotNotice));
            // Manual nominations share the same confirmation list, but not AI ownership.
            let version = this.results().unwrap().collector_version;
            this.remove_chat_pending(token.scan, version, None, cx);
            this.results().unwrap().collect(2);
            this.collector_changed(cx);
            this.queue_ai_deletions(&response.pending_deletions, token, cx);
            assert_eq!(this.results().unwrap().collector, vec![2]);
            assert!(this.results().unwrap().ai_collector.is_empty());
        });
    }

    #[cfg(feature = "snapshot")]
    #[gpui::test]
    fn pending_list_pages_keep_the_complete_shared_list_reachable(cx: &mut gpui::TestAppContext) {
        let window = cx.open_window(gpui::size(px(1100.), px(850.)), |_, cx| {
            let mut petal = pending_fixture(cx);
            petal.cleanup_panel.open = true;
            petal.cleanup_panel.tab = 2;
            petal.cleanup_panel.ai_config_expanded = false;
            let r = petal.results().unwrap();
            r.collector.clear();
            for i in 0..51 {
                let ix = r.tree.nodes.len();
                r.tree.nodes[1].children.push(ix);
                r.tree.nodes.push(crate::scan::Node {
                    name: format!("manual-{i}.zip").into(), size: 100 + i,
                    kind: Kind::File, parent: Some(1), children: vec![], items: 1,
                });
                r.collector.push(ix);
            }
            petal
        });
        let view = window.root(cx).unwrap();
        let mut visual = gpui::VisualTestContext::from_window(window.into(), cx);
        visual.update(|window, cx| window.draw(cx).clear(cx));
        assert!(visual.debug_bounds("chat-pending-path-0").is_some());
        assert!(visual.debug_bounds("chat-pending-path-50").is_none(),
            "only the current 50-item page is rendered");
        assert!(visual.debug_bounds("chat-pending-confirm").is_some());
        view.update(&mut visual, |this, cx| {
            this.cleanup_panel.chat.pending_page = 1;
            this.cleanup_panel.chat.pending_scroll.set_offset(gpui::point(px(0.), px(0.)));
            cx.notify();
        });
        visual.update(|window, cx| window.draw(cx).clear(cx));
        assert!(visual.debug_bounds("chat-pending-path-50").is_some(),
            "the 51st shared manual item remains reachable");
        assert!(visual.debug_bounds("chat-pending-path-0").is_none());
        view.read_with(&visual, |this, _| {
            let Screen::Results(r) = &this.screen else { panic!("results") };
            assert_eq!(r.collector.len(), 51);
            assert!(r.ai_collector.is_empty());
            assert!(!r.trashing);
        });
    }

    #[cfg(feature = "snapshot")]
    #[gpui::test]
    fn populated_pending_and_messages_scroll_without_displacing_small_window_composer(
        cx: &mut gpui::TestAppContext,
    ) {
        for (width, height) in [(520., 640.), (700., 640.)] {
            let window = cx.open_window(gpui::size(px(width), px(height)), |_, cx| {
                let mut petal = pending_fixture(cx);
                petal.cleanup_panel.open = true;
                petal.cleanup_panel.tab = 2;
                petal.cleanup_panel.ai_config_expanded = false;
                let r = petal.results().unwrap();
                r.collector.clear();
                for i in 0..51 {
                    let ix = r.tree.nodes.len();
                    r.tree.nodes[1].children.push(ix);
                    r.tree.nodes.push(crate::scan::Node {
                        name: format!("manual-{i}.zip").into(), size: 100 + i,
                        kind: Kind::File, parent: Some(1), children: vec![], items: 1,
                    });
                    r.collector.push(ix);
                }
                let chat = &mut petal.cleanup_panel.chat;
                chat.begin("Small window question".into(), "Small window question".into(), None, true);
                chat.complete(
                    &AgentResponse {
                        explanation: "## Answer\n\nA paragraph of advice.\n\n".repeat(50),
                        pending_deletions: vec![], proposals: vec![],
                    },
                    Token { scan: 1, revision: 0, generation: 0 },
                    false, cx,
                );
                chat.scroll.set_offset(gpui::point(px(0.), px(0.)));
                petal
            });
            let view = window.root(cx).unwrap();
            let mut visual = gpui::VisualTestContext::from_window(window.into(), cx);
            visual.update(|window, cx| window.draw(cx).clear(cx));
            // Explicitly inspect the top of the shared message/pending scroll area.
            view.update(&mut visual, |this, cx| {
                this.cleanup_panel.chat.scroll.set_offset(gpui::point(px(0.), px(0.)));
                cx.notify();
            });
            visual.update(|window, cx| window.draw(cx).clear(cx));
            let composer = visual.debug_bounds("chat-composer").expect("composer exists");
            assert!(composer.top() >= px(0.) && composer.bottom() <= px(height));
            assert!(composer.left() >= px(0.) && composer.right() <= px(width));
            let viewport = view.read_with(&visual, |this, _| this.cleanup_panel.chat.scroll.bounds());
            assert!(viewport.size.height > px(100.), "messages retain usable scroll space: {width}x{height}, viewport={viewport:?}, composer={composer:?}");
            let pending = visual.debug_bounds("chat-pending").expect("pending list exists");
            assert!(pending.top() >= viewport.top() && pending.top() < viewport.bottom());
            assert!(visual.debug_bounds("chat-pending-path-0").is_some());
            assert!(visual.debug_bounds("chat-pending-confirm").is_some());
            view.read_with(&visual, |this, _| {
                let list = this.cleanup_panel.chat.pending_scroll.bounds();
                assert!(list.size.height >= px(100.) && list.size.height <= px(120.));
                assert!(this.cleanup_panel.chat.pending_scroll.max_offset().y > px(0.));
                assert!(this.cleanup_panel.chat.scroll.max_offset().y > px(0.));
            });
            view.update(&mut visual, |this, cx| {
                this.cleanup_panel.chat.pending_page = 1;
                this.cleanup_panel.chat.pending_scroll.set_offset(gpui::point(px(0.), px(0.)));
                cx.notify();
            });
            visual.update(|window, cx| window.draw(cx).clear(cx));
            assert!(visual.debug_bounds("chat-pending-path-50").is_some());
            assert!(visual.debug_bounds("chat-pending-path-0").is_none());
            assert_eq!(visual.debug_bounds("chat-composer").unwrap(), composer);
            view.update(&mut visual, |this, cx| {
                this.cleanup_panel.chat.scroll.scroll_to_bottom();
                cx.notify();
            });
            visual.update(|window, cx| window.draw(cx).clear(cx));
            assert_eq!(visual.debug_bounds("chat-composer").unwrap(), composer);
            view.read_with(&visual, |this, _| {
                assert!(this.cleanup_panel.chat.scroll.offset().y < px(0.));
                let Screen::Results(r) = &this.screen else { panic!("results") };
                assert_eq!(r.collector.len(), 51);
                assert!(!r.trashing);
            });
        }
    }

    #[cfg(feature = "snapshot")]
    #[gpui::test]
    fn pending_invalidation_revokes_only_ai_owned_items_and_bumps_version(cx: &mut gpui::TestAppContext) {
        for scan_only in [true, false] {
            let view = cx.new(pending_fixture);
            view.update(cx, |this, cx| {
                this.results().unwrap().collect(4);
                this.collector_changed(cx);
                let token = this.cleanup_token().unwrap();
                let file = this.results().unwrap().tree.path_of(2);
                assert_eq!(this.queue_ai_deletions(&[file], token, cx),
                    tf!(Tr::CpAiQueued, "added" => 1, "skipped" => 0));
                let r = this.results().unwrap();
                assert_eq!(r.collector, vec![4, 2]);
                assert_eq!(r.ai_collector, HashSet::from([2]));
                let version = r.collector_version;
                r.collector_frees.set(Some(200));
                if scan_only { this.invalidate_scan_cleanup_jobs(); }
                else { this.invalidate_cleanup_jobs(); }
                assert!(!this.cleanup_current(token));
                let r = this.results().unwrap();
                assert_eq!(r.collector, vec![4], "manual file must survive either invalidation");
                assert!(r.ai_collector.is_empty());
                assert_eq!(r.collector_version, version.wrapping_add(1));
                assert_eq!(r.collector_frees.get(), None);
                assert!(!r.trashing);
                r.revoke_ai_collector();
                assert_eq!(r.collector_version, version.wrapping_add(1), "revocation is idempotent");
            });
        }
    }

    #[cfg(feature = "snapshot")]
    #[gpui::test]
    fn pending_ai_parent_cannot_subsume_manually_selected_descendant(cx: &mut gpui::TestAppContext) {
        let view = cx.new(pending_fixture);
        view.update(cx, |this, cx| {
            this.results().unwrap().collect(4);
            this.collector_changed(cx);
            let token = this.cleanup_token().unwrap();
            let parent = this.results().unwrap().tree.path_of(3);
            let version = this.results().unwrap().collector_version;
            assert_eq!(this.queue_ai_deletions(&[parent], token, cx),
                tf!(Tr::CpAiQueued, "added" => 0, "skipped" => 1));
            let r = this.results().unwrap();
            assert_eq!(r.collector, vec![4]);
            assert!(r.ai_collector.is_empty());
            assert_eq!(r.collector_version, version);
            this.invalidate_scan_cleanup_jobs();
            assert_eq!(this.results().unwrap().collector, vec![4]);
            assert_eq!(this.results().unwrap().collector_version, version);
        });
    }

    #[cfg(feature = "snapshot")]
    #[gpui::test]
    fn pending_manual_parent_replaces_ai_child_and_survives_invalidation(cx: &mut gpui::TestAppContext) {
        for scan_only in [true, false] {
            let view = cx.new(pending_fixture);
            view.update(cx, |this, cx| {
                let token = this.cleanup_token().unwrap();
                let child = this.results().unwrap().tree.path_of(4);
                assert_eq!(this.queue_ai_deletions(&[child], token, cx),
                    tf!(Tr::CpAiQueued, "added" => 1, "skipped" => 0));
                assert_eq!(this.results().unwrap().ai_collector, HashSet::from([4]));
                // Use the real manual selection path, including ownership reconciliation.
                this.collect_items(&[3], cx);
                let r = this.results().unwrap();
                assert_eq!(r.collector, vec![3]);
                assert!(r.ai_collector.is_empty());
                let version = r.collector_version;
                if scan_only { this.invalidate_scan_cleanup_jobs(); }
                else { this.invalidate_cleanup_jobs(); }
                let r = this.results().unwrap();
                assert_eq!(r.collector, vec![3]);
                assert!(r.ai_collector.is_empty());
                assert_eq!(r.collector_version, version);
                assert!(!r.trashing);
            });
        }
    }

    #[cfg(feature = "snapshot")]
    #[gpui::test]
    fn pending_invalidation_preserves_confirmed_trashing_selection(cx: &mut gpui::TestAppContext) {
        let view = cx.new(pending_fixture);
        view.update(cx, |this, cx| {
            let token = this.cleanup_token().unwrap();
            let path = this.results().unwrap().tree.path_of(2);
            this.queue_ai_deletions(&[path], token, cx);
            let r = this.results().unwrap();
            let version = r.collector_version;
            r.collector_frees.set(Some(100));
            // State-only simulation: never call the execution path.
            r.trashing = true;
            this.invalidate_scan_cleanup_jobs();
            this.invalidate_cleanup_jobs();
            let r = this.results().unwrap();
            assert_eq!(r.collector, vec![2]);
            assert_eq!(r.ai_collector, HashSet::from([2]));
            assert_eq!(r.collector_version, version);
            assert_eq!(r.collector_frees.get(), Some(100));
            r.trashing = false;
            r.revoke_ai_collector();
            assert!(r.collector.is_empty());
            assert!(r.ai_collector.is_empty());
            assert_eq!(r.collector_version, version.wrapping_add(1));
            assert_eq!(r.collector_frees.get(), Some(0));
        });
    }

    #[cfg(feature = "snapshot")]
    #[gpui::test]
    fn pending_data_volume_logical_paths_resolve_exactly_once(cx: &mut gpui::TestAppContext) {
        let view = cx.new(pending_fixture);
        view.update(cx, |this, cx| {
            let token = this.cleanup_token().unwrap();
            let r = this.results().unwrap();
            let logical_root = r.tree.root_path.clone();
            let logical = r.tree.path_of(2);
            let physical_root = std::path::Path::new("/System/Volumes/Data")
                .join(logical_root.strip_prefix("/").unwrap());
            r.tree.root_path = physical_root.clone();
            let physical = r.tree.path_of(2);
            assert_eq!(r.shown_path(2), logical);
            assert_eq!(r.ai_deletion_node(&logical, &mut 20_000), Some(2));
            assert_eq!(r.ai_deletion_node(&physical, &mut 20_000), Some(2));
            let double_prefix = std::path::Path::new("/System/Volumes/Data")
                .join(physical.strip_prefix("/").unwrap());
            for missing in [double_prefix, physical_root.join("Downloads/archive.zip.extra"),
                physical_root.join("Downloads/missing.zip"),
                logical_root.join("Downloads/../Downloads/archive.zip"),
                PathBuf::from("Downloads/archive.zip")] {
                assert_eq!(r.ai_deletion_node(&missing, &mut 20_000), None, "{}", missing.display());
            }
            assert_eq!(this.queue_ai_deletions(&[logical, physical], token, cx),
                tf!(Tr::CpAiQueued, "added" => 1, "skipped" => 1));
            assert_eq!(this.results().unwrap().collector, vec![2]);
            assert_eq!(this.results().unwrap().ai_collector, HashSet::from([2]));
            assert!(!this.results().unwrap().trashing);
        });
    }

    #[cfg(feature = "snapshot")]
    #[gpui::test]
    fn pending_fulltree_protected_descendants_and_unreadable_ranges_fail_closed(cx: &mut gpui::TestAppContext) {
        let view = cx.new(pending_fixture);
        view.update(cx, |this, cx| {
            let token = this.cleanup_token().unwrap();
            let r = this.results().unwrap();
            let parent = r.tree.path_of(3);
            let safe_child = r.tree.nodes[4].clone();
            // A safe nominated folder must be rejected for ANY protected descendant,
            // irrespective of what the AI snapshot happened to sample.
            for name in ["credentials.json", ".env", "private.key", "nested.app", "nested.bundle", ".ssh"] {
                r.tree.nodes[4].name = name.into();
                assert_eq!(r.ai_deletion_node(&parent, &mut 20_000), None, "{name}");
            }
            r.tree.nodes[4] = safe_child.clone();
            r.tree.nodes[4].kind = Kind::Other;
            assert_eq!(r.ai_deletion_node(&parent, &mut 20_000), None);
            r.tree.nodes[4] = safe_child.clone();
            r.tree.nodes[4].parent = Some(1);
            assert_eq!(r.ai_deletion_node(&parent, &mut 20_000), None, "broken descendant chain");
            r.tree.nodes[4] = safe_child;
            assert_eq!(r.ai_deletion_node(&parent, &mut 20_000), Some(3));
            for whole in [true, false] {
                for unreadable in [parent.clone(), parent.join("not-in-snapshot"), r.tree.path_of(1)] {
                    r.tree.unreadable = vec![crate::scan::Unreadable { path: unreadable, whole, errors: 1 }];
                    assert_eq!(r.ai_deletion_node(&parent, &mut 20_000), None);
                }
            }
            // A sibling with a shared string prefix is not an ancestor/descendant.
            r.tree.unreadable = vec![crate::scan::Unreadable {
                path: r.tree.path_of(1).join("package-sibling"), whole: true, errors: 1,
            }];
            assert_eq!(r.ai_deletion_node(&parent, &mut 20_000), Some(3));
            r.tree.unreadable.clear();
            // Repeat against a Data-volume tree: unreadable paths are physical.
            let physical_root = std::path::Path::new("/System/Volumes/Data")
                .join(r.tree.root_path.strip_prefix("/").unwrap());
            r.tree.root_path = physical_root;
            r.tree.unreadable.push(crate::scan::Unreadable {
                path: r.tree.path_of(3).join("unseen"), whole: false, errors: 1,
            });
            assert_eq!(r.ai_deletion_node(&parent, &mut 20_000), None);
            assert_eq!(this.queue_ai_deletions(&[parent], token, cx),
                tf!(Tr::CpAiQueued, "added" => 0, "skipped" => 1));
            assert!(this.results().unwrap().collector.is_empty());
            assert!(this.results().unwrap().ai_collector.is_empty());
            assert!(!this.results().unwrap().trashing);
        });
    }

    #[cfg(feature = "snapshot")]
    #[gpui::test]
    fn pending_queue_enforces_fifty_paths_and_shared_fulltree_budget(cx: &mut gpui::TestAppContext) {
        let view = cx.new(pending_fixture);
        view.update(cx, |this, cx| {
            let token = this.cleanup_token().unwrap();
            let r = this.results().unwrap();
            let mut paths = Vec::new();
            for i in 0..51 {
                let ix = r.tree.nodes.len();
                r.tree.nodes.push(crate::scan::Node {
                    name: format!("limit-{i}.zip").into(), size: 1, kind: Kind::File,
                    parent: Some(1), children: vec![], items: 1,
                });
                r.tree.nodes[1].children.push(ix);
                paths.push(r.tree.path_of(ix));
            }
            let omitted = r.tree.find(&paths[50]).unwrap();
            assert_eq!(this.queue_ai_deletions(&paths, token, cx),
                tf!(Tr::CpAiQueued, "added" => 50, "skipped" => 1));
            let r = this.results().unwrap();
            assert_eq!(r.collector.len(), 50);
            assert_eq!(r.ai_collector.len(), 50);
            assert!(!r.collector.contains(&omitted));
            assert!(!r.trashing);
        });
        let view = cx.new(pending_fixture);
        view.update(cx, |this, cx| {
            let token = this.cleanup_token().unwrap();
            let r = this.results().unwrap();
            // Folder + 19,998 files costs 19,999 visits, leaving exactly one
            // visit for archive.zip. The third nomination must fail closed.
            for i in 0..19_997 {
                let ix = r.tree.nodes.len();
                r.tree.nodes.push(crate::scan::Node {
                    name: format!("budget-{i}.bin").into(), size: 1, kind: Kind::File,
                    parent: Some(3), children: vec![], items: 1,
                });
                r.tree.nodes[3].children.push(ix);
            }
            let directory = r.tree.path_of(3);
            let file = r.tree.path_of(2);
            let mut insufficient = 19_998;
            assert_eq!(r.ai_deletion_node(&directory, &mut insufficient), None);
            let mut exact = 19_999;
            assert_eq!(r.ai_deletion_node(&directory, &mut exact), Some(3));
            assert_eq!(exact, 0);
            // Turn the unrelated opaque node into another eligible file.
            r.tree.nodes[9].kind = Kind::File;
            let last = r.tree.path_of(9);
            assert_eq!(r.ai_deletion_node(&last, &mut 0), None);
            assert_eq!(this.queue_ai_deletions(&[directory, file, last], token, cx),
                tf!(Tr::CpAiQueued, "added" => 2, "skipped" => 1));
            let r = this.results().unwrap();
            assert_eq!(r.collector, vec![3, 2]);
            assert_eq!(r.ai_collector, HashSet::from([3, 2]));
            assert!(!r.trashing);
        });
    }

    #[cfg(feature = "snapshot")]
    const PENDING_AUTHORITY_CHANGES: &[&str] = &[
        "collector", "scan", "revision", "generation", "scan-invalidation", "config-invalidation",
        "ai-busy", "cleanup-busy", "key-busy", "test-busy", "refreshing", "out-of-date",
        "admin-reading", "deleting-snapshots", "settings-error", "trashing", "no-scan",
    ];

    #[cfg(feature = "snapshot")]
    fn change_pending_authority(this: &mut Petal, change: &str, cx: &mut Context<Petal>) {
        match change {
            "collector" => this.collect_items(&[4], cx),
            "scan" => {
                let r = this.results().unwrap();
                r.id = r.id.wrapping_add(1);
            }
            "revision" => this.cleanup_panel.revision = this.cleanup_panel.revision.wrapping_add(1),
            "generation" => this.cleanup_panel.generation = this.cleanup_panel.generation.wrapping_add(1),
            "scan-invalidation" => this.invalidate_scan_cleanup_jobs(),
            "config-invalidation" => this.invalidate_cleanup_jobs(),
            "ai-busy" => this.cleanup_panel.ai_busy = true,
            "cleanup-busy" => this.cleanup_panel.cleanup_busy = true,
            "key-busy" => this.cleanup_panel.key_busy = true,
            "test-busy" => this.cleanup_panel.test_busy = true,
            "refreshing" => this.results().unwrap().refreshing = true,
            "out-of-date" => this.results().unwrap().out_of_date = true,
            "admin-reading" => this.results().unwrap().admin = AdminRead::Reading,
            "deleting-snapshots" => this.results().unwrap().deleting_snapshots = true,
            "settings-error" => this.cleanup_panel.settings = Err("synthetic settings error".into()),
            "trashing" => this.results().unwrap().trashing = true,
            "no-scan" => this.screen = Screen::Start(vec![]),
            _ => panic!("unknown authority change: {change}"),
        }
    }

    #[cfg(feature = "snapshot")]
    #[gpui::test]
    fn pending_confirmation_authority_checks_tokens_version_and_all_busy_guards(cx: &mut gpui::TestAppContext) {
        for &change in PENDING_AUTHORITY_CHANGES {
            let view = cx.new(pending_fixture);
            view.update(cx, |this, cx| {
                this.collect_items(&[2], cx);
                let captured = this.collector_cleanup_authority().expect("ready fixture");
                assert_eq!(captured, (this.cleanup_token().unwrap(), this.results().unwrap().collector_version));
                change_pending_authority(this, change, cx);
                let current = this.collector_cleanup_authority();
                assert_ne!(current, Some(captured), "{change} must revoke captured authority");
                if matches!(change, "collector" | "scan" | "revision" | "generation" |
                    "scan-invalidation" | "config-invalidation") {
                    assert!(current.is_some(), "{change} changes authority without making the UI busy");
                } else {
                    assert!(current.is_none(), "{change} must deny authority entirely");
                }
            });
        }
    }

    #[cfg(feature = "snapshot")]
    fn pending_prompt_fixture(cx: &mut Context<Petal>) -> Petal {
        let mut petal = pending_fixture(cx);
        // No filesystem setup. Even prompt details refer only to synthetic paths,
        // not the fixture's otherwise plausible Downloads/archive.zip.
        let r = petal.results().unwrap();
        r.tree.root_path = r.tree.root_path.join("Downloads/petal-regression-native-prompt-not-created");
        r.requested_root = r.tree.root_path.clone();
        petal.collect_items(&[2], cx);
        petal
    }

    #[cfg(feature = "snapshot")]
    #[gpui::test]
    fn pending_native_prompt_is_not_opened_without_ready_authority(cx: &mut gpui::TestAppContext) {
        for &change in PENDING_AUTHORITY_CHANGES {
            if matches!(change, "collector" | "scan" | "revision" | "generation" |
                "scan-invalidation" | "config-invalidation") { continue; }
            let window = cx.add_window(|_, cx| pending_prompt_fixture(cx));
            window.update(cx, |this, window, cx| {
                change_pending_authority(this, change, cx);
                assert_eq!(this.collector_cleanup_authority(), None, "{change}");
                this.trash_collected(window, cx);
            }).unwrap();
            assert!(!cx.has_pending_prompt(), "{change}: reject before asking for confirmation");
            cx.run_until_parked();
            window.update(cx, |this, window, _| {
                if let Screen::Results(r) = &this.screen {
                    assert_eq!(r.trashing, change == "trashing", "{change}: execution state unchanged");
                    assert!(r.trashed.is_none());
                    assert_eq!(r.collector, vec![2]);
                    assert!(r.tree.is_attached(2));
                }
                window.remove_window();
            }).unwrap();
        }
    }

    #[cfg(feature = "snapshot")]
    #[gpui::test]
    fn pending_native_prompt_cancellation_never_enters_trashing(cx: &mut gpui::TestAppContext) {
        let window = cx.add_window(|_, cx| pending_prompt_fixture(cx));
        let captured = window.update(cx, |this, window, cx| {
            let captured = this.collector_cleanup_authority().unwrap();
            this.trash_collected(window, cx);
            assert!(!this.results().unwrap().trashing);
            captured
        }).unwrap();
        assert!(cx.has_pending_prompt());
        cx.simulate_prompt_answer(t!(Tr::Cancel));
        cx.run_until_parked();
        assert!(!cx.has_pending_prompt());
        window.update(cx, |this, window, _| {
            assert_eq!(this.collector_cleanup_authority(), Some(captured));
            let r = this.results().unwrap();
            assert!(!r.trashing);
            assert!(r.trashed.is_none());
            assert_eq!(r.collector, vec![2]);
            assert!(r.tree.is_attached(2));
            window.remove_window();
        }).unwrap();
    }

    #[cfg(feature = "snapshot")]
    #[gpui::test]
    fn pending_native_prompt_stale_confirmation_never_enters_trashing(cx: &mut gpui::TestAppContext) {
        for &change in PENDING_AUTHORITY_CHANGES {
            // Already-trashing is a helper-only test: do not set the very state
            // this callback test is intended to prove it never enters.
            if change == "trashing" { continue; }
            let window = cx.add_window(|_, cx| pending_prompt_fixture(cx));
            window.update(cx, |this, window, cx| {
                let captured = this.collector_cleanup_authority().unwrap();
                this.trash_collected(window, cx);
                assert!(!this.results().unwrap().trashing);
                change_pending_authority(this, change, cx);
                // Safety invariant: NEVER answer yes to an unchanged authority.
                assert_ne!(this.collector_cleanup_authority(), Some(captured), "{change}");
            }).unwrap();
            assert!(cx.has_pending_prompt(), "{change}: real prompt path must be exercised");
            cx.simulate_prompt_answer(t!(Tr::MoveToTrashButton));
            cx.run_until_parked();
            assert!(!cx.has_pending_prompt());
            window.update(cx, |this, window, _| {
                assert!(this.notice_warning, "{change}: confirmation callback rejected stale authority");
                if let Screen::Results(r) = &this.screen {
                    assert!(!r.trashing, "{change}");
                    assert!(r.trashed.is_none(), "{change}");
                    assert!(r.tree.is_attached(2), "{change}: original item was not detached");
                    assert!(r.collector.contains(&2), "{change}: manual selection survives");
                } else {
                    assert_eq!(change, "no-scan");
                }
                window.remove_window();
            }).unwrap();
        }
    }

    struct ThreadWake(std::thread::Thread);
    impl std::task::Wake for ThreadWake {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.unpark();
        }
    }

    fn wait_without_ui(mut wait: ChatSaveWait) -> Result<(), String> {
        let waker = Waker::from(Arc::new(ThreadWake(std::thread::current())));
        let mut cx = TaskContext::from_waker(&waker);
        loop {
            match Pin::new(&mut wait).poll(&mut cx) {
                Poll::Ready(result) => return result,
                Poll::Pending => std::thread::park(),
            }
        }
    }

    fn close_drain_fixture(delete: bool) {
        let queue = ChatSaveQueue::default();
        let mut first = ChatArchive::default();
        let mut session = ChatSession::new("fixture".into());
        session.messages.push(entry(
            ChatRole::Assistant,
            "old reply".into(),
            ChatStatus::Complete,
        ));
        first.sessions.push(session);
        assert!(queue.enqueue(first.clone()));
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let written = Arc::new(Mutex::new(Vec::new()));
        let output = written.clone();
        let worker = queue.clone();
        let thread = std::thread::spawn(move || {
            let mut first_write = true;
            worker.run(|snapshot| {
                if first_write {
                    first_write = false;
                    started_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                }
                output.lock().unwrap().push(
                    chat_history::bounded_json(snapshot, chat_history::MAX_FILE_BYTES).unwrap(),
                );
                Ok(())
            });
        });
        started_rx.recv().unwrap();
        let mut latest = first;
        latest.sessions[0].messages[0].content = "intermediate reply".into();
        assert!(!queue.enqueue(latest.clone()));
        if delete {
            latest.sessions.clear();
        } else {
            latest.sessions[0].messages[0].content = "latest completed reply".into();
        }
        let expected = chat_history::bounded_json(&latest, chat_history::MAX_FILE_BYTES).unwrap();
        assert!(!queue.enqueue(latest));
        let mut drain = queue.wait();
        let waker = Waker::from(Arc::new(ThreadWake(std::thread::current())));
        assert!(
            Pin::new(&mut drain)
                .poll(&mut TaskContext::from_waker(&waker))
                .is_pending()
        );
        // Simulate view destruction: neither the owner nor a UI callback remains.
        drop(queue);
        release_tx.send(()).unwrap();
        assert_eq!(wait_without_ui(drain), Ok(()));
        thread.join().unwrap();
        let written = written.lock().unwrap();
        assert_eq!(written.len(), 2, "in-flight + latest only, single writer");
        assert_eq!(written.last().unwrap(), &expected);
    }

    #[test]
    fn close_drain_preserves_latest_reply_without_view() {
        close_drain_fixture(false);
    }

    #[test]
    fn close_drain_preserves_latest_deletion_without_view() {
        close_drain_fixture(true);
    }

    #[test]
    fn close_drain_failure_retains_latest_and_requires_explicit_retry() {
        let queue = ChatSaveQueue::default();
        assert!(queue.enqueue(ChatArchive::default()));
        let newer = queue.clone();
        queue.run(|_| {
            let mut latest = ChatArchive::default();
            latest
                .sessions
                .push(ChatSession::new("latest after failed write".into()));
            assert!(!newer.enqueue(latest));
            Err("fixture disk full".into())
        });
        assert_eq!(
            wait_without_ui(queue.wait()),
            Err("fixture disk full".into())
        );
        let state = queue.0.lock().unwrap();
        assert!(!state.running);
        assert_eq!(
            state.latest.as_ref().unwrap().sessions[0].title,
            "latest after failed write"
        );
        let latest = state.latest.clone().unwrap();
        drop(state);
        assert!(
            !queue.enqueue(latest.clone()),
            "no automatic retry after failure"
        );
        queue.retry();
        assert!(queue.enqueue(latest));
        queue.run(|snapshot| {
            assert_eq!(snapshot.sessions[0].title, "latest after failed write");
            Ok(())
        });
        assert_eq!(wait_without_ui(queue.wait()), Ok(()));
    }

    #[cfg(feature = "snapshot")]
    #[gpui::test]
    async fn close_drain_timeout_is_bounded_and_does_not_discard(cx: &mut gpui::TestAppContext) {
        let queue = ChatSaveQueue::default();
        assert!(queue.enqueue(ChatArchive::default()));
        let result = queue
            .drain(cx.background_executor.clone(), Duration::ZERO)
            .await;
        assert!(result.unwrap_err().contains("timed out"));
        assert!(queue.0.lock().unwrap().latest.is_some());
        queue.run(|_| Ok(()));
        assert_eq!(queue.wait().await, Ok(()));
    }

    #[cfg(feature = "snapshot")]
    #[gpui::test]
    fn close_drain_native_window_gate_waits_for_final_snapshot(cx: &mut gpui::TestAppContext) {
        for delete in [false, true] {
            let window = cx.open_window(gpui::size(px(900.), px(700.)), |window, cx| {
                let mut this = Petal {
                    screen: Screen::Start(vec![]),
                    cleanup_panel: PanelState::with_settings(Ok(Settings::default()), cx),
                    menu_bar: crate::menubar::Monitor::new(),
                    focus_handle: cx.focus_handle(),
                    error: None,
                    notice: None,
                    notice_warning: false,
                    notice_version: 0,
                    access: Access::Dismissed,
                    _access_watch: None,
                    color_by: ColorBy::Folder,
                    chart: ChartType::Sunburst,
                };
                let chat = &mut this.cleanup_panel.chat;
                chat.persistence = true;
                chat.loaded = true;
                let mut session = ChatSession::new("close fixture".into());
                session.messages.push(entry(
                    ChatRole::Assistant,
                    "old".into(),
                    ChatStatus::Complete,
                ));
                chat.archive.sessions.push(session);
                chat.dirty = true;
                let snapshot = chat.take_save_snapshot().unwrap();
                assert!(chat.saves.enqueue(snapshot));
                // The injected writer is suspended, no production IO task is spawned.
                this.install_chat_shutdown(window, cx);
                this
            });
            let view = window.root(cx).unwrap();
            let queue = view.update(cx, |this, _| this.cleanup_panel.chat.saves.clone());
            let mut visual = gpui::VisualTestContext::from_window(window.into(), cx);
            assert!(
                !visual.simulate_close(),
                "native button must veto immediate removal"
            );
            visual.run_until_parked();
            assert!(visual.read(|cx| !cx.windows().is_empty()));
            let expected = visual.update(|_, cx| {
                view.update(cx, |this, cx| {
                    let chat = &mut this.cleanup_panel.chat;
                    if delete {
                        chat.archive.sessions.clear();
                    } else {
                        chat.archive.sessions[0].messages[0].content =
                            "final reply during close".into();
                    }
                    chat.dirty = true;
                    let expected =
                        chat_history::bounded_json(&chat.archive, chat_history::MAX_FILE_BYTES)
                            .unwrap();
                    this.queue_chat_save(cx); // Coalesces into already-running fixture writer.
                    expected
                })
            });
            let mut written = Vec::new();
            queue.run(|snapshot| {
                written.push(
                    chat_history::bounded_json(snapshot, chat_history::MAX_FILE_BYTES).unwrap(),
                );
                Ok(())
            });
            visual.run_until_parked();
            assert_eq!(written.last().unwrap(), &expected);
            assert!(
                visual.read(|cx| cx.windows().is_empty()),
                "close only after final write"
            );
        }
    }

    #[cfg(feature = "snapshot")]
    #[gpui::test]
    fn close_drain_app_quit_waits_without_view_callback(cx: &mut gpui::TestAppContext) {
        let window = cx.open_window(gpui::size(px(900.), px(700.)), |window, cx| {
            let mut this = Petal {
                screen: Screen::Start(vec![]),
                cleanup_panel: PanelState::with_settings(Ok(Settings::default()), cx),
                menu_bar: crate::menubar::Monitor::new(),
                focus_handle: cx.focus_handle(),
                error: None,
                notice: None,
                notice_warning: false,
                notice_version: 0,
                access: Access::Dismissed,
                _access_watch: None,
                color_by: ColorBy::Folder,
                chart: ChartType::Sunburst,
            };
            let chat = &mut this.cleanup_panel.chat;
            chat.persistence = true;
            chat.loaded = true;
            assert!(chat.saves.enqueue(ChatArchive::default()));
            chat.archive
                .sessions
                .push(ChatSession::new("latest before app quit".into()));
            chat.dirty = true;
            this.install_chat_shutdown(window, cx);
            this
        });
        let view = window.root(cx).unwrap();
        let queue = view.update(cx, |this, _| this.cleanup_panel.chat.saves.clone());
        // Detach an injected writer before invoking shutdown, exactly like production.
        // It makes no App updates, even after shutdown destroys the window.
        let written = Arc::new(Mutex::new(Vec::new()));
        let output = written.clone();
        cx.background_executor
            .spawn(async move {
                queue.run(|snapshot| {
                    output
                        .lock()
                        .unwrap()
                        .push(snapshot.sessions.first().map(|s| s.title.clone()));
                    Ok(())
                });
            })
            .detach();
        drop(view);
        cx.update(|cx| cx.shutdown());
        assert!(cx.read(|cx| cx.windows().is_empty()));
        assert_eq!(
            written.lock().unwrap().last().unwrap().as_deref(),
            Some("latest before app quit")
        );
    }

    #[cfg(feature = "snapshot")]
    fn memory_session(title: &str, count: usize, text: &str, updated: u64) -> ChatSession {
        let mut session = ChatSession::new(title.into());
        session.created_at = 0;
        session.updated_at = updated;
        session.messages = (0..count)
            .map(|_| entry(ChatRole::User, text.into(), ChatStatus::Complete))
            .collect();
        session
    }

    #[cfg(feature = "snapshot")]
    #[gpui::test]
    fn memory_budget_preflight_merge_and_latest_snapshots(cx: &mut gpui::TestAppContext) {
        let view = cx.new(|cx| {
            let mut panel = PanelState::with_settings(Ok(Settings::default()), cx);
            let chat = &mut panel.chat;
            let token = Token {
                scan: 1,
                revision: 0,
                generation: 0,
            };
            assert!(chat.begin("current".into(), "current".into(), None, true));
            let selected = chat.selected.clone().unwrap();
            chat.complete(
                &AgentResponse {
                    explanation: "answer".into(),
                    pending_deletions: vec![],
                    proposals: vec![],
                },
                token,
                false,
                cx,
            );
            let current_entry = chat.archive.sessions[0].messages[1].id.clone();
            let rule = Settings::default().rules.remove(0);
            let key = (current_entry.clone(), rule.id.clone());
            chat.proposals.insert(key.clone(), (token, rule));
            chat.markdown
                .borrow_mut()
                .insert(current_entry.clone(), MarkdownDocument::parse("answer"));
            let mut disk = ChatArchive::default();
            for i in 0..4 {
                disk.sessions.push(memory_session(
                    &format!("old {i}"),
                    40,
                    &"x".repeat(60 * 1024),
                    i,
                ));
            }
            let evicted_entry = disk.sessions[0].messages[0].id.clone();
            chat.markdown
                .borrow_mut()
                .insert(evicted_entry.clone(), MarkdownDocument::parse("old"));
            chat.merge_archive(disk).unwrap();
            assert!(
                chat.proposals.contains_key(&key),
                "selected authority survives retention"
            );
            assert!(chat.markdown.borrow().contains_key(&current_entry));
            assert!(!chat.markdown.borrow().contains_key(&evicted_entry));
            assert_eq!(chat.selected.as_deref(), Some(selected.as_str()));
            assert!(chat.archive.sessions.len() < 5);
            assert!(!chat.archive.sessions.iter().any(|s| s.title == "old 0"));
            chat.archive.validate().unwrap();
            let memory_text: usize = chat
                .archive
                .sessions
                .iter()
                .flat_map(|s| &s.messages)
                .map(|entry| entry.content.len() + entry.detail.len())
                .sum();
            assert!(memory_text <= chat_history::MAX_FILE_BYTES);
            chat.choose("evicted-or-missing".into());
            assert_eq!(chat.selected.as_deref(), Some(selected.as_str()));

            chat.persistence = true;
            chat.loaded = true;
            chat.dirty = true;
            let first = chat.take_save_snapshot().unwrap();
            assert_eq!(first.sessions.len(), chat.archive.sessions.len());
            chat.archive.sessions[0].title = "latest snapshot".into();
            chat.dirty = true;
            let latest = chat.take_save_snapshot().unwrap();
            assert_eq!(latest.sessions[0].title, "latest snapshot");
            assert_ne!(first.sessions[0].title, latest.sessions[0].title);
            chat.finish_save(Err("fixture failure".into()));
            let before =
                chat_history::bounded_json(&chat.archive, chat_history::MAX_FILE_BYTES).unwrap();
            assert!(chat.take_save_snapshot().is_none());
            chat.save_error = None;
            let retry = chat.take_save_snapshot().unwrap();
            assert_eq!(
                before,
                chat_history::bounded_json(&retry, chat_history::MAX_FILE_BYTES).unwrap()
            );
            chat.finish_save(Ok(()));
            // Save retention itself must not invalidate current proposal capabilities.
            assert!(chat.proposals.contains_key(&key));

            // Raw text fits, but JSON control escaping leaves no safe response reserve.
            let full = memory_session("full", 22, &"\u{0001}".repeat(60 * 1024), 10);
            chat.selected = Some(full.id.clone());
            chat.archive.sessions = vec![full];
            chat.archive.validate().unwrap();
            let before =
                chat_history::bounded_json(&chat.archive, chat_history::MAX_FILE_BYTES).unwrap();
            assert!(!chat.begin("no room".into(), "no room".into(), None, false));
            assert_eq!(
                before,
                chat_history::bounded_json(&chat.archive, chat_history::MAX_FILE_BYTES).unwrap()
            );
            assert!(chat.pending_entry.is_none());
            assert!(chat.begin("new".into(), "new".into(), None, true));
            chat.complete(
                &AgentResponse {
                    explanation: "\u{0001}".repeat(60 * 1024),
                    pending_deletions: vec![],
                    proposals: vec![],
                },
                token,
                false,
                cx,
            );
            chat.archive.validate().unwrap();
            assert_eq!(
                chat.selected_mut().unwrap().messages[1].content.len(),
                60 * 1024
            );

            assert!(chat.begin("rules".into(), "rules".into(), None, false));
            let mut rule = Settings::default().rules.remove(0);
            rule.description = "\u{0001}".repeat(12 * 1024);
            chat.complete(
                &AgentResponse {
                    explanation: "answer retained".into(),
                    pending_deletions: vec![],
                    proposals: vec![rule],
                },
                token,
                true,
                cx,
            );
            let answer = chat.selected_mut().unwrap().messages.last().unwrap();
            assert_eq!(answer.content, "answer retained");
            assert!(answer.proposals.is_empty());
            assert!(chat.proposals.is_empty());
            chat.archive.validate().unwrap();
            panel.chat.persistence = false;
            Petal {
                screen: Screen::Start(vec![]),
                cleanup_panel: panel,
                menu_bar: crate::menubar::Monitor::new(),
                focus_handle: cx.focus_handle(),
                error: None,
                notice: None,
                notice_warning: false,
                notice_version: 0,
                access: Access::Dismissed,
                _access_watch: None,
                color_by: ColorBy::Folder,
                chart: ChartType::Sunburst,
            }
        });
        drop(view);
    }

    #[cfg(feature = "snapshot")]
    #[gpui::test]
    fn chat_state_races_search_limits_and_restored_proposals(cx: &mut gpui::TestAppContext) {
        let view = cx.new(|cx| {
            let mut panel = PanelState::with_settings(Ok(Settings::default()), cx);
            let chat = &mut panel.chat;
            assert!(
                !chat.persistence,
                "test injection never reads or writes real history"
            );
            assert!(chat.begin(
                "local /secret/path".into(),
                "explain selected item".into(),
                None,
                true
            ));
            assert_eq!(chat.pending_messages()[0].content, "explain selected item");
            let old_id = chat.pending_entry.clone().unwrap();
            chat.set_phase(AiPhase::Cancelled, "cancelled".into());
            let cancelled = chat.archive.sessions[0].messages[1].clone();
            assert_eq!(cancelled.status, ChatStatus::Cancelled);
            chat.complete(
                &AgentResponse {
                    explanation: "late response".into(),
                    pending_deletions: vec![],
                    proposals: vec![],
                },
                Token {
                    scan: 1,
                    revision: 0,
                    generation: 0,
                },
                true,
                cx,
            );
            assert!(
                chat.archive.sessions[0].messages[1].content.is_empty(),
                "cancelled completion cannot overwrite history"
            );
            assert!(chat.begin("next".into(), "next".into(), None, false));
            assert_ne!(chat.pending_entry.as_ref(), Some(&old_id));
            chat.set_phase(AiPhase::Failed, "timeout".into());
            assert_eq!(
                chat.pending_messages().len(),
                1,
                "failed pairs do not become transcript"
            );
            let first = chat.selected.clone().unwrap();
            assert!(chat.archive.sessions[0].matches_query("SECRET/path"));
            chat.begin(
                "another session".into(),
                "analyze current disk".into(),
                None,
                true,
            );
            let second = chat.selected.clone().unwrap();
            chat.set_phase(AiPhase::Cancelled, "cancelled".into());
            chat.choose(first.clone());
            assert_eq!(chat.selected, Some(first));
            assert!(chat.live.is_none());
            chat.choose(second);
            let rule = Settings::default().rules.into_iter().next().unwrap();
            chat.archive.sessions[0].messages[1]
                .proposals
                .push(StoredProposal {
                    rule,
                    decision: ProposalDecision::Pending,
                });
            chat.archive.normalize_for_display();
            assert_eq!(
                chat.archive.sessions[0].messages[1].proposals[0].decision,
                ProposalDecision::Expired
            );
            assert!(
                chat.proposals.is_empty(),
                "restored rules have no actionable token"
            );
            chat.archive.sessions[0].messages = (0..chat_history::MAX_ENTRIES)
                .map(|_| entry(ChatRole::User, "kept".into(), ChatStatus::Complete))
                .collect();
            assert!(!chat.begin("overflow".into(), "overflow".into(), None, false));
            assert_eq!(
                chat.archive.sessions[0].messages.len(),
                chat_history::MAX_ENTRIES
            );
            chat.persistence = true;
            chat.dirty = true;
            assert!(
                chat.take_save_snapshot().is_none(),
                "no save before loading"
            );
            chat.loaded = true;
            let first = chat.take_save_snapshot().unwrap();
            chat.archive.sessions[0].title = "latest".into();
            chat.dirty = true;
            // Snapshot capture is no longer blocked by an in-flight writer;
            // the independent queue coalesces it without starting another writer.
            let latest = chat.take_save_snapshot().unwrap();
            assert_ne!(first.sessions[0].title, latest.sessions[0].title);
            assert_eq!(latest.sessions[0].title, "latest");
            chat.finish_save(Err("disk full".into()));
            assert!(chat.take_save_snapshot().is_none());
            assert!(chat.dirty);
            chat.save_error = None;
            chat.load_error = Some("corrupt".into());
            assert!(
                chat.take_save_snapshot().is_none(),
                "load failure permanently blocks automatic saves"
            );
            panel.chat.persistence = false;
            Petal {
                screen: Screen::Start(vec![]),
                cleanup_panel: panel,
                menu_bar: crate::menubar::Monitor::new(),
                focus_handle: cx.focus_handle(),
                error: None,
                notice: None,
                notice_warning: false,
                notice_version: 0,
                access: Access::Dismissed,
                _access_watch: None,
                color_by: ColorBy::Folder,
                chart: ChartType::Sunburst,
            }
        });
        drop(view);
    }

    #[cfg(feature = "snapshot")]
    #[gpui::test]
    fn multiple_messages_markdown_and_composer_remain_visible(cx: &mut gpui::TestAppContext) {
        for (width, height) in [(1100., 850.), (700., 720.)] {
            let window = cx.open_window(gpui::size(px(width), px(height)), |_, cx| {
                let mut panel = PanelState::with_settings(Ok(Settings::default()), cx);
                panel.open = true;
                panel.tab = 2;
                panel.ai_config_expanded = false;
                panel
                    .chat
                    .begin("Question one".into(), "Question one".into(), None, true);
                panel.chat.complete(
                    &AgentResponse {
                        explanation: "# Heading\n\n**Answer one**\n\n- first\n- second".into(),
                        pending_deletions: vec![],
                        proposals: vec![],
                    },
                    Token {
                        scan: 1,
                        revision: 0,
                        generation: 0,
                    },
                    false,
                    cx,
                );
                panel
                    .chat
                    .begin("Question two".into(), "Question two".into(), None, false);
                panel.chat.complete(
                    &AgentResponse {
                        explanation: "Answer two".into(),
                        pending_deletions: vec![],
                        proposals: vec![],
                    },
                    Token {
                        scan: 1,
                        revision: 0,
                        generation: 0,
                    },
                    false,
                    cx,
                );
                Petal {
                    screen: Screen::Start(vec![]),
                    cleanup_panel: panel,
                    menu_bar: crate::menubar::Monitor::new(),
                    focus_handle: cx.focus_handle(),
                    error: None,
                    notice: None,
                    notice_warning: false,
                    notice_version: 0,
                    access: Access::Dismissed,
                    _access_watch: None,
                    color_by: ColorBy::Folder,
                    chart: ChartType::Sunburst,
                }
            });
            let view = window.root(cx).unwrap();
            let mut visual = gpui::VisualTestContext::from_window(window.into(), cx);
            visual.update(|window, cx| window.draw(cx).clear(cx));
            let ids = view.read_with(&visual, |this, _| {
                this.cleanup_panel.chat.archive.sessions[0]
                    .messages
                    .iter()
                    .map(|e| e.id.clone())
                    .collect::<Vec<_>>()
            });
            assert_eq!(ids.len(), 4);
            for index in 0..ids.len() {
                let selector = match index {
                    0 => "chat-test-entry-0",
                    1 => "chat-test-entry-1",
                    2 => "chat-test-entry-2",
                    _ => "chat-test-entry-3",
                };
                view.update(&mut visual, |this, cx| {
                    this.cleanup_panel.chat.archive.sessions[0].messages[index].id =
                        selector.into();
                    this.cleanup_panel.chat.markdown.borrow_mut().clear();
                    cx.notify();
                });
            }
            visual.update(|window, cx| window.draw(cx).clear(cx));
            for selector in [
                "chat-entry-chat-test-entry-0",
                "chat-entry-chat-test-entry-1",
                "chat-entry-chat-test-entry-2",
                "chat-entry-chat-test-entry-3",
            ] {
                assert!(visual.debug_bounds(selector).is_some());
            }
            let composer = visual.debug_bounds("chat-composer").expect("input exists");
            assert!(
                composer.bottom() <= px(height),
                "input remains inside the window"
            );
            view.update(&mut visual, |this, cx| {
                let chat = &mut this.cleanup_panel.chat;
                chat.archive.sessions[0].messages[1].content =
                    "# Long answer\n\n```text\nlong code line\n```\n\n".repeat(150);
                chat.markdown.borrow_mut().clear();
                cx.notify();
            });
            visual.update(|window, cx| window.draw(cx).clear(cx));
            assert_eq!(
                visual.debug_bounds("chat-composer").unwrap(),
                composer,
                "long Markdown only scrolls the messages"
            );
            view.read_with(&visual, |this, _| {
                assert!(this.cleanup_panel.chat.scroll.max_offset().y > px(0.))
            });
            for selector in ["ai-paths", "ai-thinking"] {
                assert!(
                    visual.debug_bounds(selector).is_some(),
                    "sharing and thinking remain reachable with history"
                );
            }
            view.update(&mut visual, |this, cx| {
                let chat = &mut this.cleanup_panel.chat;
                chat.scroll.set_offset(gpui::point(px(0.), px(0.)));
                assert!(chat.begin("New follow-up".into(), "New follow-up".into(), None, false));
                let entry = chat.archive.sessions[0].messages.last_mut().unwrap();
                entry.id = "scroll-pending".into();
                chat.pending_entry = Some(entry.id.clone());
                chat.set_phase(AiPhase::Waiting, "Waiting for latest response".into());
                cx.notify();
            });
            visual.update(|window, cx| window.draw(cx).clear(cx));
            let pending = visual
                .debug_bounds("chat-entry-scroll-pending")
                .expect("new pending turn exists");
            let viewport =
                view.read_with(&visual, |this, _| this.cleanup_panel.chat.scroll.bounds());
            assert!(
                pending.top() >= viewport.top() && pending.bottom() <= viewport.bottom(),
                "new pending status is scrolled into view after layout"
            );
            // The user scrolls up while the model is busy. Completing must not jump.
            view.update(&mut visual, |this, cx| {
                this.cleanup_panel
                    .chat
                    .scroll
                    .set_offset(gpui::point(px(0.), px(0.)));
                cx.notify();
            });
            visual.update(|window, cx| window.draw(cx).clear(cx));
            let before = view.read_with(&visual, |this, _| this.cleanup_panel.chat.scroll.offset());
            view.update(&mut visual, |this, cx| {
                this.cleanup_panel.chat.complete(
                    &AgentResponse {
                        explanation: "## New answer\n\nLong answer paragraph.\n\n".repeat(50),
                        pending_deletions: vec![],
                        proposals: vec![],
                    },
                    Token {
                        scan: 1,
                        revision: 0,
                        generation: 0,
                    },
                    false,
                    cx,
                );
                cx.notify();
            });
            visual.update(|window, cx| window.draw(cx).clear(cx));
            view.read_with(&visual, |this, _| {
                assert_eq!(
                    this.cleanup_panel.chat.scroll.offset(),
                    before,
                    "reading old messages is not interrupted"
                )
            });
            // A new send opts back into bottom-follow; completion follows resized content.
            view.update(&mut visual, |this, cx| {
                this.cleanup_panel.chat.begin(
                    "Follow bottom".into(),
                    "Follow bottom".into(),
                    None,
                    false,
                );
                cx.notify();
            });
            visual.update(|window, cx| window.draw(cx).clear(cx));
            view.update(&mut visual, |this, cx| {
                this.cleanup_panel.chat.complete(
                    &AgentResponse {
                        explanation: "Final answer.\n\n".repeat(50),
                        pending_deletions: vec![],
                        proposals: vec![],
                    },
                    Token {
                        scan: 1,
                        revision: 0,
                        generation: 0,
                    },
                    false,
                    cx,
                );
                cx.notify();
            });
            visual.update(|window, cx| window.draw(cx).clear(cx));
            view.read_with(&visual, |this, _| {
                assert!(
                    this.cleanup_panel.chat.scroll.max_offset().y
                        + this.cleanup_panel.chat.scroll.offset().y
                        <= px(2.),
                    "bottom followers stay at the bottom"
                )
            });
        }
    }

    #[cfg(feature = "snapshot")]
    #[gpui::test]
    fn own_rule_adoptions_preserve_remaining_live_authority_only(cx: &mut gpui::TestAppContext) {
        let view = cx.new(|cx| {
            let mut panel = PanelState::with_settings(Ok(Settings::default()), cx);
            let mut token = Token {
                scan: 9,
                revision: 0,
                generation: 0,
            };
            let base = Settings::default().rules.into_iter().next().unwrap();
            let proposals: Vec<_> = (0..20)
                .map(|i| {
                    let mut rule = base.clone();
                    rule.id = format!("draft-{i}");
                    rule
                })
                .collect();
            panel
                .chat
                .begin("rules".into(), "generate safe rules".into(), None, true);
            panel.chat.complete(
                &AgentResponse {
                    explanation: "review 20 rules".into(),
                    pending_deletions: vec![],
                    proposals,
                },
                token,
                true,
                cx,
            );
            assert!(!panel.chat.persistence);
            let entry_id = panel.chat.archive.sessions[0].messages[1].id.clone();
            for i in 0..20 {
                let key = (entry_id.clone(), format!("draft-{i}"));
                let captured = panel.chat.capture_own_adoption(&key, token, true).unwrap();
                let before = panel.chat.proposals.len();
                // Pure simulation of save_panel_settings SUCCESS, with no Settings::save.
                panel.chat.expire_proposals();
                panel.chat.live = None;
                token.revision = token.revision.wrapping_add(1);
                token.generation = token.generation.wrapping_add(1);
                assert!(panel.chat.restore_after_own_adoption(captured, token, true));
                assert_eq!(panel.chat.proposals.len(), before - 1);
                assert!(
                    !panel.chat.proposals.contains_key(&key),
                    "cannot adopt twice"
                );
                assert!(
                    panel
                        .chat
                        .proposals
                        .values()
                        .all(|(remaining, _)| *remaining == token)
                );
                assert!(
                    panel.chat.live.is_none(),
                    "adoption never rebases outbound context"
                );
                let cards = &panel.chat.archive.sessions[0].messages[1].proposals;
                assert!(
                    cards[..=i]
                        .iter()
                        .all(|p| p.decision == ProposalDecision::Adopted)
                );
                assert!(
                    cards[i + 1..]
                        .iter()
                        .all(|p| p.decision == ProposalDecision::Pending)
                );
            }
            // New batch for negative checks and preservation of previous decisions.
            let mut rules: Vec<_> = (0..3)
                .map(|i| {
                    let mut rule = base.clone();
                    rule.id = format!("fresh-{i}");
                    rule
                })
                .collect();
            panel
                .chat
                .begin("more rules".into(), "more rules".into(), None, false);
            panel.chat.complete(
                &AgentResponse {
                    explanation: "fresh batch".into(),
                    pending_deletions: vec![],
                    proposals: std::mem::take(&mut rules),
                },
                token,
                true,
                cx,
            );
            let entry_id = panel.chat.archive.sessions[0].messages[3].id.clone();
            let key = (entry_id.clone(), "fresh-0".into());
            assert!(
                panel
                    .chat
                    .capture_own_adoption(&key, token, false)
                    .is_none()
            );
            let stale_key = (entry_id.clone(), "fresh-1".into());
            panel
                .chat
                .proposals
                .get_mut(&stale_key)
                .unwrap()
                .0
                .generation += 1;
            assert!(
                panel.chat.capture_own_adoption(&key, token, true).is_none(),
                "one stale remaining token blocks capture"
            );
            panel.chat.proposals.get_mut(&stale_key).unwrap().0 = token;
            // Save failure: merely dropping capture leaves all original authority untouched.
            let captured = panel.chat.capture_own_adoption(&key, token, true).unwrap();
            drop(captured);
            assert_eq!(panel.chat.proposals.len(), 3);
            // A rejected proposal is never resurrected by the next own adoption.
            panel.chat.proposals.remove(&stale_key);
            panel.chat.archive.sessions[0].messages[3].proposals[1].decision =
                ProposalDecision::Rejected;
            let captured = panel.chat.capture_own_adoption(&key, token, true).unwrap();
            panel.chat.expire_proposals();
            let next = Token {
                revision: token.revision + 1,
                generation: token.generation + 1,
                ..token
            };
            assert!(panel.chat.restore_after_own_adoption(captured, next, true));
            assert_eq!(
                panel.chat.archive.sessions[0].messages[3].proposals[1].decision,
                ProposalDecision::Rejected
            );
            let last = (entry_id, "fresh-2".into());
            for bad_token in [
                Token {
                    revision: next.revision + 2,
                    generation: next.generation + 1,
                    ..next
                },
                Token {
                    revision: next.revision + 1,
                    generation: next.generation + 2,
                    ..next
                },
            ] {
                let captured = panel.chat.capture_own_adoption(&last, next, true).unwrap();
                panel.chat.expire_proposals();
                assert!(
                    !panel
                        .chat
                        .restore_after_own_adoption(captured, bad_token, true)
                );
                // Reset this pure fixture, not production authority, for the next negative case.
                panel.chat.archive.sessions[0].messages[3].proposals[2].decision =
                    ProposalDecision::Pending;
                panel
                    .chat
                    .proposals
                    .insert(last.clone(), (next, base.clone()));
            }
            let captured = panel.chat.capture_own_adoption(&last, next, true).unwrap();
            panel.chat.expire_proposals();
            assert!(
                !panel.chat.restore_after_own_adoption(
                    captured,
                    Token {
                        scan: next.scan + 1,
                        revision: next.revision + 1,
                        generation: next.generation + 1
                    },
                    true
                ),
                "scan change cannot rebase"
            );
            assert!(panel.chat.proposals.is_empty());
            assert!(
                panel.chat.archive.sessions[0].messages[1]
                    .proposals
                    .iter()
                    .all(|p| p.decision == ProposalDecision::Adopted)
            );
            Petal {
                screen: Screen::Start(vec![]),
                cleanup_panel: panel,
                menu_bar: crate::menubar::Monitor::new(),
                focus_handle: cx.focus_handle(),
                error: None,
                notice: None,
                notice_warning: false,
                notice_version: 0,
                access: Access::Dismissed,
                _access_watch: None,
                color_by: ColorBy::Folder,
                chart: ChartType::Sunburst,
            }
        });
        view.update(cx, |this, cx| {
            let rule = Settings::default().rules.into_iter().next().unwrap();
            this.cleanup_panel
                .chat
                .begin("ordinary change".into(), "rules".into(), None, true);
            this.cleanup_panel.chat.complete(
                &AgentResponse {
                    explanation: "pending rule".into(),
                    pending_deletions: vec![],
                    proposals: vec![rule],
                },
                Token {
                    scan: 1,
                    revision: 0,
                    generation: 0,
                },
                true,
                cx,
            );
            assert_eq!(this.cleanup_panel.chat.proposals.len(), 1);
            this.invalidate_cleanup_jobs();
            assert_eq!(
                this.cleanup_panel.chat.archive.sessions[0].messages[1].proposals[0].decision,
                ProposalDecision::Expired
            );
            assert!(
                this.cleanup_panel.chat.proposals.is_empty(),
                "ordinary configuration invalidation never restores capabilities"
            );
            assert!(this.cleanup_panel.chat.live.is_none());
        });
    }

    #[test]
    fn status_details_fit_archive_budget_without_exporting_oversized_raw_errors() {
        for content_bytes in [
            0,
            60 * 1024,
            chat_history::MAX_TEXT_BYTES - 1,
            chat_history::MAX_TEXT_BYTES,
        ] {
            let detail = bounded_detail("provider raw secret".repeat(8192), content_bytes);
            assert!(content_bytes + detail.len() <= chat_history::MAX_TEXT_BYTES);
            assert!(!detail.contains("provider raw secret"));
        }
        assert_eq!(bounded_detail("timeout".into(), 60 * 1024), "timeout");
    }

    #[cfg(feature = "snapshot")]
    #[gpui::test]
    fn composer_preedit_and_edit_back_are_never_sent_or_cleared(cx: &mut gpui::TestAppContext) {
        use gpui::EntityInputHandler;
        let window = cx.open_window(gpui::size(px(900.), px(700.)), |_, cx| Petal {
            screen: Screen::Start(vec![]),
            cleanup_panel: PanelState::with_settings(Ok(Settings::default()), cx),
            menu_bar: crate::menubar::Monitor::new(),
            focus_handle: cx.focus_handle(),
            error: None,
            notice: None,
            notice_warning: false,
            notice_version: 0,
            access: Access::Dismissed,
            _access_watch: None,
            color_by: ColorBy::Folder,
            chart: ChartType::Sunburst,
        });
        let view = window.root(cx).unwrap();
        let mut visual = gpui::VisualTestContext::from_window(window.into(), cx);
        visual.update(|window, cx| {
            view.update(cx, |this, cx| {
                let composer = this.cleanup_panel.chat.composer.clone();
                composer.update(cx, |input, cx| {
                    input.replace_and_mark_text_in_range(None, "候选", None, window, cx)
                });
                this.send_chat(window, cx);
                assert_eq!(this.cleanup_panel.message, t!(Tr::CpChatConfirmComposition));
                assert!(this.cleanup_panel.chat.archive.sessions.is_empty());
                assert!(composer.read(cx).is_composing());
                composer.update(cx, |input, cx| input.set_text("same", cx));
                let revision = composer.read(cx).edit_revision();
                let chat = &mut this.cleanup_panel.chat;
                chat.begin(
                    "same".into(),
                    "same".into(),
                    Some(("same".into(), revision)),
                    true,
                );
                composer.update(cx, |input, cx| {
                    input.set_text("changed", cx);
                    input.set_text("same", cx);
                });
                let response = AgentResponse {
                    explanation: "answer".into(),
                    pending_deletions: vec![],
                    proposals: vec![],
                };
                let token = Token {
                    scan: 1,
                    revision: 0,
                    generation: 0,
                };
                chat.complete(&response, token, false, cx);
                assert_eq!(
                    composer.read(cx).text(),
                    "same",
                    "edit-back text must not be cleared"
                );
                let revision = composer.read(cx).edit_revision();
                chat.begin(
                    "same".into(),
                    "same".into(),
                    Some(("same".into(), revision)),
                    false,
                );
                composer.update(cx, |input, cx| {
                    input.replace_and_mark_text_in_range(Some(0..4), "same", None, window, cx)
                });
                // Even an otherwise matching revision must not clear a marked composition.
                chat.pending_input.as_mut().unwrap().1 = composer.read(cx).edit_revision();
                chat.complete(&response, token, false, cx);
                assert_eq!(composer.read(cx).text(), "same");
                assert!(composer.read(cx).is_composing());
                composer.update(cx, |input, cx| input.unmark_text(window, cx));
                let revision = composer.read(cx).edit_revision();
                chat.begin(
                    "same".into(),
                    "same".into(),
                    Some(("same".into(), revision)),
                    false,
                );
                chat.complete(&response, token, false, cx);
                assert!(
                    composer.read(cx).text().is_empty(),
                    "unchanged committed input clears after success"
                );
            });
        });
    }

    #[test]
    fn sequence_cancel_and_replacement_reject_late_results() {
        assert!(response_current(7, 7, true));
        assert!(
            !response_current(7, 8, false),
            "cancel discards the old result"
        );
        assert!(
            !response_current(7, 9, true),
            "replacement cannot receive the cancelled result"
        );
        assert!(
            !response_current(9, 9, false),
            "completed requests cannot complete twice"
        );
        assert!(response_current(9, 9, true));
    }

    #[test]
    fn transcript_keeps_pairs_and_never_uses_failed_archive_messages() {
        let transcript: Vec<_> = (0..80)
            .map(|i| ChatMessage {
                role: if i % 2 == 0 {
                    ChatRole::User
                } else {
                    ChatRole::Assistant
                },
                content: format!("message {i}"),
            })
            .collect();
        let messages = wire_messages(&transcript, "next".into());
        assert_eq!(messages.len(), 39);
        assert_eq!(messages[0].role, ChatRole::User);
        assert_eq!(messages.last().unwrap().content, "next");
        assert!(
            messages[..messages.len() - 1]
                .chunks_exact(2)
                .all(|pair| pair[0].role == ChatRole::User && pair[1].role == ChatRole::Assistant)
        );
    }
}
