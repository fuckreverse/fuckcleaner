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

    pub(super) fn complete(
        &mut self,
        response: &AgentResponse,
        token: Token,
        actionable: bool,
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
                        this.cleanup_panel
                            .chat
                            .complete(&response, token, actionable, cx);
                        if let Some(turn) = &mut this.cleanup_panel.ai_turn {
                            turn.answer = Some(response.explanation.clone());
                        }
                        if actionable {
                            this.cleanup_panel.response = Some((token, response));
                        }
                        this.set_ai_phase(AiPhase::Complete, t!(Tr::CpAiSnapshotNotice), cx);
                    }
                    Err(error) => this.set_ai_phase(AiPhase::Failed, error, cx),
                }
            })
            .ok();
        })
        .detach();
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
            .gap_2()
            .min_w_0()
            .child(
                row().child(
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
                ),
            )
            .child(
                div()
                    .text_xs()
                    .text_color(rgb(MUTED))
                    .child(t!(Tr::CpChatPrivacy)),
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
                div()
                    .text_xs()
                    .text_color(rgb(MUTED))
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
            .child(
                div()
                    .text_xs()
                    .text_color(rgb(MUTED))
                    .child(t!(Tr::CpChatHistory)),
            )
            .child(chat.search.clone());
        let mut list = div()
            .id("chat-history-list")
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
            .min_h(px(100.))
            .min_w_0()
            .overflow_y_scroll()
            .track_scroll(&chat.scroll)
            .flex()
            .flex_col()
            .gap_3()
            .p_3();
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
        let mut current = div().flex_1().min_w_0().min_h_0().flex().flex_col().gap_3();
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
                div().id("chat-snapshot-evidence").text_xs().text_color(rgb(MUTED))
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
                row()
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
            .gap_3()
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
