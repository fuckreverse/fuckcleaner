use super::*;
use crate::agent::{self, AgentProtocol, AgentRequest, AgentResponse};
use crate::cleanup::{self, ExecutionReport, HistoryEntry};
use crate::rules::{self, CleanupAction, CleanupCategory, Plan, Rule, RuleSource};
use crate::settings::Settings;
use crate::text_input::TextInput;
use gpui::Entity;
use std::cell::RefCell;
use std::sync::atomic::AtomicBool;

#[path = "ai_chat.rs"]
mod ai_chat;
use ai_chat::ChatState;

const PAGE_SIZE: usize = 200;
const AUTO_BUDGET: usize = 200;
const RULE_ROW_HEIGHT: f32 = 64.;
const RULE_CATEGORIES: [CleanupCategory; 7] = [
    CleanupCategory::Temporary,
    CleanupCategory::Cache,
    CleanupCategory::Build,
    CleanupCategory::Logs,
    CleanupCategory::Downloads,
    CleanupCategory::Backup,
    CleanupCategory::Other,
];

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum RuleStatusFilter {
    #[default]
    All,
    Enabled,
    Disabled,
    Automatic,
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum RuleSort {
    #[default]
    Priority,
    Name,
    Status,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RuleFilterMenu {
    Source,
    Category,
    Sort,
}

#[derive(Clone, Default, PartialEq, Eq)]
struct RuleQuery {
    search: String,
    status: RuleStatusFilter,
    source: Option<RuleSource>,
    category: Option<CleanupCategory>,
    sort: RuleSort,
}

#[derive(Default)]
struct RuleIndex {
    revision: Option<u64>,
    language: crate::i18n::Lang,
    searchable: Vec<String>,
    by_id: std::collections::HashMap<String, usize>,
    query: Option<RuleQuery>,
    visible: Rc<Vec<usize>>,
    enabled: usize,
    automatic: usize,
}

impl RuleIndex {
    fn visible(&mut self, rules: &[Rule], revision: u64, query: RuleQuery) -> Rc<Vec<usize>> {
        let language = crate::i18n::lang();
        if self.revision != Some(revision) || self.language != language {
            // Build the text index once per settings revision, not per row or scroll frame.
            self.searchable = rules.iter().map(|rule| {
                format!("{} {} {} {} {} {} {} {} {} {}", rule.id, rule.name, rule.description,
                    rule.name_label(), rule.description_label(),
                    path_list(&rule.roots), rule.pattern, rule.exclude.join(" "),
                    category_label(rule.category), source_label(rule.source)).to_lowercase()
            }).collect();
            self.by_id = rules.iter().enumerate().map(|(index, rule)| (rule.id.clone(), index)).collect();
            self.enabled = rules.iter().filter(|rule| rule.enabled).count();
            self.automatic = rules.iter().filter(|rule| rule.enabled && rule.auto_clean).count();
            self.revision = Some(revision);
            self.language = language;
            self.query = None;
        }
        if self.query.as_ref() != Some(&query) {
            let terms: Vec<_> = query.search.split_whitespace().collect();
            let mut visible: Vec<_> = rules.iter().enumerate().filter(|(index, rule)| {
                let status = match query.status {
                    RuleStatusFilter::All => true,
                    RuleStatusFilter::Enabled => rule.enabled,
                    RuleStatusFilter::Disabled => !rule.enabled,
                    RuleStatusFilter::Automatic => rule.enabled && rule.auto_clean,
                };
                status && query.source.is_none_or(|source| rule.source == source)
                    && query.category.is_none_or(|category| rule.category == category)
                    && terms.iter().all(|term| self.searchable[*index].contains(term))
            }).map(|(index, _)| index).collect();
            visible.sort_by(|&a, &b| {
                let a = &rules[a];
                let b = &rules[b];
                let order = match query.sort {
                    RuleSort::Priority => b.priority.cmp(&a.priority),
                    RuleSort::Name => a.name.cmp(&b.name),
                    RuleSort::Status => b.enabled.cmp(&a.enabled).then(b.priority.cmp(&a.priority)),
                };
                order.then(a.name.cmp(&b.name)).then(a.id.cmp(&b.id))
            });
            self.visible = Rc::new(visible);
            self.query = Some(query);
        }
        self.visible.clone()
    }

    fn rule<'a>(&self, rules: &'a [Rule], id: &str) -> Option<&'a Rule> {
        rules.get(*self.by_id.get(id)?).filter(|rule| rule.id == id)
    }
}

fn rule_sort_label(sort: RuleSort) -> &'static str {
    match sort {
        RuleSort::Priority => t!(Tr::CpRulesSortPriority),
        RuleSort::Name => t!(Tr::CpRulesSortName),
        RuleSort::Status => t!(Tr::CpRulesSortStatus),
    }
}

fn rule_detail_field(label: &str, value: impl Into<SharedString>) -> gpui::Div {
    div().flex().flex_col().gap_1().min_w_0()
        .child(div().text_xs().text_color(rgb(MUTED)).child(label.to_owned()))
        .child(div().min_w_0().line_height(relative(1.5)).child(value.into()))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AiPhase {
    Consent,
    Preparing,
    Waiting,
    Complete,
    Failed,
    Cancelled,
}

struct AiTurn {
    request: String,
    phase: AiPhase,
    detail: String,
    answer: Option<String>,
}

impl AiTurn {
    fn new(request: String) -> Self {
        Self { request, phase: AiPhase::Preparing, detail: String::new(), answer: None }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Token {
    scan: u64,
    revision: u64,
    generation: u64,
}

pub(super) struct PanelState {
    pub(super) open: bool,
    tab: usize,
    settings: Result<Settings, String>,
    revision: u64,
    generation: u64,
    plan: Option<(Token, Plan)>,
    selected: HashSet<PathBuf>,
    page: usize,
    preview_busy: bool,
    preview_cancel: Arc<AtomicBool>,
    pub(super) cleanup_busy: bool,
    execution_started: bool,
    execution_cancel: Arc<AtomicBool>,
    diagnostic_page: usize,
    diagnostics_expanded: bool,
    key_busy: bool,
    test_busy: bool,
    ai_busy: bool,
    ai_sequence: u64,
    ai_config_expanded: bool,
    ai_turn: Option<AiTurn>,
    chat: ChatState,
    ai_scroll: gpui::ScrollHandle,
    response: Option<(Token, AgentResponse)>,
    editor: Option<RuleEditor>,
    rule_search: Entity<TextInput>,
    rule_query: RuleQuery,
    rule_menu: Option<RuleFilterMenu>,
    rule_selected: Option<String>,
    rule_scroll: UniformListScrollHandle,
    rule_editor_scroll: gpui::ScrollHandle,
    rule_index: RefCell<RuleIndex>,
    url: Entity<TextInput>,
    model: Entity<TextInput>,
    key: Entity<TextInput>,
    whitelist: Entity<TextInput>,
    interval: Entity<TextInput>,
    monitor_draft: crate::menubar::MenuBarConfig,
    monitor_threshold: Entity<TextInput>,
    monitor_interval: Entity<TextInput>,
    history: Vec<HistoryEntry>,
    history_busy: bool,
    history_sequence: u64,
    message: String,
    last_automatic: Instant,
}

fn input(
    value: impl Into<String>,
    placeholder: &str,
    masked: bool,
    cx: &mut Context<Petal>,
) -> Entity<TextInput> {
    let value = value.into();
    let placeholder = placeholder.to_owned();
    cx.new(move |cx| TextInput::new(value, placeholder, masked, cx))
}
fn text(entity: &Entity<TextInput>, cx: &Context<Petal>) -> String {
    entity.read(cx).text().trim().to_owned()
}
fn is_trash(action: CleanupAction) -> bool {
    action == CleanupAction::Trash
}
fn automatic_action(authorized: bool, action: CleanupAction) -> bool {
    authorized && is_trash(action)
}
fn delimited_entries(value: &str) -> impl Iterator<Item = &str> {
    value
        .split([';', '\n'])
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
}
fn paths(value: &str) -> Vec<PathBuf> {
    delimited_entries(value).map(PathBuf::from).collect()
}
fn preview_job_current(active: &Arc<AtomicBool>, worker: &Arc<AtomicBool>) -> bool {
    Arc::ptr_eq(active, worker) && !worker.load(Ordering::Acquire)
}
fn path_list(paths: &[PathBuf]) -> String {
    paths
        .iter()
        .map(|p| p.to_string_lossy())
        .collect::<Vec<_>>()
        .join("; ")
}
fn action_label(action: CleanupAction) -> &'static str {
    match action {
        CleanupAction::Trash => t!(Tr::CpActionTrash),
        CleanupAction::Permanent => t!(Tr::CpActionPermanent),
    }
}
fn category_label(category: CleanupCategory) -> &'static str {
    match category {
        CleanupCategory::Temporary => t!(Tr::CpCatTemporary),
        CleanupCategory::Cache => t!(Tr::CpCatCache),
        CleanupCategory::Build => t!(Tr::CpCatBuild),
        CleanupCategory::Logs => t!(Tr::CpCatLogs),
        CleanupCategory::Downloads => t!(Tr::CpCatDownloads),
        CleanupCategory::Backup => t!(Tr::CpCatBackup),
        CleanupCategory::Other => t!(Tr::CpCatOther),
    }
}
fn source_label(source: RuleSource) -> &'static str {
    match source {
        RuleSource::BuiltIn => t!(Tr::CpSourceBuiltIn),
        RuleSource::User => t!(Tr::CpSourceUser),
        RuleSource::Ai => t!(Tr::CpSourceAi),
    }
}
fn field(label: &str, entity: &Entity<TextInput>) -> gpui::Div {
    div()
        .flex()
        .flex_col()
        .gap_1()
        .min_w_0()
        .child(div().text_color(rgb(MUTED)).child(label.to_owned()))
        .child(entity.clone())
}
fn row() -> gpui::Div {
    div().flex().flex_wrap().items_center().gap_2()
}
fn panel_card() -> gpui::Div {
    div()
        .p_3()
        .rounded_lg()
        .bg(rgb(CARD))
        .flex()
        .flex_col()
        .gap_2()
        .min_w_0()
}

// The assistant uses quieter surfaces than the dense cleanup tables.
fn ai_card() -> gpui::Div {
    div()
        .p_5()
        .rounded_xl()
        .border_1()
        .border_color(rgb(BORDER))
        .bg(rgb(PANEL))
        .flex()
        .flex_col()
        .flex_shrink_0()
        .gap_4()
        .min_w_0()
}

fn ai_badge(label: impl Into<SharedString>, color: u32) -> gpui::Div {
    div()
        .flex()
        .items_center()
        .gap_2()
        .px_2()
        .py_1()
        .rounded_full()
        .bg(rgba((color << 8) | 0x18))
        .text_xs()
        .text_color(rgb(color))
        .child(div().size(px(5.)).rounded_full().bg(rgb(color)))
        .child(label.into())
}

fn ai_action(
    id: &'static str,
    title: &'static str,
    description: &'static str,
    chart: ChartType,
    enabled: bool,
) -> Stateful<gpui::Div> {
    div()
        .id(id)
        .flex_1()
        .flex_basis(px(220.))
        .min_w(px(200.))
        .p_4()
        .rounded_lg()
        .border_1()
        .border_color(rgb(BORDER))
        .bg(rgb(PANEL))
        .flex()
        .flex_col()
        .gap_3()
        .when(enabled, |d| {
            d.cursor_pointer()
                .hover(|s| s.bg(rgb(CARD)).border_color(rgb(ACCENT)))
                .active(|s| s.opacity(0.85))
        })
        .when(!enabled, |d| d.opacity(0.45))
        .child(
            div()
                .flex()
                .items_center()
                .gap_2()
                .child(div().text_color(rgb(ACCENT)).child(icons::chart(chart)))
                .child(div().font_weight(FontWeight::MEDIUM).child(title)),
        )
        .child(div().text_xs().text_color(rgb(MUTED)).child(description))
}

fn ai_option(
    id: &'static str,
    label: &'static str,
    checked: bool,
    enabled: bool,
    color: u32,
) -> Stateful<gpui::Div> {
    div()
        .id(id)
        .flex()
        .items_center()
        .gap_2()
        .px_3()
        .py_2()
        .rounded_lg()
        .text_xs()
        .when(enabled, |d| d.cursor_pointer().hover(|s| s.bg(rgb(CARD))))
        .when(!enabled, |d| d.opacity(0.45))
        .child(
            div()
                .w(px(26.))
                .h(px(16.))
                .px(px(2.))
                .flex()
                .items_center()
                .rounded_full()
                .bg(rgb(if checked { color } else { BORDER }))
                .when(checked, |d| d.justify_end())
                .child(div().size(px(12.)).rounded_full().bg(rgb(TEXT))),
        )
        .child(label)
}

impl PanelState {
    pub(super) fn new(cx: &mut Context<Petal>) -> Self {
        let mut state = Self::with_settings(Settings::load(), cx);
        state.chat.persistence = true;
        state
    }

    fn with_settings(settings: Result<Settings, String>, cx: &mut Context<Petal>) -> Self {
        // Input defaults are presentation only. Never turn a failed load into writable defaults.
        let config = settings
            .as_ref()
            .ok()
            .map(|s| s.agent.clone())
            .unwrap_or_default();
        let minutes = settings
            .as_ref()
            .ok()
            .map(|s| s.automation_interval_minutes)
            .unwrap_or(60);
        let monitor_draft = settings.as_ref().ok().map(|s| s.menu_bar.clone()).unwrap_or_default();
        let monitor_threshold = input(monitor_draft.threshold.to_string(), t!(Tr::MbThreshold), false, cx);
        let monitor_interval = input(monitor_draft.refresh_seconds.to_string(), t!(Tr::MbRefreshSeconds), false, cx);
        let url = input(config.base_url, "https://api.openai.com", false, cx);
        let model = input(config.model, t!(Tr::CpFieldModel), false, cx);
        let key = input("", t!(Tr::CpFieldNewKey), true, cx);
        // Refresh saved-state indicators and enabled actions as inputs change.
        for entity in [&url, &model, &key] {
            cx.observe(entity, |_, _, cx| cx.notify()).detach();
        }
        let rule_search = input("", t!(Tr::CpRulesSearch), false, cx);
        cx.observe(&rule_search, |this, entity, cx| {
            let search = entity.read(cx).text().trim().to_lowercase();
            if this.cleanup_panel.rule_query.search != search {
                this.cleanup_panel.rule_query.search = search;
                this.cleanup_panel.rule_scroll.scroll_to_item(0, ScrollStrategy::Top);
                cx.notify();
            }
        }).detach();
        Self {
            open: false,
            tab: 0,
            settings,
            revision: 0,
            generation: 0,
            plan: None,
            selected: HashSet::new(),
            page: 0,
            preview_busy: false,
            preview_cancel: Arc::new(AtomicBool::new(false)),
            cleanup_busy: false,
            execution_started: false,
            execution_cancel: Arc::new(AtomicBool::new(false)),
            diagnostic_page: 0,
            diagnostics_expanded: false,
            key_busy: false,
            test_busy: false,
            ai_busy: false,
            ai_sequence: 0,
            ai_config_expanded: !config.enabled,
            ai_turn: None,
            chat: ChatState::new(cx),
            ai_scroll: gpui::ScrollHandle::new(),
            response: None,
            editor: None,
            rule_search,
            rule_query: RuleQuery::default(),
            rule_menu: None,
            rule_selected: None,
            rule_scroll: UniformListScrollHandle::new(),
            rule_editor_scroll: gpui::ScrollHandle::new(),
            rule_index: RefCell::new(RuleIndex::default()),
            url,
            model,
            key,
            whitelist: input("", t!(Tr::CpFieldProtectedPaths), false, cx),
            interval: input(minutes.to_string(), t!(Tr::CpFieldInterval), false, cx),
            monitor_draft,
            monitor_threshold,
            monitor_interval,
            history: vec![],
            history_busy: false,
            history_sequence: 0,
            message: String::new(),
            last_automatic: Instant::now(),
        }
    }
    pub(super) fn executing(&self) -> bool {
        self.execution_started
    }
    fn writable(&self) -> bool {
        self.settings.is_ok() && !self.cleanup_busy && !self.key_busy && !self.test_busy
    }
}

impl Drop for PanelState {
    fn drop(&mut self) {
        self.execution_cancel.store(true, Ordering::Release);
        self.preview_cancel.store(true, Ordering::Release);
    }
}

fn ai_snapshot_current(captured: Token, current: Token) -> bool {
    captured.scan == current.scan && captured.revision == current.revision
}

fn editor_conflict(open_revision: u64, current_revision: u64) -> bool {
    open_revision != current_revision
}

struct RuleEditor {
    rule: Rule,
    open_revision: u64,
    name: Entity<TextInput>,
    description: Entity<TextInput>,
    roots: Entity<TextInput>,
    pattern: Entity<TextInput>,
    exclude: Entity<TextInput>,
    size: Entity<TextInput>,
    days: Entity<TextInput>,
    priority: Entity<TextInput>,
    draft_token: Option<Token>,
}
impl RuleEditor {
    fn new(mut rule: Rule, draft_id: Option<String>, cx: &mut Context<Petal>) -> Self {
        // Editing is a new local authorization boundary, never preserve AI/automatic privileges.
        rule.source = RuleSource::User;
        rule.auto_clean = false;
        if draft_id.is_some() {
            rule.action = CleanupAction::Trash;
            rule.enabled = false;
        }
        Self {
            name: input(rule.name.clone(), t!(Tr::CpFieldRuleName), false, cx),
            description: input(rule.description.clone(), t!(Tr::CpFieldDescription), false, cx),
            roots: input(
                path_list(&rule.roots),
                t!(Tr::CpFieldScopes),
                false,
                cx,
            ),
            pattern: input(rule.pattern.clone(), "**/*", false, cx),
            exclude: input(rule.exclude.join("; "), t!(Tr::CpFieldExcludeGlobs), false, cx),
            size: input(rule.min_size.to_string(), t!(Tr::CpFieldMinBytes), false, cx),
            days: input(
                rule.older_than_days
                    .map(|d| d.to_string())
                    .unwrap_or_default(),
                t!(Tr::CpFieldKeepDays),
                false,
                cx,
            ),
            priority: input(rule.priority.to_string(), t!(Tr::CpFieldPriority), false, cx),
            rule,
            open_revision: 0,
            draft_token: None,
        }
    }
    fn build(&self, cx: &Context<Petal>) -> Result<Rule, String> {
        let mut rule = self.rule.clone();
        rule.name = text(&self.name, cx);
        rule.description = text(&self.description, cx);
        rule.roots = paths(&text(&self.roots, cx));
        rule.pattern = text(&self.pattern, cx);
        rule.exclude = delimited_entries(&text(&self.exclude, cx))
            .map(str::to_owned)
            .collect();
        rule.min_size = text(&self.size, cx)
            .parse()
            .map_err(|_| t!(Tr::CpErrMinSize))?;
        let days = text(&self.days, cx);
        rule.older_than_days = if days.is_empty() {
            None
        } else {
            Some(days.parse().map_err(|_| t!(Tr::CpErrKeepDays))?)
        };
        rule.priority = text(&self.priority, cx)
            .parse()
            .map_err(|_| t!(Tr::CpErrPriority))?;
        rule.source = RuleSource::User;
        rule.validate()?;
        Ok(rule)
    }
}

impl Petal {
    fn cleanup_token(&self) -> Option<Token> {
        match &self.screen {
            Screen::Results(r) => Some(Token {
                scan: r.id,
                revision: self.cleanup_panel.revision,
                generation: self.cleanup_panel.generation,
            }),
            _ => None,
        }
    }
    fn cleanup_current(&self, token: Token) -> bool {
        self.cleanup_token() == Some(token) && self.cleanup_panel.settings.is_ok()
    }
    // Live refresh invalidates all cleanup plans/drafts, but cannot change the
    // sealed read-only snapshot already used by an AI conversation.
    pub(super) fn invalidate_scan_cleanup_jobs(&mut self) {
        let p = &mut self.cleanup_panel;
        p.preview_cancel.store(true, Ordering::Release);
        p.generation = p.generation.wrapping_add(1);
        p.plan = None;
        p.selected.clear();
        if p.response.as_ref().is_some_and(|(_, response)| !response.proposals.is_empty()) {
            if let Some(turn) = &mut p.ai_turn {
                turn.detail = t!(Tr::CpAiDraftsExpired).into();
            }
        }
        p.response = None;
        p.chat.expire_proposals();
        p.preview_busy = false;
        p.diagnostic_page = 0;
        if p.editor.as_ref().is_some_and(|editor| editor.draft_token.is_some()) {
            p.message = t!(Tr::CpDraftStale).into();
        }
    }

    fn ai_current(&self, token: Token) -> bool {
        self.cleanup_token().is_some_and(|current| ai_snapshot_current(token, current))
            && self.cleanup_panel.settings.is_ok()
    }

    fn ai_ready(&self) -> bool {
        // Read-only AI may explain a partial snapshot during live refresh.
        // Cleanup still uses the stricter cleanup_ready guard.
        matches!(&self.screen, Screen::Results(r) if !r.trashing && !r.deleting_snapshots && r.admin != AdminRead::Reading)
            && self.cleanup_panel.writable()
    }

    fn revoke_ai_consent(&mut self, disable: bool, cx: &mut Context<Self>) {
        let Ok(settings) = &mut self.cleanup_panel.settings else { return };
        settings.agent.privacy_consent = None;
        if disable { settings.agent.enabled = false; }
        // Revocation takes effect even if persistence fails, like automation revocation.
        let result = settings.save();
        self.cleanup_panel.revision = self.cleanup_panel.revision.wrapping_add(1);
        self.invalidate_cleanup_jobs();
        match result {
            Ok(()) => self.panel_message(t!(Tr::CpAiConsentRevoked), cx),
            Err(error) => self.panel_message(tf!(Tr::CpAiRevokeSaveFailed, "e" => error), cx),
        }
    }

    fn set_ai_phase(&mut self, phase: AiPhase, detail: impl Into<String>, cx: &mut Context<Self>) {
        let detail = ai_chat::bounded_detail(detail.into(), 60 * 1024);
        if let Some(turn) = &mut self.cleanup_panel.ai_turn {
            turn.phase = phase;
            turn.detail = detail.clone();
        }
        self.cleanup_panel.chat.set_phase(phase, detail);
        self.queue_chat_save(cx);
        cx.notify();
    }

    pub(super) fn invalidate_cleanup_jobs(&mut self) {
        if self.cleanup_panel.ai_busy {
            if let Some(turn) = &mut self.cleanup_panel.ai_turn {
                turn.phase = AiPhase::Cancelled;
                turn.detail = t!(Tr::CpAiRequestChanged).into();
            }
        }
        let p = &mut self.cleanup_panel;
        p.preview_cancel.store(true, Ordering::Release);
        p.generation = p.generation.wrapping_add(1);
        p.plan = None;
        p.selected.clear();
        p.response = None;
        p.chat.set_phase(AiPhase::Cancelled, t!(Tr::CpAiRequestChanged).into());
        p.chat.expire_proposals();
        p.chat.live = None;
        p.ai_sequence = p.ai_sequence.wrapping_add(1);
        p.ai_busy = false;
        p.preview_busy = false;
        p.diagnostic_page = 0;
        if p.editor
            .as_ref()
            .is_some_and(|editor| editor.draft_token.is_some())
        {
            p.message = t!(Tr::CpDraftStale).into();
        }
    }
    fn stop_panel_cleanup(&mut self, cx: &mut Context<Self>) {
        self.cleanup_panel
            .execution_cancel
            .store(true, Ordering::Release);
        self.panel_message(t!(Tr::CpStopRequested), cx);
    }
    fn disable_panel_automation(&mut self, cx: &mut Context<Self>) {
        // Cancellation is immediate even if persisting the revocation fails.
        self.cleanup_panel
            .execution_cancel
            .store(true, Ordering::Release);
        let Ok(mut next) = self.cleanup_panel.settings.clone() else {
            return;
        };
        next.automation_enabled = false;
        match next.validate().and_then(|_| next.save()) {
            Ok(()) => {
                self.cleanup_panel.settings = Ok(next);
                self.cleanup_panel.revision = self.cleanup_panel.revision.wrapping_add(1);
                self.cleanup_panel.last_automatic = Instant::now();
                self.invalidate_cleanup_jobs();
                self.panel_message(t!(Tr::CpAutoDisabledSaved), cx);
            }
            Err(e) => self.panel_message(tf!(Tr::CpAutoDisableSaveFailed, "e" => e), cx),
        }
    }
    fn panel_message(&mut self, message: impl Into<String>, cx: &mut Context<Self>) {
        self.cleanup_panel.message = message.into();
        cx.notify();
    }
    fn set_panel_language(&mut self, lang: crate::i18n::Lang, cx: &mut Context<Self>) {
        crate::i18n::set_lang(lang);
        // The language changes no cleanup-affecting configuration, so saving it
        // must not bump the revision or disturb a running batch: the editor and
        // the preview plan stay valid.
        if let Ok(mut next) = self.cleanup_panel.settings.clone() {
            next.language = Some(lang);
            if next.save().is_ok() {
                self.cleanup_panel.settings = Ok(next);
            }
        }
        cx.notify();
    }
    fn save_panel_settings(&mut self, next: Settings, cx: &mut Context<Self>) -> bool {
        if !self.cleanup_panel.writable() {
            self.panel_message(t!(Tr::CpSettingsNotSaved), cx);
            return false;
        }
        match next.validate().and_then(|_| next.save()) {
            Ok(()) => {
                self.cleanup_panel.settings = Ok(next);
                self.cleanup_panel.revision = self.cleanup_panel.revision.wrapping_add(1);
                self.cleanup_panel.last_automatic = Instant::now();
                self.invalidate_cleanup_jobs();
                self.panel_message(if self.cleanup_panel.editor.is_some() {
                    t!(Tr::CpSettingsSavedStale)
                } else { t!(Tr::CpSettingsSavedInvalidate) }, cx);
                true
            }
            Err(e) => {
                self.panel_message(tf!(Tr::CpSaveFailed, "e" => e), cx);
                false
            }
        }
    }
    fn confirm_panel_settings(
        &mut self,
        next: Settings,
        title: &str,
        detail: &str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if !self.cleanup_panel.writable() {
            return;
        }
        let revision = self.cleanup_panel.revision;
        let token = self.cleanup_token();
        window.focus(&self.focus_handle, cx);
        let answer = window.prompt(
            PromptLevel::Warning,
            title,
            Some(detail),
            &[t!(Tr::CpAuthorizeAndSave), t!(Tr::Cancel)],
            cx,
        );
        cx.spawn(async move |this, cx| {
            if answer.await == Ok(0) {
                this.update(cx, |this, cx| {
                    if revision == this.cleanup_panel.revision && token == this.cleanup_token() {
                        this.save_panel_settings(next, cx);
                    } else {
                        this.panel_message(
                            t!(Tr::CpSettingsChangedDuringConfirm),
                            cx,
                        );
                    }
                })
                .ok();
            }
        })
        .detach();
    }
    pub(super) fn menu_bar_config(&self) -> Option<crate::menubar::MenuBarConfig> {
        self.cleanup_panel.settings.as_ref().ok().map(|s| s.menu_bar.clone())
    }

    pub(super) fn open_monitor_settings(&mut self, cx: &mut Context<Self>) {
        self.cleanup_panel.open = true;
        self.cleanup_panel.tab = 3;
        self.refresh_monitor_disks(cx);
        cx.notify();
    }

    fn refresh_monitor_disks(&mut self, cx: &mut Context<Self>) {
        cx.spawn(async move |this, cx| {
            let disks = cx.background_spawn(async { crate::menubar::mounted_disks() }).await;
            this.update(cx, |this, cx| {
                this.menu_bar.disks = disks;
                cx.notify();
            }).ok();
        }).detach();
    }

    fn save_monitor_settings(&mut self, cx: &mut Context<Self>) {
        if !self.cleanup_panel.writable() { return; }
        let Ok(mut next) = self.cleanup_panel.settings.clone() else { return; };
        let mut config = self.cleanup_panel.monitor_draft.clone();
        let Ok(threshold) = text(&self.cleanup_panel.monitor_threshold, cx).parse() else {
            self.panel_message(t!(Tr::MbBadThreshold), cx); return;
        };
        let Ok(seconds) = text(&self.cleanup_panel.monitor_interval, cx).parse() else {
            self.panel_message(t!(Tr::MbBadRefresh), cx); return;
        };
        config.threshold = threshold;
        config.refresh_seconds = seconds;
        if let Err(error) = config.validate() {
            self.panel_message(error, cx); return;
        }
        next.menu_bar = config.clone();
        match next.save() {
            Ok(()) => {
                // Presentation-only settings must not invalidate cleanup plans,
                // consent or any running cleanup/AI operation.
                self.cleanup_panel.settings = Ok(next);
                self.cleanup_panel.monitor_draft = config;
                self.menu_bar.refresh_now();
                self.panel_message(t!(Tr::MbSaved), cx);
            }
            Err(error) => self.panel_message(tf!(Tr::CpSaveFailed, "e" => error), cx),
        }
    }

    fn reload_panel_settings(&mut self, cx: &mut Context<Self>) {
        if self.cleanup_panel.cleanup_busy || self.cleanup_panel.key_busy {
            return;
        }
        self.cleanup_panel.settings = Settings::load();
        self.cleanup_panel.revision = self.cleanup_panel.revision.wrapping_add(1);
        self.cleanup_panel.last_automatic = Instant::now();
        self.invalidate_cleanup_jobs();
        if let Ok(settings) = &self.cleanup_panel.settings {
            let url = settings.agent.base_url.clone();
            let model = settings.agent.model.clone();
            let minutes = settings.automation_interval_minutes.to_string();
            let monitor = settings.menu_bar.clone();
            self.cleanup_panel.monitor_threshold.update(cx, |input, cx| input.set_text(monitor.threshold.to_string(), cx));
            self.cleanup_panel.monitor_interval.update(cx, |input, cx| input.set_text(monitor.refresh_seconds.to_string(), cx));
            self.cleanup_panel.monitor_draft = monitor;
            self.cleanup_panel
                .url
                .update(cx, |input, cx| input.set_text(url, cx));
            self.cleanup_panel
                .model
                .update(cx, |input, cx| input.set_text(model, cx));
            self.cleanup_panel
                .interval
                .update(cx, |input, cx| input.set_text(minutes, cx));
        }
        self.panel_message(t!(Tr::CpReloadedStale), cx);
    }
    // Preview must cover every scope file: retain the full snapshot until core provides
    // a scope-complete snapshot helper. This copy can be expensive; never use it for AI.
    fn cleanup_tree_snapshot(&self) -> Option<Tree> {
        let Screen::Results(r) = &self.screen else {
            return None;
        };
        Some(Tree {
            root_path: r.tree.root_path.clone(),
            nodes: r.tree.nodes.clone(),
            errors: r.tree.errors,
            cloud_only: r.tree.cloud_only,
            unreadable: r.tree.unreadable.clone(),
            purgeable: r.tree.purgeable,
            ..Tree::default()
        })
    }
    fn cleanup_ready(&self) -> bool {
        matches!(&self.screen, Screen::Results(r) if !r.trashing && !r.refreshing && !r.out_of_date && !r.deleting_snapshots && r.admin != AdminRead::Reading)
            && self.cleanup_panel.writable()
    }
    fn preview_cleanup(&mut self, automatic: bool, cx: &mut Context<Self>) {
        if !self.cleanup_ready() || (automatic && self.cleanup_panel.preview_busy) {
            return;
        }
        let Some(token) = self.cleanup_token() else {
            return;
        };
        let Ok(settings) = self.cleanup_panel.settings.clone() else {
            return;
        };
        self.cleanup_panel
            .preview_cancel
            .store(true, Ordering::Release);
        let cancel = Arc::new(AtomicBool::new(false));
        self.cleanup_panel.preview_cancel = cancel.clone();
        let Some(tree) = self.cleanup_tree_snapshot() else {
            self.cleanup_panel.preview_busy = false;
            return;
        };
        let scan_integrity_errors = tree.errors > 0;
        self.cleanup_panel.plan = None;
        self.cleanup_panel.selected.clear();
        self.cleanup_panel.diagnostic_page = 0;
        self.cleanup_panel.preview_busy = true;
        self.panel_message(t!(Tr::CpVerifying), cx);
        cx.spawn(async move |this, cx| {
            let worker_cancel = cancel.clone();
            let plan = cx
                .background_spawn(async move {
                    let mut plan = rules::evaluate_cancellable(&tree, &settings, &worker_cancel);
                    if !worker_cancel.load(Ordering::Acquire) {
                        plan.items
                            .sort_by(|a, b| b.priority.cmp(&a.priority).then(a.path.cmp(&b.path)));
                    }
                    plan
                })
                .await;
            this.update(cx, |this, cx| {
                // A cancelled/replaced job must never clear the next job's busy flag.
                if !preview_job_current(&this.cleanup_panel.preview_cancel, &cancel) {
                    return;
                }
                this.cleanup_panel.preview_busy = false;
                if !this.cleanup_current(token) {
                    cx.notify();
                    return;
                }
                if automatic {
                    if scan_integrity_errors || !this.cleanup_ready() {
                        this.panel_message(t!(Tr::CpAutoPlanIncomplete), cx);
                        return;
                    }
                    let items = plan
                        .items
                        .into_iter()
                        .filter(|i| automatic_action(i.auto_clean, i.action))
                        .take(AUTO_BUDGET)
                        .collect::<Vec<_>>();
                    if !items.is_empty() {
                        this.launch_panel_cleanup(token, items, true, cx);
                    }
                    cx.notify();
                } else {
                    this.cleanup_panel.selected.clear();
                    this.cleanup_panel.page = 0;
                    this.cleanup_panel.message = tf!(Tr::CpPreviewDone, "n" => plan.items.len());
                    this.cleanup_panel.plan = Some((token, plan));
                    cx.notify();
                }
            })
            .ok();
        })
        .detach();
    }
    fn cancel_cleanup_preview(&mut self, cx: &mut Context<Self>) {
        self.cleanup_panel
            .preview_cancel
            .store(true, Ordering::Release);
        self.cleanup_panel.preview_busy = false;
        self.panel_message(t!(Tr::CpPreviewCancelled), cx);
    }
    fn confirm_panel_cleanup(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if !self.cleanup_ready() {
            return;
        }
        let Some((token, plan)) = &self.cleanup_panel.plan else {
            return;
        };
        if !self.cleanup_current(*token) {
            return;
        }
        let token = *token;
        let items = plan
            .items
            .iter()
            .filter(|i| self.cleanup_panel.selected.contains(&i.path))
            .cloned()
            .collect::<Vec<_>>();
        if items.is_empty() {
            return;
        }
        let permanent = items
            .iter()
            .filter(|i| i.action == CleanupAction::Permanent)
            .count();
        let details = items
            .iter()
            .map(|i| {
                format!(
                    "{} · {} · {}",
                    i.path.display(),
                    format_size(i.size),
                    action_label(i.action)
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        let detail = tf!(
            Tr::CpExecuteSummary,
            "n" => items.len(),
            "permanent" => permanent,
            "details" => details
        );
        let answer = window.prompt(
            PromptLevel::Warning,
            t!(Tr::CpConfirmExecute),
            Some(&detail),
            &[t!(Tr::CpContinue), t!(Tr::Cancel)],
            cx,
        );
        cx.spawn_in(window, async move |this, cx| {
            if answer.await != Ok(0) {
                return;
            }
            if permanent > 0 {
                let permanent_detail = items
                    .iter()
                    .filter(|i| i.action == CleanupAction::Permanent)
                    .map(|i| i.path.display().to_string())
                    .collect::<Vec<_>>()
                    .join("\n");
                let second = cx.update(|window, cx| {
                    window.prompt(
                        PromptLevel::Warning,
                        t!(Tr::CpPermanentWarning),
                        Some(&permanent_detail),
                        &[t!(Tr::CpConfirmPermanent), t!(Tr::Cancel)],
                        cx,
                    )
                });
                let Ok(second) = second else { return };
                if second.await != Ok(0) {
                    return;
                }
            }
            this.update(cx, |this, cx| {
                this.launch_panel_cleanup(token, items, false, cx)
            })
            .ok();
        })
        .detach();
    }
    fn launch_panel_cleanup(
        &mut self,
        token: Token,
        items: Vec<rules::RuleMatch>,
        automatic: bool,
        cx: &mut Context<Self>,
    ) {
        if !self.cleanup_current(token) || !self.cleanup_ready() {
            return;
        }
        let Ok(settings) = self.cleanup_panel.settings.clone() else {
            return;
        };
        if automatic
            && (!settings.automation_enabled
                || items.len() > AUTO_BUDGET
                || items
                    .iter()
                    .any(|i| !i.auto_clean || i.action != CleanupAction::Trash))
        {
            return;
        }
        self.cleanup_panel.execution_cancel = Arc::new(AtomicBool::new(false));
        let cancel = self.cleanup_panel.execution_cancel.clone();
        self.cleanup_panel.cleanup_busy = true;
        self.cleanup_panel.execution_started = true;
        self.panel_message(t!(Tr::CpBusyLocked), cx);
        cx.spawn(async move |this, cx| {
            let report = cx
                .background_spawn(async move {
                    cleanup::execute_cancellable(&items, &settings, automatic, &cancel)
                })
                .await;
            this.update(cx, |this, cx| {
                this.cleanup_panel.cleanup_busy = false;
                this.cleanup_panel.execution_started = false;
                this.apply_panel_cleanup_report(token, report, cx);
            })
            .ok();
        })
        .detach();
    }
    fn apply_panel_cleanup_report(
        &mut self,
        token: Token,
        report: ExecutionReport,
        cx: &mut Context<Self>,
    ) {
        if let Screen::Results(r) = &mut self.screen {
            if r.id == token.scan {
                let removed: HashSet<usize> = report
                    .completed
                    .iter()
                    .filter_map(|path| r.tree.find(path))
                    .filter(|&ix| r.tree.is_attached(ix))
                    .collect();
                let touched = r
                    .findings
                    .iter()
                    .map(|finding| {
                        finding.nodes.iter().any(|&node| {
                            removed.iter().any(|&ix| {
                                r.tree.is_ancestor_or_self(node, ix)
                                    || r.tree.is_ancestor_or_self(ix, node)
                            })
                        })
                    })
                    .collect::<Vec<_>>();
                for &ix in &removed {
                    r.tree.remove(ix);
                }
                r.update_findings(&removed, &touched);
                r.collector.retain(|&ix| r.tree.is_attached(ix));
                r.collector_version = r.collector_version.wrapping_add(1);
                r.collector_frees.set(None);
                r.trashed = None;
                r.chart_hover = None;
                r.list_hover = None;
                r.categories.clear();
                r.surveying.clear();
                r.relayout();
            }
        }
        self.invalidate_cleanup_jobs();
        self.collector_changed(cx);
        let failures = report
            .failed
            .iter()
            .map(|(p, e)| tf!(Tr::CpFailEntry, "path" => p.display().to_string(), "e" => e))
            .collect::<Vec<_>>()
            .join("\n");
        self.panel_message(
            tf!(
                Tr::CpExecuteResult,
                "n" => report.completed.len(),
                "failed" => report.failed.len(),
                "tail" => format!(
                    "{}{}",
                    failures,
                    report
                        .log_error
                        .map(|e| tf!(Tr::CpAuditError, "e" => e))
                        .unwrap_or_default()
                )
            ),
            cx,
        );
    }
    fn edit_panel_rule(
        &mut self,
        rule: Rule,
        draft: Option<String>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if !self.cleanup_panel.writable() {
            return;
        }
        if draft.is_some() && !self.cleanup_ready() {
            self.panel_message(t!(Tr::CpAiDraftsExpired), cx);
            return;
        }
        let draft_token = draft.as_ref().and_then(|_| self.cleanup_token());
        if self.cleanup_panel.editor.is_some() {
            self.panel_message(t!(Tr::CpEditorAlreadyOpen), cx);
            return;
        }
        let mut editor = RuleEditor::new(rule, draft, cx);
        editor.open_revision = self.cleanup_panel.revision;
        editor.draft_token = draft_token;
        window.focus(&editor.name.read(cx).focus_handle(), cx);
        self.cleanup_panel.rule_selected = Some(editor.rule.id.clone());
        self.cleanup_panel.rule_menu = None;
        self.cleanup_panel.rule_editor_scroll = gpui::ScrollHandle::new();
        self.cleanup_panel.editor = Some(editor);
        self.cleanup_panel.tab = 1;
        cx.notify();
    }
    fn new_panel_rule(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Ok(settings) = &self.cleanup_panel.settings else {
            return;
        };
        let rule = Rule {
            id: crate::settings::unique_name("user-")
                .to_string_lossy()
                .into_owned(),
            name: t!(Tr::CpNewCacheRule).into(),
            description: String::new(),
            category: CleanupCategory::Cache,
            roots: vec![PathBuf::from("~/Library/Caches")],
            pattern: "**/*".into(),
            exclude: vec![],
            min_size: 0,
            older_than_days: Some(30),
            priority: 0,
            enabled: false,
            auto_clean: false,
            action: settings.default_action,
            source: RuleSource::User,
        };
        self.edit_panel_rule(rule, None, window, cx);
    }
    fn save_panel_rule(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if !self.cleanup_panel.writable() {
            return;
        }
        let Some(editor) = &self.cleanup_panel.editor else {
            return;
        };
        if editor_conflict(editor.open_revision, self.cleanup_panel.revision) {
            self.panel_message(t!(Tr::CpEditorConflict), cx);
            return;
        }
        if editor
            .draft_token
            .is_some_and(|token| !self.cleanup_current(token) || !self.cleanup_ready())
        {
            self.panel_message(t!(Tr::CpDraftScanChanged), cx);
            return;
        }
        let rule = match editor.build(cx) {
            Ok(rule) => rule,
            Err(e) => {
                self.panel_message(tf!(Tr::CpRuleInvalid, "e" => e), cx);
                return;
            }
        };
        let Ok(mut next) = self.cleanup_panel.settings.clone() else {
            return;
        };
        if let Some(old) = next.rules.iter_mut().find(|r| r.id == rule.id) {
            *old = rule.clone();
        } else {
            next.rules.push(rule.clone());
        }
        if rule.auto_clean {
            let revision = editor.open_revision;
            let token = self.cleanup_token();
            let expected = serde_json::to_string(&rule).ok();
            let detail = tf!(
                Tr::CpAutoRuleSummary,
                "name" => rule.name,
                "scope" => path_list(&rule.roots)
            );
            window.focus(&self.focus_handle, cx);
            let answer = window.prompt(
                PromptLevel::Warning,
                t!(Tr::CpAuthorizeSingleRule),
                Some(&detail),
                &[t!(Tr::CpAuthorizeSaveRule), t!(Tr::Cancel)],
                cx,
            );
            cx.spawn_in(window, async move |this, cx| {
                if answer.await != Ok(0) {
                    return;
                }
                this.update_in(cx, |this, window, cx| {
                    let unchanged = this.cleanup_panel.editor.as_ref().is_some_and(|editor| {
                        !editor_conflict(editor.open_revision, revision)
                            && editor
                                .build(cx)
                                .ok()
                                .and_then(|r| serde_json::to_string(&r).ok())
                                == expected
                    });
                    if revision != this.cleanup_panel.revision
                        || token != this.cleanup_token()
                        || !unchanged
                    {
                        this.panel_message(t!(Tr::CpConfirmChangedInputs), cx);
                        return;
                    }
                    if this.save_panel_settings(next, cx) {
                        window.focus(&this.focus_handle, cx);
                        this.cleanup_panel.editor = None;
                    }
                })
                .ok();
            })
            .detach();
        } else if self.save_panel_settings(next, cx) {
            window.focus(&self.focus_handle, cx);
            self.cleanup_panel.editor = None;
        }
    }
    fn adopt_panel_draft(&mut self, id: String, enabled: bool, cx: &mut Context<Self>) {
        if !self.cleanup_panel.writable() {
            return;
        }
        let Some((token, response)) = &self.cleanup_panel.response else {
            return;
        };
        if !self.cleanup_current(*token) || !self.cleanup_ready() {
            self.panel_message(t!(Tr::CpAiDraftsExpired), cx);
            return;
        }
        let Some(mut rule) = response.proposals.iter().find(|r| r.id == id).cloned() else {
            return;
        };
        let mut remaining = response.clone();
        remaining.proposals.retain(|r| r.id != id);
        rule.enabled = enabled;
        rule.auto_clean = false;
        rule.action = CleanupAction::Trash;
        rule.source = RuleSource::Ai;
        let Ok(mut next) = self.cleanup_panel.settings.clone() else {
            return;
        };
        next.rules.push(rule);
        if self.save_panel_settings(next, cx) {
            if let Some(token) = self.cleanup_token() {
                self.cleanup_panel.response = Some((token, remaining));
            }
        }
    }
    fn save_panel_ai(&mut self, cx: &mut Context<Self>) {
        let Ok(mut next) = self.cleanup_panel.settings.clone() else {
            return;
        };
        next.agent.base_url = text(&self.cleanup_panel.url, cx);
        next.agent.model = text(&self.cleanup_panel.model, cx);
        if self.save_panel_settings(next, cx) {
            self.panel_message(t!(Tr::CpAiSavedNotice), cx);
        }
    }
    fn panel_credential_target(&self, cx: &Context<Self>) -> Result<String, String> {
        let settings = self
            .cleanup_panel
            .settings
            .as_ref()
            .map_err(|e| e.clone())?;
        let mut config = settings.agent.clone();
        config.base_url = text(&self.cleanup_panel.url, cx);
        config.model = text(&self.cleanup_panel.model, cx);
        config.validate()?;
        let scope = config.credential_scope()?;
        if config.base_url != settings.agent.base_url
            || config.model != settings.agent.model
            || scope != settings.agent.credential_scope()?
        {
            return Err(t!(Tr::CpKeyTargetUnsaved).into());
        }
        Ok(scope)
    }
    fn confirm_panel_key_delete(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if !self.cleanup_panel.writable() {
            return;
        }
        let scope = match self.panel_credential_target(cx) {
            Ok(scope) => scope,
            Err(e) => {
                self.panel_message(e, cx);
                return;
            }
        };
        let revision = self.cleanup_panel.revision;
        window.focus(&self.focus_handle, cx);
        let detail = tf!(Tr::CpDeleteKeyScope, "scope" => scope);
        let answer = window.prompt(
            PromptLevel::Warning,
            t!(Tr::CpConfirmDeleteKey),
            Some(&detail),
            &[t!(Tr::CpDeleteTargetKey), t!(Tr::Cancel)],
            cx,
        );
        cx.spawn(async move |this, cx| {
            if answer.await != Ok(0) {
                return;
            }
            this.update(cx, |this, cx| {
                if revision != this.cleanup_panel.revision
                    || this.panel_credential_target(cx).ok().as_ref() != Some(&scope)
                {
                    this.panel_message(t!(Tr::CpKeyTargetChanged), cx);
                    return;
                }
                this.store_panel_key(true, cx);
            })
            .ok();
        })
        .detach();
    }
    fn store_panel_key(&mut self, delete: bool, cx: &mut Context<Self>) {
        if !self.cleanup_panel.writable() {
            return;
        }
        let scope = match self.panel_credential_target(cx) {
            Ok(scope) => scope,
            Err(e) => {
                self.panel_message(e, cx);
                return;
            }
        };
        let target = scope.clone();
        let revision = self.cleanup_panel.revision;
        let key = text(&self.cleanup_panel.key, cx);
        let submitted_key = key.clone();
        if !delete && key.is_empty() {
            self.panel_message(t!(Tr::CpKeyEmpty), cx);
            return;
        }
        self.cleanup_panel.key_busy = true;
        cx.spawn(async move |this, cx| {
            let result = cx
                .background_spawn(async move {
                    if delete {
                        crate::credentials::delete_key_for(&scope)
                    } else {
                        crate::credentials::save_key_for(&scope, &key)
                    }
                })
                .await;
            this.update(cx, |this, cx| {
                this.cleanup_panel.key_busy = false;
                match result {
                    Ok(()) => {
                        if this.cleanup_panel.revision != revision || this.panel_credential_target(cx).ok().as_ref() != Some(&target) {
                            this.panel_message(tf!(Tr::CpKeychainDoneStale, "target" => target), cx); return;
                        }
                        if text(&this.cleanup_panel.key, cx) == submitted_key {
                            this.cleanup_panel.key.update(cx, |input, cx| input.set_text("", cx));
                        }
                        this.panel_message(
                            if delete {
                                tf!(Tr::CpKeychainDeleted, "target" => target)
                            } else {
                                tf!(Tr::CpKeychainSaved, "target" => target)
                            },
                            cx,
                        );
                    }
                    Err(e) => this.panel_message(tf!(Tr::CpKeychainFailed, "e" => e), cx),
                }
            })
            .ok();
        })
        .detach();
    }
    fn test_panel_connection(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if !self.cleanup_panel.writable() {
            return;
        }
        let Ok(settings) = self.cleanup_panel.settings.clone() else {
            return;
        };
        let config = settings.agent;
        if let Err(e) = config.validate() {
            self.panel_message(tf!(Tr::CpAiConfigInvalid, "e" => e), cx);
            return;
        }
        let target = config
            .credential_scope()
            .unwrap_or_else(|_| t!(Tr::CpLocalLoopback).into());
        let detail = tf!(Tr::CpTestExplain, "target" => target);
        window.focus(&self.focus_handle, cx);
        let answer = window.prompt(
            PromptLevel::Warning,
            t!(Tr::CpConfirmTest),
            Some(&detail),
            &[t!(Tr::CpSendProbe), t!(Tr::Cancel)],
            cx,
        );
        self.cleanup_panel.test_busy = true;
        cx.spawn(async move |this, cx| {
            let result = if answer.await == Ok(0) {
                cx.background_spawn(async move { agent::test_connection(&config) })
                    .await
            } else {
                Err(t!(Tr::CpTestCancelled).into())
            };
            this.update(cx, |this, cx| {
                this.cleanup_panel.test_busy = false;
                match result {
                    Ok(message) => this.panel_message(message, cx),
                    Err(e) => this.panel_message(tf!(Tr::CpTestFailed, "e" => e), cx),
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }
    pub(super) fn explain_cleanup_node(
        &mut self,
        ix: usize,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Screen::Results(r) = &self.screen else {
            return;
        };
        if !r.tree.is_attached(ix) || r.tree.nodes[ix].kind == Kind::Other {
            return;
        }
        let request = AgentRequest::Explain {
            path: r.tree.path_of(ix),
        };
        window.focus(&self.focus_handle, cx);
        self.cleanup_panel.open = true;
        self.cleanup_panel.tab = 2;
        self.cleanup_panel.ai_scroll = gpui::ScrollHandle::new();
        self.request_panel_ai(request, Some(ix), window, cx);
        cx.notify();
    }
    fn request_panel_ai(
        &mut self,
        request: AgentRequest,
        selected_node: Option<usize>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.cleanup_panel.ai_busy {
            self.panel_message(t!(Tr::CpAiAlreadyBusy), cx);
            return;
        }
        let manual = self.cleanup_panel.chat.next_input.take();
        let label = match &request {
            AgentRequest::Analyze => t!(Tr::CpAnalyzeDisk).to_string(),
            AgentRequest::Explain { path } => tf!(Tr::CpAiExplainRequest, "path" => path.to_string_lossy()),
            AgentRequest::GenerateRules => t!(Tr::CpGenerateDrafts).to_string(),
        };
        self.cleanup_panel.ai_turn = Some(AiTurn::new(label.clone()));
        self.cleanup_panel.response = None;
        self.cleanup_panel.ai_scroll = gpui::ScrollHandle::new();
        if !self.ai_ready() {
            self.set_ai_phase(AiPhase::Failed, t!(Tr::CpAiNotReady), cx);
            return;
        }
        let Ok(settings) = self.cleanup_panel.settings.clone() else { return };
        if !settings.agent.enabled {
            self.set_ai_phase(AiPhase::Failed, t!(Tr::CpAiNotEnabled), cx);
            self.cleanup_panel.ai_config_expanded = true;
            return;
        }
        if text(&self.cleanup_panel.url, cx) != settings.agent.base_url
            || text(&self.cleanup_panel.model, cx) != settings.agent.model {
            self.set_ai_phase(AiPhase::Failed, t!(Tr::CpAiServiceHint), cx);
            return;
        }
        let Some(token) = self.cleanup_token() else { return };
        let wire = manual.as_ref().map(|(text, _)| text.clone()).unwrap_or_else(|| match &request {
            AgentRequest::Analyze => "analyze current disk",
            AgentRequest::Explain { .. } => "explain selected item",
            AgentRequest::GenerateRules => "generate safe rules",
        }.into());
        let display = manual.as_ref().map(|(text, _)| text.clone()).unwrap_or(label);
        if !self.cleanup_panel.chat.begin(display.clone(), wire, manual, true) {
            self.panel_message(t!(Tr::CpChatLimit), cx);
            return;
        }
        self.cleanup_panel.ai_turn = Some(AiTurn::new(display));
        self.load_chat_archive(cx);
        let needs_consent = !settings.agent.has_privacy_consent();
        let node_count = match &self.screen {
            Screen::Results(r) => r.tree.nodes.len(),
            _ => return,
        };
        let detail = tf!(
            Tr::CpAnalyzeExplain,
            "target" => settings.agent.base_url,
            "protocol" => settings.agent.protocol.label(),
            "model" => settings.agent.model,
            "nodes" => node_count,
            "paths" => if settings.agent.share_paths { t!(Tr::CpPathsFull) } else { t!(Tr::CpPathsOpaque) }
        );
        let detail = format!("{detail}\n\n{}", t!(Tr::CpChatPrivacy));
        let answer = needs_consent.then(|| window.prompt(
            PromptLevel::Warning, t!(Tr::CpConfirmAnalyze), Some(&detail),
            &[t!(Tr::CpSendSummary), t!(Tr::Cancel)], cx,
        ));
        self.cleanup_panel.ai_busy = true;
        self.cleanup_panel.ai_sequence = self.cleanup_panel.ai_sequence.wrapping_add(1);
        let sequence = self.cleanup_panel.ai_sequence;
        self.cleanup_panel.message.clear();
        self.set_ai_phase(
            if needs_consent { AiPhase::Consent } else { AiPhase::Preparing },
            if needs_consent { t!(Tr::CpWaitingConsent) } else { t!(Tr::CpAiPreparing) }, cx,
        );
        cx.spawn(async move |this, cx| {
            if let Some(answer) = answer {
                if answer.await != Ok(0) {
                    this.update(cx, |this, cx| {
                        if sequence == this.cleanup_panel.ai_sequence {
                            this.cleanup_panel.ai_busy = false;
                            this.set_ai_phase(AiPhase::Cancelled, t!(Tr::CpAiConsentCancelled), cx);
                        }
                    }).ok();
                    return;
                }
            }
            let snapshot = this.update(cx, |this, cx| {
                if this.cleanup_panel.ai_sequence != sequence { return None; }
                if !this.ai_current(token) || !this.ai_ready() {
                    this.cleanup_panel.ai_busy = false;
                    this.set_ai_phase(AiPhase::Cancelled, t!(Tr::CpAiRequestChanged), cx);
                    return None;
                }
                if needs_consent {
                    // Persist only the receipt: no revision bump, job invalidation,
                    // or overwrite of newer settings captured while the prompt was open.
                    let Ok(mut next) = this.cleanup_panel.settings.clone() else { return None };
                    if let Err(error) = next.agent.remember_privacy_consent().and_then(|_| next.save()) {
                        this.cleanup_panel.ai_busy = false;
                        this.set_ai_phase(AiPhase::Failed, tf!(Tr::CpSaveFailed, "e" => error), cx);
                        return None;
                    }
                    this.cleanup_panel.settings = Ok(next);
                }
                this.set_ai_phase(AiPhase::Preparing, t!(Tr::CpAiPreparing), cx);
                let Screen::Results(r) = &this.screen else { return None };
                // Live refresh can change node IDs; drop the old hint and resolve
                // the path when the generation changed while consent was open.
                let selection = if this.cleanup_current(token) { selected_node } else { None };
                match agent::prepare_snapshot_with_selection(&r.tree, &r.findings, &settings, &request, selection) {
                    Ok(snapshot) => Some((this.cleanup_token().unwrap(), this.cleanup_ready(), snapshot)),
                    Err(error) => {
                        this.cleanup_panel.ai_busy = false;
                        this.set_ai_phase(AiPhase::Failed, error, cx);
                        None
                    }
                }
            }).ok().flatten();
            let Some((snapshot_token, draft_eligible, (tree, findings))) = snapshot else { return };
            let context_request = request.clone();
            let context_settings = settings.clone();
            let context = cx.background_spawn(async move {
                agent::context_from_tree(&tree, &findings, &context_settings, &context_request)
            }).await;
            let context = match context {
                Ok(context) => context,
                Err(error) => {
                    this.update(cx, |this, cx| {
                        if this.cleanup_panel.ai_sequence == sequence {
                            this.cleanup_panel.ai_busy = false;
                            this.set_ai_phase(AiPhase::Failed, error, cx);
                        }
                    }).ok();
                    return;
                }
            };
            let sealed_context = context.clone();
            let sealed_request = request.clone();
            let valid = this.update(cx, |this, cx| {
                if this.cleanup_panel.ai_sequence != sequence { return false; }
                if !this.ai_current(snapshot_token) || !this.ai_ready() {
                    this.cleanup_panel.ai_busy = false;
                    this.set_ai_phase(AiPhase::Cancelled, t!(Tr::CpAiRequestChanged), cx);
                    return false;
                }
                this.cleanup_panel.chat.seal(sealed_context, sealed_request, snapshot_token);
                this.set_ai_phase(AiPhase::Waiting, t!(Tr::CpAiWaitingResponse), cx);
                true
            }).unwrap_or(false);
            if !valid { return; }
            let messages = this.update(cx, |this, _| this.cleanup_panel.chat.pending_messages()).unwrap_or_default();
            let result = cx.background_spawn(async move {
                agent::run_conversation(&settings.agent, context, request, messages)
            }).await;
            this.update(cx, |this, cx| {
                if !ai_chat::response_current(sequence, this.cleanup_panel.ai_sequence, this.cleanup_panel.ai_busy) { return; }
                this.cleanup_panel.ai_busy = false;
                if !this.ai_current(snapshot_token) {
                    this.set_ai_phase(AiPhase::Cancelled, t!(Tr::CpAiRequestChanged), cx);
                    return;
                }
                match result {
                    Ok(response) => {
                        if let Some(turn) = &mut this.cleanup_panel.ai_turn {
                            turn.answer = Some(response.explanation.clone());
                        }
                        let current = draft_eligible && this.cleanup_current(snapshot_token) && this.cleanup_ready();
                        let has_drafts = !response.proposals.is_empty();
                        this.cleanup_panel.chat.complete(&response, snapshot_token, current, cx);
                        // Keep read-only text but never expose stale draft actions.
                        if current { this.cleanup_panel.response = Some((snapshot_token, response)); }
                        this.set_ai_phase(AiPhase::Complete,
                            if !current && has_drafts { t!(Tr::CpAiDraftsExpired) } else { t!(Tr::CpAiSnapshotNotice) }, cx);
                    }
                    Err(error) => this.set_ai_phase(AiPhase::Failed, error, cx),
                }
            }).ok();
        }).detach();
    }
    pub(super) fn start_cleanup_scheduler(&mut self, cx: &mut Context<Self>) {
        self.load_chat_archive(cx);
        cx.spawn(async move |this, cx| {
            loop {
                this.update(cx, |this, cx| this.queue_chat_save(cx)).ok();
                cx.background_executor()
                    .timer(Duration::from_secs(60))
                    .await;
                if this
                    .update(cx, |this, cx| {
                        let Ok(settings) = &this.cleanup_panel.settings else {
                            return;
                        };
                        let due = settings.automation_enabled
                            && settings.rules.iter().any(|r| r.enabled && r.auto_clean)
                            && this.cleanup_panel.last_automatic.elapsed()
                                >= Duration::from_secs(
                                    settings.automation_interval_minutes.saturating_mul(60),
                                );
                        if due && this.cleanup_ready() && !this.cleanup_panel.preview_busy {
                            this.cleanup_panel.last_automatic = Instant::now();
                            this.preview_cleanup(true, cx);
                        }
                    })
                    .is_err()
                {
                    break;
                }
            }
        })
        .detach();
    }
    fn load_panel_history(&mut self, cx: &mut Context<Self>) {
        if self.cleanup_panel.history_busy {
            return;
        }
        self.cleanup_panel.history_busy = true;
        self.cleanup_panel.history_sequence = self.cleanup_panel.history_sequence.wrapping_add(1);
        let sequence = self.cleanup_panel.history_sequence;
        cx.spawn(async move |this, cx| {
            let result = cx.background_spawn(async move { cleanup::history() }).await;
            this.update(cx, |this, cx| {
                if sequence != this.cleanup_panel.history_sequence {
                    return;
                }
                this.cleanup_panel.history_busy = false;
                match result {
                    Ok(mut history) => {
                        history.reverse();
                        history.truncate(PAGE_SIZE);
                        this.cleanup_panel.history = history;
                        this.panel_message(t!(Tr::CpHistoryLoaded), cx);
                    }
                    Err(e) => this.panel_message(tf!(Tr::CpHistoryFailed, "e" => e), cx),
                }
            })
            .ok();
        })
        .detach();
    }

    pub(super) fn render_cleanup_panel(&self, window: &Window, cx: &mut Context<Self>) -> gpui::Div {
        let p = &self.cleanup_panel;
        let mut tabs = row();
        if p.cleanup_busy {
            tabs = tabs.child(
                button("stop-current-cleanup", t!(Tr::CpStopCurrentCleanup))
                    .on_click(cx.listener(|this, _, _, cx| this.stop_panel_cleanup(cx))),
            );
        }
        if p.settings
            .as_ref()
            .is_ok_and(|settings| settings.automation_enabled)
        {
            tabs = tabs.child(
                button("disable-auto-now", t!(Tr::CpDisableAutoNow))
                    .on_click(cx.listener(|this, _, _, cx| this.disable_panel_automation(cx))),
            );
        }
        for (i, label) in [t!(Tr::CpTabPreview), t!(Tr::CpTabRules), t!(Tr::CpTabAi), t!(Tr::CpTabSettings)]
            .iter()
            .enumerate()
        {
            tabs = tabs.child(
                button(("cleanup-tab", i), *label)
                    .when(p.tab == i, |d| d.bg(rgb(ACCENT)))
                    .on_click(cx.listener(move |this, _, window, cx| {
                        window.focus(&this.focus_handle, cx);
                        this.cleanup_panel.tab = i;
                        if i == 2 { this.load_chat_archive(cx); }
                        if i == 3 { this.refresh_monitor_disks(cx); }
                        cx.notify();
                    })),
            );
        }
        let mut body = div()
            .id("cleanup-panel-scroll")
            .flex_1()
            .min_h_0()
            .min_w_0()
            .when((p.tab != 1 || p.settings.is_err()) && !(p.tab == 2 && p.chat.has_history()), |d| d.overflow_y_scroll())
            .flex()
            .flex_col()
            .gap_3()
            .p_3()
            .when(p.tab == 1 && p.settings.is_ok(), |d| d.p_0().overflow_hidden())
            .when(p.tab == 2 && !p.chat.has_history(), |d| d.p_6().track_scroll(&p.ai_scroll))
            .when(p.tab == 2 && p.chat.has_history(), |d| d.overflow_hidden());
        if let Err(error) = &p.settings {
            body = body.child(
                panel_card()
                    .text_color(rgb(WARNING))
                    .child(tf!(
                        Tr::CpBadSettings,
                        "error" => error
                    ))
                    .child(
                        button("reload-bad-settings", t!(Tr::CpReloadConfig)).on_click(cx.listener(
                            |this, _, window, cx| {
                                window.focus(&this.focus_handle, cx);
                                this.reload_panel_settings(cx);
                            },
                        )),
                    ),
            );
            if p.tab == 2 { body = body.child(self.render_chat_workspace(false, window.viewport_size().width < px(820.), cx)); }
        } else {
            body = body.child(match p.tab {
                0 => self.render_cleanup_preview(cx),
                1 => self.render_cleanup_rules(window, cx),
                2 => self.render_cleanup_ai(window, cx),
                _ => self.render_cleanup_settings(cx),
            });
        }
        if !p.message.is_empty() && (!matches!(p.tab, 1 | 2) || p.settings.is_err()) {
            body = body.child(panel_card().child(p.message.clone()));
        }
        div()
            .size_full()
            .flex()
            .flex_col()
            .min_w_0()
            .child(
                div()
                    .p_3()
                    .border_b_1()
                    .border_color(rgb(BORDER))
                    .child(tabs),
            )
            .child(body)
    }
    fn render_cleanup_preview(&self, cx: &mut Context<Self>) -> gpui::Div {
        let p = &self.cleanup_panel;
        let mut view = panel_card().child(t!(Tr::CpPreviewIntro))
            .child(row().child(button("preview-rules", if p.preview_busy { t!(Tr::CpRegenerate) } else { t!(Tr::CpGeneratePreview) }).when(!self.cleanup_ready(), |d| d.opacity(0.4))
                .on_click(cx.listener(|this, _, _, cx| this.preview_cleanup(false, cx))))
                .child(button("cancel-preview", t!(Tr::CpCancelVerify)).when(!p.preview_busy, |d| d.opacity(0.4))
                    .on_click(cx.listener(|this, _, _, cx| this.cancel_cleanup_preview(cx))))
                .child(button("select-trash", t!(Tr::CpSelectSafe)).on_click(cx.listener(|this, _, _, cx| {
                    if let Some((token, plan)) = &this.cleanup_panel.plan {
                        if this.cleanup_current(*token) { this.cleanup_panel.selected = plan.items.iter().filter(|i| is_trash(i.action)).map(|i| i.path.clone()).collect(); }
                    } cx.notify();
                })))
                .child(button("clear-selection", t!(Tr::CpClearSelection)).on_click(cx.listener(|this, _, _, cx| { this.cleanup_panel.selected.clear(); cx.notify(); })))
                .child(button("execute-preview", tf!(Tr::CpConfirmCount, "n" => p.selected.len())).when(p.selected.is_empty() || !self.cleanup_ready(), |d| d.opacity(0.4))
                    .on_click(cx.listener(|this, _, window, cx| this.confirm_panel_cleanup(window, cx)))));
        if let Screen::Results(results) = &self.screen {
            view = view.child(div().text_color(rgb(WARNING)).child(tf!(
                Tr::CpIntegrityNote,
                "errors" => results.tree.errors,
                "cloud" => results.tree.cloud_only,
                "unreadable" => results.tree.unreadable.len(),
                "stale" => if results.out_of_date { t!(Tr::CpRescanYes) } else { t!(Tr::CpNo) }
            )));
        }
        let Some((token, plan)) = &p.plan else {
            return view.child(t!(Tr::CpNeedScanFirst));
        };
        let token = *token;
        if !self.cleanup_current(token) {
            return view.child(t!(Tr::CpPreviewStale));
        }
        let mut summary = std::collections::BTreeMap::<String, (usize, u64)>::new();
        for item in &plan.items {
            let entry = summary
                .entry(category_label(item.category).into())
                .or_default();
            entry.0 += 1;
            entry.1 = entry.1.saturating_add(item.size);
        }
        view = view.child(
            summary
                .into_iter()
                .map(|(k, (n, bytes))| tf!(Tr::CpRuleSummaryLine, "rule" => k, "n" => n, "size" => format_size(bytes)))
                .collect::<Vec<_>>()
                .join(" · "),
        );
        let unreadable = match &self.screen {
            Screen::Results(results) => results.tree.unreadable.as_slice(),
            _ => &[],
        };
        let diagnostic_count = plan.errors.len() + plan.blocked.len() + unreadable.len();
        view = view.child(
            button(
                "expand-preview-diagnostics",
                tf!(
                    Tr::CpDiagnosticsTitle,
                    "phase" => if p.diagnostics_expanded { t!(Tr::CpCollapse) } else { t!(Tr::CpExpand) },
                    "n" => diagnostic_count
                ),
            )
            .on_click(cx.listener(|this, _, _, cx| {
                this.cleanup_panel.diagnostics_expanded = !this.cleanup_panel.diagnostics_expanded;
                cx.notify();
            })),
        );
        if p.diagnostics_expanded {
            let page = p
                .diagnostic_page
                .min(diagnostic_count.saturating_sub(1) / PAGE_SIZE);
            let entries = plan
                .errors
                .iter()
                .map(|e| tf!(Tr::CpDiagError, "e" => e))
                .chain(plan.blocked.iter().map(|e| tf!(Tr::CpDiagProtected, "e" => e)))
                .chain(
                    unreadable
                        .iter()
                        .map(|u| tf!(Tr::CpDiagUnreadable, "path" => u.path.display().to_string(), "n" => u.errors)),
                );
            let mut diagnostics = panel_card().text_color(rgb(WARNING)).child(tf!(
                Tr::CpDiagnosticsPage,
                "page" => page + 1,
                "pages" => diagnostic_count.div_ceil(PAGE_SIZE).max(1)
            ));
            for entry in entries.skip(page * PAGE_SIZE).take(PAGE_SIZE) {
                diagnostics = diagnostics.child(entry);
            }
            diagnostics = diagnostics.child(
                row()
                    .child(
                        button("diagnostics-prev", t!(Tr::CpDiagnosticsPrev)).on_click(cx.listener(
                            |this, _, _, cx| {
                                this.cleanup_panel.diagnostic_page =
                                    this.cleanup_panel.diagnostic_page.saturating_sub(1);
                                cx.notify();
                            },
                        )),
                    )
                    .child(
                        button("diagnostics-next", t!(Tr::CpDiagnosticsNext)).on_click(cx.listener(
                            move |this, _, _, cx| {
                                if (this.cleanup_panel.diagnostic_page + 1) * PAGE_SIZE
                                    < diagnostic_count
                                {
                                    this.cleanup_panel.diagnostic_page += 1;
                                }
                                cx.notify();
                            },
                        )),
                    ),
            );
            view = view.child(diagnostics);
        }
        view = view.child(tf!(
            Tr::CpBlockedSummary,
            "n" => plan.blocked_total,
            "skipped" => plan.skipped_total,
            "page" => p.page + 1,
            "pages" => plan.items.len().div_ceil(PAGE_SIZE).max(1)
        ));
        for (i, item) in plan
            .items
            .iter()
            .enumerate()
            .skip(p.page * PAGE_SIZE)
            .take(PAGE_SIZE)
        {
            let path = item.path.clone();
            let protect = path.clone();
            let selected = p.selected.contains(&path);
            view = view.child(
                panel_card()
                    .child(
                        row()
                            .child(
                                button(
                                    ("preview-check", i),
                                    if selected { t!(Tr::CpSelected) } else { t!(Tr::CpSelect) },
                                )
                                .on_click(cx.listener(
                                    move |this, _, _, cx| {
                                        if this.cleanup_current(token)
                                            && !this.cleanup_panel.cleanup_busy
                                        {
                                            if !this.cleanup_panel.selected.remove(&path) {
                                                this.cleanup_panel.selected.insert(path.clone());
                                            }
                                        }
                                        cx.notify();
                                    },
                                )),
                            )
                            .child(tf!(
                                Tr::CpRowMeta,
                                "category" => category_label(item.category),
                                "size" => format_size(item.size),
                                "priority" => item.priority,
                                "action" => action_label(item.action)
                            ))
                            .child(button(("protect-file", i), t!(Tr::CpExcludedProtected)).on_click(
                                cx.listener(move |this, _, _, cx| {
                                    let Ok(mut next) = this.cleanup_panel.settings.clone() else {
                                        return;
                                    };
                                    if !next.whitelist.contains(&protect) {
                                        next.whitelist.push(protect.clone());
                                    }
                                    this.save_panel_settings(next, cx);
                                }),
                            )),
                    )
                    .child(item.path.display().to_string())
                    .child(tf!(Tr::CpReason, "rule" => item.rule_name, "reason" => item.reason)),
            );
        }
        view.child(
            row()
                .child(
                    button("preview-prev", t!(Tr::CpPrevPage)).on_click(cx.listener(|this, _, _, cx| {
                        this.cleanup_panel.page = this.cleanup_panel.page.saturating_sub(1);
                        cx.notify();
                    })),
                )
                .child(
                    button("preview-next", t!(Tr::CpNextPage)).on_click(cx.listener(|this, _, _, cx| {
                        if let Some((_, plan)) = &this.cleanup_panel.plan {
                            if (this.cleanup_panel.page + 1) * PAGE_SIZE < plan.items.len() {
                                this.cleanup_panel.page += 1;
                            }
                        }
                        cx.notify();
                    })),
                ),
        )
    }
    fn reset_rule_filters(&mut self, cx: &mut Context<Self>) {
        self.cleanup_panel.rule_query = RuleQuery::default();
        self.cleanup_panel.rule_menu = None;
        self.cleanup_panel.rule_search.update(cx, |input, cx| input.set_text("", cx));
        self.cleanup_panel.rule_scroll.scroll_to_item(0, ScrollStrategy::Top);
        cx.notify();
    }

    fn toggle_managed_rule(&mut self, id: &str, cx: &mut Context<Self>) {
        if !self.cleanup_panel.writable() || self.cleanup_panel.editor.is_some() {
            return;
        }
        let Ok(mut next) = self.cleanup_panel.settings.clone() else { return };
        let Some(rule) = next.rules.iter_mut().find(|rule| rule.id == id) else { return };
        rule.enabled = !rule.enabled;
        self.save_panel_settings(next, cx);
    }

    fn render_cleanup_rules(&self, window: &Window, cx: &mut Context<Self>) -> gpui::Div {
        let p = &self.cleanup_panel;
        let Ok(settings) = &p.settings else { return div() };
        let visible = p.rule_index.borrow_mut().visible(&settings.rules, p.revision, p.rule_query.clone());
        let (enabled, automatic) = {
            let index = p.rule_index.borrow();
            (index.enabled, index.automatic)
        };
        let can_modify = p.writable() && p.editor.is_none();
        let has_detail = p.editor.is_some() || p.rule_selected.as_ref()
            .is_some_and(|id| p.rule_index.borrow().rule(&settings.rules, id).is_some());
        let compact = has_detail && window.viewport_size().width < px(1100.);
        let mut filters = row().gap_1();
        for (i, (status, label)) in [
            (RuleStatusFilter::All, t!(Tr::CpRulesAll)),
            (RuleStatusFilter::Enabled, t!(Tr::CpRulesEnabled)),
            (RuleStatusFilter::Disabled, t!(Tr::CpRulesDisabled)),
            (RuleStatusFilter::Automatic, t!(Tr::CpRulesAutomatic)),
        ].into_iter().enumerate() {
            filters = filters.child(
                button(("rule-status-filter", i), label).text_xs().bg(rgb(PANEL))
                    .when(p.rule_query.status == status, |d| d.bg(rgba(ACCENT_TINT)).text_color(rgb(ACCENT)))
                    .on_click(cx.listener(move |this, _, window, cx| {
                        window.focus(&this.focus_handle, cx);
                        this.cleanup_panel.rule_query.status = status;
                        this.cleanup_panel.rule_menu = None;
                        this.cleanup_panel.rule_scroll.scroll_to_item(0, ScrollStrategy::Top);
                        cx.notify();
                    })),
            );
        }
        for (i, (menu, label, value)) in [
            (RuleFilterMenu::Source, t!(Tr::CpRulesSource), p.rule_query.source.map(source_label).unwrap_or(t!(Tr::CpRulesAllSources))),
            (RuleFilterMenu::Category, t!(Tr::CpRulesCategory), p.rule_query.category.map(category_label).unwrap_or(t!(Tr::CpRulesAllCategories))),
            (RuleFilterMenu::Sort, t!(Tr::CpRulesSort), rule_sort_label(p.rule_query.sort)),
        ].into_iter().enumerate() {
            filters = filters.child(
                button(("rule-filter-menu", i), format!("{label}: {value}  {}", if p.rule_menu == Some(menu) { "⌄" } else { "›" }))
                    .text_xs().bg(rgb(PANEL))
                    .when(p.rule_menu == Some(menu), |d| d.text_color(rgb(ACCENT)))
                    .on_click(cx.listener(move |this, _, window, cx| {
                        window.focus(&this.focus_handle, cx);
                        this.cleanup_panel.rule_menu = if this.cleanup_panel.rule_menu == Some(menu) { None } else { Some(menu) };
                        cx.notify();
                    })),
            );
        }
        if p.rule_query != RuleQuery::default() {
            filters = filters.child(button("rules-reset", t!(Tr::CpRulesReset)).text_xs().text_color(rgb(MUTED))
                .on_click(cx.listener(|this, _, window, cx| {
                    window.focus(&this.focus_handle, cx);
                    this.reset_rule_filters(cx);
                })));
        }
        let mut toolbar = div().p_4().flex_none().flex().flex_col().gap_3().border_b_1().border_color(rgb(BORDER))
            .child(row().justify_between()
                .child(div().flex().flex_col().gap_1()
                    .child(div().text_lg().font_weight(FontWeight::SEMIBOLD).child(t!(Tr::CpTabRules)))
                    .child(div().text_xs().text_color(rgb(MUTED)).child(t!(Tr::CpRulesSubtitle))))
                .child(primary_button("new-rule", t!(Tr::CpRulesNewTitle), ACCENT)
                    .tooltip(tooltip(t!(Tr::CpNewRule)))
                    .when(!can_modify, |d| d.opacity(0.45))
                    .when(can_modify, |d| d.on_click(cx.listener(|this, _, window, cx| this.new_panel_rule(window, cx))))))
            .child(row().gap_3()
                .child(div().w(px(300.)).max_w_full().id("rules-search-field")
                    .tooltip(tooltip(t!(Tr::CpRulesSearchLabel))).child(p.rule_search.clone()))
                .child(div().text_xs().text_color(rgb(MUTED)).child(tf!(Tr::CpRulesCount, "visible" => visible.len(), "total" => settings.rules.len())))
                .child(div().text_xs().text_color(rgb(MUTED)).child(tf!(Tr::CpRulesStats, "enabled" => enabled, "automatic" => automatic))))
            .child(filters);
        if p.rule_menu.is_some() {
            toolbar = toolbar.child(self.render_rule_filter_choices(cx));
        }
        if p.editor.is_some() {
            toolbar = toolbar.child(div().text_xs().text_color(rgb(WARNING)).child(t!(Tr::CpRulesEditingHint)));
        }
        let mut table = div().debug_selector(|| "rules-table".into()).flex_1().min_w_0().min_h_0().flex().flex_col()
            .child(div().h(px(34.)).flex_none().px_4().flex().items_center().gap_3().bg(rgb(PANEL)).text_xs().text_color(rgb(MUTED))
                .child(div().flex_1().min_w_0().child(t!(Tr::CpRulesColumnName)))
                .when(!compact, |d| d
                    .child(div().w(px(76.)).flex_none().child(t!(Tr::CpRulesSource)))
                    .child(div().w(px(76.)).flex_none().child(t!(Tr::CpRulesCategory))))
                .child(div().w(px(90.)).flex_none().child(t!(Tr::CpRulesColumnStatus)))
                .when(!compact, |d| d.child(div().w(px(54.)).flex_none().text_right().child(t!(Tr::CpRulesColumnPriority)))));
        if visible.is_empty() {
            table = table.child(div().flex_1().flex().flex_col().items_center().justify_center().gap_3().p_5()
                .child(div().font_weight(FontWeight::MEDIUM).child(if settings.rules.is_empty() { t!(Tr::CpRulesEmpty) } else { t!(Tr::CpRulesNoMatch) }))
                .child(div().text_xs().text_color(rgb(MUTED)).child(if settings.rules.is_empty() { t!(Tr::CpRulesEmptyHint) } else { t!(Tr::CpRulesNoMatchHint) })));
        } else {
            table = table.child(div().flex_1().min_h_0().child(
                uniform_list("managed-rules", visible.len(), cx.processor(Self::render_rule_rows))
                    .track_scroll(&p.rule_scroll).size_full(),
            ));
        }
        let detail = self.render_rule_detail(cx);
        let mut view = div().size_full().min_h_0().min_w_0().flex().flex_col().child(toolbar)
            .child(div().flex_1().min_h_0().min_w_0().flex().child(table).when_some(detail, |d, detail| d.child(detail)));
        if !p.message.is_empty() {
            view = view.child(div().flex_none().px_4().py_2().border_t_1().border_color(rgb(BORDER))
                .text_xs().text_color(rgb(MUTED)).max_h(px(64.)).id("rules-notice").overflow_y_scroll().child(p.message.clone()));
        }
        view
    }

    fn render_rule_filter_choices(&self, cx: &mut Context<Self>) -> gpui::Div {
        let p = &self.cleanup_panel;
        let mut choices = row().p_2().rounded_lg().bg(rgb(PANEL));
        match p.rule_menu {
            Some(RuleFilterMenu::Source) => {
                for (i, source) in [None, Some(RuleSource::BuiltIn), Some(RuleSource::User), Some(RuleSource::Ai)].into_iter().enumerate() {
                    choices = choices.child(button(("rule-source-choice", i), source.map(source_label).unwrap_or(t!(Tr::CpRulesAllSources)))
                        .text_xs().when(p.rule_query.source == source, |d| d.text_color(rgb(ACCENT)))
                        .on_click(cx.listener(move |this, _, _, cx| {
                            this.cleanup_panel.rule_query.source = source;
                            this.cleanup_panel.rule_menu = None;
                            this.cleanup_panel.rule_scroll.scroll_to_item(0, ScrollStrategy::Top);
                            cx.notify();
                        })));
                }
            }
            Some(RuleFilterMenu::Category) => {
                for (i, category) in std::iter::once(None).chain(RULE_CATEGORIES.map(Some)).enumerate() {
                    choices = choices.child(button(("rule-category-choice", i), category.map(category_label).unwrap_or(t!(Tr::CpRulesAllCategories)))
                        .text_xs().when(p.rule_query.category == category, |d| d.text_color(rgb(ACCENT)))
                        .on_click(cx.listener(move |this, _, _, cx| {
                            this.cleanup_panel.rule_query.category = category;
                            this.cleanup_panel.rule_menu = None;
                            this.cleanup_panel.rule_scroll.scroll_to_item(0, ScrollStrategy::Top);
                            cx.notify();
                        })));
                }
            }
            Some(RuleFilterMenu::Sort) => {
                for (i, sort) in [RuleSort::Priority, RuleSort::Name, RuleSort::Status].into_iter().enumerate() {
                    choices = choices.child(button(("rule-sort-choice", i), rule_sort_label(sort))
                        .text_xs().when(p.rule_query.sort == sort, |d| d.text_color(rgb(ACCENT)))
                        .on_click(cx.listener(move |this, _, _, cx| {
                            this.cleanup_panel.rule_query.sort = sort;
                            this.cleanup_panel.rule_menu = None;
                            this.cleanup_panel.rule_scroll.scroll_to_item(0, ScrollStrategy::Top);
                            cx.notify();
                        })));
                }
            }
            None => {}
        }
        choices
    }

    fn render_rule_rows(&mut self, range: Range<usize>, window: &mut Window, cx: &mut Context<Self>) -> Vec<Stateful<gpui::Div>> {
        let p = &self.cleanup_panel;
        let Ok(settings) = &p.settings else { return vec![] };
        let visible = p.rule_index.borrow_mut().visible(&settings.rules, p.revision, p.rule_query.clone());
        let has_detail = p.editor.is_some() || p.rule_selected.as_ref()
            .is_some_and(|id| p.rule_index.borrow().rule(&settings.rules, id).is_some());
        let compact = has_detail && window.viewport_size().width < px(1100.);
        range.filter_map(|row_index| {
            let rule = settings.rules.get(*visible.get(row_index)?)?;
            let id = rule.id.clone();
            let selected = p.rule_selected.as_ref() == Some(&id);
            let detail = format!("{} · {}", path_list(&rule.roots), rule.pattern);
            Some(div().debug_selector(|| format!("rule-row-{}", rule.id))
                .id(SharedString::from(format!("managed-rule-{}", rule.id)))
                .h(px(RULE_ROW_HEIGHT)).w_full().px_4().flex().items_center().gap_3()
                .border_b_1().border_color(rgb(BORDER)).cursor_pointer()
                .when(selected, |d| d.bg(rgba(ACCENT_TINT)))
                .when(!selected, |d| d.hover(|s| s.bg(rgb(PANEL))))
                .child(div().debug_selector(|| "rule-name-cell".into()).flex_1().min_w_0().flex().flex_col().gap_1()
                    .child(div().truncate().font_weight(FontWeight::MEDIUM).child(rule.name_label().to_owned()))
                    .child(div().truncate().text_xs().text_color(rgb(MUTED)).child(detail)))
                .when(!compact, |d| d
                    .child(div().w(px(76.)).flex_none().truncate().text_xs().text_color(rgb(MUTED)).child(source_label(rule.source)))
                    .child(div().w(px(76.)).flex_none().truncate().text_xs().text_color(rgb(MUTED)).child(category_label(rule.category))))
                .child(div().w(px(90.)).flex_none().flex().flex_col().gap_1().text_xs()
                    .child(div().text_color(rgb(if rule.enabled { SAFE } else { MUTED })).child(if rule.enabled { t!(Tr::CpRulesEnabled) } else { t!(Tr::CpRulesDisabled) }))
                    .when(rule.enabled && rule.auto_clean, |d| d.child(div().truncate().text_color(rgb(ACCENT)).child(t!(Tr::CpRulesAutomatic)))))
                .when(!compact, |d| d.child(div().w(px(54.)).flex_none().text_right().text_xs().text_color(rgb(MUTED)).child(rule.priority.to_string())))
                .on_click(cx.listener(move |this, _, window, cx| {
                    window.focus(&this.focus_handle, cx);
                    if this.cleanup_panel.editor.is_some() { return }
                    this.cleanup_panel.rule_selected = Some(id.clone());
                    this.cleanup_panel.rule_menu = None;
                    cx.notify();
                })))
        }).collect()
    }

    fn render_rule_detail(&self, cx: &mut Context<Self>) -> Option<gpui::Div> {
        let p = &self.cleanup_panel;
        let settings = p.settings.as_ref().ok()?;
        let rule = p.rule_selected.as_ref().and_then(|id| p.rule_index.borrow().rule(&settings.rules, id));
        if p.editor.is_none() && rule.is_none() { return None }
        let title = if p.editor.is_some() { t!(Tr::CpRulesEditTitle) } else { t!(Tr::CpRulesDetail) };
        let mut body = div().id(SharedString::from(format!("rule-{}-{}",
                if p.editor.is_some() { "editor" } else { "detail" },
                p.editor.as_ref().map(|editor| editor.rule.id.as_str())
                    .or(p.rule_selected.as_deref()).unwrap_or_default())))
            .flex_1().min_h_0().overflow_y_scroll()
            .when(p.editor.is_some(), |d| d.track_scroll(&p.rule_editor_scroll))
            .p_4().flex().flex_col().gap_4().min_w_0();
        if p.editor.is_some() {
            body = body.child(self.render_rule_editor(cx));
        } else if let Some(rule) = rule {
            body = body.child(div().text_lg().font_weight(FontWeight::SEMIBOLD).child(rule.name_label().to_owned()))
                .child(row().child(ai_badge(source_label(rule.source), MUTED)).child(ai_badge(category_label(rule.category), ACCENT)))
                .child(div().line_height(relative(1.5)).text_color(rgb(MUTED)).child(if rule.description.is_empty() { t!(Tr::CpRulesNoDescription).to_owned() } else { rule.description_label().to_owned() }))
                .child(rule_detail_field(t!(Tr::CpRulesId), rule.id.clone()))
                .child(div().pt_3().border_t_1().border_color(rgb(BORDER)).font_weight(FontWeight::MEDIUM).child(t!(Tr::CpRulesConditions)))
                .child(rule_detail_field(t!(Tr::CpFieldScopePaths), path_list(&rule.roots)))
                .child(rule_detail_field(t!(Tr::CpFieldMatchGlobs), rule.pattern.clone()))
                .child(rule_detail_field(t!(Tr::CpFieldExcludeGlobsShort), if rule.exclude.is_empty() { t!(Tr::CpRulesNoExcludes).to_owned() } else { rule.exclude.join("; ") }))
                .child(row().items_start()
                    .child(rule_detail_field(t!(Tr::CpFieldMinSize), rule.min_size.to_string()).flex_1())
                    .child(rule_detail_field(t!(Tr::CpFieldKeepDaysShort), rule.older_than_days.map(|days| days.to_string()).unwrap_or_else(|| t!(Tr::CpNoLimit).into())).flex_1()))
                .child(rule_detail_field(t!(Tr::CpFieldPriorityShort), rule.priority.to_string()))
                .child(div().pt_3().border_t_1().border_color(rgb(BORDER)).font_weight(FontWeight::MEDIUM).child(t!(Tr::CpRulesBehavior)))
                .child(row().child(ai_badge(if rule.enabled { t!(Tr::CpRulesEnabled) } else { t!(Tr::CpRulesDisabled) }, if rule.enabled { SAFE } else { MUTED }))
                    .child(div().text_xs().text_color(rgb(if rule.action == CleanupAction::Permanent { DANGER } else { TEXT })).child(action_label(rule.action))))
                .child(rule_detail_field(t!(Tr::CpRulesAutomatic), if rule.auto_clean { t!(Tr::CpAuthorized) } else { t!(Tr::CpOff) }))
                .child(div().text_xs().text_color(rgb(MUTED)).child(t!(Tr::CpRulesAutoHint)))
                .child(div().text_xs().text_color(rgb(MUTED)).child(t!(Tr::CpRulesIntro)));
            let editable = p.writable();
            let toggle_id = rule.id.clone();
            let edit_id = rule.id.clone();
            let delete_id = rule.id.clone();
            body = body.child(row().pt_3().border_t_1().border_color(rgb(BORDER))
                .child(button("managed-rule-toggle", if rule.enabled { t!(Tr::CpRulesDisableAction) } else { t!(Tr::CpRulesEnableAction) })
                    .when(!editable, |d| d.opacity(0.45))
                    .when(editable, |d| d.on_click(cx.listener(move |this, _, _, cx| this.toggle_managed_rule(&toggle_id, cx)))))
                .child(primary_button("managed-rule-edit", t!(Tr::CpEdit), ACCENT)
                    .when(!editable, |d| d.opacity(0.45))
                    .when(editable, |d| d.on_click(cx.listener(move |this, _, window, cx| {
                        let rule = this.cleanup_panel.settings.as_ref().ok().and_then(|s| s.rules.iter().find(|r| r.id == edit_id)).cloned();
                        if let Some(rule) = rule { this.edit_panel_rule(rule, None, window, cx); }
                    }))))
                .child(button("managed-rule-delete", t!(Tr::CpDeleteRule)).text_color(rgb(DANGER))
                    .when(!editable, |d| d.opacity(0.45))
                    .when(editable, |d| d.on_click(cx.listener(move |this, _, window, cx| {
                        if this.cleanup_panel.editor.is_some() { return }
                        let Ok(mut next) = this.cleanup_panel.settings.clone() else { return };
                        if !next.rules.iter().any(|rule| rule.id == delete_id) { return }
                        next.rules.retain(|rule| rule.id != delete_id);
                        this.confirm_panel_settings(next, t!(Tr::CpConfirmDeleteRule), t!(Tr::CpDeleteRuleNote), window, cx);
                    })))));
        }
        Some(div().debug_selector(|| "rule-detail-panel".into()).w(px(360.)).flex_none().min_h_0().min_w_0().border_l_1().border_color(rgb(BORDER)).bg(rgb(PANEL))
            .flex().flex_col()
            .child(row().flex_none().p_4().border_b_1().border_color(rgb(BORDER)).justify_between()
                .child(div().font_weight(FontWeight::SEMIBOLD).child(title))
                .when(p.editor.is_none(), |d| d.child(button("close-rule-detail", "×").tooltip(tooltip(t!(Tr::CpRulesCloseDetail)))
                    .on_click(cx.listener(|this, _, _, cx| { this.cleanup_panel.rule_selected = None; cx.notify(); })))))
            .child(body)
            .when(p.editor.is_some(), |d| d.child(
                row().debug_selector(|| "rule-editor-actions".into()).flex_none().p_3().border_t_1().border_color(rgb(BORDER))
                    .child(primary_button("save-rule", t!(Tr::CpSaveRule), ACCENT)
                        .when(!p.writable(), |d| d.opacity(0.45))
                        .when(p.writable(), |d| d.on_click(cx.listener(|this, _, window, cx| this.save_panel_rule(window, cx)))))
                    .child(button("cancel-rule", t!(Tr::CpCancelEdit))
                        .on_click(cx.listener(|this, _, window, cx| {
                            window.focus(&this.focus_handle, cx);
                            this.cleanup_panel.editor = None;
                            cx.notify();
                        }))),
            )))
    }

    fn render_rule_editor(&self, cx: &mut Context<Self>) -> gpui::Div {
        let p = &self.cleanup_panel;
        let mut view = div().flex().flex_col().gap_4().min_w_0();
        if let Some(editor) = &p.editor {
            view = view.child(
                div().flex().flex_col().gap_4().min_w_0()
                    .child(div().text_xs().text_color(rgb(MUTED)).child(t!(Tr::CpEditorHint)))
                    .when(editor_conflict(editor.open_revision, p.revision) || editor.draft_token.is_some_and(|token| !self.cleanup_current(token)), |d| d.child(div().text_color(rgb(WARNING)).child(t!(Tr::CpEditorStaleWarning))))
                    .child(div().font_weight(FontWeight::MEDIUM).child(t!(Tr::CpRulesMetadata)))
                    .child(field(t!(Tr::CpFieldName), &editor.name))
                    .child(field(t!(Tr::CpFieldDescription), &editor.description))
                    .child(div().pt_3().border_t_1().border_color(rgb(BORDER)).font_weight(FontWeight::MEDIUM).child(t!(Tr::CpRulesConditions)))
                    .child(field(t!(Tr::CpFieldScopePaths), &editor.roots))
                    .child(field(t!(Tr::CpFieldMatchGlobs), &editor.pattern))
                    .child(field(t!(Tr::CpFieldExcludeGlobsShort), &editor.exclude))
                    .child(row().items_start()
                        .child(field(t!(Tr::CpFieldMinSize), &editor.size).flex_1())
                        .child(field(t!(Tr::CpFieldKeepDaysShort), &editor.days).flex_1()))
                    .child(field(t!(Tr::CpFieldPriorityShort), &editor.priority))
                    .child(div().pt_3().border_t_1().border_color(rgb(BORDER)).font_weight(FontWeight::MEDIUM).child(t!(Tr::CpRulesBehavior)))
                    .child(
                        row()
                            .child(
                                button(
                                    "edit-enabled",
                                    if editor.rule.enabled {
                                        t!(Tr::CpRuleEnabled)
                                    } else {
                                        t!(Tr::CpRuleDisabled)
                                    },
                                )
                                .on_click(cx.listener(
                                    |this, _, _, cx| {
                                        if !this.cleanup_panel.writable() { return; }
                                        if let Some(e) = &mut this.cleanup_panel.editor {
                                            e.rule.enabled = !e.rule.enabled;
                                        }
                                        cx.notify();
                                    },
                                )),
                            )
                            .child(
                                button("edit-action", action_label(editor.rule.action)).on_click(
                                    cx.listener(|this, _, _, cx| {
                                        if !this.cleanup_panel.writable() { return; }
                                        if let Some(e) = &mut this.cleanup_panel.editor {
                                            e.rule.action = if e.rule.action == CleanupAction::Trash
                                            {
                                                CleanupAction::Permanent
                                            } else {
                                                CleanupAction::Trash
                                            };
                                            e.rule.auto_clean = false;
                                        }
                                        cx.notify();
                                    }),
                                ),
                            )
                            .child(
                                button(
                                    "edit-auto",
                                    if editor.rule.auto_clean {
                                        t!(Tr::CpAutoPending)
                                    } else {
                                        t!(Tr::CpAutoOff)
                                    },
                                )
                                .on_click(cx.listener(
                                    |this, _, _, cx| {
                                        if !this.cleanup_panel.writable() { return; }
                                        if let Some(e) = &mut this.cleanup_panel.editor {
                                            e.rule.auto_clean = !e.rule.auto_clean;
                                        }
                                        cx.notify();
                                    },
                                )),
                            ),
                    ),
            );
            let mut categories = row();
            for (i, category) in RULE_CATEGORIES.into_iter().enumerate()
            {
                categories = categories.child(
                    button(("edit-category", i), category_label(category))
                        .when(editor.rule.category == category, |d| d.bg(rgb(ACCENT)))
                        .on_click(cx.listener(move |this, _, _, cx| {
                            if !this.cleanup_panel.writable() {
                                return;
                            }
                            if let Some(e) = &mut this.cleanup_panel.editor {
                                e.rule.category = category;
                            }
                            cx.notify();
                        })),
                );
            }
            view = view.child(div().text_xs().text_color(rgb(MUTED)).child(t!(Tr::CpRulesCategory))).child(categories);
        }
        view
    }
    fn render_cleanup_ai(&self, window: &Window, cx: &mut Context<Self>) -> gpui::Div {
        let p = &self.cleanup_panel;
        let Ok(settings) = &p.settings else {
            return panel_card();
        };
        let saved = text(&p.url, cx) == settings.agent.base_url
            && text(&p.model, cx) == settings.agent.model;
        let writable = p.writable();
        let can_configure = writable && !p.ai_busy;
        let can_adopt = writable && self.cleanup_ready();
        let can_request = settings.agent.enabled && saved && self.ai_ready() && !p.ai_busy;
        if p.chat.has_history() {
            let mut view = div().flex().flex_col().flex_1().min_h_0().min_w_0().gap_2()
                .child(row().flex_shrink_0().child(button("chat-analyze", t!(Tr::CpAnalyzeDisk)).when(can_request, |d| d.on_click(cx.listener(|this, _, window, cx| this.request_panel_ai(AgentRequest::Analyze, None, window, cx)))))
                    .child(button("chat-explain", t!(Tr::CpExplainSelection)).when(can_request, |d| d.on_click(cx.listener(|this, _, window, cx| {
                        if let Screen::Results(r) = &this.screen { let ix = r.focus; this.explain_cleanup_node(ix, window, cx); }
                    }))))
                    .child(button("chat-generate", t!(Tr::CpGenerateDrafts)).when(can_request, |d| d.on_click(cx.listener(|this, _, window, cx| this.request_panel_ai(AgentRequest::GenerateRules, None, window, cx)))))
                    .child(button("chat-config", t!(Tr::CpAiService)).on_click(cx.listener(|this, _, _, cx| { this.cleanup_panel.ai_config_expanded = !this.cleanup_panel.ai_config_expanded; cx.notify(); }))));
            view = view.child(self.render_ai_sharing_options(can_configure, cx).flex_shrink_0());
            if p.ai_config_expanded {
                view = view.child(div().id("chat-config-scroll").max_h(px(240.)).overflow_y_scroll().child(self.render_cleanup_ai_config(saved, can_configure, cx)));
            }
            if settings.agent.has_privacy_consent() {
                view = view.child(button("chat-reset-consent", t!(Tr::CpAiForgetConsent)).text_xs().flex_shrink_0()
                    .when(can_configure, |d| d.on_click(cx.listener(|this, _, _, cx| this.revoke_ai_consent(false, cx)))));
            }
            if !p.message.is_empty() { view = view.child(div().text_xs().text_color(rgb(WARNING)).child(p.message.clone())); }
            return view.child(self.render_chat_workspace(can_request, window.viewport_size().width < px(820.), cx));
        }
        let can_explain = can_request
            && matches!(&self.screen, Screen::Results(r)
                if r.tree.is_attached(r.focus) && r.tree.nodes[r.focus].kind != Kind::Other);
        let response = p.response.as_ref()
            .filter(|(token, _)| self.cleanup_current(*token))
            .map(|(_, response)| response);
        let (status, status_color) = if p.ai_busy {
            (t!(Tr::CpAiStatusBusy), ACCENT)
        } else if settings.agent.enabled {
            (t!(Tr::CpAiStatusReady), SAFE)
        } else {
            (t!(Tr::CpAiStatusOff), MUTED)
        };
        let header = row()
            .justify_between()
            .gap_4()
            .child(
                div().flex().items_center().gap_3().min_w_0()
                    .child(
                        div().size(px(44.)).flex().items_center().justify_center()
                            .rounded_xl().bg(rgba(ACCENT_TINT)).text_color(rgb(ACCENT))
                            .font_weight(FontWeight::BOLD).child("AI"),
                    )
                    .child(
                        div().flex().flex_col().gap_1().min_w_0()
                            .child(div().text_xl().font_weight(FontWeight::SEMIBOLD).child(t!(Tr::CpTabAi)))
                            .child(div().text_color(rgb(MUTED)).child(t!(Tr::CpAiSubtitle))),
                    ),
            )
            .child(row().child(ai_badge(status, status_color)).child(
                div().max_w(px(220.)).truncate().text_xs().text_color(rgb(MUTED))
                    .child(settings.agent.model.clone()),
            ));
        let mut view = div()
            .w_full().max_w(px(1040.)).mx_auto().flex().flex_col().flex_shrink_0().gap_5().min_w_0()
            .child(header)
            .child(
                div().flex().flex_col().gap_3()
                    .child(div().font_weight(FontWeight::MEDIUM).child(t!(Tr::CpAiActions)))
                    .child(
                        row().items_stretch().gap_3()
                            .child(ai_action("ai-analyze", t!(Tr::CpAnalyzeDisk), t!(Tr::CpAiAnalyzeHint), ChartType::Sunburst, can_request)
                                .when(can_request, |d| d.on_click(cx.listener(|this, _, window, cx| {
                                    this.request_panel_ai(AgentRequest::Analyze, None, window, cx);
                                }))))
                            .child(ai_action("ai-explain", t!(Tr::CpExplainSelection), t!(Tr::CpAiExplainHint), ChartType::Icicle, can_explain)
                                .when(can_explain, |d| d.on_click(cx.listener(|this, _, window, cx| {
                                    if let Screen::Results(r) = &this.screen {
                                        let ix = r.focus;
                                        this.explain_cleanup_node(ix, window, cx);
                                    }
                                }))))
                            .child(ai_action("ai-drafts", t!(Tr::CpGenerateDrafts), t!(Tr::CpAiDraftsHint), ChartType::Treemap, can_request)
                                .when(can_request, |d| d.on_click(cx.listener(|this, _, window, cx| {
                                    this.request_panel_ai(AgentRequest::GenerateRules, None, window, cx);
                                })))),
                    )
                    .child(
                        row().justify_between()
                            .child(div().text_xs().text_color(rgb(MUTED)).child(t!(Tr::CpAiAdvisory)))
                            .child(self.render_ai_sharing_options(can_configure, cx)),
                    ),
            );
        let mut insights = ai_card().child(
            row().justify_between()
                .child(div().font_weight(FontWeight::SEMIBOLD).child(t!(Tr::CpAiConversation)))
                .when(p.ai_busy || p.ai_turn.is_some() || response.is_some(), |d| d.child(
                    button("ai-cancel", if p.ai_busy { t!(Tr::CpCancelDiscard) } else { t!(Tr::CpClearSuggestions) })
                        .text_xs().bg(rgb(PANEL)).text_color(rgb(MUTED))
                        .on_click(cx.listener(|this, _, window, cx| {
                            window.focus(&this.focus_handle, cx);
                            this.cleanup_panel.ai_sequence = this.cleanup_panel.ai_sequence.wrapping_add(1);
                            this.cleanup_panel.ai_busy = false;
                            this.cleanup_panel.response = None;
                            if this.cleanup_panel.ai_turn.as_ref().is_some_and(|turn| matches!(turn.phase, AiPhase::Consent | AiPhase::Preparing | AiPhase::Waiting)) {
                                this.set_ai_phase(AiPhase::Cancelled, t!(Tr::CpResultCancelled), cx);
                            } else {
                                this.cleanup_panel.ai_turn = None;
                                this.cleanup_panel.message.clear();
                                cx.notify();
                            }
                        })),
                )),
        );
        if let Some(turn) = &p.ai_turn {
            let (phase, color) = match turn.phase {
                AiPhase::Consent => (t!(Tr::CpAiPhaseConsent), WARNING),
                AiPhase::Preparing => (t!(Tr::CpAiPhasePreparing), ACCENT),
                AiPhase::Waiting => (t!(Tr::CpAiPhaseWaiting), ACCENT),
                AiPhase::Complete => (t!(Tr::CpAiPhaseComplete), SAFE),
                AiPhase::Failed => (t!(Tr::CpAiPhaseFailed), WARNING),
                AiPhase::Cancelled => (t!(Tr::CpAiPhaseCancelled), MUTED),
            };
            insights = insights.child(
                div().id("ai-user-message").debug_selector(|| "ai-user-message".into())
                    .p_4().rounded_lg().bg(rgba(ACCENT_TINT)).flex().flex_col().flex_shrink_0().gap_2()
                    .child(div().text_xs().text_color(rgb(ACCENT)).child(t!(Tr::CpAiYou)))
                    .child(div().line_height(relative(1.5)).child(turn.request.clone())),
            ).child(
                div().id("ai-request-status").debug_selector(|| "ai-request-status".into())
                    .flex().flex_col().flex_shrink_0().gap_2()
                    .child(row().justify_between()
                        .child(div().text_xs().font_weight(FontWeight::MEDIUM).child(t!(Tr::CpTabAi)))
                        .child(ai_badge(phase, color)))
                    .when(!turn.detail.is_empty(), |d| d.child(
                        div().text_xs().text_color(rgb(MUTED)).line_height(relative(1.5)).child(turn.detail.clone()))),
            );
            if let Some(answer) = &turn.answer {
                let mut reply = div().id("ai-assistant-message").debug_selector(|| "ai-assistant-message".into())
                    .flex().flex_col().flex_shrink_0().gap_3().min_w_0();
                reply = reply.child(super::ai_markdown::render_markdown(answer));
                insights = insights.child(reply);
            }
        } else if response.is_none() {
            let hint = if !settings.agent.enabled {
                t!(Tr::CpAiSetupHint)
            } else if !saved {
                t!(Tr::CpAiServiceHint)
            } else if !self.ai_ready() {
                t!(Tr::CpAiScanHint)
            } else {
                t!(Tr::CpAiEmptyHint)
            };
            insights = insights.child(
                div().py_5().flex().flex_col().items_center().gap_2()
                    .child(div().text_color(rgb(ACCENT)).child(icons::chart(ChartType::Sunburst)))
                    .child(div().font_weight(FontWeight::MEDIUM).child(t!(Tr::CpAiEmptyTitle)))
                    .child(div().text_xs().text_color(rgb(MUTED)).child(hint)),
            );
        }
        if let Some(response) = response {
            if p.ai_turn.as_ref().and_then(|turn| turn.answer.as_ref()).is_none() {
                let mut explanation = div().flex().flex_col().gap_3().min_w_0()
                    .child(div().text_xs().text_color(rgb(ACCENT)).font_weight(FontWeight::MEDIUM).child(t!(Tr::CpAiResultLabel)));
                explanation = explanation.child(super::ai_markdown::render_markdown(&response.explanation));
                insights = insights.child(explanation);
            }
            if !response.proposals.is_empty() {
                insights = insights.child(
                    div().pt_4().border_t_1().border_color(rgb(BORDER)).font_weight(FontWeight::MEDIUM)
                        .child(tf!(Tr::CpAiReviewDrafts, "count" => response.proposals.len())),
                );
            }
            for (i, rule) in response.proposals.iter().enumerate() {
                let edit = rule.clone();
                let edit_id = rule.id.clone();
                let adopt = rule.id.clone();
                let enable = rule.id.clone();
                let reject = rule.id.clone();
                let retention = rule.older_than_days
                    .map(|days| tf!(Tr::CpAiDraftRetention, "days" => days))
                    .unwrap_or_else(|| t!(Tr::CpDraftNoLimit).into());
                insights = insights.child(
                    div().p_4().rounded_lg().bg(rgb(BG)).border_1().border_color(rgb(BORDER))
                        .flex().flex_col().flex_shrink_0().gap_3().min_w_0()
                        .child(row().justify_between()
                            .child(div().font_weight(FontWeight::SEMIBOLD).child(rule.name_label().to_owned()))
                            .child(row().child(ai_badge(category_label(rule.category), MUTED))
                                .child(ai_badge(retention, if rule.older_than_days.is_some() { MUTED } else { WARNING }))))
                        .child(div().text_color(rgb(MUTED)).line_height(relative(1.5)).child(rule.description_label().to_owned()))
                        .child(div().flex().flex_col().gap_2().text_xs().min_w_0()
                            .child(div().text_color(rgb(MUTED)).child(t!(Tr::CpAiDraftScope)))
                            .child(div().min_w_0().child(path_list(&rule.roots)))
                            .child(div().text_color(rgb(MUTED)).child(t!(Tr::CpAiDraftPattern)))
                            .child(div().min_w_0().child(rule.pattern.clone())))
                        .child(div().text_xs().text_color(rgb(WARNING)).line_height(relative(1.5)).child(t!(Tr::CpAiDraftSafety)))
                        .child(row().pt_2()
                            .child(button(("draft-adopt", i), t!(Tr::CpAdoptDisabled))
                                .text_color(rgb(ACCENT)).when(!can_adopt, |d| d.opacity(0.45))
                                .when(can_adopt, |d| d.on_click(cx.listener(move |this, _, window, cx| {
                                    window.focus(&this.focus_handle, cx);
                                    this.adopt_panel_draft(adopt.clone(), false, cx);
                                }))))
                            .child(button(("draft-enable", i), t!(Tr::CpAdoptEnable))
                                .when(!can_adopt, |d| d.opacity(0.45))
                                .when(can_adopt, |d| d.on_click(cx.listener(move |this, _, window, cx| {
                                    window.focus(&this.focus_handle, cx);
                                    this.adopt_panel_draft(enable.clone(), true, cx);
                                }))))
                            .child(button(("draft-edit", i), t!(Tr::CpEditAsUserRule))
                                .when(!can_adopt, |d| d.opacity(0.45))
                                .when(can_adopt, |d| d.on_click(cx.listener(move |this, _, window, cx| {
                                    this.edit_panel_rule(edit.clone(), Some(edit_id.clone()), window, cx);
                                }))))
                            .child(button(("draft-reject", i), t!(Tr::CpReject)).text_color(rgb(MUTED))
                                .on_click(cx.listener(move |this, _, window, cx| {
                                    window.focus(&this.focus_handle, cx);
                                    if let Some((_, response)) = &mut this.cleanup_panel.response {
                                        response.proposals.retain(|r| r.id != reject);
                                    }
                                    cx.notify();
                                })))),
                );
            }
        }
        if p.chat.selected.is_some() || !p.chat.archive.sessions.is_empty() {
            view = view.child(self.render_chat_workspace(can_request, window.viewport_size().width < px(820.), cx));
        } else {
            view = view.child(self.render_chat_controls(can_request, cx)).child(insights);
        }
        if !p.message.is_empty() {
            view = view.child(
                div().px_4().py_3().rounded_lg().bg(rgba(ACCENT_TINT)).border_1().border_color(rgb(BORDER))
                    .text_xs().line_height(relative(1.5)).child(p.message.clone()),
            );
        }
        let expanded = p.ai_config_expanded;
        let mut service = ai_card().p_0().gap_0().child(
            div().id("ai-config-toggle").p_4().flex().flex_wrap().items_center().justify_between().gap_3()
                .cursor_pointer().rounded_xl().hover(|s| s.bg(rgb(CARD)))
                .child(row().child(div().text_color(rgb(MUTED)).child(if expanded { "⌄" } else { "›" }))
                    .child(div().font_weight(FontWeight::MEDIUM).child(t!(Tr::CpAiService)))
                    .child(ai_badge(if saved { t!(Tr::CpAiSaved) } else { t!(Tr::CpAiUnsaved) }, if saved { MUTED } else { WARNING })))
                .child(div().text_xs().text_color(rgb(MUTED)).child(settings.agent.protocol.label()))
                .on_click(cx.listener(|this, _, window, cx| {
                    window.focus(&this.focus_handle, cx);
                    this.cleanup_panel.ai_config_expanded = !this.cleanup_panel.ai_config_expanded;
                    cx.notify();
                })),
        );
        if expanded {
            service = service.child(self.render_cleanup_ai_config(saved, can_configure, cx));
        }
        if settings.agent.has_privacy_consent() {
            service = service.child(
                row().px_4().pb_3()
                    .child(div().text_xs().text_color(rgb(MUTED)).child(t!(Tr::CpAiConsentRemembered)))
                    .child(button("ai-reset-consent", t!(Tr::CpAiForgetConsent)).text_xs()
                        .when(!can_configure, |d| d.opacity(0.45))
                        .when(can_configure, |d| d.on_click(cx.listener(|this, _, _, cx| {
                            this.revoke_ai_consent(false, cx);
                        })))),
            );
        }
        view.child(service).child(
            div().text_xs().text_color(rgb(MUTED)).line_height(relative(1.5)).child(t!(Tr::CpAiIntro)),
        )
    }

    fn render_ai_sharing_options(&self, can_configure: bool, cx: &mut Context<Self>) -> gpui::Div {
        let Ok(settings) = &self.cleanup_panel.settings else { return div() };
        row()
            .child(ai_option("ai-paths", if settings.agent.share_paths { t!(Tr::CpAiPathsShared) } else { t!(Tr::CpAiPathsHidden) }, settings.agent.share_paths, can_configure, WARNING)
                .debug_selector(|| "ai-paths".into())
                .tooltip(tooltip(t!(Tr::CpFullPathsExplain)))
                .when(can_configure, |d| d.on_click(cx.listener(|this, _, window, cx| {
                    let Ok(mut next) = this.cleanup_panel.settings.clone() else { return };
                    next.agent.share_paths = !next.agent.share_paths;
                    if next.agent.share_paths {
                        if let Err(error) = next.agent.remember_privacy_consent() {
                            this.panel_message(error, cx);
                            return;
                        }
                        this.confirm_panel_settings(next, t!(Tr::CpAllowFullPaths), t!(Tr::CpFullPathsExplain), window, cx);
                    } else {
                        this.save_panel_settings(next, cx);
                    }
                }))))
            .child(ai_option("ai-thinking", t!(Tr::CpAiThinking), settings.agent.thinking, can_configure, ACCENT)
                .debug_selector(|| "ai-thinking".into())
                .tooltip(tooltip(t!(Tr::CpAiThinkingHint)))
                .when(can_configure, |d| d.on_click(cx.listener(|this, _, _, cx| {
                    let Ok(mut next) = this.cleanup_panel.settings.clone() else { return };
                    next.agent.thinking = !next.agent.thinking;
                    this.save_panel_settings(next, cx);
                }))))
    }

    fn render_cleanup_ai_config(&self, saved: bool, can_configure: bool, cx: &mut Context<Self>) -> gpui::Div {
        let p = &self.cleanup_panel;
        let Ok(settings) = &p.settings else { return div() };
        let mut protocols = row().p_1().rounded_lg().bg(rgb(BG));
        for (i, protocol) in [AgentProtocol::ChatCompletions, AgentProtocol::Responses, AgentProtocol::Anthropic].into_iter().enumerate() {
            protocols = protocols.child(
                button(("ai-protocol", i), protocol.label()).text_xs().border_color(rgb(BG)).bg(rgb(BG))
                    .when(settings.agent.protocol == protocol, |d| d.bg(rgb(CARD)).border_color(rgb(BORDER)).text_color(rgb(ACCENT)))
                    .when(!can_configure, |d| d.opacity(0.45))
                    .when(can_configure, |d| d.on_click(cx.listener(move |this, _, _, cx| {
                        let Ok(mut next) = this.cleanup_panel.settings.clone() else { return };
                        next.agent.protocol = protocol;
                        next.agent.base_url = text(&this.cleanup_panel.url, cx);
                        next.agent.model = text(&this.cleanup_panel.model, cx);
                        this.save_panel_settings(next, cx);
                    }))),
            );
        }
        let credential_target = match self.panel_credential_target(cx) {
            Ok(scope) => tf!(Tr::CpCurrentKeyTarget, "scope" => scope),
            Err(e) => tf!(Tr::CpKeyTargetUnavailable, "e" => e),
        };
        let can_use_key = can_configure && self.panel_credential_target(cx).is_ok();
        let can_save_key = can_use_key && !text(&p.key, cx).is_empty();
        div().p_5().pt_4().border_t_1().border_color(rgb(BORDER)).flex().flex_col().gap_4().min_w_0()
            .child(div().text_xs().text_color(rgb(MUTED)).child(t!(Tr::CpAiServiceHint)))
            .child(div().flex().flex_col().gap_2()
                .child(div().text_xs().text_color(rgb(MUTED)).child(t!(Tr::CpAiProtocol))).child(protocols))
            .child(row().items_start().gap_4()
                .child(field(t!(Tr::CpFieldEndpoint), &p.url).flex_1().flex_basis(px(360.)))
                .child(field(t!(Tr::CpFieldModelShort), &p.model).flex_1().flex_basis(px(220.))))
            .child(row()
                .child(primary_button("ai-save", t!(Tr::CpSaveAiConfig), ACCENT)
                    .when(!can_configure, |d| d.opacity(0.45))
                    .when(can_configure, |d| d.on_click(cx.listener(|this, _, window, cx| {
                        window.focus(&this.focus_handle, cx);
                        this.save_panel_ai(cx);
                    }))))
                .child(button("ai-test", if p.test_busy { t!(Tr::CpTesting) } else { t!(Tr::CpTestConnection) })
                    .when(!can_configure || !saved, |d| d.opacity(0.45))
                    .when(can_configure && saved, |d| d.on_click(cx.listener(|this, _, window, cx| {
                        this.test_panel_connection(window, cx);
                    })))))
            .child(div().pt_4().border_t_1().border_color(rgb(BORDER)).flex().flex_col().gap_3().min_w_0()
                .child(field(t!(Tr::CpFieldApiKey), &p.key))
                .child(div().text_xs().text_color(rgb(MUTED)).child(t!(Tr::CpAiKeyHint)))
                .child(row()
                    .child(button("ai-key-save", if p.key_busy { t!(Tr::CpKeychainBusy) } else { t!(Tr::CpSaveKey) })
                        .when(!can_save_key, |d| d.opacity(0.45))
                        .when(can_save_key, |d| d.on_click(cx.listener(|this, _, window, cx| {
                            window.focus(&this.focus_handle, cx);
                            this.store_panel_key(false, cx);
                        }))))
                    .child(button("ai-key-delete", t!(Tr::CpDeleteKey)).text_color(rgb(DANGER))
                        .when(!can_use_key, |d| d.opacity(0.45))
                        .when(can_use_key, |d| d.on_click(cx.listener(|this, _, window, cx| {
                            this.confirm_panel_key_delete(window, cx);
                        })))))
                .child(div().text_xs().text_color(rgb(MUTED)).line_height(relative(1.5)).child(credential_target)))
            .child(div().pt_4().border_t_1().border_color(rgb(BORDER)).flex().flex_wrap().items_center().justify_between().gap_3()
                .child(ai_badge(if settings.agent.enabled { t!(Tr::CpAiStatusReady) } else { t!(Tr::CpAiStatusOff) }, if settings.agent.enabled { SAFE } else { MUTED }))
                .child(button("ai-enable", if settings.agent.enabled { t!(Tr::CpAiEnabled) } else { t!(Tr::CpAiConsent) })
                    .text_color(rgb(ACCENT))
                    .when(!can_configure || (!settings.agent.enabled && !saved), |d| d.opacity(0.45))
                    .when(can_configure && (settings.agent.enabled || saved), |d| d.on_click(cx.listener(|this, _, window, cx| {
                        let Ok(mut next) = this.cleanup_panel.settings.clone() else { return };
                        next.agent.enabled = !next.agent.enabled;
                        if next.agent.enabled {
                            let detail = tf!(Tr::CpAiEnabledExplain, "target" => next.agent.base_url, "model" => next.agent.model,
                                "protocol" => next.agent.protocol.label(),
                                "paths" => if next.agent.share_paths { t!(Tr::CpPathsFull) } else { t!(Tr::CpPathsOpaque) });
                            if let Err(error) = next.agent.remember_privacy_consent() {
                                this.panel_message(error, cx);
                                return;
                            }
                            this.confirm_panel_settings(next, t!(Tr::CpConsentSendMetadata), &detail, window, cx);
                        } else {
                            this.revoke_ai_consent(true, cx);
                        }
                    })))))
    }
    fn render_monitor_settings(&self, cx: &mut Context<Self>) -> gpui::Div {
        use crate::menubar::{DisplayUnit, ThresholdUnit};
        let p = &self.cleanup_panel;
        let draft = &p.monitor_draft;
        let writable = p.writable();
        let mut disks = self.menu_bar.disks.clone();
        if !disks.iter().any(|d| d.path == PathBuf::from("/")) {
            disks.insert(0, crate::menubar::MountedDisk { name: t!(Tr::MbStartupDisk).into(), path: PathBuf::from("/") });
        }
        if !disks.iter().any(|d| d.path == draft.mount) {
            disks.push(crate::menubar::MountedDisk { name: format!("{} · {}", draft.mount.display(), t!(Tr::MbUnavailable)), path: draft.mount.clone() });
        }
        let mut disk_options = row();
        for (i, disk) in disks.into_iter().enumerate() {
            disk_options = disk_options.child(button(("monitor-disk", i), disk.name)
                .debug_selector(move || format!("monitor-disk-{i}"))
                .when(draft.mount == disk.path, |d| d.bg(rgb(ACCENT)))
                .when(writable, |d| d.on_click(cx.listener(move |this, _, _, cx| {
                    this.cleanup_panel.monitor_draft.mount = disk.path.clone(); cx.notify();
                }))));
        }
        let mut display = row();
        for (i, unit) in [DisplayUnit::Gigabytes, DisplayUnit::Terabytes, DisplayUnit::Percent, DisplayUnit::Auto].into_iter().enumerate() {
            display = display.child(button(("monitor-unit", i), unit.label())
                .debug_selector(move || format!("monitor-unit-{i}"))
                .when(draft.display_unit == unit, |d| d.bg(rgb(ACCENT)))
                .when(writable, |d| d.on_click(cx.listener(move |this, _, _, cx| {
                    this.cleanup_panel.monitor_draft.display_unit = unit; cx.notify();
                }))));
        }
        let mut threshold_units = row();
        for (i, unit) in [ThresholdUnit::Percent, ThresholdUnit::Gigabytes].into_iter().enumerate() {
            threshold_units = threshold_units.child(button(("monitor-threshold-unit", i), unit.label())
                .when(draft.threshold_unit == unit, |d| d.bg(rgb(ACCENT)))
                .when(writable, |d| d.on_click(cx.listener(move |this, _, _, cx| {
                    this.cleanup_panel.monitor_draft.threshold_unit = unit; cx.notify();
                }))));
        }
        panel_card().debug_selector(|| "monitor-settings".into()).flex_shrink_0().border_1().border_color(rgb(BORDER))
            .child(div().font_weight(FontWeight::MEDIUM).child(t!(Tr::MbTitle)))
            .child(ai_option("monitor-enabled", t!(Tr::MbEnabled), draft.enabled, writable, ACCENT)
                .when(writable, |d| d.on_click(cx.listener(|this, _, _, cx| {
                    this.cleanup_panel.monitor_draft.enabled = !this.cleanup_panel.monitor_draft.enabled; cx.notify();
                }))))
            .child(div().text_xs().text_color(rgb(MUTED)).child(t!(Tr::MbHint)))
            .child(div().child(t!(Tr::MbDisk)).child(disk_options))
            .child(div().child(t!(Tr::MbDisplay)).child(display))
            .child(row().items_end()
                .child(field(t!(Tr::MbThreshold), &p.monitor_threshold).flex_1())
                .child(threshold_units))
            .child(field(t!(Tr::MbRefreshSeconds), &p.monitor_interval))
            .child(row()
                .child(primary_button("monitor-save", t!(Tr::MbSave), ACCENT)
                    .debug_selector(|| "monitor-save".into())
                    .when(!writable, |d| d.opacity(0.45))
                    .when(writable, |d| d.on_click(cx.listener(|this, _, window, cx| {
                        window.focus(&this.focus_handle, cx); this.save_monitor_settings(cx);
                    }))))
                .child(button("monitor-refresh-disks", t!(Tr::MbRefresh)).on_click(cx.listener(|this, _, _, cx| {
                    this.menu_bar.refresh_now(); this.refresh_monitor_disks(cx);
                }))))
    }

    fn render_cleanup_settings(&self, cx: &mut Context<Self>) -> gpui::Div {
        let p = &self.cleanup_panel;
        let Ok(settings) = &p.settings else {
            return panel_card();
        };
        let mut languages = row();
        for (i, lang) in crate::i18n::Lang::all().into_iter().enumerate() {
            languages = languages.child(
                button(("panel-lang", i), lang.label())
                    .when(crate::i18n::lang() == lang, |d| d.bg(rgb(ACCENT)))
                    .on_click(cx.listener(move |this, _, _, cx| this.set_panel_language(lang, cx))),
            );
        }
        let mut view = panel_card()
            .child(row().child(t!(Tr::CpLanguage)).child(languages))
            .child(div().text_color(rgb(MUTED)).child(t!(Tr::CpLanguageTip)))
            .child(self.render_monitor_settings(cx))
            .child(t!(Tr::CpAutoIntro))
            .child(field(t!(Tr::CpAutoInterval), &p.interval))
            .child(row().child(button("save-interval", t!(Tr::CpSaveInterval)).on_click(cx.listener(|this, _, _, cx| {
                let Ok(mut next) = this.cleanup_panel.settings.clone() else { return };
                match text(&this.cleanup_panel.interval, cx).parse() { Ok(minutes) => { next.automation_interval_minutes = minutes; this.save_panel_settings(next, cx); }, Err(_) => this.panel_message(t!(Tr::CpBadInterval), cx) }
            }))).child(button("global-auto", if settings.automation_enabled { t!(Tr::CpGlobalAutoOn) } else { t!(Tr::CpGlobalAutoOff) }).on_click(cx.listener(|this, _, window, cx| {
                let Ok(mut next) = this.cleanup_panel.settings.clone() else { return }; next.automation_enabled = !next.automation_enabled;
                if next.automation_enabled { this.confirm_panel_settings(next, t!(Tr::CpConfirmGlobalAuto), t!(Tr::CpGlobalAutoExplain), window, cx); }
                else { this.disable_panel_automation(cx); }
            }))).child(button("default-action", tf!(Tr::CpDefaultAction, "action" => action_label(settings.default_action))).on_click(cx.listener(|this, _, _, cx| {
                let Ok(mut next) = this.cleanup_panel.settings.clone() else { return }; next.default_action = if next.default_action == CleanupAction::Trash { CleanupAction::Permanent } else { CleanupAction::Trash }; this.save_panel_settings(next, cx);
            }))))
            .child(field(t!(Tr::CpWhitelistLabel), &p.whitelist))
            .child(button("add-whitelist", t!(Tr::CpAddWhitelist)).on_click(cx.listener(|this, _, _, cx| {
                let Ok(mut next) = this.cleanup_panel.settings.clone() else { return }; let entries = paths(&text(&this.cleanup_panel.whitelist, cx));
                if entries.is_empty() { this.panel_message(t!(Tr::CpNeedConcretePath), cx); return; }
                for entry in entries { if !next.whitelist.contains(&entry) { next.whitelist.push(entry); } }
                if this.save_panel_settings(next, cx) { this.cleanup_panel.whitelist.update(cx, |input, cx| input.set_text("", cx)); }
            })));
        for (i, path) in settings.whitelist.iter().enumerate() {
            let path = path.clone();
            view = view.child(row().child(path.display().to_string()).child(
                button(("remove-whitelist", i), t!(Tr::CpRemoveProtection)).on_click(cx.listener(
                    move |this, _, window, cx| {
                        let Ok(mut next) = this.cleanup_panel.settings.clone() else {
                            return;
                        };
                        next.whitelist.retain(|p| p != &path);
                        this.confirm_panel_settings(
                            next,
                            t!(Tr::CpConfirmRemoveProtection),
                            &path.display().to_string(),
                            window,
                            cx,
                        );
                    },
                )),
            ));
        }
        view = view.child(row().child(button("reload-settings", t!(Tr::CpReloadConfig)).on_click(cx.listener(|this, _, window, cx| { window.focus(&this.focus_handle, cx); this.reload_panel_settings(cx); })))
            .child(button("load-history", if p.history_busy { t!(Tr::CpLoadingHistory) } else { t!(Tr::CpLoadHistory) }).on_click(cx.listener(|this, _, _, cx| this.load_panel_history(cx)))))
            .child(t!(Tr::CpHistoryIntro));
        for (i, entry) in p.history.iter().enumerate() {
            let original = entry.path.display().to_string();
            let copy = original.clone();
            let mut record = panel_card()
                .child(tf!(
                    Tr::CpHistoryRow,
                    "status" => entry.status,
                    "action" => action_label(entry.action),
                    "time" => entry.time,
                    "mode" => if entry.automatic { t!(Tr::CpHistoryAuto) } else { t!(Tr::CpHistoryManual) }
                ))
                .child(original)
                .child(entry.detail.clone().unwrap_or_default())
                .child(
                    button(("copy-original", i), t!(Tr::CpCopyOriginalPath)).on_click(cx.listener(
                        move |_, _, _, cx| {
                            cx.write_to_clipboard(ClipboardItem::new_string(copy.clone()))
                        },
                    )),
                );
            if let Some(recovery) = &entry.recovery_path {
                let copy = recovery.display().to_string();
                record = record.child(tf!(Tr::CpRestoreReference, "copy" => copy)).child(
                    button(("copy-recovery", i), t!(Tr::CpCopyStashPath)).on_click(cx.listener(
                        move |_, _, _, cx| {
                            cx.write_to_clipboard(ClipboardItem::new_string(copy.clone()))
                        },
                    )),
                );
            }
            view = view.child(record);
        }
        view
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ai_snapshot_survives_live_generation_but_not_scan_or_config_changes() {
        let captured = Token { scan: 4, revision: 2, generation: 1 };
        assert!(ai_snapshot_current(captured, Token { generation: 90, ..captured }));
        assert!(!ai_snapshot_current(captured, Token { scan: 5, ..captured }));
        assert!(!ai_snapshot_current(captured, Token { revision: 3, ..captured }));
        assert!(captured != Token { generation: 90, ..captured }, "cleanup drafts still require the full token");
    }

    #[cfg(feature = "snapshot")]
    #[gpui::test]
    fn ai_conversation_remains_visible_during_live_refresh(cx: &mut gpui::TestAppContext) {
        // No configuration reads/writes, timers, Keychain or network requests.
        let window = cx.open_window(gpui::size(px(1240.), px(800.)), |window, cx| {
            let focus_handle = cx.focus_handle();
            window.focus(&focus_handle, cx);
            let mut panel = PanelState::with_settings(Ok(Settings::default()), cx);
            panel.open = true;
            panel.tab = 2;
            panel.ai_busy = true;
            panel.ai_sequence = 7;
            panel.ai_turn = Some(AiTurn {
                request: "Explain example-cache".into(), phase: AiPhase::Waiting,
                detail: "Waiting for response".into(), answer: None,
            });
            Petal {
                screen: Screen::Start(vec![]), cleanup_panel: panel, focus_handle,
                menu_bar: crate::menubar::Monitor::new(),
                error: None, notice: None, notice_warning: false, notice_version: 0,
                access: Access::Dismissed, _access_watch: None,
                color_by: ColorBy::Folder, chart: ChartType::Sunburst,
            }
        });
        let view = window.root(cx).unwrap();
        let mut visual = gpui::VisualTestContext::from_window(window.into(), cx);
        visual.update(|window, cx| window.draw(cx).clear(cx));
        let initial = visual.debug_bounds("ai-user-message").expect("request is visible immediately");
        assert!(initial.top() >= px(0.));
        let status = visual.debug_bounds("ai-request-status").expect("waiting state is visible");
        for _ in 0..5 {
            view.update(&mut visual, |this, cx| {
                this.cleanup_panel.preview_busy = true;
                this.invalidate_scan_cleanup_jobs();
                assert!(this.cleanup_panel.ai_busy);
                assert_eq!(this.cleanup_panel.ai_sequence, 7);
                assert!(!this.cleanup_panel.preview_busy);
                assert!(this.cleanup_panel.ai_turn.as_ref().unwrap().phase == AiPhase::Waiting);
                cx.notify();
            });
            visual.update(|window, cx| window.draw(cx).clear(cx));
            assert_eq!(visual.debug_bounds("ai-user-message").unwrap(), initial);
            assert_eq!(visual.debug_bounds("ai-request-status").unwrap(), status);
        }
        view.update(&mut visual, |this, cx| {
            let turn = this.cleanup_panel.ai_turn.as_mut().unwrap();
            turn.phase = AiPhase::Complete;
            turn.answer = Some("A read-only explanation.\n\n".repeat(30));
            this.cleanup_panel.ai_busy = false;
            this.invalidate_scan_cleanup_jobs();
            assert!(this.cleanup_panel.ai_turn.as_ref().unwrap().answer.is_some());
            cx.notify();
        });
        visual.update(|window, cx| window.draw(cx).clear(cx));
        assert!(visual.debug_bounds("ai-assistant-message").is_some());
        view.read_with(&visual, |this, _| {
            assert!(this.cleanup_panel.ai_scroll.max_offset().y > px(0.), "long replies remain scrollable");
        });
        view.update(&mut visual, |this, cx| {
            this.cleanup_panel.ai_busy = true;
            this.cleanup_panel.ai_turn.as_mut().unwrap().phase = AiPhase::Waiting;
            this.invalidate_cleanup_jobs();
            assert!(!this.cleanup_panel.ai_busy);
            assert_eq!(this.cleanup_panel.ai_sequence, 8);
            assert!(this.cleanup_panel.ai_turn.as_ref().unwrap().phase == AiPhase::Cancelled);
            cx.notify();
        });
        visual.update(|window, cx| window.draw(cx).clear(cx));
        assert!(visual.debug_bounds("ai-request-status").is_some(), "cancellation is explicit, not an empty card");
        visual.update(|window, cx| {
            view.update(cx, |this, cx| this.request_panel_ai(AgentRequest::Analyze, None, window, cx));
        });
        view.read_with(&visual, |this, _| {
            assert!(this.cleanup_panel.ai_turn.as_ref().unwrap().phase == AiPhase::Failed);
            assert!(!this.cleanup_panel.ai_turn.as_ref().unwrap().detail.is_empty());
        });
    }

    fn indexed_rule(id: &str, name: &str, priority: i32) -> Rule {
        Rule {
            id: id.into(), name: name.into(), description: "Cache files for local builds".into(),
            category: CleanupCategory::Cache, roots: vec![PathBuf::from("~/Library/Caches/Example")],
            pattern: "**/*.tmp".into(), exclude: vec!["**/keep/**".into()], min_size: 0,
            older_than_days: Some(30), priority, enabled: true, auto_clean: false,
            action: CleanupAction::Trash, source: RuleSource::User,
        }
    }

    #[test]
    fn rule_index_combines_search_source_category_and_status() {
        let mut rules = vec![indexed_rule("a", "Build CACHE", 5), indexed_rule("b", "Build cache", 8)];
        rules[0].auto_clean = true;
        rules[1].source = RuleSource::BuiltIn;
        let mut index = RuleIndex::default();
        let query = RuleQuery {
            search: "cache example *.tmp keep".into(), status: RuleStatusFilter::Automatic,
            source: Some(RuleSource::User), category: Some(CleanupCategory::Cache),
            ..Default::default()
        };
        assert_eq!(&*index.visible(&rules, 0, query.clone()), &[0]);
        assert!(index.visible(&rules, 0, RuleQuery { category: Some(CleanupCategory::Logs), ..query.clone() }).is_empty());
        assert!(index.visible(&rules, 0, RuleQuery { source: Some(RuleSource::Ai), ..query }).is_empty());
        rules[0].enabled = false;
        assert_eq!(&*index.visible(&rules, 1, RuleQuery { status: RuleStatusFilter::Disabled, ..Default::default() }), &[0]);
        assert!(index.visible(&rules, 1, RuleQuery { status: RuleStatusFilter::Automatic, ..Default::default() }).is_empty());
        assert!(index.visible(&rules, 1, RuleQuery { search: "does-not-exist".into(), ..Default::default() }).is_empty());
    }

    #[test]
    fn rule_index_sorts_stably_and_reuses_results_between_frames() {
        let rules = vec![indexed_rule("z", "Same", 10), indexed_rule("a", "Same", 10), indexed_rule("b", "Alpha", -2)];
        let mut index = RuleIndex::default();
        let first = index.visible(&rules, 0, RuleQuery::default());
        assert_eq!(&*first, &[1, 0, 2]);
        assert!(Rc::ptr_eq(&first, &index.visible(&rules, 0, RuleQuery::default())));
        assert_eq!(&*index.visible(&rules, 0, RuleQuery { sort: RuleSort::Name, ..Default::default() }), &[2, 1, 0]);
        let mut changed = rules;
        changed[1].enabled = false;
        assert_eq!(&*index.visible(&changed, 1, RuleQuery { sort: RuleSort::Status, ..Default::default() }), &[0, 2, 1]);
        assert_eq!(index.enabled, 2);
    }

    #[test]
    fn rule_index_retains_thousands_and_refreshes_after_reload_or_deletion() {
        let mut rules: Vec<_> = (0..5000).map(|i| indexed_rule(&format!("rule-{i}"), &format!("Rule {i}"), i)).collect();
        let mut index = RuleIndex::default();
        let all = index.visible(&rules, 0, RuleQuery::default());
        assert_eq!(all.len(), 5000);
        assert_eq!(all[0], 4999);
        assert_eq!(all[4999], 0);
        assert_eq!(index.rule(&rules, "rule-4999").unwrap().priority, 4999);
        assert!(index.rule(&rules, "missing").is_none());
        let query = RuleQuery { search: "rule-4999".into(), ..Default::default() };
        assert_eq!(&*index.visible(&rules, 0, query.clone()), &[4999]);
        rules.pop();
        assert!(index.visible(&rules, 1, query).is_empty());
        assert!(index.rule(&rules, "rule-4999").is_none());
        rules.swap(0, 4998);
        index.visible(&rules, 2, RuleQuery::default());
        assert_eq!(index.rule(&rules, "rule-0").unwrap().priority, 0);
        assert_eq!(index.rule(&rules, "rule-4998").unwrap().priority, 4998);
        let updated = index.visible(&rules, 2, RuleQuery::default());
        assert_eq!(updated.len(), 4999);
        assert_eq!(rules[updated[0]].id, "rule-4998");
        assert!(index.visible(&[], 3, RuleQuery::default()).is_empty());
        assert!(index.by_id.is_empty());
        assert_eq!(index.enabled, 0);
    }

    #[cfg(feature = "snapshot")]
    #[gpui::test]
    fn monitor_settings_layout_and_drafts_do_not_change_saved_configuration(cx: &mut gpui::TestAppContext) {
        // No real AppKit status item, filesystem writes, scans or timers.
        let window = cx.open_window(gpui::size(px(1240.), px(800.)), |window, cx| {
            let focus_handle = cx.focus_handle();
            window.focus(&focus_handle, cx);
            let mut panel = PanelState::with_settings(Ok(Settings::default()), cx);
            panel.open = true;
            panel.tab = 3;
            panel.ai_busy = true;
            panel.revision = 17;
            panel.generation = 23;
            let mut menu_bar = crate::menubar::Monitor::new();
            menu_bar.disks = vec![crate::menubar::MountedDisk { name: "Test external disk".into(), path: PathBuf::from("/Volumes/Test") }];
            Petal {
                screen: Screen::Start(vec![]), cleanup_panel: panel, focus_handle, menu_bar,
                error: None, notice: None, notice_warning: false, notice_version: 0,
                access: Access::Dismissed, _access_watch: None,
                color_by: ColorBy::Folder, chart: ChartType::Sunburst,
            }
        });
        let view = window.root(cx).unwrap();
        let mut visual = gpui::VisualTestContext::from_window(window.into(), cx);
        let draw = |visual: &mut gpui::VisualTestContext| visual.update(|window, cx| window.draw(cx).clear(cx));
        draw(&mut visual);
        let percent = visual.debug_bounds("monitor-unit-2").expect("percent option is visible");
        visual.simulate_click(percent.center(), gpui::Modifiers::default());
        draw(&mut visual);
        let external = visual.debug_bounds("monitor-disk-1").expect("external disk is selectable");
        visual.simulate_click(external.center(), gpui::Modifiers::default());
        draw(&mut visual);
        view.read_with(&visual, |this, _| {
            assert_eq!(this.cleanup_panel.monitor_draft.display_unit, crate::menubar::DisplayUnit::Percent);
            assert_eq!(this.cleanup_panel.monitor_draft.mount, PathBuf::from("/Volumes/Test"));
            assert_eq!(this.cleanup_panel.settings.as_ref().unwrap().menu_bar, crate::menubar::MenuBarConfig::default());
        });
        view.update(&mut visual, |this, cx| {
            this.cleanup_panel.monitor_threshold.update(cx, |input, cx| input.set_text("NaN", cx));
            this.save_monitor_settings(cx); // Validation fails before any state file is touched.
            assert_eq!(this.cleanup_panel.revision, 17);
            assert_eq!(this.cleanup_panel.generation, 23);
            assert!(this.cleanup_panel.ai_busy);
            assert!(!this.cleanup_panel.message.is_empty());
        });
        visual.simulate_resize(gpui::size(px(860.), px(560.)));
        draw(&mut visual);
        let card = visual.debug_bounds("monitor-settings").unwrap();
        let save = visual.debug_bounds("monitor-save").expect("save button remains reachable in compact window");
        assert!(save.right() <= card.right());
        assert!(save.bottom() <= card.bottom());
        assert!(card.right() <= px(860.));
    }

    #[cfg(feature = "snapshot")]
    #[gpui::test]
    fn rule_workspace_virtualizes_and_keeps_detail_usable(cx: &mut gpui::TestAppContext) {
        // A real GPUI layout, with no scan, timers, network or configuration writes.
        let window = cx.open_window(gpui::size(px(1240.), px(800.)), |window, cx| {
            let focus_handle = cx.focus_handle();
            window.focus(&focus_handle, cx);
            let mut cleanup_panel = PanelState::with_settings(Ok(Settings::default()), cx);
            cleanup_panel.open = true;
            cleanup_panel.tab = 1;
            cleanup_panel.settings = Ok(Settings {
                rules: (0..5000).map(|i| indexed_rule(&format!("rule-{i}"), &format!("Cache rule {i}"), i)).collect(),
                ..Settings::default()
            });
            Petal {
                screen: Screen::Start(vec![]), cleanup_panel, focus_handle,
                menu_bar: crate::menubar::Monitor::new(),
                error: None, notice: None, notice_warning: false, notice_version: 0,
                access: Access::Dismissed, _access_watch: None,
                color_by: ColorBy::Folder, chart: ChartType::Sunburst,
            }
        });
        let view = window.root(cx).unwrap();
        let mut visual = gpui::VisualTestContext::from_window(window.into(), cx);
        let draw = |visual: &mut gpui::VisualTestContext| {
            visual.update(|window, cx| window.draw(cx).clear(cx));
        };
        draw(&mut visual);
        let first = visual.debug_bounds("rule-row-rule-4999").expect("highest priority row is visible");
        assert_eq!(first.size.height, px(RULE_ROW_HEIGHT));
        assert!(visual.debug_bounds("rule-row-rule-0").is_none(), "off-screen rules must not be rendered");
        visual.simulate_click(first.center(), gpui::Modifiers::default());
        draw(&mut visual);
        view.read_with(&visual, |this, _| assert_eq!(this.cleanup_panel.rule_selected.as_deref(), Some("rule-4999")));
        let detail = visual.debug_bounds("rule-detail-panel").expect("row click opens details");
        let table = visual.debug_bounds("rules-table").unwrap();
        assert!(table.right() <= detail.left());
        assert_eq!(detail.size.width, px(360.));
        visual.simulate_resize(gpui::size(px(860.), px(560.)));
        draw(&mut visual);
        let detail = visual.debug_bounds("rule-detail-panel").unwrap();
        assert!(detail.right() <= px(860.));
        assert!(visual.debug_bounds("rule-name-cell").unwrap().size.width > px(200.), "compact columns must leave room for names");
        view.update(&mut visual, |this, cx| {
            this.cleanup_panel.rule_scroll.scroll_to_item(4999, ScrollStrategy::Top);
            cx.notify();
        });
        draw(&mut visual);
        let last = visual.debug_bounds("rule-row-rule-0").expect("last of 5000 rules remains reachable");
        visual.simulate_click(last.center(), gpui::Modifiers::default());
        draw(&mut visual);
        view.read_with(&visual, |this, _| assert_eq!(this.cleanup_panel.rule_selected.as_deref(), Some("rule-0")));
        view.update(&mut visual, |this, cx| {
            this.cleanup_panel.rule_search.update(cx, |input, cx| input.set_text("rule-1234", cx));
        });
        draw(&mut visual);
        let filtered = visual.debug_bounds("rule-row-rule-1234").expect("search resets scroll and reveals matching rule");
        visual.simulate_click(filtered.center(), gpui::Modifiers::default());
        draw(&mut visual);
        view.read_with(&visual, |this, _| assert_eq!(this.cleanup_panel.rule_selected.as_deref(), Some("rule-1234")));
        visual.update(|window, cx| {
            view.update(cx, |this, cx| {
                let rule = this.cleanup_panel.settings.as_ref().unwrap().rules[1234].clone();
                this.edit_panel_rule(rule, None, window, cx);
            });
        });
        draw(&mut visual);
        let actions = visual.debug_bounds("rule-editor-actions").expect("editor actions remain visible");
        let detail = visual.debug_bounds("rule-detail-panel").unwrap();
        assert!(actions.bottom() <= detail.bottom());
        assert!(actions.top() >= detail.top());
        visual.update(|window, cx| {
            view.read_with(cx, |this, cx| {
                assert_eq!(this.cleanup_panel.rule_editor_scroll.offset().y, px(0.));
                assert!(this.cleanup_panel.editor.as_ref().unwrap().name.read(cx).focus_handle().is_focused(window));
            });
        });
    }

    #[test]
    fn editor_rejects_any_changed_settings_revision() {
        assert!(!editor_conflict(9, 9));
        assert!(editor_conflict(9, 10));
        assert!(editor_conflict(u64::MAX, 0));
    }
    #[test]
    fn cancellation_is_shared_and_new_batches_are_independent() {
        let old_batch = Arc::new(AtomicBool::new(false));
        let worker = old_batch.clone();
        old_batch.store(true, Ordering::Release);
        assert!(worker.load(Ordering::Acquire));
        let new_batch = Arc::new(AtomicBool::new(false));
        assert!(!new_batch.load(Ordering::Acquire));
        assert!(worker.load(Ordering::Acquire));
    }
    #[test]
    fn credential_targets_differ_by_protocol_without_keychain_io() {
        let config = agent::AgentConfig::default();
        let first = config.credential_scope().unwrap();
        let other = agent::AgentConfig {
            protocol: AgentProtocol::Anthropic,
            ..config
        };
        assert_ne!(first, other.credential_scope().unwrap());
    }
    #[test]
    fn stale_tokens_include_scan_settings_and_tree_changes() {
        let token = Token {
            scan: 1,
            revision: 2,
            generation: 3,
        };
        assert!(token == token);
        assert!(token != Token { scan: 4, ..token });
        assert!(
            token
                != Token {
                    revision: 4,
                    ..token
                }
        );
        assert!(
            token
                != Token {
                    generation: 4,
                    ..token
                }
        );
    }
    #[test]
    fn path_inputs_preserve_comma_directories() {
        assert_eq!(
            paths(" ~/Library/Caches; /tmp/a,b\n /tmp/c,d ; "),
            vec![
                PathBuf::from("~/Library/Caches"),
                PathBuf::from("/tmp/a,b"),
                PathBuf::from("/tmp/c,d")
            ]
        );
        assert!(paths(" ; \n ").is_empty());
        assert_eq!(paths(","), vec![PathBuf::from(",")]);
    }
    #[test]
    fn exclude_inputs_preserve_brace_globs_and_commas() {
        let entries =
            delimited_entries(" **/*.{log,tmp}; cache,old/**\n**/*.bak ").collect::<Vec<_>>();
        assert_eq!(entries, vec!["**/*.{log,tmp}", "cache,old/**", "**/*.bak"]);
        let matcher = globset::Glob::new(entries[0]).unwrap().compile_matcher();
        assert!(matcher.is_match("cache/a.log"));
        assert!(matcher.is_match("cache/a.tmp"));
        assert!(!matcher.is_match("cache/a.txt"));
    }
    #[test]
    fn cancelled_preview_cannot_complete_a_replacement_job() {
        let old = Arc::new(AtomicBool::new(false));
        let old_worker = old.clone();
        assert!(preview_job_current(&old, &old_worker));
        old.store(true, Ordering::Release);
        assert!(!preview_job_current(&old, &old_worker));
        let next = Arc::new(AtomicBool::new(false));
        assert!(!preview_job_current(&next, &old_worker));
        assert!(preview_job_current(&next, &next.clone()));
    }
    #[test]
    fn permanent_is_never_a_trash_selection() {
        let actions = [
            CleanupAction::Trash,
            CleanupAction::Permanent,
            CleanupAction::Trash,
        ];
        let selected = actions
            .into_iter()
            .filter(|action| is_trash(*action))
            .collect::<Vec<_>>();
        assert_eq!(selected, vec![CleanupAction::Trash, CleanupAction::Trash]);
        assert!(automatic_action(true, CleanupAction::Trash));
        assert!(!automatic_action(false, CleanupAction::Trash));
        assert!(!automatic_action(true, CleanupAction::Permanent));
        assert_eq!((0..1000).take(AUTO_BUDGET).count(), 200);
    }
}
