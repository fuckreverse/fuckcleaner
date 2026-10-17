use super::*;
use crate::agent::{self, AgentProtocol, AgentRequest, AgentResponse};
use crate::cleanup::{self, ExecutionReport, HistoryEntry};
use crate::rules::{self, CleanupAction, CleanupCategory, Plan, Rule, RuleSource};
use crate::settings::Settings;
use crate::text_input::TextInput;
use gpui::Entity;
use std::sync::atomic::AtomicBool;

const PAGE_SIZE: usize = 200;
const AUTO_BUDGET: usize = 200;

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
    response: Option<(Token, AgentResponse)>,
    editor: Option<RuleEditor>,
    url: Entity<TextInput>,
    model: Entity<TextInput>,
    key: Entity<TextInput>,
    whitelist: Entity<TextInput>,
    interval: Entity<TextInput>,
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

impl PanelState {
    pub(super) fn new(cx: &mut Context<Petal>) -> Self {
        let settings = Settings::load();
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
            response: None,
            editor: None,
            url: input(config.base_url, "https://api.openai.com", false, cx),
            model: input(config.model, t!(Tr::CpFieldModel), false, cx),
            key: input("", t!(Tr::CpFieldNewKey), true, cx),
            whitelist: input("", t!(Tr::CpFieldProtectedPaths), false, cx),
            interval: input(minutes.to_string(), t!(Tr::CpFieldInterval), false, cx),
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
    pub(super) fn invalidate_cleanup_jobs(&mut self) {
        let p = &mut self.cleanup_panel;
        p.preview_cancel.store(true, Ordering::Release);
        p.generation = p.generation.wrapping_add(1);
        p.plan = None;
        p.selected.clear();
        p.response = None;
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
        let draft_token = draft.as_ref().and_then(|_| self.cleanup_token());
        if self.cleanup_panel.editor.is_some() {
            self.panel_message(t!(Tr::CpEditorAlreadyOpen), cx);
            return;
        }
        let mut editor = RuleEditor::new(rule, draft, cx);
        editor.open_revision = self.cleanup_panel.revision;
        editor.draft_token = draft_token;
        window.focus(&editor.name.read(cx).focus_handle(), cx);
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
            .is_some_and(|token| !self.cleanup_current(token))
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
        if !self.cleanup_current(*token) {
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
        self.request_panel_ai(request, Some(ix), window, cx);
    }
    fn request_panel_ai(
        &mut self,
        request: AgentRequest,
        selected_node: Option<usize>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.cleanup_panel.ai_busy || !self.cleanup_ready() {
            return;
        }
        let Ok(settings) = self.cleanup_panel.settings.clone() else {
            return;
        };
        if !settings.agent.enabled {
            self.panel_message(t!(Tr::CpAiNotEnabled), cx);
            return;
        }
        let Some(token) = self.cleanup_token() else {
            return;
        };
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
            "paths" => if settings.agent.share_paths {
                t!(Tr::CpPathsFull)
            } else {
                t!(Tr::CpPathsOpaque)
            }
        );
        let answer = window.prompt(
            PromptLevel::Warning,
            t!(Tr::CpConfirmAnalyze),
            Some(&detail),
            &[t!(Tr::CpSendSummary), t!(Tr::Cancel)],
            cx,
        );
        self.cleanup_panel.ai_busy = true;
        self.cleanup_panel.ai_sequence = self.cleanup_panel.ai_sequence.wrapping_add(1);
        let sequence = self.cleanup_panel.ai_sequence;
        self.panel_message(t!(Tr::CpWaitingConsent), cx);
        cx.spawn(async move |this, cx| {
            if answer.await != Ok(0) {
                this.update(cx, |this, cx| {
                    if sequence == this.cleanup_panel.ai_sequence {
                        this.cleanup_panel.ai_busy = false;
                        cx.notify();
                    }
                })
                .ok();
                return;
            }
            // The captured node hint belongs to token.scan; validate the token before using it.
            // Only bounded structural copying after consent; metadata IO stays off-thread.
            let snapshot = this
                .update(cx, |this, cx| {
                    if this.cleanup_panel.ai_sequence != sequence {
                        return None;
                    }
                    if !this.cleanup_current(token) || !this.cleanup_ready() {
                        this.cleanup_panel.ai_busy = false;
                        cx.notify();
                        return None;
                    }
                    let Screen::Results(r) = &this.screen else {
                        return None;
                    };
                    match agent::prepare_snapshot_with_selection(
                        &r.tree,
                        &r.findings,
                        &settings,
                        &request,
                        selected_node,
                    ) {
                        Ok(snapshot) => Some(snapshot),
                        Err(error) => {
                            this.cleanup_panel.ai_busy = false;
                            this.panel_message(error, cx);
                            None
                        }
                    }
                })
                .ok()
                .flatten();
            let Some((tree, findings)) = snapshot else {
                return;
            };
            // Context uses snapshot-local IDs only; never forward the original node hint.
            let context_request = request.clone();
            let context_settings = settings.clone();
            let context = cx
                .background_spawn(async move {
                    agent::context_from_tree(&tree, &findings, &context_settings, &context_request)
                })
                .await;
            // Recheck after potentially slow metadata/context construction, immediately before networking.
            let valid = this
                .update(cx, |this, cx| {
                    if this.cleanup_panel.ai_sequence != sequence {
                        return false;
                    }
                    if !this.cleanup_current(token) || !this.cleanup_ready() {
                        this.cleanup_panel.ai_busy = false;
                        cx.notify();
                        return false;
                    }
                    true
                })
                .unwrap_or(false);
            if !valid {
                return;
            }
            let response = match context {
                Ok(context) => {
                    cx.background_spawn(
                        async move { agent::run(&settings.agent, context, request) },
                    )
                    .await
                }
                Err(e) => Err(e),
            };
            this.update(cx, |this, cx| {
                if this.cleanup_panel.ai_sequence != sequence {
                    return;
                }
                this.cleanup_panel.ai_busy = false;
                if !this.cleanup_current(token) {
                    cx.notify();
                    return;
                }
                match response {
                    Ok(response) => {
                        this.cleanup_panel.response = Some((token, response));
                        this.panel_message(t!(Tr::CpAdvisoryNotice), cx);
                    }
                    Err(e) => this.panel_message(e, cx),
                }
            })
            .ok();
        })
        .detach();
    }
    pub(super) fn start_cleanup_scheduler(&mut self, cx: &mut Context<Self>) {
        cx.spawn(async move |this, cx| {
            loop {
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

    pub(super) fn render_cleanup_panel(&self, cx: &mut Context<Self>) -> gpui::Div {
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
                        cx.notify();
                    })),
            );
        }
        let mut body = div()
            .id("cleanup-panel-scroll")
            .flex_1()
            .min_h_0()
            .overflow_y_scroll()
            .flex()
            .flex_col()
            .gap_3()
            .p_3();
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
        } else {
            body = body.child(match p.tab {
                0 => self.render_cleanup_preview(cx),
                1 => self.render_cleanup_rules(cx),
                2 => self.render_cleanup_ai(cx),
                _ => self.render_cleanup_settings(cx),
            });
        }
        if !p.message.is_empty() {
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
    fn render_cleanup_rules(&self, cx: &mut Context<Self>) -> gpui::Div {
        let p = &self.cleanup_panel;
        let mut view =
            panel_card().child(
                row()
                    .child(button("new-rule", t!(Tr::CpNewRule)).on_click(
                        cx.listener(|this, _, window, cx| this.new_panel_rule(window, cx)),
                    ))
                    .child(t!(Tr::CpRulesIntro)),
            );
        if let Some(editor) = &p.editor {
            view = view.child(
                panel_card()
                    .child(t!(Tr::CpEditorHint))
                    .when(editor_conflict(editor.open_revision, p.revision) || editor.draft_token.is_some_and(|token| !self.cleanup_current(token)), |d| d.child(div().text_color(rgb(WARNING)).child(t!(Tr::CpEditorStaleWarning))))
                    .child(field(t!(Tr::CpFieldName), &editor.name))
                    .child(field(t!(Tr::CpFieldDescription), &editor.description))
                    .child(field(t!(Tr::CpFieldScopePaths), &editor.roots))
                    .child(field(t!(Tr::CpFieldMatchGlobs), &editor.pattern))
                    .child(field(t!(Tr::CpFieldExcludeGlobsShort), &editor.exclude))
                    .child(field(t!(Tr::CpFieldMinSize), &editor.size))
                    .child(field(t!(Tr::CpFieldKeepDaysShort), &editor.days))
                    .child(field(t!(Tr::CpFieldPriorityShort), &editor.priority))
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
            for (i, category) in [
                CleanupCategory::Temporary,
                CleanupCategory::Cache,
                CleanupCategory::Build,
                CleanupCategory::Logs,
                CleanupCategory::Downloads,
                CleanupCategory::Backup,
                CleanupCategory::Other,
            ]
            .into_iter()
            .enumerate()
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
            view = view.child(categories).child(
                row()
                    .child(button("save-rule", t!(Tr::CpSaveRule)).on_click(
                        cx.listener(|this, _, window, cx| this.save_panel_rule(window, cx)),
                    ))
                    .child(button("cancel-rule", t!(Tr::CpCancelEdit)).on_click(cx.listener(
                        |this, _, window, cx| {
                            window.focus(&this.focus_handle, cx);
                            this.cleanup_panel.editor = None;
                            cx.notify();
                        },
                    ))),
            );
        }
        let Ok(settings) = &p.settings else {
            return view;
        };
        let mut ordered = settings.rules.iter().collect::<Vec<_>>();
        ordered.sort_by_key(|r| std::cmp::Reverse(r.priority));
        for (i, rule) in ordered.into_iter().enumerate() {
            let edit = rule.clone();
            let id = rule.id.clone();
            let toggle_id = id.clone();
            view = view.child(
                panel_card()
                    .child(tf!(
                        Tr::CpRuleRowMeta,
                        "name" => rule.name,
                        "category" => category_label(rule.category),
                        "source" => source_label(rule.source),
                        "priority" => rule.priority,
                        "days" => rule
                            .older_than_days
                            .map(|d| d.to_string())
                            .unwrap_or_else(|| t!(Tr::CpNoLimit).into()),
                        "action" => action_label(rule.action),
                        "auto" => if rule.auto_clean {
                            t!(Tr::CpAuthorized)
                        } else {
                            t!(Tr::CpOff)
                        }
                    ))
                    .child(format!("{} / {}", path_list(&rule.roots), rule.pattern))
                    .child(
                        row()
                            .child(
                                button(
                                    ("enable-rule", i),
                                    if rule.enabled {
                                        t!(Tr::CpEnabledOn)
                                    } else {
                                        t!(Tr::CpDisabledOff)
                                    },
                                )
                                .on_click(cx.listener(
                                    move |this, _, _, cx| {
                                        if this
                                            .cleanup_panel
                                            .editor
                                            .as_ref()
                                            .is_some_and(|editor| editor.rule.id == toggle_id)
                                        {
                                            this.panel_message(
                                                t!(Tr::CpEditingLocked),
                                                cx,
                                            );
                                            return;
                                        }
                                        let Ok(mut next) = this.cleanup_panel.settings.clone()
                                        else {
                                            return;
                                        };
                                        if let Some(r) =
                                            next.rules.iter_mut().find(|r| r.id == toggle_id)
                                        {
                                            r.enabled = !r.enabled;
                                        }
                                        this.save_panel_settings(next, cx);
                                    },
                                )),
                            )
                            .child(button(("edit-rule", i), t!(Tr::CpEdit)).on_click(cx.listener(
                                move |this, _, window, cx| {
                                    this.edit_panel_rule(edit.clone(), None, window, cx)
                                },
                            )))
                            .child(button(("delete-rule", i), t!(Tr::CpDeleteRule)).on_click(cx.listener(
                                move |this, _, window, cx| {
                                    let Ok(mut next) = this.cleanup_panel.settings.clone() else {
                                        return;
                                    };
                                    next.rules.retain(|r| r.id != id);
                                    this.confirm_panel_settings(
                                        next,
                                        t!(Tr::CpConfirmDeleteRule),
                                        t!(Tr::CpDeleteRuleNote),
                                        window,
                                        cx,
                                    );
                                },
                            ))),
                    ),
            );
        }
        view
    }
    fn render_cleanup_ai(&self, cx: &mut Context<Self>) -> gpui::Div {
        let p = &self.cleanup_panel;
        let Ok(settings) = &p.settings else {
            return panel_card();
        };
        let mut protocols = row();
        for (i, protocol) in [
            AgentProtocol::ChatCompletions,
            AgentProtocol::Responses,
            AgentProtocol::Anthropic,
        ]
        .into_iter()
        .enumerate()
        {
            protocols = protocols.child(
                button(("ai-protocol", i), protocol.label())
                    .when(settings.agent.protocol == protocol, |d| d.bg(rgb(ACCENT)))
                    .on_click(cx.listener(move |this, _, _, cx| {
                        let Ok(mut next) = this.cleanup_panel.settings.clone() else {
                            return;
                        };
                        next.agent.protocol = protocol;
                        next.agent.base_url = text(&this.cleanup_panel.url, cx);
                        next.agent.model = text(&this.cleanup_panel.model, cx);
                        this.save_panel_settings(next, cx);
                    })),
            );
        }
        let credential_target = match self.panel_credential_target(cx) {
            Ok(scope) => tf!(Tr::CpCurrentKeyTarget, "scope" => scope),
            Err(e) => tf!(Tr::CpKeyTargetUnavailable, "e" => e),
        };
        let mut view = panel_card().child(t!(Tr::CpAiIntro))
            .child(credential_target)
            .child(protocols).child(field(t!(Tr::CpFieldEndpoint), &p.url)).child(field(t!(Tr::CpFieldModelShort), &p.model)).child(field(t!(Tr::CpFieldApiKey), &p.key))
            .child(row().child(button("ai-save", t!(Tr::CpSaveAiConfig)).on_click(cx.listener(|this, _, _, cx| this.save_panel_ai(cx))))
                .child(button("ai-key-save", if p.key_busy { t!(Tr::CpKeychainBusy) } else { t!(Tr::CpSaveKey) }).on_click(cx.listener(|this, _, _, cx| this.store_panel_key(false, cx))))
                .child(button("ai-key-delete", t!(Tr::CpDeleteKey)).on_click(cx.listener(|this, _, window, cx| {
                    this.confirm_panel_key_delete(window, cx);
                })))
                .child(button("ai-test", if p.test_busy { t!(Tr::CpTesting) } else { t!(Tr::CpTestConnection) }).on_click(cx.listener(|this, _, window, cx| {
                    this.test_panel_connection(window, cx);
                }))))
            .child(row().child(button("ai-enable", if settings.agent.enabled { t!(Tr::CpAiEnabled) } else { t!(Tr::CpAiConsent) }).on_click(cx.listener(|this, _, window, cx| {
                let Ok(mut next) = this.cleanup_panel.settings.clone() else { return }; next.agent.enabled = !next.agent.enabled;
                if next.agent.enabled { let detail = tf!(Tr::CpAiEnabledExplain, "target" => next.agent.base_url, "model" => next.agent.model); this.confirm_panel_settings(next, t!(Tr::CpConsentSendMetadata), &detail, window, cx); }
                else { this.save_panel_settings(next, cx); }
            }))).child(button("ai-paths", if settings.agent.share_paths { t!(Tr::CpPathsOn) } else { t!(Tr::CpPathsOff) }).on_click(cx.listener(|this, _, window, cx| {
                let Ok(mut next) = this.cleanup_panel.settings.clone() else { return }; next.agent.share_paths = !next.agent.share_paths;
                if next.agent.share_paths { this.confirm_panel_settings(next, t!(Tr::CpAllowFullPaths), t!(Tr::CpFullPathsExplain), window, cx); }
                else { this.save_panel_settings(next, cx); }
            }))).child(button("ai-thinking", if settings.agent.thinking { t!(Tr::CpThinkingOn) } else { t!(Tr::CpThinkingOff) }).on_click(cx.listener(|this, _, _, cx| {
                let Ok(mut next) = this.cleanup_panel.settings.clone() else { return }; next.agent.thinking = !next.agent.thinking;
                this.save_panel_settings(next, cx);
            }))))
            .child(row().child(button("ai-analyze", t!(Tr::CpAnalyzeDisk)).on_click(cx.listener(|this, _, window, cx| this.request_panel_ai(AgentRequest::Analyze, None, window, cx))))
                .child(button("ai-explain", t!(Tr::CpExplainSelection)).on_click(cx.listener(|this, _, window, cx| {
                    if let Screen::Results(r) = &this.screen { let ix = r.focus; this.explain_cleanup_node(ix, window, cx); }
                }))).child(button("ai-drafts", t!(Tr::CpGenerateDrafts)).on_click(cx.listener(|this, _, window, cx| this.request_panel_ai(AgentRequest::GenerateRules, None, window, cx))))
                .child(button("ai-cancel", if p.ai_busy { t!(Tr::CpCancelDiscard) } else { t!(Tr::CpClearSuggestions) }).on_click(cx.listener(|this, _, window, cx| {
                    window.focus(&this.focus_handle, cx);
                    this.cleanup_panel.ai_sequence = this.cleanup_panel.ai_sequence.wrapping_add(1); this.cleanup_panel.ai_busy = false; this.cleanup_panel.response = None;
                    this.panel_message(t!(Tr::CpResultCancelled), cx);
                }))));
        if let Some((token, response)) = &p.response {
            if self.cleanup_current(*token) {
                view = view.child(response.explanation.clone());
                for (i, rule) in response.proposals.iter().enumerate() {
                    let edit = rule.clone();
                    let edit_id = rule.id.clone();
                    let adopt = rule.id.clone();
                    let enable = rule.id.clone();
                    let reject = rule.id.clone();
                    view = view.child(panel_card().child(tf!(Tr::CpDraftMeta, "name" => rule.name, "category" => category_label(rule.category), "days" => rule.older_than_days.map(|d| d.to_string()).unwrap_or_else(|| t!(Tr::CpDraftNoLimit).into())))
                        .child(tf!(Tr::CpDraftExplain, "roots" => path_list(&rule.roots), "pattern" => rule.pattern, "blurb" => rule.description))
                        .child(row().child(button(("draft-adopt", i), t!(Tr::CpAdoptDisabled)).on_click(cx.listener(move |this, _, window, cx| { window.focus(&this.focus_handle, cx); this.adopt_panel_draft(adopt.clone(), false, cx); })))
                            .child(button(("draft-enable", i), t!(Tr::CpAdoptEnable)).on_click(cx.listener(move |this, _, window, cx| { window.focus(&this.focus_handle, cx); this.adopt_panel_draft(enable.clone(), true, cx); })))
                            .child(button(("draft-edit", i), t!(Tr::CpEditAsUserRule)).on_click(cx.listener(move |this, _, window, cx| this.edit_panel_rule(edit.clone(), Some(edit_id.clone()), window, cx))))
                            .child(button(("draft-reject", i), t!(Tr::CpReject)).on_click(cx.listener(move |this, _, window, cx| {
                                window.focus(&this.focus_handle, cx);
                                if let Some((_, response)) = &mut this.cleanup_panel.response { response.proposals.retain(|r| r.id != reject); } cx.notify();
                            })))));
                }
            }
        }
        view
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
