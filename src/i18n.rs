//! Internationalization: one exhaustive table of user-facing strings, two
//! languages (English, Simplified Chinese), zero dependencies.
//!
//! - [`Tr`] enumerates every translatable string; the compiler enforces that
//!   each key exists in both languages (the `entries!` macro builds one match
//!   per key per language).
//! - [`tr`] returns the string for the current language. Call it during render
//!   so a language switch takes effect on the next frame.
//! - [`tf`] renders a template with named `{placeholder}`s, so translations can
//!   reorder interpolated values freely (`"{a} of {b}"` ↔ `"{b} 中的 {a}"`).
//! - The language itself lives in one atomic; [`set_lang`] flips it, and
//!   [`detect_system_lang`] seeds it from macOS preferences on first use.

use std::sync::atomic::{AtomicU8, Ordering};

/// A supported interface language.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Lang {
    #[default]
    En,
    Zh,
}

impl Lang {
    /// BCP 47-ish code used in settings.json.
    pub fn code(self) -> &'static str {
        match self {
            Lang::En => "en",
            Lang::Zh => "zh",
        }
    }

    /// Each language is labelled in its own tongue, the usual convention for
    /// language pickers.
    pub fn label(self) -> &'static str {
        match self {
            Lang::En => "English",
            Lang::Zh => "简体中文",
        }
    }

    pub fn all() -> [Lang; 2] {
        [Lang::En, Lang::Zh]
    }

    /// Parse a settings or locale code (`zh-Hans-CN`, `en_US`, `ZH` …).
    pub fn from_code(code: &str) -> Lang {
        let code = code.trim().trim_matches('"').to_ascii_lowercase();
        // Accept both `zh-Hans-CN` and `en_US` spellings; underscore is common in POSIX locales.
        let normalized = code.replace('_', "-");
        if normalized.starts_with("zh") {
            Lang::Zh
        } else {
            Lang::En
        }
    }
}

impl serde::Serialize for Lang {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.code())
    }
}

impl<'de> serde::Deserialize<'de> for Lang {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Lang, D::Error> {
        let code = String::deserialize(deserializer)?;
        Ok(Lang::from_code(&code))
    }
}

/// Sentinel meaning "not decided yet": detect the system language on first use.
const UNSET: u8 = u8::MAX;
static LANG: AtomicU8 = AtomicU8::new(UNSET);

/// The language UI strings are rendered in right now. Reads are lock-free; the
/// one-time system detection is racy but idempotent, so it needs no lock.
/// Under `cargo test` the default is pinned to English so assertions on UI
/// strings stay deterministic on machines set to any language.
pub fn lang() -> Lang {
    let raw = LANG.load(Ordering::Relaxed);
    if raw != UNSET {
        return match raw {
            1 => Lang::Zh,
            _ => Lang::En,
        };
    }
    let detected = if cfg!(test) {
        Lang::En
    } else {
        detect_system_lang()
    };
    LANG.store(detected as u8, Ordering::Relaxed);
    detected
}

/// Switch the UI language. Takes effect on the next rendered frame.
pub fn set_lang(value: Lang) {
    LANG.store(value as u8, Ordering::Relaxed);
}

/// The user's preferred language, straight from macOS (or the environment for
/// CLI runs and tests): `/usr/bin/defaults read -g AppleLanguages` prints e.g.
/// `(\n    "zh-Hans-CN",\n    "en-US"\n)`; the first entry wins.
pub fn detect_system_lang() -> Lang {
    if let Ok(output) = std::process::Command::new("/usr/bin/defaults")
        .args(["read", "-g", "AppleLanguages"])
        .output()
    {
        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout);
            for line in text.lines() {
                let code = line.trim().trim_matches(['"', ',', '(', ')']);
                if code.is_empty() || code == "(" || code == ")" {
                    continue;
                }
                return Lang::from_code(code);
            }
        }
    }
    for variable in ["LC_ALL", "LC_MESSAGES", "LANG"] {
        if let Ok(value) = std::env::var(variable) {
            if !value.is_empty() {
                return Lang::from_code(&value);
            }
        }
    }
    Lang::En
}

/// The translation table: one line per string, both languages side by side.
macro_rules! entries {
    ($( $key:ident => { en: $en:expr, zh: $zh:expr } ),* $(,)?) => {
        /// Every translatable string in the app. Match is exhaustive: adding a
        /// key without both translations fails to compile.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum Tr { $($key),* }

        /// The string for `key` in the current language.
        pub fn tr(key: Tr) -> &'static str {
            match key {
                $(Tr::$key => match lang() { Lang::En => $en, Lang::Zh => $zh }),*
            }
        }

        /// Every template, for completeness checks in tests.
        #[cfg(test)]
        pub(crate) const TEMPLATES: &[(Tr, &'static str, &'static str)] = &[
            $( (Tr::$key, $en, $zh) ),*
        ];
    };
}

entries! {
    // ── File-kind categories (classify) ──
    CatApps => { en: "Apps", zh: "应用" },
    CatDownloads => { en: "Downloads & Trash", zh: "下载与废纸篓" },
    CatDeveloper => { en: "Developer files", zh: "开发文件" },
    CatCaches => { en: "Caches & logs", zh: "缓存与日志" },
    CatMedia => { en: "Photos, video & music", zh: "照片、视频与音乐" },
    CatDocuments => { en: "Documents", zh: "文档" },
    CatAppData => { en: "App data & backups", zh: "应用数据与备份" },
    CatSystem => { en: "System", zh: "系统" },
    CatMixed => { en: "Mixed folders", zh: "混合文件夹" },

    // ── Chart & colour toggles ──
    ColourCaption => { en: "Colour", zh: "颜色" },
    ColourFolder => { en: "Folder", zh: "文件夹" },
    ColourKind => { en: "Kind", zh: "类型" },
    ColourSafety => { en: "Safety", zh: "安全性" },
    SafetyNoFinding => { en: "No finding", zh: "暂无结论" },
    ChartCaption => { en: "Chart", zh: "图表" },
    ChartSunburst => { en: "Sunburst", zh: "旭日图" },
    ChartIcicle => { en: "Icicle", zh: "冰柱图" },
    ChartTreemap => { en: "Treemap", zh: "矩形树图" },
    ChartSunburstTip => { en: "Sunburst: rings round the folder (⌘1)", zh: "旭日图：围绕文件夹的环形图 (⌘1)" },
    ChartIcicleTip => { en: "Icicle: rows falling from the folder, with names (⌘2)", zh: "冰柱图：逐级展开的行列，可显示名称 (⌘2)" },
    ChartTreemapTip => { en: "Treemap: boxes sized by space, one level at a time (⌘3)", zh: "矩形树图：按空间比例的矩形，逐级查看 (⌘3)" },

    // ── Scan-complete banner ──
    AlreadyReadable => { en: "Petal could already read every folder here.", zh: "Petal 已可读取此处全部文件夹。" },
    AdminReadPrompt => { en: "Petal wants to read the folders that belong to macOS and other users, to include their sizes. It only reads names and sizes; nothing is changed.", zh: "Petal 想要读取属于 macOS 和其他用户的文件夹，以便计入它们的大小。只读取名称和大小，不会做任何更改。" },
    DeleteSnapshotsPrompt => { en: "Petal wants to delete Time Machine’s local snapshots to free the space they hold.", zh: "Petal 想要删除时间机器的本地快照，以释放它们占用的空间。" },

    // ── Safety verdicts (safety.rs) ──
    SafetySafe => { en: "Safe to delete", zh: "可安全删除" },
    SafetyReview => { en: "Review first", zh: "先确认再删" },
    SafetyManage => { en: "Manage in app", zh: "在对应应用中管理" },
    // ── Disk status item ──
    MbTitle => { en: "Menu bar disk monitor", zh: "菜单栏磁盘监控" },
    MbHint => { en: "Shows currently free space (excluding purgeable space). Closing the window keeps monitoring; Quit Petal stops it. No files are deleted automatically by this monitor.", zh: "显示当前剩余空间（不含可清理空间）。关闭窗口后仍继续监控，退出 Petal 才停止；监控本身不会自动删除文件。" },
    MbEnabled => { en: "Show disk space in menu bar", zh: "在菜单栏显示磁盘剩余空间" },
    MbStartupDisk => { en: "Startup disk", zh: "主磁盘" },
    MbDisk => { en: "Monitored disk", zh: "监控磁盘" },
    MbDisplay => { en: "Display remaining space as", zh: "剩余空间显示单位" },
    MbAutoUnit => { en: "Auto", zh: "自动" },
    MbThreshold => { en: "Turn red when remaining space is below", zh: "剩余空间低于此值时变红" },
    MbRefreshSeconds => { en: "Refresh interval (seconds, 1–3600)", zh: "刷新间隔（秒，1–3600）" },
    MbSave => { en: "Save monitor settings", zh: "保存监控设置" },
    MbSaved => { en: "Menu bar settings saved.", zh: "菜单栏设置已保存。" },
    MbBadMount => { en: "Select an absolute disk mount point without traversal.", zh: "请选择不含路径跳转的绝对磁盘挂载路径。" },
    MbBadThreshold => { en: "Threshold must be a positive number; percentages must not exceed 100.", zh: "阈值必须是正数；百分比不能超过 100。" },
    MbBadRefresh => { en: "Refresh interval must be an integer between 1 and 3600 seconds.", zh: "刷新间隔必须是 1 到 3600 秒之间的整数。" },
    MbSpaceDetail => { en: "{free} free / {total} total · {percent} remaining", zh: "剩余 {free} / 总计 {total} · 剩余 {percent}" },
    MbLowSpace => { en: "Low disk space — time to clean up.", zh: "磁盘剩余空间不足，建议清理。" },
    MbReading => { en: "Reading disk space…", zh: "正在读取磁盘空间…" },
    MbUnavailable => { en: "Disk unavailable or unmounted", zh: "磁盘不可用或已卸载" },
    MbOpen => { en: "Open Petal", zh: "打开 Petal" },
    MbClean => { en: "Scan this disk to clean up…", zh: "扫描此磁盘并清理…" },
    MbSettings => { en: "Disk monitor settings…", zh: "磁盘监控设置…" },
    MbRefresh => { en: "Refresh now", zh: "立即刷新" },
    // ── Menu bar (main.rs) ──
    MenuFile => { en: "File", zh: "文件" },
    MenuView => { en: "View", zh: "显示" },
    MenuGo => { en: "Go", zh: "前往" },
    MenuWindow => { en: "Window", zh: "窗口" },
    MenuHidePetal => { en: "Hide Petal", zh: "隐藏 Petal" },
    MenuHideOthers => { en: "Hide Others", zh: "隐藏其他" },
    MenuShowAll => { en: "Show All", zh: "全部显示" },
    MenuQuit => { en: "Quit Petal", zh: "退出 Petal" },
    MenuOpenFolder => { en: "Open Folder…", zh: "打开文件夹…" },
    MenuRescan => { en: "Rescan", zh: "重新扫描" },
    MenuReadAsAdmin => { en: "Read Protected Folders as Administrator…", zh: "以管理员身份读取受保护文件夹…" },
    MenuShowDisks => { en: "Show Disks", zh: "显示磁盘" },
    MenuCloseWindow => { en: "Close Window", zh: "关闭窗口" },
    MenuAsSunburst => { en: "as Sunburst", zh: "旭日图" },
    MenuAsIcicle => { en: "as Icicle", zh: "冰柱图" },
    MenuAsTreemap => { en: "as Treemap", zh: "矩形树图" },
    MenuEnclosingFolder => { en: "Enclosing Folder", zh: "上层文件夹" },
    MenuMinimize => { en: "Minimize", zh: "最小化" },
    MenuZoom => { en: "Zoom", zh: "缩放" },

    // ── Toolbar ──
    RulesAi => { en: "Rules & AI", zh: "规则与 AI" },
    RulesAiBack => { en: "Rules & AI · Back to chart", zh: "规则与 AI · 返回图表" },
    ScanContinuesBehind => { en: "Scan continues in the background", zh: "扫描仍在后台继续" },
    EnclosingFolderTip => { en: "Enclosing Folder (⌘↑)", zh: "上层文件夹 (⌘↑)" },
    OutOfDate => { en: "Out of date · rescan to refresh", zh: "已过期 · 重新扫描以刷新" },
    ScannedIn => { en: "Scanned in {s}s", zh: "扫描用时 {s} 秒" },
    Rescan => { en: "Rescan", zh: "重新扫描" },
    RescanTip => { en: "Scan this folder again (⌘R)", zh: "重新扫描此文件夹 (⌘R)" },
    Disks => { en: "Disks", zh: "磁盘" },
    DisksTip => { en: "Back to the list of disks (⇧⌘D)", zh: "返回磁盘列表 (⇧⌘D)" },

    // ── Start screen ──
    Scan => { en: "Scan", zh: "扫描" },
    PurgeableTooltip => { en: "Space macOS frees by itself when it needs room: Time Machine snapshots, iCloud files it can download again, caches. It’s already counted in the sizes here.", zh: "macOS 需要空间时会自行释放的部分：时间机器快照、可重新下载的 iCloud 文件、缓存。这部分已计入上方的容量。" },
    PurgeableCount => { en: "{size} purgeable", zh: "{size} 可清除" },
    StartTagline => { en: "Find out what’s taking up space on your disk.", zh: "看看磁盘空间都被什么占用了。" },
    ScanHome => { en: "Scan Home Folder", zh: "扫描个人文件夹" },
    ChooseFolder => { en: "Choose Folder…  ⌘O", zh: "选择文件夹…  ⌘O" },
    FdaTip => { en: "Tip: grant Full Disk Access in System Settings › Privacy & Security to include protected folders.", zh: "提示：在系统设置 › 隐私与安全性中授予完全磁盘访问权限，即可包含受保护的文件夹。" },
    UsedFreeOf => { en: "{used} used · {free} free of {total}", zh: "已用 {used} · 共 {total}，可用 {free}" },

    // ── Scanning screen ──
    UsedAmount => { en: "{size} used", zh: "已用 {size}" },
    ScanningLower => { en: "scanning…", zh: "扫描中…" },
    PercentEta => { en: "{percent}% · {left}", zh: "{percent}% · {left}" },
    PercentOnly => { en: "{percent}%", zh: "{percent}%" },
    EtaFinishing => { en: "finishing up…", zh: "即将完成…" },
    EtaSecondsLeft => { en: "about {n} s left", zh: "约剩 {n} 秒" },
    EtaMinutesLeft => { en: "about {n} min left", zh: "约剩 {n} 分钟" },
    ScanningNamed => { en: "Scanning “{name}”…", zh: "正在扫描“{name}”…" },
    Scanning => { en: "Scanning…", zh: "正在扫描…" },
    Cancel => { en: "Cancel", zh: "取消" },
    ScannedOf => { en: "{scanned} of {total} scanned", zh: "已扫描 {scanned}，共 {total}" },
    OfUsed => { en: "of {used} used", zh: "已用总量 {used}" },

    // ── Full Disk Access card ──
    AccessTitleMissing => { en: "See everything on your disk", zh: "查看磁盘上的全部内容" },
    AccessBodyWithBytes => { en: "{size} couldn’t be read. macOS keeps some folders private (Mail, Messages, Safari, other apps’ data) unless Petal has Full Disk Access.", zh: "{size} 无法读取。macOS 会将部分文件夹设为私有（邮件、信息、Safari 及其他应用的数据），除非 Petal 获得完全磁盘访问权限。" },
    AccessBodyPlain => { en: "macOS keeps some folders private (Mail, Messages, Safari, other apps’ data). Give Petal Full Disk Access so the scan can include them.", zh: "macOS 会将部分文件夹设为私有（邮件、信息、Safari 及其他应用的数据）。授予 Petal 完全磁盘访问权限，扫描即可包含它们。" },
    AccessTitleGranted => { en: "Full Disk Access is on", zh: "完全磁盘访问权限已开启" },
    AccessBodyGranted => { en: "Rescan to include the folders that were private before.", zh: "重新扫描以包含之前私有的文件夹。" },
    NotNow => { en: "Not now", zh: "暂不" },
    OpenPrivacySettings => { en: "Open Privacy Settings", zh: "打开隐私设置" },
    AccessHowTo => { en: "In Settings, turn on Petal (use + to add it if it isn’t listed).", zh: "在设置中打开 Petal（若列表中没有，请用 + 添加）。" },

    // ── Administrator card ──
    ReadAdminFail => { en: "Couldn’t read as administrator: {why}", zh: "无法以管理员身份读取：{why}" },
    AdminFoundMore => { en: "Read every protected folder: {more} more accounted for.", zh: "已读取全部受保护的文件夹：额外计入 {more}。" },
    AdminFoundSome => { en: "Read the protected folders: {more} more accounted for. macOS keeps {folders} even from administrators.", zh: "已读取受保护的文件夹：额外计入 {more}。macOS 保留了 {folders}，连管理员也无法访问。" },
    OneFolder => { en: "1 folder", zh: "1 个文件夹" },
    NFolders => { en: "{n} folders", zh: "{n} 个文件夹" },
    DeleteOneSnapshot => { en: "Delete the Time Machine snapshot?", zh: "删除该时间机器快照？" },
    DeleteSnapshots => { en: "Delete {n} Time Machine snapshots?", zh: "删除 {n} 个时间机器快照？" },
    SnapshotsExplain => { en: "Time Machine keeps local snapshots for a day so you can restore recent changes. Deleting them frees the space they hold; your Time Machine backups aren’t affected. macOS asks for an administrator’s password.", zh: "时间机器会保留一天内的本地快照，便于还原最近的更改。删除快照可释放其占用的空间；你的时间机器备份不受影响。macOS 会要求输入管理员密码。" },
    DeleteSnapshotsButton => { en: "Delete Snapshots", zh: "删除快照" },
    SnapshotsDeleted => { en: "Deleted the snapshots, freeing {freed} so far.", zh: "快照已删除，目前已释放 {freed}。" },
    SnapshotsDeletedDeferred => { en: "Deleted the snapshots. APFS frees their space over the next minute or so.", zh: "快照已删除。APFS 会在接下来的一分钟左右逐步释放空间。" },
    OneApfsSnapshot => { en: "1 APFS snapshot", zh: "1 个 APFS 快照" },
    NApfsSnapshots => { en: "{n} APFS snapshots", zh: "{n} 个 APFS 快照" },
    KindTimeMachine => { en: "Time Machine", zh: "时间机器" },
    KindMacosUpdate => { en: "macOS update", zh: "macOS 更新" },
    KindOtherApp => { en: "Other app", zh: "其他应用" },
    SnapshotsExplainTm => { en: "Snapshots keep earlier copies of your files, so deleting a file frees nothing while a snapshot still holds it. APFS doesn’t say how much each one holds: it’s part of “Snapshots and unreadable”. Time Machine’s are a day’s quick undo, safe to delete; the rest belong to macOS or other apps, which remove them when they’re done.", zh: "快照保存着文件的早期副本，只要快照还在，删除文件就不会释放空间。APFS 不会说明每个快照占多少：它们计入“快照与不可读”。时间机器快照是一天的快速撤销，可安全删除；其余属于 macOS 或其他应用，它们用完会自行清理。" },
    SnapshotsExplainOther => { en: "Snapshots keep earlier copies of your files, so deleting a file frees nothing while a snapshot still holds it. APFS doesn’t say how much each one holds: it’s part of “Snapshots and unreadable”. These belong to macOS or other apps, which remove them when they’re done.", zh: "快照保存着文件的早期副本，只要快照还在，删除文件就不会释放空间。APFS 不会说明每个快照占多少：它们计入“快照与不可读”。这些快照属于 macOS 或其他应用，它们用完会自行清理。" },
    Deleting => { en: "Deleting…", zh: "正在删除…" },
    DeleteTmSnapshotsButton => { en: "Delete Time Machine Snapshots…", zh: "删除时间机器快照…" },
    SnapshotsPartialFail => { en: "Couldn’t delete {n} of the snapshots: {why}", zh: "有 {n} 个快照未能删除：{why}" },
    SnapshotsFail => { en: "Couldn’t delete the snapshots: {why}", zh: "快照删除失败：{why}" },
    ReadProtectedFolders => { en: "Read protected folders", zh: "读取受保护的文件夹" },
    FoldersBelongOne => { en: "1 folder belongs", zh: "1 个文件夹属于" },
    FoldersBelongMany => { en: "{n} folders belong", zh: "{n} 个文件夹属于" },
    AdminCardBody => { en: "{folders} to macOS or other users. An administrator can read them; Petal only reads names and sizes.", zh: "{folders} macOS 或其他用户。管理员可以读取；Petal 只读取名称和大小。" },
    AdminCardReading => { en: "Reading as administrator…", zh: "正在以管理员身份读取…" },
    ReadAsAdmin => { en: "Read as Administrator…", zh: "以管理员身份读取…" },
    AdminPasswordTip => { en: "macOS asks for an administrator’s password", zh: "macOS 会要求输入管理员密码" },
    OldestSuffix => { en: " · oldest {date}", zh: " · 最早 {date}" },

    // ── Trash flow ──
    MoveOneToTrash => { en: "Move “{name}” to the Trash?", zh: "将“{name}”移到废纸篓？" },
    MoveManyToTrash => { en: "Move {n} items to the Trash?", zh: "将 {n} 项移到废纸篓？" },
    TrashFreesUp => { en: "This will free up {freed}. You can put items back from the Trash in Finder.", zh: "这将释放 {freed}。之后可在访达的废纸篓中放回原处。" },
    TrashFreesUpTentative => { en: "This will free up to {freed} (still working out how much is shared). You can put items back from the Trash in Finder.", zh: "最多可释放 {freed}（仍在计算共享部分）。之后可在访达的废纸篓中放回原处。" },
    NItemsWord => { en: "{n} items", zh: "{n} 项" },
    MoveToTrashButton => { en: "Move to Trash", zh: "移到废纸篓" },
    TrashFail => { en: "Couldn’t move to Trash: {why}", zh: "移到废纸篓失败：{why}" },

    // ── Sidebar ──
    SizeAndFiles => { en: "{size} · {n} files", zh: "{size} · {n} 个文件" },
    PrivateUntilFda => { en: "Private to macOS until Petal has Full Disk Access", zh: "macOS 私有目录，需完全磁盘访问权限才能读取" },
    SystemProtected => { en: "Protected by macOS; not even an administrator can read them", zh: "受 macOS 保护，管理员也无法读取" },
    OtherUsersOwned => { en: "Owned by macOS or another user: File › Read Protected Folders as Administrator reads them", zh: "属于 macOS 或其他用户：可通过 文件 › 以管理员身份读取受保护文件夹 读取" },
    CloudOnlyTip => { en: "In iCloud and not downloaded, so they use no space on this Mac", zh: "仅存于 iCloud 且未下载，不占用本机空间" },
    CloudOnlyCount => { en: "{n} cloud-only", zh: "{n} 项仅在云端" },
    UnreadableCount => { en: "{n} unreadable", zh: "{n} 项不可读" },

    // ── Findings ──
    Findings => { en: "Findings", zh: "清理发现" },
    SafeToDelete => { en: "{size} safe to delete", zh: "{size} 可安全删除" },
    SafeSuffix => { en: " · {size} safe to delete", zh: " · {size} 可安全删除" },
    CopiedGcCommands => { en: "Copied git gc commands for {n} repositories: paste them in Terminal", zh: "已复制 {n} 个仓库的 git gc 命令：粘贴到终端执行" },
    CopiedOneGcCommand => { en: "Copied the git gc command: paste it in Terminal", zh: "已复制 git gc 命令：粘贴到终端执行" },
    CopyGcCommands => { en: "Copy git gc Commands", zh: "复制 git gc 命令" },
    CopyCommand => { en: "Copy Command", zh: "复制命令" },
    RevealInFinder => { en: "Reveal in Finder", zh: "在访达中显示" },
    WorkingOutSavings => { en: " working out savings…", zh: " 正在计算可释放空间…" },
    CopiedPaste => { en: "Copied `{cmd}`: paste it in Terminal", zh: "已复制 `{cmd}`：粘贴到终端执行" },
    CopiedPath => { en: "Copied {path}", zh: "已复制 {path}" },
    InCollector => { en: "In Collector", zh: "已在收集箱" },
    CopyPath => { en: "Copy Path", zh: "复制路径" },
    AddToCollector => { en: "Add to Collector", zh: "加入收集箱" },
    RemoveFromCollector => { en: "Remove from Collector", zh: "从收集箱移除" },
    ExplainRow => { en: "Explain", zh: "解释" },
    MoreChips => { en: "+{n} more", zh: "还有 {n} 项" },

    // ── Rows / details ──
    Calculating => { en: "{items} · calculating…", zh: "{items} · 计算中…" },
    MovedToTrash => { en: "Moved {what} to the Trash", zh: "已将 {what} 移到废纸篓" },
    FreedUp => { en: "Freed {freed}. You can put items back from the Trash in Finder.", zh: "已释放 {freed}。之后可在访达的废纸篓中放回原处。" },
    DragToCollect => { en: "Drag items here (or press + on a row) to collect them for deletion.", zh: "把项目拖到这里（或在行上按 +），集中后删除。" },
    SharedExplainer => { en: "{size} is shared with files outside the selection (APFS clones or hard links), so deleting won’t free it", zh: "{size} 与所选范围之外的文件共享（APFS 克隆或硬链接），删除不会释放这部分空间" },

    // ── Collector ──
    Collector => { en: "Collector", zh: "收集箱" },
    CollectorSummary => { en: "{items} · frees {freed}", zh: "{items} · 可释放 {freed}" },
    Clear => { en: "Clear", zh: "清空" },
    MoveToTrash => { en: "Move to Trash…", zh: "移到废纸篓…" },
    MovingToTrash => { en: "Moving to Trash…", zh: "正在移到废纸篓…" },

    // ── Chart ──
    SmallerObjects => { en: "Smaller objects", zh: "更小的项目" },
    TooSmallDetail => { en: "{size}\n{things} too small to show", zh: "{size}\n{things} 过小，无法显示" },
    OneItem => { en: "1 item", zh: "1 项" },
    BackUp => { en: "↑ Back", zh: "↑ 返回" },
    BackTo => { en: "to “{name}”", zh: "回到“{name}”" },
    FilesSuffix => { en: "{n} files", zh: "{n} 个文件" },
    FileWord => { en: "file", zh: "文件" },
    NotReadableMoreAccess => { en: "not readable without more access", zh: "需要更多权限才能读取" },
    SnapshotsOrUnreadable => { en: "held by APFS snapshots, or not readable", zh: "被 APFS 快照占用，或不可读取" },
    ExactApfs => { en: "exact, from APFS", zh: "APFS 精确值" },
    NoFindingDetail => { en: "\nNo finding: not known to be safe", zh: "\n无结论：尚未确认可安全删除" },
    ScanComplete => { en: "Scan complete in {s} s", zh: "扫描完成，用时 {s} 秒" },
    AccountedFor => { en: "{total} accounted for{savings}", zh: "已计入 {total}{savings}" },

    // ── Cleanup panel: labels ──
    CpActionTrash => { en: "Move to Trash", zh: "移到回收站" },
    CpActionPermanent => { en: "Delete permanently (unrecoverable)", zh: "永久删除（不可恢复）" },
    CpCatTemporary => { en: "Temporary files", zh: "临时文件" },
    CpCatCache => { en: "Caches", zh: "缓存" },
    CpCatBuild => { en: "Build outputs", zh: "构建产物" },
    CpCatLogs => { en: "Logs", zh: "日志" },
    CpCatDownloads => { en: "Downloads", zh: "下载" },
    CpCatBackup => { en: "Backups", zh: "备份" },
    CpCatOther => { en: "Other", zh: "其他" },
    // ── Built-in developer cache rules ──
    CpPresetCargoCache => { en: "Cargo downloaded crate cache (review)", zh: "Cargo 下载缓存（需审阅）" },
    CpPresetRustTarget => { en: "Rust / Cargo build cache (review)", zh: "Rust / Cargo 编译缓存（需审阅）" },
    CpPresetNextCache => { en: "Next.js / React build cache (review)", zh: "Next.js / React 构建缓存（需审阅）" },
    CpPresetViteCache => { en: "Vite / React dependency cache (review)", zh: "Vite / React 依赖预构建缓存（需审阅）" },
    CpPresetWebpackCache => { en: "Webpack / CRA / React build cache (review)", zh: "Webpack / CRA / React 编译缓存（需审阅）" },
    CpPresetTurboCache => { en: "Turborepo build cache (review)", zh: "Turborepo 构建缓存（需审阅）" },
    CpPresetCargoDescription => { en: "Old downloaded .crate archives only; Cargo downloads them again when needed. Registry sources, index, installed tools and configuration are not matched.", zh: "仅匹配旧的 .crate 下载包；Cargo 会在需要时重新下载。不匹配 registry 源码、索引、已安装工具和配置。" },
    CpPresetRustDescription => { en: "Old ordinary files in Cargo target directories, including incremental compilation. Requires Cargo.toml beside target; cargo build rebuilds them.", zh: "匹配 Cargo target 目录中的旧普通文件，包含增量编译缓存。target 旁必须有 Cargo.toml；cargo build 会重新构建。" },
    CpPresetNextDescription => { en: "Old ordinary files in .next/cache only, not Next.js server or deployment outputs. Requires package.json in the project.", zh: "仅匹配 .next/cache 中的旧普通文件，不匹配 Next.js 服务端或部署产物。项目中必须有 package.json。" },
    CpPresetViteDescription => { en: "Old ordinary files in node_modules/.vite; Vite regenerates its dependency cache. Requires package.json beside node_modules.", zh: "匹配 node_modules/.vite 中的旧普通文件；Vite 会重新生成依赖缓存。node_modules 旁必须有 package.json。" },
    CpPresetWebpackDescription => { en: "Old ordinary files in node_modules/.cache, including Webpack and Babel caches. Requires package.json beside node_modules; installed dependencies are not matched.", zh: "匹配 node_modules/.cache 中的旧普通文件，包括 Webpack 和 Babel 缓存。node_modules 旁必须有 package.json；不匹配已安装依赖。" },
    CpPresetTurboDescription => { en: "Old ordinary files in .turbo/cache only, not daemon state. Requires package.json in the project.", zh: "仅匹配 .turbo/cache 中的旧普通文件，不匹配守护进程状态。项目中必须有 package.json。" },
    CpSourceBuiltIn => { en: "Built-in", zh: "内置" },
    CpSourceUser => { en: "User", zh: "用户" },
    CpSourceAi => { en: "AI draft (adopted)", zh: "AI 草案（用户采用）" },
    CpFieldModel => { en: "Model name", zh: "模型名称" },
    CpFieldNewKey => { en: "New API key; leave empty to keep the current one", zh: "新 API key；留空保留原密钥" },
    CpFieldProtectedPaths => { en: "Protected paths; separate multiple with semicolons", zh: "保护路径；多个路径用分号分隔" },
    CpFieldInterval => { en: "1–10080 minutes", zh: "1–10080 分钟" },
    CpFieldRuleName => { en: "Rule name", zh: "规则名称" },
    CpFieldDescription => { en: "Description", zh: "描述" },
    CpFieldScopes => { en: "~/Library/Caches; semicolon-separated", zh: "~/Library/Caches；分号分隔" },
    CpFieldExcludeGlobs => { en: "Exclude globs; semicolon-separated", zh: "排除 glob；分号分隔" },
    CpFieldMinBytes => { en: "Minimum size in bytes", zh: "最小字节数" },
    CpFieldKeepDays => { en: "Days to keep; empty for no limit", zh: "保留天数；空为不限" },
    CpFieldPriority => { en: "Priority (integer)", zh: "优先级（整数）" },
    CpErrMinSize => { en: "Minimum size must be a non-negative number of bytes", zh: "最小大小必须是非负字节数" },
    CpErrKeepDays => { en: "Days to keep must be a non-negative integer", zh: "保留天数必须是非负整数" },
    CpErrPriority => { en: "Priority must be an integer", zh: "优先级必须是整数" },
    CpDraftStale => { en: "The scan or configuration has changed: draft edits are kept, but a stale draft cannot be saved.", zh: "扫描或配置已改变：草案编辑输入已保留，但不可保存过期草案。" },
    CpStopRequested => { en: "Stop requested for the current cleanup: no further files will be cleaned; already-cleaned files are not restored. Wait for the execution report.", zh: "已请求停止当前清理：停止后续文件，不恢复已清理文件；请等待执行报告。" },
    CpAutoDisabledSaved => { en: "Automatic cleanup is now off and saved: this batch has been asked to stop after the current file; nothing cleaned is restored. Edit inputs are kept; their version is stale and cannot be saved.", zh: "全局自动清理已关闭并保存；当前批次已请求停止后续文件，不恢复已清理文件。编辑输入保留，旧版本不可保存。" },
    CpAutoDisableSaveFailed => { en: "This batch has been asked to stop, but turning off automatic cleanup failed to save: {e}; please try again.", zh: "当前批次已请求停止，但关闭自动清理未能保存：{e}；请重试关闭。" },
    CpSettingsNotSaved => { en: "The configuration is not writable or an operation is in progress; nothing was saved.", zh: "配置不可写或操作正在进行，未保存。" },
    CpSettingsSavedStale => { en: "Configuration saved. Edit inputs are kept, but the revision they opened is stale: saving will refuse the conflict. The old preview and AI response are invalidated.", zh: "配置已保存；编辑输入已保留，但其打开版本已过期，保存将拒绝冲突。旧预览和 AI 响应已失效。" },
    CpSettingsSavedInvalidate => { en: "Configuration saved; the old preview and AI response are invalidated. Please generate the preview again.", zh: "配置已保存；旧预览和 AI 响应已失效，请重新预览。" },
    CpSaveFailed => { en: "Saving failed; the in-memory configuration is unchanged: {e}", zh: "保存失败，内存配置未改变：{e}" },
    CpAuthorizeAndSave => { en: "Authorize and save", zh: "明确授权并保存" },
    CpSettingsChangedDuringConfirm => { en: "The configuration or scan changed during confirmation: nothing was saved; rule edit inputs are kept.", zh: "确认期间配置或扫描改变：未保存，规则编辑输入已保留。" },
    CpReloadedStale => { en: "Configuration reloaded. Rule edit inputs are kept, but their opened revision is stale. If reading failed, cleanup stays disabled and the original file is not overwritten.", zh: "已重新读取配置；规则编辑输入保留但打开版本已过期。读取失败时仍保持禁用，不覆盖原文件。" },
    CpVerifying => { en: "Verifying file metadata against rules in the background…", zh: "正在后台核对文件元数据与规则…" },
    CpAutoPlanIncomplete => { en: "The automatic plan is incomplete or the scan state changed; this round was skipped.", zh: "自动计划不完整或扫描状态改变，本轮未执行。" },
    CpPreviewDone => { en: "Preview ready: {n} candidate files; none selected by default.", zh: "预览完成：{n} 个候选文件；默认全不选。" },
    CpPreviewCancelled => { en: "Rule verification cancelled; automatic cleanup will not run this round.", zh: "已取消规则核对；本轮不执行自动清理。" },
    CpExecuteSummary => { en: "{n} files, {permanent} of them deleted permanently.\nMoving to the Trash does not free disk space right away; items can be restored manually and original paths are in the log. Finder’s “Put Back” may only return them to a quarantine folder, after which they must be moved back by the logged path; without “Put Back”, take the file out of the Trash under its original name.\nSizes are scan estimates.\n\n{details}", zh: "{n} 个文件，其中 {permanent} 个永久删除。\n移到回收站不会立即释放磁盘空间；可手动恢复，原路径见记录。Finder『放回』可能仅回到暂存目录，之后需按记录手动移回原位置；没有『放回』时从回收站取出原名文件。\n大小仅为扫描估计。\n\n{details}" },
    CpConfirmExecute => { en: "Clean up the selected preview files?", zh: "确认清理已选择的预览文件？" },
    CpContinue => { en: "Continue", zh: "继续" },
    CpPermanentWarning => { en: "Permanently deleting is unrecoverable", zh: "永久删除不可恢复" },
    CpConfirmPermanent => { en: "Permanently delete these files?", zh: "确认永久删除这些文件" },
    CpBusyLocked => { en: "Cleanup is running; configuration and scan switching are temporarily locked.", zh: "正在清理；配置和扫描切换已暂时锁定。" },
    CpExecuteResult => { en: "Finished {n} files, {failed} failed. Moving to the Trash is not the same as freeing space.\n{tail}", zh: "完成 {n} 个文件，失败 {failed} 个。移到回收站不等于已释放空间。\n{tail}" },
    CpFailEntry => { en: "{path}: {e}", zh: "{path}：{e}" },
    CpAuditError => { en: "\nAudit log error: {e}", zh: "\n审计记录错误：{e}" },
    CpEditorAlreadyOpen => { en: "A rule editor is already open; save or explicitly cancel first. Inputs will not be overwritten.", zh: "已有未关闭的规则编辑，请先保存或明确取消；不会覆盖输入。" },
    CpNewCacheRule => { en: "New cache rule", zh: "新缓存规则" },
    CpEditorConflict => { en: "Rule editor version conflict: the configuration changed, inputs are kept. Copy what you need, cancel the editor, and reopen the latest rule.", zh: "规则编辑版本冲突：配置已改变，输入已保留。请复制所需输入后取消编辑，并重新打开最新规则。" },
    CpDraftScanChanged => { en: "The draft’s scan or configuration has changed; please generate the draft again.", zh: "草案所属扫描或配置已改变，请重新生成草案。" },
    CpRuleInvalid => { en: "Rule validation failed: {e}", zh: "规则验证失败：{e}" },
    CpAutoRuleSummary => { en: "{name}\nScope: {scope}\nLocal cache/log whitelist only, at least 7 days kept, Trash only; the global switch authorizes separately.", zh: "{name}\n范围：{scope}\n仅本地缓存/日志白名单，至少保留 7 天，仅回收站；全局开关另行授权。" },
    CpAuthorizeSingleRule => { en: "Authorize automatic cleanup for this single rule?", zh: "授权此单条规则自动清理？" },
    CpAuthorizeSaveRule => { en: "Authorize and save this rule", zh: "授权并保存此规则" },
    CpConfirmChangedInputs => { en: "The configuration or edit inputs changed during confirmation: nothing was saved, inputs are kept.", zh: "确认期间配置或编辑输入改变：未保存，输入已保留。" },
    CpAiSavedNotice => { en: "AI configuration saved. For a new key, click “Save key” separately; an empty input never deletes the stored key.", zh: "AI 配置已保存。新密钥请单独点击『保存密钥』；空输入不会删除原密钥。" },
    CpKeyTargetUnsaved => { en: "The connection configuration is not saved yet: save the current endpoint, protocol and model before working with that target’s key.", zh: "连接配置尚未保存：请先保存当前地址、协议和模型，再操作该目标的密钥。" },
    CpDeleteKeyScope => { en: "Delete the credential only for this target: {scope}. Keys for other origins/protocols stay. An empty input never deletes a key.", zh: "仅删除以下目标的凭据：{scope}。其他 origin/协议的密钥保持不变。空输入不会删除密钥。" },
    CpConfirmDeleteKey => { en: "Delete the AI key for this target?", zh: "删除指定目标的 AI 密钥？" },
    CpDeleteTargetKey => { en: "Delete this target’s key", zh: "删除此目标密钥" },
    CpKeyTargetChanged => { en: "The credential target or configuration changed: deletion was cancelled; no other account was touched.", zh: "凭据目标或配置已改变：删除已取消，未操作其他账户。" },
    CpKeyEmpty => { en: "No new key entered; the stored key is unchanged.", zh: "未输入新密钥，原密钥保持不变。" },
    CpReason => { en: "{rule}: {reason}", zh: "{rule}：{reason}" },
    CpKeychainDoneStale => { en: "Keychain operation finished for target: {target}. The form has since changed; new inputs are kept, and this does not mean the new target is configured.", zh: "Keychain 操作已完成，目标：{target}；当前表单已改变，未清空新输入，也不代表新目标已配置。" },
    CpKeychainDeleted => { en: "Keychain key deleted for target: {target}.", zh: "Keychain 密钥已删除，目标：{target}。" },
    CpKeychainSaved => { en: "Key saved to the Keychain for target: {target}; input cleared.", zh: "密钥已保存到 Keychain，目标：{target}；输入已清空。" },
    CpKeychainFailed => { en: "Keychain operation failed: {e}", zh: "Keychain 操作失败：{e}" },
    CpAiConfigInvalid => { en: "The saved AI configuration is invalid: {e}", zh: "已保存的 AI 配置无效：{e}" },
    CpLocalLoopback => { en: "Local loopback service", zh: "本地回环服务" },
    CpTestExplain => { en: "Sends one fixed connectivity probe message to {target} (no scan data, paths or file contents) to check the endpoint, key and model. The test uses the saved configuration; if you just edited the form, save it first.", zh: "将向 {target} 发送一条固定的连通性探测消息（不含扫描数据、路径或文件内容），用于验证地址、密钥与模型可用性。测试使用已保存的配置；若刚修改表单请先保存。" },
    CpConfirmTest => { en: "Send the AI connectivity probe?", zh: "发送 AI 连接测试探测？" },
    CpSendProbe => { en: "Send probe", zh: "发送探测" },
    CpTestCancelled => { en: "Cancelled; no probe was sent.", zh: "已取消，未发送探测。" },
    CpTestFailed => { en: "AI connectivity test failed: {e}", zh: "AI 连接测试失败：{e}" },
    CpAiNotEnabled => { en: "Please give informed consent and enable AI first.", zh: "请先知情同意并启用 AI。" },
    CpAnalyzeExplain => { en: "Sends to: {target}\nProtocol: {protocol}; model: {model}\nScans {nodes} nodes; the summary holds at most 200 entries with sizes, file counts, local path classifications, sampled child types and recognized project markers, rule retention and risk. Filename evidence is not verified content; timestamps are not collected. No file contents are read, no scripts run, no cleanup performed.\nPaths: {paths}\nConsent is remembered for this service and sharing scope. Changing the service or sharing more data requires confirmation again. Once confirmed, a bounded metadata snapshot is built, then the summary is prepared in the background and sent. Cancelling discards the result; a request already sent cannot be recalled.", zh: "发送到：{target}\n协议：{protocol}；模型：{model}\n扫描 {nodes} 个节点，摘要最多 200 项，包含大小、文件数量、本地路径分类、子项类型样本、已知项目标记、规则保留信息与风险；名称证据不代表内容验证，未采集时间戳；不读取文件内容、不运行脚本、不执行清理。\n路径：{paths}\n将记住此服务及数据共享范围的隐私授权；更换服务或扩大共享范围时需重新确认。确认后构造有界元数据快照，再在后台准备摘要并发送，取消只丢弃结果，已发出的网络请求不能撤回。" },
    CpPathsFull => { en: "Full paths (may contain private information)", zh: "完整路径（可能包含私人信息）" },
    CpPathsOpaque => { en: "Opaque identifiers; known structure, type hints and project markers only", zh: "匿名标识；仅已知结构、类型提示和项目标记" },
    CpChatEvidence => { en: "Snapshot · {entries} items · {typed} type hints · {markers} project markers", zh: "快照证据 · {entries} 项 · {typed} 个类型提示 · {markers} 个项目标记" },
    CpChatEvidenceHint => { en: "Bounded metadata sample, not a complete inventory. Path classifications are guesses; filename markers and extensions are not content verification. No file contents or timestamps are collected. Start a new conversation after changing the scan or sharing settings.", zh: "有界元数据样本，并非完整清单。路径分类是推测；文件名标记和扩展名并非内容验证。不读取正文、不采集时间戳。扫描或共享设置改变后，请新建会话获取新证据。" },
    CpConfirmAnalyze => { en: "Send a metadata summary of this disk to the AI?", zh: "确认向 AI 发送当前磁盘元数据摘要？" },
    CpSendSummary => { en: "Agree and remember", zh: "同意并记住" },
    CpChatNew => { en: "New conversation", zh: "新建会话" },
    CpChatSearch => { en: "Search local conversations", zh: "搜索本机会话标题及全文" },
    CpChatHistory => { en: "Local history · up to 100 / 8 MiB", zh: "本机历史 · 最多 100 个 / 8 MiB" },
    CpChatSend => { en: "Send", zh: "发送" },
    CpChatInput => { en: "Ask a follow-up question…", zh: "输入问题，继续对话…" },
    CpChatPrivacy => { en: "Your input and recent complete messages in this conversation are sent to the configured service, with the sealed metadata snapshot. Other conversations are never uploaded. Inputs may contain sensitive information; history is stored locally. Send using the button (Enter does not send).", zh: "你的输入、当前会话最近的完整消息和封存元数据快照会发送给已配置的服务，不上传其他会话。输入可能包含敏感信息，历史保存在本机。请点击按钮发送（回车不会发送）。" },
    CpChatReadOnly => { en: "History is for local reading only. Sending starts a new conversation with a fresh snapshot; historical text is not forwarded.", zh: "历史仅供本机阅读。发送将使用新快照开始新会话，不转发历史文本。" },
    CpChatLimit => { en: "This conversation reached its message or storage limit (200 messages / 8 MiB, including reserved reply space). Start a new conversation; no message was truncated and your input has been kept.", zh: "当前会话已达到消息数或容量上限（200 条 / 8 MiB，含回复预留空间），请新建会话；不会截断消息，已保留输入。" },
    CpChatProposalLimit => { en: "The answer was kept, but rule proposals exceeded the local safety limit (20 rules / 64 KiB encoded) and were omitted. No actions are available for this response.", zh: "回答已保留，但规则建议超出本机安全上限（20 条 / JSON 编码 64 KiB），已省略；此回复不提供规则操作。" },
    CpChatConfirmComposition => { en: "Confirm the IME candidate before sending. Your input has been kept.", zh: "请先确认候选词再发送，已保留输入内容。" },
    CpChatDetailBounded => { en: "Status detail exceeded the display limit and was omitted.", zh: "状态详情超出展示限制，已省略。" },
    CpChatInputLimit => { en: "Input must be nonempty and at most 8192 bytes. Your input has been kept.", zh: "输入不能为空且最多 8192 字节，已保留输入内容。" },
    CpChatLoadFailed => { en: "History could not be loaded: {e}. The original file is untouched; automatic saving is disabled. New conversations remain available in memory.", zh: "历史载入失败：{e}。原文件未改动，已停止自动保存；仍可在内存中开始新对话。" },
    CpChatSaveFailed => { en: "History save failed: {e}. Messages remain in memory; retry saving.", zh: "历史保存失败：{e}。消息仍保留在内存中，请重试保存。" },
    CpChatRetrySave => { en: "Retry history save", zh: "重试保存历史" },
    CpChatDelete => { en: "Delete conversation", zh: "删除会话" },
    CpChatDeleteConfirm => { en: "Delete this local conversation?", zh: "确认删除此本机会话？" },
    CpChatAdopted => { en: "Adopted and enabled", zh: "已采纳并启用" },
    CpChatRejected => { en: "Rejected", zh: "已拒绝" },
    CpChatExpired => { en: "Expired · display only", zh: "已过期 · 仅展示" },
    CpChatPending => { en: "Pending review", zh: "待审核" },
    CpChatLoading => { en: "Loading local history…", zh: "正在载入本机历史…" },
    CpAiConversation => { en: "Current conversation", zh: "当前对话" },
    CpAiYou => { en: "You", zh: "你" },
    CpAiExplainRequest => { en: "Explain this item and its cleanup risks: {path}", zh: "请解释此项目的用途及清理风险：{path}" },
    CpAiAlreadyBusy => { en: "An AI request is already in progress. Wait for it or cancel it first.", zh: "已有 AI 请求正在处理，请等待或先取消当前请求。" },
    CpAiNotReady => { en: "Finish a scan first, or wait for cleanup, administrator reading or Keychain operations to finish.", zh: "请先完成扫描，或等待清理、管理员读取及 Keychain 操作结束。" },
    CpAiPreparing => { en: "Preparing a bounded read-only metadata snapshot. File contents are not read or sent.", zh: "正在准备有限的只读元数据快照，不读取或发送文件内容。" },
    CpAiWaitingResponse => { en: "Request sent. Waiting for the service response (up to 45 seconds; Keychain may request access). This connection is non-streaming, so the reply appears when complete.", zh: "请求处理中，等待服务回复（网络请求最多 45 秒；Keychain 可能要求授权）。当前使用非流式接口，回复完成后一次展示。" },
    CpAiPhaseConsent => { en: "Privacy confirmation", zh: "等待隐私确认" },
    CpAiPhasePreparing => { en: "Preparing summary", zh: "准备摘要" },
    CpAiPhaseWaiting => { en: "Waiting for reply", zh: "等待回复" },
    CpAiPhaseComplete => { en: "Reply received", zh: "回复完成" },
    CpAiPhaseFailed => { en: "Request failed", zh: "请求失败" },
    CpAiPhaseCancelled => { en: "Cancelled", zh: "已取消" },
    CpAiConsentCancelled => { en: "Privacy consent was cancelled. No metadata was sent.", zh: "已取消隐私确认，没有发送元数据。" },
    CpAiRequestChanged => { en: "The scan or configuration changed; this request was stopped and its result discarded. Requests already sent cannot be recalled.", zh: "扫描或配置发生变化，本次请求已停止并丢弃结果；已发出的请求无法撤回。" },
    CpAiSnapshotNotice => { en: "This reply uses a read-only snapshot. Live disk changes do not refresh it; verify current files before cleaning.", zh: "回复基于请求时的只读快照，磁盘后续变化不会更新此回复；清理前请核对当前文件。" },
    CpAiDraftsExpired => { en: "The disk changed while the request was running. Read-only advice is retained, but stale drafts cannot be adopted; generate them again.", zh: "请求期间磁盘发生变化。只读建议已保留，但过期草案不可采用，请重新生成。" },
    CpAiForgetConsent => { en: "Reset privacy consent", zh: "重置隐私授权" },
    CpAiConsentRevoked => { en: "Privacy consent has been revoked. The next AI request requires confirmation.", zh: "隐私授权已撤销，下次 AI 请求需重新确认。" },
    CpAiRevokeSaveFailed => { en: "Consent was revoked for this session, but saving failed: {e}. The revocation may not survive restart; fix the settings permissions first.", zh: "本次运行的隐私授权已撤销，但保存失败：{e}。重启后可能无法保留撤销状态，请先修复配置权限。" },
    CpAiConsentRemembered => { en: "Privacy consent remembered for this service and sharing scope", zh: "已记住此服务及数据共享范围的隐私授权" },
    CpWaitingConsent => { en: "Waiting for confirmation; the AI only advises and never adopts rules automatically.", zh: "等待确认；AI 仅提供建议，不会自动采用规则。" },
    CpAdvisoryNotice => { en: "The AI returned read-only advice. Drafts are disabled by default; after adopting them one by one, generate the preview again.", zh: "AI 返回只读建议。草案默认不启用，逐条采用后须重新预览。" },
    CpHistoryLoaded => { en: "Loaded the latest 200 records. Nothing is restored or deleted automatically.", zh: "已加载最近 200 条记录。不会自动恢复或删除暂存文件。" },
    CpHistoryFailed => { en: "Reading records failed: {e}", zh: "读取记录失败：{e}" },

    // ── Cleanup panel: tabs & buttons ──
    CpTabPreview => { en: "Cleanup preview", zh: "清理预览" },
    CpTabRules => { en: "Rules", zh: "规则管理" },
    CpTabAi => { en: "AI assistant", zh: "AI助手" },
    CpTabSettings => { en: "Settings & records", zh: "设置与记录" },
    CpBadSettings => { en: "Reading the configuration failed: {error}\nSaving, cleanup and AI are disabled; defaults will not overwrite the broken file.", zh: "配置读取失败：{error}\n保存、清理和 AI 已禁用，不会用默认值覆盖坏文件。" },
    CpReloadConfig => { en: "Reload configuration", zh: "重载配置" },
    CpStopCurrentCleanup => { en: "Stop current cleanup", zh: "停止当前清理" },
    CpDisableAutoNow => { en: "Turn off automatic cleanup", zh: "关闭自动清理" },
    CpPreviewIntro => { en: "Only ordinary files are candidates; verification runs in the background. The current preview copies the full scan tree, so large scans may briefly block the UI; files within scope are never truncated. A preview is not permission to delete; the Trash does not free space right away.", zh: "仅普通文件候选；核对在后台执行。当前预览需复制完整扫描树，大型扫描可能短暂阻塞界面；不会截断范围内文件。预览不是删除授权；回收站不会立即释放空间。" },
    CpRegenerate => { en: "Regenerate (cancels the old verification)", zh: "重新生成（取消旧核对）" },
    CpGeneratePreview => { en: "Generate cleanup preview", zh: "生成清理预览" },
    CpCancelVerify => { en: "Cancel verification", zh: "取消核对" },
    CpSelectSafe => { en: "Select all: Trash-only", zh: "选择全部：仅回收站" },
    CpClearSelection => { en: "Clear selection", zh: "清空选择" },
    CpConfirmCount => { en: "Confirm cleanup ({n})", zh: "确认清理（{n}）" },
    CpIntegrityNote => { en: "Scan integrity (not selectable): read errors {errors}; cloud-only {cloud}; unreadable folders {unreadable}; results out of date {stale}. Unknown space is not a cleanable file.", zh: "扫描完整性（不可选择）：读取错误 {errors}；云端未下载 {cloud}；不可读目录 {unreadable}；结果过期 {stale}。未知空间不作为可清理文件。" },
    CpRescanYes => { en: "Yes, rescan", zh: "是，请重新扫描" },
    CpNo => { en: "No", zh: "否" },
    CpNeedScanFirst => { en: "Finish a scan and generate a preview first. Rescan or refresh the scan to regenerate.", zh: "请先完成扫描并生成预览。扫描过期或更新后需重新生成。" },
    CpPreviewStale => { en: "The preview is stale; please generate it again.", zh: "预览已过期，请重新生成。" },
    CpRuleSummaryLine => { en: "{rule}: {n} items / {size}", zh: "{rule}：{n} 项 / {size}" },
    CpDiagnosticsTitle => { en: "{phase} diagnostics ({n} entries, not selectable)", zh: "{phase}诊断明细（{n} 条，不可选择）" },
    CpCollapse => { en: "Collapse", zh: "收起" },
    CpExpand => { en: "Expand", zh: "展开" },
    CpDiagError => { en: "Error: {e}", zh: "错误：{e}" },
    CpDiagProtected => { en: "Protected/blocked: {e}", zh: "保护/阻止：{e}" },
    CpDiagUnreadable => { en: "Unreadable: {path} ({n} errors)", zh: "不可读：{path}（{n} 个错误）" },
    CpDiagnosticsPage => { en: "Diagnostics page {page} / {pages}, up to 200 entries per page; none are selectable.", zh: "诊断第 {page} / {pages} 页，每页最多 200 条；所有诊断不可选择。" },
    CpDiagnosticsPrev => { en: "Previous diagnostics page", zh: "上一页诊断" },
    CpDiagnosticsNext => { en: "Next diagnostics page", zh: "下一页诊断" },
    CpBlockedSummary => { en: "{n} protected/blocked in total, {skipped} skipped (diagnostics may be truncated); shown by rule priority. Page {page} / {pages}, up to 200 entries per page.", zh: "保护/阻止共 {n} 项，跳过 {skipped} 项（诊断明细可能截断）；按规则优先级显示。第 {page} / {pages} 页，每页最多 200 项。" },
    CpSelected => { en: "Selected", zh: "已选择" },
    CpSelect => { en: "Select", zh: "选择" },
    CpRowMeta => { en: "{category} · {size} · priority {priority} · {action}", zh: "{category} · {size} · 优先级 {priority} · {action}" },
    CpExcludedProtected => { en: "Excluded & protected", zh: "排除并保护" },
    CpPrevPage => { en: "Previous page", zh: "上一页" },
    CpNextPage => { en: "Next page", zh: "下一页" },
    CpNewRule => { en: "New rule (disabled by default)", zh: "新增规则（默认停用）" },
    CpRulesIntro => { en: "Editing a built-in or AI rule turns it into a user rule; automatic authorization must be confirmed again. Disabling never deletes a rule.", zh: "修改内置或 AI 规则转为用户规则，自动授权重新确认；停用不会删除规则。" },
    CpRulesSubtitle => { en: "Find, review and organize your cleanup rules.", zh: "查找、审核与管理清理规则。" },
    CpRulesSearch => { en: "Search names, paths, patterns…", zh: "搜索名称、路径、匹配规则…" },
    CpRulesSearchLabel => { en: "Search rules", zh: "搜索规则" },
    CpRulesAll => { en: "All", zh: "全部" },
    CpRulesEnabled => { en: "Enabled", zh: "已启用" },
    CpRulesDisabled => { en: "Disabled", zh: "已停用" },
    CpRulesAutomatic => { en: "Auto-authorized", zh: "自动已授权" },
    CpRulesSource => { en: "Source", zh: "来源" },
    CpRulesCategory => { en: "Category", zh: "分类" },
    CpRulesAllSources => { en: "All sources", zh: "全部来源" },
    CpRulesAllCategories => { en: "All categories", zh: "全部分类" },
    CpRulesSort => { en: "Sort", zh: "排序" },
    CpRulesSortPriority => { en: "Priority: high to low", zh: "优先级：从高到低" },
    CpRulesSortName => { en: "Name", zh: "名称" },
    CpRulesSortStatus => { en: "Enabled first", zh: "已启用优先" },
    CpRulesReset => { en: "Reset filters", zh: "重置筛选" },
    CpRulesCount => { en: "{visible} of {total} rules", zh: "显示 {visible} / {total} 条规则" },
    CpRulesStats => { en: "{enabled} enabled · {automatic} auto-authorized", zh: "{enabled} 条已启用 · {automatic} 条自动已授权" },
    CpRulesColumnName => { en: "Rule / scope", zh: "规则 / 路径" },
    CpRulesColumnStatus => { en: "Status", zh: "状态" },
    CpRulesColumnPriority => { en: "Priority", zh: "优先级" },
    CpRulesEmpty => { en: "No rules yet", zh: "还没有规则" },
    CpRulesEmptyHint => { en: "Create a rule to get started. New rules are disabled by default.", zh: "新增一条规则开始管理，新规则默认停用。" },
    CpRulesNoMatch => { en: "No matching rules", zh: "没有匹配的规则" },
    CpRulesNoMatchHint => { en: "Try another keyword or reset the filters.", zh: "试试其他关键词，或重置筛选条件。" },
    CpRulesDetail => { en: "Rule details", zh: "规则详情" },
    CpRulesCloseDetail => { en: "Close details", zh: "关闭详情" },
    CpRulesMetadata => { en: "Identity & status", zh: "基本信息与状态" },
    CpRulesConditions => { en: "Match conditions", zh: "匹配条件" },
    CpRulesBehavior => { en: "Cleanup behavior", zh: "清理方式" },
    CpRulesId => { en: "Rule ID", zh: "规则 ID" },
    CpRulesNoDescription => { en: "No description", zh: "暂无描述" },
    CpRulesNoExcludes => { en: "No exclusions", zh: "无排除项" },
    CpRulesAutoHint => { en: "Per-rule authorization only; automatic cleanup also requires the global switch and a valid local scope.", zh: "这里只表示单规则授权；自动清理还需全局开关与有效的本地范围。" },
    CpRulesEditTitle => { en: "Edit rule", zh: "编辑规则" },
    CpRulesNewTitle => { en: "New rule", zh: "新增规则" },
    CpRulesEditingHint => { en: "Save or cancel this draft before changing another rule. Search and filtering remain available.", zh: "请先保存或取消当前编辑，再修改其他规则。搜索与筛选仍可使用。" },
    CpRulesEnableAction => { en: "Enable rule", zh: "启用规则" },
    CpRulesDisableAction => { en: "Disable rule", zh: "停用规则" },
    CpEditorHint => { en: "Rule editor · separate paths and excludes with semicolons (single line)", zh: "规则编辑 · 路径、排除项使用分号分隔（单行）" },
    CpEditorStaleWarning => { en: "The edited revision or draft is stale: inputs are kept, but the latest configuration cannot be overwritten. Copy what you need, explicitly cancel, then open the latest rule.", zh: "编辑版本或草案已过期：输入已保留，不能覆盖最新配置。请复制所需内容后明确取消，再打开最新规则。" },
    CpFieldName => { en: "Name", zh: "名称" },
    CpFieldScopePaths => { en: "Scope paths", zh: "范围路径" },
    CpFieldMatchGlobs => { en: "Match globs", zh: "匹配 glob" },
    CpFieldExcludeGlobsShort => { en: "Exclude globs", zh: "排除 glob" },
    CpFieldMinSize => { en: "Minimum size (bytes)", zh: "最小大小（字节）" },
    CpFieldKeepDaysShort => { en: "Days to keep", zh: "保留天数" },
    CpFieldPriorityShort => { en: "Priority", zh: "优先级" },
    CpRuleEnabled => { en: "Enabled", zh: "已启用" },
    CpRuleDisabled => { en: "Disabled (click to enable explicitly)", zh: "停用（点击显式启用）" },
    CpAutoPending => { en: "Auto: awaiting authorization", zh: "自动：待授权" },
    CpAutoOff => { en: "Auto: off", zh: "自动：关闭" },
    CpSaveRule => { en: "Validate and save rule", zh: "验证并保存规则" },
    CpCancelEdit => { en: "Cancel editing", zh: "取消编辑" },
    CpNoLimit => { en: "no limit", zh: "不限" },
    CpAuthorized => { en: "authorized", zh: "已授权" },
    CpOff => { en: "off", zh: "关闭" },
    CpEdit => { en: "Edit", zh: "编辑" },
    CpDeleteRule => { en: "Delete rule", zh: "删除规则" },
    CpConfirmDeleteRule => { en: "Delete this rule?", zh: "删除这条规则？" },
    CpDeleteRuleNote => { en: "Only the rule is removed from the configuration; no files are deleted.", zh: "只删除配置中的规则，不删除任何文件。" },
    CpCurrentKeyTarget => { en: "Current credential target: {scope} (this origin + protocol only; keys are not reused after switching)", zh: "当前凭据目标：{scope}（仅此 origin + 协议；切换后不复用旧 key）" },
    CpKeyTargetUnavailable => { en: "The credential target is unavailable: {e}", zh: "当前凭据目标不可用：{e}" },
    CpAiIntro => { en: "The AI receives sizes, file counts, local classifications, sampled child types and recognized project markers — never file contents or timestamps. Hidden paths conceal application and project names, so exact ownership may remain unknown. Samples and classifications are not deletion authorization.", zh: "AI 接收大小、文件数量、本地分类、子项类型样本与已知项目标记，不读取正文、不采集时间戳。隐藏路径会隐藏应用和项目名称，可能无法确定具体归属。样本与分类不是删除授权。" },
    CpAiSubtitle => { en: "Understand your disk. Make room with confidence.", zh: "看懂磁盘占用，让每一次清理更有把握。" },
    CpAiService => { en: "Service configuration", zh: "服务配置" },
    CpAiServiceHint => { en: "Save the endpoint and model before storing a key or enabling AI.", zh: "先保存服务地址和模型，再保存密钥并授权启用。" },
    CpAiProtocol => { en: "API protocol", zh: "接口协议" },
    CpAiKeyHint => { en: "Stored in macOS Keychain only. Switching the origin or protocol never reuses a key.", zh: "密钥仅存入 macOS 钥匙串，切换服务来源或协议不会复用旧密钥。" },
    CpAiStatusOff => { en: "Not enabled", zh: "未启用" },
    CpAiStatusReady => { en: "Enabled", zh: "已启用" },
    CpAiStatusBusy => { en: "Working", zh: "处理中" },
    CpAiActions => { en: "What would you like to explore?", zh: "想先了解什么？" },
    CpAiAnalyzeHint => { en: "Find what takes up space and where to start.", zh: "梳理空间占用，找到值得优先清理的地方。" },
    CpAiExplainHint => { en: "Understand the selected item and its cleanup risks.", zh: "了解当前文件或目录的用途与清理风险。" },
    CpAiDraftsHint => { en: "Create suggestions to review, never automatic deletions.", zh: "生成可逐条审核的规则，不会自动删除文件。" },
    CpAiPathsHidden => { en: "Paths hidden", zh: "路径已隐藏" },
    CpAiPathsShared => { en: "Full paths shared", zh: "发送完整路径" },
    CpAiThinking => { en: "Deep thinking", zh: "深度思考" },
    CpAiThinkingHint => { en: "Include the protocol's thinking/reasoning option in requests.", zh: "请求中附带当前协议的 thinking/reasoning 选项。" },
    CpAiResults => { en: "Assistant insights", zh: "助手建议" },
    CpAiResultLabel => { en: "Analysis", zh: "分析结果" },
    CpAiEmptyTitle => { en: "A little clarity before you clean", zh: "清理之前，先心中有数" },
    CpAiEmptyHint => { en: "Choose an action above. Your analysis and rule drafts will appear here.", zh: "选择上方操作，分析结果与规则草案会显示在这里。" },
    CpAiSetupHint => { en: "Configure your AI service below, then explicitly enable it to get started.", zh: "在下方配置 AI 服务，并明确授权启用后即可开始。" },
    CpAiScanHint => { en: "Scan a disk or folder first to give the assistant something to analyze.", zh: "请先扫描磁盘或文件夹，再让助手分析扫描结果。" },
    CpAiBusyTitle => { en: "Preparing your insights…", zh: "正在整理建议…" },
    CpAiBusyHint => { en: "After your confirmation, the assistant analyzes a metadata summary. A sent request cannot be recalled.", zh: "确认后，助手将分析元数据摘要。已发送的请求无法撤回。" },
    CpAiReviewDrafts => { en: "Rule drafts to review · {count}", zh: "待审核规则 · {count} 条" },
    CpAiDraftScope => { en: "Scope", zh: "适用路径" },
    CpAiDraftPattern => { en: "Match pattern", zh: "匹配规则" },
    CpAiDraftRetention => { en: "Keep {days} days", zh: "保留 {days} 天" },
    CpAiDraftSafety => { en: "Caches may need rebuilding. Drafts stay disabled by default; adoption is Trash-only with automatic cleanup off. Preview before cleaning.", zh: "缓存可能需要重建。草案默认停用；采用后仅移入回收站、关闭自动清理，清理前必须先预览。" },
    CpAiAdvisory => { en: "Suggestions only · nothing is deleted without your review", zh: "仅提供建议 · 未经审核不会删除文件" },
    CpAiSaved => { en: "Saved", zh: "已保存" },
    CpAiUnsaved => { en: "Unsaved changes", zh: "有未保存的修改" },
    CpFieldEndpoint => { en: "Endpoint (save before enabling)", zh: "服务地址（填写后先保存，再授权启用）" },
    CpFieldModelShort => { en: "Model", zh: "模型" },
    CpFieldApiKey => { en: "API key (Keychain only; never in config or logs)", zh: "API key（仅 Keychain，不进配置和日志）" },
    CpSaveAiConfig => { en: "Save AI configuration", zh: "保存 AI 配置" },
    CpKeychainBusy => { en: "Keychain operation in progress…", zh: "Keychain 操作中…" },
    CpSaveKey => { en: "Save key", zh: "保存密钥" },
    CpDeleteKey => { en: "Delete key explicitly", zh: "明确删除密钥" },
    CpTesting => { en: "Testing connection…", zh: "连接测试中…" },
    CpTestConnection => { en: "Test connection", zh: "测试连接" },
    CpAiEnabled => { en: "AI enabled (click to turn off)", zh: "AI 已启用（点击关闭）" },
    CpAiConsent => { en: "Informed consent and enable AI", zh: "知情同意并启用 AI" },
    CpAiEnabledExplain => { en: "Disk metadata will be sent to {target}, model {model}, protocol {protocol}. Paths: {paths}. File contents are never sent. Privacy consent is remembered; changing the service or sharing more data requires consent again. Turning AI off revokes consent.", zh: "磁盘元数据会发送到 {target}，模型 {model}，协议 {protocol}。路径：{paths}。不发送文件内容。隐私同意会被记住；更换服务或扩大数据共享范围时需重新确认。关闭 AI 将撤销授权。" },
    CpConsentSendMetadata => { en: "Consent to sending metadata to the named AI service?", zh: "同意向指定 AI 服务发送元数据？" },
    CpAllowFullPaths => { en: "Allow sending full paths?", zh: "允许发送完整路径？" },
    CpFullPathsExplain => { en: "Full paths can help identify the application or project, but may contain your user name, project names or private information and will be sent to the configured endpoint. Hidden paths still share coarse type hints and recognized project markers. Opaque is the safer default; credential paths stay redacted in either mode.", zh: "完整路径有助于识别具体应用或项目，但可能包含用户名、项目名和私人信息，将发送到指定服务。隐藏路径仍共享粗粒度类型提示和已知项目标记。默认匿名模式更安全；两种模式都会隐藏凭据路径。" },
    CpAnalyzeDisk => { en: "Analyze this disk", zh: "分析当前磁盘" },
    CpExplainSelection => { en: "Explain the current selection", zh: "解释当前选中项" },
    CpGenerateDrafts => { en: "Generate rule drafts", zh: "生成规则草案" },
    CpCancelDiscard => { en: "Cancel (discard result)", zh: "取消（丢弃结果）" },
    CpClearSuggestions => { en: "Clear AI suggestions", zh: "清空 AI 建议" },
    CpResultCancelled => { en: "The result was cancelled; a request already sent cannot be recalled.", zh: "结果已取消；已发出的网络请求不能撤回。" },
    CpDraftNoLimit => { en: "no limit (high risk)", zh: "不限（高风险）" },
    CpAdoptDisabled => { en: "Adopt (keep disabled)", zh: "采用（保持停用）" },
    CpAdoptEnable => { en: "Adopt and enable", zh: "采纳并启用" },
    CpEditAsUserRule => { en: "Edit as user rule", zh: "编辑为用户规则" },
    CpReject => { en: "Reject", zh: "拒绝" },
    CpAutoIntro => { en: "Automatic cleanup only checks while this app is running with scan results available, once every 60 seconds; after launch or a configuration change it waits at least the configured interval. At most 200 files per round, and both the global switch and per-rule authorization are required.", zh: "自动清理仅在本应用运行且扫描结果可用时检查，每 60 秒检查一次；启动或更新配置后至少等待配置间隔。每轮最多 200 个文件，且需全局与单规则双授权。" },
    CpAutoInterval => { en: "Automatic cleanup interval (minutes)", zh: "自动清理间隔（分钟）" },
    CpSaveInterval => { en: "Save interval", zh: "保存间隔" },
    CpBadInterval => { en: "The interval must be an integer between 1 and 10080 minutes.", zh: "间隔必须是 1–10080 分钟的整数。" },
    CpGlobalAutoOn => { en: "Global auto: on (click to turn off)", zh: "全局自动：开启（点击关闭）" },
    CpGlobalAutoOff => { en: "Global auto: off (click to authorize)", zh: "全局自动：关闭（点击授权）" },
    CpConfirmGlobalAuto => { en: "Authorize automatic cleanup while the app is running?", zh: "授权应用运行期间自动清理？" },
    CpGlobalAutoExplain => { en: "Only rules authorized per-rule and matching the local whitelist, keeping at least 7 days, Trash only. Nothing is cleaned immediately; it waits for the configured interval. At most 200 files per round, and no system background service is installed.", zh: "仅已逐条授权且符合本地白名单的规则，至少保留 7 天，仅移到回收站。不会立即清理，将等待配置间隔；每轮最多 200 个文件，不安装系统后台任务。" },
    CpDefaultAction => { en: "Default for new user rules: {action}", zh: "新用户规则默认：{action}" },
    CpWhitelistLabel => { en: "Protection whitelist (paths and their children are never cleaned)", zh: "保护白名单（路径及其子项不会清理）" },
    CpAddWhitelist => { en: "Add protected path", zh: "添加保护路径" },
    CpNeedConcretePath => { en: "Please enter at least one concrete path.", zh: "请输入至少一个具体路径。" },
    CpRemoveProtection => { en: "Remove protection", zh: "移除保护" },
    CpConfirmRemoveProtection => { en: "Remove cleanup protection for this path?", zh: "移除此路径的清理保护？" },
    CpLoadingHistory => { en: "Loading records…", zh: "读取记录中…" },
    CpLoadHistory => { en: "Load recent records", zh: "加载最近记录" },
    CpHistoryIntro => { en: "The Trash keeps original file names. Finder’s “Put Back” may first restore into a quarantine folder, after which the logged original path is needed to move them back by hand; without “Put Back”, take the file out of the Trash under its original name and move it back yourself. Successful records hold the restore path for locating the quarantine; failed stashes are for inspection only, and this app never restores automatically.", zh: "回收站保留原文件名。Finder『放回』可能先恢复到安全隔离暂存目录，再需按记录的原路径手动移回；若没有『放回』，请从回收站取出原名文件并手动移回。成功记录的恢复路径用于定位暂存；失败暂存也仅供检查，本应用不会自动恢复。" },
    CpHistoryRow => { en: "{status} · {action} · time {time} (Unix seconds) · {mode}", zh: "{status} · {action} · 时间 {time}（Unix 秒） · {mode}" },
    CpHistoryAuto => { en: "auto", zh: "自动" },
    CpHistoryManual => { en: "manual", zh: "手动" },
    CpCopyOriginalPath => { en: "Copy original path", zh: "复制原路径" },
    CpRestoreReference => { en: "Stash/restore reference path: {copy}", zh: "暂存/恢复参考路径：{copy}" },
    CpCopyStashPath => { en: "Copy stash path", zh: "复制暂存路径" },

    // ── Settings: language ──
    CpLanguage => { en: "Language", zh: "语言" },
    CpLanguageTip => { en: "Takes effect at once: the interface redraws in the chosen language.", zh: "立即生效，界面将以所选语言重新绘制。" },

    // ── Agent (AI client) errors ──
    AgChatHistoryInvalidShape => { en: "Chat history must contain complete user/assistant pairs and end with a user message", zh: "对话历史必须包含完整的用户/助手消息对，并以用户消息结束" },
    AgChatHistoryInvalidOrder => { en: "Chat history must alternate user and assistant, starting and ending with user", zh: "对话历史必须按用户和助手交替排列，并以用户消息开始和结束" },
    AgChatHistoryInvalidMessage => { en: "Chat message is blank, too large, or contains forbidden control characters", zh: "对话消息为空白、过大或包含禁止的控制字符" },
    AgChatHistoryEncode => { en: "Could not encode chat history", zh: "无法编码对话历史" },
    AgChatHistoryEncodeBlock => { en: "Could not encode conversation block", zh: "无法编码对话内容块" },
    AgChatHistoryBudget => { en: "Current chat input exceeds the transcript budget", zh: "当前对话输入超过对话记录的大小限制" },
    AgAssistantBlank => { en: "Assistant explanation must not be blank", zh: "助手说明不能为空白" },
    AgAssistantTextBudget => { en: "Assistant explanation exceeds the 60 KiB history budget", zh: "助手说明超过历史记录的 60 KiB 大小限制" },
    AgAssistantControlChars => { en: "Assistant explanation contains forbidden control characters", zh: "助手说明包含禁止的控制字符" },
    AgLocalNoRemoteKeychain => { en: "Local services do not use remote Keychain credentials", zh: "本地服务不使用远程 Keychain 凭据" },
    AgModelInvalid => { en: "The model name must not be empty, contain control characters, or exceed 200 bytes", zh: "模型名称不能为空、包含控制字符或超过 200 字节" },
    AgSummaryCancelled => { en: "AI summary cancelled", zh: "AI 摘要已取消" },
    AgNoScanResults => { en: "No scan results are available", zh: "当前没有可用的扫描结果" },
    AgSelectionInvalid => { en: "The selected node hint is invalid, unattached, beyond the depth limit, or inconsistent with the request path", zh: "选中节点提示无效、未附着、超过深度限制或与请求路径不一致" },
    AgEncodeSummary => { en: "Could not encode the scan summary", zh: "无法编码扫描摘要" },
    AgEncodeBoundedSummary => { en: "Could not encode the bounded scan summary", zh: "无法编码有限扫描摘要" },
    AgEndpointInvalid => { en: "Invalid AI service address", zh: "AI 服务地址无效" },
    AgEndpointNotHttpsUrl => { en: "The AI service address must be a valid HTTPS URL", zh: "AI 服务地址必须是有效的 HTTPS URL" },
    AgEndpointScheme => { en: "The address only allows HTTPS, or HTTP to localhost/127.0.0.1/[::1], and must not contain credentials, a query, or a fragment", zh: "服务地址仅允许 HTTPS 或 HTTP localhost/127.0.0.1/[::1]，不得含凭据、查询或片段" },
    AgEndpointProtocolMismatch => { en: "The service endpoint does not match the selected protocol", zh: "服务 endpoint 与所选协议不一致" },
    AgKeyInvalid => { en: "Invalid API key format", zh: "API key 格式无效" },
    AgEncodeContext => { en: "Could not encode the AI context", zh: "无法编码 AI 上下文" },
    AgContextTooLarge => { en: "The AI context is too large", zh: "AI 上下文过大" },
    AgNoTextResult => { en: "The service returned no text result", zh: "服务未返回文本结果" },
    AgNotFullyFinished => { en: "The service result did not finish completely or requested tools; rejected", zh: "服务结果未完整结束或请求了工具，已拒绝" },
    AgToolCallsForbidden => { en: "AI tool calls are not allowed", zh: "不允许 AI 工具调用" },
    AgResponsesUnfinished => { en: "The Responses result did not finish completely", zh: "Responses 结果未完整结束" },
    AgResponsesInvalidOutput => { en: "Invalid Responses output format", zh: "Responses 输出格式无效" },
    AgResponsesNonText => { en: "The Responses result contains non-text or tool output; rejected", zh: "Responses 包含非文本或工具输出，已拒绝" },
    AgAnthropicUnfinished => { en: "The Anthropic result did not finish completely or requested tools; rejected", zh: "Anthropic 结果未完整结束或请求了工具，已拒绝" },
    AgAnthropicInvalidOutput => { en: "Invalid Anthropic output format", zh: "Anthropic 输出格式无效" },
    AgAnthropicNonText => { en: "The Anthropic result contains non-text or tool output; rejected", zh: "Anthropic 包含非文本或工具输出，已拒绝" },
    AgTextEmptyOrTooLarge => { en: "The AI text is empty or exceeds the 64 KiB limit", zh: "AI 文本为空或超过 64 KiB 限制" },
    AgNetworkDisabled => { en: "AI network access is off by default; enable it explicitly in Settings first", zh: "AI 网络访问默认关闭，请先在设置中明确启用" },
    AgContextMismatch => { en: "The AI request does not match the scan context; generate the summary again", zh: "AI 请求与扫描上下文不匹配，请重新生成摘要" },
    AgContextModified => { en: "The scan context was modified; generate the summary again", zh: "扫描上下文被修改，请重新生成摘要" },
    AgRemoteNeedsKeychain => { en: "The remote AI service needs its API key saved to the Keychain first", zh: "远程 AI 服务需要先将 API key 保存到 Keychain" },
    AgResponseTooLarge => { en: "The AI response exceeds the 2 MiB limit", zh: "AI 响应超过 2 MiB 限制" },
    AgReadTimeout => { en: "Reading the AI response timed out (45 s per request)", zh: "AI 响应读取超时（请求限 45 秒）" },
    AgReadTruncated => { en: "The AI response was cut off early; check the service status", zh: "AI 响应被提前截断，请检查服务状态" },
    AgReadInterrupted => { en: "The AI response transfer was interrupted; check the network or service status", zh: "AI 响应传输中断，请检查网络或服务状态" },
    AgInvalidJson => { en: "The AI service returned invalid JSON", zh: "AI 服务返回了无效 JSON" },
    AgCredentialEcho => { en: "The service response echoes sensitive credentials; not shown", zh: "服务响应包含敏感凭据，已拒绝显示" },
    AgProbeUnreachable => { en: "The service returned HTTP 200 but without the expected result structure; check that the endpoint matches the protocol", zh: "服务返回 HTTP 200 但缺少预期的结果结构，请确认 endpoint 与协议匹配" },
    AgProbeOk => { en: "AI connection test succeeded: {protocol} (model {model}), {elapsed} s. The address, key and response structure all work.", zh: "AI 连接测试成功：{protocol}（模型 {model}），耗时 {elapsed} s；地址、密钥与响应结构均可用。" },
    AgFenceInvalid => { en: "Invalid rule JSON fence", zh: "规则 JSON 围栏无效" },
    AgFenceOnlyJson => { en: "Only JSON fences are allowed", zh: "仅允许 JSON 围栏" },
    AgFenceUnclosed => { en: "The rule JSON fence is not closed", zh: "规则 JSON 围栏未闭合" },
    AgDraftTooLarge => { en: "The rules JSON exceeds the 64 KiB limit", zh: "规则 JSON 超过 64 KiB 限制" },
    AgDraftEnvelopeInvalid => { en: "The rule drafts must be a strict JSON object without extra fields", zh: "规则草案必须是严格 JSON 对象，且不能有额外字段" },
    AgDraftLimit => { en: "The rule drafts exceed the text or 20-rule limit", zh: "规则草案超过文本或 20 条规则限制" },
    AgDraftDuplicateField => { en: "The rules contain duplicate JSON fields", zh: "规则包含重复 JSON 字段" },
    AgDraftFieldInvalid => { en: "A field is missing, mistyped, or forbidden", zh: "字段缺失、类型错误或含禁止字段" },
    AgDraftRejected => { en: "\nDraft {n} rejected: {e}.", zh: "\n第 {n} 条草案已拒绝：{e}。" },
    AgDraftNoneValid => { en: "\nNo usable rule drafts to review; no rules were created or enabled.", zh: "\n没有可供审核的有效规则草案；未创建或启用任何规则。" },
    AgDraftDisclaimer => { en: "\nThe rules above are disabled drafts only; review and explicitly enable each one; nothing is cleaned automatically.", zh: "\n以上规则仅为禁用状态的草案，必须逐条审核并明确启用；不会自动清理。" },
    AgDraftOutOfBounds => { en: "A field length, count, or value is out of bounds", zh: "字段长度、数量或数值超限" },
    AgDraftControlChars => { en: "A field contains control characters", zh: "字段包含控制字符" },
    AgDraftUnsafePattern => { en: "A match expression reaches outside paths or sensitive targets", zh: "匹配表达式含越界路径或敏感目标" },
    AgDraftUnsafeRoot => { en: "References a root outside the context or an unsafe one", zh: "引用了上下文外或不安全的根目录" },
    AgDraftValidationFailed => { en: "Failed the local rule safety validation", zh: "未通过本地规则安全验证" },
    AgStageConnect => { en: "creating the connection", zh: "创建连接" },
    AgStageSend => { en: "sending the request", zh: "发送请求" },
    AgTransportTimeout => { en: "timed out: 5 s to connect, 45 s per request", zh: "超时：连接限 5 秒、请求限 45 秒" },
    AgTransportConnect => { en: "connection failed: check DNS, the service port, the TLS certificate and the network; environment proxies are not used", zh: "连接失败：请检查 DNS、服务端口、TLS 证书和网络；不使用环境代理" },
    AgTransportBuilder => { en: "the request could not be built: check the address and the auth header format", zh: "请求构建失败：请检查地址及认证头格式" },
    AgTransportBody => { en: "the response failed to transfer or decode", zh: "响应传输或解码失败" },
    AgTransportOther => { en: "transfer failed: check the service and the network", zh: "传输失败：请检查服务及网络" },
    AgTransportFail => { en: "AI {stage} failed: {reason}", zh: "AI {stage}失败：{reason}" },
    AgHttpStatusFail => { en: "AI request failed (HTTP {status}): {hint}", zh: "AI 请求失败（HTTP {status}）：{hint}" },
    AgHttpRedirect => { en: "service redirects are forbidden; configure the final HTTPS endpoint directly", zh: "服务重定向被禁止，请直接配置最终 HTTPS endpoint" },
    AgHttpParams => { en: "incompatible request parameters: check the protocol, model name and endpoint", zh: "请求参数不兼容，请检查协议、模型名称与 endpoint" },
    AgHttp401 => { en: "authentication failed: save the API key again for this service and protocol", zh: "认证失败，请为当前服务和协议重新保存 API key" },
    AgHttp403 => { en: "access denied by the service: check the key's permissions and the model's authorization", zh: "服务拒绝访问，请检查 key 权限与模型授权" },
    AgHttp404 => { en: "the endpoint or model does not exist: check the protocol and base URL", zh: "endpoint 或模型不存在，请检查协议和 base URL" },
    AgHttpTimeout => { en: "the service timed out; try again later", zh: "服务端超时，请稍后重试" },
    AgHttpTooLarge => { en: "the service considers the context too large; narrow the scan scope", zh: "服务认为上下文过大，请缩小扫描范围" },
    AgHttpRateLimited => { en: "the gateway or model is rate limiting or out of quota; check quota and concurrency, and avoid repeated probes", zh: "网关或模型限流、容量不足或额度耗尽；请检查配额与并发，避免连续测试" },
    AgHttpQuota => { en: "The service reports insufficient quota or a billing limit; waiting alone may not help.", zh: "服务明确报告额度不足或达到计费上限；仅等待可能无法恢复。" },
    AgHttpThrottle => { en: "The service reports a request/token rate limit; reduce concurrency and retry later.", zh: "服务明确报告请求或 token 速率限制；请降低并发并稍后重试。" },
    AgHttpCapacity => { en: "The service reports model overload; try later or use another authorized model.", zh: "服务明确报告模型容量过载；请稍后重试或切换其他已授权模型。" },
    AgHttpRetryAfter => { en: "Retry-After: wait at least {seconds} seconds. No automatic retry was made.", zh: "Retry-After：请至少等待 {seconds} 秒，本次未自动重试。" },
    AgHttpRequestId => { en: "Request ID: {id}", zh: "请求 ID：{id}" },
    AgHttpDiagnosticSaved => { en: "Safe diagnostic saved to ai-diagnostics.jsonl (no keys or raw payloads).", zh: "安全诊断已保存至 ai-diagnostics.jsonl（不记录密钥或原始正文）。" },
    AgHttpDiagnosticFailed => { en: "The local diagnostic log could not be written; safe details may be available in the process output.", zh: "本地诊断日志写入失败；进程输出中可能仍有安全诊断信息。" },
    AgHttpServerError => { en: "the service had an internal error: retry later or check that the service is running", zh: "服务端异常，请稍后重试或检查服务运行状态" },
    AgHttpOther => { en: "check the service configuration; the service's raw response is hidden to protect credentials", zh: "请检查服务配置；为保护凭据未显示服务原始响应" },

    // ── Keychain credentials ──
    CrScopeInvalid => { en: "The credential scope must be generated by AgentConfig::credential_scope", zh: "凭据 scope 必须由 AgentConfig::credential_scope 生成" },
    CrScopeProtocolInvalid => { en: "Invalid credential protocol scope", zh: "凭据协议 scope 无效" },
    CrOriginInvalid => { en: "Invalid credential origin", zh: "凭据 origin 无效" },
    CrScopeNotHttps => { en: "The credential scope must be a normalized HTTPS origin and protocol", zh: "凭据 scope 必须是规范化的 HTTPS origin 与协议" },
    CrKeyEncodedInvalid => { en: "Invalid API key encoding in the Keychain", zh: "Keychain 中的 API key 编码无效" },
    CrReadFailed => { en: "Could not read the Keychain (error {code})", zh: "无法读取 Keychain（错误码 {code}）" },
    CrSaveFailed => { en: "Could not save to the Keychain (error {code})", zh: "无法保存 Keychain（错误码 {code}）" },
    CrDeleteFailed => { en: "Could not delete from the Keychain (error {code})", zh: "无法删除 Keychain（错误码 {code}）" },
    CrKeyFormatInvalid => { en: "The API key must be a non-empty, whitespace-free ASCII string of at most 4096 bytes", zh: "API key 必须是非空、无空白的 ASCII 字符串，且不超过 4096 字节" },

    // ── Administrator helper ──
    AdCancelled => { en: "cancelled", zh: "已取消" },
    AdHelperNoStart => { en: "the administrator helper didn't start", zh: "管理员辅助进程未能启动" },
    AdHelperUnexpected => { en: "the administrator helper sent something unexpected", zh: "管理员辅助进程返回了意外数据" },
    AdHelperStoppedEarly => { en: "the administrator helper stopped early", zh: "管理员辅助进程提前终止" },
    AdNotGranted => { en: "macOS didn't grant administrator rights (error {status})", zh: "macOS 未授予管理员权限（错误码 {status}）" },
    AdHelperStartFailed => { en: "couldn't start the administrator helper (error {status})", zh: "无法启动管理员辅助进程（错误码 {status}）" },
    AdJobReadFailed => { en: "couldn't read the job: {error}", zh: "无法读取任务：{error}" },
    AdNotAPetalJob => { en: "not a Petal job", zh: "不是 Petal 任务" },
    AdNotAVolume => { en: "“{device}” isn't a volume", zh: "“{device}”不是卷" },
    AdTmOnly => { en: "only Time Machine snapshots are deleted", zh: "仅删除时间机器快照" },
    AdDiskutilFailed => { en: "diskutil failed", zh: "diskutil 执行失败" },
    AdCountOutOfRange => { en: "count out of range", zh: "计数超出范围" },
    AdStringTooLong => { en: "string too long", zh: "字符串过长" },
    AdNotUtf8 => { en: "not UTF-8", zh: "非 UTF-8 编码" },
    AdUnknownJob => { en: "unknown job", zh: "未知任务" },
    AdUnknownKind => { en: "unknown kind", zh: "未知类型" },
    AdUnknownResult => { en: "unknown result", zh: "未知结果" },

    // ── Findings (titles & blurbs; the English strings double as stable IDs) ──
    FdTitleTrash => { en: "Trash", zh: "废纸篓" },
    FdTitleDownloads => { en: "Downloads", zh: "下载" },
    FdTitleXcodeBuild => { en: "Xcode build files", zh: "Xcode 构建文件" },
    FdTitleXcodeArchives => { en: "Xcode archives", zh: "Xcode 归档" },
    FdTitleDeviceSupport => { en: "iOS device support", zh: "iOS 设备支持文件" },
    FdTitleSimulators => { en: "iOS simulators", zh: "iOS 模拟器" },
    FdTitleDeviceBackups => { en: "iPhone & iPad backups", zh: "iPhone 与 iPad 备份" },
    FdTitleDockerImage => { en: "Docker disk image", zh: "Docker 磁盘镜像" },
    FdTitleOllamaModels => { en: "Ollama models", zh: "Ollama 模型" },
    FdTitleLmStudioModels => { en: "LM Studio models", zh: "LM Studio 模型" },
    FdTitleHuggingFaceModels => { en: "Hugging Face models", zh: "Hugging Face 模型" },
    FdTitleAppCaches => { en: "App caches", zh: "应用缓存" },
    FdTitleHomebrewDownloads => { en: "Homebrew downloads", zh: "Homebrew 下载缓存" },
    FdTitleNpmCache => { en: "npm cache", zh: "npm 缓存" },
    FdTitlePnpmStore => { en: "pnpm store", zh: "pnpm 存储库" },
    FdTitleCargoRegistry => { en: "Cargo registry", zh: "Cargo 注册表缓存" },
    FdTitleGradleCaches => { en: "Gradle caches", zh: "Gradle 缓存" },
    FdTitleMovies => { en: "Movies", zh: "影片" },
    FdTitleChromeLeftovers => { en: "Chrome update leftovers", zh: "Chrome 更新残留" },
    FdTitleMail => { en: "Mail", zh: "邮件" },
    FdTitleClaudeHistory => { en: "Claude Code history", zh: "Claude Code 历史" },
    FdTitleCodexHistory => { en: "Codex history", zh: "Codex 历史" },
    FdTitleNodeModules => { en: "node_modules", zh: "node_modules" },
    FdTitleCargoBuild => { en: "Cargo build files", zh: "Cargo 构建产物" },
    FdTitleGitData => { en: "Unpacked Git data", zh: "Git 松散对象" },
    FdBlurbTrash => { en: "Emptying the Trash frees this space", zh: "清空废纸篓即可释放这些空间" },
    FdBlurbDownloads => { en: "Old installers and archives tend to pile up here", zh: "旧安装包和压缩文件容易堆积在这里" },
    FdBlurbXcodeBuild => { en: "Xcode rebuilds these when you next build", zh: "下次构建时 Xcode 会重新生成" },
    FdBlurbXcodeArchives => { en: "Keep the ones you need to symbolicate crash logs", zh: "如需符号化崩溃日志，请保留对应归档" },
    FdBlurbDeviceSupport => { en: "Re-downloaded when a device next connects", zh: "设备下次连接时会重新下载" },
    FdBlurbSimulators => { en: "Remove old ones with `xcrun simctl delete unavailable`", zh: "用 `xcrun simctl delete unavailable` 清理旧模拟器" },
    FdBlurbDeviceBackups => { en: "Old device backups; manage them in Finder", zh: "旧设备备份；可在访达中管理" },
    FdBlurbDockerImage => { en: "Images, containers and volumes; `docker system prune` or Docker's settings shrink it", zh: "镜像、容器和数据卷；用 `docker system prune` 或 Docker 设置来缩减" },
    FdBlurbOllamaModels => { en: "Downloaded models you'd download again; remove one with `ollama rm <model>`", zh: "已下载的模型，需要时可重新下载；用 `ollama rm <model>` 删除单个模型" },
    FdBlurbLmStudioModels => { en: "Downloaded models you'd download again; remove them in LM Studio", zh: "已下载的模型，需要时可重新下载；在 LM Studio 中删除" },
    FdBlurbHuggingFaceModels => { en: "Downloaded models you'd download again; `hf cache` commands remove chosen ones", zh: "已下载的模型，需要时可重新下载；用 `hf cache` 命令删除指定模型" },
    FdBlurbAppCaches => { en: "Apps rebuild their caches as needed", zh: "应用会按需重建缓存" },
    FdBlurbHomebrewDownloads => { en: "Fetched again when needed; `brew cleanup --prune=all` clears them", zh: "需要时会重新下载；用 `brew cleanup --prune=all` 清理" },
    FdBlurbNpmCache => { en: "Re-downloaded on the next install", zh: "下次安装时会重新下载" },
    FdBlurbPnpmStore => { en: "Counts only files no project links to; `pnpm store prune` removes unused packages", zh: "仅统计没有项目链接的文件；`pnpm store prune` 可移除未使用的包" },
    FdBlurbNextBuild => { en: "Re-downloaded on the next build", zh: "下次构建时会重新下载" },
    FdBlurbMovies => { en: "Videos and editing projects", zh: "视频与剪辑工程" },
    FdBlurbChromeLeftovers => { en: "Old copies Chrome keeps while updating; quit Chrome first", zh: "Chrome 更新期间保留的旧副本；请先退出 Chrome" },
    FdBlurbMail => { en: "Messages and downloaded attachments", zh: "邮件与已下载的附件" },
    FdBlurbClaudeHistory => { en: "Your conversations, kept so you can resume them; Claude Code clears old ones itself", zh: "你的对话记录，保留以便继续会话；Claude Code 会自行清理旧记录" },
    FdBlurbCodexHistory => { en: "Your Codex conversations, kept so you can resume them", zh: "你的 Codex 对话记录，保留以便继续会话" },
    FdBlurbModules => { en: "In {n} projects; reinstall with your package manager", zh: "分布在 {n} 个项目中；可用包管理器重装" },
    FdBlurbCargoOne => { en: "In 1 Rust project; `cargo build` rebuilds them, or run `cargo clean`", zh: "分布在 1 个 Rust 项目中；`cargo build` 会重新生成，或运行 `cargo clean`" },
    FdBlurbCargoMany => { en: "In {n} Rust projects; `cargo build` rebuilds them, or run `cargo clean`", zh: "分布在 {n} 个 Rust 项目中；`cargo build` 会重新生成，或运行 `cargo clean`" },
    FdBlurbGitOne => { en: "In 1 repo; `git gc` packs it", zh: "分布在 1 个仓库中；`git gc` 可打包整理" },
    FdBlurbGitMany => { en: "In {n} repos; `git gc` packs them", zh: "分布在 {n} 个仓库中；`git gc` 可打包整理" },
}

/// Render a template with named `{placeholder}`s. Unknown names are kept
/// verbatim (loud and obvious in the UI rather than silently dropped).
pub fn tf(key: Tr, args: &[(&str, String)]) -> String {
    let template = tr(key);
    let mut out = String::with_capacity(template.len() + 16);
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        match after.find('}') {
            Some(close) => {
                let name = &after[..close];
                match args.iter().find(|(key, _)| *key == name) {
                    Some((_, value)) => out.push_str(value),
                    None => {
                        out.push('{');
                        out.push_str(name);
                        out.push('}');
                    }
                }
                rest = &after[close + 1..];
            }
            None => {
                out.push('{');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// Shorthand so call sites read `t!(Tr::Rescan)` instead of `tr(Tr::Rescan)`,
/// and `tf!(Tr::X, "name" => value)` instead of spelling out the arg slice.
#[macro_export]
macro_rules! t {
    ($key:expr) => {
        $crate::i18n::tr($key)
    };
}

/// Interpolating shorthand: `tf!(Tr::ScannedIn, "s" => "3.2")`.
#[macro_export]
macro_rules! tf {
    ($key:expr, $( $name:literal => $value:expr ),+ $(,)?) => {
        $crate::i18n::tf($key, &[ $( ($name, ($value).to_string()) ),+ ])
    };
}

/// Abbreviated month name (`1 Jan 2000`), localized for the date stamps the
/// app prints. `index` is 0-based, January first.
pub fn month_name(index: usize) -> &'static str {
    const EN: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    const ZH: [&str; 12] = [
        "1月", "2月", "3月", "4月", "5月", "6月", "7月", "8月", "9月", "10月", "11月", "12月",
    ];
    match lang() {
        Lang::Zh => ZH[index.min(11)],
        Lang::En => EN[index.min(11)],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn language_codes_map_to_languages() {
        assert_eq!(Lang::from_code("en"), Lang::En);
        assert_eq!(Lang::from_code("en_US"), Lang::En);
        assert_eq!(Lang::from_code("en-US"), Lang::En);
        assert_eq!(Lang::from_code("zh-Hans-CN"), Lang::Zh);
        assert_eq!(Lang::from_code("zh_CN.UTF-8"), Lang::Zh);
        assert_eq!(Lang::from_code("fr-FR"), Lang::En);
    }

    #[test]
    fn templates_interpolate_named_placeholders() {
        set_lang(Lang::En);
        assert_eq!(tr(Tr::Rescan), "Rescan");
        assert_eq!(tf(Tr::ScannedIn, &[("s", "3.2".into())]), "Scanned in 3.2s");
        // A missing name stays visible instead of vanishing.
        assert_eq!(tf(Tr::ScannedIn, &[]), "Scanned in {s}s");
    }

    #[test]
    fn chinese_templates_keep_every_placeholder() {
        set_lang(Lang::Zh);
        for (key, en, zh) in TEMPLATES {
            let _ = tr(*key);
            let en_names = placeholder_names(en);
            let zh_names = placeholder_names(zh);
            for name in &en_names {
                assert!(
                    zh_names.contains(&name),
                    "{key:?}: zh template {zh:?} is missing placeholder {name:?}"
                );
            }
            for name in &zh_names {
                assert!(
                    en_names.contains(&name),
                    "{key:?}: en template {en:?} is missing placeholder {name:?}"
                );
            }
        }
        set_lang(Lang::En);
    }

    fn placeholder_names(template: &str) -> Vec<&str> {
        let mut names = Vec::new();
        let bytes = template.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'{' {
                if let Some(close) = template[i + 1..].find('}') {
                    names.push(&template[i + 1..i + 1 + close]);
                    i += close + 2;
                    continue;
                }
            }
            i += 1;
        }
        names
    }
}
