use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::i18n::Tr;
use crate::{t, tf};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisplayUnit {
    #[default]
    Gigabytes,
    Terabytes,
    Percent,
    Auto,
}

impl DisplayUnit {
    pub fn label(self) -> &'static str {
        match self {
            Self::Gigabytes => "GB",
            Self::Terabytes => "TB",
            Self::Percent => "%",
            Self::Auto => t!(Tr::MbAutoUnit),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThresholdUnit {
    #[default]
    Percent,
    Gigabytes,
}

impl ThresholdUnit {
    pub fn label(self) -> &'static str {
        match self {
            Self::Percent => "%",
            Self::Gigabytes => "GB",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MenuBarConfig {
    pub enabled: bool,
    /// A mount point, not a folder on the volume. Offline volumes remain selected.
    pub mount: PathBuf,
    pub display_unit: DisplayUnit,
    pub threshold_unit: ThresholdUnit,
    pub threshold: f64,
    pub refresh_seconds: u64,
}

impl Default for MenuBarConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            mount: PathBuf::from("/"),
            display_unit: DisplayUnit::Gigabytes,
            threshold_unit: ThresholdUnit::Percent,
            threshold: 10.,
            refresh_seconds: 5,
        }
    }
}

impl MenuBarConfig {
    pub fn validate(&self) -> Result<(), String> {
        use std::os::unix::ffi::OsStrExt;
        if !self.mount.is_absolute()
            || self.mount.as_os_str().as_bytes().contains(&0)
            || self
                .mount
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(t!(Tr::MbBadMount).into());
        }
        if !self.threshold.is_finite()
            || self.threshold <= 0.
            || (self.threshold_unit == ThresholdUnit::Percent && self.threshold > 100.)
        {
            return Err(t!(Tr::MbBadThreshold).into());
        }
        if !(1..=3600).contains(&self.refresh_seconds) {
            return Err(t!(Tr::MbBadRefresh).into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Space {
    pub total: u64,
    pub free: u64,
}

impl Space {
    fn percent(&self) -> f64 {
        if self.total == 0 {
            0.
        } else {
            self.free.min(self.total) as f64 / self.total as f64 * 100.
        }
    }

    pub fn low(&self, config: &MenuBarConfig) -> bool {
        let remaining = match config.threshold_unit {
            ThresholdUnit::Percent => self.percent(),
            ThresholdUnit::Gigabytes => self.free.min(self.total) as f64 / 1e9,
        };
        remaining < config.threshold
    }

    pub fn format(&self, unit: DisplayUnit) -> String {
        let free = self.free.min(self.total) as f64;
        match unit {
            DisplayUnit::Percent => format!("{:.1}%", self.percent()),
            DisplayUnit::Gigabytes => format!("{:.1} GB", free / 1e9),
            DisplayUnit::Terabytes => format!("{:.2} TB", free / 1e12),
            DisplayUnit::Auto if free >= 1e12 => self.format(DisplayUnit::Terabytes),
            DisplayUnit::Auto if free >= 1e9 => self.format(DisplayUnit::Gigabytes),
            DisplayUnit::Auto => format!("{:.1} MB", free / 1e6),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MountedDisk {
    pub name: String,
    pub path: PathBuf,
}

/// Enumeration uses an owned getfsstat buffer, not getmntinfo's process-global buffer.
/// NOWAIT avoids contacting every mounted network filesystem on each refresh.
pub fn mounted_disks() -> Vec<MountedDisk> {
    let count = unsafe { libc::getfsstat(std::ptr::null_mut(), 0, libc::MNT_NOWAIT) };
    if count <= 0 {
        return Vec::new();
    }
    let mut mounts: Vec<libc::statfs> = (0..count + 16)
        .map(|_| unsafe { std::mem::zeroed() })
        .collect();
    let count = unsafe {
        libc::getfsstat(
            mounts.as_mut_ptr(),
            std::mem::size_of_val(mounts.as_slice()) as i32,
            libc::MNT_NOWAIT,
        )
    };
    if count <= 0 {
        return Vec::new();
    }
    let mut disks = Vec::new();
    for mount in mounts.iter().take(count as usize) {
        let path = PathBuf::from(crate::disk::cstr(&mount.f_mntonname));
        if path == Path::new("/") || path.parent() == Some(Path::new("/Volumes")) {
            let name = if path == Path::new("/") {
                t!(Tr::MbStartupDisk).to_owned()
            } else {
                path.file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned()
            };
            disks.push(MountedDisk { name, path });
        }
    }
    disks.sort_by(|a, b| {
        (a.path != Path::new("/"), &a.name).cmp(&(b.path != Path::new("/"), &b.name))
    });
    disks
}

/// Verify the actual mount point before reading space. An ejected disk's leftover
/// directory must never silently start reporting the startup disk's free space.
pub fn read_space(path: &Path) -> Option<Space> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let path_c = CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(path_c.as_ptr(), &mut stat) } != 0
        || Path::new(&crate::disk::cstr(&stat.f_mntonname)) != path
        || stat.f_blocks == 0
    {
        return None;
    }
    let block = stat.f_bsize as u64;
    let total = stat.f_blocks.checked_mul(block)?;
    let free = stat.f_bavail.checked_mul(block)?.min(total);
    Some(Space { total, free })
}

#[derive(Clone, Copy, Debug)]
pub enum Command {
    Show,
    Clean,
    Settings,
    Refresh,
    Quit,
}

pub struct Monitor {
    config: Option<MenuBarConfig>,
    pub disks: Vec<MountedDisk>,
    pub space: Option<Space>,
    next_refresh: Instant,
    pub busy: bool,
    generation: u64,
    native: Option<native::StatusItem>,
}

impl Monitor {
    pub fn new() -> Self {
        Self {
            config: None,
            disks: Vec::new(),
            space: None,
            next_refresh: Instant::now(),
            busy: false,
            generation: 0,
            native: None,
        }
    }

    pub fn enabled(&self) -> bool {
        self.native.is_some()
    }

    fn sync_config(&mut self, config: Option<MenuBarConfig>) {
        if self.config != config {
            let changed_mount =
                self.config.as_ref().map(|c| &c.mount) != config.as_ref().map(|c| &c.mount);
            let changed_enabled =
                self.config.as_ref().map(|c| c.enabled) != config.as_ref().map(|c| c.enabled);
            if changed_mount || changed_enabled {
                self.space = None;
                self.busy = false;
                self.generation = self.generation.wrapping_add(1);
            }
            self.config = config;
            self.next_refresh = Instant::now();
        }
    }

    pub fn poll(&mut self, config: Option<MenuBarConfig>) -> Vec<Command> {
        self.sync_config(config);
        let enabled = self.config.as_ref().is_some_and(|c| c.enabled);
        if enabled && self.native.is_none() {
            self.native = Some(native::StatusItem::new());
        }
        if !enabled {
            self.native = None;
        }
        if let (Some(native), Some(config)) = (&mut self.native, &self.config) {
            let name = self
                .disks
                .iter()
                .find(|disk| disk.path == config.mount)
                .map(|disk| disk.name.clone())
                .unwrap_or_else(|| {
                    if config.mount == Path::new("/") {
                        t!(Tr::MbStartupDisk).into()
                    } else {
                        config.mount.display().to_string()
                    }
                });
            native.update(config, &name, self.space.as_ref(), self.busy);
            native.commands()
        } else {
            Vec::new()
        }
    }

    pub fn refresh_now(&mut self) {
        self.next_refresh = Instant::now();
    }

    pub fn refresh_request(&mut self) -> Option<(u64, PathBuf)> {
        let config = self.config.as_ref()?;
        if !config.enabled || self.busy || Instant::now() < self.next_refresh {
            return None;
        }
        self.busy = true;
        self.generation = self.generation.wrapping_add(1);
        self.next_refresh = Instant::now() + Duration::from_secs(config.refresh_seconds);
        Some((self.generation, config.mount.clone()))
    }

    pub fn finish_refresh(
        &mut self,
        generation: u64,
        path: &Path,
        disks: Vec<MountedDisk>,
        space: Option<Space>,
    ) {
        if generation != self.generation {
            return;
        }
        self.busy = false;
        self.disks = disks;
        if self
            .config
            .as_ref()
            .is_some_and(|config| config.mount == path)
        {
            self.space = space;
        } else {
            self.next_refresh = Instant::now();
        }
    }
}

mod native {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::rc::Rc;

    use objc2::rc::Retained;
    use objc2::runtime::AnyObject;
    use objc2::{AnyThread, DefinedClass, MainThreadOnly, define_class, msg_send, sel};
    use objc2_app_kit::{
        NSColor, NSFont, NSFontAttributeName, NSForegroundColorAttributeName, NSMenu, NSMenuItem,
        NSStatusBar, NSStatusItem,
    };
    use objc2_foundation::{
        MainThreadMarker, NSAttributedString, NSDictionary, NSObject, NSObjectProtocol, NSString,
    };

    type Queue = Rc<RefCell<VecDeque<Command>>>;

    define_class!(
        // SAFETY: NSObject has no subclass requirements. Instances and callbacks
        // stay on the AppKit main thread; our StatusItem owns this target.
        #[unsafe(super = NSObject)]
        #[thread_kind = MainThreadOnly]
        #[ivars = Queue]
        struct Target;

        unsafe impl NSObjectProtocol for Target {}

        impl Target {
            #[unsafe(method(petalMenuAction:))]
            fn action(&self, sender: &NSMenuItem) {
                let command = match sender.tag() {
                    1 => Command::Show,
                    2 => Command::Clean,
                    3 => Command::Settings,
                    4 => Command::Refresh,
                    5 => Command::Quit,
                    _ => return,
                };
                self.ivars().borrow_mut().push_back(command);
            }
        }
    );

    pub(super) struct StatusItem {
        item: Retained<NSStatusItem>,
        // AppKit's target is unretained. Keep it alive for the whole menu lifetime.
        _target: Retained<Target>,
        queue: Queue,
        info: Retained<NSMenuItem>,
        status: Retained<NSMenuItem>,
        actions: Vec<Retained<NSMenuItem>>,
        previous: String,
    }

    impl StatusItem {
        pub fn new() -> Self {
            let mtm = MainThreadMarker::new().expect("status item must be created on main thread");
            let queue = Queue::default();
            let target: Retained<Target> =
                unsafe { msg_send![super(Target::alloc(mtm).set_ivars(queue.clone())), init] };
            let item = NSStatusBar::systemStatusBar().statusItemWithLength(-1.);
            let menu = NSMenu::initWithTitle(NSMenu::alloc(mtm), &NSString::from_str("Petal"));
            menu.setAutoenablesItems(false);
            let make_item = |title: &str, tag: isize| {
                // SAFETY: the selector is implemented above with AppKit's action signature.
                let row = unsafe {
                    NSMenuItem::initWithTitle_action_keyEquivalent(
                        NSMenuItem::alloc(mtm),
                        &NSString::from_str(title),
                        (tag != 0).then(|| sel!(petalMenuAction:)),
                        &NSString::from_str(""),
                    )
                };
                row.setTag(tag);
                row.setEnabled(tag != 0);
                if tag != 0 {
                    unsafe { row.setTarget(Some(&target)) };
                }
                menu.addItem(&row);
                row
            };
            let info = make_item("Petal", 0);
            let status = make_item("", 0);
            menu.addItem(&NSMenuItem::separatorItem(mtm));
            let actions = (1..=5).map(|tag| make_item("", tag)).collect();
            item.setMenu(Some(&menu));
            Self {
                item,
                _target: target,
                queue,
                info,
                status,
                actions,
                previous: String::new(),
            }
        }

        pub fn commands(&self) -> Vec<Command> {
            self.queue.borrow_mut().drain(..).collect()
        }

        pub fn update(
            &mut self,
            config: &MenuBarConfig,
            name: &str,
            space: Option<&Space>,
            busy: bool,
        ) {
            let low = space.is_some_and(|space| space.low(config));
            let title = match space {
                Some(space) => format!(
                    "{} {}",
                    if low { "!" } else { "▤" },
                    space.format(config.display_unit)
                ),
                None => "▤ —".into(),
            };
            let status = match space {
                Some(space) => tf!(Tr::MbSpaceDetail, "free" => space.format(DisplayUnit::Auto),
                    "total" => format!("{:.1} GB", space.total as f64 / 1e9), "percent" => space.format(DisplayUnit::Percent)),
                None => t!(if busy {
                    Tr::MbReading
                } else {
                    Tr::MbUnavailable
                })
                .into(),
            };
            let tooltip = format!(
                "Petal · {name}\n{status}{}",
                if low {
                    format!("\n{}", t!(Tr::MbLowSpace))
                } else {
                    String::new()
                }
            );
            let key = format!("{title}{tooltip}{:?}", crate::i18n::lang());
            if self.previous == key {
                return;
            }
            self.previous = key;
            let mtm = MainThreadMarker::new().expect("status item must be updated on main thread");
            if let Some(button) = self.item.button(mtm) {
                let color = if low {
                    NSColor::systemRedColor()
                } else if space.is_none() {
                    NSColor::secondaryLabelColor()
                } else {
                    NSColor::labelColor()
                };
                let font = NSFont::monospacedDigitSystemFontOfSize_weight(12., 0.);
                // SAFETY: AppKit attribute keys are paired with their required types.
                let attrs = unsafe {
                    NSDictionary::from_slices(
                        &[NSForegroundColorAttributeName, NSFontAttributeName],
                        &[color.as_ref() as &AnyObject, font.as_ref() as &AnyObject],
                    )
                };
                let attributed = unsafe {
                    NSAttributedString::initWithString_attributes(
                        NSAttributedString::alloc(),
                        &NSString::from_str(&title),
                        Some(&attrs),
                    )
                };
                button.setAttributedTitle(&attributed);
                button.setToolTip(Some(&NSString::from_str(&tooltip)));
            }
            self.info
                .setTitle(&NSString::from_str(&format!("Petal · {name}")));
            self.status.setTitle(&NSString::from_str(&status));
            for (item, label) in self.actions.iter().zip([
                t!(Tr::MbOpen),
                t!(Tr::MbClean),
                t!(Tr::MbSettings),
                t!(Tr::MbRefresh),
                t!(Tr::MenuQuit),
            ]) {
                item.setTitle(&NSString::from_str(label));
            }
            self.actions[1].setEnabled(space.is_some());
        }
    }

    impl Drop for StatusItem {
        fn drop(&mut self) {
            // Remove the menu before dropping its unretained target.
            self.item.setMenu(None);
            NSStatusBar::systemStatusBar().removeStatusItem(&self.item);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_remaining_space_in_decimal_units() {
        let space = Space {
            total: 1_000_000_000_000,
            free: 125_000_000_000,
        };
        assert_eq!(space.format(DisplayUnit::Gigabytes), "125.0 GB");
        assert_eq!(space.format(DisplayUnit::Terabytes), "0.12 TB");
        assert_eq!(space.format(DisplayUnit::Percent), "12.5%");
        assert_eq!(space.format(DisplayUnit::Auto), "125.0 GB");
        assert_eq!(
            Space {
                total: 10_000_000,
                free: 500_000
            }
            .format(DisplayUnit::Auto),
            "0.5 MB"
        );
        assert_eq!(
            Space {
                total: 2_000_000_000_000,
                free: 1_500_000_000_000
            }
            .format(DisplayUnit::Auto),
            "1.50 TB"
        );
    }

    #[test]
    fn thresholds_use_remaining_not_used_space_and_are_strict() {
        let space = Space {
            total: 1_000_000_000_000,
            free: 100_000_000_000,
        };
        let mut config = MenuBarConfig::default();
        assert!(!space.low(&config));
        config.threshold = 10.1;
        assert!(space.low(&config));
        config.threshold_unit = ThresholdUnit::Gigabytes;
        config.threshold = 100.;
        assert!(!space.low(&config));
        config.threshold = 101.;
        assert!(space.low(&config));
        assert!(
            Space {
                total: 100,
                free: 0
            }
            .low(&MenuBarConfig::default())
        );
        assert_eq!(
            Space {
                total: 100,
                free: 200
            }
            .format(DisplayUnit::Percent),
            "100.0%"
        );
        assert_eq!(
            Space { total: 0, free: 0 }.format(DisplayUnit::Percent),
            "0.0%"
        );
    }

    #[test]
    fn validates_config_and_accepts_offline_mounts() {
        let mut config = MenuBarConfig::default();
        assert!(config.validate().is_ok());
        config.mount = PathBuf::from("/Volumes/Offline");
        assert!(config.validate().is_ok());
        for threshold in [f64::NAN, f64::INFINITY, -1., 0., 101.] {
            config.threshold = threshold;
            assert!(config.validate().is_err());
        }
        config.threshold = 10.;
        for interval in [0, 3601] {
            config.refresh_seconds = interval;
            assert!(config.validate().is_err());
        }
        config.refresh_seconds = 5;
        config.mount = PathBuf::from("relative");
        assert!(config.validate().is_err());
    }

    #[test]
    fn missing_disk_or_plain_directory_never_reports_startup_space() {
        assert!(read_space(Path::new("/petal-missing-volume")).is_none());
        assert!(read_space(Path::new("/Users")).is_none());
        assert!(read_space(Path::new("/")).is_some());
        assert!(
            mounted_disks()
                .iter()
                .any(|disk| disk.path == Path::new("/"))
        );
    }

    #[test]
    fn disk_switch_can_refresh_before_old_sample_returns() {
        let mut monitor = Monitor::new();
        monitor.sync_config(Some(MenuBarConfig::default()));
        let (old, _) = monitor.refresh_request().unwrap();
        monitor.sync_config(Some(MenuBarConfig {
            mount: PathBuf::from("/Volumes/Other"),
            ..Default::default()
        }));
        let (current, mount) = monitor
            .refresh_request()
            .expect("new disk must not wait for old disk");
        assert_ne!(old, current);
        monitor.finish_refresh(
            old,
            Path::new("/"),
            Vec::new(),
            Some(Space {
                total: 100,
                free: 10,
            }),
        );
        assert!(
            monitor.busy,
            "old request must not mark current request idle"
        );
        assert!(monitor.space.is_none());
        monitor.finish_refresh(
            current,
            &mount,
            Vec::new(),
            Some(Space {
                total: 200,
                free: 20,
            }),
        );
        assert!(!monitor.busy);
        assert_eq!(
            monitor.space,
            Some(Space {
                total: 200,
                free: 20
            })
        );
        assert!(
            monitor.refresh_request().is_none(),
            "respect refresh interval"
        );
        monitor.refresh_now();
        assert!(monitor.refresh_request().is_some());
    }

    #[test]
    fn disabled_monitor_does_not_sample_and_reenable_invalidates_old_read() {
        let mut monitor = Monitor::new();
        monitor.sync_config(Some(MenuBarConfig::default()));
        let (old, _) = monitor.refresh_request().unwrap();
        monitor.sync_config(Some(MenuBarConfig {
            enabled: false,
            ..Default::default()
        }));
        assert!(monitor.refresh_request().is_none());
        monitor.sync_config(Some(MenuBarConfig::default()));
        let (new, _) = monitor.refresh_request().unwrap();
        assert_ne!(old, new);
    }

    #[test]
    fn discards_inflight_sample_after_disk_switch() {
        let mut monitor = Monitor::new();
        monitor.config = Some(MenuBarConfig {
            enabled: false,
            mount: PathBuf::from("/Volumes/Other"),
            ..Default::default()
        });
        monitor.busy = true;
        monitor.finish_refresh(
            0,
            Path::new("/"),
            Vec::new(),
            Some(Space {
                total: 100,
                free: 10,
            }),
        );
        assert!(!monitor.busy);
        assert!(monitor.space.is_none());
        assert!(monitor.next_refresh <= Instant::now());
    }
}
