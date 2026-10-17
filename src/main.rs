mod admin;
mod agent;
mod app;
mod cleanup;
mod credentials;
mod classify;
mod cli;
mod clock;
mod dirlist;
mod disk;
mod eta;
mod findings;
mod i18n;
mod icons;
mod json;
mod live;
mod motion;
mod onboarding;
mod rules;
mod safety;
mod scan;
mod settings;
mod text_input;
#[cfg(feature = "snapshot")]
mod snapshot;
mod sunburst;
mod treemap;
mod trashing;
mod watch;

use std::path::PathBuf;

use gpui::{
    App, Bounds, KeyBinding, Menu, MenuItem, TitlebarOptions, WindowBounds, WindowOptions, actions,
    point, prelude::*, px, size,
};

use app::{ChartType, GoUp, OpenFolder, Petal, ReadAsAdmin, Rescan, ShowIcicle, ShowSunburst, ShowTreemap, StartOver};
use i18n::Tr;

actions!(petal, [Quit, Hide, HideOthers, ShowAll, Minimize, Zoom, CloseWindow]);

fn main() {
    let _ = app::LAUNCHED.set(std::time::Instant::now());
    let args: Vec<String> = std::env::args().collect();
    // Windowless commands for scripts and agents: `petal scan PATH [--json]` and
    // `petal findings [PATH] [--json]` (see `cli`).
    if let Some(command @ ("scan" | "findings")) = args.get(1).map(String::as_str) {
        std::process::exit(cli::main(command, &args[2..]));
    }
    // Headless benchmark: `petal --bench-scan <path> [runs]`
    if args.get(1).map(String::as_str) == Some("--bench-scan") {
        let path = PathBuf::from(args.get(2).expect("path required"));
        let runs = args.get(3).and_then(|r| r.parse().ok()).unwrap_or(5);
        scan::bench(&path, runs);
        return;
    }
    // Diagnostic: does this process have Full Disk Access? (Launch through `open` to ask
    // about Petal.app itself rather than the terminal that started it.)
    if args.get(1).map(String::as_str) == Some("--check-access") {
        println!("full disk access: {}", if onboarding::has_full_disk_access() { "yes" } else { "no" });
        return;
    }
    // The administrator helper (see `admin`): `petal --admin <job file>`, started as root.
    if args.get(1).map(String::as_str) == Some("--admin") {
        let Some(job) = args.get(2) else { std::process::exit(2) };
        std::process::exit(admin::helper_main(std::path::Path::new(job)));
    }
    // Headless live-chart benchmark: `petal --bench-live <path> [runs]`
    if args.get(1).map(String::as_str) == Some("--bench-live") {
        let path = PathBuf::from(args.get(2).expect("path required"));
        let runs = args.get(3).and_then(|r| r.parse().ok()).unwrap_or(3);
        live::bench(&path, runs);
        return;
    }
    // On first launch, start scanning the startup disk straight away.
    let initial = args.get(1).map(PathBuf::from).or_else(|| onboarding::is_first_run().then(|| PathBuf::from("/")));

    gpui_platform::application().run(move |cx: &mut App| {
        cx.on_action(|_: &Quit, cx| cx.quit());
        cx.on_action(|_: &Hide, cx| cx.hide());
        cx.on_action(|_: &HideOthers, cx| cx.hide_other_apps());
        cx.on_action(|_: &ShowAll, cx| cx.unhide_other_apps());
        cx.on_action(|_: &Minimize, cx| with_window(cx, |window| window.minimize_window()));
        cx.on_action(|_: &Zoom, cx| with_window(cx, |window| window.zoom_window()));
        cx.on_action(|_: &CloseWindow, cx| with_window(cx, |window| window.remove_window()));
        text_input::bind_keys(cx);
        cx.bind_keys([
            KeyBinding::new("cmd-q", Quit, None),
            KeyBinding::new("cmd-h", Hide, None),
            KeyBinding::new("alt-cmd-h", HideOthers, None),
            KeyBinding::new("cmd-m", Minimize, None),
            KeyBinding::new("cmd-w", CloseWindow, None),
            KeyBinding::new("cmd-o", OpenFolder, None),
            KeyBinding::new("cmd-r", Rescan, None),
            KeyBinding::new("cmd-up", GoUp, Some("Petal && !TextInput")),
            KeyBinding::new("backspace", GoUp, Some("Petal && !TextInput")),
            KeyBinding::new("escape", GoUp, Some("Petal && !TextInput")),
            KeyBinding::new("cmd-shift-d", StartOver, None),
            KeyBinding::new("cmd-1", ShowSunburst, None),
            KeyBinding::new("cmd-2", ShowIcicle, None),
            KeyBinding::new("cmd-3", ShowTreemap, None),
        ]);
        // Seed the UI language from settings before the menus and window are
        // built; the fallback follows the system language.
        let saved_language = crate::settings::Settings::load().ok().and_then(|settings| settings.language);
        i18n::set_lang(saved_language.unwrap_or_else(i18n::detect_system_lang));
        cx.set_menus(menus(ChartType::Sunburst));

        let bounds = Bounds::centered(None, size(px(1240.), px(800.)), cx);
        cx.open_window(
            WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(bounds)),
                titlebar: Some(TitlebarOptions {
                    title: Some("Petal".into()),
                    appears_transparent: true,
                    traffic_light_position: Some(point(px(16.), px(16.))),
                }),
                window_min_size: Some(size(px(860.), px(560.))),
                // Petal draws its own toolbar in the titlebar and handles dragging and
                // double-clicks there itself; otherwise macOS also acts on double-clicks
                // on the toolbar's buttons (minimizing the window, say).
                app_owns_titlebar_drag: true,
                ..Default::default()
            },
            |window, cx| cx.new(|cx| Petal::new(initial, window, cx)),
        )
        .expect("failed to open window");

        cx.on_window_closed(|cx, _| {
            if cx.windows().is_empty() {
                cx.quit();
            }
        })
        .detach();
        cx.activate(true);
    });
}

/// The menu bar, with the chart type in use ticked in the View menu (the app sets them again
/// when it changes). Titles come from the i18n table, so re-set the menus after a language
/// switch.
pub fn menus(chart: ChartType) -> Vec<Menu> {
    vec![
        Menu {
            name: "Petal".into(),
            items: vec![
                MenuItem::action(t!(Tr::MenuHidePetal), Hide),
                MenuItem::action(t!(Tr::MenuHideOthers), HideOthers),
                MenuItem::action(t!(Tr::MenuShowAll), ShowAll),
                MenuItem::separator(),
                MenuItem::action(t!(Tr::MenuQuit), Quit),
            ],
            disabled: false,
        },
        Menu {
            name: t!(Tr::MenuFile).to_string().into(),
            items: vec![
                MenuItem::action(t!(Tr::MenuOpenFolder), OpenFolder),
                MenuItem::action(t!(Tr::MenuRescan), Rescan),
                MenuItem::action(t!(Tr::MenuReadAsAdmin), ReadAsAdmin),
                MenuItem::separator(),
                MenuItem::action(t!(Tr::MenuShowDisks), StartOver),
                MenuItem::separator(),
                MenuItem::action(t!(Tr::MenuCloseWindow), CloseWindow),
            ],
            disabled: false,
        },
        Menu {
            name: t!(Tr::MenuView).to_string().into(),
            items: vec![
                MenuItem::action(t!(Tr::MenuAsSunburst), ShowSunburst).checked(chart == ChartType::Sunburst),
                MenuItem::action(t!(Tr::MenuAsIcicle), ShowIcicle).checked(chart == ChartType::Icicle),
                MenuItem::action(t!(Tr::MenuAsTreemap), ShowTreemap).checked(chart == ChartType::Treemap),
            ],
            disabled: false,
        },
        Menu {
            name: t!(Tr::MenuGo).to_string().into(),
            items: vec![MenuItem::action(t!(Tr::MenuEnclosingFolder), GoUp)],
            disabled: false,
        },
        Menu {
            name: t!(Tr::MenuWindow).to_string().into(),
            items: vec![MenuItem::action(t!(Tr::MenuMinimize), Minimize), MenuItem::action(t!(Tr::MenuZoom), Zoom)],
            disabled: false,
        },
    ]
}

/// Run `f` on the frontmost window, if Petal has one.
fn with_window(cx: &mut App, f: impl FnOnce(&mut gpui::Window)) {
    if let Some(window) = cx.active_window() {
        window.update(cx, |_, window, _| f(window)).ok();
    }
}
