//! Follow the desktop's light/dark preference.
//!
//! GTK 4.8 does not read the desktop's color scheme by itself, so IrcGoo does.
//! The preference comes from the freedesktop settings portal
//! (`org.freedesktop.appearance color-scheme`), which GNOME, KDE and others
//! provide. Without the portal, GNOME's `org.gnome.desktop.interface
//! color-scheme` setting is used. Changes are followed while IrcGoo runs.
//!
//! A preference for dark or light sets GTK's `gtk-application-prefer-dark-theme`.
//! "No preference" restores the value it had at startup, which comes from GTK's
//! own `settings.ini`. A theme that is dark by name (such as "Adwaita-dark") stays
//! dark either way.

use gtk::prelude::*;
use gtk::{gio, glib};
use std::cell::{Cell, RefCell};

const PORTAL_NAME: &str = "org.freedesktop.portal.Desktop";
const PORTAL_PATH: &str = "/org/freedesktop/portal/desktop";
const PORTAL_SETTINGS: &str = "org.freedesktop.portal.Settings";
const APPEARANCE: &str = "org.freedesktop.appearance";
const COLOR_SCHEME: &str = "color-scheme";
const PORTAL_TIMEOUT_MS: i32 = 5000;
const GNOME_INTERFACE: &str = "org.gnome.desktop.interface";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Scheme {
    NoPreference,
    Dark,
    Light,
}

thread_local! {
    static INITIAL_PREFER_DARK: Cell<bool> = const { Cell::new(false) };
    static ON_DARK_CHANGED: Cell<Option<fn(bool)>> = const { Cell::new(None) };
    static LAST_DARK: Cell<Option<bool>> = const { Cell::new(None) };
    /// The portal proxy or GSettings object, kept alive so its change signal keeps firing.
    static SOURCE: RefCell<Option<glib::Object>> = const { RefCell::new(None) };
}

/// Start following the desktop. `on_dark_changed` is called now and whenever the
/// effective theme switches between light and dark.
pub fn follow_desktop(on_dark_changed: fn(bool)) {
    let Some(settings) = gtk::Settings::default() else {
        return;
    };
    INITIAL_PREFER_DARK.set(settings.is_gtk_application_prefer_dark_theme());
    ON_DARK_CHANGED.set(Some(on_dark_changed));
    settings.connect_gtk_application_prefer_dark_theme_notify(report_dark);
    settings.connect_gtk_theme_name_notify(report_dark);
    report_dark(&settings);

    gio::DBusProxy::for_bus(
        gio::BusType::Session,
        gio::DBusProxyFlags::DO_NOT_LOAD_PROPERTIES,
        None,
        PORTAL_NAME,
        PORTAL_PATH,
        PORTAL_SETTINGS,
        None::<&gio::Cancellable>,
        |result| match result {
            Ok(proxy) => read_portal(proxy, "ReadOne"),
            Err(_) => use_gnome_settings(),
        },
    );
}

/// Read the color scheme from the portal. `ReadOne` is newer; older portals (such as
/// the one in Debian bookworm) only have `Read`.
fn read_portal(proxy: gio::DBusProxy, method: &'static str) {
    let args = (APPEARANCE, COLOR_SCHEME).to_variant();
    let p = proxy.clone();
    proxy.call(
        method,
        Some(&args),
        gio::DBusCallFlags::NONE,
        PORTAL_TIMEOUT_MS,
        None::<&gio::Cancellable>,
        move |result| match result {
            Ok(reply) => {
                apply(portal_scheme(&reply.child_value(0)));
                p.connect_g_signal(|_, _, signal, params| {
                    if signal == "SettingChanged"
                        && params.n_children() == 3
                        && params.child_value(0).str() == Some(APPEARANCE)
                        && params.child_value(1).str() == Some(COLOR_SCHEME)
                    {
                        apply(portal_scheme(&params.child_value(2)));
                    }
                });
                SOURCE.with_borrow_mut(|s| *s = Some(p.upcast()));
            }
            Err(e) if method == "ReadOne" && e.matches(gio::DBusError::UnknownMethod) => read_portal(p, "Read"),
            Err(_) => use_gnome_settings(),
        },
    );
}

/// The portal's value: 0 no preference, 1 dark, 2 light, possibly inside nested variants.
fn portal_scheme(value: &glib::Variant) -> Scheme {
    let mut v = value.clone();
    while v.type_() == glib::VariantTy::VARIANT
        && let Some(inner) = v.as_variant()
    {
        v = inner;
    }
    match v.get::<u32>() {
        Some(1) => Scheme::Dark,
        Some(2) => Scheme::Light,
        _ => Scheme::NoPreference,
    }
}

fn use_gnome_settings() {
    let Some(schema) = gio::SettingsSchemaSource::default().and_then(|s| s.lookup(GNOME_INTERFACE, true)) else {
        return;
    };
    if !schema.has_key(COLOR_SCHEME) {
        return;
    }
    let settings = gio::Settings::new(GNOME_INTERFACE);
    settings.connect_changed(Some(COLOR_SCHEME), |s, _| apply(gnome_scheme(s)));
    apply(gnome_scheme(&settings));
    SOURCE.with_borrow_mut(|s| *s = Some(settings.upcast()));
}

fn gnome_scheme(settings: &gio::Settings) -> Scheme {
    match settings.string(COLOR_SCHEME).as_str() {
        "prefer-dark" => Scheme::Dark,
        "prefer-light" => Scheme::Light,
        _ => Scheme::NoPreference,
    }
}

fn apply(scheme: Scheme) {
    let Some(settings) = gtk::Settings::default() else {
        return;
    };
    let prefer_dark = match scheme {
        Scheme::Dark => true,
        Scheme::Light => false,
        Scheme::NoPreference => INITIAL_PREFER_DARK.get(),
    };
    if settings.is_gtk_application_prefer_dark_theme() != prefer_dark {
        settings.set_gtk_application_prefer_dark_theme(prefer_dark);
    }
}

/// Whether GTK is showing a dark theme: the dark variant was requested, or the theme
/// is dark by name.
fn is_dark(settings: &gtk::Settings) -> bool {
    let name = settings
        .gtk_theme_name()
        .map(|n| n.to_ascii_lowercase())
        .unwrap_or_default();
    settings.is_gtk_application_prefer_dark_theme() || name.ends_with("-dark") || name.ends_with(":dark")
}

fn report_dark(settings: &gtk::Settings) {
    let dark = is_dark(settings);
    if LAST_DARK.replace(Some(dark)) != Some(dark)
        && let Some(f) = ON_DARK_CHANGED.get()
    {
        f(dark);
    }
}
