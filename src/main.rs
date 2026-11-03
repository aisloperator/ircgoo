//! IrcGoo: an IRC client for Linux desktops, built with GTK4.

mod app;
mod config;
mod irc;
mod net;
mod prefs;
mod socks;
mod tab;
mod theme;
mod tls;

use gtk::glib;
use gtk::prelude::*;

fn main() -> glib::ExitCode {
    let application = gtk::Application::builder().application_id(app::APP_ID).build();
    application.connect_activate(app::activate);
    application.run()
}
