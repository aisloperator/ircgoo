//! Settings windows. Unlike the main window these use a conventional dialog layout.

use crate::app::App;
use crate::config::{Bouncer, MAX_FONT_SIZE, MIN_FONT_SIZE, Network, Sasl, SaslMech, Server};
use gtk::prelude::*;
use std::cell::{Cell, RefCell};
use std::path::PathBuf;
use std::rc::{Rc, Weak};

fn label(text: &str) -> gtk::Label {
    gtk::Label::builder().label(text).xalign(1.0).build()
}

/// Explanatory text. Wrapped by hand: GTK's label wrapping inside notebooks and grids
/// produces inconsistent height-for-width measurements.
fn hint(text: &str) -> gtk::Label {
    let mut wrapped = String::new();
    let mut col = 0;
    for word in text.split_whitespace() {
        if col > 0 && col + 1 + word.chars().count() > 60 {
            wrapped.push('\n');
            col = 0;
        } else if col > 0 {
            wrapped.push(' ');
            col += 1;
        }
        wrapped.push_str(word);
        col += word.chars().count();
    }
    let l = gtk::Label::builder().label(wrapped).xalign(0.0).build();
    l.add_css_class("dim-label");
    l
}

/// "11" or "10.5": point sizes without a needless ".0".
fn fmt_pt(pt: f64) -> String {
    let r = (pt * 10.0).round() / 10.0;
    if r.fract() == 0.0 {
        format!("{r:.0}")
    } else {
        format!("{r:.1}")
    }
}

fn grid() -> gtk::Grid {
    gtk::Grid::builder()
        .row_spacing(8)
        .column_spacing(12)
        .margin_top(12)
        .margin_bottom(12)
        .margin_start(12)
        .margin_end(12)
        .build()
}

fn port_spin() -> gtk::SpinButton {
    let s = gtk::SpinButton::with_range(1.0, 65535.0, 1.0);
    s.set_digits(0);
    s
}

fn entry() -> gtk::Entry {
    gtk::Entry::builder().hexpand(true).build()
}

fn password() -> gtk::PasswordEntry {
    gtk::PasswordEntry::builder().show_peek_icon(true).hexpand(true).build()
}

/// A window with Cancel / Save buttons in the header bar.
fn dialog_window(
    parent: &impl IsA<gtk::Window>,
    title: &str,
    ok_label: &str,
    modal: bool,
) -> (gtk::Window, gtk::Button, gtk::Button) {
    let window = gtk::Window::builder()
        .title(title)
        .transient_for(parent)
        .modal(modal)
        .destroy_with_parent(true)
        .build();
    let header = gtk::HeaderBar::new();
    header.set_show_title_buttons(false);
    let cancel = gtk::Button::with_mnemonic("_Cancel");
    let ok = gtk::Button::with_mnemonic(ok_label);
    ok.add_css_class("suggested-action");
    header.pack_start(&cancel);
    header.pack_end(&ok);
    window.set_titlebar(Some(&header));
    window.set_default_widget(Some(&ok));
    let w = window.clone();
    cancel.connect_clicked(move |_| w.close());
    (window, ok, cancel)
}

fn show_error(parent: &impl IsA<gtk::Window>, text: &str) {
    let d = gtk::MessageDialog::builder()
        .transient_for(parent)
        .modal(true)
        .message_type(gtk::MessageType::Error)
        .buttons(gtk::ButtonsType::Ok)
        .text(text)
        .build();
    d.connect_response(|d, _| d.close());
    d.present();
}

fn choose_file(parent: &impl IsA<gtk::Window>, title: &str, on_chosen: impl Fn(PathBuf) + 'static) {
    let dlg = gtk::FileChooserNative::new(
        Some(title),
        Some(parent),
        gtk::FileChooserAction::Open,
        Some("_Open"),
        Some("_Cancel"),
    );
    dlg.set_modal(true);
    // The native dialog must be kept alive until it responds.
    let holder = Rc::new(RefCell::new(Some(dlg.clone())));
    dlg.connect_response(move |d, resp| {
        if resp == gtk::ResponseType::Accept
            && let Some(p) = d.file().and_then(|f| f.path())
        {
            on_chosen(p);
        }
        holder.borrow_mut().take();
    });
    dlg.show();
}

// ----- Preferences --------------------------------------------------------------------------

pub fn show_preferences(app: &Rc<App>) {
    if let Some(w) = app.prefs_window.borrow().as_ref() {
        w.present();
        return;
    }
    let (window, save, _) = dialog_window(&app.window, "Preferences", "_Save", false);
    let cfg = app.config.borrow().clone();

    let g = grid();
    let ident = gtk::Label::builder()
        .label("<b>Identity</b>")
        .use_markup(true)
        .xalign(0.0)
        .build();
    g.attach(&ident, 0, 0, 2, 1);
    let nick = entry();
    nick.set_text(&cfg.nick);
    let username = entry();
    username.set_text(&cfg.username);
    let realname = entry();
    realname.set_text(&cfg.realname);
    g.attach(&label("Nickname"), 0, 1, 1, 1);
    g.attach(&nick, 1, 1, 1, 1);
    g.attach(&label("Username"), 0, 2, 1, 1);
    g.attach(&username, 1, 2, 1, 1);
    g.attach(&label("Real name"), 0, 3, 1, 1);
    g.attach(&realname, 1, 3, 1, 1);
    g.attach(
        &hint("These are the defaults; each network can override them."),
        1,
        4,
        1,
        1,
    );

    let proxy_title = gtk::Label::builder()
        .label("<b>SOCKS5 Proxy</b>")
        .use_markup(true)
        .xalign(0.0)
        .margin_top(12)
        .build();
    g.attach(&proxy_title, 0, 5, 2, 1);
    let proxy_on = gtk::CheckButton::with_label("Use a SOCKS5 proxy for all network connections");
    proxy_on.set_active(cfg.proxy.enabled);
    g.attach(&proxy_on, 0, 6, 2, 1);
    let phost = entry();
    phost.set_text(&cfg.proxy.host);
    let pport = port_spin();
    pport.set_value(cfg.proxy.port.into());
    let puser = entry();
    puser.set_text(&cfg.proxy.username);
    let ppass = password();
    ppass.set_text(&cfg.proxy.password);
    g.attach(&label("Host"), 0, 7, 1, 1);
    g.attach(&phost, 1, 7, 1, 1);
    g.attach(&label("Port"), 0, 8, 1, 1);
    g.attach(&pport, 1, 8, 1, 1);
    g.attach(&label("Username"), 0, 9, 1, 1);
    g.attach(&puser, 1, 9, 1, 1);
    g.attach(&label("Password"), 0, 10, 1, 1);
    g.attach(&ppass, 1, 10, 1, 1);
    g.attach(
        &hint("Host names are resolved by the proxy. Individual networks can opt out in the Networks window. Changes apply to new connections."),
        1,
        11,
        1,
        1,
    );
    let sync = {
        let ws: Vec<gtk::Widget> = vec![
            phost.clone().upcast(),
            pport.clone().upcast(),
            puser.clone().upcast(),
            ppass.clone().upcast(),
        ];
        move |on: bool| ws.iter().for_each(|w| w.set_sensitive(on))
    };
    sync(cfg.proxy.enabled);
    proxy_on.connect_toggled(move |b| sync(b.is_active()));

    let msg_title = gtk::Label::builder()
        .label("<b>Messages</b>")
        .use_markup(true)
        .xalign(0.0)
        .margin_top(12)
        .build();
    g.attach(&msg_title, 0, 12, 2, 1);
    let desktop_size = app.desktop_mono_font_size();
    let default_label = match desktop_size {
        Some(pt) => format!("Use the desktop's monospace font size ({} pt)", fmt_pt(pt)),
        None => "Use the desktop's monospace font size".to_string(),
    };
    let font_default = gtk::CheckButton::with_label(&default_label);
    font_default.set_active(cfg.message_font_size.is_none());
    g.attach(&font_default, 0, 13, 2, 1);
    let font_size = gtk::SpinButton::with_range(f64::from(MIN_FONT_SIZE), f64::from(MAX_FONT_SIZE), 1.0);
    font_size.set_digits(0);
    font_size.set_value(
        cfg.message_font_size
            .map(f64::from)
            .or(desktop_size)
            .unwrap_or(11.0)
            .round(),
    );
    font_size.set_sensitive(cfg.message_font_size.is_some());
    let size_box = gtk::Box::new(gtk::Orientation::Horizontal, 6);
    size_box.append(&font_size);
    size_box.append(&gtk::Label::new(Some("points")));
    g.attach(&label("Font size"), 0, 14, 1, 1);
    g.attach(&size_box, 1, 14, 1, 1);
    let fs = font_size.clone();
    font_default.connect_toggled(move |b| fs.set_sensitive(!b.is_active()));

    window.set_child(Some(&g));

    let app_w = Rc::downgrade(app);
    let win = window.clone();
    save.connect_clicked(move |_| {
        let Some(app) = app_w.upgrade() else { return };
        if nick.text().trim().is_empty() {
            return show_error(&win, "The nickname cannot be empty.");
        }
        let res = app.update_config(|c| {
            c.nick = nick.text().trim().to_string();
            c.username = username.text().trim().to_string();
            c.realname = realname.text().trim().to_string();
            c.proxy.enabled = proxy_on.is_active();
            c.proxy.host = phost.text().trim().to_string();
            c.proxy.port = pport.value_as_int() as u16;
            c.proxy.username = puser.text().to_string();
            c.proxy.password = ppass.text().to_string();
            c.message_font_size = (!font_default.is_active()).then(|| font_size.value_as_int() as u32);
        });
        match res {
            Ok(()) => win.close(),
            Err(e) => show_error(&win, &e),
        }
    });
    let app_w = Rc::downgrade(app);
    window.connect_close_request(move |_| {
        if let Some(app) = app_w.upgrade() {
            app.prefs_window.borrow_mut().take();
        }
        gtk::glib::Propagation::Proceed
    });
    *app.prefs_window.borrow_mut() = Some(window.clone());
    window.present();
}

// ----- SASL editor (shared by network and server settings) ----------------------------------

struct SaslEditor {
    grid: gtk::Grid,
    mech: gtk::DropDown,
    account: gtk::Entry,
    password: gtk::PasswordEntry,
    cert: gtk::Entry,
    cert_btn: gtk::Button,
}

impl SaslEditor {
    fn new(parent: &gtk::Window) -> Rc<SaslEditor> {
        let g = grid();
        g.set_margin_start(0);
        g.set_margin_end(0);
        let mech =
            gtk::DropDown::from_strings(&["None", "PLAIN (account and password)", "EXTERNAL (client certificate)"]);
        let account = entry();
        let password = password();
        let cert = entry();
        let cert_btn = gtk::Button::with_label("Choose…");
        let cert_box = gtk::Box::new(gtk::Orientation::Horizontal, 6);
        cert_box.append(&cert);
        cert_box.append(&cert_btn);
        g.attach(&label("Mechanism"), 0, 0, 1, 1);
        g.attach(&mech, 1, 0, 1, 1);
        g.attach(&label("Account"), 0, 1, 1, 1);
        g.attach(&account, 1, 1, 1, 1);
        g.attach(&label("Password"), 0, 2, 1, 1);
        g.attach(&password, 1, 2, 1, 1);
        g.attach(&label("Client certificate"), 0, 3, 1, 1);
        g.attach(&cert_box, 1, 3, 1, 1);
        g.attach(
            &hint("For EXTERNAL: a PEM file containing the certificate and its private key."),
            1,
            4,
            1,
            1,
        );
        let ed = Rc::new(SaslEditor {
            grid: g,
            mech,
            account,
            password,
            cert,
            cert_btn,
        });
        let w = Rc::downgrade(&ed);
        ed.mech.connect_selected_notify(move |_| {
            if let Some(ed) = w.upgrade() {
                ed.sync();
            }
        });
        let w = Rc::downgrade(&ed);
        let parent = parent.clone();
        ed.cert_btn.connect_clicked(move |_| {
            let w = w.clone();
            choose_file(&parent, "Choose Client Certificate", move |p| {
                if let Some(ed) = w.upgrade() {
                    ed.cert.set_text(&p.to_string_lossy());
                }
            });
        });
        ed.sync();
        ed
    }

    fn sync(&self) {
        let m = SaslMech::from_index(self.mech.selected());
        self.account.set_sensitive(m == SaslMech::Plain);
        self.password.set_sensitive(m == SaslMech::Plain);
        self.cert.set_sensitive(m == SaslMech::External);
        self.cert_btn.set_sensitive(m == SaslMech::External);
    }

    fn set(&self, s: &Sasl) {
        self.mech.set_selected(s.mech.index());
        self.account.set_text(&s.account);
        self.password.set_text(&s.password);
        self.cert.set_text(&s.cert_file);
        self.sync();
    }

    fn get(&self) -> Sasl {
        Sasl {
            mech: SaslMech::from_index(self.mech.selected()),
            account: self.account.text().trim().to_string(),
            password: self.password.text().to_string(),
            cert_file: self.cert.text().trim().to_string(),
        }
    }

    fn set_sensitive(&self, on: bool) {
        self.grid.set_sensitive(on);
    }
}

// ----- Server dialog ------------------------------------------------------------------------

fn edit_server(parent: &gtk::Window, server: Server, on_ok: impl Fn(Server) + 'static) {
    let title = if server.host.is_empty() {
        "Add Server"
    } else {
        "Edit Server"
    };
    let (window, ok, _) = dialog_window(parent, title, "_OK", true);
    let g = grid();
    let host = entry();
    host.set_text(&server.host);
    host.set_activates_default(true);
    let port = port_spin();
    port.set_value(server.port.into());
    let tls = gtk::CheckButton::with_label("Use TLS");
    tls.set_active(server.tls);
    g.attach(&label("Host name or IP"), 0, 0, 1, 1);
    g.attach(&host, 1, 0, 1, 1);
    g.attach(&label("Port"), 0, 1, 1, 1);
    g.attach(&port, 1, 1, 1, 1);
    g.attach(&tls, 1, 2, 1, 1);
    let override_btn = gtk::CheckButton::with_label("Use different SASL authentication for this server");
    override_btn.set_active(server.sasl.is_some());
    override_btn.set_margin_top(12);
    g.attach(&override_btn, 0, 3, 2, 1);
    let sasl = SaslEditor::new(&window);
    sasl.set(&server.sasl.clone().unwrap_or_default());
    sasl.set_sensitive(server.sasl.is_some());
    g.attach(&sasl.grid, 0, 4, 2, 1);
    let s2 = sasl.clone();
    override_btn.connect_toggled(move |b| s2.set_sensitive(b.is_active()));
    // Port follows the TLS toggle when it is at a standard value.
    let p2 = port.clone();
    tls.connect_toggled(move |b| match (b.is_active(), p2.value_as_int()) {
        (true, 6667) => p2.set_value(6697.0),
        (false, 6697) => p2.set_value(6667.0),
        _ => {}
    });
    window.set_child(Some(&g));
    let win = window.clone();
    ok.connect_clicked(move |_| {
        let h = host.text().trim().to_string();
        if h.is_empty() {
            return show_error(&win, "Enter a host name or IP address.");
        }
        on_ok(Server {
            host: h,
            port: port.value_as_int() as u16,
            tls: tls.is_active(),
            sasl: override_btn.is_active().then(|| sasl.get()),
        });
        win.close();
    });
    window.present();
}

// ----- Networks window ----------------------------------------------------------------------

pub struct NetworksWindow {
    app: Weak<App>,
    window: gtk::Window,
    list: gtk::ListBox,
    editor: gtk::Notebook,
    remove_btn: gtk::Button,
    nets: RefCell<Vec<Network>>,
    current: Cell<Option<usize>>,
    loading: Cell<bool>,
    // General
    name: gtk::Entry,
    autoconnect: gtk::CheckButton,
    use_proxy: gtk::CheckButton,
    nick: gtk::Entry,
    username: gtk::Entry,
    realname: gtk::Entry,
    autojoin: gtk::Entry,
    // Servers
    servers_list: gtk::ListBox,
    servers: RefCell<Vec<Server>>,
    // Authentication
    sasl: Rc<SaslEditor>,
    // TLS
    use_system_cas: gtk::CheckButton,
    certs_list: gtk::ListBox,
    certs: RefCell<Vec<String>>,
    // Bouncer
    b_enabled: gtk::CheckButton,
    b_host: gtk::Entry,
    b_port: gtk::SpinButton,
    b_tls: gtk::CheckButton,
    b_user: gtk::Entry,
    b_network: gtk::Entry,
    b_pass: gtk::PasswordEntry,
    b_grid: gtk::Grid,
}

fn list_row(text: &str) -> gtk::Label {
    gtk::Label::builder()
        .label(text)
        .xalign(0.0)
        .margin_top(6)
        .margin_bottom(6)
        .margin_start(8)
        .margin_end(8)
        .build()
}

fn clear_list(list: &gtk::ListBox) {
    while let Some(c) = list.first_child() {
        list.remove(&c);
    }
}

fn button_column(buttons: &[&gtk::Button]) -> gtk::Box {
    let b = gtk::Box::new(gtk::Orientation::Vertical, 6);
    for btn in buttons {
        b.append(*btn);
    }
    b
}

fn framed_list(list: &gtk::ListBox, height: i32) -> gtk::ScrolledWindow {
    gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .min_content_height(height)
        .hexpand(true)
        .vexpand(true)
        .has_frame(true)
        .child(list)
        .build()
}

pub fn show_networks(app: &Rc<App>) {
    if let Some(w) = app.networks_window.borrow().as_ref() {
        w.window.present();
        return;
    }
    let nw = NetworksWindow::new(app);
    *app.networks_window.borrow_mut() = Some(nw.clone());
    nw.window.present();
}

impl NetworksWindow {
    fn new(app: &Rc<App>) -> Rc<NetworksWindow> {
        let (window, save, _) = dialog_window(&app.window, "Networks", "_Save", false);
        window.set_default_size(720, 520);

        // Sidebar
        let list = gtk::ListBox::builder()
            .selection_mode(gtk::SelectionMode::Browse)
            .build();
        let add_btn = gtk::Button::from_icon_name("list-add-symbolic");
        add_btn.set_tooltip_text(Some("Add Network"));
        let remove_btn = gtk::Button::from_icon_name("list-remove-symbolic");
        remove_btn.set_tooltip_text(Some("Remove Network"));
        let sidebar_btns = gtk::Box::new(gtk::Orientation::Horizontal, 6);
        sidebar_btns.append(&add_btn);
        sidebar_btns.append(&remove_btn);
        let sidebar = gtk::Box::new(gtk::Orientation::Vertical, 6);
        sidebar.set_margin_top(12);
        sidebar.set_margin_bottom(12);
        sidebar.set_margin_start(12);
        let side_sw = framed_list(&list, 200);
        side_sw.set_min_content_width(160);
        side_sw.set_hexpand(false);
        sidebar.append(&side_sw);
        sidebar.append(&sidebar_btns);

        // General page
        let g = grid();
        let name = entry();
        let autoconnect = gtk::CheckButton::with_label("Connect automatically when IrcGoo starts");
        let use_proxy = gtk::CheckButton::with_label("Use the SOCKS5 proxy (when enabled in Preferences)");
        let nick = entry();
        let username = entry();
        let realname = entry();
        let autojoin = entry();
        let cfg = app.config.borrow().clone();
        nick.set_placeholder_text(Some(&format!("Default: {}", cfg.nick)));
        username.set_placeholder_text(Some(&format!("Default: {}", cfg.username)));
        realname.set_placeholder_text(Some(&format!("Default: {}", cfg.realname)));
        autojoin.set_placeholder_text(Some("#channel, #other key"));
        g.attach(&label("Name"), 0, 0, 1, 1);
        g.attach(&name, 1, 0, 1, 1);
        g.attach(&autoconnect, 1, 1, 1, 1);
        g.attach(&use_proxy, 1, 2, 1, 1);
        g.attach(&label("Nickname"), 0, 3, 1, 1);
        g.attach(&nick, 1, 3, 1, 1);
        g.attach(&label("Username"), 0, 4, 1, 1);
        g.attach(&username, 1, 4, 1, 1);
        g.attach(&label("Real name"), 0, 5, 1, 1);
        g.attach(&realname, 1, 5, 1, 1);
        g.attach(&label("Channels to join"), 0, 6, 1, 1);
        g.attach(&autojoin, 1, 6, 1, 1);
        g.attach(
            &hint("Comma-separated. Leave identity fields empty to use the defaults from Preferences."),
            1,
            7,
            1,
            1,
        );

        // Servers page
        let sg = grid();
        let servers_list = gtk::ListBox::new();
        let s_add = gtk::Button::with_label("Add…");
        let s_edit = gtk::Button::with_label("Edit…");
        let s_remove = gtk::Button::with_label("Remove");
        let s_up = gtk::Button::with_label("Move Up");
        let s_down = gtk::Button::with_label("Move Down");
        sg.attach(&framed_list(&servers_list, 160), 0, 0, 1, 1);
        sg.attach(
            &button_column(&[&s_add, &s_edit, &s_remove, &s_up, &s_down]),
            1,
            0,
            1,
            1,
        );
        sg.attach(&hint("Servers are tried in order. The same host may appear more than once with different ports or TLS settings."), 0, 1, 2, 1);

        // Authentication page
        let ag = grid();
        let sasl = SaslEditor::new(&window);
        ag.attach(&sasl.grid, 0, 0, 1, 1);
        ag.attach(&hint("SASL authentication for this network. Individual servers can override it. Leave it at None for unauthenticated connections."), 0, 1, 1, 1);

        // TLS page
        let tg = grid();
        let use_system_cas = gtk::CheckButton::with_label("Trust the system's certificate authorities");
        let certs_list = gtk::ListBox::new();
        let c_add = gtk::Button::with_label("Add…");
        let c_remove = gtk::Button::with_label("Remove");
        tg.attach(&use_system_cas, 0, 0, 2, 1);
        tg.attach(
            &gtk::Label::builder()
                .label("Additional trusted certificates:")
                .xalign(0.0)
                .build(),
            0,
            1,
            2,
            1,
        );
        tg.attach(&framed_list(&certs_list, 120), 0, 2, 1, 1);
        tg.attach(&button_column(&[&c_add, &c_remove]), 1, 2, 1, 1);
        tg.attach(
            &hint("PEM files with CA certificates, or a server's own certificate (for example a self-signed bouncer certificate), which is then trusted exactly."),
            0,
            3,
            2,
            1,
        );

        // Bouncer page
        let bg = grid();
        let b_enabled = gtk::CheckButton::with_label("Connect through an IRC bouncer (such as ZNC)");
        let b_host = entry();
        let b_port = port_spin();
        let b_tls = gtk::CheckButton::with_label("Use TLS");
        let b_user = entry();
        let b_network = entry();
        let b_pass = password();
        let b_grid = grid();
        b_grid.set_margin_start(0);
        b_grid.set_margin_top(0);
        b_grid.attach(&label("Host"), 0, 0, 1, 1);
        b_grid.attach(&b_host, 1, 0, 1, 1);
        b_grid.attach(&label("Port"), 0, 1, 1, 1);
        b_grid.attach(&b_port, 1, 1, 1, 1);
        b_grid.attach(&b_tls, 1, 2, 1, 1);
        b_grid.attach(&label("Username"), 0, 3, 1, 1);
        b_grid.attach(&b_user, 1, 3, 1, 1);
        b_grid.attach(&label("Bouncer network"), 0, 4, 1, 1);
        b_grid.attach(&b_network, 1, 4, 1, 1);
        b_grid.attach(&label("Password"), 0, 5, 1, 1);
        b_grid.attach(&b_pass, 1, 5, 1, 1);
        bg.attach(&b_enabled, 0, 0, 1, 1);
        bg.attach(&b_grid, 0, 1, 1, 1);
        bg.attach(&hint("When enabled, IrcGoo connects to the bouncer instead of the server list and logs in with PASS username/network:password. TLS trust settings still apply."), 0, 2, 1, 1);

        let editor = gtk::Notebook::new();
        editor.set_hexpand(true);
        editor.append_page(&g, Some(&gtk::Label::new(Some("General"))));
        editor.append_page(&sg, Some(&gtk::Label::new(Some("Servers"))));
        editor.append_page(&ag, Some(&gtk::Label::new(Some("Authentication"))));
        editor.append_page(&tg, Some(&gtk::Label::new(Some("TLS"))));
        editor.append_page(&bg, Some(&gtk::Label::new(Some("Bouncer"))));
        editor.set_margin_top(12);
        editor.set_margin_bottom(12);
        editor.set_margin_end(12);

        let body = gtk::Box::new(gtk::Orientation::Horizontal, 12);
        body.append(&sidebar);
        body.append(&editor);
        window.set_child(Some(&body));

        let nw = Rc::new(NetworksWindow {
            app: Rc::downgrade(app),
            window,
            list,
            editor,
            remove_btn,
            nets: RefCell::new(cfg.networks.clone()),
            current: Cell::new(None),
            loading: Cell::new(false),
            name,
            autoconnect,
            use_proxy,
            nick,
            username,
            realname,
            autojoin,
            servers_list,
            servers: RefCell::new(Vec::new()),
            sasl,
            use_system_cas,
            certs_list,
            certs: RefCell::new(Vec::new()),
            b_enabled,
            b_host,
            b_port,
            b_tls,
            b_user,
            b_network,
            b_pass,
            b_grid,
        });

        for n in nw.nets.borrow().iter() {
            nw.list.append(&list_row(&n.name));
        }

        let w = Rc::downgrade(&nw);
        nw.list.connect_row_selected(move |_, row| {
            if let Some(nw) = w.upgrade() {
                nw.store_current();
                nw.current.set(row.map(|r| r.index() as usize));
                nw.load_current();
            }
        });
        let w = Rc::downgrade(&nw);
        nw.name.connect_changed(move |e| {
            let Some(nw) = w.upgrade() else { return };
            if nw.loading.get() {
                return;
            }
            if let Some(row) = nw.current.get().and_then(|i| nw.list.row_at_index(i as i32))
                && let Some(l) = row.child().and_downcast::<gtk::Label>()
            {
                l.set_text(&e.text());
            }
        });
        let w = Rc::downgrade(&nw);
        nw.b_enabled.connect_toggled(move |b| {
            if let Some(nw) = w.upgrade() {
                nw.b_grid.set_sensitive(b.is_active());
            }
        });

        let w = Rc::downgrade(&nw);
        add_btn.connect_clicked(move |_| {
            let Some(nw) = w.upgrade() else { return };
            nw.store_current();
            let mut n = 1;
            let name = loop {
                let candidate = if n == 1 {
                    "New Network".to_string()
                } else {
                    format!("New Network {n}")
                };
                if !nw.nets.borrow().iter().any(|x| x.name.eq_ignore_ascii_case(&candidate)) {
                    break candidate;
                }
                n += 1;
            };
            nw.nets.borrow_mut().push(Network {
                name: name.clone(),
                ..Network::default()
            });
            nw.list.append(&list_row(&name));
            let idx = nw.nets.borrow().len() as i32 - 1;
            nw.list.select_row(nw.list.row_at_index(idx).as_ref());
            nw.editor.set_current_page(Some(0));
            nw.name.grab_focus();
        });
        let w = Rc::downgrade(&nw);
        nw.remove_btn.connect_clicked(move |_| {
            let Some(nw) = w.upgrade() else { return };
            let Some(i) = nw.current.get() else { return };
            nw.current.set(None);
            nw.nets.borrow_mut().remove(i);
            if let Some(row) = nw.list.row_at_index(i as i32) {
                nw.list.remove(&row);
            }
            let len = nw.nets.borrow().len();
            if len > 0 {
                nw.list.select_row(nw.list.row_at_index(i.min(len - 1) as i32).as_ref());
            } else {
                nw.load_current();
            }
        });

        // Server list buttons
        let w = Rc::downgrade(&nw);
        s_add.connect_clicked(move |_| {
            let Some(nw) = w.upgrade() else { return };
            let w2 = Rc::downgrade(&nw);
            edit_server(&nw.window, Server::default(), move |s| {
                if let Some(nw) = w2.upgrade() {
                    nw.servers.borrow_mut().push(s);
                    nw.refresh_servers(Some(nw.servers.borrow().len() - 1));
                }
            });
        });
        let w = Rc::downgrade(&nw);
        let edit = move || {
            let Some(nw) = w.upgrade() else { return };
            let Some(i) = nw.servers_list.selected_row().map(|r| r.index() as usize) else {
                return;
            };
            let Some(server) = nw.servers.borrow().get(i).cloned() else {
                return;
            };
            let w2 = Rc::downgrade(&nw);
            edit_server(&nw.window, server, move |s| {
                if let Some(nw) = w2.upgrade() {
                    nw.servers.borrow_mut()[i] = s;
                    nw.refresh_servers(Some(i));
                }
            });
        };
        let edit = Rc::new(edit);
        let e2 = edit.clone();
        s_edit.connect_clicked(move |_| e2());
        nw.servers_list.connect_row_activated(move |_, _| edit());
        let w = Rc::downgrade(&nw);
        s_remove.connect_clicked(move |_| {
            let Some(nw) = w.upgrade() else { return };
            let Some(i) = nw.servers_list.selected_row().map(|r| r.index() as usize) else {
                return;
            };
            nw.servers.borrow_mut().remove(i);
            let len = nw.servers.borrow().len();
            nw.refresh_servers((len > 0).then(|| i.min(len - 1)));
        });
        for (btn, up) in [(&s_up, true), (&s_down, false)] {
            let w = Rc::downgrade(&nw);
            btn.connect_clicked(move |_| {
                let Some(nw) = w.upgrade() else { return };
                let Some(i) = nw.servers_list.selected_row().map(|r| r.index() as usize) else {
                    return;
                };
                let len = nw.servers.borrow().len();
                let j = if up {
                    i.checked_sub(1)
                } else {
                    (i + 1 < len).then_some(i + 1)
                };
                if let Some(j) = j {
                    nw.servers.borrow_mut().swap(i, j);
                    nw.refresh_servers(Some(j));
                }
            });
        }

        // Certificate list buttons
        let w = Rc::downgrade(&nw);
        c_add.connect_clicked(move |_| {
            let Some(nw) = w.upgrade() else { return };
            let w2 = Rc::downgrade(&nw);
            choose_file(&nw.window, "Add Trusted Certificate", move |p| {
                if let Some(nw) = w2.upgrade() {
                    nw.certs.borrow_mut().push(p.to_string_lossy().into_owned());
                    nw.refresh_certs();
                }
            });
        });
        let w = Rc::downgrade(&nw);
        c_remove.connect_clicked(move |_| {
            let Some(nw) = w.upgrade() else { return };
            if let Some(i) = nw.certs_list.selected_row().map(|r| r.index() as usize) {
                nw.certs.borrow_mut().remove(i);
                nw.refresh_certs();
            }
        });

        let w = Rc::downgrade(&nw);
        save.connect_clicked(move |_| {
            if let Some(nw) = w.upgrade() {
                nw.save();
            }
        });
        let w = Rc::downgrade(&nw);
        nw.window.connect_close_request(move |_| {
            if let Some(app) = w.upgrade().and_then(|nw| nw.app.upgrade()) {
                app.networks_window.borrow_mut().take();
            }
            gtk::glib::Propagation::Proceed
        });

        if nw.nets.borrow().is_empty() {
            nw.load_current();
        } else {
            nw.list.select_row(nw.list.row_at_index(0).as_ref());
        }
        nw
    }

    fn refresh_servers(&self, select: Option<usize>) {
        clear_list(&self.servers_list);
        for s in self.servers.borrow().iter() {
            let extra = if s.sasl.is_some() {
                "  — own SASL settings"
            } else {
                ""
            };
            self.servers_list.append(&list_row(&format!("{}{extra}", s.describe())));
        }
        if let Some(i) = select {
            self.servers_list
                .select_row(self.servers_list.row_at_index(i as i32).as_ref());
        }
    }

    fn refresh_certs(&self) {
        clear_list(&self.certs_list);
        for c in self.certs.borrow().iter() {
            self.certs_list.append(&list_row(c));
        }
    }

    fn load_current(&self) {
        self.loading.set(true);
        let net = self.current.get().and_then(|i| self.nets.borrow().get(i).cloned());
        self.editor.set_sensitive(net.is_some());
        self.remove_btn.set_sensitive(net.is_some());
        let n = net.unwrap_or_default();
        self.name.set_text(&n.name);
        self.autoconnect.set_active(n.autoconnect);
        self.use_proxy.set_active(n.use_proxy);
        self.nick.set_text(&n.nick);
        self.username.set_text(&n.username);
        self.realname.set_text(&n.realname);
        self.autojoin.set_text(&n.autojoin.join(", "));
        *self.servers.borrow_mut() = n.servers.clone();
        self.refresh_servers(None);
        self.sasl.set(&n.sasl);
        self.use_system_cas.set_active(n.use_system_cas);
        *self.certs.borrow_mut() = n.trusted_certs.clone();
        self.refresh_certs();
        let b = &n.bouncer;
        self.b_enabled.set_active(b.enabled);
        self.b_grid.set_sensitive(b.enabled);
        self.b_host.set_text(&b.host);
        self.b_port.set_value(b.port.into());
        self.b_tls.set_active(b.tls);
        self.b_user.set_text(&b.username);
        self.b_network.set_text(&b.network);
        self.b_pass.set_text(&b.password);
        self.loading.set(false);
    }

    fn store_current(&self) {
        let Some(i) = self.current.get() else { return };
        let mut nets = self.nets.borrow_mut();
        let Some(n) = nets.get_mut(i) else { return };
        n.name = self.name.text().trim().to_string();
        n.autoconnect = self.autoconnect.is_active();
        n.use_proxy = self.use_proxy.is_active();
        n.nick = self.nick.text().trim().to_string();
        n.username = self.username.text().trim().to_string();
        n.realname = self.realname.text().trim().to_string();
        n.autojoin = self
            .autojoin
            .text()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        n.servers = self.servers.borrow().clone();
        n.sasl = self.sasl.get();
        n.use_system_cas = self.use_system_cas.is_active();
        n.trusted_certs = self.certs.borrow().clone();
        n.bouncer = Bouncer {
            enabled: self.b_enabled.is_active(),
            host: self.b_host.text().trim().to_string(),
            port: self.b_port.value_as_int() as u16,
            tls: self.b_tls.is_active(),
            username: self.b_user.text().trim().to_string(),
            network: self.b_network.text().trim().to_string(),
            password: self.b_pass.text().to_string(),
        };
    }

    fn save(&self) {
        self.store_current();
        let nets = self.nets.borrow().clone();
        for (i, n) in nets.iter().enumerate() {
            if n.name.is_empty() {
                return show_error(&self.window, "Every network needs a name.");
            }
            if nets[..i].iter().any(|o| o.name.eq_ignore_ascii_case(&n.name)) {
                return show_error(
                    &self.window,
                    &format!("There is more than one network named \"{}\".", n.name),
                );
            }
            if n.bouncer.enabled && n.bouncer.host.is_empty() {
                return show_error(
                    &self.window,
                    &format!("Network \"{}\" uses a bouncer but has no bouncer host.", n.name),
                );
            }
        }
        let Some(app) = self.app.upgrade() else { return };
        match app.update_config(|c| c.networks = nets) {
            Ok(()) => self.window.close(),
            Err(e) => show_error(&self.window, &e),
        }
    }
}
