//! One notebook tab: message view, optional nick list, and the bottom bar (nick, lag, entry).

use crate::irc::{self, Style};
use gtk::prelude::*;
use gtk::{gdk, gio, glib, pango};
use std::cell::{Cell, RefCell};
use std::rc::Rc;

/// Lines kept per tab; older lines are trimmed (logging will be a separate feature).
const MAX_LINES: usize = 5000;

/// Nick colours for light themes.
const NICK_COLORS: [&str; 12] = [
    "#c01c28", "#26a269", "#1c71d8", "#a347ba", "#e66100", "#2190a4", "#9c6e03", "#c64600", "#3a8f3a", "#813d9c",
    "#0e7d8c", "#b5835a",
];
/// The same hues, lightened for dark themes.
const NICK_COLORS_DARK: [&str; 12] = [
    "#f66151", "#57e389", "#62a0ea", "#dc8add", "#ffa348", "#5ec7d9", "#e5c64f", "#ff8c5a", "#8ff0a4", "#c88fe0",
    "#4fd1c5", "#d9b38c",
];

/// Text tags with their light-theme and dark-theme foreground colours.
const TAG_COLORS: [(&str, &str, &str); 7] = [
    ("time", "#888888", "#9a9996"),
    ("marker", "#3584e4", "#78aeed"),
    ("dim", "#888888", "#9a9996"),
    ("error", "#e01b24", "#ff7b63"),
    ("join", "#26a269", "#57e389"),
    ("part", "#c64600", "#ff8c5a"),
    ("notice", "#a347ba", "#dc8add"),
];

const MIRC_COLORS: [&str; 16] = [
    "#ffffff", "#000000", "#00007f", "#009300", "#ff0000", "#7f0000", "#9c009c", "#fc7f00", "#ffff00", "#00fc00",
    "#009393", "#00ffff", "#0000fc", "#ff00ff", "#7f7f7f", "#d2d2d2",
];

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum TabKind {
    Home,
    Status(String),
    Channel(String, String),
    Query(String, String),
}

impl TabKind {
    pub fn network(&self) -> Option<&str> {
        match self {
            TabKind::Home => None,
            TabKind::Status(n) | TabKind::Channel(n, _) | TabKind::Query(n, _) => Some(n),
        }
    }
    pub fn target(&self) -> Option<&str> {
        match self {
            TabKind::Channel(_, t) | TabKind::Query(_, t) => Some(t),
            _ => None,
        }
    }
    pub fn title(&self) -> String {
        match self {
            TabKind::Home => "IrcGoo".into(),
            TabKind::Status(n) => n.clone(),
            TabKind::Channel(_, t) | TabKind::Query(_, t) => t.clone(),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Activity {
    None,
    Message,
    Highlight,
}

pub enum Part<'a> {
    /// Literal text with an optional tag name ("" for none).
    Text(&'a str, &'static str),
    /// A nick, coloured by hash.
    Nick(&'a str),
    /// IRC text that may contain mIRC formatting codes.
    Irc(&'a str),
}

pub struct Completion {
    pub start: usize,
    pub candidates: Vec<String>,
    pub index: usize,
    pub suffix: String,
}

pub struct Tab {
    pub kind: RefCell<TabKind>,
    pub root: gtk::Box,
    pub label: gtk::Label,
    pub view: gtk::TextView,
    pub buffer: gtk::TextBuffer,
    /// Extra context menu section: "Open Link" when the pointer was last pressed on a URL.
    link_menu: gio::Menu,
    pub scroller: gtk::ScrolledWindow,
    end_mark: gtk::TextMark,
    /// Whether the view should stay scrolled to the end: true until the user scrolls away from it.
    follow_end: Rc<Cell<bool>>,
    pub nick_label: gtk::Label,
    pub lag_label: gtk::Label,
    pub entry: gtk::Entry,
    pub nicklist: Option<NickList>,
    pub history: RefCell<Vec<String>>,
    pub history_pos: Cell<Option<usize>>,
    pub history_draft: RefCell<String>,
    pub completion: RefCell<Option<Completion>>,
    pub completing: Cell<bool>,
    lines: Cell<usize>,
    pub activity: Cell<Activity>,
}

pub struct NickList {
    pub container: gtk::Box,
    pub list: gtk::ListBox,
    pub popover: gtk::PopoverMenu,
    /// Nick for each row, by row index.
    pub nicks: RefCell<Vec<String>>,
    pub labels: RefCell<Vec<gtk::Label>>,
}

thread_local! {
    static TAG_TABLE: gtk::TextTagTable = build_tag_table();
}

fn build_tag_table() -> gtk::TextTagTable {
    let table = gtk::TextTagTable::new();
    let add = |tag: gtk::TextTag| {
        table.add(&tag);
    };
    for (name, light, _) in TAG_COLORS {
        add(gtk::TextTag::builder().name(name).foreground(light).build());
    }
    add(gtk::TextTag::builder().name("own").weight(700).build());
    add(gtk::TextTag::builder()
        .name("highlight")
        .background_rgba(&gdk::RGBA::new(1.0, 0.75, 0.0, 0.25))
        .paragraph_background_rgba(&gdk::RGBA::new(1.0, 0.75, 0.0, 0.18))
        .build());
    add(gtk::TextTag::builder().name("b").weight(700).build());
    add(gtk::TextTag::builder().name("i").style(pango::Style::Italic).build());
    add(gtk::TextTag::builder()
        .name("u")
        .underline(pango::Underline::Single)
        .build());
    add(gtk::TextTag::builder().name("s").strikethrough(true).build());
    add(gtk::TextTag::builder().name("m").family("monospace").build());
    for (i, c) in NICK_COLORS.iter().enumerate() {
        add(gtk::TextTag::builder().name(format!("nick{i}")).foreground(*c).build());
    }
    for (i, c) in MIRC_COLORS.iter().enumerate() {
        add(gtk::TextTag::builder().name(format!("fg{i}")).foreground(*c).build());
        add(gtk::TextTag::builder().name(format!("bg{i}")).background(*c).build());
    }
    table
}

/// Switch the shared text tags between colours for light and dark themes. mIRC colour
/// codes are left alone: they are absolute colours chosen by the sender.
pub fn set_dark_palette(dark: bool) {
    TAG_TABLE.with(|table| {
        let set = |name: &str, color: &str| {
            if let Some(tag) = table.lookup(name) {
                tag.set_foreground(Some(color));
            }
        };
        for (name, light, dark_color) in TAG_COLORS {
            set(name, if dark { dark_color } else { light });
        }
        let nick_colors = if dark { &NICK_COLORS_DARK } else { &NICK_COLORS };
        for (i, c) in nick_colors.iter().enumerate() {
            set(&format!("nick{i}"), c);
        }
    });
}

pub fn nick_tag(nick: &str) -> String {
    let mut h: u32 = 2166136261;
    for b in irc::irc_lower(nick).bytes() {
        h = (h ^ u32::from(b)).wrapping_mul(16777619);
    }
    format!("nick{}", h as usize % NICK_COLORS.len())
}

fn style_tags(st: &Style) -> Vec<String> {
    let mut v = Vec::new();
    if st.bold {
        v.push("b".to_string());
    }
    if st.italic {
        v.push("i".to_string());
    }
    if st.underline {
        v.push("u".to_string());
    }
    if st.strike {
        v.push("s".to_string());
    }
    if st.mono {
        v.push("m".to_string());
    }
    let (fg, bg) = if st.reverse {
        (st.bg.or(Some(0)), st.fg.or(Some(1)))
    } else {
        (st.fg, st.bg)
    };
    if let Some(f) = fg {
        v.push(format!("fg{f}"));
    }
    if let Some(b) = bg {
        v.push(format!("bg{b}"));
    }
    v
}

pub fn now_hms() -> String {
    glib::DateTime::now_local()
        .ok()
        .and_then(|d| d.format("%H:%M:%S").ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "--:--:--".into())
}

fn at_end(adj: &gtk::Adjustment) -> bool {
    adj.value() + adj.page_size() >= adj.upper() - 8.0
}

/// Keep `follow` up to date and keep the view at the end while it is set.
///
/// The adjustment's value changes both when the user scrolls and when GTK
/// lays the text out again for a new geometry (window resize, rewrapped lines,
/// the nick list shown or hidden, a tab shown for the first time after a
/// resize). While such a relayout is in progress, GtkTextView also restores
/// its own earlier offset, which would look like the user scrolling. So after
/// any change of the content height or page size, value changes are ignored
/// until the main loop is idle (text validation runs at a higher priority);
/// then the view returns to the end if it was following it. Other value
/// changes are the user scrolling and decide whether to follow the end.
fn track_follow_end(adj: &gtk::Adjustment, follow: &Rc<Cell<bool>>) {
    let geometry = Rc::new(Cell::new((adj.upper(), adj.page_size())));
    let settling = Rc::new(Cell::new(false));
    let relayout = {
        let follow = follow.clone();
        let geometry = geometry.clone();
        let settling = settling.clone();
        move |adj: &gtk::Adjustment| {
            geometry.set((adj.upper(), adj.page_size()));
            if settling.replace(true) {
                return;
            }
            let (adj, follow, settling) = (adj.clone(), follow.clone(), settling.clone());
            glib::idle_add_local_full(glib::Priority::LOW, move || {
                settling.set(false);
                if follow.get() && !at_end(&adj) {
                    adj.set_value(adj.upper() - adj.page_size());
                }
                glib::ControlFlow::Break
            });
        }
    };
    let relayout = Rc::new(relayout);
    let r = relayout.clone();
    adj.connect_changed(move |adj| r(adj));
    let follow = follow.clone();
    adj.connect_value_changed(move |adj| {
        if geometry.get() != (adj.upper(), adj.page_size()) {
            relayout(adj);
        } else if !settling.get() {
            follow.set(at_end(adj));
        }
    });
}

impl Tab {
    pub fn new(kind: TabKind, nicklist_visible: bool) -> Tab {
        let buffer = TAG_TABLE.with(|t| gtk::TextBuffer::new(Some(t)));
        let view = gtk::TextView::builder()
            .buffer(&buffer)
            .editable(false)
            .cursor_visible(false)
            .wrap_mode(gtk::WrapMode::WordChar)
            .monospace(true)
            .left_margin(4)
            .right_margin(4)
            .pixels_above_lines(1)
            .build();
        view.add_css_class("ircgoo-messages");
        let link_menu = gio::Menu::new();
        view.set_extra_menu(Some(&link_menu));
        let scroller = gtk::ScrolledWindow::builder()
            .hscrollbar_policy(gtk::PolicyType::Never)
            .vexpand(true)
            .hexpand(true)
            .child(&view)
            .build();
        let end_mark = buffer.create_mark(Some("end"), &buffer.end_iter(), false);
        let follow_end = Rc::new(Cell::new(true));
        track_follow_end(&scroller.vadjustment(), &follow_end);

        let nicklist = matches!(kind, TabKind::Channel(..)).then(|| {
            let list = gtk::ListBox::builder().selection_mode(gtk::SelectionMode::None).build();
            list.add_css_class("ircgoo-nicklist");
            let sw = gtk::ScrolledWindow::builder()
                .hscrollbar_policy(gtk::PolicyType::Never)
                .min_content_width(110)
                .vexpand(true)
                .child(&list)
                .build();
            let container = gtk::Box::new(gtk::Orientation::Vertical, 0);
            container.append(&sw);
            container.set_visible(nicklist_visible);
            let popover = gtk::PopoverMenu::from_model(None::<&gtk::gio::MenuModel>);
            popover.set_has_arrow(false);
            popover.set_halign(gtk::Align::Start);
            popover.set_parent(&container);
            NickList {
                container,
                list,
                popover,
                nicks: RefCell::new(Vec::new()),
                labels: RefCell::new(Vec::new()),
            }
        });

        let body: gtk::Widget = match &nicklist {
            Some(nl) => {
                let paned = gtk::Paned::builder()
                    .orientation(gtk::Orientation::Horizontal)
                    .start_child(&scroller)
                    .end_child(&nl.container)
                    .resize_start_child(true)
                    .resize_end_child(false)
                    .shrink_end_child(false)
                    .wide_handle(false)
                    .vexpand(true)
                    .build();
                paned.upcast()
            }
            None => scroller.clone().upcast(),
        };

        let nick_label = gtk::Label::builder().xalign(0.0).build();
        nick_label.add_css_class("ircgoo-nick");
        let lag_label = gtk::Label::builder().visible(false).build();
        lag_label.add_css_class("ircgoo-lag");
        let entry = gtk::Entry::builder().hexpand(true).build();
        entry.add_css_class("ircgoo-entry");
        let bottom = gtk::Box::new(gtk::Orientation::Horizontal, 6);
        bottom.add_css_class("ircgoo-bottom");
        bottom.append(&nick_label);
        bottom.append(&lag_label);
        bottom.append(&entry);

        let root = gtk::Box::new(gtk::Orientation::Vertical, 0);
        root.append(&body);
        root.append(&bottom);

        let label = gtk::Label::new(Some(&kind.title()));
        label.add_css_class("ircgoo-tab-label");

        Tab {
            kind: RefCell::new(kind),
            root,
            label,
            view,
            buffer,
            link_menu,
            scroller,
            end_mark,
            follow_end,
            nick_label,
            lag_label,
            entry,
            nicklist,
            history: RefCell::new(Vec::new()),
            history_pos: Cell::new(None),
            history_draft: RefCell::new(String::new()),
            completion: RefCell::new(None),
            completing: Cell::new(false),
            lines: Cell::new(0),
            activity: Cell::new(Activity::None),
        }
    }

    pub fn kind(&self) -> TabKind {
        self.kind.borrow().clone()
    }

    pub fn network(&self) -> Option<String> {
        self.kind.borrow().network().map(str::to_string)
    }

    pub fn target(&self) -> Option<String> {
        self.kind.borrow().target().map(str::to_string)
    }

    pub fn set_kind(&self, kind: TabKind) {
        self.label.set_text(&kind.title());
        *self.kind.borrow_mut() = kind;
    }

    /// Append one line, prefixed with the local time.
    pub fn line(&self, parts: &[Part], line_tag: Option<&str>) {
        let buf = &self.buffer;
        let mut iter = buf.end_iter();
        let line_start = iter.offset();
        if self.lines.get() > 0 {
            buf.insert(&mut iter, "\n");
        }
        buf.insert_with_tags_by_name(&mut iter, &now_hms(), &["time"]);
        buf.insert(&mut iter, " ");
        for part in parts {
            match part {
                Part::Text(t, tag) => {
                    if tag.is_empty() {
                        buf.insert(&mut iter, t);
                    } else {
                        buf.insert_with_tags_by_name(&mut iter, t, &[tag]);
                    }
                }
                Part::Nick(n) => {
                    let tag = nick_tag(n);
                    buf.insert_with_tags_by_name(&mut iter, n, &[tag.as_str()]);
                }
                Part::Irc(text) => {
                    for (st, chunk) in irc::parse_formatting(text) {
                        let tags = style_tags(&st);
                        let refs: Vec<&str> = tags.iter().map(String::as_str).collect();
                        buf.insert_with_tags_by_name(&mut iter, &chunk, &refs);
                    }
                }
            }
        }
        if let Some(tag) = line_tag {
            let start = buf.iter_at_offset(line_start);
            buf.apply_tag_by_name(tag, &start, &buf.end_iter());
        }
        self.lines.set(self.lines.get() + 1);
        if self.lines.get() > MAX_LINES {
            let excess = (self.lines.get() - MAX_LINES) as i32;
            if let Some(mut end) = buf.iter_at_line(excess) {
                let mut start = buf.start_iter();
                buf.delete(&mut start, &mut end);
                self.lines.set(MAX_LINES);
            }
        }
        if self.follow_end.get() {
            buf.move_mark(&self.end_mark, &buf.end_iter());
            self.view.scroll_mark_onscreen(&self.end_mark);
        }
    }

    /// Offer "Open Link" in the context menu only if view position `x`, `y` is on a URL.
    pub fn update_link_menu(&self, x: f64, y: f64) {
        self.link_menu.remove_all();
        let (bx, by) = self
            .view
            .window_to_buffer_coords(gtk::TextWindowType::Widget, x as i32, y as i32);
        let Some(iter) = self.view.iter_at_location(bx, by) else {
            return;
        };
        let mut start = iter;
        start.set_line_offset(0);
        let mut end = iter;
        if !end.ends_line() {
            end.forward_to_line_end();
        }
        let text = self.buffer.text(&start, &end, true);
        if let Some(url) = irc::url_at(&text, iter.line_offset() as usize) {
            let item = gio::MenuItem::new(Some("Open Link"), None);
            item.set_action_and_target_value(Some("win.open-link"), Some(&url.to_variant()));
            self.link_menu.append_item(&item);
        }
    }

    pub fn clear(&self) {
        self.buffer.set_text("");
        self.lines.set(0);
        self.follow_end.set(true);
    }

    pub fn scroll_page(&self, down: bool) {
        let adj = self.scroller.vadjustment();
        let step = adj.page_size() * 0.9;
        let v = if down { adj.value() + step } else { adj.value() - step };
        adj.set_value(v.clamp(adj.lower(), adj.upper() - adj.page_size()));
    }

    pub fn set_activity(&self, a: Activity) {
        self.activity.set(a);
        self.label.remove_css_class("activity");
        self.label.remove_css_class("highlight");
        match a {
            Activity::None => {}
            Activity::Message => self.label.add_css_class("activity"),
            Activity::Highlight => self.label.add_css_class("highlight"),
        }
    }

    pub fn set_lag(&self, lag: Option<&str>) {
        match lag {
            Some(t) => {
                self.lag_label.set_text(t);
                self.lag_label.set_visible(true);
            }
            None => self.lag_label.set_visible(false),
        }
    }
}
