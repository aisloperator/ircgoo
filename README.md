# IrcGoo

IrcGoo was created by AI Sloperator with Claude Code.

No license is given.

Website: <https://www.aisloperator.com/>

IrcGoo is a spartan, keyboard-driven IRC client for Linux desktops (X11 or Wayland),
written in Rust with GTK4. The main window is designed to occupy a small corner of
the screen without wasting space. It has a row of tabs, one for each channel or private
chat, and the main menu sits in the same row.

## Features

- Multiple IRC networks connected at the same time, with at most one server per network
  at a time. Each network has an ordered server list with failover and reconnection.
- Plain TCP or TLS per server. The same host may appear several times with different
  ports or TLS settings.
- SOCKS5 proxy (with optional username/password) for all connections, with a per-network
  opt-out. Host names are resolved by the proxy.
- SASL PLAIN and EXTERNAL (client certificate) per network, with per-server overrides.
- Per-network TLS trust: the system CA bundle and/or extra PEM files. A file may contain
  a CA certificate or a server's own (for example self-signed) certificate, which is then
  trusted exactly.
- IRC bouncer support (ZNC style `PASS user/network:password`).
- Per-network nick, username and real name overrides.
- Channel nick lists, sorted by rank. A context menu offers private chat, whois, op/deop,
  voice/devoice and kick. Hovering a nick shows its real name, idle time and so on, fetched
  from the server with WHOIS and cached.
- A lag indicator (for example `Lag:3s`) appears in the bottom bar only when lag is
  significant.
- Selectable, copyable message text with mIRC colours and formatting. Every line starts
  with the local time (`hh:mm:ss`).
- Nick and channel completion with Tab, plus per-tab input history.
- Hovering a tab shows its network, the server's host and port, and "TLS" or "non-TLS".
  With a bouncer, the bouncer's address is shown.

Logging is intentionally not implemented yet.

## Building

Requirements:

- Rust 1.92 or newer, required by the `gtk4` crate. Debian 13, Debian 12 and PureOS
  package older versions, so install a current toolchain with
  [rustup](https://rustup.rs/).
- GTK 4.8 or newer with development files, `pkg-config`, and a C compiler. On Debian:

  ```sh
  sudo apt install libgtk-4-dev pkg-config gcc
  ```

Then:

```sh
cargo build --release
./target/release/ircgoo
```

Optionally install the desktop entry so IrcGoo appears in application menus:

```sh
install -Dm755 target/release/ircgoo ~/.local/bin/ircgoo
install -Dm644 data/com.aisloperator.IrcGoo.desktop ~/.local/share/applications/com.aisloperator.IrcGoo.desktop
```

Run the unit tests with `cargo test`.

## Configuration

Settings live in `$XDG_CONFIG_HOME/ircgoo/ircgoo.conf` (usually `~/.config/ircgoo/`). The
file is a GLib key file and is normally edited through the Preferences and Networks
windows (press F10 to open the menu). It can contain passwords in plain text, so IrcGoo
writes it with mode 0600 in a 0700 directory. On first run it creates a configuration
with your login name as nick and a Libera.Chat network that does not connect
automatically.

The message text uses a monospace font. Its size follows the desktop's monospace font size
by default (GNOME's monospace font setting when available, otherwise GTK's default font
size). Preferences can set a fixed size instead.

## Keyboard

| Key | Action |
|---|---|
| F10 | Main menu |
| Alt+1 … Alt+0 | Go to tab 1–10 |
| Ctrl+Page Down / Ctrl+Tab | Next tab |
| Ctrl+Page Up / Ctrl+Shift+Tab | Previous tab |
| Ctrl+W | Close tab |
| Ctrl+L | Clear the tab's messages (like `/clear`) |
| Ctrl+Shift+L | Show or hide the nick list |
| Ctrl+, | Preferences |
| Ctrl+Q | Quit |
| Tab | Complete a nick or channel |
| Up / Down | Input history |
| Page Up / Page Down | Scroll messages |

Typing while the message area has focus goes to the input field.

## Commands

| Command | Description |
|---|---|
| `/join` `/j` `<#chan>[,<#chan>] [keys]` | Join channels |
| `/part` `/p` `[#chan] [reason]` | Leave a channel (the tab stays open) |
| `/close` | Close the tab (parts a channel; on a network tab, disconnects) |
| `/msg <target> <text>` | Send a message |
| `/query <nick> [text]` | Open a private chat |
| `/me <action>` | Send an action |
| `/notice <target> <text>` | Send a notice |
| `/nick <newnick>` | Change nick |
| `/topic [text]` | Show or set the topic |
| `/op` `/deop` `/voice` `/devoice` `<nicks>` | Change channel user modes |
| `/kick <nick> [reason]` | Kick a user |
| `/mode [target] <modes> [args]` | Set or show modes |
| `/whois <nick>` | Show information about a user |
| `/names [#chan]` | List channel users |
| `/invite <nick> [#chan]` | Invite a user |
| `/away [message]` | Set or clear away status |
| `/ctcp <target> <command> [args]` | Send a CTCP request |
| `/network [list]` | List configured networks |
| `/network connect <name>` | Connect to a network |
| `/network disconnect [name]` | Disconnect from a network |
| `/server [list\|next\|<n>\|<host>[:port]]` | Show or change this network's server |
| `/quit [reason]` | Disconnect from this tab's network |
| `/exit` | Quit IrcGoo |
| `/quote` `/raw <line>` | Send a raw protocol line |
| `/clear` `/c` | Clear the tab |
| `/help` | List commands |

Other `/commands` are sent to the server as-is. Start a line with `//` to send a
message that begins with `/`.

## Design notes

- The message area is a `GtkTextView` with text tags for colours. That gives native
  multi-line selection, clipboard and accessibility. Each tab keeps the last 5000 lines.
- Each connection runs on its own thread with blocking I/O. Events reach the GTK main
  loop through a channel. There is no async runtime.
- Dependencies are deliberately few: `gtk4` (only APIs up to GTK 4.8, so it runs on
  Debian bookworm and PureOS), `rustls` with the `ring` backend, and `rustls-native-certs`.
  Configuration uses GLib's key file support, and SOCKS5, SASL and IRC parsing are
  implemented here.
- libadwaita is not used yet. The layout is meant to become adaptive for Linux phones
  later.
