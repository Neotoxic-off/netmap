//! The terminal UI: the network as a device tree, with a details popup for each device.

use std::cmp::Reverse;
use std::f64::consts::{FRAC_PI_2, TAU};
use std::fs;
use std::io::{self, Write};
use std::ops::ControlFlow;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;
use std::time::Duration;

use ratatui::backend::Backend;
use ratatui::crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyEventKind,
    KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use ratatui::crossterm::execute;
use ratatui::layout::{Constraint, Layout, Position, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::symbols::Marker;
use ratatui::text::{Line, Span};
use ratatui::widgets::canvas::{Canvas, Context, Line as Link};
use ratatui::widgets::{
    Block, BorderType, Cell, Clear, Padding, Paragraph, Row, Table, TableState, Wrap,
};
use ratatui::{Frame, Terminal};

use crate::cache;
use crate::device::{Device, DeviceKind, Presence, Role};
use crate::net::{Interface, Ping};
use crate::report;
use crate::scan;

const ACCENT: Color = Color::Rgb(137, 220, 235);
const LABEL: Color = Color::Rgb(250, 179, 135);
const MUTED: Color = Color::Rgb(127, 132, 156);
const OK: Color = Color::Rgb(166, 227, 161);
const ERROR: Color = Color::Rgb(243, 139, 168);
const PENDING: Color = Color::Rgb(255, 158, 44);
/// Background of the selected row: dark enough for every text colour to stay readable.
const SELECTION: Color = Color::Rgb(58, 62, 88);
const BOLD: Style = Style::new().add_modifier(Modifier::BOLD);

const TICK: Duration = Duration::from_millis(100);
const LABEL_WIDTH: usize = 14;
const POPUP_MAX_WIDTH: u16 = 100;
/// Screen cells kept visible around the popup, per axis.
const POPUP_MARGIN: u16 = 4;
const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
/// Widest device label on the map, in cells.
const MAP_LABEL_WIDTH: usize = 18;
/// How long a device keeps its NEW badge after its first sighting.
const NEW_FOR: u64 = 24 * 60 * 60;
/// The keys worth a place in the header; `?` lists them all.
const KEYS: [(&str, &str); 6] = [
    ("↑/↓", "Navigate"),
    ("Enter/click", "Details"),
    ("/", "Filter"),
    ("m", "Map"),
    ("?", "All keys"),
    ("q", "Quit"),
];
const HELP: [(&str, &str); 14] = [
    ("↑/↓  j/k", "Move, or scroll the details"),
    ("Enter / click", "Open or close the details of a device"),
    ("/", "Filter by name, address, vendor, type or network"),
    ("s", "Change the sort order"),
    ("n", "Give the selected device a name of your own"),
    ("d", "Forget the selected device, once it is away"),
    ("m", "Show the map"),
    ("r", "Rescan: full port scan of new and stale devices only"),
    ("R", "Rescan every port of every device"),
    ("c", "Copy the address of the selected device"),
    ("e", "Export a report"),
    ("Esc", "Close, clear the filter, then quit"),
    ("q", "Quit"),
    ("?", "This help"),
];

/// The system's own copy command: one line of text does not need a clipboard library.
#[cfg(windows)]
const CLIPBOARD: &[&str] = &["clip"];
#[cfg(target_os = "macos")]
const CLIPBOARD: &[&str] = &["pbcopy"];
// shortcut: X11 only, add `wl-copy` when someone runs this under Wayland without XWayland.
#[cfg(all(unix, not(target_os = "macos")))]
const CLIPBOARD: &[&str] = &["xclip", "-selection", "clipboard"];

/// Puts a text on the clipboard.
type Copy = fn(&str) -> io::Result<()>;

type ScanResult = Result<Vec<Device>, String>;
/// Runs a scan, handing over the device list each time it gets more complete. It is told
/// the devices already known, and whether to redo every full port scan regardless.
pub type Discover = fn(&[Interface], &[Device], bool, &dyn Fn(Vec<Device>)) -> Result<(), String>;

#[derive(Clone, Copy, PartialEq, Eq)]
enum View {
    List,
    Map,
}

/// Saves the devices for the next start.
pub type Persist = fn(&[Device]);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Sort {
    /// Grouped by network, gateway first: the order that draws the tree.
    Network,
    Name,
    Address,
    Kind,
    Latency,
    LastSeen,
}

impl Sort {
    const fn next(self) -> Self {
        match self {
            Self::Network => Self::Name,
            Self::Name => Self::Address,
            Self::Address => Self::Kind,
            Self::Kind => Self::Latency,
            Self::Latency => Self::LastSeen,
            Self::LastSeen => Self::Network,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Network => "network",
            Self::Name => "name",
            Self::Address => "address",
            Self::Kind => "type",
            Self::Latency => "ping",
            Self::LastSeen => "last seen",
        }
    }
}

/// What the text being typed is for.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Prompt {
    Filter,
    Rename,
}

impl Prompt {
    const fn label(self) -> &'static str {
        match self {
            Self::Filter => "Filter",
            Self::Rename => "Name",
        }
    }
}

enum Status {
    Scanning(Receiver<ScanResult>),
    Ready,
    Failed(String),
}

struct App {
    /// Our own addresses, one per network being mapped.
    interfaces: Vec<Interface>,
    discover: Discover,
    devices: Vec<Device>,
    table: TableState,
    status: Status,
    view: View,
    persist: Persist,
    copy: Copy,
    /// Only devices matching this are listed. Empty: all of them.
    filter: String,
    sort: Sort,
    /// The text being typed and what for, while a prompt is open.
    typing: Option<(Prompt, String)>,
    help: bool,
    /// The outcome of the last action (export, forget…), shown under the list until the next scan.
    notice: Option<String>,
    /// Where reports are written.
    report_folder: PathBuf,
    /// Whether the details popup of the selected device is open.
    popup: bool,
    detail_scroll: u16,
    /// Where the device rows and the popup were last drawn, to map mouse clicks.
    rows_area: Rect,
    popup_area: Rect,
    ticks: usize,
}

pub fn run(
    interfaces: Vec<Interface>,
    known: Vec<Device>,
    discover: Discover,
    persist: Persist,
) -> io::Result<()> {
    let mut app = App::new(interfaces, known, discover);
    app.persist = persist;
    let mut terminal = ratatui::init();
    let result = execute!(io::stdout(), EnableMouseCapture)
        .and_then(|()| app.event_loop(&mut terminal, read_event));
    // Best effort: the terminal must be handed back even if this fails.
    let _ = execute!(io::stdout(), DisableMouseCapture);
    ratatui::restore();
    result
}

fn to_clipboard(text: &str) -> io::Result<()> {
    let mut command = Command::new(CLIPBOARD[0])
        .args(&CLIPBOARD[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    // Taken, so it is closed once written: the command waits for the end of its input.
    command
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(text.as_bytes())?;
    command.wait().map(drop)
}

/// Waits one tick for an input event.
fn read_event() -> io::Result<Option<Event>> {
    Ok(if event::poll(TICK)? {
        Some(event::read()?)
    } else {
        None
    })
}

impl App {
    /// Starts on the devices remembered from earlier runs while a first scan refreshes them.
    fn new(interfaces: Vec<Interface>, known: Vec<Device>, discover: Discover) -> Self {
        let mut app = Self {
            interfaces,
            discover,
            devices: known,
            table: TableState::default().with_selected(0),
            status: Status::Ready,
            view: View::List,
            persist: |_| {},
            copy: to_clipboard,
            filter: String::new(),
            sort: Sort::Network,
            typing: None,
            help: false,
            notice: None,
            report_folder: PathBuf::from("."),
            popup: false,
            detail_scroll: 0,
            rows_area: Rect::ZERO,
            popup_area: Rect::ZERO,
            ticks: 0,
        };
        app.rescan(false);
        app
    }

    fn event_loop<B: Backend>(
        &mut self,
        terminal: &mut Terminal<B>,
        mut next_event: impl FnMut() -> io::Result<Option<Event>>,
    ) -> io::Result<()> {
        loop {
            self.collect_scan();
            self.ticks = self.ticks.wrapping_add(1);
            terminal.draw(|frame| self.draw(frame))?;
            if let Some(event) = next_event()? {
                if self.on_event(event).is_break() {
                    return Ok(());
                }
            }
        }
    }

    /// Breaks when the event asks to quit.
    fn on_event(&mut self, event: Event) -> ControlFlow<()> {
        match event {
            // Windows also reports key releases.
            Event::Key(key) if key.kind == KeyEventKind::Press => return self.on_key(key),
            Event::Mouse(mouse) => self.on_mouse(mouse),
            _ => {}
        }
        ControlFlow::Continue(())
    }

    fn on_key(&mut self, key: KeyEvent) -> ControlFlow<()> {
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            return ControlFlow::Break(());
        }
        if self.typing.is_some() {
            self.on_typing(key);
            return ControlFlow::Continue(());
        }
        if self.help {
            self.help = false;
            return ControlFlow::Continue(());
        }
        let on_list = self.view == View::List && !self.popup;
        match key.code {
            KeyCode::Char('q') => return ControlFlow::Break(()),
            KeyCode::Esc | KeyCode::Enter if self.popup => self.popup = false,
            KeyCode::Esc | KeyCode::Char('m') if self.view == View::Map => self.view = View::List,
            KeyCode::Esc if !self.filter.is_empty() => self.set_filter(String::new()),
            KeyCode::Esc => return ControlFlow::Break(()),
            KeyCode::Char('m') => (self.view, self.popup) = (View::Map, false),
            KeyCode::Char('?') => self.help = true,
            KeyCode::Enter if on_list => self.open_popup(),
            KeyCode::Char('/') if on_list => {
                self.typing = Some((Prompt::Filter, self.filter.clone()))
            }
            KeyCode::Char('s') if on_list => {
                self.sort = self.sort.next();
                self.table.select(Some(0));
            }
            KeyCode::Char('n') if self.view == View::List => self.start_renaming(),
            KeyCode::Char('d') | KeyCode::Delete if self.view == View::List => self.forget(),
            KeyCode::Char('r') => self.rescan(false),
            KeyCode::Char('R') => self.rescan(true),
            KeyCode::Char('c') => self.copy_ip(),
            KeyCode::Char('e') => self.export_report(),
            KeyCode::Down | KeyCode::Char('j') => self.scroll(true),
            KeyCode::Up | KeyCode::Char('k') => self.scroll(false),
            KeyCode::Home if !self.popup => self.table.select_first(),
            KeyCode::End if !self.popup => self.table.select_last(),
            _ => {}
        }
        ControlFlow::Continue(())
    }

    /// Edits the open prompt: Enter applies it, Esc drops it.
    fn on_typing(&mut self, key: KeyEvent) {
        let Some((prompt, mut text)) = self.typing.take() else {
            return;
        };
        if prompt == Prompt::Filter {
            // The list changes with every keystroke: start again from its top.
            self.table.select(Some(0));
        }
        match (key.code, prompt) {
            (KeyCode::Esc, _) => return,
            (KeyCode::Enter, Prompt::Filter) => return self.set_filter(text),
            (KeyCode::Enter, Prompt::Rename) => return self.rename(&text),
            (KeyCode::Char(character), _) => text.push(character),
            (KeyCode::Backspace, _) => drop(text.pop()),
            _ => {}
        }
        self.typing = Some((prompt, text));
    }

    fn set_filter(&mut self, filter: String) {
        self.filter = filter;
        self.table.select(Some(0));
    }

    fn start_renaming(&mut self) {
        if let Some(device) = self.selected() {
            self.typing = Some((Prompt::Rename, device.label.clone().unwrap_or_default()));
        }
    }

    /// Gives the selected device the user's own name; a blank one gives it its discovered name back.
    fn rename(&mut self, label: &str) {
        let Some(index) = self.selected_index() else {
            return;
        };
        self.devices[index].label = Some(label.trim().to_owned()).filter(|label| !label.is_empty());
        (self.persist)(&self.devices);
    }

    /// Drops the selected device from memory. Only one that is away: one that is there would
    /// be back at the next scan, and a running scan would bring anything back.
    fn forget(&mut self) {
        let Some(index) = self.selected_index() else {
            return;
        };
        self.notice = Some(if matches!(self.status, Status::Scanning(_)) {
            "A scan is running: forget devices once it is done".to_owned()
        } else if self.devices[index].presence != Presence::Offline {
            "Only a device that is away can be forgotten".to_owned()
        } else {
            let gone = self.devices.remove(index);
            self.popup = false;
            (self.persist)(&self.devices);
            format!("Forgot {}", gone.name())
        });
    }

    /// The devices to list, as indexes into `devices`: filtered, then sorted.
    fn visible(&self) -> Vec<usize> {
        let filter = match &self.typing {
            Some((Prompt::Filter, text)) => text,
            _ => &self.filter,
        };
        let needle = filter.to_lowercase();
        let mut shown: Vec<usize> = (0..self.devices.len())
            .filter(|&index| matches_filter(&self.devices[index], &needle))
            .collect();
        let device = |index: &usize| &self.devices[*index];
        let ping = |index: &usize| {
            device(index)
                .ping
                .map_or(f64::INFINITY, |ping| ping.latency_ms)
        };
        match self.sort {
            Sort::Network => {}
            Sort::Name => shown.sort_by_cached_key(|index| device(index).name().to_lowercase()),
            Sort::Address => shown.sort_by_key(|index| device(index).ip),
            Sort::Kind => shown.sort_by_cached_key(|index| device(index).kind().to_string()),
            Sort::Latency => shown.sort_by(|a, b| ping(a).total_cmp(&ping(b))),
            Sort::LastSeen => shown.sort_by_key(|index| Reverse(device(index).last_seen)),
        }
        shown
    }

    fn on_mouse(&mut self, mouse: MouseEvent) {
        if self.typing.is_some() {
            return;
        }
        if self.help {
            self.help = false;
            return;
        }
        let at = Position::new(mouse.column, mouse.row);
        match mouse.kind {
            MouseEventKind::ScrollDown => self.scroll(true),
            MouseEventKind::ScrollUp => self.scroll(false),
            MouseEventKind::Down(MouseButton::Left) if self.view == View::Map => {}
            MouseEventKind::Down(MouseButton::Left) if self.popup => {
                self.popup = self.popup_area.contains(at);
            }
            MouseEventKind::Down(MouseButton::Left) if self.rows_area.contains(at) => {
                let row = usize::from(mouse.row - self.rows_area.y) + self.table.offset();
                if row < self.visible().len() {
                    self.table.select(Some(row));
                    self.open_popup();
                }
            }
            _ => {}
        }
    }

    /// Moves through the details when the popup is open, through the devices otherwise.
    fn scroll(&mut self, down: bool) {
        match (self.popup, down) {
            (true, true) => self.detail_scroll = self.detail_scroll.saturating_add(1),
            (true, false) => self.detail_scroll = self.detail_scroll.saturating_sub(1),
            (false, true) => self.table.select_next(),
            (false, false) => self.table.select_previous(),
        }
    }

    /// The position in `devices` of the selected row.
    fn selected_index(&self) -> Option<usize> {
        self.visible().get(self.table.selected()?).copied()
    }

    fn selected(&self) -> Option<&Device> {
        self.selected_index().map(|index| &self.devices[index])
    }

    fn open_popup(&mut self) {
        self.popup = self.selected().is_some();
        self.detail_scroll = 0;
    }

    /// Puts the address of the selected device on the clipboard and says so.
    fn copy_ip(&mut self) {
        let Some(ip) = self.selected().map(|device| device.ip.to_string()) else {
            return;
        };
        self.notice = Some(match (self.copy)(&ip) {
            Ok(()) => format!("Copied {ip}"),
            Err(error) => format!("{ip} not copied: {error}"),
        });
    }

    /// Writes the report next to where the tool was started and says where it went.
    fn export_report(&mut self) {
        let now = cache::now();
        let path = self.report_folder.join(report::file_name(now));
        let written = fs::write(&path, report::render(&self.interfaces, &self.devices, now));
        self.notice = Some(match written {
            Ok(()) => format!("Report saved to {}", path.display()),
            Err(error) => format!("Report not saved: {error}"),
        });
    }

    /// `force` redoes the full port scan of every device instead of only new or stale ones.
    fn rescan(&mut self, force: bool) {
        if matches!(self.status, Status::Scanning(_)) {
            return;
        }
        self.notice = None;
        // Nothing is certain again until the scan says so.
        self.devices
            .iter_mut()
            .for_each(|device| device.presence = Presence::Checking);
        let (sender, receiver) = mpsc::channel();
        let (discover, interfaces) = (self.discover, self.interfaces.clone());
        let known = self.devices.clone();
        thread::spawn(move || {
            // Send errors are ignored: the UI may have quit meanwhile, nobody left to tell.
            let report = |devices: Vec<Device>| drop(sender.send(Ok(devices)));
            if let Err(error) = discover(&interfaces, &known, force, &report) {
                let _ = sender.send(Err(error));
            }
        });
        self.status = Status::Scanning(receiver);
    }

    /// Takes every partial result so far; the scan is over once its thread hangs up.
    fn collect_scan(&mut self) {
        loop {
            let Status::Scanning(receiver) = &self.status else {
                return;
            };
            match receiver.try_recv() {
                Err(TryRecvError::Empty) => return,
                Err(TryRecvError::Disconnected) => self.status = Status::Ready,
                Ok(Err(error)) => self.status = Status::Failed(error),
                Ok(Ok(mut devices)) => {
                    // A name given while the scan was running must survive its results.
                    for device in &mut devices {
                        let current = self
                            .devices
                            .iter()
                            .find(|current| current.same_device(device));
                        if let Some(current) = current {
                            device.label.clone_from(&current.label);
                        }
                    }
                    self.devices = devices;
                    (self.persist)(&self.devices);
                    self.table.select(Some(self.table.selected().unwrap_or(0)));
                }
            }
        }
    }

    fn draw(&mut self, frame: &mut Frame) {
        let [header, body] =
            Layout::vertical([Constraint::Length(8), Constraint::Min(0)]).areas(frame.area());
        let header_frame = panel(" netmap ".to_owned());
        let [facts, keys] = Layout::horizontal([Constraint::Min(0), Constraint::Length(28)])
            .areas(header_frame.inner(header));

        frame.render_widget(header_frame, header);
        frame.render_widget(Paragraph::new(self.summary()), facts);
        frame.render_widget(Paragraph::new(key_hints()), keys);
        // Drawn first: rendering the table is what clamps the selection to a real row.
        self.draw_devices(frame, body);
        if self.view == View::Map {
            self.draw_map(frame, body);
        } else if self.popup {
            self.draw_popup(frame, frame.area());
        }
        if self.help {
            draw_help(frame, frame.area());
        }
    }

    fn summary(&self) -> Vec<Line<'static>> {
        let networks: Vec<String> = self
            .interfaces
            .iter()
            .map(|interface| interface.subnet.to_string())
            .collect();
        let addresses: Vec<String> = self
            .interfaces
            .iter()
            .map(|interface| interface.ip.to_string())
            .collect();
        let gateways: Vec<String> = self
            .devices
            .iter()
            .filter(|device| device.role == Role::Gateway)
            .map(|device| device.ip.to_string())
            .collect();
        let gateways = if gateways.is_empty() {
            "not found".to_owned()
        } else {
            gateways.join(", ")
        };
        vec![
            fact("Networks", &networks.join(", ")),
            fact("This device", &addresses.join(", ")),
            fact("Gateways", &gateways),
            self.census(),
            labeled("Status", self.status_span()),
        ]
    }

    /// How many devices there are, and how many in each state.
    fn census(&self) -> Line<'static> {
        let mut line = fact("Devices", &self.devices.len().to_string());
        for presence in [Presence::Online, Presence::Offline, Presence::Checking] {
            let count = self
                .devices
                .iter()
                .filter(|device| device.presence == presence)
                .count();
            if count > 0 {
                line.extend([
                    Span::raw("   "),
                    presence_dot(presence),
                    Span::raw(format!(" {count}")),
                ]);
            }
        }
        line
    }

    fn list_title(&self, shown: usize) -> String {
        let total = self.devices.len();
        let count = if shown == total {
            total.to_string()
        } else {
            format!("{shown}/{total}")
        };
        match self.sort {
            Sort::Network => format!(" Devices[{count}] "),
            sort => format!(" Devices[{count}] by {} ", sort.label()),
        }
    }

    /// Under the list: what is being typed, else the filter in force, else the last message.
    fn list_footer(&self) -> Line<'static> {
        match (&self.typing, &self.notice) {
            (Some((prompt, text)), _) => {
                Line::styled(format!(" {}: {text}▏ ", prompt.label()), BOLD.fg(LABEL))
            }
            (None, _) if !self.filter.is_empty() => {
                Line::styled(format!(" Filter: {} ", self.filter), LABEL)
            }
            (None, Some(notice)) => Line::styled(format!(" {notice} "), OK).centered(),
            (None, None) => Line::default(),
        }
    }

    fn status_span(&self) -> Span<'static> {
        let spinner = SPINNER[self.ticks % SPINNER.len()];
        match &self.status {
            Status::Scanning(_) if self.devices.is_empty() => {
                Span::styled(format!("{spinner} Discovering devices…"), ACCENT)
            }
            Status::Scanning(_) => Span::styled(format!("{spinner} Scanning new devices…"), ACCENT),
            Status::Ready => Span::styled("● Ready", OK),
            Status::Failed(error) => Span::styled(format!("● {error}"), ERROR),
        }
    }

    /// The table doubles as the map: on each network, devices hang off its gateway.
    /// A filter or another sort order flattens it into a plain list.
    fn draw_devices(&mut self, frame: &mut Frame, area: Rect) {
        let shown = self.visible();
        let block = panel(self.list_title(shown.len())).title_bottom(self.list_footer());
        let devices = &self.devices;
        let as_tree = self.sort == Sort::Network && shown.len() == devices.len();
        let now = cache::now();
        let oldest = devices
            .iter()
            .map(|device| device.first_seen)
            .min()
            .unwrap_or(now);
        let rows = shown.iter().map(|&index| {
            let device = &devices[index];
            let on_same_network = |other: &Device| other.subnet == device.subnet;
            let rooted = devices
                .iter()
                .any(|other| other.role == Role::Gateway && on_same_network(other));
            let branch = match devices.get(index + 1) {
                _ if !as_tree || !rooted || device.role == Role::Gateway => "",
                Some(next) if on_same_network(next) => "├─ ",
                _ => "└─ ",
            };
            let mut name = vec![
                Span::raw(branch),
                presence_dot(device.presence),
                Span::raw(format!(" {}", device.name())),
            ];
            if is_new(device, now, oldest) {
                name.push(Span::styled(" NEW", BOLD.fg(OK)));
            }
            let os = device.os_family().map(|family| family.to_string());
            Row::new([
                Cell::from(Line::from(name)),
                Cell::from(device.ip.to_string()),
                Cell::from(Span::styled(device.subnet.to_string(), MUTED)),
                Cell::from(device.vendor.clone().unwrap_or_default()),
                Cell::from(kind_span(device.kind())),
                Cell::from(os.unwrap_or_default()),
                Cell::from(device.ping.map(latency).unwrap_or_default()),
            ])
            .style(if device.presence == Presence::Offline {
                Style::new().fg(MUTED)
            } else {
                Style::new()
            })
        });
        let widths = [
            Constraint::Fill(3),
            Constraint::Length(15),
            Constraint::Length(18),
            Constraint::Fill(2),
            Constraint::Length(14),
            Constraint::Length(18),
            Constraint::Length(8),
        ];
        let inner = block.inner(area);
        // Device rows start under the column titles.
        self.rows_area = Rect {
            y: inner.y.saturating_add(1),
            height: inner.height.saturating_sub(1),
            ..inner
        };
        let titles = ["NAME", "IP", "NETWORK", "VENDOR", "TYPE", "OS", "PING"];
        let table = Table::new(rows, widths)
            .header(Row::new(titles).style(BOLD.fg(MUTED)))
            .row_highlight_style(BOLD.bg(SELECTION))
            .block(block);
        frame.render_stateful_widget(table, area, &mut self.table);
    }

    /// Everything about the selected device, centered over the table and as tall as it needs.
    fn draw_popup(&mut self, frame: &mut Frame, area: Rect) {
        let Some(device) = self.selected() else {
            self.popup = false;
            return;
        };
        let block = panel(format!(" {} ", device.name()))
            .title_bottom(Line::styled(" ↑/↓ scroll · Esc close ", MUTED).centered());
        let details = Paragraph::new(details(device, cache::now())).wrap(Wrap { trim: false });

        let width = area.width.saturating_sub(POPUP_MARGIN).min(POPUP_MAX_WIDTH);
        let frame_size = Rect::new(0, 0, width, u16::MAX);
        let chrome = frame_size.height - block.inner(frame_size).height;
        // Counted after wrapping, so the last line stays reachable in a narrow terminal.
        let lines =
            u16::try_from(details.line_count(block.inner(frame_size).width)).unwrap_or(u16::MAX);
        let height = lines
            .saturating_add(chrome)
            .min(area.height.saturating_sub(POPUP_MARGIN));
        let popup = Rect::new(
            area.x + (area.width - width) / 2,
            area.y + (area.height - height) / 2,
            width,
            height,
        );

        let hidden = lines.saturating_sub(height.saturating_sub(chrome));
        self.detail_scroll = self.detail_scroll.min(hidden);
        self.popup_area = popup;
        frame.render_widget(Clear, popup);
        frame.render_widget(details.scroll((self.detail_scroll, 0)).block(block), popup);
    }

    /// Every network as a star: its gateway (or just its name) in the middle, its devices around.
    /// shortcut: one ring per network, labels overlap past ~20 devices; add rings when that hurts.
    fn draw_map(&self, frame: &mut Frame, area: Rect) {
        let block = panel(" Map ".to_owned());
        let inner = block.inner(area);
        let (width, height) = (f64::from(inner.width), f64::from(inner.height));
        let mut networks: Vec<_> = self.devices.iter().map(|device| device.subnet).collect();
        networks.dedup();
        let slot = width / networks.len().max(1) as f64;

        let map = Canvas::default()
            .block(block)
            .marker(Marker::Braille)
            .x_bounds([0.0, width])
            .y_bounds([0.0, height])
            .paint(|canvas| {
                for (index, network) in networks.iter().enumerate() {
                    let members = self
                        .devices
                        .iter()
                        .filter(|device| device.subnet == *network);
                    let (hubs, spokes): (Vec<&Device>, Vec<&Device>) =
                        members.partition(|device| device.role == Role::Gateway);
                    let center = Point {
                        x: slot * (index as f64 + 0.5),
                        y: height / 2.0,
                    };
                    let reach = Point {
                        x: (slot - MAP_LABEL_WIDTH as f64) / 2.0 - 1.0,
                        y: height / 2.0 - 1.5,
                    };
                    let spots = ring(spokes.len(), center, reach);
                    for spot in &spots {
                        let link = Link {
                            x1: center.x,
                            y1: center.y,
                            x2: spot.x,
                            y2: spot.y,
                            color: MUTED,
                        };
                        canvas.draw(&link);
                    }
                    // Labels go on their own layer so links never cut through them.
                    canvas.layer();
                    for (device, spot) in spokes.iter().zip(&spots) {
                        print_centered(canvas, *spot, map_label(device));
                    }
                    for hub in hubs {
                        print_centered(canvas, center, map_label(hub));
                    }
                    let name = Line::styled(network.to_string(), BOLD.fg(ACCENT));
                    print_centered(
                        canvas,
                        Point {
                            y: center.y - 1.0,
                            ..center
                        },
                        name,
                    );
                }
            });
        frame.render_widget(Clear, area);
        frame.render_widget(map, area);
    }
}

fn panel(title: String) -> Block<'static> {
    Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(ACCENT)
        .padding(Padding::horizontal(1))
        .title(Line::styled(title, BOLD.fg(ACCENT)).centered())
}

fn key_hints() -> Vec<Line<'static>> {
    KEYS.iter()
        .map(|(key, action)| {
            Line::from(vec![
                Span::styled(format!("{:<14}", format!("<{key}>")), BOLD.fg(ACCENT)),
                Span::styled(*action, MUTED),
            ])
        })
        .collect()
}

fn labeled(label: &str, value: Span<'static>) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{label:<LABEL_WIDTH$}"), LABEL),
        value,
    ])
}

fn fact(label: &str, value: &str) -> Line<'static> {
    labeled(label, Span::styled(value.to_owned(), BOLD))
}

fn heading(title: &str) -> Line<'static> {
    Line::styled(title.to_owned(), BOLD.fg(ACCENT))
}

fn kind_span(kind: DeviceKind) -> Span<'static> {
    Span::styled(format!("{} {kind}", kind_glyph(kind)), kind_color(kind))
}

/// A point of the map, in canvas cells.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Point {
    x: f64,
    y: f64,
}

/// `count` points evenly spread on the ellipse of radii `reach` around `center`, from the top.
fn ring(count: usize, center: Point, reach: Point) -> Vec<Point> {
    (0..count)
        .map(|index| {
            let angle = FRAC_PI_2 + TAU * index as f64 / count as f64;
            Point {
                x: center.x + reach.x * angle.cos(),
                y: center.y + reach.y * angle.sin(),
            }
        })
        .collect()
}

fn map_label(device: &Device) -> Line<'static> {
    let name: String = device.name().chars().take(MAP_LABEL_WIDTH - 2).collect();
    let kind = device.kind();
    let color = if device.presence == Presence::Offline {
        MUTED
    } else {
        kind_color(kind)
    };
    Line::styled(format!("{} {name}", kind_glyph(kind)), color)
}

fn print_centered(canvas: &mut Context<'_>, at: Point, label: Line<'static>) {
    let half = label.width() as f64 / 2.0;
    canvas.print((at.x - half).max(0.0), at.y, label);
}

/// Whether `needle` (lower case) appears in what the list shows of the device.
fn matches_filter(device: &Device, needle: &str) -> bool {
    let mac = device.mac.map(|mac| mac.to_string()).unwrap_or_default();
    let shown = [
        device.name(),
        &device.ip.to_string(),
        &mac,
        device.vendor.as_deref().unwrap_or_default(),
        &device.kind().to_string(),
        &device.subnet.to_string(),
    ];
    needle.is_empty() || shown.join(" ").to_lowercase().contains(needle)
}

/// A device first seen recently, unless it dates from the very first scan like everything else.
fn is_new(device: &Device, now: u64, oldest: u64) -> bool {
    device.first_seen > oldest && now.saturating_sub(device.first_seen) < NEW_FOR
}

/// Every key, and what the colours mean.
fn draw_help(frame: &mut Frame, area: Rect) {
    let mut lines: Vec<Line<'static>> = HELP
        .iter()
        .map(|(key, action)| {
            Line::from(vec![
                Span::styled(format!("{key:<16}"), BOLD.fg(ACCENT)),
                Span::raw(*action),
            ])
        })
        .collect();
    let legend = [
        (Presence::Online, "there, and fully scanned"),
        (Presence::Offline, "away"),
        (
            Presence::Checking,
            "not confirmed yet, or waiting for its full port scan",
        ),
    ];
    lines.push(Line::default());
    lines.extend(legend.map(|(presence, meaning)| {
        Line::from(vec![
            presence_dot(presence),
            Span::raw(format!("               {meaning}")),
        ])
    }));
    lines.push(Line::from(vec![
        Span::styled(format!("{:<16}", "NEW"), BOLD.fg(OK)),
        Span::raw("first seen less than a day ago"),
    ]));

    let width = area.width.saturating_sub(POPUP_MARGIN).min(76);
    let height = u16::try_from(lines.len() + 2)
        .unwrap_or(u16::MAX)
        .min(area.height);
    let popup = Rect::new(
        area.x + (area.width - width) / 2,
        area.y + (area.height - height) / 2,
        width,
        height,
    );
    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(lines).block(panel(" Help ".to_owned())),
        popup,
    );
}

/// Green: there. Red: away. Orange: not confirmed yet, or still waiting for its full scan.
fn presence_dot(presence: Presence) -> Span<'static> {
    let color = match presence {
        Presence::Online => OK,
        Presence::Offline => ERROR,
        Presence::Checking => PENDING,
    };
    Span::styled("●", color)
}

/// When `then` was, both relative and exact: `2 h ago (2026-11-13 14:02:11 UTC)`.
fn moment(now: u64, then: u64) -> String {
    format!("{} ({} UTC)", age(now, then), report::date_time(then))
}

/// How long ago `then` was, in the largest unit that fits.
fn age(now: u64, then: u64) -> String {
    match now.saturating_sub(then) {
        seconds if seconds < 60 => "just now".to_owned(),
        seconds if seconds < 3_600 => format!("{} min ago", seconds / 60),
        seconds if seconds < 86_400 => format!("{} h ago", seconds / 3_600),
        seconds => format!("{} d ago", seconds / 86_400),
    }
}

fn latency(ping: Ping) -> String {
    match ping.latency_ms {
        fast if fast < 1.0 => "<1 ms".to_owned(),
        slow => format!("{slow:.0} ms"),
    }
}

/// Everything the scan learned about one device; unknown fields are left out.
fn details(device: &Device, now: u64) -> Vec<Line<'static>> {
    let mac = device.mac.map(|mac| match mac.is_randomized() {
        true => format!("{mac} (private, randomized)"),
        false => mac.to_string(),
    });
    let os = device
        .os_family()
        .map(|family| format!("{family} (guessed from ping TTL)"));
    let ping = device
        .ping
        .map(|ping| format!("{:.1} ms (TTL {})", ping.latency_ms, ping.ttl));
    let netbios = device.netbios.as_ref();
    let optional = |label: &str, value: Option<&str>| value.map(|value| fact(label, value));

    let mut lines = vec![
        heading("Identity"),
        fact("Name", device.name()),
        labeled("Type", kind_span(device.kind())),
        fact("IP", &device.ip.to_string()),
        fact("Network", &device.subnet.to_string()),
        labeled("Status", presence_dot(device.presence)),
        fact("First seen", &moment(now, device.first_seen)),
        fact("Last seen", &moment(now, device.last_seen)),
    ];
    lines.extend(
        [
            optional("MAC", mac.as_deref()),
            optional("Vendor", device.vendor.as_deref()),
            optional("Hostname", device.hostname.as_deref()),
            optional(
                "NetBIOS name",
                netbios.and_then(|netbios| netbios.name.as_deref()),
            ),
            optional(
                "Workgroup",
                netbios.and_then(|netbios| netbios.workgroup.as_deref()),
            ),
            optional("OS family", os.as_deref()),
            optional("Ping", ping.as_deref()),
        ]
        .into_iter()
        .flatten(),
    );

    if let Some(upnp) = &device.upnp {
        lines.extend([Line::default(), heading("UPnP")]);
        lines.extend(
            [
                optional("Name", upnp.friendly_name.as_deref()),
                optional("Manufacturer", upnp.manufacturer.as_deref()),
                optional("Model", upnp.model.as_deref()),
                optional("Model number", upnp.model_number.as_deref()),
                optional("Serial number", upnp.serial_number.as_deref()),
                optional("Device type", upnp.device_type.as_deref()),
                optional("Web interface", upnp.url.as_deref()),
                optional("Server", upnp.server.as_deref()),
            ]
            .into_iter()
            .flatten(),
        );
    }

    if !device.mdns.is_empty() {
        lines.extend([Line::default(), heading("Advertised services (mDNS)")]);
        lines.extend(device.mdns.iter().map(|service| Line::raw(service.clone())));
    }

    lines.extend([
        Line::default(),
        heading(&format!("Open TCP ports ({})", device.probes.len())),
    ]);
    let scanned = device
        .ports_scanned
        .map_or("never".to_owned(), |at| moment(now, at));
    lines.push(fact("Full scan", &scanned));
    if device.probes.is_empty() {
        lines.push(Line::styled("None found", MUTED));
    }
    lines.extend(device.probes.iter().map(|probe| {
        let port = format!("{}/tcp", probe.port);
        let protocol = scan::port_name(probe.port).unwrap_or("unknown");
        Line::from(vec![
            Span::styled(format!("{port:<LABEL_WIDTH$}"), LABEL),
            Span::styled(format!("{protocol:<11}"), BOLD),
            Span::styled(probe.banner.clone().unwrap_or_default(), MUTED),
        ])
    }));
    lines
}

const fn kind_glyph(kind: DeviceKind) -> &'static str {
    match kind {
        DeviceKind::Gateway => "◆",
        DeviceKind::ThisDevice => "●",
        DeviceKind::Printer => "▤",
        DeviceKind::Camera => "◉",
        DeviceKind::Media => "▶",
        DeviceKind::Phone => "▮",
        DeviceKind::Server => "▦",
        DeviceKind::Computer => "▭",
        DeviceKind::Iot => "⌂",
        DeviceKind::Unknown => "○",
    }
}

const fn kind_color(kind: DeviceKind) -> Color {
    match kind {
        DeviceKind::Gateway => ACCENT,
        DeviceKind::ThisDevice => OK,
        DeviceKind::Printer => Color::Rgb(203, 166, 247),
        DeviceKind::Camera => ERROR,
        DeviceKind::Media => Color::Rgb(245, 194, 231),
        DeviceKind::Phone => Color::Rgb(137, 180, 250),
        DeviceKind::Server => Color::Rgb(249, 226, 175),
        DeviceKind::Computer => Color::Rgb(148, 226, 213),
        DeviceKind::Iot => LABEL,
        DeviceKind::Unknown => MUTED,
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use ratatui::backend::TestBackend;

    use super::*;
    use crate::lookup::Netbios;
    use crate::net::Subnet;
    use crate::scan::{Probe, Upnp};

    const ME: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 20);
    /// On the 120x30 test screen the first device row is drawn here.
    const FIRST_ROW: u16 = 10;

    fn lan() -> Vec<Interface> {
        vec![Interface {
            ip: ME,
            subnet: Subnet::new(ME, 24),
        }]
    }

    fn device(host: u8, role: Role, name: &str) -> Device {
        Device {
            ip: Ipv4Addr::new(192, 168, 1, host),
            subnet: Subnet::new(ME, 24),
            ping: Some(Ping {
                ttl: 64,
                latency_ms: 2.4,
            }),
            netbios: None,
            mdns: Vec::new(),
            label: None,
            first_seen: 0,
            last_seen: cache::now(),
            ports_scanned: Some(cache::now().saturating_sub(7_200)),
            presence: Presence::Online,
            role,
            mac: format!("a4:bb:cc:00:11:{host:02x}").parse().ok(),
            hostname: Some(name.to_owned()),
            vendor: Some("Acme".to_owned()),
            upnp: None,
            probes: vec![
                Probe {
                    port: 22,
                    banner: Some("SSH-2.0-OpenSSH_9.6".to_owned()),
                },
                Probe {
                    port: 8123,
                    banner: None,
                },
            ],
        }
    }

    fn home() -> Vec<Device> {
        vec![
            device(1, Role::Gateway, "box"),
            device(5, Role::Peer, "tv"),
            device(7, Role::Peer, "nas"),
        ]
    }

    fn finds_nothing(
        _: &[Interface],
        _: &[Device],
        _: bool,
        _: &dyn Fn(Vec<Device>),
    ) -> Result<(), String> {
        Ok(())
    }

    fn app(devices: Vec<Device>, status: Status) -> App {
        App {
            interfaces: lan(),
            discover: finds_nothing,
            devices,
            table: TableState::default().with_selected(0),
            status,
            view: View::List,
            persist: |_| {},
            copy: |_| Ok(()),
            filter: String::new(),
            sort: Sort::Network,
            typing: None,
            help: false,
            notice: None,
            report_folder: PathBuf::from("."),
            popup: false,
            detail_scroll: 0,
            rows_area: Rect::ZERO,
            popup_area: Rect::ZERO,
            ticks: 0,
        }
    }

    fn screen(app: &mut App) -> String {
        let mut terminal = Terminal::new(TestBackend::new(120, 30)).unwrap();
        terminal.draw(|frame| app.draw(frame)).unwrap();
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect()
    }

    fn scrolled_to_the_end(app: &mut App) -> String {
        app.detail_scroll = u16::MAX;
        screen(app)
    }

    /// The colour of the presence dot of each device row, top to bottom.
    fn dots(app: &mut App) -> Vec<Color> {
        let mut terminal = Terminal::new(TestBackend::new(120, 30)).unwrap();
        terminal.draw(|frame| app.draw(frame)).unwrap();
        let buffer = terminal.backend().buffer();
        // The dot sits right before the name: at the start of the row, or after the tree branch.
        (FIRST_ROW..30)
            .filter_map(|row| {
                [2, 5]
                    .map(|column| &buffer[(column, row)])
                    .into_iter()
                    .find(|cell| cell.symbol() == "●")
            })
            .map(|cell| cell.fg)
            .collect()
    }

    fn assert_shows(screen: &str, expected: &[&str]) {
        for text in expected {
            assert!(screen.contains(text), "missing {text:?}");
        }
    }

    fn settle(app: &mut App) {
        while matches!(app.status, Status::Scanning(_)) {
            app.collect_scan();
            thread::sleep(Duration::from_millis(1));
        }
    }

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    /// Presses a key that must not quit.
    fn tap(app: &mut App, code: KeyCode) {
        assert!(app.on_key(press(code)).is_continue());
    }

    fn mouse(app: &mut App, kind: MouseEventKind, column: u16, row: u16) {
        let event = MouseEvent {
            kind,
            column,
            row,
            modifiers: KeyModifiers::NONE,
        };
        assert!(app.on_event(Event::Mouse(event)).is_continue());
    }

    fn click(app: &mut App, column: u16, row: u16) {
        mouse(app, MouseEventKind::Down(MouseButton::Left), column, row);
    }

    #[test]
    fn draws_the_network_as_a_full_width_tree() {
        let mut app = app(home(), Status::Ready);
        let screen = screen(&mut app);
        assert_shows(
            &screen,
            &[
                " netmap ",
                "Devices[3]",
                "● Ready",
                "</>",
                "<m>",
                "<?>",
                "192.168.1.1 ",
                "● box",
                "├─ ● tv",
                "└─ ● nas",
                "◆ Router",
                "▦ Server",
                "192.168.1.0/24",
                "Acme",
                "Unix",
                "2 ms",
                "<Enter/click>",
                "NETWORK",
                "PING",
            ],
        );
        assert!(screen.starts_with('╭'), "the header sits in a frame");
        assert!(
            !screen.contains("OPEN PORTS") && !screen.contains("8123"),
            "ports are details"
        );
        assert!(
            !screen.contains("Open TCP ports"),
            "details stay hidden until asked for"
        );
    }

    #[test]
    fn enter_opens_the_details_popup_and_escape_closes_it() {
        let mut app = app(home(), Status::Ready);
        app.table.select(Some(2));
        tap(&mut app, KeyCode::Enter);
        assert_shows(
            &screen(&mut app),
            &[
                " nas ",
                "Identity",
                "192.168.1.7",
                "a4:bb:cc:00:11:07",
                "Open TCP ports (2)",
                "22/tcp",
                "SSH-2.0-OpenSSH_9.6",
                "8123/tcp",
                "Esc close",
                " netmap ",
                "just now",
                "2 h ago",
                "SSH",
                "Unix (guessed from ping TTL)",
                "2.4 ms (TTL 64)",
                "unknown",
                " UTC)",
            ],
        );

        tap(&mut app, KeyCode::Esc);
        assert!(!screen(&mut app).contains("Open TCP ports"));
        tap(&mut app, KeyCode::Enter);
        tap(&mut app, KeyCode::Enter);
        assert!(!app.popup, "Enter toggles");
    }

    #[test]
    fn popup_shows_upnp_private_mac_and_portless_devices() {
        let mut phone = device(9, Role::Peer, "phone");
        phone.mac = "02:00:00:00:00:01".parse().ok();
        phone.probes.clear();
        phone.netbios = Some(Netbios {
            name: Some("PHONE".to_owned()),
            workgroup: Some("HOME".to_owned()),
        });
        phone.mdns = vec!["_companion-link._tcp".to_owned()];
        phone.upnp = Some(Upnp {
            server: Some("Linux UPnP/1.0".to_owned()),
            friendly_name: Some("Living room".to_owned()),
            manufacturer: Some("Initech".to_owned()),
            model: Some("X1".to_owned()),
            url: Some("http://192.168.1.9/".to_owned()),
            ..Upnp::default()
        });
        let mut app = app(vec![phone], Status::Ready);
        assert_shows(&screen(&mut app), &["not found"]);
        tap(&mut app, KeyCode::Enter);
        let screen = screen(&mut app);
        assert_shows(
            &screen,
            &[
                " Living room ",
                "02:00:00:00:00:01 (private, randomized)",
                "Initech",
                "X1",
                "Linux UPnP/1.0",
                "http://192.168.1.9/",
                "PHONE",
                "HOME",
            ],
        );
        assert!(!screen.contains("└─"), "no tree without a gateway");
        let end = scrolled_to_the_end(&mut app);
        assert_shows(
            &end,
            &[
                "Advertised services (mDNS)",
                "_companion-link._tcp",
                "None found",
            ],
        );
    }

    #[test]
    fn each_network_gets_its_own_tree() {
        let virtual_network = Subnet::new(Ipv4Addr::new(172, 20, 0, 1), 20);
        let mut vm = device(2, Role::Peer, "vm");
        vm.ip = Ipv4Addr::new(172, 20, 0, 2);
        vm.subnet = virtual_network;
        vm.ping = Some(Ping {
            ttl: 128,
            latency_ms: 0.3,
        });
        let mut devices = home();
        devices.insert(0, vm);

        let mut app = app(devices, Status::Ready);
        app.interfaces.push(Interface {
            ip: Ipv4Addr::new(172, 20, 0, 1),
            subnet: virtual_network,
        });
        let screen = screen(&mut app);
        assert_shows(
            &screen,
            &[
                "192.168.1.0/24, 172.20.0.0/20",
                "192.168.1.20, 172.20.0.1",
                "├─ ● tv",
                "└─ ● nas",
                "172.20.0.2",
                "Windows",
                "<1 ms",
            ],
        );
        assert!(
            screen.contains("● vm") && !screen.contains("─ ● vm"),
            "no gateway, no tree"
        );
    }

    #[test]
    fn starts_on_remembered_devices_shown_offline_until_seen_again() {
        let mut remembered = home();
        remembered
            .iter_mut()
            .for_each(|device| device.presence = Presence::Offline);
        remembered[2].last_seen = cache::now().saturating_sub(3 * 86_400);
        remembered[2].ports_scanned = None;
        let mut app = App::new(lan(), remembered, finds_nothing);
        assert_eq!((app.devices.len(), app.table.selected()), (3, Some(0)));
        settle(&mut app);

        assert_eq!(
            dots(&mut app),
            [PENDING; 3],
            "remembered, not confirmed by any scan yet"
        );
        app.table.select(Some(2));
        tap(&mut app, KeyCode::Enter);
        assert_shows(&screen(&mut app), &["Status", "3 d ago (", "never"]);
    }

    #[test]
    fn a_rescan_passes_on_what_is_known_and_whether_to_force() {
        fn echo(
            _: &[Interface],
            known: &[Device],
            force: bool,
            report: &dyn Fn(Vec<Device>),
        ) -> Result<(), String> {
            let mut witness = known
                .first()
                .cloned()
                .expect("the app starts with one device");
            witness.hostname = Some(format!("known={} force={force}", known.len()));
            report(vec![witness]);
            Ok(())
        }
        let mut app = App::new(lan(), vec![device(7, Role::Peer, "nas")], echo);
        settle(&mut app);
        assert_eq!(app.devices[0].name(), "known=1 force=false");
        tap(&mut app, KeyCode::Char('R'));
        settle(&mut app);
        assert_eq!(app.devices[0].name(), "known=1 force=true");
    }

    #[test]
    fn ages_use_the_largest_unit_that_fits() {
        let ages = [
            (0, "just now"),
            (59, "just now"),
            (60, "1 min ago"),
            (7_199, "1 h ago"),
            (172_800, "2 d ago"),
        ];
        for (seconds, expected) in ages {
            assert_eq!(age(1_000_000, 1_000_000 - seconds), expected);
        }
        assert_eq!(
            age(5, 9),
            "just now",
            "a clock that went backwards is not an error"
        );
    }

    #[test]
    fn m_opens_the_map_of_every_network() {
        let virtual_network = Subnet::new(Ipv4Addr::new(172, 20, 0, 1), 20);
        let mut vm = device(2, Role::Peer, "vm");
        vm.subnet = virtual_network;
        vm.presence = Presence::Offline;
        let mut devices = home();
        devices.insert(0, vm);
        let mut app = app(devices, Status::Ready);
        tap(&mut app, KeyCode::Enter);

        tap(&mut app, KeyCode::Char('m'));
        assert!(
            app.view == View::Map && !app.popup,
            "the map replaces whatever was open"
        );
        let screen = screen(&mut app);
        assert_shows(
            &screen,
            &[
                " Map ",
                "◆ box",
                "nas",
                "tv",
                "vm",
                "192.168.1.0/24",
                "172.20.0.0/20",
                " netmap ",
            ],
        );
        let is_braille = |symbol: char| ('\u{2801}'..='\u{28ff}').contains(&symbol);
        assert!(screen.chars().any(is_braille), "links are drawn");
        assert!(
            !screen.contains("NAME") && !screen.contains("Devices["),
            "the list is hidden"
        );

        tap(&mut app, KeyCode::Enter);
        click(&mut app, 10, FIRST_ROW);
        assert!(!app.popup, "nothing opens from the map");
        tap(&mut app, KeyCode::Char('m'));
        assert!(app.view == View::List);
        tap(&mut app, KeyCode::Char('m'));
        tap(&mut app, KeyCode::Esc);
        assert!(app.view == View::List, "Esc leaves the map before it quits");
        assert!(app.on_key(press(KeyCode::Esc)).is_break());
    }

    #[test]
    fn map_spreads_devices_around_their_hub() {
        let center = Point { x: 50.0, y: 10.0 };
        let reach = Point { x: 20.0, y: 5.0 };
        assert!(ring(0, center, reach).is_empty());
        let spots = ring(4, center, reach);
        let expected = [(50.0, 15.0), (30.0, 10.0), (50.0, 5.0), (70.0, 10.0)];
        for (spot, (x, y)) in spots.iter().zip(expected) {
            assert!(
                (spot.x - x).abs() < 1e-9 && (spot.y - y).abs() < 1e-9,
                "{spot:?}"
            );
        }

        let mut away = device(7, Role::Peer, "a-very-long-device-name.lan");
        away.presence = Presence::Offline;
        let label = map_label(&away);
        assert_eq!(label.width(), MAP_LABEL_WIDTH);
        assert_eq!(label.style.fg, Some(MUTED));
        // An empty map still draws.
        let mut empty = app(Vec::new(), Status::Ready);
        tap(&mut empty, KeyCode::Char('m'));
        assert_shows(&screen(&mut empty), &[" Map "]);
    }

    #[test]
    fn c_copies_the_address_of_the_selected_device() {
        let mut app = app(home(), Status::Ready);
        app.table.select(Some(1));
        tap(&mut app, KeyCode::Char('c'));
        assert_shows(&screen(&mut app), &[" Copied 192.168.1.5 "]);

        app.copy = |_| Err(io::Error::other("no clipboard"));
        tap(&mut app, KeyCode::Char('c'));
        assert_shows(
            &screen(&mut app),
            &[" 192.168.1.5 not copied: no clipboard "],
        );

        let mut empty = app_without_devices();
        tap(&mut empty, KeyCode::Char('c'));
        assert_eq!(empty.notice, None, "nothing selected, nothing copied");
    }

    #[test]
    fn e_exports_a_report_and_says_where() {
        let folder =
            std::env::temp_dir().join(format!("netmap-test-report-{}", std::process::id()));
        fs::create_dir_all(&folder).unwrap();
        let mut app = app(home(), Status::Ready);
        app.report_folder = folder.clone();

        tap(&mut app, KeyCode::Char('e'));
        let notice = app.notice.clone().unwrap();
        let saved: Vec<PathBuf> = fs::read_dir(&folder)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        assert_eq!(saved.len(), 1);
        assert_eq!(notice, format!("Report saved to {}", saved[0].display()));
        let report = fs::read_to_string(&saved[0]).unwrap();
        assert!(report.contains("## Network 192.168.1.0/24"));
        assert!(report.contains("### nas (192.168.1.7)"));
        assert_shows(&screen(&mut app), &[" Report saved to ", "● Ready"]);

        fs::remove_dir_all(&folder).unwrap();
        tap(&mut app, KeyCode::Char('e'));
        let failure = app.notice.as_deref().unwrap();
        assert!(failure.starts_with("Report not saved: "), "{failure}");
    }

    #[test]
    fn a_coloured_dot_tells_presence() {
        let mut devices = home();
        devices[1].presence = Presence::Offline;
        devices[2].presence = Presence::Checking;
        let mut app = app(devices, Status::Ready);
        assert_eq!(
            dots(&mut app),
            [OK, ERROR, PENDING],
            "selected row included"
        );
        let screen = screen(&mut app);
        assert!(
            !screen.contains("offline") && !screen.contains("online"),
            "no words, just the dot"
        );

        let colours = [Presence::Online, Presence::Offline, Presence::Checking].map(presence_dot);
        assert_eq!(
            colours.map(|dot| dot.style.fg),
            [Some(OK), Some(ERROR), Some(PENDING)]
        );
    }

    fn type_text(app: &mut App, text: &str) {
        text.chars()
            .for_each(|character| tap(app, KeyCode::Char(character)));
    }

    fn names(app: &App) -> Vec<&str> {
        app.visible()
            .into_iter()
            .map(|index| app.devices[index].name())
            .collect()
    }

    #[test]
    fn slash_filters_the_list_as_you_type() {
        let mut app = app(home(), Status::Ready);
        app.table.select(Some(2));
        tap(&mut app, KeyCode::Char('/'));
        type_text(&mut app, "NAx");
        tap(&mut app, KeyCode::Backspace);
        tap(&mut app, KeyCode::Left);
        assert_eq!(
            (names(&app), app.table.selected()),
            (vec!["nas"], Some(0)),
            "live, case-blind"
        );
        let typing = screen(&mut app);
        assert_shows(&typing, &["Devices[1/3]", " Filter: NA▏ ", "● nas"]);
        assert!(!typing.contains("─ ●"), "a filtered list is flat");
        assert!(
            app.on_key(press(KeyCode::Char('q'))).is_continue(),
            "q is just a letter here"
        );
        tap(&mut app, KeyCode::Backspace);

        tap(&mut app, KeyCode::Enter);
        assert!(app.typing.is_none() && app.filter == "NA");
        assert_shows(&screen(&mut app), &[" Filter: NA ", "Devices[1/3]"]);
        tap(&mut app, KeyCode::Enter);
        assert_shows(&screen(&mut app), &[" nas ", "Open TCP ports"]);
        tap(&mut app, KeyCode::Esc);

        tap(&mut app, KeyCode::Char('/'));
        type_text(&mut app, "zzz");
        assert!(names(&app).is_empty());
        tap(&mut app, KeyCode::Esc);
        assert_eq!(
            (app.filter.as_str(), names(&app)),
            ("NA", vec!["nas"]),
            "Esc drops what was typed"
        );

        tap(&mut app, KeyCode::Esc);
        assert!(
            app.filter.is_empty() && names(&app).len() == 3,
            "Esc clears the filter before it quits"
        );
        assert!(app.on_key(press(KeyCode::Esc)).is_break());
    }

    #[test]
    fn filter_looks_at_everything_the_list_shows() {
        let nas = device(7, Role::Peer, "nas");
        for needle in ["", "nas", "192.168.1.7", "a4:bb", "acme", "server", "/24"] {
            assert!(matches_filter(&nas, needle), "{needle:?}");
        }
        assert!(!matches_filter(&nas, "printer"));
        // Mouse input is ignored while typing.
        let mut app = app(home(), Status::Ready);
        screen(&mut app);
        tap(&mut app, KeyCode::Char('/'));
        click(&mut app, 10, FIRST_ROW + 1);
        assert!(!app.popup && app.typing.is_some());
        assert!(app
            .on_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL))
            .is_break());
    }

    #[test]
    fn s_cycles_through_the_sort_orders() {
        let mut devices = home();
        devices[0].ping = None;
        devices[1].ping = Some(Ping {
            ttl: 64,
            latency_ms: 9.0,
        });
        devices[1].last_seen = 50;
        devices[2].last_seen = 10;
        devices[2].probes.clear();
        let mut app = app(devices, Status::Ready);
        app.table.select(Some(2));

        let order = |app: &App| {
            names(app)
                .into_iter()
                .map(str::to_owned)
                .collect::<Vec<_>>()
        };
        let mut orders = vec![order(&app)];
        for _ in 0..5 {
            tap(&mut app, KeyCode::Char('s'));
            orders.push(order(&app));
        }
        let expected = [
            ["box", "tv", "nas"], // network
            ["box", "nas", "tv"], // name
            ["box", "tv", "nas"], // address
            ["tv", "box", "nas"], // type: Media, Router, Unknown
            ["nas", "tv", "box"], // ping: silent devices last
            ["box", "tv", "nas"], // last seen: most recent first
        ];
        assert_eq!(orders, expected);
        assert_eq!(
            app.table.selected(),
            Some(0),
            "a new order starts from its top"
        );
        let by_last_seen = screen(&mut app);
        assert_shows(&by_last_seen, &["Devices[3] by last seen"]);
        assert!(!by_last_seen.contains("─ ●"), "a sorted list is flat");
        tap(&mut app, KeyCode::Char('s'));
        assert!(app.sort == Sort::Network);
        let labels = [Sort::Name, Sort::Address, Sort::Kind, Sort::Latency].map(Sort::label);
        assert_eq!(labels, ["name", "address", "type", "ping"]);
    }

    #[test]
    fn n_names_a_device_and_saves_it() {
        static SAVED: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
        fn record(devices: &[Device]) {
            SAVED.lock().unwrap().push(
                devices
                    .iter()
                    .map(Device::name)
                    .collect::<Vec<_>>()
                    .join(","),
            );
        }
        let mut app = app(home(), Status::Ready);
        app.persist = record;
        app.table.select(Some(1));

        tap(&mut app, KeyCode::Char('n'));
        type_text(&mut app, " Living room TV ");
        assert_shows(&screen(&mut app), &[" Name:  Living room TV ▏ "]);
        tap(&mut app, KeyCode::Enter);
        assert_eq!(app.devices[1].name(), "Living room TV");
        assert_shows(&screen(&mut app), &["├─ ● Living room TV"]);

        tap(&mut app, KeyCode::Char('n'));
        assert_eq!(
            app.typing.as_ref().map(|(_, text)| text.as_str()),
            Some("Living room TV")
        );
        tap(&mut app, KeyCode::Esc);
        assert_eq!(
            app.devices[1].name(),
            "Living room TV",
            "Esc changes nothing"
        );

        tap(&mut app, KeyCode::Char('n'));
        (0..20).for_each(|_| tap(&mut app, KeyCode::Backspace));
        tap(&mut app, KeyCode::Enter);
        assert_eq!(
            app.devices[1].name(),
            "tv",
            "a blank name gives the discovered one back"
        );
        assert_eq!(
            *SAVED.lock().unwrap(),
            ["box,Living room TV,nas", "box,tv,nas"]
        );

        let mut empty = app_without_devices();
        tap(&mut empty, KeyCode::Char('n'));
        assert!(empty.typing.is_none(), "nothing to name");
        empty.rename("ghost");
        empty.on_typing(press(KeyCode::Enter));
    }

    fn app_without_devices() -> App {
        app(Vec::new(), Status::Ready)
    }

    #[test]
    fn a_name_given_during_a_scan_survives_its_results() {
        static SAVES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let (sender, receiver) = mpsc::channel();
        let mut app = app(home(), Status::Scanning(receiver));
        app.persist = |_| {
            SAVES.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        };
        app.table.select(Some(2));
        app.rename("Vault");
        let mut rescanned = home();
        rescanned.push(device(9, Role::Peer, "guest"));
        sender.send(Ok(rescanned)).unwrap();
        app.collect_scan();
        assert_eq!(names(&app), ["box", "tv", "Vault", "guest"]);
        assert_eq!(
            SAVES.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "once for the name, once for the scan"
        );
    }

    #[test]
    fn d_forgets_only_devices_that_are_away() {
        let mut devices = home();
        devices[2].presence = Presence::Offline;
        let mut app = app(devices, Status::Ready);

        tap(&mut app, KeyCode::Char('d'));
        assert_eq!(app.devices.len(), 3);
        assert_shows(
            &screen(&mut app),
            &["Only a device that is away can be forgotten"],
        );

        app.table.select(Some(2));
        app.status = Status::Scanning(mpsc::channel().1);
        tap(&mut app, KeyCode::Delete);
        assert_eq!(app.devices.len(), 3);
        assert!(app
            .notice
            .as_deref()
            .is_some_and(|notice| notice.starts_with("A scan is running")));

        app.status = Status::Ready;
        tap(&mut app, KeyCode::Enter);
        tap(&mut app, KeyCode::Char('d'));
        assert_eq!((names(&app), app.popup), (vec!["box", "tv"], false));
        assert_shows(&screen(&mut app), &[" Forgot nas ", "Devices[2]"]);

        let mut empty = app_without_devices();
        tap(&mut empty, KeyCode::Char('d'));
        assert!(empty.notice.is_none());
    }

    #[test]
    fn question_mark_shows_every_key_and_the_colours() {
        let mut app = app(home(), Status::Ready);
        tap(&mut app, KeyCode::Char('?'));
        let help = screen(&mut app);
        assert_shows(
            &help,
            &[
                " Help ",
                "Forget the selected device",
                "Rescan every port",
                "away",
                "NEW",
            ],
        );
        assert!(
            HELP.iter().all(|(_, action)| help.contains(action)),
            "nothing is cut off"
        );

        tap(&mut app, KeyCode::Char('q'));
        assert!(!app.help, "any key closes it, even q");
        tap(&mut app, KeyCode::Char('?'));
        click(&mut app, 0, 0);
        assert!(!app.help && !screen(&mut app).contains(" Help "));
    }

    #[test]
    fn header_counts_devices_by_presence() {
        let mut devices = home();
        devices[1].presence = Presence::Offline;
        let mut app = app(devices, Status::Ready);
        let census = app.census();
        let text: String = census
            .spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect();
        assert_eq!(text, "Devices       3   ● 2   ● 1");
        assert_eq!(census.spans[3].style.fg, Some(OK));
        assert_eq!(census.spans[6].style.fg, Some(ERROR));
        assert_shows(&screen(&mut app), &["3   ● 2   ● 1"]);
    }

    #[test]
    fn recent_arrivals_are_flagged_new() {
        let now = cache::now();
        let mut devices = home();
        devices
            .iter_mut()
            .for_each(|device| device.first_seen = now - 30 * 86_400);
        assert!(
            !screen(&mut app(devices.clone(), Status::Ready)).contains("NEW"),
            "all from day one"
        );

        devices[2].first_seen = now - 3_600;
        devices[1].first_seen = now - 2 * 86_400;
        let mut app = app(devices, Status::Ready);
        let screen = screen(&mut app);
        assert_shows(&screen, &["└─ ● nas NEW"]);
        assert!(!screen.contains("tv NEW") && !screen.contains("box NEW"));
        assert!(
            !is_new(&app.devices[2], now, now - 3_600),
            "the oldest device is never new"
        );
    }

    #[test]
    fn popup_needs_a_device() {
        let mut app = app(Vec::new(), Status::Ready);
        tap(&mut app, KeyCode::Enter);
        assert!(!app.popup);

        // The device list can empty out under an open popup (a rescan that finds nothing).
        app.popup = true;
        screen(&mut app);
        assert!(!app.popup);
    }

    #[test]
    fn shows_every_scan_status() {
        let scanning = || Status::Scanning(mpsc::channel().1);
        assert_shows(
            &screen(&mut app(Vec::new(), scanning())),
            &["Discovering devices…"],
        );
        assert_shows(
            &screen(&mut app(home(), scanning())),
            &["Scanning new devices…"],
        );
        assert_shows(
            &screen(&mut app(Vec::new(), Status::Failed("boom".to_owned()))),
            &["● boom"],
        );
    }

    #[test]
    fn every_kind_has_its_own_glyph() {
        let kinds = [
            DeviceKind::Gateway,
            DeviceKind::ThisDevice,
            DeviceKind::Printer,
            DeviceKind::Camera,
            DeviceKind::Media,
            DeviceKind::Phone,
            DeviceKind::Server,
            DeviceKind::Computer,
            DeviceKind::Iot,
            DeviceKind::Unknown,
        ];
        let mut glyphs: Vec<&str> = kinds.into_iter().map(kind_glyph).collect();
        glyphs.sort_unstable();
        glyphs.dedup();
        assert_eq!(glyphs.len(), kinds.len());
        assert!(kinds
            .into_iter()
            .all(|kind| kind_span(kind).style.fg == Some(kind_color(kind))));
    }

    #[test]
    fn keys_navigate_the_list_and_quit() {
        let mut app = app(home(), Status::Ready);

        tap(&mut app, KeyCode::Down);
        tap(&mut app, KeyCode::Char('j'));
        assert_eq!(app.table.selected(), Some(2));
        tap(&mut app, KeyCode::Up);
        tap(&mut app, KeyCode::Char('k'));
        assert_eq!(app.table.selected(), Some(0));
        tap(&mut app, KeyCode::End);
        screen(&mut app);
        assert_eq!(app.table.selected(), Some(2));
        tap(&mut app, KeyCode::Home);
        assert_eq!(app.table.selected(), Some(0));
        tap(&mut app, KeyCode::Char('x'));
        tap(&mut app, KeyCode::Char('c'));

        assert!(app.on_key(press(KeyCode::Char('q'))).is_break());
        assert!(app.on_key(press(KeyCode::Esc)).is_break());
        assert!(app
            .on_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL))
            .is_break());
    }

    #[test]
    fn keys_scroll_the_popup_instead_of_the_list() {
        let mut app = app(home(), Status::Ready);
        tap(&mut app, KeyCode::Enter);

        tap(&mut app, KeyCode::Down);
        tap(&mut app, KeyCode::Down);
        tap(&mut app, KeyCode::Up);
        assert_eq!((app.detail_scroll, app.table.selected()), (1, Some(0)));
        tap(&mut app, KeyCode::End);
        tap(&mut app, KeyCode::Home);
        assert_eq!(
            app.table.selected(),
            Some(0),
            "the list is frozen under the popup"
        );
        screen(&mut app);
        assert_eq!(app.detail_scroll, 0, "details that fit do not scroll");

        assert!(app.on_key(press(KeyCode::Char('q'))).is_break());
        assert!(app
            .on_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL))
            .is_break());
        tap(&mut app, KeyCode::Esc);
        assert!(!app.popup, "Esc closes the popup before it quits");
    }

    #[test]
    fn long_details_scroll_but_not_past_the_end() {
        let mut busy = device(7, Role::Peer, "nas");
        // The long banner wraps: scrolling must count rendered lines, not logical ones.
        busy.probes = (1..=60)
            .map(|port| Probe {
                port,
                banner: Some("x".repeat(90)),
            })
            .collect();
        let mut app = app(vec![busy], Status::Ready);
        tap(&mut app, KeyCode::Enter);
        app.detail_scroll = u16::MAX;
        let screen = screen(&mut app);
        assert!(app.detail_scroll > 60 && app.detail_scroll < u16::MAX);
        assert!(app.popup_area.height < 30 && app.popup_area.width <= POPUP_MAX_WIDTH);
        assert_shows(&screen, &["60/tcp"]);
    }

    #[test]
    fn clicking_a_device_opens_its_popup() {
        let mut app = app(home(), Status::Ready);
        screen(&mut app);

        click(&mut app, 10, FIRST_ROW - 1); // Column titles.
        click(&mut app, 10, FIRST_ROW + 3); // Below the last device.
        click(&mut app, 10, 2); // Header.
        assert!(!app.popup);

        click(&mut app, 10, FIRST_ROW + 1);
        assert!(app.popup);
        assert_eq!(app.table.selected(), Some(1));
        assert_shows(&screen(&mut app), &[" tv ", "Open TCP ports (2)"]);

        click(&mut app, 60, 15);
        assert!(app.popup, "a click inside the popup keeps it open");
        click(&mut app, 0, 0);
        assert!(!app.popup, "a click outside closes it");
    }

    #[test]
    fn mouse_wheel_scrolls_whatever_is_in_front() {
        let mut app = app(home(), Status::Ready);
        mouse(&mut app, MouseEventKind::ScrollDown, 0, 0);
        assert_eq!(app.table.selected(), Some(1));
        mouse(&mut app, MouseEventKind::ScrollUp, 0, 0);
        assert_eq!(app.table.selected(), Some(0));
        mouse(&mut app, MouseEventKind::Moved, 0, 0);

        tap(&mut app, KeyCode::Enter);
        mouse(&mut app, MouseEventKind::ScrollDown, 0, 0);
        assert_eq!((app.detail_scroll, app.table.selected()), (1, Some(0)));
        mouse(&mut app, MouseEventKind::ScrollUp, 0, 0);
        assert_eq!(app.detail_scroll, 0);
    }

    #[test]
    fn only_presses_and_mouse_events_count() {
        let mut app = app(home(), Status::Ready);
        let release = KeyEvent::new_with_kind(
            KeyCode::Char('q'),
            KeyModifiers::NONE,
            KeyEventKind::Release,
        );
        assert!(app.on_event(Event::Key(release)).is_continue());
        assert!(app.on_event(Event::FocusGained).is_continue());
        assert!(app.on_event(Event::Key(press(KeyCode::Down))).is_continue());
        assert_eq!(app.table.selected(), Some(1));
        assert!(app
            .on_event(Event::Key(press(KeyCode::Char('q'))))
            .is_break());
    }

    #[test]
    fn collects_partial_results_then_becomes_ready() {
        let mut app = App::new(lan(), Vec::new(), |interfaces, _, _, report| {
            report(Vec::new());
            report(vec![Device {
                ip: interfaces[0].ip,
                subnet: interfaces[0].subnet,
                ping: None,
                netbios: None,
                mdns: Vec::new(),
                label: None,
                first_seen: 0,
                last_seen: 0,
                ports_scanned: None,
                presence: Presence::Online,
                role: Role::This,
                mac: None,
                hostname: None,
                vendor: None,
                upnp: None,
                probes: Vec::new(),
            }]);
            Ok(())
        });
        app.rescan(true); // Ignored: a scan is already running.
        settle(&mut app);
        assert!(matches!(app.status, Status::Ready));
        assert_eq!(app.devices.len(), 1);
        assert_eq!(app.table.selected(), Some(0));

        app.notice = Some("old news".to_owned());
        tap(&mut app, KeyCode::Char('r'));
        assert!(matches!(app.status, Status::Scanning(_)) && app.notice.is_none());
        assert!(app
            .devices
            .iter()
            .all(|device| device.presence == Presence::Checking));
        settle(&mut app);
        assert_eq!(app.devices.len(), 1);
    }

    #[test]
    fn a_scan_can_find_nothing_or_fail() {
        let mut idle = App::new(lan(), Vec::new(), finds_nothing);
        settle(&mut idle);
        assert!(matches!(idle.status, Status::Ready) && idle.devices.is_empty());

        let mut app = App::new(lan(), Vec::new(), |_, _, _, _| {
            Err("no vendor database".to_owned())
        });
        settle(&mut app);
        assert!(matches!(&app.status, Status::Failed(error) if error == "no vendor database"));
    }

    #[test]
    fn event_loop_draws_until_quit() {
        let mut app = app(home(), Status::Ready);
        let mut terminal = Terminal::new(TestBackend::new(120, 30)).unwrap();
        let keys = [KeyCode::Down, KeyCode::Char('q')].map(|code| Some(Event::Key(press(code))));
        let mut events = [None].into_iter().chain(keys);
        app.event_loop(&mut terminal, || Ok(events.next().flatten()))
            .unwrap();
        assert_eq!((app.ticks, app.table.selected()), (3, Some(1)));

        let failing = app.event_loop(&mut terminal, || Err(io::Error::other("input closed")));
        assert!(failing.is_err());
    }

    /// A made-up home network, so the screenshots show no real device.
    fn showcase() -> Vec<Device> {
        let peer = |host: u8, name: &str, vendor: &str, ports: &[u16]| Device {
            vendor: Some(vendor.to_owned()),
            probes: ports
                .iter()
                .map(|&port| Probe { port, banner: None })
                .collect(),
            ..device(host, Role::Peer, name)
        };
        let lab = |host: u8, role: Role, name: &str| Device {
            ip: Ipv4Addr::new(10, 0, 0, host),
            subnet: Subnet::new(Ipv4Addr::new(10, 0, 0, 2), 24),
            ..device(host, role, name)
        };
        vec![
            Device {
                vendor: Some("Sagemcom".to_owned()),
                upnp: Some(Upnp {
                    friendly_name: Some("Fiber Box 6".to_owned()),
                    manufacturer: Some("Sagemcom".to_owned()),
                    model: Some("F6-AX".to_owned()),
                    url: Some("http://192.168.1.1/".to_owned()),
                    ..Upnp::default()
                }),
                ..device(1, Role::Gateway, "box")
            },
            Device {
                role: Role::This,
                ..peer(20, "workstation", "Intel", &[445, 3389])
            },
            Device {
                mdns: vec!["_googlecast._tcp".to_owned(), "_airplay._tcp".to_owned()],
                ..peer(5, "living-room-tv", "Samsung", &[8009])
            },
            Device {
                netbios: Some(Netbios {
                    name: Some("NAS".to_owned()),
                    workgroup: Some("HOME".to_owned()),
                }),
                ..peer(7, "nas", "Synology", &[22, 80, 443, 445, 5000, 32400])
            },
            peer(12, "office-printer", "HP", &[80, 631, 9100]),
            peer(31, "front-door-camera", "Reolink", &[80, 554]),
            Device {
                first_seen: cache::now(),
                ..peer(42, "pixel-8", "Google", &[])
            },
            Device {
                presence: Presence::Offline,
                ping: None,
                ..peer(50, "thermostat", "Espressif", &[1883])
            },
            Device {
                presence: Presence::Checking,
                ..peer(60, "laptop", "Dell", &[445])
            },
            lab(1, Role::Gateway, "lab-router"),
            lab(10, Role::Peer, "build-server"),
        ]
    }

    /// The screen as a web page: one fixed-size box per terminal cell, so nothing drifts.
    fn html(app: &mut App) -> String {
        const CSS: &str = "body{margin:0;padding:16px;background:#1e1e2e}\
            .t{display:grid;grid-template-columns:repeat(120,9px);grid-auto-rows:19px;\
            font:15px/19px 'Cascadia Mono',Consolas,monospace;text-align:center}\
            .t b{font-weight:normal;overflow:hidden}";
        let css = |color: Color, fallback: &str| match color {
            Color::Rgb(red, green, blue) => format!("rgb({red},{green},{blue})"),
            _ => fallback.to_owned(),
        };
        let mut terminal = Terminal::new(TestBackend::new(120, 34)).unwrap();
        terminal.draw(|frame| app.draw(frame)).unwrap();
        let cells: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| {
                let weight = if cell.modifier.contains(Modifier::BOLD) {
                    ";font-weight:bold"
                } else {
                    ""
                };
                let symbol = cell.symbol().replace('&', "&amp;").replace('<', "&lt;");
                let (ink, paper) = (css(cell.fg, "#cdd6f4"), css(cell.bg, "transparent"));
                format!("<b style=\"color:{ink};background:{paper}{weight}\">{symbol}</b>")
            })
            .collect();
        format!("<!doctype html><meta charset=\"utf-8\"><style>{CSS}</style><div class=\"t\">{cells}</div>")
    }

    /// Writes the README screenshots as web pages into `target/screens`:
    /// `cargo test screenshots -- --ignored`, then capture each page with a headless browser.
    #[test]
    #[ignore = "writes files; run on demand to refresh the README screenshots"]
    fn screenshots() {
        let folder = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/screens");
        fs::create_dir_all(&folder).unwrap();
        let mut app = app(showcase(), Status::Ready);
        let a_while_ago = cache::now() - 40 * 86_400;
        app.devices
            .iter_mut()
            .filter(|device| device.first_seen == 0)
            .for_each(|device| device.first_seen = a_while_ago);
        let lab = Ipv4Addr::new(10, 0, 0, 2);
        app.interfaces.push(Interface {
            ip: lab,
            subnet: Subnet::new(lab, 24),
        });
        let shoot = |name: &str, app: &mut App| {
            fs::write(folder.join(format!("{name}.html")), html(app)).unwrap();
        };

        shoot("list", &mut app);
        app.table.select(Some(3));
        tap(&mut app, KeyCode::Enter);
        shoot("details", &mut app);
        tap(&mut app, KeyCode::Esc);
        tap(&mut app, KeyCode::Char('m'));
        shoot("map", &mut app);
        tap(&mut app, KeyCode::Char('m'));
        tap(&mut app, KeyCode::Char('?'));
        shoot("help", &mut app);
    }
}
