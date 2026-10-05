//! 彩色 TUI 输出helpers。
//!
//! 风格对齐 `../x_key_scanner`：启动横幅是硬编码 ansi_shadow 艺术字 + 逐列
//! 青→品红 truecolor 渐变；section/field/ok 用 anstyle 配色。
//! 收发包内容用方框框起来，顶部标注方向 / seq / 命令字等。

use anstyle::{AnsiColor, Color, RgbColor, Style};
use std::io::Write;

use crate::art::BANNER_ART;

fn styled(style: Style, text: &str) -> String {
    format!("{style}{text}{style:#}")
}

fn fg(c: AnsiColor) -> Style {
    Style::new().fg_color(Some(Color::Ansi(c)))
}

/// Linear cyan(0,255,255)→magenta(255,0,255) at position `t` in [0,1].
fn gradient(t: f32) -> Style {
    let t = t.clamp(0.0, 1.0);
    let r = (t * 255.0).round() as u8;
    let g = ((1.0 - t) * 255.0).round() as u8;
    Style::new()
        .fg_color(Some(Color::Rgb(RgbColor(r, g, 255))))
        .bold()
}

/// 结构化输出（hexdump / 解码树）的语义色板：不同用途用不同颜色，便于区分。
pub mod palette {
    use anstyle::{AnsiColor, Color, Style};

    fn c(col: AnsiColor) -> Style {
        Style::new().fg_color(Some(Color::Ansi(col)))
    }

    /// 暗色：偏移、省略标记、标点。
    pub fn dim() -> Style {
        c(AnsiColor::BrightBlack)
    }
    /// hexdump 行首偏移。
    pub fn offset() -> Style {
        dim()
    }
    /// hexdump 的十六进制字节。
    pub fn hex() -> Style {
        c(AnsiColor::Cyan)
    }
    /// hexdump 的可打印 ASCII。
    pub fn ascii() -> Style {
        c(AnsiColor::Green)
    }
    /// 解码树的字段号。
    pub fn tag() -> Style {
        c(AnsiColor::Yellow).bold()
    }
    /// 数值字面量。
    pub fn num() -> Style {
        c(AnsiColor::BrightWhite)
    }
    /// 整数/浮点/fixed 类型名。
    pub fn ty_num() -> Style {
        c(AnsiColor::BrightCyan)
    }
    /// 字符串类型名。
    pub fn ty_text() -> Style {
        c(AnsiColor::Green)
    }
    /// bytes 类型名。
    pub fn ty_bytes() -> Style {
        c(AnsiColor::Magenta)
    }
    /// message/struct/list/map 容器类型名。
    pub fn ty_container() -> Style {
        c(AnsiColor::Yellow)
    }
    /// 标点（箭头、括号等）。
    pub fn punct() -> Style {
        c(AnsiColor::BrightBlack)
    }
}

/// 给一段文本套上颜色（返回带 ANSI 的字符串）。
pub fn paint(style: Style, text: &str) -> String {
    styled(style, text)
}

/// 渲染 hexdump：`偏移 + hex + ASCII`。`max` 为 `Some(n)` 时只预览前 `n` 字节
/// 并在末尾标注省略量，`None` 表示完整渲染。返回的行已带颜色。
pub fn hexdump_lines(bytes: &[u8], per_line: usize, max: Option<usize>) -> Vec<String> {
    if bytes.is_empty() {
        return vec![paint(palette::dim(), "(empty)")];
    }
    let per_line = per_line.max(1);
    let take = max.map_or(bytes.len(), |m| m.min(bytes.len()));
    let mut out = Vec::with_capacity(take / per_line + 2);
    for (li, chunk) in bytes[..take].chunks(per_line).enumerate() {
        let mut hexs = String::new();
        for i in 0..per_line {
            if i > 0 {
                hexs.push(' ');
            }
            match chunk.get(i) {
                Some(b) => hexs.push_str(&paint(palette::hex(), &format!("{b:02x}"))),
                None => hexs.push_str("  "),
            }
        }
        let mut ascii = String::new();
        for &b in chunk {
            let (ch, style) = if (0x20..=0x7e).contains(&b) {
                (b as char, palette::ascii())
            } else {
                ('.', palette::dim())
            };
            ascii.push_str(&paint(style, &ch.to_string()));
        }
        out.push(format!(
            "{}  {hexs}  {ascii}",
            paint(palette::offset(), &format!("{:04x}", li * per_line))
        ));
    }
    if bytes.len() > take {
        out.push(paint(
            palette::dim(),
            &format!("… (+{}B)", bytes.len() - take),
        ));
    }
    out
}

/// Print the big startup banner: gradient figlet art + a subtitle line.
pub fn app_banner(subtitle: &str) {
    let mut out = anstream::stdout();
    let _ = writeln!(out);
    let width = BANNER_ART
        .iter()
        .map(|l| l.chars().count())
        .max()
        .unwrap_or(1)
        .max(1) as f32;
    for line in BANNER_ART {
        let mut painted = String::new();
        for (col, ch) in line.chars().enumerate() {
            if ch == ' ' {
                painted.push(' ');
            } else {
                let g = gradient(col as f32 / width);
                painted.push_str(&format!("{g}{ch}{g:#}"));
            }
        }
        let _ = writeln!(out, "{painted}");
    }
    let _ = writeln!(out, "  {}\n", styled(fg(AnsiColor::BrightBlack), subtitle));
}

/// A section header (dim rule under a bold cyan title).
pub fn section(title: &str) {
    let s = fg(AnsiColor::Cyan).bold();
    let mut out = anstream::stdout();
    let _ = writeln!(out, "\n{}", styled(s, title));
    let _ = writeln!(
        out,
        "{}",
        styled(
            fg(AnsiColor::BrightBlack),
            &"─".repeat(title.chars().count().max(1))
        )
    );
}

/// A "label: value" line with a dim label and a bright value.
pub fn field(label: &str, value: &str) {
    let l = fg(AnsiColor::BrightBlack);
    let v = fg(AnsiColor::White).bold();
    let mut out = anstream::stdout();
    let _ = writeln!(out, "  {:<20} {}", styled(l, label), styled(v, value));
}

pub fn ok(msg: &str) {
    let mut out = anstream::stdout();
    let _ = writeln!(
        out,
        "{}  {msg}",
        styled(fg(AnsiColor::Green).bold(), "[ ok ]")
    );
}

pub fn info(msg: &str) {
    let mut out = anstream::stdout();
    let _ = writeln!(
        out,
        "{} {msg}",
        styled(fg(AnsiColor::Blue).bold(), "[info]")
    );
}

pub fn warn(msg: &str) {
    let mut out = anstream::stderr();
    let _ = writeln!(
        out,
        "{} {msg}",
        styled(fg(AnsiColor::Yellow).bold(), "[warn]")
    );
}

pub fn error(msg: &str) {
    let mut out = anstream::stderr();
    let _ = writeln!(out, "{} {msg}", styled(fg(AnsiColor::Red).bold(), "[fail]"));
}

/// Highlight a recovered key/value prominently.
pub fn key_line(label: &str, value: &str) {
    let l = fg(AnsiColor::BrightBlack);
    let v = fg(AnsiColor::BrightGreen).bold();
    let mut out = anstream::stdout();
    let _ = writeln!(out, "  {:<20} {}", styled(l, label), styled(v, value));
}

/// 收发方向。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    /// 客户端 -> 服务端。
    Tx,
    /// 服务端 -> 客户端。
    Rx,
}

impl Dir {
    pub fn label(self) -> &'static str {
        match self {
            Dir::Tx => "TX",
            Dir::Rx => "RX",
        }
    }

    pub fn arrow(self) -> &'static str {
        match self {
            Dir::Tx => "→",
            Dir::Rx => "←",
        }
    }

    /// TX 用青绿，RX 用品红——两个方向一眼可辨。
    fn style(self) -> Style {
        match self {
            Dir::Tx => fg(AnsiColor::BrightGreen).bold(),
            Dir::Rx => fg(AnsiColor::BrightMagenta).bold(),
        }
    }
}

/// 一个字符的显示宽度：CJK 全角/emoji 记 2 列，其余 1 列。
fn char_width(c: char) -> usize {
    let u = c as u32;
    // 常见东亚全角区段与 emoji（近似覆盖，足够对齐 TUI）。
    if (0x1100..=0x115F).contains(&u)
        || (0x2E80..=0xA4CF).contains(&u)
        || (0xAC00..=0xD7A3).contains(&u)
        || (0xF900..=0xFAFF).contains(&u)
        || (0xFE30..=0xFE4F).contains(&u)
        || (0xFF00..=0xFF60).contains(&u)
        || (0xFFE0..=0xFFE6).contains(&u)
        || (0x1F300..=0x1FAFF).contains(&u)
    {
        2
    } else {
        1
    }
}

/// 显示宽度：跳过 ANSI CSI 转义序列（颜色不计宽），其余按 `char_width` 累加。
fn display_width(s: &str) -> usize {
    let mut width = 0;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            if chars.peek() == Some(&'[') {
                chars.next();
                for e in chars.by_ref() {
                    if ('\u{40}'..='\u{7e}').contains(&e) {
                        break;
                    }
                }
            }
            continue;
        }
        width += char_width(c);
    }
    width
}

fn pad_to(s: &str, cols: usize) -> String {
    let w = display_width(s);
    if w >= cols {
        s.to_string()
    } else {
        format!("{s}{}", " ".repeat(cols - w))
    }
}

/// 探测终端可见列数（stdout 非 TTY 时返回 None，此时不做宽度限制）。
#[cfg(unix)]
fn terminal_width() -> Option<usize> {
    // SAFETY: TIOCGWINSZ fills a properly sized winsize struct, or fails.
    unsafe {
        let mut ws: libc::winsize = std::mem::zeroed();
        if libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut ws) == 0 && ws.ws_col > 0 {
            Some(ws.ws_col as usize)
        } else {
            None
        }
    }
}

/// Windows：从控制台窗口缓冲区信息里取可见宽度。
#[cfg(windows)]
fn terminal_width() -> Option<usize> {
    use windows_sys::Win32::System::Console::{
        CONSOLE_SCREEN_BUFFER_INFO, GetConsoleScreenBufferInfo, GetStdHandle, STD_OUTPUT_HANDLE,
    };
    // SAFETY: queries the stdout console screen buffer info.
    unsafe {
        let handle = GetStdHandle(STD_OUTPUT_HANDLE);
        let mut info: CONSOLE_SCREEN_BUFFER_INFO = std::mem::zeroed();
        if GetConsoleScreenBufferInfo(handle, &mut info) != 0 {
            let w = (info.srWindow.Right - info.srWindow.Left + 1) as usize;
            (w > 0).then_some(w)
        } else {
            None
        }
    }
}

/// 按可见宽度把一行截断到 `max_cols` 以内（ANSI 转义不计宽）。发生截断时在末尾
/// 加 `…` 并重置颜色，避免样式串到框线上。宁可截断也不换行。
fn truncate_visible(s: &str, max_cols: usize) -> String {
    if display_width(s) <= max_cols {
        return s.to_string();
    }
    // 预留 1 列给省略号。
    let limit = max_cols.saturating_sub(1);
    let mut out = String::new();
    let mut width = 0usize;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            out.push(c);
            if chars.peek() == Some(&'[') {
                out.push(chars.next().unwrap());
                for e in chars.by_ref() {
                    out.push(e);
                    if ('\u{40}'..='\u{7e}').contains(&e) {
                        break;
                    }
                }
            }
            continue;
        }
        let w = char_width(c);
        if width + w > limit {
            break;
        }
        out.push(c);
        width += w;
    }
    out.push_str("\u{1b}[0m");
    out.push('…');
    out
}

/// 供方框之外的普通行输出使用：按当前终端宽度截断一行，并把内嵌换行转义掉。
/// 终端宽度未知（非 TTY）时不做限制。
pub fn fit_line_to_terminal(s: &str, indent: usize) -> String {
    let sanitized = s.replace('\r', "\\r").replace('\n', "\\n");
    match terminal_width() {
        Some(w) => truncate_visible(&sanitized, w.saturating_sub(indent)),
        None => sanitized,
    }
}

/// 方框渲染：正文可含 ANSI 颜色，宽度按可见字符计算（`display_width` 会跳过转义序列）。
/// 顶部 header 段用 ` · ` 连接。
pub fn render_box(dir: Dir, segments: &[String], body: &[String], min_width: usize) -> String {
    render_box_bounded(dir, segments, body, min_width, terminal_width())
}

/// `render_box` 的实现体，额外接受一个显式宽度上限（`None` = 不限宽，便于测试）。
fn render_box_bounded(
    dir: Dir,
    segments: &[String],
    body: &[String],
    min_width: usize,
    max_width: Option<usize>,
) -> String {
    let head = format!("{} {} {}", dir.arrow(), dir.label(), segments.join(" · "));
    let head_w = display_width(&head);
    // 内容区可用上限：每行总宽 = content_w + 4（`│ ` + 内容 + ` │`），必须 ≤ 终端宽度。
    let cap = max_width.map(|w| w.saturating_sub(4)).filter(|&w| w > 0);
    // 内容区宽度：必须 ≥ 最长正文行（否则 pad_to 填不下会溢出、右边框右移），
    // 也 ≥ 头部宽度 + 1（`head` 后跟一个空格），再取 min_width；最后按终端宽度封顶。
    let max_body = body.iter().map(|l| display_width(l)).max().unwrap_or(0);
    let mut content_w = max_body.max(head_w + 1).max(min_width);
    if let Some(c) = cap {
        content_w = content_w.min(c);
    }
    // 上边框：`┌ <head> ────┐`，各行总宽 = head_w + dashes + 4 = content_w + 4。
    // 头部若超过内容区宽度（终端很窄时），同样按可见宽度截断，保证各行等宽。
    let head = truncate_visible(&head, content_w);
    let head_w = display_width(&head);
    let dashes = content_w.saturating_sub(head_w);
    let mut out = String::new();
    out.push('┌');
    out.push(' ');
    out.push_str(&head);
    out.push(' ');
    out.push_str(&"─".repeat(dashes));
    out.push('┐');
    out.push('\n');

    for line in body {
        // 先把可能存在的原始换行转义掉，避免内嵌换行把方框冲断。
        let sanitized = line.replace('\r', "\\r").replace('\n', "\\n");
        let fitted = match cap {
            Some(c) => truncate_visible(&sanitized, c),
            None => sanitized,
        };
        out.push_str("│ ");
        out.push_str(&pad_to(&fitted, content_w));
        out.push_str(" │\n");
    }
    out.push('└');
    out.push_str(&"─".repeat(content_w + 2));
    out.push('┘');
    out
}

/// 彩色方框：把 render_box 的边框染成方向色、头部段加粗。
pub fn packet_box(dir: Dir, segments: &[String], body: &[String], min_width: usize) {
    let plain = render_box(dir, segments, body, min_width);
    let border = dir.style();
    let mut out = anstream::stdout();
    for (i, line) in plain.lines().enumerate() {
        let painted = if i == 0 {
            styled(border, line)
        } else {
            // 只给首尾框线着色，内容保持原样。
            let bytes: Vec<char> = line.chars().collect();
            if bytes.len() >= 2 {
                let mid: String = bytes[1..bytes.len() - 1].iter().collect();
                format!(
                    "{}{}{}",
                    styled(border, &bytes[0].to_string()),
                    mid,
                    styled(border, &bytes[bytes.len() - 1].to_string())
                )
            } else {
                line.to_string()
            }
        };
        let _ = writeln!(out, "{painted}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn box_has_correct_corners_and_width() {
        let b = render_box(
            Dir::Tx,
            &["seq=1".into(), "cmd=Foo.Bar".into()],
            &["hello".into(), "world!!".into()],
            0,
        );
        let lines: Vec<&str> = b.lines().collect();
        assert_eq!(lines.len(), 4); // 上框 + 2 行 + 下框
        assert!(lines[0].starts_with('┌') && lines[0].ends_with('┐'));
        assert!(lines[3].starts_with('└') && lines[3].ends_with('┘'));
        assert!(
            lines[0].contains("TX")
                && lines[0].contains("seq=1")
                && lines[0].contains("cmd=Foo.Bar")
        );
        // 所有行显示宽度一致
        let w = display_width(lines[0]);
        for l in &lines {
            assert_eq!(display_width(l), w, "line width mismatch: {l:?}");
        }
    }

    #[test]
    fn longest_body_line_does_not_overflow_border() {
        // 回归：最长正文行恰好等于内容区宽度时，右边框不得右移。
        let long = "0000  ".to_string() + &"aa ".repeat(32);
        let long = long.trim_end().to_string();
        let b = render_box(
            Dir::Tx,
            &["seq=1".into()],
            &[long.clone(), "short".into()],
            0,
        );
        let lines: Vec<&str> = b.lines().collect();
        let w = display_width(lines[0]);
        for l in &lines {
            assert_eq!(display_width(l), w, "line width mismatch: {l:?}");
        }
        // 最长行本身也落在框内（宽度与其它行一致）
        assert!(lines.iter().any(|l| l.contains("aa")));
    }

    #[test]
    fn rx_label_and_wide_chars() {
        let b = render_box(Dir::Rx, &["seq=2".into()], &["中文内容".into()], 0);
        assert!(b.contains("RX") && b.contains("←"));
        let lines: Vec<&str> = b.lines().collect();
        assert_eq!(display_width(lines[0]), display_width(lines[1]));
    }

    #[test]
    fn hexdump_has_offset_hex_ascii() {
        // 每行 hex 段按 per_line 对齐：偏移 4 + 2 空格 + 16 字节 hex(47) + 2 空格 + ASCII 3 = 58
        let lines = hexdump_lines(b"AB\n", 16, None);
        assert_eq!(lines.len(), 1);
        assert_eq!(display_width(&lines[0]), 4 + 2 + 47 + 2 + 3);
        assert!(lines[0].contains('A') && lines[0].contains('.'));
        assert!(lines[0].contains("\u{1b}["));
    }

    #[test]
    fn hexdump_preview_marks_truncation() {
        let b: Vec<u8> = (0u8..200).collect();
        let preview = hexdump_lines(&b, 16, Some(128));
        assert_eq!(preview.len(), 9); // 8 行 hex + 1 行省略
        assert!(preview.last().unwrap().contains("(+72B)"));

        let full = hexdump_lines(&b, 16, None);
        assert_eq!(full.len(), 13); // ceil(200/16) == 13，无省略行
        assert!(!full.iter().any(|l| l.contains("\u{2026} (+")));
    }

    #[test]
    fn hexdump_empty() {
        let lines = hexdump_lines(&[], 32, None);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("(empty)"));
    }

    #[test]
    fn ansi_sequences_do_not_count_toward_width() {
        let plain = "0000  41 42 43";
        let painted = format!(
            "{}{}{}{}",
            paint(palette::offset(), "0000"),
            "  ",
            paint(palette::hex(), "41 42 43"),
            ""
        );
        assert_eq!(display_width(plain), display_width(&painted));
    }

    #[test]
    fn truncate_visible_keeps_ansi_and_adds_ellipsis() {
        let painted = paint(palette::tag(), &"x".repeat(100));
        let cut = truncate_visible(&painted, 20);
        // 可见宽度 == 上限（19 内容 + 1 省略号）。
        assert_eq!(display_width(&cut), 20);
        assert!(cut.ends_with('…'));
        // 颜色起始序列保留，且末尾显式复位，避免样式串到框线。
        assert!(cut.contains("\u{1b}["));
        assert!(cut.ends_with("\u{1b}[0m…"));
    }

    #[test]
    fn long_body_line_is_truncated_not_wrapped() {
        // 模拟终端宽度 80：方框总宽不得超过 80，且长行以省略号截断。
        let long = "a".repeat(500);
        let b = render_box_bounded(
            Dir::Tx,
            &["seq=1".into()],
            &[long.clone(), "short".into()],
            0,
            Some(80),
        );
        let lines: Vec<&str> = b.lines().collect();
        assert!(lines.iter().all(|l| display_width(l) <= 80), "溢出终端宽度");
        let w = display_width(lines[0]);
        for l in &lines {
            assert_eq!(display_width(l), w, "line width mismatch: {l:?}");
        }
        assert!(lines.iter().any(|l| l.contains('…')));
    }

    #[test]
    fn embedded_newline_does_not_break_box() {
        // 正文行内嵌换行必须被转义，否则会冲断方框（左右边框数量 == 总行数）。
        let body = vec!["a\nb\rc".to_string()];
        let b = render_box_bounded(Dir::Rx, &["seq=1".into()], &body, 0, Some(80));
        let lines: Vec<&str> = b.lines().collect();
        assert_eq!(lines.len(), 3); // 上框 + 1 行 + 下框
        assert!(lines[1].contains("\\n") && lines[1].contains("\\r"));
        let w = display_width(lines[0]);
        for l in &lines {
            assert_eq!(display_width(l), w, "line width mismatch: {l:?}");
        }
    }

    #[test]
    fn narrow_terminal_truncates_header_too() {
        // 终端极窄时头部也要截断，各行仍需等宽。
        let b = render_box_bounded(
            Dir::Tx,
            &["seq=1".into(), "cmd=A.B".into()],
            &["x".into()],
            0,
            Some(20),
        );
        let lines: Vec<&str> = b.lines().collect();
        let w = display_width(lines[0]);
        assert!(w <= 20, "方框超过终端宽度: {w}");
        for l in &lines {
            assert_eq!(display_width(l), w, "line width mismatch: {l:?}");
        }
    }

    #[test]
    fn colored_hexdump_fits_box() {
        // 集成：带 ANSI 的 hexdump 行放进方框后，各显示宽度仍需一致。
        let body = hexdump_lines(b"GET / HTTP/1.1\r\n\r\n", 16, None);
        let b = render_box(Dir::Tx, &["seq=1".into()], &body, 0);
        let lines: Vec<&str> = b.lines().collect();
        let w = display_width(lines[0]);
        for l in &lines {
            assert_eq!(display_width(l), w, "line width mismatch: {l:?}");
        }
        // ASCII 逐字符着色，故只断言字符存在，不断言连续子串。
        assert!(b.contains('G') && b.contains('E') && b.contains('T'));
    }

    #[test]
    fn gradient_stays_in_range() {
        assert_eq!(
            gradient(-1.0).get_fg_color(),
            Some(Color::Rgb(RgbColor(0, 255, 255)))
        );
        assert_eq!(
            gradient(2.0).get_fg_color(),
            Some(Color::Rgb(RgbColor(255, 0, 255)))
        );
    }
}
