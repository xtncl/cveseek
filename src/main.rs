use std::io;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, TableState},
    Frame, Terminal,
};
use serde::Deserialize;

// ── CLI ───────────────────────────────────────────────────────────────────────

struct Cli {
    query: String,
    key: String,
}

impl Cli {
    fn parse() -> Self {
        let args: Vec<String> = std::env::args().collect();
        let mut query = None;
        let mut key = std::env::var("NVD_API_KEY").unwrap_or_default();

        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "-q" | "--query" => {
                    i += 1;
                    query = args.get(i).cloned();
                }
                "-k" | "--key" => {
                    i += 1;
                    if let Some(k) = args.get(i) {
                        key = k.clone();
                    }
                }
                "-h" | "--help" => {
                    eprintln!("Usage: cvesearch -q <search term> [-k <nvd-api-key>]");
                    eprintln!("  -q, --query  Search query (required)");
                    eprintln!("  -k, --key    NVD API key (optional; also $NVD_API_KEY)");
                    std::process::exit(0);
                }
                _ => {}
            }
            i += 1;
        }

        let query = query.unwrap_or_else(|| {
            eprintln!("Error: -q <query> is required.");
            eprintln!("Usage: cvesearch -q \"Windows Server 2016\"");
            std::process::exit(1);
        });

        Cli { query, key }
    }
}

// ── NVD API Types ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct NvdResponse {
    #[serde(rename = "totalResults")]
    total_results: u32,
    vulnerabilities: Vec<VulnEntry>,
}

#[derive(Deserialize, Clone)]
struct VulnEntry {
    cve: CveItem,
}

#[derive(Deserialize, Clone)]
struct CveItem {
    id: String,
    published: String,
    #[serde(rename = "lastModified")]
    last_modified: String,
    #[serde(rename = "vulnStatus")]
    vuln_status: String,
    #[serde(default)]
    descriptions: Vec<Description>,
    #[serde(default)]
    metrics: Metrics,
    #[serde(default)]
    weaknesses: Vec<Weakness>,
    #[serde(default)]
    references: Vec<Reference>,
    #[serde(default)]
    configurations: Vec<Configuration>,
}

#[derive(Deserialize, Clone)]
struct Description {
    lang: String,
    value: String,
}

#[derive(Deserialize, Default, Clone)]
struct Metrics {
    #[serde(rename = "cvssMetricV31", default)]
    v31: Vec<CvssMetric>,
    #[serde(rename = "cvssMetricV30", default)]
    v30: Vec<CvssMetric>,
    #[serde(rename = "cvssMetricV2", default)]
    v2: Vec<CvssMetricV2>,
}

#[derive(Deserialize, Clone)]
struct CvssMetric {
    #[serde(rename = "cvssData")]
    data: CvssData,
}

#[derive(Deserialize, Clone)]
struct CvssData {
    #[serde(rename = "baseScore")]
    base_score: f64,
    #[serde(rename = "baseSeverity")]
    base_severity: String,
    #[serde(rename = "vectorString")]
    vector_string: String,
    #[serde(rename = "attackVector", default)]
    attack_vector: String,
    #[serde(rename = "attackComplexity", default)]
    attack_complexity: String,
    #[serde(rename = "privilegesRequired", default)]
    privileges_required: String,
    #[serde(rename = "userInteraction", default)]
    user_interaction: String,
    #[serde(rename = "confidentialityImpact", default)]
    confidentiality_impact: String,
    #[serde(rename = "integrityImpact", default)]
    integrity_impact: String,
    #[serde(rename = "availabilityImpact", default)]
    availability_impact: String,
}

#[derive(Deserialize, Clone)]
struct CvssMetricV2 {
    #[serde(rename = "cvssData")]
    data: CvssDataV2,
    #[serde(rename = "baseSeverity")]
    base_severity: String,
}

#[derive(Deserialize, Clone)]
struct CvssDataV2 {
    #[serde(rename = "baseScore")]
    base_score: f64,
    #[serde(rename = "vectorString")]
    vector_string: String,
}

#[derive(Deserialize, Clone)]
struct Weakness {
    #[serde(default)]
    description: Vec<Description>,
}

#[derive(Deserialize, Clone)]
struct Reference {
    url: String,
}

#[derive(Deserialize, Clone)]
struct Configuration {
    #[serde(default)]
    nodes: Vec<Node>,
}

#[derive(Deserialize, Clone)]
struct Node {
    #[serde(rename = "cpeMatch", default)]
    cpe_match: Vec<CpeMatch>,
}

#[derive(Deserialize, Clone)]
struct CpeMatch {
    vulnerable: bool,
    criteria: String,
    #[serde(rename = "versionEndIncluding", default)]
    version_end_including: String,
    #[serde(rename = "versionEndExcluding", default)]
    version_end_excluding: String,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

struct SevInfo {
    label: String,
    score: f64,
    vector: String,
    av: String,
    ac: String,
    pr: String,
    ui: String,
    c: String,
    i: String,
    a: String,
}

fn get_severity(cve: &CveItem) -> SevInfo {
    if let Some(m) = cve.metrics.v31.first() {
        return SevInfo {
            label: m.data.base_severity.to_uppercase(),
            score: m.data.base_score,
            vector: m.data.vector_string.clone(),
            av: m.data.attack_vector.clone(),
            ac: m.data.attack_complexity.clone(),
            pr: m.data.privileges_required.clone(),
            ui: m.data.user_interaction.clone(),
            c: m.data.confidentiality_impact.clone(),
            i: m.data.integrity_impact.clone(),
            a: m.data.availability_impact.clone(),
        };
    }
    if let Some(m) = cve.metrics.v30.first() {
        return SevInfo {
            label: m.data.base_severity.to_uppercase(),
            score: m.data.base_score,
            vector: m.data.vector_string.clone(),
            av: m.data.attack_vector.clone(),
            ac: m.data.attack_complexity.clone(),
            pr: m.data.privileges_required.clone(),
            ui: m.data.user_interaction.clone(),
            c: m.data.confidentiality_impact.clone(),
            i: m.data.integrity_impact.clone(),
            a: m.data.availability_impact.clone(),
        };
    }
    if let Some(m) = cve.metrics.v2.first() {
        return SevInfo {
            label: m.base_severity.to_uppercase(),
            score: m.data.base_score,
            vector: m.data.vector_string.clone(),
            av: String::new(),
            ac: String::new(),
            pr: String::new(),
            ui: String::new(),
            c: String::new(),
            i: String::new(),
            a: String::new(),
        };
    }
    SevInfo {
        label: "N/A".into(),
        score: 0.0,
        vector: String::new(),
        av: String::new(),
        ac: String::new(),
        pr: String::new(),
        ui: String::new(),
        c: String::new(),
        i: String::new(),
        a: String::new(),
    }
}

fn severity_color(sev: &str) -> Color {
    match sev {
        "CRITICAL" => Color::Rgb(255, 117, 127), // #ff757f
        "HIGH"     => Color::Rgb(255, 150, 108), // #ff966c
        "MEDIUM"   => Color::Rgb(255, 199, 119), // #ffc777
        "LOW"      => Color::Rgb(195, 232, 141), // #c3e88d
        _          => Color::Rgb(99, 109, 166),  // #636da6
    }
}

fn english_desc(descs: &[Description]) -> &str {
    descs
        .iter()
        .find(|d| d.lang == "en")
        .map(|d| d.value.as_str())
        .unwrap_or("No description available.")
}

fn get_cwes(cve: &CveItem) -> Vec<String> {
    let mut out = vec![];
    let mut seen = std::collections::HashSet::new();
    for w in &cve.weaknesses {
        for d in &w.description {
            if d.lang == "en" && seen.insert(d.value.clone()) {
                out.push(d.value.clone());
            }
        }
    }
    out
}

fn get_products(cve: &CveItem) -> Vec<String> {
    let mut out = vec![];
    let mut seen = std::collections::HashSet::new();
    for cfg in &cve.configurations {
        for node in &cfg.nodes {
            for cpe in &node.cpe_match {
                if !cpe.vulnerable {
                    continue;
                }
                let parts: Vec<&str> = cpe.criteria.split(':').collect();
                if parts.len() < 5 {
                    continue;
                }
                let key = format!("{}:{}", parts[3], parts[4]);
                if !seen.insert(key.clone()) {
                    continue;
                }
                let ver = if !cpe.version_end_excluding.is_empty() {
                    format!(" < {}", cpe.version_end_excluding)
                } else if !cpe.version_end_including.is_empty() {
                    format!(" <= {}", cpe.version_end_including)
                } else if parts.len() > 5 && parts[5] != "*" && parts[5] != "-" {
                    format!(" {}", parts[5])
                } else {
                    String::new()
                };
                out.push(format!("{}{}", key, ver));
            }
        }
    }
    out
}

fn short_date(s: &str) -> &str {
    if s.len() >= 10 {
        &s[..10]
    } else {
        s
    }
}

fn truncate_str(s: &str, max: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= max {
        s.to_string()
    } else if max <= 3 {
        chars[..max].iter().collect()
    } else {
        let mut r: String = chars[..max - 3].iter().collect();
        r.push_str("...");
        r
    }
}

/// Remove all HTML tags, returning plain text.
fn strip_html(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut in_tag = false;
    for ch in html.chars() {
        match (in_tag, ch) {
            (false, '<') => in_tag = true,
            (true, '>') => in_tag = false,
            (false, _) => out.push(ch),
            _ => {}
        }
    }
    out
}

fn apply_html_flags(base: Style, bold: bool, italic: bool, underline: bool) -> Style {
    let mut s = base;
    if bold {
        s = s.add_modifier(Modifier::BOLD);
    }
    if italic {
        s = s.add_modifier(Modifier::ITALIC);
    }
    if underline {
        s = s.add_modifier(Modifier::UNDERLINED);
    }
    s
}

/// Parse HTML into (text_chunk, Style) segments.
/// Recognises <b>, <strong>, <i>, <em>, <u> and their closing variants.
fn parse_html_segments(html: &str, base: Style) -> Vec<(String, Style)> {
    let mut segments: Vec<(String, Style)> = vec![];
    let mut text = String::new();
    let mut tag_buf = String::new();
    let mut in_tag = false;
    let mut bold = false;
    let mut italic = false;
    let mut underline = false;
    let mut current_style = base;

    for ch in html.chars() {
        match (in_tag, ch) {
            (false, '<') => {
                in_tag = true;
                tag_buf.clear();
            }
            (true, '>') => {
                in_tag = false;
                if !text.is_empty() {
                    segments.push((std::mem::take(&mut text), current_style));
                }
                match tag_buf.trim().to_lowercase().as_str() {
                    "b" | "strong" => bold = true,
                    "/b" | "/strong" => bold = false,
                    "i" | "em" => italic = true,
                    "/i" | "/em" => italic = false,
                    "u" => underline = true,
                    "/u" => underline = false,
                    _ => {}
                }
                current_style = apply_html_flags(base, bold, italic, underline);
                tag_buf.clear();
            }
            (true, _) => tag_buf.push(ch),
            (false, _) => text.push(ch),
        }
    }
    if !text.is_empty() {
        segments.push((text, current_style));
    }
    segments
}

/// Word-wrap HTML content, producing ratatui Lines with proper inline styling.
fn html_to_lines(html: &str, width: usize, base: Style) -> Vec<Line<'static>> {
    let segments = parse_html_segments(html, base);

    // Flatten into (word, style) pairs
    let mut word_runs: Vec<(String, Style)> = vec![];
    for (text, style) in segments {
        for word in text.split_whitespace() {
            word_runs.push((word.to_string(), style));
        }
    }

    let mut lines: Vec<Line<'static>> = vec![];
    let mut cur_spans: Vec<Span<'static>> = vec![];
    let mut cur_width: usize = 0;

    for (word, style) in word_runs {
        let word_len = word.chars().count();
        let needed = if cur_width > 0 { 1 + word_len } else { word_len };

        if cur_width > 0 && cur_width + needed > width {
            lines.push(Line::from(std::mem::take(&mut cur_spans)));
            cur_width = 0;
        }

        let s = if cur_width > 0 {
            format!(" {}", word)
        } else {
            word
        };
        cur_width += s.chars().count();
        cur_spans.push(Span::styled(s, style));
    }

    if !cur_spans.is_empty() {
        lines.push(Line::from(cur_spans));
    }
    if lines.is_empty() {
        lines.push(Line::default());
    }
    lines
}

// ── Filter Overlay ────────────────────────────────────────────────────────────

struct FilterOverlay {
    products: Vec<String>,
    checked: Vec<bool>,
    include_no_cpe: bool,
    /// Index within visible_items(), not the full list.
    cursor: usize,
    /// Scroll offset within visible_items().
    list_scroll: usize,
    focus_confirm: bool,
    search_query: String,
    search_mode: bool,
}

impl FilterOverlay {
    fn new(products: Vec<String>) -> Self {
        let n = products.len();
        FilterOverlay {
            products,
            checked: vec![true; n],
            include_no_cpe: true,
            cursor: 0,
            list_scroll: 0,
            focus_confirm: false,
            search_query: String::new(),
            search_mode: false,
        }
    }

    fn item_count(&self) -> usize {
        self.products.len() + 1
    }

    /// Indices into the full item list that match the current search query.
    /// Index products.len() represents the "no CPE" entry.
    fn visible_items(&self) -> Vec<usize> {
        if self.search_query.is_empty() {
            (0..self.item_count()).collect()
        } else {
            let q = self.search_query.to_lowercase();
            let mut v: Vec<usize> = self.products
                .iter()
                .enumerate()
                .filter(|(_, p)| p.to_lowercase().contains(&q))
                .map(|(i, _)| i)
                .collect();
            if "(cves without product info)".contains(&q) {
                v.push(self.products.len());
            }
            v
        }
    }

    fn clamp_cursor(&mut self) {
        let len = self.visible_items().len();
        if len == 0 {
            self.cursor = 0;
        } else if self.cursor >= len {
            self.cursor = len - 1;
        }
    }

    fn move_cursor(&mut self, delta: i64) {
        if self.focus_confirm {
            if delta < 0 {
                self.focus_confirm = false;
                let len = self.visible_items().len();
                self.cursor = len.saturating_sub(1);
            }
            return;
        }
        let vis_len = self.visible_items().len();
        if vis_len == 0 {
            return;
        }
        let max = vis_len as i64 - 1;
        let cur = self.cursor as i64;
        let new = (cur + delta).max(0).min(max);
        if delta > 0 && cur == max {
            self.focus_confirm = true;
        } else {
            self.cursor = new as usize;
        }
    }

    fn toggle_current(&mut self) {
        if self.focus_confirm {
            return;
        }
        let vis = self.visible_items();
        if vis.is_empty() {
            return;
        }
        let real = vis[self.cursor];
        if real < self.products.len() {
            self.checked[real] = !self.checked[real];
        } else {
            self.include_no_cpe = !self.include_no_cpe;
        }
        // Advance to next item automatically.
        if self.cursor + 1 < vis.len() {
            self.cursor += 1;
        }
    }

    fn select_all(&mut self) {
        if self.search_query.is_empty() {
            for c in &mut self.checked {
                *c = true;
            }
            self.include_no_cpe = true;
        } else {
            for &real in &self.visible_items() {
                if real < self.products.len() {
                    self.checked[real] = true;
                } else {
                    self.include_no_cpe = true;
                }
            }
        }
    }

    fn select_none(&mut self) {
        if self.search_query.is_empty() {
            for c in &mut self.checked {
                *c = false;
            }
            self.include_no_cpe = false;
        } else {
            for &real in &self.visible_items() {
                if real < self.products.len() {
                    self.checked[real] = false;
                } else {
                    self.include_no_cpe = false;
                }
            }
        }
    }

    /// Called from the renderer with the actual viewport height so scroll
    /// can be adjusted symmetrically (padding above and below cursor).
    fn adjust_scroll(&mut self, visible_height: usize) {
        const PAD: usize = 3;
        let vis_len = self.visible_items().len();
        if vis_len == 0 || visible_height == 0 {
            self.list_scroll = 0;
            return;
        }
        // Cursor too close to top → scroll up.
        if self.cursor < self.list_scroll + PAD {
            self.list_scroll = self.cursor.saturating_sub(PAD);
        }
        // Cursor too close to bottom → scroll down.
        if visible_height > 0 && self.cursor + PAD + 1 > self.list_scroll + visible_height {
            self.list_scroll = self.cursor + PAD + 1 - visible_height;
        }
        // Never scroll past the end.
        let max_scroll = vis_len.saturating_sub(visible_height);
        self.list_scroll = self.list_scroll.min(max_scroll);
    }

    fn tab_confirm(&mut self) {
        self.focus_confirm = !self.focus_confirm;
    }

    fn search_push(&mut self, c: char) {
        self.search_query.push(c);
        self.clamp_cursor();
    }

    fn search_pop(&mut self) {
        self.search_query.pop();
        self.clamp_cursor();
    }

    fn enter_search(&mut self) {
        self.search_mode = true;
        self.focus_confirm = false;
    }

    fn exit_search(&mut self, clear: bool) {
        self.search_mode = false;
        if clear {
            self.search_query.clear();
        }
        self.clamp_cursor();
    }
}

// ── App State ─────────────────────────────────────────────────────────────────

enum AppState {
    Loading { tick: u8 },
    Error(String),
    Loaded {
        all_cves: Vec<VulnEntry>,
        cves: Vec<VulnEntry>,
        total: u32,
        table_state: TableState,
        preview_scroll: u16,
        filter_overlay: FilterOverlay,
        filter_open: bool,
    },
}

enum FetchMsg {
    Done(Result<(Vec<VulnEntry>, u32), String>),
}

struct App {
    query: String,
    state: AppState,
    rx: mpsc::Receiver<FetchMsg>,
}

impl App {
    fn new(query: String, api_key: String) -> Self {
        let (tx, rx) = mpsc::channel();
        let q = query.clone();
        thread::spawn(move || {
            let result = fetch_cves(&q, &api_key);
            let _ = tx.send(FetchMsg::Done(result));
        });
        App {
            query,
            state: AppState::Loading { tick: 0 },
            rx,
        }
    }

    fn poll_fetch(&mut self) {
        if let Ok(FetchMsg::Done(result)) = self.rx.try_recv() {
            match result {
                Ok((mut all_cves, total)) => {
                    // Newest published date first
                    all_cves.sort_by(|a, b| b.cve.published.cmp(&a.cve.published));
                    let mut ts = TableState::default();
                    if !all_cves.is_empty() {
                        ts.select(Some(0));
                    }
                    let products = collect_all_products(&all_cves);
                    let filter_overlay = FilterOverlay::new(products);
                    let cves = all_cves.clone();
                    self.state = AppState::Loaded {
                        all_cves,
                        cves,
                        total,
                        table_state: ts,
                        preview_scroll: 0,
                        filter_overlay,
                        filter_open: false,
                    };
                }
                Err(e) => {
                    self.state = AppState::Error(e);
                }
            }
        }
    }

    fn tick(&mut self) {
        if let AppState::Loading { tick } = &mut self.state {
            *tick = tick.wrapping_add(1);
        }
    }

    fn move_cursor(&mut self, delta: i64) {
        if let AppState::Loaded {
            cves,
            table_state,
            preview_scroll,
            ..
        } = &mut self.state
        {
            let len = cves.len();
            if len == 0 {
                return;
            }
            let cur = table_state.selected().unwrap_or(0) as i64;
            let new_idx = (cur + delta).max(0).min((len - 1) as i64) as usize;
            table_state.select(Some(new_idx));
            *preview_scroll = 0;
        }
    }

    fn scroll_preview(&mut self, delta: i16) {
        if let AppState::Loaded { preview_scroll, .. } = &mut self.state {
            let new_val = (*preview_scroll as i32 + delta as i32).max(0) as u16;
            *preview_scroll = new_val;
        }
    }

    fn goto_first(&mut self) {
        if let AppState::Loaded {
            table_state,
            preview_scroll,
            ..
        } = &mut self.state
        {
            table_state.select(Some(0));
            *preview_scroll = 0;
        }
    }

    fn goto_last(&mut self) {
        if let AppState::Loaded {
            cves,
            table_state,
            preview_scroll,
            ..
        } = &mut self.state
        {
            if !cves.is_empty() {
                table_state.select(Some(cves.len() - 1));
                *preview_scroll = 0;
            }
        }
    }

    fn toggle_filter(&mut self) {
        if let AppState::Loaded { filter_open, .. } = &mut self.state {
            *filter_open = !*filter_open;
        }
    }

    fn filter_move_cursor(&mut self, delta: i64) {
        if let AppState::Loaded { filter_open, filter_overlay, .. } = &mut self.state {
            if *filter_open {
                filter_overlay.move_cursor(delta);
            }
        }
    }

    fn filter_toggle(&mut self) {
        if let AppState::Loaded { filter_open, filter_overlay, .. } = &mut self.state {
            if *filter_open {
                filter_overlay.toggle_current();
            }
        }
    }

    fn filter_select_all(&mut self) {
        if let AppState::Loaded { filter_open, filter_overlay, .. } = &mut self.state {
            if *filter_open {
                filter_overlay.select_all();
            }
        }
    }

    fn filter_select_none(&mut self) {
        if let AppState::Loaded { filter_open, filter_overlay, .. } = &mut self.state {
            if *filter_open {
                filter_overlay.select_none();
            }
        }
    }

    fn filter_tab(&mut self) {
        if let AppState::Loaded { filter_open, filter_overlay, .. } = &mut self.state {
            if *filter_open {
                filter_overlay.tab_confirm();
            }
        }
    }

    fn filter_search_enter(&mut self) {
        if let AppState::Loaded { filter_open, filter_overlay, .. } = &mut self.state {
            if *filter_open {
                filter_overlay.enter_search();
            }
        }
    }

    fn filter_search_exit(&mut self, clear: bool) {
        if let AppState::Loaded { filter_open, filter_overlay, .. } = &mut self.state {
            if *filter_open {
                filter_overlay.exit_search(clear);
            }
        }
    }

    fn filter_search_push(&mut self, c: char) {
        if let AppState::Loaded { filter_open, filter_overlay, .. } = &mut self.state {
            if *filter_open {
                filter_overlay.search_push(c);
            }
        }
    }

    fn filter_search_pop(&mut self) {
        if let AppState::Loaded { filter_open, filter_overlay, .. } = &mut self.state {
            if *filter_open {
                filter_overlay.search_pop();
            }
        }
    }

    fn apply_filter(&mut self) {
        if let AppState::Loaded {
            all_cves,
            cves,
            filter_overlay,
            filter_open,
            table_state,
            preview_scroll,
            ..
        } = &mut self.state
        {
            let selected: std::collections::HashSet<String> = filter_overlay
                .products
                .iter()
                .enumerate()
                .filter(|(i, _)| filter_overlay.checked[*i])
                .map(|(_, p)| p.clone())
                .collect();
            let include_no_cpe = filter_overlay.include_no_cpe;
            let all_checked = filter_overlay.checked.iter().all(|&c| c) && include_no_cpe;

            if all_checked {
                *cves = all_cves.clone();
            } else {
                *cves = all_cves
                    .iter()
                    .filter(|entry| {
                        let products = get_products(&entry.cve);
                        if products.is_empty() {
                            include_no_cpe
                        } else {
                            products.iter().any(|p| {
                                let base = p.splitn(2, ' ').next().unwrap_or(p);
                                selected.contains(base)
                            })
                        }
                    })
                    .cloned()
                    .collect();
            }

            *filter_open = false;
            let mut ts = TableState::default();
            if !cves.is_empty() {
                ts.select(Some(0));
            }
            *table_state = ts;
            *preview_scroll = 0;
        }
    }
}

// ── Fetch + Helpers ───────────────────────────────────────────────────────────

fn collect_all_products(all_cves: &[VulnEntry]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = vec![];
    for entry in all_cves {
        for p in get_products(&entry.cve) {
            let base = p.splitn(2, ' ').next().unwrap_or(&p).to_string();
            if seen.insert(base.clone()) {
                out.push(base);
            }
        }
    }
    out.sort();
    out
}

fn fetch_cves(query: &str, api_key: &str) -> Result<(Vec<VulnEntry>, u32), String> {
    let encoded = urlencoding::encode(query);
    let url = format!(
        "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={}",
        encoded
    );
    let mut req = ureq::get(&url).set("User-Agent", "cvesearch/1.0");
    if !api_key.is_empty() {
        req = req.set("apiKey", api_key);
    }
    let resp = req
        .call()
        .map_err(|e| format!("Request failed: {}", e))?;

    let body: NvdResponse = resp
        .into_json()
        .map_err(|e| format!("Parse error: {}", e))?;

    Ok((body.vulnerabilities, body.total_results))
}

// ── Rendering ─────────────────────────────────────────────────────────────────

// TokyoNight Moon palette
const C_BORDER: Color = Color::Rgb(68, 74, 115);    // #444a73
const C_HEADER: Color = Color::Rgb(134, 225, 252);  // #86e1fc  cyan
const C_DIM: Color = Color::Rgb(99, 109, 166);      // #636da6  comments
const C_DEFAULT: Color = Color::Rgb(200, 211, 245); // #c8d3f5  foreground
const C_BLUE: Color = Color::Rgb(130, 170, 255);    // #82aaff
const C_YELLOW: Color = Color::Rgb(255, 199, 119);  // #ffc777
const C_SEL_BG: Color = Color::Rgb(45, 63, 118);   // #2d3f76  selection

fn ui(f: &mut Frame, app: &mut App) {
    let area = f.size();

    // Vertical split: header (1 line) + body
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(0)])
        .split(area);

    // ── Header bar ──────────────────────────────────────────────────────────
    let header_text = match &app.state {
        AppState::Loading { .. } => Line::from(vec![
            Span::styled("  cvesearch ", Style::default().fg(C_BLUE).add_modifier(Modifier::BOLD)),
            Span::styled("query: ", Style::default().fg(C_HEADER)),
            Span::styled(app.query.as_str(), Style::default().fg(C_DEFAULT)),
            Span::styled("  fetching...", Style::default().fg(C_DIM)),
        ]),
        AppState::Error(_) => Line::from(vec![
            Span::styled("  cvesearch ", Style::default().fg(C_BLUE).add_modifier(Modifier::BOLD)),
            Span::styled("  error  ", Style::default().fg(Color::Rgb(251, 73, 52))),
            Span::styled("  [q] quit", Style::default().fg(C_DIM)),
        ]),
        AppState::Loaded { cves, total, .. } => Line::from(vec![
            Span::styled("  cvesearch ", Style::default().fg(C_BLUE).add_modifier(Modifier::BOLD)),
            Span::styled("query: ", Style::default().fg(C_HEADER)),
            Span::styled(app.query.as_str(), Style::default().fg(C_DEFAULT)),
            Span::styled(
                format!("  {}/{} results", cves.len(), total),
                Style::default().fg(C_HEADER),
            ),
            Span::styled(
                "  [↑↓/jk] nav  [PgUp/PgDn] page  [g/G] top/bot  [^d/^u] scroll preview  [f] filter  [q] quit",
                Style::default().fg(C_DIM),
            ),
        ]),
    };
    f.render_widget(Paragraph::new(header_text), layout[0]);

    // ── Body ────────────────────────────────────────────────────────────────
    match &mut app.state {
        AppState::Loading { tick } => {
            let frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
            let frame = frames[(*tick as usize / 3) % frames.len()];
            let text = format!(
                "\n\n   {} Querying NIST NVD for \"{}\"...\n\n   This may take a moment.",
                frame, app.query
            );
            f.render_widget(
                Paragraph::new(text).style(Style::default().fg(C_BLUE)),
                layout[1],
            );
        }
        AppState::Error(e) => {
            let msg = format!("\n\n   Error: {}\n\n   Press q to quit.", e);
            f.render_widget(
                Paragraph::new(msg).style(Style::default().fg(Color::Rgb(251, 73, 52))),
                layout[1],
            );
        }
        AppState::Loaded {
            cves,
            table_state,
            preview_scroll,
            filter_open,
            filter_overlay,
            ..
        } => {
            if cves.is_empty() {
                f.render_widget(
                    Paragraph::new(format!(
                        "\n\n   No CVEs found for \"{}\"\n\n   Press q to quit.",
                        app.query
                    ))
                    .style(Style::default().fg(C_DIM)),
                    layout[1],
                );
                if *filter_open {
                    render_filter_overlay(f, area, filter_overlay);
                }
                return;
            }

            let body_chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
                .split(layout[1]);

            render_list(f, body_chunks[0], cves, table_state);
            render_preview(f, body_chunks[1], cves, table_state.selected(), *preview_scroll);

            if *filter_open {
                render_filter_overlay(f, area, filter_overlay);
            }
        }
    }
}

fn render_list(
    f: &mut Frame,
    area: ratatui::layout::Rect,
    cves: &[VulnEntry],
    table_state: &mut TableState,
) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(C_BORDER))
        .title(Span::styled(
            " CVE List ",
            Style::default().fg(C_HEADER).add_modifier(Modifier::BOLD),
        ));

    let header_cells = ["CVE ID", "SEVERITY", "DESCRIPTION"]
        .iter()
        .map(|h| {
            Cell::from(*h).style(
                Style::default()
                    .fg(C_HEADER)
                    .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
            )
        });
    let header = Row::new(header_cells).height(1);

    let rows: Vec<Row> = cves
        .iter()
        .map(|entry| {
            let cve = &entry.cve;
            let sev = get_severity(cve);
            let desc = english_desc(&cve.descriptions);
            let sev_color = severity_color(&sev.label);

            let id_cell = Cell::from(cve.id.clone()).style(Style::default().fg(C_BLUE));
            let sev_cell = Cell::from(sev.label).style(
                Style::default()
                    .fg(sev_color)
                    .add_modifier(Modifier::BOLD),
            );
            let desc_cell =
                Cell::from(truncate_str(&strip_html(desc), 120)).style(Style::default().fg(C_DEFAULT));

            Row::new(vec![id_cell, sev_cell, desc_cell]).height(1)
        })
        .collect();

    let widths = [
        Constraint::Length(20),
        Constraint::Length(10),
        Constraint::Fill(1),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(block)
        .highlight_style(
            Style::default()
                .bg(C_SEL_BG)
                .fg(C_YELLOW)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");

    f.render_stateful_widget(table, area, table_state);
}

fn render_preview(
    f: &mut Frame,
    area: ratatui::layout::Rect,
    cves: &[VulnEntry],
    selected: Option<usize>,
    scroll: u16,
) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(C_BORDER))
        .title(Span::styled(
            " Preview ",
            Style::default().fg(C_HEADER).add_modifier(Modifier::BOLD),
        ));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let Some(idx) = selected else {
        return;
    };
    if idx >= cves.len() {
        return;
    }

    let cve = &cves[idx].cve;
    let sev = get_severity(cve);
    let desc = english_desc(&cve.descriptions);
    let cwes = get_cwes(cve);
    let products = get_products(cve);
    let sev_color = severity_color(&sev.label);

    let w = inner.width as usize;
    let sep: String = "─".repeat(w.saturating_sub(1));

    let mut lines: Vec<Line> = vec![];

    // Title
    lines.push(Line::from(Span::styled(
        cve.id.as_str(),
        Style::default()
            .fg(C_DEFAULT)
            .add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::default());

    // Severity + score
    lines.push(Line::from(vec![
        Span::styled("Severity  ", Style::default().fg(C_HEADER)),
        Span::styled(
            format!(" {} ", sev.label),
            Style::default()
                .fg(sev_color)
                .add_modifier(Modifier::BOLD | Modifier::REVERSED),
        ),
        Span::styled(
            format!("  {:.1}", sev.score),
            Style::default().fg(C_DEFAULT),
        ),
    ]));

    // CVSS details (if available)
    if !sev.av.is_empty() {
        lines.push(Line::from(vec![
            Span::styled("AV:", Style::default().fg(C_HEADER)),
            Span::styled(
                format!(" {:<12}", abbrev(&sev.av)),
                Style::default().fg(C_DEFAULT),
            ),
            Span::styled("AC:", Style::default().fg(C_HEADER)),
            Span::styled(
                format!(" {:<8}", abbrev(&sev.ac)),
                Style::default().fg(C_DEFAULT),
            ),
            Span::styled("PR:", Style::default().fg(C_HEADER)),
            Span::styled(
                format!(" {:<8}", abbrev(&sev.pr)),
                Style::default().fg(C_DEFAULT),
            ),
            Span::styled("UI:", Style::default().fg(C_HEADER)),
            Span::styled(
                format!(" {}", abbrev(&sev.ui)),
                Style::default().fg(C_DEFAULT),
            ),
        ]));
        lines.push(Line::from(vec![
            Span::styled("C:", Style::default().fg(C_HEADER)),
            Span::styled(
                format!(" {:<13}", abbrev(&sev.c)),
                Style::default().fg(C_DEFAULT),
            ),
            Span::styled("I:", Style::default().fg(C_HEADER)),
            Span::styled(
                format!(" {:<13}", abbrev(&sev.i)),
                Style::default().fg(C_DEFAULT),
            ),
            Span::styled("A:", Style::default().fg(C_HEADER)),
            Span::styled(
                format!(" {}", abbrev(&sev.a)),
                Style::default().fg(C_DEFAULT),
            ),
        ]));
    }

    // Status + dates
    lines.push(Line::from(vec![
        Span::styled("Status    ", Style::default().fg(C_HEADER)),
        Span::styled(cve.vuln_status.as_str(), Style::default().fg(C_DIM)),
    ]));
    lines.push(Line::from(vec![
        Span::styled("Published ", Style::default().fg(C_HEADER)),
        Span::styled(
            short_date(&cve.published),
            Style::default().fg(C_DEFAULT),
        ),
        Span::styled("   Modified ", Style::default().fg(C_HEADER)),
        Span::styled(
            short_date(&cve.last_modified),
            Style::default().fg(C_DEFAULT),
        ),
    ]));

    // Vector string
    if !sev.vector.is_empty() {
        lines.push(Line::from(vec![
            Span::styled("Vector    ", Style::default().fg(C_HEADER)),
            Span::styled(sev.vector.as_str(), Style::default().fg(C_DIM)),
        ]));
    }

    lines.push(Line::default());

    // Description section
    lines.push(Line::from(Span::styled(
        "Description",
        Style::default()
            .fg(C_HEADER)
            .add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::from(Span::styled(
        sep.as_str(),
        Style::default().fg(C_BORDER),
    )));
    let wrap_width = w.saturating_sub(2);
    for html_line in html_to_lines(desc, wrap_width, Style::default().fg(C_DEFAULT)) {
        lines.push(html_line);
    }

    // Weaknesses
    if !cwes.is_empty() {
        lines.push(Line::default());
        lines.push(Line::from(Span::styled(
            "Weaknesses (CWE)",
            Style::default()
                .fg(C_HEADER)
                .add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(Span::styled(
            sep.as_str(),
            Style::default().fg(C_BORDER),
        )));
        for cwe in &cwes {
            lines.push(Line::from(vec![
                Span::styled("  • ", Style::default().fg(C_DIM)),
                Span::styled(cwe.as_str(), Style::default().fg(C_YELLOW)),
            ]));
        }
    }

    // Affected products
    if !products.is_empty() {
        lines.push(Line::default());
        lines.push(Line::from(Span::styled(
            "Affected Products",
            Style::default()
                .fg(C_HEADER)
                .add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(Span::styled(
            sep.as_str(),
            Style::default().fg(C_BORDER),
        )));
        let max_p = 10usize;
        for (i, p) in products.iter().enumerate() {
            if i >= max_p {
                lines.push(Line::from(Span::styled(
                    format!("  ... and {} more", products.len() - max_p),
                    Style::default().fg(C_DIM),
                )));
                break;
            }
            lines.push(Line::from(vec![
                Span::styled("  • ", Style::default().fg(C_DIM)),
                Span::styled(p.as_str(), Style::default().fg(C_DEFAULT)),
            ]));
        }
    }

    // References
    if !cve.references.is_empty() {
        lines.push(Line::default());
        lines.push(Line::from(Span::styled(
            "References",
            Style::default()
                .fg(C_HEADER)
                .add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(Span::styled(
            sep.as_str(),
            Style::default().fg(C_BORDER),
        )));
        let max_r = 8usize;
        for (i, r) in cve.references.iter().enumerate() {
            if i >= max_r {
                lines.push(Line::from(Span::styled(
                    format!("  ... and {} more", cve.references.len() - max_r),
                    Style::default().fg(C_DIM),
                )));
                break;
            }
            lines.push(Line::from(Span::styled(
                format!("  {}", truncate_str(&r.url, w.saturating_sub(4))),
                Style::default().fg(C_BLUE),
            )));
        }
    }

    let paragraph = Paragraph::new(lines).scroll((scroll, 0));
    f.render_widget(paragraph, inner);
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

fn render_filter_overlay(f: &mut Frame, area: Rect, overlay: &mut FilterOverlay) {

    let popup_area = centered_rect(72, 78, area);
    f.render_widget(Clear, popup_area);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(C_HEADER))
        .title(Span::styled(
            " Filter by Product ",
            Style::default().fg(C_HEADER).add_modifier(Modifier::BOLD),
        ));

    let inner = block.inner(popup_area);
    f.render_widget(block, popup_area);

    if inner.height < 6 || inner.width < 20 {
        return;
    }

    // Layout: hint | search | separator | list | separator | confirm
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // hints
            Constraint::Length(1), // search bar
            Constraint::Length(1), // separator
            Constraint::Min(1),    // list
            Constraint::Length(1), // separator
            Constraint::Length(1), // confirm
        ])
        .split(inner);

    // Hint line
    let hint = Line::from(vec![
        Span::styled("[a]", Style::default().fg(C_YELLOW)),
        Span::styled(" all  ", Style::default().fg(C_DIM)),
        Span::styled("[n]", Style::default().fg(C_YELLOW)),
        Span::styled(" none  ", Style::default().fg(C_DIM)),
        Span::styled("[Space]", Style::default().fg(C_YELLOW)),
        Span::styled(" toggle  ", Style::default().fg(C_DIM)),
        Span::styled("[Tab]", Style::default().fg(C_YELLOW)),
        Span::styled(" confirm  ", Style::default().fg(C_DIM)),
        Span::styled("[Esc]", Style::default().fg(C_YELLOW)),
        Span::styled(" cancel", Style::default().fg(C_DIM)),
    ]);
    f.render_widget(Paragraph::new(hint), chunks[0]);

    // Search bar
    let search_line = if overlay.search_mode {
        Line::from(vec![
            Span::styled("/ ", Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
            Span::styled(overlay.search_query.as_str(), Style::default().fg(C_DEFAULT)),
            Span::styled("█", Style::default().fg(C_DIM)),
        ])
    } else if !overlay.search_query.is_empty() {
        Line::from(vec![
            Span::styled("/ ", Style::default().fg(C_DIM)),
            Span::styled(overlay.search_query.as_str(), Style::default().fg(C_YELLOW)),
            Span::styled("  [/] edit  [Esc in search] clear", Style::default().fg(C_DIM)),
        ])
    } else {
        Line::from(Span::styled(
            "[/] search",
            Style::default().fg(C_DIM),
        ))
    };
    f.render_widget(Paragraph::new(search_line), chunks[1]);

    let sep_str = "─".repeat(inner.width as usize);
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            sep_str.clone(),
            Style::default().fg(C_BORDER),
        ))),
        chunks[2],
    );

    // Scrollable product list
    let visible = chunks[3].height as usize;
    overlay.adjust_scroll(visible);
    let vis_items = overlay.visible_items();
    let total_vis = vis_items.len();
    let scroll_offset = if overlay.focus_confirm { 0 } else { overlay.list_scroll };

    let mut lines: Vec<Line> = vec![];
    let end = (scroll_offset + visible).min(total_vis);
    for vis_idx in scroll_offset..end {
        let is_cursor = !overlay.focus_confirm && vis_idx == overlay.cursor;
        let real = vis_items[vis_idx];
        let (checked, label) = if real < overlay.products.len() {
            (overlay.checked[real], overlay.products[real].as_str())
        } else {
            (overlay.include_no_cpe, "(CVEs without product info)")
        };

        let prefix = if is_cursor { "▶ " } else { "  " };
        let checkbox = if checked { "[x] " } else { "[ ] " };

        let row_style = if is_cursor {
            Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(C_DEFAULT)
        };
        let check_style = if checked {
            Style::default().fg(Color::Green)
        } else {
            Style::default().fg(C_DIM)
        };

        // Highlight matching part of label when searching
        if !overlay.search_query.is_empty() && !is_cursor {
            let q = overlay.search_query.to_lowercase();
            let label_lower = label.to_lowercase();
            if let Some(pos) = label_lower.find(&q) {
                let max_w = chunks[3].width.saturating_sub(6) as usize;
                let before = truncate_str(&label[..pos], max_w);
                let matched = &label[pos..pos + q.len()];
                let after_start = pos + q.len();
                let after = if after_start < label.len() {
                    truncate_str(&label[after_start..], max_w.saturating_sub(before.len() + matched.len()))
                } else {
                    String::new()
                };
                lines.push(Line::from(vec![
                    Span::styled(prefix.to_string(), row_style),
                    Span::styled(checkbox.to_string(), check_style),
                    Span::styled(before, Style::default().fg(C_DEFAULT)),
                    Span::styled(matched.to_string(), Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
                    Span::styled(after, Style::default().fg(C_DEFAULT)),
                ]));
                continue;
            }
        }

        lines.push(Line::from(vec![
            Span::styled(prefix.to_string(), row_style),
            Span::styled(checkbox.to_string(), check_style),
            Span::styled(
                truncate_str(label, chunks[3].width.saturating_sub(6) as usize),
                row_style,
            ),
        ]));
    }
    f.render_widget(Paragraph::new(lines), chunks[3]);

    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            sep_str,
            Style::default().fg(C_BORDER),
        ))),
        chunks[4],
    );

    // Confirm button (right-aligned)
    let (confirm_label, confirm_style) = if overlay.focus_confirm {
        (
            "[ Confirm ]",
            Style::default()
                .fg(Color::Black)
                .bg(C_HEADER)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        ("  Confirm  ", Style::default().fg(C_HEADER))
    };
    let pad = (inner.width as usize).saturating_sub(confirm_label.len());
    let confirm_line = Line::from(vec![
        Span::styled(" ".repeat(pad), Style::default()),
        Span::styled(confirm_label, confirm_style),
    ]);
    f.render_widget(Paragraph::new(confirm_line), chunks[5]);
}

fn abbrev(s: &str) -> &str {
    match s {
        "NETWORK" => "NET",
        "ADJACENT" => "ADJ",
        "LOCAL" => "LOCAL",
        "PHYSICAL" => "PHYS",
        "HIGH" => "HIGH",
        "LOW" => "LOW",
        "MEDIUM" => "MED",
        "NONE" => "NONE",
        "REQUIRED" => "REQ",
        "CHANGED" => "CHGD",
        "UNCHANGED" => "UNCHG",
        "PARTIAL" => "PART",
        "COMPLETE" => "COMP",
        other => other,
    }
}

// ── Main ──────────────────────────────────────────────────────────────────────

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(cli.query, cli.key);

    let tick_rate = Duration::from_millis(50);

    loop {
        app.poll_fetch();
        app.tick();

        terminal.draw(|f| ui(f, &mut app))?;

        if event::poll(tick_rate)? {
            if let Event::Key(key) = event::read()? {
                let filter_open =
                    matches!(&app.state, AppState::Loaded { filter_open: true, .. });
                let search_mode = if let AppState::Loaded { filter_open: true, filter_overlay, .. } =
                    &app.state
                {
                    filter_overlay.search_mode
                } else {
                    false
                };

                if filter_open && search_mode {
                    match key.code {
                        KeyCode::Esc => app.filter_search_exit(true),
                        KeyCode::Enter => app.filter_search_exit(false),
                        KeyCode::Backspace => app.filter_search_pop(),
                        KeyCode::Up => app.filter_move_cursor(-1),
                        KeyCode::Down => app.filter_move_cursor(1),
                        KeyCode::Char(c) => app.filter_search_push(c),
                        _ => {}
                    }
                } else if filter_open {
                    match (key.code, key.modifiers) {
                        (KeyCode::Char('q'), _)
                        | (KeyCode::Char('c'), KeyModifiers::CONTROL) => break,
                        (KeyCode::Esc, _) | (KeyCode::Char('f'), _) => app.toggle_filter(),
                        (KeyCode::Char('/'), _) => app.filter_search_enter(),
                        (KeyCode::Up, _) | (KeyCode::Char('k'), _) => {
                            app.filter_move_cursor(-1)
                        }
                        (KeyCode::Down, _) | (KeyCode::Char('j'), _) => {
                            app.filter_move_cursor(1)
                        }
                        (KeyCode::Char(' '), _) => app.filter_toggle(),
                        (KeyCode::Char('a'), _) => app.filter_select_all(),
                        (KeyCode::Char('n'), _) => app.filter_select_none(),
                        (KeyCode::Tab, _) => app.filter_tab(),
                        (KeyCode::Enter, _) => app.apply_filter(),
                        _ => {}
                    }
                } else {
                    match (key.code, key.modifiers) {
                        (KeyCode::Char('q'), _)
                        | (KeyCode::Char('c'), KeyModifiers::CONTROL) => break,
                        (KeyCode::Up, _) | (KeyCode::Char('k'), _) => app.move_cursor(-1),
                        (KeyCode::Down, _) | (KeyCode::Char('j'), _) => app.move_cursor(1),
                        (KeyCode::PageUp, _) => app.move_cursor(-15),
                        (KeyCode::PageDown, _) => app.move_cursor(15),
                        (KeyCode::Char('g'), _) => app.goto_first(),
                        (KeyCode::Char('G'), _) => app.goto_last(),
                        (KeyCode::Char('d'), KeyModifiers::CONTROL) => app.scroll_preview(8),
                        (KeyCode::Char('u'), KeyModifiers::CONTROL) => app.scroll_preview(-8),
                        (KeyCode::Char('f'), _) => app.toggle_filter(),
                        _ => {}
                    }
                }
            }
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    Ok(())
}
