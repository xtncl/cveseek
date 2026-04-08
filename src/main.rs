use std::io;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, KeyModifiers},
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
    query: Option<String>,
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
                    eprintln!("cveseek {} — NVD CVE search TUI", env!("CARGO_PKG_VERSION"));
                    eprintln!("by Christian Lepuschitz (@xtncl) — https://github.com/xtncl/cveseek");
                    eprintln!();
                    eprintln!("Usage: cveseek [-q <query>] [-k <api-key>]");
                    eprintln!("  -q, --query  Keyword search query (interactive if omitted)");
                    eprintln!("  -k, --key    NVD API key (also $NVD_API_KEY)");
                    eprintln!();
                    eprintln!("Press [?] inside the app for more information.");
                    std::process::exit(0);
                }
                _ => {}
            }
            i += 1;
        }

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

// ── CPE types (for product search) ───────────────────────────────────────────

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
enum CpeType { Os, Hardware, Application, Unknown }

impl CpeType {
    fn from_part(part: &str) -> Self {
        match part { "o" => Self::Os, "h" => Self::Hardware, "a" => Self::Application, _ => Self::Unknown }
    }
    fn badge(&self) -> &'static str {
        match self { Self::Os => "[OS] ", Self::Hardware => "[HW] ", Self::Application => "[App]", Self::Unknown => "[?]  " }
    }
    fn badge_color(&self) -> Color {
        match self {
            Self::Os          => Color::Rgb(195, 232, 141),
            Self::Hardware    => Color::Rgb(130, 170, 255),
            Self::Application => Color::Rgb(255, 199, 119),
            Self::Unknown     => Color::Rgb(99, 109, 166),
        }
    }
}

#[derive(Deserialize)]
struct NvdCpeResponse {
    products: Vec<NvdCpeProduct>,
}

#[derive(Deserialize)]
struct NvdCpeProduct { cpe: NvdCpe }

#[derive(Deserialize)]
struct NvdCpe {
    #[serde(rename = "cpeName")]
    cpe_name: String,
    #[serde(default)]
    titles: Vec<CpeApiTitle>,
    #[serde(default)]
    deprecated: bool,
}

#[derive(Deserialize)]
struct CpeApiTitle { title: String, lang: String }

#[derive(Clone)]
struct CpeEntry {
    cpe_name: String,
    vendor: String,
    product: String,
    title: String,
    kind: CpeType,
}

impl CpeEntry {
    fn from_api(raw: &NvdCpe) -> Self {
        let parts: Vec<&str> = raw.cpe_name.split(':').collect();
        let kind    = CpeType::from_part(parts.get(2).copied().unwrap_or(""));
        let vendor  = parts.get(3).copied().unwrap_or("").to_string();
        let product = parts.get(4).copied().unwrap_or("").to_string();
        let title   = raw.titles.iter()
            .find(|t| t.lang == "en")
            .map(|t| t.title.clone())
            .unwrap_or_else(|| format!("{}: {}", vendor, product));
        CpeEntry { cpe_name: raw.cpe_name.clone(), vendor, product, title, kind }
    }

    fn display_label(&self) -> String {
        if self.title.is_empty() { format!("{}: {}", self.vendor, self.product) }
        else { self.title.clone() }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum SearchMode { Keyword, Cpe }

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
    kinds: Vec<CpeType>,
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
    fn new_with_kinds(products: Vec<String>, kinds: Vec<CpeType>) -> Self {
        let n = products.len();
        FilterOverlay {
            products,
            kinds,
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

// ── CPE Overlay (for product-first search) ────────────────────────────────────

struct CpeOverlay {
    entries: Vec<CpeEntry>,
    checked: Vec<bool>,
    cursor: usize,
    list_scroll: usize,
    search_query: String,
    search_mode: bool,
}

impl CpeOverlay {
    fn new(mut entries: Vec<CpeEntry>, query: &str) -> Self {
        let q = query.to_lowercase();
        entries.sort_by(|a, b| {
            cpe_relevance_tier(a, &q).cmp(&cpe_relevance_tier(b, &q))
                .then(a.kind.cmp(&b.kind))
                .then(a.vendor.to_lowercase().cmp(&b.vendor.to_lowercase()))
                .then(a.product.to_lowercase().cmp(&b.product.to_lowercase()))
        });
        let n = entries.len();
        CpeOverlay { entries, checked: vec![false; n], cursor: 0, list_scroll: 0,
            search_query: String::new(), search_mode: false }
    }

    fn select_all(&mut self) {
        if self.search_query.is_empty() {
            for c in &mut self.checked { *c = true; }
        } else {
            for &i in &self.visible_items() { self.checked[i] = true; }
        }
    }

    fn select_none(&mut self) {
        if self.search_query.is_empty() {
            for c in &mut self.checked { *c = false; }
        } else {
            for &i in &self.visible_items() { self.checked[i] = false; }
        }
    }

    fn visible_items(&self) -> Vec<usize> {
        if self.search_query.is_empty() {
            (0..self.entries.len()).collect()
        } else {
            let q = self.search_query.to_lowercase();
            self.entries.iter().enumerate()
                .filter(|(_, e)| {
                    e.display_label().to_lowercase().contains(&q)
                        || e.vendor.to_lowercase().contains(&q)
                        || e.product.to_lowercase().contains(&q)
                })
                .map(|(i, _)| i)
                .collect()
        }
    }

    fn clamp_cursor(&mut self) {
        let len = self.visible_items().len();
        if len == 0 { self.cursor = 0; }
        else if self.cursor >= len { self.cursor = len - 1; }
    }

    fn move_cursor(&mut self, delta: i64) {
        let vis_len = self.visible_items().len();
        if vis_len == 0 { return; }
        let new = (self.cursor as i64 + delta).max(0).min(vis_len as i64 - 1);
        self.cursor = new as usize;
    }

    fn toggle_current(&mut self) {
        let vis = self.visible_items();
        if vis.is_empty() { return; }
        let real = vis[self.cursor];
        self.checked[real] = !self.checked[real];
        if self.cursor + 1 < vis.len() { self.cursor += 1; }
    }

    fn adjust_scroll(&mut self, visible_height: usize) {
        const PAD: usize = 3;
        let vis_len = self.visible_items().len();
        if vis_len == 0 || visible_height == 0 { self.list_scroll = 0; return; }
        if self.cursor < self.list_scroll + PAD {
            self.list_scroll = self.cursor.saturating_sub(PAD);
        }
        if self.cursor + PAD + 1 > self.list_scroll + visible_height {
            self.list_scroll = self.cursor + PAD + 1 - visible_height;
        }
        self.list_scroll = self.list_scroll.min(vis_len.saturating_sub(visible_height));
    }

    fn selected_cpe_names(&self) -> Vec<String> {
        self.entries.iter().enumerate()
            .filter(|(i, _)| self.checked[*i])
            .map(|(_, e)| e.cpe_name.clone())
            .collect()
    }

    fn has_selection(&self) -> bool { self.checked.iter().any(|&c| c) }

    fn search_push(&mut self, c: char) { self.search_query.push(c); self.clamp_cursor(); }
    fn search_pop(&mut self) { self.search_query.pop(); self.clamp_cursor(); }
    fn enter_search(&mut self) { self.search_mode = true; }
    fn exit_search(&mut self, clear: bool) {
        self.search_mode = false;
        if clear { self.search_query.clear(); }
        self.clamp_cursor();
    }
}

// ── App State ─────────────────────────────────────────────────────────────────

#[derive(PartialEq, Clone, Copy)]
enum PaneFocus { List, Preview }

enum AppState {
    QueryInput { input: String, mode: SearchMode },
    Loading { tick: u8 },
    CpeLoading { query: String, tick: u8 },
    CpeResults { query: String, overlay: CpeOverlay, status_line: String },
    Error(String),
    Loaded {
        all_cves: Vec<VulnEntry>,
        cves: Vec<VulnEntry>,
        total: u32,
        table_state: TableState,
        preview_scroll: u16,
        filter_overlay: FilterOverlay,
        filter_open: bool,
        focus: PaneFocus,
        preview_open: bool,
        search_input: Option<String>,
    },
}

enum FetchMsg {
    Done(Result<(Vec<VulnEntry>, u32), String>),
    CpeDone(Result<Vec<CpeEntry>, String>),
}

struct App {
    query: String,
    api_key: String,
    state: AppState,
    rx: Option<mpsc::Receiver<FetchMsg>>,
    show_about: bool,
}

impl App {
    /// Start with a known query (e.g. from -q flag).
    fn new(query: String, api_key: String) -> Self {
        let (tx, rx) = mpsc::channel();
        let q = query.clone();
        let k = api_key.clone();
        thread::spawn(move || {
            let result = fetch_cves(&q, &k);
            let _ = tx.send(FetchMsg::Done(result));
        });
        App {
            query,
            api_key,
            state: AppState::Loading { tick: 0 },
            rx: Some(rx),
            show_about: false,
        }
    }

    /// Start interactively: show the query input screen first.
    fn new_interactive(api_key: String) -> Self {
        App {
            query: String::new(),
            api_key,
            state: AppState::QueryInput { input: String::new(), mode: SearchMode::Keyword },
            rx: None,
            show_about: false,
        }
    }

    /// Fire a CPE keyword search from the interactive screen.
    fn submit_cpe_search(&mut self, query: String) {
        let (tx, rx) = mpsc::channel();
        let q = query.clone();
        let k = self.api_key.clone();
        thread::spawn(move || { let _ = tx.send(FetchMsg::CpeDone(fetch_cpes(&q, &k))); });
        self.state = AppState::CpeLoading { query, tick: 0 };
        self.rx = Some(rx);
    }

    /// Fire a CVE search by CPE name(s) after user selects from the overlay.
    fn submit_cpe_query(&mut self, cpe_names: Vec<String>, label: String) {
        let (tx, rx) = mpsc::channel();
        let k = self.api_key.clone();
        thread::spawn(move || { let _ = tx.send(FetchMsg::Done(fetch_cves_by_cpe(&cpe_names, &k))); });
        self.query = label;
        self.state = AppState::Loading { tick: 0 };
        self.rx = Some(rx);
    }

    /// Submit the query typed in the interactive input screen.
    fn submit_query(&mut self, query: String) {
        let (tx, rx) = mpsc::channel();
        let q = query.clone();
        let k = self.api_key.clone();
        thread::spawn(move || {
            let result = fetch_cves(&q, &k);
            let _ = tx.send(FetchMsg::Done(result));
        });
        self.query = query;
        self.state = AppState::Loading { tick: 0 };
        self.rx = Some(rx);
    }

    fn poll_fetch(&mut self) {
        if let Some(rx) = &self.rx {
            match rx.try_recv() {
                Ok(FetchMsg::Done(result)) => {
                    match result {
                        Ok((mut all_cves, total)) => {
                            all_cves.sort_by(|a, b| b.cve.published.cmp(&a.cve.published));
                            let mut ts = TableState::default();
                            if !all_cves.is_empty() { ts.select(Some(0)); }
                            let filter_overlay = collect_all_products(&all_cves);
                            let cves = all_cves.clone();
                            self.state = AppState::Loaded {
                                all_cves, cves, total, table_state: ts, preview_scroll: 0,
                                filter_overlay, filter_open: false, focus: PaneFocus::List,
                                preview_open: true, search_input: None,
                            };
                        }
                        Err(e) => { self.state = AppState::Error(e); }
                    }
                }
                Ok(FetchMsg::CpeDone(result)) => {
                    match result {
                        Ok(entries) => {
                            let query = match &self.state {
                                AppState::CpeLoading { query, .. } => query.clone(),
                                _ => String::new(),
                            };
                            let status = format!("{} products found", entries.len());
                            let overlay = CpeOverlay::new(entries, &query);
                            self.state = AppState::CpeResults {
                                query,
                                overlay,
                                status_line: status,
                            };
                        }
                        Err(e) => { self.state = AppState::Error(e); }
                    }
                }
                Err(_) => {}
            }
        }
    }

    fn tick(&mut self) {
        match &mut self.state {
            AppState::Loading { tick } | AppState::CpeLoading { tick, .. } => {
                *tick = tick.wrapping_add(1);
            }
            _ => {}
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

    fn focus_list(&mut self) {
        if let AppState::Loaded { focus, .. } = &mut self.state {
            *focus = PaneFocus::List;
        }
    }

    fn focus_preview(&mut self) {
        if let AppState::Loaded { focus, preview_open, .. } = &mut self.state {
            if *preview_open {
                *focus = PaneFocus::Preview;
            }
        }
    }

    fn toggle_preview(&mut self) {
        if let AppState::Loaded { preview_open, focus, .. } = &mut self.state {
            *preview_open = !*preview_open;
            if !*preview_open {
                *focus = PaneFocus::List;
            }
        }
    }

    fn reopen_search(&mut self) {
        if let AppState::Loaded { search_input, .. } = &mut self.state {
            *search_input = Some(String::new());
        }
    }

    fn close_search_input(&mut self) {
        if let AppState::Loaded { search_input, .. } = &mut self.state {
            *search_input = None;
        }
    }

    fn search_input_push(&mut self, c: char) {
        if let AppState::Loaded { search_input: Some(s), .. } = &mut self.state {
            s.push(c);
        }
    }

    fn search_input_pop(&mut self) {
        if let AppState::Loaded { search_input: Some(s), .. } = &mut self.state {
            s.pop();
        }
    }
}

// ── Fetch + Helpers ───────────────────────────────────────────────────────────

fn cpe_relevance_tier(e: &CpeEntry, q: &str) -> u8 {
    if e.vendor.to_lowercase() == q || e.product.to_lowercase() == q { 0 }
    else if e.vendor.to_lowercase().contains(q) || e.product.to_lowercase().contains(q)
        || e.display_label().to_lowercase().contains(q) { 1 }
    else { 2 }
}

fn parse_cpe_part(criteria: &str) -> CpeType {
    let parts: Vec<&str> = criteria.split(':').collect();
    CpeType::from_part(parts.get(2).copied().unwrap_or(""))
}

fn collect_all_products(all_cves: &[VulnEntry]) -> FilterOverlay {
    let mut seen: std::collections::HashMap<String, CpeType> = std::collections::HashMap::new();
    for entry in all_cves {
        for cfg in &entry.cve.configurations {
            for node in &cfg.nodes {
                for cpe in &node.cpe_match {
                    if !cpe.vulnerable { continue; }
                    let parts: Vec<&str> = cpe.criteria.split(':').collect();
                    if parts.len() < 5 { continue; }
                    let base = format!("{}:{}", parts[3], parts[4]);
                    seen.entry(base).or_insert_with(|| parse_cpe_part(&cpe.criteria));
                }
            }
        }
    }
    // Sort by (kind, product key) so OS appears first
    let mut pairs: Vec<(String, CpeType)> = seen.into_iter().collect();
    pairs.sort_by(|a, b| a.1.cmp(&b.1).then(a.0.cmp(&b.0)));
    let products: Vec<String> = pairs.iter().map(|(p, _)| p.clone()).collect();
    let kinds: Vec<CpeType> = pairs.into_iter().map(|(_, k)| k).collect();
    FilterOverlay::new_with_kinds(products, kinds)
}

const NVD_PAGE_SIZE: u32 = 2000;

fn nvd_get(url: &str, api_key: &str) -> Result<NvdResponse, String> {
    let mut req = ureq::get(url).set("User-Agent", "cveseek/1.0");
    if !api_key.is_empty() { req = req.set("apiKey", api_key); }
    req.call()
        .map_err(|e| format!("Request failed: {}", e))?
        .into_json::<NvdResponse>()
        .map_err(|e| format!("Parse error: {}", e))
}

/// Fetch the most recent CVEs for a base URL (no pagination params).
/// If totalResults > PAGE_SIZE, fetches the last page so the user sees
/// the newest CVEs instead of the oldest.
fn fetch_recent(base_url: &str, api_key: &str) -> Result<(Vec<VulnEntry>, u32), String> {
    let url = format!("{}&resultsPerPage={}", base_url, NVD_PAGE_SIZE);
    let body = nvd_get(&url, api_key)?;
    let total = body.total_results;
    if total <= NVD_PAGE_SIZE {
        return Ok((body.vulnerabilities, total));
    }
    // Fetch last page — contains the most recently published CVEs
    let start = total - NVD_PAGE_SIZE;
    let url2 = format!("{}&resultsPerPage={}&startIndex={}", base_url, NVD_PAGE_SIZE, start);
    let body2 = nvd_get(&url2, api_key)?;
    Ok((body2.vulnerabilities, total))
}

fn fetch_cves(query: &str, api_key: &str) -> Result<(Vec<VulnEntry>, u32), String> {
    let encoded = urlencoding::encode(query);
    let base = format!("https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={}", encoded);
    fetch_recent(&base, api_key)
}

fn fetch_cpes(query: &str, api_key: &str) -> Result<Vec<CpeEntry>, String> {
    let encoded = urlencoding::encode(query);
    let url = format!(
        "https://services.nvd.nist.gov/rest/json/cpes/2.0?keywordSearch={}",
        encoded
    );
    let mut req = ureq::get(&url).set("User-Agent", "cveseek/1.0");
    if !api_key.is_empty() {
        req = req.set("apiKey", api_key);
    }
    let resp = req.call().map_err(|e| format!("CPE request failed: {}", e))?;
    let body: NvdCpeResponse = resp.into_json().map_err(|e| format!("CPE parse error: {}", e))?;

    // Deduplicate by (vendor, product, kind): keep wildcard-version entry if available,
    // otherwise the first seen. This removes hundreds of per-version entries.
    let mut seen: std::collections::HashMap<(String, String), CpeEntry> =
        std::collections::HashMap::new();
    for raw in &body.products {
        if raw.cpe.deprecated { continue; }
        let entry = CpeEntry::from_api(&raw.cpe);
        let parts: Vec<&str> = raw.cpe.cpe_name.split(':').collect();
        let version = parts.get(5).copied().unwrap_or("*");
        let is_wildcard = version == "*" || version == "-";
        let key = (entry.vendor.clone(), entry.product.clone());
        match seen.entry(key) {
            std::collections::hash_map::Entry::Vacant(e) => { e.insert(entry); }
            std::collections::hash_map::Entry::Occupied(mut e) => {
                if is_wildcard { *e.get_mut() = entry; }
            }
        }
    }
    Ok(seen.into_values().collect())
}

fn fetch_cves_by_cpe(cpe_names: &[String], api_key: &str) -> Result<(Vec<VulnEntry>, u32), String> {
    let mut all: Vec<VulnEntry> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut total: u32 = 0;
    for cpe_name in cpe_names {
        if api_key.is_empty() { thread::sleep(Duration::from_millis(650)); }
        let encoded = urlencoding::encode(cpe_name);
        let base = format!("https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={}", encoded);
        let (entries, count) = fetch_recent(&base, api_key)?;
        total = total.saturating_add(count);
        for entry in entries {
            if seen.insert(entry.cve.id.clone()) { all.push(entry); }
        }
    }
    Ok((all, total))
}

fn build_cpe_label(overlay: &CpeOverlay) -> String {
    let selected: Vec<&CpeEntry> = overlay.entries.iter().enumerate()
        .filter(|(i, _)| overlay.checked[*i])
        .map(|(_, e)| e)
        .collect();
    match selected.len() {
        0 => String::new(),
        1 => format!("{} ({})", selected[0].display_label(), selected[0].kind.badge().trim()),
        2 => format!("{} ({}), {} ({})",
            selected[0].display_label(), selected[0].kind.badge().trim(),
            selected[1].display_label(), selected[1].kind.badge().trim()),
        n => format!("{} ({}) + {} more",
            selected[0].display_label(), selected[0].kind.badge().trim(), n - 1),
    }
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

    'draw: {

    // Vertical split: header (1 line) + body
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(0)])
        .split(area);

    // ── Header bar ──────────────────────────────────────────────────────────
    let header_text = match &app.state {
        AppState::QueryInput { mode, .. } => Line::from(vec![
            Span::styled("  cveseek ", Style::default().fg(C_BLUE).add_modifier(Modifier::BOLD)),
            Span::styled(
                if *mode == SearchMode::Keyword { "Keyword Search" } else { "Product Search (CPE)" },
                Style::default().fg(C_DIM),
            ),
        ]),
        AppState::Loading { .. } => Line::from(vec![
            Span::styled("  cveseek ", Style::default().fg(C_BLUE).add_modifier(Modifier::BOLD)),
            Span::styled("query: ", Style::default().fg(C_HEADER)),
            Span::styled(app.query.as_str(), Style::default().fg(C_DEFAULT)),
            Span::styled("  fetching...", Style::default().fg(C_DIM)),
        ]),
        AppState::CpeLoading { query, .. } => Line::from(vec![
            Span::styled("  cveseek ", Style::default().fg(C_BLUE).add_modifier(Modifier::BOLD)),
            Span::styled("product search: ", Style::default().fg(C_HEADER)),
            Span::styled(query.as_str(), Style::default().fg(C_DEFAULT)),
            Span::styled("  searching...", Style::default().fg(C_DIM)),
        ]),
        AppState::CpeResults { query, overlay, .. } => Line::from(vec![
            Span::styled("  cveseek ", Style::default().fg(C_BLUE).add_modifier(Modifier::BOLD)),
            Span::styled("product search: ", Style::default().fg(C_HEADER)),
            Span::styled(query.as_str(), Style::default().fg(C_DEFAULT)),
            Span::styled(
                format!("  {} selected", overlay.checked.iter().filter(|&&c| c).count()),
                Style::default().fg(C_HEADER),
            ),
            Span::styled(
                "  [Space] toggle  [Enter] load CVEs  [/] filter  [Esc] back",
                Style::default().fg(C_DIM),
            ),
        ]),
        AppState::Error(_) => Line::from(vec![
            Span::styled("  cveseek ", Style::default().fg(C_BLUE).add_modifier(Modifier::BOLD)),
            Span::styled("  error  ", Style::default().fg(Color::Rgb(251, 73, 52))),
            Span::styled("  [q] quit", Style::default().fg(C_DIM)),
        ]),
        AppState::Loaded { cves, total, focus, preview_open, .. } => Line::from(vec![
            Span::styled("  cveseek ", Style::default().fg(C_BLUE).add_modifier(Modifier::BOLD)),
            Span::styled("query: ", Style::default().fg(C_HEADER)),
            Span::styled(app.query.as_str(), Style::default().fg(C_DEFAULT)),
            Span::styled(
                format!("  {}/{} results", cves.len(), total),
                Style::default().fg(C_HEADER),
            ),
            Span::styled(
                if *preview_open && *focus == PaneFocus::Preview {
                    "  [↑↓] scroll  [←] list  [Enter] hide preview  [f] filter  [s] search  [q] quit"
                } else {
                    "  [↑↓/jk] nav  [→] preview  [Enter] toggle preview  [f] filter  [s] search  [q] quit"
                },
                Style::default().fg(C_DIM),
            ),
        ]),
    };
    f.render_widget(Paragraph::new(header_text), layout[0]);

    // ── Body ────────────────────────────────────────────────────────────────
    match &mut app.state {
        AppState::QueryInput { input, mode } => {
            render_query_input(f, layout[1], input, *mode);
            break 'draw;
        }
        AppState::CpeLoading { tick, .. } => {
            let frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
            let frame = frames[(*tick as usize / 3) % frames.len()];
            let query = if let AppState::CpeLoading { query, .. } = &app.state { query.as_str() } else { "" };
            let text = format!(
                "\n\n   {} Searching NVD product database for \"{}\"...\n\n   This may take a moment.",
                frame, query
            );
            f.render_widget(Paragraph::new(text).style(Style::default().fg(C_BLUE)), layout[1]);
            break 'draw;
        }
        AppState::CpeResults { overlay, status_line, .. } => {
            let status = status_line.clone();
            render_cpe_results(f, layout[1], overlay, &status);
            break 'draw;
        }
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
            focus,
            preview_open,
            search_input,
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
                break 'draw;
            }

            if *preview_open {
                let body_chunks = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
                    .split(layout[1]);
                render_list(f, body_chunks[0], cves, table_state,
                    *focus == PaneFocus::List, true);
                render_preview(f, body_chunks[1], cves, table_state.selected(),
                    *preview_scroll, *focus == PaneFocus::Preview);
            } else {
                render_list(f, layout[1], cves, table_state, true, false);
            }

            if *filter_open {
                render_filter_overlay(f, area, filter_overlay);
            }
            if let Some(input) = search_input {
                render_search_overlay(f, area, input, &app.query.clone());
            }
        }
    }

    } // end 'draw block

    if app.show_about {
        render_about_overlay(f, area);
    }
}

fn render_list(
    f: &mut Frame,
    area: Rect,
    cves: &[VulnEntry],
    table_state: &mut TableState,
    active: bool,
    preview_open: bool,
) {
    let border_color = if active { C_HEADER } else { C_BORDER };
    let title_style  = if active {
        Style::default().fg(C_HEADER).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(C_DIM)
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color))
        .title(Span::styled(" CVE List ", title_style));

    // Extra columns shown when preview is hidden, depending on terminal width.
    let show_published = !preview_open && area.width >= 85;
    let show_modified  = !preview_open && area.width >= 103;
    let show_status    = !preview_open && area.width >= 125;

    let mut col_names: Vec<&str> = vec!["CVE ID", "SEV", "DESCRIPTION"];
    if show_published { col_names.push("PUBLISHED"); }
    if show_modified  { col_names.push("MODIFIED"); }
    if show_status    { col_names.push("STATUS"); }

    let header_cells = col_names.iter().map(|h| {
        Cell::from(*h).style(
            Style::default().fg(C_HEADER).add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
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

            let mut cells = vec![
                Cell::from(cve.id.clone()).style(Style::default().fg(C_BLUE)),
                Cell::from(sev.label).style(Style::default().fg(sev_color).add_modifier(Modifier::BOLD)),
                Cell::from(truncate_str(&strip_html(desc), 120)).style(Style::default().fg(C_DEFAULT)),
            ];
            if show_published {
                cells.push(Cell::from(short_date(&cve.published).to_string())
                    .style(Style::default().fg(C_DIM)));
            }
            if show_modified {
                cells.push(Cell::from(short_date(&cve.last_modified).to_string())
                    .style(Style::default().fg(C_DIM)));
            }
            if show_status {
                cells.push(Cell::from(truncate_str(&cve.vuln_status, 18))
                    .style(Style::default().fg(C_DIM)));
            }
            Row::new(cells).height(1)
        })
        .collect();

    let mut widths = vec![
        Constraint::Length(20),
        Constraint::Length(9),
        Constraint::Fill(1),
    ];
    if show_published { widths.push(Constraint::Length(12)); }
    if show_modified  { widths.push(Constraint::Length(12)); }
    if show_status    { widths.push(Constraint::Length(18)); }

    let table = Table::new(rows, widths)
        .header(header)
        .block(block)
        .highlight_style(
            Style::default().bg(C_SEL_BG).fg(C_YELLOW).add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");

    f.render_stateful_widget(table, area, table_state);
}

fn render_preview(
    f: &mut Frame,
    area: Rect,
    cves: &[VulnEntry],
    selected: Option<usize>,
    scroll: u16,
    active: bool,
) {
    let border_color = if active { C_HEADER } else { C_BORDER };
    let title_style  = if active {
        Style::default().fg(C_HEADER).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(C_DIM)
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color))
        .title(Span::styled(" Preview ", title_style));

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

fn render_search_overlay(f: &mut Frame, area: Rect, input: &str, prev_query: &str) {
    let popup_area = centered_rect(58, 38, area);
    f.render_widget(Clear, popup_area);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(C_HEADER))
        .title(Span::styled(
            " New Search ",
            Style::default().fg(C_HEADER).add_modifier(Modifier::BOLD),
        ));
    let inner = block.inner(popup_area);
    f.render_widget(block, popup_area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(1),
            Constraint::Length(1), // prev query hint
            Constraint::Length(1), // spacer
            Constraint::Length(3), // input (border + content + border)
            Constraint::Length(1), // spacer
            Constraint::Length(1), // hint
            Constraint::Min(1),
        ])
        .split(inner);

    // Previous query (grayed out)
    if !prev_query.is_empty() {
        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled("Current:  ", Style::default().fg(C_DIM)),
                Span::styled(prev_query, Style::default().fg(C_DIM).add_modifier(Modifier::ITALIC)),
            ])),
            chunks[1],
        );
    }

    // Input field with block cursor
    let display = format!("{}\u{2588}", input);
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(display, Style::default().fg(C_DEFAULT))))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(C_BORDER)),
            ),
        chunks[3],
    );

    // Hint
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("[Enter]", Style::default().fg(C_YELLOW)),
            Span::styled(" search  ", Style::default().fg(C_DIM)),
            Span::styled("[Esc/q]", Style::default().fg(C_YELLOW)),
            Span::styled(" cancel", Style::default().fg(C_DIM)),
        ]))
        .alignment(ratatui::layout::Alignment::Center),
        chunks[5],
    );
}

fn render_query_input(f: &mut Frame, area: Rect, input: &str, mode: SearchMode) {
    let box_area = centered_rect(60, 50, area);
    f.render_widget(Clear, box_area);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(C_HEADER))
        .title(Span::styled(
            " cveseek ",
            Style::default().fg(C_BLUE).add_modifier(Modifier::BOLD),
        ));

    let inner = block.inner(box_area);
    f.render_widget(block, box_area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(1),    // spacer top
            Constraint::Length(1), // subtitle
            Constraint::Length(1), // spacer
            Constraint::Length(1), // mode toggle
            Constraint::Length(1), // spacer
            Constraint::Length(1), // input label
            Constraint::Length(3), // input field
            Constraint::Length(1), // spacer
            Constraint::Length(1), // hint
            Constraint::Min(1),    // spacer bottom
        ])
        .split(inner);

    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            "NVD Vulnerability Search",
            Style::default().fg(C_DIM),
        ))).alignment(ratatui::layout::Alignment::Center),
        chunks[1],
    );

    // Mode toggle: [● Keyword] / Product  or  Keyword / [● Product]
    let (kw_style, cpe_style) = if mode == SearchMode::Keyword {
        (
            Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD | Modifier::REVERSED),
            Style::default().fg(C_DIM),
        )
    } else {
        (
            Style::default().fg(C_DIM),
            Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD | Modifier::REVERSED),
        )
    };
    let mode_line = Line::from(vec![
        Span::styled(" Keyword ", kw_style),
        Span::styled("  /  ", Style::default().fg(C_DIM)),
        Span::styled(" Product (CPE) ", cpe_style),
        Span::styled("   [Tab] switch", Style::default().fg(C_DIM)),
    ]);
    f.render_widget(
        Paragraph::new(mode_line).alignment(ratatui::layout::Alignment::Center),
        chunks[3],
    );

    let label = if mode == SearchMode::Keyword { "Keyword search:" } else { "Product / vendor:" };
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(label, Style::default().fg(C_HEADER)))),
        chunks[5],
    );

    let display_input = format!("{}\u{2588}", input);
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(display_input, Style::default().fg(C_DEFAULT))))
            .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(C_BORDER))),
        chunks[6],
    );

    let hint = Line::from(vec![
        Span::styled("[Enter]", Style::default().fg(C_YELLOW)),
        Span::styled(" search  ", Style::default().fg(C_DIM)),
        Span::styled("[Esc/q]", Style::default().fg(C_YELLOW)),
        Span::styled(" quit", Style::default().fg(C_DIM)),
    ]);
    f.render_widget(
        Paragraph::new(hint).alignment(ratatui::layout::Alignment::Center),
        chunks[8],
    );
}

fn render_cpe_results(f: &mut Frame, area: Rect, overlay: &mut CpeOverlay, status_line: &str) {
    let popup_area = centered_rect(72, 82, area);
    f.render_widget(Clear, popup_area);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(C_HEADER))
        .title(Span::styled(
            " Product Search ",
            Style::default().fg(C_HEADER).add_modifier(Modifier::BOLD),
        ));
    let inner = block.inner(popup_area);
    f.render_widget(block, popup_area);

    if inner.height < 6 || inner.width < 20 { return; }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // hints
            Constraint::Length(1), // search bar
            Constraint::Length(1), // separator
            Constraint::Min(1),    // list
            Constraint::Length(1), // separator
            Constraint::Length(1), // status + confirm
        ])
        .split(inner);

    // Hint line
    f.render_widget(Paragraph::new(Line::from(vec![
        Span::styled("[a]", Style::default().fg(C_YELLOW)),
        Span::styled(" all  ", Style::default().fg(C_DIM)),
        Span::styled("[n]", Style::default().fg(C_YELLOW)),
        Span::styled(" none  ", Style::default().fg(C_DIM)),
        Span::styled("[Space]", Style::default().fg(C_YELLOW)),
        Span::styled(" toggle  ", Style::default().fg(C_DIM)),
        Span::styled("[/]", Style::default().fg(C_YELLOW)),
        Span::styled(" filter  ", Style::default().fg(C_DIM)),
        Span::styled("[Enter]", Style::default().fg(C_YELLOW)),
        Span::styled(" load CVEs  ", Style::default().fg(C_DIM)),
        Span::styled("[Esc]", Style::default().fg(C_YELLOW)),
        Span::styled(" back", Style::default().fg(C_DIM)),
    ])), chunks[0]);

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
            Span::styled("  [/] edit  [Esc] clear", Style::default().fg(C_DIM)),
        ])
    } else {
        Line::from(Span::styled("[/] filter products", Style::default().fg(C_DIM)))
    };
    f.render_widget(Paragraph::new(search_line), chunks[1]);

    let sep = "─".repeat(inner.width as usize);
    f.render_widget(Paragraph::new(Line::from(Span::styled(sep.as_str(), Style::default().fg(C_BORDER)))), chunks[2]);

    // Product list
    if overlay.entries.is_empty() {
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "  No products found. Press Esc to go back.",
                Style::default().fg(C_DIM),
            ))),
            chunks[3],
        );
    } else {
        let visible_height = chunks[3].height as usize;
        overlay.adjust_scroll(visible_height);
        let vis_items = overlay.visible_items();
        let total_vis = vis_items.len();
        let scroll_offset = overlay.list_scroll;

        let mut lines: Vec<Line> = vec![];
        let end = (scroll_offset + visible_height).min(total_vis);
        for vis_idx in scroll_offset..end {
            let is_cursor = vis_idx == overlay.cursor;
            let real = vis_items[vis_idx];
            let entry = &overlay.entries[real];
            let checked = overlay.checked[real];

            let prefix    = if is_cursor { "▶ " } else { "  " };
            let checkbox  = if checked { "[x] " } else { "[ ] " };
            let row_style = if is_cursor {
                Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(C_DEFAULT)
            };
            let check_style = if checked { Style::default().fg(Color::Green) } else { Style::default().fg(C_DIM) };
            let label = entry.display_label();
            let max_label = chunks[3].width.saturating_sub(13) as usize; // prefix+badge+checkbox

            lines.push(Line::from(vec![
                Span::styled(prefix.to_string(), row_style),
                Span::styled(entry.kind.badge(), Style::default().fg(entry.kind.badge_color())),
                Span::styled(" ", Style::default()),
                Span::styled(checkbox.to_string(), check_style),
                Span::styled(truncate_str(&label, max_label), row_style),
            ]));
        }
        f.render_widget(Paragraph::new(lines), chunks[3]);
    }

    f.render_widget(Paragraph::new(Line::from(Span::styled(sep.as_str(), Style::default().fg(C_BORDER)))), chunks[4]);

    // Status + confirm button
    let selected_count = overlay.checked.iter().filter(|&&c| c).count();
    let status_text = format!("{}  •  {} selected", status_line, selected_count);
    let (confirm_label, confirm_style) = if overlay.has_selection() {
        ("[ Load CVEs ]", Style::default().fg(Color::Black).bg(C_HEADER).add_modifier(Modifier::BOLD))
    } else {
        ("  Load CVEs  ", Style::default().fg(C_DIM))
    };
    let pad = (inner.width as usize).saturating_sub(status_text.len() + confirm_label.len());
    f.render_widget(Paragraph::new(Line::from(vec![
        Span::styled(status_text, Style::default().fg(C_DIM)),
        Span::styled(" ".repeat(pad), Style::default()),
        Span::styled(confirm_label, confirm_style),
    ])), chunks[5]);
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

fn render_about_overlay(f: &mut Frame, area: Rect) {
    let popup_area = centered_rect(50, 50, area);
    f.render_widget(ratatui::widgets::Clear, popup_area);

    let version = env!("CARGO_PKG_VERSION");
    let lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("  cveseek ", Style::default().fg(C_BLUE).add_modifier(Modifier::BOLD)),
            Span::styled(format!("v{}", version), Style::default().fg(C_DIM)),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "  A fast, keyboard-driven terminal UI for searching",
            Style::default().fg(C_DEFAULT),
        )),
        Line::from(Span::styled(
            "  and browsing CVE vulnerabilities via the NIST NVD API.",
            Style::default().fg(C_DEFAULT),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("  © 2026  ", Style::default().fg(C_DIM)),
            Span::styled("Christian Lepuschitz", Style::default().fg(C_YELLOW)),
            Span::styled(" (@xtncl)", Style::default().fg(C_DIM)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  ", Style::default()),
            Span::styled("https://github.com/xtncl/cveseek", Style::default().fg(C_BLUE)),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "  Press any key to close",
            Style::default().fg(C_DIM),
        )),
        Line::from(""),
    ];

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(C_BLUE))
        .title(Span::styled(" About ", Style::default().fg(C_BLUE).add_modifier(Modifier::BOLD)));

    f.render_widget(Paragraph::new(lines).block(block), popup_area);
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

        let kind = if real < overlay.kinds.len() { &overlay.kinds[real] } else { &CpeType::Unknown };
        let badge = kind.badge();
        let badge_color = kind.badge_color();
        let max_w = chunks[3].width.saturating_sub(6 + badge.len() as u16 + 1) as usize;

        // Highlight matching part of label when searching
        if !overlay.search_query.is_empty() && !is_cursor {
            let q = overlay.search_query.to_lowercase();
            let label_lower = label.to_lowercase();
            if let Some(pos) = label_lower.find(&q) {
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
                    Span::styled(badge, Style::default().fg(badge_color)),
                    Span::styled(" ", Style::default()),
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
            Span::styled(badge, Style::default().fg(badge_color)),
            Span::styled(" ", Style::default()),
            Span::styled(truncate_str(label, max_w), row_style),
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

    let mut app = match cli.query {
        Some(q) => App::new(q, cli.key),
        None    => App::new_interactive(cli.key),
    };

    let tick_rate = Duration::from_millis(50);

    loop {
        app.poll_fetch();
        app.tick();

        terminal.draw(|f| ui(f, &mut app))?;

        if event::poll(tick_rate)? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press { continue; }

                // ── About overlay (highest priority) ─────────────────────────
                if app.show_about {
                    app.show_about = false;
                    continue;
                }
                if key.code == KeyCode::Char('?') {
                    app.show_about = true;
                    continue;
                }

                // ── Query input screen ───────────────────────────────────────
                if let AppState::QueryInput { input, mode } = &mut app.state {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => break,
                        KeyCode::Tab => {
                            *mode = if *mode == SearchMode::Keyword { SearchMode::Cpe } else { SearchMode::Keyword };
                        }
                        KeyCode::Char(c) => { input.push(c); }
                        KeyCode::Backspace => { input.pop(); }
                        KeyCode::Enter => {
                            let q = input.trim().to_string();
                            if !q.is_empty() {
                                let m = *mode;
                                if m == SearchMode::Keyword { app.submit_query(q); }
                                else { app.submit_cpe_search(q); }
                            }
                        }
                        _ => {}
                    }
                    continue;
                }

                // ── CPE results screen ───────────────────────────────────────
                if matches!(&app.state, AppState::CpeLoading { .. }) {
                    if let (KeyCode::Char('c'), KeyModifiers::CONTROL) = (key.code, key.modifiers) { break; }
                    continue;
                }
                if let AppState::CpeResults { overlay, .. } = &mut app.state {
                    if overlay.search_mode {
                        match key.code {
                            KeyCode::Esc        => overlay.exit_search(true),
                            KeyCode::Enter      => overlay.exit_search(false),
                            KeyCode::Backspace  => overlay.search_pop(),
                            KeyCode::Up         => overlay.move_cursor(-1),
                            KeyCode::Down       => overlay.move_cursor(1),
                            KeyCode::Char(c)    => overlay.search_push(c),
                            _ => {}
                        }
                    } else {
                        match (key.code, key.modifiers) {
                            (KeyCode::Char('c'), KeyModifiers::CONTROL) => break,
                            (KeyCode::Esc, _) | (KeyCode::Char('q'), _) => {
                                app.state = AppState::QueryInput {
                                    input: String::new(), mode: SearchMode::Cpe,
                                };
                            }
                            (KeyCode::Char('/'), _) => {
                                if let AppState::CpeResults { overlay, .. } = &mut app.state {
                                    overlay.enter_search();
                                }
                            }
                            (KeyCode::Up, _) | (KeyCode::Char('k'), _) => {
                                if let AppState::CpeResults { overlay, .. } = &mut app.state {
                                    overlay.move_cursor(-1);
                                }
                            }
                            (KeyCode::Down, _) | (KeyCode::Char('j'), _) => {
                                if let AppState::CpeResults { overlay, .. } = &mut app.state {
                                    overlay.move_cursor(1);
                                }
                            }
                            (KeyCode::PageUp, _) => {
                                if let AppState::CpeResults { overlay, .. } = &mut app.state {
                                    overlay.move_cursor(-15);
                                }
                            }
                            (KeyCode::PageDown, _) => {
                                if let AppState::CpeResults { overlay, .. } = &mut app.state {
                                    overlay.move_cursor(15);
                                }
                            }
                            (KeyCode::Char(' '), _) => {
                                if let AppState::CpeResults { overlay, .. } = &mut app.state {
                                    overlay.toggle_current();
                                }
                            }
                            (KeyCode::Char('a'), _) => {
                                if let AppState::CpeResults { overlay, .. } = &mut app.state {
                                    overlay.select_all();
                                }
                            }
                            (KeyCode::Char('n'), _) => {
                                if let AppState::CpeResults { overlay, .. } = &mut app.state {
                                    overlay.select_none();
                                }
                            }
                            (KeyCode::Enter, _) => {
                                if let AppState::CpeResults { overlay, .. } = &mut app.state {
                                    if overlay.has_selection() {
                                        let names = overlay.selected_cpe_names();
                                        let label = build_cpe_label(overlay);
                                        app.submit_cpe_query(names, label);
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    continue;
                }

                // ── Search overlay (s key) ───────────────────────────────────
                let search_overlay_open =
                    matches!(&app.state, AppState::Loaded { search_input: Some(_), .. });
                if search_overlay_open {
                    match key.code {
                        KeyCode::Esc | KeyCode::Char('q') => app.close_search_input(),
                        KeyCode::Backspace => app.search_input_pop(),
                        KeyCode::Char(c) => app.search_input_push(c),
                        KeyCode::Enter => {
                            let q = if let AppState::Loaded { search_input: Some(s), .. } = &app.state {
                                s.trim().to_string()
                            } else { String::new() };
                            if !q.is_empty() { app.submit_query(q); }
                            else             { app.close_search_input(); }
                        }
                        _ => {}
                    }
                    continue;
                }

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
                        (KeyCode::Char('c'), KeyModifiers::CONTROL) => break,
                        (KeyCode::Esc, _)
                        | (KeyCode::Char('f'), _)
                        | (KeyCode::Char('q'), _) => app.toggle_filter(),
                        (KeyCode::Char('/'), _) => app.filter_search_enter(),
                        (KeyCode::Up, _) | (KeyCode::Char('k'), _) => app.filter_move_cursor(-1),
                        (KeyCode::Down, _) | (KeyCode::Char('j'), _) => app.filter_move_cursor(1),
                        (KeyCode::PageUp, _) => app.filter_move_cursor(-15),
                        (KeyCode::PageDown, _) => app.filter_move_cursor(15),
                        (KeyCode::Char('u'), KeyModifiers::CONTROL) => app.filter_move_cursor(-8),
                        (KeyCode::Char('d'), KeyModifiers::CONTROL) => app.filter_move_cursor(8),
                        (KeyCode::Char(' '), _) => app.filter_toggle(),
                        (KeyCode::Char('a'), _) => app.filter_select_all(),
                        (KeyCode::Char('n'), _) => app.filter_select_none(),
                        (KeyCode::Tab, _) => app.filter_tab(),
                        (KeyCode::Enter, _) => app.apply_filter(),
                        _ => {}
                    }
                } else {
                    // Determine current focus for routing ↑/↓
                    let in_preview = matches!(&app.state,
                        AppState::Loaded { focus: PaneFocus::Preview, preview_open: true, .. });

                    match (key.code, key.modifiers) {
                        (KeyCode::Char('c'), KeyModifiers::CONTROL) => break,

                        // q / Esc: close active pane or quit
                        (KeyCode::Char('q'), _) | (KeyCode::Esc, _) => {
                            if in_preview { app.focus_list(); }
                            else          { break; }
                        }

                        // Focus switching
                        (KeyCode::Right, _) => app.focus_preview(),
                        (KeyCode::Left, _)  => app.focus_list(),

                        // Up/Down routed by focus
                        (KeyCode::Up, _) | (KeyCode::Char('k'), _) => {
                            if in_preview { app.scroll_preview(-3); }
                            else          { app.move_cursor(-1); }
                        }
                        (KeyCode::Down, _) | (KeyCode::Char('j'), _) => {
                            if in_preview { app.scroll_preview(3); }
                            else          { app.move_cursor(1); }
                        }

                        // List-only navigation
                        (KeyCode::PageUp, _)   => app.move_cursor(-15),
                        (KeyCode::PageDown, _) => app.move_cursor(15),
                        (KeyCode::Char('g'), _) => app.goto_first(),
                        (KeyCode::Char('G'), _) => app.goto_last(),

                        // Preview scroll (kept for power users)
                        (KeyCode::Char('d'), KeyModifiers::CONTROL) => app.scroll_preview(8),
                        (KeyCode::Char('u'), KeyModifiers::CONTROL) => app.scroll_preview(-8),

                        // Toggle preview pane
                        (KeyCode::Enter, _) => app.toggle_preview(),

                        // Filter + new search
                        (KeyCode::Char('f'), _) => app.toggle_filter(),
                        (KeyCode::Char('s'), _) => app.reopen_search(),

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
