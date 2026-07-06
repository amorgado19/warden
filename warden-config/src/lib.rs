//! # `warden-config` — boot configuration schema + parser
//!
//! Parses `warden.toml` (ADR-0001 IMP-005 / build-spec §3.2) into typed structs.
//!
//! ## Why a hand-rolled parser (build-spec NEG-001)
//! The config is a **security input**: on real hardware it may be attacker-
//! influenced, so GC-03 requires treating every byte as hostile. The stock
//! `toml` crate needs `std`; rather than pull a large `no_std` dependency into a
//! trust root, we parse a small, strict TOML *subset* ourselves — bounded, with
//! no `unwrap` on input, returning a readable [`ConfigError`] (with a line
//! number) on anything malformed so the loader can drop to a rescue prompt
//! instead of panicking (AC1.3).
//!
//! ## Supported subset
//! * `# comments` to end of line (a `#` inside a basic string is literal)
//! * tables `[global]`, `[assess]`; array-of-tables `[[entry]]`
//! * `key = value`, where value is a basic string, integer, boolean, or an
//!   array of basic strings
//! * basic-string escapes: `\\ \" \n \t \r \0`
//!
//! Anything outside the subset (unknown table, unknown key, wrong value type,
//! trailing junk, unterminated string, …) is a hard error with a line number.
//!
//! The crate is `#![no_std]` for the firmware build but compiles with `std`
//! under `cfg(test)` so its parser can be unit-tested on the host.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

/// A fully-parsed, validated boot configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub global: Global,
    pub entries: Vec<Entry>,
    pub assess: Option<Assess>,
}

/// The `[global]` table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Global {
    /// Seconds before the default entry is auto-selected. `0` means wait forever.
    pub timeout: u32,
    /// Id of the entry selected on timeout (always resolves to a real entry).
    pub default: String,
    /// Where the menu is presented.
    pub console: ConsoleMode,
}

/// Console routing (DEC-008).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsoleMode {
    Serial,
    Firmware,
    Both,
}

/// One `[[entry]]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub id: String,
    pub title: String,
    pub protocol: Protocol,
    pub kernel: String,
    pub initrd: Option<String>,
    pub cmdline: Option<String>,
    pub modules: Vec<String>,
    pub signature: Option<String>,
}

/// Kernel boot protocol (DEC-005).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    LinuxEfi,
    WardenRich,
    /// Chainload an arbitrary UEFI application via LoadImage/StartImage (DEC-011).
    /// Only ever used when an entry declares it — never auto-discovered.
    Chainload,
}

/// The `[assess]` table (A/B rollback, DEC-012). Consumed in P6.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Assess {
    pub enabled: bool,
    pub max_tries: u32,
}

impl Config {
    /// Index of the entry named by `global.default` (guaranteed to exist).
    #[must_use]
    pub fn default_index(&self) -> usize {
        self.entries
            .iter()
            .position(|e| e.id == self.global.default)
            .unwrap_or(0)
    }
}

impl Protocol {
    /// Human-readable protocol name (for the menu / logs).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Protocol::LinuxEfi => "linux-efi",
            Protocol::WardenRich => "warden-rich",
            Protocol::Chainload => "chainload",
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// A configuration parse/validation error, with a 1-based line number
/// (`0` == not tied to a specific line).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    pub line: usize,
    pub msg: String,
}

impl ConfigError {
    fn at(line: usize, msg: impl Into<String>) -> Self {
        Self { line, msg: msg.into() }
    }
    fn global(msg: impl Into<String>) -> Self {
        Self { line: 0, msg: msg.into() }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.line == 0 {
            write!(f, "config error: {}", self.msg)
        } else {
            write!(f, "config error (line {}): {}", self.line, self.msg)
        }
    }
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

/// Parse `warden.toml` text into a validated [`Config`].
///
/// # Errors
/// Returns a [`ConfigError`] on any malformed or invalid input.
pub fn parse(input: &str) -> Result<Config, ConfigError> {
    let mut p = Parser::default();
    for (idx, raw) in input.lines().enumerate() {
        p.feed(raw, idx + 1)?;
    }
    p.finish()
}

/// A single parsed value.
enum Value {
    Str(String),
    Int(i64),
    Bool(bool),
    Arr(Vec<String>),
}

impl Value {
    fn type_name(&self) -> &'static str {
        match self {
            Value::Str(_) => "string",
            Value::Int(_) => "integer",
            Value::Bool(_) => "boolean",
            Value::Arr(_) => "array",
        }
    }
}

/// Which table subsequent `key = value` lines belong to.
enum Section {
    None,
    Global,
    Assess,
    Entry(usize),
}

/// Accumulates fields as lines are fed, then validates in [`Parser::finish`].
struct Parser {
    section: Section,
    // [global]
    saw_global: bool,
    g_timeout: Option<u32>,
    g_default: Option<String>,
    g_console: Option<ConsoleMode>,
    // [assess]
    saw_assess: bool,
    a_enabled: Option<bool>,
    a_max_tries: Option<u32>,
    // [[entry]]
    entries: Vec<EntryBuilder>,
}

impl Default for Parser {
    fn default() -> Self {
        Self {
            section: Section::None,
            saw_global: false,
            g_timeout: None,
            g_default: None,
            g_console: None,
            saw_assess: false,
            a_enabled: None,
            a_max_tries: None,
            entries: Vec::new(),
        }
    }
}

/// Set an as-yet-unset field, or reject a duplicate key. Strict TOML makes
/// repeated keys a hard error rather than last-value-wins (GC-03: hostile input
/// is rejected, not silently reinterpreted).
fn set_once<T>(slot: &mut Option<T>, value: T, key: &str, line: usize) -> Result<(), ConfigError> {
    if slot.is_some() {
        return Err(ConfigError::at(line, format!("duplicate key `{key}`")));
    }
    *slot = Some(value);
    Ok(())
}

#[derive(Default)]
struct EntryBuilder {
    id: Option<String>,
    title: Option<String>,
    protocol: Option<Protocol>,
    kernel: Option<String>,
    initrd: Option<String>,
    cmdline: Option<String>,
    modules: Option<Vec<String>>,
    signature: Option<String>,
}

impl Parser {
    fn feed(&mut self, raw: &str, line: usize) -> Result<(), ConfigError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            return Ok(());
        }
        if let Some(rest) = trimmed.strip_prefix("[[") {
            self.header_array(rest, line)
        } else if let Some(rest) = trimmed.strip_prefix('[') {
            self.header_table(rest, line)
        } else {
            self.key_value(trimmed, line)
        }
    }

    /// `[[entry]]` — array-of-tables header. `rest` is everything after `[[`.
    fn header_array(&mut self, rest: &str, line: usize) -> Result<(), ConfigError> {
        let body = strip_comment(rest);
        let name = body
            .trim_end()
            .strip_suffix("]]")
            .ok_or_else(|| ConfigError::at(line, "expected `]]` to close array-of-tables header"))?
            .trim();
        if name != "entry" {
            return Err(ConfigError::at(line, format!("unknown array-of-tables `[[{name}]]` (only `[[entry]]` is supported)")));
        }
        self.entries.push(EntryBuilder::default());
        self.section = Section::Entry(self.entries.len() - 1);
        Ok(())
    }

    /// `[global]` / `[assess]` — table header. `rest` is everything after `[`.
    fn header_table(&mut self, rest: &str, line: usize) -> Result<(), ConfigError> {
        let body = strip_comment(rest);
        let name = body
            .trim_end()
            .strip_suffix(']')
            .ok_or_else(|| ConfigError::at(line, "expected `]` to close table header"))?
            .trim();
        match name {
            "global" => {
                if self.saw_global {
                    return Err(ConfigError::at(line, "duplicate table `[global]`"));
                }
                self.saw_global = true;
                self.section = Section::Global;
            }
            "assess" => {
                if self.saw_assess {
                    return Err(ConfigError::at(line, "duplicate table `[assess]`"));
                }
                self.saw_assess = true;
                self.section = Section::Assess;
            }
            other => {
                return Err(ConfigError::at(line, format!("unknown table `[{other}]` (expected `global`, `assess`, or `[[entry]]`)")));
            }
        }
        Ok(())
    }

    fn key_value(&mut self, content: &str, line: usize) -> Result<(), ConfigError> {
        let eq = content
            .find('=')
            .ok_or_else(|| ConfigError::at(line, "expected `key = value`"))?;
        let key = content[..eq].trim();
        if key.is_empty() || !key.bytes().all(is_key_byte) {
            return Err(ConfigError::at(line, format!("invalid key `{key}`")));
        }
        let mut cur = Cursor::new(&content[eq + 1..]);
        let value = parse_value(&mut cur, line)?;
        cur.skip_ws();
        let tail = cur.rest();
        if !tail.is_empty() && !tail.starts_with('#') {
            return Err(ConfigError::at(line, format!("trailing characters after value: `{}`", tail.trim_end())));
        }
        self.assign(key, value, line)
    }

    fn assign(&mut self, key: &str, value: Value, line: usize) -> Result<(), ConfigError> {
        match self.section {
            Section::None => Err(ConfigError::at(line, format!("key `{key}` appears before any `[table]`"))),
            Section::Global => self.assign_global(key, value, line),
            Section::Assess => self.assign_assess(key, value, line),
            Section::Entry(idx) => Self::assign_entry(&mut self.entries[idx], key, value, line),
        }
    }

    fn assign_global(&mut self, key: &str, value: Value, line: usize) -> Result<(), ConfigError> {
        match key {
            "timeout" => set_once(&mut self.g_timeout, as_u32(&value, key, line)?, key, line),
            "default" => set_once(&mut self.g_default, as_string(value, key, line)?, key, line),
            "console" => {
                let s = as_string(value, key, line)?;
                let mode = match s.as_str() {
                    "serial" => ConsoleMode::Serial,
                    "firmware" => ConsoleMode::Firmware,
                    "both" => ConsoleMode::Both,
                    other => {
                        return Err(ConfigError::at(line, format!("console = \"{other}\" invalid (expected serial | firmware | both)")));
                    }
                };
                set_once(&mut self.g_console, mode, key, line)
            }
            other => Err(ConfigError::at(line, format!("unknown key `{other}` in [global]"))),
        }
    }

    fn assign_assess(&mut self, key: &str, value: Value, line: usize) -> Result<(), ConfigError> {
        match key {
            "enabled" => set_once(&mut self.a_enabled, as_bool(&value, key, line)?, key, line),
            "max_tries" => set_once(&mut self.a_max_tries, as_u32(&value, key, line)?, key, line),
            other => Err(ConfigError::at(line, format!("unknown key `{other}` in [assess]"))),
        }
    }

    fn assign_entry(e: &mut EntryBuilder, key: &str, value: Value, line: usize) -> Result<(), ConfigError> {
        match key {
            "id" => set_once(&mut e.id, as_string(value, key, line)?, key, line),
            "title" => set_once(&mut e.title, as_string(value, key, line)?, key, line),
            "kernel" => set_once(&mut e.kernel, as_string(value, key, line)?, key, line),
            "initrd" => set_once(&mut e.initrd, as_string(value, key, line)?, key, line),
            "cmdline" => set_once(&mut e.cmdline, as_string(value, key, line)?, key, line),
            "signature" => set_once(&mut e.signature, as_string(value, key, line)?, key, line),
            "protocol" => {
                let s = as_string(value, key, line)?;
                let proto = match s.as_str() {
                    "linux-efi" => Protocol::LinuxEfi,
                    "warden-rich" => Protocol::WardenRich,
                    "chainload" => Protocol::Chainload,
                    other => {
                        return Err(ConfigError::at(line, format!("protocol = \"{other}\" invalid (expected linux-efi | warden-rich | chainload)")));
                    }
                };
                set_once(&mut e.protocol, proto, key, line)
            }
            "modules" => set_once(&mut e.modules, as_str_array(value, key, line)?, key, line),
            other => Err(ConfigError::at(line, format!("unknown key `{other}` in [[entry]]"))),
        }
    }

    fn finish(self) -> Result<Config, ConfigError> {
        if self.entries.is_empty() {
            return Err(ConfigError::global("no [[entry]] defined — nothing to boot"));
        }

        let mut entries = Vec::with_capacity(self.entries.len());
        for (i, b) in self.entries.into_iter().enumerate() {
            let id = b.id.ok_or_else(|| ConfigError::global(format!("entry #{} is missing `id`", i + 1)))?;
            let miss = |field: &str| ConfigError::global(format!("entry `{id}` is missing `{field}`"));
            entries.push(Entry {
                title: b.title.ok_or_else(|| miss("title"))?,
                protocol: b.protocol.ok_or_else(|| miss("protocol"))?,
                kernel: b.kernel.ok_or_else(|| miss("kernel"))?,
                initrd: b.initrd,
                cmdline: b.cmdline,
                modules: b.modules.unwrap_or_default(),
                signature: b.signature,
                id,
            });
        }

        // Cap id length: entry ids double as A/B slot ids, stored in a 32-byte
        // on-disk field (must match `warden_assess::ID_LEN`). A longer id could
        // never be confirmed, so reject it up front rather than silently truncate.
        for e in &entries {
            if e.id.len() > 32 {
                return Err(ConfigError::global(format!(
                    "entry id `{}` is {} bytes; the maximum is 32 (A/B slot-id limit)",
                    e.id,
                    e.id.len()
                )));
            }
        }

        // Reject duplicate ids — otherwise `default` and menu selection are ambiguous.
        for i in 0..entries.len() {
            for j in (i + 1)..entries.len() {
                if entries[i].id == entries[j].id {
                    return Err(ConfigError::global(format!("duplicate entry id `{}`", entries[i].id)));
                }
            }
        }

        // Resolve the default: if given it must name a real entry; else use the first.
        let default = match self.g_default {
            Some(d) => {
                if !entries.iter().any(|e| e.id == d) {
                    return Err(ConfigError::global(format!("global.default = \"{d}\" matches no entry")));
                }
                d
            }
            None => entries[0].id.clone(),
        };

        let global = Global {
            timeout: self.g_timeout.unwrap_or(5),
            default,
            console: self.g_console.unwrap_or(ConsoleMode::Serial),
        };

        let assess = if self.saw_assess {
            Some(Assess {
                enabled: self.a_enabled.unwrap_or(false),
                max_tries: self.a_max_tries.unwrap_or(3),
            })
        } else {
            None
        };

        Ok(Config { global, entries, assess })
    }
}

// ---------------------------------------------------------------------------
// Value coercion helpers
// ---------------------------------------------------------------------------

fn as_string(v: Value, key: &str, line: usize) -> Result<String, ConfigError> {
    match v {
        Value::Str(s) => Ok(s),
        other => Err(ConfigError::at(line, format!("`{key}` expects a string, found {}", other.type_name()))),
    }
}

fn as_bool(v: &Value, key: &str, line: usize) -> Result<bool, ConfigError> {
    match v {
        Value::Bool(b) => Ok(*b),
        other => Err(ConfigError::at(line, format!("`{key}` expects a boolean, found {}", other.type_name()))),
    }
}

fn as_u32(v: &Value, key: &str, line: usize) -> Result<u32, ConfigError> {
    match v {
        Value::Int(n) => u32::try_from(*n)
            .map_err(|_| ConfigError::at(line, format!("`{key}` = {n} out of range for a non-negative 32-bit integer"))),
        other => Err(ConfigError::at(line, format!("`{key}` expects an integer, found {}", other.type_name()))),
    }
}

fn as_str_array(v: Value, key: &str, line: usize) -> Result<Vec<String>, ConfigError> {
    match v {
        Value::Arr(a) => Ok(a),
        other => Err(ConfigError::at(line, format!("`{key}` expects an array of strings, found {}", other.type_name()))),
    }
}

// ---------------------------------------------------------------------------
// Lexing primitives
// ---------------------------------------------------------------------------

fn is_key_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

/// Cut a line/header fragment at the first `#` (comment). Only used where no
/// string literal can appear (table headers); value comments are handled by the
/// value parser leaving a `#`-prefixed tail.
fn strip_comment(s: &str) -> &str {
    match s.find('#') {
        Some(i) => &s[..i],
        None => s,
    }
}

/// A byte-offset cursor over a `&str`, advancing by whole UTF-8 chars.
struct Cursor<'a> {
    s: &'a str,
    i: usize,
}

impl<'a> Cursor<'a> {
    fn new(s: &'a str) -> Self {
        Self { s, i: 0 }
    }
    fn rest(&self) -> &'a str {
        &self.s[self.i..]
    }
    fn peek(&self) -> Option<char> {
        self.rest().chars().next()
    }
    fn bump(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.i += c.len_utf8();
        Some(c)
    }
    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(' ') | Some('\t')) {
            self.bump();
        }
    }
}

fn parse_value(cur: &mut Cursor, line: usize) -> Result<Value, ConfigError> {
    cur.skip_ws();
    match cur.peek() {
        Some('"') => Ok(Value::Str(parse_string(cur, line)?)),
        Some('[') => Ok(Value::Arr(parse_array(cur, line)?)),
        Some('t') | Some('f') => parse_bool(cur, line),
        Some(c) if c == '-' || c == '+' || c.is_ascii_digit() => parse_int(cur, line),
        Some(c) => Err(ConfigError::at(line, format!("unexpected `{c}` where a value was expected"))),
        None => Err(ConfigError::at(line, "expected a value after `=`")),
    }
}

fn parse_string(cur: &mut Cursor, line: usize) -> Result<String, ConfigError> {
    cur.bump(); // consume opening quote
    let mut out = String::new();
    loop {
        match cur.bump() {
            None => return Err(ConfigError::at(line, "unterminated string (missing closing `\"`)")),
            Some('"') => return Ok(out),
            Some('\\') => match cur.bump() {
                Some('\\') => out.push('\\'),
                Some('"') => out.push('"'),
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('r') => out.push('\r'),
                Some('0') => out.push('\0'),
                Some(other) => {
                    return Err(ConfigError::at(line, format!("invalid escape `\\{other}` in string")));
                }
                None => return Err(ConfigError::at(line, "unterminated escape at end of string")),
            },
            // Reject raw control characters (except tab): TOML requires them to
            // be escaped, and letting e.g. a bare ESC (0x1B) through would allow
            // a hostile `title` to inject terminal escape sequences and spoof the
            // boot menu on the operator's console (GC-03 / CWE-150).
            Some(c) if c.is_control() && c != '\t' => {
                return Err(ConfigError::at(line, "unescaped control character in string (must be escaped)"));
            }
            Some(c) => out.push(c),
        }
    }
}

fn parse_array(cur: &mut Cursor, line: usize) -> Result<Vec<String>, ConfigError> {
    cur.bump(); // consume '['
    let mut items = Vec::new();
    loop {
        cur.skip_ws();
        match cur.peek() {
            None => return Err(ConfigError::at(line, "unterminated array (missing closing `]`)")),
            Some(']') => {
                cur.bump();
                return Ok(items);
            }
            Some('"') => {
                items.push(parse_string(cur, line)?);
                cur.skip_ws();
                match cur.peek() {
                    Some(',') => {
                        cur.bump();
                    }
                    Some(']') => {
                        cur.bump();
                        return Ok(items);
                    }
                    _ => return Err(ConfigError::at(line, "expected `,` or `]` in array")),
                }
            }
            Some(c) => {
                return Err(ConfigError::at(line, format!("arrays may only contain strings, found `{c}`")));
            }
        }
    }
}

fn parse_bool(cur: &mut Cursor, line: usize) -> Result<Value, ConfigError> {
    let start = cur.i;
    while matches!(cur.peek(), Some(c) if c.is_ascii_alphabetic()) {
        cur.bump();
    }
    match &cur.s[start..cur.i] {
        "true" => Ok(Value::Bool(true)),
        "false" => Ok(Value::Bool(false)),
        other => Err(ConfigError::at(line, format!("invalid value `{other}` (expected true/false)"))),
    }
}

fn parse_int(cur: &mut Cursor, line: usize) -> Result<Value, ConfigError> {
    let start = cur.i;
    if matches!(cur.peek(), Some('-') | Some('+')) {
        cur.bump();
    }
    let digits_start = cur.i;
    while matches!(cur.peek(), Some(c) if c.is_ascii_digit() || c == '_') {
        cur.bump();
    }
    let digits = &cur.s[digits_start..cur.i];
    if digits.is_empty() {
        return Err(ConfigError::at(line, "expected digits in integer"));
    }
    // TOML permits `_` only *between* digits, and forbids leading zeros.
    if digits.starts_with('_') || digits.ends_with('_') || digits.contains("__") {
        return Err(ConfigError::at(line, "misplaced `_` in integer (allowed only between digits)"));
    }
    let cleaned: String = digits.chars().filter(|c| *c != '_').collect();
    if cleaned.len() > 1 && cleaned.starts_with('0') {
        return Err(ConfigError::at(line, "integer must not have a leading zero"));
    }
    let raw = &cur.s[start..cur.i];
    let signed: String = raw.chars().filter(|c| *c != '_').collect();
    signed
        .parse::<i64>()
        .map(Value::Int)
        .map_err(|_| ConfigError::at(line, format!("integer `{raw}` is out of range")))
}

// ---------------------------------------------------------------------------
// Tests (host-only)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = r#"
# comment line
[global]
timeout = 3            # inline comment
default = "demo"
console = "serial"

[[entry]]
id       = "demo"
title    = "Demo Entry (Linux EFI)"
protocol = "linux-efi"
kernel   = "esp:/vmlinuz-demo"
cmdline  = "console=ttyS0 ro quiet"

[[entry]]
id       = "rescue"
title    = "Rescue Kernel"
protocol = "warden-rich"
kernel   = "esp:/rescue.elf"
modules  = ["esp:/a.mod", "esp:/b.mod"]

[assess]
enabled   = true
max_tries = 3
"#;

    #[test]
    fn parses_valid_config() {
        let c = parse(VALID).expect("valid config should parse");
        assert_eq!(c.global.timeout, 3);
        assert_eq!(c.global.default, "demo");
        assert_eq!(c.global.console, ConsoleMode::Serial);
        assert_eq!(c.entries.len(), 2);
        assert_eq!(c.default_index(), 0);

        let demo = &c.entries[0];
        assert_eq!(demo.id, "demo");
        assert_eq!(demo.protocol, Protocol::LinuxEfi);
        assert_eq!(demo.kernel, "esp:/vmlinuz-demo");
        assert_eq!(demo.cmdline.as_deref(), Some("console=ttyS0 ro quiet"));
        assert!(demo.modules.is_empty());

        let rescue = &c.entries[1];
        assert_eq!(rescue.protocol, Protocol::WardenRich);
        assert_eq!(rescue.modules, vec!["esp:/a.mod", "esp:/b.mod"]);

        let a = c.assess.expect("assess present");
        assert!(a.enabled);
        assert_eq!(a.max_tries, 3);
    }

    #[test]
    fn defaults_are_applied() {
        // no [global], no [assess]; single entry.
        let c = parse("[[entry]]\nid=\"only\"\ntitle=\"T\"\nprotocol=\"linux-efi\"\nkernel=\"k\"\n").unwrap();
        assert_eq!(c.global.timeout, 5); // default
        assert_eq!(c.global.default, "only"); // first entry
        assert_eq!(c.global.console, ConsoleMode::Serial);
        assert!(c.assess.is_none());
    }

    #[test]
    fn hash_inside_string_is_literal() {
        let c = parse("[[entry]]\nid=\"a\"\ntitle=\"a # b\"\nprotocol=\"linux-efi\"\nkernel=\"k\"\n").unwrap();
        assert_eq!(c.entries[0].title, "a # b");
    }

    #[test]
    fn string_escapes() {
        let c = parse("[[entry]]\nid=\"a\"\ntitle=\"tab\\tnl\\nq\\\"end\"\nprotocol=\"linux-efi\"\nkernel=\"k\"\n").unwrap();
        assert_eq!(c.entries[0].title, "tab\tnl\nq\"end");
    }

    #[test]
    fn integer_underscores_and_signs() {
        let c = parse("[global]\ntimeout = 1_0\ndefault=\"a\"\n[[entry]]\nid=\"a\"\ntitle=\"t\"\nprotocol=\"linux-efi\"\nkernel=\"k\"\n").unwrap();
        assert_eq!(c.global.timeout, 10);
    }

    fn err(input: &str) -> ConfigError {
        parse(input).expect_err("expected a parse error")
    }

    #[test]
    fn rejects_unterminated_string() {
        let e = err("[[entry]]\nid = \"demo\ntitle=\"t\"\n");
        assert_eq!(e.line, 2);
        assert!(e.msg.contains("unterminated string"), "{}", e.msg);
    }

    #[test]
    fn rejects_unknown_table() {
        let e = err("[bogus]\nx = 1\n");
        assert_eq!(e.line, 1);
        assert!(e.msg.contains("unknown table"), "{}", e.msg);
    }

    #[test]
    fn rejects_unknown_key() {
        let e = err("[global]\nnope = 1\n");
        assert!(e.msg.contains("unknown key"), "{}", e.msg);
    }

    #[test]
    fn rejects_bad_protocol() {
        let e = err("[[entry]]\nid=\"a\"\ntitle=\"t\"\nprotocol=\"multiboot\"\nkernel=\"k\"\n");
        assert!(e.msg.contains("protocol"), "{}", e.msg);
    }

    #[test]
    fn rejects_wrong_type() {
        let e = err("[global]\ntimeout = \"three\"\ndefault=\"a\"\n[[entry]]\nid=\"a\"\ntitle=\"t\"\nprotocol=\"linux-efi\"\nkernel=\"k\"\n");
        assert!(e.msg.contains("expects an integer"), "{}", e.msg);
    }

    #[test]
    fn rejects_negative_timeout() {
        let e = err("[global]\ntimeout = -1\ndefault=\"a\"\n[[entry]]\nid=\"a\"\ntitle=\"t\"\nprotocol=\"linux-efi\"\nkernel=\"k\"\n");
        assert!(e.msg.contains("out of range"), "{}", e.msg);
    }

    #[test]
    fn rejects_missing_required_field() {
        let e = err("[[entry]]\nid=\"a\"\ntitle=\"t\"\nprotocol=\"linux-efi\"\n"); // no kernel
        assert!(e.msg.contains("missing `kernel`"), "{}", e.msg);
    }

    #[test]
    fn rejects_no_entries() {
        let e = err("[global]\ntimeout=1\ndefault=\"x\"\n");
        assert!(e.msg.contains("no [[entry]]"), "{}", e.msg);
    }

    #[test]
    fn rejects_default_pointing_nowhere() {
        let e = err("[global]\ndefault=\"ghost\"\n[[entry]]\nid=\"real\"\ntitle=\"t\"\nprotocol=\"linux-efi\"\nkernel=\"k\"\n");
        assert!(e.msg.contains("matches no entry"), "{}", e.msg);
    }

    #[test]
    fn rejects_duplicate_ids() {
        let e = err("[[entry]]\nid=\"x\"\ntitle=\"t\"\nprotocol=\"linux-efi\"\nkernel=\"k\"\n[[entry]]\nid=\"x\"\ntitle=\"t2\"\nprotocol=\"linux-efi\"\nkernel=\"k2\"\n");
        assert!(e.msg.contains("duplicate entry id"), "{}", e.msg);
    }

    #[test]
    fn rejects_key_before_table() {
        let e = err("foo = 1\n[global]\n");
        assert_eq!(e.line, 1);
        assert!(e.msg.contains("before any"), "{}", e.msg);
    }

    #[test]
    fn rejects_trailing_junk() {
        let e = err("[global]\ntimeout = 3 5\ndefault=\"a\"\n[[entry]]\nid=\"a\"\ntitle=\"t\"\nprotocol=\"linux-efi\"\nkernel=\"k\"\n");
        assert!(e.msg.contains("trailing characters"), "{}", e.msg);
    }

    #[test]
    fn empty_input_is_error_not_panic() {
        let e = err("");
        assert!(e.msg.contains("no [[entry]]"), "{}", e.msg);
    }

    #[test]
    fn crlf_line_endings_ok() {
        let c = parse("[[entry]]\r\nid=\"a\"\r\ntitle=\"t\"\r\nprotocol=\"linux-efi\"\r\nkernel=\"k\"\r\n").unwrap();
        assert_eq!(c.entries[0].id, "a");
    }

    #[test]
    fn rejects_raw_control_char_in_string() {
        // A bare ESC (0x1B) embedded in a title — the menu-spoofing vector.
        let e = err("[[entry]]\nid=\"a\"\ntitle=\"x\u{1b}[2Jy\"\nprotocol=\"linux-efi\"\nkernel=\"k\"\n");
        assert!(e.msg.contains("control character"), "{}", e.msg);
    }

    #[test]
    fn rejects_duplicate_key() {
        let e = err("[[entry]]\nid=\"a\"\ntitle=\"t\"\nprotocol=\"linux-efi\"\nkernel=\"good\"\nkernel=\"evil\"\n");
        assert!(e.msg.contains("duplicate key"), "{}", e.msg);
    }

    #[test]
    fn rejects_duplicate_global_table() {
        let e = err("[global]\ntimeout=1\n[global]\ntimeout=2\n[[entry]]\nid=\"a\"\ntitle=\"t\"\nprotocol=\"linux-efi\"\nkernel=\"k\"\n");
        assert!(e.msg.contains("duplicate table `[global]`"), "{}", e.msg);
    }

    #[test]
    fn rejects_leading_zero_and_bad_underscores() {
        for bad in ["0755", "1_", "1__0", "_5"] {
            let src = alloc::format!(
                "[global]\ntimeout = {bad}\n[[entry]]\nid=\"a\"\ntitle=\"t\"\nprotocol=\"linux-efi\"\nkernel=\"k\"\n"
            );
            assert!(parse(&src).is_err(), "expected `{bad}` to be rejected");
        }
        // A plain zero is still fine (timeout = 0 == wait forever).
        assert!(parse("[global]\ntimeout = 0\n[[entry]]\nid=\"a\"\ntitle=\"t\"\nprotocol=\"linux-efi\"\nkernel=\"k\"\n").is_ok());
    }
}
