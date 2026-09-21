use anyhow::{bail, Context, Result};
use serde::{Serialize,Deserialize};
use std::time::Duration;

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn label(&self) -> &'static str {
        match self {
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum EventKind {
    Exec,
    Write,
    Connect,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Field {
    Path,
    Basename,
    AncestryPath,
    AncestryBasename,
    Uid,
    DstIp,
    DstPort,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    Prefix,
    Suffix,
    Contains,
    Exact,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Condition {
    pub field: Field,
    pub op: Op,
    pub values: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Match {
    #[serde(default)]
    pub all: Vec<Condition>,
    #[serde(default)]
    pub any: Vec<Condition>,
    #[serde(default)]
    pub not: Vec<Condition>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Correlate {
    pub after: String,
    pub within: String,
    #[serde(default)]
    pub same_process: bool,
}

impl Correlate {
    pub fn window(&self) -> Result<Duration> {
        let s = self.within.trim();
        let (num, unit) = s.split_at(
            s.find(|c: char| !c.is_ascii_digit())
                .with_context(|| format!("bad duration {s:?}"))?,
        );
        let n: u64 = num.parse().with_context(|| format!("bad duration {s:?}"))?;
        Ok(match unit {
            "s" => Duration::from_secs(n),
            "m" => Duration::from_secs(n * 60),
            "ms" => Duration::from_millis(n),
            other => bail!("unknown duration unit {other:?} in {s:?}"),
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Rule {
    pub id: String,
    pub severity: Severity,
    #[serde(default)]
    pub attack: Vec<String>,
    pub on: EventKind,
    #[serde(default)]
    pub r#match: Match,
    #[serde(default)]
    pub correlate: Option<Correlate>,
    pub message: String,
}

#[derive(Debug, Deserialize)]
struct RuleFile {
    rule: Vec<Rule>,
}

pub fn load(path: &str) -> Result<Vec<Rule>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading rules from {path}"))?;
    let parsed: RuleFile =
        toml::from_str(&text).with_context(|| format!("parsing {path}"))?;

    for r in &parsed.rule {
        if let Some(c) = &r.correlate {
            c.window()
                .with_context(|| format!("rule {}", r.id))?;
            if !parsed.rule.iter().any(|other| other.id == c.after) {
                bail!("rule {} correlates after unknown rule {}", r.id, c.after);
            }
        }
    }

    Ok(parsed.rule)
}
pub struct EventFacts<'a> {
    pub kind: EventKind,
    pub path: &'a str,
    pub ancestry: &'a [String],
    pub uid: u32,
    pub dst_ip: &'a str,
    pub dst_port: u16,
}

impl<'a> EventFacts<'a> {
    fn basename(&self) -> &str {
        self.path.rsplit('/').next().unwrap_or(self.path)
    }
}

fn matches_str(op: Op, haystack: &str, needle: &str) -> bool {
    match op {
        Op::Prefix => haystack.starts_with(needle),
        Op::Suffix => haystack.ends_with(needle),
        Op::Contains => haystack.contains(needle),
        Op::Exact => haystack == needle,
    }
}

impl Condition {
    fn eval(&self, facts: &EventFacts) -> bool {
        match self.field {
            Field::Path => self
                .values
                .iter()
                .any(|v| matches_str(self.op, facts.path, v)),
            Field::Basename => self
                .values
                .iter()
                .any(|v| matches_str(self.op, facts.basename(), v)),
            Field::AncestryPath => facts.ancestry.iter().any(|a| {
                self.values.iter().any(|v| matches_str(self.op, a, v))
            }),
            Field::AncestryBasename => facts.ancestry.iter().any(|a| {
                let base = a.rsplit('/').next().unwrap_or(a);
                self.values.iter().any(|v| matches_str(self.op, base, v))
            }),
            Field::Uid => {
                let uid = facts.uid.to_string();
                self.values.iter().any(|v| matches_str(self.op, &uid, v))
            }
            Field::DstIp => self
                .values
                .iter()
                .any(|v| matches_str(self.op, facts.dst_ip, v)),
            Field::DstPort => {
                let port = facts.dst_port.to_string();
                self.values.iter().any(|v| matches_str(self.op, &port, v))
            }
        }
    }
}

impl Match {
    fn eval(&self, facts: &EventFacts) -> bool {
        if !self.all.iter().all(|c| c.eval(facts)) {
            return false;
        }
        if !self.any.is_empty() && !self.any.iter().any(|c| c.eval(facts)) {
            return false;
        }
        if self.not.iter().any(|c| c.eval(facts)) {
            return false;
        }
        true
    }
}

impl Rule {
    pub fn matches(&self, facts: &EventFacts) -> bool {
        self.on == facts.kind && self.r#match.eval(facts)
    }

    pub fn render(&self, facts: &EventFacts, extra: &[(&str, String)]) -> String {
        let mut out = self
            .message
            .replace("{path}", facts.path)
            .replace("{basename}", facts.basename())
            .replace("{uid}", &facts.uid.to_string())
            .replace("{dst_ip}", facts.dst_ip)
            .replace("{dst_port}", &facts.dst_port.to_string());
        for (k, v) in extra {
            out = out.replace(&format!("{{{k}}}"), v);
        }
        out
    }
}
