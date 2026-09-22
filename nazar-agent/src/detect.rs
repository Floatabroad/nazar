use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use anyhow::Result;
use serde::Serialize;

use crate::{
    proc_table::{ProcKey, ProcTable},
    rules::{Correlate, EventFacts, EventKind, Rule, Severity},
};

#[derive(Debug, Serialize)]
pub struct Alert {
    pub timestamp_ms: u64,
    pub rule_id: String,
    pub severity: Severity,
    pub attack: Vec<String>,
    pub message: String,
    pub ancestry: Vec<String>,
}

impl Alert {
    pub fn render(&self) -> String {
        let chain = if self.ancestry.is_empty() {
            "?".to_string()
        } else {
            self.ancestry.join(" <- ")
        };
        format!(
            "[{}] {} ({}) {}\n    chain: {}",
            self.severity.label(),
            self.rule_id,
            self.attack.join(","),
            self.message,
            chain
        )
    }
    pub fn to_json(&self) -> String {
        serde_json::to_string(self)
            .unwrap_or_else(|e| format!(r#"{{"error":"serialize failed: {e}"}}"#))
    }
}

struct PriorHit {
    rule_id: String,
    path: String,
    at: Instant,
}

pub struct Engine {
    rules: Vec<Rule>,

    windows: Vec<Option<Duration>>,

    history: HashMap<ProcKey, Vec<PriorHit>>,

    max_window: Duration,
}

impl Engine {
    pub fn load(path: &str) -> Result<Self> {
        let rules = crate::rules::load(path)?;
        let windows = rules
            .iter()
            .map(|r| r.correlate.as_ref().map(Correlate::window).transpose())
            .collect::<Result<Vec<Option<Duration>>>>()?;
        let max_window = windows
            .iter()
            .flatten()
            .copied()
            .max()
            .unwrap_or(Duration::from_secs(0));
        Ok(Engine {
            rules,
            windows,
            history: HashMap::new(),
            max_window,
        })
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    fn find_prior(
        &self,
        key: ProcKey,
        after: &str,
        window: Duration,
        same_process: bool,
    ) -> Option<&PriorHit> {
        if same_process {
            self.history
                .get(&key)?
                .iter()
                .rev()
                .find(|h| h.rule_id == after && h.at.elapsed() < window)
        } else {
            self.history
                .values()
                .filter_map(|hits| {
                    hits.iter()
                        .rev()
                        .find(|h| h.rule_id == after && h.at.elapsed() < window)
                })
                .max_by_key(|h| h.at)
        }
    }

    fn chain(table: &ProcTable, key: ProcKey) -> Vec<String> {
        table
            .ancestry(key)
            .iter()
            .map(|n| {
                if n.exe.is_empty() {
                    n.comm.clone()
                } else {
                    n.exe.clone()
                }
            })
            .collect()
    }

    fn evaluate(
        &mut self,
        table: &ProcTable,
        key: ProcKey,
        kind: EventKind,
        path: &str,
        dst_ip: &str,
        dst_port: u16,
    ) -> Option<Alert> {
        let ancestry = Self::chain(table, key);
        let node = table.resolve(&key);
        let actor = node
            .map(|n| {
                if n.exe.is_empty() {
                    n.comm.clone()
                } else {
                    n.exe.clone()
                }
            })
            .unwrap_or_default();
        let uid = node.map(|n| n.uid).unwrap_or(0);
        let argv: &[String] = node.map(|n| n.argv.as_slice()).unwrap_or(&[]);

        let facts = EventFacts {
            kind,
            path,
            ancestry: &ancestry,
            argv,
            uid,
            dst_ip,
            dst_port,
        };

        let matched: Vec<usize> = self
            .rules
            .iter()
            .enumerate()
            .filter(|(_, rule)| rule.matches(&facts))
            .map(|(idx, _)| idx)
            .collect();

        let mut fired: Option<(usize, Vec<(&'static str, String)>)> = None;

        for &idx in &matched {
            let rule = &self.rules[idx];
            let mut extra: Vec<(&'static str, String)> = vec![("actor", actor.clone())];

            if let Some(c) = &rule.correlate {
                let window = self.windows[idx].unwrap_or(Duration::from_secs(0));
                match self.find_prior(key, &c.after, window, c.same_process) {
                    Some(h) => {
                        extra.push(("prior_path", h.path.clone()));
                        extra.push(("delay", format!("{:.1}s", h.at.elapsed().as_secs_f64())));
                    }
                    None => continue,
                }
            }

            fired = Some((idx, extra));
            break;
        }

        let now = Instant::now();
        let ids: Vec<String> = matched.iter().map(|&i| self.rules[i].id.clone()).collect();
        let hits = self.history.entry(key).or_default();
        for id in ids {
            hits.push(PriorHit {
                rule_id: id,
                path: path.to_string(),
                at: now,
            });
        }

        let (idx, extra) = fired?;
        let rule = &self.rules[idx];
        let message = rule.render(&facts, &extra);

        Some(Alert {
            timestamp_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
            rule_id: rule.id.clone(),
            severity: rule.severity,
            attack: rule.attack.clone(),
            message,
            ancestry,
        })
    }

    pub fn on_exec(&mut self, table: &ProcTable, key: ProcKey, path: &str) -> Option<Alert> {
        self.evaluate(table, key, EventKind::Exec, path, "", 0)
    }

    pub fn on_write(&mut self, table: &ProcTable, key: ProcKey, path: &str) -> Option<Alert> {
        self.evaluate(table, key, EventKind::Write, path, "", 0)
    }

    pub fn on_connect(
        &mut self,
        table: &ProcTable,
        key: ProcKey,
        dst_ip: &str,
        dst_port: u16,
    ) -> Option<Alert> {
        let path = table
            .resolve(&key)
            .map(|n| n.exe.clone())
            .unwrap_or_default();
        self.evaluate(table, key, EventKind::Connect, &path, dst_ip, dst_port)
    }

    pub fn expire(&mut self) {
        let max = self.max_window;
        self.history.retain(|_, hits| {
            hits.retain(|h| h.at.elapsed() < max);
            !hits.is_empty()
        });
    }
}
