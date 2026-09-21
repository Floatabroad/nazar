use crate::proc_table::{ProcKey, ProcTable};
use crate::rules::{EventFacts, EventKind, Rule, Severity};
use anyhow::Result;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use serde::Serialize;

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
        serde_json::to_string(self).unwrap_or_else(|e| {
            format!(r#"{{"error":"serialize failed: {e}"}}"#)
        })
    }
}

struct PriorHit {
    rule_id: String,
    path: String,
    at: Instant,
}

pub struct Engine {
    rules: Vec<Rule>,

    history: HashMap<ProcKey, Vec<PriorHit>>,

    max_window: Duration,
}

impl Engine {
    pub fn load(path: &str) -> Result<Self> {
        let rules = crate::rules::load(path)?;
        let max_window = rules
            .iter()
            .filter_map(|r| r.correlate.as_ref())
            .filter_map(|c| c.window().ok())
            .max()
            .unwrap_or(Duration::from_secs(0));
        Ok(Engine {
            rules,
            history: HashMap::new(),
            max_window,
        })
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    fn chain(table: &ProcTable, key: ProcKey) -> Vec<String> {
        table
            .ancestry(key)
            .iter()
            .map(|n| if n.exe.is_empty() { n.comm.clone() } else { n.exe.clone() })
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
        let actor = table
            .resolve(&key)
            .map(|n| if n.exe.is_empty() { n.comm.clone() } else { n.exe.clone() })
            .unwrap_or_default();
        let uid = table.resolve(&key).map(|n| n.uid).unwrap_or(0);

        let facts = EventFacts {
            kind,
            path,
            ancestry: &ancestry,
            uid,
            dst_ip,
            dst_port,
        };

        let mut fired: Option<(usize, Vec<(&'static str, String)>)> = None;

        for (idx, rule) in self.rules.iter().enumerate() {
            if !rule.matches(&facts) {
                continue;
            }

            let mut extra: Vec<(&'static str, String)> =
                vec![("actor", actor.clone())];


            if let Some(c) = &rule.correlate {
                let window = c.window().unwrap_or(Duration::from_secs(0));
                let prior = self
                    .history
                    .get(&key)
                    .and_then(|hits| {
                        hits.iter()
                            .rev()
                            .find(|h| h.rule_id == c.after && h.at.elapsed() < window)
                    });
                match prior {
                    Some(h) => {
                        extra.push(("prior_path", h.path.clone()));
                        extra.push((
                            "delay",
                            format!("{:.1}s", h.at.elapsed().as_secs_f64()),
                        ));
                    }
                    None => continue,
                }
            }

            fired = Some((idx, extra));
            break;
        }

        let (idx, extra) = fired?;
        let rule = &self.rules[idx];
        let message = rule.render(&facts, &extra);


        self.history.entry(key).or_default().push(PriorHit {
            rule_id: rule.id.clone(),
            path: path.to_string(),
            at: Instant::now(),
        });

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
