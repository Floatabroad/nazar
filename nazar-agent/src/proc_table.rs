use std::collections::{HashMap, HashSet};
use std::time::Instant;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ProcKey {
    pub tgid: u32,
    pub start_time: u64,
}

#[derive(Debug)]
pub struct ProcNode {
    pub key: ProcKey,
    pub parent: Option<ProcKey>,
    pub exe: String,
    pub argv: Vec<String>,
    pub comm: String,
    pub uid: u32,
    pub exited_at: Option<Instant>,
    pub children: HashSet<ProcKey>,
}

impl ProcNode {
    fn new(key: ProcKey) -> Self {
        ProcNode {
            key,
            parent: None,
            exe: String::new(),
            argv: Vec::new(),
            comm: String::new(),
            uid: 0,
            exited_at: None,
            children: HashSet::new(),
        }
    }
}

pub struct ProcTable {
    nodes: HashMap<ProcKey, ProcNode>,
    pending_parent: HashMap<u32, u32>,
    by_tgid: HashMap<u32, ProcKey>,
}

impl ProcTable {
    pub fn new() -> Self {
        ProcTable {
            nodes: HashMap::new(),
            pending_parent: HashMap::new(),
            by_tgid: HashMap::new(),
        }
    }

    pub fn on_fork(&mut self, parent_tgid: u32, _parent_start: u64, child_tgid: u32) {
        let child_key = ProcKey { tgid: child_tgid, start_time: 0 };
        let mut node = ProcNode::new(child_key);

        if let Some(&parent_key) = self.by_tgid.get(&parent_tgid) {
            node.parent = Some(parent_key);
            if let Some(parent) = self.nodes.get_mut(&parent_key) {
                parent.children.insert(child_key);
            }
        }


        if let Some(parent) = node.parent.and_then(|k| self.nodes.get(&k)) {
            node.comm = parent.comm.clone();
            node.exe = parent.exe.clone();
        }

        self.nodes.insert(child_key, node);
        self.by_tgid.insert(child_tgid, child_key);
    }

           fn ensure(&mut self, key: ProcKey) -> &mut ProcNode {
        if self.nodes.contains_key(&key) {
            return self.nodes.get_mut(&key).unwrap();
        }


        let placeholder = ProcKey { tgid: key.tgid, start_time: 0 };
        if key.start_time != 0 {
            if let Some(mut node) = self.nodes.remove(&placeholder) {
                if let Some(pk) = node.parent {
                    if let Some(parent) = self.nodes.get_mut(&pk) {
                        parent.children.remove(&placeholder);
                        parent.children.insert(key);
                    }
                }

                let children: Vec<ProcKey> = node.children.iter().copied().collect();
                for ck in children {
                    if let Some(child) = self.nodes.get_mut(&ck) {
                        child.parent = Some(key);
                    }
                }
                node.key = key;
                self.nodes.insert(key, node);
                self.by_tgid.insert(key.tgid, key);
                return self.nodes.get_mut(&key).unwrap();
            }
        }


        let mut node = ProcNode::new(key);
        if let Some(ptgid) = self.pending_parent.remove(&key.tgid) {
            if let Some(&parent_key) = self.by_tgid.get(&ptgid) {
                node.parent = Some(parent_key);
                if let Some(parent) = self.nodes.get_mut(&parent_key) {
                    parent.children.insert(key);
                }
            }
        }
        self.nodes.insert(key, node);
        self.by_tgid.insert(key.tgid, key);
        self.nodes.get_mut(&key).unwrap()
    }

    pub fn on_exec(&mut self, key: ProcKey, comm: &str, uid: u32, argv: Vec<String>) {
        let node = self.ensure(key);
        node.comm = comm.to_string();
        node.uid = uid;
        node.argv = argv;
    }

    pub fn on_proc_exec(&mut self, key: ProcKey, exe: &str) {
        let node = self.ensure(key);
        node.exe = exe.to_string();
    }

       pub fn on_exit(&mut self, key: ProcKey, group_dead: bool) {
        if !group_dead {
            return;
        }
        let target = if self.nodes.contains_key(&key) {
            key
        } else {
            ProcKey { tgid: key.tgid, start_time: 0 }
        };
        if let Some(node) = self.nodes.get_mut(&target) {
            node.exited_at = Some(Instant::now());
        }
        self.by_tgid.remove(&key.tgid);
    }

    pub fn resolve(&self, key: &ProcKey) -> Option<&ProcNode> {
        if let Some(node) = self.nodes.get(key) {
            return Some(node);
        }
        let alt = self.by_tgid.get(&key.tgid)?;
        self.nodes.get(alt)
    }

    
       pub fn ancestry(&self, key: ProcKey) -> Vec<&ProcNode> {
        let mut out = Vec::new();
        let start = self.resolve(&key).and_then(|n| n.parent);
        let mut cur = start;
        while let Some(k) = cur {
            match self.nodes.get(&k) {
                Some(node) => {
                    out.push(node);
                    cur = node.parent;
                }
                None => break,
            }
        }
        out
    }

    pub fn get(&self, key: &ProcKey) -> Option<&ProcNode> {
        self.nodes.get(key)
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn reap(&mut self, grace: std::time::Duration) {
        let now = Instant::now();
        let dead: Vec<ProcKey> = self
            .nodes
            .values()
            .filter(|n| {
                n.exited_at.map(|t| now.duration_since(t) > grace).unwrap_or(false)
                    && n.children.is_empty()
            })
            .map(|n| n.key)
            .collect();

        for key in dead {
            if let Some(node) = self.nodes.remove(&key) {
                if let Some(pk) = node.parent {
                    if let Some(parent) = self.nodes.get_mut(&pk) {
                        parent.children.remove(&key);
                    }
                }
            }
        }
    }
    pub fn seed(&mut self, procs: Vec<crate::procfs::ProcInfo>) {
        for p in &procs {
            let key = ProcKey { tgid: p.tgid, start_time: p.start_time_ns };
            let mut node = ProcNode::new(key);
            node.comm = p.comm.clone();
            node.exe = p.exe.clone();
            node.argv = p.argv.clone();
            node.uid = p.uid;
            self.nodes.insert(key, node);
            self.by_tgid.insert(p.tgid, key);
        }

        for p in &procs {
            let Some(&child_key) = self.by_tgid.get(&p.tgid) else { continue };
            let Some(&parent_key) = self.by_tgid.get(&p.ppid) else { continue };
            if let Some(node) = self.nodes.get_mut(&child_key) {
                node.parent = Some(parent_key);
            }
            if let Some(parent) = self.nodes.get_mut(&parent_key) {
                parent.children.insert(child_key);
            }
        }
    }
}
