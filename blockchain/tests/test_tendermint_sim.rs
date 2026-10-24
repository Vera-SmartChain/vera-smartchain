//! Randomized network simulation of the Tendermint state machine (`vera_blockchain::tendermint`).
//!
//! Each run: N validators (some Byzantine, total Byzantine power < 1/3), a network that
//! drops, delays and reorders messages until GST and is timely afterwards, periodic
//! gossip (the paper's reliable-gossip assumption), and decision certificates for nodes
//! that fall behind. Checked on EVERY run:
//!   - Agreement: no two honest nodes decide different values at the same height.
//!   - Termination: after GST, every honest node decides `TARGET` heights.
//! Byzantine nodes equivocate: two proposals when they are proposer, votes for every
//! value they see (different ones to different peers), nil votes and future-round votes.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::sync::Arc;
use vera_blockchain::tendermint::*;

#[derive(Clone, Debug, PartialEq)]
struct Val {
    id: ValueId,
}
impl Value for Val {
    fn id(&self) -> ValueId {
        self.id
    }
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        // splitmix64
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
    fn chance(&mut self, p: f64) -> bool {
        (self.next() as f64 / u64::MAX as f64) < p
    }
}

fn mix(x: u64) -> u64 {
    Rng(x).next()
}

fn node_id(i: usize) -> NodeId {
    [i as u8 + 1; 32]
}

fn value_id(h: u64, r: u64, proposer: usize, nonce: u64) -> ValueId {
    let mut id = [0u8; 32];
    id[..8].copy_from_slice(&h.to_le_bytes());
    id[8..16].copy_from_slice(&r.to_le_bytes());
    id[16] = proposer as u8;
    id[17..25].copy_from_slice(&nonce.to_le_bytes());
    id[31] = 0xAB;
    id
}

#[derive(Clone, Debug)]
enum Msg {
    Proposal { h: u64, r: u64, v: Val, vr: Option<u64>, from: usize },
    Vote { kind: VoteKind, h: u64, r: u64, id: Option<ValueId>, from: usize },
    /// Catch-up certificate (stands in for block sync): value decided at h.
    Decision { h: u64, v: Val },
}

impl Msg {
    fn height(&self) -> u64 {
        match self {
            Msg::Proposal { h, .. } | Msg::Vote { h, .. } | Msg::Decision { h, .. } => *h,
        }
    }
}

enum Ev {
    Deliver { to: usize, msg: Msg },
    Timeout { node: usize, kind: TimeoutKind, h: u64, r: u64 },
    GetValue { node: usize, h: u64, r: u64 },
    Gossip { node: usize },
    ByzTick { node: usize },
}

struct Honest {
    sm: Tendermint<Val, ()>,
    height: u64,
    sent: Vec<Msg>,
    /// Everything received for the current height: relayed by gossip, as real nodes do
    /// (the paper's liveness proof assumes correct nodes relay what they receive).
    relay: Vec<Msg>,
    relay_keys: HashSet<String>,
    future: Vec<Msg>,
    certs: Vec<Msg>,
}

#[derive(Default)]
struct Byz {
    max_h: u64,
    max_r: u64,
    proposed: HashSet<(u64, u64)>,
    voted: HashSet<(u64, u64, ValueId)>,
    /// Values seen proposed at (height, round): re-proposed later with that old round
    /// as valid_round, to attack the lock rule of L28.
    seen: Vec<(u64, u64, Val)>,
}

struct Cfg {
    weights: Vec<u128>,
    byz: Vec<usize>,
    p_drop: f64,
    max_delay_pre: u64,
    max_delay_post: u64,
    gst: u64,
    target: u64,
    t_end: u64,
    /// None = the paper's strict quorum (> 2/3); Some = VERA's on-chain ceil(2T/3).
    vera_quorum: bool,
    /// (node, from_ms, to_ms): an honest node that processes nothing in that window
    /// (paused VM / long GC); everything addressed to it waits until it wakes up.
    sleep: Option<(usize, u64, u64)>,
}

struct Sim {
    cfg: Cfg,
    rng: Rng,
    now: u64,
    seq: u64,
    queue: BinaryHeap<(Reverse<u64>, Reverse<u64>, usize)>,
    events: Vec<Option<Ev>>,
    honest: HashMap<usize, Honest>,
    byz: HashMap<usize, Byz>,
    proposer: ProposerFn,
    decided: HashMap<u64, ValueId>,
    decisions: HashMap<(usize, u64), ValueId>,
    violation: Option<String>,
    equivocations: u64,
    nonce: u64,
    max_round: u64,
}

impl Sim {
    fn new(cfg: Cfg, seed: u64) -> Self {
        let weights = cfg.weights.clone();
        let total: u128 = weights.iter().sum();
        // Stake-weighted pseudo-random proposer per (height, round).
        let proposer: ProposerFn = Arc::new(move |h, r| {
            let target = (mix(h.wrapping_mul(1_000_003) ^ r.wrapping_mul(7_919)) as u128) % total;
            let mut acc = 0u128;
            for (i, w) in weights.iter().enumerate() {
                acc += *w;
                if target < acc {
                    return node_id(i);
                }
            }
            node_id(weights.len() - 1)
        });
        let n = cfg.weights.len();
        let mut honest = HashMap::new();
        let mut byz = HashMap::new();
        for i in 0..n {
            if cfg.byz.contains(&i) {
                byz.insert(i, Byz::default());
            } else {
                honest.insert(i, Honest {
                    sm: Tendermint::new(Some(node_id(i)), proposer.clone()),
                    height: 1,
                    sent: Vec::new(),
                    relay: Vec::new(),
                    relay_keys: HashSet::new(),
                    future: Vec::new(),
                    certs: Vec::new(),
                });
            }
        }
        Sim {
            cfg,
            rng: Rng(seed.wrapping_mul(0x2545F4914F6CDD1D) ^ 0xC0FFEE),
            now: 0,
            seq: 0,
            queue: BinaryHeap::new(),
            events: Vec::new(),
            honest,
            byz,
            proposer,
            decided: HashMap::new(),
            decisions: HashMap::new(),
            violation: None,
            equivocations: 0,
            nonce: 0,
            max_round: 0,
        }
    }

    fn n(&self) -> usize {
        self.cfg.weights.len()
    }

    fn quorum(&self) -> u128 {
        let total: u128 = self.cfg.weights.iter().sum();
        if self.cfg.vera_quorum { (total * 2 + 2) / 3 } else { Tendermint::<Val, ()>::strict_quorum(total) }
    }

    fn validators(&self) -> Vec<(NodeId, u128)> {
        self.cfg.weights.iter().enumerate().map(|(i, w)| (node_id(i), *w)).collect()
    }

    fn index_of(id: &NodeId) -> usize {
        id[0] as usize - 1
    }

    fn schedule(&mut self, at: u64, ev: Ev) {
        self.seq += 1;
        self.events.push(Some(ev));
        self.queue.push((Reverse(at), Reverse(self.seq), self.events.len() - 1));
    }

    /// Network: before GST messages may be dropped and arrive late (in any order).
    fn send(&mut self, from: usize, to: usize, msg: Msg) {
        if from == to {
            self.schedule(self.now, Ev::Deliver { to, msg });
            return;
        }
        let pre = self.now < self.cfg.gst;
        if pre && self.rng.chance(self.cfg.p_drop) {
            return;
        }
        let max = if pre { self.cfg.max_delay_pre } else { self.cfg.max_delay_post };
        let d = 1 + self.rng.below(max);
        self.schedule(self.now + d, Ev::Deliver { to, msg });
    }

    fn broadcast(&mut self, from: usize, msg: Msg) {
        for to in 0..self.n() {
            self.send(from, to, msg.clone());
        }
    }

    fn timeout_ms(kind: TimeoutKind, r: u64) -> u64 {
        match kind {
            TimeoutKind::Propose => 300 + 200 * r,
            TimeoutKind::Prevote | TimeoutKind::Precommit => 200 + 100 * r,
        }
    }

    fn record_decision(&mut self, node: usize, h: u64, id: ValueId) {
        self.decisions.insert((node, h), id);
        match self.decided.get(&h) {
            Some(prev) if *prev != id => {
                self.violation.get_or_insert(format!(
                    "AGREEMENT VIOLATED at height {}: node {} decided {:02x?} but another honest node decided {:02x?}",
                    h, node, &id[..4], &prev[..4]
                ));
            }
            None => {
                self.decided.insert(h, id);
            }
            _ => {}
        }
    }

    fn exec(&mut self, node: usize, outs: Vec<Output<Val, ()>>) {
        for o in outs {
            match o {
                Output::GetValue { height, round } => {
                    self.schedule(self.now + 1, Ev::GetValue { node, h: height, r: round });
                }
                Output::Proposal { height, round, value, valid_round } => {
                    let msg = Msg::Proposal { h: height, r: round, v: value, vr: valid_round, from: node };
                    self.honest.get_mut(&node).unwrap().sent.push(msg.clone());
                    self.broadcast(node, msg);
                }
                Output::Vote { kind, height, round, id } => {
                    self.max_round = self.max_round.max(round);
                    let msg = Msg::Vote { kind, h: height, r: round, id, from: node };
                    self.honest.get_mut(&node).unwrap().sent.push(msg.clone());
                    self.broadcast(node, msg);
                }
                Output::ScheduleTimeout { kind, height, round } => {
                    let at = self.now + Self::timeout_ms(kind, round);
                    self.schedule(at, Ev::Timeout { node, kind, h: height, r: round });
                }
                Output::Decide { height, value, commits, .. } => {
                    let power: u128 = commits.iter().map(|(n, _)| self.cfg.weights[Self::index_of(n)]).sum();
                    assert!(power >= self.quorum(), "Decide without a quorum commit certificate");
                    self.decide_and_advance(node, height, value);
                }
                Output::Equivocation { .. } => self.equivocations += 1,
            }
        }
    }

    fn decide_and_advance(&mut self, node: usize, h: u64, value: Val) {
        self.record_decision(node, h, value.id());
        let cert = Msg::Decision { h, v: value };
        self.broadcast(node, cert.clone());
        let vals = self.validators();
        let (outs, replay) = {
            let st = self.honest.get_mut(&node).unwrap();
            st.certs.push(cert);
            if st.certs.len() > 3 {
                st.certs.remove(0);
            }
            st.height = h + 1;
            st.sent.clear();
            st.relay.clear();
            st.relay_keys.clear();
            let q = (self.cfg.vera_quorum, self.cfg.weights.iter().sum::<u128>());
            let quorum = if q.0 { (q.1 * 2 + 2) / 3 } else { Tendermint::<Val, ()>::strict_quorum(q.1) };
            let outs = st.sm.start_height(h + 1, vals, quorum);
            let (now_msgs, later): (Vec<Msg>, Vec<Msg>) =
                std::mem::take(&mut st.future).into_iter().partition(|m| m.height() == h + 1);
            st.future = later.into_iter().filter(|m| m.height() > h + 1).collect();
            (outs, now_msgs)
        };
        self.exec(node, outs);
        for m in replay {
            self.deliver_honest(node, m);
        }
    }

    fn deliver_honest(&mut self, node: usize, msg: Msg) {
        let height = self.honest[&node].height;
        let mh = msg.height();
        if mh < height {
            return;
        }
        if mh > height {
            let st = self.honest.get_mut(&node).unwrap();
            if st.future.len() < 20_000 {
                st.future.push(msg);
            }
            return;
        }
        if !matches!(msg, Msg::Decision { .. }) {
            let st = self.honest.get_mut(&node).unwrap();
            let key = format!("{:?}", msg);
            if st.relay_keys.insert(key) {
                st.relay.push(msg.clone());
            }
        }
        let outs = match msg {
            Msg::Decision { h, v } => {
                self.decide_and_advance(node, h, v);
                return;
            }
            Msg::Proposal { h, r, v, vr, from } => {
                self.honest.get_mut(&node).unwrap().sm.on_proposal(h, r, v, vr, node_id(from), true)
            }
            Msg::Vote { kind, h, r, id, from } => {
                self.honest.get_mut(&node).unwrap().sm.on_vote(kind, h, r, id, node_id(from), ())
            }
        };
        self.exec(node, outs);
    }

    fn byz_send_votes(&mut self, me: usize, h: u64, r: u64, id: Option<ValueId>) {
        for to in 0..self.n() {
            if self.rng.chance(0.7) {
                self.send(me, to, Msg::Vote { kind: VoteKind::Prevote, h, r, id, from: me });
            }
            if self.rng.chance(0.7) {
                self.send(me, to, Msg::Vote { kind: VoteKind::Precommit, h, r, id, from: me });
            }
        }
    }

    fn byz_maybe_propose(&mut self, me: usize, h: u64, r: u64) {
        if (self.proposer)(h, r) != node_id(me) || self.byz[&me].proposed.contains(&(h, r)) {
            return;
        }
        self.byz.get_mut(&me).unwrap().proposed.insert((h, r));
        let old: Vec<(u64, Val)> = self.byz[&me].seen.iter()
            .filter(|(sh, sr, _)| *sh == h && *sr < r)
            .map(|(_, sr, v)| (*sr, v.clone()))
            .collect();
        if !old.is_empty() && self.rng.chance(0.6) {
            // Re-propose an old value claiming its old round as valid_round, possibly
            // different old values to different peers.
            for to in 0..self.n() {
                let (vr, v) = old[self.rng.below(old.len() as u64) as usize].clone();
                self.send(me, to, Msg::Proposal { h, r, v, vr: Some(vr), from: me });
            }
            return;
        }
        self.nonce += 2;
        let a = Val { id: value_id(h, r, me, self.nonce) };
        let b = Val { id: value_id(h, r, me, self.nonce + 1) };
        for to in 0..self.n() {
            let v = if self.rng.chance(0.5) { a.clone() } else { b.clone() };
            self.send(me, to, Msg::Proposal { h, r, v, vr: None, from: me });
        }
    }

    fn deliver_byz(&mut self, me: usize, msg: Msg) {
        let (h, r) = match &msg {
            Msg::Proposal { h, r, .. } | Msg::Vote { h, r, .. } => (*h, *r),
            Msg::Decision { h, .. } => (*h + 1, 0),
        };
        {
            let b = self.byz.get_mut(&me).unwrap();
            if h > b.max_h {
                b.max_h = h;
                b.max_r = 0;
            }
            if h == b.max_h {
                b.max_r = b.max_r.max(r);
            }
        }
        self.byz_maybe_propose(me, h, r);
        if let Msg::Proposal { h, r, v, .. } = msg {
            let b = self.byz.get_mut(&me).unwrap();
            if !b.seen.iter().any(|(sh, sr, sv)| *sh == h && *sr == r && sv.id() == v.id()) && b.seen.len() < 64 {
                b.seen.push((h, r, v.clone()));
            }
            let key = (h, r, v.id());
            if self.byz.get_mut(&me).unwrap().voted.insert(key) {
                self.byz_send_votes(me, h, r, Some(v.id()));
            }
        }
    }

    fn handle(&mut self, ev: Ev) {
        if let Some((n, from, to)) = self.cfg.sleep {
            let target = match &ev {
                Ev::Deliver { to, .. } => Some(*to),
                Ev::Timeout { node, .. } | Ev::GetValue { node, .. } | Ev::Gossip { node } => Some(*node),
                Ev::ByzTick { .. } => None,
            };
            if target == Some(n) && self.now >= from && self.now < to {
                self.schedule(to, ev);
                return;
            }
        }
        match ev {
            Ev::Deliver { to, msg } => {
                if self.honest.contains_key(&to) {
                    self.deliver_honest(to, msg);
                } else {
                    self.deliver_byz(to, msg);
                }
            }
            Ev::Timeout { node, kind, h, r } => {
                let outs = self.honest.get_mut(&node).unwrap().sm.on_timeout(kind, h, r);
                self.exec(node, outs);
            }
            Ev::GetValue { node, h, r } => {
                self.nonce += 1;
                let v = Val { id: value_id(h, r, node, self.nonce) };
                let outs = self.honest.get_mut(&node).unwrap().sm.on_value(h, r, v);
                self.exec(node, outs);
            }
            Ev::Gossip { node } => {
                // Reliable gossip: re-send this height's messages and recent certificates.
                let msgs: Vec<Msg> = {
                    let st = &self.honest[&node];
                    st.sent.iter().chain(st.relay.iter()).chain(st.certs.iter()).cloned().collect()
                };
                for m in msgs {
                    self.broadcast(node, m);
                }
                self.schedule(self.now + 1000, Ev::Gossip { node });
            }
            Ev::ByzTick { node } => {
                // Nil votes and votes for future rounds, trying to drag honest nodes around.
                let (h, r) = (self.byz[&node].max_h.max(1), self.byz[&node].max_r);
                let rr = r + self.rng.below(3);
                self.byz_send_votes(node, h, rr, None);
                self.byz_maybe_propose(node, h, rr);
                let at = self.now + 150 + self.rng.below(300);
                self.schedule(at, Ev::ByzTick { node });
            }
        }
    }

    fn run(&mut self) -> Result<(), String> {
        let vals = self.validators();
        let quorum = self.quorum();
        let mut ids: Vec<usize> = self.honest.keys().copied().collect();
        ids.sort_unstable();
        for i in &ids {
            let outs = self.honest.get_mut(i).unwrap().sm.start_height(1, vals.clone(), quorum);
            self.exec(*i, outs);
            let at = 500 + self.rng.below(500);
            self.schedule(at, Ev::Gossip { node: *i });
        }
        let mut byz: Vec<usize> = self.byz.keys().copied().collect();
        byz.sort_unstable();
        for b in byz {
            self.schedule(100, Ev::ByzTick { node: b });
        }
        let mut steps: u64 = 0;
        while let Some((Reverse(at), _, idx)) = self.queue.pop() {
            if at > self.cfg.t_end {
                break;
            }
            self.now = at;
            let ev = self.events[idx].take().unwrap();
            self.handle(ev);
            steps += 1;
            if let Some(v) = &self.violation {
                return Err(v.clone());
            }
            if steps % 1024 == 0 && self.honest.values().all(|s| s.height > self.cfg.target) {
                return Ok(());
            }
            if steps > 30_000_000 {
                return Err("simulation step limit".into());
            }
        }
        let lagging: Vec<(usize, u64)> = self.honest.iter()
            .filter(|(_, s)| s.height <= self.cfg.target)
            .map(|(i, s)| (*i, s.height))
            .collect();
        if std::env::var("TM_DEBUG").is_ok() {
            let mut ids: Vec<&usize> = self.honest.keys().collect();
            ids.sort();
            for i in ids {
                let st = &self.honest[i];
                eprintln!("node {} h={} round={} step={:?} locked_round={:?} decided={} future={} relay={}",
                    i, st.height, st.sm.round(), st.sm.step(), st.sm.locked_round(), st.sm.is_decided(), st.future.len(), st.relay.len());
                if let Some(dbg) = st.sm.debug_round(st.sm.round()) { eprintln!("   {}", dbg); }
            }
        }
        if lagging.is_empty() {
            Ok(())
        } else {
            Err(format!("TERMINATION FAILED by t={} ms (GST {}): nodes still at heights {:?}", self.cfg.t_end, self.cfg.gst, lagging))
        }
    }
}

fn run_many(name: &str, seeds: std::ops::Range<u64>, make: impl Fn() -> Cfg) {
    let cfg = make();
    let total: u128 = cfg.weights.iter().sum();
    let byz_power: u128 = cfg.byz.iter().map(|i| cfg.weights[*i]).sum();
    let quorum = if cfg.vera_quorum { (total * 2 + 2) / 3 } else { total * 2 / 3 + 1 };
    assert!(2 * quorum - total > byz_power, "{}: quorums must overlap in more than the Byzantine power", name);
    let mut max_round = 0;
    let mut equivocations = 0;
    let count = seeds.end - seeds.start;
    for seed in seeds {
        let mut sim = Sim::new(make(), seed);
        if let Err(e) = sim.run() {
            panic!("{} seed {}: {}", name, seed, e);
        }
        max_round = max_round.max(sim.max_round);
        equivocations += sim.equivocations;
    }
    println!("{}: {} runs OK (max round reached {}, equivocations seen {})", name, count, max_round, equivocations);
}

fn seeds(default: u64) -> std::ops::Range<u64> {
    if let Ok(one) = std::env::var("TM_SEED") {
        let x: u64 = one.parse().unwrap();
        return x..x + 1;
    }
    let n = std::env::var("TM_SEEDS").ok().and_then(|s| s.parse().ok()).unwrap_or(default);
    0..n
}

#[test]
fn sim_4_validators_1_byzantine() {
    run_many("4 validators, 1 byzantine", seeds(400), || Cfg {
        weights: vec![1, 1, 1, 1],
        byz: vec![3],
        p_drop: 0.3,
        max_delay_pre: 2000,
        max_delay_post: 100,
        gst: 10_000,
        target: 5,
        t_end: 90_000,
        vera_quorum: false,
        sleep: None,
    });
}

#[test]
fn sim_7_validators_2_byzantine() {
    run_many("7 validators, 2 byzantine", seeds(150), || Cfg {
        weights: vec![1; 7],
        byz: vec![2, 5],
        p_drop: 0.3,
        max_delay_pre: 2000,
        max_delay_post: 100,
        gst: 10_000,
        target: 4,
        t_end: 90_000,
        vera_quorum: false,
        sleep: None,
    });
}

#[test]
fn sim_4_honest_heavy_loss() {
    run_many("4 honest, 60% loss before GST", seeds(300), || Cfg {
        weights: vec![1, 1, 1, 1],
        byz: vec![],
        p_drop: 0.6,
        max_delay_pre: 3000,
        max_delay_post: 100,
        gst: 15_000,
        target: 5,
        t_end: 90_000,
        vera_quorum: false,
        sleep: None,
    });
}

#[test]
fn sim_unequal_stake_byzantine_quarter() {
    run_many("stake 40/25/15/10/10, byzantine = 25%", seeds(200), || Cfg {
        weights: vec![40, 25, 15, 10, 10],
        byz: vec![1],
        p_drop: 0.3,
        max_delay_pre: 2000,
        max_delay_post: 100,
        gst: 10_000,
        target: 4,
        t_end: 90_000,
        vera_quorum: false,
        sleep: None,
    });
}

#[test]
fn sim_vera_quorum_6_validators_1_byzantine() {
    // VERA's on-chain rule ceil(2T/3): 4 of 6. Overlap 2·4−6 = 2 > 1 Byzantine.
    run_many("6 validators, VERA quorum 4/6, 1 byzantine", seeds(300), || Cfg {
        weights: vec![1; 6],
        byz: vec![4],
        p_drop: 0.3,
        max_delay_pre: 2000,
        max_delay_post: 100,
        gst: 10_000,
        target: 4,
        t_end: 90_000,
        vera_quorum: true,
        sleep: None,
    });
}

#[test]
fn sim_vera_quorum_3_honest_like_testnet() {
    // Today's testnet: 3 equal validators, VERA quorum 2 of 3 (crash-tolerant only).
    run_many("3 honest validators, VERA quorum 2/3", seeds(300), || Cfg {
        weights: vec![32, 32, 32],
        byz: vec![],
        p_drop: 0.4,
        max_delay_pre: 2000,
        max_delay_post: 100,
        gst: 10_000,
        target: 5,
        t_end: 90_000,
        vera_quorum: true,
        sleep: None,
    });
}

#[test]
fn sim_honest_node_sleeps_while_others_advance_rounds() {
    // 7 validators, 2 Byzantine, 1 honest asleep from 1 s to 45 s: the 4 awake honest
    // validators alone are no quorum (5 of 7), so rounds keep failing and growing. On
    // waking, the sleeper is far behind in rounds; L55 (f+1 messages from a higher
    // round) is what pulls it straight to the others' round.
    run_many("7 validators, 2 byzantine, 1 honest asleep 44 s", seeds(150), || Cfg {
        weights: vec![1; 7],
        byz: vec![2, 5],
        p_drop: 0.1,
        max_delay_pre: 500,
        max_delay_post: 100,
        gst: 5_000,
        target: 3,
        t_end: 75_000,
        vera_quorum: false,
        sleep: Some((6, 1_000, 45_000)),
    });
}
