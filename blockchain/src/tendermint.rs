//! Tendermint BFT consensus as a pure state machine (no I/O, no clock, no crypto).
//!
//! Literal implementation of Algorithm 1 of Buchman, Kwon & Milosevic,
//! "The latest gossip on BFT consensus" (arXiv:1807.04938). Every rule is tagged with
//! the line of the paper's pseudocode it implements ("L22", "L36", ...).
//!
//! Contract with the host (the node):
//! - It verifies signatures, and checks that a proposal's value is valid, BEFORE calling
//!   `on_proposal` / `on_vote`. Validity is passed in as `valid`.
//! - It executes every returned `Output`: signs and broadcasts proposals and votes,
//!   arms timers, builds a value on `GetValue`, and applies the block on `Decide`.
//! - Its own proposals and votes go through `on_proposal` / `on_vote` like everybody
//!   else's (gossip to self), so they count towards quorums and commit certificates.
//! - After `Decide` it applies the block and calls `start_height(h + 1, ...)`.
//!   Messages for a future height must be buffered and replayed after that call.
//!
//! Voting power: the paper's "2f+1" is a QUORUM of power and its "f+1" is "more power
//! than the total minus a quorum" (some honest validator is guaranteed in it). The host
//! passes the quorum to `start_height`: the paper's choice is "more than 2/3 of the
//! total" (`strict_quorum`); VERA passes its on-chain `supermajority_threshold()` so the
//! engine decides exactly when a block's commit certificate is valid on chain.
//! Safety needs two quorums to overlap in more than the Byzantine power:
//! 2·quorum − total > byzantine power.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

pub type ValueId = [u8; 32];
pub type NodeId = [u8; 32];

/// A proposable value (a block). `id()` is what validators vote on (the block hash).
pub trait Value: Clone {
    fn id(&self) -> ValueId;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Step {
    Propose,
    Prevote,
    Precommit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VoteKind {
    Prevote,
    Precommit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TimeoutKind {
    Propose,
    Prevote,
    Precommit,
}

/// Effects the host must execute.
#[derive(Clone, Debug, PartialEq)]
pub enum Output<V, S> {
    /// Build a value for (height, round) and pass it to `on_value`.
    GetValue { height: u64, round: u64 },
    /// Sign and broadcast ⟨PROPOSAL, height, round, value, valid_round⟩.
    Proposal { height: u64, round: u64, value: V, valid_round: Option<u64> },
    /// Sign and broadcast ⟨PREVOTE|PRECOMMIT, height, round, id⟩ (`None` = nil).
    Vote { kind: VoteKind, height: u64, round: u64, id: Option<ValueId> },
    /// Arm a timer; call `on_timeout` when it fires. The duration must grow with the
    /// round (the paper's timeoutX(round)), or the protocol may never terminate.
    ScheduleTimeout { kind: TimeoutKind, height: u64, round: u64 },
    /// `value` is decided at `height`. `commits` are the >2/3 precommits that decided
    /// it (the commit certificate).
    Decide { height: u64, round: u64, value: V, commits: Vec<(NodeId, S)> },
    /// `from` sent two different messages of the same kind for one (height, round).
    /// Only the first one is used; this is evidence for slashing.
    Equivocation { height: u64, round: u64, from: NodeId },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum OnceRule {
    L34,
    L36,
    L47,
}

struct StoredProposal<V> {
    value: V,
    valid_round: Option<u64>,
    valid: bool,
}

pub type ProposerFn = Arc<dyn Fn(u64, u64) -> NodeId + Send + Sync>;

/// Votes of one kind for one round: every DISTINCT vote a validator sent. An honest
/// validator sends one; a Byzantine one may send several. The paper counts every
/// message, so a conflicting vote counts towards the tally of the value it names:
/// keeping only the first one would let an equivocator show different honest nodes
/// different polkas and stall the network (CometBFT solves the same case with its
/// "peer claims +2/3 majority" conflicting-vote rule). Safety is unaffected: quorum
/// intersection only relies on honest validators never voting twice.
type VoteLog<S> = HashMap<u64, HashMap<NodeId, Vec<(Option<ValueId>, S)>>>;

/// Distinct conflicting votes kept per validator per round (memory bound against a
/// flooding equivocator). A vote for the round's proposal is always kept.
const MAX_VOTES_PER_VALIDATOR_ROUND: usize = 4;

pub struct Tendermint<V: Value, S: Clone> {
    me: Option<NodeId>,
    validators: HashMap<NodeId, u128>,
    total_power: u128,
    quorum_power: u128,
    proposer: ProposerFn,

    height: u64,
    round: u64,
    step: Step,
    decided: bool,
    // (round, value): the paper's lockedRound/lockedValue and validRound/validValue.
    locked: Option<(u64, V)>,
    valid: Option<(u64, V)>,
    awaiting_value: bool,

    // Message log of the current height, per round.
    proposals: HashMap<u64, StoredProposal<V>>,
    prevotes: VoteLog<S>,
    precommits: VoteLog<S>,
    senders: HashMap<u64, HashSet<NodeId>>,
    fired: HashSet<(u64, OnceRule)>,
}

impl<V: Value, S: Clone> Tendermint<V, S> {
    /// `me` is None for a non-validator (it follows and decides, but never sends).
    pub fn new(me: Option<NodeId>, proposer: ProposerFn) -> Self {
        Self {
            me,
            validators: HashMap::new(),
            total_power: 0,
            quorum_power: 0,
            proposer,
            height: 0,
            round: 0,
            step: Step::Propose,
            decided: true, // inert until start_height
            locked: None,
            valid: None,
            awaiting_value: false,
            proposals: HashMap::new(),
            prevotes: HashMap::new(),
            precommits: HashMap::new(),
            senders: HashMap::new(),
            fired: HashSet::new(),
        }
    }

    pub fn height(&self) -> u64 { self.height }
    pub fn round(&self) -> u64 { self.round }
    pub fn step(&self) -> Step { self.step }
    pub fn is_decided(&self) -> bool { self.decided }
    pub fn locked_round(&self) -> Option<u64> { self.locked.as_ref().map(|(r, _)| *r) }

    /// Diagnostic summary of one round of the current height.
    pub fn debug_round(&self, round: u64) -> Option<String> {
        let short = |id: &Option<ValueId>| id.map_or("nil".to_string(), |i| format!("{:02x}{:02x}", i[16], i[17]));
        let votes = |log: &VoteLog<S>| {
            let mut v: Vec<String> = log.get(&round).map(|m| m.iter()
                .flat_map(|(n, vs)| vs.iter().map(move |(id, _)| format!("{}:{}", n[0] - 1, short(id))))
                .collect()).unwrap_or_default();
            v.sort();
            v.join(",")
        };
        Some(format!("r{} proposal={:?} prevotes=[{}] precommits=[{}] valid_round={:?} fired={:?} proposer={}",
            round,
            self.proposals.get(&round).map(|p| (short(&Some(p.value.id())), p.valid_round)),
            votes(&self.prevotes), votes(&self.precommits),
            self.valid.as_ref().map(|(r, _)| *r),
            self.fired.iter().filter(|(r, _)| *r == round).map(|(_, f)| *f).collect::<Vec<_>>(),
            (self.proposer)(self.height, round)[0] - 1))
    }

    /// The paper's quorum: more than 2/3 of `total`.
    pub fn strict_quorum(total: u128) -> u128 {
        total * 2 / 3 + 1
    }

    /// L10-L11 + L54: starts `height` with its validator set (stake per validator) and the
    /// power that forms a quorum (must be more than half of the total).
    pub fn start_height(&mut self, height: u64, validators: Vec<(NodeId, u128)>, quorum: u128) -> Vec<Output<V, S>> {
        self.validators = validators.into_iter().filter(|(_, p)| *p > 0).collect();
        self.total_power = self.validators.values().sum();
        assert!(quorum * 2 > self.total_power && quorum <= self.total_power,
            "quorum {} must be more than half of the total power {}", quorum, self.total_power);
        self.quorum_power = quorum;
        self.height = height;
        self.decided = false;
        self.locked = None;
        self.valid = None;
        self.proposals.clear();
        self.prevotes.clear();
        self.precommits.clear();
        self.senders.clear();
        self.fired.clear();
        let mut out = Vec::new();
        self.start_round(0, &mut out);
        self.evaluate(&mut out);
        out
    }

    /// Answer to `GetValue` (L18: proposal ← getValue()).
    pub fn on_value(&mut self, height: u64, round: u64, value: V) -> Vec<Output<V, S>> {
        let mut out = Vec::new();
        if !self.decided && height == self.height && round == self.round
            && self.step == Step::Propose && self.awaiting_value
        {
            self.awaiting_value = false;
            // L19: broadcast ⟨PROPOSAL, h, round, proposal, validRound = -1⟩
            out.push(Output::Proposal { height, round, value, valid_round: None });
        }
        out
    }

    pub fn on_proposal(
        &mut self,
        height: u64,
        round: u64,
        value: V,
        valid_round: Option<u64>,
        from: NodeId,
        valid: bool,
    ) -> Vec<Output<V, S>> {
        let mut out = Vec::new();
        if self.decided || height != self.height || from != (self.proposer)(height, round) {
            return out;
        }
        if let Some(prev) = self.proposals.get(&round) {
            if prev.value.id() != value.id() {
                out.push(Output::Equivocation { height, round, from });
            }
            return out;
        }
        // A valid_round must be an earlier round (L28 only uses vr < round).
        let valid_round = valid_round.filter(|vr| *vr < round);
        self.proposals.insert(round, StoredProposal { value, valid_round, valid });
        self.senders.entry(round).or_default().insert(from);
        self.evaluate(&mut out);
        out
    }

    pub fn on_vote(
        &mut self,
        kind: VoteKind,
        height: u64,
        round: u64,
        id: Option<ValueId>,
        from: NodeId,
        sig: S,
    ) -> Vec<Output<V, S>> {
        let mut out = Vec::new();
        if self.decided || height != self.height || !self.validators.contains_key(&from) {
            return out;
        }
        let for_proposal = id.is_some() && self.proposals.get(&round).map(|p| p.value.id()) == id;
        let log = match kind {
            VoteKind::Prevote => &mut self.prevotes,
            VoteKind::Precommit => &mut self.precommits,
        };
        let votes = log.entry(round).or_default().entry(from).or_default();
        if votes.iter().any(|(v, _)| *v == id) {
            return out; // duplicate
        }
        if !votes.is_empty() {
            out.push(Output::Equivocation { height, round, from });
            if votes.len() >= MAX_VOTES_PER_VALIDATOR_ROUND && !for_proposal {
                return out;
            }
        }
        votes.push((id, sig));
        self.senders.entry(round).or_default().insert(from);
        self.evaluate(&mut out);
        out
    }

    pub fn on_timeout(&mut self, kind: TimeoutKind, height: u64, round: u64) -> Vec<Output<V, S>> {
        let mut out = Vec::new();
        if self.decided || height != self.height || round != self.round {
            return out;
        }
        match kind {
            // L57-L60
            TimeoutKind::Propose if self.step == Step::Propose => {
                self.vote(VoteKind::Prevote, None, &mut out);
                self.step = Step::Prevote;
            }
            // L61-L64
            TimeoutKind::Prevote if self.step == Step::Prevote => {
                self.vote(VoteKind::Precommit, None, &mut out);
                self.step = Step::Precommit;
            }
            // L65-L67
            TimeoutKind::Precommit => {
                self.start_round(round + 1, &mut out);
            }
            _ => {}
        }
        self.evaluate(&mut out);
        out
    }

    // ----------------------------------------------------------------------------

    fn is_proposer(&self, height: u64, round: u64) -> bool {
        self.me.map_or(false, |me| (self.proposer)(height, round) == me)
    }

    fn quorum(&self, power: u128) -> bool {
        power >= self.quorum_power
    }

    /// The paper's f+1: more power than total − quorum, so at least one validator in the
    /// set is honest (with the strict quorum this is "more than 1/3").
    fn one_third(&self, power: u128) -> bool {
        power > self.total_power - self.quorum_power
    }

    fn power_for(&self, kind: VoteKind, round: u64, id: Option<ValueId>) -> u128 {
        let log = match kind {
            VoteKind::Prevote => &self.prevotes,
            VoteKind::Precommit => &self.precommits,
        };
        log.get(&round).map_or(0, |votes| {
            votes.iter()
                .filter(|(_, vs)| vs.iter().any(|(v, _)| *v == id))
                .map(|(from, _)| self.validators.get(from).copied().unwrap_or(0))
                .sum()
        })
    }

    fn power_any(&self, kind: VoteKind, round: u64) -> u128 {
        let log = match kind {
            VoteKind::Prevote => &self.prevotes,
            VoteKind::Precommit => &self.precommits,
        };
        log.get(&round).map_or(0, |votes| {
            votes.keys().map(|from| self.validators.get(from).copied().unwrap_or(0)).sum()
        })
    }

    fn vote(&self, kind: VoteKind, id: Option<ValueId>, out: &mut Vec<Output<V, S>>) {
        if self.me.map_or(false, |me| self.validators.contains_key(&me)) {
            out.push(Output::Vote { kind, height: self.height, round: self.round, id });
        }
    }

    /// L11-L21 StartRound(round)
    fn start_round(&mut self, round: u64, out: &mut Vec<Output<V, S>>) {
        self.round = round;
        self.step = Step::Propose;
        self.awaiting_value = false;
        if self.is_proposer(self.height, round) {
            match &self.valid {
                // L15-L16: re-propose validValue with its validRound
                Some((vr, v)) => out.push(Output::Proposal {
                    height: self.height,
                    round,
                    value: v.clone(),
                    valid_round: Some(*vr),
                }),
                // L18: proposal ← getValue()
                None => {
                    self.awaiting_value = true;
                    out.push(Output::GetValue { height: self.height, round });
                }
            }
        } else {
            // L21
            out.push(Output::ScheduleTimeout { kind: TimeoutKind::Propose, height: self.height, round });
        }
    }

    /// Applies rules until none fires (each firing changes state or a once-flag).
    fn evaluate(&mut self, out: &mut Vec<Output<V, S>>) {
        while !self.decided && self.try_rules(out) {}
    }

    fn try_rules(&mut self, out: &mut Vec<Output<V, S>>) -> bool {
        let h = self.height;
        let r = self.round;

        // L49-L54: decide — a proposal of ANY round with >2/3 precommits for its value.
        let mut rounds: Vec<u64> = self.proposals.keys().copied().collect();
        rounds.sort_unstable();
        for pr in rounds {
            let p = &self.proposals[&pr];
            let id = p.value.id();
            if p.valid && self.quorum(self.power_for(VoteKind::Precommit, pr, Some(id))) {
                let value = p.value.clone();
                let commits = self.precommits[&pr].iter()
                    .filter_map(|(from, vs)| vs.iter()
                        .find(|(v, _)| *v == Some(id))
                        .map(|(_, sig)| (*from, sig.clone())))
                    .collect();
                self.decided = true;
                out.push(Output::Decide { height: h, round: pr, value, commits });
                return false;
            }
        }

        // L55-L56: >1/3 of the power is already in a higher round → jump to it.
        let higher = self.senders.iter()
            .filter(|(rr, _)| **rr > r)
            .filter(|(_, who)| {
                let p: u128 = who.iter().map(|n| self.validators.get(n).copied().unwrap_or(0)).sum();
                self.one_third(p)
            })
            .map(|(rr, _)| *rr)
            .max();
        if let Some(target) = higher {
            self.start_round(target, out);
            return true;
        }

        if self.step == Step::Propose {
            if let Some(p) = self.proposals.get(&r) {
                let id = p.value.id();
                match p.valid_round {
                    // L22-L27
                    None => {
                        let ok = p.valid && self.locked.as_ref().map_or(true, |(_, lv)| lv.id() == id);
                        self.vote(VoteKind::Prevote, if ok { Some(id) } else { None }, out);
                        self.step = Step::Prevote;
                        return true;
                    }
                    // L28-L33
                    Some(vr) => {
                        if self.quorum(self.power_for(VoteKind::Prevote, vr, Some(id))) {
                            let ok = p.valid && self.locked.as_ref()
                                .map_or(true, |(lr, lv)| *lr <= vr || lv.id() == id);
                            self.vote(VoteKind::Prevote, if ok { Some(id) } else { None }, out);
                            self.step = Step::Prevote;
                            return true;
                        }
                    }
                }
            }
        }

        // L34-L35
        if self.step == Step::Prevote
            && !self.fired.contains(&(r, OnceRule::L34))
            && self.quorum(self.power_any(VoteKind::Prevote, r))
        {
            self.fired.insert((r, OnceRule::L34));
            out.push(Output::ScheduleTimeout { kind: TimeoutKind::Prevote, height: h, round: r });
            return true;
        }

        // L36-L43
        if self.step >= Step::Prevote && !self.fired.contains(&(r, OnceRule::L36)) {
            if let Some(p) = self.proposals.get(&r) {
                let id = p.value.id();
                if p.valid && self.quorum(self.power_for(VoteKind::Prevote, r, Some(id))) {
                    let value = p.value.clone();
                    self.fired.insert((r, OnceRule::L36));
                    if self.step == Step::Prevote {
                        self.locked = Some((r, value.clone()));
                        self.vote(VoteKind::Precommit, Some(id), out);
                        self.step = Step::Precommit;
                    }
                    self.valid = Some((r, value));
                    return true;
                }
            }
        }

        // L44-L46
        if self.step == Step::Prevote && self.quorum(self.power_for(VoteKind::Prevote, r, None)) {
            self.vote(VoteKind::Precommit, None, out);
            self.step = Step::Precommit;
            return true;
        }

        // L47-L48
        if !self.fired.contains(&(r, OnceRule::L47)) && self.quorum(self.power_any(VoteKind::Precommit, r)) {
            self.fired.insert((r, OnceRule::L47));
            out.push(Output::ScheduleTimeout { kind: TimeoutKind::Precommit, height: h, round: r });
            return true;
        }

        false
    }
}
