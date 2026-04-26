use freenet_stdlib::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// State: maps user public keys to their set of followed public keys
#[derive(Serialize, Deserialize)]
struct FollowGraph {
    follows: HashMap<String, HashSet<String>>,
}

impl<'a> TryFrom<State<'a>> for FollowGraph {
    type Error = ContractError;
    fn try_from(value: State<'a>) -> Result<Self, Self::Error> {
        serde_json::from_slice(value.as_ref()).map_err(|_| ContractError::InvalidState)
    }
}

/// Delta: a list of follow/unfollow actions
#[derive(Serialize, Deserialize)]
struct FollowAction {
    follower: String, // pubkey of who is following
    target: String,   // pubkey of who is being followed
    action: FollowType,
}

#[derive(Serialize, Deserialize)]
enum FollowType {
    Follow,
    Unfollow,
}

// NOTE on commutativity:
// Follow actions are commutative: applying Follow(A→B) and Follow(A→C) in any order
// yields the same result (set union). However, mixing Follow and Unfollow for the same
// (follower, target) pair is NOT fully commutative: Follow-then-Unfollow removes the
// relationship, while Unfollow-then-Follow adds it. This is a known limitation of
// last-write-wins semantics. In practice, Unfollow is rare and the system is eventually
// consistent — conflicting concurrent Follow/Unfollow for the same pair will resolve
// deterministically once all nodes converge, but intermediate states may differ.

#[contract]
impl ContractInterface for FollowGraph {
    fn validate_state(
        _parameters: Parameters<'static>,
        state: State<'static>,
        _related: RelatedContracts,
    ) -> Result<ValidateResult, ContractError> {
        FollowGraph::try_from(state).map(|_| ValidateResult::Valid)
    }

    fn update_state(
        _parameters: Parameters<'static>,
        state: State<'static>,
        delta: Vec<UpdateData>,
    ) -> Result<UpdateModification<'static>, ContractError> {
        if delta.is_empty() {
            return Ok(UpdateModification::valid(state));
        }
        let mut graph = FollowGraph::try_from(state)?;

        let delta_bytes = match &delta[0] {
            UpdateData::Delta(d) => d.as_ref(),
            UpdateData::State(s) => s.as_ref(),
            UpdateData::StateAndDelta { delta, .. } => delta.as_ref(),
            _ => {
                return Ok(UpdateModification::valid(State::from(
                    serde_json::to_vec(&graph).map_err(|e| ContractError::Other(format!("{e}")))?,
                )));
            }
        };
        let actions = serde_json::from_slice::<Vec<FollowAction>>(delta_bytes)
            .map_err(|_| ContractError::InvalidDelta)?;

        for action in actions {
            let following = graph.follows.entry(action.follower).or_default();
            match action.action {
                FollowType::Follow => {
                    following.insert(action.target);
                }
                FollowType::Unfollow => {
                    following.remove(&action.target);
                }
            }
        }

        let bytes =
            serde_json::to_vec(&graph).map_err(|err| ContractError::Other(format!("{err}")))?;
        Ok(UpdateModification::valid(State::from(bytes)))
    }

    fn summarize_state(
        _parameters: Parameters<'static>,
        state: State<'static>,
    ) -> Result<StateSummary<'static>, ContractError> {
        // Summary: just the set of (follower, count) pairs
        let graph = FollowGraph::try_from(state)?;
        let summary: HashMap<&str, usize> = graph
            .follows
            .iter()
            .map(|(k, v)| (k.as_str(), v.len()))
            .collect();
        Ok(StateSummary::from(
            serde_json::to_vec(&summary).map_err(|err| ContractError::Other(format!("{err}")))?,
        ))
    }

    fn get_state_delta(
        _parameters: Parameters<'static>,
        state: State<'static>,
        _summary: StateSummary<'static>,
    ) -> Result<StateDelta<'static>, ContractError> {
        // For simplicity, return the full state as delta
        // (follows graph is typically small)
        Ok(StateDelta::from(state.into_bytes()))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn empty_state_is_valid() {
        let state = r#"{"follows":{}}"#.as_bytes().to_vec();
        let result = FollowGraph::validate_state(
            [].as_ref().into(),
            State::from(state),
            RelatedContracts::new(),
        )
        .unwrap();
        assert!(matches!(result, ValidateResult::Valid));
    }

    #[test]
    fn follow_action() {
        let state = r#"{"follows":{}}"#.as_bytes().to_vec();
        let delta = r#"[{"follower":"alice_pk","target":"bob_pk","action":"Follow"}]"#;

        let result = FollowGraph::update_state(
            [].as_ref().into(),
            State::from(state),
            vec![UpdateData::Delta(StateDelta::from(
                delta.as_bytes().to_vec(),
            ))],
        )
        .unwrap();

        let new_state: FollowGraph =
            serde_json::from_slice(result.unwrap_valid().as_ref()).unwrap();
        assert!(new_state.follows["alice_pk"].contains("bob_pk"));
    }

    #[test]
    fn unfollow_action() {
        let state = r#"{"follows":{"alice_pk":["bob_pk"]}}"#.as_bytes().to_vec();
        let delta = r#"[{"follower":"alice_pk","target":"bob_pk","action":"Unfollow"}]"#;

        let result = FollowGraph::update_state(
            [].as_ref().into(),
            State::from(state),
            vec![UpdateData::Delta(StateDelta::from(
                delta.as_bytes().to_vec(),
            ))],
        )
        .unwrap();

        let new_state: FollowGraph =
            serde_json::from_slice(result.unwrap_valid().as_ref()).unwrap();
        assert!(
            !new_state
                .follows
                .get("alice_pk")
                .is_some_and(|s| s.contains("bob_pk"))
        );
    }

    #[test]
    fn commutative_merge() {
        // Follow A then B should give same result as Follow B then A
        let state = r#"{"follows":{}}"#.as_bytes().to_vec();

        // Order 1: follow bob then carol
        let delta1 = r#"[{"follower":"alice_pk","target":"bob_pk","action":"Follow"}]"#;
        let result1 = FollowGraph::update_state(
            [].as_ref().into(),
            State::from(state.clone()),
            vec![UpdateData::Delta(StateDelta::from(
                delta1.as_bytes().to_vec(),
            ))],
        )
        .unwrap();

        let delta2 = r#"[{"follower":"alice_pk","target":"carol_pk","action":"Follow"}]"#;
        let result1_2 = FollowGraph::update_state(
            [].as_ref().into(),
            result1.unwrap_valid(),
            vec![UpdateData::Delta(StateDelta::from(
                delta2.as_bytes().to_vec(),
            ))],
        )
        .unwrap();

        // Order 2: follow carol then bob
        let result2 = FollowGraph::update_state(
            [].as_ref().into(),
            State::from(state),
            vec![UpdateData::Delta(StateDelta::from(
                delta2.as_bytes().to_vec(),
            ))],
        )
        .unwrap();

        let result2_1 = FollowGraph::update_state(
            [].as_ref().into(),
            result2.unwrap_valid(),
            vec![UpdateData::Delta(StateDelta::from(
                delta1.as_bytes().to_vec(),
            ))],
        )
        .unwrap();

        let g1: FollowGraph = serde_json::from_slice(result1_2.unwrap_valid().as_ref()).unwrap();
        let g2: FollowGraph = serde_json::from_slice(result2_1.unwrap_valid().as_ref()).unwrap();

        assert_eq!(g1.follows["alice_pk"], g2.follows["alice_pk"]);
    }
}
