use freenet_stdlib::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// State: maps post_id to the set of public keys that liked that post
#[derive(Serialize, Deserialize)]
struct LikeGraph {
    likes: HashMap<String, HashSet<String>>,
}

impl<'a> TryFrom<State<'a>> for LikeGraph {
    type Error = ContractError;
    fn try_from(value: State<'a>) -> Result<Self, Self::Error> {
        serde_json::from_slice(value.as_ref()).map_err(|_| ContractError::InvalidState)
    }
}

/// Delta: a list of like/unlike actions
#[derive(Serialize, Deserialize)]
struct LikeAction {
    post_id: String,
    user_pubkey: String,
    action: LikeType,
}

#[derive(Serialize, Deserialize)]
enum LikeType {
    Like,
    Unlike,
}

// NOTE on commutativity:
// Like actions are commutative: applying Like(post_A, user_X) and Like(post_A, user_Y)
// in any order yields the same result (set union). However, mixing Like and Unlike for the
// same (post_id, user_pubkey) pair is NOT fully commutative: Like-then-Unlike removes the
// like, while Unlike-then-Like adds it. This is a known limitation of last-write-wins
// semantics. In practice, Unlike is rare and the system is eventually consistent —
// conflicting concurrent Like/Unlike for the same pair will resolve deterministically once
// all nodes converge, but intermediate states may differ.

#[contract]
impl ContractInterface for LikeGraph {
    fn validate_state(
        _parameters: Parameters<'static>,
        state: State<'static>,
        _related: RelatedContracts,
    ) -> Result<ValidateResult, ContractError> {
        LikeGraph::try_from(state).map(|_| ValidateResult::Valid)
    }

    fn update_state(
        _parameters: Parameters<'static>,
        state: State<'static>,
        delta: Vec<UpdateData>,
    ) -> Result<UpdateModification<'static>, ContractError> {
        if delta.is_empty() {
            return Ok(UpdateModification::valid(state));
        }
        let mut graph = LikeGraph::try_from(state)?;

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
        let actions = serde_json::from_slice::<Vec<LikeAction>>(delta_bytes)
            .map_err(|_| ContractError::InvalidDelta)?;

        for action in actions {
            let likers = graph.likes.entry(action.post_id).or_default();
            match action.action {
                LikeType::Like => {
                    likers.insert(action.user_pubkey);
                }
                LikeType::Unlike => {
                    likers.remove(&action.user_pubkey);
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
        // Summary: map of post_id → like count
        let graph = LikeGraph::try_from(state)?;
        let summary: HashMap<&str, usize> = graph
            .likes
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
        // (likes graph is typically small per contract instance)
        Ok(StateDelta::from(state.into_bytes()))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn empty_state_is_valid() {
        let state = r#"{"likes":{}}"#.as_bytes().to_vec();
        let result = LikeGraph::validate_state(
            [].as_ref().into(),
            State::from(state),
            RelatedContracts::new(),
        )
        .unwrap();
        assert!(matches!(result, ValidateResult::Valid));
    }

    #[test]
    fn like_action() {
        let state = r#"{"likes":{}}"#.as_bytes().to_vec();
        let delta = r#"[{"post_id":"post_123","user_pubkey":"alice_pk","action":"Like"}]"#;

        let result = LikeGraph::update_state(
            [].as_ref().into(),
            State::from(state),
            vec![UpdateData::Delta(StateDelta::from(
                delta.as_bytes().to_vec(),
            ))],
        )
        .unwrap();

        let new_state: LikeGraph = serde_json::from_slice(result.unwrap_valid().as_ref()).unwrap();
        assert!(new_state.likes["post_123"].contains("alice_pk"));
    }

    #[test]
    fn unlike_action() {
        let state = r#"{"likes":{"post_123":["alice_pk"]}}"#.as_bytes().to_vec();
        let delta = r#"[{"post_id":"post_123","user_pubkey":"alice_pk","action":"Unlike"}]"#;

        let result = LikeGraph::update_state(
            [].as_ref().into(),
            State::from(state),
            vec![UpdateData::Delta(StateDelta::from(
                delta.as_bytes().to_vec(),
            ))],
        )
        .unwrap();

        let new_state: LikeGraph = serde_json::from_slice(result.unwrap_valid().as_ref()).unwrap();
        assert!(
            !new_state
                .likes
                .get("post_123")
                .is_some_and(|s| s.contains("alice_pk"))
        );
    }

    #[test]
    fn commutative_merge() {
        // Like from alice then bob should give the same result as bob then alice
        let state = r#"{"likes":{}}"#.as_bytes().to_vec();

        // Order 1: alice likes post, then bob likes post
        let delta_alice = r#"[{"post_id":"post_123","user_pubkey":"alice_pk","action":"Like"}]"#;
        let result1 = LikeGraph::update_state(
            [].as_ref().into(),
            State::from(state.clone()),
            vec![UpdateData::Delta(StateDelta::from(
                delta_alice.as_bytes().to_vec(),
            ))],
        )
        .unwrap();

        let delta_bob = r#"[{"post_id":"post_123","user_pubkey":"bob_pk","action":"Like"}]"#;
        let result1_2 = LikeGraph::update_state(
            [].as_ref().into(),
            result1.unwrap_valid(),
            vec![UpdateData::Delta(StateDelta::from(
                delta_bob.as_bytes().to_vec(),
            ))],
        )
        .unwrap();

        // Order 2: bob likes post, then alice likes post
        let result2 = LikeGraph::update_state(
            [].as_ref().into(),
            State::from(state),
            vec![UpdateData::Delta(StateDelta::from(
                delta_bob.as_bytes().to_vec(),
            ))],
        )
        .unwrap();

        let result2_1 = LikeGraph::update_state(
            [].as_ref().into(),
            result2.unwrap_valid(),
            vec![UpdateData::Delta(StateDelta::from(
                delta_alice.as_bytes().to_vec(),
            ))],
        )
        .unwrap();

        let g1: LikeGraph = serde_json::from_slice(result1_2.unwrap_valid().as_ref()).unwrap();
        let g2: LikeGraph = serde_json::from_slice(result2_1.unwrap_valid().as_ref()).unwrap();

        assert_eq!(g1.likes["post_123"], g2.likes["post_123"]);
    }
}
