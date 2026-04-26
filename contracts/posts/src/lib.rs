use freenet_stdlib::prelude::{
    blake3::{Hasher as Blake3, traits::digest::Digest},
    *,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct PostsFeed {
    posts: Vec<Post>,
}

impl<'a> TryFrom<State<'a>> for PostsFeed {
    type Error = ContractError;

    fn try_from(value: State<'a>) -> Result<Self, Self::Error> {
        serde_json::from_slice(value.as_ref()).map_err(|_| ContractError::InvalidState)
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Post {
    pub id: String,                   // unique ID: "{author_pubkey}-{timestamp_ms}"
    pub author_pubkey: String,        // hex-encoded public key
    pub author_name: String,          // display name
    pub author_handle: String,        // @handle
    pub content: String,              // post text (max 280 chars)
    pub timestamp: u64,               // unix timestamp milliseconds
    pub signature: Option<Box<[u8]>>, // signature over content bytes
}

impl Post {
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Blake3::new();
        hasher.update(self.id.as_bytes());
        let hash_val = hasher.finalize();
        let mut key = [0; 32];
        key.copy_from_slice(&hash_val[..]);
        key
    }
}

#[derive(Serialize, Deserialize)]
struct FeedSummary {
    summaries: Vec<MessageSummary>,
}

impl<'a> From<&'a mut PostsFeed> for FeedSummary {
    fn from(feed: &'a mut PostsFeed) -> Self {
        let mut summaries = Vec::with_capacity(feed.posts.len());
        for post in &feed.posts {
            summaries.push(MessageSummary(post.hash()));
        }
        FeedSummary { summaries }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct MessageSummary([u8; 32]);

impl<'a> TryFrom<StateSummary<'a>> for MessageSummary {
    type Error = ContractError;
    fn try_from(value: StateSummary<'a>) -> Result<Self, Self::Error> {
        serde_json::from_slice(&value).map_err(|_| ContractError::InvalidState)
    }
}

#[contract]
impl ContractInterface for PostsFeed {
    fn validate_state(
        _parameters: Parameters<'static>,
        state: State<'static>,
        _related: RelatedContracts,
    ) -> Result<ValidateResult, ContractError> {
        let feed = PostsFeed::try_from(state)?;
        for post in &feed.posts {
            if post.content.len() > 280 {
                return Ok(ValidateResult::Invalid);
            }
            if post.id.is_empty() || post.author_pubkey.is_empty() {
                return Ok(ValidateResult::Invalid);
            }
        }
        Ok(ValidateResult::Valid)
    }

    fn update_state(
        _parameters: Parameters<'static>,
        state: State<'static>,
        delta: Vec<UpdateData>,
    ) -> Result<UpdateModification<'static>, ContractError> {
        if delta.is_empty() {
            return Ok(UpdateModification::valid(state));
        }
        let mut feed = PostsFeed::try_from(state)?;
        feed.posts.sort_by_cached_key(|p| p.hash());

        let delta_bytes = match &delta[0] {
            UpdateData::Delta(d) => d.as_ref(),
            UpdateData::State(s) => s.as_ref(),
            UpdateData::StateAndDelta { delta, .. } => delta.as_ref(),
            _ => {
                return Ok(UpdateModification::valid(State::from(
                    serde_json::to_vec(&feed).map_err(|e| ContractError::Other(format!("{e}")))?,
                )));
            }
        };
        let mut incoming = serde_json::from_slice::<Vec<Post>>(delta_bytes)
            .map_err(|_| ContractError::InvalidDelta)?;
        incoming.sort_by_cached_key(|p| p.hash());

        for post in incoming {
            if post.content.len() > 280 {
                continue; // skip invalid posts
            }
            if feed
                .posts
                .binary_search_by_key(&post.hash(), |o| o.hash())
                .is_err()
            {
                feed.posts.push(post);
            }
        }

        let feed_bytes =
            serde_json::to_vec(&feed).map_err(|err| ContractError::Other(format!("{err}")))?;
        Ok(UpdateModification::valid(State::from(feed_bytes)))
    }

    fn summarize_state(
        _parameters: Parameters<'static>,
        state: State<'static>,
    ) -> Result<StateSummary<'static>, ContractError> {
        let mut feed = PostsFeed::try_from(state).unwrap();
        let only_posts = FeedSummary::from(&mut feed);
        Ok(StateSummary::from(
            serde_json::to_vec(&only_posts)
                .map_err(|err| ContractError::Other(format!("{err}")))?,
        ))
    }

    fn get_state_delta(
        _parameters: Parameters<'static>,
        state: State<'static>,
        summary: StateSummary<'static>,
    ) -> Result<StateDelta<'static>, ContractError> {
        let feed = PostsFeed::try_from(state).unwrap();
        let mut summary = match serde_json::from_slice::<FeedSummary>(&summary) {
            Ok(summary) => summary,
            Err(_) => {
                // empty summary
                FeedSummary { summaries: vec![] }
            }
        };
        summary.summaries.sort();
        let mut final_posts = vec![];
        for post in feed.posts {
            let hash = post.hash();
            if summary
                .summaries
                .binary_search_by(|m| m.0.as_ref().cmp(&hash[..]))
                .is_err()
            {
                final_posts.push(post);
            }
        }
        Ok(StateDelta::from(
            serde_json::to_vec(&final_posts)
                .map_err(|err| ContractError::Other(format!("{err}")))?,
        ))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn make_post(id: &str, author_pubkey: &str, content: &str) -> Post {
        Post {
            id: id.to_string(),
            author_pubkey: author_pubkey.to_string(),
            author_name: "Test User".to_string(),
            author_handle: "@testuser".to_string(),
            content: content.to_string(),
            timestamp: 1_700_000_000_000,
            signature: None,
        }
    }

    #[test]
    fn conversions() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{
            "posts": [
                {
                    "id": "deadbeef-1700000000000",
                    "author_pubkey": "deadbeef",
                    "author_name": "Alice",
                    "author_handle": "@alice",
                    "content": "Hello world",
                    "timestamp": 1700000000000,
                    "signature": null
                }
            ]
        }"#;
        let _feed = PostsFeed::try_from(State::from(json.as_bytes()))?;
        Ok(())
    }

    #[test]
    fn validate_state() -> Result<(), Box<dyn std::error::Error>> {
        // Valid state
        let post = make_post("pubkey1-1700000000000", "pubkey1", "Hello!");
        let feed = PostsFeed { posts: vec![post] };
        let state_bytes = serde_json::to_vec(&feed)?;

        let valid = PostsFeed::validate_state(
            [].as_ref().into(),
            State::from(state_bytes),
            RelatedContracts::new(),
        )?;
        assert!(matches!(valid, ValidateResult::Valid));

        // Content too long (> 280 chars)
        let long_content = "x".repeat(281);
        let post_long = make_post("pubkey2-1700000000001", "pubkey2", &long_content);
        let feed_long = PostsFeed {
            posts: vec![post_long],
        };
        let state_long = serde_json::to_vec(&feed_long)?;

        let invalid = PostsFeed::validate_state(
            [].as_ref().into(),
            State::from(state_long),
            RelatedContracts::new(),
        )?;
        assert!(matches!(invalid, ValidateResult::Invalid));

        // Empty id
        let mut post_empty_id = make_post("", "pubkey3", "content");
        post_empty_id.id = "".to_string();
        let feed_empty = PostsFeed {
            posts: vec![post_empty_id],
        };
        let state_empty = serde_json::to_vec(&feed_empty)?;

        let invalid2 = PostsFeed::validate_state(
            [].as_ref().into(),
            State::from(state_empty),
            RelatedContracts::new(),
        )?;
        assert!(matches!(invalid2, ValidateResult::Invalid));

        Ok(())
    }

    #[test]
    fn update_state() -> Result<(), Box<dyn std::error::Error>> {
        let post1 = make_post("pubkey1-1700000000000", "pubkey1", "First post");
        let feed = PostsFeed {
            posts: vec![post1.clone()],
        };
        let state_bytes = serde_json::to_vec(&feed)?;

        let post2 = make_post("pubkey2-1700000000001", "pubkey2", "Second post");
        let delta_bytes = serde_json::to_vec(&vec![post2.clone()])?;
        let delta = StateDelta::from(delta_bytes);

        let new_state = PostsFeed::update_state(
            [].as_ref().into(),
            State::from(state_bytes),
            vec![UpdateData::Delta(delta)],
        )?
        .unwrap_valid();

        let updated_feed: PostsFeed = serde_json::from_slice(new_state.as_ref())?;
        assert_eq!(updated_feed.posts.len(), 2);

        // Verify commutativity: duplicate post should not be added
        let duplicate_delta = serde_json::to_vec(&vec![post1])?;
        let new_state2 = PostsFeed::update_state(
            [].as_ref().into(),
            new_state,
            vec![UpdateData::Delta(StateDelta::from(duplicate_delta))],
        )?
        .unwrap_valid();
        let feed2: PostsFeed = serde_json::from_slice(new_state2.as_ref())?;
        assert_eq!(feed2.posts.len(), 2); // no duplicate added

        // Content > 280 chars should be skipped
        let long_post = make_post("pubkey3-1700000000002", "pubkey3", &"x".repeat(281));
        let long_delta = serde_json::to_vec(&vec![long_post])?;
        let new_state3 = PostsFeed::update_state(
            [].as_ref().into(),
            new_state2,
            vec![UpdateData::Delta(StateDelta::from(long_delta))],
        )?
        .unwrap_valid();
        let feed3: PostsFeed = serde_json::from_slice(new_state3.as_ref())?;
        assert_eq!(feed3.posts.len(), 2); // long post skipped

        Ok(())
    }

    #[test]
    fn summarize_state() -> Result<(), Box<dyn std::error::Error>> {
        let post = make_post("pubkey1-1700000000000", "pubkey1", "Hello!");
        let feed = PostsFeed { posts: vec![post] };
        let state_bytes = serde_json::to_vec(&feed)?;

        let summary = PostsFeed::summarize_state([].as_ref().into(), State::from(state_bytes))?;
        let feed_summary = serde_json::from_slice::<FeedSummary>(summary.as_ref()).unwrap();
        assert_eq!(feed_summary.summaries.len(), 1);
        Ok(())
    }

    #[test]
    fn get_state_delta() -> Result<(), Box<dyn std::error::Error>> {
        let post1 = make_post("pubkey1-1700000000000", "pubkey1", "First post");
        let post2 = make_post("pubkey2-1700000000001", "pubkey2", "Second post");
        let feed = PostsFeed {
            posts: vec![post1.clone(), post2.clone()],
        };
        let state_bytes = serde_json::to_vec(&feed)?;

        // Summary only contains post1 — delta should return post2
        // Build summary via FeedSummary::from
        let summary = FeedSummary::from(&mut PostsFeed { posts: vec![post1] });

        let delta = PostsFeed::get_state_delta(
            [].as_ref().into(),
            State::from(state_bytes),
            serde_json::to_vec(&summary).unwrap().into(),
        )?;

        let delta_posts: Vec<Post> = serde_json::from_slice(delta.as_ref())?;
        assert_eq!(delta_posts.len(), 1);
        assert_eq!(delta_posts[0].id, "pubkey2-1700000000001");

        Ok(())
    }
}
