use rand::Rng;
use std::{collections::HashMap, time::Instant};

type Id = u64;

pub fn new_user_id() -> Id {
    rand::thread_rng().gen()
}

#[derive(Debug)]
pub struct Vote {
    time: Instant,
    text: String,
}

impl Vote {
    pub fn new(text: String) -> Self {
        let time = Instant::now();
        Self { time, text }
    }
}

#[derive(Debug)]
pub struct Poll {
    votes_by_user: HashMap<Id, Vote>,

    private_id: Id,
    public_id: Id,
    title: String,
}

impl Poll {
    pub fn new(title: &str) -> Self {
        let mut rng = rand::thread_rng();
        let private_id = rng.gen();
        let public_id = rng.gen();
        Self {
            votes_by_user: HashMap::default(),
            private_id,
            public_id,
            title: title.to_owned(),
        }
    }
    pub fn private_id(&self) -> Id {
        self.private_id
    }

    pub fn public_id(&self) -> Id {
        self.public_id
    }

    pub fn title(&self) -> &str {
        self.title.as_ref()
    }

    pub fn votes(&self) -> Vec<(&str, u32)> {
        let mut m = HashMap::new();
        for (_k, v) in &self.votes_by_user {
            *m.entry(v.text.as_str()).or_insert(0) += 1;
        }
        let mut v: Vec<(_, _)> = m.into_iter().collect();
        v.sort();
        v
    }

    pub fn vote(&mut self, user_id: Id, vote: String) {
        self.votes_by_user.insert(user_id, Vote::new(vote));
    }
    pub fn clear(&mut self) {
        self.votes_by_user.clear();
    }
}

#[derive(Debug, Default)]
pub struct State {
    poll_by_public_key: HashMap<Id, Poll>,
    pub_by_private: HashMap<Id, Id>,
}

impl State {
    pub fn new_poll(&mut self, title: &str) -> &mut Poll {
        let poll = Poll::new(title);
        self.pub_by_private
            .insert(poll.private_id, poll.public_id);
        let pub_id = poll.public_id;
        self.poll_by_public_key.insert(pub_id, poll);
        let poll = self
            .poll_by_public_key
            .get_mut(&pub_id)
            .expect("just inserted");

        poll
    }

    pub fn poll_by_public_key(&mut self, public_id: Id) -> Option<&mut Poll> {
        self.poll_by_public_key.get_mut(&public_id)
    }

    pub fn poll_by_private_key(&mut self, private_id: Id) -> Option<&mut Poll> {
        self.poll_by_public_key
            .get_mut(self.pub_by_private.get(&private_id)?)
    }
}
