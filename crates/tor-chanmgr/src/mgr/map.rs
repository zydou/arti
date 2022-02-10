//! Simple implementation for the internal map state of a ChanMgr.

use std::time::Duration;

use super::{AbstractChannel, Pending};
use crate::{Error, Result};

use std::collections::{hash_map, HashMap};

/// A map from channel id to channel state.
///
/// We make this a separate type instead of just using
/// `Mutex<HashMap<...>>` to limit the amount of code that can see and
/// lock the Mutex here.  (We're using a blocking mutex close to async
/// code, so we need to be careful.)
pub(crate) struct ChannelMap<C: AbstractChannel> {
    /// A map from identity to channel, or to pending channel status.
    ///
    /// (Danger: this uses a blocking mutex close to async code.  This mutex
    /// must never be held while an await is happening.)
    channels: std::sync::Mutex<HashMap<C::Ident, ChannelState<C>>>,
}

/// Structure that can only be constructed from within this module.
/// Used to make sure that only we can construct ChannelState::Poisoned.
pub(crate) struct Priv {
    /// (This field is private)
    _unused: (),
}

/// The state of a channel (or channel build attempt) within a map.
pub(crate) enum ChannelState<C> {
    /// An open channel.
    ///
    /// This channel might not be usable: it might be closing or
    /// broken.  We need to check its is_usable() method before
    /// yielding it to the user.
    Open(OpenEntry<C>),
    /// A channel that's getting built.
    Building(Pending<C>),
    /// A temporary invalid state.
    ///
    /// We insert this into the map temporarily as a placeholder in
    /// `change_state()`.
    Poisoned(Priv),
}

/// An open channel entry.
#[derive(Clone)]
pub(crate) struct OpenEntry<C> {
    /// The underlying open channel.
    pub(crate) channel: C,
    /// The maximum unused duration allowed for this channel.
    pub(crate) max_unused_duration: Duration,
}

impl<C: Clone> ChannelState<C> {
    /// Create a new shallow copy of this ChannelState.
    #[cfg(test)]
    fn clone_ref(&self) -> Result<Self> {
        use ChannelState::*;
        match self {
            Open(ent) => Ok(Open(ent.clone())),
            Building(pending) => Ok(Building(pending.clone())),
            Poisoned(_) => Err(Error::Internal("Poisoned state in channel map")),
        }
    }

    /// For testing: either give the Open channel inside this state,
    /// or panic if there is none.
    #[cfg(test)]
    fn unwrap_open(&self) -> C {
        match self {
            ChannelState::Open(ent) => ent.clone().channel,
            _ => panic!("Not an open channel"),
        }
    }
}

impl<C: AbstractChannel> ChannelState<C> {
    /// Return an error if `ident`is definitely not a matching
    /// matching identity for this state.
    fn check_ident(&self, ident: &C::Ident) -> Result<()> {
        match self {
            ChannelState::Open(ent) => {
                if ent.channel.ident() == ident {
                    Ok(())
                } else {
                    Err(Error::Internal("Identity mismatch"))
                }
            }
            ChannelState::Poisoned(_) => Err(Error::Internal("Poisoned state in channel map")),
            ChannelState::Building(_) => Ok(()),
        }
    }

    /// Return true if a channel is ready to expire.
    /// Update `expire_after` if a smaller duration than
    /// the given value is required to expire this channel.
    fn ready_to_expire(&self, expire_after: &mut Duration) -> bool {
        if let ChannelState::Open(ent) = self {
            let unused_duration = ent.channel.duration_unused();
            if let Some(unused_duration) = unused_duration {
                let max_unused_duration = ent.max_unused_duration;

                if let Some(remaining) = max_unused_duration.checked_sub(unused_duration) {
                    *expire_after = std::cmp::min(*expire_after, remaining);
                    false
                } else {
                    true
                }
            } else {
                // still in use
                false
            }
        } else {
            false
        }
    }
}

impl<C: AbstractChannel> ChannelMap<C> {
    /// Create a new empty ChannelMap.
    pub(crate) fn new() -> Self {
        ChannelMap {
            channels: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Return the channel state for the given identity, if any.
    #[cfg(test)]
    pub(crate) fn get(&self, ident: &C::Ident) -> Result<Option<ChannelState<C>>> {
        let map = self.channels.lock()?;
        map.get(ident).map(ChannelState::clone_ref).transpose()
    }

    /// Replace the channel state for `ident` with `newval`, and return the
    /// previous value if any.
    pub(crate) fn replace(
        &self,
        ident: C::Ident,
        newval: ChannelState<C>,
    ) -> Result<Option<ChannelState<C>>> {
        newval.check_ident(&ident)?;
        let mut map = self.channels.lock()?;
        Ok(map.insert(ident, newval))
    }

    /// Remove and return the state for `ident`, if any.
    pub(crate) fn remove(&self, ident: &C::Ident) -> Result<Option<ChannelState<C>>> {
        let mut map = self.channels.lock()?;
        Ok(map.remove(ident))
    }

    /// Remove every unusable state from the map.
    #[cfg(test)]
    pub(crate) fn remove_unusable(&self) -> Result<()> {
        let mut map = self.channels.lock()?;
        map.retain(|_, state| match state {
            ChannelState::Poisoned(_) => false,
            ChannelState::Open(ent) => ent.channel.is_usable(),
            ChannelState::Building(_) => true,
        });
        Ok(())
    }

    /// Replace the state whose identity is `ident` with a new state.
    ///
    /// The provided function `func` is invoked on the old state (if
    /// any), and must return a tuple containing an optional new
    /// state, and an arbitrary return value for this function.
    ///
    /// Because `func` is run while holding the lock on this object,
    /// it should be fast and nonblocking.  In return, you can be sure
    /// that it's running atomically with respect to other accessors
    /// of this map.
    ///
    /// If `func` panics, or if it returns a channel with a different
    /// identity, this position in the map will be become unusable and
    /// future accesses to that position may fail.
    pub(crate) fn change_state<F, V>(&self, ident: &C::Ident, func: F) -> Result<V>
    where
        F: FnOnce(Option<ChannelState<C>>) -> (Option<ChannelState<C>>, V),
    {
        use hash_map::Entry::*;
        let mut map = self.channels.lock()?;
        let entry = map.entry(ident.clone());
        match entry {
            Occupied(mut occupied) => {
                // Temporarily replace the entry for this identity with
                // a poisoned entry.
                let mut oldent = ChannelState::Poisoned(Priv { _unused: () });
                std::mem::swap(occupied.get_mut(), &mut oldent);
                let (newval, output) = func(Some(oldent));
                match newval {
                    Some(mut newent) => {
                        newent.check_ident(ident)?;
                        std::mem::swap(occupied.get_mut(), &mut newent);
                    }
                    None => {
                        occupied.remove();
                    }
                };
                Ok(output)
            }
            Vacant(vacant) => {
                let (newval, output) = func(None);
                if let Some(newent) = newval {
                    newent.check_ident(ident)?;
                    vacant.insert(newent);
                }
                Ok(output)
            }
        }
    }

    /// Expire all channels that have been unused for too long.
    ///
    /// Return a Duration until the next time at which
    /// a channel _could_ expire.
    pub(crate) fn expire_channels(&self) -> Duration {
        let mut ret = Duration::from_secs(180);
        self.channels
            .lock()
            .expect("Poisoned lock")
            .retain(|_id, chan| !chan.ready_to_expire(&mut ret));
        ret
    }
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]
    use super::*;
    #[derive(Eq, PartialEq, Clone, Debug)]
    struct FakeChannel {
        ident: &'static str,
        usable: bool,
        unused_duration: Option<u64>,
    }
    impl AbstractChannel for FakeChannel {
        type Ident = u8;
        fn ident(&self) -> &Self::Ident {
            &self.ident.as_bytes()[0]
        }
        fn is_usable(&self) -> bool {
            self.usable
        }
        fn duration_unused(&self) -> Option<Duration> {
            self.unused_duration.map(Duration::from_secs)
        }
    }
    fn ch(ident: &'static str) -> ChannelState<FakeChannel> {
        let channel = FakeChannel {
            ident,
            usable: true,
            unused_duration: None,
        };
        ChannelState::Open(OpenEntry {
            channel,
            max_unused_duration: Duration::from_secs(180),
        })
    }
    fn ch_with_details(
        ident: &'static str,
        max_unused_duration: Duration,
        unused_duration: Option<u64>,
    ) -> ChannelState<FakeChannel> {
        let channel = FakeChannel {
            ident,
            usable: true,
            unused_duration,
        };
        ChannelState::Open(OpenEntry {
            channel,
            max_unused_duration,
        })
    }
    fn closed(ident: &'static str) -> ChannelState<FakeChannel> {
        let channel = FakeChannel {
            ident,
            usable: false,
            unused_duration: None,
        };
        ChannelState::Open(OpenEntry {
            channel,
            max_unused_duration: Duration::from_secs(180),
        })
    }

    #[test]
    fn simple_ops() {
        let map = ChannelMap::new();
        use ChannelState::Open;

        assert!(map.replace(b'h', ch("hello")).unwrap().is_none());
        assert!(map.replace(b'w', ch("wello")).unwrap().is_none());

        match map.get(&b'h') {
            Ok(Some(Open(ent))) if ent.channel.ident == "hello" => {}
            _ => panic!(),
        }

        assert!(map.get(&b'W').unwrap().is_none());

        match map.replace(b'h', ch("hebbo")) {
            Ok(Some(Open(ent))) if ent.channel.ident == "hello" => {}
            _ => panic!(),
        }

        assert!(map.remove(&b'Z').unwrap().is_none());
        match map.remove(&b'h') {
            Ok(Some(Open(ent))) if ent.channel.ident == "hebbo" => {}
            _ => panic!(),
        }
    }

    #[test]
    fn rmv_unusable() {
        let map = ChannelMap::new();

        map.replace(b'm', closed("machen")).unwrap();
        map.replace(b'f', ch("feinen")).unwrap();
        map.replace(b'w', closed("wir")).unwrap();
        map.replace(b'F', ch("Fug")).unwrap();

        map.remove_unusable().unwrap();

        assert!(map.get(&b'm').unwrap().is_none());
        assert!(map.get(&b'w').unwrap().is_none());
        assert!(map.get(&b'f').unwrap().is_some());
        assert!(map.get(&b'F').unwrap().is_some());
    }

    #[test]
    fn change() {
        let map = ChannelMap::new();

        map.replace(b'w', ch("wir")).unwrap();
        map.replace(b'm', ch("machen")).unwrap();
        map.replace(b'f', ch("feinen")).unwrap();
        map.replace(b'F', ch("Fug")).unwrap();

        //  Replace Some with Some.
        let (old, v) = map
            .change_state(&b'F', |state| (Some(ch("FUG")), (state, 99_u8)))
            .unwrap();
        assert_eq!(old.unwrap().unwrap_open().ident, "Fug");
        assert_eq!(v, 99);
        assert_eq!(map.get(&b'F').unwrap().unwrap().unwrap_open().ident, "FUG");

        // Replace Some with None.
        let (old, v) = map
            .change_state(&b'f', |state| (None, (state, 123_u8)))
            .unwrap();
        assert_eq!(old.unwrap().unwrap_open().ident, "feinen");
        assert_eq!(v, 123);
        assert!(map.get(&b'f').unwrap().is_none());

        // Replace None with Some.
        let (old, v) = map
            .change_state(&b'G', |state| (Some(ch("Geheimnisse")), (state, "Hi")))
            .unwrap();
        assert!(old.is_none());
        assert_eq!(v, "Hi");
        assert_eq!(
            map.get(&b'G').unwrap().unwrap().unwrap_open().ident,
            "Geheimnisse"
        );

        // Replace None with None
        let (old, v) = map
            .change_state(&b'Q', |state| (None, (state, "---")))
            .unwrap();
        assert!(old.is_none());
        assert_eq!(v, "---");
        assert!(map.get(&b'Q').unwrap().is_none());

        // Try replacing None with invalid entry (with mismatched ID)
        let e = map.change_state(&b'P', |state| (Some(ch("Geheimnisse")), (state, "Hi")));
        assert!(matches!(e, Err(Error::Internal(_))));
        assert!(matches!(map.get(&b'P'), Ok(None)));

        // Try replacing Some with invalid entry (mismatched ID)
        let e = map.change_state(&b'G', |state| (Some(ch("Wobbledy")), (state, "Hi")));
        assert!(matches!(e, Err(Error::Internal(_))));
        assert!(matches!(map.get(&b'G'), Err(Error::Internal(_))));
    }

    #[test]
    fn expire_channels() {
        let map = ChannelMap::new();

        // Channel that has been unused beyond max duration allowed is expired
        map.replace(
            b'w',
            ch_with_details("wello", Duration::from_secs(180), Some(181)),
        )
        .unwrap();

        // Minimum value of max unused duration is 180 seconds
        assert_eq!(180, map.expire_channels().as_secs());
        assert!(map.get(&b'w').unwrap().is_none());

        let map = ChannelMap::new();

        // Channel that has been unused for shorter than max unused duration
        map.replace(
            b'w',
            ch_with_details("wello", Duration::from_secs(180), Some(120)),
        )
        .unwrap();

        map.replace(
            b'y',
            ch_with_details("yello", Duration::from_secs(180), Some(170)),
        )
        .unwrap();

        // Channel that has been unused beyond max duration allowed is expired
        map.replace(
            b'g',
            ch_with_details("gello", Duration::from_secs(180), Some(181)),
        )
        .unwrap();

        // Closed channel should be retained
        map.replace(b'h', closed("hello")).unwrap();

        // Return duration until next channel expires
        assert_eq!(10, map.expire_channels().as_secs());
        assert!(map.get(&b'w').unwrap().is_some());
        assert!(map.get(&b'y').unwrap().is_some());
        assert!(map.get(&b'h').unwrap().is_some());
        assert!(map.get(&b'g').unwrap().is_none());
    }
}
