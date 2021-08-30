//! Simple implementation for the internal map state of a ChanMgr.

use super::{AbstractChannel, Pending};
use crate::{Error, Result};

use std::collections::{hash_map, HashMap};
use std::sync::Arc;

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
    Open(Arc<C>),
    /// A channel that's getting built.
    Building(Pending<C>),
    /// A temporary invalid state.
    ///
    /// We insert this into the map temporarily as a placeholder in
    /// `change_state()`.
    Poisoned(Priv),
}

impl<C> ChannelState<C> {
    /// Create a new shallow copy of this ChannelState.
    fn clone_ref(&self) -> Result<Self> {
        use ChannelState::*;
        match self {
            Open(chan) => Ok(Open(Arc::clone(chan))),
            Building(pending) => Ok(Building(pending.clone())),
            Poisoned(_) => Err(Error::Internal("Poisoned state in channel map")),
        }
    }

    /// For testing: either give the Open channel inside this state,
    /// or panic if there is none.
    #[cfg(test)]
    fn unwrap_open(&self) -> Arc<C> {
        match self {
            ChannelState::Open(chan) => Arc::clone(chan),
            _ => panic!("Not an open channel"),
        }
    }
}

impl<C: AbstractChannel> ChannelState<C> {
    /// Return an error if `ident`is definitely not a matching
    /// matching identity for this state.
    fn check_ident(&self, ident: &C::Ident) -> Result<()> {
        match self {
            ChannelState::Open(chan) => {
                if chan.ident() == ident {
                    Ok(())
                } else {
                    Err(Error::Internal("Identity mismatch"))
                }
            }
            ChannelState::Poisoned(_) => Err(Error::Internal("Poisoned state in channel map")),
            ChannelState::Building(_) => Ok(()),
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
    pub(crate) fn remove_unusable(&self) -> Result<()> {
        let mut map = self.channels.lock()?;
        map.retain(|_, state| match state {
            ChannelState::Poisoned(_) => false,
            ChannelState::Open(ch) => ch.is_usable(),
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
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]
    use super::*;
    #[derive(Eq, PartialEq, Debug)]
    struct FakeChannel {
        ident: &'static str,
        usable: bool,
    }
    impl AbstractChannel for FakeChannel {
        type Ident = u8;
        fn ident(&self) -> &Self::Ident {
            &self.ident.as_bytes()[0]
        }
        fn is_usable(&self) -> bool {
            self.usable
        }
    }
    fn ch(ident: &'static str) -> ChannelState<FakeChannel> {
        ChannelState::Open(Arc::new(FakeChannel {
            ident,
            usable: true,
        }))
    }
    fn closed(ident: &'static str) -> ChannelState<FakeChannel> {
        ChannelState::Open(Arc::new(FakeChannel {
            ident,
            usable: false,
        }))
    }

    #[test]
    fn simple_ops() {
        let map = ChannelMap::new();
        use ChannelState::Open;

        assert!(map.replace(b'h', ch("hello")).unwrap().is_none());
        assert!(map.replace(b'w', ch("wello")).unwrap().is_none());

        match map.get(&b'h') {
            Ok(Some(Open(chan))) if chan.ident == "hello" => {}
            _ => panic!(),
        }

        assert!(map.get(&b'W').unwrap().is_none());

        match map.replace(b'h', ch("hebbo")) {
            Ok(Some(Open(chan))) if chan.ident == "hello" => {}
            _ => panic!(),
        }

        assert!(map.remove(&b'Z').unwrap().is_none());
        match map.remove(&b'h') {
            Ok(Some(Open(chan))) if chan.ident == "hebbo" => {}
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
}
