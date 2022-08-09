//! Parameters influencing all channels in a Tor client

use educe::Educe;

use tor_cell::chancell::msg::PaddingNegotiate;

use super::padding;

/// Generate most of the module: things which contain or process all params fields (or each one)
///
/// There is one call to this macro, which has as argument
/// the body of `struct ChannelPaddingInstructions`, with the following differences:
///
///  * field visibility specifiers are not specified; they are provided by the macro
///  * non-doc attributes that ought to be applied to fields in `ChannelPaddingInstructions`
///    are prefixed with `field`, e.g. `#[field educe(Default ...)]`;
///    this allows applying doc attributes to other items too.
///
/// Generates, fairly straightforwardly:
///
/// ```ignore
/// pub struct ChannelPaddingInstructions { ... } // containing the fields as specified
/// pub struct ChannelPaddingInstructionsUpdates { ... } // containing `Option` of each field
/// pub fn ChannelPaddingInstructions::initial_update(&self) -> ChannelPaddingInstructionsUpdates;
/// pub fn ChannelPaddingInstructionsUpdatesBuilder::$field(self, new_value: _) -> Self;
/// ```
///
/// Within the macro body, we indent the per-field `$( )*` with 2 spaces.
macro_rules! define_channels_params_and_automatic_impls { { $(
    $( #[doc $($doc_attr:tt)*] )*
    $( #[field $other_attr:meta] )*
    $field:ident : $ty:ty
),* $(,)? } => {

    /// Initial, and, overall, parameters for channels
    ///
    /// This is used both to generate the initial parameters,
    /// and to handle updates:
    /// when used for handling updates,
    /// it contains the last parameters that has been implemented.
    ///
    /// Central code managing all channels will contain a `ChannelPaddingInstructions`,
    /// and use `ChannelPaddingInstructionsUpdatesBuilder` to both update that params
    /// and generate `ChannelPaddingInstructionsUpdates` messages representing the changes.
    ///
    /// The channel frontend (methods on `Channel`)
    /// processes `ChannelPaddingInstructionsUpdates` from the channel manager,
    /// possibly into channel-specific updates.
    ///
    /// `Default` is a placeholder to use pending availability of a netdir etc.
    #[derive(Debug, Educe, Clone, Eq, PartialEq)]
    #[educe(Default)]
    pub struct ChannelPaddingInstructions {
      $(
        $( #[doc $($doc_attr)*] )*
        $( #[$other_attr] )*
        pub(crate) $field: $ty,
      )*
    }

    /// Reparameterisation message
    ///
    /// Can contain updates to each of the fields in `ChannelPaddingInstructions`.
    /// Constructed via [`ChannelPaddingInstructionsUpdatesBuilder`],
    /// which is obtained from [`ChannelPaddingInstructions::start_update`].
    ///
    /// Sent to all channel implementations, when they ought to change their behaviour.
    #[derive(Debug, Default, Clone, Eq, PartialEq)]
    pub struct ChannelPaddingInstructionsUpdates {
      $(
        /// New value, if it has changed.
        ///
        /// Having this contain `Option` allows the sender of an update to promise
        /// that the value hasn't changed, and thereby allows the channel implementation
        /// to avoid touching state that it doesn't need to (eg, timers).
        pub(crate) $field: Option<$ty>,
      )*
    }

    impl ChannelPaddingInstructions {
        /// Create an update message which sets all non-default settings in `self`
        ///
        /// Used during channel startup.
        #[must_use = "initial_update makes an updates message that must be sent to have effect"]
        pub fn initial_update(&self) -> Option<ChannelPaddingInstructionsUpdates> {
            let mut supposed = ChannelPaddingInstructions::default();
            supposed.start_update()
              $(
                .$field(self.$field.clone())
              )*
                .finish()
        }
    }

    impl<'c> ChannelPaddingInstructionsUpdatesBuilder<'c> {
      $(
        $( #[doc $($doc_attr)*] )*
        ///
        /// (Adds this setting to the update, if it has changed.)
        pub fn $field(mut self, new_value: $ty) -> Self {
            if &new_value != &self.params.$field {
                self
                    .update
                    .get_or_insert_with(|| Default::default())
                    .$field = Some(new_value.clone());
                self.params.$field = new_value;
            }
            self
        }
      )*
    }

    impl ChannelPaddingInstructionsUpdates {
        /// Combines `more` into `self`
        ///
        /// Values from `more` override ones in `self`.
        pub fn combine(&mut self, more: &Self) {
          $(
            if let Some(new_value) = &more.$field {
                self.$field = Some(new_value.clone());
            }
          )*
        }

      $(
        #[cfg(feature = "testing")]
        $( #[doc $($doc_attr)*] )*
        ///
        /// Accessor.
        /// For testing the logic which generates channel padding control instructions.
        pub fn $field(&self) -> Option<&$ty> {
            self.$field.as_ref()
        }
      )*
    }
} }

define_channels_params_and_automatic_impls! {
    /// Whether to send padding
    #[field educe(Default(expression = "interim_enable_by_env_var()"))]
    padding_enable: bool,

    /// Padding timing parameters
    ///
    /// This is in abeyance if `send_padding` is `false`;
    /// we still pass it because the usual case is that padding is enabled/disabled
    /// rather than the parameters changing,
    /// so the padding timer always keeps parameters, even when disabled.
    padding_parameters: padding::Parameters,

    /// Channel padding negotiation cell
    padding_negotiate: PaddingNegotiate,
}

/// Placeholder function for saying whether to enable channel padding
///
/// This will be abolished in due course.
pub(crate) fn interim_enable_by_env_var() -> bool {
    std::env::var("ARTI_EXPERIMENTAL_CHANNEL_PADDING").unwrap_or_default() != ""
}

/// Builder for a channels params update
///
/// Obtain this from `ChannelPaddingInstructions::update`,
/// call zero or more setter methods,
/// call [`finish`](ChannelPaddingInstructionsUpdatesBuilder::finish),
/// and then send the resulting message.
///
/// # Panics
///
/// Panics if dropped.  Instead, call `finish`.
pub struct ChannelPaddingInstructionsUpdatesBuilder<'c> {
    /// Tracking the existing params
    params: &'c mut ChannelPaddingInstructions,

    /// The update we are building
    ///
    /// `None` means nothing has changed yet.
    update: Option<ChannelPaddingInstructionsUpdates>,

    /// Make it hard to write code paths that drop this
    drop_bomb: bool,
}

impl ChannelPaddingInstructions {
    /// Start building an update to channel parameters
    ///
    /// The builder **must not be dropped**, once created;
    /// instead, [`finish`](ChannelPaddingInstructionsUpdatesBuilder::finish) must be called.
    /// So prepare your new values first, perhaps fallibly,
    /// and only then create and use the builder and send the update, infallibly.
    ///
    /// (This is because the builder uses `self: ChannelPaddingInstructions`
    /// to track which values have changed,
    /// and the values in `self` are updated immediately by the field update methods.)
    ///
    /// # Panics
    ///
    /// [`ChannelPaddingInstructionsUpdatesBuilder`] panics if it is dropped.
    pub fn start_update(&mut self) -> ChannelPaddingInstructionsUpdatesBuilder {
        ChannelPaddingInstructionsUpdatesBuilder {
            params: self,
            update: None,
            drop_bomb: true,
        }
    }
}

impl<'c> Drop for ChannelPaddingInstructionsUpdatesBuilder<'c> {
    fn drop(&mut self) {
        assert!(!self.drop_bomb, "ChannelPaddingInstructionsUpdatesBuilder dropped");
    }
}

impl<'c> ChannelPaddingInstructionsUpdatesBuilder<'c> {
    /// Finalise the update
    ///
    /// If nothing actually changed, returns `None`.
    /// (Tracking this, and returning `None`, allows us to avoid bothering
    /// every channel with a null update.)
    ///
    /// If `Some` is returned, the update **must** be implemented,
    /// since the underlying tracking [`ChannelPaddingInstructions`] has already been updated.
    #[must_use = "the update from finish() must be sent, to avoid losing params changes"]
    pub fn finish(mut self) -> Option<ChannelPaddingInstructionsUpdates> {
        self.drop_bomb = false;
        self.update.take()
    }
}
