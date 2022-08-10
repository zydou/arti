#  Using Zeroize in Arti.

The [`zeroize`] crate provides a best-effort mechanism to ensure that memory is
reset to zero before it is dropped.  Here we describe what we use it for, and
why.

This document will not explain the limitations of the `zeroize` crate: for those,
see the crate's documentation.

## What can Zeroize defend us against?

There are several ways that memory can get revealed to an attacker:

1. A programming bug might reveal uninitialized freed memory from the heap or
   stack.  This is less of a concern in safe Rust, but we still do link against
   some code written in unsafe languages.
2. A programming bug might reveal in-use memory from a different allocation on
   the heap or stack. This is also less of a concern in safe Rust.  (Zeroize
   cannot defend against this, since it only clears objects when they become
   unused.)
3. The memory might be written to a swap file.  (Zeroize cannot defend against
   this, but it can limit the window of time during which the secrets are in RAM
   to be swapped out.)
4. The memory might be revealed via a local attack by an attacker with physical
   or administrative access. (Zeroize can't prevent this either, but it can
   limit the window of time during which the secret are in RAM.)

So we see that zeroizing memory is not a categorical way to prevent
memory-exposure attacks. Instead, it is a defense-in-depth mechanism to limit
the impacts of these attacks if and when they occur.

There are several possible impacts of a memory exposure.  The most important
ones seem to be, in decreasing order of severity.

1. The attacker might learn a private key, and thereby be able to impersonate a
   relay or onion service.
2. The attacker might learn an ephemeral secret key, and thereby be able to
   decrypt traffic that had been sent over the network.  This would threaten
   forward-secrecy.
3. The attacker might learn information that would help them perform traffic
   analysis, like which guards a user was configured to use at a given time, or
   information about a path through the network, or an IP address that the user
   had been trying to connect to.

## Analysis and policies

During an exposure of type 2, 3, or 4 above, `zeroize` will never render the
attack completely harmless: it will only limit its impact.  Therefore, it
makes sense to use it as part of a defense-in-depth strategy to try to lower
the impact of these attacks if they occur.

Information of types 1 and 2 is fairly well contained in individual places in
the code. Information of type 3, however, is spread all over the place: it's
hard to categorically reason that any particular piece of data _wouldn't_ help
the attacker do traffic analysis.

Therefore, we are going to try to use `zeroize` to protect secret encryption
keys and private keys only.

Furthermore, though we will consider failure to use `zeroize` in these cases as
a bug, we will not treat it as a critical security bug: instead, we'll treat it
only as a missing defense-in-depth to be addressed under our usual update
schedule.

## Other defenses

There are orthogonal defenses against these attacks that we don't consider here.  
They include:

1. Encrypted swap
2. Reducing the amount of unsafe code, and sandboxing that code in a separate process.
3. Keeping secrets in memory pages marked as unswappable.
4. Disabling swap entirely.
5. OS-level mechanisms to make it harder for other processes to read the given
   process's memory.
6. Replacement allocator implementations that just zeroize everything.
