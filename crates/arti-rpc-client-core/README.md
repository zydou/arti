

Notes so far:

 * On top of io::{BufRead,Write}, we build llconn::{Reader,Writer}.  Reader is a tiny wrapper; Writer validates the
   syntax of outgoing messages.

 * On top of them, we build conn::RpcConn.  This is the one I expect most users would want; it
   matches requests to responses and assigns IDs as needed.

 * I'm not using tokio or async at all.  I'm trying to keep dependencies to a minimum.

 * I am *not* following our usual practice with Display on errors; instead, I am including
   inner errors in the Display implementation of the outer errors.  The rationale here
   is that we probably just want to return a single string for FFI purposes.


 Coming next:
 * [x] clean out the X X X Xs
 * [x] diziet's revisions on connimpl.
 * [x] actual implementations for making connections.
 * [ ] More tests.
 * [ ] update this readme.
 * [x] interface for connecting to arti
 * [ ] C FFI wrappers for everything reasonable
 * [ ] enable the usual warnings.
 * [ ] Finish this readme.
