//! Hidden service (onion service) client key management functionality

// TODO HS what layer should be responsible for finding and dispatching keys?
// I think it should be as high as possible, so keys should be passed into
// the hs connector for each connection.  Otherwise there would have to be an
// HsKeyProvider trait here, and error handling gets complicated.

