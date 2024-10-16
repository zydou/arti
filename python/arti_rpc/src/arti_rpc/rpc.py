"""
Type-based wrappers around our FFI functions.

These types are responsible for providing a python-like API
to the Arti RPC library.

TODO RPC: NOTE that these APIs are still in flux;
we will break them a lot before we declare them stable.
Don't use them in production.
"""

# mypy: allow-redefinition

from __future__ import annotations

# Design notes:
#
# - Every object gets a reference to the ctypes library object
#   from the `ffi` module.
#   We do this to better support programs that want exact control
#   over how the library is loaded.
#
# - Exported types start with "Arti", to make imports safer.

import json
import os
import socket
from ctypes import POINTER, byref, c_int, _Pointer as Ptr
from enum import Enum
import arti_rpc.ffi
from arti_rpc.ffi import (
    ArtiRpcStr as FfiStr,
    ArtiRpcError as FfiError,
    ArtiRpcHandle as FfiHandle,
    ArtiRpcConn as FfiConn,
    _ArtiRpcStatus as FfiStatus,
)
from typing import Optional,Tuple,Union # needed for Python 3.9, which lacks some syntax.

if os.name == "nt":
    def _socket_is_valid(sock):
        """Return true if `sock` is a valid SOCKET."""
        return sock != arti_rpc.ffi.INVALID_SOCKET

else:

    def _socket_is_valid(sock):
        """Return true if `sock` is a valid fd."""
        return sock >= 0

class _RpcBase:
    def __init__(self, rpc_lib):
        self._rpc = rpc_lib

    def _consume_rpc_str(self, s: Ptr[FfiStr]) -> str:
        """
        Consume an ffi.ArtiRpcStr and return a python string.
        """
        try:
            bs = self._rpc.arti_rpc_str_get(s)
            return bs.decode("utf-8")
        finally:
            self._rpc.arti_rpc_str_free(s)

    def _handle_error(self, rv: FfiStatus, error_ptr: Ptr[FfiError]) -> None:
        """
        If `(rv,error_ptr)` indicates an error, then raise that error.
        Otherwise do nothing.

        NOTE: Here we rely on the property that,
        when there is an error in a function,
        _only the error is actually set_.
        (No other object was constructed and needs to be freed.)
        """
        if rv != 0:
            raise ArtiRpcError(rv, error_ptr, self._rpc)
        elif error_ptr:
            # This should be impossible; it indicates misbehavior on arti's part.
            raise ArtiRpcError(rv, error_ptr, self._rpc)

class ArtiRpcConn(_RpcBase):
    """
    An open connection to Arti.
    """
    _conn: Optional[Ptr[FfiConn]]
    _session_id: str

    def __init__(self, connect_string: str, rpc_lib=None):
        """
        Try to connect to Arti, using the parameters specified in
        `connect_str`.

        If `rpc_lib` is specified, it must be a ctypes DLL,
        constructed with `arti_rpc.ffi.get_library`.
        If it's None, we use the default.
        """
        if rpc_lib is None:
            rpc_lib = arti_rpc.ffi.get_library()

        _RpcBase.__init__(self, rpc_lib)

        self._conn = None
        conn = POINTER(arti_rpc.ffi.ArtiRpcConn)()
        error = POINTER(arti_rpc.ffi.ArtiRpcError)()
        rv = self._rpc.arti_rpc_connect(
            connect_string.encode("utf-8"), byref(conn), byref(error)
        )
        self._handle_error(rv, error)
        assert conn
        self._conn = conn
        s = self._rpc.arti_rpc_conn_get_session_id(self._conn).decode("utf-8")
        self._session_id = s

    def __del__(self):
        if hasattr(self, '_conn'):
            # Note that if _conn is set, then _rpc is necessarily set.
            self._rpc.arti_rpc_conn_free(self._conn)

    def make_object(self, object_id:str) -> ArtiRpcObject:
        """
        Return an ArtiRpcObject for a given object ID on this connection.

        (The `ArtiRpcObject` API is a convenience wrapper that provides
        a more ergonomic interface to `execute` and `execute_with_handle`.)
        """
        return ArtiRpcObject(object_id, self)

    def session(self) -> ArtiRpcObject:
        """
        Return an ArtiRpcObject for this connection's Session object.

        (The Session is the root object of any RPC session;
        by invoking methods on the session,
        you can get the IDs for other objects.)
        """
        return self.make_object(self._session_id)

    def execute(self, msg: str) -> str:
        """
        Run an RPC request on this connection.

        On success, return a string containing the RPC reply.
        Otherwise, raise an error.

        You may (and probably should) omit the `id` field from your request.
        If you do, a new id will be automatically generated.
        """
        response = POINTER(arti_rpc.ffi.ArtiRpcStr)()
        error = POINTER(arti_rpc.ffi.ArtiRpcError)()
        rv = self._rpc.arti_rpc_conn_execute(
            self._conn, msg.encode("utf-8"), byref(response), byref(error)
        )
        self._handle_error(rv, error)
        return self._consume_rpc_str(response)

    def execute_with_handle(self, msg: str) -> ArtiRequestHandle:
        """
        Launch an RPC request on this connection, and return a ArtiRequestHandle
        to the open request.

        This API is suitable for use when you want incremental updates
        about the request status.
        """
        handle = POINTER(arti_rpc.ffi.ArtiRpcHandle)()
        error = POINTER(arti_rpc.ffi.ArtiRpcError)()
        rv = self._rpc.arti_rpc_conn_execute_with_handle(
            self._conn, msg.encode("utf-8"), byref(handle), byref(error)
        )
        self._handle_error(rv, error)
        return ArtiRequestHandle(handle, self._rpc)

    def connect(
        self,
        hostname: str,
        port: int,
        *,
        on_object:Union[ArtiRpcObject,str,None]=None,
        isolation:str="",
        want_stream_id:bool=False,
    ) : #TODO returntype is a bit silly. Make it sensible before annotating it.
        """
        Open an anonymized data stream to `hostname`:`port` over Arti.

        If `on_object` if provided, is the client-like object which will
        be told to open the connection.  Otherwise, the session
        will be told to open the connection.

        If `isolation` is provided, the resulting stream will be configured
        not to share a circuit with any other stream
        having a different `isolation`.

        If `want_stream_id` is true, then we register the resulting data stream
        as an RPC object, and return it along with the resulting socket.

        Caveats: TODO RPC.  Copy-paste the caveats from arti-rpc-client-core,
        once they have stabilized.
        """
        hostname: bytes = hostname.encode("utf-8")
        isolation: bytes = isolation.encode("utf-8")
        on_object: Optional[bytes] = _opt_object_id_to_bytes(on_object)
        if want_stream_id:
            stream_id = POINTER(arti_rpc.ffi.ArtiRpcStr)()
            stream_id_ptr = byref(stream_id)
        else:
            stream_id_ptr = None
        sock_cint = c_int(arti_rpc.ffi.INVALID_SOCKET)
        error = POINTER(arti_rpc.ffi.ArtiRpcError)()

        rv = self._rpc.arti_rpc_conn_open_stream(
            self._conn,
            hostname,
            port,
            on_object,
            isolation,
            byref(sock_cint),
            stream_id_ptr,
            byref(error),
        )
        self._handle_error(rv, error)

        assert _socket_is_valid(sock_cint.value)
        sock = socket.socket(fileno=sock_cint.value)

        if want_stream_id:
            return (sock, stream_id) # TODO: change stream_id into an Object.
        else:
            return sock


class ArtiRpcError(Exception):
    """
    An error returned by the RPC library.
    """
    _rv: FfiStatus
    _err: Ptr[FfiError]

    def __init__(self, rv: FfiStatus, err: Ptr[FfiError], rpc):
        self._rv = rv
        self._err = err
        self._rpc = rpc

    def __del__(self):
        self._rpc.arti_rpc_err_free(self._err)

    def __str__(self):
        status = self._rpc.arti_rpc_status_to_str(
            self._rpc.arti_rpc_err_status(self._err)
        ).decode("utf-8")
        msg = self._rpc.arti_rpc_err_message(self._err).decode("utf-8")
        return f"{status}: {msg}"

    def os_error_code(self) -> Optional[int]:
        """
        Return the OS error code (e.g., errno) associated with this error,
        if there is one.
        """
        code = self._rpc.arti_rpc_err_os_code(self._rpc._err)
        if code == 0:
            return None
        else:
            return code

    def response(self) -> Optional[int]:
        """
        Return the error response message associated with this error,
        if there is one.
        """
        response = self._rpc.arti_rpc_err_response(self._err)
        if response is None:
            return None
        else:
            return response.decode("utf-8")

def _opt_object_id_to_bytes(object_id: Union[ArtiRpcObject, str, None]) -> Optional[bytes]:
    """
    Convert `object_id` (if it is present) to a `bytes`.
    """
    if object_id is None:
        return None
    elif isinstance(object_id, ArtiRpcObject):
        return object_id.id().encode("UTF-8")
    else:
        return object_id.encode("UTF-8")

class ArtiRpcObject(_RpcBase):
    """
    Wrapper around an object ID and an ArtiRpcConn;
    used to launch RPC requests ergonomically.
    """
    _id: str
    _conn: ArtiRpcConn

    def __init__(self, object_id: str, connection: ArtiRpcConn):
        _RpcBase.__init__(self, connection._rpc)
        self._id = object_id
        self._conn = connection

    def id(self) -> str:
        """
        Return the ObjectId for this object.
        """
        return self._id

    # TODO RPC BREAKING: This needs some way to take a 'meta' field
    def invoke(self, method: str, **params):
        """
        Invoke a given RPC method with a given set of parameters,
        wait for it to complete,
        and return its result as a json object.
        """
        request = {"obj": self._id, "method": method, "params": params}
        result = self._conn.execute(json.dumps(request))
        return json.loads(result)["result"]

    # TODO RPC BREAKING: This needs some way to take a 'meta' field
    def invoke_with_handle(self, method: str, **params):
        """
        Invoke a given RPC method with a given set of parameters,
        and return an RpcHandle that can be used to check its progress.
        """
        request = {"obj": self._id, "method": method, "params": params}
        return self._conn.execute_with_handle(json.dumps(request))


class ArtiResponseTypeCode(Enum):
    """
    Value to indiate the type of a response to an RPC request.

    Returned by `ArtiRequestHandle::wait_raw`.
    """
    RESULT = 1
    UPDATE = 2
    ERROR = 3

class ArtiRequestHandle(_RpcBase):
    """
    Handle to a pending RPC request.
    """
    _handle: Ptr[FfiHandle]

    def __init__(self, handle: Ptr[FfiHandle], rpc):
        _RpcBase.__init__(self, rpc)
        self._handle = handle

    def __del__(self):
        self._rpc.arti_rpc_handle_free(self._handle)

    def wait_raw(self) -> Tuple[ArtiResponseTypeCode, str]:
        """
        Wait for a response (update, error, or final result)
        on this handle.

        Return a tuple of (responsetype, response),
        where responsetype is a ArtiResponseTypeCode.

        TODO RPC: Add a wrapper for this type that returns a more useful
        result.
        """
        response = POINTER(arti_rpc.ffi.ArtiRpcStr)()
        responsetype = arti_rpc.ffi.ArtiRpcResponseType(0)
        error = POINTER(arti_rpc.ffi.ArtiRpcError)()
        rv = self._rpc.arti_rpc_handle_wait(
            self._handle, byref(response), byref(responsetype), byref(error)
        )
        self._handle_error(rv, error)
        response_str = self._consume_rpc_str(response)
        return (ArtiResponseTypeCode(responsetype.value), response_str)

