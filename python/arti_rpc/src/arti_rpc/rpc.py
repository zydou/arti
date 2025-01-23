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
import logging
import os
import socket
import sys
from ctypes import POINTER, byref, c_int, _Pointer as Ptr
from enum import Enum
import arti_rpc.ffi
from arti_rpc.ffi import (
    ArtiRpcStr as FfiStr,
    ArtiRpcError as FfiError,
    ArtiRpcHandle as FfiHandle,
    ArtiRpcConn as FfiConn,
    ArtiRpcConnBuilder as FfiBuilder,
    _ArtiRpcStatus as FfiStatus,
)
from typing import (
    Optional,
    Tuple,
    Union,
)  # needed for Python 3.9, which lacks some syntax.

if os.name == "nt":

    def _socket_is_valid(sock):
        """Return true if `sock` is a valid SOCKET."""
        return sock != arti_rpc.ffi.INVALID_SOCKET

else:

    def _socket_is_valid(sock):
        """Return true if `sock` is a valid fd."""
        return sock >= 0


_logger = logging.getLogger(__name__)


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


def _into_json_str(o: Union[str, dict]) -> str:
    """
    If 'o' is a dict, convert it into a json string.

    Otherwise return it as-is.
    """
    if isinstance(o, dict):
        return json.dumps(o)
    else:
        return o


class _BuildEntType(Enum):
    """
    Value to indicate the kind of an RPC connect point search path entry.

    Returned by ArtiRpcResponse.kind().
    """

    LITERAL_CONNECT_POINT = 1
    EXPANDABLE_PATH = 2
    LITERAL_PATH = 3


class ArtiRpcConnBuilder(_RpcBase):
    """
    A builder object used to configure connections to Arti.
    """

    _builder: Optional[Ptr[FfiBuilder]]

    def __init__(self, rpc_lib=None):
        """
        Return a new ArtiR
        """
        self._builder = None

        if rpc_lib is None:
            rpc_lib = arti_rpc.ffi.get_library()

        _RpcBase.__init__(self, rpc_lib)

        builder = POINTER(arti_rpc.ffi.ArtiRpcConnBuilder)()
        error = POINTER(arti_rpc.ffi.ArtiRpcError)()
        rv = self._rpc.arti_rpc_conn_builder_new(byref(builder), byref(error))
        self._handle_error(rv, error)
        assert builder
        self._builder = builder

    def __del__(self):
        if self._builder is not None:
            self._rpc.arti_rpc_conn_builder_free(self._builder)
            self._builder = None

    def _prepend_entry(self, entrykind: _BuildEntType, entry: str) -> None:
        """
        Helper: Prepend `entry` to the search path of this builder.
        """
        error = POINTER(arti_rpc.ffi.ArtiRpcError)()
        rv = self._rpc.arti_rpc_conn_builder_prepend_entry(
            self._builder, entrykind.value, entry.encode("utf-8"), byref(error)
        )
        self._handle_error(rv, error)

    def prepend_literal_connect_point(self, connect_point: str) -> None:
        """
        Prepend `connect_point` to this builder's search path
        as a literal connect point.
        """
        self._prepend_entry(_BuildEntType.LITERAL_CONNECT_POINT, connect_point)

    def prepend_expandable_path(self, path: str) -> None:
        """
        Prepend `path` to this builder's search path
        as an expandable path (one to which Arti's variable substitution applies).
        """
        self._prepend_entry(_BuildEntType.EXPANDABLE_PATH, path)

    def prepend_literal_path(self, path: str) -> None:
        """
        Prepend `path` to this builder's search path
        as a literal path (one to which Arti's variable substitution does not apply).
        """
        self._prepend_entry(_BuildEntType.LITERAL_PATH, path)

    def connect(self) -> ArtiRpcConn:
        """
        Use the settings in this builder to open a connection to Arti.
        """
        conn = self._connect_inner()

        return ArtiRpcConn(rpc_lib=self._rpc, _conn=conn)

    def _connect_inner(self) -> Ptr[FfiConn]:
        """
        Helper: Use the settings in this builder to open a connection to Arti,
        and return a pointer to that connection.
        """
        conn = POINTER(arti_rpc.ffi.ArtiRpcConn)()
        error = POINTER(arti_rpc.ffi.ArtiRpcError)()
        rv = self._rpc.arti_rpc_conn_builder_connect(
            self._builder, byref(conn), byref(error)
        )
        self._handle_error(rv, error)
        assert conn

        return conn


class ArtiRpcConn(_RpcBase):
    """
    An open connection to Arti.
    """

    _conn: Optional[Ptr[FfiConn]]
    _session: ArtiRpcObject
    _conn_object: ArtiRpcObject

    def __init__(self, rpc_lib=None, _conn: Optional[Ptr[FfiConn]] = None):
        """
        Try to connect to Arti using default settings.

        If `rpc_lib` is specified, it must be a ctypes DLL,
        constructed with `arti_rpc.ffi.get_library`.
        If it's None, we use the default.
        """
        self._conn = None

        if rpc_lib is None:
            rpc_lib = arti_rpc.ffi.get_library()

        _RpcBase.__init__(self, rpc_lib)

        if _conn is None:
            _conn = ArtiRpcConnBuilder()._connect_inner()

        self._conn = _conn
        s = self._rpc.arti_rpc_conn_get_session_id(self._conn).decode("utf-8")
        self._session = self.make_object(s)
        self._conn_object = self.make_object("connection")

    def __del__(self):
        if self._conn is not None:
            # Note that if _conn is set, then _rpc is necessarily set.
            self._rpc.arti_rpc_conn_free(self._conn)
            self._conn = None

    def make_object(self, object_id: str) -> ArtiRpcObject:
        """
        Return an ArtiRpcObject for a given object ID on this connection.

        (The `ArtiRpcObject` API is a convenience wrapper that provides
        a more ergonomic interface to `execute` and `execute_with_handle`.)
        """
        return ArtiRpcObject(object_id, self)

    def connection(self) -> ArtiRpcObject:
        """
        Return an ArtiRpcObject for this connection itself.

        The connection object is used to cancel and otherwise manipulate
        RPC requests.
        """
        return self._conn_object

    def session(self) -> ArtiRpcObject:
        """
        Return an ArtiRpcObject for this connection's Session object.

        (The Session is the root object of any RPC session;
        by invoking methods on the session,
        you can get the IDs for other objects.)
        """
        return self._session

    def execute(self, request: Union[str, dict]) -> dict:
        """
        Run an RPC request on this connection.

        On success, return the "response" from the RPC reply.
        Otherwise, raise an error.

        You may (and probably should) omit the `id` field from your request.
        If you do, a new id will be automatically generated.

        The request may be a string, or a dict that will be encoded
        as a json object.
        """
        msg = _into_json_str(request)
        response = POINTER(arti_rpc.ffi.ArtiRpcStr)()
        error = POINTER(arti_rpc.ffi.ArtiRpcError)()
        rv = self._rpc.arti_rpc_conn_execute(
            self._conn, msg.encode("utf-8"), byref(response), byref(error)
        )
        self._handle_error(rv, error)
        r = ArtiRpcResponse(self._consume_rpc_str(response))
        assert r.kind() == ArtiRpcResponseKind.RESULT
        return r["result"]

    def execute_with_handle(self, request: Union[str, dict]) -> ArtiRequestHandle:
        """
        Launch an RPC request on this connection, and return a ArtiRequestHandle
        to the open request.

        This API is suitable for use when you want incremental updates
        about the request status.
        """
        msg = _into_json_str(request)
        handle = POINTER(arti_rpc.ffi.ArtiRpcHandle)()
        error = POINTER(arti_rpc.ffi.ArtiRpcError)()
        rv = self._rpc.arti_rpc_conn_execute_with_handle(
            self._conn, msg.encode("utf-8"), byref(handle), byref(error)
        )
        self._handle_error(rv, error)
        return ArtiRequestHandle(handle, self, self._rpc)

    def open_stream(
        self,
        hostname: str,
        port: int,
        *,
        on_object: Union[ArtiRpcObject, str, None] = None,
        isolation: str = "",
        want_stream_id: bool = False,
    ) -> Tuple[socket.socket, Optional[ArtiRpcObject]]:
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
            stream_id_obj = self.make_object(self._consume_rpc_str(stream_id))
            return (sock, stream_id_obj)
        else:
            return (sock, None)


class ArtiRpcErrorStatus(Enum):
    """
    Value return to indicate the type of an error returned by the
    RPC library.

    This may or may not correspond to an error from the RPC server.

    Returned by ArtiRpcError.status_code()

    See arti-rpc-client-core documentation for more information.
    """

    SUCCESS = 0
    INVALID_INPUT = 1
    NOT_SUPPORTED = 2
    CONNECT_IO = 3
    BAD_AUTH = 4
    PEER_PROTOCOL_VIOLATION = 5
    SHUTDOWN = 6
    INTERNAL = 7
    REQUEST_FAILED = 8
    REQUEST_COMPLETED = 9
    PROXY_IO = 10
    STREAM_FAILED = 11
    NOT_AUTHENTICATED = 12
    ALL_CONNECT_ATTEMPTS_FAILED = 13
    CONNECT_POINT_NOT_USABLE = 14
    BAD_CONNECT_POINT_PATH = 15


def _error_status_from_int(status: int) -> Union[ArtiRpcErrorStatus, int]:
    """
    If `status` is a recognized member of `ArtiRpcErrorStatus`,
    return that member.
    Otherwise, return `status`.
    """
    try:
        return ArtiRpcErrorStatus(status)
    except ValueError:
        return status


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
        if self._err is not None:
            self._rpc.arti_rpc_err_free(self._err)
            self._err = None

    def __str__(self):
        status = self._rpc.arti_rpc_status_to_str(
            self._rpc.arti_rpc_err_status(self._err)
        ).decode("utf-8")
        msg = self._rpc.arti_rpc_err_message(self._err).decode("utf-8")
        if status == msg:
            return status
        else:
            return f"{status}: {msg}"

    def status_code(self) -> Union[ArtiRpcErrorStatus, int]:
        """
        Return the status code for this error.

        This code is generated by the underlying RPC library.
        """
        return _error_status_from_int(self._rpc.arti_rpc_err_status(self._err))

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

    def response_str(self) -> Optional[str]:
        """
        Return the RPC response string associated with this error,
        if this error represents an error message from the RPC server.
        """
        response = self._rpc.arti_rpc_err_response(self._err)
        if response is None:
            return None
        else:
            return response.decode("utf-8")

    def response_obj(self) -> Optional[dict]:
        """
        Return the RPC error object associated with this error,
        if this error represents an error message from the RPC server.
        """
        response = self.response_str()
        if response is None:
            return None
        else:
            return json.loads(response)["error"]


def _opt_object_id_to_bytes(
    object_id: Union[ArtiRpcObject, str, None]
) -> Optional[bytes]:
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
    _owned: bool
    _meta: Optional[dict]

    def __init__(self, object_id: str, connection: ArtiRpcConn):
        _RpcBase.__init__(self, connection._rpc)
        self._id = object_id
        self._conn = connection
        self._owned = True
        self._meta = None

    def id(self) -> str:
        """
        Return the ObjectId for this object.
        """
        return self._id

    def invoke(self, method: str, **params) -> dict:
        """
        Invoke a given RPC method with a given set of parameters,
        wait for it to complete,
        and return its result as a json object.
        """
        request = {"obj": self._id, "method": method, "params": params}
        if self._meta is not None:
            request["meta"] = self._meta
        return self._conn.execute(json.dumps(request))

    def invoke_with_handle(self, method: str, **params):
        """
        Invoke a given RPC method with a given set of parameters,
        and return an RpcHandle that can be used to check its progress.
        """
        request = {"obj": self._id, "method": method, "params": params}
        if self._meta is not None:
            request["meta"] = self._meta
        return self._conn.execute_with_handle(json.dumps(request))

    def with_meta(self, **params) -> ArtiRpcObject:
        """
        Return a helper that can be used to set meta-parameters
        on a request made with this object.

        Currently recognized meta-parameters are "updates"
        and "require": See rpc-meta-draft.md for more information.

        The wrapper will support `invoke` and `invoke_with_handle`,
        and will pass them any provided `params` given as an argument
        to this function as meta-request parameters.

        The resulting object does not have ownership on the
        underlying RPC object.
        """
        new_obj = ArtiRpcObject(self._id, self._conn)
        new_obj._owned = False
        if params:
            new_obj._meta = params
        else:
            new_obj._meta = None
        return new_obj

    def release_ownership(self):
        """
        Release ownership of the underlying RPC object.

        By default, when the last reference to an ArtiRpcObject is dropped,
        we tell the RPC server to release the corresponding RPC ObjectID.
        After that happens, nothing else can use that ObjectID
        (and the object may get freed on the server side,
        if nothing else refers to it.)

        Calling this method releases ownership, such that we will not
        tell the RPC server to release the ObjectID when this object is dropped.
        """
        self._owned = False

    def __del__(self):
        if self._owned and self._conn._conn is not None:
            try:
                self.invoke("rpc:release")
            except ArtiRpcError:
                _logger.warn("RPC error while deleting object", exc_info=sys.exc_info())


class ArtiRpcResponseKind(Enum):
    """
    Value to indicate the type of a response to an RPC request.

    Returned by ArtiRpcResponse.kind().
    """

    RESULT = 1
    UPDATE = 2
    ERROR = 3


class ArtiRpcResponse:
    """
    A response from the RPC server.

    May be a successful result;
    an incremental update;
    or an error.
    """

    _kind: ArtiRpcResponseKind
    _response: str
    _obj: dict

    def __init__(self, response: str):
        self._response = response
        self._obj = json.loads(response)

        have_result = "result" in self._obj
        have_error = "error" in self._obj
        have_update = "update" in self._obj

        # Here we (ab)use the property that the booleans True and False
        # can also be used as the ints 1 and 0.
        assert have_result + have_error + have_update == 1

        if have_result:
            self._kind = ArtiRpcResponseKind.RESULT
        elif have_error:
            self._kind = ArtiRpcResponseKind.ERROR
        elif have_update:
            self._kind = ArtiRpcResponseKind.UPDATE
        else:
            # Unreachable.
            assert False

    def __str__(self):
        return self._response

    def __getitem__(self, key: str):
        return self._obj[key]

    def kind(self) -> ArtiRpcResponseKind:
        """Return the kind of response that this is."""
        return self._kind

    def error(self) -> Optional[dict]:
        """
        If this is an error response, return its `error` member.
        Otherwise return `None`.
        """
        return self._obj.get("error")

    def result(self) -> Optional[dict]:
        """
        If this is a successful result, return its 'result' member.
        Otherwise return `None`.
        """
        return self._obj.get("result")

    def update(self) -> Optional[dict]:
        """
        If this is an incremental update, return its 'update' member.
        Otherwise return `None`.
        """
        return self._obj.get("update")


class ArtiRequestHandle(_RpcBase):
    """
    Handle to a pending RPC request.

    NOTE: Dropping this handle does not cancel the request.
    If you want to cancel the request on the server side,
    use the cancel method.
    """

    _handle: Ptr[FfiHandle]
    _conn: ArtiRpcConn
    _id: str

    def __init__(self, handle: Ptr[FfiHandle], conn: ArtiRpcConn, rpc):
        _RpcBase.__init__(self, rpc)
        self._conn = conn
        self._handle = handle

    def __del__(self):
        if self._handle is not None:
            self._rpc.arti_rpc_handle_free(self._handle)
            self._handle = None

    def wait(self) -> ArtiRpcResponse:
        """
        Wait for a response (update, error, or final result)
        on this handle.

        Return the response received.
        """
        response = POINTER(arti_rpc.ffi.ArtiRpcStr)()
        responsetype = arti_rpc.ffi.ArtiRpcResponseType(0)
        error = POINTER(arti_rpc.ffi.ArtiRpcError)()
        rv = self._rpc.arti_rpc_handle_wait(
            self._handle, byref(response), byref(responsetype), byref(error)
        )
        self._handle_error(rv, error)
        response_obj = ArtiRpcResponse(self._consume_rpc_str(response))
        expected_kind = ArtiRpcResponseKind(responsetype.value)
        assert response_obj.kind() == expected_kind
        return response_obj

    def cancel(self):
        """
        Attempt to cancel this request.

        This can fail if the request has alrady stopped,
        or if it stops before we have a chance to cancel it.
        """
        error = POINTER(arti_rpc.ffi.ArtiRpcError)()
        rv = self._rpc.arti_rpc_conn_cancel_handle(
            self._conn._conn, self._handle, byref(error)
        )

        self._handle_error(rv, error)
