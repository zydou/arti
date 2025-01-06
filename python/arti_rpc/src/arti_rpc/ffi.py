"""
ctypes-based wrappers for the functions exposed by arti-rpc-client-core.

These wrappers deliberately do as little as possible.
"""

from __future__ import annotations

import ctypes
from ctypes import (
    POINTER,
    c_char_p,
    c_int,
    sizeof,
    c_void_p,
    c_uint64,
    c_uint32,
    Structure,
)

import os
import sys

##########
# Declare some types for use with ctypes.


class ArtiRpcStr(Structure):
    """FFI type: String returned by the RPC protocol."""

    _fields_ = []


class ArtiRpcConnBuilder(Structure):
    """FFI type: Builder for constructing RPC connections."""

    _fields_ = []


class ArtiRpcConn(Structure):
    """FFI type: Connection to Arti via the RPC protocol."""

    _fields_ = []


class ArtiRpcError(Structure):
    """FFI type: Error from the RPC library."""

    _fields_ = []


class ArtiRpcHandle(Structure):
    """FFI type: Handle to an open RPC request."""

    _fields_ = []


ArtiRpcResponseType = c_int

_ConnOut = POINTER(POINTER(ArtiRpcConn))
_BuilderOut = POINTER(POINTER(ArtiRpcConnBuilder))
_ErrorOut = POINTER(POINTER(ArtiRpcError))
_RpcStrOut = POINTER(POINTER(ArtiRpcStr))
_RpcHandleOut = POINTER(POINTER(ArtiRpcHandle))
_ArtiRpcResponseTypeOut = POINTER(ArtiRpcResponseType)

_ArtiRpcStatus = c_uint32

_ArtiRpcRawSocket: type
if os.name == "nt":
    # Alas, SOCKET on win32 is defined as UINT_PTR_T,
    # which ctypes doesn't know about.
    if sizeof(c_void_p) == 4:
        _ArtiRpcRawSocket = c_uint32
        INVALID_SOCKET = (1 << 32) - 1
    elif sizeof(c_void_p) == 8:
        _ArtiRpcRawSocket = c_uint64
        INVALID_SOCKET = (1 << 64) - 1
    else:
        raise NotImplementedError()
else:
    _ArtiRpcRawSocket = c_int
    INVALID_SOCKET = -1


##########
# Tell ctypes about the function signatures.


def _annotate_library(lib: ctypes.CDLL):
    """Helper: annotate a ctypes dll `lib` with appropriate function signatures."""
    lib.arti_rpc_conn_open_stream.restype = _ArtiRpcStatus
    lib.arti_rpc_conn_open_stream.argtypes = [
        POINTER(ArtiRpcConn),
        c_char_p,
        c_int,
        c_char_p,
        c_char_p,
        POINTER(_ArtiRpcRawSocket),
        _RpcStrOut,
        _ErrorOut,
    ]

    lib.arti_rpc_conn_execute.argtypes = [
        POINTER(ArtiRpcConn),
        c_char_p,
        _RpcStrOut,
        _ErrorOut,
    ]
    lib.arti_rpc_conn_execute.restype = _ArtiRpcStatus

    lib.arti_rpc_conn_execute_with_handle.argtypes = [
        POINTER(ArtiRpcConn),
        c_char_p,
        _RpcHandleOut,
        _ErrorOut,
    ]
    lib.arti_rpc_conn_execute_with_handle.restype = _ArtiRpcStatus

    lib.arti_rpc_conn_get_session_id.argtypes = [POINTER(ArtiRpcConn)]
    lib.arti_rpc_conn_get_session_id.restype = c_char_p

    lib.arti_rpc_conn_builder_new.argtypes = [_BuilderOut, _ErrorOut]
    lib.arti_rpc_conn_builder_new.restype = _ArtiRpcStatus

    lib.arti_rpc_conn_builder_free.argtypes = [POINTER(ArtiRpcConnBuilder)]
    lib.arti_rpc_conn_builder_free.restype = None

    lib.arti_rpc_conn_builder_prepend_entry.argtypes = [
        POINTER(ArtiRpcConnBuilder),
        c_int,
        c_char_p,
        _ErrorOut,
    ]
    lib.arti_rpc_conn_builder_prepend_entry.restype = _ArtiRpcStatus

    lib.arti_rpc_conn_builder_connect.argtypes = [
        POINTER(ArtiRpcConnBuilder),
        _ConnOut,
        _ErrorOut,
    ]
    lib.arti_rpc_conn_builder_connect.restype = _ArtiRpcStatus

    lib.arti_rpc_conn_free.argtypes = [POINTER(ArtiRpcConn)]
    lib.arti_rpc_conn_free.restype = None

    lib.arti_rpc_err_free.argtypes = [POINTER(ArtiRpcError)]
    lib.arti_rpc_err_free.restype = None

    lib.arti_rpc_err_message.argtypes = [POINTER(ArtiRpcError)]
    lib.arti_rpc_err_message.restype = c_char_p

    lib.arti_rpc_err_os_error_code.argtypes = [POINTER(ArtiRpcError)]
    lib.arti_rpc_err_os_error_code.restype = c_int

    lib.arti_rpc_err_response.argtypes = [POINTER(ArtiRpcError)]
    lib.arti_rpc_err_response.restype = c_char_p

    lib.arti_rpc_err_status.argtypes = [POINTER(ArtiRpcError)]
    lib.arti_rpc_err_status.restype = _ArtiRpcStatus

    lib.arti_rpc_handle_free.argtypes = [POINTER(ArtiRpcHandle)]
    lib.arti_rpc_handle_free.restype = None

    lib.arti_rpc_handle_wait.argtypes = [
        POINTER(ArtiRpcHandle),
        _RpcStrOut,
        _ArtiRpcResponseTypeOut,
        _ErrorOut,
    ]
    lib.arti_rpc_handle_wait.restype = _ArtiRpcStatus

    lib.arti_rpc_status_to_str.argtypes = [_ArtiRpcStatus]
    lib.arti_rpc_status_to_str.restype = c_char_p

    lib.arti_rpc_str_free.argtypes = [POINTER(ArtiRpcStr)]
    lib.arti_rpc_str_free.restype = None

    lib.arti_rpc_str_get.argtypes = [POINTER(ArtiRpcStr)]
    lib.arti_rpc_str_get.restype = c_char_p


def _load_library():
    """Allocate a new shared library.

    First, look in the path in $LIBARTI_RPC_CLIENT_CORE (if it is
    set).  Otherwise, use the default path from LoadLibrary.

    """
    p = os.environ.get("LIBARTI_RPC_CLIENT_CORE")
    if p is not None:
        return ctypes.cdll.LoadLibrary(p)

    # TODO RPC: Do we need to start versioning this?
    base = "libarti_rpc_client_core"
    if sys.platform == "darwin":
        ext = "dylib"
    elif sys.platform == "win32":
        ext = "dll"
    else:
        ext = "so"
    libname = f"{base}.{ext}"

    return ctypes.cdll.LoadLibrary(libname)


_THE_LIBRARY = None


def get_library() -> ctypes.CDLL:
    """Try to find the shared library, loading it if needed.

    By default, we use the ctypes library's notion of the standard
    search path for shared libraries.

    Users can override the location of the library
    with the environment variable `LIBARTI_RPC_CLIENT_CORE`.
    """
    global _THE_LIBRARY
    if _THE_LIBRARY is not None:
        return _THE_LIBRARY

    lib = _load_library()
    _annotate_library(lib)
    _THE_LIBRARY = lib
    return lib
