"""Ferry preflight hook: records DNS lookups and outbound connects, with the caller.

`ferry preflight` puts this directory on PYTHONPATH for the command under test
only, so Python loads it at startup. It registers a PEP 578 audit hook for
socket events and appends one JSON line per non-loopback lookup or connect to
$FERRY_PREFLIGHT_NETLOG, naming the first stack frame outside the standard
library and the common HTTP clients, i.e. the library that wanted the network.

It never raises into the application and does nothing unless the environment
variable is set. Calls made from native code (C or Rust extensions) bypass
Python's audit events; the OS-level sandbox evidence covers those.
"""

import ipaddress
import json
import os
import sys
import threading

_PATH = os.environ.get("FERRY_PREFLIGHT_NETLOG")
_EVENTS = frozenset({"socket.getaddrinfo", "socket.connect", "socket.gethostbyname", "socket.gethostbyname_ex",
                     "socket.gethostbyaddr"})
# Frames whose top-level module starts with one of these are plumbing (stdlib
# networking, HTTP clients and their transports, e.g. httpx2/httpcore2), not
# the caller we want to name.
_PLUMBING = (
    "socket", "_socket", "ssl", "http", "urllib", "requests", "h11", "h2", "aiohttp", "anyio", "sniffio",
    "asyncio", "selectors", "concurrent", "threading", "trio", "websockets", "certifi", "truststore", "idna",
    "encodings", "importlib", "email", "sitecustomize",
)
_state = threading.local()


def _local(host):
    # Only "localhost" and IP literals of this host. A DNS name that merely starts like one
    # (127.0.0.1.nip.io) needs a resolver, so it is not local.
    if not isinstance(host, str):
        return False
    if host == "" or host.lower() == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_unspecified


def _caller():
    frame = sys._getframe(2)
    while frame is not None:
        module = frame.f_globals.get("__name__") or ""
        if not module.split(".")[0].startswith(_PLUMBING):
            return module, "%s:%d" % (frame.f_code.co_filename, frame.f_lineno)
        frame = frame.f_back
    return None, None


def _hook(event, args):
    if event not in _EVENTS or getattr(_state, "busy", False):
        return
    _state.busy = True
    try:
        port = None
        if event == "socket.getaddrinfo":
            host, port = args[0], args[1]
        elif event == "socket.connect":
            address = args[1]
            if not (isinstance(address, tuple) and len(address) >= 2):
                return  # AF_UNIX and other local sockets
            host, port = address[0], address[1]
        else:
            host = args[0]
        if isinstance(host, bytes):
            host = host.decode("ascii", "replace")
        if host is None:
            return
        local = _local(host)
        if local and event == "socket.connect":
            return  # loopback traffic is expected
        module, location = _caller()
        record = {
            "event": event.split(".", 1)[1], "host": str(host),
            "port": port if isinstance(port, int) else (str(port) if port is not None else None),
            "module": module, "location": location, "pid": os.getpid(),
            # Local lookups are recorded so the preflight can explain macOS
            # resolver-socket denials that carry no host name.
            "local": local,
        }
        with open(_PATH, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")
    except Exception:
        pass
    finally:
        _state.busy = False


if _PATH:
    try:
        sys.addaudithook(_hook)
    except Exception:
        pass
