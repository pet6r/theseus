"""Wire OS-level drag-and-drop of files onto the Theseus DearPyGui viewport.

DearPyGui has no built-in support for receiving files dropped from Windows
Explorer. We do it manually via Win32: enable WM_DROPFILES on the viewport
HWND, subclass its WndProc, and forward dropped paths to a Python callback.

Windows-only. On non-Windows, `install_file_drop_handler` is a no-op.
"""

from __future__ import annotations

import ctypes
import logging
import sys
from ctypes import wintypes
from typing import Callable, Optional

log = logging.getLogger("theseus.gui_drop")

WM_DROPFILES = 0x0233
GWLP_WNDPROC = -4

# Module-globals to keep ctypes closures from being garbage-collected
# while the OS still holds pointers to them.
_new_wndproc_ref: Optional[ctypes.WINFUNCTYPE] = None
_old_wndproc: Optional[int] = None


def install_file_drop_handler(viewport_title: str, callback: Callable[[str], None]) -> bool:
    """Enable file drag-drop onto the viewport titled `viewport_title`.

    `callback(path)` is invoked once per dropped file, on the UI thread.

    Returns True if the handler was installed; False if Windows APIs were
    unavailable or the window could not be found.
    """
    if not sys.platform.startswith("win"):
        return False

    global _new_wndproc_ref, _old_wndproc

    user32 = ctypes.windll.user32
    shell32 = ctypes.windll.shell32

    # Pin argtypes so Python ints survive the boundary on x64 (default is c_int).
    user32.FindWindowW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR]
    user32.FindWindowW.restype = wintypes.HWND

    shell32.DragAcceptFiles.argtypes = [wintypes.HWND, wintypes.BOOL]
    shell32.DragAcceptFiles.restype = None

    shell32.DragFinish.argtypes = [wintypes.HANDLE]
    shell32.DragFinish.restype = None

    hwnd = user32.FindWindowW(None, viewport_title)
    if not hwnd:
        log.warning("install_file_drop_handler: window %r not found", viewport_title)
        return False

    shell32.DragAcceptFiles(hwnd, True)

    WNDPROC = ctypes.WINFUNCTYPE(
        ctypes.c_long,
        wintypes.HWND,
        wintypes.UINT,
        wintypes.WPARAM,
        wintypes.LPARAM,
    )

    SetWindowLongPtr = user32.SetWindowLongPtrW
    SetWindowLongPtr.restype = ctypes.c_void_p
    SetWindowLongPtr.argtypes = [wintypes.HWND, ctypes.c_int, WNDPROC]

    CallWindowProc = user32.CallWindowProcW
    CallWindowProc.restype = ctypes.c_long
    CallWindowProc.argtypes = [
        ctypes.c_void_p,
        wintypes.HWND,
        wintypes.UINT,
        wintypes.WPARAM,
        wintypes.LPARAM,
    ]

    DragQueryFile = shell32.DragQueryFileW
    DragQueryFile.argtypes = [
        wintypes.HANDLE,
        wintypes.UINT,
        wintypes.LPWSTR,
        wintypes.UINT,
    ]
    DragQueryFile.restype = wintypes.UINT

    def _proc(hwnd_, msg, wparam, lparam):
        if msg == WM_DROPFILES:
            hdrop = wparam
            try:
                count = DragQueryFile(hdrop, 0xFFFFFFFF, None, 0)
                for i in range(count):
                    length = DragQueryFile(hdrop, i, None, 0)
                    buf = ctypes.create_unicode_buffer(length + 1)
                    DragQueryFile(hdrop, i, buf, length + 1)
                    try:
                        callback(buf.value)
                    except Exception:  # noqa: BLE001
                        log.exception("file drop callback failed for %r", buf.value)
            finally:
                shell32.DragFinish(hdrop)
            return 0
        return CallWindowProc(_old_wndproc, hwnd_, msg, wparam, lparam)

    _new_wndproc_ref = WNDPROC(_proc)
    _old_wndproc = SetWindowLongPtr(hwnd, GWLP_WNDPROC, _new_wndproc_ref)
    log.info("installed file-drop handler on hwnd=0x%x", hwnd)
    return True
