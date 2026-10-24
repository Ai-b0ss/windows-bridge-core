"""Own-window PrintWindow observation on an inactive agent desktop.

This route is not WGC and does not establish application/task success.
The caller must execute inside the owned hidden worker so its timeout/job
contains an application that fails to return from synchronous PrintWindow.
"""
import base64
import ctypes
from ctypes import wintypes as w
import hashlib
import struct
import zlib

MAX_PIXELS = 4_000_000
MAX_PNG_BYTES = 1_000_000

class HiddenCaptureError(RuntimeError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)

def png_from_bgra(width, height, pixels):
    if type(width) is not int or type(height) is not int or min(width, height) <= 0 or width*height > MAX_PIXELS:
        raise HiddenCaptureError("HIDDEN_CAPTURE_SIZE_INVALID")
    if len(pixels) != width*height*4:
        raise HiddenCaptureError("HIDDEN_CAPTURE_PIXELS_INVALID")
    # GDI's reserved alpha byte is not opacity. Encode opaque RGB.
    rows = []
    for y in range(height):
        bgra = pixels[y*width*4:(y+1)*width*4]
        rgb = bytearray(width*3)
        rgb[0::3] = bgra[2::4]
        rgb[1::3] = bgra[1::4]
        rgb[2::3] = bgra[0::4]
        rows.append(b"\0"+rgb)
    def chunk(kind, data):
        return struct.pack(">I", len(data))+kind+data+struct.pack(">I", zlib.crc32(kind+data)&0xffffffff)
    png = (b"\x89PNG\r\n\x1a\n"+chunk(b"IHDR", struct.pack(">IIBBBBB", width,height,8,2,0,0,0))
           +chunk(b"IDAT", zlib.compress(b"".join(rows)))+chunk(b"IEND", b""))
    if len(png) > MAX_PNG_BYTES:
        raise HiddenCaptureError("HIDDEN_CAPTURE_REPLY_TOO_LARGE")
    return png

def capture_owned_window(hwnd, owns, *, backend=None, identity=None):
    if type(hwnd) is not int or hwnd <= 0 or not owns(hwnd):
        raise HiddenCaptureError("HIDDEN_WINDOW_NOT_OWNED")
    if identity is None:
        from cua_desktop_identity import desktop_identity
        identity = desktop_identity
    desktop = identity()
    if not desktop["current"].startswith("FFBridge-Agent-") or desktop["current"] == desktop["input"]:
        raise HiddenCaptureError("HIDDEN_DESKTOP_IDENTITY_INVALID")
    backend = backend if backend is not None else Win32PrintWindow()
    width, height, pixels = backend.capture(hwnd)
    # Never release pixels from a target that disappeared or changed ownership.
    if not owns(hwnd) or identity() != desktop:
        raise HiddenCaptureError("HIDDEN_CAPTURE_TARGET_CHANGED")
    png = png_from_bgra(width, height, pixels)
    return {"engine":"PRINTWINDOW", "hwnd":hwnd, "frame_w":width, "frame_h":height,
            "image_mime":"image/png", "image_base64":base64.b64encode(png).decode("ascii"),
            "image_sha256":hashlib.sha256(png).hexdigest(),
            "private_desktop":desktop["current"], "physical_input_used":False,
            "owner_desktop_access_allowed":False, "verified":False,
            "verification_required":True, "wgc_used":False}

class Win32PrintWindow:
    def __init__(self):
        self.u=ctypes.WinDLL("user32",use_last_error=True)
        self.g=ctypes.WinDLL("gdi32",use_last_error=True)
        self.u.GetWindowRect.argtypes=[w.HWND,ctypes.POINTER(w.RECT)];self.u.GetWindowRect.restype=w.BOOL
        self.u.GetDC.argtypes=[w.HWND];self.u.GetDC.restype=w.HDC
        self.u.ReleaseDC.argtypes=[w.HWND,w.HDC];self.u.ReleaseDC.restype=ctypes.c_int
        self.u.PrintWindow.argtypes=[w.HWND,w.HDC,w.UINT];self.u.PrintWindow.restype=w.BOOL
        self.g.CreateCompatibleDC.argtypes=[w.HDC];self.g.CreateCompatibleDC.restype=w.HDC
        self.g.CreateCompatibleBitmap.argtypes=[w.HDC,ctypes.c_int,ctypes.c_int];self.g.CreateCompatibleBitmap.restype=w.HANDLE
        self.g.SelectObject.argtypes=[w.HDC,w.HANDLE];self.g.SelectObject.restype=w.HANDLE
        self.g.DeleteObject.argtypes=[w.HANDLE];self.g.DeleteObject.restype=w.BOOL
        self.g.DeleteDC.argtypes=[w.HDC];self.g.DeleteDC.restype=w.BOOL
        self.g.GetDIBits.argtypes=[w.HDC,w.HANDLE,w.UINT,w.UINT,w.LPVOID,w.LPVOID,w.UINT];self.g.GetDIBits.restype=ctypes.c_int

    def capture(self, hwnd):
        rect=w.RECT()
        if not self.u.GetWindowRect(hwnd,ctypes.byref(rect)):
            raise HiddenCaptureError("HIDDEN_CAPTURE_RECT_FAILED")
        width,height=rect.right-rect.left,rect.bottom-rect.top
        if min(width,height)<=0 or width*height>MAX_PIXELS:
            raise HiddenCaptureError("HIDDEN_CAPTURE_SIZE_INVALID")
        dc=memory=bitmap=previous=None
        selected=False
        try:
            dc=self.u.GetDC(hwnd)
            if not dc:raise HiddenCaptureError("HIDDEN_CAPTURE_DC_FAILED")
            memory=self.g.CreateCompatibleDC(dc)
            if not memory:raise HiddenCaptureError("HIDDEN_CAPTURE_MEMORY_DC_FAILED")
            bitmap=self.g.CreateCompatibleBitmap(dc,width,height)
            if not bitmap:raise HiddenCaptureError("HIDDEN_CAPTURE_BITMAP_FAILED")
            previous=self.g.SelectObject(memory,bitmap)
            if not previous or previous==ctypes.c_void_p(-1).value:
                raise HiddenCaptureError("HIDDEN_CAPTURE_SELECT_FAILED")
            selected=True
            if not self.u.PrintWindow(hwnd,memory,0):
                raise HiddenCaptureError("HIDDEN_CAPTURE_RENDER_FAILED")
            self.g.SelectObject(memory,previous);selected=False
            info=ctypes.create_string_buffer(struct.pack("<IiiHHIIiiII",40,width,-height,1,32,0,width*height*4,0,0,0,0)+bytes(16))
            pixels=ctypes.create_string_buffer(width*height*4)
            if self.g.GetDIBits(memory,bitmap,0,height,pixels,info,0)!=height:
                raise HiddenCaptureError("HIDDEN_CAPTURE_READBACK_FAILED")
            after=w.RECT()
            if not self.u.GetWindowRect(hwnd,ctypes.byref(after)) or tuple((after.left,after.top,after.right,after.bottom))!=tuple((rect.left,rect.top,rect.right,rect.bottom)):
                raise HiddenCaptureError("HIDDEN_CAPTURE_TARGET_CHANGED")
            return width,height,pixels.raw
        finally:
            if selected:self.g.SelectObject(memory,previous)
            if bitmap:self.g.DeleteObject(bitmap)
            if memory:self.g.DeleteDC(memory)
            if dc:self.u.ReleaseDC(hwnd,dc)
