using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;
using Vortice.Direct3D;
using Vortice.Direct3D11;
using Vortice.DXGI;
using Windows.Graphics.Capture;
using Windows.Graphics.DirectX;
using Windows.Graphics.DirectX.Direct3D11;

internal static class SidecarHost
{
    [DllImport("d3d11.dll", EntryPoint = "CreateDirect3D11DeviceFromDXGIDevice")]
    private static extern uint CreateDirect3D11DeviceFromDXGIDevice(IntPtr dxgiDevice, out IntPtr graphicsDevice);

    private sealed class WgcSession : IDisposable
    {
        internal long Hwnd { get; }
        private readonly ID3D11Device _device;
        private readonly IDirect3DDevice _direct3DDevice;
        private readonly Direct3D11CaptureFramePool _framePool;
        private readonly GraphicsCaptureSession _session;
        private Windows.Graphics.SizeInt32 _poolSize;
        private int _poolResizeEvents;
        internal WgcSession(long hwnd)
        {
            Hwnd = hwnd;
            try {
                if (!GraphicsCaptureSession.IsSupported()) throw new NotSupportedException("WGC_UNSUPPORTED");
            } catch (Exception ex) { ex.Data["capture_stage"] = "graphics-capture-runtime-preflight"; throw; }
            GraphicsCaptureItem item;
            try { item = Program.CreateItem(new IntPtr(hwnd)); }
            catch (Exception ex) { ex.Data["capture_stage"] = "create-window-capture-item"; throw; }
            var size = item.Size;
            var hr = D3D11.D3D11CreateDevice(null, DriverType.Hardware, DeviceCreationFlags.BgraSupport, null, out ID3D11Device? device);
            try { hr.CheckError(); }
            catch (Exception ex) { ex.Data["capture_stage"] = "create-d3d11-device"; throw; }
            _device = device!;
            using var dxgiDevice = _device.QueryInterface<IDXGIDevice>();
            var wrapHr = CreateDirect3D11DeviceFromDXGIDevice(dxgiDevice.NativePointer, out var graphicsDevicePtr);
            if (wrapHr != 0 || graphicsDevicePtr == IntPtr.Zero)
                throw new InvalidOperationException("D3D11_WINRT_WRAP_FAILED");
            try { _direct3DDevice = WinRT.MarshalInterface<IDirect3DDevice>.FromAbi(graphicsDevicePtr); }
            finally { Marshal.Release(graphicsDevicePtr); }
            _poolSize = size;
            _framePool = Direct3D11CaptureFramePool.CreateFreeThreaded(
                _direct3DDevice, DirectXPixelFormat.B8G8R8A8UIntNormalized, 2, _poolSize);
            _session = _framePool.CreateCaptureSession(item);
            _session.IsCursorCaptureEnabled = false;
            _session.StartCapture();
        }

        internal async Task<Dictionary<string, object>> CaptureAsync(
            int timeoutMs, int stableFrames, long minFreshTicks, string? previousHash, bool includePixels, int maxPixelBytes)
        {
            var sw = Stopwatch.StartNew();
            var seen = 0;
            var preBoundary = 0;
            var previousFrames = 0;
            string? lastHash = null;
            var streak = 0;
            PixelStats lastPixels = default;
            Windows.Graphics.SizeInt32 lastSize = default;
            long lastFrameTicks = 0;
            while (sw.ElapsedMilliseconds < timeoutMs)
            {
                var frame = _framePool.TryGetNextFrame();
                if (frame is null) { await Task.Delay(1); continue; }
                seen++;
                var content = frame.ContentSize;
                if (content.Width != _poolSize.Width || content.Height != _poolSize.Height)
                {
                    frame.Dispose();
                    if (content.Width <= 0 || content.Height <= 0)
                        throw new InvalidOperationException("TARGET_SIZE_INVALID");
                    _framePool.Recreate(
                        _direct3DDevice, DirectXPixelFormat.B8G8R8A8UIntNormalized, 2, content);
                    _poolSize = content;
                    _poolResizeEvents++;
                    lastHash = null;
                    streak = 0;
                    continue;
                }
                using (frame)
                {
                    lastFrameTicks = frame.SystemRelativeTime.Ticks;
                    if (minFreshTicks > 0 && lastFrameTicks < minFreshTicks) { preBoundary++; continue; }
                    var pixels = PixelReadback.Read(frame.Surface, _device, content.Width, content.Height);
                    if (previousHash is not null && pixels.Sha256 == previousHash)
                    {
                        previousFrames++;
                        lastHash = null;
                        streak = 0;
                        continue;
                    }
                    streak = pixels.Sha256 == lastHash ? streak + 1 : 1;
                    lastHash = pixels.Sha256;
                    lastPixels = pixels;
                    lastSize = content;
                    if (streak >= stableFrames)
                    {
                        var result = Result(true, seen, preBoundary, previousFrames, streak, lastFrameTicks, lastSize, lastPixels, sw.Elapsed.TotalMilliseconds);
                        if (includePixels)
                        {
                            var bytesRequired = checked(content.Width * content.Height * 4);
                            if (bytesRequired > maxPixelBytes) throw new InvalidOperationException("PIXEL_PAYLOAD_TOO_LARGE");
                            var withPixels = PixelReadback.ReadFrame(frame.Surface, _device, content.Width, content.Height, true);
                            result["pixel_bgra_base64"] = Convert.ToBase64String(withPixels.Bgra!);
                            result["pixel_format"] = "BGRA8_TOP_DOWN";
                        }
                        return result;
                    }
                }
            }
            return Result(false, seen, preBoundary, previousFrames, streak, lastFrameTicks, lastSize, lastPixels, sw.Elapsed.TotalMilliseconds);
        }

        private Dictionary<string, object> Result(bool ok, int seen, int pre, int previous,
            int streak, long frameTicks, Windows.Graphics.SizeInt32 size, PixelStats pixels, double elapsedMs)
        {
            return new Dictionary<string, object>
            {
                ["ok"] = ok,
                ["engine"] = "WGC",
                ["hwnd"] = Hwnd,
                ["frames_seen"] = seen,
                ["pre_boundary_frames_rejected"] = pre,
                ["previous_state_frames"] = previous,
                ["pool_resize_events"] = _poolResizeEvents,
                ["stable_streak"] = streak,
                ["frame_system_relative_ticks"] = frameTicks,
                ["frame_w"] = size.Width,
                ["frame_h"] = size.Height,
                ["pixel_sha256"] = pixels.Sha256 ?? "",
                ["pixel_bytes"] = pixels.Bytes,
                ["elapsed_ms"] = Math.Round(elapsedMs, 3),
                ["raw_pixels_persisted"] = false
            };
        }

        public void Dispose()
        {
            _session.Dispose();
            _framePool.Dispose();
            if (_direct3DDevice is IDisposable disposable) disposable.Dispose();
            _device.Dispose();
        }
    }

    private static long MonotonicTimeSpanTicks() =>
        TimeSpan.FromSeconds((double)Stopwatch.GetTimestamp() / Stopwatch.Frequency).Ticks;
    internal static async Task<int> RunAsync()
    {
        WgcSession? capture = null;
        try
        {
            string? line;
            while ((line = await Console.In.ReadLineAsync()) is not null)
            {
                string id = "";
                try
                {
                    using var doc = JsonDocument.Parse(line);
                    var root = doc.RootElement;
                    id = root.GetProperty("id").GetString() ?? "";
                    var op = root.GetProperty("op").GetString() ?? "";
                    var args = root.TryGetProperty("args", out var a) ? a : default;
                    if (op == "hang") { await Task.Delay(Timeout.Infinite); continue; }
                    if (op == "crash") Environment.Exit(23);
                    if (op == "mark")
                    {
                        Emit(id, new Dictionary<string, object> { ["ok"] = true, ["monotonic_ticks"] = MonotonicTimeSpanTicks(), ["pid"] = Environment.ProcessId });
                        continue;
                    }
                    if (op == "capabilities") {
                        try { Emit(id, new Dictionary<string, object> { ["ok"] = true, ["wgc_supported"] = GraphicsCaptureSession.IsSupported(), ["owner_hwnd_used"] = false, ["capture_started"] = false }); }
                        catch (Exception ex) { ex.Data["capture_stage"] = "graphics-capture-runtime-preflight"; throw; }
                        continue;
                    }
                    if (op != "capture") { EmitError(id, "UNSUPPORTED_OP"); continue; }

                    var hwnd = args.GetProperty("hwnd").GetInt64();
                    var timeoutMs = args.TryGetProperty("timeout_ms", out var t) ? t.GetInt32() : 1500;
                    var stableFrames = args.TryGetProperty("stable_frames", out var s) ? s.GetInt32() : 2;
                    var minFresh = args.TryGetProperty("min_fresh_ticks", out var m) ? m.GetInt64() : 0;
                    var previousHash = args.TryGetProperty("previous_hash", out var p) && p.ValueKind == JsonValueKind.String ? p.GetString() : null;
                    var includePixels = args.TryGetProperty("include_pixels", out var ip) && ip.ValueKind == JsonValueKind.True;
                    var maxPixelBytes = args.TryGetProperty("max_pixel_bytes", out var mp) ? mp.GetInt32() : 12000000;
                    var freshSession = args.TryGetProperty("fresh_session", out var fs) && fs.ValueKind == JsonValueKind.True;
                    if (hwnd == 0 || timeoutMs < 100 || timeoutMs > 10000 || stableFrames < 1 || stableFrames > 4 || maxPixelBytes < 1024 || maxPixelBytes > 16000000)
                    {
                        EmitError(id, "BAD_CAPTURE_ARGS");
                        continue;
                    }
                    if (capture is null || capture.Hwnd != hwnd || freshSession)
                    {
                        capture?.Dispose();
                        capture = new WgcSession(hwnd);
                    }
                    var result = await capture.CaptureAsync(timeoutMs, stableFrames, minFresh, previousHash, includePixels, maxPixelBytes);
                    result["pid"] = Environment.ProcessId;
                    Emit(id, result);
                }
                catch (Exception ex)
                {
                    Emit(id, new Dictionary<string, object>
                    {
                        ["ok"] = false,
                        ["error"] = ex is TimeoutException ? ex.Message : ex.GetType().Name,
                        ["hresult"] = ex.HResult,
                        ["capture_stage"] = ex.Data["capture_stage"]?.ToString() ?? "start-or-read-frame",
                        ["pid"] = Environment.ProcessId
                    });
                }
            }
            return 0;
        }
        finally { capture?.Dispose(); }
    }
    private static void Emit(string id, Dictionary<string, object> payload)
    {
        payload["id"] = id;
        Console.Out.WriteLine(JsonSerializer.Serialize(payload));
        Console.Out.Flush();
    }

    private static void EmitError(string id, string error) =>
        Emit(id, new Dictionary<string, object>
        {
            ["ok"] = false,
            ["error"] = error,
            ["pid"] = Environment.ProcessId
        });
}
