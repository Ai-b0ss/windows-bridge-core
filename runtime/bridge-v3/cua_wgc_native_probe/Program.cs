using System.Diagnostics;
using System.Runtime.InteropServices;
using Vortice.Direct3D;
using Vortice.Direct3D11;
using Vortice.DXGI;
using Windows.Graphics.Capture;
using Windows.Graphics.DirectX;
using Windows.Graphics.DirectX.Direct3D11;

[ComImport]
[Guid("3628E81B-3CAC-4C60-B7F4-23CE0E0C3356")]
[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface IGraphicsCaptureItemInterop
{
    [PreserveSig]
    int CreateForWindow(IntPtr hwnd, ref Guid iid, out IntPtr ppv);
}

internal static class Program
{
    private static readonly Guid IID_Interop = new("3628E81B-3CAC-4C60-B7F4-23CE0E0C3356");
    private static readonly Guid IID_Item = new("79C3F95B-31F7-4EC2-A464-632EF5D30760");

    [DllImport("user32.dll")]
    private static extern IntPtr GetForegroundWindow();

    [DllImport("combase.dll", PreserveSig = true)]
    private static extern int WindowsCreateString([MarshalAs(UnmanagedType.LPWStr)] string source, uint length, out IntPtr hstring);

    [DllImport("combase.dll", PreserveSig = true)]
    private static extern int WindowsDeleteString(IntPtr hstring);

    [DllImport("combase.dll", PreserveSig = true)]
    private static extern int RoGetActivationFactory(IntPtr activatableClassId, ref Guid iid, out IntPtr factory);

    [DllImport("d3d11.dll", EntryPoint = "CreateDirect3D11DeviceFromDXGIDevice")]
    private static extern uint CreateDirect3D11DeviceFromDXGIDevice(IntPtr dxgiDevice, out IntPtr graphicsDevice);

    internal static GraphicsCaptureItem CreateItem(IntPtr hwnd)
    {
        const string runtimeClass = "Windows.Graphics.Capture.GraphicsCaptureItem";
        var hr = WindowsCreateString(runtimeClass, (uint)runtimeClass.Length, out var hstring);
        Marshal.ThrowExceptionForHR(hr);
        IntPtr factoryPtr = IntPtr.Zero;
        IntPtr itemPtr = IntPtr.Zero;
        try
        {
            var iid = IID_Interop;
            hr = RoGetActivationFactory(hstring, ref iid, out factoryPtr);
            Marshal.ThrowExceptionForHR(hr);
            var interop = (IGraphicsCaptureItemInterop)Marshal.GetObjectForIUnknown(factoryPtr);
            var itemIid = IID_Item;
            hr = interop.CreateForWindow(hwnd, ref itemIid, out itemPtr);
            Marshal.ThrowExceptionForHR(hr);
            return WinRT.MarshalInterface<GraphicsCaptureItem>.FromAbi(itemPtr);
        }
        finally
        {
            if (itemPtr != IntPtr.Zero) Marshal.Release(itemPtr);
            if (factoryPtr != IntPtr.Zero) Marshal.Release(factoryPtr);
            WindowsDeleteString(hstring);
        }
    }

    private static async Task<int> Main(string[] args)
    {
        if (args.Length > 0 && args[0] == "--jsonl-sidecar")
            return await SidecarHost.RunAsync();
        if (args.Length > 0 && args[0] == "--dxgi-probe")
            return DxgiProbe.Run(args.Skip(1).ToArray());

        var timeoutMs = args.Length > 0 && int.TryParse(args[0], out var parsed) ? parsed : 3000;
        var sw = Stopwatch.StartNew();
        try
        {
            Console.WriteLine($"{{\"phase\":\"start\",\"timeout_ms\":{timeoutMs}}}");
            if (!GraphicsCaptureSession.IsSupported())
            {
                Console.WriteLine("{\"ok\":false,\"error\":\"WGC_UNSUPPORTED\"}");
                return 2;
            }

            var hwnd = args.Length > 1 && long.TryParse(args[1], out var hwndArg) ? new IntPtr(hwndArg) : GetForegroundWindow();
            if (hwnd == IntPtr.Zero)
            {
                Console.WriteLine("{\"ok\":false,\"error\":\"NO_FOREGROUND_WINDOW\"}");
                return 3;
            }

            var item = CreateItem(hwnd);
            var size = item.Size;
            var d3dHr = D3D11.D3D11CreateDevice(null, DriverType.Hardware, DeviceCreationFlags.BgraSupport, null, out ID3D11Device? device);
            d3dHr.CheckError();
            using var ownedDevice = device;
            using var dxgiDevice = device!.QueryInterface<IDXGIDevice>();

            var wrapHr = CreateDirect3D11DeviceFromDXGIDevice(dxgiDevice.NativePointer, out var graphicsDevicePtr);
            if (wrapHr != 0 || graphicsDevicePtr == IntPtr.Zero)
            {
                Console.WriteLine($"{{\"ok\":false,\"error\":\"D3D11_WINRT_WRAP_FAILED\",\"hresult\":{wrapHr}}}");
                return 4;
            }

            IDirect3DDevice direct3DDevice;
            try
            {
                direct3DDevice = WinRT.MarshalInterface<IDirect3DDevice>.FromAbi(graphicsDevicePtr);
            }
            finally
            {
                Marshal.Release(graphicsDevicePtr);
            }

            using var framePool = Direct3D11CaptureFramePool.CreateFreeThreaded(
                direct3DDevice,
                DirectXPixelFormat.B8G8R8A8UIntNormalized,
                1,
                size);
            using var session = framePool.CreateCaptureSession(item);
            session.IsCursorCaptureEnabled = false;
            session.StartCapture();

            Direct3D11CaptureFrame? frame = null;
            while (sw.ElapsedMilliseconds < timeoutMs)
            {
                frame = framePool.TryGetNextFrame();
                if (frame is not null) break;
                await Task.Delay(10);
            }

            if (frame is null)
            {
                Console.WriteLine($"{{\"ok\":false,\"error\":\"FRAME_TIMEOUT\",\"elapsed_ms\":{sw.ElapsedMilliseconds},\"item_w\":{size.Width},\"item_h\":{size.Height}}}");
                return 5;
            }

            using (frame)
            {
                var content = frame.ContentSize;
                var surfaceOk = frame.Surface is not null;
                if (!surfaceOk) throw new InvalidOperationException("FRAME_SURFACE_NULL");
                var pixels = PixelReadback.Read(frame.Surface!, device!, content.Width, content.Height);
                Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object> {
                    ["ok"] = true, ["engine"] = "WGC", ["target"] = "hwnd", ["hwnd"] = hwnd.ToInt64(),
                    ["elapsed_ms"] = sw.ElapsedMilliseconds, ["item_w"] = size.Width, ["item_h"] = size.Height,
                    ["frame_w"] = content.Width, ["frame_h"] = content.Height, ["surface"] = true,
                    ["pixel_sha256"] = pixels.Sha256, ["pixel_bytes"] = pixels.Bytes,
                    ["mean_byte"] = pixels.MeanByte, ["min_byte"] = pixels.MinByte, ["max_byte"] = pixels.MaxByte
                }));
            }
            return 0;
        }
        catch (Exception ex)
        {
            var type = ex.GetType().Name.Replace("\"", "");
            Console.WriteLine($"{{\"ok\":false,\"error\":\"EXCEPTION\",\"type\":\"{type}\",\"hresult\":{ex.HResult},\"elapsed_ms\":{sw.ElapsedMilliseconds}}}");
            return 10;
        }
    }
}
