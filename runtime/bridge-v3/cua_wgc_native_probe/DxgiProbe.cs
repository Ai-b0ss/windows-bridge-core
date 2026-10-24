using System.Diagnostics;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using Vortice.Direct3D;
using Vortice.Direct3D11;
using Vortice.DXGI;
using static Vortice.DXGI.DXGI;

internal static class DxgiProbe
{
    internal static int Run(string[] args)
    {
        var timeoutMs = args.Length > 0 && int.TryParse(args[0], out var t) ? Math.Clamp(t, 50, 5000) : 1000;
        var sw = Stopwatch.StartNew();
        try
        {
            using var factory = CreateDXGIFactory1<IDXGIFactory1>();
            var adapterHr = factory.EnumAdapters1(0, out IDXGIAdapter1? adapter);
            adapterHr.CheckError();
            using var ownedAdapter = adapter!;
            var outputs = new List<Dictionary<string, object>>();
            for (uint i = 0; i < 16; i++)
            {
                var hr = ownedAdapter.EnumOutputs(i, out IDXGIOutput? candidate);
                if (hr.Failure || candidate is null) break;
                using (candidate)
                {
                    var d = candidate.Description;
                    outputs.Add(new Dictionary<string, object> {
                        ["index"] = i, ["device"] = d.DeviceName,
                        ["left"] = d.DesktopCoordinates.Left, ["top"] = d.DesktopCoordinates.Top,
                        ["right"] = d.DesktopCoordinates.Right, ["bottom"] = d.DesktopCoordinates.Bottom,
                        ["attached"] = d.AttachedToDesktop
                    });
                }
            }
            if (outputs.Count == 0) throw new InvalidOperationException("DXGI_NO_OUTPUTS");
            var outputHr = ownedAdapter.EnumOutputs(0, out IDXGIOutput? selectedOutput);
            outputHr.CheckError();
            using var output = selectedOutput!;
            using var output1 = output.QueryInterface<IDXGIOutput1>();
            var bounds = output1.Description.DesktopCoordinates;
            var width = bounds.Right - bounds.Left;
            var height = bounds.Bottom - bounds.Top;
            var create = D3D11.D3D11CreateDevice(
                ownedAdapter, DriverType.Unknown, DeviceCreationFlags.BgraSupport, null,
                out ID3D11Device? device);
            create.CheckError();
            using var ownedDevice = device!;
            using var duplication = output1.DuplicateOutput(ownedDevice);
            var acquired = false;
            IDXGIResource? desktopResource = null;
            try
            {
                var hr = duplication.AcquireNextFrame((uint)timeoutMs, out var frameInfo, out desktopResource);
                hr.CheckError();
                acquired = true;
                using var source = desktopResource!.QueryInterface<ID3D11Texture2D>();
                var desc = source.Description;
                var stagingDesc = new Texture2DDescription(
                    desc.Format, desc.Width, desc.Height, 1, 1,
                    BindFlags.None, ResourceUsage.Staging, CpuAccessFlags.Read,
                    1, 0, ResourceOptionFlags.None);
                using var staging = ownedDevice.CreateTexture2D(in stagingDesc);
                var context = ownedDevice.ImmediateContext;
                context.CopyResource(staging, source);
                var mapped = context.Map(staging, 0, MapMode.Read, Vortice.Direct3D11.MapFlags.None);
                string fullHash;
                string cropHash;
                var cropW = Math.Min(128, width);
                var cropH = Math.Min(128, height);
                var cropX = Math.Max(0, (width - cropW) / 2);
                var cropY = Math.Max(0, (height - cropH) / 2);
                try
                {
                    using var full = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                    using var crop = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                    var rowBytes = checked(width * 4);
                    var row = new byte[rowBytes];
                    var cropRow = new byte[cropW * 4];
                    for (var y = 0; y < height; y++)
                    {
                        var rowPtr = IntPtr.Add(mapped.DataPointer, checked((int)(y * mapped.RowPitch)));
                        Marshal.Copy(rowPtr, row, 0, rowBytes);
                        full.AppendData(row);
                        if (y >= cropY && y < cropY + cropH)
                        {
                            Buffer.BlockCopy(row, cropX * 4, cropRow, 0, cropRow.Length);
                            crop.AppendData(cropRow);
                        }
                    }
                    fullHash = Convert.ToHexString(full.GetHashAndReset()).ToLowerInvariant();
                    cropHash = Convert.ToHexString(crop.GetHashAndReset()).ToLowerInvariant();
                }
                finally { context.Unmap(staging, 0); }
                var result = new Dictionary<string, object> {
                    ["ok"] = true, ["engine"] = "DXGI_DESKTOP_DUPLICATION",
                    ["output_count"] = outputs.Count, ["outputs"] = outputs,
                    ["width"] = width, ["height"] = height,
                    ["origin_x"] = bounds.Left, ["origin_y"] = bounds.Top,
                    ["pixel_sha256"] = fullHash, ["crop_sha256"] = cropHash,
                    ["crop"] = new[] {cropX, cropY, cropW, cropH},
                    ["elapsed_ms"] = Math.Round(sw.Elapsed.TotalMilliseconds, 3),
                    ["raw_pixels_persisted"] = false
                };
                Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(result));
                return 0;
            }
            finally
            {
                desktopResource?.Dispose();
                if (acquired)
                {
                    try { duplication.ReleaseFrame(); } catch { }
                }
            }
        }
        catch (Exception ex)
        {
            var payload = new Dictionary<string, object> {
                ["ok"] = false, ["engine"] = "DXGI_DESKTOP_DUPLICATION",
                ["error"] = ex.GetType().Name, ["message"] = ex.Message,
                ["hresult"] = ex.HResult,
                ["elapsed_ms"] = Math.Round(sw.Elapsed.TotalMilliseconds, 3)
            };
            Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(payload));
            return 20;
        }
    }
}
