using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Vortice.Direct3D11;
using Windows.Graphics.DirectX.Direct3D11;

[UnmanagedFunctionPointer(CallingConvention.StdCall)]
internal delegate int GetDxgiInterfaceDelegate(IntPtr @this, ref Guid iid, out IntPtr p);

internal readonly record struct PixelStats(
    string Sha256,
    long Bytes,
    double MeanByte,
    byte MinByte,
    byte MaxByte);

internal readonly record struct PixelFrame(
    PixelStats Stats,
    byte[]? Bgra);

internal static class PixelReadback
{
    private static readonly Guid IID_Access = new("A9B3D012-3DF2-4EE3-B8D1-8695F457D3C1");
    private static readonly Guid IID_Texture2D = new("6F15AAF2-D208-4E89-9AB4-489535D34F9C");

    internal static PixelStats Read(IDirect3DSurface surface, ID3D11Device device, int width, int height) =>
        ReadFrame(surface, device, width, height, false).Stats;

    internal static PixelFrame ReadFrame(
        IDirect3DSurface surface, ID3D11Device device, int width, int height, bool includePixels)
    {
        if (width <= 0 || height <= 0) throw new ArgumentOutOfRangeException(nameof(width));
        IntPtr unknown = IntPtr.Zero;
        IntPtr accessPtr = IntPtr.Zero;
        IntPtr texturePtr = IntPtr.Zero;
        try
        {
            unknown = ((WinRT.IWinRTObject)surface).NativeObject.GetRef();
            var iidAccess = IID_Access;
            Marshal.ThrowExceptionForHR(Marshal.QueryInterface(unknown, ref iidAccess, out accessPtr));
            var vtable = Marshal.ReadIntPtr(accessPtr);
            var getInterfacePtr = Marshal.ReadIntPtr(vtable, IntPtr.Size * 3);
            var getInterface = Marshal.GetDelegateForFunctionPointer<GetDxgiInterfaceDelegate>(getInterfacePtr);
            var iidTexture = IID_Texture2D;
            Marshal.ThrowExceptionForHR(getInterface(accessPtr, ref iidTexture, out texturePtr));
            using var source = new ID3D11Texture2D(texturePtr);
            texturePtr = IntPtr.Zero;

            var desc = source.Description;
            if ((int)desc.Width < width || (int)desc.Height < height)
                throw new InvalidOperationException("CAPTURE_TEXTURE_TOO_SMALL");
            var stagingDesc = new Texture2DDescription(
                desc.Format, desc.Width, desc.Height, 1, 1,
                BindFlags.None, ResourceUsage.Staging, CpuAccessFlags.Read,
                1, 0, ResourceOptionFlags.None);
            using var staging = device.CreateTexture2D(in stagingDesc);
            var context = device.ImmediateContext;
            context.CopyResource(staging, source);
            var mapped = context.Map(staging, 0, MapMode.Read, MapFlags.None);
            try
            {
                var rowBytes = checked(width * 4);
                var row = new byte[rowBytes];
                var pixels = includePixels ? new byte[checked(rowBytes * height)] : null;
                using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                long bytes = 0;
                ulong sum = 0;
                byte min = byte.MaxValue;
                byte max = byte.MinValue;
                for (var y = 0; y < height; y++)
                {
                    var rowPtr = IntPtr.Add(mapped.DataPointer, checked((int)(y * mapped.RowPitch)));
                    Marshal.Copy(rowPtr, row, 0, rowBytes);
                    hash.AppendData(row);
                    if (pixels is not null) Buffer.BlockCopy(row, 0, pixels, y * rowBytes, rowBytes);
                    bytes += row.Length;
                    foreach (var value in row)
                    {
                        sum += value;
                        if (value < min) min = value;
                        if (value > max) max = value;
                    }
                }
                var digest = Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
                var stats = new PixelStats(digest, bytes, bytes == 0 ? 0 : (double)sum / bytes, min, max);
                return new PixelFrame(stats, pixels);
            }
            finally { context.Unmap(staging, 0); }
        }
        finally
        {
            if (texturePtr != IntPtr.Zero) Marshal.Release(texturePtr);
            if (accessPtr != IntPtr.Zero) Marshal.Release(accessPtr);
            if (unknown != IntPtr.Zero) Marshal.Release(unknown);
        }
    }
}
