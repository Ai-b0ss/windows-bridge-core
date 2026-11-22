using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

internal static class Program {
    const string PipeName = "ff_browser_companion_v1";
    const string ExpectedOrigin = "chrome-extension://mmhkecdcdceeibbhalmfhjleeebgdbhk/";
    static readonly AutoResetEvent ResponseReady = new AutoResetEvent(false);
    static readonly ManualResetEvent ChromeDone = new ManualResetEvent(false);
    static readonly object StateLock = new object();
    static readonly object OutputLock = new object();
    static Stream ChromeInput;
    static Stream ChromeOutput;
    static string PendingId;
    static string PendingResponse;
    static volatile bool ChromeClosed;

    static string CanonicalRoot() {
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        return Path.Combine(local, "FF-Windows-Bridge", "bridge-v3");
    }

    static string NormalizeRoot(string root) {
        return Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar).ToLowerInvariant();
    }

    static string PipeForRoot(string root) {
        var normalized = NormalizeRoot(root);
        if (normalized == NormalizeRoot(CanonicalRoot())) return PipeName;
        using (var sha = SHA256.Create()) {
            var hash = sha.ComputeHash(Encoding.Unicode.GetBytes(normalized));
            return PipeName + "_" + BitConverter.ToString(hash, 0, 16).Replace("-", "").ToLowerInvariant();
        }
    }

    static string ReadSecret(string root) {
        var path = Path.Combine(root, "secret");
        if (!File.Exists(path)) throw new InvalidOperationException("BRIDGE_SECRET_MISSING");
        var value = File.ReadAllText(path, Encoding.ASCII).Trim();
        if (value.Length < 16) throw new InvalidOperationException("BRIDGE_SECRET_INVALID");
        return value;
    }

    static byte[] ReadExactly(Stream stream, int count) {
        var buffer = new byte[count];
        var offset = 0;
        while (offset < count) {
            var n = stream.Read(buffer, offset, count - offset);
            if (n <= 0) return null;
            offset += n;
        }
        return buffer;
    }

    static string ReadNativeMessage() {
        var header = ReadExactly(ChromeInput, 4);
        if (header == null) return null;
        var length = BitConverter.ToInt32(header, 0);
        if (length <= 0 || length > 4 * 1024 * 1024) throw new InvalidDataException("NATIVE_MESSAGE_SIZE_INVALID");
        var payload = ReadExactly(ChromeInput, length);
        if (payload == null) return null;
        return Encoding.UTF8.GetString(payload);
    }

    static void WriteNativeMessage(string json) {
        var payload = Encoding.UTF8.GetBytes(json);
        if (payload.Length > 1024 * 1024) throw new InvalidDataException("NATIVE_RESPONSE_TOO_LARGE");
        var header = BitConverter.GetBytes(payload.Length);
        lock (OutputLock) {
            ChromeOutput.Write(header, 0, header.Length);
            ChromeOutput.Write(payload, 0, payload.Length);
            ChromeOutput.Flush();
        }
    }

    static Dictionary<string, object> ParseObject(string json) {
        var value = new JavaScriptSerializer().DeserializeObject(json) as Dictionary<string, object>;
        if (value == null) throw new InvalidDataException("JSON_OBJECT_REQUIRED");
        return value;
    }

    static void ReaderLoop() {
        try {
            for (;;) {
                var raw = ReadNativeMessage();
                if (raw == null) break;
                Dictionary<string, object> message;
                try { message = ParseObject(raw); } catch { continue; }
                object typeValue, idValue;
                if (!message.TryGetValue("type", out typeValue) || Convert.ToString(typeValue) != "response") continue;
                if (!message.TryGetValue("request_id", out idValue)) continue;
                var requestId = Convert.ToString(idValue);
                lock (StateLock) {
                    if (PendingId == requestId) {
                        PendingResponse = raw;
                        ResponseReady.Set();
                    }
                }
            }
        } catch {}
        ChromeClosed = true;
        ChromeDone.Set();
        ResponseReady.Set();
    }

    static NamedPipeServerStream CreatePipe(string pipeName) {
        var security = new PipeSecurity();
        var sid = WindowsIdentity.GetCurrent().User;
        security.SetOwner(sid);
        security.AddAccessRule(new PipeAccessRule(sid, PipeAccessRights.FullControl, AccessControlType.Allow));
        return new NamedPipeServerStream(
            pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous, 8192, 8192, security);
    }

    static string Error(string code) {
        return new JavaScriptSerializer().Serialize(new Dictionary<string, object> {
            {"ok", false}, {"error_code", code}, {"message", code}
        });
    }

    static bool AllowedMethod(string method) {
        switch (method) {
            case "health":
            case "capabilities":
            case "download.prepare":
            case "download.status":
            case "download.wait":
            case "download.cleanup":
                return true;
            default: return false;
        }
    }

    static string HandlePipeRequest(string raw, string secret) {
        Dictionary<string, object> request;
        try { request = ParseObject(raw); } catch { return Error("IPC_REQUEST_INVALID"); }
        object authValue, idValue, methodValue;
        if (!request.TryGetValue("auth", out authValue) || Convert.ToString(authValue) != secret)
            return Error("IPC_AUTH_FAILED");
        if (!request.TryGetValue("request_id", out idValue) || String.IsNullOrWhiteSpace(Convert.ToString(idValue)))
            return Error("IPC_REQUEST_ID_REQUIRED");
        if (!request.TryGetValue("method", out methodValue) || !AllowedMethod(Convert.ToString(methodValue)))
            return Error("IPC_METHOD_FORBIDDEN");
        request.Remove("auth");
        request["type"] = "command";
        var requestId = Convert.ToString(idValue);
        lock (StateLock) {
            if (ChromeClosed) return Error("IPC_EXTENSION_DISCONNECTED");
            ResponseReady.Reset();
            PendingId = requestId;
            PendingResponse = null;
        }
        try { WriteNativeMessage(new JavaScriptSerializer().Serialize(request)); }
        catch { lock (StateLock) { PendingId = null; } return Error("IPC_EXTENSION_WRITE_FAILED"); }
        if (!ResponseReady.WaitOne(35000)) {
            lock (StateLock) { PendingId = null; PendingResponse = null; }
            return Error("IPC_EXTENSION_TIMEOUT");
        }
        lock (StateLock) {
            var response = PendingResponse;
            PendingId = null;
            PendingResponse = null;
            if (response != null) return response;
        }
        return Error(ChromeClosed ? "IPC_EXTENSION_DISCONNECTED" : "IPC_EXTENSION_NO_RESPONSE");
    }

    static int Await(IAsyncResult operation, int timeoutMillis) {
        return WaitHandle.WaitAny(new[] { operation.AsyncWaitHandle, ChromeDone }, timeoutMillis);
    }

    static string ReadPipeLine(NamedPipeServerStream pipe) {
        var timer = System.Diagnostics.Stopwatch.StartNew();
        var buffer = new byte[4096];
        using (var body = new MemoryStream()) {
            while (body.Length < 1024 * 1024) {
                var pending = pipe.BeginRead(buffer, 0, buffer.Length, null, null);
                if (Await(pending, Math.Max(0, 5000 - (int)timer.ElapsedMilliseconds)) != 0) return null;
                var count = pipe.EndRead(pending);
                if (count == 0) return null;
                var newline = Array.IndexOf(buffer, (byte)'\n', 0, count);
                body.Write(buffer, 0, newline < 0 ? count : newline);
                if (newline >= 0) return Encoding.UTF8.GetString(body.ToArray()).TrimEnd('\r');
            }
        }
        return null;
    }

    static void ServePipe(string secret, string pipeName) {
        NamedPipeServerStream listener;
        try { listener = CreatePipe(pipeName); }
        catch (IOException) {
            WriteNativeMessage("{\"type\":\"host_error\",\"error_code\":\"HOST_PIPE_BUSY\"}");
            throw;
        }
        using (var pipe = listener) {
            WriteNativeMessage("{\"type\":\"host_ready\",\"protocol_version\":1}");
            while (!ChromeClosed) {
                var waiting = pipe.BeginWaitForConnection(null, null);
                if (Await(waiting, Timeout.Infinite) != 0) return;
                pipe.EndWaitForConnection(waiting);
                try {
                    var line = ReadPipeLine(pipe);
                    if (line != null) {
                        var bytes = Encoding.UTF8.GetBytes(HandlePipeRequest(line, secret) + "\n");
                        var writing = pipe.BeginWrite(bytes, 0, bytes.Length, null, null);
                        if (Await(writing, 5000) == 0) {
                            pipe.EndWrite(writing);
                            // DisconnectNamedPipe discards unread bytes. The one-request client closes
                            // after reading its frame, so keep this instance alive until EOF or timeout.
                            var receipt = pipe.BeginRead(new byte[1], 0, 1, null, null);
                            if (Await(receipt, 5000) == 0) pipe.EndRead(receipt);
                        }
                    }
                } catch (IOException) {
                    // A disconnected IPC caller does not require closing Chrome's native port.
                } finally {
                    if (pipe.IsConnected) pipe.Disconnect();
                }
            }
        }
    }

    public static int Main(string[] args) {
        try {
            if (args.Length < 1 || !String.Equals(args[0], ExpectedOrigin, StringComparison.Ordinal)) {
                Console.Error.WriteLine("FF_COMPANION_HOST_ORIGIN_INVALID");
                return 3;
            }
            var root = AppDomain.CurrentDomain.BaseDirectory;
            var secret = ReadSecret(root);
            ChromeInput = Console.OpenStandardInput();
            ChromeOutput = Console.OpenStandardOutput();
            var reader = new Thread(ReaderLoop) { IsBackground = true, Name = "ff-companion-native-reader" };
            reader.Start();
            ServePipe(secret, PipeForRoot(root));
            return 0;
        } catch (InvalidOperationException error) {
            var code = error.Message;
            Console.Error.WriteLine(code == "BRIDGE_SECRET_MISSING" || code == "BRIDGE_SECRET_INVALID" ? code : "FF_COMPANION_HOST_FAILED");
            return 2;
        } catch {
            Console.Error.WriteLine("FF_COMPANION_HOST_FAILED");
            return 2;
        }
    }
}
