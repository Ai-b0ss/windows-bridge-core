using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

internal static class Program {
    const string PipeName = "ff_browser_companion_v1";
    const string ExpectedOrigin = "chrome-extension://mmhkecdcdceeibbhalmfhjleeebgdbhk/";
    static readonly JavaScriptSerializer Json = new JavaScriptSerializer();
    static readonly AutoResetEvent ResponseReady = new AutoResetEvent(false);
    static readonly object StateLock = new object();
    static readonly object OutputLock = new object();
    static Stream ChromeInput;
    static Stream ChromeOutput;
    static string PendingId;
    static string PendingResponse;
    static volatile bool ChromeClosed;

    static string SecretPath() {
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        return Path.Combine(local, "FF-Windows-Bridge", "bridge-v3", "secret");
    }

    static string ReadSecret() {
        var path = SecretPath();
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
        var value = Json.DeserializeObject(json) as Dictionary<string, object>;
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
        ResponseReady.Set();
    }

    static NamedPipeServerStream CreatePipe() {
        var security = new PipeSecurity();
        var sid = WindowsIdentity.GetCurrent().User;
        security.SetOwner(sid);
        security.AddAccessRule(new PipeAccessRule(sid, PipeAccessRights.FullControl, AccessControlType.Allow));
        return new NamedPipeServerStream(
            PipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
            PipeOptions.None, 8192, 8192, security);
    }

    static string Error(string code) {
        return Json.Serialize(new Dictionary<string, object> {
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
            PendingId = requestId;
            PendingResponse = null;
        }
        try { WriteNativeMessage(Json.Serialize(request)); }
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

    static void ServePipe(string secret) {
        while (!ChromeClosed) {
            using (var pipe = CreatePipe()) {
                pipe.WaitForConnection();
                using (var reader = new StreamReader(pipe, new UTF8Encoding(false), false, 8192, true))
                using (var writer = new StreamWriter(pipe, new UTF8Encoding(false), 8192, true) { AutoFlush = true }) {
                    var line = reader.ReadLine();
                    if (line != null) writer.WriteLine(HandlePipeRequest(line, secret));
                }
            }
        }
    }

    public static int Main(string[] args) {
        try {
            if (args.Length < 1 || !String.Equals(args[0], ExpectedOrigin, StringComparison.Ordinal)) return 3;
            var secret = ReadSecret();
            ChromeInput = Console.OpenStandardInput();
            ChromeOutput = Console.OpenStandardOutput();
            var reader = new Thread(ReaderLoop) { IsBackground = true, Name = "ff-companion-native-reader" };
            reader.Start();
            ServePipe(secret);
            return 0;
        } catch {
            return 2;
        }
    }
}
