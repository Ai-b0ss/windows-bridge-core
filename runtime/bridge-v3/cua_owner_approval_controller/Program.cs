using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using Windows.Security.Credentials.UI;

// Trusted, owner-operated controller. Never exposed as an FF RPC operation.
// Approval requires Windows Hello; CLI flags/JSON booleans cannot grant consent.
internal static class Program {
  [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr pointer);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
  static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string sddl,uint revision,out IntPtr descriptor,out uint size);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
  static extern bool SetFileSecurityW(string path,uint information,IntPtr descriptor);

  static void OwnerAcl(string path) {
    var sid=WindowsIdentity.GetCurrent().User?.Value??throw new InvalidOperationException("CONTROLLER_USER_IDENTITY_UNAVAILABLE");
    if(!ConvertStringSecurityDescriptorToSecurityDescriptorW("D:P(A;;FA;;;"+sid+")",1,out var descriptor,out _))
      throw new InvalidOperationException("CONTROLLER_ACL_FAILED");
    try {if(!SetFileSecurityW(path,0x80000004,descriptor))throw new InvalidOperationException("CONTROLLER_ACL_FAILED");}
    finally{LocalFree(descriptor);}
  }
  static void OwnedPath(string path) {
    var current=Path.GetFullPath(path);
    while(!string.IsNullOrEmpty(current)) {
      if((File.Exists(current)||Directory.Exists(current))&&(File.GetAttributes(current)&FileAttributes.ReparsePoint)!=0)
        throw new InvalidOperationException("CONTROLLER_PATH_LINK_FORBIDDEN");
      current=Path.GetDirectoryName(current);
    }
  }
  static void Atomic(string path,byte[] bytes,bool secret=false) {
    OwnedPath(path);Directory.CreateDirectory(Path.GetDirectoryName(path)!);
    var temp=path+".tmp-"+Guid.NewGuid().ToString("N");
    try {
      using(var stream=new FileStream(temp,FileMode.CreateNew,FileAccess.Write,FileShare.None)) {
        if(secret)OwnerAcl(temp);
        stream.Write(bytes);stream.Flush(true);
      }
      File.Move(temp,path,false);
    }finally{if(File.Exists(temp))File.Delete(temp);}
  }
  static object Public(RSA rsa) {var p=rsa.ExportParameters(false);return new {n=Convert.ToHexString(p.Modulus!).ToLowerInvariant(),e=65537};}
  static byte[] Canonical(JsonElement value) {
    using var buffer=new MemoryStream();
    using(var writer=new Utf8JsonWriter(buffer,new JsonWriterOptions{Encoder=JavaScriptEncoder.UnsafeRelaxedJsonEscaping}))Write(writer,value);
    return buffer.ToArray();
  }
  static void Write(Utf8JsonWriter w,JsonElement e) {
    if(e.ValueKind==JsonValueKind.Object){w.WriteStartObject();foreach(var p in e.EnumerateObject().OrderBy(p=>p.Name,StringComparer.Ordinal)){w.WritePropertyName(p.Name);Write(w,p.Value);}w.WriteEndObject();}
    else if(e.ValueKind==JsonValueKind.Array){w.WriteStartArray();foreach(var item in e.EnumerateArray())Write(w,item);w.WriteEndArray();}
    else e.WriteTo(w);
  }
  static JsonElement Parse(byte[] bytes)=>JsonDocument.Parse(bytes,new JsonDocumentOptions{MaxDepth=64}).RootElement.Clone();
  static string Arg(string[] args,string name) {int i=Array.IndexOf(args,name);return i>=0&&i+1<args.Length?args[i+1]:throw new InvalidOperationException("CONTROLLER_ARGUMENT_REQUIRED:"+name);}
  static async Task<int> Main(string[] args) {
    try {
      if(args.Contains("--availability")) {
        var state=await UserConsentVerifier.CheckAvailabilityAsync();
        Console.WriteLine(JsonSerializer.Serialize(new {ok=true,windows_hello=state.ToString(),approval_granted=false}));return 0;
      }
      if(args.Contains("--canonical-request")) {
        var inspected=Parse(File.ReadAllBytes(Arg(args,"--request")));
        Console.WriteLine(Encoding.UTF8.GetString(Canonical(inspected)));return 0;
      }
      var root=Path.GetFullPath(Arg(args,"--controller-root"));OwnedPath(root);
      var keyPath=Path.Combine(root,"controller-key.json");
      if(args.Contains("--initialize")) {
        var bridge=Path.GetFullPath(Arg(args,"--bridge-root"));OwnedPath(bridge);
        if(root.StartsWith(bridge.TrimEnd(Path.DirectorySeparatorChar)+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase)||root==bridge)
          throw new InvalidOperationException("CONTROLLER_PRIVATE_KEY_MUST_BE_OUTSIDE_RUNTIME");
        if(File.Exists(keyPath))throw new InvalidOperationException("CONTROLLER_ALREADY_INITIALIZED_NO_KEY_RESET");
        if(File.Exists(Path.Combine(root,"owner-approval-public.json"))||File.Exists(Path.Combine(bridge,"state","task-authority","owner-approval-public.json")))
          throw new InvalidOperationException("CONTROLLER_PUBLIC_KEY_EXISTS_NO_RESET");
        var initAvailable=await UserConsentVerifier.CheckAvailabilityAsync();
        if(initAvailable!=UserConsentVerifierAvailability.Available)throw new InvalidOperationException("CONTROLLER_OWNER_AUTH_REQUIRED:"+initAvailable);
        if(await UserConsentVerifier.RequestVerificationAsync("Provision an FF owner approval key. Each approval is scoped to one exact invocation. The key stays in Windows Hello and is not exportable.")!=UserConsentVerificationResult.Verified)
          throw new InvalidOperationException("CONTROLLER_OWNER_AUTH_NOT_VERIFIED");
        var name="FFBridge.OwnerController."+Guid.NewGuid().ToString("N");
        var parameters=new CngKeyCreationParameters {Provider=new CngProvider("Microsoft Passport Key Storage Provider"),
          ExportPolicy=CngExportPolicies.None,KeyUsage=CngKeyUsages.Signing,
          UIPolicy=new CngUIPolicy(CngUIProtectionLevels.ForceHighProtection,"FF owner approval","Approve a task-scoped FF invocation")};
        parameters.Parameters.Add(new CngProperty("Length",BitConverter.GetBytes(2048),CngPropertyOptions.None));
        using var initKey=CngKey.Create(CngAlgorithm.Rsa,name,parameters);
        if(initKey.ExportPolicy!=CngExportPolicies.None||initKey.UIPolicy.ProtectionLevel!=CngUIProtectionLevels.ForceHighProtection) {
          initKey.Delete();throw new InvalidOperationException("CONTROLLER_USER_PRESENCE_KEY_POLICY_UNAVAILABLE");
        }
        using var initRsa=new RSACng(initKey);
        var pub=JsonSerializer.SerializeToUtf8Bytes(Public(initRsa));
        var createdFiles=new List<string>();
        try {
          foreach(var publicPath in new[]{Path.Combine(root,"owner-approval-public.json"),Path.Combine(bridge,"state","task-authority","owner-approval-public.json")}) {
            Atomic(publicPath,pub);createdFiles.Add(publicPath);
          }
          Atomic(keyPath,JsonSerializer.SerializeToUtf8Bytes(new {name,provider=parameters.Provider.Provider}),true);
        } catch {
          initKey.Delete();
          foreach(var created in createdFiles)if(File.ReadAllBytes(created).SequenceEqual(pub))File.Delete(created);
          throw;
        }
        Console.WriteLine("{\"ok\":true,\"initialized\":true,\"approval_granted\":false,\"private_key_protection\":\"WindowsHello-nonexportable-user-presence-CNG\"}");return 0;
      }
      if(!args.Contains("--review"))throw new InvalidOperationException("CONTROLLER_REVIEW_REQUIRED");
      var request=Parse(File.ReadAllBytes(Arg(args,"--request")));
      var op=request.GetProperty("op").GetString()??throw new InvalidOperationException("CONTROLLER_OPERATION_REQUIRED");
      var invocationArgs=request.GetProperty("args");
      if(invocationArgs.TryGetProperty("signed_approval",out _)||invocationArgs.TryGetProperty("authorization_id",out _))
        throw new InvalidOperationException("CONTROLLER_REQUEST_MUST_BE_UNSIGNED");
      var agent=invocationArgs.GetProperty("agent_id").GetString();var task=invocationArgs.GetProperty("task_id").GetString();
      if(string.IsNullOrWhiteSpace(agent)||string.IsNullOrWhiteSpace(task))throw new InvalidOperationException("CONTROLLER_TASK_IDENTITY_REQUIRED");
      var digest=Convert.ToHexString(SHA256.HashData(Canonical(request))).ToLowerInvariant();
      var available=await UserConsentVerifier.CheckAvailabilityAsync();
      if(available!=UserConsentVerifierAvailability.Available)throw new InvalidOperationException("CONTROLLER_OWNER_AUTH_REQUIRED:"+available);
      // Windows-owned user verification cannot be replaced with an agent's
      // assertion, piped 'yes', callback boolean or test signer.
      var effects=invocationArgs.TryGetProperty("consequences",out var consequences)?consequences.ToString():
        invocationArgs.TryGetProperty("targets",out var targets)?"Desktop target scope: "+targets.ToString():throw new InvalidOperationException("CONTROLLER_EXPLICIT_EFFECT_SCOPE_REQUIRED");
      if(effects.Length>1200)throw new InvalidOperationException("CONTROLLER_EFFECT_SCOPE_REQUIRES_SMALLER_REVIEW");
      var decision=await UserConsentVerifier.RequestVerificationAsync("FF approval: "+op+"; agent "+agent+"; task "+task+"; "+effects+"; exact SHA256 "+digest);
      if(decision!=UserConsentVerificationResult.Verified)throw new InvalidOperationException("CONTROLLER_OWNER_AUTH_NOT_VERIFIED:"+decision);
      var now=DateTimeOffset.UtcNow.ToUnixTimeSeconds();
      var payload=new Dictionary<string,object?>{{"schema","ff-owner-approval-v1"},{"agent",agent},{"task",task},{"request",request},
        {"approval_reference","WindowsHello-verified-exact-invocation:"+digest},{"not_before",now-1},{"expires",now+600},{"uses",1},{"nonce",Guid.NewGuid().ToString("N")}};
      var descriptor=Parse(File.ReadAllBytes(keyPath));
      if(descriptor.GetProperty("provider").GetString()!="Microsoft Passport Key Storage Provider")throw new InvalidOperationException("CONTROLLER_KEY_PROVIDER_INVALID");
      using var key=CngKey.Open(descriptor.GetProperty("name").GetString()!,new CngProvider("Microsoft Passport Key Storage Provider"));
      if(key.ExportPolicy!=CngExportPolicies.None||key.UIPolicy.ProtectionLevel!=CngUIProtectionLevels.ForceHighProtection)
        throw new InvalidOperationException("CONTROLLER_USER_PRESENCE_KEY_POLICY_UNAVAILABLE");
      using(var rsa=new RSACng(key)) {
        var unsigned=Parse(JsonSerializer.SerializeToUtf8Bytes(payload));
        payload["signature"]=Convert.ToBase64String(rsa.SignData(Canonical(unsigned),HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1));
        Atomic(Arg(args,"--output"),JsonSerializer.SerializeToUtf8Bytes(payload));
      }
      Console.WriteLine("{\"ok\":true,\"approval_granted\":true,\"proof\":\"WindowsHelloVerified\"}");return 0;
    }catch(Exception e){Console.WriteLine(JsonSerializer.Serialize(new {ok=false,error_code=e.Message.Split(':')[0],detail=e.Message,hresult=e.HResult,approval_granted=false}));return 1;}
  }
}
