using System;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using System.Windows.Automation;

internal sealed class WorkItem {
    public Dictionary<string, object> Request;
    public readonly ManualResetEventSlim Done = new ManualResetEventSlim(false);
    public Dictionary<string, object> Response;
}

internal static class Program {
    private static readonly JavaScriptSerializer Json = new JavaScriptSerializer { MaxJsonLength = 8 * 1024 * 1024 };
    private static readonly BlockingCollection<WorkItem> Queue = new BlockingCollection<WorkItem>();
    [DllImport("user32.dll")] private static extern IntPtr GetForegroundWindow();

    [MTAThread]
    private static int Main() {
        var utf8 = new UTF8Encoding(false, true);
        Console.InputEncoding = utf8;
        Console.OutputEncoding = utf8;
        Console.SetIn(new StreamReader(Console.OpenStandardInput(), utf8, false, 4096, false));
        Console.SetOut(new StreamWriter(Console.OpenStandardOutput(), utf8, 4096, false) { AutoFlush = true });
        var worker = new Thread(WorkerLoop) { IsBackground = true, Name = "uia-mta-worker" };
        worker.SetApartmentState(ApartmentState.MTA);
        worker.Start();
        string line;
        while ((line = Console.ReadLine()) != null) {
            var item = new WorkItem();
            try { item.Request = Json.Deserialize<Dictionary<string, object>>(line); }
            catch (Exception ex) { Emit(Error("INVALID_JSON", ex.Message)); continue; }
            Queue.Add(item); item.Done.Wait(); Emit(item.Response);
        }
        Queue.CompleteAdding();
        return 0;
    }

    private static void WorkerLoop() {
        foreach (var item in Queue.GetConsumingEnumerable()) {
            try { item.Response = Dispatch(item.Request); }
            catch (ElementNotAvailableException ex) { item.Response = Error("STALE_TARGET", ex.Message); }
            catch (InvalidOperationException ex) { item.Response = Error("ACTION_UNSUPPORTED", ex.Message); }
            catch (Exception ex) { item.Response = Error("UIA_ERROR", ex.GetType().Name + ": " + ex.Message); }
            finally {
                object requestId;
                if (item.Response != null && item.Request != null && item.Request.TryGetValue("id", out requestId))
                    item.Response["id"] = requestId;
                item.Done.Set();
            }
        }
    }

    private static Dictionary<string, object> Dispatch(Dictionary<string, object> r) {
        var id = GetString(r, "id", null);
        var q = r.ContainsKey("args") ? r["args"] as Dictionary<string, object> : null;
        if (q == null) q = r;
        var response = DispatchPayload(GetString(r, "op"), q);
        if (id != null) response["id"] = id;
        return response;
    }

    private static Dictionary<string, object> DispatchPayload(string op, Dictionary<string, object> r) {
        if (op == "capabilities") return Ok(new Dictionary<string, object> {
            {"engine", "system-windows-automation"}, {"apartment", "MTA"},
            {"persistent", true}, {"physical_input_fallback", false},
            {"actions", new [] {"set_value", "invoke", "toggle", "select", "expand", "collapse", "scroll_into_view", "scroll"}}
        });
        var hwnd = new IntPtr(Convert.ToInt64(r["hwnd"]));
        if (op == "excel_save") return ExcelSave(hwnd,r);
        if (op == "word_document") return WordDocument(hwnd,r);
        if (op == "powerpoint_document") return GetString(r,"action")=="read" ? PowerPointRead(hwnd,r) : PowerPointWrite(hwnd,r);
        var root = AutomationElement.FromHandle(hwnd);
        if (root == null) return Error("TARGET_NOT_FOUND", "HWND is not an automation root");
        if (op == "fingerprint") return Ok(new Dictionary<string, object>{{"hwnd", hwnd.ToInt64()}, {"process_id", root.Current.ProcessId}});
        if (op == "snapshot") return Snapshot(root, hwnd, GetInt(r, "max_items", 256));
        var identity = r["identity"] as Dictionary<string, object>;
        if (identity == null) return Error("INVALID_ARGUMENT", "identity object required");
        var element = Resolve(root, identity);
        if (element == null) return Error("STALE_TARGET", "semantic identity no longer resolves");
        if (op == "get") return Ok(new Dictionary<string, object>{{"entity", Describe(element, root, identity)}});
        if (op == "act") return Act(element, root, hwnd, identity, r);
        return Error("UNKNOWN_OP", op);
    }

    private static Dictionary<string, object> Snapshot(AutomationElement root, IntPtr hwnd, int maxItems) {
        if (maxItems < 1 || maxItems > 512) return Error("INVALID_ARGUMENT", "max_items must be between 1 and 512");
        var sw = Stopwatch.StartNew();
        var entities = new List<Dictionary<string, object>>();
        var seen = new Dictionary<string, int>();
        var walker = TreeWalker.ControlViewWalker;
        var pending = new Stack<KeyValuePair<AutomationElement, int[]>>();
        var first = walker.GetFirstChild(root);
        if (first != null) pending.Push(new KeyValuePair<AutomationElement, int[]>(first, new [] {0}));
        while (pending.Count > 0 && entities.Count < maxItems) {
            var item = pending.Pop();
            var el = item.Key; var path = item.Value;
            var next = walker.GetNextSibling(el);
            if (next != null) {
                var nextPath = (int[])path.Clone(); nextPath[nextPath.Length - 1]++;
                pending.Push(new KeyValuePair<AutomationElement, int[]>(next, nextPath));
            }
            var child = walker.GetFirstChild(el);
            if (child != null) {
                var childPath = new int[path.Length + 1]; Array.Copy(path, childPath, path.Length);
                pending.Push(new KeyValuePair<AutomationElement, int[]>(child, childPath));
            }
            var key = BaseIdentityKey(el);
            int ordinal = seen.ContainsKey(key) ? seen[key] : 0;
            seen[key] = ordinal + 1;
            entities.Add(Describe(el, root, new Dictionary<string, object>{{"ordinal", ordinal}, {"hierarchy_path", path}, {"runtime_id", SafeRuntimeId(el)}}));
        }
        sw.Stop();
        return Ok(new Dictionary<string, object> {
            {"hwnd", hwnd.ToInt64()}, {"count", entities.Count}, {"entities", entities}, {"max_items", maxItems},
            {"latency_ms", sw.Elapsed.TotalMilliseconds}, {"foreground_hwnd", GetForegroundWindow().ToInt64()}
        });
    }

    private static AutomationElement Resolve(AutomationElement root, Dictionary<string, object> id) {
        if (id.ContainsKey("hierarchy_path")) {
            var byPath = ResolvePath(root, id["hierarchy_path"]);
            if (byPath == null || !IdentityMatches(byPath, id) || !RuntimeHintMatches(byPath, id)) return null;
            return byPath;
        }
        var found = root.FindAll(TreeScope.Descendants, Condition.TrueCondition);
        int wanted = GetInt(id, "ordinal", 0), ordinal = 0;
        for (int i = 0; i < found.Count; i++) {
            var el = found[i];
            if (!IdentityMatches(el, id)) continue;
            if (ordinal++ == wanted) return el;
        }
        return null;
    }

    private static bool IdentityMatches(AutomationElement el, Dictionary<string, object> id) {
        return MatchIfPresent(id, "automation_id", el.Current.AutomationId) &&
               MatchIfPresent(id, "name", el.Current.Name) &&
               MatchIfPresent(id, "class_name", el.Current.ClassName) &&
               MatchIfPresent(id, "control_type", el.Current.ControlType.ProgrammaticName);
    }

    private static Dictionary<string, object> Describe(AutomationElement el, AutomationElement root, Dictionary<string, object> seed) {
        var actions = new List<string>();
        object pattern;
        if (el.TryGetCurrentPattern(ValuePattern.Pattern, out pattern)) actions.Add("set_value");
        if (el.TryGetCurrentPattern(InvokePattern.Pattern, out pattern)) actions.Add("invoke");
        if (el.TryGetCurrentPattern(TogglePattern.Pattern, out pattern)) actions.Add("toggle");
        if (el.TryGetCurrentPattern(SelectionItemPattern.Pattern, out pattern)) actions.Add("select");
        if (el.TryGetCurrentPattern(ExpandCollapsePattern.Pattern, out pattern)) { actions.Add("expand"); actions.Add("collapse"); }
        if (el.TryGetCurrentPattern(ScrollItemPattern.Pattern, out pattern)) actions.Add("scroll_into_view");
        if (el.TryGetCurrentPattern(ScrollPattern.Pattern, out pattern)) actions.Add("scroll");
        var key = BaseIdentityKey(el);
        int ordinal = seed.ContainsKey("ordinal") ? Convert.ToInt32(seed["ordinal"]) : ComputeOrdinal(root, el, key);
        var identity = new Dictionary<string, object> {
            {"class_name", el.Current.ClassName ?? ""}, {"control_type", el.Current.ControlType.ProgrammaticName ?? ""}, {"ordinal", ordinal},
            {"hierarchy_path", seed.ContainsKey("hierarchy_path") ? seed["hierarchy_path"] : ComputePath(root, el)},
            {"runtime_id", seed.ContainsKey("runtime_id") ? seed["runtime_id"] : SafeRuntimeId(el)}
        };
        if (!String.IsNullOrEmpty(el.Current.AutomationId)) identity["automation_id"] = el.Current.AutomationId;
        // The no-focus dispatcher guards the observed name even when the
        // provider supplies an AutomationId. Preserve both identities.
        identity["name_hint"] = el.Current.Name ?? "";
        string value = null;
        if (el.TryGetCurrentPattern(ValuePattern.Pattern, out pattern)) value = ((ValuePattern)pattern).Current.Value;
        string toggleState = null, expandState = null; bool? selected = null, hScrollable = null, vScrollable = null;
        double? hPercent = null, vPercent = null;
        if (el.TryGetCurrentPattern(TogglePattern.Pattern, out pattern)) toggleState = ((TogglePattern)pattern).Current.ToggleState.ToString();
        if (el.TryGetCurrentPattern(SelectionItemPattern.Pattern, out pattern)) selected = ((SelectionItemPattern)pattern).Current.IsSelected;
        if (el.TryGetCurrentPattern(ExpandCollapsePattern.Pattern, out pattern)) expandState = ((ExpandCollapsePattern)pattern).Current.ExpandCollapseState.ToString();
        if (el.TryGetCurrentPattern(ScrollPattern.Pattern, out pattern)) { var sp = (ScrollPattern)pattern; hScrollable = sp.Current.HorizontallyScrollable; vScrollable = sp.Current.VerticallyScrollable; hPercent = sp.Current.HorizontalScrollPercent; vPercent = sp.Current.VerticalScrollPercent; }
        return new Dictionary<string, object> {
            {"identity", identity}, {"name", el.Current.Name ?? ""}, {"automation_id", el.Current.AutomationId ?? ""},
            {"class_name", el.Current.ClassName ?? ""}, {"role", el.Current.ControlType.ProgrammaticName ?? ""},
            {"value", value}, {"enabled", el.Current.IsEnabled}, {"offscreen", el.Current.IsOffscreen},
            {"toggle_state", toggleState}, {"selected", selected}, {"expand_state", expandState},
            {"horizontally_scrollable", hScrollable}, {"vertically_scrollable", vScrollable},
            {"horizontal_scroll_percent", hPercent}, {"vertical_scroll_percent", vPercent},
            {"actions", actions.ToArray()}
        };
    }

    private static int ComputeOrdinal(AutomationElement root, AutomationElement target, string key) {
        var found = root.FindAll(TreeScope.Descendants, Condition.TrueCondition); int n = 0;
        for (int i = 0; i < found.Count; i++) {
            if (BaseIdentityKey(found[i]) != key) continue;
            if (SameRuntimeId(found[i], target)) return n;
            n++;
        }
        return 0;
    }

    private static Dictionary<string, object> Act(AutomationElement el, AutomationElement root, IntPtr hwnd, Dictionary<string, object> identity, Dictionary<string, object> r) {
        string action = GetString(r, "action");
        string value = GetString(r, "value", "");
        long fgBefore = GetForegroundWindow().ToInt64();
        var sw = Stopwatch.StartNew(); object pattern;
        bool noFocus = r.ContainsKey("no_focus") && r["no_focus"] is bool && (bool)r["no_focus"];
        if (noFocus && action != "invoke") return Error("ACTION_UNSUPPORTED", "no-focus route supports invoke only");
        string noFocusRoute = null;
        if (noFocus) noFocusRoute = NoFocusInvoke.Invoke(hwnd,identity);
        else if (action == "set_value" && el.TryGetCurrentPattern(ValuePattern.Pattern, out pattern)) ((ValuePattern)pattern).SetValue(value);
        else if (action == "invoke" && el.TryGetCurrentPattern(InvokePattern.Pattern, out pattern)) ((InvokePattern)pattern).Invoke();
        else if (action == "toggle" && el.TryGetCurrentPattern(TogglePattern.Pattern, out pattern)) ((TogglePattern)pattern).Toggle();
        else if (action == "select" && el.TryGetCurrentPattern(SelectionItemPattern.Pattern, out pattern)) ((SelectionItemPattern)pattern).Select();
        else if (action == "expand" && el.TryGetCurrentPattern(ExpandCollapsePattern.Pattern, out pattern)) ((ExpandCollapsePattern)pattern).Expand();
        else if (action == "collapse" && el.TryGetCurrentPattern(ExpandCollapsePattern.Pattern, out pattern)) ((ExpandCollapsePattern)pattern).Collapse();
        else if (action == "scroll_into_view" && el.TryGetCurrentPattern(ScrollItemPattern.Pattern, out pattern)) ((ScrollItemPattern)pattern).ScrollIntoView();
        else if (action == "scroll" && el.TryGetCurrentPattern(ScrollPattern.Pattern, out pattern)) {
            var horizontal = ParseScrollAmount(GetString(r, "horizontal", "NoAmount"));
            var vertical = ParseScrollAmount(GetString(r, "vertical", "NoAmount"));
            ((ScrollPattern)pattern).Scroll(horizontal, vertical);
        }
        else return Error("ACTION_UNSUPPORTED", action);
        sw.Stop();
        var resolved = Resolve(root, identity);
        if (resolved == null) return Error("STALE_TARGET", "target disappeared after action");
        var after = Describe(resolved, root, identity);
        long fgAfter = GetForegroundWindow().ToInt64();
        return Ok(new Dictionary<string, object> {
            {"action", action}, {"latency_ms", sw.Elapsed.TotalMilliseconds}, {"entity_after", after},
            {"foreground_before", fgBefore}, {"foreground_after", fgAfter}, {"focus_preserved", fgBefore == fgAfter},
            {"cursor_preserved", true}, {"physical_input_used", false}, {"auto_set_focus_disabled", noFocus},
            {"direct_msaa_default_action", noFocusRoute == "RAW_MSAA"},
            {"direct_uia_invoke", noFocusRoute == "NATIVE_UIA_INVOKE"}, {"no_focus_route", noFocusRoute}, {"verified", false}
        });
    }

    private static ScrollAmount ParseScrollAmount(string value) {
        ScrollAmount parsed;
        if (!Enum.TryParse<ScrollAmount>(value, true, out parsed)) throw new ArgumentException("invalid scroll amount: " + value);
        return parsed;
    }

    private static string BaseIdentityKey(AutomationElement el) {
        return (el.Current.AutomationId ?? "") + "\u001f" + (el.Current.Name ?? "") + "\u001f" +
               (el.Current.ClassName ?? "") + "\u001f" + (el.Current.ControlType.ProgrammaticName ?? "");
    }


    private static int[] ComputePath(AutomationElement root, AutomationElement target) {
        var walker = TreeWalker.ControlViewWalker;
        var reversed = new List<int>();
        var current = target;
        while (current != null && !SameRuntimeId(current, root)) {
            var parent = walker.GetParent(current);
            if (parent == null) return new int[0];
            int index = 0; bool found = false;
            for (var child = walker.GetFirstChild(parent); child != null; child = walker.GetNextSibling(child), index++) {
                if (SameRuntimeId(child, current)) { found = true; break; }
            }
            if (!found) return new int[0];
            reversed.Add(index);
            current = parent;
        }
        reversed.Reverse();
        return reversed.ToArray();
    }

    private static AutomationElement ResolvePath(AutomationElement root, object rawPath) {
        var path = ToIntList(rawPath);
        if (path == null || path.Count == 0) return null;
        var walker = TreeWalker.ControlViewWalker;
        var current = root;
        foreach (var wanted in path) {
            int index = 0;
            var child = walker.GetFirstChild(current);
            while (child != null && index < wanted) { child = walker.GetNextSibling(child); index++; }
            if (child == null) return null;
            current = child;
        }
        return current;
    }

    private static List<int> ToIntList(object raw) {
        var result = new List<int>();
        var enumerable = raw as IEnumerable;
        if (enumerable == null || raw is string) return null;
        foreach (var item in enumerable) result.Add(Convert.ToInt32(item));
        return result;
    }

    private static int[] SafeRuntimeId(AutomationElement el) {
        try { return el.GetRuntimeId() ?? new int[0]; } catch { return new int[0]; }
    }

    private static bool RuntimeHintMatches(AutomationElement el, Dictionary<string, object> id) {
        object raw;
        if (!id.TryGetValue("runtime_id", out raw)) return true;
        var expected = ToIntList(raw);
        if (expected == null || expected.Count == 0) return true;
        var actual = SafeRuntimeId(el);
        return expected.SequenceEqual(actual);
    }

    private static bool SameRuntimeId(AutomationElement a, AutomationElement b) {
        try { return a.GetRuntimeId().SequenceEqual(b.GetRuntimeId()); } catch { return false; }
    }

    private static bool Eq(string a, string b) { return String.Equals(a ?? "", b ?? "", StringComparison.Ordinal); }
    private static bool MatchIfPresent(Dictionary<string, object> id, string key, string actual) {
        object expected; return !id.TryGetValue(key, out expected) || Eq(actual, Convert.ToString(expected));
    }
    private static string GetString(Dictionary<string, object> d, string k, string fallback = null) {
        object v; if (!d.TryGetValue(k, out v) || v == null) return fallback;
        return Convert.ToString(v);
    }
    private static int GetInt(Dictionary<string, object> d, string k, int fallback) {
        object v; if (!d.TryGetValue(k, out v) || v == null) return fallback;
        return Convert.ToInt32(v);
    }
    [DllImport("user32.dll",CharSet=CharSet.Unicode)] private static extern int GetClassName(IntPtr hwnd,StringBuilder name,int count);
    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr hwnd,out uint pid);
    [DllImport("oleacc.dll")] private static extern int AccessibleObjectFromWindow(IntPtr hwnd,uint objectId,ref Guid iid,out IntPtr accessible);
    private delegate bool ChildCallback(IntPtr hwnd,IntPtr data);
    [DllImport("user32.dll")] private static extern bool EnumChildWindows(IntPtr hwnd,ChildCallback callback,IntPtr data);
    private static string WindowClass(IntPtr hwnd) { var name=new StringBuilder(256);GetClassName(hwnd,name,name.Capacity);return name.ToString(); }
    private static object ComProperty(object instance,string name,params object[] args) {
        return instance.GetType().InvokeMember(name,BindingFlags.GetProperty,null,instance,args);
    }
    private static Dictionary<string,object> ExcelSave(IntPtr hwnd,Dictionary<string,object> r) {
        var objects=new List<object>();IntPtr pointer=IntPtr.Zero;bool attempted=false;
        try {
            uint pid;GetWindowThreadProcessId(hwnd,out pid);
            if(pid!=Convert.ToUInt32(r["pid"])||WindowClass(hwnd)!="XLMAIN")return Error("HIDDEN_WINDOW_NOT_OWNED","Excel HWND identity changed");
            var children=new List<IntPtr>();
            EnumChildWindows(hwnd,delegate(IntPtr child,IntPtr unused){uint childPid;GetWindowThreadProcessId(child,out childPid);if(childPid==pid&&WindowClass(child)=="EXCEL7")children.Add(child);return true;},IntPtr.Zero);
            if(children.Count!=1)return Error("OWN_EXCEL_NATIVE_OBJECT_NOT_UNIQUE","one EXCEL7 required");
            var iid=new Guid("00020400-0000-0000-C000-000000000046");
            Marshal.ThrowExceptionForHR(AccessibleObjectFromWindow(children[0],0xfffffff0,ref iid,out pointer));
            var native=Marshal.GetObjectForIUnknown(pointer);objects.Add(native);
            var app=ComProperty(native,"Application");objects.Add(app);
            if(Convert.ToInt64(ComProperty(app,"Hwnd"))!=hwnd.ToInt64())return Error("OWN_EXCEL_APPLICATION_IDENTITY_MISMATCH","native application HWND changed");
            var books=ComProperty(app,"Workbooks");objects.Add(books);
            if(Convert.ToInt32(ComProperty(books,"Count"))!=1)return Error("OWN_WORKBOOK_IDENTITY_MISMATCH","one owned workbook required");
            var book=ComProperty(books,"Item",1);objects.Add(book);
            var expected=Path.GetFullPath(GetString(r,"book_path"));
            if(!String.Equals(Path.GetFullPath(Convert.ToString(ComProperty(book,"FullName"))),expected,StringComparison.OrdinalIgnoreCase))return Error("OWN_WORKBOOK_IDENTITY_MISMATCH","workbook path changed");
            GetWindowThreadProcessId(hwnd,out pid);
            if(pid!=Convert.ToUInt32(r["pid"]))return Error("HIDDEN_WINDOW_NOT_OWNED","Excel identity changed before save");
            attempted=true;
            book.GetType().InvokeMember("Save",BindingFlags.InvokeMethod,null,book,new object[0]);
            bool saved=Convert.ToBoolean(ComProperty(book,"Saved"));
            return Ok(new Dictionary<string,object>{{"saved",saved},{"verified",saved},{"attempted",true},{"retry_safe",false},{"physical_input_used",false},{"sheet_writes_performed",false},{"route","OWN_HWND_NATIVE_COM_SAVE_ONLY"}});
        }catch(Exception ex) {
            var error=Error("OWN_EXCEL_SAVE_FAILED",ex.GetType().Name+": "+ex.Message);
            error["details"]=new Dictionary<string,object>{{"attempted",attempted},{"retry_safe",!attempted}};return error;
        }finally {
            if(pointer!=IntPtr.Zero)Marshal.Release(pointer);
            foreach(var item in objects.Distinct().Reverse())if(Marshal.IsComObject(item))Marshal.ReleaseComObject(item);
        }
    }
    private static Dictionary<string,object> WordDocument(IntPtr hwnd,Dictionary<string,object> r) {
        var objects=new List<object>();IntPtr pointer=IntPtr.Zero;bool attempted=false;
        try {
            uint pid;GetWindowThreadProcessId(hwnd,out pid);
            if(pid!=Convert.ToUInt32(r["pid"])||WindowClass(hwnd)!="OpusApp")return BeforeEffectError("HIDDEN_WINDOW_NOT_OWNED","Word HWND identity changed");
            var children=new List<IntPtr>();
            EnumChildWindows(hwnd,delegate(IntPtr child,IntPtr unused){uint childPid;GetWindowThreadProcessId(child,out childPid);if(childPid==pid&&WindowClass(child)=="_WwG")children.Add(child);return true;},IntPtr.Zero);
            if(children.Count!=1)return BeforeEffectError("OWN_WORD_NATIVE_OBJECT_NOT_UNIQUE","one owned _WwG required");
            var iid=new Guid("00020400-0000-0000-C000-000000000046");
            Marshal.ThrowExceptionForHR(AccessibleObjectFromWindow(children[0],0xfffffff0,ref iid,out pointer));
            var native=Marshal.GetObjectForIUnknown(pointer);objects.Add(native);
            if(Convert.ToInt64(ComProperty(native,"Hwnd"))!=hwnd.ToInt64())return BeforeEffectError("OWN_WORD_WINDOW_IDENTITY_MISMATCH","native Window HWND changed");
            var document=ComProperty(native,"Document");objects.Add(document);
            // Bind to this exact Window.Document, never ActiveDocument or an
            // application-wide index. Recovery may open other documents.
            var documentWindows=ComProperty(document,"Windows");objects.Add(documentWindows);
            if(Convert.ToInt32(ComProperty(documentWindows,"Count"))!=1)return BeforeEffectError("OWN_DOCUMENT_IDENTITY_MISMATCH","one window for the target document required");
            var documentWindow=documentWindows.GetType().InvokeMember("Item",BindingFlags.InvokeMethod,null,documentWindows,new object[]{1});objects.Add(documentWindow);
            if(Convert.ToInt64(ComProperty(documentWindow,"Hwnd"))!=hwnd.ToInt64())return BeforeEffectError("OWN_DOCUMENT_IDENTITY_MISMATCH","document window differs from the owned HWND");
            var expected=Path.GetFullPath(GetString(r,"document_path"));
            if(!String.Equals(Path.GetFullPath(Convert.ToString(ComProperty(document,"FullName"))),expected,StringComparison.OrdinalIgnoreCase))return BeforeEffectError("OWN_DOCUMENT_IDENTITY_MISMATCH","document path changed");
            var content=ComProperty(document,"Content");objects.Add(content);
            string text=Convert.ToString(ComProperty(content,"Text"));
            string action=GetString(r,"action");
            if(action=="read")return Ok(new Dictionary<string,object>{{"text",text},{"verified",true},{"attempted",false},{"physical_input_used",false},{"route","OWN_HWND_NATIVE_COM_DOCUMENT"}});
            if(action!="save"&&action!="replace")return BeforeEffectError("ACTION_UNSUPPORTED",action);
            string replacement=null;
            if(action=="replace") {
                if(text!=GetString(r,"expected_text"))return BeforeEffectError("OWN_DOCUMENT_CONTENT_CHANGED","expected text does not match; no write performed");
                replacement=GetString(r,"replacement_text");
                if(replacement==null||replacement.Length<1||replacement.Length>65536||!replacement.EndsWith("\r",StringComparison.Ordinal))return BeforeEffectError("INVALID_ARGUMENT","bounded Word content ending with its final paragraph mark required");
            }
            GetWindowThreadProcessId(hwnd,out pid);
            if(pid!=Convert.ToUInt32(r["pid"])||WindowClass(hwnd)!="OpusApp"||Convert.ToInt64(ComProperty(native,"Hwnd"))!=hwnd.ToInt64())return BeforeEffectError("HIDDEN_WINDOW_NOT_OWNED","Word identity changed before effect");
            if(!String.Equals(Path.GetFullPath(Convert.ToString(ComProperty(document,"FullName"))),expected,StringComparison.OrdinalIgnoreCase))return BeforeEffectError("OWN_DOCUMENT_IDENTITY_MISMATCH","document path changed before effect");
            if(Convert.ToInt32(ComProperty(documentWindows,"Count"))!=1||Convert.ToInt64(ComProperty(documentWindow,"Hwnd"))!=hwnd.ToInt64())return BeforeEffectError("OWN_DOCUMENT_IDENTITY_MISMATCH","document window changed before effect");
            if(action=="replace"&&Convert.ToString(ComProperty(content,"Text"))!=GetString(r,"expected_text"))return BeforeEffectError("OWN_DOCUMENT_CONTENT_CHANGED","content changed before effect; no write performed");
            attempted=true;
            // Word retains the mandatory final paragraph mark. Setting it as
            // additional text would create an unintended empty paragraph.
            if(action=="replace")content.GetType().InvokeMember("Text",BindingFlags.SetProperty,null,content,new object[]{replacement.Substring(0,replacement.Length-1)});
            document.GetType().InvokeMember("Save",BindingFlags.InvokeMethod,null,document,new object[0]);
            string after=Convert.ToString(ComProperty(content,"Text"));
            bool saved=Convert.ToBoolean(ComProperty(document,"Saved"));
            GetWindowThreadProcessId(hwnd,out pid);
            bool identityPreserved=pid==Convert.ToUInt32(r["pid"])&&WindowClass(hwnd)=="OpusApp"&&Convert.ToInt64(ComProperty(native,"Hwnd"))==hwnd.ToInt64()&&Convert.ToInt32(ComProperty(documentWindows,"Count"))==1&&Convert.ToInt64(ComProperty(documentWindow,"Hwnd"))==hwnd.ToInt64()&&String.Equals(Path.GetFullPath(Convert.ToString(ComProperty(document,"FullName"))),expected,StringComparison.OrdinalIgnoreCase);
            bool verified=saved&&identityPreserved&&(action!="replace"||after==replacement);
            return Ok(new Dictionary<string,object>{{"saved",saved},{"verified",verified},{"text",after},{"attempted",true},{"retry_safe",false},{"physical_input_used",false},{"route","OWN_HWND_NATIVE_COM_DOCUMENT"}});
        }catch(Exception ex) {
            var cause=ex.GetBaseException();
            var error=Error("OWN_WORD_DOCUMENT_FAILED",cause.GetType().Name+": "+cause.Message);
            ((Dictionary<string,object>)error["error"])["details"]=new Dictionary<string,object>{{"attempted",attempted},{"retry_safe",!attempted}};return error;
        }finally {
            if(pointer!=IntPtr.Zero)Marshal.Release(pointer);
            foreach(var item in objects.Distinct().Reverse())if(Marshal.IsComObject(item))Marshal.ReleaseComObject(item);
        }
    }
    private static Dictionary<string,object> PowerPointRead(IntPtr hwnd,Dictionary<string,object> r) {
        var objects=new List<object>(); var pointers=new List<IntPtr>();
        try {
            uint pid;GetWindowThreadProcessId(hwnd,out pid);
            if(pid!=Convert.ToUInt32(r["pid"])||WindowClass(hwnd)!="PPTFrameClass")return BeforeEffectError("HIDDEN_WINDOW_NOT_OWNED","PowerPoint frame identity changed");
            var children=new List<IntPtr>();
            EnumChildWindows(hwnd,delegate(IntPtr child,IntPtr unused){uint cp;GetWindowThreadProcessId(child,out cp);if(cp==pid&&(WindowClass(child)=="paneClassDC"||WindowClass(child)=="mdiClass"))children.Add(child);return true;},IntPtr.Zero);
            var childClasses=new List<Dictionary<string,object>>();
            EnumChildWindows(hwnd,delegate(IntPtr child,IntPtr unused){uint cp;GetWindowThreadProcessId(child,out cp);if(cp==pid)childClasses.Add(new Dictionary<string,object>{{"hwnd",child.ToInt64()},{"class",WindowClass(child)}});return true;},IntPtr.Zero);
            var diagnostics=new List<Dictionary<string,object>>();var nativeWindows=new Dictionary<IntPtr,object>();var nativeChildren=new Dictionary<IntPtr,IntPtr>();
            foreach(var child in children) {
                IntPtr pointer=IntPtr.Zero;
                var iid=new Guid("00020400-0000-0000-C000-000000000046");
                int hr=AccessibleObjectFromWindow(child,0xfffffff0,ref iid,out pointer);
                var diagnostic=new Dictionary<string,object>{{"child_hwnd",child.ToInt64()},{"class",WindowClass(child)},{"hresult",hr}};diagnostics.Add(diagnostic);
                if(pointer==IntPtr.Zero||hr<0){if(pointer!=IntPtr.Zero)Marshal.Release(pointer);continue;}
                pointers.Add(pointer);var native=Marshal.GetObjectForIUnknown(pointer);objects.Add(native);
                IntPtr identity=Marshal.GetIUnknownForObject(native);pointers.Add(identity);
                nativeWindows[identity]=native;nativeChildren[identity]=child;
            }
            if(nativeWindows.Count!=1) {
                var e=BeforeEffectError("OWN_POWERPOINT_NATIVE_WINDOW_NOT_UNIQUE","one canonical DocumentWindow required");
                ((Dictionary<string,object>)e["error"])["details"]=new Dictionary<string,object>{{"attempted",false},{"retry_safe",true},{"panes",diagnostics},{"child_classes",childClasses},{"canonical_window_count",nativeWindows.Count}};return e;
            }
            var window=nativeWindows.Values.First();var presentation=ComProperty(window,"Presentation");objects.Add(presentation);
            string expected=Path.GetFullPath(GetString(r,"document_path"));
            string actual=Path.GetFullPath(Convert.ToString(ComProperty(presentation,"FullName")));
            if(!String.Equals(actual,expected,StringComparison.OrdinalIgnoreCase))return BeforeEffectError("OWN_DOCUMENT_IDENTITY_MISMATCH","presentation path differs");
            var presentationWindows=ComProperty(presentation,"Windows");objects.Add(presentationWindows);
            int windowCount=Convert.ToInt32(ComProperty(presentationWindows,"Count"));
            if(windowCount!=1)return BeforeEffectError("OWN_DOCUMENT_IDENTITY_MISMATCH","one presentation window required");
            var member=presentationWindows.GetType().InvokeMember("Item",BindingFlags.InvokeMethod,null,presentationWindows,new object[]{1});objects.Add(member);
            IntPtr memberIdentity=Marshal.GetIUnknownForObject(member);pointers.Add(memberIdentity);
            if(!nativeWindows.ContainsKey(memberIdentity))return BeforeEffectError("OWN_DOCUMENT_IDENTITY_MISMATCH","native DocumentWindow differs from presentation window");
            var slides=ComProperty(presentation,"Slides");objects.Add(slides);
            int count=Convert.ToInt32(ComProperty(slides,"Count"));if(count>32)return BeforeEffectError("DOCUMENT_READ_LIMIT","at most 32 slides for bounded probe");
            var records=new List<Dictionary<string,object>>();int totalChars=0;
            for(int i=1;i<=count;i++) {
                var slide=slides.GetType().InvokeMember("Item",BindingFlags.InvokeMethod,null,slides,new object[]{i});objects.Add(slide);
                var shapes=ComProperty(slide,"Shapes");objects.Add(shapes);int sc=Convert.ToInt32(ComProperty(shapes,"Count"));
                if(sc>128)return BeforeEffectError("DOCUMENT_READ_LIMIT","at most 128 shapes per slide");
                var shapeRecords=new List<Dictionary<string,object>>();
                for(int j=1;j<=sc;j++) {
                    var shape=shapes.GetType().InvokeMember("Item",BindingFlags.InvokeMethod,null,shapes,new object[]{j});objects.Add(shape);
                    var sr=new Dictionary<string,object>{{"shape_id",Convert.ToInt32(ComProperty(shape,"Id"))},{"name",Convert.ToString(ComProperty(shape,"Name"))}};
                    if(Convert.ToInt32(ComProperty(shape,"HasTextFrame"))==-1) {
                        var frame=ComProperty(shape,"TextFrame");objects.Add(frame);var range=ComProperty(frame,"TextRange");objects.Add(range);
                        sr["auto_size"]=Convert.ToInt32(ComProperty(frame,"AutoSize"));
                        string text=Convert.ToString(ComProperty(range,"Text"));totalChars+=text.Length;
                        if(totalChars>65536)return BeforeEffectError("DOCUMENT_READ_LIMIT","bounded text limit");sr["text"]=text;
                    }
                    shapeRecords.Add(sr);
                }
                records.Add(new Dictionary<string,object>{{"slide_id",Convert.ToInt32(ComProperty(slide,"SlideID"))},{"shapes",shapeRecords}});
            }
            GetWindowThreadProcessId(hwnd,out pid);
            if(pid!=Convert.ToUInt32(r["pid"])||WindowClass(hwnd)!="PPTFrameClass"||!String.Equals(Path.GetFullPath(Convert.ToString(ComProperty(presentation,"FullName"))),expected,StringComparison.OrdinalIgnoreCase))return BeforeEffectError("OWN_DOCUMENT_IDENTITY_MISMATCH","identity changed while reading");
            if(!PowerPointBindingMatches(hwnd,pid,nativeChildren.Keys.Select(key=>nativeChildren[key]).First(),window,presentation,expected))return BeforeEffectError("OWN_DOCUMENT_IDENTITY_MISMATCH","native binding changed while reading");
            return Ok(new Dictionary<string,object>{{"verified",true},{"attempted",false},{"physical_input_used",false},{"route","OWN_HWND_NATIVE_COM_POWERPOINT_DOCUMENT"},{"panes",diagnostics},{"canonical_window_count",nativeWindows.Count},{"presentation_windows",windowCount},{"canonical_window_matches",true},{"slides",records}});
        }catch(Exception ex){return BeforeEffectError("OWN_POWERPOINT_READ_FAILED",ex.GetBaseException().GetType().Name+": "+ex.GetBaseException().Message);}
        finally {
            foreach(var pointer in pointers)if(pointer!=IntPtr.Zero)Marshal.Release(pointer);
            foreach(var item in objects.Distinct().Reverse())if(Marshal.IsComObject(item))Marshal.ReleaseComObject(item);
        }
    }

    [DllImport("user32.dll")] private static extern IntPtr GetAncestor(IntPtr hwnd,uint flags);
    private static bool SameComObject(object a,object b) {
        IntPtr pa=IntPtr.Zero,pb=IntPtr.Zero;
        try{pa=Marshal.GetIUnknownForObject(a);pb=Marshal.GetIUnknownForObject(b);return pa==pb;}
        finally{if(pa!=IntPtr.Zero)Marshal.Release(pa);if(pb!=IntPtr.Zero)Marshal.Release(pb);}
    }
    private static bool PowerPointBindingMatches(IntPtr hwnd,uint pid,IntPtr child,object window,object presentation,string path) {
        uint current,cp;GetWindowThreadProcessId(hwnd,out current);GetWindowThreadProcessId(child,out cp);
        if(current!=pid||cp!=pid||WindowClass(hwnd)!="PPTFrameClass"||GetAncestor(child,2)!=hwnd)return false;
        IntPtr pointer=IntPtr.Zero;object rebound=null,windows=null,member=null;
        try {
            var iid=new Guid("00020400-0000-0000-C000-000000000046");
            int hr=AccessibleObjectFromWindow(child,0xfffffff0,ref iid,out pointer);if(hr<0||pointer==IntPtr.Zero)return false;
            rebound=Marshal.GetObjectForIUnknown(pointer);
            if(!SameComObject(window,rebound)||!String.Equals(Path.GetFullPath(Convert.ToString(ComProperty(presentation,"FullName"))),path,StringComparison.OrdinalIgnoreCase))return false;
            windows=ComProperty(presentation,"Windows");if(Convert.ToInt32(ComProperty(windows,"Count"))!=1)return false;
            member=windows.GetType().InvokeMember("Item",BindingFlags.InvokeMethod,null,windows,new object[]{1});
            return SameComObject(window,member);
        }finally {
            if(pointer!=IntPtr.Zero)Marshal.Release(pointer);
            foreach(var item in new[]{member,windows,rebound}.Where(x=>x!=null).Distinct())if(Marshal.IsComObject(item))Marshal.ReleaseComObject(item);
        }
    }
    private static Dictionary<string,object> PowerPointWrite(IntPtr hwnd,Dictionary<string,object> r) {
        var objects=new List<object>();bool attempted=false;
        try {
            uint pid;GetWindowThreadProcessId(hwnd,out pid);
            if(pid!=Convert.ToUInt32(r["pid"])||WindowClass(hwnd)!="PPTFrameClass")return BeforeEffectError("HIDDEN_WINDOW_NOT_OWNED","PowerPoint frame changed");
            string path=Path.GetFullPath(GetString(r,"document_path"));
            var children=new List<IntPtr>();
            EnumChildWindows(hwnd,delegate(IntPtr c,IntPtr d){uint cp;GetWindowThreadProcessId(c,out cp);string cls=WindowClass(c);if(cp==pid&&(cls=="paneClassDC"||cls=="mdiClass"))children.Add(c);return true;},IntPtr.Zero);
            var bound=new List<KeyValuePair<IntPtr,object>>();
            foreach(var child in children) {
                IntPtr pointer=IntPtr.Zero;
                try {
                    var iid=new Guid("00020400-0000-0000-C000-000000000046");int hr=AccessibleObjectFromWindow(child,0xfffffff0,ref iid,out pointer);
                    if(hr<0||pointer==IntPtr.Zero)continue;
                    var native=Marshal.GetObjectForIUnknown(pointer);objects.Add(native);
                    if(!bound.Any(x=>SameComObject(x.Value,native)))bound.Add(new KeyValuePair<IntPtr,object>(child,native));
                }finally{if(pointer!=IntPtr.Zero)Marshal.Release(pointer);}
            }
            if(bound.Count!=1)return BeforeEffectError("OWN_POWERPOINT_NATIVE_WINDOW_NOT_UNIQUE","one canonical native window required");
            var window=bound[0].Value;var presentation=ComProperty(window,"Presentation");objects.Add(presentation);
            if(!PowerPointBindingMatches(hwnd,pid,bound[0].Key,window,presentation,path))return BeforeEffectError("OWN_DOCUMENT_IDENTITY_MISMATCH","native presentation binding differs");
            string action=GetString(r,"action");
            if(action=="save") {
                if(!PowerPointBindingMatches(hwnd,pid,bound[0].Key,window,presentation,path))return BeforeEffectError("OWN_DOCUMENT_IDENTITY_MISMATCH","binding changed before save");
                attempted=true;presentation.GetType().InvokeMember("Save",BindingFlags.InvokeMethod,null,presentation,new object[0]);
                bool savedOnly=Convert.ToInt32(ComProperty(presentation,"Saved"))==-1;
                return Ok(new Dictionary<string,object>{{"saved",savedOnly},{"verified",savedOnly&&PowerPointBindingMatches(hwnd,pid,bound[0].Key,window,presentation,path)},{"attempted",true},{"retry_safe",false},{"physical_input_used",false},{"route","OWN_HWND_NATIVE_COM_POWERPOINT_DOCUMENT"}});
            }
            if(action!="replace")return BeforeEffectError("ACTION_UNSUPPORTED",action);
            var slides=ComProperty(presentation,"Slides");objects.Add(slides);
            object slide;
            try{slide=slides.GetType().InvokeMember("FindBySlideID",BindingFlags.InvokeMethod,null,slides,new object[]{Convert.ToInt32(r["slide_id"])});}
            catch{return BeforeEffectError("OWN_DOCUMENT_TARGET_CHANGED","observed slide ID not found");}
            objects.Add(slide);var shapes=ComProperty(slide,"Shapes");objects.Add(shapes);
            int count=Convert.ToInt32(ComProperty(shapes,"Count"));if(count>128)return BeforeEffectError("DOCUMENT_READ_LIMIT","bounded shape limit");
            var matches=new List<object>();
            for(int i=1;i<=count;i++) {
                var shape=shapes.GetType().InvokeMember("Item",BindingFlags.InvokeMethod,null,shapes,new object[]{i});objects.Add(shape);
                if(Convert.ToInt32(ComProperty(shape,"Id"))==Convert.ToInt32(r["shape_id"]))matches.Add(shape);
            }
            if(matches.Count!=1)return BeforeEffectError("OWN_DOCUMENT_TARGET_CHANGED","observed shape ID not found uniquely");
            var target=matches[0];string expectedName=GetString(r,"shape_name"),expectedText=GetString(r,"expected_text"),replacement=GetString(r,"replacement_text");
            if(expectedName==null||expectedText==null||replacement==null||expectedText.Length>65536||replacement.Length>65536)return BeforeEffectError("INVALID_ARGUMENT","bounded expected name/text and replacement required");
            if(Convert.ToString(ComProperty(target,"Name"))!=expectedName||Convert.ToInt32(ComProperty(target,"HasTextFrame"))!=-1)return BeforeEffectError("OWN_DOCUMENT_TARGET_CHANGED","observed shape identity differs");
            var frame=ComProperty(target,"TextFrame");objects.Add(frame);var range=ComProperty(frame,"TextRange");objects.Add(range);
            if(Convert.ToInt32(ComProperty(frame,"AutoSize"))!=0)return BeforeEffectError("OWN_DOCUMENT_LAYOUT_UNSUPPORTED","text replacement requires a fixed-size text frame; automatic resizing would change layout");
            if(Convert.ToString(ComProperty(range,"Text"))!=expectedText)return BeforeEffectError("OWN_DOCUMENT_CONTENT_CHANGED","expected text differs; no write");
            if(!PowerPointBindingMatches(hwnd,pid,bound[0].Key,window,presentation,path)||Convert.ToInt32(ComProperty(slide,"SlideID"))!=Convert.ToInt32(r["slide_id"])||Convert.ToInt32(ComProperty(target,"Id"))!=Convert.ToInt32(r["shape_id"])||Convert.ToString(ComProperty(target,"Name"))!=expectedName)return BeforeEffectError("OWN_DOCUMENT_TARGET_CHANGED","binding changed before effect");
            if(Convert.ToString(ComProperty(range,"Text"))!=expectedText)return BeforeEffectError("OWN_DOCUMENT_CONTENT_CHANGED","content changed before effect; no write");
            attempted=true;
            range.GetType().InvokeMember("Text",BindingFlags.SetProperty,null,range,new object[]{replacement});
            presentation.GetType().InvokeMember("Save",BindingFlags.InvokeMethod,null,presentation,new object[0]);
            bool saved=Convert.ToInt32(ComProperty(presentation,"Saved"))==-1;
            string after=Convert.ToString(ComProperty(range,"Text"));
            bool verified=saved&&after==replacement&&PowerPointBindingMatches(hwnd,pid,bound[0].Key,window,presentation,path);
            return Ok(new Dictionary<string,object>{{"saved",saved},{"verified",verified},{"text",after},{"attempted",true},{"retry_safe",false},{"physical_input_used",false},{"route","OWN_HWND_NATIVE_COM_POWERPOINT_DOCUMENT"}});
        }catch(Exception ex) {
            var error=Error("OWN_POWERPOINT_DOCUMENT_FAILED",ex.GetBaseException().GetType().Name+": "+ex.GetBaseException().Message);
            ((Dictionary<string,object>)error["error"])["details"]=new Dictionary<string,object>{{"attempted",attempted},{"retry_safe",!attempted}};return error;
        }finally{foreach(var item in objects.Distinct().Reverse())if(Marshal.IsComObject(item))Marshal.ReleaseComObject(item);}
    }

    private static Dictionary<string, object> Ok(Dictionary<string, object> payload) {
        payload["ok"] = true; return payload;
    }
    private static Dictionary<string,object> BeforeEffectError(string code,string message) {
        var error=Error(code,message);
        ((Dictionary<string,object>)error["error"])["details"]=new Dictionary<string,object>{{"attempted",false},{"retry_safe",true}};
        return error;
    }
    private static Dictionary<string, object> Error(string code, string message) {
        return new Dictionary<string, object>{{"ok", false}, {"error", new Dictionary<string, object>{{"code", code}, {"message", message}}}};
    }
    private static void Emit(Dictionary<string, object> payload) {
        Console.WriteLine(Json.Serialize(payload)); Console.Out.Flush();
    }
}

// Native UIA2 invoke with AutoSetFocus=false. SDK vtable slots are documented in
// microsoft/win32metadata generation/WinSDK/RecompiledIdlHeaders/um/UIAutomationClient.h.
internal static class NoFocusInvoke {
    private sealed class MsaaTargetUnavailableBeforeDispatch : Exception { }
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] private delegate int PutBool(IntPtr self,int value);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] private delegate int GetBool(IntPtr self,out int value);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] private delegate int OutPtr(IntPtr self,out IntPtr value);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] private delegate int FromPtr(IntPtr self,IntPtr input,out IntPtr value);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] private delegate int PatternAs(IntPtr self,int id,ref Guid iid,out IntPtr value);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] private delegate int InvokeOnly(IntPtr self);
        [DllImport("ole32.dll")] private static extern int CoCreateInstance(ref Guid clsid,IntPtr outer,uint context,ref Guid iid,out IntPtr value);
    [DllImport("oleaut32.dll")] private static extern int SafeArrayGetLBound(IntPtr array,uint dimension,out int lower);
    [DllImport("oleaut32.dll")] private static extern int SafeArrayGetUBound(IntPtr array,uint dimension,out int upper);
    [DllImport("oleaut32.dll")] private static extern int SafeArrayAccessData(IntPtr array,out IntPtr data);
    [DllImport("oleaut32.dll")] private static extern int SafeArrayUnaccessData(IntPtr array);
    [DllImport("oleaut32.dll")] private static extern int SafeArrayDestroy(IntPtr array);
    private static T Method<T>(IntPtr pointer,int slot) where T:class {
        if (pointer==IntPtr.Zero) throw new ElementNotAvailableException();
        var address=Marshal.ReadIntPtr(Marshal.ReadIntPtr(pointer),slot*IntPtr.Size);
        return (T)(object)Marshal.GetDelegateForFunctionPointer(address,typeof(T));
    }
    private static void Check(int hr) { Marshal.ThrowExceptionForHR(hr); }
    private static void Release(ref IntPtr value) {
        if(value!=IntPtr.Zero) { Marshal.Release(value);value=IntPtr.Zero; }
    }
    [DllImport("oleacc.dll")] private static extern int AccessibleObjectFromWindow(IntPtr hwnd,uint objectId,ref Guid iid,out IntPtr accessible);
    [DllImport("oleacc.dll")] private static extern int AccessibleChildren([MarshalAs(UnmanagedType.Interface)]object accessible,int first,int count,[Out,MarshalAs(UnmanagedType.LPArray,ArraySubType=UnmanagedType.Struct)]object[] children,out int obtained);
    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr hwnd,out uint pid);
    private static readonly Guid AccessibleIid=new Guid("618736e0-3c3d-11cf-810c-00aa00389b71");
    private static string WantedName;
    private static int WantedRole,MatchCount,MatchChild;
    private static IntPtr MatchPointer;
    private static void RecordAccessible(object raw,int child) {
        object name,role;
        try {
            name=raw.GetType().InvokeMember("accName",System.Reflection.BindingFlags.GetProperty,null,raw,new object[]{child});
            role=raw.GetType().InvokeMember("accRole",System.Reflection.BindingFlags.GetProperty,null,raw,new object[]{child});
        } catch(COMException) { throw; }
        if(Convert.ToString(name)!=WantedName || !(role is int) || (int)role!=WantedRole)return;
        MatchCount++;
        if(MatchCount==1) { MatchPointer=Marshal.GetIUnknownForObject(raw);MatchChild=child; }
    }
    private static void CollectAccessible(object raw,int depth,ref int budget) {
        if(depth>24 || --budget<0)throw new InvalidOperationException("MSAA traversal limit");
        RecordAccessible(raw,0);
        int count;
        try { count=Convert.ToInt32(raw.GetType().InvokeMember("accChildCount",System.Reflection.BindingFlags.GetProperty,null,raw,new object[0])); }
        catch(COMException) { throw; }
        if(count<0 || count>512)throw new InvalidOperationException("MSAA child limit");
        if(count==0)return;
        object[] children=new object[count];int obtained;
        Check(AccessibleChildren(raw,0,count,children,out obtained));
        if(obtained<0 || obtained>count)throw new InvalidOperationException("invalid MSAA child count");
        try {
            for(int i=0;i<obtained;i++) {
                if(children[i] is int) {
                    if(--budget<0)throw new InvalidOperationException("MSAA traversal limit");
                    RecordAccessible(raw,(int)children[i]);
                } else if(children[i]!=null && Marshal.IsComObject(children[i])) {
                    CollectAccessible(children[i],depth+1,ref budget);
                }
            }
        } finally {
            foreach(object child in children)
                if(child!=null && Marshal.IsComObject(child))Marshal.ReleaseComObject(child);
        }
    }
    private static void InvokeRawAccessible(IntPtr rootHwnd,IntPtr walker,IntPtr guarded) {
        IntPtr current=IntPtr.Zero,next=IntPtr.Zero,accessible=IntPtr.Zero;
        object raw=null;
        try {
            current=guarded;Marshal.AddRef(current);
            int hwnd=0;
            for(int i=0;i<128;i++) {
                Check(Method<GetBool>(current,36)(current,out hwnd));
                if(hwnd!=0)break;
                Check(Method<FromPtr>(walker,3)(walker,current,out next));Release(ref current);current=next;next=IntPtr.Zero;
            }
            if(hwnd==0)throw new ElementNotAvailableException("no MSAA host window");
            uint rootPid,hostPid;GetWindowThreadProcessId(rootHwnd,out rootPid);GetWindowThreadProcessId(new IntPtr(hwnd),out hostPid);
            if(rootPid==0 || rootPid!=hostPid)throw new ElementNotAvailableException("MSAA host process changed");
            Guid iid=AccessibleIid;
            Check(AccessibleObjectFromWindow(new IntPtr(hwnd),0xfffffffc,ref iid,out accessible));
            raw=Marshal.GetObjectForIUnknown(accessible);int budget=512;
            MatchCount=0;MatchPointer=IntPtr.Zero;
            try {
                CollectAccessible(raw,0,ref budget);
                if(MatchCount==0)throw new MsaaTargetUnavailableBeforeDispatch();
                if(MatchCount!=1)throw new InvalidOperationException("MSAA semantic target is not unique: "+MatchCount);
                object match=Marshal.GetObjectForIUnknown(MatchPointer);
                try { match.GetType().InvokeMember("accDoDefaultAction",System.Reflection.BindingFlags.InvokeMethod,null,match,new object[]{MatchChild}); }
                finally { Marshal.ReleaseComObject(match); }
            } finally { Release(ref MatchPointer); }
        } finally {
            if(raw!=null)Marshal.ReleaseComObject(raw);
            Release(ref accessible);Release(ref next);Release(ref current);
        }
    }
    private static int[] RuntimeId(IntPtr element) {
        IntPtr array=IntPtr.Zero,data=IntPtr.Zero;bool accessed=false;
        try {
            Check(Method<OutPtr>(element,4)(element,out array));
            int lower,upper;Check(SafeArrayGetLBound(array,1,out lower));Check(SafeArrayGetUBound(array,1,out upper));
            if(upper<lower)return new int[0];
            if(upper-lower>255) throw new InvalidOperationException("invalid runtime id");
            int[] result=new int[upper-lower+1];Check(SafeArrayAccessData(array,out data));accessed=true;
            Marshal.Copy(data,result,0,result.Length);return result;
        } finally {
            if(accessed)SafeArrayUnaccessData(array);
            if(array!=IntPtr.Zero)SafeArrayDestroy(array);
        }
    }
    public static string Invoke(IntPtr hwnd,Dictionary<string,object> identity) {
        var path=(identity["hierarchy_path"] as IEnumerable).Cast<object>().Select(Convert.ToInt32).ToArray();
        var runtime=(identity["runtime_id"] as IEnumerable).Cast<object>().Select(Convert.ToInt32).ToArray();
        if(path.Length<1 || path.Length>128 || path.Any(x=>x<0 || x>511) || runtime.Length<1)
            throw new ElementNotAvailableException("invalid guarded identity");
        string stage="create";
        IntPtr client=IntPtr.Zero,walker=IntPtr.Zero,element=IntPtr.Zero,pattern=IntPtr.Zero,next=IntPtr.Zero,accessible=IntPtr.Zero;
        try {
            Guid clsid=new Guid("e22ad333-b25f-460c-83d0-0581107395c9");
            Guid iid=new Guid("34723aff-0c9d-49d0-9896-7ab52df8cd8a");
            Check(CoCreateInstance(ref clsid,IntPtr.Zero,1,ref iid,out client));
            Check(Method<PutBool>(client,59)(client,0));
            int enabled;Check(Method<GetBool>(client,58)(client,out enabled));
            if(enabled!=0)throw new InvalidOperationException("AutoSetFocus was not disabled");
            stage="root";
            Check(Method<FromPtr>(client,6)(client,hwnd,out element));
            stage="walker";
            Check(Method<OutPtr>(client,14)(client,out walker));
            stage="walk";
            foreach(int ordinal in path) {
                Check(Method<FromPtr>(walker,4)(walker,element,out next));Release(ref element);element=next;next=IntPtr.Zero;
                for(int i=0;i<ordinal;i++) {
                    Check(Method<FromPtr>(walker,6)(walker,element,out next));Release(ref element);element=next;next=IntPtr.Zero;
                }
            }
            stage="runtime";
            if(!RuntimeId(element).SequenceEqual(runtime))throw new ElementNotAvailableException("runtime identity changed");
            WantedName=Convert.ToString(identity["name_hint"]);
            if(String.IsNullOrEmpty(WantedName))throw new InvalidOperationException("MSAA name guard missing");
            Guid legacy=new Guid("828055ad-355b-4435-86d5-3b51c14a9b1b");
            // Reading a Legacy pattern may fail for a genuine UIA provider.
            // Choose the native pattern only before any mutating dispatch.
            // Keep the same exact hierarchy/RuntimeId and AutoSetFocus guard.
            try {
                stage="legacy-pattern";
                Check(Method<PatternAs>(element,14)(element,10018,ref legacy,out pattern));
                stage="legacy-role";
                Check(Method<GetBool>(pattern,10)(pattern,out WantedRole));
            } catch(Exception legacyError) {
                if (!(legacyError is COMException) && !(legacyError is ElementNotAvailableException)) throw;
                Release(ref pattern);
                stage="native-invoke-revalidate";
                if(!RuntimeId(element).SequenceEqual(runtime))throw new ElementNotAvailableException("runtime identity changed after legacy read");
                stage="native-invoke-pattern";
                Guid invoke=new Guid("fb377fbe-8ea6-46d5-9c73-6499642d3059");
                Check(Method<PatternAs>(element,14)(element,10000,ref invoke,out pattern));
                stage="native-invoke-dispatch";
                Check(Method<InvokeOnly>(pattern,3)(pattern));
                return "NATIVE_UIA_INVOKE";
            }
            stage="raw-msaa";
            try {
                InvokeRawAccessible(hwnd,walker,element);
                return "RAW_MSAA";
            } catch(MsaaTargetUnavailableBeforeDispatch) {
                // No accDoDefaultAction was reached. Some UIA controls expose
                // a Legacy pattern but are absent from the MSAA host tree.
                // Select the native pattern only after exact revalidation.
                Release(ref pattern);
                stage="native-invoke-revalidate-after-empty-msaa";
                if(!RuntimeId(element).SequenceEqual(runtime))throw new ElementNotAvailableException("runtime identity changed after MSAA selection");
                stage="native-invoke-pattern-after-empty-msaa";
                Guid invoke=new Guid("fb377fbe-8ea6-46d5-9c73-6499642d3059");
                Check(Method<PatternAs>(element,14)(element,10000,ref invoke,out pattern));
                stage="native-invoke-dispatch-after-empty-msaa";
                Check(Method<InvokeOnly>(pattern,3)(pattern));
                return "NATIVE_UIA_INVOKE";
            }
        } catch(Exception ex) {
            throw new COMException("NO_FOCUS_"+stage+": "+ex.Message,ex.HResult);
        } finally {
            Release(ref next);Release(ref accessible);Release(ref pattern);Release(ref element);Release(ref walker);Release(ref client);
        }
    }
}
