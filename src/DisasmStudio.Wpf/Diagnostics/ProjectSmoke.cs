using System.IO;
using System.Text;
using DisasmStudio.Core.Analysis;
using DisasmStudio.Debug;
using DisasmStudio.Wpf.ViewModels;

namespace DisasmStudio.Wpf.Diagnostics;

/// <summary>A console self-test for <c>.dsproj</c> persistence (<see cref="ProjectFile"/>), run via
/// <c>DisasmStudio --smoke-project</c>. Pure serialization — no GUI, no binary — so it verifies that the v7
/// live-session state round-trips: breakpoints (fields + <see cref="HwKind"/>/<see cref="MemAccess"/>/
/// <see cref="HitCountMode"/> enums), the execution trace, byte patches (base64), static jump what-ifs, and
/// the existing markup; plus that an older (pre-v7) file with none of those fields still loads (nulls).
/// Returns 0 if every assertion passes, else the number of failures.</summary>
internal static class ProjectSmoke
{
    public static int Run()
    {
        int fail = 0, total = 0;
        var report = new StringBuilder();
        void Log(string s) { Console.Out.WriteLine(s); report.AppendLine(s); }
        void Check(string desc, bool ok) { total++; if (!ok) fail++; Log($"  [{(ok ? "PASS" : "FAIL")}] {desc}"); }

        Log("ProjectFile (.dsproj) persistence smoke test");

        var proj = new ProjectFile
        {
            BinaryPath = @"C:\some\path\target.exe",
            Format = "PE",
            CurrentVa = 0x401234,
            CenterTab = 1,
            LoadedSections = [".rdata", ".data"],
            LoadHeader = true,
            Markup = new Markup
            {
                Names = { [0x401000] = "main", [0x402000] = "decrypt" },
                Comments = { [0x401010] = "loop start" },
                Bookmarks = { 0x401234, 0x405000 },
                Functions = { 0x403000 },
            },
            Breakpoints = new()
            {
                // plain software breakpoint
                [0x401000] = new BpDef(),
                // hardware write breakpoint, size 4, disabled
                [0x402000] = new BpDef { Hardware = true, Kind = HwKind.Write, Size = 4, Enabled = false },
                // conditional software breakpoint with a hit-count rule
                [0x403000] = new BpDef { Condition = "rax == 0x1C", HitMode = HitCountMode.AtLeast, HitTarget = 3 },
                // software memory (data) breakpoint over a range
                [0x404000] = new BpDef { Memory = true, MemLength = 16, MemAccess = MemAccess.ReadWrite },
            },
            Trace = [0x401000, 0x401002, 0x401007, 0x40100c],
            Patches = [new PatchRun(0x200, [0x90, 0x90, 0x90]), new PatchRun(0x400, [0xEB, 0xFE])],
            JumpAssumptions = new() { [0x401010] = true, [0x401020] = false },
        };

        string path = Path.Combine(Path.GetTempPath(), "disasmstudio_smoke_project.dsproj");
        proj.Save(path);
        var back = ProjectFile.Load(path);

        // ---- base fields ----
        Check("Version is 7", back.Version == 7);
        Check("BinaryPath round-trips", back.BinaryPath == proj.BinaryPath);
        Check("CurrentVa round-trips", back.CurrentVa == 0x401234);
        Check("CenterTab round-trips", back.CenterTab == 1);
        Check("LoadedSections round-trips", back.LoadedSections is { Count: 2 } ls && ls[0] == ".rdata" && ls[1] == ".data");
        Check("LoadHeader round-trips", back.LoadHeader);

        // ---- markup ----
        Check("Markup names", back.Markup?.Names.GetValueOrDefault(0x401000UL) == "main"
                              && back.Markup?.Names.GetValueOrDefault(0x402000UL) == "decrypt");
        Check("Markup comments", back.Markup?.Comments.GetValueOrDefault(0x401010UL) == "loop start");
        Check("Markup bookmarks", back.Markup?.Bookmarks.Contains(0x401234) == true && back.Markup?.Bookmarks.Contains(0x405000) == true);
        Check("Markup functions", back.Markup?.Functions.Contains(0x403000) == true);

        // ---- breakpoints (fields + enums) ----
        var bps = back.Breakpoints;
        Check("Breakpoints count == 4", bps is { Count: 4 });
        Check("plain sw bp default", bps?[0x401000] is { Hardware: false, Memory: false, Enabled: true, Condition: null, HitMode: HitCountMode.None });
        Check("hw write bp fields", bps?[0x402000] is { Hardware: true, Kind: HwKind.Write, Size: 4, Enabled: false });
        Check("conditional hit-count bp", bps?[0x403000] is { Condition: "rax == 0x1C", HitMode: HitCountMode.AtLeast, HitTarget: 3 });
        Check("memory bp fields", bps?[0x404000] is { Memory: true, MemLength: 16, MemAccess: MemAccess.ReadWrite });

        // ---- trace ----
        Check("Trace round-trips", back.Trace is { Count: 4 } t && t[0] == 0x401000 && t[3] == 0x40100c);

        // ---- patches (base64 byte[] + offset) ----
        var p = back.Patches;
        Check("Patches count == 2", p is { Count: 2 });
        Check("patch run 0 (0x200: 90 90 90)", p?[0] is { Offset: 0x200 } r0 && r0.Bytes.Length == 3 && r0.Bytes[0] == 0x90 && r0.Bytes[2] == 0x90);
        Check("patch run 1 (0x400: EB FE)", p?[1] is { Offset: 0x400 } r1 && r1.Bytes.Length == 2 && r1.Bytes[0] == 0xEB && r1.Bytes[1] == 0xFE);

        // ---- jump what-ifs ----
        Check("JumpAssumptions round-trip", back.JumpAssumptions is { Count: 2 } j && j[0x401010] && !j[0x401020]);

        // ---- enums serialised as strings (robust to enum value reordering) ----
        string json = File.ReadAllText(path);
        Check("enums stored as strings (\"Write\")", json.Contains("\"Write\""));
        Check("patch bytes stored as base64 (\"kJCQ\" == 90 90 90)", json.Contains("kJCQ"));

        // ---- backward compat: a pre-v7 file (no live-session fields) loads with nulls ----
        string legacy = """
        { "Version": 6, "BinaryPath": "x.bin", "Format": "PE", "CurrentVa": 4198400, "CenterTab": 0, "LoadHeader": false }
        """;
        string legacyPath = Path.Combine(Path.GetTempPath(), "disasmstudio_smoke_project_v6.dsproj");
        File.WriteAllText(legacyPath, legacy);
        var old = ProjectFile.Load(legacyPath);
        Check("v6 loads: Version 6", old.Version == 6);
        Check("v6 loads: CurrentVa read", old.CurrentVa == 4198400);
        Check("v6 loads: Breakpoints null", old.Breakpoints is null);
        Check("v6 loads: Trace null", old.Trace is null);
        Check("v6 loads: Patches null", old.Patches is null);
        Check("v6 loads: JumpAssumptions null", old.JumpAssumptions is null);

        // ---- empty project round-trips (all live-session fields stay null, no throw) ----
        string emptyPath = Path.Combine(Path.GetTempPath(), "disasmstudio_smoke_project_empty.dsproj");
        new ProjectFile { BinaryPath = "y.bin", Format = "PE" }.Save(emptyPath);
        var emptyBack = ProjectFile.Load(emptyPath);
        Check("empty project round-trips with null session state",
            emptyBack.Breakpoints is null && emptyBack.Trace is null && emptyBack.Patches is null && emptyBack.JumpAssumptions is null);

        Log(fail == 0 ? $"All {total} checks passed." : $"{fail}/{total} checks FAILED.");

        try
        {
            string rp = Path.Combine(Path.GetTempPath(), "disasmstudio_smoke_project.txt");
            File.WriteAllText(rp, report.ToString());
            Console.Out.WriteLine($"(report written to {rp})");
        }
        catch { /* best-effort */ }

        return fail;
    }
}
