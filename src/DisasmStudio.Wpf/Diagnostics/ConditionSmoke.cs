using System.IO;
using System.Text;
using DisasmStudio.Debug;

namespace DisasmStudio.Wpf.Diagnostics;

/// <summary>A console self-test for the breakpoint-condition evaluator (<see cref="ConditionExpr"/>), run via
/// <c>DisasmStudio --smoke-cond</c>. Pure logic — no GUI, no debuggee — so it verifies parsing, sub-register
/// masking, flags, memory deref, operator precedence and the no-throw edge cases quickly. Returns 0 if every
/// assertion passes, else the number of failures.</summary>
internal static class ConditionSmoke
{
    public static int Run()
    {
        int fail = 0, total = 0;
        var report = new StringBuilder();
        void Log(string s) { Console.Out.WriteLine(s); report.AppendLine(s); }

        static RegisterSet R64(params (string Name, ulong Value)[] items)
        {
            var r = new RegisterSet { Is32 = false };
            foreach (var (n, v) in items) r.Add(n, v);
            return r;
        }

        // A grab-bag register set used by most checks.
        var regs = R64(
            ("rax", 0x1234567890ABCDEF), ("rbx", 0x10), ("rcx", 0x1C), ("rdx", 0),
            ("rsp", 0x1000), ("r8", 0xAAAAAAAA00001234),
            ("rflags", 0x40 /* ZF set (bit 6) */));

        // memory: qword at 0x1008 == 0xDEAD, byte at 0x2000 == 0x90
        ulong? Mem(ulong a, int n) => a switch
        {
            0x1008 when n == 8 => 0xDEAD,
            0x2000 when n == 1 => 0x90,
            _ => null,
        };

        bool Eval(string text, RegisterSet r, Func<ulong, int, ulong?>? mem = null)
        {
            if (!ConditionExpr.TryParse(text, out var ex, out var err) || ex is null)
                throw new Exception($"parse failed: {err ?? "(empty)"}");
            return ex.EvaluateBool(new EvalContext { Regs = r, ReadMem = mem ?? ((_, _) => null) });
        }

        void Check(string desc, bool actual, bool expected)
        {
            total++;
            bool pass = actual == expected;
            if (!pass) fail++;
            Log($"  [{(pass ? "PASS" : "FAIL")}] {desc}");
        }

        // Hex-default (the memory address box): whole expression evaluated, un-prefixed numbers are hex.
        ulong EvalHex(string text, RegisterSet r, Func<ulong, int, ulong?>? mem = null)
        {
            if (!ConditionExpr.TryParse(text, out var ex, out var err, hexNumbers: true) || ex is null)
                throw new Exception($"parse failed: {err ?? "(empty)"}");
            return ex.Evaluate(new EvalContext { Regs = r, ReadMem = mem ?? ((_, _) => null) });
        }

        void CheckVal(string desc, ulong actual, ulong expected)
        {
            total++;
            bool pass = actual == expected;
            if (!pass) fail++;
            Log($"  [{(pass ? "PASS" : "FAIL")}] {desc}  (got 0x{actual:X})");
        }

        void CheckParseError(string text)
        {
            total++;
            bool isError = !ConditionExpr.TryParse(text, out _, out var err) && err is not null;
            if (!isError) fail++;
            Log($"  [{(isError ? "PASS" : "FAIL")}] parse error reported for: {text}");
        }

        Log("ConditionExpr smoke test");

        // basic comparisons
        Check("rcx == 0x1C", Eval("rcx == 0x1C", regs), true);
        Check("rcx == 5 (false)", Eval("rcx == 5", regs), false);
        Check("rcx != 5", Eval("rcx != 5", regs), true);
        Check("rbx > 0x1000 (false)", Eval("rbx > 0x1000", regs), false);

        // sub-registers: eax/ax/al/ah of rax=0x1234567890ABCDEF
        Check("eax == 0x90ABCDEF", Eval("eax == 0x90ABCDEF", regs), true);
        Check("ax == 0xCDEF", Eval("ax == 0xCDEF", regs), true);
        Check("al == 0xEF", Eval("al == 0xEF", regs), true);
        Check("ah == 0xCD", Eval("ah == 0xCD", regs), true);
        Check("r8d == 0x1234", Eval("r8d == 0x1234", regs), true);
        Check("r8b == 0x34", Eval("r8b == 0x34", regs), true);

        // flags
        Check("ZF == 1", Eval("ZF == 1", regs), true);
        Check("CF == 0", Eval("CF == 0", regs), true);
        Check("eax < 0x90ABCDF0 && ZF == 1", Eval("eax < 0x90ABCDF0 && ZF == 1", regs), true);

        // memory deref (default ptr size + sized)
        Check("[rsp+8] == 0xDEAD", Eval("[rsp+8] == 0xDEAD", regs, Mem), true);
        Check("qword [rsp+8] == 0xDEAD", Eval("qword [rsp+8] == 0xDEAD", regs, Mem), true);
        Check("byte [0x2000] == 0x90", Eval("byte [0x2000] == 0x90", regs, Mem), true);
        Check("[0x3000] == 0 (unreadable -> 0)", Eval("[0x3000] == 0", regs, Mem), true);

        // arithmetic + precedence
        Check("1 + 2 * 3 == 7", Eval("1 + 2 * 3 == 7", regs), true);
        Check("(1 + 2) * 3 == 9", Eval("(1 + 2) * 3 == 9", regs), true);
        Check("rbx + 0x10 == 0x20", Eval("rbx + 0x10 == 0x20", regs), true);
        Check("1 << 4 == 0x10", Eval("1 << 4 == 0x10", regs), true);
        Check("~0 == 0xFFFFFFFFFFFFFFFF", Eval("~0 == 0xFFFFFFFFFFFFFFFF", regs), true);
        Check("!0 (true)", Eval("!0", regs), true);
        Check("!5 (false)", Eval("!5", regs), false);
        Check("unsigned: 0 - 1 > 0", Eval("0 - 1 > 0", regs), true);
        Check("divide by zero -> 0 (no throw)", Eval("rax / 0 == 0", regs), true);
        Check("logical or short-circuit", Eval("rcx == 0x1C || [0x9999] == 1", regs, Mem), true);

        // hex-default address-box expressions (the feature: `eax` worked but `eax+4` did not)
        Log("hex-default (memory address box)");
        CheckVal("eax -> 0x90ABCDEF", EvalHex("eax", regs), 0x90ABCDEF);
        CheckVal("bare 401000 is hex", EvalHex("401000", regs), 0x401000);
        CheckVal("eax+4", EvalHex("eax+4", regs), 0x90ABCDF3);
        CheckVal("eax+10 (offset is hex)", EvalHex("eax+10", regs), 0x90ABCDFF);
        CheckVal("1C is hex 0x1C", EvalHex("1C", regs), 0x1C);
        CheckVal("rbx*2", EvalHex("rbx*2", regs), 0x20);
        CheckVal("0x10 + 10 (both hex)", EvalHex("0x10 + 10", regs), 0x20);
        CheckVal("[rsp+8] deref", EvalHex("[rsp+8]", regs, Mem), 0xDEAD);
        CheckVal("[rsp+8]+2", EvalHex("[rsp+8]+2", regs, Mem), 0xDEAF);
        CheckVal("rcx register only", EvalHex("rcx", regs), 0x1C);
        // rsp+4 vs rsp+8 resolve to distinct addresses (they only *look* the same because both fall in one
        // 16-byte hex row); rax+N resolves to rax+N even when rax holds a small, unmapped value.
        CheckVal("rsp+4 (rsp=0x1000)", EvalHex("rsp+4", regs), 0x1004);
        CheckVal("rsp+8 (rsp=0x1000)", EvalHex("rsp+8", regs), 0x1008);
        CheckVal("rax+4", EvalHex("rax+4", regs), 0x1234567890ABCDF3);
        CheckVal("rax+8", EvalHex("rax+8", regs), 0x1234567890ABCDF7);

        // x64-only register on a 32-bit target resolves to 0 (full32 == null)
        var regs32 = new RegisterSet { Is32 = true };
        regs32.Add("eax", 0x1234);
        regs32.Add("eflags", 0);
        Check("r8 == 0 on 32-bit target", Eval("r8 == 0", regs32), true);
        Check("ax == 0x1234 on 32-bit target", Eval("ax == 0x1234", regs32), true);

        // empty condition parses to null (unconditional), no error
        total++;
        bool emptyOk = ConditionExpr.TryParse("   ", out var emptyEx, out var emptyErr) && emptyEx is null && emptyErr is null;
        if (!emptyOk) fail++;
        Log($"  [{(emptyOk ? "PASS" : "FAIL")}] empty condition -> null expr, no error");

        // malformed expressions report an error
        CheckParseError("rax ==");
        CheckParseError("bogusreg == 1");
        CheckParseError("(rax + 1");
        CheckParseError("[rax");
        CheckParseError("rax == 0x10000000000000000");   // 2^64 — must be a clean error, not OverflowException
        Check("max ulong literal parses", Eval("rax == 0xFFFFFFFFFFFFFFFF", R64(("rax", ulong.MaxValue))), true);

        Log(fail == 0 ? $"All {total} checks passed." : $"{fail}/{total} checks FAILED.");

        try
        {
            string path = Path.Combine(Path.GetTempPath(), "disasmstudio_smoke_cond.txt");
            File.WriteAllText(path, report.ToString());
            Console.Out.WriteLine($"(report written to {path})");
        }
        catch { /* best-effort */ }

        return fail;
    }
}
