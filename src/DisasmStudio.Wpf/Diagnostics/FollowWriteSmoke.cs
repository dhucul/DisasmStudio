using System;
using System.IO;
using System.Text;
using DisasmStudio.Core.Disasm;
using DisasmStudio.Core.Formats;
using DisasmStudio.Debug;

namespace DisasmStudio.Wpf.Diagnostics;

/// <summary>
/// Hidden self-test for the debugger's "follow writes" resolver (<see cref="WriteTarget.TryResolve"/>) — the only
/// real logic behind auto-scrolling the memory views to the location the current instruction writes to. Decodes a
/// handful of x64 instructions (each written to a temp blob, loaded as a <see cref="RawImage"/>, decoded by the
/// real <see cref="Disassembler"/>), resolves the write target against a synthetic <see cref="RegisterSet"/>, and
/// asserts the effective address + width — and that reads and stack pushes resolve to nothing. Prints to the
/// launching terminal and exits — no UI. Usage: DisasmStudio.exe --smoke-followwrite
/// </summary>
internal static class FollowWriteSmoke
{
    public static int Run()
    {
        var log = new StringBuilder();
        void Log(string s) { log.AppendLine(s); Console.WriteLine(s); }

        Log("=== follow-write smoke ===");
        bool pass = true;

        // One register snapshot covering every base used below (names are distinct, so they can share it).
        var regs = new RegisterSet { Is32 = false };
        regs.Add("rax", 0);
        regs.Add("rbx", 0x140000);
        regs.Add("rcx", 0x2000);
        regs.Add("rbp", 0x50000);
        regs.Add("rsp", 0x60000);
        regs.Add("rip", 0x1000);

        string path = Path.Combine(Path.GetTempPath(), "ds_smoke_fw.bin");
        try
        {
            bool Case(string name, byte[] bytes, ulong ip, bool wantOk, ulong wantEa, int wantSize)
            {
                File.WriteAllBytes(path, bytes);
                bool ok; ulong ea = 0; int size = 0;
                using (var img = RawImage.Load(path, ip, 64))
                {
                    var dis = new Disassembler(img);
                    ok = dis.TryDecodeAt(ip, out var insn) && WriteTarget.TryResolve(insn, regs, out ea, out size);
                }
                bool good = ok == wantOk && (!wantOk || (ea == wantEa && size == wantSize));
                Log($"  {name,-26} ok={ok} ea={ea:X} size={size}  " +
                    $"(want ok={wantOk}{(wantOk ? $" ea={wantEa:X} size={wantSize}" : "")}) => {(good ? "ok" : "FAIL")}");
                return good;
            }

            pass &= Case("mov [rbx+8],rax",   [0x48, 0x89, 0x43, 0x08],             0x1000, true,  0x140008, 8);
            pass &= Case("mov byte [rcx],5",  [0xC6, 0x01, 0x05],                   0x1000, true,  0x2000,   1);
            pass &= Case("mov [rip+0x100],rax", [0x48, 0x89, 0x05, 0x00, 0x01, 0x00, 0x00], 0x1000, true, 0x1107, 8);
            // Regression guards for the SS-segment bug: [rbp-8] and [rsp+0x20] use the SS segment but are real
            // explicit writes to locals/args — they MUST be followed.
            pass &= Case("mov [rbp-8],rax",   [0x48, 0x89, 0x45, 0xF8],             0x1000, true,  0x4FFF8,  8);
            pass &= Case("mov [rsp+0x20],rax", [0x48, 0x89, 0x44, 0x24, 0x20],      0x1000, true,  0x60020,  8);
            pass &= Case("mov eax,[rbx] (read)", [0x8B, 0x03],                      0x1000, false, 0, 0);
            pass &= Case("push rax (stack)",   [0x50],                              0x1000, false, 0, 0);
            pass &= Case("push [rbx] (mem read)", [0xFF, 0x33],                     0x1000, false, 0, 0);
        }
        catch (Exception ex) { Log($"  EXCEPTION: {ex}"); pass = false; }
        finally { try { File.Delete(path); } catch { } }

        Log(pass ? "RESULT: PASS" : "RESULT: FAIL");
        return pass ? 0 : 1;
    }
}
