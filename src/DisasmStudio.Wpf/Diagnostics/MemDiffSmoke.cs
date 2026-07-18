using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using DisasmStudio.Core.Formats;
using DisasmStudio.Wpf.Controls;

namespace DisasmStudio.Wpf.Diagnostics;

/// <summary>
/// Hidden self-test for the "changed since last step" memory highlight (<see cref="HexView"/>). Part A checks the
/// pure by-VA diff (<see cref="HexView.DiffChangedVas"/>) with exact expected VA sets across the tricky cases: an
/// in-place change, no change, a null baseline, and a scroll forward/backward between two captures (where only the
/// overlapping VAs may be flagged). Part B drives the real control end-to-end: load a temp blob as a
/// <see cref="RawImage"/>, arrange the <see cref="HexView"/>, capture a baseline, mutate a visible byte via
/// <c>PatchVa</c> (so <c>ReadVa</c> returns a new value — as a stepped instruction would), and assert exactly that
/// VA is flagged and the control renders without throwing; then confirm <c>highlight:false</c> (the edit-refresh
/// path) advances the baseline without flagging. Prints to the launching terminal and exits — no UI.
/// Usage: DisasmStudio.exe --smoke-memdiff
/// </summary>
internal static class MemDiffSmoke
{
    public static int Run()
    {
        var log = new StringBuilder();
        void Log(string s) { log.AppendLine(s); Console.WriteLine(s); }

        Log("=== mem-diff smoke ===");
        bool pass = true;
        var into = new HashSet<ulong>();

        // ---- Part A: pure diff logic ----
        bool A(string name, byte[]? prev, ulong prevBase, byte[] cur, ulong baseVa, int read, ulong[] expected)
        {
            HexView.DiffChangedVas(prev, prevBase, prev?.Length ?? 0, cur, baseVa, read, into);
            var got = into.OrderBy(v => v).ToArray();
            bool ok = got.SequenceEqual(expected.OrderBy(v => v));
            Log($"  [A] {name,-22} got={{{string.Join(",", got.Select(v => v.ToString("X")))}}} " +
                $"expected={{{string.Join(",", expected.Select(v => v.ToString("X")))}}} => {(ok ? "ok" : "FAIL")}");
            return ok;
        }

        // in-place change at index 1
        pass &= A("in-place change", new byte[] { 0, 1, 2, 3 }, 0x1000, new byte[] { 0, 9, 2, 3 }, 0x1000, 4, [0x1001]);
        // identical → nothing
        pass &= A("no change", new byte[] { 0, 1, 2, 3 }, 0x1000, new byte[] { 0, 1, 2, 3 }, 0x1000, 4, []);
        // no baseline (first stop) → nothing
        pass &= A("null baseline", null, 0, new byte[] { 5, 6, 7, 8 }, 0x1000, 4, []);
        // scroll forward by 2: prev=[0x1000..0x1003], cur base=0x1002 → overlap {0x1002,0x1003}.
        //   cur[0]=0x1002 changed (prev 2 -> 0x22), cur[1]=0x1003 same, cur[2..3]=0x1004..5 have no baseline.
        pass &= A("scroll forward", new byte[] { 0, 1, 2, 3 }, 0x1000, new byte[] { 0x22, 3, 0xEE, 0xFF }, 0x1002, 4, [0x1002]);
        // scroll backward by 2: prev base=0x1002, cur base=0x1000 → cur[0..1]=0x1000..1 map to negative index (skip),
        //   cur[2]=0x1002 vs prev[0]=0xA (changed), cur[3]=0x1003 vs prev[1]=0xB (same).
        pass &= A("scroll backward", new byte[] { 0xA, 0xB, 0xC, 0xD }, 0x1002, new byte[] { 1, 2, 0x99, 0xB }, 0x1000, 4, [0x1002]);

        // ---- Part B: end-to-end through the real control ----
        string path = Path.Combine(Path.GetTempPath(), "ds_smoke_memdiff.bin");
        try
        {
            File.WriteAllBytes(path, new byte[4096]);                       // 4 KiB of zeros
            using var img = RawImage.Load(path, 0x400000, 64);

            var hex = new HexView();
            hex.SetImage(img);
            hex.Measure(new Size(560, 400));
            hex.Arrange(new Rect(0, 0, 560, 400));
            hex.UpdateLayout();

            hex.RefreshWithChangeHighlight();                              // capture baseline — nothing flagged yet
            bool baselineEmpty = hex.ChangedVasForTest.Count == 0;

            ulong target = img.MinVa + 0x20;                               // a byte well within the visible region
            img.PatchVa(target, new byte[] { 0xAB });                      // ReadVa now returns 0xAB here
            hex.RefreshWithChangeHighlight();                              // diff vs baseline → this VA changed
            bool flaggedOne = hex.ChangedVasForTest.Count == 1 && hex.ChangedVasForTest.Contains(target);

            bool rendered = RenderNoThrow(hex, Log);

            // edit-refresh path: change another byte but pass highlight:false → baseline advances, nothing flagged
            img.PatchVa(img.MinVa + 0x21, new byte[] { 0xCD });
            hex.RefreshWithChangeHighlight(highlight: false);
            bool editSuppressed = hex.ChangedVasForTest.Count == 0;

            Log($"  [B] baselineEmpty={baselineEmpty} flaggedOne={flaggedOne} rendered={rendered} editSuppressed={editSuppressed}");
            pass &= baselineEmpty && flaggedOne && rendered && editSuppressed;
        }
        catch (Exception ex) { Log($"  [B] EXCEPTION: {ex}"); pass = false; }
        finally { try { File.Delete(path); } catch { } }

        Log(pass ? "RESULT: PASS" : "RESULT: FAIL");
        return pass ? 0 : 1;
    }

    // Arrange + render the HexView off-screen and confirm it painted more than a flat background without throwing.
    private static bool RenderNoThrow(HexView hex, Action<string> log)
    {
        try
        {
            const int w = 560, h = 400;
            var rtb = new RenderTargetBitmap(w, h, 96, 96, PixelFormats.Pbgra32);
            rtb.Render(hex);
            var px = new int[w * h];
            rtb.CopyPixels(px, w * 4, 0);
            int first = px[0], distinct = 0;
            foreach (int p in px) if (p != first) { distinct++; if (distinct > 100) break; }
            log($"  render {w}x{h}: distinctPixels>{(distinct > 100 ? "100" : distinct.ToString())}");
            return distinct > 100;
        }
        catch (Exception ex) { log($"  render EXCEPTION: {ex.Message}"); return false; }
    }
}
