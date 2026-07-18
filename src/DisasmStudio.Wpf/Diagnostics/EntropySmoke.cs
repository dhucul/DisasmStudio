using System;
using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using DisasmStudio.Core.Formats;
using DisasmStudio.Wpf.Controls;
using DisasmStudio.Wpf.ViewModels;

namespace DisasmStudio.Wpf.Diagnostics;

/// <summary>
/// Hidden self-test for the Entropy tab's math (<see cref="EntropyData.Build"/>). Writes a temp blob with three
/// 4 KiB regions — all-zero (entropy ≈ 0), every byte value 0…255 uniformly (entropy ≈ 8), and a constant byte
/// (≈ 0) — loads it as a <see cref="RawImage"/>, builds the entropy profile, and asserts the per-block minimum
/// is near 0, the maximum near 8, and the whole-file value sits strictly between. Proves the block scan, the
/// whole-file histogram, and per-section entropy all line up. Prints to the launching terminal and exits — no UI.
/// Usage: DisasmStudio.exe --smoke-entropy
/// </summary>
internal static class EntropySmoke
{
    public static int Run(string? file = null)
    {
        var log = new StringBuilder();
        void Log(string s) { log.AppendLine(s); Console.WriteLine(s); }

        Log("=== entropy smoke ===");
        string path = Path.Combine(Path.GetTempPath(), "ds_smoke_entropy.bin");
        bool pass = false;
        try
        {
            const int region = 4096;
            var bytes = new byte[region * 3];
            // [0, 4K): zeros → 0 bits/byte.  [4K, 8K): 0,1,…,255 repeating → 8 bits/byte.  [8K, 12K): 0xAA → 0.
            for (int i = 0; i < region; i++) bytes[region + i] = (byte)(i & 0xFF);
            for (int i = 0; i < region; i++) bytes[region * 2 + i] = 0xAA;
            File.WriteAllBytes(path, bytes);

            using var img = RawImage.Load(path, 0x400000, 64);
            var d = EntropyData.Build(img);

            double min = double.MaxValue, max = double.MinValue;
            foreach (double b in d.Blocks) { if (b < min) min = b; if (b > max) max = b; }

            Log($"  blocks={d.Blocks.Length} blockSize={d.BlockSize} min={min:F3} max={max:F3} overall={d.Overall:F3}");
            foreach (var s in d.Sections) Log($"  section {s.Name}: {s.Entropy} (high={s.IsHigh})");

            bool blocksOk = d.Blocks.Length > 0 && min <= 0.10 && max >= 7.90;
            bool overallOk = d.Overall > 0.5 && d.Overall < 7.9;   // mixed blob: strictly between the extremes
            bool sectionsOk = d.Sections.Count >= 1 && d.Sections[0].HasData;

            // Exercise the graph control's OnRender headlessly (we're on WPF's STA thread inside the live App):
            // arrange an EntropyView, render it to a bitmap, and confirm it drew more than a flat background.
            // NOTE: the section-table DataGrid/ProgressBar binding cannot be exercised here — the read-only-binding
            // activation only fires under the real app's render/message loop, so that path is verified end-to-end
            // via UI Automation (open the Entropy tab on a real file) rather than in this headless self-test.
            bool renderOk = RenderProducesGraph(d, Log);

            pass = blocksOk && overallOk && sectionsOk && renderOk;
            Log($"  => blocksOk={blocksOk} overallOk={overallOk} sectionsOk={sectionsOk} renderOk={renderOk}");
        }
        catch (Exception ex) { Log($"  EXCEPTION: {ex}"); }
        finally { try { File.Delete(path); } catch { } }

        // Optional real-file pass: load an actual PE/ELF/Mach-O and dump its per-section entropy (sanity, not a
        // fixed expectation) — exercises the true multi-section image path (e.g. PeImage.ReadByteAtOffset).
        if (file is not null)
        {
            Log($"--- real file: {file} ---");
            IBinaryImage? img = null;
            try
            {
                img = BinaryLoader.Load(file);
                var d = EntropyData.Build(img);
                Log($"  {img.FormatName}  len={d.FileLength}  overall={d.Overall:F2}");
                foreach (var s in d.Sections) Log($"    {s.Name,-12} {s.Entropy,6}{(s.IsHigh ? "  packed?" : "")}");
                bool realOk = d.Overall is > 0 and < 8 && d.Sections.Count > 0 && d.Blocks.Length > 0;
                Log($"  => realOk={realOk}");
                pass = pass && realOk;
            }
            catch (Exception ex) { Log($"  real-file EXCEPTION: {ex.Message}"); pass = false; }
            finally { (img as IDisposable)?.Dispose(); }
        }

        Log(pass ? "RESULT: PASS" : "RESULT: FAIL");
        return pass ? 0 : 1;
    }

    // Render an EntropyView with the built data to an off-screen bitmap and confirm the graph actually drew
    // (more than one distinct pixel colour) without throwing.
    private static bool RenderProducesGraph(EntropyData d, Action<string> log)
    {
        try
        {
            const int w = 480, h = 220;
            var view = new EntropyView();
            view.SetData(d);
            view.Measure(new Size(w, h));
            view.Arrange(new Rect(0, 0, w, h));
            view.UpdateLayout();

            var rtb = new RenderTargetBitmap(w, h, 96, 96, PixelFormats.Pbgra32);
            rtb.Render(view);

            var px = new int[w * h];
            rtb.CopyPixels(px, w * 4, 0);
            int first = px[0], distinct = 0;
            foreach (int p in px) if (p != first) { distinct++; if (distinct > 100) break; }
            log($"  render {w}x{h}: distinctPixels>{(distinct > 100 ? "100" : distinct.ToString())}");
            return distinct > 100;   // a flat background would be ~0; the heat curve paints many colours
        }
        catch (Exception ex) { log($"  render EXCEPTION: {ex.Message}"); return false; }
    }
}
