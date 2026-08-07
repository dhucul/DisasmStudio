using System.Text;
using DisasmStudio.Core.Unpacking;

namespace DisasmStudio.Debug.Unpacking;

/// <summary>
/// OEP detection via API-call breakpoints. Plants breakpoints on key post-unpacking APIs
/// (VirtualProtect, VirtualAlloc, GetProcAddress, LoadLibrary) and tracks call counts.
/// When the stub finishes its loader work (last GetProcAddress, or VirtualProtect restoring
/// execute on a previously-W+X section), steps out and watches where execution goes next.
/// Works on protectors that use the Windows loader APIs to prepare the original code.
/// </summary>
public sealed class ApiBreakpointStrategy : IOepStrategy
{
    private const int MaxApiCalls = 500; // safety limit

    private enum Phase { Init, WaitApiCall, StepOut, WaitStepOut, WaitBreakpoint, Done }

    private readonly StringBuilder _log = new();
    private Phase _phase = Phase.Init;
    private readonly Dictionary<ulong, string> _apiBps = [];   // va -> api name
    private readonly Dictionary<string, int> _callCounts = [];
    private int _totalCalls;

    // APIs to break on, in priority order.
    private static readonly string[] TargetApis =
    [
        "VirtualProtect",
        "VirtualAlloc",
        "VirtualAllocEx",
        "GetProcAddress",
        "LoadLibraryA",
        "LoadLibraryW",
        "LoadLibraryExA",
        "LoadLibraryExW",
    ];

    public OepMethod Method => OepMethod.ApiBreakpoint;
    public string Log => _log.ToString();
    public bool IsDone => _phase == Phase.Done;

    public ulong? Begin(DebuggerEngine eng)
    {
        _log.Append("API breakpoint: resolving target API addresses from the import table…\n");

        var hdr = eng.ReadMemory(eng.ImageBase, 0x1000);
        if (!PeView.TryParse(hdr, out var view))
        {
            _log.Append("  Could not parse PE headers.\n");
            _phase = Phase.Done;
            return null;
        }

        // Walk the import descriptor table to find the target APIs.
        var (importRva, importSize) = view.DataDir(1); // IMAGE_DIRECTORY_ENTRY_IMPORT
        if (importRva == 0 || importSize < 20)
        {
            _log.Append("  No import directory found.\n");
            _phase = Phase.Done;
            return null;
        }

        int ptrSize = eng.Is64 ? 8 : 4;
        ulong ordinalFlag = eng.Is64 ? 1UL << 63 : 1UL << 31;
        ulong importStart = eng.ImageBase + importRva;
        int maxDescriptors = (int)(importSize / 20);

        for (int i = 0; i < maxDescriptors; i++)
        {
            ulong descAddr = importStart + (ulong)(i * 20);
            var desc = eng.ReadMemory(descAddr, 20);
            if (desc.Length < 20) break;

            uint iltRva = BitConverter.ToUInt32(desc, 0);  // OriginalFirstThunk (ILT) — hint/name RVAs
            uint iatRva = BitConverter.ToUInt32(desc, 16); // FirstThunk (IAT) — bound API addresses
            uint nameRva = BitConverter.ToUInt32(desc, 12);
            if (iltRva == 0 || nameRva == 0) break; // null descriptor = end of table

            // Read the DLL name.
            var dllNameBytes = eng.ReadMemory(eng.ImageBase + nameRva, 64);
            string dllName = ReadNullTerminatedAscii(dllNameBytes);

            // Walk the ILT (for hint/name RVAs) and IAT (for bound API addresses) in parallel.
            for (int t = 0; t < 256; t++)
            {
                // Read the ILT entry (hint/name RVA, or ordinal with high bit set).
                ulong iltSlotAddr = eng.ImageBase + iltRva + (ulong)(t * ptrSize);
                var iltBytes = eng.ReadMemory(iltSlotAddr, ptrSize);
                if (iltBytes.Length < ptrSize) break;

                ulong iltVal = ptrSize == 8
                    ? BitConverter.ToUInt64(iltBytes, 0)
                    : BitConverter.ToUInt32(iltBytes, 0);
                if (iltVal == 0) break; // end of this DLL's thunk table

                // Read the IAT entry (bound API address, already resolved by the loader).
                ulong iatSlotAddr = eng.ImageBase + iatRva + (ulong)(t * ptrSize);
                var iatBytes = eng.ReadMemory(iatSlotAddr, ptrSize);
                if (iatBytes.Length < ptrSize) break;

                ulong apiAddr = ptrSize == 8
                    ? BitConverter.ToUInt64(iatBytes, 0)
                    : BitConverter.ToUInt32(iatBytes, 0);

                if (apiAddr == 0 || (apiAddr & ordinalFlag) != 0) continue;

                // Read the hint/name from the ILT to identify the API.
                ulong hintNameRva = iltVal & ~ordinalFlag;
                if (hintNameRva == 0) continue;
                var hintNameBytes = eng.ReadMemory(eng.ImageBase + hintNameRva, 128);
                if (hintNameBytes.Length < 4) continue;
                string apiName = ReadNullTerminatedAscii(hintNameBytes.AsSpan(2));

                foreach (var target in TargetApis)
                {
                    if (apiName.Equals(target, StringComparison.OrdinalIgnoreCase) && !_apiBps.ContainsKey(apiAddr))
                    {
                        if (eng.TrySetBreakpoint(apiAddr))
                        {
                            _apiBps[apiAddr] = target;
                            _callCounts[target] = 0;
                            _log.Append($"  {target} at {apiAddr:X} — breakpoint armed.\n");
                        }
                    }
                }
            }
        }

        if (_apiBps.Count == 0)
        {
            _log.Append("  No target APIs found in the import table.\n");
            _phase = Phase.Done;
            return null;
        }

        _log.Append($"  Armed {_apiBps.Count} API breakpoint(s); running.\n");
        _phase = Phase.WaitApiCall;
        eng.Go();
        return null;
    }

    public ulong? OnStop(DebuggerEngine eng, StopInfo stop)
    {
        switch (_phase)
        {
            case Phase.WaitApiCall:
            {
                if (stop.Reason != StopReason.Breakpoint || !_apiBps.TryGetValue(stop.Address, out var apiName))
                {
                    eng.Go();
                    return null;
                }

                _callCounts[apiName] = _callCounts.GetValueOrDefault(apiName) + 1;
                _totalCalls++;
                _log.Append($"  {apiName} called ({_callCounts[apiName]}x, total {_totalCalls}).\n");

                if (_totalCalls >= MaxApiCalls)
                {
                    _log.Append($"  API call limit ({MaxApiCalls}) reached; giving up.\n");
                    Disarm(eng);
                    _phase = Phase.Done;
                    return null;
                }

                // For VirtualProtect: step out and see where execution returns.
                // The return address is often near the OEP.
                if (apiName == "VirtualProtect")
                {
                    // Read the return address from the stack.
                    var sp = eng.GetRegisters()?.Sp ?? 0;
                    var retBytes = eng.ReadMemory(sp, eng.Is64 ? 8 : 4);
                    ulong retAddr = retBytes.Length >= (eng.Is64 ? 8 : 4)
                        ? (eng.Is64 ? BitConverter.ToUInt64(retBytes, 0) : BitConverter.ToUInt32(retBytes, 0))
                        : 0;

                    if (retAddr != 0)
                    {
                        _log.Append($"    VirtualProtect return address: {retAddr:X}. Stepping out…\n");
                        _phase = Phase.StepOut;
                        eng.StepOut();
                        return null;
                    }
                }

                // For GetProcAddress: if it's been called several times already, the stub may be
                // finishing import resolution. Step out and watch.
                if (apiName == "GetProcAddress" && _callCounts[apiName] >= 3)
                {
                    _log.Append($"    GetProcAddress called {_callCounts[apiName]}x — stepping out to find OEP.\n");
                    _phase = Phase.StepOut;
                    eng.StepOut();
                    return null;
                }

                // For LoadLibrary: step out to see what happens after the DLL load.
                if (apiName.StartsWith("LoadLibrary", StringComparison.OrdinalIgnoreCase))
                {
                    _log.Append($"    {apiName} called — stepping out.\n");
                    _phase = Phase.StepOut;
                    eng.StepOut();
                    return null;
                }

                // Default: just continue running.
                eng.Go();
                return null;
            }

            case Phase.StepOut:
            {
                // We've stepped out of the API call. The return address is where execution resumes.
                // Check if it looks like a prologue.
                var head = eng.ReadMemory(stop.Address, 32);
                if (head.Length >= 2 && OepValidator.LooksLikeOep(head, eng.Is64))
                {
                    Disarm(eng);
                    _log.Append($"OEP candidate (API breakpoint step-out) at {stop.Address:X}.\n");
                    return stop.Address;
                }

                // Not a prologue — set a breakpoint a few instructions ahead and run.
                // Or just keep running and wait for the next API call.
                _log.Append($"    Step-out landed at {stop.Address:X} — not a prologue; continuing.\n");
                _phase = Phase.WaitApiCall;
                eng.Go();
                return null;
            }

            default:
                eng.Go();
                return null;
        }
    }

    public bool Owns(DebuggerEngine eng, StopInfo stop) =>
        (_phase == Phase.WaitApiCall && stop.Reason == StopReason.Breakpoint && _apiBps.ContainsKey(stop.Address))
        || (_phase == Phase.StepOut && stop.Reason == StopReason.Step);

    public void Abort(DebuggerEngine eng)
    {
        Disarm(eng);
        _log.Append("API breakpoint strategy aborted.\n");
    }

    private void Disarm(DebuggerEngine eng)
    {
        _phase = Phase.Done;
        foreach (var va in _apiBps.Keys)
            eng.RemoveBreakpoint(va);
        _apiBps.Clear();
    }

    private static string ReadNullTerminatedAscii(byte[] bytes)
    {
        int end = Array.IndexOf(bytes, (byte)0);
        if (end < 0) end = bytes.Length;
        return Encoding.ASCII.GetString(bytes, 0, end);
    }

    private static string ReadNullTerminatedAscii(ReadOnlySpan<byte> span)
    {
        int end = span.IndexOf((byte)0);
        if (end < 0) end = span.Length;
        return Encoding.ASCII.GetString(span[..end]);
    }
}
