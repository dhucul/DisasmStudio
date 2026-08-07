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
    /// <summary>Return address the in-flight step-out should land on, or 0 when none is pending. Recorded
    /// because the landing is otherwise indistinguishable from any other breakpoint stop.</summary>
    private ulong _stepOutRet;

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
                    return BeginStepOut(eng, "VirtualProtect");

                // For GetProcAddress: if it's been called several times already, the stub may be
                // finishing import resolution. Step out and watch.
                if (apiName == "GetProcAddress" && _callCounts[apiName] >= 3)
                    return BeginStepOut(eng, $"GetProcAddress called {_callCounts[apiName]}x");

                // For LoadLibrary: step out to see what happens after the DLL load.
                if (apiName.StartsWith("LoadLibrary", StringComparison.OrdinalIgnoreCase))
                    return BeginStepOut(eng, apiName);

                // Default: just continue running.
                eng.Go();
                return null;
            }

            case Phase.StepOut:
            {
                // One of our own API breakpoints fired before the step-out landed. Resuming here would cancel
                // the pending step-out and strand this phase, so fold the hit back into WaitApiCall, which
                // counts it — MaxApiCalls then still bounds the run.
                if (stop.Reason == StopReason.Breakpoint && stop.Address != _stepOutRet
                    && _apiBps.ContainsKey(stop.Address))
                {
                    _stepOutRet = 0;
                    _phase = Phase.WaitApiCall;
                    return OnStop(eng, stop);
                }

                // The step-out lands on the engine's temp breakpoint at the return address, which surfaces as
                // StopReason.Breakpoint; StopReason.Step is only the fallback taken when no temp breakpoint
                // could be planted. Anything else is not our landing and must not be read as one:
                // UnpackSession forwards every stop without an Owns gate, so treating a stray address as the
                // step-out result would report it as the OEP.
                bool landed = (_stepOutRet != 0 && stop.Address == _stepOutRet) || stop.Reason == StopReason.Step;
                _stepOutRet = 0;
                if (!landed)
                {
                    _phase = Phase.WaitApiCall;
                    eng.Go();
                    return null;
                }

                // We've stepped out of the API call. The return address is where execution resumes.
                // Check if it looks like a prologue.
                var head = eng.ReadMemory(stop.Address, 32);
                if (head.Length >= 2 && OepValidator.LooksLikeOep(head, eng.Is64))
                {
                    Disarm(eng);
                    _log.Append($"OEP candidate (API breakpoint step-out) at {stop.Address:X}.\n");
                    return stop.Address;
                }

                // Not a prologue — keep running and wait for the next API call.
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

    /// <summary>Record the return address and issue the step-out. Reading it up front is what lets
    /// <see cref="Owns"/> and <see cref="OnStop"/> tell the landing from any other breakpoint stop — at an API
    /// entry breakpoint the return address is still the top of the stack, before the callee's prologue.</summary>
    private ulong? BeginStepOut(DebuggerEngine eng, string why)
    {
        int n = eng.Is64 ? 8 : 4;
        ulong sp = eng.GetRegisters()?.Sp ?? 0;
        var retBytes = sp != 0 ? eng.ReadMemory(sp, n) : [];
        _stepOutRet = retBytes.Length >= n
            ? (eng.Is64 ? BitConverter.ToUInt64(retBytes, 0) : BitConverter.ToUInt32(retBytes, 0))
            : 0;

        if (_stepOutRet == 0)
        {
            // Without a return address the landing could not be recognised, and a step-out would be resolved by
            // the engine's single-step fallback into an unbounded walk. Keep waiting for the next API call.
            _log.Append($"    {why} — return address unreadable; continuing without stepping out.\n");
            eng.Go();
            return null;
        }

        _log.Append($"    {why} — return address {_stepOutRet:X}. Stepping out…\n");
        _phase = Phase.StepOut;
        eng.StepOut();
        return null;
    }

    public bool Owns(DebuggerEngine eng, StopInfo stop) =>
        (_phase == Phase.WaitApiCall && stop.Reason == StopReason.Breakpoint && _apiBps.ContainsKey(stop.Address))
        || (_phase == Phase.StepOut && OwnsStepOutStop(stop));

    /// <summary>A stop during <see cref="Phase.StepOut"/> is ours in three shapes: the step-out landing on the
    /// engine's temp breakpoint at the recorded return address (<see cref="StopReason.Breakpoint"/> — see
    /// <c>DebuggerEngine</c>'s temp-breakpoint stop), its single-step fallback when no temp breakpoint could be
    /// planted (<see cref="StopReason.Step"/>), or one of our own API breakpoints firing before the step-out
    /// lands. That last one has to be claimed too: routed away as a user breakpoint it would be resumed with
    /// <c>Go()</c>, which cancels the pending step-out and strands this phase for the rest of the run.</summary>
    private bool OwnsStepOutStop(StopInfo stop) =>
        stop.Reason == StopReason.Step
        || (stop.Reason == StopReason.Breakpoint
            && (stop.Address == _stepOutRet || _apiBps.ContainsKey(stop.Address)));

    public void Abort(DebuggerEngine eng)
    {
        Disarm(eng);
        _log.Append("API breakpoint strategy aborted.\n");
    }

    private void Disarm(DebuggerEngine eng)
    {
        _phase = Phase.Done;
        _stepOutRet = 0;
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
