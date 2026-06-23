# DisasmStudio

A Binary Ninja–style disassembler for Windows — soft, dark, high-DPI WPF. Loads PE / ELF / raw
binaries, disassembles x86/x64 (via [Iced](https://github.com/icedland/iced)), and presents a
linear listing, a per-function control-flow graph, and a hex view, with the usual reverse-engineering
side panels and fluid navigation. Built to stay crisp on 4K/5K monitors and responsive on large files.

## Features

- **Formats:** PE (`.exe`/`.dll`), ELF (32/64-bit, x86/x64), and raw/flat blobs (shellcode, dumps)
  at a chosen base address — all behind one `IBinaryImage` abstraction.
- **Linear view:** a custom, virtualized listing that decodes and formats only the rows on screen,
  so it scrolls smoothly over multi-million-instruction images. Soft syntax colouring, named branch
  targets (`sub_`/`loc_`/imports/exports), inline string comments, and a branch-arrow gutter.
- **Code/data classification:** a recursive-descent code map (from entry, exports, the PE x64 `.pdata`
  function table, jump tables, and code pointers found in data — vtables/callbacks), plus a gap scan
  that recognises function prologues (incl. `endbr64`) in the unreached `.text` gaps to recover
  indirectly-called functions, determines what's really code; everything else in
  `.text` — int3 padding, jump tables, literals — renders as data (`db`/`dd`/`dq`/strings) instead of
  disassembled junk. Typically ~97% code, ~3% data. The same pass discovers indirect-only functions
  (e.g. COM vtable methods) that have no direct callers.
- **Optional sections (resources, header, data) — IDA-style:** by default only code lands in the
  listing. When you open a file (or later, from the **Sections** panel) you can fold any non-executable
  section — `.rsrc`, `.data`, `.rdata`, `.reloc`, `.pdata` — and the **PE header** into the linear view,
  where they render as data (`db`/`dd`/`dq` and recognised strings) in address order, just like IDA.
  The choice is per-section, remembered in the `.dsproj`, and toggling a section re-analyses in place.
- **Resource browser:** a **Resources** side tab parses the PE resource directory (`.rsrc`) into the
  familiar type → name/id → language tree. Selecting a leaf previews it by type — manifests/HTML as
  text, **version info** as parsed file/product versions + string fields, **string tables** decoded,
  and **bitmaps/icons** rendered as images (the packed DIB is wrapped into a BMP/ICO for display);
  anything else falls back to a hex dump. *Save resource…* writes the raw bytes, and double-clicking a
  leaf navigates the other views to its address.
- **Graph view:** per-function control-flow graph — basic-block cards of coloured instructions with
  colour-coded edges (taken / fall-through / jump / switch-case). Pan (drag), zoom (Ctrl+wheel),
  fit-to-view, click-to-sync with the linear view.
- **Decompiler (multi-level IL + Pseudo-C):** a per-function decompiler in the Binary Ninja mold,
  shown in a *Decompiler* tab with a Low IL / Medium IL / High IL / Pseudo-C selector. **Low IL**
  lifts each instruction to register/memory/flag semantics (flags handled as deferred conditions so a
  `cmp`/`jcc` pair becomes `a < b`); **Medium IL** promotes constant stack slots to named locals/args,
  elides prologue/epilogue and stack-pointer bookkeeping, forward-substitutes and constant-folds
  expressions, drops dead stores (CFG liveness), and recovers call arguments (x64 register convention,
  reusing the API annotations); **High IL** recovers structured control flow — `if`/`else`,
  `while`, `switch`, `break`/`continue` — using dominators for loops and post-dominators for
  conditional merges, falling back to `goto`/labels on irreducible code so it is never wrong; and
  **Pseudo-C** renders that as C with a best-effort signature, local declarations and call sites.
  Built lazily on a background thread and cached per function; instructions outside the lifted x86/x64
  subset degrade to a faithful `__asm(...)` line. Click any line to sync the other panes; double-click
  a call to follow the callee. Best-effort by design — the IL tiers are the most reliable, structured
  C the most ambitious.
- **Jump-table (switch) recovery:** indirect `jmp`s that dispatch through a jump table are resolved
  statically — recovering the table base (`lea`/displacement), the case count (`cmp` bound), and the
  entries from the binary's data. Handles absolute-pointer tables (`jmp [base+idx*8]`, x64/x86) and
  MSVC/GCC RVA-offset tables (`mov [tab+idx*4]; add; jmp reg`). Case targets become real CFG edges +
  `loc_` labels, and the `jmp` is annotated `; switch (N cases)`. True dynamic dispatch (vtables,
  function pointers) is left indirect, as it should be.
- **Hex view:** on-demand, virtualized over the whole address space; **editable** — type hex over the
  caret byte (edited bytes highlighted).
- **Patching (x86/x64):** right-click an instruction → *Patch…* to assemble a replacement (`nop`,
  `jmp 0x…`, `mov eax, 1`, branches, simple ALU/mov ops — via Iced's encoder) or NOP it out; raw hex
  bytes are also accepted. Patches cover whole instructions and NOP-pad the remainder to stay aligned.
  Edits are an in-memory overlay seen everywhere; a patch re-decodes only the changed region and
  splices it into the linear index (no full re-sweep — milliseconds, not seconds), with Ctrl+Z undo.
  *Save Patched As…* writes a new binary.
- **Windows API awareness (IDA/BN-style):** a bundled database of ~100 common Win32 prototypes
  annotates each API call site with the function's parameters and, where it can prove them, the
  argument *values* — recovered by a short backward scan of the registers (x64 rcx/rdx/r8/r9, plus
  x64 stack args at `[rsp+0x20+…]`) or stack pushes (x86) feeding the call. Integer arguments are
  decoded into symbolic constants: access masks (`FILE_ACCESS`, `PROCESS_ACCESS`, `REGSAM`,
  `TOKEN_ACCESS`, `FILE_MAP`), share modes, page protections (`PAGE_*`), allocation types (`MEM_*`),
  creation dispositions, and file flags/attributes (`FILE_FLAG_*`/`FILE_ATTRIBUTE_*`). e.g.
  `RegOpenKeyExW(hKey, lpSubKey=L"Software\\…", samDesired=KEY_READ)`,
  `VirtualAlloc(…, flAllocationType=MEM_COMMIT, flProtect=PAGE_EXECUTE_READWRITE)`. Shown inline in
  both linear and graph views.
- **Side panels:** Functions, Strings, Imports, Exports, Sections (with per-section "load into listing"
  toggles), Resources (the `.rsrc` tree + preview), and live Cross-references.
- **C++ demangling:** mangled symbol names are demangled to readable signatures throughout (Functions
  list, Exports/Imports, labels) — MSVC names (`?…`) via the OS `UnDecorateSymbolName`, and Itanium
  names (`_Z…`, GCC/Clang/MinGW/ELF) via a built-in demangler. Anything unrecognised is left as-is.
- **Projects:** save the session as a `.dsproj` (binary reference, load options, and current view
  state) via *Save Project…* and reopen it with *Open Project…* — it re-analyses on open (fast, always
  consistent with the engine). The format is versioned to carry future user edits (renames, comments).
- **Export:** *Save ASM…* / *Save C…* on the toolbar write the whole-program disassembly listing
  (`.asm`) or the decompiled C of every function (`.c`); both stream to disk on a background thread
  with a progress bar. Right-click a function in the linear view (*Save function as ASM…*) or the
  decompiler (*Save function as C…*) to export just that one. The C save offers two flavours via the
  dialog's file-type box: **readable** Pseudo-C, or **compilable** C — a self-contained translation
  unit (generated preamble declaring the registers as integer globals, typed pointer casts, an
  indirect-call helper, forward prototypes) that compiles under MSVC (`cl /c`). It's an approximation
  for inspection/tweaking, not a faithful rebuild.
- **Debugger (x86/x64, live):** launch the loaded PE under the debugger or *Attach…* to a running
  process by PID. The disassembly switches to **live process memory** (so packed/self-modifying code is
  shown as it executes), with the current instruction highlighted and followed. Run/Continue (F5),
  Step Into (F7), Step Over (F8), Step Out (Shift+F11), Pause, Stop, and Run-to-cursor; software
  breakpoints (F2 / gutter) and hardware breakpoints + watchpoints (Dr0–3). A bottom panel shows
  **registers** (editable, with x64dbg-style **dereferencing** — `r9 → start`, `rcx → "C:\\…"`),
  the **stack** and a **memory dump** (both dereferenced), the **call stack**, and breakpoints,
  threads and modules. 32-bit targets are debugged from the 64-bit host via WOW64.
- **Debug a DLL:** a DLL can't be launched on its own, so pressing Run on a loaded DLL opens a small
  *Debug DLL* dialog that hosts it in an EXE (the way x64dbg uses a loaddll stub). The default host is
  the bitness-matched OS `rundll32.exe`; you can browse to a custom host EXE (e.g. the real consumer
  app) and pass command-line arguments, and optionally pick an exported function to break at. When the DLL
  maps into the host the debugger retargets to it — `ImageBase`/disassembly rebased to the DLL's real
  load address — and breaks at the chosen export (or, by default, the DLL's DllMain), from where everything above (stepping,
  breakpoints, registers, stack) works on the DLL itself.
- **Generic unpacker (run-to-OEP → dump → rebuild imports):** for packed/compressed executables, the
  **Unpack…** toolbar button runs the target under the debugger, automatically stops at the **Original
  Entry Point** (an *Auto* strategy: the x86 ESP-trick, then NX/execute section breakpoints — the original
  sections are made non-executable so only the OEP code fetch faults, never the stub's decompression writes;
  or a manual OEP), then **dumps the unpacked image from memory**, **reconstructs the Import Address Table**
  (ImpRec/Scylla-style — resolving each IAT slot against the live modules' export tables and following
  simple redirection stubs), fixes the entry point, and writes a clean, re-analyzable PE you can reopen in
  place. The **section layout is tidied** so the result reads like an ordinary executable rather than
  `UPX0`/`UPX1`/…: the section holding the OEP becomes `.text`, the resource section `.rsrc`, the rebuilt
  imports `.idata`, and the now-dead unpack stub section is **dropped** (its bytes zeroed and the preceding
  section grown over the gap so the layout stays contiguous). A UPX stub usually keeps the **Load Config** the
  loader needs (security cookie / CFG tables) inside itself; that one directory is **relocated** into the
  rebuilt `.idata` and its data-directory repointed, so the stub can still be removed. The rebuilt executable
  also **runs** — the writer resets the `/GS` security cookie, neutralizes the
  Control-Flow-Guard indirect-call pointers, and chooses the right base/relocation strategy (keep ASLR when a
  full relocation table is present, otherwise pin the original base) so a dumped image launches as a fresh
  process (verified end-to-end on UPX-packed and live x86/x64 targets). A packer detector (entropy + section signatures for UPX, ASPack, FSG, PECompact, MPRESS, …) flags
  packed files on open and warns when a code-virtualizing protector (VMProtect/Themida) is detected, since
  those can't be recovered by dumping. Virtualizers are caught structurally too — an RWX high-entropy entry
  stub, a stripped import directory, and odd/duplicated section names — so a build whose `.vmpN` section
  names have been renamed or stripped is still classified as an un-dumpable virtualizer rather than a
  generic "unknown packer." An optional **job-object sandbox** blocks the untrusted target from
  spawning child processes and kills it on close (process-level containment only — use a VM for truly
  untrusted samples). Handles both x86 and x64 targets. For aggressively protected targets there is also a
  **Run-free** strategy (no OEP trace — no single-step, hardware watchpoint or section guard) that just runs
  the target and dumps when it settles or faults, plus per-run toggles for the code-modifying parts of the
  hide layer (the ntdll/user32 API hooks, and the rdtsc patch of the target's own code) so you can tell
  whether the *debugger* is what a self-CRC / anti-hook protector is detecting. When a run dies, the failure
  is **localized**: the fault site is reported with its module + offset, the faulting instruction
  disassembled from live memory, the registers, and — for an access violation — exactly what address it
  tried to read/write/execute and that page's state, and the (partially) decrypted image is **dumped at the
  fault** for offline inspection. Run-free also takes an entry snapshot and a few short timed memory snapshots
  before the final settle dump so you can compare section entropy over time and see whether a VM body ever becomes less opaque
  before an anti-debug self-crash; when probes exist the unpack dialog surfaces the lowest-entropy one through
  **Devirt best probe**.
  If no snapshot exposes a static dispatcher, the **Trace VM loop/handlers** strategy single-steps a bounded
  execution window and writes a `.vmtrace.txt` report with hot indirect dispatch sites, concrete runtime
  handler targets, and short handler-body samples. This is trace-based recovery evidence, not a restored
  native-code unpack.
- **Anti-anti-debug ("Hide debugger"):** a ScyllaHide-style layer (toolbar checkbox; always on during
  *Unpack*) that hides the debugger from a target's detection checks. Applied at the loader breakpoint —
  before the program's own code runs — it normalizes the PEB (`BeingDebugged`, the `NtGlobalFlag` heap-debug
  bits, and the process heap's `Flags`/`ForceFlags`) and installs silent hooks on the ntdll routines
  protectors query — `NtQueryInformationProcess` (`ProcessDebugPort`/`DebugObjectHandle`/`DebugFlags`),
  `NtSetInformationThread` (`ThreadHideFromDebugger`), and `NtQuerySystemInformation`
  (`SystemKernelDebuggerInformation`) — emulating a clean "not debugged" result, and defeats the
  close-invalid-handle trick. It also masks the debug registers from `NtGetContextThread` (so hardware
  breakpoints are invisible to self-inspection) and preserves them across `NtSetContextThread` (so the target
  can't clear them), and feeds a slow synthetic clock to the timing functions
  (`GetTickCount`/`GetTickCount64`/`QueryPerformanceCounter`/`GetSystemTimeAsFileTime` and the `Nt*`
  equivalents) so single-step/breakpoint slowdowns don't show up as a time delta. It even intercepts the
  `rdtsc`/`rdtscp` instructions themselves — found by disassembling the target's code (skipping packed/
  high-entropy sections so it never corrupts compressed data) and emulated from the same synthetic clock.
  Works for x86 and x64 targets.
- **Navigation:** double-click to follow a call/branch, Back/Forward history, Ctrl+G go-to-address,
  and an address box. Open a file from the command line (`DisasmStudio <path>`) or via *Open…*.
- **Help:** a *Help ▾* toolbar menu with a grouped keyboard-shortcut reference (also opened with **F1**) —
  covering the debugger, navigation, and the linear / hex / graph / decompiler views — and an *About* box
  (name, version, feature overview, runtime).
- **High-DPI:** per-monitor-v2 aware; DPI-correct text and pixel-snapped lines that re-render sharply
  when moved between displays of different scale.

## Layout

```
src/
  DisasmStudio.Core/     engine (no WPF): Formats/, Disasm/, Analysis/, IL/, Export/
  DisasmStudio.Debug/    live debugger: Win32 debug-loop interop, breakpoints, live image/disasm, dereference
  DisasmStudio.Wpf/      UI: custom controls, soft slate theme, view-models
```

The analysis runs on a background thread: scan strings → one linear sweep building the instruction
index + cross-references + call/branch targets → name resolution + function list. Per-function CFGs
are built lazily when a function is opened in the graph, keeping huge files fast.

## APIs & libraries

A small, deliberate set of dependencies: one disassembler library, the OS debugging and symbol APIs, and
the .NET base class library.

**Iced (`Iced.Intel`, NuGet 1.21.0)** — the x86/x64 decoder *and* encoder. Everything that touches machine
code goes through it: `Decoder` for disassembly, the formatter for operand text, `FlowControl`/operand
metadata for the analysis (calls, branches, jump-table shapes), and the `Encoder`/`BlockEncoder` for the
*Patch…* assembler.

**Win32 debugging API (`kernel32.dll`, P/Invoke in `DisasmStudio.Debug/Native.cs`)** — the entire live
debugger. Called only on Windows; 32-bit (WOW64) targets use the `Wow64*` context entry points.

| Function | Used for |
| --- | --- |
| `CreateProcessW` (`DEBUG_ONLY_THIS_PROCESS`) | Launch the target under the debugger |
| `DebugActiveProcess` / `DebugActiveProcessStop` | Attach to / detach from a running process by PID |
| `DebugSetProcessKillOnExit` | Keep an attached process alive after we detach |
| `WaitForDebugEvent` / `ContinueDebugEvent` | The debug-event loop — stops, exceptions, thread/module load |
| `DebugBreakProcess` | Inject a break for *Pause* |
| `ReadProcessMemory` / `WriteProcessMemory` | Read live memory (disasm, dump, stack) and write breakpoint / patch bytes |
| `VirtualProtectEx` | Make a code page writable to plant / restore an `int3` (`0xCC`) |
| `VirtualQueryEx` | Page state and protection (is an address committed / executable) |
| `FlushInstructionCache` | Flush the i-cache after writing breakpoint or patch bytes |
| `GetThreadContext` / `SetThreadContext` | Read / write x64 registers, the trap flag, and Dr0–7 |
| `Wow64GetThreadContext` / `Wow64SetThreadContext` | The same for a 32-bit (WOW64) target |
| `IsWow64Process` | Detect a 32-bit target so the right context is used |
| `TerminateProcess` | Stop a launched debuggee |
| `K32GetModuleFileNameEx` | Resolve a loaded module's path (modules panel, names) |
| `CloseHandle` | Release process / thread / file handles |

**`dbghelp.dll` — `UnDecorateSymbolName`** — demangles MSVC C++ names (`?…`) to readable signatures. Itanium
names (`_Z…`, GCC/Clang/MinGW/ELF) are demangled by a built-in demangler instead
(`DisasmStudio.Core/Analysis/Demangler.cs`).

**.NET base class library:**
- **`System.IO.MemoryMappedFiles`** — the on-disk binary is read through a read-only memory-mapped view
  (`MappedFile`), so only the pages actually touched fault into RAM and a multi-hundred-MB target never sits
  on the managed heap.
- **`NativeMemory.AlignedAlloc` + `Marshal`** — the x64 `CONTEXT` must be 16-byte aligned for
  `GetThreadContext`; registers are read/written through `Marshal` at fixed offsets (`ThreadContextAccess`).
- **`System.Text.Json`** — `.dsproj` projects and the exception-filter policy
  (`%AppData%\DisasmStudio\exceptions.json`) are serialized with it.
- **WPF (`PresentationFramework` / `WindowsBase`)** — the UI: the custom virtualized controls, the dark
  theme, and per-monitor-v2 high-DPI handling.

## Build & run

```
dotnet build DisasmStudio.slnx -c Debug
dotnet run --project src/DisasmStudio.Wpf
# or open a target directly:
dotnet run --project src/DisasmStudio.Wpf -- C:\Windows\System32\notepad.exe
```

Requires the .NET 10 SDK (Windows). x64.

## Scope

v1 targets x86/x64 static analysis, a best-effort decompiler (multi-level IL + Pseudo-C), and a live
user-mode debugger (Windows PE; x86/x64). Out of scope (for now): signatures/FLIRT, kernel/remote
debugging, time-travel, scripting/plugins, other architectures, .NET managed debugging, and PDB symbol
servers — the call stack uses a best-effort frame/return-address heuristic (no full `.pdata` unwind
yet), and symbols come from the app's own analysis + demangler rather than a symbol server.

### Devirtualization (experimental foundation)

`DisasmStudio.Core/Devirt/` is the start of a VM-protector devirtualizer (VMProtect/Themida-class). Given a
**decrypted** image it discovers the VM entry/dispatcher/handler table, classifies each handler's stack-VM
semantics, decodes the bytecode the VIP walks, and lifts it back into the shared IR so the existing
`Structurer` + Pseudo-C emitter render readable C — no separate renderer. It is honest about its limits,
returning `NoVmFound` / `ImageEncrypted` / `UnsupportedVm` / `PartialRecovery` rather than guessing. This is a *foundation*,
proven end-to-end on a synthetic stack VM (the engine and a built-in `Synthetic/SyntheticVm` are exercised
by the `.smoke_devirt` harness); it is **not** a complete devirtualizer. The toolbar's **Devirt...** action
runs the experimental engine on the current image, and unpacker failures with a fault snapshot enable
**Devirt snapshot** so the RVA-indexed memory dump is analysed at the runtime image base. Deferred: real VMProtect/Themida
version-specific handler signatures and deobfuscation, VIP decryption schedules, multi-entry whole-program
recovery, and — the gating prerequisite for real samples — obtaining a decrypted dump past a
protector's anti-debug (virtualized code is only present, decrypted, at runtime).

The decrypt-dump prerequisite is the hard part: a well-hardened VMProtect build can detect even a *clean*
user-mode debugger (one with no breakpoints, single-stepping, hardware watchpoints, code patches or
detectable hooks) and quietly sabotage itself before it ever decrypts — defeating that is its own
research effort (deep per-check tracing, or kernel-level hiding) and is out of scope here. The unpacker's
Run-free mode, hide-layer toggles and fault localization (above) are the tools for *diagnosing* how far a
given sample gets; they do not promise to beat a top-tier protector's anti-debug.
