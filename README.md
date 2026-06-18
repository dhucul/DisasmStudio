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
- **Graph view:** per-function control-flow graph — basic-block cards of coloured instructions with
  colour-coded edges (taken / fall-through / jump / switch-case). Pan (drag), zoom (Ctrl+wheel),
  fit-to-view, click-to-sync with the linear view.
- **Jump-table (switch) recovery:** indirect `jmp`s that dispatch through a jump table are resolved
  statically — recovering the table base (`lea`/displacement), the case count (`cmp` bound), and the
  entries from the binary's data. Handles absolute-pointer tables (`jmp [base+idx*8]`, x64/x86) and
  MSVC/GCC RVA-offset tables (`mov [tab+idx*4]; add; jmp reg`). Case targets become real CFG edges +
  `loc_` labels, and the `jmp` is annotated `; switch (N cases)`. True dynamic dispatch (vtables,
  function pointers) is left indirect, as it should be.
- **Hex view:** on-demand, virtualized over the whole address space.
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
- **Side panels:** Functions, Strings, Imports, Sections, and live Cross-references.
- **Projects:** save the session as a `.dsproj` (binary reference, load options, and current view
  state) via *Save Project…* and reopen it with *Open Project…* — it re-analyses on open (fast, always
  consistent with the engine). The format is versioned to carry future user edits (renames, comments).
- **Navigation:** double-click to follow a call/branch, Back/Forward history, Ctrl+G go-to-address,
  and an address box. Open a file from the command line (`DisasmStudio <path>`) or via *Open…*.
- **High-DPI:** per-monitor-v2 aware; DPI-correct text and pixel-snapped lines that re-render sharply
  when moved between displays of different scale.

## Layout

```
src/
  DisasmStudio.Core/     engine (no WPF): Formats/, Disasm/, Analysis/
  DisasmStudio.Wpf/      UI: custom controls, soft slate theme, view-models
```

The analysis runs on a background thread: scan strings → one linear sweep building the instruction
index + cross-references + call/branch targets → name resolution + function list. Per-function CFGs
are built lazily when a function is opened in the graph, keeping huge files fast.

## Build & run

```
dotnet build DisasmStudio.slnx -c Debug
dotnet run --project src/DisasmStudio.Wpf
# or open a target directly:
dotnet run --project src/DisasmStudio.Wpf -- C:\Windows\System32\notepad.exe
```

Requires the .NET 10 SDK (Windows). x64.

## Scope

v1 targets x86/x64 static analysis. Out of scope (for now): decompilation, signatures/FLIRT,
debugging, scripting/plugins, other architectures, patching/assembling, and PDB symbol servers — the
`IBinaryImage` / token-formatter / Iced-bitness seams are left in place to add these later.
