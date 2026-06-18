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
- **Graph view:** per-function control-flow graph — basic-block cards of coloured instructions with
  colour-coded edges (taken / fall-through / jump). Pan (drag), zoom (Ctrl+wheel), fit-to-view,
  click-to-sync with the linear view.
- **Hex view:** on-demand, virtualized over the whole address space.
- **Side panels:** Functions, Strings, Imports, Sections, and live Cross-references.
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
