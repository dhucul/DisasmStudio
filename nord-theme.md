# Nord theme spec ("nord3" — deep / saturated-blue / vivid)

A portable, project-agnostic color spec. This is the palette shipped in DisasmStudio 2.6.0.
To apply it to another app, map each **role** below to wherever that app keeps its colors —
don't just edit one file. Hand this whole document to any project and ask to "apply the Nord
theme by role."

## Design intent

A Nord-derived dark scheme: **deepest Polar Night** surfaces, a **brighter saturated-blue**
chrome accent (instead of Nord's frost cyan), and **vivid aurora/frost** syntax colors. Cool,
high body-contrast, easy on the eyes for long reading sessions.

Surface rule: background is darkest, each surface tier steps lighter —
`#1B2028 < #21272F < #272D37 < #343C4A < #404959 < #4F596B`.

Text rule: use **light** text everywhere, EXCEPT use **dark** text (`#1B2028`) when it sits on
the light accent fill (e.g. a checked toggle/checkbox). The accent here is medium-bright, so
light text on it is fine — only flip to dark if you make the accent noticeably lighter.

## Palette by role

### Chrome (windows, panels, buttons, lists, tabs, menus, dialogs)
| Role | Hex | Use |
|---|---|---|
| Background | `#1B2028` | window / app background (darkest) |
| Surface | `#272D37` | panels, lists, tabs, dialog bg |
| Surface2 | `#343C4A` | raised controls (buttons, inputs, popups), block headers |
| SurfaceAlt | `#21272F` | alt rows, gutters |
| Outline | `#404959` | default borders / separators |
| OutlineStrong | `#4F596B` | stronger borders (tooltip, popup, checkbox, block border) |
| TextPrimary | `#F0F3F8` | primary text |
| TextSecondary | `#DCE2EC` | labels, secondary text |
| TextMuted | `#8A95A9` | muted / disabled / hint text |
| Accent | `#6090D4` | accent: focus, checked, selection brush, links |
| AccentHover | `#84AEEC` | accent hover |
| AccentPressed | `#4A78B8` | accent pressed |
| AccentSoft | `#2C3C55` | soft accent fill (hover rows/buttons) |
| Selection | `#36496A` | selected-row background |
| Warn | `#F2D08A` | warnings (amber/gold) |
| Error | `#D85F6A` | errors (red) |

### Syntax / data views (disassembly, code editors, structured data)
| Role | Hex | Use |
|---|---|---|
| Address | `#88AEDE` | address column / line numbers |
| Bytes | `#6E7C97` | raw bytes / dim secondary column |
| FuncName / String | `#F2D08A` | function headers, string literals |
| Mnemonic / Keyword-verb | `#9CBEF2` | instruction mnemonics / primary keywords |
| Register / Type | `#9BDAD7` (`#90D6C9` types) | registers; recovered C types |
| Number | `#D49ACE` | numeric literals |
| Symbol | `#B9D998` | named targets (sub_/loc_/imports), identifiers |
| Keyword / Prefix | `#93DCEE` | directives, rep/lock prefixes, frost keywords |
| Punctuation | `#7886A2` | punctuation |
| Text | `#F2F5FA` | primary/fallback text |
| Comment | `#6B7894` | comments |
| Variable | `#E4EAF3` | recovered variables / locals |

### Editor decorations / debugger states
| Role | Hex | Use |
|---|---|---|
| Separator | `#404959` | column / function rules |
| CurrentLine | `#272D37` | current-line band |
| CurrentIp (band) | `#524B33` | current-instruction amber band (debugger) |
| Breakpoint | `#D85F6A` | software breakpoint marker (red) |
| HwBreakpoint | `#93DCEE` | hardware breakpoint marker (cyan) |
| CoveredTrace (band) | `#3C4D30` | executed/covered line tint (green) |
| GutterBg | `#21272F` | line-number gutter background |

### Graph / node view
| Role | Hex |
|---|---|
| Edge taken | `#B4DC90` |
| Edge fall-through | `#7886A2` |
| Edge jump | `#8AAEEC` |
| Edge switch-case | `#CD96C4` |
| Block fill | `#272D37` |
| Block border | `#4F596B` |
| Block header | `#343C4A` |

### Hex view
| Role | Hex |
|---|---|
| Background | `#1B2028` |
| Address | `#88AEDE` |
| Hex digits | `#F2F5FA` |
| ASCII | `#B4DC90` |
| Dim (zero/unreadable) | `#4F596B` |
| Patched byte | `#E0926F` |
| Selection overlay | `#6090D4` at ~40% alpha (`#666090D4` ARGB) |

## How to apply it to a project (the important part)

Colors are usually NOT centralized. Before editing, find **every color "home"** the app has,
or you'll recolor only part of it:

1. **Central theme dictionary / stylesheet** — the chrome (WPF `ResourceDictionary`, CSS vars,
   a `Colors`/`Theme` class). Map the *Chrome* roles here.
2. **Custom-painted views** — code that draws with raw color values (syntax highlighters,
   canvas/`OnRender` controls, graph/hex views). Often a second palette in code, independent of
   #1. Map the *Syntax / decorations / graph / hex* roles here.
3. **Code-built dialogs / one-offs** — windows that hardcode their own `Bg/Fg/Accent`. Map the
   *Chrome* roles (+ Warn/Error) here.

Watch for the **same hex duplicated** across homes — changing one won't propagate to the others.
After recoloring, grep the source for the OLD palette's hex values; only intentionally-kept
literals should remain.

### Platform notes
- **WPF**: theme dict brushes (ideally `DynamicResource` if you want runtime switching),
  plus any `Color.FromRgb`/`SolidColorBrush` literals in custom controls and dialogs.
- **WinForms**: `Color.FromArgb`, control `BackColor`/`ForeColor`, and any owner-draw painting.
- **Native Win32 / GDI**: convert each hex to a `COLORREF` (`RGB(r,g,b)` — note GDI is BGR
  ordered in memory) for `CreateSolidBrush`/`SetTextColor`/`SetBkColor`; there's no brush
  dictionary, so it's a per-paint re-map.
- **Web/CSS**: drop the hex into CSS custom properties (`--bg`, `--accent`, …) and reference them.

## Reference implementation

See DisasmStudio (`C:\Users\dhucu\source\repos\DisasmStudio`):
- `src/DisasmStudio.Wpf/Themes/Dark.xaml` — chrome (named brushes)
- `src/DisasmStudio.Wpf/Services/SyntaxTheme.cs` — syntax / views / decorations / graph
- `src/DisasmStudio.Wpf/Controls/HexView.cs` — hex palette
- the code-built dialogs (`Dialogs.cs`, `HelpDialog.cs`, `UnpackerDialog.cs`, …) — per-dialog Bg/Fg/Sub
