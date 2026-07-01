# Arc-Dark theme spec ("arc-dark" — flat / cool-grey / Arc blue)

A portable, project-agnostic color spec. This is the palette DisasmStudio ships (the WPF
UI, the disassembly/graph/hex views, and the code-built dialogs). It mirrors the role
vocabulary of `nord-theme.md` exactly, so the two are drop-in interchangeable **by role** —
apply the Arc-Dark theme by mapping each role to wherever the target app stores colors.

It reproduces the look of the Kvantum `arc-dark` Qt style (the GTK/KDE Arc theme, dark
variant): flat cool-grey surfaces, muted borders, and the signature Arc blue `#5294E2` as
the single accent.

## Design intent

Calm, flat, and low-chroma. Surfaces are cool blue-grey and close in value, so panels read
as one quiet field rather than a stack of contrasting boxes; the accent is the only
saturated color in the chrome. Controls are flat — hover lifts a surface one step lighter,
press sinks it one step darker, and blue appears only to mark focus, selection, or a checked
state (never as a hover flood).

- **Surface rule** (darkest → lightest): `#2B2E39 < #33373F < #383C4A < #404552`
  (`Background < SurfaceAlt < Surface < Surface2`). Buttons hover to `#474D5C` and press to
  `#31353F`.
- **Text rule**: light text (`#D3DAE3`) on all dark surfaces; white (`#FFFFFF`) on the
  Arc-blue checked/selected fills; **dark text** (`#2B2E39`) only when it sits on a *filled*
  light accent (the pressed state of the green/amber/red semantic buttons).

## Palette by role

### Chrome (windows, panels, buttons, lists, tabs, menus, dialogs)
| Role | Hex | Use |
| --- | --- | --- |
| Background | `#2B2E39` | window / app background (darkest) |
| Surface | `#383C4A` | panels, lists, tabs, dialog bg |
| Surface2 | `#404552` | raised controls (buttons, inputs, popups), block headers |
| SurfaceAlt | `#33373F` | alt rows, gutters |
| SurfaceHover | `#474D5C` | button hover fill |
| SurfacePressed | `#31353F` | button press fill |
| Outline | `#454C5C` | default borders / separators |
| OutlineStrong | `#565E70` | stronger borders (tooltip, popup, checkbox, block border) |
| TextPrimary | `#D3DAE3` | primary text |
| TextSecondary | `#C0C7D1` | labels, secondary text |
| TextMuted | `#8A929E` | muted / disabled / hint text |
| Accent | `#5294E2` | focus, checked, selection brush, links |
| AccentHover | `#6FA8E8` | accent hover |
| AccentPressed | `#4180CE` | accent pressed |
| AccentSoft | `#37455C` | soft accent fill (hover rows) |
| Selection | `#3A5678` | selected-row background |
| Warn | `#F0883E` | warnings (orange) |
| Error | `#E24C56` | errors (red) |

### Syntax / data views (disassembly, code editors, structured data)
| Role | Hex | Use |
| --- | --- | --- |
| Address | `#7FB0EA` | address column / line numbers |
| Bytes | `#6B7385` | raw bytes / dim secondary column |
| FuncName / String | `#E8A25A` | function headers, string literals |
| Mnemonic / Keyword-verb | `#8FB6EE` | instruction mnemonics / primary keywords |
| Register / Type | `#7FD0C4` (`#66C9BC` types) | registers; recovered C types |
| Number | `#C79BE0` | numeric literals |
| Symbol | `#9FD07A` | named targets (sub_/loc_/imports), identifiers |
| Keyword / Prefix | `#5FBFD6` | directives, rep/lock prefixes |
| Punctuation | `#78808F` | punctuation |
| Text | `#D3DAE3` | primary/fallback text |
| Comment | `#6E7686` | comments |
| Variable | `#C9D0DA` | recovered variables / locals |

### Editor decorations / debugger states
| Role | Hex | Use |
| --- | --- | --- |
| Separator | `#454C5C` | column / function rules |
| CurrentLine | `#383C4A` | current-line band |
| CurrentIp (band) | `#4A4634` | current-instruction amber band (debugger) |
| Breakpoint | `#E24C56` | software breakpoint marker (red) |
| HwBreakpoint | `#7FD0E0` | hardware breakpoint marker (cyan) |
| CoveredTrace (band) | `#2E4A3A` | executed/covered line tint (green) |
| GutterBg | `#33373F` | line-number gutter background |

### Graph / node view
| Role | Hex |
| --- | --- |
| Edge taken | `#9FD07A` |
| Edge fall-through | `#78808F` |
| Edge jump | `#6FA8E8` |
| Edge switch-case | `#C79BE0` |
| Block fill | `#383C4A` |
| Block border | `#565E70` |
| Block header | `#404552` |

### Hex view
| Role | Hex |
| --- | --- |
| Background | `#2B2E39` |
| Address | `#7FB0EA` |
| Hex digits | `#D3DAE3` |
| ASCII | `#9FD07A` |
| Dim (zero/unreadable) | `#565E70` |
| Patched byte | `#F0883E` |
| Selection overlay | `#5294E2` at ~40% alpha (`#665294E2` ARGB) |

## How to apply it to a project

1. **Central theme dictionary / stylesheet** (WPF `ResourceDictionary`, CSS vars, a
   `Colors`/`Theme` class) — map the **Chrome** roles.
2. **Custom-painted views** (syntax highlighters, `OnRender`/canvas controls, graph/hex
   views) — map the **Syntax / decorations / graph / hex** roles. This is often a second
   palette in code, independent of #1.
3. **Code-built dialogs / one-offs** that hardcode `Bg/Fg/Accent` — map the **Chrome** roles
   plus Warn/Error.

The same hex is often duplicated across these homes (changing one won't propagate), so after
recoloring, grep the source for the *old* palette's hex values and confirm only intentional
literals remain.

### Platform notes
- **WPF** — theme-dictionary brushes via `StaticResource`/`DynamicResource`; code palettes as
  `SolidColorBrush(Color.FromRgb(...))`.
- **WinForms** — `Color.FromArgb` + `BackColor`/`ForeColor` + owner-draw.
- **Native Win32/GDI** — `COLORREF` via `RGB()` (GDI stores BGR) for `CreateSolidBrush` /
  `SetTextColor` / `SetBkColor`.
- **Web/CSS** — custom properties (`--bg`, `--accent`, …).

## Reference implementation
- `src/DisasmStudio.Wpf/Themes/Dark.xaml` — chrome named brushes + control styles.
- `src/DisasmStudio.Wpf/Services/SyntaxTheme.cs` — syntax/views/decorations/graph.
- `src/DisasmStudio.Wpf/Controls/HexView.cs` — hex palette.
- The code-built dialogs (`Dialogs.cs`, `HelpDialog.cs`, `ExceptionDialog.cs`,
  `DevirtReportDialog.cs`, `UnpackerDialog.cs`, `NonInvasiveDumpDialog.cs`,
  `ResourcePreview.cs`) — hardcoded `Bg/Fg/Sub/Accent/Warn`.

See `nord-theme.md` for the earlier Nord variant; the role names are identical, so switching
between the two is a hex-for-hex swap.
