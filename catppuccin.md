# Catppuccin Frappé theme spec ("catppuccin-frappe" — soft / muted / pastel-accent)

A portable, project-agnostic color spec. This is the palette DisasmStudio ships (the WPF
UI, the disassembly/graph/hex views, and the code-built dialogs). It mirrors the role
vocabulary of `arc-dark.md` and `nord-theme.md` exactly, so all three are drop-in
interchangeable **by role** — apply a theme by mapping each role to wherever the target app
stores colors.

It reproduces the [Catppuccin](https://github.com/catppuccin/catppuccin) **Frappé** flavor
(the medium-dark member of the four flavors: Latte / Frappé / Macchiato / Mocha), with
**Lavender** `#babbf1` as the single UI accent.

## Design intent

Soft, muted, low-contrast. Surfaces are a warm blue-grey and close in value, so panels read
as one quiet field rather than a stack of contrasting boxes; the accent is a gentle pastel.
Controls are flat — hover lifts a surface one step lighter, press sinks it one step darker,
and lavender appears only to mark focus, selection, or a checked state (never as a hover
flood).

- **Surface rule** (darkest → lightest): `#232634 < #292C3C < #303446 < #414559 < #51576D < #626880`
  (`crust < mantle < base < surface0 < surface1 < surface2`). The window is `base`; panels are
  `surface0`; raised controls are `surface1`; buttons hover to `surface2` and press to `crust`.
- **Text rule**: light text (`#C6D0F5`) on all dark surfaces; **dark text** (`crust #232634`)
  whenever it sits on a *filled* pastel accent — the checked/selected lavender fill and the
  pressed state of the green/peach/red semantic buttons. Catppuccin accents are light, so
  on-accent text is **never white**.

## Palette by role

### Chrome (windows, panels, buttons, lists, tabs, menus, dialogs)
| Role | Hex | Catppuccin token | Use |
| --- | --- | --- | --- |
| Background | `#303446` | base | window / app background |
| Surface | `#414559` | surface0 | panels, lists, tabs, dialog bg |
| Surface2 | `#51576D` | surface1 | raised controls (buttons, inputs, popups), block headers |
| SurfaceAlt | `#292C3C` | mantle | alt rows, gutters |
| SurfaceHover | `#626880` | surface2 | button hover fill |
| SurfacePressed | `#232634` | crust | button press fill |
| Outline | `#51576D` | surface1 | default borders / separators |
| OutlineStrong | `#626880` | surface2 | stronger borders (tooltip, popup, checkbox, block border) |
| TextPrimary | `#C6D0F5` | text | primary text |
| TextSecondary | `#B5BFE2` | subtext1 | labels, secondary text |
| TextMuted | `#838BA7` | overlay1 | muted / disabled / hint text |
| Accent | `#BABBF1` | lavender | focus, checked, selection brush, links |
| AccentHover | `#CBCCF4` | lavender ↑ | accent hover |
| AccentPressed | `#9193BE` | lavender ↓ | accent pressed |
| AccentSoft | `#4C4F68` | lavender wash | soft accent fill (hover rows) |
| Selection | `#575A76` | lavender-tint | selected-row background |
| Warn | `#EF9F76` | peach | warnings |
| Error | `#E78284` | red | errors |
| OnAccent | `#232634` | crust | text/glyph on any filled accent or semantic fill |

Semantic toolbar buttons (Run/Pause/Stop) also use `Success #A6D189` (green) plus dim same-hue
washes `SuccessSoft #434D51`, `WarnSoft #4B434D`, `DangerSoft #4D4050` (each ~16–20% of the
accent blended over `base`).

### Syntax / data views (disassembly, code editors, structured data)
| Role | Hex | Catppuccin token | Use |
| --- | --- | --- | --- |
| Address | `#8CAAEE` | blue | address column / line numbers |
| Bytes | `#838BA7` | overlay1 | raw bytes / dim secondary column |
| FuncName | `#E5C890` | yellow | function headers |
| String / StringRef | `#EF9F76` | peach | string literals, referenced-at marker |
| Mnemonic | `#8CAAEE` | blue | instruction mnemonics |
| Register | `#81C8BE` | teal | registers |
| Type | `#99D1DB` | sky | recovered C types |
| Number | `#EF9F76` | peach | numeric literals |
| Symbol | `#A6D189` | green | named targets (sub_/loc_/imports), identifiers |
| Keyword / Prefix | `#CA9EE6` | mauve | directives, rep/lock prefixes |
| Punctuation | `#949CBB` | overlay2 | punctuation |
| Text | `#C6D0F5` | text | primary/fallback text |
| Comment | `#737994` | overlay0 | comments |
| Variable | `#B5BFE2` | subtext1 | recovered variables / locals |

Hue choices follow Catppuccin's port style guide where it maps to assembly: keywords → mauve,
functions/mnemonics/addresses → blue, registers → teal, types → sky, numbers/strings → peach,
symbols → green, comments → overlay0.

### Editor decorations / debugger states
| Role | Hex | Use |
| --- | --- | --- |
| Separator | `#51576D` | column / function rules (surface1) |
| CurrentLine | `#414559` | current-line band (surface0) |
| CurrentIp (band) | `#4E4A35` | current-instruction amber band (debugger) |
| Breakpoint | `#E78284` | software breakpoint marker (red) |
| HwBreakpoint | `#99D1DB` | hardware breakpoint marker (sky) |
| CoveredTrace (band) | `#384A3C` | executed/covered line tint (green) |
| GutterBg | `#292C3C` | line-number gutter background (mantle) |

### Graph / node view
| Role | Hex | Token |
| --- | --- | --- |
| Edge taken | `#A6D189` | green |
| Edge fall-through | `#838BA7` | overlay1 |
| Edge jump | `#8CAAEE` | blue |
| Edge switch-case | `#CA9EE6` | mauve |
| Block fill | `#414559` | surface0 |
| Block border | `#626880` | surface2 |
| Block header | `#51576D` | surface1 |

### Hex view
| Role | Hex | Token |
| --- | --- | --- |
| Background | `#303446` | base |
| Address | `#8CAAEE` | blue |
| Hex digits | `#C6D0F5` | text |
| ASCII | `#A6D189` | green |
| Dim (zero/unreadable) | `#626880` | surface2 |
| Patched byte | `#EF9F76` | peach |
| Selection overlay | `#BABBF1` at ~40% alpha (`#66BABBF1` ARGB) | lavender |

## How to apply it to a project

1. **Central theme dictionary / stylesheet** (WPF `ResourceDictionary`, CSS vars, a
   `Colors`/`Theme` class) — map the **Chrome** roles.
2. **Custom-painted views** (syntax highlighters, `OnRender`/canvas controls, graph/hex
   views) — map the **Syntax / decorations / graph / hex** roles.
3. **Code-built dialogs / one-offs** that hardcode `Bg/Fg/Accent` — map the **Chrome** roles
   plus Warn/Error.

**Watch the on-accent text**: because Catppuccin accents are light, any white-on-accent literal
must flip to `OnAccent` (`#232634`).

### Platform notes
- **WPF** — theme-dictionary brushes via `StaticResource`/`DynamicResource`; code palettes as
  `SolidColorBrush(Color.FromRgb(...))`.
- **WinForms** — `Color.FromArgb` + `BackColor`/`ForeColor` + owner-draw.
- **Native Win32/GDI** — `COLORREF` via `RGB()` (GDI stores BGR) for `CreateSolidBrush` /
  `SetTextColor` / `SetBkColor`.
- **Web/CSS** — custom properties (`--bg`, `--accent`, …).

## Reference implementation

DisasmStudio centralizes all of the above into a **single source of truth** —
`src/DisasmStudio.Wpf/Services/Palette.cs`. It holds the 26 Catppuccin tokens (plus two
hand-tuned debugger bands and the accent alias) as the only per-flavour edit point; the derived
accent/semantic tints are *computed* (blended over `base`), and it exposes both `Color`s (for XAML
`x:Static`) and frozen `SolidColorBrush`es (for code). **To switch flavour, edit only the token
block in `Palette.cs`.** The consumers each just map roles → palette tokens:

- `Themes/Dark.xaml` — chrome named brushes (`Color="{x:Static svc:Palette.*}"`) + control styles.
- `Services/SyntaxTheme.cs` — syntax/views/decorations/graph roles → `Palette.*Brush`.
- `Controls/HexView.cs` — hex palette → `Palette.*Brush`.
- The code-built dialogs (`Dialogs.cs`, `HelpDialog.cs`, `ExceptionDialog.cs`,
  `DevirtReportDialog.cs`, `UnpackerDialog.cs`, `NonInvasiveDumpDialog.cs`, `ResourcePreview.cs`)
  — `Bg/Fg/Sub/Accent/Warn` → `Palette.*Brush`.

(Because everything reads from `Palette.cs`, `Color.FromRgb`/`FromArgb` appears in exactly one
file — there is only one place a colour is written.)

See `arc-dark.md` and `nord-theme.md` for the earlier variants; the role names are identical,
so switching between any of them is a hex-for-hex swap. Other Catppuccin flavors (Latte,
Macchiato, Mocha) swap in by replacing the token hexes in `Palette.cs` with that flavor's palette.
