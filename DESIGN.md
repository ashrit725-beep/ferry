---
name: Ferry console
description: The enclave's pre-flight checklist, a dark operator console where every fact is a challenge with a stamped, evidenced response.
colors:
  amber: "#f2a93b"
  amber-hover: "#f7ba5c"
  amber-press: "#d98e1f"
  amber-subtle: "#2a2417"
  on-amber: "#1a1203"
  selection: "#604b2b"
  rail: "#050f2b"
  rail-hover: "#0a1a44"
  rail-active: "#112459"
  rail-text: "#bfc9de"
  rail-muted: "#8fa0c0"
  rail-border: "#16254b"
  inset: "#0d121a"
  ground: "#121823"
  panel: "#171f2c"
  raised: "#1e2837"
  hover: "#263143"
  bone: "#e8e6de"
  text-2: "#b3b9c6"
  text-3: "#9099aa"
  hairline: "#263044"
  leader: "#4a566b"
  line-control: "#6b7a92"
  scrim: "rgb(3 8 20 / 0.72)"
  ok: "#3dd6a0"
  ok-subtle: "#0f2f27"
  bad: "#ff6a6a"
  bad-subtle: "#351a1f"
  on-bad: "#1b0a0e"
  info: "#6cb2ff"
  info-subtle: "#14263f"
  neutral: "#9ba5b6"
  neutral-subtle: "#232b39"
typography:
  display:
    fontFamily: "Azeret Mono, ui-monospace, SFMono-Regular, Menlo, Consolas, monospace"
    fontSize: "2.5rem"
    fontWeight: 500
    lineHeight: "3.5rem"
    letterSpacing: "-0.02em"
    fontFeature: "\"tnum\""
  headline:
    fontFamily: "Archivo Variable, system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: "1.75rem"
    fontWeight: 600
    lineHeight: "2.25rem"
    letterSpacing: "-0.01em"
    fontVariation: "\"wdth\" 112"
  readout:
    fontFamily: "Azeret Mono, ui-monospace, SFMono-Regular, Menlo, Consolas, monospace"
    fontSize: "1.25rem"
    fontWeight: 400
    lineHeight: 1
    fontFeature: "\"tnum\""
  title:
    fontFamily: "Archivo Variable, system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: "0.875rem"
    fontWeight: 600
    lineHeight: "1.25rem"
  body:
    fontFamily: "Archivo Variable, system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: "0.8125rem"
    fontWeight: 400
    lineHeight: "1.25rem"
    fontFeature: "\"tnum\""
  body-prose:
    fontFamily: "Archivo Variable, system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: "0.875rem"
    fontWeight: 400
    lineHeight: "1.25rem"
  table:
    fontFamily: "Archivo Variable, system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: "0.75rem"
    fontWeight: 400
    lineHeight: "1rem"
    fontFeature: "\"tnum\""
  label-caps:
    fontFamily: "Archivo Variable, system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: "0.6875rem"
    fontWeight: 500
    lineHeight: "1rem"
    letterSpacing: "0.14em"
  stamp:
    fontFamily: "Archivo Variable, system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: "0.6875rem"
    fontWeight: 500
    lineHeight: "1rem"
    letterSpacing: "0.06em"
  stage:
    fontFamily: "Archivo Variable, system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: "0.75rem"
    fontWeight: 600
    lineHeight: "1.25rem"
    letterSpacing: "0.12em"
    fontVariation: "\"wdth\" 112"
  mono:
    fontFamily: "Azeret Mono, ui-monospace, SFMono-Regular, Menlo, Consolas, monospace"
    fontSize: "0.75rem"
    fontWeight: 400
    lineHeight: "1rem"
    fontFeature: "\"tnum\""
rounded:
  code: "2px"
  sm: "3px"
  md: "4px"
  xl: "6px"
  2xl: "8px"
spacing:
  "1": "4px"
  "2": "8px"
  "3": "12px"
  "4": "16px"
  "6": "24px"
  row: "32px"
  control: "32px"
  topbar: "48px"
  rail: "232px"
components:
  button-primary:
    backgroundColor: "{colors.bone}"
    textColor: "{colors.ground}"
    typography: "{typography.body}"
    rounded: "{rounded.md}"
    padding: "0 10px"
    height: "32px"
  button-attention:
    backgroundColor: "{colors.amber}"
    textColor: "{colors.on-amber}"
    typography: "{typography.body}"
    rounded: "{rounded.md}"
    padding: "0 10px"
    height: "32px"
  button-attention-hover:
    backgroundColor: "{colors.amber-hover}"
  button-attention-active:
    backgroundColor: "{colors.amber-press}"
  button-danger:
    backgroundColor: "{colors.bad}"
    textColor: "{colors.on-bad}"
    rounded: "{rounded.md}"
    padding: "0 10px"
    height: "32px"
  button-ghost-hover:
    backgroundColor: "{colors.hover}"
    textColor: "{colors.bone}"
  input:
    textColor: "{colors.bone}"
    typography: "{typography.body}"
    rounded: "{rounded.md}"
    padding: "4px 10px"
    height: "32px"
  section-panel:
    backgroundColor: "{colors.panel}"
    textColor: "{colors.bone}"
    rounded: "{rounded.md}"
    padding: "12px"
  floating-layer:
    backgroundColor: "{colors.raised}"
    textColor: "{colors.bone}"
    rounded: "{rounded.md}"
    padding: "16px"
  stamp-confirmed:
    backgroundColor: "{colors.ok-subtle}"
    textColor: "{colors.ok}"
    typography: "{typography.stamp}"
    rounded: "{rounded.sm}"
    padding: "0 6px"
    height: "20px"
  stamp-pending:
    backgroundColor: "{colors.amber-subtle}"
    textColor: "{colors.amber}"
    typography: "{typography.stamp}"
    rounded: "{rounded.sm}"
    padding: "0 6px"
    height: "20px"
  stamp-failed:
    backgroundColor: "{colors.bad-subtle}"
    textColor: "{colors.bad}"
    typography: "{typography.stamp}"
    rounded: "{rounded.sm}"
    padding: "0 6px"
    height: "20px"
  stamp-info:
    backgroundColor: "{colors.info-subtle}"
    textColor: "{colors.info}"
    typography: "{typography.stamp}"
    rounded: "{rounded.sm}"
    padding: "0 6px"
    height: "20px"
  stamp-neutral:
    backgroundColor: "{colors.neutral-subtle}"
    textColor: "{colors.neutral}"
    typography: "{typography.stamp}"
    rounded: "{rounded.sm}"
    padding: "0 6px"
    height: "20px"
  checklist-line:
    textColor: "{colors.bone}"
    typography: "{typography.body}"
    padding: "4px 0"
    height: "32px"
  nav-item:
    backgroundColor: "{colors.rail}"
    textColor: "{colors.rail-text}"
    typography: "{typography.body}"
    padding: "0 16px"
    height: "40px"
  nav-item-active:
    backgroundColor: "{colors.rail-active}"
    textColor: "{colors.bone}"
  table-header:
    backgroundColor: "{colors.panel}"
    textColor: "{colors.text-2}"
    typography: "{typography.table}"
    padding: "0 12px"
    height: "32px"
---

# Design System: Ferry console

## Overview

**Creative North Star: "The Pre-Flight Checklist"**

The console reads like a kneeboard checklist in a dark cockpit. Every fact an operator or auditor needs is a line: the challenge on the left, a dotted leader, and a stamped response on the right that carries its evidence (a count, a hash, a signer, a version). Lines are read top to bottom, attention items first, and one click opens the record behind any response. The ground is a near-black blue; navigation sits in a committed deeper-blue rail; type is bone-white on hairline-bordered panels.

Density is operational, not airy: 13px UI, 12px tables, 32px rows and controls, a 4/8 spacing rhythm and 4px corners throughout. Depth comes from a lightness ladder of blue-greys, never from shadows on in-flow surfaces. Amber is the single attention voice; green, red and blue appear only where they carry state, and every state is a glyph plus a word, so nothing depends on colour alone.

The world refuses the category default of a row of same-size metric cards on a grey ground with one accent. Counts that matter appear once, in the lifecycle band or on a checklist line, not in a parallel tile row.

**Key Characteristics:**
- Challenge-and-response lines with dotted leaders and stamped responses are the identifying mark.
- One dark scene; no light theme exists.
- Amber means "a human is needed here" (or "this is where you are"); it is never decoration.
- Archivo for UI and prose-like meta; Azeret Mono for anything a machine wrote (hashes, ids, paths, model names, counts in readouts).
- Flat panels on a lightness ladder; shadow only on layers that float.
- Motion confirms state: the leader draws, the stamp lands, a digest scrambles in. One ambient moment in the shell: the lifecycle beam crossing the air gap.

## Colors

A near-black blue ground with a deeper-blue rail, bone type, one amber for attention and three state hues that only ever speak for state.

### Primary
- **Checklist Amber** (`amber`): the one attention colour. Pending and warning stamps, the primary action on the first pending checklist line, the active nav bar and icon, the selected table row's 1px inset edge, the inbox-waiting marker, the running-jobs link, the focus ring, the text caret and the Ferry mark. Hover and press step to `amber-hover` and `amber-press`; text on a filled amber surface is `on-amber`. `amber-subtle` is the stamp and callout well behind amber text. `selection` is a dimmed amber for text selection.

### Secondary
- **Pass Green** (`ok`, well `ok-subtle`): confirmed, verified, intact, healthy, and the reached segment of the lifecycle baseline.
- **Fail Red** (`bad`, well `bad-subtle`, `on-bad` for text on a solid fill): failed, denied, error, the first bad audit event, and the solid confirm button of a destructive dialog.
- **Info Blue** (`info`, well `info-subtle`): informational stamps and the first chart series.

### Neutral
- **Kneeboard Rail** (`rail`): the navigation rail and its footer gateway block. `rail-hover` and `rail-active` are the rail's own hover and current-page fills; `rail-text` and `rail-muted` are its type; `rail-border` its dividers. `rail-active` also colours scrollbar thumbs.
- **Enclave Ground** (`ground`): the page background and the sticky top bar.
- **Well** (`inset`): recessed wells: the top bar's command field and inline code.
- **Panel** (`panel`): every in-flow section surface, table headers, footers.
- **Raised** (`raised`): floating layers (dialogs, command palette, popovers, toasts).
- **Hover** (`hover`): row and link hover, muted fills.
- **Bone** (`bone`): primary text, the filled primary button.
- **Secondary Text** (`text-2`) and **Tertiary Text** (`text-3`): descriptions, table headers and values; captions, caps labels, timestamps and meta.
- **Hairline** (`hairline`): every panel ring, divider and table rule.
- **Leader** (`leader`): the dotted leaders and the connected-side lifecycle baseline.
- **Control Line** (`line-control`): input and select borders.
- **Retired Grey** (`neutral`, well `neutral-subtle`): revoked, retired, not-applicable items.
- **Scrim** (`scrim`): the overlay behind dialogs and sheets.

### Named Rules
**The One Voice Rule.** Amber is the only attention colour. If amber is on screen, a human is needed there, or it marks where the user is (focus, current page, selection). The primary action that is not pending is bone, not amber.

**The State Only Rule.** Green, red and blue appear only where they carry a state, and always beside a glyph and a word. A stamp that would read the same in greyscale is correct.

## Typography

**Display Font:** Archivo Variable (with system-ui, -apple-system, Segoe UI, sans-serif)
**Body Font:** Archivo Variable
**Label/Mono Font:** Azeret Mono (with ui-monospace, SFMono-Regular, Menlo, Consolas, monospace)

**Character:** Archivo is a sturdy grotesque with a width axis; widened (112%) it gives page titles and lifecycle stages a placard stance, and at regular width it carries UI and prose. Azeret Mono centres its punctuation in the cell, so versions, addresses, times and digests read as written. Tabular numerals are on by default for the whole document.

### Hierarchy
- **Display** (Azeret Mono 500, 40px rising to 48px at large widths, 56px line): the lifecycle band's stage counts only. Unreached stages print in tertiary grey.
- **Headline** (Archivo 600, 28px rising to 30px from small screens, 36px line, -0.01em, width 112%): the single h1 per page, focused after navigation.
- **Readout** (Azeret Mono 400, 20px; 28px for the large size): live figures with a 12px tertiary label above.
- **Title** (Archivo 600, 14px, 20px line): section panel titles.
- **Body** (Archivo 400, 13px, 20px line): the default UI size: checklist labels, buttons, inputs, nav. Prose descriptions under page titles run at 14px (`body-prose`) capped at 72ch.
- **Table** (Archivo 400, 12px, 16px line): table cells and headers, checklist response values, captions, panel descriptions.
- **Label caps** (Archivo 500, 11px, 0.14em tracking, uppercase): checklist section labels, lifecycle group captions ("Connected side", "This enclave"), the rail's Gateway block label. Each is the heading of the group it labels.
- **Stamp** (Archivo 500, 11px, 0.06em tracking, uppercase; 12px at the medium size): stamp words and small row tags ("New", "First bad", job kind).
- **Stage** (Archivo 600, 12px with 0.12em tracking below extra-large, 14px with 0.16em from extra-large, uppercase, width 112%): lifecycle stage names. The air-gap tag holds 11px at 0.16em.
- **Mono** (Azeret Mono 400/500, inherits size): hashes, digests, ids, key ids, paths, URLs, model names, commands, JSON, table counters.

### Named Rules
**The Machine Wrote It Rule.** If a machine produced the string (hash, id, path, URL, model name, command, JSON), it is set in Azeret Mono. If a person reads it as a sentence, time or summary, it is Archivo, even when it contains numbers.

**The Caps Are Headings Rule.** Wide-tracked caps label a checklist group, a stage or a stamp. They are the label of what follows, never a decorative line stacked above a page or panel title.

## Layout

A fixed app shell: a 232px rail on the left (off-canvas sheet below the large breakpoint), a sticky 48px top bar (page name left, Cmd-K command field centred at 30% width or 420px from extra-large, running-jobs link and user block right), and a main column capped at 1440px with 16px gutters, 24px from the large breakpoint, and 16 to 20px vertical padding. `scroll-padding-top` of 64px keeps focused content clear of the bar.

Pages stack full-width rows on a 16px gap. On the Overview, rows split two-thirds/one-third from the large breakpoint (readiness checklist beside the 24-hour gateway readouts) and halves from medium (paired panels). Readouts sit in a hairline-ruled grid (2 columns, 4 from small, 8 from 2xl) made by a 1px gap over a hairline background.

Rhythm is 4/8: panel headers are 8px by 12px, panel bodies 12px, table cells 12px horizontal at 32px height, checklist lines at least 32px. A checklist response wraps to its own right-aligned line only when it does not fit beside the label. Under 768px the lifecycle band becomes a vertical list with a dashed air-gap divider; from 768px to extra-large it tightens (smaller stage labels, a 208px air gap instead of 288px). Under 640px tables of four or more columns, or with row actions, stack each row into labelled lines in the page flow; from 640px a table that overflows scrolls sideways inside its panel with the actions column pinned right and a cue line beneath it. Dialogs cap at the viewport height less 32px and scroll only their body.

**The 32 Rule.** Rows, controls and header cells are 32px tall. Touch-coarse pointers enlarge shell icon buttons to 40 to 44px; nothing else grows.

## Elevation & Depth

Depth is tonal. Surfaces climb a lightness ladder: rail (darkest), inset well, ground, panel, raised, hover. In-flow panels carry a 1px hairline ring and no shadow. Floating layers (dialogs, the command palette, toasts) sit on raised with a single deep, soft shadow. The only other shadows are functional edges: a 1px inset amber line on the selected or decisive row, and a hairline plus a short ground-coloured shade on the pinned actions column while other columns scroll beneath it.

### Shadow Vocabulary
- **Float** (`box-shadow: 0 12px 32px -12px rgb(2 6 18 / 0.75)`): dialogs, alert dialogs, command palette, toasts. Nothing in-flow.
- **Selected edge** (`box-shadow: inset 1px 0 0 0 var(--amber)`): the selected table row and the decisive rule in a policy explanation.
- **Pinned edge** (`box-shadow: inset 1px 0 0 0 var(--hairline), -8px 0 8px -8px var(--ground)`): the pinned actions column, only while its table overflows sideways.

### Named Rules
**The Flat Panel Rule.** A surface in the page flow is flat: panel colour plus a hairline ring. Shadow means "this floats above the page" and nothing else.

## Shapes

Corners are tight and uniform: 4px on panels, buttons, inputs, dialogs and the palette; 3px on stamps, small links and focusable inline targets; 2px on inline code wells. Larger radius steps exist (6px, 8px) but the shipped surfaces stay at 4px. Borders are 1px hairlines; the leader is a 1.5px dotted rule; the air-gap tag is a 1px leader-coloured box. Status marks are 24-unit SVG rings with a 2px round-capped stroke that draws a check, cross, bar or dot; pending is a dashed ring. Lifecycle stages are circles on a 4px baseline with a visible break at the air gap.

**The Square Shoulder Rule.** Nothing in the console is pill-shaped or soft. If a corner exceeds 4px on an in-flow element, it is wrong.

## Components

### Buttons
Compact and literal: 32px tall, 4px corners, 13px medium label, 6px icon gap, 1px press nudge.
- **Primary:** filled bone with ground text; hover dims to 85%, press to 75%.
- **Attention:** filled amber with on-amber text, stepping to amber-hover and amber-press. Reserved for the primary action on a pending checklist line.
- **Danger:** solid fail red with on-bad text (about 7:1). Only the confirm button of a destructive dialog; never a tint.
- **Outline / Secondary / Ghost:** ground or raised fills with a hairline or control-line border; hover to the hover fill with bone text.
- **Focus:** the global 2px amber outline at 2px offset (4px on h1 and main). Disabled drops to 50% opacity.
- **Sizes:** 24px (xs), 28px (sm), 32px (default), 36px (lg); square icon variants at the same heights.

### Stamps (status badges)
The response half of every challenge. A 20px (or 24px) inline box: 3px corners, 1px border at 40% of the state hue, the state's subtle well, state-coloured caps word with a 12px status mark. Six states: confirmed (green), pending and warning (amber), failed (red), info (blue), neutral (grey). The word is always rendered; unknown values still print. When a stamp's state changes after mount it lands from 0.92 to 1 scale with an opacity rise in 180ms.

### Section panels
- **Corner Style:** 4px.
- **Background:** panel, with a 1px hairline ring; the ring turns amber at 50% when the section needs a human.
- **Header:** at least 40px, 8px by 12px padding, hairline bottom rule, 14px semibold title with an optional 12px secondary description, actions and an "Open ..." link (12px, arrow icon) on the right.
- **Body:** 12px padding, or flush for tables and lists. Optional footer in 12px tertiary on a hairline top rule.

### Inputs / Fields
- **Style:** 32px, 4px corners, 1px control-line border on a translucent control-line wash, 13px text, tertiary Archivo placeholder.
- **Focus:** border turns amber plus the global amber outline.
- **Error:** fail-red border with a 3px red ring at low alpha. **Disabled:** 50% opacity. Fields go read-only, not disabled, while a request runs.

### Navigation
The rail: 40px items with a 16px icon (1.75 stroke) and 13px label in rail-text, hover to rail-hover and bone. The current page fills rail-active, turns the label medium bone and the icon amber, and carries a 2px amber bar inset 8px from top and bottom on the left edge. The rail header holds the amber Ferry mark and name; the footer holds the Gateway block (serving stamp, backends healthy, server host in mono, local time). Below the large breakpoint the rail becomes an off-canvas sheet opened from the top bar.

### Data tables
12px text, 32px sticky panel-coloured header in medium secondary text with sortable headers as small hover targets, hairline row rules, hover fill, selected rows on the hover fill with the 1px amber inset edge. Rows reorder in place with a 200ms layout transition.
- **Row actions:** the actions column is sticky right from 640px at every width, so no row action is ever hidden or covered. It turns opaque (following the row's hover, selection and tone tint) and takes the pinned edge only while the table overflows; focus moving under the pin scrolls the table back to clear it.
- **Overflow cue:** a 11px secondary line below the table, outside the header, reads "More columns, scroll sideways" or "Earlier columns, scroll back" with a chevron. No fade covers cells.
- **Fewer columns first:** secondary facts fold under the cell they describe as a 12px tertiary note (type and size under a name, actor under a time) before a table is allowed to scroll.
- **Phones (under 640px):** tables of four or more columns or with actions stack: the first column is the row title (13px medium), every other value is a line with its 11px tertiary column name in a 104px label column, empty values take no line, actions get their own left-aligned line, and values the detail view carries can be dropped. Stacked tables join the page scroll; no nested scroller, pin or cue.
- **Machine ids in cells:** model, backend, app, bundle and source names are one nowrap mono run, middle-truncated with the full value in the title and the copied text; paths break only after "/"; a digest's "sha256:" prefix may wrap above its hash on phones.

### Dialogs
Raised surface, 4px corners, hairline ring and the float shadow. A three-row grid: a header with a 14px medium title and hairline rule, a body that scrolls and contains its overscroll, and a footer of right-aligned actions on a hairline rule. Capped at the viewport height less 32px so header and footer always stay on screen.

### Checklist line (signature component)
Item, dotted leader, response, stamp. The label (13px bone) is the line's link, stretched over the whole line so the evidence opens the record too; the leader is a 1.5px dotted rule in leader grey that fills the remaining width; the response is 12px secondary Archivo with digests and ids in their own mono; the stamp closes the line. A detail line (12px tertiary) can sit underneath; an action button can follow the stamp. Lines group under a caps section label with a right-aligned count and hairline dividers. When a line's state changes after mount, the leader draws left to right in 240ms ease-out and the stamp lands in 180ms; on mount and under reduced motion both appear static.

### Lifecycle band (signature component)
Full content width on the Overview. Two groups on one 4px baseline: the connected side (Packed, Signed) muted, then a break with the boxed "Air gap" tag and "reviewed transfer" caption (amber inbox marker when bundles wait), then this enclave (Verified, Imported, Serving) with display-size mono counts; captions cap at 176px. The reached part of the enclave baseline is green at 70%; stage circles fill green when reached. The beam crossing the gap is the shell's one ambient motion and is a still line under reduced motion.

### Readouts and share bar
Readouts: 12px tertiary label, 20px (or 28px) mono figure, optional hint; figures turn amber when they need attention and roll digits only after a user-caused change. The outcome share bar pairs each state colour with a legend swatch, and the denied segment is hatched so it reads without colour.

## Do's and Don'ts

### Do:
- **Do** express every status as a stamp: glyph, word and state hue together.
- **Do** put the page's primary action on the first pending checklist line, in the attention button.
- **Do** set hashes, ids, paths, model names, commands and JSON in Azeret Mono, and times, summaries and counts-in-sentences in Archivo with tabular numerals.
- **Do** keep in-flow surfaces flat (panel plus hairline ring) and reserve the float shadow for dialogs, the palette and toasts.
- **Do** keep state transitions at 125 to 250ms on the exponential ease-out (`cubic-bezier(0.23, 1, 0.32, 1)`), and let reduced motion keep short opacity and colour feedback while stopping transforms and loops.
- **Do** print revoked and retired items in neutral grey.

### Don't:
- **Don't** use amber for decoration, emphasis or a non-pending primary action; bone is the primary fill.
- **Don't** use green, red or blue as accents, chart decoration or brand colour.
- **Don't** add a row of same-size count tiles that repeats what the checklist or lifecycle band already confirms.
- **Don't** stack a caps label above a page or panel title as an eyebrow; caps are the group's own heading.
- **Don't** round in-flow elements past 4px or use pill shapes.
- **Don't** add a second ambient animation inside the shell; the lifecycle beam is the only one.
- **Don't** convey state by colour alone.
