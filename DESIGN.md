# Design System — Freenet Microblogging

## 1. Visual Theme & Atmosphere

A decentralized microblogging app that feels like X/Twitter in structure but carries Freenet's visual identity. The UI uses X's proven three-column layout (sidebar nav / main feed / contextual panel) with Freenet Blue (`#0066CC`) as the primary accent replacing X's brand blue.

The atmosphere is clean and functional — not flashy fintech like Stripe, not stark monochrome like X. It sits between: enough color to feel welcoming, enough restraint to feel trustworthy. The peer-to-peer nature of Freenet should feel transparent, not intimidating.

Light mode uses Freenet's `#F8FAFC` cool blue-gray canvas (not pure white) with white cards, giving subtle depth without heavy shadows. Dark mode uses `#121212` with `#1E1E1E` elevated surfaces — deep and restful, matching Freenet's existing dark theme.

The accent blue (`#0066CC`) drives all interactive elements: links, buttons, active states, compose actions. A secondary green (`#339966`) from Freenet's Ghost Keys branding appears sparingly for success/confirmation states.

Typography uses a system font stack — fast loading, native feel, zero FOIT/FOUT. Information density is moderate: not as packed as X's timeline, not as sparse as a marketing page.

**Key Characteristics:**
- System font stack — native feel, no custom font loading
- Freenet Blue (`#0066CC` light / `#4DA6FF` dark) as the sole interactive accent
- Flat cards with 1px border separators — minimal shadow use
- Three-column layout at desktop, collapsing to single column on mobile
- Both light and dark modes as first-class citizens
- Conservative border-radius: 0px on posts, 16px on cards, pill (20-28px) on buttons

## 2. Color Palette & Roles

### Light Mode

| Token | Hex | Role |
|-------|-----|------|
| `--bg-primary` | `#F8FAFC` | Page canvas |
| `--bg-elevated` | `#FFFFFF` | Cards, compose box, sidebar, post cards |
| `--bg-hover` | `#F0F4F8` | Hover state on rows/items |
| `--text-primary` | `#000000` | Headings, display names |
| `--text-secondary` | `#374151` | Post body text |
| `--text-muted` | `#64748B` | Timestamps, metadata, handles |
| `--accent` | `#0066CC` | Links, buttons, active tab, compose CTA |
| `--accent-hover` | `#004C99` | Button/link hover |
| `--accent-soft` | `rgba(0,102,204,0.10)` | Active nav background, like/repost hover |
| `--success` | `#339966` | Confirmation, repost active indicator |
| `--error` | `#DC2626` | Delete, error states |
| `--border` | `rgba(0,0,0,0.06)` | Card borders, post dividers |
| `--border-strong` | `#E5E7EB` | Section separators |

### Dark Mode

| Token | Hex | Role |
|-------|-----|------|
| `--bg-primary` | `#121212` | Page canvas |
| `--bg-elevated` | `#1E1E1E` | Cards, compose box, sidebar, post cards |
| `--bg-hover` | `#2A2A2A` | Hover state on rows/items |
| `--text-primary` | `#FFFFFF` | Headings, display names |
| `--text-secondary` | `#E0E0E0` | Post body text |
| `--text-muted` | `#94A3B8` | Timestamps, metadata, handles |
| `--accent` | `#4DA6FF` | Links, buttons, active tab (brighter for dark contrast) |
| `--accent-hover` | `#80BFFF` | Button/link hover |
| `--accent-soft` | `rgba(77,166,255,0.16)` | Active nav background, like/repost hover |
| `--success` | `#4DCC8F` | Confirmation, repost active indicator |
| `--error` | `#EF4444` | Delete, error states |
| `--border` | `rgba(255,255,255,0.08)` | Card borders, post dividers |
| `--border-strong` | `#2A2A2A` | Section separators |

### Accent Shift Rationale

The accent shifts from `#0066CC` → `#4DA6FF` in dark mode for WCAG AA contrast compliance on `#1E1E1E` surfaces. This matches how freenet.org handles the same transition.

## 3. Typography Rules

### Font Family
- **Primary:** `-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif`
- **Monospace:** `"SF Mono", "Fira Code", "Fira Mono", Menlo, monospace` (contract keys, hashes only)

### Hierarchy

| Role | Size | Weight | Line Height | Color | Usage |
|------|------|--------|-------------|-------|-------|
| Display Name | 15px | 700 | 1.25 | `--text-primary` | Post author, profile name |
| Handle | 15px | 400 | 1.25 | `--text-muted` | @handle, timestamps |
| Post Body | 15px | 400 | 1.40 | `--text-secondary` | Post content |
| Post Large | 23px | 700 | 1.30 | `--text-primary` | Detail view post (single post page) |
| Nav Item | 20px | 400 | 1.25 | `--text-primary` | Sidebar navigation labels |
| Nav Item Active | 20px | 700 | 1.25 | `--text-primary` | Active nav item |
| Section Header | 20px | 700 | 1.25 | `--text-primary` | "Home", "Trending on Freenet" |
| Meta / Stats | 13px | 400 | 1.25 | `--text-muted` | Like/repost counts, "Replying to" |
| Button | 15px | 700 | 1.00 | `#FFFFFF` | Compose CTA, action buttons |
| Button Small | 14px | 600 | 1.00 | varies | Follow, secondary actions |
| Tiny Label | 12px | 400 | 1.25 | `--text-muted` | Badge labels, contract key excerpts |

### Principles
- 15px as baseline (matches X) — readable on all densities
- Only two weights in practice: 400 (regular) and 700 (bold). 600 used sparingly for small buttons
- No letter-spacing adjustments — system fonts handle this natively
- Monospace only for Freenet-specific data (contract keys, hashes) — never for UI text

## 4. Component Stylings

### Buttons

**Primary CTA (Post)**
- Background: gradient `linear-gradient(135deg, #0066CC 0%, #004C99 100%)` (light) / `linear-gradient(135deg, #4DA6FF 0%, #0066CC 100%)` (dark)
- Text: `#FFFFFF` (light) / `#121212` (dark)
- Padding: 14px 20px
- Radius: 28px (pill)
- Font: 17px weight 700
- Full width in sidebar, inline in compose area

**Post Button (Inline)**
- Background: `--accent`
- Text: `#FFFFFF`
- Padding: 8px 20px
- Radius: 20px (pill)
- Font: 14px weight 700

**Follow**
- Background: `#000000` (light) / `#FFFFFF` (dark)
- Text: `#FFFFFF` (light) / `#121212` (dark)
- Padding: 6px 16px
- Radius: 20px (pill)
- Font: 14px weight 700

**Ghost / Icon Action**
- Background: transparent
- Icon/text: `--text-muted`
- Hover background: `--accent-soft` (circle, 34px)
- Hover icon: `--accent` (reply/share), `--success` (repost), `#DC2626` (like)

### Post Card
- Background: `--bg-elevated`
- Border: 1px bottom `--border` (separator between posts)
- Corner radius: 0px (flat, full-width)
- Padding: 12px 16px
- Layout: horizontal — 40px avatar circle + vertical body
- Body: name row (display name + handle + timestamp) → content → action bar
- Action bar: horizontal, `space-between`, icons at 18px with counts at 13px

### Compose Box
- Same structure as post card
- Input placeholder: "What's happening on Freenet?" at 18px, `--text-muted`
- Post button right-aligned below input
- Bottom border separator

### Navigation Item
- Layout: horizontal, 24px icon + 20px label, 12px padding all sides
- Radius: 28px (pill)
- Active: `--accent-soft` background, `--accent` icon and text, weight 700
- Inactive: transparent background, `--text-primary`, weight 400
- Hover: `--bg-hover` background

### Trending Card
- Background: `--bg-elevated`
- Border: 1px `--border`
- Radius: 16px, clip overflow
- Header: 20px/700 `--text-primary`, 14px 16px padding
- Items: vertical stack, each with category (13px muted), topic (15px/700), count (13px muted)
- Item padding: 10px 16px

### Who to Follow Card
- Same container styling as Trending Card
- Items: horizontal — 40px avatar + vertical info (name 15px/700 + handle 13px/400) + Follow button
- Item padding: 10px 16px, 10px gap

### Feed Tab Bar
- Horizontal, equal-width tabs
- Active: `--text-primary`, weight 700, 4px bottom bar in `--accent`, rounded 2px
- Inactive: `--text-muted`, weight 400, no underline
- Container: 1px bottom border `--border`
- Padding: 16px 0

### Search Box
- Background: `--bg-hover`
- Radius: 24px (pill)
- Padding: 10px 16px
- Icon: 18px search, `--text-muted`
- Placeholder: 15px/400, `--text-muted`
- Focus: 1px border `--accent`

### Avatar
- Shape: circle (ellipse)
- Sizes: 40px (post/compose), 48px (profile mention), 36px (logo area)
- Default: gradient fill using brand colors
- Compose avatar: gradient `#0066CC` → `#004C99`

## 5. Layout Principles

### Grid Structure
- **Sidebar:** 260px fixed width
- **Main Feed:** flexible, fills remaining space
- **Right Panel:** 320px fixed width
- **Sidebar-to-feed boundary:** 1px vertical border (not gap)
- **Feed-to-panel boundary:** 1px vertical border (not gap)

### Spacing System
- Base unit: 4px
- Scale: 4, 8, 10, 12, 16, 20, 24, 28, 32
- Post internal padding: 12px vertical, 16px horizontal
- Card padding: 14-16px header, 10-16px items
- Sidebar padding: 24px top, 16px sides
- Right panel padding: 16px top, 20px sides
- Navigation gap between items: 8px

### Feed Behavior
- Posts separated by 1px bottom borders (no vertical gaps)
- Compose box pinned above timeline
- Tab bar pinned above compose box
- Infinite scroll pattern for loading more posts

### Whitespace Philosophy
- **Dense feed, generous chrome:** Posts are compact and information-rich, but the sidebar and right panel breathe with generous padding. This creates a focused reading experience flanked by comfortable navigation.
- **No decorative spacing:** Every gap serves a structural purpose. Feed dividers are 1px borders, not 8px gaps.

### Border Radius Scale

| Size | Value | Use |
|------|-------|-----|
| None | 0px | Post cards (full-width, flat) |
| Small | 2px | Tab indicator bar |
| Card | 16px | Trending card, follow card |
| Pill | 20px | Follow button, post button, search |
| Pill Large | 28px | Sidebar nav items, compose CTA |
| Circle | 50% | Avatars |

## 6. Depth & Elevation

| Level | Treatment | Use |
|-------|-----------|-----|
| Flat (L0) | No shadow | Page canvas, post cards, feed area |
| Bordered (L1) | 1px border `--border` | Card containers, trending, who-to-follow |
| Subtle (L2) | `0 1px 2px rgba(0,0,0,0.06), 0 4px 14px rgba(0,0,0,0.05)` | Dropdowns, tooltips, compose modal |
| Elevated (L3) | `0 4px 12px rgba(0,0,0,0.12)` | Floating menus, notifications panel |
| Focus Ring | `0 0 0 2px var(--accent)` | Keyboard focus indicator |

### Dark Mode Shadows
- L2: `0 1px 2px rgba(0,0,0,0.4), 0 6px 20px rgba(0,0,0,0.4)`
- L3: `0 4px 12px rgba(0,0,0,0.5)`

### Philosophy
Minimal shadows. Borders handle most visual separation — matching X's flat-with-borders approach. Shadows reserved for floating/overlay elements only.

## 7. Do's and Don'ts

### Do
- Use `--accent` only for interactive elements: links, buttons, active states, tab indicators
- Use system font stack for all text — no custom fonts
- Keep posts as flat full-width cards separated by 1px borders
- Shift accent color between light/dark modes for WCAG contrast
- Use `--text-muted` for all secondary information (handles, timestamps, counts)
- Invert Follow button colors between modes (black→white)
- Use pill shapes (20-28px radius) for all buttons
- Keep action icons at 18px with 13px counts

### Don't
- Don't use Freenet Green (`#339966`) for buttons or links — reserve for success states only
- Don't add shadows to post cards — they should be flat with border separators
- Don't use rounded corners on post cards — they are full-width and edge-to-edge
- Don't use pure black (`#000000`) for body text in dark mode — use `#FFFFFF` for headings, `#E0E0E0` for body
- Don't mix density: keep feed compact, keep chrome generous
- Don't use `--accent` for decorative purposes — it signals interactivity
- Don't add borders between action icons in the post action bar
- Don't use more than two font weights (400 and 700) in the primary font

## 8. Responsive Behavior

### Breakpoints

| Name | Width | Layout Changes |
|------|-------|----------------|
| Mobile | <768px | Single column feed. Bottom tab bar (Home, Search, Notifications, Profile). Right panel hidden. Compose as floating action button (FAB). |
| Tablet | 768–1024px | Two columns: icon-only sidebar (68px) + feed. Right panel hidden. Compose in feed. |
| Desktop | 1024–1280px | Three columns with narrower right panel (280px). Full sidebar. |
| Large Desktop | >1280px | Three columns at designed proportions (260 / flex / 320). Centered with max-width 1280px. |

### Touch Targets
- All interactive elements: minimum 44px touch target
- Post action icons: 18px visual, 40px hit area on mobile
- Navigation items: full-width touch target
- Bottom tab bar items: equal-width, 48px tall minimum

### Collapsing Strategy
- **Sidebar:** Full labels → icon-only (68px) → bottom tab bar
- **Right panel:** Full → hidden (content accessible via Explore tab)
- **Post cards:** No change — full-width at all sizes
- **Compose:** In-feed → floating action button (FAB) on mobile
- **Trending/Follow cards:** Visible → moved to Explore screen on mobile
- **Typography:** No size reduction — 15px body remains readable at all breakpoints

### Mobile-Specific
- Bottom tab bar: 4 icons (Home, Search, Bell, User), active state uses `--accent`
- Floating compose button: 56px circle, bottom-right, `--accent` background, white plus icon
- Pull-to-refresh on timeline
- Swipe gestures: none (avoid accidental navigation)

## 9. Agent Prompt Guide

### Quick Color Reference

| Role | Light | Dark |
|------|-------|------|
| CTA / Accent | `#0066CC` | `#4DA6FF` |
| CTA Hover | `#004C99` | `#80BFFF` |
| Page Background | `#F8FAFC` | `#121212` |
| Card / Surface | `#FFFFFF` | `#1E1E1E` |
| Hover Background | `#F0F4F8` | `#2A2A2A` |
| Heading Text | `#000000` | `#FFFFFF` |
| Body Text | `#374151` | `#E0E0E0` |
| Muted Text | `#64748B` | `#94A3B8` |
| Border | `rgba(0,0,0,0.06)` | `rgba(255,255,255,0.08)` |
| Success | `#339966` | `#4DCC8F` |
| Error | `#DC2626` | `#EF4444` |
| Accent Soft BG | `rgba(0,102,204,0.10)` | `rgba(77,166,255,0.16)` |

### Example Component Prompts

- "Create a post card: full-width, white background (#FFFFFF), 1px bottom border rgba(0,0,0,0.06). Horizontal layout: 40px green circle avatar, then vertical body. Name row: 'Ian Clarke' 15px/700 black + '@sanity · 2h' 15px/400 #64748B. Body: 15px/400 #374151, line-height 1.4. Action bar: space-between, icons at 18px #64748B with 13px counts."

- "Create sidebar navigation: vertical, 260px wide, white background, 24px top padding 16px side padding. Logo row: 36px blue gradient circle + 'freenet' 22px/700. Nav items: 24px icon + 20px label, pill shape 28px radius, 12px padding. Active item: rgba(0,102,204,0.10) background, #0066CC icon and text. Post button: full-width pill, gradient #0066CC→#004C99, white text 17px/700."

- "Create trending card: #FFFFFF background, 16px radius, 1px border rgba(0,0,0,0.06). Header: 'Trending on Freenet' 20px/700. Items: category 13px #64748B, topic 15px/700 black, count 13px #64748B. Padding 10px 16px per item."

- "Dark mode post: #1E1E1E background, 1px bottom border rgba(255,255,255,0.08). Name: 15px/700 #FFFFFF. Handle: 15px/400 #94A3B8. Body: 15px/400 #E0E0E0. Action icons: 18px #94A3B8."

### Iteration Guide

1. **Always specify mode** — light and dark use different accent, text, and surface colors
2. **Accent is interactive only** — if it's not clickable, don't make it `--accent`
3. **Two font weights** — 400 for body/labels, 700 for names/headings/buttons
4. **Border, not shadow** — use 1px `--border` for separation, shadows only for floating elements
5. **Pill buttons** — all buttons use pill radius (20-28px), never square or slightly rounded
6. **Post cards are flat** — 0px radius, full-width, 1px bottom border only
7. **Follow button inverts** — black on light, white on dark
8. **Muted text for metadata** — timestamps, handles, counts always use `--text-muted`
9. **Success green is rare** — only for confirmed actions (repost done, publish success)
10. **System fonts only** — no Google Fonts, no custom typefaces, no font-feature-settings
