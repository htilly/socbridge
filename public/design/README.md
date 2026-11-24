# SocBridge design system

Everything visual in the web UI comes from this directory. The page inlines
`tokens.css`, `fonts.css` and `components.css` (in that order) under a nonce
CSP; `logo.svg`, `favicon.svg` and `fonts/` are served from `/design/`.

## The mark

An aperture: four blades around a square opening. One blade per backend; the
opening is the only way in. It is a single path rotated 0/90/180/270 degrees:

```
M -R -R  L R -R  L R -a  L -a -a  Z        R = 44, a = 13 (open)
```

Blades at 0° and 180° use `--brass`, at 90° and 270° `--brass-d`. The mark is
also a state indicator: the opening closes (`a` → `--aperture-closed`) while
signed out and opens to `--aperture-open` when a session is live. The UI
animates `a` over `--motion-aperture` and jumps straight to the end state
under `prefers-reduced-motion`. `logo.svg` and `favicon.svg` are the static
open state; a unit test keeps their geometry in sync with `tokens.css`.

## Colour

| Token | Use |
|---|---|
| `--ink` | base, panels |
| `--slate` | raised surfaces |
| `--steel` | hairlines; secondary text (lifted toward `--haze` for contrast) |
| `--brass` | identity, focus rings, primary actions |
| `--brass-d` | darker blades, hover |
| `--haze` | text on dark |
| `--paper` | light mode base |

Severity has its own scale (`--sev-{critical,high,medium,low,info}-{bg,fg}`).
**`--brass` is never used for severity.** It is reserved for identity, focus
and primary actions; if the brand colour also meant "medium", brand and
warning would become indistinguishable. UI errors reuse the critical pair.

Component styles reference tokens only. No raw colour values outside
`tokens.css` (and the two SVG files, which cannot read CSS variables).

## Type

- **Instrument Sans** for interface and headings.
- **Martian Mono** for data only: CVE IDs, hashes, agent IDs, fingerprints,
  token hints, versions. Use the `.data` class. Not for labels or decoration.

Both are self-hosted (SIL OFL 1.1, licences in `fonts/`) so the UI works on a
network without internet access. Update them with `npm run fonts:update`.

## Attack map

The *Pew pew map* is the one deliberately retro surface: an amber CRT with its
own `--crt-*` tokens, the same in both themes. Do not use them elsewhere.
`world.json` holds country outlines from Natural Earth 1:110m (public domain)
as flat lon,lat lists, grouped per country.

## Avoid

No shields, padlocks, matrix green, glitch effects or hex patterns.
