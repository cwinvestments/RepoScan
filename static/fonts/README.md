# Fonts

Bundled font files belong here. The CSS references
`fonts/JetBrainsMono-Regular.woff2` and `fonts/JetBrainsMono-Bold.woff2`.

**No font files are bundled with this repo.** The JetBrains Mono license
(Apache-2.0) is compatible with redistribution, but to keep the repo
dependency-light and avoid committing binary assets we fall back to the
system monospace stack defined in `static/style.css`:

```
"JetBrains Mono", "Fira Code", ui-monospace, SFMono-Regular,
Menlo, Consolas, "Liberation Mono", monospace
```

If you want the designed look, drop the `.woff2` files in this directory
and the browser will pick them up automatically via `@font-face`. Source:
<https://www.jetbrains.com/lp/mono/>.
