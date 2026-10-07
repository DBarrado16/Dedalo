"""Verificación por tema de los colores usados por Dedalo, sin dependencias."""
import json
from pathlib import Path
import re

root = Path(__file__).resolve().parent.parent
css = (root / "dedalo/static/style.css").read_text(encoding="utf-8-sig")

def luminance(color):
    values = [int(color[i:i + 2], 16) / 255 for i in (1, 3, 5)]
    values = [v / 12.92 if v <= .04045 else ((v + .055) / 1.055) ** 2.4 for v in values]
    return sum(v * weight for v, weight in zip(values, (.2126, .7152, .0722)))

results = []
for theme, selector in (("light", r":root\s*"), ("dark", r':root\[data-theme="dark"\]\s*')):
    block = re.search(selector + r"\{([^}]+)\}", css)[1]
    colors = dict(re.findall(r"--([\w-]+):\s*(#[\da-f]{6});", block))
    pairs = [(fg, bg) for fg in ("ink", "muted", "good", "warning", "bad", "action", "link")
             for bg in ("ground", "surface", "inset", "selection")]
    pairs += [("action-ink", "action"), ("action-ink", "action-hover")]
    for fg, bg in pairs:
        a, b = sorted((luminance(colors[fg]), luminance(colors[bg])))
        ratio = (b + .05) / (a + .05)
        minimum = 3 if fg == "action" else 4.5  # action: iconos/foco; link: texto
        results.append(dict(theme=theme, foreground=fg, background=bg,
                            ratio=round(ratio, 2), minimum=minimum, aa=ratio >= minimum))
(root / "design/contrast.json").write_text(json.dumps(results, indent=2) + "\n")
failed = [r for r in results if not r["aa"]]
print(json.dumps({"pairs": len(results), "failed": failed}, indent=2))
raise SystemExit(bool(failed))
