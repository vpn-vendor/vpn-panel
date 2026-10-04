#!/usr/bin/env python3
"""Собирает значки проекта из знака и токенов тёмной темы.

    gen-icons.py

Знак — матрица mark.txt. Значок программы и вкладки — «окно»: рамка и полоса
заголовка вокруг знака, цвета тёмной темы (один файл узнаваем на любом фоне).
Знак в шапке — клетки матрицы цветом текущего текста: цвет задаёт стиль шапки.
Выходы и входы записываются в отпечаток; страж сверяет его при каждом гейте.
"""
import os
import re
import subprocess
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
APP_ICON = os.path.join(ROOT, "debian", "assets", "vpn-panel.svg")
MARK_TMPL = os.path.join(ROOT, "resources", "views", "components", "brand-mark.tmpl")
FAVICON_TMPL = os.path.join(ROOT, "resources", "views", "components", "brand-favicon.tmpl")
STAMP = os.path.join(ROOT, "debian", "assets", "icons.sha256")
# Окно: рамка в одну клетку, полоса заголовка в три, знак с полями по бокам
# в две клетки и сверху в три; окно квадратное — значки в системе квадратные.
FRAME, TITLE, PAD_X, PAD_TOP = 1, 3, 2, 3
# Размер значка программы в пикселях — опорный размер вектора для растровых копий.
APP_PX = 128


def mark_rows():
    rows = [r for r in open(os.path.join(HERE, "mark.txt"), encoding="utf-8").read().split("\n") if r]
    if len({len(r) for r in rows}) != 1 or set("".join(rows)) - {"#", "."}:
        raise SystemExit("mark.txt: строки одной длины из «#» и «.»")
    return rows


def dark_tokens():
    css = open(os.path.join(ROOT, "public", "css", "app.css"), encoding="utf-8").read()
    block = re.search(r':root\[data-theme="dark"\]\s*\{(.*?)\n\}', css, re.S)
    if not block:
        raise SystemExit("в app.css нет блока тёмной темы")
    return dict(re.findall(r"(--[a-z0-9-]+):\s*(#[0-9a-fA-F]{6})", block.group(1)))


def runs(rows, ox=0, oy=0):
    """Подряд идущие клетки строки — один прямоугольник."""
    out = []
    for y, row in enumerate(rows):
        x = 0
        while x < len(row):
            if row[x] == "#":
                start = x
                while x < len(row) and row[x] == "#":
                    x += 1
                out.append((ox + start, oy + y, x - start))
            else:
                x += 1
    return out


def rects(items, attr):
    return "".join(f'<rect x="{x}" y="{y}" width="{w}" height="1"{attr}/>' for x, y, w in items)


def window_svg(rows, tok, px):
    cols, height = len(rows[0]), len(rows)
    n = cols + 2 * (FRAME + PAD_X)
    if n - TITLE - FRAME < PAD_TOP + height:
        raise SystemExit("знак не помещается в окно")
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{px}" height="{px}" viewBox="0 0 {n} {n}" '
            f'shape-rendering="crispEdges">'
            f'<rect width="{n}" height="{n}" fill="{tok["--accent-line"]}"/>'
            f'<rect x="{FRAME}" y="{TITLE}" width="{n - 2 * FRAME}" height="{n - TITLE - FRAME}" fill="{tok["--surface"]}"/>'
            + rects(runs(rows, FRAME + PAD_X, TITLE + PAD_TOP), f' fill="{tok["--accent"]}"') + "</svg>")


def build():
    rows, tok = mark_rows(), dark_tokens()
    app = window_svg(rows, tok, APP_PX) + "\n"
    mark = ('{{ define "components/brand-mark" }}'
            f'<svg class="brand-mark" viewBox="0 0 {len(rows[0])} {len(rows)}" aria-hidden="true" focusable="false" '
            'xmlns="http://www.w3.org/2000/svg" shape-rendering="crispEdges">'
            + rects(runs(rows), ' fill="currentColor"') + "</svg>{{ end }}\n")
    favicon = ('{{ define "components/brand-favicon" }}<link rel="icon" href="data:image/svg+xml,'
               + urllib.parse.quote(window_svg(rows, tok, APP_PX), safe="") + '">{{ end }}\n')
    return {APP_ICON: app, MARK_TMPL: mark, FAVICON_TMPL: favicon}


def main():
    for path, text in build().items():
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
    stamp = subprocess.run(["bash", os.path.join(ROOT, "scripts", "check-brand.sh"), "--print-icons"],
                           capture_output=True, text=True, check=True).stdout
    with open(STAMP, "w", encoding="utf-8") as f:
        f.write(stamp)


if __name__ == "__main__":
    main()
