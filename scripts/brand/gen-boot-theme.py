#!/usr/bin/env python3
"""Собирает тему экрана запроса пароля из знака, токенов тёмной темы и
кодов подсказок агента. Готовые файлы лежат в пакете; после правки любого
входа тему пересобирают этим сценарием, а страж сверяет отпечаток входов.

    gen-boot-theme.py [каталог]     по умолчанию — каталог темы в пакете

Тексты отрисовываются картинками трёх размеров с переносом по ширине: экран
не зависит от шрифтов initramfs. Выход: vpn-panel.plymouth, vpn-panel.script,
PNG и отпечаток входов.
"""
import os
import re
import subprocess
import sys

from PIL import Image, ImageDraw, ImageFont

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
OUT_DEFAULT = os.path.join(ROOT, "debian", "assets", "boot-theme")
FONT = os.environ.get("THEME_FONT", "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf")
NAME = "vpn-panel"
THEME_DIR = f"/usr/share/plymouth/themes/{NAME}"
# Шкала текстов по размеру экрана (s, m, l) — высота строки в пикселях.
TEXT_PX = {"s": 16, "m": 22, "l": 30}
# Ширина строки — самый узкий экран своей ступени (640, 800, 1440) без полей;
# длиннее — перенос по словам.
TEXT_WIDTH = {"s": 600, "m": 760, "l": 1300}
TEXTS_TSV = os.path.join(ROOT, "internal", "diskcrypt", "texts.tsv")
# Подписи над полем и строка о клавиатуре — свои места в сценарии; остальное
# — сообщения под полем.
FIXED = {"vp:unlock", "vp:new", "vp:repeat", "vp:current", "vp:caps", "vp:layout"}
# Цвет по роли кода; не названные — ошибки.
COLOR = {"vp:unlock": "--text-muted", "vp:new": "--text-muted", "vp:repeat": "--text-muted", "vp:current": "--text-muted",
         "vp:caps": "--warn", "vp:layout": "--accent-line", "vp:intro": "--text", "vp:done": "--ok",
         "vp:change-intro": "--text", "vp:changed": "--ok", "vp:kept": "--text-muted"}


def texts():
    out = {}
    for line in open(TEXTS_TSV, encoding="utf-8"):
        code, sep, text = line.rstrip("\n").partition("\t")
        if sep:
            out[code] = text
    return out


def wrap(text, font, width):
    lines, cur = [], ""
    for word in text.split(" "):
        cand = (cur + " " + word).strip()
        if cur and font.getlength(cand) > width:
            lines.append(cur)
            cur = word
        else:
            cur = cand
    return lines + [cur]


def dark_tokens():
    css = open(os.path.join(ROOT, "public", "css", "app.css"), encoding="utf-8").read()
    block = re.search(r':root\[data-theme="dark"\]\s*\{(.*?)\n\}', css, re.S)
    if not block:
        sys.exit("в app.css нет блока тёмной темы")
    return dict(re.findall(r"(--[a-z0-9-]+):\s*(#[0-9a-fA-F]{6})", block.group(1)))


def rgb(hexv):
    return tuple(int(hexv[i:i + 2], 16) for i in (1, 3, 5))


def main(out):
    tok = dark_tokens()
    os.makedirs(out, exist_ok=True)
    rows = [r for r in open(os.path.join(HERE, "mark.txt"), encoding="utf-8").read().split("\n") if r]
    if len({len(r) for r in rows}) != 1 or set("".join(rows)) - {"#", "."}:
        sys.exit("mark.txt: строки одной длины из «#» и «.»")

    for name, token in (("px-mark", "--accent"), ("px-field", "--surface-3"),
                        ("px-line", "--accent-line"), ("px-text", "--text")):
        Image.new("RGBA", (1, 1), rgb(tok[token]) + (255,)).save(os.path.join(out, name + ".png"))

    all_texts = texts()
    for size, px in TEXT_PX.items():
        font = ImageFont.truetype(FONT, px)
        line_h = px + px // 2
        for code, text in all_texts.items():
            lines = wrap(text, font, TEXT_WIDTH[size])
            w = max(int(font.getlength(ln)) for ln in lines) + 2
            im = Image.new("RGBA", (w, line_h * len(lines)), (0, 0, 0, 0))
            d = ImageDraw.Draw(im)
            fill = rgb(tok[COLOR.get(code, "--danger")]) + (255,)
            for i, ln in enumerate(lines):
                x = (w - int(font.getlength(ln))) // 2
                d.text((x, i * line_h + (line_h - px) // 2), ln, font=font, fill=fill)
            im.save(os.path.join(out, f"text-{code.removeprefix('vp:')}-{size}.png"))
        r = max(3, px // 4)
        # Точка рисуется вчетверо крупнее и уменьшается — гладкий край.
        big = Image.new("RGBA", (r * 8, r * 8), (0, 0, 0, 0))
        ImageDraw.Draw(big).ellipse([0, 0, r * 8 - 1, r * 8 - 1], fill=rgb(tok["--text"]) + (255,))
        big.resize((r * 2, r * 2), Image.LANCZOS).save(os.path.join(out, f"dot-{size}.png"))

    def color(hexv):
        return ", ".join(f"{c / 255:.3f}" for c in rgb(hexv))

    mark = "\n".join(f'mark[{i}] = "{r}";' for i, r in enumerate(rows))
    mark += f"\nMARK_ROWS = {len(rows)};\nMARK_COLS = {len(rows[0])};"
    script = open(os.path.join(HERE, "boot-theme.script.in"), encoding="utf-8").read()
    msgs = [c for c in all_texts if c not in FIXED]
    messages = "\n".join(f'msg_code[{i}] = "{c}";\nmsg_file[{i}] = "text-{c.removeprefix("vp:")}";'
                         for i, c in enumerate(msgs))
    messages += f"\nMSG_COUNT = {len(msgs)};"
    script = script.replace("@BG@", color(tok["--bg"])).replace("@MARK_ROWS@", mark)
    script = script.replace("@MESSAGES@", messages)
    open(os.path.join(out, NAME + ".script"), "w", encoding="utf-8").write(script)
    open(os.path.join(out, NAME + ".plymouth"), "w", encoding="utf-8").write(
        f"[Plymouth Theme]\nName={NAME}\nDescription=Экран запроса пароля\nModuleName=script\n\n"
        f"[script]\nImageDir={THEME_DIR}\nScriptFile={THEME_DIR}/{NAME}.script\n")
    # Отпечаток входов считает страж — одна процедура на сборку и проверку.
    stamp = subprocess.run(["bash", os.path.join(ROOT, "scripts", "check-brand.sh"), "--print"],
                           capture_output=True, text=True, check=True).stdout
    open(os.path.join(out, "inputs.sha256"), "w", encoding="utf-8").write(stamp)


if __name__ == "__main__":
    if len(sys.argv) > 2:
        sys.exit(__doc__)
    main(sys.argv[1] if len(sys.argv) == 2 else OUT_DEFAULT)
