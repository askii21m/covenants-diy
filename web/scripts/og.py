"""Redraw the opcode line on the preview image from the boot shell's list.

The list of opcodes is written out by hand in the readme, the boot shell
and this image. The first two are held to the ruleset switches by a test;
this image is pixels, so nothing can read it back. Instead the line it was
drawn with is stamped into the file, and the test compares that.

Everything above the line is left alone: the band under it is lifted from
64px lower, which is four grid squares, so the grid comes back in phase.

    python3 scripts/og.py        from web/, after changing the switches
"""

import pathlib
import re
import tempfile

from PIL import Image, ImageDraw, ImageFont, PngImagePlugin
from fontTools.ttLib import TTFont

WEB = pathlib.Path(__file__).resolve().parent.parent
OG = WEB / "public" / "og.png"
# Where the line sits, and how much room it may take before it crowds the edge.
LEFT, BASELINE, BAND_TOP, BAND_H, GRID = 98, 436, 414, 30, 64
MAX_WIDTH = 1200 - LEFT - 100
COLOUR = (0, 102, 92)


def ops_line() -> str:
    html = (WEB / "index.html").read_text()
    m = re.search(r'<p class="ops">([^<]+)</p>', html)
    if not m:
        raise SystemExit("index.html has no opcode line to draw")
    return " ".join(m.group(1).split())


def mono(tmp: pathlib.Path) -> pathlib.Path:
    """The site's own font, which ships compressed for the browser."""
    ttf = tmp / "mono.ttf"
    f = TTFont(WEB / "public" / "fonts" / "jetbrains-mono-latin.woff2")
    f.flavor = None
    f.save(ttf)
    return ttf


def main() -> None:
    line = ops_line()
    im = Image.open(OG).convert("RGB")
    with tempfile.TemporaryDirectory() as td:
        path = str(mono(pathlib.Path(td)))
        size = 21
        while size > 10:
            font = ImageFont.truetype(path, size)
            box = font.getbbox(line)
            if box[2] - box[0] <= MAX_WIDTH:
                break
            size -= 1
        im.paste(im.crop((0, BAND_TOP + GRID, im.width, BAND_TOP + GRID + BAND_H)), (0, BAND_TOP))
        ImageDraw.Draw(im).text((LEFT, BASELINE), line, font=font, fill=COLOUR, anchor="ls")
    meta = PngImagePlugin.PngInfo()
    meta.add_text("opcodes", line)
    im.save(OG, pnginfo=meta)
    print(f"og.png: {line} ({size}px)")


if __name__ == "__main__":
    main()
