"""Generate the ComputerCheck app icon source (1024x1024 PNG).

On-brand: ARGUS dark tile, C-LAB cyan mark = a monitor (computer) with a check
(the '*-check' family motif). Rendered at 4x and downscaled for clean edges.
Run: python3 scripts/make-icon.py  ->  build/icon-source.png
Then: npx tauri icon build/icon-source.png
"""
from PIL import Image, ImageDraw, ImageFilter
from pathlib import Path

S = 4096            # supersample canvas
OUT = 1024
CYAN = (91, 227, 195, 255)     # ARGUS C-LAB cyan in sRGB (#5be3c3)
BG_TOP = (16, 22, 27, 255)     # #10161b
BG_BOT = (8, 11, 14, 255)      # #080b0e

img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
d = ImageDraw.Draw(img)

def sc(v):  # scale a 1024-space value to the supersample canvas
    return int(v * S / 1024)

# --- rounded tile with vertical gradient -----------------------------------
margin = sc(76)
radius = sc(228)
tile = Image.new("RGBA", (S, S), (0, 0, 0, 0))
grad = Image.new("RGBA", (1, S), (0, 0, 0, 0))
for y in range(S):
    t = y / S
    grad.putpixel((0, y), tuple(int(BG_TOP[i] + (BG_BOT[i] - BG_TOP[i]) * t) for i in range(4)))
grad = grad.resize((S, S))
mask = Image.new("L", (S, S), 0)
ImageDraw.Draw(mask).rounded_rectangle([margin, margin, S - margin, S - margin], radius=radius, fill=255)
tile.paste(grad, (0, 0), mask)
# subtle cyan hairline border
ImageDraw.Draw(tile).rounded_rectangle(
    [margin, margin, S - margin, S - margin], radius=radius, outline=(91, 227, 195, 60), width=sc(3)
)
img = Image.alpha_composite(img, tile)
d = ImageDraw.Draw(img)

# --- the mark: monitor + stand + check -------------------------------------
mark = Image.new("RGBA", (S, S), (0, 0, 0, 0))
m = ImageDraw.Draw(mark)
stroke = sc(46)

# monitor screen (rounded-rect outline)
sx0, sy0, sx1, sy1 = sc(300), sc(286), sc(724), sc(606)
m.rounded_rectangle([sx0, sy0, sx1, sy1], radius=sc(40), outline=CYAN, width=stroke)

# stand: neck + base
neck_w = sc(40)
m.rounded_rectangle([sc(512) - neck_w // 2, sc(606), sc(512) + neck_w // 2, sc(680)], radius=sc(8), fill=CYAN)
base_w = sc(170)
m.rounded_rectangle([sc(512) - base_w, sc(672), sc(512) + base_w, sc(672) + sc(36)], radius=sc(18), fill=CYAN)

# check mark inside the screen, with round caps/joints
cw = sc(56)
pts = [(sc(392), sc(452)), (sc(470), sc(524)), (sc(636), sc(384))]
m.line(pts, fill=CYAN, width=cw, joint="curve")
for (px, py) in [pts[0], pts[2]]:
    r = cw // 2
    m.ellipse([px - r, py - r, px + r, py + r], fill=CYAN)

# soft glow under the mark
glow = mark.filter(ImageFilter.GaussianBlur(sc(14)))
img = Image.alpha_composite(img, glow)
img = Image.alpha_composite(img, mark)

# --- downscale + save -------------------------------------------------------
out = img.resize((OUT, OUT), Image.LANCZOS)
build = Path(__file__).resolve().parent.parent / "build"
build.mkdir(exist_ok=True)
dest = build / "icon-source.png"
out.save(dest)
print("wrote", dest)
