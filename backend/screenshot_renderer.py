"""
Render terminal output as a professional annotated screenshot
with severity-colored boxes around important findings.
"""
from PIL import Image, ImageDraw, ImageFont
from pathlib import Path
from datetime import datetime, timezone
import re


SEVERITY_RULES = [
    ("CRITICAL", (255, 45, 45), [
        r"\bopen\b", r"\bvulnerable\b", r"VULNERABLE", r"\bCVE-\d{4}-\d+\b",
        r"\[\s*CRITICAL\s*\]", r"CRITICAL", r"\bexploitable\b",
        r"remote code execution", r"\bRCE\b", r"authentication bypass",
    ]),
    ("HIGH", (255, 140, 0), [
        r"\[\s*HIGH\s*\]", r"\bHIGH\b", r"\bsuspicious\b", r"\bmalware\b", r"\bbackdoor\b",
    ]),
    ("MEDIUM", (255, 210, 30), [
        r"\[\s*MEDIUM\s*\]", r"\bMEDIUM\b", r"\bunknown\b",
        r"\bpotential\b", r"\bwarning\b", r"\bfiltered\b",
    ]),
    ("LOW", (80, 200, 120), [
        r"\[\s*LOW\s*\]", r"\bLOW\b", r"\binfo\b", r"\bclosed\b", r"\bignored\b",
    ]),
]


def classify_line(line: str):
    if not line.strip():
        return (None, None)
    for name, color, patterns in SEVERITY_RULES:
        for p in patterns:
            if re.search(p, line, re.IGNORECASE):
                return (name, color)
    return (None, None)


def render_terminal_screenshot(command: str, output: str, output_path: Path, target: str = "local") -> Path:
    lines = output.split("\n")
    if len(lines) > 100:
        lines = lines[:100] + [f"... ({len(lines) - 100} more lines truncated)"]

    display_lines = [f"guardian@zangbeto:~$ {command}", ""] + lines

    LINE_HEIGHT = 22
    HEADER_HEIGHT = 70
    LEGEND_HEIGHT = 45
    PADDING_LEFT = 20
    PADDING_RIGHT = 20
    IMG_WIDTH = 1200
    IMG_HEIGHT = HEADER_HEIGHT + (len(display_lines) * LINE_HEIGHT) + LEGEND_HEIGHT + 40

    img = Image.new("RGB", (IMG_WIDTH, IMG_HEIGHT), color=(12, 14, 18))
    draw = ImageDraw.Draw(img)

    try:
        font = ImageFont.truetype("consola.ttf", 14)
        font_bold = ImageFont.truetype("consolab.ttf", 14)
        header_font = ImageFont.truetype("consolab.ttf", 15)
        small_font = ImageFont.truetype("consola.ttf", 11)
        legend_font = ImageFont.truetype("consolab.ttf", 12)
    except OSError:
        try:
            font = ImageFont.truetype("DejaVuSansMono.ttf", 14)
            font_bold = ImageFont.truetype("DejaVuSansMono-Bold.ttf", 14)
            header_font = ImageFont.truetype("DejaVuSansMono-Bold.ttf", 15)
            small_font = ImageFont.truetype("DejaVuSansMono.ttf", 11)
            legend_font = ImageFont.truetype("DejaVuSansMono-Bold.ttf", 12)
        except OSError:
            font = font_bold = header_font = small_font = legend_font = ImageFont.load_default()

    # HEADER
    draw.rectangle([(0, 0), (IMG_WIDTH, HEADER_HEIGHT - 10)], fill=(22, 26, 34))
    draw.ellipse([(22, 22), (38, 38)], fill=(255, 95, 87))
    draw.ellipse([(48, 22), (64, 38)], fill=(255, 189, 46))
    draw.ellipse([(74, 22), (90, 38)], fill=(39, 201, 63))
    draw.text((110, 20), "ZANGBETO SANDBOX TERMINAL  -  KALI LINUX", fill=(0, 240, 130), font=header_font)

    target_badge = f"TARGET: {target.upper()}"
    bbox = draw.textbbox((0, 0), target_badge, font=small_font)
    badge_x = IMG_WIDTH - (bbox[2] - bbox[0]) - 30
    draw.rectangle([(badge_x - 8, 20), (IMG_WIDTH - 22, 40)], fill=(30, 60, 40), outline=(0, 200, 100))
    draw.text((badge_x, 22), target_badge, fill=(0, 240, 130), font=small_font)
    draw.rectangle([(0, HEADER_HEIGHT - 10), (IMG_WIDTH, HEADER_HEIGHT - 8)], fill=(0, 200, 100))

    # BODY
    y = HEADER_HEIGHT + 10
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for i, line in enumerate(display_lines):
        if i == 0:
            draw.text((PADDING_LEFT, y), ">", fill=(0, 240, 130), font=font_bold)
            draw.text((PADDING_LEFT + 22, y), line, fill=(220, 220, 220), font=font_bold)
        else:
            severity, color = classify_line(line)
            if severity:
                severity_counts[severity] += 1
                line_bbox = draw.textbbox((PADDING_LEFT, y), line, font=font)
                box_x0 = line_bbox[0] - 8
                box_y0 = line_bbox[1] - 3
                box_x1 = min(line_bbox[2] + 8, IMG_WIDTH - PADDING_RIGHT)
                box_y1 = line_bbox[3] + 3

                overlay = Image.new("RGBA", img.size, (0, 0, 0, 0))
                overlay_draw = ImageDraw.Draw(overlay)
                overlay_draw.rectangle(
                    [(box_x0, box_y0), (box_x1, box_y1)],
                    fill=(color[0], color[1], color[2], 30)
                )
                img = Image.alpha_composite(img.convert("RGBA"), overlay).convert("RGB")
                draw = ImageDraw.Draw(img)

                draw.rectangle([(box_x0, box_y0), (box_x1, box_y1)], outline=color, width=2)
                draw.text((PADDING_LEFT, y), line, fill=color, font=font_bold)

                tag_text = f"[{severity}]"
                tag_bbox = draw.textbbox((0, 0), tag_text, font=legend_font)
                draw.text((IMG_WIDTH - (tag_bbox[2] - tag_bbox[0]) - 25, y + 2), tag_text, fill=color, font=legend_font)
            else:
                draw.text((PADDING_LEFT, y), line, fill=(200, 200, 200), font=font)
        y += LINE_HEIGHT

    # LEGEND
    legend_y = IMG_HEIGHT - LEGEND_HEIGHT - 5
    draw.line([(0, legend_y - 10), (IMG_WIDTH, legend_y - 10)], fill=(60, 60, 70), width=1)
    x = PADDING_LEFT
    for name, color in [("CRITICAL", (255, 45, 45)), ("HIGH", (255, 140, 0)),
                         ("MEDIUM", (255, 210, 30)), ("LOW", (80, 200, 120))]:
        draw.rectangle([(x, legend_y + 5), (x + 14, legend_y + 19)], fill=color)
        draw.text((x + 22, legend_y + 6), f"{name}: {severity_counts[name]}", fill=(200, 200, 200), font=legend_font)
        x += 180

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    ts_text = f"Generated: {timestamp}"
    ts_bbox = draw.textbbox((0, 0), ts_text, font=small_font)
    draw.text((IMG_WIDTH - (ts_bbox[2] - ts_bbox[0]) - 25, legend_y + 6), ts_text, fill=(120, 120, 130), font=small_font)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    img.save(output_path, "PNG", optimize=True)
    return output_path


def count_by_severity(output: str) -> dict:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for line in output.split("\n"):
        severity, _ = classify_line(line)
        if severity:
            counts[severity] += 1
    return counts