#!/usr/bin/env python3
from __future__ import annotations

import os
import sys
from textwrap import wrap
from PIL import Image, ImageDraw, ImageFont

WIDTH = 1920
HEIGHT = 1080


def pick_font(candidates: list[str], size: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    for path in candidates:
        if os.path.exists(path):
            try:
                return ImageFont.truetype(path, size=size)
            except OSError:
                continue
    return ImageFont.load_default()


def wrap_to_width(text: str, font: ImageFont.ImageFont, max_width: int, draw: ImageDraw.ImageDraw) -> list[str]:
    words = text.split()
    if not words:
        return [""]
    lines: list[str] = []
    current: list[str] = []
    for word in words:
        trial = " ".join(current + [word])
        bbox = draw.textbbox((0, 0), trial, font=font)
        if (bbox[2] - bbox[0]) <= max_width:
            current.append(word)
        else:
            if current:
                lines.append(" ".join(current))
            current = [word]
    if current:
        lines.append(" ".join(current))
    return lines


def draw_text_block(
    draw: ImageDraw.ImageDraw,
    text: str,
    x: int,
    y: int,
    font: ImageFont.ImageFont,
    color: tuple[int, int, int],
    max_width: int,
    line_gap: int,
) -> int:
    y_pos = y
    for paragraph in text.split("\n"):
        if not paragraph.strip():
            y_pos += line_gap
            continue
        for line in wrap_to_width(paragraph, font, max_width, draw):
            draw.text((x, y_pos), line, font=font, fill=color)
            box = draw.textbbox((x, y_pos), line, font=font)
            y_pos += (box[3] - box[1]) + line_gap
    return y_pos


def make_slide(idx: int, slide: dict, out_dir: str, fonts: dict[str, ImageFont.ImageFont]) -> None:
    img = Image.new("RGB", (WIDTH, HEIGHT), slide["bg"])
    draw = ImageDraw.Draw(img)

    # Main panel
    panel_x0, panel_y0 = 90, 80
    panel_x1, panel_y1 = WIDTH - 90, HEIGHT - 80
    draw.rounded_rectangle((panel_x0, panel_y0, panel_x1, panel_y1), radius=28, fill=(20, 28, 44), outline=(66, 83, 115), width=3)

    # Title
    title = slide["title"]
    draw.text((150, 130), title, font=fonts["title"], fill=(236, 242, 255))

    # Bullet text
    y = 240
    for bullet in slide.get("bullets", []):
        draw.ellipse((160, y + 14, 176, y + 30), fill=(125, 211, 252))
        y = draw_text_block(
            draw,
            bullet,
            195,
            y,
            fonts["body"],
            (223, 233, 252),
            1520,
            8,
        )
        y += 14

    # Command example panel
    cmd = slide.get("command")
    if cmd:
        box_top = max(y + 18, 580)
        draw.rounded_rectangle((150, box_top, WIDTH - 150, box_top + 260), radius=18, fill=(8, 12, 20), outline=(61, 78, 109), width=2)
        draw.text((180, box_top + 18), "Example", font=fonts["label"], fill=(147, 197, 253))
        draw_text_block(draw, cmd, 180, box_top + 58, fonts["mono"], (205, 250, 219), 1530, 6)

    # Footer
    footer = slide.get("footer")
    if footer:
        draw.text((150, HEIGHT - 148), footer, font=fonts["label"], fill=(148, 163, 184))

    path = os.path.join(out_dir, f"slide-{idx:02d}.png")
    img.save(path, format="PNG")


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: render_video_slides.py <output_dir>", file=sys.stderr)
        return 1

    out_dir = sys.argv[1]
    os.makedirs(out_dir, exist_ok=True)

    fonts = {
        "title": pick_font([
            "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
            "/System/Library/Fonts/Supplemental/Helvetica Bold.ttf",
        ], 62),
        "body": pick_font([
            "/System/Library/Fonts/Supplemental/Arial.ttf",
            "/System/Library/Fonts/Supplemental/Helvetica.ttf",
        ], 38),
        "label": pick_font([
            "/System/Library/Fonts/Supplemental/Arial.ttf",
            "/System/Library/Fonts/Supplemental/Helvetica.ttf",
        ], 30),
        "mono": pick_font([
            "/System/Library/Fonts/Menlo.ttc",
            "/System/Library/Fonts/SFNSMono.ttf",
        ], 34),
    }

    slides = [
        {
            "title": "k8sgrade: Kubernetes Health Scoring",
            "bg": (15, 23, 42),
            "bullets": [
                "Single Bash script that checks health, security, and RBAC posture.",
                "Starts at score 100 and applies deductions for detected risks.",
            ],
            "command": "$ ./k8sgrade.sh\nSelect a context and namespace when prompted.",
            "footer": "Interactive mode for guided discovery",
        },
        {
            "title": "Direct Run Example",
            "bg": (17, 24, 39),
            "bullets": [
                "Use direct mode when context and namespace are already known.",
                "Great for scheduled checks and CI pipelines.",
            ],
            "command": "$ ./k8sgrade.sh -c devopsart-k8s -n aiops\nContext: devopsart-k8s\nNamespace: aiops",
            "footer": "Non-interactive and repeatable",
        },
        {
            "title": "Security and CSV Export",
            "bg": (12, 74, 110),
            "bullets": [
                "Enable Trivy checks and capture full results into CSV.",
                "Useful for reporting and trend tracking over time.",
            ],
            "command": "$ ./k8sgrade.sh --install-trivy -c devopsart-k8s -n aiops --export-csv ./k8sgrade-report.csv\n$ head -5 ./k8sgrade-report.csv",
            "footer": "Adds vulnerability signals + report artifact",
        },
        {
            "title": "Example Output Sections",
            "bg": (30, 41, 59),
            "bullets": [
                "Node status, pod health, workload safety, exposure controls.",
                "Service account and RBAC review, score breakdown, final grade.",
            ],
            "command": "k8sgrade report\n- Nodes not ready: 0\n- Pending pods: 1\n- Total restarts: 3\n- Critical image signals: 0",
            "footer": "Read score breakdown to prioritize fixes",
        },
        {
            "title": "Grade Bands",
            "bg": (63, 63, 70),
            "bullets": [
                "A+ 95-100  Production hardened",
                "A 85-94 Production ready | B 70-84 Minor gaps",
                "C 55-69 Needs attention | D 40-54 Significant issues | F 0-39 Critical",
            ],
            "command": "Final Score: 88\nGrade: A\nTop recommendation: add missing PodDisruptionBudget",
            "footer": "Use recommendations for quick wins first",
        },
        {
            "title": "Start Here",
            "bg": (31, 41, 55),
            "bullets": [
                "Begin with interactive mode.",
                "Move to direct mode and CSV export for automation.",
            ],
            "command": "$ ./k8sgrade.sh\n$ ./k8sgrade.sh -a -c devopsart-k8s -n aiops --export-csv ./k8sgrade-report.csv",
            "footer": "k8sgrade walkthrough complete",
        },
    ]

    for i, slide in enumerate(slides, start=1):
        make_slide(i, slide, out_dir, fonts)

    print(f"Rendered {len(slides)} slides in {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
