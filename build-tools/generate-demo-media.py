#!/usr/bin/env python3
"""
Demo Media Generator for user-connectivity-triage.
Renders an animated terminal recording GIF (assets/demo.gif) and HD MP4 (assets/demo.mp4)
illustrating collector intake, 7-layer decision tree evaluation,
APIPA DHCP failure diagnosis, and ITSM escalation ticket generation.
Zero emoji, enterprise aesthetic.
"""

import os
import subprocess
import sys
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

SKILL_ROOT = Path(__file__).resolve().parent.parent
ASSETS_DIR = SKILL_ROOT / "assets"
ASSETS_DIR.mkdir(parents=True, exist_ok=True)

WIDTH, HEIGHT = 900, 520
BG_COLOR = (15, 20, 25)
PANEL_HEADER = (25, 33, 44)
TEXT_COLOR = (220, 225, 230)
DIM_TEXT = (110, 120, 135)
GREEN_ACCENT = (50, 205, 120)
YELLOW_ACCENT = (245, 180, 50)
RED_ACCENT = (255, 80, 80)
BLUE_ACCENT = (70, 160, 245)
BORDER_COLOR = (40, 50, 65)


def get_font(size: int = 14):
    try:
        return ImageFont.truetype("consola.ttf", size)
    except IOError:
        try:
            return ImageFont.truetype("Courier New.ttf", size)
        except IOError:
            return ImageFont.load_default()


def create_terminal_base():
    img = Image.new("RGB", (WIDTH, HEIGHT), BG_COLOR)
    draw = ImageDraw.Draw(img)

    # Header bar
    draw.rectangle([0, 0, WIDTH, 36], fill=PANEL_HEADER)
    draw.line([0, 36, WIDTH, 36], fill=BORDER_COLOR, width=1)

    # Window control circles
    draw.ellipse([14, 12, 24, 22], fill=(60, 70, 85))
    draw.ellipse([32, 12, 42, 22], fill=(60, 70, 85))
    draw.ellipse([50, 12, 60, 22], fill=(60, 70, 85))

    font_title = get_font(12)
    title_text = "helpdesk-technician@service-desk: ~/user-connectivity-triage"
    draw.text((WIDTH // 2 - 190, 11), title_text, fill=DIM_TEXT, font=font_title)

    return img


def render_frames():
    font = get_font(13)
    frames = []

    script_lines = [
        ("helpdesk@desk:~$ python scripts/triage_connectivity.py -i telemetry.json --sanitize", TEXT_COLOR),
        ("================================================================================", BORDER_COLOR),
        ("USER CONNECTIVITY TRIAGE & LAYER DIAGNOSTIC REPORT", TEXT_COLOR),
        ("================================================================================", BORDER_COLOR),
        ("Target Endpoint : host-f3c67aa3.corp.example.com", BLUE_ACCENT),
        ("Operating System: Windows 11 Enterprise (23H2)", DIM_TEXT),
        ("--------------------------------------------------------------------------------", BORDER_COLOR),
        ("TRIAGE RESULT   : [FAIL] LAYER 3 - NETWORK / IP CONFIGURATION (DHCP FAILURE)", RED_ACCENT),
        ("PRIORITY        : P2 - High", YELLOW_ACCENT),
        ("DIAGNOSIS       : Endpoint failed to obtain DHCP lease; self-assigned APIPA (169.254.x.x)", RED_ACCENT),
        ("--------------------------------------------------------------------------------", BORDER_COLOR),
        ("TECHNICAL TELEMETRY EVIDENCE:", YELLOW_ACCENT),
        ("  * Interface 'Ethernet' assigned APIPA address: 169.254.45.120 (Subnet: 255.255.0.0)", TEXT_COLOR),
        ("  * Interface 'Ethernet' has no default gateway configured", TEXT_COLOR),
        ("--------------------------------------------------------------------------------", BORDER_COLOR),
        ("LEVEL 1 RESOLUTION STEPS (FOR END USER):", GREEN_ACCENT),
        ("  1. Restart local Wi-Fi router or home internet modem.", TEXT_COLOR),
        ("  2. Disconnect and reconnect network cable for 10 seconds.", TEXT_COLOR),
        ("--------------------------------------------------------------------------------", BORDER_COLOR),
        ("TIER 2 / TIER 3 ESCALATION BRIEF (FOR IT SERVICE DESK):", BLUE_ACCENT),
        ("  * Execute 'ipconfig /renew' to re-request DHCP lease from server.", TEXT_COLOR),
        ("  * Inspect DHCP server scope exhaustion or VLAN helper-address relay.", TEXT_COLOR),
        ("================================================================================", BORDER_COLOR),
        ("[SUCCESS] Exported L2/L3 escalation ticket to ticket-escalation.md", GREEN_ACCENT),
    ]

    for count in range(1, len(script_lines) + 1):
        frame = create_terminal_base()
        draw = ImageDraw.Draw(frame)

        y = 50
        for idx in range(count):
            line_text, line_color = script_lines[idx]
            draw.text((25, y), line_text, fill=line_color, font=font)
            y += 19

        if count < len(script_lines):
            draw.rectangle([25, y, 33, y + 15], fill=GREEN_ACCENT)

        duration = 1 if count < len(script_lines) else 15
        for _ in range(duration):
            frames.append(frame)

    return frames


def build_media():
    print("Generating demo frames for user-connectivity-triage...")
    frames = render_frames()
    gif_path = ASSETS_DIR / "demo.gif"
    mp4_path = ASSETS_DIR / "demo.mp4"

    # Save GIF
    frames[0].save(
        gif_path,
        save_all=True,
        append_images=frames[1:],
        duration=180,
        loop=0,
        optimize=True
    )
    print(f"Generated demo GIF: {gif_path} ({gif_path.stat().st_size / 1024:.1f} KB)")

    # Render MP4 via ffmpeg
    temp_dir = Path(__file__).parent / "_temp_frames"
    temp_dir.mkdir(parents=True, exist_ok=True)
    try:
        for idx, f in enumerate(frames):
            f.save(temp_dir / f"frame_{idx:04d}.png")

        cmd = [
            "ffmpeg", "-y",
            "-framerate", "5",
            "-i", str(temp_dir / "frame_%04d.png"),
            "-c:v", "libx264",
            "-pix_fmt", "yuv420p",
            "-crf", "18",
            str(mp4_path)
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode == 0:
            print(f"Generated demo MP4: {mp4_path} ({mp4_path.stat().st_size / 1024:.1f} KB)")
        else:
            print(f"Warning: ffmpeg error: {res.stderr}")
    finally:
        for p in temp_dir.glob("*.png"):
            p.unlink()
        temp_dir.rmdir()


if __name__ == "__main__":
    build_media()
