#!/usr/bin/env python3
import argparse
import os
import re
import shutil
from pathlib import Path


TEXT_EXTS = {
    ".txt",
    ".html",
    ".htm",
    ".xhtml",
    ".shtml",
    ".css",
    ".js",
    ".json",
    ".xml",
    ".csv",
    ".svg",
    ".md",
    ".ini",
    ".cfg",
    ".conf",
    ".yml",
    ".yaml",
    ".php",
    ".asp",
    ".aspx",
    ".jsp",
    ".cgi",
    ".pl",
    ".rb",
    ".py",
    ".sh",
}

BINARY_EXTS = {
    ".jpg",
    ".jpeg",
    ".gif",
    ".png",
    ".bmp",
    ".webp",
    ".ico",
    ".pdf",
    ".zip",
    ".gz",
    ".bz2",
    ".xz",
    ".7z",
    ".rar",
    ".tgz",
    ".swf",
    ".mp3",
    ".mp4",
    ".m4a",
    ".wav",
    ".ogg",
    ".avi",
    ".mov",
    ".wmv",
    ".woff",
    ".woff2",
    ".ttf",
    ".otf",
    ".eot",
}

ENCODINGS = [
    "utf-8",
    "utf-8-sig",
    "cp932",
    "shift_jis",
    "euc_jp",
    "iso2022_jp",
]

HTML_EXTS = {".html", ".htm", ".xhtml", ".shtml"}
CSS_EXTS = {".css"}
XML_EXTS = {".xml", ".xhtml", ".svg"}


def parse_args():
    parser = argparse.ArgumentParser(
        description="Copy public_html to public_html_utf8, converting text files to UTF-8."
    )
    parser.add_argument(
        "--source",
        default="public_html",
        help="Source directory (default: %(default)s)",
    )
    parser.add_argument(
        "--dest",
        default="public_html_utf8",
        help="Destination directory (default: %(default)s)",
    )
    return parser.parse_args()


def is_probably_binary(path, data):
    ext = path.suffix.lower()
    if ext in BINARY_EXTS:
        return True
    if ext in TEXT_EXTS:
        return False
    if not data:
        return False
    if b"\x00" in data:
        return True
    nontext = sum(1 for b in data if b < 9 or (13 < b < 32))
    return nontext / len(data) > 0.3


def decode_text(data):
    for encoding in ENCODINGS:
        try:
            return data.decode(encoding), encoding, False
        except UnicodeDecodeError:
            continue
    return data.decode("cp932", errors="replace"), "cp932", True


def update_html_charset(text):
    def repl(match):
        prefix = match.group(1)
        quote = match.group(2) or ""
        return f"{prefix}{quote}utf-8"

    return re.sub(r"(?i)(charset=)(['\"]?)[a-z0-9._-]+", repl, text)


def update_css_charset(text):
    return re.sub(
        r'(?i)(@charset\s+)(["\'])[a-z0-9._-]+(["\'])',
        r'\1"utf-8"',
        text,
    )


def update_xml_encoding(text):
    return re.sub(
        r'(?i)(encoding=)(["\'])[a-z0-9._-]+(["\'])',
        r'\1"utf-8"',
        text,
    )


def convert_tree(source, dest):
    source = Path(source)
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)

    for root, _, files in os.walk(source):
        root_path = Path(root)
        rel = root_path.relative_to(source)
        dest_root = dest / rel
        dest_root.mkdir(parents=True, exist_ok=True)

        for filename in files:
            src_path = root_path / filename
            dst_path = dest_root / filename
            data = src_path.read_bytes()

            if is_probably_binary(src_path, data):
                dst_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src_path, dst_path)
                continue

            text, _, _ = decode_text(data)
            suffix = src_path.suffix.lower()
            if suffix in HTML_EXTS:
                text = update_html_charset(text)
            elif suffix in CSS_EXTS:
                text = update_css_charset(text)
            elif suffix in XML_EXTS:
                text = update_xml_encoding(text)

            dst_path.parent.mkdir(parents=True, exist_ok=True)
            dst_path.write_bytes(text.encode("utf-8"))
            shutil.copystat(src_path, dst_path)


def main():
    args = parse_args()
    convert_tree(args.source, args.dest)


if __name__ == "__main__":
    main()
