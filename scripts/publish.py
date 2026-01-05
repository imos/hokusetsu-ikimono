#!/usr/bin/env python3
import argparse
import os
import posixpath
import re
import shutil
import urllib.parse
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

NOTICE_TEXT = (
    "このページは故下山孝さんの「北摂の生き物」をご遺族の了解のもと"
    '<a href="http://hitoshizen.jp/">池田・人と自然の会</a>が転載しています。'
    "一部データが欠けている部分があります。"
)
NOTICE_HTML = (
    '<div style="font-size: 80%;font-weight: bold;'
    'border: 1px solid #888;border-radius: 10px;'
    'padding: 0.5em 2em;background: white;color: #000;">'
    f"{NOTICE_TEXT}</div>"
)

ABSOLUTE_DOMAIN = "http://www.hokusetsu-ikimono.com/"


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Merge public_html and ashitaka_html into published, converting text to UTF-8."
        )
    )
    parser.add_argument(
        "--public",
        default="public_html",
        help="Primary source directory (default: %(default)s)",
    )
    parser.add_argument(
        "--ashitaka",
        default="ashitaka_html",
        help="Secondary source directory (default: %(default)s)",
    )
    parser.add_argument(
        "--dest",
        default="docs",
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


def insert_notice_html(text):
    if NOTICE_TEXT in text:
        return text
    notice_block = f"\n{NOTICE_HTML}\n"
    match = re.search(r"(?i)<body[^>]*>", text)
    if match:
        end = match.end()
        return text[:end] + notice_block + text[end:]
    return notice_block + text


def url_to_relative(url, current_dir):
    parsed = urllib.parse.urlsplit(url)
    path = parsed.path
    if path in ("", "/"):
        rel_path = "./"
    else:
        target = path.lstrip("/")
        rel_path = posixpath.relpath(target, start=current_dir)
        if path.endswith("/") and not rel_path.endswith("/"):
            rel_path = rel_path + "/"
        if rel_path == ".":
            rel_path = "./"
    if parsed.query:
        rel_path = f"{rel_path}?{parsed.query}"
    if parsed.fragment:
        rel_path = f"{rel_path}#{parsed.fragment}"
    return rel_path


def rewrite_absolute_links(text, current_dir):
    pattern = re.compile(
        r'(?i)\b(href|src)\s*=\s*([\'"])(http://www\.hokusetsu-ikimono\.com/[^\'"]*)\2'
    )

    def replacer(match):
        attr = match.group(1)
        quote = match.group(2)
        url = match.group(3)
        rel = url_to_relative(url, current_dir)
        return f"{attr}={quote}{rel}{quote}"

    return pattern.sub(replacer, text)


def collect_files(root):
    root = Path(root)
    files = {}
    if not root.exists():
        return files
    for path in root.rglob("*"):
        if path.is_file():
            rel = path.relative_to(root).as_posix()
            files[rel] = path
    return files


def merge_sources(public_dir, ashitaka_dir):
    merged = {}
    merged.update(collect_files(ashitaka_dir))
    merged.update(collect_files(public_dir))
    return merged


def prepare_dest(dest):
    dest = Path(dest)
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True, exist_ok=True)
    return dest


def write_text_file(src_path, dest_path, rel_posix):
    data = src_path.read_bytes()
    text, _, _ = decode_text(data)
    suffix = src_path.suffix.lower()

    if suffix in HTML_EXTS:
        text = update_html_charset(text)
        text = insert_notice_html(text)
        current_dir = posixpath.dirname(rel_posix) or "."
        text = rewrite_absolute_links(text, current_dir)
    elif suffix in CSS_EXTS:
        text = update_css_charset(text)
    elif suffix in XML_EXTS:
        text = update_xml_encoding(text)

    dest_path.parent.mkdir(parents=True, exist_ok=True)
    dest_path.write_bytes(text.encode("utf-8"))
    shutil.copystat(src_path, dest_path)


def publish(public_dir, ashitaka_dir, dest_dir):
    sources = merge_sources(public_dir, ashitaka_dir)
    if not sources:
        raise SystemExit("No source files found in public_html or ashitaka_html.")

    dest_root = prepare_dest(dest_dir)
    for rel_posix, src_path in sources.items():
        dest_path = dest_root / rel_posix
        data = src_path.read_bytes()
        if is_probably_binary(src_path, data):
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src_path, dest_path)
        else:
            write_text_file(src_path, dest_path, rel_posix)


def main():
    args = parse_args()
    publish(args.public, args.ashitaka, args.dest)


if __name__ == "__main__":
    main()
