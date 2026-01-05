#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from datetime import datetime
import re


CDX_ENDPOINT = "https://web.archive.org/cdx/search/cdx"
WAYBACK_PREFIX = "https://web.archive.org/web/"
DEFAULT_DOMAIN = "www.hokusetsu-ikimono.com"
USER_AGENT = "hokusetsu-ikimono-archiver/1.0 (+https://web.archive.org)"
DEFAULT_STATE_DIR = "scripts/.archive_state"
RETRY_COUNT = 3
RETRY_DELAY_SECONDS = 5
RETRY_ERRNOS = {61, 111, 10061}


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Download all archived files under a domain from the Wayback Machine "
            "into a local directory, with resume support."
        )
    )
    parser.add_argument(
        "--domain",
        default=DEFAULT_DOMAIN,
        help="Domain to archive (default: %(default)s)",
    )
    parser.add_argument(
        "--output",
        default="public_html",
        help="Output directory for downloaded files (default: %(default)s)",
    )
    parser.add_argument(
        "--state-dir",
        default=DEFAULT_STATE_DIR,
        help="Base directory for resume state files (default: %(default)s)",
    )
    parser.add_argument(
        "--refresh-cdx",
        action="store_true",
        help="Refresh the CDX list even if a cached copy exists",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.2,
        help="Delay between downloads in seconds (default: %(default)s)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Limit number of URLs to download (default: 0 means no limit)",
    )
    parser.add_argument(
        "--skip-failed",
        action="store_true",
        help="Skip URLs recorded as failed in a previous run",
    )
    parser.add_argument(
        "--before",
        default="",
        help=(
            "Only download snapshots before this date "
            "(YYYY-MM-DD, YYYYMMDD, YYYY-MM, or YYYYMM)"
        ),
    )
    return parser.parse_args()


def load_lines(path):
    if not path.exists():
        return set()
    with path.open("r", encoding="utf-8") as handle:
        return {line.strip() for line in handle if line.strip()}


def append_line(path, line):
    with path.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")


def state_key_for_domain(domain):
    value = domain.strip()
    if not value:
        return "unknown"
    if "://" in value:
        parsed = urllib.parse.urlsplit(value)
    else:
        parsed = urllib.parse.urlsplit(f"http://{value}")
    host = parsed.hostname or value
    path = parsed.path or ""
    if path in ("", "/"):
        key = host
    else:
        key = host + path
    key = key.strip("/")
    return re.sub(r"[^a-zA-Z0-9._-]+", "_", key)


def load_state_marker(state_dir):
    marker_path = state_dir / "state.json"
    if not marker_path.exists():
        return None
    try:
        with marker_path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None
    return data.get("domain")


def write_state_marker(state_dir, domain):
    marker_path = state_dir / "state.json"
    if marker_path.exists():
        return
    data = {"domain": domain}
    with marker_path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, ensure_ascii=True, indent=2)
        handle.write("\n")


def infer_domain_from_cdx(cache_path):
    if not cache_path.exists():
        return None
    try:
        with cache_path.open("r", encoding="utf-8") as handle:
            rows = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None
    if not rows or not isinstance(rows, list):
        return None
    header = rows[0]
    if not isinstance(header, list):
        return None
    try:
        original_index = header.index("original")
    except ValueError:
        return None
    for row in rows[1:]:
        if isinstance(row, list) and len(row) > original_index:
            original = row[original_index]
            parsed = urllib.parse.urlsplit(original)
            if parsed.hostname:
                return parsed.hostname
    return None


def resolve_state_dir(base_dir, domain):
    base_dir = Path(base_dir)
    domain_key = state_key_for_domain(domain)
    candidate = base_dir / domain_key
    marker_domain = load_state_marker(base_dir)
    if marker_domain:
        if state_key_for_domain(marker_domain) == domain_key:
            return base_dir
        return candidate
    if candidate.exists():
        return candidate
    inferred = infer_domain_from_cdx(base_dir / "cdx_cache.json")
    if inferred and state_key_for_domain(inferred) == domain_key:
        return base_dir
    return candidate


def parse_before_date(value):
    value = value.strip()
    if not value:
        return None
    formats = ("%Y-%m-%d", "%Y%m%d", "%Y-%m", "%Y%m")
    for fmt in formats:
        try:
            parsed = datetime.strptime(value, fmt)
            if fmt in ("%Y-%m", "%Y%m"):
                parsed = parsed.replace(day=1)
            return parsed.strftime("%Y%m%d000000")
        except ValueError:
            continue
    raise ValueError(f"Unsupported date format: {value}")


def filter_timestamps(timestamps, cutoff):
    if not cutoff:
        return timestamps
    return [timestamp for timestamp in timestamps if timestamp < cutoff]


def extract_errno_from_text(text):
    match = re.search(r"Errno\s+(\d+)", text)
    if match:
        return int(match.group(1))
    return None


def extract_errno(exc):
    if isinstance(exc, urllib.error.URLError):
        reason = exc.reason
        if isinstance(reason, BaseException):
            errno = getattr(reason, "errno", None)
            if errno is not None:
                return errno
        errno = extract_errno_from_text(str(reason))
        if errno is not None:
            return errno
        return extract_errno_from_text(str(exc))

    errno = getattr(exc, "errno", None)
    if errno is not None:
        return errno
    return extract_errno_from_text(str(exc))


def should_retry_error(exc):
    errno = extract_errno(exc)
    if errno in RETRY_ERRNOS:
        return True
    if "Connection refused" in str(exc):
        return True
    if isinstance(exc, urllib.error.URLError):
        if "Connection refused" in str(exc.reason):
            return True
    return False


def urlopen_with_retry(request, timeout=60):
    for attempt in range(RETRY_COUNT):
        try:
            return urllib.request.urlopen(request, timeout=timeout)
        except (urllib.error.URLError, OSError) as exc:
            if not should_retry_error(exc) or attempt >= RETRY_COUNT - 1:
                raise
            time.sleep(RETRY_DELAY_SECONDS)


def fetch_cdx_rows(domain, cache_path, refresh=False):
    if cache_path.exists() and not refresh:
        with cache_path.open("r", encoding="utf-8") as handle:
            return json.load(handle)

    normalized = domain.rstrip("/")
    query = {
        "url": f"{normalized}/*",
        "output": "json",
        "fl": "timestamp,original,statuscode",
        "filter": "statuscode:200",
    }
    url = CDX_ENDPOINT + "?" + urllib.parse.urlencode(query)
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urlopen_with_retry(req, timeout=60) as resp:
        raw = resp.read()
    rows = json.loads(raw.decode("utf-8"))
    with cache_path.open("w", encoding="utf-8") as handle:
        json.dump(rows, handle, ensure_ascii=True, indent=2)
    return rows


def fetch_cdx_rows_for_original(original_url):
    query = {
        "url": original_url,
        "output": "json",
        "fl": "timestamp,original,statuscode",
        "filter": "statuscode:200",
        "matchType": "exact",
    }
    url = CDX_ENDPOINT + "?" + urllib.parse.urlencode(query)
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urlopen_with_retry(req, timeout=60) as resp:
        raw = resp.read()
    return json.loads(raw.decode("utf-8"))


def build_capture_map(rows, cutoff=None):
    if not rows:
        return {}
    header = rows[0]
    try:
        ts_index = header.index("timestamp")
        original_index = header.index("original")
    except ValueError:
        raise RuntimeError("Unexpected CDX header format")

    captures = {}
    for row in rows[1:]:
        if len(row) <= max(ts_index, original_index):
            continue
        timestamp = row[ts_index]
        original = row[original_index]
        if cutoff and timestamp >= cutoff:
            continue
        captures.setdefault(original, []).append(timestamp)

    for timestamps in captures.values():
        timestamps.sort(reverse=True)
    return captures


def extract_timestamps(rows, cutoff=None):
    if not rows:
        return []
    header = rows[0]
    try:
        ts_index = header.index("timestamp")
    except ValueError:
        return []
    timestamps = []
    for row in rows[1:]:
        if len(row) > ts_index:
            timestamps.append(row[ts_index])
    timestamps = filter_timestamps(timestamps, cutoff)
    timestamps.sort(reverse=True)
    return timestamps


def safe_path_parts(path):
    parts = []
    for part in path.split("/"):
        if not part or part == ".":
            continue
        if part == "..":
            parts.append("_")
            continue
        parts.append(part)
    return parts


def add_query_suffix(filename, query):
    if not query:
        return filename
    digest = hashlib.sha1(query.encode("utf-8")).hexdigest()[:12]
    stem, ext = os.path.splitext(filename)
    if ext:
        return f"{stem}__q_{digest}{ext}"
    return f"{filename}__q_{digest}"


def url_to_local_path(original_url, output_dir):
    parsed = urllib.parse.urlsplit(original_url)
    path = parsed.path or "/"
    if path.endswith("/"):
        path = path + "index.html"

    parts = safe_path_parts(path)
    if not parts:
        parts = ["index.html"]
    filename = parts[-1]
    filename = add_query_suffix(filename, parsed.query)
    parts[-1] = filename

    return output_dir.joinpath(*parts)


def build_netloc(parsed, hostname):
    netloc = hostname
    if parsed.port:
        netloc = f"{hostname}:{parsed.port}"
    if parsed.username:
        auth = parsed.username
        if parsed.password:
            auth = f"{auth}:{parsed.password}"
        netloc = f"{auth}@{netloc}"
    return netloc


def url_with_host(parsed, hostname):
    netloc = build_netloc(parsed, hostname)
    return urllib.parse.urlunsplit(
        (parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment)
    )


def host_variants(original_url):
    parsed = urllib.parse.urlsplit(original_url)
    hostname = parsed.hostname
    if not hostname:
        return []
    variants = []
    if hostname.startswith("www."):
        variants.append(hostname[len("www."):])
    else:
        variants.append(f"www.{hostname}")
    return [url_with_host(parsed, host) for host in variants]


def iter_candidate_urls(original_url):
    seen = set()
    for candidate in [original_url] + host_variants(original_url):
        if candidate not in seen:
            seen.add(candidate)
            yield candidate


def get_timestamps_for_url(original_url, captures, fallback_cache, fetcher, cutoff):
    if original_url in captures:
        return filter_timestamps(captures[original_url], cutoff)
    if original_url in fallback_cache:
        return filter_timestamps(fallback_cache[original_url], cutoff)
    if fetcher is None:
        return []
    try:
        rows = fetcher(original_url)
    except Exception as exc:  # pylint: disable=broad-except
        print(
            f"[cdx] failed to fetch timestamps for {original_url}: {exc}",
            file=sys.stderr,
        )
        fallback_cache[original_url] = []
        return []
    timestamps = extract_timestamps(rows, cutoff)
    fallback_cache[original_url] = timestamps
    return timestamps


def select_metadata_candidate(original_url, captures, fallback_cache, fetcher, cutoff):
    for candidate in iter_candidate_urls(original_url):
        timestamps = get_timestamps_for_url(
            candidate, captures, fallback_cache, fetcher, cutoff
        )
        if timestamps:
            return candidate, timestamps[0]
    return None, None


def download_with_fallback(
    original_url,
    dest_path,
    captures,
    fallback_cache,
    fetcher,
    downloader,
    cutoff,
):
    last_error = ""
    for candidate in iter_candidate_urls(original_url):
        timestamps = get_timestamps_for_url(
            candidate, captures, fallback_cache, fetcher, cutoff
        )
        for timestamp in timestamps:
            archive_url = f"{WAYBACK_PREFIX}{timestamp}id_/{candidate}"
            try:
                meta = downloader(archive_url, dest_path)
            except Exception as exc:  # pylint: disable=broad-except
                last_error = str(exc)
                continue
            return True, candidate, timestamp, meta, ""
    return False, None, None, None, last_error


def download_capture(archive_url, dest_path):
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = dest_path.with_suffix(dest_path.suffix + ".part")
    if tmp_path.exists():
        tmp_path.unlink()

    req = urllib.request.Request(archive_url, headers={"User-Agent": USER_AGENT})
    with urlopen_with_retry(req, timeout=60) as resp:
        status = getattr(resp, "status", 200)
        if status != 200:
            raise RuntimeError(f"HTTP {status}")
        content_type = resp.headers.get("Content-Type")
        content_length = resp.headers.get("Content-Length")
        effective_url = resp.geturl()
        with tmp_path.open("wb") as handle:
            while True:
                chunk = resp.read(1024 * 64)
                if not chunk:
                    break
                handle.write(chunk)

    tmp_path.replace(dest_path)
    return {
        "status": status,
        "content_type": content_type,
        "content_length": content_length,
        "effective_url": effective_url,
    }


def metadata_path_for(dest_path):
    return dest_path.with_name(dest_path.name + ".json")


def write_metadata(dest_path, metadata):
    meta_path = metadata_path_for(dest_path)
    with meta_path.open("w", encoding="utf-8") as handle:
        json.dump(metadata, handle, ensure_ascii=True, indent=2, sort_keys=True)
        handle.write("\n")


def timestamp_to_date(timestamp):
    if not timestamp:
        return None
    try:
        return datetime.strptime(timestamp, "%Y%m%d%H%M%S").date().isoformat()
    except ValueError:
        return None


def main():
    args = parse_args()
    cutoff = parse_before_date(args.before)
    output_dir = Path(args.output)
    state_dir = resolve_state_dir(args.state_dir, args.domain)
    state_dir.mkdir(parents=True, exist_ok=True)
    write_state_marker(state_dir, args.domain)
    output_dir.mkdir(parents=True, exist_ok=True)

    downloaded_path = state_dir / "downloaded.txt"
    failed_path = state_dir / "failed.txt"
    cdx_cache_path = state_dir / "cdx_cache.json"

    downloaded = load_lines(downloaded_path)
    failed = load_lines(failed_path)

    rows = fetch_cdx_rows(args.domain, cdx_cache_path, refresh=args.refresh_cdx)
    captures = build_capture_map(rows, cutoff=cutoff)
    fallback_cache = {}

    originals = sorted(captures.keys())
    if args.limit > 0:
        originals = originals[: args.limit]

    total = len(originals)
    for index, original in enumerate(originals, start=1):
        dest_path = url_to_local_path(original, output_dir)
        meta_path = metadata_path_for(dest_path)
        already_downloaded = original in downloaded

        if already_downloaded and dest_path.exists() and dest_path.stat().st_size > 0:
            if not meta_path.exists():
                candidate_url, timestamp = select_metadata_candidate(
                    original,
                    captures,
                    fallback_cache,
                    fetch_cdx_rows_for_original,
                    cutoff,
                )
                archive_url = (
                    f"{WAYBACK_PREFIX}{timestamp}id_/{candidate_url}"
                    if timestamp
                    else None
                )
                metadata = {
                    "archive_url": archive_url,
                    "content_length": None,
                    "content_type": None,
                    "downloaded_at": datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
                    "effective_url": None,
                    "note": "metadata generated without re-downloading existing file",
                    "original_url": original,
                    "output_path": str(dest_path.relative_to(output_dir)),
                    "resolved_original_url": candidate_url,
                    "snapshot_date": timestamp_to_date(timestamp),
                    "status": None,
                    "timestamp": timestamp,
                    "file_size": dest_path.stat().st_size,
                }
                write_metadata(dest_path, metadata)
            continue

        if args.skip_failed and original in failed:
            continue

        if dest_path.exists() and dest_path.stat().st_size > 0:
            if not meta_path.exists():
                candidate_url, timestamp = select_metadata_candidate(
                    original,
                    captures,
                    fallback_cache,
                    fetch_cdx_rows_for_original,
                    cutoff,
                )
                archive_url = (
                    f"{WAYBACK_PREFIX}{timestamp}id_/{candidate_url}"
                    if timestamp
                    else None
                )
                metadata = {
                    "archive_url": archive_url,
                    "content_length": None,
                    "content_type": None,
                    "downloaded_at": datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
                    "effective_url": None,
                    "note": "metadata generated without re-downloading existing file",
                    "original_url": original,
                    "output_path": str(dest_path.relative_to(output_dir)),
                    "resolved_original_url": candidate_url,
                    "snapshot_date": timestamp_to_date(timestamp),
                    "status": None,
                    "timestamp": timestamp,
                    "file_size": dest_path.stat().st_size,
                }
                write_metadata(dest_path, metadata)
            if original not in downloaded:
                downloaded.add(original)
                append_line(downloaded_path, original)
            continue

        success, selected_original, selected_timestamp, selected_meta, last_error = (
            download_with_fallback(
                original,
                dest_path,
                captures,
                fallback_cache,
                fetch_cdx_rows_for_original,
                download_capture,
                cutoff,
            )
        )

        if success:
            metadata = {
                "archive_url": f"{WAYBACK_PREFIX}{selected_timestamp}id_/{selected_original}",
                "content_length": selected_meta.get("content_length") if selected_meta else None,
                "content_type": selected_meta.get("content_type") if selected_meta else None,
                "downloaded_at": datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
                "effective_url": selected_meta.get("effective_url") if selected_meta else None,
                "original_url": original,
                "output_path": str(dest_path.relative_to(output_dir)),
                "resolved_original_url": selected_original,
                "snapshot_date": timestamp_to_date(selected_timestamp),
                "status": selected_meta.get("status") if selected_meta else None,
                "timestamp": selected_timestamp,
                "file_size": dest_path.stat().st_size,
            }
            write_metadata(dest_path, metadata)
            if original not in downloaded:
                downloaded.add(original)
                append_line(downloaded_path, original)
            print(f"[{index}/{total}] saved {original}")
        else:
            append_line(failed_path, original)
            print(
                f"[{index}/{total}] failed {original} ({last_error or 'unknown error'})",
                file=sys.stderr,
            )

        if args.delay > 0:
            time.sleep(args.delay)


if __name__ == "__main__":
    main()
