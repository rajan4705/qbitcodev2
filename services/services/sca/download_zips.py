"""
OSV Ecosystem Zip Downloader
============================
Downloads official vulnerability dumps (.zip) from Google OSV for:
  c, cpp, csharp, go, java, js, kotlin, php, ruby, python, rust, swift, typescript

Usage:
  python vul_packages/download_zips.py --all
  python vul_packages/download_zips.py python js rust
"""

import sys
import os
import argparse
from pathlib import Path
import requests

OSV_BUCKET_URL = "https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip"

LANGUAGE_TO_OSV = {
    "python": "PyPI",
    "js": "npm",
    "javascript": "npm",
    "typescript": "npm",
    "go": "Go",
    "java": "Maven",
    "kotlin": "Maven",
    "rust": "crates.io",
    "csharp": "NuGet",
    "c#": "NuGet",
    "php": "Packagist",
    "ruby": "RubyGems",
    "swift": "SwiftURL",
    "c": "OSS-Fuzz",
    "cpp": "OSS-Fuzz",
}

DEFAULT_ALL_ECOSYSTEMS = [
    "PyPI", "npm", "Go", "Maven", "crates.io", 
    "NuGet", "Packagist", "RubyGems", "SwiftURL", "OSS-Fuzz"
]

DEFAULT_OUTPUT_DIR = Path(__file__).parent / "zips"


def download_ecosystem_zip(ecosystem, output_dir=DEFAULT_OUTPUT_DIR, force=False):
    """Downloads all.zip dump for a given OSV ecosystem with streaming progress."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    dest_file = output_dir / f"{ecosystem}_all.zip"

    if dest_file.exists() and not force and dest_file.stat().st_size > 0:
        file_size_mb = dest_file.stat().st_size / (1024 * 1024)
        print(f"[=] Already exists: {dest_file.name} ({file_size_mb:.2f} MB). Skipping (use --force to redownload).")
        return dest_file

    url = OSV_BUCKET_URL.format(ecosystem=ecosystem)
    print(f"\n[*] Downloading: {ecosystem}")
    print(f"    URL: {url}")
    print(f"    Saving to: {dest_file}")

    try:
        response = requests.get(url, stream=True, timeout=120)
        if response.status_code != 200:
            print(f"[!] Error: HTTP {response.status_code} for {ecosystem} at {url}")
            return None

        total_bytes = int(response.headers.get("content-length", 0))
        downloaded = 0
        chunk_size = 1024 * 1024

        with open(dest_file, "wb") as f:
            for chunk in response.iter_content(chunk_size=chunk_size):
                if chunk:
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total_bytes > 0:
                        percent = (downloaded / total_bytes) * 100
                        print(f"\r    Progress: {downloaded / (1024*1024):.1f} MB / {total_bytes / (1024*1024):.1f} MB ({percent:.1f}%)", end="", flush=True)
                    else:
                        print(f"\r    Progress: {downloaded / (1024*1024):.1f} MB", end="", flush=True)

        print(f"\n[+] Saved: {dest_file.name} ({downloaded / (1024*1024):.2f} MB)")
        return dest_file

    except Exception as e:
        print(f"\n[!] Download failed for {ecosystem}: {e}")
        if dest_file.exists():
            dest_file.unlink()
        return None


def main():
    parser = argparse.ArgumentParser(description="Download Google OSV vulnerability dumps (.zip).")
    parser.add_argument("targets", nargs="*", help="Languages or ecosystems to download (e.g. python js rust)")
    parser.add_argument("--all", action="store_true", help="Download dumps for all 13 ecosystems")
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR), help=f"Directory to save zip files (default: {DEFAULT_OUTPUT_DIR})")
    parser.add_argument("--force", action="store_true", help="Force re-download even if the zip file exists")

    args = parser.parse_args()

    ecosystems_to_download = set()
    if args.all or not args.targets:
        if not args.all:
            print("No target specified. Defaulting to all ecosystems (--all).")
        ecosystems_to_download.update(DEFAULT_ALL_ECOSYSTEMS)
    else:
        for t in args.targets:
            key = t.lower().strip()
            if key in LANGUAGE_TO_OSV:
                ecosystems_to_download.add(LANGUAGE_TO_OSV[key])
            else:
                ecosystems_to_download.add(t)

    print("=" * 65)
    print("OSV ECOSYSTEM ZIP DOWNLOADER")
    print(f"Target Ecosystems : {', '.join(sorted(ecosystems_to_download))}")
    print(f"Destination Dir   : {args.output_dir}")
    print("=" * 65)

    downloaded = []
    for eco in sorted(ecosystems_to_download):
        res = download_ecosystem_zip(eco, output_dir=args.output_dir, force=args.force)
        if res:
            downloaded.append(res)

    print("\n" + "=" * 65)
    print(f"[+] Complete: {len(downloaded)} / {len(ecosystems_to_download)} files in '{args.output_dir}'")
    print("=" * 65)


if __name__ == "__main__":
    main()

