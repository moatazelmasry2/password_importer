#!/usr/bin/env python3
import argparse
import tarfile
import tempfile
from pathlib import Path
import shutil
import io


def stream_copy_text(src: Path, dst: Path, append: bool = False) -> None:
    """
    Stream text from src to dst without loading the whole file into memory.
    Decodes as UTF-8 with replacement for invalid bytes.
    """
    mode = "a" if append else "w"
    with src.open("rb") as rb, open(dst, mode, encoding="utf-8", newline="") as wt:
        reader = io.TextIOWrapper(rb, encoding="utf-8", errors="replace")
        while True:
            chunk = reader.read(1024 * 1024)  # 1 MiB of decoded text
            if not chunk:
                break
            wt.write(chunk)


def is_probably_text(file_path: Path, sample_bytes: int = 4096) -> bool:
    """
    Heuristic: try decoding a small sample as UTF-8 (with strict errors).
    If it decodes cleanly, treat as text. Otherwise, not text.
    """
    try:
        with file_path.open("rb") as f:
            chunk = f.read(sample_bytes)
        chunk.decode("utf-8")  # will raise UnicodeDecodeError if not text-like
        return True
    except Exception:
        return False

def read_text(path: Path) -> str:
    """
    Read a file as UTF-8 text. If decoding fails, fall back to 'utf-8' with replacement.
    """
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return path.read_text(encoding="utf-8", errors="replace")

def process_archive(archive_path: Path, output_dir: Path) -> None:
    base_name = archive_path.name
    # Strip the .tar.gz (or .tgz / .tar) safely
    out_stem = base_name
    for suffix in (".tar.gz", ".tgz", ".tar"):
        if out_stem.endswith(suffix):
            out_stem = out_stem[: -len(suffix)]
            break

    out_path = output_dir / f"{out_stem}.txt"
    # Ensure temp root exists (we'll place temp dirs inside the output dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    out_path = output_dir / f"{out_stem}.txt"
    # Create a simple, deterministic temp directory INSIDE the output directory
    output_dir.mkdir(parents=True, exist_ok=True)
    tmpdir = output_dir / f".extract_{out_stem}"
    if tmpdir.exists():
        shutil.rmtree(tmpdir, ignore_errors=True)
    tmpdir.mkdir(parents=True, exist_ok=True)
    try:

        # Extract
        try:
            with tarfile.open(archive_path, "r:*") as tf:
                tf.extractall(tmpdir)
        except tarfile.TarError as e:
            print(f"[WARN] Skipping {archive_path}: not a valid tar archive ({e})")
            return

        # Collect files (no directories), flattening subdirs
        file_paths = [p for p in tmpdir.rglob("*") if p.is_file()]

        if not file_paths:
            print(f"[WARN] {archive_path}: archive contained no files; skipping.")
            return

        # Keep only text-like files
        text_files = [p for p in file_paths if is_probably_text(p)]

        if not text_files:
            print(f"[WARN] {archive_path}: no text files detected; skipping.")
            return

        if len(text_files) == 1:
            # Single text file → stream copy
            output_dir.mkdir(parents=True, exist_ok=True)
            stream_copy_text(text_files[0], out_path, append=False)
            print(f"[OK] Wrote single-file output: {out_path}")
        else:
            # Multiple text files → concatenate in sorted path order
            text_files.sort(key=lambda p: str(p))
            output_dir.mkdir(parents=True, exist_ok=True)
            first = True
            for p in text_files:
                if not first:
                    with out_path.open("a", encoding="utf-8", newline="") as out_f:
                        out_f.write("\n")
                stream_copy_text(p, out_path, append=not first)
                first = False
            print(f"[OK] Wrote concatenated output ({len(text_files)} files): {out_path}")
    finally:
        # Clean up our temp directory to keep output_dir tidy
        shutil.rmtree(tmpdir, ignore_errors=True)

def main():
    parser = argparse.ArgumentParser(
        description="Process tar.gz archives of text files into single .txt outputs."
    )
    parser.add_argument("input_dir", type=Path, help="Directory containing .tar.gz files")
    parser.add_argument("output_dir", type=Path, help="Directory to write .txt outputs")
    args = parser.parse_args()

    input_dir: Path = args.input_dir
    output_dir: Path = args.output_dir

    if not input_dir.exists() or not input_dir.is_dir():
        raise SystemExit(f"Input directory does not exist or is not a directory: {input_dir}")

    archives = sorted(input_dir.glob("*.tar.gz"))
    # also support .tgz for convenience
    archives += sorted(input_dir.glob("*.tgz"))

    if not archives:
        print(f"[INFO] No .tar.gz or .tgz files found in {input_dir}. Nothing to do.")
        return

    for archive_path in archives:
        process_archive(archive_path, output_dir)

if __name__ == "__main__":
    main()
