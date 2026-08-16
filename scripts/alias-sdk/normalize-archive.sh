#!/usr/bin/env bash
set -euo pipefail

archive_format="${1:-}"
archive_path="${2:-}"
[[ -n "$archive_format" && -f "$archive_path" ]] || {
    echo "Usage: $0 {tar-gz|zip} ARCHIVE" >&2
    exit 2
}

for command_name in find sort touch; do
    command -v "$command_name" >/dev/null 2>&1 || {
        echo "Archive normalization failed: missing $command_name" >&2
        exit 1
    }
done

archive_path="$(cd "$(dirname "$archive_path")" && pwd)/$(basename "$archive_path")"
temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/alias-normalize.XXXXXX")"
trap 'rm -rf "$temporary_directory"' EXIT
source_directory="$temporary_directory/source"
mkdir -p "$source_directory"

normalize_times() {
    find "$source_directory" -exec touch -h -t 198001010000 {} +
}

case "$archive_format" in
    tar-gz)
        command -v tar >/dev/null 2>&1 || {
            echo "Archive normalization failed: missing tar" >&2
            exit 1
        }
        command -v gzip >/dev/null 2>&1 || {
            echo "Archive normalization failed: missing gzip" >&2
            exit 1
        }
        tar -xzf "$archive_path" -C "$source_directory"
        normalize_times
        if tar --version 2>&1 | grep -q 'GNU tar'; then
            tar_identity=(--owner=0 --group=0 --numeric-owner)
        else
            tar_identity=(--uid 0 --gid 0 --uname root --gname root)
        fi
        (
            cd "$source_directory"
            find . -mindepth 1 -print0 \
                | while IFS= read -r -d '' entry; do
                    printf '%s\0' "${entry#./}"
                done \
                | LC_ALL=C sort -z \
                | COPYFILE_DISABLE=1 tar \
                    --null \
                    --no-recursion \
                    "${tar_identity[@]}" \
                    --format ustar \
                    -T - \
                    -cf - \
                | gzip -n -9 >"$temporary_directory/archive.tar.gz"
        )
        if tar -tzf "$temporary_directory/archive.tar.gz" | grep -Eq '^(\./|/)'; then
            echo "Archive normalization failed: archive contains a non-canonical path" >&2
            exit 1
        fi
        mv "$temporary_directory/archive.tar.gz" "$archive_path"
        ;;
    zip)
        command -v unzip >/dev/null 2>&1 || {
            echo "Archive normalization failed: missing unzip" >&2
            exit 1
        }
        command -v zip >/dev/null 2>&1 || {
            echo "Archive normalization failed: missing zip" >&2
            exit 1
        }
        unzip -q "$archive_path" -d "$source_directory"
        normalize_times
        (
            cd "$source_directory"
            find . \( -type f -o -type l \) -print \
                | LC_ALL=C sort \
                | zip -X -q -9 -y "$temporary_directory/archive.zip" -@
        )
        mv "$temporary_directory/archive.zip" "$archive_path"
        ;;
    *)
        echo "Archive normalization failed: expected tar-gz or zip" >&2
        exit 2
        ;;
esac

echo "Normalized $archive_format archive at $archive_path"
