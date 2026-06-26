#!/usr/bin/env bash
set -euo pipefail

DOCS_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT_FILE="$DOCS_DIR/k8sgrade-walkthrough.mp4"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/k8sgrade-video.XXXXXX")"
trap 'rm -rf "$WORK_DIR"' EXIT

PYTHON_BIN="${PYTHON_BIN:-/usr/local/bin/python3}"
if [[ ! -x "$PYTHON_BIN" ]]; then
  PYTHON_BIN="$(command -v python3 || true)"
fi

for cmd in ffmpeg ffprobe say; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Missing required command: $cmd" >&2
    exit 1
  fi
done

if [[ -z "$PYTHON_BIN" ]] || [[ ! -x "$PYTHON_BIN" ]]; then
  echo "Missing required command: python3" >&2
  exit 1
fi

choose_voice() {
  local requested="${VOICE:-}"
  local available

  if [[ -n "$requested" ]]; then
    if say -v '?' | awk '{print $1}' | grep -Fxq "$requested"; then
      printf '%s' "$requested"
      return 0
    fi
    echo "WARNING: requested voice '$requested' is not available; selecting best Indian fallback." >&2
  fi

  for available in Rishi Lekha; do
    if say -v '?' | awk '{print $1}' | grep -Fxq "$available"; then
      printf '%s' "$available"
      return 0
    fi
  done

  printf '%s' "Samantha"
}

NARRATION_VOICE="$(choose_voice)"
echo "Using voice: $NARRATION_VOICE"

"$PYTHON_BIN" "$DOCS_DIR/render_video_slides.py" "$WORK_DIR"

make_segment() {
  local idx="$1"
  local narration="$2"

  local image_file="$WORK_DIR/slide-${idx}.png"
  local audio_file="$WORK_DIR/slide-${idx}.aiff"
  local seg_file="$WORK_DIR/seg-${idx}.mp4"
  local duration_raw=""
  local duration=""

  if [[ ! -f "$image_file" ]]; then
    echo "ERROR: missing slide image: $image_file" >&2
    exit 1
  fi

  say -v "$NARRATION_VOICE" -r 168 -o "$audio_file" "$narration"

  duration_raw="$(ffprobe -v error -show_entries format=duration -of default=noprint_wrappers=1:nokey=1 "$audio_file")"
  duration="$(awk -v d="$duration_raw" 'BEGIN { printf "%.2f", d + 1.2 }')"

  ffmpeg -y \
    -loop 1 -framerate 30 -i "$image_file" \
    -i "$audio_file" \
    -t "$duration" \
    -c:v libx264 -pix_fmt yuv420p -r 30 \
    -c:a aac -b:a 160k -shortest \
    "$seg_file" >/dev/null 2>&1

  printf "file '%s'\n" "$seg_file" >> "$WORK_DIR/segments.txt"
}

: > "$WORK_DIR/segments.txt"

make_segment 01 \
  "This is k8sgrade. It is a Bash based Kubernetes health and security scoring tool that inspects a namespace and gives practical recommendations."

make_segment 02 \
  "Here is the direct run example. If you already know context and namespace, pass c and n flags for repeatable automated checks."

make_segment 03 \
  "This example enables Trivy and exports CSV. It captures vulnerability signals and stores the score breakdown for reporting."

make_segment 04 \
  "This slide shows sample output sections, including nodes, pending pods, restarts, and critical image findings."

make_segment 05 \
  "The final score maps to grade bands from A plus to F. Use the recommendation list to prioritize quick wins first."

make_segment 06 \
  "Start with interactive mode, then use direct mode and CSV export for ongoing cluster posture checks in operations and CI pipelines."

ffmpeg -y -f concat -safe 0 -i "$WORK_DIR/segments.txt" -c:v libx264 -pix_fmt yuv420p -c:a aac -b:a 160k "$OUT_FILE" >/dev/null 2>&1

echo "Created video: $OUT_FILE"
