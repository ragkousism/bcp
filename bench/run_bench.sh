#!/bin/sh
set -e

usage() {
  echo "Usage: $0 sender|receiver [bcp_path] [sizes...]"
  echo "Examples:"
  echo "  $0 receiver ./bcp 64k 1m 100m 1g"
  echo "  $0 sender   ./bcp 64k 1m 100m 1g"
  exit 1
}

if [ $# -lt 1 ]; then
  usage
fi

MODE=$1
shift

BCP="./bcp"
if [ $# -gt 0 ] && [ -x "$1" ]; then
  BCP=$1
  shift
fi

SIZES="$*"
if [ -z "$SIZES" ]; then
  SIZES="64k 1m 100m 1g"
fi

BASE_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
DATA_DIR="$BASE_DIR/data"
LOG_DIR="$BASE_DIR/logs"

mkdir -p "$DATA_DIR" "$LOG_DIR"

DATA_SRC=${DATA_SRC:-/dev/zero}

TIME_BIN="time"
TIME_FLAG=""
if [ -x /usr/bin/time ]; then
  TIME_BIN=/usr/bin/time
  if $TIME_BIN -v true >/dev/null 2>&1; then
    TIME_FLAG="-v"
  elif $TIME_BIN -l true >/dev/null 2>&1; then
    TIME_FLAG="-l"
  fi
fi

run_with_time() {
  cmd=$1
  log=$2
  if [ "$TIME_BIN" = "time" ]; then
    ( time sh -c "$cmd" ) >>"$log" 2>&1
  else
    if [ -n "$TIME_FLAG" ]; then
      $TIME_BIN "$TIME_FLAG" sh -c "$cmd" >>"$log" 2>&1
    else
      $TIME_BIN sh -c "$cmd" >>"$log" 2>&1
    fi
  fi
}

make_file() {
  size=$1
  out=$2
  case "$size" in
    64k) dd if="$DATA_SRC" of="$out" bs=1024 count=64 ;;
    1m) dd if="$DATA_SRC" of="$out" bs=1048576 count=1 ;;
    100m) dd if="$DATA_SRC" of="$out" bs=1048576 count=100 ;;
    1g) dd if="$DATA_SRC" of="$out" bs=1048576 count=1024 ;;
    *)
      echo "Unknown size: $size"
      exit 1
      ;;
  esac
}

if [ ! -x "$BCP" ]; then
  echo "bcp not found or not executable: $BCP"
  exit 1
fi

case "$MODE" in
  sender)
    for size in $SIZES; do
      file="$DATA_DIR/bench_${size}.bin"
      if [ ! -f "$file" ]; then
        make_file "$size" "$file"
      fi
      log="$LOG_DIR/sender_${size}_$(date +%Y%m%d_%H%M%S).log"
      echo "=== sender $size $(date) ===" >>"$log"
      run_with_time "$BCP \"$file\"" "$log"
    done
    ;;
  receiver)
    cd "$DATA_DIR"
    for size in $SIZES; do
      log="$LOG_DIR/receiver_${size}_$(date +%Y%m%d_%H%M%S).log"
      echo "=== receiver $size $(date) ===" >>"$log"
      run_with_time "$BCP" "$log"
      if [ -z "${KEEP_FILES:-}" ]; then
        rm -f "bench_${size}.bin"
      fi
    done
    ;;
  *)
    usage
    ;;
esac
