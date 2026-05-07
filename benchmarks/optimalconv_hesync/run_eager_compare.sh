#!/bin/bash
set -u
cd "$(dirname "$0")"
mkdir -p sweep_logs

# Args mirror run_sweep.sh: resnet ker_wid=3 depth=20 wide_case=1 test_num=1 cf100=false
ARGS="resnet 3 20 1 1 false"

ts() { date -Iseconds; }

for mode in on off; do
    case "$mode" in
        on)  envval=1 ;;
        off) envval=0 ;;
    esac
    log="sweep_logs/eager_${mode}.log"
    echo "=== eager=${mode} starting at $(ts) -> $log ==="
    HESYNC_EAGER_PREFETCH="${envval}" GODEBUG=madvdontneed=1 \
        ./optimalconv_hesync $ARGS > "$log" 2>&1
    echo "=== eager=${mode} finished at $(ts) ==="
done
echo "=== both runs done at $(ts) ==="
