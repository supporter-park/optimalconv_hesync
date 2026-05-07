#!/bin/bash
set -u
cd "$(dirname "$0")"
mkdir -p sweep_logs
for i in 1 2 3; do
    log="sweep_logs/sweep_run${i}.log"
    echo "=== sweep run ${i} starting at $(date -Iseconds) ==="
    GODEBUG=madvdontneed=1 ./optimalconv_hesync resnet 3 20 1 1 false > "$log" 2>&1
    echo "=== sweep run ${i} finished at $(date -Iseconds) (log: $log) ==="
done
echo "=== all 3 sweeps done at $(date -Iseconds) ==="
