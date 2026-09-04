#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "$(dirname -- "${BASH_SOURCE[0]}")")" && pwd)
test_root=$(mktemp -d)
trap 'rm -rf "$test_root"' EXIT

assert_eq() {
    if [ "$1" != "$2" ]; then
        printf 'expected %s, got %s\n' "$2" "$1" >&2
        exit 1
    fi
}

run_case() {
    local name=$1 profile=$2 profiles=$3 game_status=$4 expected_status=$5 expected_set=$6 expected_launch=$7
    local screensaver=${8:-1}
    local bin="$test_root/$name" log="$test_root/$name.log"
    mkdir -p "$bin"
    : > "$log"
    cat > "$bin/powerprofilesctl" <<EOF
#!/usr/bin/env bash
case "\$1" in
    get) printf '%s\\n' '$profile' ;;
    list) printf '%s\\n' '$profiles' ;;
    set) printf 'set:%s\\n' "\$2" >> '$log' ;;
    launch)
        printf 'launch\\n' >> '$log'
        exit '$game_status'
        ;;
esac
EOF
    cat > "$bin/systemd-inhibit" <<EOF
#!/usr/bin/env bash
printf 'inhibit\\n' >> '$log'
while [ "\$1" != -- ] && [ "\$1" != powerprofilesctl ]; do shift; done
if [ "\$1" = -- ]; then shift; fi
"\$@"
EOF
    cat > "$bin/game" <<EOF
#!/usr/bin/env bash
printf 'game\\n' >> '$log'
printf 'arg:%s\\n' "\$@" >> '$log'
exit '$game_status'
EOF
    chmod +x "$bin"/*

    set +e
    if [ "$screensaver" = 1 ]; then
        PATH="$bin:/usr/bin" GAME_PERFORMANCE_SCREENSAVER_ON=1 "$script_dir/usr/bin/game-performance" game "argument with spaces"
    else
        PATH="$bin:/usr/bin" "$script_dir/usr/bin/game-performance" game "argument with spaces"
    fi
    local actual_status=$?
    set -e
    assert_eq "$actual_status" "$expected_status"
    local actual_set actual_launch
    actual_set=$(grep -c '^set:' "$log" || true)
    actual_launch=$(grep -c '^launch$' "$log" || true)
    assert_eq "$actual_set" "$expected_set"
    assert_eq "$actual_launch" "$expected_launch"
}

run_case initial-performance performance 'balanced: performance: power-saver:' 0 0 0 0
run_case initial-balanced balanced 'balanced: performance: power-saver:' 0 0 1 1
run_case initial-power-saver power-saver 'balanced: performance: power-saver:' 0 0 1 1
run_case game-fails balanced 'balanced: performance: power-saver:' 7 7 1 1
run_case no-performance balanced 'balanced:' 0 0 0 0
grep -Fqx 'arg:argument with spaces' "$test_root/no-performance.log"
run_case default-inhibit balanced 'balanced: performance:' 0 0 1 1 0

signal_case() {
    local bin="$test_root/signal" log="$test_root/signal.log" wrapper_pid child_pid wrapper_status
    mkdir -p "$bin"
    : > "$log"
    cat > "$bin/powerprofilesctl" <<EOF
#!/usr/bin/env bash
case "\$1" in
    get) printf 'balanced\\n' ;;
    list) printf 'balanced: performance:\\n' ;;
    set) printf 'set:%s\\n' "\$2" >> '$log' ;;
    launch)
        printf 'launch\\n' >> '$log'
        "$bin/game" &
        child_pid=\$!
        terminate() {
            kill -TERM "\$child_pid" 2>/dev/null || true
            wait "\$child_pid" 2>/dev/null || true
            printf 'launch-return\\n' >> '$log'
            exit 143
        }
        trap terminate TERM INT
        wait "\$child_pid"
        launch_status=\$?
        printf 'launch-return\\n' >> '$log'
        exit "\$launch_status"
        ;;
esac
EOF
    cat > "$bin/game" <<EOF
#!/usr/bin/env bash
printf '%s\\n' "\$BASHPID" > '$test_root/signal-child.pid'
trap 'printf "child-stopped\\n" >> "$log"; exit 143' TERM INT
while :; do sleep 1; done
EOF
    chmod +x "$bin"/*

    PATH="$bin:/usr/bin" GAME_PERFORMANCE_SCREENSAVER_ON=1 \
        /usr/bin/bash "$script_dir/usr/bin/game-performance" game &
    wrapper_pid=$!
    for _ in {1..50}; do
        [ -s "$test_root/signal-child.pid" ] && break
        sleep 0.02
    done
    child_pid=$(cat "$test_root/signal-child.pid")
    kill -TERM "$wrapper_pid"
    set +e
    wait "$wrapper_pid"
    wrapper_status=$?
    set -e
    assert_eq "$wrapper_status" 143
    if kill -0 "$child_pid" 2>/dev/null; then
        printf 'signal child remained alive: %s\\n' "$child_pid" >&2
        exit 1
    fi
    local child_line set_line launch_return_line
    child_line=$(grep -n '^child-stopped$' "$log" | cut -d: -f1 | head -1)
    launch_return_line=$(grep -n '^launch-return$' "$log" | cut -d: -f1 | head -1)
    set_line=$(grep -n '^set:balanced$' "$log" | cut -d: -f1 | head -1)
    [ -n "$child_line" ] && [ -n "$launch_return_line" ] && [ -n "$set_line" ]
    [ "$child_line" -lt "$launch_return_line" ] && [ "$launch_return_line" -lt "$set_line" ]
}

signal_case

missing="$test_root/missing"
mkdir -p "$missing"
set +e
PATH="$missing" GAME_PERFORMANCE_SCREENSAVER_ON=1 /usr/bin/bash "$script_dir/usr/bin/game-performance" game >/dev/null 2>&1
missing_status=$?
set -e
assert_eq "$missing_status" 1

printf 'game-performance tests: PASS\n'
