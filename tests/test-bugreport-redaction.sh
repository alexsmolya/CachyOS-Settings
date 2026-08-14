#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=../usr/bin/cachyos-bugreport.sh
source "$repo_root/usr/bin/cachyos-bugreport.sh"
original_collect_sensitive_values=$(declare -f collect_sensitive_values)

test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' EXIT

collect_sensitive_values() {
    cat <<'EOF'
<home-dir-redacted>	/home/alex
<username-redacted>	alex
<ip-address-redacted>	192.0.2.44
<ip-address-redacted>	2001:db8::44
<mac-address-redacted>	02:11:22:33:44:55
<machine-id-redacted>	0123456789abcdef0123456789abcdef
<uuid-redacted>	ABCD-1234
<ssid-redacted>	cachyos
<usb-serial-redacted>	CURRENT-USB-123
EOF
}

LOG_FILENAME="$test_dir/report.log"
cat >"$LOG_FILENAME" <<'EOF'
uname: Linux cachyos 7.1.6-1-cachyos #1 SMP PREEMPT_DYNAMIC x86_64 GNU/Linux
repo cachyos-v4 package linux-cachyos kernel 7.1.6-1-cachyos
firmware version 6.18.44.1
Host Name: cachyos
systemd: Set hostname to cachyos.
home=/home/alex/config user=alex allocation=ok
current IPv4=192.0.2.44 current IPv6=2001:db8::44
MAC=02:11:22:33:44:55 machine=0123456789abcdef0123456789abcdef
filesystem UUID=ABCD-1234 standard=123e4567-e89b-12d3-a456-426614174000 historical PARTUUID=DEAD-BEEF
connected to cachyos; SerialNumber: CURRENT-USB-123
old firewall SRC=198.51.100.22 DST=2001:db8::99 MAC=AA:BB:CC:DD:EE:FF
old lease address=10.2.3.4 gateway=2001:db8::1
old wifi SSID="Old Cafe" and access point 'Older Cafe'
old device Serial Number: OLD-USB-456
machine-id=abcdefabcdefabcdefabcdefabcdefab
opened QUrl("file:///mnt/private/one") then QUrl("file:///home/alex/two") safely
contact maintainer@example.org
EOF

redact >/dev/null

cat >"$test_dir/expected.log" <<'EOF'
uname: Linux <hostname-redacted> 7.1.6-1-cachyos #1 SMP PREEMPT_DYNAMIC x86_64 GNU/Linux
repo cachyos-v4 package linux-cachyos kernel 7.1.6-1-cachyos
firmware version 6.18.44.1
Host Name: <hostname-redacted>
systemd: Set hostname to <hostname-redacted>.
home=<home-dir-redacted>/config user=<username-redacted> allocation=ok
current IPv4=<ip-address-redacted> current IPv6=<ip-address-redacted>
MAC=<mac-address-redacted> machine=<machine-id-redacted>
filesystem UUID=<uuid-redacted> standard=<uuid-redacted> historical PARTUUID=<uuid-redacted>
connected to <ssid-redacted>; SerialNumber: <usb-serial-redacted>
old firewall SRC=<ip-address-redacted> DST=<ip-address-redacted> MAC=<mac-address-redacted>
old lease address=<ip-address-redacted> gateway=<ip-address-redacted>
old wifi SSID=<ssid-redacted> and access point '<ssid-redacted>'
old device Serial Number: <usb-serial-redacted>
machine-id=<machine-id-redacted>
opened QUrl("file://<path-redacted>") then QUrl("file://<path-redacted>") safely
contact <email-address-redacted>
EOF

diff -u "$test_dir/expected.log" "$LOG_FILENAME"

eval "$original_collect_sensitive_values"
SUDO_USER=root
ip() {
    printf '%s\n' '2: eth0 inet 192.0.2.55/24 scope global eth0' '2: eth0 inet6 2001:db8::55/64 scope global'
}
lsblk() { printf '%s\n' 'MOCK-UUID'; }
nmcli() { printf '%s\n' '802-11-wireless:Cafe:Lab'; }
udevadm() { printf '%s\n' 'E: ID_SERIAL_SHORT=MOCK-USB'; }
inventory=$(collect_sensitive_values)
grep -Fxq $'<ip-address-redacted>\t192.0.2.55' <<<"$inventory"
grep -Fxq $'<ip-address-redacted>\t2001:db8::55' <<<"$inventory"
grep -Fxq $'<uuid-redacted>\tMOCK-UUID' <<<"$inventory"
grep -Fxq $'<ssid-redacted>\tCafe:Lab' <<<"$inventory"
grep -Fxq $'<usb-serial-redacted>\tMOCK-USB' <<<"$inventory"

collect_sensitive_values() { :; }
LOG_FILENAME="$test_dir/empty-inventory.log"
printf '%s\n' 'plain diagnostic text remains intact' >"$LOG_FILENAME"
redact >/dev/null
grep -Fxq 'plain diagnostic text remains intact' "$LOG_FILENAME"

printf '%s\n' 'bugreport redaction tests: PASS'
