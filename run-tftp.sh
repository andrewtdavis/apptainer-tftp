#!/usr/bin/env bash
#
# run-tftp.sh
#
# SYNOPSIS
#   run-tftp.sh [--path DIR] [--bind IP] [--log]
#               [--arista] [--aruba] [--brocade] [--cisco]
#               [--dell-switch] [--extreme] [--fortinet]
#               [--juniper] [--paloalto] [--supportassist]
#               [--ubiquiti]
#
# DESCRIPTION
#   Helper script to:
#     - Build an Apptainer-based TFTP server image if missing (non-root, requires internet)
#     - Run a disposable TFTP server in an Apptainer container
#     - Bind the TFTP server to a specific directory on the host
#     - Optionally bind TFTP to a single IP/interface and open TFTP only on that interface:
#         * firewalld if present (RHEL/Rocky/CentOS/Alma/etc.)
#         * ufw if present (Ubuntu/Debian)
#     - Optionally enable file logging (tftp.log in the chosen directory)
#     - Print vendor/device-specific example commands for common uses
#     - Clean up firewall rules on exit (Ctrl-C)
#
# EXAMPLES
#   Build image (first run will prompt) and run with defaults:
#     ./run-tftp.sh
#
#   Run TFTP bound to 192.168.1.1 and store files in ~/documents/firmware:
#     ./run-tftp.sh --bind 192.168.1.1 --path "$HOME/documents/firmware"
#
#   Same as above, with file logging and Dell SupportAssist + Cisco examples:
#     ./run-tftp.sh --bind 192.168.1.1 \
#                   --path "$HOME/documents/firmware" \
#                   --log \
#                   --supportassist --cisco
#
# NOTES
#   - Building the Apptainer image requires internet access to pull rockylinux:9.
#   - Requires Apptainer to be installed on the host:
#       RHEL/Rocky:    sudo dnf install apptainer
#       Ubuntu/Debian: sudo apt install apptainer
#   - Uses firewalld if available; otherwise uses ufw if available.
#     If neither is present, no firewall changes are made.
#   - The TFTP server listens on UDP port 69 inside the container.
#   - The script prints all instructions and vendor examples first,
#     then runs `apptainer run` in the foreground. Ctrl-C stops the
#     server and triggers firewall cleanup.
#
# AUTHOR
#   Andrew Davis <andrew.davis@gladstone.ucsf.edu>
#

set -euo pipefail

# ------------------------------------------------------------------------
# APPTAINER PRESENCE CHECK
# ------------------------------------------------------------------------

if ! command -v apptainer >/dev/null 2>&1; then
    echo "Error: apptainer is not installed or not in PATH."
    echo "Install it first, e.g.:"
    echo "  RHEL/Rocky:    sudo dnf install apptainer"
    echo "  Ubuntu/Debian: sudo apt install apptainer"
    exit 1
fi

# ------------------------------------------------------------------------
# USER CONFIGURATION
# ------------------------------------------------------------------------

IMAGE="tftp-rhel9.sif"
DEF_FILE="tftp-rhel9.def"

# Optional static IP to advertise in examples.
# Leave empty to rely on auto-detection or --bind.
HOST_IP=""

# ------------------------------------------------------------------------
# PHASE 1: BUILD IMAGE IF MISSING (NO ROOT REQUIRED)
# ------------------------------------------------------------------------

if [[ ! -f "$IMAGE" ]]; then
    echo "Apptainer image '$IMAGE' not found."
    echo "This script can build it for you (requires internet to pull rockylinux:9)."
    read -r -p "Build '$IMAGE' now? [y/N] " REPLY
    case "$REPLY" in
        [yY][eE][sS]|[yY])
            echo "Writing Apptainer definition to '$DEF_FILE'..."
            cat >"$DEF_FILE" <<'DEFEOF'
Bootstrap: docker
From: rockylinux:9

%post
    dnf -y install python3-pip
    pip3 install --no-cache-dir tftpy

    mkdir -p /usr/local/bin

    cat >/usr/local/bin/start-tftp.sh <<'EOF'
#!/usr/bin/env bash
set -e

TFTP_ROOT=${TFTP_ROOT:-/tmp}
TFTP_PORT=${TFTP_PORT:-69}
TFTP_BIND_IP=${TFTP_BIND_IP:-0.0.0.0}
TFTP_FILE_LOG=${TFTP_FILE_LOG:-0}

mkdir -p "$TFTP_ROOT"
chmod 777 "$TFTP_ROOT"

echo "Starting TFTP server on ${TFTP_BIND_IP}:${TFTP_PORT}"
echo "Serving directory: $TFTP_ROOT"
if [ "$TFTP_FILE_LOG" != "0" ]; then
    echo "File logging enabled (tftp.log in TFTP_ROOT)."
else
    echo "File logging disabled (stdout/stderr only)."
fi
echo "Ctrl-C to stop."


python3 - <<'PYEOF'
import os
import logging
import datetime
import tftpy

root = os.environ.get("TFTP_ROOT", "/tmp")
port = int(os.environ.get("TFTP_PORT", "69"))
bind_ip = os.environ.get("TFTP_BIND_IP", "0.0.0.0")
file_log_flag = os.environ.get("TFTP_FILE_LOG", "0")

os.makedirs(root, exist_ok=True)

#
# Logging – keep session-level info, drop per-block noise
#
class TftpNoiseFilter(logging.Filter):
    noisy_substrings = [
        "sending dat", "received dat", "received ack",
        "sending ack", "handling dat packet", "send ack to block",
        "sending ack to block", "handling ack packet",
        "blocknumber", "blkno",
    ]
    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage().lower()
        return not any(s in msg for s in self.noisy_substrings)

fmt = logging.Formatter(
    "%(asctime)s %(levelname)s [%(name)s] %(message)s",
    "%Y-%m-%d %H:%M:%S",
)

# tftpy's logger (connect + summary stats)
tftpy_log = logging.getLogger("tftpy")
tftpy_log.setLevel(logging.INFO)

console = logging.StreamHandler()
console.setFormatter(fmt)
console.addFilter(TftpNoiseFilter())
tftpy_log.addHandler(console)

# Our wrapper logger for extra messages
log = logging.getLogger("tftp-wrapper")
log.setLevel(logging.INFO)
log.addHandler(console)

# Optional file logging
if file_log_flag not in ("0", "", "false", "False", "no", "NO"):
    log_file = os.path.join(root, "tftp.log")
    fh = logging.FileHandler(log_file)
    fh.setFormatter(fmt)
    fh.addFilter(TftpNoiseFilter())
    tftpy_log.addHandler(fh)
    log.addHandler(fh)
    log.info("File logging enabled: %s", log_file)
else:
    log.info("File logging disabled (stdout/stderr only)")

#
# ---- FILE NAMING & COLLISION AVOIDANCE ----
#

def make_prefixed_name(client_ip: str, path: str) -> str:
    """
    Build <client-ip>-Tyyyymmddhhmmss-filename
    """
    ts = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    base = os.path.basename(str(path)) or "unnamed"
    base = base.replace("..", "_")
    return f"{client_ip}-T{ts}-{base}"

def unique_path(path: str) -> str:
    """
    Ensure we don't overwrite an existing file:
      foo -> foo.1 -> foo.2 -> ...
    """
    if not os.path.exists(path):
        return path
    base = path
    idx = 1
    while os.path.exists(path):
        path = f"{base}.{idx}"
        idx += 1
    return path

#
# upload_open hook – signature for this tftpy:
#   upload_open(path, context)
#
def upload_open(path, context):
    client_ip = getattr(context, "host", "unknown")
    prefixed = make_prefixed_name(client_ip, path)
    full_path = unique_path(os.path.join(root, prefixed))

    log.info(
        "Starting upload from %s: remote='%s' -> local='%s'",
        client_ip,
        os.path.basename(str(path)),
        os.path.basename(full_path),
    )

    # tftpy will write into this file and log end-of-transfer stats
    return open(full_path, "wb")

log.info(
    "TFTP server starting on %s:%s, root=%s",
    bind_ip, port, root,
)

server = tftpy.TftpServer(
    tftproot=root,
    upload_open=upload_open,
)

server.listen(bind_ip, port)
PYEOF
EOF

    chmod +x /usr/local/bin/start-tftp.sh

%runscript
    exec /usr/local/bin/start-tftp.sh
DEFEOF

            echo "Building Apptainer image '$IMAGE' (requires internet)..."
            apptainer build "$IMAGE" "$DEF_FILE"
            echo "Image '$IMAGE' built successfully."
            ;;
        *)
            echo "Not building image. Please build '$IMAGE' manually or rerun and answer 'y'."
            exit 1
            ;;
    esac
fi

# ------------------------------------------------------------------------
# PHASE 2: ROOT CHECK AND RE-EXEC
# ------------------------------------------------------------------------

if [[ $EUID -ne 0 ]]; then
    echo "Re-running as root with sudo..."
    exec sudo "$0" "$@"
fi

# ------------------------------------------------------------------------
# PHASE 3: RUNTIME LOGIC (RUNS AS ROOT)
# ------------------------------------------------------------------------

HOST_PATH="/tmp"

FW_OPENED=0
FW_BACKEND="none"   # "firewalld", "ufw", or "none"
FW_ZONE=""
UFW_RULE=""
IFACE=""

BIND_IP=""
ENABLE_FILE_LOG=0

# vendor flags (alphabetical by flag name)
FLAG_ARISTA=0
FLAG_ARUBA=0
FLAG_BROCADE=0
FLAG_CISCO=0
FLAG_DELLSWITCH=0
FLAG_EXTREME=0
FLAG_FORTINET=0
FLAG_JUNIPER=0
FLAG_PALOALTO=0
FLAG_SUPPORTASSIST=0
FLAG_UBIQUITI=0

usage() {
    cat <<EOF
Usage: $(basename "$0") [--path /path/to/store/uploads] [--bind IP] [--log]
                        [--arista] [--aruba] [--brocade] [--cisco]
                        [--dell-switch] [--extreme] [--fortinet]
                        [--juniper] [--paloalto] [--supportassist]
                        [--ubiquiti]

Options:
  --path PATH        Host directory for TFTP uploads (default: /tmp)
  --bind IP          IP address to bind TFTP to and use in example URLs
  --log              Enable file logging (tftp.log in the chosen path)

  --arista           Print Arista EOS config-to-TFTP example
  --aruba            Print Aruba / HPE ProCurve config-to-TFTP examples
  --brocade          Print Brocade / ICX / FastIron config-to-TFTP example
  --cisco            Print Cisco IOS/IOS-XE/NX-OS TFTP examples
  --dell-switch      Print Dell Networking (OS10/FTOS/N-Series) example
  --extreme          Print Extreme Networks ExtremeXOS examples
  --fortinet         Print FortiGate backup-to-TFTP example
  --juniper          Print Junos config-to-TFTP example
  --paloalto         Print Palo Alto PAN-OS TFTP image-loading note/example
  --supportassist    Print Dell iDRAC SupportAssist example
  --ubiquiti         Print Ubiquiti EdgeSwitch-style example

  -h, --help         Show this help

Examples:
  $(basename "$0")
  $(basename "$0") --path "\$HOME/documents/firmware"
  $(basename "$0") --bind 192.168.1.1 --path "\$HOME/documents/firmware" --log --supportassist --cisco
EOF
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --path)
            if [[ $# -lt 2 ]]; then
                echo "Error: --path requires a directory" >&2
                exit 1
            fi
            HOST_PATH="$2"
            shift 2
            ;;
        --bind|--bind-ip)
            if [[ $# -lt 2 ]]; then
                echo "Error: --bind requires an IP address" >&2
                exit 1
            fi
            BIND_IP="$2"
            shift 2
            ;;
        --log)
            ENABLE_FILE_LOG=1
            shift 1
            ;;
        --arista)
            FLAG_ARISTA=1
            shift 1
            ;;
        --aruba)
            FLAG_ARUBA=1
            shift 1
            ;;
        --brocade)
            FLAG_BROCADE=1
            shift 1
            ;;
        --cisco)
            FLAG_CISCO=1
            shift 1
            ;;
        --dell-switch)
            FLAG_DELLSWITCH=1
            shift 1
            ;;
        --extreme)
            FLAG_EXTREME=1
            shift 1
            ;;
        --fortinet)
            FLAG_FORTINET=1
            shift 1
            ;;
        --juniper)
            FLAG_JUNIPER=1
            shift 1
            ;;
        --paloalto)
            FLAG_PALOALTO=1
            shift 1
            ;;
        --supportassist|-supportassist)
            FLAG_SUPPORTASSIST=1
            shift 1
            ;;
        --ubiquiti)
            FLAG_UBIQUITI=1
            shift 1
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            usage
            exit 1
            ;;
    esac
done

# Expand ~ (in case it wasn't expanded by the shell)
HOST_PATH="${HOST_PATH/#\~/$HOME}"
mkdir -p "$HOST_PATH"
chmod 777 "$HOST_PATH" || true

cleanup() {
    echo
    echo "Cleaning up..."
    if [[ "$FW_OPENED" -eq 1 ]]; then
        if [[ "$FW_BACKEND" == "firewalld" ]] && command -v firewall-cmd >/dev/null 2>&1; then
            if [[ -n "$FW_ZONE" ]]; then
                echo "Removing firewalld rule from zone '$FW_ZONE'..."
                firewall-cmd --zone="$FW_ZONE" --remove-service=tftp >/dev/null 2>&1 || true
            else
                echo "Removing firewalld rule from default zone..."
                firewall-cmd --remove-service=tftp >/dev/null 2>&1 || true
            fi
        elif [[ "$FW_BACKEND" == "ufw" ]] && command -v ufw >/dev/null 2>&1 && [[ -n "$UFW_RULE" ]]; then
            echo "Removing ufw rule: ufw delete $UFW_RULE"
            ufw delete $UFW_RULE >/dev/null 2>&1 || true
        fi
    fi
    echo "Done."
}
trap cleanup EXIT

# Resolve HOST_IP / BIND_IP relationship
if [[ -z "$HOST_IP" && -z "$BIND_IP" ]]; then
    if command -v ip >/dev/null 2>&1; then
        DETECTED=$(ip route get 1.1.1.1 2>/dev/null | awk '/src/ {print $7; exit}' || true)
        [[ -n "${DETECTED:-}" ]] && HOST_IP="$DETECTED" && BIND_IP="$DETECTED"
    fi
elif [[ -z "$HOST_IP" && -n "$BIND_IP" ]]; then
    HOST_IP="$BIND_IP"
elif [[ -n "$HOST_IP" && -z "$BIND_IP" ]]; then
    BIND_IP="$HOST_IP"
fi

[[ -z "$HOST_IP" ]] && HOST_IP="<your-server-ip>"

# Determine interface for BIND_IP if we have one
if [[ -n "$BIND_IP" ]] && command -v ip >/dev/null 2>&1; then
    IFACE=$(ip -o -4 addr show | awk -v ip="$BIND_IP" '
        {
            split($4, a, "/");
            if (a[1] == ip) { print $2; exit }
        }')
fi

# Detect firewall backend
if command -v firewall-cmd >/dev/null 2>&1; then
    FW_BACKEND="firewalld"
elif command -v ufw >/dev/null 2>&1; then
    FW_BACKEND="ufw"
else
    FW_BACKEND="none"
fi

# Setup firewall rule depending on backend
if [[ "$FW_BACKEND" == "firewalld" ]]; then
    if [[ -n "$BIND_IP" && -n "${IFACE:-}" ]]; then
        ZONE=$(firewall-cmd --get-zone-of-interface="$IFACE" 2>/dev/null || true)
        if [[ -n "$ZONE" ]]; then
            echo "Adding TFTP service to firewalld zone '$ZONE' (interface $IFACE, IP $BIND_IP)..."
            firewall-cmd --zone="$ZONE" --add-service=tftp
            FW_OPENED=1
            FW_ZONE="$ZONE"
        else
            echo "Interface zone not detected; using default firewalld zone."
            firewall-cmd --add-service=tftp
            FW_OPENED=1
        fi
    else
        echo "No bind IP or interface detected; adding TFTP to default firewalld zone."
        firewall-cmd --add-service=tftp
        FW_OPENED=1
    fi
elif [[ "$FW_BACKEND" == "ufw" ]]; then
    if [[ -n "$IFACE" ]]; then
        UFW_RULE="allow in on $IFACE to any port 69 proto udp"
    else
        UFW_RULE="allow 69/udp"
    fi
    echo "Adding ufw rule: ufw $UFW_RULE"
    ufw $UFW_RULE || echo "Warning: ufw rule may not have been applied."
    FW_OPENED=1
else
    echo "No firewalld or ufw detected; skipping firewall configuration."
fi

echo
echo "TFTP upload directory (host): $HOST_PATH"
echo "TFTP upload directory (container): /tmp"
if [[ "$ENABLE_FILE_LOG" -eq 1 ]]; then
    echo "File logging: enabled (host log at $HOST_PATH/tftp.log)"
else
    echo "File logging: disabled (stdout/stderr only)"
fi
[[ -n "$BIND_IP" ]] && echo "TFTP binding to IP: $BIND_IP"
echo
echo "Generic TFTP URL:"
echo "  tftp://$HOST_IP/<filename>"
echo

# Vendor / use-case specific examples (alphabetical by flag)

if [[ "$FLAG_ARISTA" -eq 1 ]]; then
    echo "Arista EOS example (on the switch):"
    echo "  copy running-config tftp://$HOST_IP/<hostname>-running.cfg"
    echo
fi

if [[ "$FLAG_ARUBA" -eq 1 ]]; then
    echo "Aruba / HPE ProCurve examples:"
    echo "  copy running-config tftp $HOST_IP <switchname>-running.cfg"
    echo "  copy startup-config tftp $HOST_IP <switchname>-startup.cfg"
    echo
fi

if [[ "$FLAG_BROCADE" -eq 1 ]]; then
    echo "Brocade / ICX / FastIron example:"
    echo "  copy running-config tftp $HOST_IP <switchname>-running.cfg"
    echo
fi

if [[ "$FLAG_CISCO" -eq 1 ]]; then
    echo "Cisco IOS / IOS-XE / NX-OS examples:"
    echo "  copy running-config tftp:"
    echo "    Address or name of remote host []? $HOST_IP"
    echo "    Destination filename [running-config]? <hostname>-running.cfg"
    echo
    echo "One-liner (if supported):"
    echo "  copy running-config tftp://$HOST_IP/<hostname>-running.cfg"
    echo
fi

if [[ "$FLAG_DELLSWITCH" -eq 1 ]]; then
    echo "Dell Networking OS10 / FTOS / N-Series example:"
    echo "  copy running-config tftp://$HOST_IP/<hostname>-running.cfg"
    echo
fi

if [[ "$FLAG_EXTREME" -eq 1 ]]; then
    echo "Extreme Networks ExtremeXOS examples:"
    echo "  save configuration tftp://$HOST_IP/<hostname>-running.cfg"
    echo "  tftp put <hostname>-running.cfg $HOST_IP vr VR-Default"
    echo
fi

if [[ "$FLAG_FORTINET" -eq 1 ]]; then
    echo "Fortinet FortiGate example:"
    echo "  execute backup config tftp <hostname>-config.conf $HOST_IP"
    echo
fi

if [[ "$FLAG_JUNIPER" -eq 1 ]]; then
    echo "Juniper Junos example:"
    echo "  file copy /config/juniper.conf.gz tftp://$HOST_IP/juniper.conf.gz"
    echo
fi

if [[ "$FLAG_PALOALTO" -eq 1 ]]; then
    echo "Palo Alto PAN-OS note (TFTP mainly for image loading):"
    echo "  In maintenance / boot loader mode, you can pull images via TFTP, e.g.:"
    echo "    > tftp get $HOST_IP <panos-image-file>"
    echo "  For normal config backups, prefer SCP/SFTP/HTTPS."
    echo
fi

if [[ "$FLAG_SUPPORTASSIST" -eq 1 ]]; then
    echo "Dell iDRAC SupportAssist example (from idrac via ssh):"
    echo "  racadm supportassist exportlastcollection -l tftp://$HOST_IP/"
    echo
fi

if [[ "$FLAG_UBIQUITI" -eq 1 ]]; then
    echo "Ubiquiti EdgeSwitch-style example:"
    echo "  copy running-config tftp:"
    echo "    Address or name of remote host []? $HOST_IP"
    echo "    Destination filename [running-config]? <hostname>-running.cfg"
    echo
fi

if [[ "$FLAG_ARISTA" -eq 0 && "$FLAG_ARUBA" -eq 0 && "$FLAG_BROCADE" -eq 0 && \
      "$FLAG_CISCO" -eq 0 && "$FLAG_DELLSWITCH" -eq 0 && "$FLAG_EXTREME" -eq 0 && \
      "$FLAG_FORTINET" -eq 0 && "$FLAG_JUNIPER" -eq 0 && "$FLAG_PALOALTO" -eq 0 && \
      "$FLAG_SUPPORTASSIST" -eq 0 && "$FLAG_UBIQUITI" -eq 0 ]]; then
    echo "No vendor flags specified; use the generic URL above in your device's TFTP command."
    echo
fi

echo "Press Ctrl-C to stop the TFTP server and clean up firewall rules."
echo

# Build Apptainer env args
APPT_ENV_ARGS=()
if [[ -n "$BIND_IP" ]]; then
    APPT_ENV_ARGS+=(--env "TFTP_BIND_IP=$BIND_IP")
fi
if [[ "$ENABLE_FILE_LOG" -eq 1 ]]; then
    APPT_ENV_ARGS+=(--env "TFTP_FILE_LOG=1")
fi

# Run container (blocks until Ctrl-C)
apptainer run "${APPT_ENV_ARGS[@]}" --bind "$HOST_PATH":/tmp "$IMAGE"