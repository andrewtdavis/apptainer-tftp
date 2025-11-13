# run-tftp.sh – Portable Disposable TFTP Server with Apptainer

`run-tftp.sh` is a portable, firewall-aware helper script that launches a **disposable, isolated TFTP server** inside an **Apptainer** (Singularity-compatible) container.  
It is designed for network engineers, sysadmins, and datacenter operators who need a *safe, temporary, predictable* TFTP endpoint for:

- Switch/router config backups
- Firmware/image transfers
- Dell iDRAC SupportAssist log exports
- Juniper / Cisco / Arista / Extreme file operations
- PAN-OS loader-mode image retrieval
- Lab/field work where installing systemwide TFTP is undesirable

The script requires **no system-level TFTP installation**, does **not modify system config**, cleans up automatically, and works consistently on **Rocky/RHEL**, **Ubuntu/Debian**, and other Linux distributions.

---

## Features

### ✓ Fully Portable
- The TFTP server runs **entirely inside an Apptainer image** (Rocky Linux 9 + Python + tftpy).
- No system packages, daemons, or config files are altered.
- Deletes all firewall changes upon exit (even on Ctrl-C).

### ✓ Disposable, Isolated TFTP Service
- Ephemeral runtime root at `/tmp` inside the container.
- No persistent state unless you bind a directory explicitly.
- Nothing survives after you Ctrl-C.

### ✓ Strong File Safety
- Filenames are rewritten on upload as:

```
<client-ip>-TyyyymmddHHMMSS-filename[.N]
```

Ensures:
- No overwrites
- Easy identification of which device uploaded each file
- Multi-device parallel transfers remain predictable  
- Optional per-session file logging (`tftp.log`)

### ✓ Works on Both Firewalld (RHEL/Rocky) and UFW (Ubuntu/Debian)
Automatically:
- Detects the firewall backend
- Determines interface for the bind IP
- Opens *only* the correct port (UDP/69)
- Removes rules automatically on exit

### ✓ Rich Vendor Support
Optional flags print real-world TFTP examples for:

- `--arista`
- `--aruba`
- `--brocade`
- `--cisco`
- `--dell-switch`
- `--extreme`
- `--fortinet`
- `--juniper`
- `--paloalto`
- `--supportassist`
- `--ubiquiti`

Each example automatically substitutes your server’s IP.

### ✓ Self-building
If the Apptainer image does not exist:
- Script prompts the user
- Builds `tftp-rhel9.sif` automatically
- Uses Rocky Linux 9 base
- Installs Python + tftpy inside the container

No root required to build.

---

## Requirements

- **Linux host** (Rocky, RHEL, Alma, Debian, Ubuntu, etc.)
- **Apptainer installed**
  - Rocky/RHEL: `sudo dnf install apptainer`
  - Ubuntu/Debian: `sudo apt install apptainer`
- Root privileges **only for runtime**, not for build  
  (script re-execs itself via `sudo`)

---

## Quick Start

### Start a TFTP server using /tmp:

```bash
./run-tftp.sh
```

### Bind to a specific IP & directory:

```bash
./run-tftp.sh --bind 192.168.1.1 --path ~/firmware
```

### Enable file logging:

```bash
./run-tftp.sh --log
```

Output:

```
TFTP upload directory (host): /home/user/firmware
Generic TFTP URL:
  tftp://192.168.1.1/<filename>
```

### Dell iDRAC SupportAssist example

```bash
./run-tftp.sh --supportassist --bind 192.168.1.1
```

Which prints:

```
racadm supportassist exportlastcollection -l tftp://192.168.1.1/
```

---

## File Handling Behavior

Uploaded files are automatically saved as:

```
<client-ip>-T20251112215604-running-config
```

If the file already exists:

```
<client-ip>-T20251112215604-running-config.1
<client-ip>-T20251112215604-running-config.2
...
```

This makes the server safe for:
- Multi-user test labs
- Switch fleets backing up in parallel
- Automated backup jobs
- Unpredictable filename sources (e.g., iDRAC, FortiGate)

---

## How It Works

### 1. Script parses flags and environment
- Resolves `--path`, `--bind`, and `--log`
- Auto-detects interface for `--bind`
- Chooses firewall backend (`firewalld` or `ufw`)

### 2. Builds the Apptainer image if missing
The definition file:

- Pulls `rockylinux:9`
- Installs Python + `tftpy`
- Creates `/usr/local/bin/start-tftp.sh`
- Embeds the Python TFTP server

### 3. Starts containerized TFTP
Using:

```bash
apptainer run \
    --bind "$HOST_PATH":/tmp \
    --env TFTP_BIND_IP=<IP> \
    --env TFTP_FILE_LOG=<0|1> \
    tftp-rhel9.sif
```

### 4. Python TFTP server handles uploads
Handles:
- Filename rewriting
- Logging (stdout or tftp.log)
- Collision avoidance
- Quieting noisy per-block logs
- Vendor-agnostic, RFC-compliant TFTP operations

### 5. Cleanup
When the user hits **Ctrl-C**:
- Apptainer container stops
- Firewall entries removed
- Script exits cleanly

---

## Testing Environments

The script has been validated on:

- **Rocky Linux 9** (firewalld)
- **Rocky Linux 8**
- **Ubuntu 22.04** (ufw)
- **Debian 12**

---

## FAQ

### Why use Apptainer instead of a system TFTP server?
Because system-level TFTP frequently causes issues:

- Conflicts with existing network services  
- SELinux denials  
- Hard-to-clean configs  
- Requires root to install/remove  
- Embedded devices may require special filename handling  

This server is always clean, predictable, ephemeral, and isolated.

### Does it allow GET and PUT?
Yes — the Python server supports both.

### Does it support large files?
Yes. TFTP uses blocksize options when supported by clients, and the script suppresses noisy logs while still tracking transfer stats.

---

## Contributing

Please submit issues or PRs for:

- Additional vendor examples  
- Additional OS firewall backends  
- New features in the embedded TFTP server  
- Optional SFTP mode for secure transfers  

---

## License

MIT License  
(c) Andrew Davis, UCSF Gladstone Institutes.
