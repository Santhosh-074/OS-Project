# Linux Performance Analyzer (using /proc filesystem)

A command-line **Linux system performance monitoring tool** built entirely in C, using **no external libraries**. It reads live kernel data directly from the `/proc` and `/sys` virtual filesystems to report CPU usage, memory pressure, per-process resource consumption, disk I/O, network stats, file descriptors, and battery status — with color-coded output and an intelligent alerting system.

This project was built as part of an **Operating Systems (OS) course project**, demonstrating practical understanding of Linux kernel internals: CPU scheduling counters, memory accounting, process states, and I/O statistics as exposed through `procfs`/`sysfs`.

## Features

| # | Feature |
|---|---------|
| 1 | CPU details + usage events |
| 2 | Per-core performance tracking with delta sampling |
| 3 | Per-process CPU % and memory % tracking (two-snapshot sampling) |
| 4 | System uptime |
| 5 | Load average |
| 6 | Memory usage with 3-level intelligent alerts (WARNING / CRITICAL / EMERGENCY) |
| 7 | Process analysis across all states |
| 8 | Top processes by memory & CPU |
| 9 | Network interfaces + TCP connection states |
| 10 | Disk usage + I/O statistics |
| 11 | File descriptor usage & kernel limits |
| 12 | Battery status monitoring |
| 13 | Real-time monitor (5 snapshots, 2s interval) |
| 14 | View all alert & event logs |
| 15 | Export full system snapshot to a timestamped file |
| 16 | Show all information at once |

### Key implementation highlights
- **Zero external dependencies** — pure C standard library + Linux syscalls
- **Real CPU usage calculation** using scheduler tick deltas from `/proc/stat`
- **Three-level alert system** (WARNING/CRITICAL/EMERGENCY) with persistent logging to `/tmp/`
- **Per-core and per-process tracking** using two-point sampling
- **TCP connection state parsing** from `/proc/net/tcp`
- **Disk and I/O stats** via `/proc/diskstats` and `statvfs()`
- **File descriptor exhaustion detection** — a common real-world production issue
- **Battery monitoring** via `/sys/class/power_supply/`
- **Snapshot export** for incident-response style reporting

## Data Sources

| Metric | Source |
|---|---|
| CPU usage | `/proc/stat` |
| Memory | `/proc/meminfo` |
| Processes | `/proc/[pid]/stat`, `/proc/[pid]/status` |
| Load average | `/proc/loadavg` |
| Network | `/proc/net/dev`, `/proc/net/tcp` |
| Disk | `/proc/diskstats`, `statvfs()` |
| File descriptors | `/proc/sys/fs/file-nr` |
| Battery | `/sys/class/power_supply/` |

## Requirements

- Linux OS (uses `/proc` and `/sys`, so it will **not** run on Windows/macOS natively — use WSL2 or a Linux VM if needed)
- GCC or any C compiler

## Compilation & Usage

```bash
gcc osproject.c -o analyzer
./analyzer
```

You'll see an interactive menu — enter a number (0–16) to run that feature.

## Logs & Output Files

The tool writes logs and snapshots to `/tmp/`:
- `/tmp/analyzer_alerts.log` — main alert/event log
- `/tmp/analyzer_percore.log` — per-core tracking log
- `/tmp/analyzer_procs.log` — per-process tracking log
- `/tmp/sys_snapshot_<timestamp>.txt` — exported full snapshots (option 15)

## Project Structure

```
.
├── osproject.c     # Main source file
└── README.md       # This file
```

## Author

Kethavath Santhosh Naik
B.Tech, Information Technology
National Institute of Technology Karnataka, Surathkal

## License

This project is open-sourced for academic and learning purposes.
