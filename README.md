# [sys3num](https://github.com/lakshan-sameera/sys3num.sh)

**sys3num** is an advanced, stealthy Linux post-exploitation and enumeration script crafted for modern CTFs, Red Team engagements, and penetration testing.

Unlike traditional scripts that blindly traverse the root filesystem and trigger massive EDR alerts, sys3num is designed to be highly targeted. It actively hunts for modern Cloud/AI secrets, Maps inner container networking, and delivers instant copy-paste zero-day payloads for vulnerable kernels—all using completely native bash and living-off-the-land utilities.

---

## 🔥 Features
- **Stealth Mode (`--stealth`)**: Bypasses noisy, full-disk searches (like recursive `getcap` or heavily nested SUID searches) to evade Endpoint Detection and Response (EDR) agents.
- **AI & Cloud Credential Hunting**: Aggressively targets `.env` files and `kubeconfig` clusters. Extracts tokens for OpenAI, Anthropic, AWS, GCP, GitLab, and HuggingFace safely, utilizing regex against common developer staging paths.
- **"Deleted Secret" Ghost Scraping**: Uses `lsof` (`+L1`) to identify temporary files, volatile passwords, or scripts that a developer deleted, but remain alive in memory because their file descriptor is still open.
- **Advanced Container Pivoting**: Maps internal Docker/K8s subnets (172.x, 10.x) and detects Host PID namespace sharing (`init/systemd`), providing instant SSH tunnel/Chisel pivot generation.
- **Honeypot & Deception Detection**: Automatically identifies if you are trapped in a honeypot (Cowrie, Kippo, Dionaea) by detecting fake Python-based binaries, known honeypot users/configs, and unusually restricted process counts.
- **Cryptominer Hunting**: Automatically detects illicit crypto miners (XMRig, Kinsing, kdevtmpfsi) by analyzing high-CPU usage in transient memory stores (`/dev/shm`, `/tmp`), identifying deleted payload binaries, and intercepting Stratum pool network traffic bounds (ports 3333, 4444, etc.).
- **Instant Zero-Day Payloads**: Its offline vulnerability dictionary does not just tell you that you are vulnerable; it natively supplies the specific `curl` / `wget` one-liner to compile and pop a root shell for exploits like DirtyPipe and Netfilter UAFs.
- **GTFOBins Auto-Exploitation**: Automatically matches SUID binaries and allowed `sudo` commands against an embedded GTFOBins dictionary to provide immediate, context-aware privilege escalation payloads.
- **Advanced Misconfiguration Auditing**: Checks and correlates `sudo/doas` rules, dangerous group memberships (`docker`, `disk`, etc.), PATH hijacking, world-writable directories, Systemd timers, NFS `no_root_squash`, writable critical files, and capability leaks.
- **Automated Version Extraction**: Extracts critical userland binary versions directly (e.g., `sudo`, `pkexec`, `bash`) to immediately flag vulnerabilities like Baron Samedit, PwnKit, and Shellshock.
- **JSON & File Exports**: Cleanly structures findings via `--json` or strips ANSI color output via `--output FILE` for easy pipeline ingestion and reporting.
- **Dynamic Live Process Snooping**: Monitors `ps` for short bursts to catch plaintext passwords being actively typed or passed during cron job execution.
- **Online NVD API Validation**: Capable of dynamically querying the official NIST NVD CVE API to determine live vulnerabilities on arbitrary or newer kernels.

---

## 🚀 How to Use

Simply download the script onto the target machine, make it executable, and run it.

```bash
# Provide execution permissions
chmod +x sys3num.sh

# Run standard enumeration
./sys3num.sh
```

### Command Line Flags

You can customize the script's behavior using the following flags:

- `--stealth` : Runs the script in stealth mode. Limits file system traversal significantly to avoid triggering EDR alarms.
- `--quick` : Runs a faster version of the standard scan, limiting depth on some intensive filesystem checks.
- `--online` : Forces the script to query the NVD database online for exact CVEs related to the discovered Linux kernel version.
- `--api-key [KEY]` : Provide a free [NIST NVD API Key](https://nvd.nist.gov/developers/request-an-api-key) to avoid the default 6-second rate limit safety delay.
- `--output [FILE]` : Save results to a specified file, cleanly stripping ANSI color codes.
- `--json` : Output findings purely as structured JSON for easy pipeline ingestion, suppressing normal interactive logging.

**Example with flags:**
```bash
# Execute stealthy and quick scan
./sys3num.sh --quick --stealth

# Auto-query NVD API using a key and save findings
./sys3num.sh --api-key xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx --online --output report.txt

# Export exactly as JSON
./sys3num.sh --json > findings.json
```

---

## 🤝 Contributing
Contributors are extremely welcome! If you have ideas for new advanced vectors, payload snippets for the offline dictionary, or general optimizations, please feel free to contribute:

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingVector`)
3. Commit your Changes (`git commit -m 'Add some AmazingVector'`)
4. Push to the Branch (`git push origin feature/AmazingVector`)
5. Open a Pull Request

---

## 📜 License
Distributed under the MIT License. See `LICENSE` for more information.

---
*Disclaimer: This tool is intended strictly for educational purposes, legitimate penetration testing, and authorized red-team engagements. The authors are not responsible for any misuse or damage caused by this software.*
