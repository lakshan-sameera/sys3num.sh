# sys3num

**sys3num** is an advanced, stealthy Linux post-exploitation and enumeration script crafted for modern CTFs, Red Team engagements, and penetration testing.

Unlike traditional scripts that blindly traverse the root filesystem and trigger massive EDR alerts, sys3num is designed to be highly targeted. It actively hunts for modern Cloud/AI secrets, Maps inner container networking, and delivers instant copy-paste zero-day payloads for vulnerable kernels—all using completely native bash and living-off-the-land utilities.

---

## 🔥 Features
- **Stealth Mode (`--stealth`)**: Bypasses noisy, full-disk searches (like recursive `getcap` or heavily nested SUID searches) to evade Endpoint Detection and Response (EDR) agents.
- **AI & Cloud Credential Hunting**: Aggressively targets `.env` files and `kubeconfig` clusters. Extracts tokens for OpenAI, Anthropic, AWS, GCP, GitLab, and HuggingFace safely, utilizing regex against common developer staging paths.
- **"Deleted Secret" Ghost Scraping**: Uses `lsof` (`+L1`) to identify temporary files, volatile passwords, or scripts that a developer deleted, but remain alive in memory because their file descriptor is still open.
- **Advanced Container Pivoting**: Maps internal Docker/K8s subnets (172.x, 10.x) and detects Host PID namespace sharing (`init/systemd`), providing instant SSH tunnel/Chisel pivot generation.
- **Instant Zero-Day Payloads**: Its offline vulnerability dictionary does not just tell you that you are vulnerable; it natively supplies the specific `curl` / `wget` one-liner to compile and pop a root shell for exploits like DirtyPipe and Netfilter UAFs.
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

**Example with flags:**
```bash
./sys3num.sh --stealth --api-key xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx --online
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
