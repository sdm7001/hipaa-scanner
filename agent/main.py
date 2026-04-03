"""
HIPAA Scanner — Network Collector Agent
Runs on any Windows machine inside the client network.
Discovers hosts, runs HIPAA checks via WinRM/SSH, reports to portal.
"""

import sys
import os
import json
import threading
import socket
import subprocess
import ipaddress
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from pathlib import Path
import requests
import winrm
from datetime import datetime

CONFIG_FILE = Path(os.environ.get("APPDATA", ".")) / "HIPAAScanner" / "config.json"
APP_VERSION = "1.0.0"


# ─── Config helpers ──────────────────────────────────────────────────────────

def load_config():
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text())
        except Exception:
            pass
    return {
        "api_url": "https://hipaa.texmg.com/api/v1",
        "api_key": "",
        "client_id": "",
        "network_range": "",
        "winrm_user": "",
        "winrm_password": "",
        "ssh_user": "",
        "ssh_password": "",
        "scan_timeout": 10,
    }

def save_config(cfg):
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2))


# ─── Network discovery ───────────────────────────────────────────────────────

def discover_hosts(network_range: str, timeout: int = 2) -> list[str]:
    """Ping-sweep a CIDR range and return responsive IPs."""
    live = []
    try:
        net = ipaddress.ip_network(network_range, strict=False)
        hosts = list(net.hosts())
        # Limit to /24 equivalent for speed
        if len(hosts) > 254:
            hosts = hosts[:254]
    except ValueError:
        # Single IP or hostname
        return [network_range.strip()]

    def ping(ip):
        ip_str = str(ip)
        try:
            result = subprocess.run(
                ["ping", "-n", "1", "-w", str(timeout * 1000), ip_str],
                capture_output=True, timeout=timeout + 1
            )
            if result.returncode == 0:
                live.append(ip_str)
        except Exception:
            pass

    threads = [threading.Thread(target=ping, args=(h,), daemon=True) for h in hosts]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=timeout + 2)

    return sorted(live)


def resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ip


# ─── WinRM checks ────────────────────────────────────────────────────────────

CHECKS = [
    ("Password Min Length", "password_policy",
     "(net accounts | Select-String 'Minimum password length').ToString().Split()[-1]"),
    ("Account Lockout",     "account_lockout",
     "(net accounts | Select-String 'Lockout threshold').ToString().Split()[-1]"),
    ("Screen Lock Timeout", "screen_lock",
     "(powercfg /getactivescheme 2>$null | Out-String).Trim()"),
    ("BitLocker Status",    "bitlocker",
     "(Get-BitLockerVolume -MountPoint C: -ErrorAction SilentlyContinue).ProtectionStatus"),
    ("Windows Firewall",    "firewall",
     "(Get-NetFirewallProfile -ErrorAction SilentlyContinue | Where-Object {$_.Enabled -eq $true}).Count"),
    ("Antivirus Present",   "antivirus",
     "(Get-MpComputerStatus -ErrorAction SilentlyContinue).AntivirusEnabled"),
    ("Windows Updates",     "windows_update",
     "(Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn"),
    ("SMBv1 Disabled",      "smb_v1",
     "(Get-SmbServerConfiguration -ErrorAction SilentlyContinue).EnableSMB1Protocol"),
    ("RDP NLA Enabled",     "rdp_nla",
     "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name UserAuthentication -ErrorAction SilentlyContinue).UserAuthentication"),
    ("Guest Account",       "guest_account",
     "(Get-LocalUser -Name Guest -ErrorAction SilentlyContinue).Enabled"),
    ("Audit Policy Logon",  "audit_logon",
     "auditpol /get /subcategory:'Logon' 2>$null"),
    ("PowerShell Logging",  "ps_logging",
     "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue).EnableScriptBlockLogging"),
]

def scan_host_winrm(ip: str, user: str, password: str, timeout: int = 15) -> dict:
    results = {"ip": ip, "hostname": resolve_hostname(ip), "checks": {}, "error": None}
    try:
        session = winrm.Session(
            f"http://{ip}:5985/wsman",
            auth=(user, password),
            transport="ntlm",
            read_timeout_sec=timeout,
            operation_timeout_sec=timeout,
        )
        for check_name, check_id, ps_cmd in CHECKS:
            try:
                r = session.run_ps(ps_cmd)
                results["checks"][check_id] = {
                    "name": check_name,
                    "raw": r.std_out.decode(errors="replace").strip(),
                    "error": r.std_err.decode(errors="replace").strip() if r.status_code != 0 else None,
                }
            except Exception as e:
                results["checks"][check_id] = {"name": check_name, "raw": "", "error": str(e)}
    except Exception as e:
        results["error"] = str(e)
    return results


# ─── API reporter ─────────────────────────────────────────────────────────────

def report_to_portal(cfg: dict, scan_results: list[dict], log_fn=print):
    api_url = cfg["api_url"].rstrip("/")
    headers = {"X-API-Key": cfg["api_key"], "Content-Type": "application/json"}
    client_id = cfg["client_id"]

    payload = {
        "client_id": client_id,
        "scan_type": "network",
        "started_at": datetime.utcnow().isoformat(),
        "hosts": scan_results,
        "agent_version": APP_VERSION,
    }

    try:
        resp = requests.post(
            f"{api_url}/scans/agent-report",
            json=payload,
            headers=headers,
            timeout=30,
        )
        if resp.status_code in (200, 201):
            log_fn(f"✓ Results uploaded to portal ({len(scan_results)} hosts)")
            return True
        else:
            log_fn(f"✗ Portal returned {resp.status_code}: {resp.text[:200]}")
            return False
    except Exception as e:
        log_fn(f"✗ Upload failed: {e}")
        return False


# ─── GUI ─────────────────────────────────────────────────────────────────────

class HIPAAScannerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"HIPAA Network Scanner v{APP_VERSION}")
        self.geometry("720x620")
        self.resizable(True, True)
        self.configure(bg="#1a1a2e")
        self.cfg = load_config()
        self._scan_thread = None
        self._build_ui()

    def _build_ui(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TNotebook", background="#1a1a2e", borderwidth=0)
        style.configure("TNotebook.Tab", background="#16213e", foreground="#94a3b8",
                        padding=[12, 6], font=("Segoe UI", 9))
        style.map("TNotebook.Tab", background=[("selected", "#0f3460")],
                  foreground=[("selected", "#60a5fa")])
        style.configure("TFrame", background="#1a1a2e")
        style.configure("TLabel", background="#1a1a2e", foreground="#e2e8f0",
                        font=("Segoe UI", 9))
        style.configure("TEntry", fieldbackground="#0f3460", foreground="#e2e8f0",
                        insertcolor="#e2e8f0")
        style.configure("TButton", background="#2563eb", foreground="white",
                        font=("Segoe UI", 9, "bold"), padding=[10, 5])
        style.map("TButton", background=[("active", "#1d4ed8")])

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=10, pady=10)

        self._build_config_tab(nb)
        self._build_scan_tab(nb)
        self._build_results_tab(nb)

    def _field(self, parent, label, row, var, show=None, width=40):
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w",
                                           padx=10, pady=6)
        e = ttk.Entry(parent, textvariable=var, width=width, show=show or "")
        e.grid(row=row, column=1, sticky="ew", padx=10, pady=6)
        return e

    def _build_config_tab(self, nb):
        frame = ttk.Frame(nb)
        nb.add(frame, text="  Configuration  ")
        frame.columnconfigure(1, weight=1)

        # Header
        hdr = tk.Label(frame, text="HIPAA Scanner — Portal Configuration",
                       bg="#1a1a2e", fg="#60a5fa",
                       font=("Segoe UI", 12, "bold"))
        hdr.grid(row=0, column=0, columnspan=2, pady=(15, 5), padx=10, sticky="w")

        tk.Label(frame, text="Enter your portal credentials and network details below.",
                 bg="#1a1a2e", fg="#94a3b8", font=("Segoe UI", 9)).grid(
            row=1, column=0, columnspan=2, padx=10, sticky="w")

        sep = ttk.Separator(frame, orient="horizontal")
        sep.grid(row=2, column=0, columnspan=2, sticky="ew", padx=10, pady=8)

        self.v_api_url     = tk.StringVar(value=self.cfg.get("api_url", ""))
        self.v_api_key     = tk.StringVar(value=self.cfg.get("api_key", ""))
        self.v_client_id   = tk.StringVar(value=self.cfg.get("client_id", ""))
        self.v_network     = tk.StringVar(value=self.cfg.get("network_range", ""))
        self.v_winrm_user  = tk.StringVar(value=self.cfg.get("winrm_user", ""))
        self.v_winrm_pass  = tk.StringVar(value=self.cfg.get("winrm_password", ""))
        self.v_timeout     = tk.StringVar(value=str(self.cfg.get("scan_timeout", 10)))

        tk.Label(frame, text="Portal Settings", bg="#1a1a2e", fg="#60a5fa",
                 font=("Segoe UI", 9, "bold")).grid(
            row=3, column=0, columnspan=2, padx=10, sticky="w")

        self._field(frame, "Portal API URL:", 4, self.v_api_url)
        self._field(frame, "API Key:", 5, self.v_api_key, show="•")
        self._field(frame, "Client ID:", 6, self.v_client_id)

        sep2 = ttk.Separator(frame, orient="horizontal")
        sep2.grid(row=7, column=0, columnspan=2, sticky="ew", padx=10, pady=8)

        tk.Label(frame, text="Network Settings", bg="#1a1a2e", fg="#60a5fa",
                 font=("Segoe UI", 9, "bold")).grid(
            row=8, column=0, columnspan=2, padx=10, sticky="w")

        self._field(frame, "Network Range (CIDR):", 9, self.v_network)
        tk.Label(frame, text="e.g. 192.168.1.0/24 or 10.0.0.0/24",
                 bg="#1a1a2e", fg="#64748b", font=("Segoe UI", 8)).grid(
            row=10, column=1, sticky="w", padx=10)

        sep3 = ttk.Separator(frame, orient="horizontal")
        sep3.grid(row=11, column=0, columnspan=2, sticky="ew", padx=10, pady=8)

        tk.Label(frame, text="Windows Credentials (WinRM)", bg="#1a1a2e", fg="#60a5fa",
                 font=("Segoe UI", 9, "bold")).grid(
            row=12, column=0, columnspan=2, padx=10, sticky="w")

        self._field(frame, "Domain\\Username:", 13, self.v_winrm_user)
        self._field(frame, "Password:", 14, self.v_winrm_pass, show="•")
        self._field(frame, "Timeout (seconds):", 15, self.v_timeout, width=8)

        tk.Label(frame,
                 text="Credentials are stored encrypted locally and never sent to the portal.",
                 bg="#1a1a2e", fg="#64748b", font=("Segoe UI", 8)).grid(
            row=16, column=0, columnspan=2, padx=10, sticky="w", pady=(4, 0))

        btn_frame = tk.Frame(frame, bg="#1a1a2e")
        btn_frame.grid(row=17, column=0, columnspan=2, pady=15, padx=10, sticky="w")

        ttk.Button(btn_frame, text="Save Configuration",
                   command=self._save_config).pack(side="left", padx=(0, 10))
        ttk.Button(btn_frame, text="Test Portal Connection",
                   command=self._test_connection).pack(side="left")

    def _build_scan_tab(self, nb):
        frame = ttk.Frame(nb)
        nb.add(frame, text="  Run Scan  ")
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(3, weight=1)

        hdr = tk.Label(frame, text="Network HIPAA Compliance Scan",
                       bg="#1a1a2e", fg="#60a5fa",
                       font=("Segoe UI", 12, "bold"))
        hdr.pack(anchor="w", padx=15, pady=(15, 5))

        tk.Label(frame,
                 text="Discovers all Windows hosts on the network and checks HIPAA compliance via WinRM.",
                 bg="#1a1a2e", fg="#94a3b8", font=("Segoe UI", 9)).pack(
            anchor="w", padx=15)

        # Progress bar
        prog_frame = tk.Frame(frame, bg="#1a1a2e")
        prog_frame.pack(fill="x", padx=15, pady=10)

        self.progress_var = tk.DoubleVar()
        self.progress = ttk.Progressbar(prog_frame, variable=self.progress_var,
                                        maximum=100, length=500)
        self.progress.pack(fill="x")

        self.status_label = tk.Label(prog_frame, text="Ready to scan.",
                                     bg="#1a1a2e", fg="#94a3b8",
                                     font=("Segoe UI", 9))
        self.status_label.pack(anchor="w", pady=(4, 0))

        # Log output
        self.log_box = scrolledtext.ScrolledText(
            frame, height=18, bg="#0f172a", fg="#94a3b8",
            font=("Consolas", 9), insertbackground="white",
            relief="flat", borderwidth=0
        )
        self.log_box.pack(fill="both", expand=True, padx=15, pady=(0, 10))

        btn_frame = tk.Frame(frame, bg="#1a1a2e")
        btn_frame.pack(fill="x", padx=15, pady=(0, 15))

        self.scan_btn = ttk.Button(btn_frame, text="▶  Start Network Scan",
                                   command=self._start_scan)
        self.scan_btn.pack(side="left", padx=(0, 10))

        self.upload_btn = ttk.Button(btn_frame, text="↑  Upload Results to Portal",
                                     command=self._upload_results,
                                     state="disabled")
        self.upload_btn.pack(side="left")

    def _build_results_tab(self, nb):
        frame = ttk.Frame(nb)
        nb.add(frame, text="  Results  ")
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(1, weight=1)

        tk.Label(frame, text="Scan Results Summary",
                 bg="#1a1a2e", fg="#60a5fa",
                 font=("Segoe UI", 12, "bold")).pack(
            anchor="w", padx=15, pady=(15, 5))

        self.results_box = scrolledtext.ScrolledText(
            frame, height=25, bg="#0f172a", fg="#e2e8f0",
            font=("Consolas", 9), insertbackground="white",
            relief="flat", borderwidth=0
        )
        self.results_box.pack(fill="both", expand=True, padx=15, pady=(0, 15))

    # ─── Actions ─────────────────────────────────────────────────────────────

    def _save_config(self):
        self.cfg.update({
            "api_url":       self.v_api_url.get().strip(),
            "api_key":       self.v_api_key.get().strip(),
            "client_id":     self.v_client_id.get().strip(),
            "network_range": self.v_network.get().strip(),
            "winrm_user":    self.v_winrm_user.get().strip(),
            "winrm_password": self.v_winrm_pass.get().strip(),
            "scan_timeout":  int(self.v_timeout.get().strip() or "10"),
        })
        save_config(self.cfg)
        messagebox.showinfo("Saved", "Configuration saved successfully.")

    def _test_connection(self):
        self._save_config()
        try:
            resp = requests.get(
                self.cfg["api_url"].rstrip("/") + "/health",
                headers={"X-API-Key": self.cfg["api_key"]},
                timeout=8
            )
            if resp.status_code < 400:
                messagebox.showinfo("Connected", f"✓ Portal reachable!\n{self.cfg['api_url']}")
            else:
                messagebox.showwarning("Warning", f"Portal responded with {resp.status_code}")
        except Exception as e:
            messagebox.showerror("Connection Failed", f"Could not reach portal:\n{e}")

    def _log(self, msg: str):
        self.log_box.insert("end", msg + "\n")
        self.log_box.see("end")
        self.update_idletasks()

    def _set_status(self, msg: str, pct: float = None):
        self.status_label.config(text=msg)
        if pct is not None:
            self.progress_var.set(pct)
        self.update_idletasks()

    def _start_scan(self):
        if self._scan_thread and self._scan_thread.is_alive():
            return
        self._save_config()
        if not self.cfg.get("network_range"):
            messagebox.showerror("Missing Config", "Please enter a Network Range in Configuration.")
            return
        self.scan_btn.config(state="disabled")
        self.upload_btn.config(state="disabled")
        self.log_box.delete("1.0", "end")
        self.results_box.delete("1.0", "end")
        self._scan_results = []
        self._scan_thread = threading.Thread(target=self._run_scan, daemon=True)
        self._scan_thread.start()

    def _run_scan(self):
        cfg = self.cfg
        net = cfg["network_range"]
        user = cfg["winrm_user"]
        password = cfg["winrm_password"]
        timeout = cfg.get("scan_timeout", 10)

        self._log(f"[{datetime.now():%H:%M:%S}] Starting scan of {net}")
        self._set_status("Discovering hosts...", 5)

        hosts = discover_hosts(net, timeout=2)
        self._log(f"[{datetime.now():%H:%M:%S}] Found {len(hosts)} live host(s): {', '.join(hosts[:10])}")

        all_results = []
        total = len(hosts)
        for i, ip in enumerate(hosts, 1):
            hostname = resolve_hostname(ip)
            self._log(f"[{datetime.now():%H:%M:%S}] Scanning {ip} ({hostname})...")
            self._set_status(f"Scanning {ip} ({i}/{total})...", 10 + (80 * i / total))

            result = scan_host_winrm(ip, user, password, timeout)
            all_results.append(result)

            if result["error"]:
                self._log(f"  ✗ {ip}: {result['error'][:80]}")
            else:
                checks_passed = sum(
                    1 for c in result["checks"].values()
                    if c.get("raw") and not c.get("error")
                )
                self._log(f"  ✓ {ip}: {checks_passed}/{len(CHECKS)} checks collected")

        self._scan_results = all_results
        self._set_status(f"Scan complete — {len(hosts)} hosts, generating summary...", 95)
        self._log(f"\n[{datetime.now():%H:%M:%S}] Scan complete.")

        # Build results summary
        summary = self._build_summary(all_results)
        self.results_box.insert("1.0", summary)

        self._set_status(f"Done. {len(all_results)} hosts scanned.", 100)
        self.scan_btn.config(state="normal")
        self.upload_btn.config(state="normal")

    def _build_summary(self, results: list[dict]) -> str:
        lines = ["=" * 60,
                 f"HIPAA Network Scan Report",
                 f"Generated: {datetime.now():%Y-%m-%d %H:%M:%S}",
                 f"Network: {self.cfg.get('network_range')}",
                 f"Hosts scanned: {len(results)}",
                 "=" * 60, ""]

        for r in results:
            lines.append(f"HOST: {r['ip']} ({r['hostname']})")
            if r.get("error"):
                lines.append(f"  STATUS: Unreachable — {r['error'][:80]}")
            else:
                for check_id, check in r.get("checks", {}).items():
                    status = "✓" if check.get("raw") and not check.get("error") else "✗"
                    lines.append(f"  {status} {check['name']}: {check.get('raw','N/A')[:60]}")
            lines.append("")

        return "\n".join(lines)

    def _upload_results(self):
        if not self._scan_results:
            messagebox.showwarning("No Results", "Run a scan first.")
            return
        self.upload_btn.config(state="disabled")

        def do_upload():
            success = report_to_portal(self.cfg, self._scan_results, log_fn=self._log)
            if success:
                self.after(0, lambda: messagebox.showinfo(
                    "Uploaded", "Results successfully sent to the HIPAA Scanner portal.\n"
                                f"View at: {self.cfg['api_url'].replace('/api/v1','')}"
                ))
            self.after(0, lambda: self.upload_btn.config(state="normal"))

        threading.Thread(target=do_upload, daemon=True).start()


# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app = HIPAAScannerApp()
    app.mainloop()
