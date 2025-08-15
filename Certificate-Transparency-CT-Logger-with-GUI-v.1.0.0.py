import requests
import json
import os
import hashlib
import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from OpenSSL.crypto import load_certificate, FILETYPE_PEM, X509Store, X509StoreContext, X509StoreContextError
from plyer import notification
import csv

# SSLyze imports for v3+
from sslyze import Scanner, ServerScanRequest, ScanCommand
from sslyze.server_connectivity import ServerNetworkLocation

# ------------------------
# Configuration
# ------------------------
DATA_FILE = "certificates.json"
AUTO_REFRESH_INTERVAL = 60 * 10  # 10 minutes
EXPIRY_WARNING_DAYS = 30  # days before expiry to warn


# ------------------------
# Helper Functions
# ------------------------
def fetch_certificates(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            certs_json = response.json()
            for c in certs_json:
                c["pem"] = f"-----BEGIN CERTIFICATE-----\n{c.get('min_cert_id', '')}==\n-----END CERTIFICATE-----"
            return certs_json
        else:
            messagebox.showerror("Error", f"Failed to fetch certificates. Status code: {response.status_code}")
            return []
    except Exception as e:
        messagebox.showerror("Error", f"Error fetching certificates: {e}")
        return []


def load_previous_data(file_path):
    if os.path.exists(file_path):
        with open(file_path, "r") as f:
            return json.load(f)
    return {}


def save_data(file_path, data):
    with open(file_path, "w") as f:
        json.dump(data, f, indent=4)


def certificate_hash(cert):
    unique_str = cert.get('issuer_name', '') + cert.get('common_name', '') + str(cert.get('not_before', ''))
    return hashlib.sha256(unique_str.encode()).hexdigest()


def check_new_certificates(domain):
    current_certs = fetch_certificates(domain)
    previous_certs = load_previous_data(DATA_FILE)
    new_certs = []
    updated_data = previous_certs.copy()

    for cert in current_certs:
        cert_id = certificate_hash(cert)
        if cert_id not in previous_certs:
            new_certs.append(cert)
            updated_data[cert_id] = {
                "common_name": cert.get("common_name"),
                "issuer": cert.get("issuer_name"),
                "not_before": cert.get("not_before"),
                "not_after": cert.get("not_after")
            }

    save_data(DATA_FILE, updated_data)
    return new_certs


def check_certificate_expiry(cert):
    try:
        not_after = datetime.strptime(cert.get("not_after"), "%Y-%m-%dT%H:%M:%S")
        days_left = (not_after - datetime.utcnow()).days
        if days_left < 0:
            return "expired", days_left
        elif days_left <= EXPIRY_WARNING_DAYS:
            return "warning", days_left
        else:
            return "valid", days_left
    except Exception:
        return "unknown", None


def notify_user(title, message):
    notification.notify(
        title=title,
        message=message,
        timeout=5
    )


# ------------------------
# TLS & Chain Validation
# ------------------------
def validate_certificate_chain(cert_pem):
    try:
        cert = load_certificate(FILETYPE_PEM, cert_pem.encode())
        store = X509Store()
        store_ctx = X509StoreContext(store, cert)
        store_ctx.verify_certificate()
        return True, "Chain valid"
    except X509StoreContextError as e:
        return False, f"Chain validation failed: {e}"
    except Exception as e:
        return False, f"Chain validation error: {e}"


def scan_tls(domain):
    try:
        server_location = ServerNetworkLocation(hostname=domain, port=443)
        scanner = Scanner()
        scan_request = ServerScanRequest(
            server_location=server_location,
            scan_commands=[
                ScanCommand.TLS_1_0_CIPHER_SUITES,
                ScanCommand.TLS_1_1_CIPHER_SUITES,
                ScanCommand.TLS_1_2_CIPHER_SUITES,
                ScanCommand.TLS_1_3_CIPHER_SUITES
            ]
        )
        scanner.queue_scans([scan_request])
        scanner.process_all_scans()
        results = scanner.get_results()
        tls_results = []
        for result in results:
            for command, command_result in result.scan_commands_results.items():
                tls_results.append(f"{command.name}: {command_result.__class__.__name__}")
        return tls_results
    except Exception as e:
        return [f"TLS scan failed: {e}"]


# ------------------------
# GUI Functions
# ------------------------
def display_certificates(certs, domain):
    output_box.insert(tk.END, f"Checked at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} for domain: {domain}\n\n")

    if not certs:
        output_box.insert(tk.END, "No new certificates found.\n\n")
    else:
        output_box.insert(tk.END, f"Found {len(certs)} new certificate(s):\n\n")
        for cert in certs:
            status, days_left = check_certificate_expiry(cert)
            output_box.insert(tk.END, "-" * 80 + "\n")
            output_box.insert(tk.END, f"Common Name: {cert.get('common_name')}\n")
            output_box.insert(tk.END, f"Issuer: {cert.get('issuer_name')}\n")
            output_box.insert(tk.END, f"Valid From: {cert.get('not_before')}\n")
            output_box.insert(tk.END, f"Valid To: {cert.get('not_after')} ({days_left} days left)\n")

            cert_pem = cert.get("pem", "")
            if cert_pem:
                valid_chain, chain_msg = validate_certificate_chain(cert_pem)
                output_box.insert(tk.END, f"Chain Validation: {chain_msg}\n")

            tls_results = scan_tls(cert.get("common_name", domain))
            output_box.insert(tk.END, "TLS Scan Results:\n")
            for line in tls_results:
                output_box.insert(tk.END, f"  {line}\n")

            output_box.insert(tk.END, "-" * 80 + "\n\n")

            if status in ["warning", "expired"]:
                notify_user(f"Certificate Alert: {cert.get('common_name')}",
                            f"Status: {status}, Days left: {days_left}")

    output_box.see(tk.END)


def run_check():
    domains = domain_entry.get().strip().split(",")
    if not domains:
        messagebox.showwarning("Input Error", "Please enter at least one domain.")
        return
    output_box.delete(1.0, tk.END)
    for domain in domains:
        domain = domain.strip()
        new_certs = check_new_certificates(domain)
        display_certificates(new_certs, domain)


def auto_refresh():
    run_check()
    root.after(AUTO_REFRESH_INTERVAL * 1000, auto_refresh)


def export_results():
    file_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                             filetypes=[("Text Files", "*.txt"), ("JSON Files", "*.json"),
                                                        ("CSV Files", "*.csv")])
    if file_path:
        try:
            content = output_box.get(1.0, tk.END)
            if file_path.endswith(".csv"):
                lines = content.strip().split("\n")
                with open(file_path, "w", newline="") as f:
                    writer = csv.writer(f)
                    for line in lines:
                        writer.writerow([line])
            elif file_path.endswith(".json"):
                with open(file_path, "w") as f:
                    json.dump({"log": content}, f, indent=4)
            else:
                with open(file_path, "w") as f:
                    f.write(content)
            messagebox.showinfo("Export Successful", f"Results saved to {file_path}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Could not save file: {e}")


def about():
    messagebox.showinfo("About",
                        "Certificate Transparency Logger\nPython Tkinter Desktop Tool\nIncludes expiry monitoring, TLS scan, chain validation, notifications")


# ------------------------
# GUI Layout
# ------------------------
root = tk.Tk()
root.title("Certificate Transparency Logger")
root.geometry("1000x700")

# Domain Entry
tk.Label(root, text="Enter domains (comma separated):").pack(pady=5)
domain_entry = tk.Entry(root, width=80)
domain_entry.pack(pady=5)

# Buttons
btn_frame = tk.Frame(root)
btn_frame.pack(pady=5)
tk.Button(btn_frame, text="Check Certificates", command=run_check).pack(side=tk.LEFT, padx=5)
tk.Button(btn_frame, text="Export Results", command=export_results).pack(side=tk.LEFT, padx=5)

# Output Box
output_box = scrolledtext.ScrolledText(root, width=120, height=35)
output_box.pack(pady=10)

# Menu
menu_bar = tk.Menu(root)
root.config(menu=menu_bar)

file_menu = tk.Menu(menu_bar, tearoff=0)
file_menu.add_command(label="Check Now", command=run_check)
file_menu.add_command(label="Export Results", command=export_results)
file_menu.add_separator()
file_menu.add_command(label="Exit", command=root.quit)
menu_bar.add_cascade(label="File", menu=file_menu)

help_menu = tk.Menu(menu_bar, tearoff=0)
help_menu.add_command(label="About", command=about)
menu_bar.add_cascade(label="Help", menu=help_menu)

# Auto-refresh
root.after(AUTO_REFRESH_INTERVAL * 1000, auto_refresh)

root.mainloop()
