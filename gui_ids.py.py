# Intrusion Detection System GUI
# Includes: login/register, admin approvals, guest access, intrusion logging, zone simulation, CSV export


import tkinter as tk
from tkinter import messagebox, filedialog
from datetime import datetime
import os
import csv

# -----------------------------
# File Paths
# -----------------------------
users_file = "users.txt"
pending_admins_file = "pending_admins.txt"
log_file = "intrusion_log.txt"

# -----------------------------
# Zone Button Layout
# -----------------------------
zones = {
    "Main Door": (90, 50),
    "Back Door": (295, 50),
    "Window 1": (90, 150),
    "Hallway": (200, 160),
    "Storage Room": (290, 260)
}

# Only guests can access these zones
guest_allowed = ["Main Door", "Back Door"]

# Hours during which access is allowed without alert
authorized_hours = range(8, 20)  # 8AM–8PM

# -----------------------------
# Load existing users from file
# -----------------------------
def load_users():
    if not os.path.exists(users_file):
        return {}
    with open(users_file, "r") as f:
        lines = f.readlines()
    users = {}
    for line in lines:
        parts = line.strip().split(",")
        if len(parts) == 3:
            users[parts[0]] = (parts[1], parts[2])  # username: (password, role)
    return users

# Save approved user
def save_user(username, password, role):
    with open(users_file, "a") as f:
        f.write(f"{username},{password},{role}\n")

# Save pending admin request
def save_pending_admin(username, password):
    with open(pending_admins_file, "a") as f:
        f.write(f"{username},{password},admin\n")

# -----------------------------
# Admin Approval GUI (only for Musab)
# -----------------------------
def show_admin_approval():
    if not os.path.exists(pending_admins_file):
        messagebox.showinfo("No Requests", "No pending admin requests.")
        return

    approval_win = tk.Toplevel()
    approval_win.title("Pending Admin Approvals")

    with open(pending_admins_file, "r") as f:
        requests = f.readlines()

    # Approve selected request
    def approve(index):
        line = requests.pop(index)
        with open(users_file, "a") as f:
            f.write(line)
        refresh()
        save_pending()

    # Reject selected request
    def reject(index):
        requests.pop(index)
        refresh()
        save_pending()

    def save_pending():
        with open(pending_admins_file, "w") as f:
            f.writelines(requests)

    # Refresh displayed list
    def refresh():
        for widget in approval_win.winfo_children():
            widget.destroy()
        for idx, line in enumerate(requests):
            user = line.strip().split(",")[0]
            tk.Label(approval_win, text=f"{user} wants admin access").grid(row=idx, column=0)
            tk.Button(approval_win, text="Approve", command=lambda i=idx: approve(i)).grid(row=idx, column=1)
            tk.Button(approval_win, text="Reject", command=lambda i=idx: reject(i)).grid(row=idx, column=2)

    refresh()

# -----------------------------
# Login + Register Interface
# -----------------------------
def show_login():
    def try_login():
        users = load_users()
        u, p = username_entry.get(), password_entry.get()
        if u in users:
            stored_pw, role = users[u]
            if p == stored_pw:
                messagebox.showinfo("Welcome Back", f"Welcome back, {u}! Ready to monitor your zones.")
                login_win.destroy()
                show_dashboard(u, role)
                return
        messagebox.showerror("Login Failed", "Wrong username or password")

    # Registration process with admin pending check
    def register():
        def submit_register():
            u = reg_user.get()
            p = reg_pass.get()
            r = role_var.get().lower()

            if not u or not p or not r:
                messagebox.showerror("Error", "Please fill all fields")
                return

            users = load_users()
            if u in users:
                messagebox.showerror("Error", "User already exists")
                return

            if r == "admin":
                save_pending_admin(u, p)
                messagebox.showinfo("Pending", f"Admin request submitted for {u}.")
                messagebox.showwarning("🔔 Notification", f"New admin request submitted: {u}")
                messagebox.showinfo("Info", "Thank you for registering. Once approved, you'll gain admin access to monitor and authorize zones.")
            elif r == "guest":
                save_user(u, p, "guest")
                messagebox.showinfo("Success", "Guest account created.")
                messagebox.showinfo("Welcome", "Welcome to the Intrusion Detection System. As a guest, you can monitor limited zones like entrances. For full access, request admin rights.")
                reg_win.destroy()
            else:
                messagebox.showerror("Error", "Role must be 'admin' or 'guest'")

        reg_win = tk.Toplevel()
        reg_win.title("Register")
        tk.Label(reg_win, text="Username").pack()
        reg_user = tk.Entry(reg_win)
        reg_user.pack()
        tk.Label(reg_win, text="Password").pack()
        reg_pass = tk.Entry(reg_win, show="*")
        reg_pass.pack()
        tk.Label(reg_win, text="Role (admin/guest)").pack()
        role_var = tk.StringVar()
        tk.Entry(reg_win, textvariable=role_var).pack()
        tk.Button(reg_win, text="Register", command=submit_register).pack()

    # Main Login Window
    login_win = tk.Tk()
    login_win.title("Login")
    tk.Label(login_win, text="Username").pack()
    username_entry = tk.Entry(login_win)
    username_entry.pack()
    tk.Label(login_win, text="Password").pack()
    password_entry = tk.Entry(login_win, show="*")
    password_entry.pack()
    tk.Button(login_win, text="Login", command=try_login).pack(pady=5)
    tk.Button(login_win, text="Register", command=register).pack()
    login_win.mainloop()

# -----------------------------
# Dashboard (Main App Interface)
# -----------------------------
def show_dashboard(current_user, role):
    def on_zone_click(zone):
        now = datetime.now()
        time_str = now.strftime("%Y-%m-%d %H:%M:%S")
        after_hours = now.hour not in authorized_hours
        alert = " [AFTER HOURS]" if after_hours else ""
        entry = f"[{time_str}] {current_user} accessed {zone}{alert}"
        log_list.insert(tk.END, entry)
        with open(log_file, "a") as f:
            f.write(entry + "\n")
        messagebox.showwarning("Zone Accessed", entry)

    # Logout and return to login screen
    def logout():
        root.destroy()
        show_login()

    # Export logs to CSV file for reports
    def export_log():
        if not os.path.exists(log_file):
            messagebox.showinfo("No Log", "No logs available to export.")
            return
        export_path = os.path.join(os.getcwd(), "intrusion_log_report.csv")
        with open(log_file, "r") as lf, open(export_path, "w", newline='') as ef:
            writer = csv.writer(ef)
            writer.writerow(["Timestamp", "Message"])
            for line in lf:
                if ']' in line:
                    time, msg = line.strip().split("] ", 1)
                    writer.writerow([time.strip("["), msg])
        messagebox.showinfo("Exported", f"Log exported to {export_path}")

    # Create main window
    root = tk.Tk()
    root.title(f"🏠 Dashboard - {role.upper()}")
    root.configure(bg="#f0f0f0")

    # Header title
    tk.Label(root, text="🏠 Smart Intrusion Detection System", font=("Helvetica", 16, "bold"), bg="#f0f0f0").pack(pady=10)

    # Background image / canvas layout
    try:
        bg = tk.PhotoImage(file="house_layout.png")
        canvas = tk.Canvas(root, width=bg.width(), height=bg.height())
        canvas.pack()
        canvas.create_image(0, 0, image=bg, anchor=tk.NW)
        canvas.image = bg
    except:
        canvas = tk.Canvas(root, width=400, height=350, bg="#dbe9f4")
        canvas.pack()

    # Create a button for each zone
    for zone, (x, y) in zones.items():
        if role == "guest" and zone not in guest_allowed:
            continue
        btn = tk.Button(root, text=zone, width=12, font=("Arial", 10, "bold"), bg="#e0f7fa", relief=tk.RAISED,
                        command=lambda z=zone: on_zone_click(z))
        canvas.create_window(x, y, window=btn)

    # Intrusion log section
    tk.Label(root, text="🔍 Intrusion Log", font=("Arial", 12, "bold"), bg="#f0f0f0").pack(pady=(10, 0))
    log_list = tk.Listbox(root, width=60, height=10)
    log_list.pack(pady=5)

    # Bottom button section
    button_frame = tk.Frame(root, bg="#f0f0f0")
    button_frame.pack(pady=5)

    # Admin only: approve panel
    if current_user == "Musab" and role == "admin":
        tk.Button(button_frame, text="🛠 Approve Admin Requests", command=show_admin_approval).pack(side=tk.LEFT, padx=5)

    # Export log / logout
    tk.Button(button_frame, text="Export Log to CSV", command=export_log).pack(side=tk.LEFT, padx=5)
    tk.Button(button_frame, text="Logout", command=logout).pack(side=tk.LEFT, padx=5)

    # Footer with status info
    status = f"Logged in as: {current_user.upper()} ({role}) | {datetime.now().strftime('%Y-%m-%d')}"
    tk.Label(root, text=status, font=("Arial", 9), bg="#d0d0d0").pack(fill=tk.X, side=tk.BOTTOM)

    root.mainloop()

# -----------------------------
# Startup check and launch
# -----------------------------
if not os.path.exists(users_file):
    with open(users_file, "w") as f:
        f.write("Musab,123,admin\n")

show_login()