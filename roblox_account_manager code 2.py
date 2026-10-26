"""
Roblox Multi-Account Manager (Windows, Python 3.8+, no extra packages)

What it does
  * Stores multiple accounts; each .ROBLOSECURITY cookie is encrypted with
    Windows DPAPI (only your Windows user can decrypt it).
  * Launches each account in its own Roblox window using Roblox's official
    authentication-ticket flow (same thing the website uses to start the game).
  * Holds Roblox's single-instance mutex so several clients can run at once.
  * Staggers launches so the machine isn't hit by several clients loading at once.

Usage
  1. Start this manager FIRST, then launch Roblox through it.
     (If Roblox is already open, close it first - it must not hold the mutex.)
  2. Add account -> paste its .ROBLOSECURITY cookie.
     Get it from a logged-in browser: DevTools > Application > Cookies > roblox.com.
     Never share that cookie with anyone; it is equivalent to your password.
  3. Select accounts, enter a Place ID, click Launch.
"""
import base64
import ctypes
import ctypes.wintypes as wt
import json
import os
import random
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk

if sys.platform != "win32":
    sys.exit("This tool only works on Windows.")

DATA_DIR = os.path.join(os.environ.get("APPDATA", "."), "RobloxMultiManager")
DATA_FILE = os.path.join(DATA_DIR, "accounts.json")
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) RobloxAccountManager/1.0"

crypt32 = ctypes.windll.crypt32
kernel32 = ctypes.windll.kernel32
kernel32.LocalFree.argtypes = [ctypes.c_void_p]
kernel32.CreateMutexW.restype = wt.HANDLE
kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, wt.BOOL, wt.LPCWSTR]


# ---------- DPAPI encryption ----------
class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wt.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _in_blob(data: bytes):
    buf = ctypes.create_string_buffer(data, len(data))
    return DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), buf


def _crypt(fn, data: bytes) -> bytes:
    blob, _keep = _in_blob(data)
    out = DATA_BLOB()
    if not fn(ctypes.byref(blob), None, None, None, None, 0, ctypes.byref(out)):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        kernel32.LocalFree(ctypes.cast(out.pbData, ctypes.c_void_p))


def protect(text: str) -> str:
    return base64.b64encode(_crypt(crypt32.CryptProtectData, text.encode())).decode()


def unprotect(b64: str) -> str:
    return _crypt(crypt32.CryptUnprotectData, base64.b64decode(b64)).decode()


# ---------- Account storage ----------
def load_accounts():
    try:
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def save_accounts(accounts):
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(accounts, f, indent=2)


# ---------- Roblox web API ----------
def _request(url, cookie, method="GET", body=None, csrf=None):
    headers = {
        "User-Agent": UA,
        "Cookie": f".ROBLOSECURITY={cookie}",
        "Referer": "https://www.roblox.com/",
        "Content-Type": "application/json",
    }
    if csrf:
        headers["X-CSRF-TOKEN"] = csrf
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    return urllib.request.urlopen(req, timeout=15)


def get_user(cookie):
    """Returns (id, name) if the cookie is valid, else raises."""
    with _request("https://users.roblox.com/v1/users/authenticated", cookie) as r:
        data = json.loads(r.read())
    return data["id"], data["name"]


class LoginError(Exception):
    pass


def login_with_password(username, password):
    """Signs in with Roblox's login endpoint and returns the .ROBLOSECURITY cookie.
    The password is only sent to Roblox and is never stored.
    Roblox may demand a captcha or 2-step code for some logins; this tool does not
    try to bypass those - it reports them so you can use 'Add (cookie)' instead."""
    import re
    url = "https://auth.roblox.com/v2/login"
    body = json.dumps({"ctype": "Username", "cvalue": username,
                       "password": password}).encode()
    csrf = None
    for _ in range(2):
        headers = {"User-Agent": UA, "Content-Type": "application/json",
                   "Referer": "https://www.roblox.com/"}
        if csrf:
            headers["X-CSRF-TOKEN"] = csrf
        req = urllib.request.Request(url, data=body, method="POST", headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                for header in r.headers.get_all("Set-Cookie") or []:
                    m = re.search(r"\.ROBLOSECURITY=([^;]+)", header)
                    if m and m.group(1):
                        return m.group(1)
                raise LoginError("This account needs a 2-step verification code, which "
                                 "this quick login can't complete. Use 'Add (cookie)'.")
        except urllib.error.HTTPError as e:
            if e.code == 403 and e.headers.get("x-csrf-token") and not csrf:
                csrf = e.headers["x-csrf-token"]
                continue
            try:
                err = json.loads(e.read())["errors"][0]
            except Exception:
                raise LoginError(f"Login failed (HTTP {e.code}).")
            code = err.get("code")
            if code == 1:
                raise LoginError("Incorrect username or password.")
            if code == 2 or "hallenge" in err.get("message", ""):
                raise LoginError("Roblox is asking for a captcha/verification check. "
                                 "Log in once in your browser, then use 'Add (cookie)'.")
            raise LoginError(err.get("message", f"Login failed (HTTP {e.code})."))
    raise LoginError("Login failed. Try again.")


def get_auth_ticket(cookie):
    url = "https://auth.roblox.com/v1/authentication-ticket"
    try:
        _request(url, cookie, "POST", b"{}")
    except urllib.error.HTTPError as e:
        csrf = e.headers.get("x-csrf-token")
        if e.code != 403 or not csrf:
            raise
        with _request(url, cookie, "POST", b"{}", csrf) as r:
            ticket = r.headers.get("rbx-authentication-ticket")
            if ticket:
                return ticket
    raise RuntimeError("Could not get an authentication ticket (cookie expired?)")


def launch_game(cookie, place_id):
    ticket = get_auth_ticket(cookie)
    tracker = str(random.randint(10**10, 10**11 - 1))
    place_url = (
        "https://assetgame.roblox.com/game/PlaceLauncher.ashx?request=RequestGame"
        f"&browserTrackerId={tracker}&placeId={place_id}&isPlayTogetherGame=false"
    )
    uri = (
        "roblox-player:1+launchmode:play"
        f"+gameinfo:{ticket}"
        f"+launchtime:{int(time.time() * 1000)}"
        f"+placelauncherurl:{urllib.parse.quote(place_url, safe='')}"
        f"+browsertrackerid:{tracker}"
        "+robloxLocale:en_us+gameLocale:en_us+channel:+LaunchExp:InApp"
    )
    os.startfile(uri)


# ---------- Multi-instance ----------
_mutex_handle = None


def hold_singleton_mutex():
    """Roblox refuses to start a 2nd client if this mutex already exists.
    Creating it first (and keeping it) lets multiple clients run."""
    global _mutex_handle
    _mutex_handle = kernel32.CreateMutexW(None, True, "ROBLOX_singletonMutex")
    return bool(_mutex_handle) and ctypes.GetLastError() != 183  # 183 = already existed


# ---------- GUI ----------
class LoginDialog(tk.Toplevel):
    """Quick add: username + password. The password is used once, never saved."""

    def __init__(self, app):
        super().__init__(app)
        self.app = app
        self.title("Quick add account")
        self.resizable(False, False)
        self.transient(app)
        self.grab_set()
        ttk.Label(self, text="Username").grid(row=0, column=0, padx=8, pady=6, sticky="e")
        self.user = ttk.Entry(self, width=28)
        self.user.grid(row=0, column=1, padx=8)
        ttk.Label(self, text="Password").grid(row=1, column=0, padx=8, pady=6, sticky="e")
        self.pw = ttk.Entry(self, width=28, show="*")
        self.pw.grid(row=1, column=1, padx=8)
        self.msg = ttk.Label(self, wraplength=300,
                             text="Your password is used once to sign in and is never saved.")
        self.msg.grid(row=2, column=0, columnspan=2, padx=8, pady=4)
        self.btn = ttk.Button(self, text="Sign in & add", command=self.submit)
        self.btn.grid(row=3, column=0, columnspan=2, pady=(2, 10))
        self.pw.bind("<Return>", lambda e: self.submit())
        self.user.focus()

    def submit(self):
        user, pw = self.user.get().strip(), self.pw.get()
        if not user or not pw:
            return
        self.pw.delete(0, "end")  # don't leave the password sitting in the box
        self.btn.state(["disabled"])
        self.msg.config(text="Signing in...")
        threading.Thread(target=self.work, args=(user, pw), daemon=True).start()

    def work(self, user, pw):
        try:
            cookie = login_with_password(user, pw)
            uid, name = get_user(cookie)
        except LoginError as e:
            self.after(0, self.fail, str(e))
            return
        except Exception as e:
            self.after(0, self.fail, f"Network error: {e}")
            return
        self.after(0, self.done, cookie, uid, name)

    def fail(self, text):
        self.msg.config(text=text)
        self.btn.state(["!disabled"])

    def done(self, cookie, uid, name):
        self.app.store(cookie, uid, name)
        self.destroy()


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Roblox Multi-Account Manager")
        self.geometry("640x430")
        self.accounts = load_accounts()

        got_mutex = hold_singleton_mutex()
        status = ("Multi-instance: ACTIVE" if got_mutex else
                  "Multi-instance: NOT active - close Roblox, then restart this tool")
        ttk.Label(self, text=status,
                  foreground="green" if got_mutex else "red").pack(pady=(8, 2))

        self.tree = ttk.Treeview(self, columns=("name", "id", "state"),
                                 show="headings", selectmode="extended", height=10)
        for col, w in (("name", 220), ("id", 140), ("state", 150)):
            self.tree.heading(col, text=col.capitalize())
            self.tree.column(col, width=w)
        self.tree.pack(fill="both", expand=True, padx=10, pady=6)

        row = ttk.Frame(self)
        row.pack(fill="x", padx=10)
        ttk.Label(row, text="Place ID:").pack(side="left")
        self.place = ttk.Entry(row, width=16)
        self.place.pack(side="left", padx=(4, 12))
        ttk.Label(row, text="Delay between launches (s):").pack(side="left")
        self.delay = ttk.Spinbox(row, from_=0, to=60, width=4)
        self.delay.set(10)
        self.delay.pack(side="left", padx=4)

        btns = ttk.Frame(self)
        btns.pack(pady=10)
        for text, cmd in (("Quick add", self.quick_add), ("Add (cookie)", self.add),
                          ("Remove", self.remove),
                          ("Validate", self.validate), ("Launch selected", self.launch)):
            ttk.Button(btns, text=text, command=cmd).pack(side="left", padx=4)

        self.refresh()

    def refresh(self):
        self.tree.delete(*self.tree.get_children())
        for i, a in enumerate(self.accounts):
            self.tree.insert("", "end", iid=str(i),
                             values=(a["name"], a["id"], a.get("state", "")))

    def selected(self):
        return [self.accounts[int(i)] for i in self.tree.selection()]

    def set_state(self, acct, text):
        acct["state"] = text
        self.after(0, self.refresh)

    def add(self):
        cookie = simpledialog.askstring(
            "Add account", "Paste the .ROBLOSECURITY cookie value:", show="*", parent=self)
        if not cookie:
            return
        cookie = cookie.strip().strip('"')
        try:
            uid, name = get_user(cookie)
        except Exception as e:
            messagebox.showerror("Invalid cookie", f"Could not sign in with that cookie.\n\n{e}")
            return
        self.store(cookie, uid, name)

    def store(self, cookie, uid, name):
        self.accounts = [a for a in self.accounts if a["id"] != uid]
        self.accounts.append({"id": uid, "name": name, "cookie": protect(cookie)})
        save_accounts(self.accounts)
        self.refresh()

    def quick_add(self):
        LoginDialog(self)

    def remove(self):
        sel = self.selected()
        if sel and messagebox.askyesno("Remove", f"Remove {len(sel)} account(s)?"):
            ids = {a["id"] for a in sel}
            self.accounts = [a for a in self.accounts if a["id"] not in ids]
            save_accounts(self.accounts)
            self.refresh()

    def validate(self):
        def work(accts):
            for a in accts:
                try:
                    get_user(unprotect(a["cookie"]))
                    self.set_state(a, "valid")
                except Exception:
                    self.set_state(a, "EXPIRED - re-add")
        threading.Thread(target=work, args=(self.selected() or self.accounts,),
                         daemon=True).start()

    def launch(self):
        place = self.place.get().strip()
        if not place.isdigit():
            messagebox.showwarning("Place ID", "Enter a numeric Place ID.")
            return
        accts = self.selected()
        if not accts:
            messagebox.showinfo("Launch", "Select at least one account.")
            return
        try:
            delay = float(self.delay.get())
        except ValueError:
            delay = 10

        def work():
            for n, a in enumerate(accts):
                try:
                    self.set_state(a, "launching...")
                    launch_game(unprotect(a["cookie"]), place)
                    self.set_state(a, "launched")
                except Exception as e:
                    self.set_state(a, f"failed: {str(e)[:30]}")
                if n < len(accts) - 1:
                    time.sleep(delay)  # stagger so clients don't all load at once
        threading.Thread(target=work, daemon=True).start()


if __name__ == "__main__":
    App().mainloop()
