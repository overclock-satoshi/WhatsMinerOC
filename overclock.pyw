#!/usr/bin/python3
# version: 1.0

from collections.abc import Callable

import threading
import concurrent.futures
import re

import tkinter as tk
from tkinter import ttk

import ssl
from urllib import parse
from http import client, cookies
import ipaddress

ctx = ssl._create_unverified_context()
ctx.set_ciphers('DEFAULT')
ssl._create_default_https_context = lambda: ctx

API_URL = f"/cgi-bin/luci/admin/network/overclock_api"

# helper function
def do_post(ip, url, login_token, data):
	body = parse.urlencode(data).encode('utf-8')
	headers = {
		'Content-Type': 'application/x-www-form-urlencoded',
		'Content-Length': str(len(body)),
	}

	if login_token is not None and len(login_token) > 0:
		c = cookies.SimpleCookie()
		c['sysauth'] = login_token
		headers['Cookie'] = c['sysauth'].OutputString()

	conn = client.HTTPSConnection(ip, timeout=10)
	conn.request('POST', url, body, headers)
	return conn.getresponse()

# helper function
def do_login(ip, login, password):
	data = { 'luci_username': login, 'luci_password': password }
	res = do_post(ip, '/cgi-bin/luci/', '', data)

	c = cookies.SimpleCookie()
	c.load(res.getheader('Set-Cookie', ''))

	return c['sysauth'].value


def validate_float(value):
	if value == "":
		return True

	try:
		v = float(value)
		return v >= 0.0
	except ValueError:
		return False

def validate_int(value):
	if value == "":
		return True

	try:
		v = int(value)
		return v >= 0
	except ValueError:
		return False

ValidIpAddressRegex = re.compile("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$")

def validate_ip(value):
	return ValidIpAddressRegex.match(value) != None


class InpBase:
	def __init__(self, master: tk.Misc, label: str) -> None:
		self.frame = tk.Frame(master)
		self.frame.pack(fill=tk.X, padx=2, pady=2)

		self.lbl = tk.Label(self.frame, text=label, width=16, anchor="w")
		self.lbl.pack(side=tk.LEFT)

class InpLine(InpBase):
	def __init__(self, master: tk.Misc, label: str, validate_fn: Callable[[], None] | None = None) -> None:
		super().__init__(master, label)

		self.val = tk.StringVar()
		self.entry = tk.Entry(self.frame, textvariable=self.val)
		self.entry.pack(fill=tk.X, expand=True)

		if validate_fn:
			self.entry.bind("<KeyPress>", lambda e: validate_fn())
			self.entry.bind("<KeyRelease>", lambda e: validate_fn())


class InpCheck(InpBase):
	def __init__(self, master: tk.Misc, label: str) -> None:
		super().__init__(master, label)

		self.val = tk.BooleanVar()
		self.chk = tk.Checkbutton(self.frame, variable=self.val)
		self.chk.pack(side=tk.LEFT)

class InpCombo(InpBase):
	def __init__(self, master: tk.Misc, label: str, values: list[str]) -> None:
		super().__init__(master, label)

		self.val = tk.StringVar()
		self.combo = ttk.Combobox(self.frame, textvariable=self.val, state="readonly", values=values)
		self.combo.pack(fill=tk.X, expand=True)

def disableChildren(parent):
	for child in parent.winfo_children():
		wtype = child.winfo_class()
		if wtype not in ('Frame','Labelframe'):
			child.configure(state='disable')
		else:
			disableChildren(child)

def enableChildren(parent: tk.Widget):
	for child in parent.winfo_children():
		wtype = child.winfo_class()
		if wtype not in ('Frame', 'Labelframe'):
			if wtype in ('TCombobox'):
				child.configure(state='readonly')  # type: ignore
			else:
				child.configure(state='normal')  # type: ignore
		else:
			enableChildren(child)

def add_checked(d: dict, k: str, v: tk.StringVar, t: type) -> None:
	val = v.get()
	if val != '':
		d[k] = t(val)

def add_checked_combo(d: dict, k: str, v: tk.StringVar, kv: dict) -> None:
	val = v.get()
	if val != '':
		d[k] = kv[val]

class LogModal:
	def __init__(self, parent: tk.Tk) -> None:
		self.parent = parent
		self.root = tk.Toplevel(self.parent)
		self.root.geometry("500x400")
		self.done = False
		self.lck = threading.Lock()

		self.text = tk.Text(self.root, width=0, height=0)
		self.text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

		self.scroll = tk.Scrollbar(self.root, command=self.text.yview)
		self.scroll.pack(side=tk.RIGHT, fill=tk.Y)

		self.text.config(yscrollcommand=self.scroll.set)

		self.root.wait_visibility()
		self.root.grab_set()
		self.root.transient(parent)

	def append_text(self, msg: str) -> None:
		with self.lck:
			self.text.config(state=tk.NORMAL)
			self.text.insert(tk.END, msg)
			self.text.config(state=tk.DISABLED)

	def check_done(self) -> None:
		if self.done:
			self.on_done()

	def on_done(self) -> None:
		self.root.grab_release()
		self.root.destroy()

def apply_ip(ip: str, login: str, password: str, vals: dict, m: LogModal) -> None:
	try:
		m.append_text(f"[{ip}] Login...\n")
		login_token = do_login(ip, login, password)

		if login_token is None or len(login_token) == 0:
			raise Exception("Can't login. Check ip, login and password")

		m.append_text(f"[{ip}] Applying...\n")
		response = do_post(ip, API_URL, login_token, vals)
		m.append_text(f"[{ip}] Result: {response.read().decode()}\n")
	except Exception as ex:
		m.append_text(f"[{ip}] Error: {ex}\n")

def apply_ips(it: ipaddress.IPv4Address, end: ipaddress.IPv4Address, login: str, password: str, vals: dict, m: LogModal):
	m.root.protocol("WM_DELETE_WINDOW", m.check_done)


	m.append_text(f"Apply to range {it}-{end}\n")

	with concurrent.futures.ThreadPoolExecutor(4) as executor:
		while it <= end:
			ip = str(it)
			executor.submit(apply_ip, ip, login, password, vals, m)
			it += 1

		executor.shutdown(wait=True, cancel_futures=False)

	m.append_text(f"Done\n")

	m.done = True

class App:
	def __init__(self, root: tk.Tk) -> None:
		self.root = root
		self.root.title("Overclock")
		self.root.resizable(True, False)
		self.root.minsize(300, 0)

		self.inputs_valid = True

		self.main_frame = self.subframe(self.root)

		self.creds_frame = self.subframe(self.main_frame)
		self.ips_frame = self.subframe(self.main_frame)
		self.enab_frame = self.subframe(self.main_frame)
		self.lc_frame = self.subframe(self.main_frame)
		self.vals_frame = self.subframe(self.main_frame)
		self.hint_frame = self.subframe(self.main_frame)
		self.btns_frame = self.subframe(self.main_frame)

		self.creds_login = InpLine(self.creds_frame, "Login")
		self.creds_password = InpLine(self.creds_frame, "Password")

		self.ip_from = InpLine(self.ips_frame, "IP from", self.check_valids)
		self.ip_to = InpLine(self.ips_frame, "IP to", self.check_valids)

		self.chk_default = InpCheck(self.enab_frame, "Default")

		self.liquid_cooling = InpCombo(self.lc_frame, "Liquid cooling", ['', 'Enable', 'Disable'])

		self.freq_target = InpLine(self.vals_frame, "Freq target", self.check_valids)
		self.voltage_target = InpLine(self.vals_frame, "Voltage target", self.check_valids)
		self.voltage_min = InpLine(self.vals_frame, "Voltage min", self.check_valids)
		self.voltage_limit = InpLine(self.vals_frame, "Voltage limit", self.check_valids)
		self.board_temp_target = InpLine(self.vals_frame, "Board temp target", self.check_valids)
		#self.pass_percent = InpLine(self.vals_frame, "Pass percent", self.check_valids)
		self.power_limit = InpLine(self.vals_frame, "Power limit", self.check_valids)
		self.power_max = InpLine(self.vals_frame, "Power max", self.check_valids)
		#self.power_rate = InpLine(self.vals_frame, "Power rate", self.check_valids)

		self.lbl_hint = tk.Label(self.hint_frame, text="An empty value will not change the setting on device")
		self.lbl_hint.pack(padx=5)

		self.btn_apply = tk.Button(self.btns_frame, text="Apply")
		self.btn_apply.pack(anchor=tk.E, padx=5, pady=5)

		self.btn_apply.bind("<Button-1>", lambda e: self.on_apply())
		self.creds_login.val.set("admin")
		self.creds_password.val.set("admin")
		self.creds_password.entry.config(show="*")
		self.ip_from.val.set("192.168.1.1")
		self.ip_to.val.set("192.168.1.1")
		self.chk_default.chk.bind("<Button-1>", lambda e: self.on_default())

		self.check_valids_misc()
		self.check_valids_vals()

	def check_valids_misc(self) -> bool:
		res = True

		res = res and validate_ip(self.ip_from.val.get())
		res = res and validate_ip(self.ip_to.val.get())

		return res

	def check_valids_vals(self) -> bool:
		res = True

		res = res and validate_int(self.freq_target.val.get())
		res = res and validate_int(self.voltage_target.val.get())
		res = res and validate_int(self.voltage_min.val.get())
		res = res and validate_int(self.voltage_limit.val.get())
		res = res and validate_int(self.board_temp_target.val.get())
		#res = res and validate_float(self.pass_percent.val.get())
		res = res and validate_int(self.power_limit.val.get())
		res = res and validate_int(self.power_max.val.get())
		#res = res and validate_float(self.power_rate.val.get())

		return res

	def check_valids(self) -> None:
		if not self.chk_default.val.get() and not self.check_valids_vals():
			self.on_invalid_inputs()
			return

		if not self.check_valids_misc():
			self.on_invalid_inputs()
			return

		self.on_valid_inputs()

	def on_valid_inputs(self) -> None:
		if not self.inputs_valid:
			enableChildren(self.btns_frame)
			self.inputs_valid = True

	def on_invalid_inputs(self) -> None:
		if self.inputs_valid:
			disableChildren(self.btns_frame)
			self.inputs_valid = False

	def on_default(self) -> None:
		if self.chk_default.val.get(): # called before changing the flag
			enableChildren(self.vals_frame)
			enableChildren(self.lc_frame)

			if self.check_valids_misc() and self.check_valids_vals():
				self.on_valid_inputs()
			else:
				self.on_invalid_inputs()
		else:
			disableChildren(self.vals_frame)
			disableChildren(self.lc_frame)

			if self.check_valids_misc():
				self.on_valid_inputs()
			else:
				self.on_invalid_inputs()

	def on_apply(self) -> None:
		if not self.chk_default.val.get() and not self.check_valids_vals():
			return

		if not self.check_valids_misc():
			return

		login = self.creds_login.val.get()
		password = self.creds_password.val.get()

		vals = {}
		vals['set'] = 1

		if not self.chk_default.val.get():
			add_checked(vals, 'freq_target', self.freq_target.val, int)
			add_checked(vals, 'voltage_target', self.voltage_target.val, int)
			add_checked(vals, 'voltage_min', self.voltage_min.val, int)
			add_checked(vals, 'voltage_limit', self.voltage_limit.val, int)
			add_checked(vals, 'board_temp_target', self.board_temp_target.val, int)
			#add_checked(vals, 'pass_percent', self.pass_percent.val, float)
			add_checked(vals, 'power_limit', self.power_limit.val, int)
			add_checked(vals, 'power_max', self.power_max.val, int)
			#add_checked(vals, 'power_rate', self.power_rate.val, float)
			add_checked_combo(vals, 'liquid_cooling', self.liquid_cooling.val, { 'Enable': 1, 'Disable': 0 })

		it = ipaddress.IPv4Address(self.ip_from.val.get())
		end = ipaddress.IPv4Address(self.ip_to.val.get())

		m = LogModal(self.root)

		t = threading.Thread(target=apply_ips,args=[it, end, login, password, vals, m])
		t.start()

		self.root.wait_window(m.root)
		t.join()

	def subframe(self, master: tk.Misc) -> tk.Frame:
		f = tk.Frame(master, relief=tk.RAISED, borderwidth=0)
		f.pack(fill=tk.X, pady=3, expand=True)
		return f


if __name__ == "__main__":
	root = tk.Tk()
	app = App(root)
	root.mainloop()

