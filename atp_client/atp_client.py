import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import requests
import json
import uuid
import threading
from datetime import datetime
from urllib.parse import urlparse

class FinanceATPClient:
    def __init__(self, root):
        self.root = root
        self.root.title("FinanceATP API Client")
        self.root.geometry("900x700")

        # デフォルト設定
        self.base_url = tk.StringVar(value="http://localhost:3000/api/v1")
        self.api_key = tk.StringVar(value="your-api-key-here")

        # スタイル設定
        style = ttk.Style()
        style.theme_use('clam')

        self.create_layout()

    def create_layout(self):
        # --- 上部: 設定エリア ---
        config_frame = ttk.LabelFrame(self.root, text="API Configuration", padding=10)
        config_frame.pack(fill="x", padx=10, pady=5)

        ttk.Label(config_frame, text="Base URL:").grid(row=0, column=0, padx=5)
        ttk.Entry(config_frame, textvariable=self.base_url, width=40).grid(row=0, column=1, padx=5)

        ttk.Label(config_frame, text="X-API-Key:").grid(row=0, column=2, padx=5)
        ttk.Entry(config_frame, textvariable=self.api_key, width=20).grid(row=0, column=3, padx=5)

        ttk.Button(config_frame, text="Health Check", command=self.check_health).grid(row=0, column=4, padx=10)

        # --- 中部: 機能タブ ---
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(expand=True, fill="both", padx=10, pady=5)

        self.create_tab_read_users()
        self.create_tab_write_users()
        self.create_tab_read_accounts()
        self.create_tab_write_transfers()
        self.create_tab_admin_mint()
        self.create_tab_admin_burn()
        self.create_tab_admin_events()
        self.create_tab_admin_api_keys()

        # --- 下部: ログ/レスポンスエリア ---
        log_frame = ttk.LabelFrame(self.root, text="Response / Logs", padding=10)
        log_frame.pack(fill="both", expand=True, padx=10, pady=5)

        self.log_area = scrolledtext.ScrolledText(log_frame, height=10, state='disabled', font=("Consolas", 9))
        self.log_area.pack(fill="both", expand=True)
        
        # クリアボタン
        ttk.Button(log_frame, text="Clear Log", command=self.clear_log).pack(anchor="e", pady=5)

    def create_tab_read_users(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="read:users")

        frame = ttk.LabelFrame(tab, text="Get User Info", padding=10)
        frame.pack(fill="x", padx=10, pady=5)

        self.ru_id = tk.StringVar()
        ttk.Label(frame, text="User ID:").grid(row=0, column=0, padx=5, pady=5)
        ttk.Entry(frame, textvariable=self.ru_id, width=36).grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(frame, text="GET Info", command=self.get_user).grid(row=0, column=2, padx=5, pady=5)

    def create_tab_write_users(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="write:users")

        # ユーザー作成
        frame_create = ttk.LabelFrame(tab, text="Create User", padding=10)
        frame_create.pack(fill="x", padx=10, pady=5)

        self.cu_id = tk.StringVar()
        self.cu_name = tk.StringVar()
        self.cu_email = tk.StringVar()
        self.cu_display = tk.StringVar()

        grid_opts = {'padx': 5, 'pady': 2, 'sticky': 'w'}
        
        ttk.Label(frame_create, text="User ID (UUID):").grid(row=0, column=0, **grid_opts)
        entry_uuid = ttk.Entry(frame_create, textvariable=self.cu_id, width=36)
        entry_uuid.grid(row=0, column=1, **grid_opts)
        ttk.Button(frame_create, text="Gen UUID", command=lambda: self.cu_id.set(str(uuid.uuid4()))).grid(row=0, column=2, **grid_opts)

        ttk.Label(frame_create, text="Username:").grid(row=1, column=0, **grid_opts)
        ttk.Entry(frame_create, textvariable=self.cu_name, width=20).grid(row=1, column=1, **grid_opts)

        ttk.Label(frame_create, text="Email:").grid(row=2, column=0, **grid_opts)
        ttk.Entry(frame_create, textvariable=self.cu_email, width=30).grid(row=2, column=1, **grid_opts)
        
        ttk.Label(frame_create, text="Display Name:").grid(row=3, column=0, **grid_opts)
        ttk.Entry(frame_create, textvariable=self.cu_display, width=30).grid(row=3, column=1, **grid_opts)

        ttk.Button(frame_create, text="POST /users", command=self.create_user).grid(row=4, column=1, pady=10)

        # ユーザー更新・削除
        frame_manage = ttk.LabelFrame(tab, text="Update / Delete User", padding=10)
        frame_manage.pack(fill="x", padx=10, pady=5)

        self.mu_id = tk.StringVar()
        self.mu_display = tk.StringVar()
        self.mu_email = tk.StringVar()

        ttk.Label(frame_manage, text="Target User ID:").grid(row=0, column=0, **grid_opts)
        ttk.Entry(frame_manage, textvariable=self.mu_id, width=36).grid(row=0, column=1, **grid_opts)

        ttk.Label(frame_manage, text="New Display Name:").grid(row=1, column=0, **grid_opts)
        ttk.Entry(frame_manage, textvariable=self.mu_display, width=30).grid(row=1, column=1, **grid_opts)

        ttk.Label(frame_manage, text="New Email:").grid(row=2, column=0, **grid_opts)
        ttk.Entry(frame_manage, textvariable=self.mu_email, width=30).grid(row=2, column=1, **grid_opts)

        ttk.Button(frame_manage, text="PATCH (Update)", command=self.update_user).grid(row=3, column=1, sticky='w', pady=5)
        ttk.Button(frame_manage, text="DELETE (Revoke)", command=self.delete_user).grid(row=3, column=1, sticky='e', pady=5, padx=20)

    def create_tab_read_accounts(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="read:accounts")

        frame = ttk.LabelFrame(tab, text="Get Balance", padding=10)
        frame.pack(fill="x", padx=10, pady=5)

        self.ra_id = tk.StringVar()
        ttk.Label(frame, text="User ID:").grid(row=0, column=0, padx=5, pady=5)
        ttk.Entry(frame, textvariable=self.ra_id, width=36).grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(frame, text="GET Balance", command=self.get_balance).grid(row=0, column=2, padx=5, pady=5)

    def create_tab_write_transfers(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="write:transfers")

        frame = ttk.LabelFrame(tab, text="Execute Transfer", padding=10)
        frame.pack(fill="x", padx=10, pady=5)

        self.tr_from = tk.StringVar()
        self.tr_to = tk.StringVar()
        self.tr_amount = tk.StringVar()
        self.tr_memo = tk.StringVar()

        grid_opts = {'padx': 5, 'pady': 5, 'sticky': 'w'}

        ttk.Label(frame, text="From User ID:").grid(row=0, column=0, **grid_opts)
        ttk.Entry(frame, textvariable=self.tr_from, width=36).grid(row=0, column=1, **grid_opts)

        ttk.Label(frame, text="To User ID:").grid(row=1, column=0, **grid_opts)
        ttk.Entry(frame, textvariable=self.tr_to, width=36).grid(row=1, column=1, **grid_opts)

        ttk.Label(frame, text="Amount:").grid(row=2, column=0, **grid_opts)
        ttk.Entry(frame, textvariable=self.tr_amount, width=20).grid(row=2, column=1, **grid_opts)
        ttk.Label(frame, text="(e.g. 100.00000000)").grid(row=2, column=2, **grid_opts)

        ttk.Label(frame, text="Memo:").grid(row=3, column=0, **grid_opts)
        ttk.Entry(frame, textvariable=self.tr_memo, width=40).grid(row=3, column=1, **grid_opts)

        ttk.Button(frame, text="POST /transfers", command=self.execute_transfer).grid(row=4, column=1, pady=10)

    def create_tab_admin_mint(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="admin:mint")

        # Mint
        frame_mint = ttk.LabelFrame(tab, text="Mint ATP (Issue)", padding=10)
        frame_mint.pack(fill="x", padx=10, pady=5)

        self.mint_to = tk.StringVar()
        self.mint_amount = tk.StringVar()
        self.mint_reason = tk.StringVar()

        grid_opts = {'padx': 5, 'pady': 2, 'sticky': 'w'}

        ttk.Label(frame_mint, text="Recipient User ID:").grid(row=0, column=0, **grid_opts)
        ttk.Entry(frame_mint, textvariable=self.mint_to, width=36).grid(row=0, column=1, **grid_opts)

        ttk.Label(frame_mint, text="Amount:").grid(row=1, column=0, **grid_opts)
        ttk.Entry(frame_mint, textvariable=self.mint_amount, width=20).grid(row=1, column=1, **grid_opts)

        ttk.Label(frame_mint, text="Reason:").grid(row=2, column=0, **grid_opts)
        ttk.Entry(frame_mint, textvariable=self.mint_reason, width=30).grid(row=2, column=1, **grid_opts)

        ttk.Button(frame_mint, text="POST /admin/mint", command=self.execute_mint).grid(row=3, column=1, pady=5)

    def create_tab_admin_burn(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="admin:burn")

        frame_burn = ttk.LabelFrame(tab, text="Burn ATP", padding=10)
        frame_burn.pack(fill="x", padx=10, pady=5)

        self.burn_from = tk.StringVar()
        self.burn_amount = tk.StringVar()
        self.burn_reason = tk.StringVar()

        grid_opts = {'padx': 5, 'pady': 2, 'sticky': 'w'}

        ttk.Label(frame_burn, text="From User ID:").grid(row=0, column=0, **grid_opts)
        ttk.Entry(frame_burn, textvariable=self.burn_from, width=36).grid(row=0, column=1, **grid_opts)

        ttk.Label(frame_burn, text="Amount:").grid(row=1, column=0, **grid_opts)
        ttk.Entry(frame_burn, textvariable=self.burn_amount, width=20).grid(row=1, column=1, **grid_opts)

        ttk.Label(frame_burn, text="Reason:").grid(row=2, column=0, **grid_opts)
        ttk.Entry(frame_burn, textvariable=self.burn_reason, width=30).grid(row=2, column=1, **grid_opts)

        ttk.Button(frame_burn, text="POST /admin/burn", command=self.execute_burn).grid(row=3, column=1, pady=5)

    def create_tab_admin_events(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="admin:events")

        list_frame = ttk.LabelFrame(tab, text="Event Log", padding=10)
        list_frame.pack(fill="both", expand=True, padx=10, pady=5)

        columns = ("id", "type", "aggregate_id", "created_at")
        self.events_tree = ttk.Treeview(list_frame, columns=columns, show="headings", height=15)
        
        self.events_tree.heading("id", text="Event ID")
        self.events_tree.heading("type", text="Type")
        self.events_tree.heading("aggregate_id", text="Aggregate ID")
        self.events_tree.heading("created_at", text="Created At")
        
        self.events_tree.column("id", width=220)
        self.events_tree.column("type", width=150)
        self.events_tree.column("aggregate_id", width=220)
        self.events_tree.column("created_at", width=150)
        
        self.events_tree.pack(fill="both", expand=True, side="left")
        
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.events_tree.yview)
        scrollbar.pack(side="right", fill="y")
        self.events_tree.configure(yscrollcommand=scrollbar.set)
        
        ttk.Button(list_frame, text="Refresh Events", command=self.list_events).pack(anchor="s", pady=5)
        self.events_tree.bind("<<TreeviewSelect>>", self.on_event_select)
        self.event_data_map = {}

    def create_tab_admin_api_keys(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="admin:api-keys")

        # --- List Area ---
        list_frame = ttk.LabelFrame(tab, text="Existing API Keys", padding=10)
        list_frame.pack(fill="both", expand=True, padx=10, pady=5)

        columns = ("id", "name", "prefix", "permissions", "rate_limit", "active", "created")
        self.keys_tree = ttk.Treeview(list_frame, columns=columns, show="headings", height=8)
        
        headers = {
            "id": "ID", "name": "Name", "prefix": "Prefix", 
            "permissions": "Permissions", "rate_limit": "Rate Limit", 
            "active": "Active", "created": "Created"
        }
        widths = {
            "id": 200, "name": 100, "prefix": 60, 
            "permissions": 150, "rate_limit": 80, 
            "active": 60, "created": 120
        }

        for col, text in headers.items():
            self.keys_tree.heading(col, text=text)
            self.keys_tree.column(col, width=widths[col])

        self.keys_tree.pack(fill="both", expand=True, side="left")
        
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.keys_tree.yview)
        scrollbar.pack(side="right", fill="y")
        self.keys_tree.configure(yscrollcommand=scrollbar.set)

        ttk.Button(list_frame, text="Refresh List", command=self.list_api_keys).pack(anchor="s", pady=5)
        
        self.keys_tree.bind("<<TreeviewSelect>>", self.on_key_select)

        # --- Management Area ---
        manage_frame = ttk.LabelFrame(tab, text="Manage API Key", padding=10)
        manage_frame.pack(fill="x", padx=10, pady=5)

        self.ak_id = tk.StringVar()
        self.ak_name = tk.StringVar()
        self.ak_rate = tk.StringVar(value="1000")
        self.ak_active = tk.BooleanVar(value=True)

        grid_opts = {'padx': 5, 'pady': 2, 'sticky': 'w'}

        ttk.Label(manage_frame, text="Key ID:").grid(row=0, column=0, **grid_opts)
        ttk.Entry(manage_frame, textvariable=self.ak_id, width=36).grid(row=0, column=1, **grid_opts)
        ttk.Button(manage_frame, text="Gen UUID", command=lambda: self.ak_id.set(str(uuid.uuid4()))).grid(row=0, column=2, **grid_opts)
        ttk.Button(manage_frame, text="Clear Selection", command=self.clear_key_selection).grid(row=0, column=3, **grid_opts)

        ttk.Label(manage_frame, text="Name:").grid(row=1, column=0, **grid_opts)
        ttk.Entry(manage_frame, textvariable=self.ak_name, width=30).grid(row=1, column=1, **grid_opts)

        ttk.Label(manage_frame, text="Permissions:").grid(row=2, column=0, padx=5, pady=2, sticky='nw')
        
        perm_frame = ttk.Frame(manage_frame)
        perm_frame.grid(row=2, column=1, columnspan=3, **grid_opts)
        
        self.available_permissions = [
            "read:users", "write:users", "read:accounts", "write:transfers",
            "admin:mint", "admin:burn", "admin:events", "admin:api-keys"
        ]
        self.perm_vars = {}
        for i, perm in enumerate(self.available_permissions):
            self.perm_vars[perm] = tk.BooleanVar()
            ttk.Checkbutton(perm_frame, text=perm, variable=self.perm_vars[perm]).grid(row=i//3, column=i%3, sticky='w', padx=2)

        ttk.Label(manage_frame, text="Rate Limit (/min):").grid(row=3, column=0, **grid_opts)
        ttk.Entry(manage_frame, textvariable=self.ak_rate, width=10).grid(row=3, column=1, **grid_opts)

        ttk.Checkbutton(manage_frame, text="Is Active", variable=self.ak_active).grid(row=3, column=2, **grid_opts)

        btn_frame = ttk.Frame(manage_frame)
        btn_frame.grid(row=4, column=0, columnspan=3, pady=10)

        ttk.Button(btn_frame, text="Create New Key", command=self.create_api_key).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Update Key", command=self.update_api_key).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Revoke (Delete)", command=self.delete_api_key).pack(side="left", padx=5)

    # --- Logic & API Calls ---

    def log(self, message):
        self.log_area.config(state='normal')
        self.log_area.insert(tk.END, f"[{datetime.now().strftime('%H:%M:%S')}] {message}\n")
        self.log_area.see(tk.END)
        self.log_area.config(state='disabled')

    def clear_log(self):
        self.log_area.config(state='normal')
        self.log_area.delete(1.0, tk.END)
        self.log_area.config(state='disabled')

    def send_request(self, method, endpoint, payload=None, extra_headers=None, callback=None, override_url=None):
        def run():
            if override_url:
                url = override_url
            else:
                url = f"{self.base_url.get()}{endpoint}"
            headers = {
                "Content-Type": "application/json",
                "X-API-Key": self.api_key.get()
            }
            
            # 冪等性キーの自動付与 (POSTの場合)
            if method == "POST":
                headers["Idempotency-Key"] = str(uuid.uuid4())

            if extra_headers:
                headers.update(extra_headers)

            self.log(f"Request: {method} {url}")
            if payload:
                self.log(f"Payload: {json.dumps(payload, indent=2)}")

            try:
                response = requests.request(method, url, headers=headers, json=payload)
                
                try:
                    resp_json = response.json()
                    formatted_resp = json.dumps(resp_json, indent=2, ensure_ascii=False)
                except:
                    formatted_resp = response.text

                self.log(f"Status: {response.status_code}")
                self.log(f"Response:\n{formatted_resp}\n" + "-"*40)

                if callback:
                    self.root.after(0, callback, response)

            except Exception as e:
                self.log(f"Error: {str(e)}")

        # GUIをフリーズさせないために別スレッドで実行
        threading.Thread(target=run, daemon=True).start()

    def check_health(self):
        try:
            base = self.base_url.get()
            parsed = urlparse(base)
            health_url = f"{parsed.scheme}://{parsed.netloc}/health"
            self.send_request("GET", "", override_url=health_url)
        except Exception:
            self.send_request("GET", "/health")

    def create_user(self):
        user_id = self.cu_id.get().strip()
        if not user_id:
            user_id = str(uuid.uuid4())
            self.cu_id.set(user_id) # UIに反映

        payload = {
            "user_id": user_id,
            "username": self.cu_name.get(),
            "email": self.cu_email.get(),
            "display_name": self.cu_display.get()
        }
        self.send_request("POST", "/users", payload)

    def get_user(self):
        uid = self.ru_id.get().strip()
        if not uid:
            messagebox.showwarning("Error", "User ID is required")
            return
        self.send_request("GET", f"/users/{uid}")

    def get_balance(self):
        uid = self.ra_id.get().strip()
        if not uid:
            messagebox.showwarning("Error", "User ID is required")
            return
        self.send_request("GET", f"/users/{uid}/balance")

    def update_user(self):
        uid = self.mu_id.get().strip()
        if not uid:
            messagebox.showwarning("Error", "User ID is required")
            return
        
        payload = {}
        if self.mu_display.get().strip():
            payload["display_name"] = self.mu_display.get().strip()
        if self.mu_email.get().strip():
            payload["email"] = self.mu_email.get().strip()
            
        if not payload:
            messagebox.showwarning("Error", "No fields to update")
            return
            
        self.send_request("PATCH", f"/users/{uid}", payload)

    def delete_user(self):
        uid = self.mu_id.get().strip()
        if not uid: return
        if messagebox.askyesno("Confirm", f"Delete (Revoke) User {uid}?"):
            self.send_request("DELETE", f"/users/{uid}")

    def execute_transfer(self):
        from_id = self.tr_from.get().strip()
        to_id = self.tr_to.get().strip()
        amount = self.tr_amount.get().strip()

        if not (from_id and to_id and amount):
            messagebox.showwarning("Error", "From, To, and Amount are required")
            return

        payload = {
            "from_user_id": from_id,
            "to_user_id": to_id,
            "amount": amount,
            "memo": self.tr_memo.get()
        }
        
        # 仕様書に基づき、X-Request-User-Id ヘッダーを設定
        # ここでは送金元ユーザーがリクエストしていると仮定
        headers = {"X-Request-User-Id": from_id}
        
        self.send_request("POST", "/transfers", payload, extra_headers=headers)

    def execute_mint(self):
        payload = {
            "recipient_user_id": self.mint_to.get().strip(),
            "amount": self.mint_amount.get().strip(),
            "reason": self.mint_reason.get().strip()
        }
        self.send_request("POST", "/admin/mint", payload)

    def execute_burn(self):
        payload = {
            "from_user_id": self.burn_from.get().strip(),
            "amount": self.burn_amount.get().strip(),
            "reason": self.burn_reason.get().strip()
        }
        self.send_request("POST", "/admin/burn", payload)

    def list_events(self):
        def callback(response):
            for item in self.events_tree.get_children():
                self.events_tree.delete(item)
            self.event_data_map = {}
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    if isinstance(data, dict) and "events" in data:
                        events_list = data["events"]
                    else:
                        events_list = data if isinstance(data, list) else []

                    for event in events_list:
                        eid = event.get("id") or event.get("event_id") or ""
                        item_id = self.events_tree.insert("", "end", values=(
                            eid,
                            event.get("type") or event.get("event_type"),
                            event.get("aggregate_id") or event.get("stream_id"),
                            event.get("created_at")
                        ))
                        self.event_data_map[item_id] = event
                except Exception as e:
                    self.log(f"Error parsing events: {e}")
        self.send_request("GET", "/admin/events", callback=callback)

    def on_event_select(self, event):
        for item_id in self.events_tree.selection():
            if data := self.event_data_map.get(item_id):
                self.log(f"Selected Event:\n{json.dumps(data, indent=2, ensure_ascii=False)}")

    def list_api_keys(self):
        def callback(response):
            # Clear tree
            for item in self.keys_tree.get_children():
                self.keys_tree.delete(item)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    for key in data:
                        perms = ",".join(key.get("permissions", []))
                        self.keys_tree.insert("", "end", values=(
                            key.get("id"),
                            key.get("name"),
                            key.get("key_prefix"),
                            perms,
                            key.get("rate_limit_per_minute"),
                            key.get("is_active"),
                            key.get("created_at")
                        ))
                except Exception as e:
                    self.log(f"Error parsing list: {e}")
        
        self.send_request("GET", "/admin/api-keys", callback=callback)

    def on_key_select(self, event):
        selected_items = self.keys_tree.selection()
        if not selected_items:
            return
        item = selected_items[0]
        values = self.keys_tree.item(item, "values")
        # values: id, name, prefix, permissions, rate_limit, active, created
        
        self.ak_id.set(values[0])
        self.ak_name.set(values[1])
        self.ak_rate.set(values[4])
        
        current_perms = [p.strip() for p in values[3].split(",") if p.strip()]
        for perm, var in self.perm_vars.items():
            var.set(perm in current_perms)
        
        is_active = str(values[5]).lower() == 'true' or str(values[5]) == '1'
        self.ak_active.set(is_active)

    def clear_key_selection(self):
        self.keys_tree.selection_remove(self.keys_tree.selection())
        self.ak_id.set("")
        self.ak_name.set("")
        self.ak_rate.set("1000")
        self.ak_active.set(True)
        for var in self.perm_vars.values():
            var.set(False)

    def show_api_key_popup(self, api_key):
        popup = tk.Toplevel(self.root)
        popup.title("API Key Created")
        popup.geometry("450x150")
        
        ttk.Label(popup, text="API Key created successfully.\nPlease copy and save it now (it won't be shown again):", wraplength=430).pack(pady=10)
        
        entry = ttk.Entry(popup, width=60)
        entry.insert(0, api_key)
        entry.pack(pady=5, padx=10)
        entry.configure(state='readonly') # Read-only but selectable
        
        # Auto-select text
        entry.select_range(0, tk.END)
        entry.focus_set()
        
        ttk.Button(popup, text="Close", command=popup.destroy).pack(pady=10)

    def create_api_key(self):
        perms = [perm for perm, var in self.perm_vars.items() if var.get()]
        payload = {
            "name": self.ak_name.get(),
            "permissions": perms,
            "rate_limit_per_minute": int(self.ak_rate.get() or 1000)
        }
        if self.ak_id.get().strip():
            payload["id"] = self.ak_id.get().strip()

        def on_create(response):
            if response.status_code == 201:
                self.list_api_keys()
                data = response.json()
                if "api_key" in data:
                    self.show_api_key_popup(data["api_key"])
        
        self.send_request("POST", "/admin/api-keys", payload, callback=on_create)

    def update_api_key(self):
        key_id = self.ak_id.get()
        if not key_id: return
        perms = [perm for perm, var in self.perm_vars.items() if var.get()]
        payload = {
            "name": self.ak_name.get(),
            "permissions": perms,
            "rate_limit_per_minute": int(self.ak_rate.get() or 1000),
            "is_active": self.ak_active.get()
        }
        self.send_request("PATCH", f"/admin/api-keys/{key_id}", payload, callback=lambda r: self.list_api_keys() if r.status_code == 200 else None)

    def delete_api_key(self):
        key_id = self.ak_id.get()
        if not key_id: return
        if messagebox.askyesno("Confirm", f"Revoke API Key {key_id}?"):
            self.send_request("DELETE", f"/admin/api-keys/{key_id}", callback=lambda r: self.list_api_keys() if r.status_code == 204 else None)

if __name__ == "__main__":
    root = tk.Tk()
    app = FinanceATPClient(root)
    root.mainloop()
