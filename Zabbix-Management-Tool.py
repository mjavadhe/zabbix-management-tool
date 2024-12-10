import tkinter as tk
from tkinter import ttk, messagebox
import requests
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from threading import Thread
import time

class ZabbixManagementApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Zabbix Management Tool")
        self.root.geometry("800x800")

        # Create Notebook (Tabbed Interface)
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # API Configuration Variables
        self.zabbix_url = tk.StringVar()
        self.api_token = tk.StringVar()
        self.is_api_configured = False

        # Initialize global variables
        self.current_host_id = None
        self.current_item_id = None
        self.selected_item_name = tk.StringVar(value="Select an Item")

        # Create Tabs
        self.create_api_config_tab()
        self.create_add_host_tab()
        self.create_delete_host_tab()
        self.create_manage_host_status_tab()
        self.create_monitoring_tab()
        self.create_ids_tab()

        # Disable All Tabs Except API Configuration
        self.disable_all_tabs()

    def disable_all_tabs(self):
        # Disable all tabs except the first one (API Configuration)
        for i in range(1, self.notebook.index("end")):
            self.notebook.tab(i, state="disabled")

    def enable_all_tabs(self):
        # Enable all tabs except the first one
        for i in range(1, self.notebook.index("end")):
            self.notebook.tab(i, state="normal")

    def create_api_config_tab(self):
        self.api_config_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.api_config_frame, text="API Configuration")

        # Form frame
        form_frame = ttk.Frame(self.api_config_frame, padding=20)
        form_frame.pack(pady=20)

        # Zabbix URL
        ttk.Label(form_frame, text="Zabbix URL:").grid(row=0, column=0, sticky=tk.W, pady=5)
        zabbix_url_entry = ttk.Entry(form_frame, width=50, textvariable=self.zabbix_url)
        zabbix_url_entry.grid(row=0, column=1, pady=5)

        # API Token
        ttk.Label(form_frame, text="API Token:").grid(row=1, column=0, sticky=tk.W, pady=5)
        api_token_entry = ttk.Entry(form_frame, width=50, textvariable=self.api_token, show="*")
        api_token_entry.grid(row=1, column=1, pady=5)

        # Validate Button
        validate_button = ttk.Button(form_frame, text="Validate & Save", command=self.validate_api_config)
        validate_button.grid(row=2, column=1, pady=20, sticky=tk.E)

        # Result Label
        self.api_config_result_label = ttk.Label(self.api_config_frame, text="", font=("Arial", 12))
        self.api_config_result_label.pack()

    def validate_api_config(self):
        url = self.zabbix_url.get().strip()
        token = self.api_token.get().strip()

        if not url or not token:
            self.api_config_result_label.config(text="URL and Token are required!", foreground="red")
            return

        # Test API connection
        payload = {
            "jsonrpc": "2.0",
            "method": "apiinfo.version",
            "params": [],
            "id": 1
        }

        try:
            response = requests.post(url, json=payload, headers={'Content-Type': 'application/json'})
            result = response.json()

            if "result" in result:
                self.is_api_configured = True
                self.api_config_result_label.config(text="API Configuration Successful!", foreground="green")
                
                # Enable other tabs
                self.enable_all_tabs()
            else:
                self.is_api_configured = False
                self.api_config_result_label.config(text="Invalid API Configuration", foreground="red")
        except Exception as e:
            self.is_api_configured = False
            self.api_config_result_label.config(text=f"Connection Error: {str(e)}", foreground="red")

    def create_add_host_tab(self):
        add_host_frame = ttk.Frame(self.notebook)
        self.notebook.add(add_host_frame, text="Add Host")

        # Form frame
        form_frame = ttk.Frame(add_host_frame, padding=20)
        form_frame.pack(pady=20)

        # Host Name
        ttk.Label(form_frame, text="Host Name:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.host_entry = ttk.Entry(form_frame, width=40)
        self.host_entry.grid(row=0, column=1, pady=5)

        # IP Address
        ttk.Label(form_frame, text="IP Address:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.ip_entry = ttk.Entry(form_frame, width=40)
        self.ip_entry.grid(row=1, column=1, pady=5)

        # Group ID
        ttk.Label(form_frame, text="Group ID:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.group_entry = ttk.Entry(form_frame, width=40)
        self.group_entry.grid(row=2, column=1, pady=5)

        # Add Host button
        submit_button = ttk.Button(form_frame, text="Add Host", command=self.submit_host)
        submit_button.grid(row=3, column=1, padx=10, pady=5)

        # Result Label
        self.add_host_result_label = ttk.Label(add_host_frame, text="", font=("Arial", 12))
        self.add_host_result_label.pack()

    

    def create_add_host_tab(self):
        add_host_frame = ttk.Frame(self.notebook)
        self.notebook.add(add_host_frame, text="Add Host")

        # Form frame
        form_frame = ttk.Frame(add_host_frame, padding=20)
        form_frame.pack(pady=20)

        # Host Name
        ttk.Label(form_frame, text="Host Name:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.host_entry = ttk.Entry(form_frame, width=40)
        self.host_entry.grid(row=0, column=1, pady=5)

        # Add Host button
        submit_button = ttk.Button(form_frame, text="Add Host", command=self.submit_host)
        submit_button.grid(row=0, column=2, padx=10, pady=5)

        # IP Address
        ttk.Label(form_frame, text="IP Address:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.ip_entry = ttk.Entry(form_frame, width=40)
        self.ip_entry.grid(row=1, column=1, pady=5)

        # Group ID
        ttk.Label(form_frame, text="Group ID:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.group_entry = ttk.Entry(form_frame, width=40)
        self.group_entry.grid(row=2, column=1, pady=5)

        # Template IDs
        self.template_entries = []
        self.add_template_field(form_frame)

        # Result Label
        self.add_host_result_label = ttk.Label(add_host_frame, text="", font=("Arial", 12))
        self.add_host_result_label.pack()

    def add_template_field(self, form_frame):
        row = len(self.template_entries) + 3  # Start from row 3 (after Host, IP, Group)
        
        # Create Template ID field
        template_label = ttk.Label(form_frame, text=f"Template ID {row - 2}:")
        template_label.grid(row=row, column=0, sticky=tk.W, pady=5)
        
        template_entry = ttk.Entry(form_frame, width=40)
        template_entry.grid(row=row, column=1, pady=5)
        self.template_entries.append(template_entry)

        # Add "+" button to create new template field
        if row - 2 < 3:  # Limit the number of "+" buttons to 3 for simplicity
            add_button = ttk.Button(form_frame, text="+", command=lambda: self.add_template_field(form_frame))
            add_button.grid(row=row, column=2, pady=5)

    def submit_host(self):
        ip_address = self.ip_entry.get().strip()
        group_id = self.group_entry.get().strip()
        host_name = self.host_entry.get().strip()

        if not (ip_address and group_id and host_name):
            self.add_host_result_label.config(
                text="All fields are required!", foreground="red"
            )
            return

        template_ids = [entry.get().strip() for entry in self.template_entries if entry.get().strip()]

        if not template_ids:
            self.add_host_result_label.config(
                text="At least one Template ID is required!", foreground="red"
            )
            return

        payload = {
            "jsonrpc": "2.0",
            "method": "host.create",
            "params": {
                "host": host_name,
                "interfaces": [
                    {
                        "type": 1,
                        "main": 1,
                        "useip": 1,
                        "ip": ip_address,
                        "dns": "",
                        "port": "10050",
                    }
                ],
                "groups": [{"groupid": group_id}],
                "templates": [{"templateid": template_id} for template_id in template_ids],
            },
            "auth": self.api_token.get(),
            "id": 1,
        }

        response = requests.post(self.zabbix_url.get(), json=payload)
        result = response.json()

        if "result" in result:
            self.add_host_result_label.config(
                text=f"Host '{host_name}' added successfully! Host ID: {result['result']['hostids']}",
                foreground="green",
            )
        else:
            error_message = result.get("error", {}).get("data", "Unknown error")
            self.add_host_result_label.config(
                text=f"Failed to add host: {error_message}",
                foreground="red",
            )


    def create_delete_host_tab(self):
        delete_host_frame = ttk.Frame(self.notebook)
        self.notebook.add(delete_host_frame, text="Delete Host")

        # Form frame
        form_frame = ttk.Frame(delete_host_frame, padding=20)
        form_frame.pack(pady=20)

        # Host Name
        ttk.Label(form_frame, text="Host Name:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.delete_host_entry = ttk.Entry(form_frame, width=40)
        self.delete_host_entry.grid(row=0, column=1, pady=5)

        # Delete Button
        delete_button = ttk.Button(form_frame, text="Delete Host", command=self.handle_delete)
        delete_button.grid(row=1, column=1, pady=20, sticky=tk.E)

        # Result Label
        self.delete_host_result_label = ttk.Label(delete_host_frame, text="", font=("Arial", 12))
        self.delete_host_result_label.pack()

    def handle_delete(self):
        host_name = self.delete_host_entry.get().strip()

        if not host_name:
            self.delete_host_result_label.config(text="Host Name is required!", foreground="red")
            return

        host_id = self.get_host_id_by_name(host_name)

        if host_id:
            response = self.delete_host_by_id(host_id)
            if "result" in response:
                self.delete_host_result_label.config(
                    text=f"Host '{host_name}' deleted successfully.",
                    foreground="green",
                )
            else:
                error_message = response.get("error", {}).get("data", "Unknown error")
                self.delete_host_result_label.config(
                    text=f"Failed to delete host: {error_message}",
                    foreground="red",
                )
        else:
            self.delete_host_result_label.config(text=f"No host found with the name '{host_name}'.", foreground="red")

    def get_host_id_by_name(self, host_name):
        payload = {
            "jsonrpc": "2.0",
            "method": "host.get",
            "params": {
                "output": ["hostid"],
                "filter": {"host": [host_name]}
            },
            "auth": self.api_token.get(),
            "id": 1
        }
        response = requests.post(self.zabbix_url.get(), json=payload)
        result = response.json().get("result")
        if result:
            return result[0]["hostid"]
        return None

    def delete_host_by_id(self, host_id):
        payload = {
            "jsonrpc": "2.0",
            "method": "host.delete",
            "params": [host_id],
            "auth": self.api_token.get(),
            "id": 2
        }
        response = requests.post(self.zabbix_url.get(), json=payload)
        return response.json()

    def create_manage_host_status_tab(self):
        manage_host_frame = ttk.Frame(self.notebook)
        self.notebook.add(manage_host_frame, text="Manage Host Status")

        # Host Name Label and Entry
        host_name_label = ttk.Label(manage_host_frame, text="Host Name:")
        host_name_label.pack(pady=10)
        self.manage_host_name_entry = ttk.Entry(manage_host_frame, width=30)
        self.manage_host_name_entry.pack(pady=5)

        # Action Label and Combo Box
        action_label = ttk.Label(manage_host_frame, text="Action:")
        action_label.pack(pady=10)
        self.action_combo = ttk.Combobox(manage_host_frame, values=["Enable", "Disable"], state="readonly", width=27)
        self.action_combo.pack(pady=5)
        self.action_combo.set("Select an Action")

        # Submit Button
        submit_button = ttk.Button(manage_host_frame, text="Submit", command=self.handle_host_status)
        submit_button.pack(pady=20)

    def handle_host_status(self):
        host_name = self.manage_host_name_entry.get().strip()
        action = self.action_combo.get()

        if not host_name:
            messagebox.showerror("Input Error", "Please enter a host name.")
            return

        status_map = {"Enable": 0, "Disable": 1}
        if action not in status_map:
            messagebox.showerror("Input Error", "Please select a valid action.")
            return

        host_id = self.get_host_id_by_name(host_name)

        if host_id:
            result = self.set_host_status(host_id, status_map[action])
            if "result" in result:
                messagebox.showinfo("Success", f"Host '{host_name}' successfully {action.lower()}d.")
            else:
                error_msg = result.get("error", {}).get("data", "Unknown error")
                messagebox.showerror("Error", f"Failed to {action.lower()} host. {error_msg}")
        else:
            messagebox.showerror("Error", f"Host '{host_name}' not found.")

    def set_host_status(self, host_id, status):
        payload = {
            "jsonrpc": "2.0",
            "method": "host.update",
            "params": {
                "hostid": host_id,
                "status": status
            },
            "id": 2,
            "auth": self.api_token.get()
        }
        response = requests.post(self.zabbix_url.get(), json=payload)
        return response.json()

    def create_monitoring_tab(self):
        monitoring_frame = ttk.Frame(self.notebook)
        self.notebook.add(monitoring_frame, text="Monitoring")

        # Top frame for inputs
        top_frame = ttk.Frame(monitoring_frame, padding=10)
        top_frame.pack(fill=tk.X)

        ttk.Label(top_frame, text="Hostname:").pack(side=tk.LEFT, padx=5)
        self.monitoring_hostname_entry = ttk.Entry(top_frame, width=20)
        self.monitoring_hostname_entry.pack(side=tk.LEFT, padx=5)

        load_button = ttk.Button(top_frame, text="Load Items", command=self.populate_items)
        load_button.pack(side=tk.LEFT, padx=10)

        self.monitoring_result_label = ttk.Label(top_frame, text="", font=("Arial", 12))
        self.monitoring_result_label.pack(side=tk.LEFT, padx=10)

        # Middle frame for graphs
        middle_frame = ttk.Frame(monitoring_frame, padding=10)
        middle_frame.pack(fill=tk.BOTH, expand=True)

        self.fig, self.ax = plt.subplots(figsize=(10, 5))
        self.canvas = FigureCanvasTkAgg(self.fig, master=middle_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        # Bottom frame for item selection
        bottom_frame = ttk.Frame(monitoring_frame, padding=10)
        bottom_frame.pack(fill=tk.X)

        ttk.Label(bottom_frame, text="Item:").pack(side=tk.LEFT, padx=5)
        self.item_menu = ttk.OptionMenu(bottom_frame, self.selected_item_name, "Select an Item")
        self.item_menu.pack(side=tk.LEFT, padx=5)

        self.monitoring_value_label = ttk.Label(bottom_frame, text="", font=("Arial", 14))
        self.monitoring_value_label.pack(side=tk.LEFT, padx=10)

        # Start real-time updater thread
        Thread(target=self.update_data, daemon=True).start()

    def populate_items(self):
        hostname = self.monitoring_hostname_entry.get()
        host_id = self.get_host_id_by_name(hostname)

        if not host_id:
            self.monitoring_result_label.config(text=f"Host '{hostname}' not found!", foreground="red")
            return

        self.current_host_id = host_id
        items = self.get_host_items(host_id)

        # Populate items dropdown
        self.item_menu["menu"].delete(0, "end")
        for item in items:
            self.item_menu["menu"].add_command(
                label=item["name"], command=lambda i=item: self.select_item(i)
            )

        self.monitoring_result_label.config(text=f"Items loaded for {hostname}", foreground="green")

    def get_host_items(self, host_id):
        payload = {
            "jsonrpc": "2.0",
            "method": "item.get",
            "params": {
                "hostids": host_id,
                "output": ["itemid", "name", "key_"],
            },
            "auth": self.api_token.get(),
            "id": 1,
        }
        response = requests.post(self.zabbix_url.get(), json=payload).json()
        return response.get("result", [])

    def get_item_data(self, item_id, limit=10):
        payload = {
            "jsonrpc": "2.0",
            "method": "history.get",
            "params": {
                "history": 3,  # Float type
                "itemids": item_id,
                "sortfield": "clock",
                "sortorder": "DESC",
                "limit": limit,
            },
            "auth": self.api_token.get(),
            "id": 1,
        }
        response = requests.post(self.zabbix_url.get(), json=payload).json()
        history = response.get("result", [])
        return [float(h["value"]) for h in history][::-1] if history else []

    def update_data(self):
        while True:
            if self.current_item_id:
                try:
                    data = self.get_item_data(self.current_item_id)
                    timestamps = list(range(len(data)))

                    # Update graph
                    self.ax.clear()
                    self.ax.plot(timestamps, data, marker="o", label=self.selected_item_name.get())
                    self.ax.set_title(self.selected_item_name.get())
                    self.ax.set_ylabel("Value")
                    self.ax.legend()
                    self.canvas.draw()

                    # Update current value
                    if data:
                        self.monitoring_value_label.config(text=f"Current Value: {data[-1]:.2f}")
                except Exception as e:
                    print(f"Error: {e}")
            time.sleep(5)

    def select_item(self, item):
        self.current_item_id = item["itemid"]
        self.selected_item_name.set(item["name"])
        self.monitoring_value_label.config(text="")

    def create_ids_tab(self):
        ids_frame = ttk.Frame(self.notebook)
        self.notebook.add(ids_frame, text="IDs")

        # Host Groups Section
        frame_host_groups = ttk.LabelFrame(ids_frame, text="Host Groups", padding=(10, 10))
        frame_host_groups.pack(fill="both", expand=True, padx=10, pady=10)

        self.tree_host_groups = ttk.Treeview(frame_host_groups, columns=("Group ID", "Name"), show="headings")
        self.tree_host_groups.heading("Group ID", text="Group ID")
        self.tree_host_groups.heading("Name", text="Name")
        self.tree_host_groups.column("Group ID", width=200, anchor="center")
        self.tree_host_groups.column("Name", width=400, anchor="w")
        self.tree_host_groups.pack(fill="both", expand=True, padx=5, pady=5)

        btn_refresh_host_groups = ttk.Button(frame_host_groups, text="Refresh Host Groups", command=self.display_host_groups)
        btn_refresh_host_groups.pack(pady=5)

        # Templates Section
        frame_templates = ttk.LabelFrame(ids_frame, text="Templates", padding=(10, 10))
        frame_templates.pack(fill="both", expand=True, padx=10, pady=10)

        self.tree_templates = ttk.Treeview(frame_templates, columns=("Template ID", "Name"), show="headings")
        self.tree_templates.heading("Template ID", text="Template ID")
        self.tree_templates.heading("Name", text="Name")
        self.tree_templates.column("Template ID", width=200, anchor="center")
        self.tree_templates.column("Name", width=400, anchor="w")
        self.tree_templates.pack(fill="both", expand=True, padx=5, pady=5)

        btn_refresh_templates = ttk.Button(frame_templates, text="Refresh Templates", command=self.display_templates)
        btn_refresh_templates.pack(pady=5)

        # Initial Data Load
        self.display_host_groups()
        self.display_templates()

    def fetch_data_from_zabbix(self, method, fields):
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": {
                "output": fields
            },
            "auth": self.api_token.get(),
            "id": 1
        }
        try:
            response = requests.post(self.zabbix_url.get(), json=payload)
            response.raise_for_status()
            data = response.json()
            if "result" in data:
                return data["result"]
            else:
                raise ValueError(f"Error from Zabbix: {data.get('error', 'Unknown error')}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to fetch data: {e}")
            return []

    def display_host_groups(self):
        host_groups = self.fetch_data_from_zabbix("hostgroup.get", ["groupid", "name"])
        self.tree_host_groups.delete(*self.tree_host_groups.get_children())
        for group in host_groups:
            self.tree_host_groups.insert("", "end", values=(group["groupid"], group["name"]))

    def display_templates(self):
        templates = self.fetch_data_from_zabbix("template.get", ["templateid", "name"])
        self.tree_templates.delete(*self.tree_templates.get_children())
        for template in templates:
            self.tree_templates.insert("", "end", values=(template["templateid"], template["name"]))

    
    def create_about_me_tab(self):
        about_me_frame = ttk.Frame(self.notebook)
        self.notebook.add(about_me_frame, text="About Me")

        about_me_section = ttk.LabelFrame(about_me_frame, text="About Me", padding=(10, 10))
        about_me_section.pack(fill="x", padx=10, pady=10)

        about_me_label = ttk.Label(
            about_me_section,
            text="Hello, I am Mohammad Javad Heydarpanah, a Python and Django programmer. "
                "I hope you enjoy this program.",
            wraplength=600,
            anchor="center"
        )
        about_me_label.pack(pady=5)

        tell_me_section = ttk.LabelFrame(about_me_frame, text="Tell Me", padding=(10, 10))
        tell_me_section.pack(fill="x", padx=10, pady=10)

        contacts = [
            {"name": "GitHub", "url": "https://github.com/mjavadhe"},
            {"name": "Linkedin", "url": "https://linkedin.com/in/mohamadjavad-heydarpanah-13377223b/"},
            {"name": "Telegram", "url": "https://t.me/mjavad_he"},
            {"name": "Instagram", "url": "https://instagram.com/mjavad.he"},

        ]

        for contact in contacts:
            contact_label = ttk.Label(
                tell_me_section,
                text=contact["name"],
                foreground="blue", 
                cursor="hand2" 
            )
            contact_label.pack(anchor="w", padx=10, pady=5)
            contact_label.bind("<Button-1>", lambda e, url=contact["url"]: self.open_url(url))

    def open_url(self, url):
        import webbrowser
        webbrowser.open_new(url)

    def create_help_tab(self):
        about_me_frame = ttk.Frame(self.notebook)
        self.notebook.add(about_me_frame, text="Help")

        about_me_section = ttk.LabelFrame(about_me_frame, text="Help", padding=(10, 10))
        about_me_section.pack(fill="x", padx=10, pady=10)

        about_me_label = ttk.Label(
            about_me_section,
            text="This program is an open source software written in Python, so if you need to make changes to this program, you can clone the Zabbix Manager repository from my GitHub, apply the necessary changes, and run the program.",
            wraplength=600,
            anchor="center"
        )
        about_me_label.pack(pady=5)

        tell_me_section = ttk.LabelFrame(about_me_frame, text="Zabbix Manager Repository", padding=(10, 10))
        tell_me_section.pack(fill="x", padx=10, pady=10)

        contacts = [
            {"name": "GitHub", "url": "https://github.com/mjavadhe/zabbix-management-tool"},
        ]

        for contact in contacts:
            contact_label = ttk.Label(
                tell_me_section,
                text=contact["name"],
                foreground="blue", 
                cursor="hand2" 
            )
            contact_label.pack(anchor="w", padx=10, pady=5)
            contact_label.bind("<Button-1>", lambda e, url=contact["url"]: self.open_url(url))

    def open_url(self, url):
        import webbrowser
        webbrowser.open_new(url)

def main():
    root = tk.Tk()
    app = ZabbixManagementApp(root)
    app.create_about_me_tab()
    app.create_help_tab()

    root.mainloop()

if __name__ == "__main__":
    main()
