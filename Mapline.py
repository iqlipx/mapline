#!/usr/bin/env python3

import psutil
import requests
import tkintermapview
import threading
import time
import sys
import socket
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter
from typing import Dict, List, Optional, Tuple

try:
    import tkinter as tk
    from tkinter import ttk, messagebox, scrolledtext
    import matplotlib
    matplotlib.use('TkAgg')
    from matplotlib.figure import Figure
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    import matplotlib.dates as mdates
except Exception:
    print("Tkinter and matplotlib are required.")
    print("pip install matplotlib")
    print("On some Linux distros: sudo apt install python3-tk")
    raise

# ------------- Config -------------
GEO_API_URL = "http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,lat,lon,org,query,isp,as"
PUBLIC_IP_SERVICE = "https://api.ipify.org?format=text"
REFRESH_INTERVAL = 8.0  # seconds for auto refresh
MAX_GEO_WORKERS = 10  # parallel geolocation requests
MAX_DNS_WORKERS = 10  # parallel DNS resolution
BANDWIDTH_UPDATE_INTERVAL = 2.0  # seconds for bandwidth monitoring updates
# -----------------------------------

PROTOCOL_MAP = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET",
    25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
    143: "IMAP", 443: "HTTPS", 465: "SMTPS", 587: "SMTP",
    993: "IMAPS", 995: "POP3S", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-ALT",
    8443: "HTTPS-ALT", 27017: "MongoDB"
}

# simple in-memory cache (ip -> geoinfo dict)
_geo_cache: Dict[str, Optional[dict]] = {}
_geo_lock = threading.Lock()

# DNS cache (ip -> domain name)
_dns_cache: Dict[str, Optional[str]] = {}
_dns_lock = threading.Lock()

_connection_history: Dict[Tuple, dict] = {}  # key: (ip, port, pid) -> {first_seen, last_seen, total_bytes}
_history_lock = threading.Lock()

_process_io_history: Dict[int, dict] = {}  # key: pid -> {timestamp, io_counters}
_process_io_lock = threading.Lock()

def get_public_ip() -> Optional[str]:
    """
    Retrieve the public IP address of this machine.
    
    Returns:
        Public IP address as string, or None if failed
    """
    try:
        r = requests.get(PUBLIC_IP_SERVICE, timeout=5)
        r.raise_for_status()
        return r.text.strip()
    except Exception as e:
        print(f"Failed to get public IP: {e}")
        return None

def detect_protocol(port: int) -> str:
    """
    Detect protocol based on port number.
    
    Args:
        port: Port number
        
    Returns:
        Protocol name or "Port-{port}" if unknown
    """
    return PROTOCOL_MAP.get(port, f"Port-{port}")

def geolocate_ip(ip: str) -> Optional[dict]:
    """
    Geolocate an IP address using ip-api.com.
    
    Args:
        ip: IP address to geolocate
        
    Returns:
        Dictionary with geolocation info or None if failed
    """
    with _geo_lock:
        if ip in _geo_cache:
            return _geo_cache[ip]
    
    try:
        url = GEO_API_URL.format(ip=ip)
        r = requests.get(url, timeout=6)
        r.raise_for_status()
        data = r.json()
        
        if data.get("status") == "success":
            info = {
                "country": data.get("country"),
                "region": data.get("regionName"),
                "city": data.get("city"),
                "lat": float(data.get("lat")),
                "lon": float(data.get("lon")),
                "org": data.get("org"),
                "query": data.get("query"),
                "isp": data.get("isp"),
                "as": data.get("as")
            }
            with _geo_lock:
                _geo_cache[ip] = info
            return info
        else:
            print(f"Geolocation failed for {ip}: {data.get('message')}")
            return None
    except Exception as e:
        print(f"Exception while geolocating {ip}: {e}")
        return None

def geolocate_ips_batch(ips: List[str]) -> Dict[str, Optional[dict]]:
    """
    Geolocate multiple IPs in parallel.
    
    Args:
        ips: List of IP addresses
        
    Returns:
        Dictionary mapping IP to geolocation info
    """
    results = {}
    uncached_ips = []
    
    # Check cache first
    with _geo_lock:
        for ip in ips:
            if ip in _geo_cache:
                results[ip] = _geo_cache[ip]
            else:
                uncached_ips.append(ip)
    
    # Fetch uncached IPs in parallel
    if uncached_ips:
        with ThreadPoolExecutor(max_workers=MAX_GEO_WORKERS) as executor:
            future_to_ip = {executor.submit(geolocate_ip, ip): ip for ip in uncached_ips}
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    geo_info = future.result()
                    results[ip] = geo_info
                except Exception as e:
                    print(f"Error geolocating {ip}: {e}")
                    results[ip] = None
    
    return results

def resolve_dns(ip: str) -> Optional[str]:
    """
    Reverse DNS lookup for IP address.
    
    Args:
        ip: IP address to resolve
        
    Returns:
        Domain name or None if resolution failed
    """
    with _dns_lock:
        if ip in _dns_cache:
            return _dns_cache[ip]
    
    try:
        domain = socket.gethostbyaddr(ip)[0]
        with _dns_lock:
            _dns_cache[ip] = domain
        return domain
    except (socket.herror, socket.gaierror, socket.timeout):
        with _dns_lock:
            _dns_cache[ip] = None
        return None

def resolve_dns_batch(ips: List[str]) -> Dict[str, Optional[str]]:
    """
    Resolve multiple IPs in parallel.
    
    Args:
        ips: List of IP addresses
        
    Returns:
        Dictionary mapping IP to domain name
    """
    results = {}
    uncached_ips = []
    
    with _dns_lock:
        for ip in ips:
            if ip in _dns_cache:
                results[ip] = _dns_cache[ip]
            else:
                uncached_ips.append(ip)
    
    if uncached_ips:
        with ThreadPoolExecutor(max_workers=MAX_DNS_WORKERS) as executor:
            future_to_ip = {executor.submit(resolve_dns, ip): ip for ip in uncached_ips}
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    domain = future.result()
                    results[ip] = domain
                except Exception as e:
                    print(f"Error resolving DNS for {ip}: {e}")
                    results[ip] = None
    
    return results

def format_bytes(bytes_val: float) -> str:
    """
    Format bytes into human-readable format.
    
    Args:
        bytes_val: Number of bytes
        
    Returns:
        Formatted string (e.g., "1.5 MB")
    """
    if bytes_val < 1024:
        return f"{bytes_val:.0f} B"
    elif bytes_val < 1024 * 1024:
        return f"{bytes_val / 1024:.1f} KB"
    elif bytes_val < 1024 * 1024 * 1024:
        return f"{bytes_val / (1024 * 1024):.1f} MB"
    else:
        return f"{bytes_val / (1024 * 1024 * 1024):.2f} GB"

def format_rate(bytes_per_sec: float) -> str:
    """
    Format transfer rate into human-readable format.
    
    Args:
        bytes_per_sec: Bytes per second
        
    Returns:
        Formatted string (e.g., "1.5 MB/s")
    """
    return f"{format_bytes(bytes_per_sec)}/s"

def list_outbound_connections() -> List[dict]:
    """
    List all active outbound network connections.
    
    Returns:
        List of connection dictionaries with details
    """
    conns = []
    current_time = datetime.now()
    
    for c in psutil.net_connections(kind='inet'):
        raddr = c.raddr
        if not raddr:
            continue
        r_ip = raddr[0]
        r_port = raddr[1] if len(raddr) > 1 else None

        # Skip localhost and link-local addresses
        try:
            if r_ip.startswith("127.") or r_ip.startswith("::1") or r_ip.startswith("169.254."):
                continue
        except Exception:
            pass

        state = c.status
        proc_name = None
        
        try:
            if c.pid:
                proc = psutil.Process(c.pid)
                proc_name = proc.name()
        except Exception:
            proc_name = None

        conn_key = (r_ip, r_port, c.pid)
        
        with _history_lock:
            if conn_key not in _connection_history:
                _connection_history[conn_key] = {
                    'first_seen': current_time,
                    'last_seen': current_time,
                    'total_bytes': 0
                }
            else:
                _connection_history[conn_key]['last_seen'] = current_time

        conns.append({
            "pid": c.pid,
            "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else None,
            "raddr": f"{r_ip}:{r_port}",
            "r_ip": r_ip,
            "r_port": r_port,
            "status": state,
            "proc_name": proc_name,
            "conn_key": conn_key
        })
    
    # Remove duplicates
    seen = set()
    uniq = []
    for c in conns:
        key = (c["r_ip"], c["r_port"], c["pid"])
        if key in seen:
            continue
        seen.add(key)
        uniq.append(c)
    
    return uniq

# ----------------- GUI -----------------
class OutboundMapperApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Mapline")
        self.geometry("1200x800")
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        self.dark_mode = False
        self.setup_styles()

        self.running = False
        self.auto_thread = None
        self.bandwidth_monitoring = False
        self.bandwidth_thread = None
        
        self.public_loc = None
        self.remote_infos = []
        self.all_remote_infos = []
        self.map_markers = []
        self.map_paths = []
        
        self.bandwidth_data = {}  # conn_key -> {rate, total, last_update, conn}
        self.system_io_last = None
        self.system_io_timestamp = None

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.connections_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.connections_frame, text="Connections")
        self.setup_connections_tab()

        self.map_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.map_frame, text="Map View")
        self.setup_map_tab()

        self.stats_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.stats_frame, text="Statistics")
        self.setup_stats_tab()

        self.grouping_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.grouping_frame, text="Grouping")
        self.setup_grouping_tab()
        
        self.bandwidth_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.bandwidth_frame, text="Bandwidth Monitor")
        self.setup_bandwidth_tab()

        status_frame = ttk.Frame(self)
        status_frame.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.theme_btn = ttk.Button(status_frame, text="🌙 Dark Mode", command=self.toggle_theme, width=12)
        self.theme_btn.pack(side=tk.RIGHT, padx=5, pady=2)
        
        self.status_var = tk.StringVar(value="Ready")
        status = ttk.Label(status_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # initial refresh
        self.refresh_once()

    def setup_styles(self):
        """Setup ttk styles for light and dark themes"""
        self.style = ttk.Style()
        self.style.map('TButton',
            foreground=[('active', '#000000')],
            background=[('active', '#e0e0e0')]
        )
        self.apply_light_theme()
    
    def apply_light_theme(self):
        """Apply light theme colors"""
        self.configure(bg='#f0f0f0')
        self.style.theme_use('default')
        self.style.configure('TFrame', background='#f0f0f0')
        self.style.configure('TLabel', background='#f0f0f0', foreground='#000000')
        self.style.configure('TButton', background='#ffffff', foreground='#000000')
        self.style.map('TButton',
            foreground=[('active', '#000000')],
            background=[('active', '#e0e0e0')]
        )
        self.style.configure('TNotebook', background='#f0f0f0')
        self.style.configure('TNotebook.Tab', background='#d0d0d0', foreground='#000000')
        self.style.map('TNotebook.Tab', background=[('selected', '#f0f0f0')])
        self.style.configure('Treeview', background='#ffffff', foreground='#000000', fieldbackground='#ffffff')
        self.style.configure('TLabelframe', background='#f0f0f0', foreground='#000000')
        self.style.configure('TLabelframe.Label', background='#f0f0f0', foreground='#000000')
    
    def apply_dark_theme(self):
        """Apply dark theme colors"""
        self.configure(bg='#2b2b2b')
        self.style.theme_use('default')
        self.style.configure('TFrame', background='#2b2b2b')
        self.style.configure('TLabel', background='#2b2b2b', foreground='#e0e0e0')
        self.style.configure('TButton', background='#3c3c3c', foreground='#e0e0e0')
        self.style.map('TButton',
            foreground=[('active', '#ffffff')],
            background=[('active', '#505050')]
        )
        self.style.configure('TNotebook', background='#2b2b2b')
        self.style.configure('TNotebook.Tab', background='#3c3c3c', foreground='#e0e0e0')
        self.style.map('TNotebook.Tab', background=[('selected', '#2b2b2b')])
        self.style.configure('Treeview', background='#1e1e1e', foreground='#e0e0e0', fieldbackground='#1e1e1e')
        self.style.map('Treeview', background=[('selected', '#404040')], foreground=[('selected', '#ffffff')])
        self.style.configure('TLabelframe', background='#2b2b2b', foreground='#e0e0e0')
        self.style.configure('TLabelframe.Label', background='#2b2b2b', foreground='#e0e0e0')
    
    def toggle_theme(self):
        """Toggle between light and dark themes"""
        self.dark_mode = not self.dark_mode
        if self.dark_mode:
            self.apply_dark_theme()
            self.theme_btn.config(text="☀️ Light Mode")
        else:
            self.apply_light_theme()
            self.theme_btn.config(text="🌙 Dark Mode")

    def setup_connections_tab(self):
        """Setup the connections list tab"""
        # Top control buttons
        top_frame = ttk.Frame(self.connections_frame)
        top_frame.pack(side=tk.TOP, fill=tk.X, padx=6, pady=6)

        self.refresh_btn = ttk.Button(top_frame, text="Refresh Now", command=self.refresh_once)
        self.refresh_btn.pack(side=tk.LEFT, padx=(0,6))

        self.toggle_btn = ttk.Button(top_frame, text="Start Auto Refresh", command=self.toggle_auto)
        self.toggle_btn.pack(side=tk.LEFT, padx=(0,6))

        self.interval_label = ttk.Label(top_frame, text=f"Auto interval: {REFRESH_INTERVAL:.0f}s")
        self.interval_label.pack(side=tk.LEFT, padx=(12,0))

        filter_frame = ttk.LabelFrame(self.connections_frame, text="Filters", padding=10)
        filter_frame.pack(side=tk.TOP, fill=tk.X, padx=6, pady=(0,6))

        # Process filter
        ttk.Label(filter_frame, text="Process:").grid(row=0, column=0, sticky=tk.W, padx=(0,5))
        self.process_filter_var = tk.StringVar()
        self.process_filter_entry = ttk.Entry(filter_frame, textvariable=self.process_filter_var, width=20)
        self.process_filter_entry.grid(row=0, column=1, padx=(0,10))

        # Country filter
        ttk.Label(filter_frame, text="Country:").grid(row=0, column=2, sticky=tk.W, padx=(0,5))
        self.country_filter_var = tk.StringVar()
        self.country_filter_entry = ttk.Entry(filter_frame, textvariable=self.country_filter_var, width=20)
        self.country_filter_entry.grid(row=0, column=3, padx=(0,10))

        # Port filter
        ttk.Label(filter_frame, text="Port:").grid(row=0, column=4, sticky=tk.W, padx=(0,5))
        self.port_filter_var = tk.StringVar()
        self.port_filter_entry = ttk.Entry(filter_frame, textvariable=self.port_filter_var, width=10)
        self.port_filter_entry.grid(row=0, column=5, padx=(0,10))

        # Apply and Clear buttons
        ttk.Button(filter_frame, text="Apply Filters", command=self.apply_filters).grid(row=0, column=6, padx=(0,5))
        ttk.Button(filter_frame, text="Clear Filters", command=self.clear_filters).grid(row=0, column=7)

        cols = ("remote", "domain", "protocol", "process", "status", "geo")
        self.tree = ttk.Treeview(self.connections_frame, columns=cols, show="headings", selectmode="browse")
        self.tree.heading("remote", text="Remote (IP:port)")
        self.tree.heading("domain", text="Domain Name")
        self.tree.heading("protocol", text="Protocol")
        self.tree.heading("process", text="Process (PID)")
        self.tree.heading("status", text="State")
        self.tree.heading("geo", text="Geolocation")
        self.tree.column("remote", width=180)
        self.tree.column("domain", width=200)
        self.tree.column("protocol", width=100)
        self.tree.column("process", width=150)
        self.tree.column("status", width=100)
        self.tree.column("geo", width=250)
        
        self.tree.bind("<Double-Button-1>", self.show_connection_details)
        
        self.tree.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=6, pady=(0,6))

    def setup_map_tab(self):
        """Setup the map view tab with tkintermapview"""
        control_frame = ttk.Frame(self.map_frame)
        control_frame.pack(side=tk.TOP, fill=tk.X, padx=6, pady=6)

        ttk.Button(control_frame, text="Refresh Map", command=self.refresh_map).pack(side=tk.LEFT, padx=(0,6))
        
        try:
            self.map_widget = tkintermapview.TkinterMapView(
                self.map_frame, 
                corner_radius=0,
                use_database_only=False,
                max_zoom=19
            )
            self.map_widget.pack(fill=tk.BOTH, expand=True, padx=6, pady=(0,6))
            # Set initial position (world view)
            self.map_widget.set_position(20.0, 0.0)
            self.map_widget.set_zoom(2)
        except Exception as e:
            print(f"Error creating map widget: {e}")
            error_label = ttk.Label(self.map_frame, text=f"Error: Could not create map viewer\n{str(e)}", foreground="red")
            error_label.pack(fill=tk.BOTH, expand=True)

    def setup_stats_tab(self):
        """Setup the statistics tab with charts"""
        control_frame = ttk.Frame(self.stats_frame)
        control_frame.pack(side=tk.TOP, fill=tk.X, padx=6, pady=6)

        ttk.Button(control_frame, text="Refresh Statistics", command=self.refresh_statistics).pack(side=tk.LEFT, padx=(0,6))
        ttk.Label(control_frame, text="Statistics are based on current connections", font=('', 9, 'italic')).pack(side=tk.LEFT)

        # Create notebook for different chart types
        self.stats_notebook = ttk.Notebook(self.stats_frame)
        self.stats_notebook.pack(fill=tk.BOTH, expand=True, padx=6, pady=(0,6))

        # Country chart frame
        self.country_chart_frame = ttk.Frame(self.stats_notebook)
        self.stats_notebook.add(self.country_chart_frame, text="By Country")

        # Process chart frame
        self.process_chart_frame = ttk.Frame(self.stats_notebook)
        self.stats_notebook.add(self.process_chart_frame, text="By Process")

        # Port chart frame
        self.port_chart_frame = ttk.Frame(self.stats_notebook)
        self.stats_notebook.add(self.port_chart_frame, text="By Port")

        self.protocol_chart_frame = ttk.Frame(self.stats_notebook)
        self.stats_notebook.add(self.protocol_chart_frame, text="By Protocol")

    def setup_grouping_tab(self):
        """Setup the connection grouping tab"""
        control_frame = ttk.Frame(self.grouping_frame)
        control_frame.pack(side=tk.TOP, fill=tk.X, padx=6, pady=6)

        ttk.Label(control_frame, text="Group By:", font=('', 10, 'bold')).pack(side=tk.LEFT, padx=(0,10))
        
        self.grouping_method = tk.StringVar(value="domain")
        ttk.Radiobutton(control_frame, text="Domain", variable=self.grouping_method, value="domain", command=self.refresh_grouping).pack(side=tk.LEFT, padx=(0,10))
        ttk.Radiobutton(control_frame, text="Organization (ASN)", variable=self.grouping_method, value="asn", command=self.refresh_grouping).pack(side=tk.LEFT, padx=(0,10))
        ttk.Radiobutton(control_frame, text="Subnet (/24)", variable=self.grouping_method, value="subnet", command=self.refresh_grouping).pack(side=tk.LEFT, padx=(0,10))
        
        ttk.Button(control_frame, text="Refresh Groups", command=self.refresh_grouping).pack(side=tk.LEFT, padx=(20,0))

        # Grouping treeview
        cols = ("group", "count", "details")
        self.group_tree = ttk.Treeview(self.grouping_frame, columns=cols, show="tree headings", selectmode="browse")
        self.group_tree.heading("#0", text="Group")
        self.group_tree.heading("group", text="Group Name")
        self.group_tree.heading("count", text="Connections")
        self.group_tree.heading("details", text="Details")
        self.group_tree.column("#0", width=300)
        self.group_tree.column("group", width=300)
        self.group_tree.column("count", width=100)
        self.group_tree.column("details", width=400)
        
        self.group_tree.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=6, pady=(0,6))


    def setup_bandwidth_tab(self):
        """Setup the bandwidth monitoring tab"""
        control_frame = ttk.Frame(self.bandwidth_frame)
        control_frame.pack(side=tk.TOP, fill=tk.X, padx=6, pady=6)

        self.bandwidth_toggle_btn = ttk.Button(control_frame, text="Start Monitoring", command=self.toggle_bandwidth_monitoring)
        self.bandwidth_toggle_btn.pack(side=tk.LEFT, padx=(0,6))
        
        ttk.Label(control_frame, text=f"Update interval: {BANDWIDTH_UPDATE_INTERVAL:.1f}s", font=('', 9, 'italic')).pack(side=tk.LEFT, padx=(10,0))
        
        # Summary frame
        summary_frame = ttk.LabelFrame(self.bandwidth_frame, text="Network Summary", padding=10)
        summary_frame.pack(side=tk.TOP, fill=tk.X, padx=6, pady=(0,6))
        
        self.total_rate_var = tk.StringVar(value="Total Rate: 0 B/s")
        ttk.Label(summary_frame, textvariable=self.total_rate_var, font=('', 10, 'bold')).pack(side=tk.LEFT, padx=(0,20))
        
        self.active_conns_var = tk.StringVar(value="Active Connections: 0")
        ttk.Label(summary_frame, textvariable=self.active_conns_var, font=('', 10)).pack(side=tk.LEFT)
        
        # Bandwidth treeview
        cols = ("connection", "process", "protocol", "rate", "total", "duration")
        self.bandwidth_tree = ttk.Treeview(self.bandwidth_frame, columns=cols, show="headings", selectmode="browse")
        self.bandwidth_tree.heading("connection", text="Connection (IP:Port)")
        self.bandwidth_tree.heading("process", text="Process")
        self.bandwidth_tree.heading("protocol", text="Protocol")
        self.bandwidth_tree.heading("rate", text="Transfer Rate")
        self.bandwidth_tree.heading("total", text="Total Data")
        self.bandwidth_tree.heading("duration", text="Duration")
        
        self.bandwidth_tree.column("connection", width=180)
        self.bandwidth_tree.column("process", width=150)
        self.bandwidth_tree.column("protocol", width=100)
        self.bandwidth_tree.column("rate", width=120)
        self.bandwidth_tree.column("total", width=120)
        self.bandwidth_tree.column("duration", width=100)
        
        self.bandwidth_tree.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=6, pady=(0,6))


    def set_status(self, text):
        self.status_var.set(text)
        self.update_idletasks()

    def refresh_once(self):
        """Refresh connections list with parallel geolocation and DNS resolution"""
        self.set_status("Refreshing connections...")
        try:
            conns = list_outbound_connections()
            self.tree.delete(*self.tree.get_children())

            unique_ips = list(set(c["r_ip"] for c in conns))
            
            self.set_status(f"Geolocating {len(unique_ips)} IPs...")
            geo_results = geolocate_ips_batch(unique_ips)

            self.set_status(f"Resolving DNS for {len(unique_ips)} IPs...")
            dns_results = resolve_dns_batch(unique_ips)

            remote_infos = []
            for c in conns:
                conn_key = c["conn_key"]
                
                remote_infos.append({
                    "ip": c["r_ip"],
                    "port": c["r_port"],
                    "proc_name": f"{c['proc_name']} (PID {c['pid']})" if c['proc_name'] else f"PID {c['pid']}",
                    "proc_name_only": c["proc_name"] or "Unknown",
                    "status": c['status'],
                    "protocol": detect_protocol(c["r_port"]),
                    "conn_key": conn_key,
                    "raw": c
                })

            for r in remote_infos:
                g = geo_results.get(r["ip"])
                d = dns_results.get(r["ip"])
                r["geoinfo"] = g
                r["domain"] = d
                geo_desc = f"{g.get('city')}, {g.get('country')}" if g else "Unknown"
                domain_display = d if d else "-"
                
                self.tree.insert("", tk.END, values=(
                    f"{r['ip']}:{r['port']}", 
                    domain_display,
                    r['protocol'],
                    r['proc_name'], 
                    r['status'], 
                    geo_desc
                ))

            self.all_remote_infos = remote_infos  # Store for filtering
            self.set_status(f"Refreshed at {datetime.now().strftime('%H:%M:%S')} — {len(remote_infos)} remote hosts found")
        except Exception as e:
            self.set_status(f"Error refreshing: {e}")
            print("Error in refresh:", e)

    def show_connection_details(self, event):
        """Show detailed information about a connection in a new window"""
        selection = self.tree.selection()
        if not selection:
            return
        
        item = self.tree.item(selection[0])
        values = item['values']
        
        # Find the connection info
        remote_addr = values[0]
        ip = remote_addr.split(':')[0]
        
        # Find full connection info
        conn_info = None
        for r in self.all_remote_infos:
            if f"{r['ip']}:{r['port']}" == remote_addr:
                conn_info = r
                break
        
        if not conn_info:
            return
        
        # Create details window
        details_window = tk.Toplevel(self)
        details_window.title(f"Connection Details - {ip}")
        details_window.geometry("600x500")
        
        if self.dark_mode:
            details_window.configure(bg='#2b2b2b')
        
        # Create scrolled text widget
        text_widget = scrolledtext.ScrolledText(details_window, wrap=tk.WORD, font=('Courier', 10))
        if self.dark_mode:
            text_widget.configure(bg='#1e1e1e', fg='#e0e0e0', insertbackground='#e0e0e0')
        text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Add basic info
        text_widget.insert(tk.END, "=" * 60 + "\n")
        text_widget.insert(tk.END, "CONNECTION DETAILS\n")
        text_widget.insert(tk.END, "=" * 60 + "\n\n")
        
        text_widget.insert(tk.END, f"Remote IP:        {conn_info['ip']}\n")
        text_widget.insert(tk.END, f"Remote Port:      {conn_info['port']}\n")
        text_widget.insert(tk.END, f"Protocol:         {conn_info['protocol']}\n")
        text_widget.insert(tk.END, f"Domain Name:      {conn_info.get('domain') or 'N/A'}\n")
        text_widget.insert(tk.END, f"Process:          {conn_info['proc_name']}\n")
        text_widget.insert(tk.END, f"Status:           {conn_info['status']}\n\n")
        
        # Add geolocation info
        g = conn_info.get('geoinfo')
        if g:
            text_widget.insert(tk.END, "-" * 60 + "\n")
            text_widget.insert(tk.END, "GEOLOCATION\n")
            text_widget.insert(tk.END, "-" * 60 + "\n\n")
            text_widget.insert(tk.END, f"Country:          {g.get('country', 'N/A')}\n")
            text_widget.insert(tk.END, f"Region:           {g.get('region', 'N/A')}\n")
            text_widget.insert(tk.END, f"City:             {g.get('city', 'N/A')}\n")
            text_widget.insert(tk.END, f"Coordinates:      {g.get('lat', 'N/A')}, {g.get('lon', 'N/A')}\n")
            text_widget.insert(tk.END, f"ISP:              {g.get('isp', 'N/A')}\n")
            text_widget.insert(tk.END, f"Organization:     {g.get('org', 'N/A')}\n")
            text_widget.insert(tk.END, f"AS Number:        {g.get('as', 'N/A')}\n\n")
        
        
        text_widget.config(state=tk.DISABLED)

    def apply_filters(self):
        """Apply filters to the connections list"""
        process_filter = self.process_filter_var.get().lower().strip()
        country_filter = self.country_filter_var.get().lower().strip()
        port_filter = self.port_filter_var.get().strip()

        self.tree.delete(*self.tree.get_children())
        filtered_count = 0

        for r in self.all_remote_infos:
            # Apply process filter
            if process_filter and process_filter not in r['proc_name'].lower():
                continue
            
            # Apply country filter
            g = r.get("geoinfo")
            if country_filter and g:
                country = g.get('country', '').lower()
                if country_filter not in country:
                    continue
            elif country_filter and not g:
                continue
            
            # Apply port filter
            if port_filter and str(r['port']) != port_filter:
                continue

            # Add to tree if passes all filters
            geo_desc = f"{g.get('city')}, {g.get('country')}" if g else "Unknown"
            domain_display = r.get('domain') if r.get('domain') else "-"
            self.tree.insert("", tk.END, values=(
                f"{r['ip']}:{r['port']}", 
                domain_display,
                r['protocol'],
                r['proc_name'], 
                r['status'], 
                geo_desc
            ))
            filtered_count += 1

        self.set_status(f"Filters applied — {filtered_count} of {len(self.all_remote_infos)} connections shown")

    def clear_filters(self):
        """Clear all filters and show all connections"""
        self.process_filter_var.set("")
        self.country_filter_var.set("")
        self.port_filter_var.set("")
        
        self.tree.delete(*self.tree.get_children())
        for r in self.all_remote_infos:
            g = r.get("geoinfo")
            geo_desc = f"{g.get('city')}, {g.get('country')}" if g else "Unknown"
            domain_display = r.get('domain') if r.get('domain') else "-"
            self.tree.insert("", tk.END, values=(
                f"{r['ip']}:{r['port']}", 
                domain_display,
                r['protocol'],
                r['proc_name'], 
                r['status'], 
                geo_desc
            ))
        
        self.set_status(f"Filters cleared — {len(self.all_remote_infos)} connections shown")

    def build_and_show_map(self):
        """Build the map and switch to map tab - runs in background thread"""
        def build_map_thread():
            try:
                self.set_status("Obtaining public IP and geolocation...")
                public_ip = get_public_ip()
                self.public_loc = None
                if public_ip:
                    public_geo = geolocate_ip(public_ip)
                    if public_geo:
                        self.public_loc = {
                            "ip": public_ip, 
                            "lat": public_geo["lat"], 
                            "lon": public_geo["lon"], 
                            "place": f"{public_geo.get('city')}, {public_geo.get('country')}"
                        }
                    else:
                        self.public_loc = {"ip": public_ip, "lat": None, "lon": None, "place": ""}
                else:
                    self.public_loc = None

                conns = list_outbound_connections()
                
                unique_ips = list(set(c["r_ip"] for c in conns))
                self.set_status(f"Geolocating {len(unique_ips)} unique IPs...")
                geo_results = geolocate_ips_batch(unique_ips)
                
                self.set_status(f"Resolving DNS for {len(unique_ips)} IPs...")
                dns_results = resolve_dns_batch(unique_ips)
                
                self.remote_infos = []
                for c in conns:
                    proc_name = c["proc_name"] or f"PID {c['pid']}"
                    protocol = detect_protocol(c["r_port"])
                    info = {
                        "ip": c["r_ip"],
                        "port": c["r_port"],
                        "proc_name": proc_name,
                        "proc_name_only": c["proc_name"] or "Unknown",
                        "status": c["status"],
                        "protocol": protocol,
                        "geoinfo": geo_results.get(c["r_ip"]),
                        "domain": dns_results.get(c["r_ip"])
                    }
                    self.remote_infos.append(info)

                self.set_status("Rendering map...")
                self.after(0, self._render_map_on_main_thread)
                
            except Exception as e:
                self.set_status(f"Map build failed: {e}")
                print(f"Map build error: {e}")
                self.after(0, lambda: messagebox.showerror("Map Error", f"Failed to build map: {e}"))
        
        # Start background thread
        threading.Thread(target=build_map_thread, daemon=True).start()

    def _render_map_on_main_thread(self):
        """Render map on main thread after data is prepared"""
        try:
            self.render_map()
            self.notebook.select(1)  # Switch to map tab
            self.set_status(f"Map displayed ({len(self.remote_infos)} connections)")
        except Exception as e:
            self.set_status(f"Map render failed: {e}")
            print(f"Map render error: {e}")

    def render_map(self):
        """Render the map using tkintermapview with markers and paths"""
        self.map_widget.delete_all_marker()
        self.map_widget.delete_all_path()
        
        # Determine starting position and calculate bounds
        all_lats = []
        all_lons = []
        
        if self.public_loc and self.public_loc.get("lat") is not None:
            all_lats.append(self.public_loc["lat"])
            all_lons.append(self.public_loc["lon"])
        
        for r in self.remote_infos:
            g = r.get("geoinfo")
            if g and g.get("lat") is not None:
                all_lats.append(g["lat"])
                all_lons.append(g["lon"])
        
        if all_lats and all_lons:
            center_lat = sum(all_lats) / len(all_lats)
            center_lon = sum(all_lons) / len(all_lons)
            self.map_widget.set_position(center_lat, center_lon)
            
            # Calculate appropriate zoom level based on marker spread
            lat_range = max(all_lats) - min(all_lats) if len(all_lats) > 1 else 0
            lon_range = max(all_lons) - min(all_lons) if len(all_lons) > 1 else 0
            max_range = max(lat_range, lon_range)
            
            if max_range > 100:
                zoom = 2
            elif max_range > 50:
                zoom = 3
            elif max_range > 20:
                zoom = 4
            elif max_range > 10:
                zoom = 5
            else:
                zoom = 6
            
            self.map_widget.set_zoom(zoom)
        else:
            self.map_widget.set_position(20.0, 0.0)
            self.map_widget.set_zoom(2)
        
        if self.public_loc and self.public_loc.get("lat") is not None:
            marker_text = f"Your IP: {self.public_loc['ip']}"
            self.map_widget.set_marker(
                self.public_loc["lat"], 
                self.public_loc["lon"],
                text=marker_text,
                marker_color_circle="green",
                marker_color_outside="darkgreen"
            )
        
        for r in self.remote_infos:
            g = r.get("geoinfo")
            if g and g.get("lat") is not None:
                domain_text = f"\n{r['domain']}" if r.get('domain') else ""
                marker_text = f"{r['ip']}:{r['port']} ({r['protocol']}){domain_text}\n{r['proc_name']}"
                self.map_widget.set_marker(
                    g["lat"], 
                    g["lon"],
                    text=marker_text,
                    marker_color_circle="red",
                    marker_color_outside="darkred"
                )
                
                if self.public_loc and self.public_loc.get("lat") is not None:
                    path_coords = [
                        (self.public_loc["lat"], self.public_loc["lon"]),
                        (g["lat"], g["lon"])
                    ]
                    self.map_widget.set_path(path_coords, color="blue", width=2)

    def refresh_map(self):
        """Refresh the map with current connections"""
        self.build_and_show_map()

    def refresh_statistics(self):
        """Refresh statistics charts based on current connections"""
        if not self.all_remote_infos:
            messagebox.showinfo("No Data", "Please refresh connections first")
            return
        
        self.set_status("Generating statistics...")
        
        # Clear existing charts
        for widget in self.country_chart_frame.winfo_children():
            widget.destroy()
        for widget in self.process_chart_frame.winfo_children():
            widget.destroy()
        for widget in self.port_chart_frame.winfo_children():
            widget.destroy()
        for widget in self.protocol_chart_frame.winfo_children():
            widget.destroy()
        
        # Generate charts
        self.generate_country_chart()
        self.generate_process_chart()
        self.generate_port_chart()
        self.generate_protocol_chart()
        
        self.set_status("Statistics updated")

    def generate_country_chart(self):
        """Generate bar chart of connections by country"""
        countries = []
        for r in self.all_remote_infos:
            g = r.get("geoinfo")
            if g and g.get("country"):
                countries.append(g["country"])
        
        if not countries:
            ttk.Label(self.country_chart_frame, text="No country data available", font=('', 12)).pack(expand=True)
            return
        
        country_counts = Counter(countries)
        top_countries = country_counts.most_common(10)
        
        fig = Figure(figsize=(8, 5), dpi=100)
        ax = fig.add_subplot(111)
        
        names = [c[0] for c in top_countries]
        counts = [c[1] for c in top_countries]
        
        ax.barh(names, counts, color='steelblue')
        ax.set_xlabel('Number of Connections')
        ax.set_title('Top 10 Countries by Connection Count')
        ax.invert_yaxis()
        
        canvas = FigureCanvasTkAgg(fig, master=self.country_chart_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

    def generate_process_chart(self):
        """Generate bar chart of connections by process"""
        processes = [r["proc_name_only"] for r in self.all_remote_infos]
        
        if not processes:
            ttk.Label(self.process_chart_frame, text="No process data available", font=('', 12)).pack(expand=True)
            return
        
        process_counts = Counter(processes)
        top_processes = process_counts.most_common(10)
        
        fig = Figure(figsize=(8, 5), dpi=100)
        ax = fig.add_subplot(111)
        
        names = [p[0] for p in top_processes]
        counts = [p[1] for p in top_processes]
        
        ax.barh(names, counts, color='coral')
        ax.set_xlabel('Number of Connections')
        ax.set_title('Top 10 Processes by Connection Count')
        ax.invert_yaxis()
        
        canvas = FigureCanvasTkAgg(fig, master=self.process_chart_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

    def generate_port_chart(self):
        """Generate bar chart of connections by port"""
        ports = [str(r["port"]) for r in self.all_remote_infos if r["port"]]
        
        if not ports:
            ttk.Label(self.port_chart_frame, text="No port data available", font=('', 12)).pack(expand=True)
            return
        
        port_counts = Counter(ports)
        top_ports = port_counts.most_common(10)
        
        fig = Figure(figsize=(8, 5), dpi=100)
        ax = fig.add_subplot(111)
        
        names = [f"Port {p[0]}" for p in top_ports]
        counts = [p[1] for p in top_ports]
        
        ax.barh(names, counts, color='mediumseagreen')
        ax.set_xlabel('Number of Connections')
        ax.set_title('Top 10 Ports by Connection Count')
        ax.invert_yaxis()
        
        canvas = FigureCanvasTkAgg(fig, master=self.port_chart_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

    def generate_protocol_chart(self):
        """Generate bar chart of connections by protocol"""
        protocols = [r["protocol"] for r in self.all_remote_infos if r.get("protocol")]
        
        if not protocols:
            ttk.Label(self.protocol_chart_frame, text="No protocol data available", font=('', 12)).pack(expand=True)
            return
        
        protocol_counts = Counter(protocols)
        top_protocols = protocol_counts.most_common(10)
        
        fig = Figure(figsize=(8, 5), dpi=100)
        ax = fig.add_subplot(111)
        
        names = [p[0] for p in top_protocols]
        counts = [p[1] for p in top_protocols]
        
        ax.barh(names, counts, color='mediumpurple')
        ax.set_xlabel('Number of Connections')
        ax.set_title('Top 10 Protocols by Connection Count')
        ax.invert_yaxis()
        
        canvas = FigureCanvasTkAgg(fig, master=self.protocol_chart_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

    def refresh_grouping(self):
        """Refresh the grouping view based on selected method"""
        if not self.all_remote_infos:
            messagebox.showinfo("No Data", "Please refresh connections first")
            return
        
        self.group_tree.delete(*self.group_tree.get_children())
        method = self.grouping_method.get()
        
        groups = {}
        
        for r in self.all_remote_infos:
            if method == "domain":
                group_key = r.get('domain') or "No Domain"
            elif method == "asn":
                g = r.get('geoinfo')
                group_key = g.get('org') if g and g.get('org') else "Unknown Organization"
            elif method == "subnet":
                ip_parts = r['ip'].split('.')
                if len(ip_parts) == 4:
                    group_key = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
                else:
                    group_key = "Invalid IP"
            else:
                group_key = "Unknown"
            
            if group_key not in groups:
                groups[group_key] = []
            groups[group_key].append(r)
        
        # Sort groups by connection count
        sorted_groups = sorted(groups.items(), key=lambda x: len(x[1]), reverse=True)
        
        for group_name, connections in sorted_groups:
            # Insert parent node with group name in tree column
            parent_id = self.group_tree.insert("", tk.END, text=f"📁 {group_name}", values=("", len(connections), ""))
            
            # Insert child nodes
            for conn in connections:
                g = conn.get('geoinfo')
                geo_desc = f"{g.get('city')}, {g.get('country')}" if g else "Unknown"
                child_text = f"{conn['ip']}:{conn['port']}"
                child_details = f"{conn['proc_name']} | {conn['protocol']} | {geo_desc}"
                self.group_tree.insert(parent_id, tk.END, text=f"   └─ {child_text}", values=("", "", child_details))
        
        self.set_status(f"Grouped {len(self.all_remote_infos)} connections into {len(groups)} groups by {method}")

    def toggle_bandwidth_monitoring(self):
        """Toggle bandwidth monitoring on/off"""
        if not self.bandwidth_monitoring:
            self.bandwidth_monitoring = True
            self.bandwidth_toggle_btn.config(text="Stop Monitoring")
            self.bandwidth_thread = threading.Thread(target=self._bandwidth_monitoring_loop, daemon=True)
            self.bandwidth_thread.start()
            self.set_status("Bandwidth monitoring started")
        else:
            self.bandwidth_monitoring = False
            self.bandwidth_toggle_btn.config(text="Start Monitoring")
            self.set_status("Bandwidth monitoring stopped")

    def _bandwidth_monitoring_loop(self):
        """Background thread for bandwidth monitoring"""
        while self.bandwidth_monitoring:
            try:
                self.update_bandwidth_data()
                self.after(0, self.refresh_bandwidth_display)
            except Exception as e:
                print(f"Bandwidth monitoring error: {e}")
            
            time.sleep(BANDWIDTH_UPDATE_INTERVAL)

    def update_bandwidth_data(self):
        """Update bandwidth data for all connections"""
        current_time = datetime.now()
        
        # Get system-wide network I/O
        try:
            io_counters = psutil.net_io_counters()
            current_io = io_counters.bytes_sent + io_counters.bytes_recv
            
            if self.system_io_last is not None and self.system_io_timestamp is not None:
                time_diff = (current_time - self.system_io_timestamp).total_seconds()
                if time_diff > 0:
                    bytes_diff = current_io - self.system_io_last
                    system_rate = bytes_diff / time_diff
                else:
                    system_rate = 0
            else:
                system_rate = 0
            
            self.system_io_last = current_io
            self.system_io_timestamp = current_time
            
        except Exception as e:
            print(f"Error getting system I/O: {e}")
            system_rate = 0
        
        # Get active connections
        conns = list_outbound_connections()
        active_conn_keys = set()
        
        # Update bandwidth data for each connection
        for conn in conns:
            conn_key = conn['conn_key']
            active_conn_keys.add(conn_key)
            
            with _history_lock:
                if conn_key in _connection_history:
                    hist = _connection_history[conn_key]
                    duration = (current_time - hist['first_seen']).total_seconds()
                    
                    # Estimate bandwidth (simplified - divide system rate by number of connections)
                    estimated_rate = system_rate / max(len(conns), 1)
                    
                    # Update total bytes (accumulate estimated data)
                    if conn_key in self.bandwidth_data:
                        last_update = self.bandwidth_data[conn_key].get('last_update', current_time)
                        time_since_update = (current_time - last_update).total_seconds()
                        bytes_since_update = estimated_rate * time_since_update
                        hist['total_bytes'] += bytes_since_update
                    
                    self.bandwidth_data[conn_key] = {
                        'rate': estimated_rate,
                        'total': hist['total_bytes'],
                        'duration': duration,
                        'last_update': current_time,
                        'conn': conn
                    }
        
        # Remove data for closed connections
        closed_keys = set(self.bandwidth_data.keys()) - active_conn_keys
        for key in closed_keys:
            del self.bandwidth_data[key]

    def refresh_bandwidth_display(self):
        """Refresh the bandwidth display with current data"""
        try:
            self.bandwidth_tree.delete(*self.bandwidth_tree.get_children())
            
            total_rate = 0
            active_count = len(self.bandwidth_data)
            
            # Sort by transfer rate (highest first)
            sorted_data = sorted(self.bandwidth_data.items(), key=lambda x: x[1]['rate'], reverse=True)
            
            for conn_key, data in sorted_data:
                conn = data['conn']
                rate = data['rate']
                total = data['total']
                duration = data['duration']
                
                total_rate += rate
                
                # Format duration
                duration_str = f"{int(duration)}s"
                if duration >= 60:
                    duration_str = f"{int(duration/60)}m {int(duration%60)}s"
                
                protocol = detect_protocol(conn['r_port'])
                proc_name = conn['proc_name'] or f"PID {conn['pid']}"
                
                self.bandwidth_tree.insert("", tk.END, values=(
                    f"{conn['r_ip']}:{conn['r_port']}",
                    proc_name,
                    protocol,
                    format_rate(rate),
                    format_bytes(total),
                    duration_str
                ))
            
            # Update summary
            self.total_rate_var.set(f"Total Rate: {format_rate(total_rate)}")
            self.active_conns_var.set(f"Active Connections: {active_count}")
            
        except Exception as e:
            print(f"Error refreshing bandwidth display: {e}")

    def _auto_refresh_loop(self):
        while self.running:
            self.refresh_once()
            for _ in range(int(REFRESH_INTERVAL*2)):
                if not self.running:
                    break
                time.sleep(0.5)

    def toggle_auto(self):
        if not self.running:
            self.running = True
            self.toggle_btn.config(text="Stop Auto Refresh")
            self.auto_thread = threading.Thread(target=self._auto_refresh_loop, daemon=True)
            self.auto_thread.start()
            self.set_status("Auto-refresh started")
        else:
            self.running = False
            self.toggle_btn.config(text="Start Auto Refresh")
            self.set_status("Auto-refresh stopped")

    def on_close(self):
        """Clean shutdown of the application"""
        if self.running:
            self.running = False
        if self.bandwidth_monitoring:
            self.bandwidth_monitoring = False
        self.destroy()

# ----------------- main -----------------
def main():
    try:
        import psutil, requests, tkintermapview, matplotlib
    except Exception as e:
        print("Missing dependency:", e)
        print("pip install psutil requests tkintermapview matplotlib")
        sys.exit(1)

    app = OutboundMapperApp()
    app.mainloop()

if __name__ == "__main__":
    main()
