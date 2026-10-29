#!/usr/bin/env python3
"""CocoScanner v2.02 Phase 6 — local threat-intelligence correlation and ATT&CK context."""
import ipaddress, json, queue, re, shutil, socket, subprocess, threading, time, hashlib, csv, os
from datetime import datetime, timezone
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"; DATA.mkdir(exist_ok=True)
PACKETS = DATA / "packets.json"; DEVICES = DATA / "devices.json"
MAX_PACKETS = 3000
# Bright professional analyst palette: warm white canvas, clean panels, vivid orange accents.
BG="#f3f6fa"; PANEL="#ffffff"; PANEL2="#edf1f6"; TEXT="#202a36"; MUTED="#64748b"; ACCENT="#f06423"; GREEN="#16834a"; RED="#c62828"; GOLD="#b45309"

def stamp():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")
def load(path, default):
    try: return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError): return default
def save(path, obj):
    tmp=path.with_suffix(".tmp"); tmp.write_text(json.dumps(obj, indent=2), encoding="utf-8"); tmp.replace(path)
def local_ip():
    try:
        s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.connect(("192.0.2.1",80)); ip=s.getsockname()[0]; s.close(); return ip
    except OSError: return "unknown"
def iface_default():
    try:
        p=subprocess.check_output(["ip","-o","route","show","default"],text=True,timeout=3).split()
        return p[p.index("dev")+1] if "dev" in p else ""
    except Exception: return ""
def subnet_default():
    ip,iface=local_ip(),iface_default()
    try:
        p=subprocess.check_output(["ip","-o","-f","inet","addr","show","dev",iface],text=True,timeout=3).split()
        for v in p:
            if "/" in v:
                n=ipaddress.ip_interface(v)
                if str(n.ip)==ip:return str(n.network)
    except Exception: pass
    return f"{ip}/24" if ip!="unknown" else ""
def safe_net(value):
    n=ipaddress.ip_network(value.strip(),strict=False)
    if n.version!=4 or n.num_addresses>4096: raise ValueError("Use an IPv4 subnet with at most 4096 addresses.")
    if not (n.is_private or n.is_loopback or n.is_link_local): raise ValueError("Only private, loopback, or link-local subnets are allowed.")
    return str(n)

def decode_packet(pkt):
    from scapy.all import Ether, ARP, IP, IPv6, TCP, UDP, ICMP, DNS, Raw
    rec={"timestamp":datetime.fromtimestamp(float(getattr(pkt,"time",time.time())),timezone.utc).isoformat(timespec="milliseconds"),
         "src":"—","dst":"—","protocol":"OTHER","src_port":None,"dst_port":None,"length":len(pkt),
         "summary":pkt.summary(),"tcp_flags":None,"ttl":None,"ip_id":None,"src_mac":None,"dst_mac":None,
         "dns":"","dns_name":"","dns_type":"","dns_qr":None,"payload_hex":"","payload_ascii":"","layers":[],"tcp_seq":None,"tcp_ack":None,"tcp_window":None,"tcp_payload_len":0}
    if Ether in pkt: rec["src_mac"],rec["dst_mac"]=pkt[Ether].src,pkt[Ether].dst
    if ARP in pkt:
        rec.update(protocol="ARP",src=pkt[ARP].psrc or pkt[ARP].hwsrc,dst=pkt[ARP].pdst or pkt[ARP].hwdst)
    if IP in pkt:
        p=pkt[IP]; rec.update(src=p.src,dst=p.dst,protocol="IPv4",ttl=int(p.ttl),ip_id=int(p.id))
    elif IPv6 in pkt:
        p=pkt[IPv6]; rec.update(src=p.src,dst=p.dst,protocol="IPv6",ttl=int(p.hlim))
    if TCP in pkt:
        p=pkt[TCP]; rec.update(protocol="TCP" if IP in pkt else "TCP6",src_port=int(p.sport),dst_port=int(p.dport),tcp_flags=str(p.flags),tcp_seq=int(p.seq),tcp_ack=int(p.ack),tcp_window=int(p.window),tcp_payload_len=len(bytes(p.payload)) if p.payload else 0)
    elif UDP in pkt:
        p=pkt[UDP]; rec.update(protocol="UDP" if IP in pkt else "UDP6",src_port=int(p.sport),dst_port=int(p.dport))
    elif ICMP in pkt: rec["protocol"]="ICMP"
    if DNS in pkt:
        rec["dns"]=pkt[DNS].summary()
        rec["dns_qr"]="response" if int(pkt[DNS].qr)==1 else "query"
        try:
            q=pkt[DNS].qd
            rec["dns_name"]=q.qname.decode("utf-8","replace").rstrip(".") if q and getattr(q,"qname",None) else ""
            rec["dns_type"]=str(int(q.qtype)) if q and getattr(q,"qtype",None) is not None else ""
        except Exception: pass
    if Raw in pkt:
        b=bytes(pkt[Raw].load)[:256]; rec["payload_hex"]=b.hex(" "); rec["payload_ascii"]="".join(chr(x) if 32<=x<127 else "." for x in b)
    layer=pkt
    for _ in range(18):
        if layer is None or layer.__class__.__name__=="NoPayload": break
        try: fields={k:str(v)[:180] for k,v in layer.fields.items()}
        except Exception: fields={}
        rec["layers"].append({"name":layer.__class__.__name__,"fields":fields})
        layer=getattr(layer,"payload",None)
    return rec

class App:
 def __init__(self,root):
    self.root=root; root.title("CocoScanner — Desktop Network Monitor"); root.geometry("1450x900"); root.minsize(980,640); root.configure(bg=BG)
    self.q=queue.Queue(maxsize=10000); self.stop=threading.Event(); self.capturing=False
    self.capture_error=None
    self.capture_count=0
    self.capture_started=None
    self.capture_worker_thread=None
    self.packets=load(PACKETS,[]); self.devices=load(DEVICES,[])
    self.session_raw_packets=[]
    self.flow_state={}
    self.http_events=[]
    self.alert_events=load(DATA / "alerts.json",[])
    if not isinstance(self.alert_events,list): self.alert_events=[]
    for _a in self.alert_events:
     if isinstance(_a,dict):
      _a.setdefault("id",self.alert_id(_a))
      _a.setdefault("status","new")
      _a.setdefault("notes","")
    self.tcp_streams={}
    self.stream_rows=[]
    self.dns_events=[]
    self.pcap_lab_path=""; self.pcap_lab_packets=[]; self.pcap_lab_report={}
    self.ioc_path = DATA / "indicators.json"
    self.iocs = load(self.ioc_path, [])
    if not isinstance(self.iocs, list): self.iocs = []
    self.ioc_matches = []
    self.device_history=load(DATA / "device_history.json",[])
    self.cases_path=DATA / "cases.json"
    self.cases=load(self.cases_path,[])
    if not isinstance(self.cases,list): self.cases=[]
    self.imported_security_events=[]
    self.flow_first_seen={}
    self.rate_samples=[]
    self.last_rate_update=time.time()
    self.last_packet_total=0
    if not isinstance(self.packets,list): self.packets=[]
    if not isinstance(self.devices,list): self.devices=[]
    self.configure_styles(); self.build(); self.refresh_all(); root.after(120,self.drain); root.after(450,self.animate_status); root.protocol("WM_DELETE_WINDOW",self.close)
    self.show_splash()
 def show_splash(self):
    """Brief branded welcome screen; automatically opens the workspace in under two seconds."""
    try:
     self.root.withdraw()
     splash=tk.Toplevel(self.root); splash.overrideredirect(True); splash.configure(bg="#f3f6fa")
     width,height=520,280
     splash.update_idletasks(); x=(splash.winfo_screenwidth()-width)//2; y=(splash.winfo_screenheight()-height)//2
     splash.geometry(f"{width}x{height}+{x}+{y}")
     tk.Frame(splash,bg=ACCENT,height=7).pack(fill="x")
     body=tk.Frame(splash,bg="#f3f6fa",padx=30,pady=28); body.pack(fill="both",expand=True)
     tk.Label(body,text="CocoScanner",bg="#f3f6fa",fg=ACCENT,font=("DejaVu Sans",27,"bold")).pack(pady=(10,4))
     tk.Label(body,text="NETWORK VISIBILITY  •  THREAT INVESTIGATION",bg="#f3f6fa",fg="#526174",font=("DejaVu Sans",9,"bold")).pack()
     tk.Frame(body,bg="#dbe3ed",height=1).pack(fill="x",pady=18)
     tk.Label(body,text="Preparing your analyst workspace…",bg="#f3f6fa",fg="#526174",font=("DejaVu Sans",10)).pack()
     splash.after(1600,lambda: self._finish_splash(splash))
    except tk.TclError:
     self.root.deiconify()
 def _finish_splash(self,splash):
    try:splash.destroy()
    except tk.TclError:pass
    self.root.deiconify(); self.root.lift()
 def configure_styles(self):
    s=ttk.Style()
    try:s.theme_use("clam")
    except tk.TclError:pass
    s.configure("TFrame",background=BG); s.configure("Panel.TFrame",background=PANEL)
    s.configure("AccentBar.TFrame",background=ACCENT)
    s.configure("TLabel",background=BG,foreground=TEXT,font=("DejaVu Sans",10))
    s.configure("Muted.TLabel",background=PANEL,foreground=MUTED,font=("DejaVu Sans",9))
    s.configure("Title.TLabel",background=BG,foreground=ACCENT,font=("DejaVu Sans",22,"bold"))
    s.configure("Subtitle.TLabel",background=BG,foreground=MUTED,font=("DejaVu Sans",8,"bold"))
    s.configure("TButton",padding=(7,4),font=("DejaVu Sans",9,"bold"),background="#e7edf4",foreground=TEXT,relief="flat")
    s.map("TButton",background=[("active","#d9e3ef"),("pressed","#cbd7e5"),("disabled","#edf0f4")],foreground=[("active",TEXT),("disabled","#9aa4b2")])
    s.configure("Accent.TButton",background=ACCENT,foreground="#ffffff",padding=(9,5),relief="flat")
    s.map("Accent.TButton",background=[("active","#d94e13"),("pressed","#bd3f0d"),("disabled","#e9b39d")],foreground=[("disabled","#ffffff")])
    s.configure("Stop.TButton",background="#fde8e7",foreground="#a61b1b",padding=(7,4),relief="flat")
    s.map("Stop.TButton",background=[("active","#fbd0ce"),("pressed","#f6b9b5")])
    s.configure("TEntry",fieldbackground="#ffffff",foreground=TEXT,insertcolor=ACCENT,bordercolor="#cbd5e1",padding=4)
    s.configure("TCombobox",fieldbackground="#ffffff",background="#e7edf4",foreground=TEXT,arrowcolor=ACCENT,padding=4)
    s.map("TCombobox",fieldbackground=[("readonly","#ffffff")],foreground=[("readonly",TEXT)])
    s.configure("TNotebook",background=BG,borderwidth=0,tabmargins=(0,2,0,0))
    s.configure("TNotebook.Tab",background="#e4eaf2",foreground="#425166",padding=(10,6),borderwidth=0,font=("DejaVu Sans",8,"bold"))
    s.map("TNotebook.Tab",background=[("selected",ACCENT),("active","#d5e0ec")],foreground=[("selected","#ffffff"),("active",TEXT)],expand=[("selected",[1,1,1,0])])
    s.configure("Treeview",background="#ffffff",fieldbackground="#ffffff",foreground=TEXT,rowheight=24,borderwidth=0,font=("DejaVu Sans",9))
    s.configure("Treeview.Heading",background="#e8eef5",foreground="#334155",font=("DejaVu Sans",9,"bold"),padding=5,relief="flat")
    s.map("Treeview",background=[("selected","#ffe2d4")],foreground=[("selected","#7c2d12")])
    s.map("Treeview.Heading",background=[("active","#ffd4bf")],foreground=[("active","#7c2d12")])
 def animate_status(self):
    if not hasattr(self,"status_label"):
     self.root.after(450,self.animate_status); return
    # Subtle accent pulse on the status indicator; no blocking animation loop.
    if self.capturing:
     self._pulse = not getattr(self,"_pulse",False)
     self.status_label.configure(foreground=ACCENT if self._pulse else GREEN)
    else:
     self.status_label.configure(foreground=RED if "ERROR" in self.status.get() else GREEN)
    self.root.after(450,self.animate_status)
 def build(self):
    menubar=tk.Menu(self.root,tearoff=0,bg="#ffffff",fg=TEXT,activebackground=ACCENT,activeforeground="#ffffff",bd=0)
    file_menu=tk.Menu(menubar,tearoff=0,bg="#ffffff",fg=TEXT,activebackground=ACCENT,activeforeground="#ffffff",bd=0)
    file_menu.add_command(label="Export current data…",command=self.export)
    file_menu.add_separator(); file_menu.add_command(label="Exit",command=self.close)
    menubar.add_cascade(label="File",menu=file_menu)
    capture_menu=tk.Menu(menubar,tearoff=0,bg="#ffffff",fg=TEXT,activebackground=ACCENT,activeforeground="#ffffff",bd=0)
    capture_menu.add_command(label="Start capture",command=self.start_capture)
    capture_menu.add_command(label="Stop capture",command=self.stop_capture)
    menubar.add_cascade(label="Capture",menu=capture_menu)
    view_menu=tk.Menu(menubar,tearoff=0,bg="#ffffff",fg=TEXT,activebackground=ACCENT,activeforeground="#ffffff",bd=0)
    view_menu.add_command(label="Refresh workspace",command=self.refresh_all)
    menubar.add_cascade(label="View",menu=view_menu)
    help_menu=tk.Menu(menubar,tearoff=0,bg="#ffffff",fg=TEXT,activebackground=ACCENT,activeforeground="#ffffff",bd=0)
    help_menu.add_command(label="User Guide / How to Operate",command=self.show_help)
    help_menu.add_command(label="Quick Start",command=self.show_quick_start)
    help_menu.add_separator(); help_menu.add_command(label="Diagnostics",command=self.show_diagnostics)
    help_menu.add_command(label="About CocoScanner",command=self.show_about)
    menubar.add_cascade(label="Help",menu=help_menu)
    self.root.configure(menu=menubar)
    header=ttk.Frame(self.root,padding=(10,6,10,5)); header.pack(fill="x")
    brand=ttk.Frame(header); brand.pack(side="left",fill="x",expand=True)
    ttk.Label(brand,text="CocoScanner",style="Title.TLabel").pack(anchor="w")
    ttk.Label(brand,text="NETWORK VISIBILITY  /  THREAT INTELLIGENCE  /  PCAP INVESTIGATION",style="Subtitle.TLabel").pack(anchor="w",pady=(1,0))
    self.status=tk.StringVar(value="●  READY"); self.status_label=ttk.Label(header,textvariable=self.status,font=("DejaVu Sans",10,"bold")); self.status_label.pack(side="right",pady=(10,0))
    ttk.Frame(self.root,style="AccentBar.TFrame",height=3).pack(fill="x",padx=10,pady=(0,5))
    self.status_label.configure(foreground=GREEN)
    controls=ttk.Frame(self.root,padding=(10,0,10,6)); controls.pack(fill="x")
    ttk.Label(controls,text="INTERFACE").pack(side="left")
    self.iface=tk.StringVar(value=iface_default()); ttk.Entry(controls,textvariable=self.iface,width=13).pack(side="left",padx=(4,7))
    self.start_btn=ttk.Button(controls,text="▶  Start capture",style="Accent.TButton",command=self.start_capture); self.start_btn.pack(side="left",padx=3)
    self.stop_btn=ttk.Button(controls,text="■  Stop",style="Stop.TButton",command=self.stop_capture); self.stop_btn.pack(side="left",padx=3)
    ttk.Separator(controls,orient="vertical").pack(side="left",fill="y",padx=12)
    ttk.Label(controls,text="PRIVATE SUBNET").pack(side="left")
    self.subnet=tk.StringVar(value=subnet_default()); ttk.Entry(controls,textvariable=self.subnet,width=19).pack(side="left",padx=4)
    ttk.Button(controls,text="⌕  Discover devices",command=self.scan).pack(side="left",padx=3)
    ttk.Button(controls,text="↻  Refresh",command=self.refresh_all).pack(side="left",padx=3)
    self.tabs=ttk.Notebook(self.root); self.tabs.pack(fill="both",expand=True,padx=8,pady=(0,5))
    self.packet_tab=ttk.Frame(self.tabs,style="Panel.TFrame",padding=12)
    self.flows_tab=ttk.Frame(self.tabs,style="Panel.TFrame",padding=12)
    self.streams_tab=ttk.Frame(self.tabs,style="Panel.TFrame",padding=12)
    self.http_tab=ttk.Frame(self.tabs,style="Panel.TFrame",padding=12)
    self.alerts_tab=ttk.Frame(self.tabs,style="Panel.TFrame",padding=12)
    self.devices_tab=ttk.Frame(self.tabs,style="Panel.TFrame",padding=12)
    self.stats_tab=ttk.Frame(self.tabs,style="Panel.TFrame",padding=12)
    self.dns_tab=ttk.Frame(self.tabs,style="Panel.TFrame",padding=12)
    self.pcap_tab=ttk.Frame(self.tabs,style="Panel.TFrame",padding=12)
    self.threat_tab=ttk.Frame(self.tabs,style="Panel.TFrame",padding=12)
    self.cases_tab=ttk.Frame(self.tabs,style="Panel.TFrame",padding=12)
    self.tabs.add(self.packet_tab,text="  Packet Inspector  ")
    self.tabs.add(self.flows_tab,text="  TCP Flows  ")
    self.tabs.add(self.streams_tab,text="  TCP Streams  ")
    self.tabs.add(self.http_tab,text="  HTTP Inspector  ")
    self.tabs.add(self.alerts_tab,text="  Alerts  ")
    self.tabs.add(self.devices_tab,text="  Device Inventory  ")
    self.tabs.add(self.stats_tab,text="  Protocol Overview  ")
    self.tabs.add(self.dns_tab,text="  DNS History  ")
    self.tabs.add(self.pcap_tab,text="  PCAP Lab & Reports  ")
    self.tabs.add(self.threat_tab,text="  Threat Intel Lab  ")
    self.tabs.add(self.cases_tab,text="  Cases & SIEM Logs  ")
    self.build_packet_tab(); self.build_device_tab(); self.build_stats_tab(); self.build_dns_tab()
    self.build_flows_tab(); self.build_http_tab(); self.build_alerts_tab(); self.build_streams_tab(); self.build_pcap_tab(); self.build_threat_tab(); self.build_cases_tab()
    foot=ttk.Frame(self.root,padding=(10,0,10,5)); foot.pack(fill="x")
    ttk.Label(foot,text=f"Local IP: {local_ip()}  •  Interface: {iface_default() or 'unknown'}  •  JSON storage  •  HTTPS remains encrypted",foreground=MUTED).pack(side="left")
    ttk.Button(foot,text="Export JSON…",command=self.export).pack(side="right")
 def build_cases_tab(self):
    top=ttk.Frame(self.cases_tab,style="Panel.TFrame");top.pack(fill="x",pady=(0,8))
    ttk.Label(top,text="CASE MANAGEMENT  •  SURICATA / ZEEK LOG INGESTION",style="Muted.TLabel").pack(side="left")
    ttk.Button(top,text="New case…",style="Accent.TButton",command=self.new_case_dialog).pack(side="right",padx=3)
    ttk.Button(top,text="Attach loaded PCAP",command=self.attach_pcap_to_case).pack(side="right",padx=3)
    ttk.Button(top,text="Import Suricata / Zeek logs…",command=self.import_security_logs).pack(side="right",padx=3)
    ttk.Button(top,text="Export selected case…",command=self.export_case).pack(side="right",padx=3)
    pane=ttk.Panedwindow(self.cases_tab,orient="vertical");pane.pack(fill="both",expand=True)
    upper=ttk.Frame(pane,style="Panel.TFrame");lower=ttk.Frame(pane,style="Panel.TFrame");pane.add(upper,weight=2);pane.add(lower,weight=2)
    cols=("id","title","severity","status","updated","evidence")
    self.case_tree=ttk.Treeview(upper,columns=cols,show="headings",height=8)
    for c,t,w in [("id","CASE ID",150),("title","TITLE",360),("severity","SEVERITY",100),("status","STATUS",130),("updated","UPDATED (UTC)",190),("evidence","EVIDENCE",90)]:self.case_tree.heading(c,text=t);self.case_tree.column(c,width=w,stretch=c in ("title",))
    self.case_tree.pack(fill="both",expand=True);self.case_tree.bind("<<TreeviewSelect>>",self.show_case_detail)
    ttk.Label(lower,text="CASE DETAILS / IMPORTED SECURITY EVENTS",style="Muted.TLabel").pack(anchor="w")
    self.case_detail=tk.Text(lower,bg="#ffffff",fg=TEXT,font=("DejaVu Sans Mono",9),height=12,wrap="word",relief="flat")
    self.case_detail.pack(fill="both",expand=True,pady=(4,0))
    self.refresh_cases()

 def refresh_cases(self):
    if not hasattr(self,"case_tree"):return
    for item in self.case_tree.get_children():self.case_tree.delete(item)
    for c in sorted(self.cases,key=lambda x:x.get("updated_at",""),reverse=True):
     self.case_tree.insert("","end",iid=c.get("id"),values=(c.get("id"),c.get("title"),c.get("severity"),c.get("status"),c.get("updated_at",""),len(c.get("evidence",[]))))

 def selected_case(self):
    sel=self.case_tree.selection() if hasattr(self,"case_tree") else ()
    if not sel:return None
    return next((c for c in self.cases if c.get("id")==sel[0]),None)

 def show_case_detail(self,_=None):
    c=self.selected_case()
    if not c:return
    self.case_detail.delete("1.0","end")
    self.case_detail.insert("1.0",json.dumps(c,indent=2,ensure_ascii=False)+"\n\nIMPORTED SECURITY EVENTS\n"+json.dumps(self.imported_security_events[-100:],indent=2,ensure_ascii=False))

 def new_case_dialog(self):
    win=tk.Toplevel(self.root);win.title("Create investigation case");win.geometry("480x390");win.configure(bg=BG);win.transient(self.root);win.grab_set()
    frame=ttk.Frame(win,padding=18);frame.pack(fill="both",expand=True)
    ttk.Label(frame,text="Create investigation case",style="Title.TLabel").pack(anchor="w",pady=(0,10))
    title=tk.StringVar();severity=tk.StringVar(value="medium");status=tk.StringVar(value="new");notes=tk.StringVar()
    for label,var,values in [("Case title",title,None),("Severity",severity,["informational","low","medium","high","critical"]),("Status",status,["new","investigating","contained","resolved","closed"]),("Initial notes",notes,None)]:
     ttk.Label(frame,text=label).pack(anchor="w",pady=(5,2))
     if values:ttk.Combobox(frame,textvariable=var,values=values,state="readonly").pack(fill="x")
     else:ttk.Entry(frame,textvariable=var).pack(fill="x")
    def create():
     name=title.get().strip()
     if not name:messagebox.showerror("Title required","Enter a case title.",parent=win);return
     case={"id":"NS-"+datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")+f"-{len(self.cases)+1:03d}","title":name[:180],"severity":severity.get(),"status":status.get(),"created_at":stamp(),"updated_at":stamp(),"notes":notes.get().strip()[:5000],"evidence":[],"timeline":[{"time":stamp(),"event":"Case created"}]}
     self.cases.append(case);save(self.cases_path,self.cases);self.refresh_cases();self.case_tree.selection_set(case["id"]);self.show_case_detail();win.destroy();self.set_status("CASE CREATED • "+case["id"])
    ttk.Button(frame,text="Create case",style="Accent.TButton",command=create).pack(anchor="e",pady=12)

 def attach_pcap_to_case(self):
    c=self.selected_case()
    if not c:messagebox.showinfo("Select a case","Select a case row first.");return
    if not self.pcap_lab_path or not Path(self.pcap_lab_path).is_file():messagebox.showinfo("Load a PCAP first","Load a local PCAP file in PCAP Lab first.");return
    h=hashlib.sha256()
    try:
     with open(self.pcap_lab_path,"rb") as f:
      for chunk in iter(lambda:f.read(1024*1024),b""):h.update(chunk)
     evidence={"type":"pcap","path":self.pcap_lab_path,"sha256":h.hexdigest(),"attached_at":stamp(),"packets_analyzed":len(self.pcap_lab_packets)}
     if not any(e.get("sha256")==evidence["sha256"] for e in c.get("evidence",[])):c.setdefault("evidence",[]).append(evidence)
     c.setdefault("timeline",[]).append({"time":stamp(),"event":"PCAP evidence attached; SHA-256 calculated"});c["updated_at"]=stamp();save(self.cases_path,self.cases);self.refresh_cases();self.case_tree.selection_set(c["id"]);self.show_case_detail();self.set_status("EVIDENCE ATTACHED • SHA-256 VERIFIED")
    except OSError as e:messagebox.showerror("Evidence error",str(e))

 def export_case(self):
    c=self.selected_case()
    if not c:messagebox.showinfo("Select a case","Select a case row first.");return
    path=filedialog.asksaveasfilename(title="Export case bundle manifest",defaultextension=".json",filetypes=[("Case JSON","*.json"),("HTML case report","*.html")],initialfile=f"{c['id']}-case.json")
    if not path:return
    try:
     target=Path(path);bundle={"application":"CocoScanner","exported_at":stamp(),"case":c,"security_events":self.imported_security_events[-500:],"integrity_note":"SHA-256 hashes verify byte equality against the hash recorded at attachment time; they do not alone prove provenance or chain of custody."}
     if target.suffix.lower()==".html":
      import html
      target.write_text("<!doctype html><meta charset='utf-8'><title>CocoScanner Case</title><body style='font:15px system-ui;max-width:1000px;margin:30px auto'><h1>CocoScanner Case "+html.escape(c["id"])+"</h1><pre>"+html.escape(json.dumps(bundle,indent=2,ensure_ascii=False))+"</pre></body>",encoding="utf-8")
     else:target.write_text(json.dumps(bundle,indent=2,ensure_ascii=False),encoding="utf-8")
     messagebox.showinfo("Case exported",f"Saved case report to:\n{target}")
    except OSError as e:messagebox.showerror("Export failed",str(e))

 def import_security_logs(self):
    path=filedialog.askopenfilename(title="Import Suricata eve.json or Zeek logs",filetypes=[("Security logs","*.json *.log *.tsv *.txt"),("All files","*.*")])
    if not path:return
    try:
     p=Path(path);rows=[]
     if p.suffix.lower()==".json":
      # Suricata eve.json: one JSON object per line. Bound import to avoid memory exhaustion.
      with p.open(encoding="utf-8",errors="replace") as f:
       for line in f:
        if len(rows)>=20000:break
        if len(line)>1_000_000:continue
        try:obj=json.loads(line)
        except json.JSONDecodeError:continue
        if isinstance(obj,dict):
         event_type=str(obj.get("event_type","unknown"));alert=obj.get("alert") if isinstance(obj.get("alert"),dict) else {}
         rows.append({"source_file":p.name,"timestamp":str(obj.get("timestamp","")),"source_ip":str(obj.get("src_ip","")),"source_port":obj.get("src_port"),"destination_ip":str(obj.get("dest_ip",obj.get("dst_ip",""))),"destination_port":obj.get("dest_port",obj.get("dst_port")),"event_type":event_type,"signature":str(alert.get("signature",obj.get("notice",{}).get("msg","") if isinstance(obj.get("notice"),dict) else ""))[:300],"severity":alert.get("severity"),"engine":"Suricata/EVE or JSON event"})
     else:
      # Zeek TSV commonly begins with #separator and #fields metadata lines.
      fields=[]
      with p.open(encoding="utf-8",errors="replace") as f:
       for line in f:
        if len(rows)>=20000:break
        line=line.rstrip("\n")
        if line.startswith("#fields"):
         fields=line.split("\t")[1:];continue
        if not line or line.startswith("#") or not fields:continue
        vals=line.split("\t")
        if len(vals)!=len(fields):continue
        d=dict(zip(fields,vals));rows.append({"source_file":p.name,"timestamp":d.get("ts",""),"source_ip":d.get("id.orig_h",""),"source_port":d.get("id.orig_p",""),"destination_ip":d.get("id.resp_h",""),"destination_port":d.get("id.resp_p",""),"event_type":p.stem,"signature":str(d.get("query",d.get("service","")))[:300],"severity":"unknown","engine":"Zeek TSV"})
     self.imported_security_events=rows
     self.case_detail.delete("1.0","end");self.case_detail.insert("1.0",f"Imported {len(rows)} event record(s) from {p.name}.\n\nThis is log ingestion and normalization, not a live Suricata/Zeek runtime integration. Review the source tool's own alert semantics.\n\n"+json.dumps(rows[:100],indent=2,ensure_ascii=False))
     self.set_status(f"SECURITY LOGS IMPORTED • {len(rows)} EVENTS")
     messagebox.showinfo("Log import complete",f"Imported {len(rows)} normalized event(s).\nRecords are held in this application session and included in case exports.")
    except (OSError,ValueError) as e:messagebox.showerror("Log import failed",str(e))

 def show_diagnostics(self):
    details={"application":"CocoScanner v2.02 Phase 6+","python":__import__("sys").version.split()[0],"platform":__import__("platform").platform(),"interface":self.iface.get().strip(),"capture_running":self.capturing,"packets_in_memory":len(self.packets),"current_session_packets":len(self.session_raw_packets),"capture_queue_depth":self.q.qsize(),"ioc_count":len(self.iocs),"case_count":len(self.cases),"imported_security_events":len(self.imported_security_events),"data_directory":str(DATA)}
    try:
     import scapy;details["scapy"]="installed"
    except ImportError:details["scapy"]="not installed"
    details["nmap"]="available" if shutil.which("nmap") else "not installed"
    messagebox.showinfo("CocoScanner Diagnostics",json.dumps(details,indent=2))

 def build_packet_tab(self):
    top=ttk.Frame(self.packet_tab,style="Panel.TFrame"); top.pack(fill="x",pady=(0,9))
    ttk.Label(top,text="PACKETS VISIBLE TO THIS INTERFACE",style="Muted.TLabel").pack(side="left")
    ttk.Label(top,text="Find packets").pack(side="left",padx=(20,5))
    self.filter=tk.StringVar(); e=ttk.Entry(top,textvariable=self.filter,width=32); e.pack(side="left"); e.bind("<KeyRelease>",lambda _ : self.refresh_packets())
    ttk.Button(top,text="Clear search",command=lambda:(self.filter.set(""),self.refresh_packets())).pack(side="left",padx=6)
    ttk.Button(top,text="Export PCAP…",command=self.export_pcap).pack(side="right",padx=(6,0))
    ttk.Button(top,text="Export JSON…",command=self.export).pack(side="right",padx=(6,0))
    ttk.Button(top,text="Clear session",command=self.clear_session).pack(side="right")
    split=ttk.Panedwindow(self.packet_tab,orient="vertical"); split.pack(fill="both",expand=True)
    upper=ttk.Frame(split,style="Panel.TFrame"); lower=ttk.Frame(split,style="Panel.TFrame")
    split.add(upper,weight=3); split.add(lower,weight=2)
    cols=("time","src","dst","proto","len","flags","summary"); self.tree=ttk.Treeview(upper,columns=cols,show="headings",selectmode="browse")
    heads={"time":"TIMESTAMP (UTC)","src":"SOURCE","dst":"DESTINATION","proto":"PROTOCOL","len":"BYTES","flags":"FLAGS","summary":"PACKET SUMMARY"}
    widths={"time":190,"src":170,"dst":170,"proto":75,"len":65,"flags":60,"summary":330}
    for c in cols:self.tree.heading(c,text=heads[c]);self.tree.column(c,width=widths[c],minwidth=50,stretch=c=="summary")
    y=ttk.Scrollbar(upper,orient="vertical",command=self.tree.yview); x=ttk.Scrollbar(upper,orient="horizontal",command=self.tree.xview); self.tree.configure(yscrollcommand=y.set,xscrollcommand=x.set)
    self.tree.pack(fill="both",expand=True,side="top"); y.pack(side="right",fill="y"); x.pack(fill="x")
    self.tree.bind("<<TreeviewSelect>>",self.show_details)
    ttk.Label(lower,text="SELECTED PACKET DETAILS",style="Muted.TLabel").pack(anchor="w",pady=(4,6))
    detail=ttk.Panedwindow(lower,orient="horizontal"); detail.pack(fill="both",expand=True)
    a=ttk.Frame(detail,style="Panel.TFrame"); b=ttk.Frame(detail,style="Panel.TFrame"); detail.add(a,weight=3);detail.add(b,weight=2)
    self.fields=tk.Text(a,bg="#ffffff",fg="#243244",font=("DejaVu Sans Mono",9),wrap="word",relief="flat",height=10); self.fields.pack(fill="both",expand=True)
    self.payload=tk.Text(b,bg="#ffffff",fg="#243244",font=("DejaVu Sans Mono",9),wrap="word",relief="flat",height=10); self.payload.pack(fill="both",expand=True)
 def build_device_tab(self):
    bar=ttk.Frame(self.devices_tab,style="Panel.TFrame");bar.pack(fill="x",pady=(0,8))
    ttk.Label(bar,text="DISCOVERED DEVICES ON YOUR AUTHORIZED PRIVATE SUBNET",style="Muted.TLabel").pack(side="left")
    ttk.Button(bar,text="Scan now",style="Accent.TButton",command=self.scan).pack(side="right")
    cols=("ip","host","mac","vendor","first","last","state");self.dev_tree=ttk.Treeview(self.devices_tab,columns=cols,show="headings")
    heads={"ip":"IP ADDRESS","host":"HOSTNAME","mac":"MAC ADDRESS","vendor":"VENDOR","first":"FIRST SEEN","last":"LAST SEEN","state":"STATUS"}
    widths={"ip":140,"host":180,"mac":160,"vendor":180,"first":180,"last":180,"state":90}
    for c in cols:self.dev_tree.heading(c,text=heads[c]);self.dev_tree.column(c,width=widths[c],minwidth=70)
    sy=ttk.Scrollbar(self.devices_tab,orient="vertical",command=self.dev_tree.yview);self.dev_tree.configure(yscrollcommand=sy.set)
    self.dev_tree.pack(side="left",fill="both",expand=True);sy.pack(side="right",fill="y")

 def build_dns_tab(self):
    bar=ttk.Frame(self.dns_tab,style="Panel.TFrame");bar.pack(fill="x",pady=(0,8))
    ttk.Label(bar,text="OBSERVED DNS QUERIES / RESPONSES — metadata only",style="Muted.TLabel").pack(side="left")
    ttk.Button(bar,text="Export DNS JSON…",command=self.export_dns).pack(side="right")
    cols=("time","src","dst","type","name","summary")
    self.dns_tree=ttk.Treeview(self.dns_tab,columns=cols,show="headings")
    heads={"time":"TIMESTAMP (UTC)","src":"SOURCE","dst":"DNS SERVER","type":"TYPE","name":"QUERY NAME","summary":"DETAIL"}
    widths={"time":205,"src":190,"dst":190,"type":100,"name":280,"summary":320}
    for c in cols:self.dns_tree.heading(c,text=heads[c]);self.dns_tree.column(c,width=widths[c],minwidth=70,stretch=c in ("name","summary"))
    self.dns_tree.pack(fill="both",expand=True)
    ttk.Label(self.dns_tab,text="History only includes DNS packets visible to the selected capture interface.",style="Muted.TLabel").pack(anchor="w",pady=(8,0))

 def build_stats_tab(self):
    ttk.Label(self.stats_tab,text="PROTOCOL DISTRIBUTION",style="Muted.TLabel").pack(anchor="w")
    self.stats_text=tk.Text(self.stats_tab,bg="#ffffff",fg="#243244",font=("DejaVu Sans Mono",11),relief="flat",wrap="word")
    self.stats_text.pack(fill="both",expand=True,pady=(8,0))

 def show_help(self):
    """Open the bundled operator guide in a readable, scrollable window."""
    path=ROOT / "HELP.md"
    try:
     content=path.read_text(encoding="utf-8")
    except OSError:
     content="CocoScanner User Guide is missing. Re-extract the complete application ZIP."
    win=tk.Toplevel(self.root); win.title("CocoScanner — User Guide"); win.geometry("920x720"); win.minsize(680,480); win.configure(bg=BG)
    top=ttk.Frame(win,padding=(16,12)); top.pack(fill="x")
    ttk.Label(top,text="CocoScanner OPERATOR GUIDE",style="Title.TLabel").pack(side="left")
    ttk.Button(top,text="Close",command=win.destroy).pack(side="right")
    body=ttk.Frame(win,padding=(16,0,16,16)); body.pack(fill="both",expand=True)
    box=tk.Text(body,bg="#ffffff",fg=TEXT,insertbackground=TEXT,selectbackground="#24515a",font=("DejaVu Sans Mono",10),wrap="word",relief="flat",padx=14,pady=12)
    scroll=ttk.Scrollbar(body,orient="vertical",command=box.yview); box.configure(yscrollcommand=scroll.set)
    box.pack(side="left",fill="both",expand=True); scroll.pack(side="right",fill="y")
    box.insert("1.0",content); box.configure(state="disabled")

 def show_quick_start(self):
    messagebox.showinfo("CocoScanner — Quick Start", "LIVE MONITORING\n1. Select the network interface shown at the top (commonly wlan0 or enp…).\n2. Click Start capture. Use Stop when finished.\n3. Select a packet to inspect decoded fields and payload preview.\n\nOFFLINE PCAP\n1. Open PCAP Lab & Reports.\n2. Load a .pcap, .pcapng, or .cap file.\n3. Analyze capture, review findings, and export an HTML or JSON report.\n\nDEVICE DISCOVERY\nEnter an authorized private IPv4 subnet (for example 192.168.1.0/24) and click Discover devices. Only scan networks you own or have permission to assess.\n\nFor detailed search syntax, alerts, exports, troubleshooting, and limitations, open Help → User Guide.")

 def show_about(self):
    messagebox.showinfo("About CocoScanner", "CocoScanner — Desktop Network Monitor\nVersion: v2.02 Phase 6\nBuilt with Python, Tkinter, Scapy, Nmap, and JSON.\nLocal desktop application; no web server or SQLite database.\n\nUse only on networks and captures you own or are authorized to inspect.")

 def set_status(self,text,error=False):
    self.status.set(("●  " + text) if not text.startswith("●") else text);self.status_label.configure(foreground=RED if error else GREEN)

 def build_flows_tab(self):
    ttk.Label(self.flows_tab,text="TCP CONVERSATIONS — grouped by endpoint tuple",style="Muted.TLabel").pack(anchor="w",pady=(0,8))
    cols=("src","dst","packets","bytes","flags","last")
    self.flow_tree=ttk.Treeview(self.flows_tab,columns=cols,show="headings")
    heads={"src":"SOURCE","dst":"DESTINATION","packets":"PACKETS","bytes":"BYTES","flags":"FLAGS SEEN","last":"LAST SEEN"}
    widths={"src":220,"dst":220,"packets":90,"bytes":100,"flags":180,"last":220}
    for c in cols:self.flow_tree.heading(c,text=heads[c]);self.flow_tree.column(c,width=widths[c],minwidth=70)
    self.flow_tree.pack(fill="both",expand=True)
    ttk.Label(self.flows_tab,text="Conversation summaries are derived from captured packets; they do not guarantee complete stream visibility.",style="Muted.TLabel").pack(anchor="w",pady=(8,0))
 def build_http_tab(self):
    ttk.Label(self.http_tab,text="CLEAR-TEXT HTTP OBSERVATIONS",style="Muted.TLabel").pack(anchor="w",pady=(0,8))
    ttk.Label(self.http_tab,text="Only HTTP visible in captured TCP payloads can be identified. HTTPS is encrypted. This is a lightweight stream preview, not a full browser-grade proxy.",style="Muted.TLabel",wraplength=900).pack(anchor="w",pady=(0,10))
    cols=("time","src","dst","kind","line")
    self.http_tree=ttk.Treeview(self.http_tab,columns=cols,show="headings")
    heads={"time":"TIMESTAMP (UTC)","src":"SOURCE","dst":"DESTINATION","kind":"TYPE","line":"HTTP START LINE"}
    widths={"time":190,"src":190,"dst":190,"kind":100,"line":480}
    for c in cols:self.http_tree.heading(c,text=heads[c]);self.http_tree.column(c,width=widths[c],minwidth=70,stretch=c=="line")
    self.http_tree.pack(fill="both",expand=True)
    self.http_detail=tk.Text(self.http_tab,bg="#ffffff",fg="#243244",font=("DejaVu Sans Mono",9),wrap="word",height=8,relief="flat")
    self.http_detail.pack(fill="x",pady=(8,0))
    self.http_tree.bind("<<TreeviewSelect>>",self.show_http_detail)
 def build_alerts_tab(self):
    top=ttk.Frame(self.alerts_tab,style="Panel.TFrame");top.pack(fill="x",pady=(0,8))
    ttk.Label(top,text="DETECTION WORKSPACE — heuristics require analyst validation",style="Muted.TLabel").pack(side="left")
    ttk.Button(top,text="Mark investigating",command=lambda:self.set_alert_status("investigating")).pack(side="right",padx=(5,0))
    ttk.Button(top,text="Resolve",command=lambda:self.set_alert_status("resolved")).pack(side="right",padx=(5,0))
    ttk.Button(top,text="Add analyst note",command=self.add_alert_note).pack(side="right",padx=(5,0))
    ttk.Button(top,text="Export alerts…",command=self.export_alerts).pack(side="right",padx=(5,0))
    cols=("time","severity","rule","status","src","detail")
    self.alert_tree=ttk.Treeview(self.alerts_tab,columns=cols,show="headings")
    heads={"time":"TIMESTAMP (UTC)","severity":"SEVERITY","rule":"DETECTION","status":"STATUS","src":"SOURCE","detail":"EVIDENCE"}
    widths={"time":180,"severity":90,"rule":200,"status":120,"src":150,"detail":500}
    for c in cols:self.alert_tree.heading(c,text=heads[c]);self.alert_tree.column(c,width=widths[c],minwidth=70,stretch=c=="detail")
    self.alert_tree.pack(fill="both",expand=True)
    self.alert_tree.bind("<<TreeviewSelect>>",self.show_alert_detail)
    self.alert_detail=tk.Text(self.alerts_tab,bg="#ffffff",fg="#243244",font=("DejaVu Sans Mono",9),height=7,wrap="word",relief="flat")
    self.alert_detail.pack(fill="x",pady=(8,0))

 def build_streams_tab(self):
    ttk.Label(self.streams_tab,text="TCP STREAM RECONSTRUCTION — best-effort, based on visible packets",style="Muted.TLabel").pack(anchor="w",pady=(0,8))
    ttk.Label(self.streams_tab,text="Select a conversation to view reconstructed printable bytes. Gaps, retransmissions, packet loss, and asymmetric visibility may make streams incomplete.",style="Muted.TLabel",wraplength=1000).pack(anchor="w",pady=(0,10))
    split=ttk.Panedwindow(self.streams_tab,orient="vertical");split.pack(fill="both",expand=True)
    top=ttk.Frame(split,style="Panel.TFrame");bottom=ttk.Frame(split,style="Panel.TFrame");split.add(top,weight=1);split.add(bottom,weight=2)
    cols=("key","packets","bytes","last","status");self.stream_tree=ttk.Treeview(top,columns=cols,show="headings",height=8)
    heads={"key":"TCP CONVERSATION","packets":"SEGMENTS","bytes":"PAYLOAD BYTES","last":"LAST SEEN","status":"REASSEMBLY"}
    widths={"key":430,"packets":90,"bytes":120,"last":220,"status":160}
    for c in cols:self.stream_tree.heading(c,text=heads[c]);self.stream_tree.column(c,width=widths[c],minwidth=70)
    self.stream_tree.pack(fill="both",expand=True);self.stream_tree.bind("<<TreeviewSelect>>",self.show_stream)
    self.stream_text=tk.Text(bottom,bg="#ffffff",fg="#243244",font=("DejaVu Sans Mono",9),wrap="word",relief="flat")
    self.stream_text.pack(fill="both",expand=True,pady=(8,0))

 def build_threat_tab(self):
    bar=ttk.Frame(self.threat_tab,style="Panel.TFrame");bar.pack(fill="x",pady=(0,8))
    ttk.Label(bar,text="LOCAL IOC CORRELATION • OFFLINE BY DEFAULT",style="Muted.TLabel").pack(side="left")
    ttk.Button(bar,text="Add indicator…",style="Accent.TButton",command=self.add_ioc_dialog).pack(side="right",padx=(5,0))
    ttk.Button(bar,text="Remove selected",command=self.remove_ioc).pack(side="right",padx=5)
    ttk.Button(bar,text="Import CSV/JSON…",command=self.import_iocs).pack(side="right",padx=5)
    ttk.Button(bar,text="Export feed…",command=self.export_iocs).pack(side="right",padx=5)
    ttk.Button(bar,text="Correlate loaded PCAP",command=self.correlate_iocs).pack(side="right",padx=5)
    ttk.Label(self.threat_tab,text="Indicators are stored locally. No IPs or domains are sent to third-party reputation services. Import a feed you trust, then correlate it with the loaded PCAP.",style="Muted.TLabel",wraplength=1100).pack(anchor="w",pady=(0,8))
    split=ttk.Panedwindow(self.threat_tab,orient="vertical");split.pack(fill="both",expand=True)
    upper=ttk.Frame(split,style="Panel.TFrame");lower=ttk.Frame(split,style="Panel.TFrame");split.add(upper,weight=3);split.add(lower,weight=2)
    ttk.Label(upper,text="INDICATOR LIBRARY",style="Muted.TLabel").pack(anchor="w",pady=(0,5))
    cols=("type","value","source","confidence","notes")
    self.ioc_tree=ttk.Treeview(upper,columns=cols,show="headings",height=8)
    for c,t,w in [("type","TYPE",95),("value","INDICATOR",260),("source","SOURCE",180),("confidence","CONFIDENCE",105),("notes","NOTES",350)]:self.ioc_tree.heading(c,text=t);self.ioc_tree.column(c,width=w,anchor="w")
    sy=ttk.Scrollbar(upper,orient="vertical",command=self.ioc_tree.yview);self.ioc_tree.configure(yscrollcommand=sy.set)
    self.ioc_tree.pack(side="left",fill="both",expand=True);sy.pack(side="right",fill="y")
    ttk.Label(lower,text="CORRELATION RESULTS & MITRE ATT&CK CONTEXT",style="Muted.TLabel").pack(anchor="w",pady=(0,5))
    self.ioc_results=tk.Text(lower,bg="#ffffff",fg=TEXT,font=("DejaVu Sans Mono",9),height=9,wrap="word",relief="flat")
    self.ioc_results.pack(fill="both",expand=True)
    self.refresh_iocs()

 def _normalize_ioc(self, typ, value):
    typ=(typ or "").strip().lower();value=(value or "").strip().strip(".").lower()
    if typ in ("ip","ipv4","ipv6","ip-address","ip address"):
     try:value=str(ipaddress.ip_address(value))
     except ValueError:raise ValueError("Enter a valid IPv4 or IPv6 address.")
     typ="ip"
    elif typ in ("domain","hostname","dns"):
     if len(value)>253 or not value or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",part) for part in value.split(".")) or "." not in value:
      raise ValueError("Enter a valid domain/hostname such as example.org.")
     typ="domain"
    else:raise ValueError("Indicator type must be IP or domain.")
    return typ,value

 def refresh_iocs(self):
    if not hasattr(self,"ioc_tree"):return
    for item in self.ioc_tree.get_children():self.ioc_tree.delete(item)
    for i,x in enumerate(self.iocs):
     if not isinstance(x,dict):continue
     self.ioc_tree.insert("","end",iid=str(i),values=(x.get("type",""),x.get("value",""),x.get("source","local"),x.get("confidence","unknown"),x.get("notes","")))

 def remove_ioc(self):
    selected=self.ioc_tree.selection()
    if not selected:return
    indexes=sorted((int(x) for x in selected),reverse=True)
    values=[self.iocs[i].get("value","") for i in indexes if 0<=i<len(self.iocs)]
    if not messagebox.askyesno("Remove indicators",f"Remove {len(values)} selected indicator(s)?\n\n"+", ".join(values[:8])):return
    for i in indexes:
     if 0<=i<len(self.iocs):self.iocs.pop(i)
    save(self.ioc_path,self.iocs);self.refresh_iocs();self.set_status(f"IOC REMOVED • {len(values)}")

 def add_ioc_dialog(self):
    win=tk.Toplevel(self.root);win.title("Add threat indicator");win.geometry("480x330");win.configure(bg=BG);win.transient(self.root);win.grab_set()
    frame=ttk.Frame(win,padding=18);frame.pack(fill="both",expand=True)
    ttk.Label(frame,text="Add an indicator to the local library",style="Title.TLabel").pack(anchor="w",pady=(0,12))
    typ=tk.StringVar(value="domain");value=tk.StringVar();source=tk.StringVar(value="Analyst-added");conf=tk.StringVar(value="medium");notes=tk.StringVar()
    for label,var in [("Type (ip/domain)",typ),("Indicator value",value),("Source / feed name",source),("Confidence (low/medium/high)",conf),("Analyst notes",notes)]:
     ttk.Label(frame,text=label).pack(anchor="w",pady=(5,2));ttk.Entry(frame,textvariable=var).pack(fill="x")
    def save_one():
     try:t,v=self._normalize_ioc(typ.get(),value.get())
     except ValueError as e:messagebox.showerror("Invalid indicator",str(e),parent=win);return
     if any(x.get("type")==t and x.get("value")==v for x in self.iocs):messagebox.showinfo("Already exists","That indicator is already in the library.",parent=win);return
     self.iocs.append({"type":t,"value":v,"source":source.get().strip() or "Analyst-added","confidence":conf.get().strip().lower() or "unknown","notes":notes.get().strip(),"added_at":stamp(),"expires_at":""})
     save(self.ioc_path,self.iocs);self.refresh_iocs();win.destroy();self.set_status(f"IOC ADDED • {v}")
    ttk.Button(frame,text="Save indicator",style="Accent.TButton",command=save_one).pack(anchor="e",pady=12)

 def import_iocs(self):
    path=filedialog.askopenfilename(title="Import indicators",filetypes=[("IOC feeds","*.json *.csv"),("JSON","*.json"),("CSV","*.csv"),("All files","*.*")])
    if not path:return
    try:
     if Path(path).suffix.lower()==".csv":
      import csv
      with open(path,newline="",encoding="utf-8-sig") as f:rows=list(csv.DictReader(f))
     else:
      raw=json.loads(Path(path).read_text(encoding="utf-8"));rows=raw.get("indicators",[]) if isinstance(raw,dict) else raw
     if not isinstance(rows,list):raise ValueError("Expected a JSON list or an object with an indicators list.")
     added=0;skipped=0
     existing={(x.get("type"),x.get("value")) for x in self.iocs if isinstance(x,dict)}
     for row in rows:
      if not isinstance(row,dict):skipped+=1;continue
      try:t,v=self._normalize_ioc(row.get("type",row.get("indicator_type","")),row.get("value",row.get("indicator","")))
      except ValueError:skipped+=1;continue
      if (t,v) in existing:skipped+=1;continue
      self.iocs.append({"type":t,"value":v,"source":str(row.get("source") or Path(path).name)[:160],"confidence":str(row.get("confidence") or "unknown")[:40].lower(),"notes":str(row.get("notes") or row.get("description") or "")[:500],"added_at":stamp(),"expires_at":""});existing.add((t,v));added+=1
     save(self.ioc_path,self.iocs);self.refresh_iocs();self.set_status(f"IOC IMPORT COMPLETE • {added} added")
     messagebox.showinfo("Import complete",f"Added: {added}\nSkipped invalid/duplicate rows: {skipped}\nStored locally in {self.ioc_path}")
    except Exception as e:messagebox.showerror("Import failed",str(e))

 def export_iocs(self):
    path=filedialog.asksaveasfilename(title="Export local indicator feed",defaultextension=".json",filetypes=[("JSON feed","*.json"),("CSV feed","*.csv")],initialfile="CocoScanner-indicators.json")
    if not path:return
    try:
     if Path(path).suffix.lower()==".csv":
      import csv
      with open(path,"w",newline="",encoding="utf-8") as f:
       w=csv.DictWriter(f,fieldnames=["type","value","source","confidence","notes","added_at"]);w.writeheader();w.writerows(self.iocs)
     else:Path(path).write_text(json.dumps({"generated_at":stamp(),"indicators":self.iocs},indent=2),encoding="utf-8")
     messagebox.showinfo("Export complete",f"Saved {len(self.iocs)} indicators to:\n{path}")
    except Exception as e:messagebox.showerror("Export failed",str(e))

 def correlate_iocs(self):
    if not self.pcap_lab_packets:
     messagebox.showinfo("Load a capture first","Open PCAP Lab & Reports and load a capture before correlation.");return
    if not self.iocs:
     messagebox.showinfo("No indicators","Add indicators or import a trusted CSV/JSON feed first.");return
    now=datetime.now(timezone.utc)
    def is_expired(item):
     raw=str(item.get("expires_at") or "").strip()
     if not raw:return False
     try:
      dt=datetime.fromisoformat(raw.replace("Z","+00:00"))
      if dt.tzinfo is None:dt=dt.replace(tzinfo=timezone.utc)
      return dt <= now
     except ValueError:return True
    lookup={(x.get("type"),x.get("value")):x for x in self.iocs if isinstance(x,dict) and not is_expired(x)};matches=[]
    for idx,r in enumerate(self.pcap_lab_packets):
     observed=[]
     for field in ("src","dst"):
      val=r.get(field)
      if val and ("ip",str(val).lower()) in lookup:observed.append(("ip",str(val).lower(),field))
     name=str(r.get("dns_name") or "").rstrip(".").lower()
     if name:
      # Exact domain and parent-domain matches, allowing a feed entry to match subdomains.
      parts=name.split(".")
      for j in range(len(parts)-1):
       candidate=".".join(parts[j:])
       if ("domain",candidate) in lookup:observed.append(("domain",candidate,"dns_name"))
     for typ,val,field in observed:
      ioc=lookup[(typ,val)]
      matches.append({"packet_index":idx,"timestamp":r.get("timestamp",""),"indicator_type":typ,"indicator":val,"field":field,"source":ioc.get("source","unknown"),"confidence":ioc.get("confidence","unknown"),"notes":ioc.get("notes","")})
    self.ioc_matches=matches
    attack=[]
    findings=(self.pcap_lab_report or {}).get("findings",[])
    for f in findings:
     title=f.get("title","")
     if "SYN port sweep" in title:attack.append({"technique":"T1046","name":"Network Service Discovery","reason":title,"tactic":"Discovery"})
    if any(m.get("indicator_type")=="domain" and m.get("field")=="dns_name" for m in matches):
     attack.append({"technique":"T1071.004","name":"DNS","reason":"A DNS name matched an imported indicator. DNS use alone is normal; validate the domain, endpoint, and surrounding traffic before mapping behavior.","tactic":"Potential Command and Control context (unconfirmed)"})
    if matches and not attack:
     attack.append({"technique":"Needs analyst mapping","name":"IOC match requires context","reason":"An imported IOC matched packet metadata; the match alone does not establish an ATT&CK technique.","tactic":"Unmapped"})
    report={"generated_at":stamp(),"capture":self.pcap_lab_path,"indicator_count":len(self.iocs),"match_count":len(matches),"matches":matches,"mitre_attack_context":attack,"note":"IOC matches indicate overlap with the imported local feed only; feed quality, freshness, shared hosting, NAT, and benign reuse must be validated. ATT&CK mappings are hypotheses, not confirmed techniques."}
    self.pcap_lab_report["threat_intel_correlation"]=report
    lines=["CocoScanner — THREAT INTELLIGENCE CORRELATION", "="*58, f"Capture: {self.pcap_lab_path}",f"Indicators loaded: {len(self.iocs)}",f"Packet-level matches: {len(matches)}","","IOC MATCHES"]
    if matches:
     for m in matches[:500]:lines.append(f"[{m['confidence'].upper()}] packet #{m['packet_index']+1} {m['timestamp']} | {m['indicator_type']}={m['indicator']} | field={m['field']} | source={m['source']} | {m['notes']}")
     if len(matches)>500:lines.append(f"… {len(matches)-500} additional matches omitted from this view (retained in report data).")
    else:lines.append("No matches against the currently imported local indicators. This does not establish that traffic is benign.")
    lines += ["","MITRE ATT&CK CONTEXT (HYPOTHESES)"]
    for a in attack:lines.append(f"{a['technique']} — {a['name']} [{a['tactic']}]: {a['reason']}")
    if not attack:lines.append("No current heuristic supplied a contextual technique mapping.")
    lines += ["","ANALYST GUIDANCE",report["note"],"No external reputation lookup was performed; no indicator values were transmitted."]
    self.ioc_results.delete("1.0","end");self.ioc_results.insert("1.0","\n".join(lines));self.set_status(f"IOC CORRELATION COMPLETE • {len(matches)} match(es)")

 def build_pcap_tab(self):
    bar=ttk.Frame(self.pcap_tab,style="Panel.TFrame");bar.pack(fill="x",pady=(0,8))
    ttk.Label(bar,text="OFFLINE PCAP INVESTIGATION — analysis does not transmit traffic",style="Muted.TLabel").pack(side="left")
    ttk.Button(bar,text="Load PCAP…",style="Accent.TButton",command=self.load_pcap_lab).pack(side="right",padx=(5,0))
    self.pcap_analyze_btn=ttk.Button(bar,text="Analyze capture",command=self.analyze_pcap_lab,state="disabled");self.pcap_analyze_btn.pack(side="right",padx=5)
    self.pcap_report_btn=ttk.Button(bar,text="Export investigation report…",command=self.export_pcap_report,state="disabled");self.pcap_report_btn.pack(side="right",padx=5)
    self.pcap_file_label=ttk.Label(self.pcap_tab,text="No PCAP loaded",style="Muted.TLabel");self.pcap_file_label.pack(anchor="w",pady=(0,8))
    self.pcap_summary=tk.Text(self.pcap_tab,bg="#ffffff",fg="#243244",font=("DejaVu Sans Mono",10),height=9,wrap="word",relief="flat")
    self.pcap_summary.pack(fill="x",pady=(0,8))
    ttk.Label(self.pcap_tab,text="PACKET TIMELINE — select a row to inspect its decoded fields",style="Muted.TLabel").pack(anchor="w",pady=(0,5))
    cols=("index","time","src","dst","proto","length","flags","finding")
    self.pcap_tree=ttk.Treeview(self.pcap_tab,columns=cols,show="headings")
    heads={"index":"#","time":"TIMESTAMP (UTC)","src":"SOURCE","dst":"DESTINATION","proto":"PROTOCOL","length":"BYTES","flags":"FLAGS","finding":"FINDING / OBSERVATION"}
    widths={"index":55,"time":190,"src":150,"dst":150,"proto":85,"length":70,"flags":65,"finding":300}
    for c in cols:self.pcap_tree.heading(c,text=heads[c]);self.pcap_tree.column(c,width=widths[c],minwidth=45,stretch=c in ("src","dst","finding"))
    self.pcap_tree.pack(fill="both",expand=True)
    self.pcap_tree.bind("<<TreeviewSelect>>",self.show_pcap_packet)
    self.pcap_detail=tk.Text(self.pcap_tab,bg="#ffffff",fg="#243244",font=("DejaVu Sans Mono",9),height=5,wrap="word",relief="flat")
    self.pcap_detail.pack(fill="x",pady=(8,0))
    self.pcap_summary.insert("1.0","Load a PCAP/PCAPNG file to run offline protocol, DNS, talker, and suspicious SYN-sweep heuristics. The source capture is not modified. Large files are capped at 50,000 packets for responsiveness.")
 def load_pcap_lab(self):
    path=filedialog.askopenfilename(title="Load packet capture",filetypes=[("Packet captures","*.pcap *.pcapng *.cap"),("All files","*.*")])
    if not path:return
    self.pcap_file_label.configure(text=f"Loading: {path}")
    self.pcap_analyze_btn.configure(state="disabled");self.pcap_report_btn.configure(state="disabled")
    self.pcap_summary.delete("1.0","end");self.pcap_summary.insert("1.0","Reading capture in background…")
    threading.Thread(target=self._read_pcap_lab,args=(path,),daemon=True).start()
 def _read_pcap_lab(self,path):
    try:
     from scapy.utils import PcapReader
     records=[]; total=0
     with PcapReader(path) as reader:
      for pkt in reader:
       total+=1
       if len(records)<50000:
        try:records.append(decode_packet(pkt))
        except Exception:continue
     self.root.after(0,lambda:self._pcap_loaded(path,records,total,None))
    except Exception as exc:
     self.root.after(0,lambda err=str(exc):self._pcap_loaded(path,[],0,err))
 def _pcap_loaded(self,path,records,total,error):
    if error:
     self.pcap_file_label.configure(text="PCAP load failed")
     self.pcap_summary.delete("1.0","end");self.pcap_summary.insert("1.0",f"Could not read capture:\n{error}")
     self.set_status("PCAP LOAD ERROR",True);return
    self.pcap_lab_path=path;self.pcap_lab_packets=records;self.pcap_lab_report={"source_file":path,"packets_read":total,"packets_analyzed":len(records)}
    self.ioc_matches=[]
    if hasattr(self,"ioc_results"):
     self.ioc_results.delete("1.0","end")
     self.ioc_results.insert("1.0","Capture changed. Run analysis, then correlate against the current indicator library.")
    self.pcap_file_label.configure(text=f"Loaded: {path}  •  {len(records):,} analyzed / {total:,} total packets"+("  •  analysis capped at 50,000" if total>len(records) else ""))
    self.pcap_analyze_btn.configure(state="normal")
    self.pcap_summary.delete("1.0","end");self.pcap_summary.insert("1.0",f"Capture loaded. {len(records):,} packet records decoded. Click Analyze capture to generate a report.")
    self._populate_pcap_rows({});self.set_status(f"PCAP LOADED • {len(records):,} packets")
 def analyze_pcap_lab(self):
    if not self.pcap_lab_packets:return
    recs=self.pcap_lab_packets; counts={};talkers={};domains={};syn_ports={};row_findings={};findings=[]
    def add_finding(sev,title,detail,indices=None):
     finding={"severity":sev,"title":title,"detail":detail,"packet_indices":list(indices or [])};findings.append(finding)
     for ix in finding["packet_indices"]:row_findings.setdefault(ix,[]).append(title)
    for i,r in enumerate(recs):
     proto=r.get("protocol","OTHER");counts[proto]=counts.get(proto,0)+1
     for ip in (r.get("src"),r.get("dst")):
      if not ip or ip=="—":continue
      ent=talkers.setdefault(ip,{"packets":0,"bytes":0});ent["packets"]+=1;ent["bytes"]+=int(r.get("length") or 0)
     if r.get("dns_name"):
      name=r["dns_name"];domains[name]=domains.get(name,0)+1
     flags=r.get("tcp_flags") or ""
     if proto=="TCP" and "S" in flags and "A" not in flags and r.get("src"):
      syn_ports.setdefault(r["src"],{}).setdefault(r.get("dst_port"),[]).append(i)
     if int(r.get("length") or 0)>=1500:row_findings.setdefault(i,[]).append("Large frame (≥1500 bytes)")
    large_frames=[i for i,r in enumerate(recs) if int(r.get("length") or 0)>=1500]
    if large_frames:add_finding("INFO","Large frames observed",f"{len(large_frames)} packet(s) are at least 1500 bytes. This may be normal for jumbo frames or capture/link-layer details.",large_frames)
    for src,ports in syn_ports.items():
     distinct={p for p in ports if p is not None}
     if len(distinct)>=15:
      indices=[ix for seq in ports.values() for ix in seq]
      add_finding("MEDIUM","Possible SYN port sweep",f"{src} sent SYN-only packets to {len(distinct)} distinct destination ports in this capture. This can be legitimate scanning or monitoring; validate context.",indices)
    for name,count in sorted(domains.items(),key=lambda x:-x[1])[:10]:
     pass
    if not findings:add_finding("INFO","No configured heuristic triggered","No SYN sweep heuristic triggered. This is not proof that the capture is benign.",[])
    start=min((r.get("timestamp","") for r in recs if r.get("timestamp")),default="—");end=max((r.get("timestamp","") for r in recs if r.get("timestamp")),default="—")
    prior_correlation=(self.pcap_lab_report or {}).get("threat_intel_correlation")
    capture_sha256="unavailable"
    try:
     h=hashlib.sha256()
     with open(self.pcap_lab_path,"rb") as evidence_file:
      for chunk in iter(lambda:evidence_file.read(1024*1024),b""):h.update(chunk)
     capture_sha256=h.hexdigest()
    except OSError:pass
    report={"generated_at":stamp(),"source_file":self.pcap_lab_path,"source_sha256":capture_sha256,"packets_read":self.pcap_lab_report.get("packets_read",len(recs)),"packets_analyzed":len(recs),"capture_start_utc":start,"capture_end_utc":end,"protocol_counts":counts,"top_talkers":sorted([{"ip":ip,**v} for ip,v in talkers.items()],key=lambda x:-x["bytes"])[:15],"top_dns_names":[{"name":n,"observations":c} for n,c in sorted(domains.items(),key=lambda x:-x[1])[:20]],"findings":findings,"mitre_attack_context":[{"technique":"T1046","name":"Network Service Discovery","tactic":"Discovery","reason":"Possible SYN port sweep heuristic triggered; validate against packet evidence."} for f in findings if "SYN port sweep" in f.get("title","")],"limitations":["Offline heuristics are not proof of malicious activity.","Packet visibility depends on the original capture point.","HTTPS application payloads remain encrypted.","At most 50,000 packets are analyzed per file."]}
    if prior_correlation:
     report["threat_intel_correlation"]=prior_correlation
    self.pcap_lab_report=report;self._populate_pcap_rows(row_findings)
    lines=["CocoScanner — PCAP INVESTIGATION REPORT","="*62,f"Source: {self.pcap_lab_path}",f"Generated: {report['generated_at']}",f"Packets analyzed: {len(recs):,}",f"Capture time range: {start} → {end}","","PROTOCOL DISTRIBUTION"]
    for proto,count in sorted(counts.items(),key=lambda x:-x[1]):lines.append(f"  {proto:<12} {count:>8,} ({100*count/max(1,len(recs)):.1f}%)")
    lines += ["","TOP TALKERS (source + destination appearances)"]
    for t in report["top_talkers"]:lines.append(f"  {t['ip']:<40} packets={t['packets']} bytes={t['bytes']}")
    lines += ["","TOP DNS NAMES"]
    for d in report["top_dns_names"]:lines.append(f"  {d['name']} ({d['observations']} observations)")
    lines += ["","FINDINGS"]
    for f in findings:lines.append(f"  [{f['severity']}] {f['title']}: {f['detail']} (packet rows: {', '.join(map(str,f['packet_indices'][:30])) or 'none'})")
    lines += ["","LIMITATIONS"]+["  • "+x for x in report["limitations"]]
    self.pcap_summary.delete("1.0","end");self.pcap_summary.insert("1.0","\n".join(lines))
    self.pcap_report_btn.configure(state="normal");self.set_status(f"PCAP ANALYSIS COMPLETE • {len(findings)} finding(s)")
 def _populate_pcap_rows(self,row_findings):
    for item in self.pcap_tree.get_children():self.pcap_tree.delete(item)
    for i,r in enumerate(self.pcap_lab_packets[:3000]):
     src=f"{r.get('src','—')}:{r.get('src_port') or '—'}";dst=f"{r.get('dst','—')}:{r.get('dst_port') or '—'}"
     note="; ".join(row_findings.get(i,[]))
     self.pcap_tree.insert("","end",iid=str(i),values=(i+1,r.get("timestamp",""),src,dst,r.get("protocol",""),r.get("length",0),r.get("tcp_flags") or "—",note))
 def show_pcap_packet(self,_=None):
    sel=self.pcap_tree.selection()
    if not sel:return
    try:i=int(sel[0]);r=self.pcap_lab_packets[i]
    except (ValueError,IndexError):return
    self.pcap_detail.delete("1.0","end")
    self.pcap_detail.insert("1.0",f"Packet row: {i+1}\nTime: {r.get('timestamp')}\n{r.get('protocol')} {r.get('src')}:{r.get('src_port') or '—'} → {r.get('dst')}:{r.get('dst_port') or '—'}\nLength: {r.get('length')} bytes | TCP flags: {r.get('tcp_flags') or '—'} | DNS: {r.get('dns_name') or '—'}\nSummary: {r.get('summary','')}\nPayload preview: {r.get('payload_ascii') or '(none)'}")
 def export_pcap_report(self):
    if not self.pcap_lab_report or not self.pcap_lab_report.get("findings"):
     messagebox.showinfo("Analyze first","Load and analyze a capture before exporting a report.");return
    path=filedialog.asksaveasfilename(title="Export investigation report",defaultextension=".html",filetypes=[("HTML report","*.html"),("JSON report","*.json")],initialfile="CocoScanner-investigation-report.html")
    if not path:return
    try:
     import html
     target=Path(path)
     if target.suffix.lower()==".json":target.write_text(json.dumps(self.pcap_lab_report,indent=2),encoding="utf-8")
     else:
      r=self.pcap_lab_report
      protocols="".join(f"<tr><td>{html.escape(str(k))}</td><td>{v:,}</td></tr>" for k,v in sorted(r.get("protocol_counts",{}).items(),key=lambda x:-x[1]))
      talkers="".join(f"<tr><td>{html.escape(t['ip'])}</td><td>{t['packets']}</td><td>{t['bytes']:,}</td></tr>" for t in r.get("top_talkers",[]))
      dns="".join(f"<tr><td>{html.escape(d['name'])}</td><td>{d['observations']}</td></tr>" for d in r.get("top_dns_names",[]))
      finds="".join(f"<article><h3>[{html.escape(f['severity'])}] {html.escape(f['title'])}</h3><p>{html.escape(f['detail'])}</p><small>Packet rows: {html.escape(', '.join(map(str,f.get('packet_indices',[])[:100])) or 'none')}</small></article>" for f in r.get("findings",[]))
      limitations="".join(f"<li>{html.escape(x)}</li>" for x in r.get("limitations",[]))
      corr=r.get("threat_intel_correlation",{})
      corr_rows="".join(f"<tr><td>{html.escape(str(m.get('indicator','')))}</td><td>{html.escape(str(m.get('indicator_type','')))}</td><td>{int(m.get('packet_index',0))+1}</td><td>{html.escape(str(m.get('source','')))}</td><td>{html.escape(str(m.get('confidence','')))}</td></tr>" for m in corr.get("matches",[])[:1000])
      attack_rows="".join(f"<li><b>{html.escape(str(a.get('technique','')))} — {html.escape(str(a.get('name','')))}</b> ({html.escape(str(a.get('tactic','')))}): {html.escape(str(a.get('reason','')))}</li>" for a in corr.get("mitre_attack_context",[]))
      corr_section=(f"<section><h2>Threat intelligence correlation</h2><p>Local indicators: {corr.get('indicator_count',0)}; matches: {corr.get('match_count',0)}</p><table><tr><th>Indicator</th><th>Type</th><th>Packet row</th><th>Source</th><th>Confidence</th></tr>{corr_rows}</table><h3>ATT&CK context (hypotheses)</h3><ul>{attack_rows}</ul><p><small>{html.escape(str(corr.get('note','No IOC correlation performed.')))}</small></p></section>" if corr else "")
      doc=f'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>CocoScanner Investigation Report</title><style>body{{font:16px system-ui;max-width:1050px;margin:36px auto;padding:0 18px;background:#0b1220;color:#243244}}h1,h2{{color:#0f766e}}section,article{{background:#121d2d;padding:16px;border-radius:10px;margin:12px 0}}table{{border-collapse:collapse;width:100%}}td,th{{padding:8px;border-bottom:1px solid #334155;text-align:left}}small{{color:#64748b}}</style><h1>CocoScanner — PCAP Investigation Report</h1><p>Generated: {html.escape(r.get('generated_at',''))}</p><section><h2>Capture</h2><p>Source: {html.escape(r.get('source_file',''))}</p><p>Packets analyzed: {r.get('packets_analyzed',0):,} / {r.get('packets_read',0):,}</p><p>UTC range: {html.escape(r.get('capture_start_utc',''))} → {html.escape(r.get('capture_end_utc',''))}</p></section><section><h2>Protocol distribution</h2><table><tr><th>Protocol</th><th>Packets</th></tr>{protocols}</table></section><section><h2>Top talkers</h2><table><tr><th>IP</th><th>Appearances</th><th>Observed bytes</th></tr>{talkers}</table></section><section><h2>Top DNS names</h2><table><tr><th>Name</th><th>Observations</th></tr>{dns}</table></section><section><h2>Findings</h2>{finds}</section>{corr_section}<section><h2>Limitations</h2><ul>{limitations}</ul><p><small>Heuristics support investigation; they do not establish malicious intent. HTTPS application payloads remain encrypted.</small></p></section></html>'''
      target.write_text(doc,encoding="utf-8")
     messagebox.showinfo("Report exported",f"Saved investigation report to:\n{target}")
    except Exception as exc:messagebox.showerror("Report export failed",str(exc))

 def start_capture(self):
    if self.capturing:
     return
    iface=self.iface.get().strip()
    if not iface:
     messagebox.showerror("Interface required","Choose an interface shown by `ip -br addr`.")
     return
    try:
     from scapy.all import sniff, get_if_list
    except ImportError:
     messagebox.showerror("Scapy missing","Run ./setup.sh first.")
     return
    try:
     available=get_if_list()
    except Exception as exc:
     messagebox.showerror("Interface check failed",str(exc))
     return
    if iface not in available:
     messagebox.showerror("Unknown interface",f"'{iface}' was not found by Scapy. Available interfaces:\\n"+", ".join(available))
     self.set_status("ERROR  •  invalid interface",True)
     return
    self.stop=threading.Event()
    self.capture_error=None
    self.capture_count=0
    self.capture_started=time.time()
    self.capturing=True
    self.start_btn.configure(state="disabled")
    self.stop_btn.configure(state="normal")
    self.set_status("STARTING CAPTURE  •  "+iface)
    self.capture_worker_thread=threading.Thread(target=self.capture_worker,args=(iface,self.stop),daemon=True)
    self.capture_worker_thread.start()
 def capture_worker(self,iface,stop):
    try:
     from scapy.all import sniff
     def handle(pkt):
      if stop.is_set():
       return
      try:
       record=decode_packet(pkt)
       try:
        self.q.put_nowait(("packet",(record,pkt)))
       except queue.Full:
        # Avoid blocking packet capture if the UI queue is temporarily saturated.
        pass
      except Exception as exc:
       try:self.q.put_nowait(("error",f"Packet decode failed: {exc}"))
       except queue.Full:pass
     while not stop.is_set():
      sniff(iface=iface,prn=handle,store=False,timeout=0.75)
    except Exception as exc:
     self.capture_error=str(exc)
     try:self.q.put_nowait(("error",str(exc)))
     except queue.Full:pass
    finally:
     try:self.q.put_nowait(("stopped",None))
     except queue.Full:pass
 def stop_capture(self):
    if not self.capturing:
     return
    self.stop.set()
    self.stop_btn.configure(state="disabled")
    self.set_status("STOP REQUESTED")
 def scan(self):
    try:net=safe_net(self.subnet.get())
    except Exception as e:messagebox.showerror("Invalid subnet",str(e));return
    if not shutil.which("nmap"):messagebox.showerror("Nmap missing","Run ./setup.sh first.");return
    self.set_status("SCANNING  •  "+net)
    threading.Thread(target=self.scan_worker,args=(net,),daemon=True).start()
 def scan_worker(self,net):
    try:
     p=subprocess.run(["nmap","-sn","-T3","--max-retries","1",net],capture_output=True,text=True,timeout=120)
     if p.returncode not in (0,1):raise RuntimeError(p.stderr[-800:] or "Nmap scan failed")
     found=[];cur=None
     for line in p.stdout.splitlines():
      line=line.strip()
      if line.startswith("Nmap scan report for "):
       if cur:found.append(cur)
       label=line[len("Nmap scan report for "):];ip=label.rsplit("(",1)[-1].rstrip(")") if "(" in label and label.endswith(")") else label
       host=label[:label.rfind(" (")] if " (" in label else ""
       cur={"ip":ip,"hostname":host,"mac":"","vendor":"","last_seen":stamp()}
      elif cur and line.startswith("MAC Address: "):
       bits=line[len("MAC Address: "):].split(" ",1);cur["mac"]=bits[0];cur["vendor"]=bits[1].strip("()") if len(bits)>1 else ""
     if cur:found.append(cur)
     old={d.get("ip"):d for d in load(DEVICES,[]) if isinstance(d,dict)}
     history=load(DATA / "device_history.json",[])
     previous={e.get("ip") for e in history if isinstance(e,dict)}
     now=stamp()
     for d in found:
      d["first_seen"]=old.get(d["ip"],{}).get("first_seen",d["last_seen"])
      d["new_device"]=d["ip"] not in previous
      history.append({"ip":d["ip"],"hostname":d.get("hostname",""),"mac":d.get("mac",""),"event":"seen","timestamp":now,"new_device":d["new_device"]})
     history=history[-5000:]
     save(DATA / "device_history.json",history)
     save(DEVICES,found)
     self.q.put(("devices",found));self.q.put(("message",f"Discovery complete: {len(found)} device(s)"))
    except Exception as e:self.q.put(("error","Scan failed: "+str(e)))
 def drain(self):
    dirty=False
    try:
     while True:
      kind,val=self.q.get_nowait()
      if kind=="packet":
       rec,rawpkt=val
       self.packets.append(rec)
       self.session_raw_packets.append(rawpkt)
       self.capture_count+=1
       if len(self.session_raw_packets)>MAX_PACKETS:self.session_raw_packets=self.session_raw_packets[-MAX_PACKETS:]
       if len(self.packets)>MAX_PACKETS:self.packets=self.packets[-MAX_PACKETS:]
       self.process_flow(rec)
       self.process_dns(rec)
       self.process_http(rec)
       self.process_stream(rec,rawpkt)
       self.process_alerts(rec)
       dirty=True
      elif kind=="devices":
       self.devices=val;self.refresh_devices()
      elif kind=="message":
       self.set_status(val)
      elif kind=="error":
       self.capture_error=str(val)
       self.set_status("ERROR  •  "+str(val)[:150],True)
      elif kind=="stopped":
       self.capturing=False
       self.start_btn.configure(state="normal")
       self.stop_btn.configure(state="normal")
       if self.capture_error:
        self.set_status("ERROR  •  "+self.capture_error[:150],True)
       else:
        self.set_status(f"CAPTURE STOPPED  •  {self.capture_count} packets")
    except queue.Empty:
     pass
    if dirty:
     try:
      save(PACKETS,self.packets)
     except Exception as exc:
      self.set_status("STORAGE ERROR  •  "+str(exc)[:130],True)
     self.refresh_packets();self.refresh_stats();self.refresh_flows();self.refresh_http();self.refresh_alerts();self.refresh_streams();self.refresh_dns()
    self.root.after(120,self.drain)

 def process_flow(self,rec):
    if rec.get("protocol") not in ("TCP","TCP6"): return
    src=f'{rec.get("src")}:{rec.get("src_port")}'; dst=f'{rec.get("dst")}:{rec.get("dst_port")}'
    key=tuple(sorted((src,dst)))
    item=self.flow_state.setdefault(key,{"src":src,"dst":dst,"packets":0,"bytes":0,"flags":set(),"last":rec.get("timestamp")})
    item["packets"]+=1;item["bytes"]+=int(rec.get("length") or 0);item["last"]=rec.get("timestamp")
    if rec.get("tcp_flags"):item["flags"].add(rec["tcp_flags"])

 def process_dns(self,rec):
    if not rec.get("dns"):return
    event={"timestamp":rec.get("timestamp",""),"src":f'{rec.get("src","")}:{rec.get("src_port") or ""}',
           "dst":f'{rec.get("dst","")}:{rec.get("dst_port") or ""}',
           "type":rec.get("dns_qr") or "DNS","name":rec.get("dns_name") or "",
           "summary":rec.get("dns","")}
    sig=(event["timestamp"],event["src"],event["dst"],event["summary"])
    if any((e["timestamp"],e["src"],e["dst"],e["summary"])==sig for e in self.dns_events[-100:]):return
    self.dns_events.append(event);self.dns_events=self.dns_events[-2000:]
 def refresh_dns(self):
    if not hasattr(self,"dns_tree"):return
    for i in self.dns_tree.get_children():self.dns_tree.delete(i)
    for e in reversed(self.dns_events):
     self.dns_tree.insert("","end",values=(e["timestamp"],e["src"],e["dst"],e["type"],e["name"],e["summary"]))
 def export_dns(self):
    path=filedialog.asksaveasfilename(title="Export DNS history",defaultextension=".json",filetypes=[("JSON files","*.json")],initialfile="CocoScanner-dns-history.json")
    if not path:return
    try:
     Path(path).write_text(json.dumps(self.dns_events,indent=2),encoding="utf-8")
     messagebox.showinfo("Export complete",f"Exported {len(self.dns_events)} DNS events.")
    except Exception as exc:messagebox.showerror("Export failed",str(exc))

 def refresh_flows(self):
    if not hasattr(self,"flow_tree"):return
    for i in self.flow_tree.get_children():self.flow_tree.delete(i)
    for item in sorted(self.flow_state.values(),key=lambda x:x["last"],reverse=True):
     self.flow_tree.insert("","end",values=(item["src"],item["dst"],item["packets"],item["bytes"],",".join(sorted(item["flags"])),item["last"]))
 def process_http(self,rec):
    # Inspect only clear-text HTTP-like data in the captured preview. No TLS decryption.
    payload=rec.get("payload_ascii","")
    if not payload:return
    first=payload.splitlines()[0].strip() if payload.splitlines() else ""
    is_request=bool(re.match(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|CONNECT)\s+\S+\s+HTTP/1\.[01]$",first))
    is_response=bool(re.match(r"^HTTP/1\.[01]\s+\d{3}\b",first))
    if not (is_request or is_response):return
    kind="REQUEST" if is_request else "RESPONSE"
    # Deduplicate retransmissions / repeated payload snippets.
    sig=(rec.get("timestamp"),rec.get("src"),rec.get("dst"),first)
    if any(e.get("_sig")==str(sig) for e in self.http_events[-100:]):return
    self.http_events.append({"timestamp":rec.get("timestamp"),"src":f'{rec.get("src")}:{rec.get("src_port")}',"dst":f'{rec.get("dst")}:{rec.get("dst_port")}',"kind":kind,"line":first,"preview":payload,"_sig":str(sig)})
    self.http_events=self.http_events[-500:]
 def refresh_http(self):
    if not hasattr(self,"http_tree"):return
    for i in self.http_tree.get_children():self.http_tree.delete(i)
    for e in reversed(self.http_events):
     self.http_tree.insert("","end",values=(e["timestamp"],e["src"],e["dst"],e["kind"],e["line"]))
 def show_http_detail(self,_=None):
    sel=self.http_tree.selection()
    if not sel:return
    vals=self.http_tree.item(sel[0],"values")
    event=next((e for e in reversed(self.http_events) if e["timestamp"]==vals[0] and e["src"]==vals[1] and e["line"]==vals[4]),None)
    if event:
     self.http_detail.delete("1.0","end")
     self.http_detail.insert("1.0",f'{event["kind"]} PREVIEW\\n{event["src"]} → {event["dst"]}\\n\\n{event["preview"]}\\n\\nLimited to captured payload preview; TCP segments may be incomplete. HTTPS cannot be inspected passively.')

 def process_stream(self,rec,rawpkt):
    if rec.get("protocol") not in ("TCP","TCP6"):return
    try:
     from scapy.all import TCP, IP, IPv6
     if TCP not in rawpkt:return
     tcp=rawpkt[TCP]; payload=bytes(tcp.payload)
     if not payload:return
     src=rec.get("src");dst=rec.get("dst");sport=int(tcp.sport);dport=int(tcp.dport)
     key=f"{src}:{sport} ↔ {dst}:{dport}"
     stream=self.tcp_streams.setdefault(key,{"key":key,"segments":0,"bytes":0,"last":rec.get("timestamp"),"chunks":[],"data":b"","status":"Collecting"})
     stream["segments"]+=1;stream["bytes"]+=len(payload);stream["last"]=rec.get("timestamp")
     stream["chunks"].append((int(tcp.seq),payload))
     # Bound per-stream memory. Sort by sequence and append unseen contiguous bytes best-effort.
     stream["chunks"]=stream["chunks"][-300:]
     chunks=sorted(stream["chunks"],key=lambda x:x[0])
     assembled=bytearray();next_seq=None
     for seq,data in chunks:
      if next_seq is None:
       assembled.extend(data);next_seq=seq+len(data)
      elif seq+len(data)<=next_seq:
       continue
      elif seq<=next_seq:
       assembled.extend(data[next_seq-seq:]);next_seq=seq+len(data)
      else:
       # Gap detected; preserve marker and continue with observed segment.
       assembled.extend(b"\n[... TCP sequence gap ...]\n");assembled.extend(data);next_seq=seq+len(data)
     stream["data"]=bytes(assembled[-65536:])
     stream["status"]="Gap / partial" if b"TCP sequence gap" in stream["data"] else "Best-effort"
     text=stream["data"].decode("utf-8","replace")
     if re.search(r"(?m)^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|HTTP/1\.[01])\s",text):
      stream["status"]="HTTP-like data"
     self.stream_rows=list(self.tcp_streams.values())[-300:]
    except Exception:
     return
 def refresh_streams(self):
    if not hasattr(self,"stream_tree"):return
    for i in self.stream_tree.get_children():self.stream_tree.delete(i)
    for idx,item in enumerate(sorted(self.tcp_streams.values(),key=lambda x:x["last"],reverse=True)):
     self.stream_tree.insert("","end",iid=f"s{idx}",values=(item["key"],item["segments"],item["bytes"],item["last"],item["status"]))
 def show_stream(self,_=None):
    sel=self.stream_tree.selection()
    if not sel:return
    vals=self.stream_tree.item(sel[0],"values")
    key=vals[0]
    item=self.tcp_streams.get(key)
    if not item:return
    raw=item["data"]
    preview=raw.decode("utf-8","replace")
    if not preview.strip():preview="(No printable application data reconstructed for this conversation.)"
    self.stream_text.delete("1.0","end")
    self.stream_text.insert("1.0",f'Conversation: {key}\nSegments: {item["segments"]}  Payload bytes: {item["bytes"]}\nStatus: {item["status"]}\n\nRECONSTRUCTED PREVIEW (bounded to 64 KiB)\n{"-"*60}\n{preview}\n\nThis is best-effort reconstruction from packets visible to this interface; it may contain gaps or duplicate data. HTTPS/TLS application content remains encrypted.')

 def persist_alerts(self):
    try: save(DATA / "alerts.json",self.alert_events)
    except Exception as exc:self.set_status("ALERT STORAGE ERROR • "+str(exc)[:120],True)
 def alert_id(self,event):
    import hashlib
    base=f'{event.get("timestamp","")}|{event.get("rule","")}|{event.get("src","")}|{event.get("detail","")}'
    return hashlib.sha256(base.encode("utf-8","replace")).hexdigest()[:16]
 def add_alert(self,severity,rule,detail,src="",packet=None):
    event={"id":"","timestamp":stamp(),"severity":severity,"rule":rule,"detail":detail,"src":src,
           "status":"new","notes":"","evidence":packet or {},"_epoch":time.time()}
    event["id"]=self.alert_id(event)
    if any(a.get("id")==event["id"] for a in self.alert_events if isinstance(a,dict)):return
    self.alert_events.append(event);self.alert_events=self.alert_events[-2000:]
    self.persist_alerts()
 def set_alert_status(self,status):
    sel=self.alert_tree.selection()
    if not sel:messagebox.showinfo("Select an alert","Select an alert row first.");return
    event=next((a for a in self.alert_events if a.get("id")==sel[0]),None)
    if not event:return
    event["status"]=status;event["updated_at"]=stamp();self.persist_alerts();self.refresh_alerts()
    self.set_status(f"Alert {status}: {event.get('rule','')}")
 def add_alert_note(self):
    sel=self.alert_tree.selection()
    if not sel:messagebox.showinfo("Select an alert","Select an alert row first.");return
    event=next((a for a in self.alert_events if a.get("id")==sel[0]),None)
    if not event:return
    win=tk.Toplevel(self.root);win.title("Analyst note");win.geometry("560x300");win.configure(bg=BG)
    ttk.Label(win,text=f'{event.get("rule","Alert")} — analyst note').pack(anchor="w",padx=12,pady=10)
    box=tk.Text(win,bg="#ffffff",fg=TEXT,insertbackground=TEXT,wrap="word");box.pack(fill="both",expand=True,padx=12,pady=5)
    box.insert("1.0",event.get("notes",""))
    def save_note():
     event["notes"]=box.get("1.0","end").strip();event["updated_at"]=stamp();self.persist_alerts();self.show_alert_detail();win.destroy()
    ttk.Button(win,text="Save note",command=save_note).pack(anchor="e",padx=12,pady=10)
 def show_alert_detail(self,_=None):
    if not hasattr(self,"alert_detail"):return
    sel=self.alert_tree.selection()
    if not sel:return
    event=next((a for a in self.alert_events if a.get("id")==sel[0]),None)
    if not event:return
    self.alert_detail.delete("1.0","end")
    self.alert_detail.insert("1.0",f'Rule: {event.get("rule")}\\nSeverity: {event.get("severity")}\\nStatus: {event.get("status","new")}\\nTimestamp: {event.get("timestamp")}\\nSource: {event.get("src","—")}\\n\\nEvidence: {event.get("detail","")}\\n\\nAnalyst notes:\\n{event.get("notes","(none)")}')
 def export_alerts(self):
    path=filedialog.asksaveasfilename(title="Export alert history",defaultextension=".json",filetypes=[("JSON files","*.json")],initialfile="CocoScanner-alerts.json")
    if not path:return
    try:
     Path(path).write_text(json.dumps(self.alert_events,indent=2),encoding="utf-8")
     messagebox.showinfo("Export complete",f"Exported {len(self.alert_events)} alerts.")
    except Exception as exc:messagebox.showerror("Export failed",str(exc))

 def process_alerts(self,rec):
    rules=load(DATA / "rules.json",None)
    if not isinstance(rules,list):
     rules=[
      {"id":"NET-001","name":"Possible port sweep","enabled":True,"severity":"MEDIUM","threshold":20,"window_seconds":60},
      {"id":"NET-002","name":"DNS query observed","enabled":True,"severity":"INFO","threshold":1,"window_seconds":60}
     ]
     try:save(DATA / "rules.json",rules)
     except Exception:pass
    enabled={r.get("name"):r for r in rules if isinstance(r,dict) and r.get("enabled",True)}
    if rec.get("protocol")=="TCP" and "S" in (rec.get("tcp_flags") or "") and "A" not in (rec.get("tcp_flags") or ""):
     now=time.time();src=rec.get("src")
     recent=[p for p in self.packets[-500:] if p.get("src")==src and p.get("protocol")=="TCP" and "S" in (p.get("tcp_flags") or "") and "A" not in (p.get("tcp_flags") or "")]
     ports={p.get("dst_port") for p in recent}
     rule=enabled.get("Possible port sweep",{})
     try:threshold=max(2,min(4096,int(rule.get("threshold",20))))
     except (TypeError,ValueError):threshold=20
     try:window_seconds=max(1,min(86400,int(rule.get("window_seconds",60))))
     except (TypeError,ValueError):window_seconds=60
     if rule and len(ports)>=threshold and not any(a.get("rule")=="Possible port sweep" and a.get("src")==src and now-a.get("_epoch",0)<window_seconds for a in self.alert_events if isinstance(a,dict)):
      self.add_alert(rule.get("severity","MEDIUM"),"Possible port sweep",f"{src} sent SYN packets to {len(ports)} distinct destination ports in recent captured traffic (threshold {threshold})",src,{"src":src,"dst":rec.get("dst"),"dst_port":rec.get("dst_port"),"tcp_flags":rec.get("tcp_flags")})
    rule=enabled.get("DNS query observed",{})
    if rule and rec.get("dns") and rec.get("dns_qr")=="query":
     self.add_alert(rule.get("severity","INFO"),"DNS query observed",f'{rec.get("src")} queried {rec.get("dns_name") or "(name unavailable)"}',rec.get("src",""),{"src":rec.get("src"),"dst":rec.get("dst"),"dns_name":rec.get("dns_name"),"dns_type":rec.get("dns_type")})

 def refresh_alerts(self):
    if not hasattr(self,"alert_tree"):return
    for i in self.alert_tree.get_children():self.alert_tree.delete(i)
    for a in reversed(self.alert_events):
     if not isinstance(a,dict):continue
     aid=a.get("id") or self.alert_id(a);a["id"]=aid
     self.alert_tree.insert("","end",iid=aid,values=(a.get("timestamp",""),a.get("severity","INFO"),a.get("rule",""),a.get("status","new"),a.get("src",""),a.get("detail","")))

 def refresh_all(self):self.refresh_packets();self.refresh_devices();self.refresh_stats();self.refresh_flows();self.refresh_http();self.refresh_alerts();self.refresh_streams();self.refresh_dns()
 def packet_matches_filter(self,rec,query):
    """Small safe display-filter parser; terms are ANDed, no eval/exec."""
    if not query.strip(): return True
    q=query.strip().lower()
    # Preserve free-text search when query isn't in the supported filter grammar.
    terms=re.split(r"\s+and\s+|\s+",q)
    text=" ".join(str(rec.get(k,"")) for k in ("timestamp","src","dst","protocol","src_port","dst_port","summary","tcp_flags","dns")).lower()
    recognized=True
    for term in terms:
     if not term: continue
     if term in ("tcp","udp","icmp","arp","dns","ipv4","ipv6"):
      if term=="dns":
       if not rec.get("dns"):return False
      elif term not in str(rec.get("protocol","")).lower():return False
     elif term.startswith("host="):
      ip=term.split("=",1)[1]
      if ip not in (str(rec.get("src","")).lower(),str(rec.get("dst","")).lower()):return False
     elif term.startswith("src="):
      if str(rec.get("src","")).lower()!=term.split("=",1)[1]:return False
     elif term.startswith("dst="):
      if str(rec.get("dst","")).lower()!=term.split("=",1)[1]:return False
     elif term.startswith("port="):
      try:port=int(term.split("=",1)[1])
      except ValueError:return False
      if port not in (rec.get("src_port"),rec.get("dst_port")):return False
     elif term.startswith("srcport="):
      try:port=int(term.split("=",1)[1])
      except ValueError:return False
      if rec.get("src_port")!=port:return False
     elif term.startswith("dstport="):
      try:port=int(term.split("=",1)[1])
      except ValueError:return False
      if rec.get("dst_port")!=port:return False
     elif term.startswith("len>"):
      try:n=int(term[4:])
      except ValueError:return False
      if int(rec.get("length") or 0)<=n:return False
     elif term.startswith("len<"):
      try:n=int(term[4:])
      except ValueError:return False
      if int(rec.get("length") or 0)>=n:return False
     elif term.startswith("flags="):
      if term.split("=",1)[1].upper() not in str(rec.get("tcp_flags","")).upper():return False
     else:
      recognized=False
      break
    if recognized:return True
    return q in text
 def refresh_packets(self):
    if not hasattr(self,"tree"):return
    query=self.filter.get().strip()
    for i in self.tree.get_children():self.tree.delete(i)
    self.visible=[]
    # Stable row IDs prevent selecting the wrong record when packets share timestamps.
    start=max(0,len(self.packets)-MAX_PACKETS)
    for idx in range(len(self.packets)-1,start-1,-1):
     rec=self.packets[idx]
     if not self.packet_matches_filter(rec,query):continue
     self.visible.append(rec)
     src=f'{rec.get("src","—")}:{rec.get("src_port") or "—"}';dst=f'{rec.get("dst","—")}:{rec.get("dst_port") or "—"}'
     self.tree.insert("","end",iid=f"packet-{idx}",values=(rec.get("timestamp",""),src,dst,rec.get("protocol",""),rec.get("length",""),rec.get("tcp_flags") or "—",rec.get("summary","")))
    self.refresh_stats()
 def show_details(self,_=None):
    sel=self.tree.selection()
    if not sel:return
    iid=self.tree.item(sel[0],"iid")
    try:idx=int(iid.split("-",1)[1]);rec=self.packets[idx]
    except (ValueError,IndexError,AttributeError):return
    lines=[f'Timestamp: {rec.get("timestamp")}',f'Protocol: {rec.get("protocol")}    Length: {rec.get("length")} bytes',
      f'Source: {rec.get("src")}:{rec.get("src_port") or "—"}',f'Destination: {rec.get("dst")}:{rec.get("dst_port") or "—"}',
      f'Source MAC: {rec.get("src_mac") or "—"}',f'Destination MAC: {rec.get("dst_mac") or "—"}',
      f'TTL / hop limit: {rec.get("ttl") or "—"}    IPv4 ID: {rec.get("ip_id") or "—"}    TCP flags: {rec.get("tcp_flags") or "—"}',
      f'TCP sequence: {rec.get("tcp_seq") if rec.get("tcp_seq") is not None else "—"}    ACK: {rec.get("tcp_ack") if rec.get("tcp_ack") is not None else "—"}    Window: {rec.get("tcp_window") if rec.get("tcp_window") is not None else "—"}    TCP payload: {rec.get("tcp_payload_len",0)} bytes', 
      f'DNS: {rec.get("dns") or "—"}',f'Summary: {rec.get("summary","")}',"","DECODED PROTOCOL LAYERS"]
    for layer in rec.get("layers",[]):
     lines.append(f'[{layer["name"]}]')
     for k,v in layer.get("fields",{}).items():lines.append(f"  {k}: {v}")
    self.fields.delete("1.0","end");self.fields.insert("1.0","\n".join(lines))
    self.payload.delete("1.0","end");self.payload.insert("1.0","HEX PREVIEW (up to 256 bytes)\n"+(rec.get("payload_hex") or "(no raw payload)")+"\n\nASCII PREVIEW\n"+(rec.get("payload_ascii") or "(empty)")+"\n\nHTTPS payloads remain encrypted; this is not HTTP stream reconstruction.")
 def refresh_devices(self):
    if not hasattr(self,"dev_tree"):return
    for i in self.dev_tree.get_children():self.dev_tree.delete(i)
    for d in self.devices:
     self.dev_tree.insert("","end",values=(d.get("ip",""),d.get("hostname") or "—",d.get("mac") or "—",d.get("vendor") or "—",d.get("first_seen",""),d.get("last_seen",""),"NEW" if d.get("new_device") else "UP"))
 def refresh_stats(self):
    if not hasattr(self,"stats_text"):return
    counts={}
    talkers={}
    bytes_total=0
    for p in self.packets:
     proto=p.get("protocol","OTHER");counts[proto]=counts.get(proto,0)+1
     size=int(p.get("length") or 0);bytes_total+=size
     for endpoint in (p.get("src"),p.get("dst")):
      if endpoint and endpoint!="—":
       talkers[endpoint]=talkers.get(endpoint,{"packets":0,"bytes":0})
       talkers[endpoint]["packets"]+=1;talkers[endpoint]["bytes"]+=size
    total=len(self.packets)
    now=time.time()
    if now-self.last_rate_update>=1:
     delta=max(1,now-self.last_rate_update)
     pps=max(0,total-self.last_packet_total)/delta
     self.rate_samples.append({"time":stamp(),"pps":round(pps,2),"bps":round((bytes_total-getattr(self,"_last_total_bytes",0))*8/delta,2)})
     self.rate_samples=self.rate_samples[-120:]
     self.last_rate_update=now;self.last_packet_total=total;self._last_total_bytes=bytes_total
    latest=self.rate_samples[-1] if self.rate_samples else {"pps":0,"bps":0}
    lines=[f"Captured packet records: {total}",f"Devices in latest inventory: {len(self.devices)}",
           f"Observed bytes (packet lengths): {bytes_total:,}",f"Approx. capture rate: {latest['pps']:.1f} packets/sec",
           f"Approx. observed bit rate: {latest['bps']:.0f} bit/sec",
           f"TCP conversations: {len(self.flow_state)}",f"DNS events this session: {len(self.dns_events)}",
           f"Security alerts this session: {len(self.alert_events)}","",
           "PROTOCOL DISTRIBUTION","-"*54,"Protocol                 Packets       Share"]
    for proto,count in sorted(counts.items(),key=lambda x:-x[1]):
     pct=100*count/total if total else 0;bar="█"*min(30,round(pct/3.34))
     lines.append(f"{proto:<20} {count:>7}       {pct:5.1f}%  {bar}")
    lines += ["","TOP TALKERS (endpoint appearances; source and destination both counted)","-"*70]
    for ip,item in sorted(talkers.items(),key=lambda x:-x[1]["bytes"])[:10]:
     lines.append(f"{ip:<38} packets {item['packets']:>7}   observed bytes {item['bytes']:>12,}")
    lines += ["","Rate estimates use packets processed by the UI, not a hardware-accurate interface counter.",
              "Visibility depends on interface/network configuration. HTTPS payloads are not decrypted."]
    self.stats_text.delete("1.0","end");self.stats_text.insert("1.0","\n".join(lines))
 def clear_session(self):
    if self.capturing:
     messagebox.showwarning("Capture active", "Stop live capture before clearing packet history.")
     return
    if not messagebox.askyesno("Clear packet history", "Delete saved packet history and reset in-memory flow/stream/DNS views? Existing alerts and device inventory will be retained."):
     return
    self.packets=[]
    self.session_raw_packets=[]
    self.flow_state={}
    self.flow_first_seen={}
    self.http_events=[]
    self.tcp_streams={}
    self.stream_rows=[]
    self.dns_events=[]
    self.rate_samples=[]
    self.last_packet_total=0
    self._last_total_bytes=0
    self.last_rate_update=time.time()
    try:
     save(PACKETS, [])
    except Exception as exc:
     messagebox.showerror("Storage error", f"Could not clear packet history:\n{exc}")
     self.set_status("STORAGE ERROR", True)
     return
    self.refresh_packets()
    self.refresh_stats()
    self.refresh_flows()
    self.refresh_http()
    self.refresh_alerts()
    self.refresh_streams()
    self.refresh_dns()
    self.fields.delete("1.0", "end")
    self.payload.delete("1.0", "end")
    self.set_status("PACKET HISTORY CLEARED • ALERTS AND DEVICES RETAINED")

 def export_pcap(self):
    if not self.session_raw_packets:
     messagebox.showinfo("No packets","Capture packets in this session before exporting a PCAP.")
     return
    path=filedialog.asksaveasfilename(title="Export captured packets",defaultextension=".pcap",filetypes=[("PCAP files","*.pcap")],initialfile="CocoScanner-capture.pcap")
    if not path:return
    try:
     from scapy.utils import wrpcap
     wrpcap(path,self.session_raw_packets)
     messagebox.showinfo("PCAP export complete",f"Saved {len(self.session_raw_packets)} packets. Open the file in Wireshark for deeper analysis.")
    except Exception as e:messagebox.showerror("PCAP export failed",str(e))

 def export(self):
    path=filedialog.asksaveasfilename(title="Export packet records",defaultextension=".json",filetypes=[("JSON","*.json")],initialfile="CocoScanner-packets.json")
    if path:
     try:save(Path(path),self.packets);messagebox.showinfo("Export complete",f"Exported {len(self.packets)} records.")
     except Exception as e:messagebox.showerror("Export failed",str(e))
 def close(self):
    try:
     if self.capturing:self.stop.set()
    finally:
     self.root.destroy()
def main():
 root=tk.Tk();App(root);root.mainloop()
if __name__=="__main__":main()
