import time
import threading
import logging
import json
import datetime
import psutil
from http.server import BaseHTTPRequestHandler, HTTPServer
from functools import partial

logger = logging.getLogger('dashboard')


class DashboardServer:

    def __init__(self, config, shared_state, state_lock, baseline_engine, blocker):
        self.config = config
        self.shared_state = shared_state
        self.state_lock = state_lock
        self.baseline_engine = baseline_engine
        self.blocker = blocker
        self.port = config['dashboard']['port']
        self._server = None

    def stop(self):
        if self._server:
            self._server.shutdown()

    def run(self):
        handler = partial(DashboardHandler,
                          shared_state=self.shared_state,
                          state_lock=self.state_lock,
                          baseline_engine=self.baseline_engine)
        self._server = HTTPServer(('0.0.0.0', self.port), handler)
        logger.info(f"Dashboard on port {self.port}")
        self._server.serve_forever()


class DashboardHandler(BaseHTTPRequestHandler):

    def __init__(self, *args, shared_state, state_lock, baseline_engine, **kwargs):
        self.shared_state = shared_state
        self.state_lock = state_lock
        self.baseline_engine = baseline_engine
        super().__init__(*args, **kwargs)

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        if self.path.startswith('/api/metrics'):
            self._serve_metrics()
        elif self.path.startswith('/api/baseline-history'):
            self._serve_baseline_history()
        else:
            self._serve_dashboard()

    def _serve_metrics(self):
        with self.state_lock:
            state = dict(self.shared_state)
            banned = {ip: dict(info) for ip, info in state.get('banned_ips', {}).items()}

        cpu = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory()
        uptime = time.time() - state.get('uptime_start', time.time())

        data = {
            'global_req_rate': round(state.get('global_req_rate', 0), 3),
            'effective_mean': round(state.get('effective_mean', 0), 4),
            'effective_stddev': round(state.get('effective_stddev', 0), 4),
            'baseline_ready': state.get('baseline_ready', False),
            'banned_ips': banned,
            'top_ips': state.get('top_ips', {}),
            'total_requests': state.get('total_requests', 0),
            'cpu_percent': cpu,
            'mem_percent': round(mem.percent, 1),
            'mem_used_mb': round(mem.used / 1024 / 1024, 1),
            'uptime_seconds': round(uptime, 0),
            'timestamp': datetime.datetime.utcnow().isoformat() + 'Z',
        }
        body = json.dumps(data).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(body)

    def _serve_baseline_history(self):
        history = self.baseline_engine.get_history()
        body = json.dumps(history).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(body)

    def _serve_dashboard(self):
        html = self._build_html()
        body = html.encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(body)

    def _build_html(self):
        return '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>HNG Anomaly Detection Engine</title>
<style>
@import url("https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Exo+2:wght@300;600;800&display=swap");
:root{--bg:#060a10;--panel:#0d1420;--border:#1a2e4a;--accent:#00d4ff;--accent2:#ff3e6c;--accent3:#39ff14;--text:#c8e0f4;--muted:#4a6080;--warn:#ffaa00;}
*{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--bg);color:var(--text);font-family:"Exo 2",sans-serif;min-height:100vh;}
body::before{content:"";position:fixed;inset:0;background-image:linear-gradient(rgba(0,212,255,0.03) 1px,transparent 1px),linear-gradient(90deg,rgba(0,212,255,0.03) 1px,transparent 1px);background-size:40px 40px;pointer-events:none;z-index:0;}
header{position:relative;z-index:1;padding:20px 32px;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid var(--border);background:linear-gradient(135deg,rgba(0,212,255,0.08) 0%,transparent 60%);}
.logo{display:flex;align-items:center;gap:14px;}
.logo-icon{width:44px;height:44px;background:linear-gradient(135deg,var(--accent),var(--accent2));border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:22px;animation:pulse 2s ease-in-out infinite;}
@keyframes pulse{0%,100%{box-shadow:0 0 20px rgba(0,212,255,0.4);}50%{box-shadow:0 0 40px rgba(0,212,255,0.8);}}
h1{font-size:1.4rem;font-weight:800;color:var(--accent);letter-spacing:2px;text-transform:uppercase;}
.subtitle{font-size:0.75rem;color:var(--muted);font-family:"Share Tech Mono",monospace;}
.status-bar{display:flex;align-items:center;gap:24px;font-family:"Share Tech Mono",monospace;font-size:0.8rem;}
.dot{width:8px;height:8px;border-radius:50%;background:var(--accent3);box-shadow:0 0 8px var(--accent3);display:inline-block;margin-right:6px;animation:blink 1.5s ease-in-out infinite;}
@keyframes blink{0%,100%{opacity:1;}50%{opacity:0.3;}}
.main{position:relative;z-index:1;display:grid;grid-template-columns:repeat(4,1fr);gap:16px;padding:24px 32px;}
.card{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:20px;position:relative;overflow:hidden;}
.card::before{content:"";position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,var(--accent),transparent);}
.card.danger::before{background:linear-gradient(90deg,var(--accent2),transparent);}
.card.success::before{background:linear-gradient(90deg,var(--accent3),transparent);}
.card.warn::before{background:linear-gradient(90deg,var(--warn),transparent);}
.card.wide{grid-column:span 2;}.card.full{grid-column:span 4;}
.label{font-size:0.7rem;font-weight:600;letter-spacing:2px;color:var(--muted);text-transform:uppercase;margin-bottom:8px;}
.value{font-size:2rem;font-weight:800;font-family:"Share Tech Mono",monospace;color:var(--accent);line-height:1;}
.value.danger{color:var(--accent2);}.value.green{color:var(--accent3);}.value.warn{color:var(--warn);}
.sub{font-size:0.75rem;color:var(--muted);margin-top:6px;font-family:"Share Tech Mono",monospace;}
table{width:100%;border-collapse:collapse;font-family:"Share Tech Mono",monospace;font-size:0.82rem;}
th{color:var(--muted);font-weight:600;text-align:left;padding:6px 10px;border-bottom:1px solid var(--border);font-size:0.7rem;text-transform:uppercase;letter-spacing:1px;}
td{padding:7px 10px;border-bottom:1px solid rgba(26,46,74,0.5);}
tr:last-child td{border-bottom:none;}
.badge{background:rgba(0,212,255,0.12);border:1px solid rgba(0,212,255,0.3);padding:2px 8px;border-radius:4px;color:var(--accent);font-size:0.78rem;}
.badge.banned{background:rgba(255,62,108,0.12);border-color:rgba(255,62,108,0.3);color:var(--accent2);}
.bar-wrap{height:6px;background:var(--border);border-radius:3px;overflow:hidden;margin-top:10px;}
.bar{height:100%;border-radius:3px;background:linear-gradient(90deg,var(--accent),var(--accent2));transition:width 0.5s;}
.empty{color:var(--muted);font-style:italic;font-size:0.8rem;padding:10px 0;}
footer{position:relative;z-index:1;text-align:center;padding:16px;color:var(--muted);font-size:0.72rem;font-family:"Share Tech Mono",monospace;border-top:1px solid var(--border);}
canvas{width:100%;height:120px;}
.pills{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px;}
.pill{padding:4px 12px;border-radius:20px;font-size:0.72rem;font-family:"Share Tech Mono",monospace;background:rgba(0,212,255,0.1);border:1px solid rgba(0,212,255,0.2);color:var(--accent);}
</style>
</head>
<body>
<header>
  <div class="logo">
    <div class="logo-icon">&#128737;</div>
    <div><h1>HNG Anomaly Detection Engine</h1><div class="subtitle">DDoS Detection &amp; Response &mdash; cloud.ng</div></div>
  </div>
  <div class="status-bar">
    <span><span class="dot"></span><span id="live-status">INITIALIZING</span></span>
    <span id="clock">--:--:--</span>
  </div>
</header>
<div class="main">
  <div class="card"><div class="label">Global Req/s</div><div class="value" id="val-rate">0.00</div><div class="sub">requests per second</div></div>
  <div class="card danger"><div class="label">Banned IPs</div><div class="value danger" id="val-banned">0</div><div class="sub" id="sub-banned">no active bans</div></div>
  <div class="card"><div class="label">Baseline Mean</div><div class="value" id="val-mean">--</div><div class="sub">effective req/s</div></div>
  <div class="card"><div class="label">Std Deviation</div><div class="value" id="val-stddev">--</div><div class="sub" id="sub-ready">warming up...</div></div>
  <div class="card"><div class="label">CPU Usage</div><div class="value" id="val-cpu">--%</div><div class="bar-wrap"><div class="bar" id="bar-cpu" style="width:0%"></div></div></div>
  <div class="card"><div class="label">Memory</div><div class="value" id="val-mem">--%</div><div class="sub" id="sub-mem">-- MB</div><div class="bar-wrap"><div class="bar" id="bar-mem" style="width:0%"></div></div></div>
  <div class="card success"><div class="label">Uptime</div><div class="value green" id="val-uptime">0s</div><div class="sub">daemon running</div></div>
  <div class="card"><div class="label">Total Requests</div><div class="value" id="val-total">0</div><div class="sub">since start</div></div>
  <div class="card wide"><div class="label">Top 10 Source IPs (last 60s)</div><div id="top-ips"><div class="empty">No data yet.</div></div></div>
  <div class="card wide danger"><div class="label">Currently Banned IPs</div><div id="banned-ips"><div class="empty">No IPs banned.</div></div></div>
  <div class="card full"><div class="label">Baseline Over Time</div><canvas id="chart"></canvas><div class="pills" id="pills"></div></div>
</div>
<footer>Auto-refreshes every 3s &nbsp;|&nbsp; HNG DevOps Track Stage 3 &nbsp;|&nbsp; <span id="last-update">Never</span></footer>
<script>
function fmtUptime(s){const h=Math.floor(s/3600),m=Math.floor((s%3600)/60),sec=Math.floor(s%60);return h>0?h+"h "+m+"m "+sec+"s":m>0?m+"m "+sec+"s":sec+"s";}
function el(id){return document.getElementById(id);}
setInterval(()=>el("clock").textContent=new Date().toLocaleTimeString(),1000);
async function refresh(){
  try{
    const d=await fetch("/api/metrics?_="+Date.now()).then(r=>r.json());
    el("live-status").textContent=d.baseline_ready?"LIVE":"WARMING UP";
    el("val-rate").textContent=d.global_req_rate.toFixed(2);
    const bc=Object.keys(d.banned_ips||{}).length;
    el("val-banned").textContent=bc;
    el("sub-banned").textContent=bc===1?"1 active ban":bc+" active bans";
    el("val-mean").textContent=d.effective_mean.toFixed(4);
    el("val-stddev").textContent=d.effective_stddev.toFixed(4);
    el("sub-ready").textContent=d.baseline_ready?"baseline ready":"warming up...";
    el("val-cpu").textContent=d.cpu_percent.toFixed(1)+"%";
    el("bar-cpu").style.width=Math.min(d.cpu_percent,100)+"%";
    el("val-mem").textContent=d.mem_percent.toFixed(1)+"%";
    el("sub-mem").textContent=d.mem_used_mb+" MB used";
    el("bar-mem").style.width=Math.min(d.mem_percent,100)+"%";
    el("val-uptime").textContent=fmtUptime(d.uptime_seconds);
    el("val-total").textContent=d.total_requests.toLocaleString();
    const top=Object.entries(d.top_ips||{}).sort((a,b)=>b[1]-a[1]).slice(0,10);
    const maxR=top.length>0?top[0][1]:1;
    el("top-ips").innerHTML=top.length===0?"<div class='empty'>No traffic yet.</div>":
      "<table><thead><tr><th>IP</th><th>Reqs</th><th>Share</th></tr></thead><tbody>"+
      top.map(([ip,c])=>`<tr><td><span class='badge'>${ip}</span></td><td>${c}</td><td><div class='bar-wrap'><div class='bar' style='width:${Math.round(c/maxR*100)}%'></div></div></td></tr>`).join("")+
      "</tbody></table>";
    const bans=Object.entries(d.banned_ips||{});
    const now=Date.now()/1000;
    el("banned-ips").innerHTML=bans.length===0?"<div class='empty'>No IPs currently banned.</div>":
      "<table><thead><tr><th>IP</th><th>Reason</th><th>Duration</th><th>Expires In</th></tr></thead><tbody>"+
      bans.map(([ip,i])=>`<tr><td><span class='badge banned'>${ip}</span></td><td>${i.reason||"-"}</td><td>${i.label||"-"}</td><td style='color:var(--warn)'>${i.duration>=2592000?"permanent":fmtUptime(Math.max(0,i.duration-(now-i.banned_at)))}</td></tr>`).join("")+
      "</tbody></table>";
    el("last-update").textContent="Updated: "+new Date().toLocaleTimeString();
  }catch(e){el("live-status").textContent="ERROR";}
  try{
    const h=await fetch("/api/baseline-history?_="+Date.now()).then(r=>r.json());
    if(!h||h.length===0)return;
    const canvas=el("chart"),ctx=canvas.getContext("2d");
    const W=canvas.offsetWidth,H=120;
    canvas.width=W;canvas.height=H;
    const means=h.map(x=>x.mean),maxV=Math.max(...means,0.1),minV=Math.min(...means,0),range=maxV-minV||1;
    ctx.clearRect(0,0,W,H);
    ctx.strokeStyle="rgba(26,46,74,0.6)";ctx.lineWidth=1;
    for(let i=0;i<=4;i++){const y=(i/4)*H;ctx.beginPath();ctx.moveTo(0,y);ctx.lineTo(W,y);ctx.stroke();}
    ctx.beginPath();ctx.strokeStyle="#00d4ff";ctx.lineWidth=2;
    h.forEach((p,i)=>{const x=(i/(h.length-1))*W,y=H-((p.mean-minV)/range)*H*0.9-H*0.05;i===0?ctx.moveTo(x,y):ctx.lineTo(x,y);});
    ctx.stroke();
    ctx.lineTo(W,H);ctx.lineTo(0,H);ctx.closePath();ctx.fillStyle="rgba(0,212,255,0.08)";ctx.fill();
    const l=h[h.length-1];
    el("pills").innerHTML=`<span class='pill'>mean: ${l.mean.toFixed(4)} req/s</span><span class='pill'>±σ: ${l.stddev.toFixed(4)}</span><span class='pill'>source: ${l.source||"rolling"}</span><span class='pill'>samples: ${l.samples||"-"}</span>`;
  }catch(e){}
}
setInterval(refresh,3000);refresh();
</script>
</body>
</html>'''
