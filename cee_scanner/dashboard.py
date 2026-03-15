"""
cee_scanner.dashboard
Generates shareable HTML dashboard with threat intelligence embedded.
"""
from datetime import datetime, timezone
from pathlib import Path

SEV_COLOR = {"critical":"#FF2D55","warning":"#FF9500","ok":"#30D158","error":"#8E8E93"}
COUNTRY_FLAG = {
    "Czech Republic":"🇨🇿","Poland":"🇵🇱","Hungary":"🇭🇺","Slovakia":"🇸🇰","Romania":"🇷🇴"
}
THREAT_CHECKS = {"urlhaus","safebrowsing","virustotal","spamhaus","breach"}
THREAT_LABELS = {
    "urlhaus":      "URLhaus",
    "safebrowsing": "SafeBrowsing",
    "virustotal":   "VirusTotal",
    "spamhaus":     "Spamhaus",
    "breach":       "HIBP",
}
CHECK_ICONS = {
    "ssl":"🔒","headers":"🛡","dns":"🌐","https_redirect":"↪","typosquat":"🎭",
    "performance":"⚡","urlhaus":"🦠","safebrowsing":"💻","virustotal":"🧪",
    "spamhaus":"📧","breach":"💥","cve":"🐛","darkweb":"🕵️",
    "whois":"📋","email_security":"✉️","ip_intel":"🔍","shodan":"📡",
    "open_ports":"🚪","sast":"💻","sca":"📦","dast":"🌐","iac":"🏗",
}

def _rc(s):
    if s>=60: return "#FF2D55"
    if s>=30: return "#FF9500"
    return "#30D158"

def _rl(s):
    if s>=60: return "HIGH RISK"
    if s>=30: return "MEDIUM"
    return "LOW RISK"

def _e(s):
    return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")


def generate_dashboard(data: dict, output_path: str) -> str:
    gen = data.get("generated_at","")
    try:
        display_date = datetime.fromisoformat(gen).strftime("%B %d, %Y at %H:%M UTC")
    except Exception:
        display_date = gen

    summaries = data.get("country_summaries", {})
    global_avg = data.get("global_avg_risk", 0)
    total_domains = data.get("total_domains", 0)

    # Global threat counts
    total_threat_hits = sum(
        1 for s in summaries.values()
        for d in s.get("domains",[])
        for c in d.get("checks",[])
        if c.get("check") in THREAT_CHECKS and c.get("status") == "critical"
    )
    total_active_malware = sum(
        1 for s in summaries.values()
        for d in s.get("domains",[])
        for c in d.get("checks",[])
        if c.get("check") == "urlhaus" and "ACTIVE" in c.get("title","")
    )

    # ── Build country cards ───────────────────────────────────────────────────
    country_cards = ""
    for country, summary in summaries.items():
        flag = COUNTRY_FLAG.get(country, "🌍")
        avg  = summary["avg_risk_score"]
        color = _rc(int(avg))

        country_threats = sum(
            1 for d in summary["domains"]
            for c in d.get("checks",[])
            if c.get("check") in THREAT_CHECKS and c.get("status")=="critical"
        )

        domain_rows = ""
        for d in summary["domains"]:
            dr = _rc(d["risk_score"])
            by_name = {c["check"]: c for c in d.get("checks",[])}

            # Threat pills row
            threat_pills = ""
            for chk in ["urlhaus","safebrowsing","virustotal","spamhaus","breach"]:
                c = by_name.get(chk)
                if not c:
                    threat_pills += f'<span class="tp tp-unk" title="{THREAT_LABELS[chk]}: no data">{THREAT_LABELS[chk]} —</span>'
                    continue
                st = c["status"]
                if st == "critical":
                    cls = "tp-crit"
                    sym = "⚠"
                elif st == "warning":
                    cls = "tp-warn"
                    sym = "⚠"
                elif st == "ok":
                    cls = "tp-ok"
                    sym = "✓"
                else:
                    cls = "tp-unk"
                    sym = "—"
                tip = _e(c.get("title",""))
                threat_pills += f'<span class="tp {cls}" title="{tip}">{THREAT_LABELS[chk]} {sym}</span>'

            # Config dots
            config_dots = ""
            for chk in ["ssl","headers","dns","https_redirect","typosquat","performance"]:
                c = by_name.get(chk)
                if not c:
                    continue
                clr = SEV_COLOR.get(c["status"],"#8E8E93")
                tip = _e(f"{c['check']}: {c.get('title','')}")
                config_dots += f'<span class="dot" style="background:{clr}" title="{tip}"></span>'

            # Detail: threat intel section
            threat_detail = ""
            for chk in ["urlhaus","safebrowsing","virustotal","spamhaus","breach"]:
                c = by_name.get(chk)
                if not c:
                    continue
                clr = SEV_COLOR.get(c["status"],"#8E8E93")
                icon = CHECK_ICONS.get(chk,"•")
                detail_text = _e(c.get("detail",""))
                threat_detail += f"""
<div class="dc" style="border-left:3px solid {clr}">
  <div class="dc-head"><span class="dc-name">{icon} {THREAT_LABELS[chk]}</span>
  <span class="dc-badge" style="color:{clr}">{c['status'].upper()}</span></div>
  <span class="dc-title" style="color:{clr}">{_e(c.get('title',''))}</span>
  {"<span class='dc-det'>"+detail_text+"</span>" if detail_text else ""}
</div>"""

            # Detail: config section
            config_detail = ""
            for chk in ["ssl","headers","dns","https_redirect","typosquat","performance"]:
                c = by_name.get(chk)
                if not c:
                    continue
                clr = SEV_COLOR.get(c["status"],"#8E8E93")
                icon = CHECK_ICONS.get(chk,"•")
                detail_text = _e(c.get("detail",""))
                config_detail += f"""
<div class="dc" style="border-left:3px solid {clr}">
  <span class="dc-name">{icon} {c['check'].upper().replace('_',' ')}</span>
  <span class="dc-title" style="color:{clr}">{_e(c.get('title',''))}</span>
  {"<span class='dc-det'>"+detail_text+"</span>" if detail_text else ""}
</div>"""

            row_id = d["domain"].replace(".","_").replace("-","_")
            domain_rows += f"""
<tr class="dr" onclick="tog('{row_id}')">
  <td class="dn">{d["domain"]}</td>
  <td><span class="rb" style="color:{dr};border-color:{dr}">{d["risk_score"]}</span></td>
  <td class="tc">{threat_pills}</td>
  <td class="dd">{config_dots}</td>
</tr>
<tr id="det_{row_id}" style="display:none">
  <td colspan="4" style="padding:0">
    <div class="det-outer">
      <div class="det-sec">
        <div class="det-sec-title">🚨 THREAT INTELLIGENCE</div>
        <div class="det-box">{threat_detail}</div>
      </div>
      <div class="det-sec">
        <div class="det-sec-title">🔧 CONFIGURATION CHECKS</div>
        <div class="det-box">{config_detail}</div>
      </div>
    </div>
  </td>
</tr>"""

        # Stat pill helper
        def pill(label, value, color="#CDD6F4"):
            return f'<div class="sp"><span class="sp-l">{label}</span><span class="sp-v" style="color:{color}">{value}</span></div>'

        tc_color = "#FF2D55" if country_threats > 0 else "#30D158"
        country_cards += f"""
<div class="cc" data-country="{country}">
  <div class="ch">
    <div style="display:flex;align-items:center;gap:10px">
      <span style="font-size:22px">{flag}</span>
      <span style="font-size:15px;font-weight:700">{country}</span>
    </div>
    <div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center">
      {pill("AVG RISK", avg, color)}
      {pill("CRITICAL", summary["total_critical"], "#FF2D55")}
      {pill("THREATS", country_threats, tc_color)}
      {pill("DOMAINS", summary["domain_count"])}
      <span class="rlb" style="color:{color};border-color:{color}">{_rl(int(avg))}</span>
    </div>
  </div>
  <table class="dt">
    <thead><tr>
      <th>DOMAIN</th><th>RISK</th>
      <th>THREAT INTEL — URLhaus · SafeBrowsing · VirusTotal · Spamhaus · HIBP</th>
      <th>CONFIG</th>
    </tr></thead>
    <tbody>{domain_rows}</tbody>
  </table>
</div>"""

    # ── Ranking sidebar ───────────────────────────────────────────────────────
    ranking = ""
    for i,(country,s) in enumerate(sorted(summaries.items(), key=lambda x:x[1]["avg_risk_score"], reverse=True)):
        flag = COUNTRY_FLAG.get(country,"🌍")
        clr  = _rc(int(s["avg_risk_score"]))
        bw   = int(s["avg_risk_score"])
        ranking += f"""
<div style="display:flex;align-items:center;gap:7px;margin-bottom:11px">
  <span style="font-family:monospace;font-size:10px;color:#6C7086;width:14px">{i+1}</span>
  <span style="font-size:16px">{flag}</span>
  <span style="font-size:11px;font-weight:600;min-width:80px">{country}</span>
  <div style="flex:1;height:4px;background:#2A2A3E;border-radius:2px;overflow:hidden">
    <div style="width:{bw}%;height:100%;background:{clr};border-radius:2px"></div>
  </div>
  <span style="font-family:monospace;font-size:11px;font-weight:700;color:{clr};width:28px;text-align:right">{s["avg_risk_score"]}</span>
</div>"""

    # Filter buttons
    filter_btns = '<button class="fb active" onclick="fc(\'all\',this)">All Countries</button>'
    for c in summaries:
        flag = COUNTRY_FLAG.get(c,"🌍")
        filter_btns += f'<button class="fb" onclick="fc(\'{c}\',this)">{flag} {c}</button>'

    # Threat alert banner
    if total_threat_hits > 0:
        banner = f"""
<div class="banner banner-threat">
  <span style="font-size:22px">🚨</span>
  <div>
    <div style="font-weight:700;color:#FF2D55;margin-bottom:2px">{total_threat_hits} THREAT INTELLIGENCE HIT(S) DETECTED ACROSS {total_domains} DOMAINS</div>
    <div style="font-size:11px;color:#6C7086">URLhaus · Google Safe Browsing · VirusTotal · Spamhaus feeds checked. Click any domain row to see full threat details.</div>
  </div>
</div>"""
    else:
        banner = f"""
<div class="banner banner-clean">
  <span style="font-size:22px">✅</span>
  <div>
    <div style="font-weight:700;color:#30D158;margin-bottom:2px">NO ACTIVE THREATS DETECTED ACROSS {total_domains} DOMAINS</div>
    <div style="font-size:11px;color:#6C7086">All domains checked against URLhaus, Google Safe Browsing, VirusTotal and Spamhaus. Clean.</div>
  </div>
</div>"""

    # ── Assemble full HTML ────────────────────────────────────────────────────
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>CEE Cyber Risk Dashboard — SwarmHawk AI</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet"/>
<style>
:root{{--bg:#0A0A0F;--bg2:#111118;--panel:#16161E;--b:#1E1E2E;--b2:#2A2A3E;--tx:#CDD6F4;--sub:#6C7086;--ac:#89B4FA}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--tx);font-family:'Inter',sans-serif;font-size:14px;line-height:1.6}}
.topbar{{background:var(--bg2);border-bottom:1px solid var(--b2);padding:13px 26px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:100}}
.logo{{font-family:'JetBrains Mono',monospace;font-size:14px;font-weight:700;color:var(--ac);letter-spacing:2px}}
.tm{{font-size:11px;color:var(--sub)}} .tm span{{color:var(--tx)}}
.hero{{padding:24px 26px 18px;border-bottom:1px solid var(--b);background:linear-gradient(180deg,rgba(137,180,250,.04) 0%,transparent 100%)}}
.hero h1{{font-size:20px;font-weight:700;margin-bottom:3px}}
.hero-sub{{font-size:11px;color:var(--sub);margin-bottom:18px}}
.hs-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:9px;max-width:900px}}
.hs{{background:var(--panel);border:1px solid var(--b2);border-radius:8px;padding:12px 16px}}
.hs-l{{font-size:9px;letter-spacing:2px;color:var(--sub);margin-bottom:3px;font-weight:600}}
.hs-v{{font-family:'JetBrains Mono',monospace;font-size:24px;font-weight:700;line-height:1;color:var(--ac)}}
.banner{{margin:14px 26px;border-radius:8px;padding:12px 16px;display:flex;align-items:center;gap:12px}}
.banner-threat{{background:rgba(255,45,85,.08);border:1px solid rgba(255,45,85,.3)}}
.banner-clean{{background:rgba(48,209,88,.06);border:1px solid rgba(48,209,88,.25)}}
.main{{display:grid;grid-template-columns:1fr 255px;min-height:calc(100vh - 160px)}}
.left{{padding:18px 26px;border-right:1px solid var(--b)}}
.right{{padding:18px}}
.st{{font-size:10px;font-weight:700;letter-spacing:3px;color:var(--sub);margin-bottom:12px;padding-bottom:6px;border-bottom:1px solid var(--b)}}
.disc{{background:rgba(249,226,175,.05);border:1px solid rgba(249,226,175,.15);border-radius:6px;padding:9px 13px;font-size:10px;color:rgba(249,226,175,.6);margin-bottom:14px;line-height:1.6}}
.fb-wrap{{display:flex;gap:7px;margin-bottom:16px;flex-wrap:wrap}}
.fb{{padding:4px 13px;border:1px solid var(--b2);background:var(--panel);color:var(--sub);border-radius:20px;font-size:10px;cursor:pointer;font-family:'Inter',sans-serif;transition:all .2s}}
.fb:hover,.fb.active{{border-color:var(--ac);color:var(--ac);background:rgba(137,180,250,.08)}}
.cc{{background:var(--panel);border:1px solid var(--b2);border-radius:10px;margin-bottom:13px;overflow:hidden}}
.ch{{display:flex;align-items:center;justify-content:space-between;padding:13px 17px;border-bottom:1px solid var(--b);flex-wrap:wrap;gap:9px}}
.sp{{background:var(--bg);border:1px solid var(--b2);border-radius:5px;padding:4px 9px;display:flex;flex-direction:column;align-items:center;min-width:52px}}
.sp-l{{font-size:8px;letter-spacing:1.5px;color:var(--sub);font-weight:600}}
.sp-v{{font-family:'JetBrains Mono',monospace;font-size:14px;font-weight:700;line-height:1.3}}
.rlb{{padding:3px 8px;border:1px solid;border-radius:4px;font-size:9px;font-weight:700;letter-spacing:1.5px}}
.dt{{width:100%;border-collapse:collapse;font-size:11px}}
.dt th{{padding:6px 13px;text-align:left;font-size:9px;letter-spacing:2px;color:var(--sub);font-weight:600;background:rgba(0,0,0,.2);border-bottom:1px solid var(--b)}}
.dr{{cursor:pointer;transition:background .15s}}
.dr:hover{{background:rgba(137,180,250,.04)}}
.dr td{{padding:8px 13px;border-bottom:1px solid rgba(30,30,46,.8);vertical-align:middle}}
.dn{{font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--ac)}}
.rb{{font-family:'JetBrains Mono',monospace;font-size:12px;font-weight:700;padding:2px 7px;border:1px solid;border-radius:4px}}
.tc{{display:flex;gap:4px;flex-wrap:wrap;align-items:center}}
.tp{{font-size:9px;font-weight:700;padding:2px 6px;border-radius:3px;letter-spacing:.3px;cursor:help;white-space:nowrap}}
.tp-crit{{background:rgba(255,45,85,.15);color:#FF2D55;border:1px solid rgba(255,45,85,.4)}}
.tp-warn{{background:rgba(255,149,0,.12);color:#FF9500;border:1px solid rgba(255,149,0,.3)}}
.tp-ok{{background:rgba(48,209,88,.08);color:#30D158;border:1px solid rgba(48,209,88,.2)}}
.tp-unk{{background:rgba(142,142,147,.1);color:#8E8E93;border:1px solid rgba(142,142,147,.2)}}
.dd{{display:flex;gap:4px;align-items:center}}
.dot{{width:8px;height:8px;border-radius:50%;cursor:help;flex-shrink:0}}
.det-outer{{background:var(--bg);border-bottom:1px solid var(--b2);display:grid;grid-template-columns:1fr 1fr}}
.det-sec{{padding:11px 13px;border-right:1px solid var(--b)}}
.det-sec:last-child{{border-right:none}}
.det-sec-title{{font-size:9px;font-weight:700;letter-spacing:2px;color:var(--sub);margin-bottom:7px}}
.det-box{{display:flex;flex-direction:column;gap:5px}}
.dc{{padding:7px 9px;background:var(--panel);border-radius:4px}}
.dc-head{{display:flex;justify-content:space-between;align-items:center;margin-bottom:2px}}
.dc-name{{display:block;font-size:9px;letter-spacing:1.5px;color:var(--sub);font-weight:600}}
.dc-badge{{font-size:9px;font-weight:700;letter-spacing:1px}}
.dc-title{{display:block;font-size:11px;font-weight:600;margin-bottom:1px}}
.dc-det{{display:block;font-size:10px;color:var(--sub);font-family:'JetBrains Mono',monospace;word-break:break-word;margin-top:2px}}
.footer{{padding:14px 26px;border-top:1px solid var(--b);font-size:11px;color:var(--sub);display:flex;justify-content:space-between;background:var(--bg2)}}
@media(max-width:900px){{.main{{grid-template-columns:1fr}}.det-outer{{grid-template-columns:1fr}}}}
</style>
</head>
<body>

<div class="topbar">
  <div class="logo">✦ SWARMHAWK — CEE CYBER RISK</div>
  <div class="tm">Scan: <span>{display_date}</span> &nbsp;|&nbsp; Domains: <span>{total_domains}</span> &nbsp;|&nbsp; Mode: <span>PASSIVE OSINT + THREAT INTEL</span></div>
</div>

<div class="hero">
  <h1>Central &amp; Eastern Europe — Cyber Risk Dashboard</h1>
  <div class="hero-sub">SSL · Headers · DNS · URLhaus · Google Safe Browsing · VirusTotal · Spamhaus · HaveIBeenPwned</div>
  <div class="hs-grid">
    <div class="hs"><div class="hs-l">GLOBAL AVG RISK</div><div class="hs-v" style="color:{_rc(int(global_avg))}">{global_avg}</div></div>
    <div class="hs"><div class="hs-l">COUNTRIES</div><div class="hs-v">{len(summaries)}</div></div>
    <div class="hs"><div class="hs-l">DOMAINS SCANNED</div><div class="hs-v">{total_domains}</div></div>
    <div class="hs"><div class="hs-l">THREAT HITS</div><div class="hs-v" style="color:{"#FF2D55" if total_threat_hits else "#30D158"}">{total_threat_hits}</div></div>
    <div class="hs"><div class="hs-l">ACTIVE MALWARE</div><div class="hs-v" style="color:{"#FF2D55" if total_active_malware else "#30D158"}">{total_active_malware}</div></div>
    <div class="hs"><div class="hs-l">INTEL SOURCES</div><div class="hs-v" style="font-size:13px;color:#89B4FA">4 FEEDS</div></div>
  </div>
</div>

{banner}

<div class="main">
  <div class="left">
    <div class="disc">⚠ Passive OSINT only — SSL, DNS, HTTP headers, URLhaus malware feed, Google Safe Browsing, VirusTotal (70+ AV engines), Spamhaus block list, HaveIBeenPwned breach database. No active scanning. All data is publicly available.</div>
    <div class="fb-wrap">{filter_btns}</div>
    <div id="cards">{country_cards}</div>
  </div>

  <div class="right">
    <div class="st">REGIONAL RANKING</div>
    {ranking}

    <div style="margin-top:22px"><div class="st">THREAT INTEL SOURCES</div>
    <div style="font-size:11px;color:var(--sub);line-height:2.1">
      🦠 <b style="color:var(--tx)">URLhaus</b> — Real-time malware URLs<br/>
      💻 <b style="color:var(--tx)">Google SafeBrowsing</b> — Chrome flags<br/>
      🧪 <b style="color:var(--tx)">VirusTotal</b> — 70+ AV engines<br/>
      📧 <b style="color:var(--tx)">Spamhaus DBL</b> — Block list<br/>
      💥 <b style="color:var(--tx)">HaveIBeenPwned</b> — Breaches
    </div></div>

    <div style="margin-top:22px"><div class="st">CONFIG CHECKS</div>
    <div style="font-size:11px;color:var(--sub);line-height:2.1">
      🔒 SSL certificate expiry<br/>
      🛡 Security headers<br/>
      🌐 DNS configuration<br/>
      ↪ HTTPS redirect<br/>
      🎭 Typosquat domains<br/>
      ⚡ Response time
    </div></div>

    <div style="margin-top:22px"><div class="st">FREE API KEYS NEEDED</div>
    <div style="font-size:10px;color:var(--sub);line-height:1.9;font-family:'JetBrains Mono',monospace">
      VIRUSTOTAL_API_KEY<br/>
      GOOGLE_SAFEBROWSING_KEY<br/>
      <span style="color:#30D158">URLhaus + Spamhaus: free,<br/>no key needed</span>
    </div></div>
  </div>
</div>

<div class="footer">
  <span>✦ SwarmHawk AI — Passive OSINT + Threat Intelligence</span>
  <span>Generated {display_date}</span>
</div>

<script>
function tog(id){{var r=document.getElementById("det_"+id);if(r)r.style.display=r.style.display==="none"?"table-row":"none";}}
function fc(c,btn){{document.querySelectorAll(".fb").forEach(b=>b.classList.remove("active"));if(btn)btn.classList.add("active");document.querySelectorAll(".cc").forEach(el=>{{var n=el.querySelector("span[style*='font-size:15px']");if(n)el.style.display=(c==="all"||n.textContent===c)?"block":"none";}});}}
</script>
</body>
</html>"""

    Path(output_path).write_text(html, encoding="utf-8")
    return output_path
