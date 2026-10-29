# NETSENTINEL v2.02 — Phase 6: Threat Intelligence & Correlation Lab

## UI refresh
- High-contrast charcoal workspace with vivid orange highlights inspired by security testing tools.
- Stronger selected-tab contrast, clearer button states, bright table headings, and a visible status indicator.
- The visual refresh does not change capture or detection semantics.

Native Ubuntu desktop network investigation app built with Python, Tkinter, Scapy, Nmap, and JSON. No Flask, hosted website, or SQLite.

## Phase 6 additions
- **Help menu** with an in-app operator guide, quick start, and About dialog. The bundled `HELP.md` documents every tab, supported packet search expressions, examples, Ubuntu commands, exports, troubleshooting, and investigation limitations.
- Cleaner Packet Inspector toolbar: removed the on-screen expression cheat-sheet and renamed the control to **Find packets**; detailed search syntax is available from **Help → User Guide / How to Operate**.
- **Threat Intel Lab** for manually adding IP/domain indicators, importing trusted CSV/JSON feeds, removing indicators, and exporting the local library.
- Background file reading so capture loading does not block the UI.
- Packet timeline with timestamp, endpoints, protocol, size, TCP flags, and linked observations.
- Offline protocol distribution, top talkers, top DNS names, large-frame observations, and a heuristic for possible SYN port sweeps.
- Select a packet row to view its decoded summary and payload preview.
- Correlate imported indicators against IP endpoints and DNS names in the loaded PCAP, including parent-domain matches for subdomains.
- Add contextual MITRE ATT&CK technique references for selected heuristics; mappings are explicitly hypotheses requiring analyst validation.
- Export an HTML investigation report or JSON report containing capture metadata, findings, IOC correlation matches, ATT&CK context, protocol counts, talkers, DNS names, and limitations.
- Analyzes at most 50,000 packets per file and displays up to 3,000 rows in the timeline for responsiveness.
- Analysis is offline and does not transmit packets or change the source capture.

## Existing features retained
Live packet capture, custom packet filters, TCP flows and best-effort stream reconstruction, clear-text HTTP observations, DNS history, device discovery/inventory, protocol overview, alert workflow with analyst notes, JSON storage, and PCAP export.

## Install and launch on Ubuntu
```bash
chmod +x setup.sh run.sh
./setup.sh
./run.sh
```

`setup.sh` installs the required Ubuntu packages and Scapy into a virtual environment. `run.sh` launches with elevated privileges for packet capture. PCAP loading/report generation can be used on files readable by the user; live capture requires appropriate privileges.

## Important limitations
- Captures only contain traffic visible at the original capture point/interface.
- HTTPS application payloads remain encrypted.
- TCP stream reconstruction is best-effort.
- The SYN sweep and large-frame observations are heuristics, not proof of malicious behavior. Legitimate network administration can trigger them.
- Reports are intended to support analyst investigation, not certify a capture as safe or malicious.
- Monitor only networks and devices you own or are authorized to inspect.

## Rule configuration
Live detection rules are stored in `data/rules.json`; alert workflow data is stored in `data/alerts.json`. The app uses JSON files rather than a database.


## Phase 6 — Threat Intel Lab
Import trusted local IOC feeds in CSV/JSON, add IP/domain indicators, correlate them with a loaded PCAP, and review contextual MITRE ATT&CK mappings. Correlation is offline by default and does not send indicator values to third parties. See Help → User Guide.

## Reliability hardening / regression checks
- Removed duplicate construction of the TCP Flows, HTTP Inspector, Alerts, and TCP Streams widgets that could make those tabs render twice.
- Packet selection now uses stable row identifiers instead of matching timestamps, avoiding wrong packet details when multiple packets share the same timestamp.
- Clear Session now resets packet/flow/stream/HTTP/DNS state consistently, refuses to clear while capture is active, and retains alert history and device inventory.
- Re-analyzing a capture preserves existing IOC correlation results for that same loaded capture; loading a different capture clears stale correlation display state.
- Invalid custom port-sweep threshold/window values fall back to safe defaults rather than breaking packet processing.
- Added a lightweight core regression suite. Run it from the project directory with:

```bash
python3 -m unittest discover -s tests -v
```

The automated regression suite and a headless Tkinter GUI smoke test passed in the build environment. Full live packet capture, Nmap discovery on your specific network, and Scapy PCAP decoding must still be verified on your Ubuntu machine after installing dependencies; the build environment did not have Scapy available and could not reach package repositories.

## Interface update (Bright Workspace)
- Light warm-white workspace with high-contrast text and bright orange action accents.
- Compact toolbar and tabs to leave more vertical room for packet tables and investigation details.
- Top-aligned File, Capture, View, and Help menus.
- Brief NETSENTINEL welcome screen that transitions automatically to the analyst workspace in about 1.6 seconds.


## Phase 6+ investigation additions

- **Cases & SIEM Logs**: create local cases with severity, status, notes, timeline, and attached evidence.
- **Evidence integrity**: attaching a loaded PCAP calculates a SHA-256 hash and records the path and packet count in the case. A hash helps detect byte changes; it does not prove provenance or custody by itself.
- **Suricata / Zeek ingestion**: import Suricata EVE JSON (newline-delimited JSON) or Zeek TSV logs for local review and case export. This is file ingestion, not a live integration with either service.
- **IOC expiration**: imported indicators can provide an `expires_at` ISO-8601 timestamp; expired or invalidly dated indicators are excluded from correlation.
- **Diagnostics**: Help → Diagnostics reports Python, Scapy/Nmap availability, capture state, queue depth, and local counts.
- **PCAP hash**: PCAP analysis reports now include a SHA-256 hash of the original capture when readable.

These additions do not make NETSENTINEL a production SIEM. Validate behavior on your system, run only authorized scans/captures, and retain original evidence files securely.

## Download from GitHub

After the maintainer publishes this project in a public GitHub repository, select **Code → Download ZIP**, or clone it:

```bash
git clone https://github.com/YOUR-USERNAME/netsentinel.git
cd netsentinel
chmod +x setup.sh run.sh
./setup.sh
./run.sh
```

Replace `YOUR-USERNAME` with the repository owner's GitHub username. See `PUBLISH_TO_GITHUB.md` for maintainer publishing instructions.

## Project status and responsible use

This is an actively developed desktop investigation tool, not a production SIEM. Validate capture behavior and detections in your own environment. Heuristic alerts may be false positives or miss activity. Only monitor networks and devices you own or are authorized to assess. Never publish packet captures or local investigation records containing private data.
