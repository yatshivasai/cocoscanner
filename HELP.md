COCOSCANNER — PROFESSIONAL OPERATOR GUIDE
Version: v2.02 Phase 5 | Ubuntu desktop edition

CONTENTS
1. Purpose and safe-use boundaries
2. First launch
3. Live packet capture
4. Packet search syntax and examples
5. Reading packet details
6. TCP Flows, TCP Streams, and HTTP Inspector
7. Alerts and analyst workflow
8. Device Inventory and authorized discovery
9. DNS History and Protocol Overview
10. PCAP Lab and investigation reports
11. Export and local data files
12. Useful Ubuntu commands
13. Troubleshooting
14. Interpretation limits and analyst checklist

1. PURPOSE AND SAFE-USE BOUNDARIES
COCOSCANNER is a local desktop tool for observing traffic visible to your selected network interface, reviewing network metadata, inspecting authorized packet captures, and documenting findings. It is not a full replacement for Wireshark, Zeek, Suricata, or an enterprise SIEM. Use it only on systems, networks, and capture files you own or have explicit permission to inspect.

A capture sees only packets available at the selected interface and capture point. A normal switched network interface generally does not see every other device's unicast traffic. HTTPS/TLS application content remains encrypted; metadata such as endpoints, ports, timing, sizes, and some DNS may still be visible depending on the network and capture point.

2. FIRST LAUNCH
From a terminal, enter the extracted application directory and run:

    chmod +x setup.sh run.sh
    ./setup.sh
    ./run.sh

The setup script installs required Ubuntu packages and creates a Python virtual environment. The run script launches the app with elevated privileges for packet capture. Do not run random scripts from untrusted sources as root; inspect scripts before granting privileges.

Useful initial checks:

    ip -br link                 # list interfaces
    ip -br addr                 # show interface addresses
    ip route                    # show routes and default gateway
    nmap --version              # confirm Nmap is installed

Common interface names include wlan0, wlp2s0, eth0, and enp3s0. Use the interface that carries the traffic you want to observe.

3. LIVE PACKET CAPTURE
1. In the top bar, review the INTERFACE field. Enter a valid interface name if needed.
2. Click Start capture and reproduce the activity you are authorized to investigate.
3. The Packet Inspector lists packets captured by that interface. Select a row to populate the decoded details and payload preview below.
4. Click Stop when finished. Use Refresh if you want the other panels to update from current stored data.
5. Use Export PCAP to save packets from the current live session when available, or Export JSON for the application's packet records.
6. Clear session clears the current packet session from the view/storage workflow; export evidence first if you need to preserve it.

Keep captures short and scoped to the investigation. Packet captures can contain sensitive information, including internal addresses and unencrypted application data. Store and share them carefully.

4. PACKET SEARCH SYNTAX AND EXAMPLES
The Packet Inspector has a compact search field. It supports a small set of COCOSCANNER-specific expressions, not the full Wireshark display-filter language and not tcpdump/BPF syntax. Matching is case-insensitive for protocol names and text. Multiple supported expressions are combined with AND when separated by spaces or the word 'and'. If the input is not recognized as one of the supported expressions, the app falls back to a simple text search across packet metadata.

Supported expressions:

    tcp                 TCP packets
    udp                 UDP packets
    icmp                ICMP packets
    arp                 ARP packets
    ipv4                IPv4 packets
    ipv6                IPv6 packets
    dns                 Packets decoded as DNS
    host=192.168.1.10   Packets where source OR destination matches this IP
    src=192.168.1.10    Packets whose source IP matches
    dst=192.168.1.1     Packets whose destination IP matches
    port=443            Packets with source OR destination port 443
    srcport=51514       Packets whose source port matches
    dstport=443         Packets whose destination port matches
    len>1000            Packets larger than 1000 bytes
    len<128             Packets smaller than 128 bytes
    flags=S             TCP flags text contains S (SYN)

Examples:

    tcp
    dns
    host=192.168.1.10
    tcp dstport=443
    tcp and dstport=443
    src=192.168.1.25 udp
    len>1000
    flags=S
    192.168.1.10         # simple text search if not a supported expression

Notes:
- Use actual IP addresses and numeric ports; do not include angle brackets.
- Expressions are ANDed; there is no OR syntax or parenthesis support.
- 'host=' matches either endpoint; 'src=' and 'dst=' are directional.
- 'flags=S' checks whether the recorded TCP flag string contains S; it is a quick narrowing aid, not a complete TCP-state analysis.
- Search is applied to packets retained in the current packet list. It does not change the network capture itself.
- The search is deliberately limited and safe; do not assume arbitrary Wireshark syntax such as ip.addr == ... will work.

5. READING PACKET DETAILS
Select a packet row to inspect timestamp, protocol, length, source/destination IP and ports, MAC addresses when present, TTL/hop limit, IPv4 ID, TCP flags, sequence/acknowledgement numbers, window size, DNS summary, decoded protocol layers, and a short payload preview where available.

A payload preview is not a complete application transcript. Binary bytes may look like unreadable text. Encrypted TLS/HTTPS payloads cannot be read as plaintext by this tool. Avoid treating a port number alone as proof of the application protocol.

6. TCP FLOWS, TCP STREAMS, AND HTTP INSPECTOR
- TCP Flows groups observed TCP packets by endpoint tuple and summarizes packet/byte counts and flags seen.
- TCP Streams attempts best-effort reconstruction of observed TCP payloads. Missing packets, asymmetric visibility, retransmissions, or capture start/end points can make a stream incomplete or out of order.
- HTTP Inspector surfaces recognizable clear-text HTTP observations. It cannot decrypt HTTPS and may not identify every HTTP message.

Use these panels to pivot from a packet to the broader conversation. Verify important conclusions against the original capture and other evidence.

7. ALERTS AND ANALYST WORKFLOW
Open Alerts to review generated events. Select an alert to inspect its details/evidence, add an analyst note, and update its status (New, Investigating, or Resolved, depending on the control labels). Export alert records when needed.

Rules and alert state are stored under the application's data directory. Current rules include informational DNS query observations and a heuristic for possible SYN port sweeps. A sweep alert is a lead to investigate, not proof of scanning or malicious intent. Authorized inventory tools, monitoring systems, and software updates can generate similar patterns. Review source, timing, destination ports, surrounding packets, and asset ownership before escalating.

8. DEVICE INVENTORY AND AUTHORIZED DISCOVERY
Enter an IPv4 private subnet in CIDR notation, for example:

    192.168.1.0/24
    10.0.0.0/24
    172.16.5.0/24

Then click Discover devices. Only private, loopback, or link-local IPv4 networks are accepted, and the app limits the subnet size. Confirm the subnet carefully before scanning. Discovery results depend on reachability, host firewall settings, network segmentation, and privileges; a missing device is not proof that it is offline.

Equivalent command-line host discovery for an authorized subnet:

    nmap -sn 192.168.1.0/24

Replace the example with your own authorized subnet. Do not scan networks without permission.

9. DNS HISTORY AND PROTOCOL OVERVIEW
- DNS History lists DNS queries/responses that were visible and decoded by the app. It is not a complete DNS audit log; encrypted DNS (DoH/DoT), cached answers, and unseen traffic will not necessarily appear.
- Protocol Overview summarizes observed protocol counts and traffic rates/talkers based on available records. Rates are approximate and depend on the active observation window and retained packet data.
- Device history records sightings observed by the app. A last-seen timestamp reflects observed evidence, not a guarantee of current online status.

10. PCAP LAB AND INVESTIGATION REPORTS
1. Open PCAP Lab & Reports.
2. Choose Load PCAP and select a .pcap, .pcapng, or .cap file that you are authorized to analyze.
3. Click Analyze capture and wait for processing to finish.
4. Review capture metadata, protocol distribution, top talkers, DNS names, and heuristic findings.
5. Select packet rows to review individual packet details and related observations.
6. Export an HTML report for a readable case summary or JSON for structured follow-up.

The analyzer is offline: it reads the selected file and does not transmit packets or intentionally modify the original capture. For responsiveness, analysis is capped at 50,000 packets and the timeline displays up to 3,000 rows. A finding may refer to patterns across the analyzed packet set rather than a confirmed attack. Preserve the original capture and record its source, acquisition time, timezone, and integrity hash for formal investigations.

Optional integrity hash command:

    sha256sum evidence.pcap

Save the output with your case notes. Hash the original before analysis when evidence integrity matters.

11. EXPORTS AND LOCAL DATA FILES
The application stores state locally in the data/ directory. Depending on features used, files include packet/device records, device history, alert records, and detection rules. Keep the whole data folder with the application if you need continuity between sessions. Back it up before editing JSON manually. Stop the app before manually changing files, and preserve a copy of the originals.

Common exports include packet JSON, PCAP, DNS JSON, alerts JSON, and PCAP investigation reports in HTML or JSON. Check export paths and confirm files were created before closing the application.

12. USEFUL UBUNTU COMMANDS
Show interfaces and addresses:

    ip -br link
    ip -br addr
    ip route

Check Nmap and Python:

    nmap --version
    python3 --version

List available capture interfaces (requires Scapy in the app environment):

    sudo ./venv/bin/python -c "from scapy.all import get_if_list; print('\\n'.join(get_if_list()))"

Capture a short authorized sample with tcpdump (if installed):

    sudo tcpdump -i wlan0 -c 200 -w sample.pcap

Replace wlan0 with the correct interface. Stop automatically after 200 packets. To stop sooner, press Ctrl+C. Treat the output as sensitive evidence. COCOSCANNER can then load sample.pcap in the PCAP Lab.

Check whether a capture file exists and inspect its hash:

    ls -lh sample.pcap
    sha256sum sample.pcap

13. TROUBLESHOOTING
- Permission/capture error: launch with ./run.sh and check that the interface exists with ip -br link. Some systems restrict packet capture; do not change system security settings blindly.
- No packets appear: verify the selected interface, generate authorized traffic, and remember that switched networks do not expose all devices' traffic to every port.
- Device discovery returns nothing: verify the subnet/CIDR, local routing, and that the hosts are reachable. Firewalls may block discovery probes.
- PCAP will not load: verify the file is a valid supported capture, is readable, and is not truncated/corrupt. Try a copy of the file and preserve the original.
- Window is too small: resize the application window; the UI supports a minimum desktop size.
- Missing Python dependency: rerun ./setup.sh and read terminal output for the exact package error.
- GUI does not launch over SSH: Tkinter needs a graphical desktop/session. Run it in the local Ubuntu desktop or configure an approved GUI-forwarding method.
- Search gives no matches: clear the search and retry with one supported expression, then combine expressions gradually.

14. PROFESSIONAL ANALYST CHECKLIST
Before capture: document authorization, scope, interface, time/timezone, and purpose.
During capture: minimize collection, note actions and timestamps, and avoid unnecessary sensitive traffic.
After capture: preserve the original file, calculate SHA-256 when evidence integrity matters, record findings separately from assumptions, and export reports.
For each alert: validate the underlying packets, check asset ownership and expected behavior, correlate with other telemetry, record uncertainty, and document why the alert was resolved or escalated.

Remember: an alert is a lead, not a verdict. Confirm findings using context and independent evidence.


## Threat Intel Lab (Phase 6)

The Threat Intel Lab performs **local/offline IOC correlation** against packet metadata in the currently loaded PCAP. It does not contact reputation services and does not transmit captured addresses or domain names.

### Add or import indicators
- Choose **Add indicator…** to add an IP address or domain manually.
- Choose **Import CSV/JSON…** to load a feed. JSON can be a list of objects or `{ "indicators": [...] }`. Each row/object should include `type` (`ip` or `domain`) and `value`; optional fields are `source`, `confidence`, and `notes` (CSV headers are the same).
- Choose **Export feed…** to back up or share the local indicator library.
- Indicators are saved under `data/indicators.json`. Only import feeds from sources you trust and record provenance/freshness.

### Correlate against a capture
1. Open **PCAP Lab & Reports** and load a `.pcap`, `.pcapng`, or `.cap` file.
2. Click **Analyze capture** there if you want the current heuristic findings included in ATT&CK context.
3. Open **Threat Intel Lab** and choose **Correlate loaded PCAP**.
4. Review packet-level matches, indicator source, confidence, and notes. A domain indicator can match the exact DNS name or a subdomain.
5. Export the PCAP report from the PCAP tab to preserve the correlation object in JSON report data.

### ATT&CK context
The app provides contextual mappings, not a certification that an adversary used a technique. A possible SYN port sweep may map to MITRE ATT&CK **T1046 — Network Service Discovery**. DNS observations may be shown with **T1071.004 — DNS** as context only; ordinary DNS is expected on most networks. An IOC match may suggest reviewing **T1071 — Application Layer Protocol**, but an IOC match alone does not establish command-and-control. Validate timing, direction, endpoint role, feed quality, and surrounding packet evidence.

### Important limitations
- A match means only that the observed value matched an indicator imported into your local library; it is not a live reputation verdict.
- False positives can occur due to shared hosting, NAT, CDNs, dynamic addresses, stale feeds, and benign reuse.
- No automatic external reputation lookups are performed; this is deliberate to keep investigations private and predictable.
- Correlation is limited to visible source/destination IPs and DNS names decoded from the selected capture. Encrypted HTTPS payloads are not decrypted.

## Cases & SIEM Logs

Use **Cases & SIEM Logs** to create a case, choose severity/status, and record initial notes. Select a case before attaching evidence or exporting it. To attach the currently loaded PCAP, load the file in PCAP Lab, select a case, and click **Attach loaded PCAP**. COCOSCANNER records the path, packet count, timestamp, and SHA-256 hash. Keep the original capture in a secure location; the app references it rather than copying it into the case bundle.

Use **Import Suricata / Zeek logs…** to ingest a local Suricata EVE JSON file (one JSON object per line) or a Zeek TSV log with a `#fields` header. Imports are capped at 20,000 event rows for responsiveness. This is offline log ingestion, not a live connection to Suricata or Zeek. Imported events are held in the current application session and included in case exports.

Select a case and choose **Export selected case…** to create JSON or HTML case summaries. A SHA-256 hash helps identify whether evidence bytes have changed since attachment, but does not by itself prove source, authenticity, or chain of custody.

### Diagnostics

Open **Help → Diagnostics** to inspect runtime dependency availability, capture status, queue depth, and local record counts. If live capture fails, check that Scapy is installed, the selected interface exists, and the process has suitable capture permissions.
