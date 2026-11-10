# NetSentinel · AI-assisted mini SOC

**Live demo:** https://vuthevinh2125.github.io/netsentinel/ · English / Tiếng Việt

NetSentinel watches a company network the way a small Security Operations Centre would: it learns how every host normally behaves, raises alerts from rules, an anomaly model and a beaconing detector, chains the alerts into incidents, and then an **AI analyst investigates each incident with read-only tools** and writes the report, including saying when an alert is a false alarm.

Everything runs on a reproducible lab: seven days of traffic from a simulated 54-host company with seven injected, MITRE ATT&CK-labelled attacks and several legitimate activities that look suspicious on purpose. That makes every number below checkable. The detectors are then tested on **real, labelled malware traffic** from a university security lab, including a blind test on a dataset they never saw, and the README reports what broke.

![NetSentinel dashboard](docs/screenshot.png)

## Results

Five independently generated networks (seeds 7, 11, 23, 42, 99), seven attacks each, scored against the injected ground truth:

| Metric | Rules only | Model only | Rules + beaconing | **Hybrid** |
|---|---|---|---|---|
| Attacks detected | 71% | 57% | 86% | **100%** |
| Alert precision | 83% | 100% | 75% | **84%** |
| False alerts / day | 0.2 | 0 | 0.4 | **0.4** |
| A1 C2 beaconing | 0% | 0% | 100% | **100%** |
| A2 Port scan (fast) | 100% | 100% | 100% | **100%** |
| A3 Port scan (slow) | 0% | 100% | 0% | **100%** |
| A4 SSH brute force → success | 100% | 0% | 100% | **100%** |
| A5 Lateral movement over SMB | 100% | 100% | 100% | **100%** |
| A6 DNS tunnelling | 100% | 100% | 100% | **100%** |
| A7 Exfiltration | 100% | 0% | 100% | **100%** |

No single method is enough: rules miss the low-and-slow scan, the anomaly model misses brute force and a one-off large upload, and only the combination catches all seven. The remaining false alerts come from two deliberate traps (a monitoring agent's perfectly regular heartbeat and an admin's software push over SMB), and the AI analyst closes both as benign.

**AI analyst:** 10/10 correct verdicts (5 incidents × English and Vietnamese), graded on 7 checks per report: verdict, severity, every IOC named, MITRE looked up, investigation method, containment first, language.

## Results on real traffic

The lab proves the pipeline end to end; real captures show whether it survives contact with real machines. NetSentinel was run, with the same detectors and thresholds, on **28 public Zeek captures from the [Stratosphere Laboratory](https://github.com/stratosphereips/security-datasets-for-testing)** (Czech Technical University in Prague): 662 hours and 664,922 real flows from Windows machines infected with known malware, plus machines left clean on the Internet. Every flow carries the lab's own label, which is read only to grade.

| Malware family | Infected host-days | Detected | True / all alerts |
|---|---|---|---|
| Trickbot | 5 | **5/5** | 133 / 134 |
| Dridex | 5 | **5/5** | 20 / 20 |
| Kovter | 2 | **2/2** | 10 / 10 |
| Bladabindi RAT | 1 | **1/1** | 3 / 3 |
| Cridex | 5 | 1/5 | 1 / 1 |

**14 of 18 infected host-days detected, 73% alert precision, 2.2 false alerts per day, and none on the four clean days.** Infected machines were usually flagged within minutes of their first malicious connection.

What real data taught, in order:

1. **First run: 34% precision, 12.5 false alerts a day.** Almost all of them were IPv6 neighbour-discovery multicast (`ff02::…`) being treated as an Internet host that the machine "beaconed" to. The simulated lab has no IPv6, so it never showed. Fixing address classification (only globally routable unicast counts as the Internet) took precision to 95%.
2. **Declaring the monitored machine as part of the network.** Some captures give it a public university address, so it was invisible to the outbound detectors. A real SOC lists its own ranges (`HOME_NET` in Suricata), so the adapter does the same, working the address out from traffic volume and never from labels. This is the honest configuration, and it brings the clean machine's own periodic traffic into view: precision settles at 73%.
3. **Tried and rejected: a size-regularity beacon check** (in the spirit of RITA). It caught Cridex, whose C2 timing is too jittery for the interval test, but it also flagged Microsoft telemetry, which sends identical requests all day. It was not shipped, and Cridex stays in the table at 1/5.

The 61 remaining false alerts are mostly BitTorrent retrying dead peers, cloud sync and telemetry (Dropbox, Microsoft, AWS) and NTP. That is exactly the queue the AI analyst is meant to triage. Slow scans from the Internet against a single machine are mostly missed (1 of 6 days), because the scan rule looks for one source probing many ports quickly. The anomaly model is not used on these captures: a capture that starts already infected has no clean baseline to learn from.

```bash
bash scripts/fetch_stratosphere.sh            # ~120 MB of labelled Zeek logs into data/stratosphere
python -m netsentinel real-eval               # the table above, plus docs/data/real.json for the dashboard
```

### Blind test: IoT-23

The Windows results above came after two changes made while looking at that data, so they are development numbers. To get one nobody can call tuned, the detectors were frozen and run **once** on a dataset they had never seen: **[IoT-23](https://www.stratosphereips.org/datasets-iot23)**, 20 captures of Linux IoT devices infected with Mirai, Torii, Hajime, Okiru and other botnets. That is a different kind of machine and a different kind of malware. Only the log reader was extended to parse its format.

| Malware family | Infected devices | Detected | True / all alerts |
|---|---|---|---|
| Mirai | 8 | **7/8** | 9 / 19 |
| Kenjiro | 2 | **2/2** | 2 / 2 |
| Torii | 2 | 0/2 | 0 / 4 |
| Muhstik, Hajime, Hakai, Okiru, IRCBot, Gagfyt, Hide and Seek | 1 each | **7/7** | 114 / 130 |
| Trojan | 1 | 0/1 | 0 / 2 |

**16 of 20 infected devices caught, 80% alert precision, 4.2 false alerts per day, over 1.5 million flows.** Mass scanning (Mirai, Hajime, Kenjiro, IRCBot, Muhstik) is caught by the scan rule; C2 heartbeats (Hakai, Hide and Seek) by the beaconing detector. The misses are the quiet ones: Torii and the Trojan sent only 4 to 16 malicious flows in the whole capture, and one Mirai capture had 82, too few for volume- or rhythm-based detection.

Most scenarios are the first 100,000 flows of the original capture, from a public GitHub mirror (the official server is not reachable from every network). The mirror was checked against the original log of scenario 3-1: the same 99,999 flows with the same labels.

```bash
bash scripts/fetch_iot23.sh                   # ~260 MB into data/iot23
python -m netsentinel real-eval --iot23 data/iot23
```

## How it works

```
lab network ─► features per host / 5 min ─► rules ─┐
                                           ─► anomaly model (Isolation Forest on robust z-scores) ─┼─► alerts ─► incidents ─► AI analyst ─► report
flows · logins · DNS ──────────────────────► beaconing (inter-arrival regularity) ─┘        (pivot chaining)    (tool use)
```

| Layer | What it does | Where |
|---|---|---|
| Lab network | 54 hosts on 3 VLANs with office-hour behaviour. Attacks: C2 beaconing (T1071.001), fast and slow port scans (T1046), SSH brute force with success (T1110), SMB lateral movement with a stolen admin account (T1021.002), DNS tunnelling (T1071.004), exfiltration (T1048). Traps: authorised vulnerability scan, nightly 1.5 GB backup, admin software push, monitoring heartbeat, password typos, proxy-blocked sites. Attack intensity is randomised per seed. | `netsentinel/simulate.py` |
| Rules | Port scan, brute force (sliding 10-minute window, critical on success), SMB fan-out by an account from a host it never used, DNS tunnelling (length + entropy + uniqueness), large upload to a never-seen destination. Authorised scanners are suppressed with a reason. | `netsentinel/detect.py` |
| Anomaly model | Each host is compared with **its own** baseline (median / MAD robust z-scores on structural counts: distinct ports, unanswered probes, internal hosts touched, SMB peers, new external destinations, failed logins, long random DNS names), then scored by an Isolation Forest. An alert needs both an unusual score and a ≥6σ shift, so it can always say *why*. | `netsentinel/detect.py` |
| Beaconing | Many small connections to a rare external host with low jitter in the inter-arrival times. Behaviour that already existed during the baseline is kept out of attack chains. | `netsentinel/detect.py` |
| Incidents | Alerts are joined when they share a source, or when a later alert starts from a host an earlier alert touched and that host had no earlier alerts (a pivot). The phished workstation → database → exfiltration story becomes one incident. | `netsentinel/detect.py` |
| AI analyst | A Claude tool-use loop with six read-only tools (`get_incident`, `host_profile`, `query_flows`, `auth_events`, `dns_queries`, `lookup_mitre`) and a structured `submit_report`. A deterministic playbook analyst uses the same tools offline, so the pipeline works without an API key and gives a baseline to compare the LLM against. | `netsentinel/agent/` |
| Evaluation | Attack-level recall, alert precision and false alerts per day across seeds; seven checks per AI report. | `netsentinel/evaluate.py`, `netsentinel/agent/evals.py` |

## Run it

```bash
pip install -r requirements.txt
python -m pytest -q                         # 22 tests
python -m netsentinel compare               # the table above
python -m netsentinel run --seed 11         # new network, writes docs/data/demo.json
python -m netsentinel agent-eval            # grade the analyst
bash scripts/fetch_stratosphere.sh && python -m netsentinel real-eval   # real captures
python web/app.py                           # live dashboard on http://localhost:8000/?seed=11
```

To let Claude write the reports instead of the playbook analyst:

```bash
export ANTHROPIC_API_KEY=sk-ant-...         # or NETSENTINEL_LLM_URL=https://your-proxy
python -m netsentinel agent-eval --analyst claude
```

The same seven checks grade both analysts, so the comparison is like for like.

## Honest limits

- The lab data is simulated. The real-traffic evaluation uses public research captures of single machines over about a day each. That tests the C2 and scan detectors on real malware, but not lateral movement across a real company network, and not the anomaly model, which needs a clean baseline.
- The Windows real-data numbers come after the two changes described above, which were made while looking at that dataset, so they are development results. The IoT-23 numbers are the blind test.
- The playbook analyst is written for these seven attack types; its perfect score shows the harness works, not that it generalises. Generalising is the LLM analyst's job, and the eval exists to measure it.
- No organisation's private logs were used at any point.

## Tiếng Việt

NetSentinel là một SOC mini có AI:
- **Phát hiện:** luật, mô hình bất thường cho từng máy và bộ phát hiện beaconing cùng theo dõi lưu lượng, đăng nhập và DNS của một mạng doanh nghiệp mô phỏng 54 máy.
- **Gom sự cố:** các cảnh báo được nối thành chuỗi tấn công.
- **Điều tra:** một AI analyst dùng công cụ chỉ-đọc để điều tra từng sự cố, rồi viết báo cáo song ngữ và nêu rõ khi nào là báo động giả.

Trên 5 mạng sinh độc lập, cách kết hợp phát hiện **7/7** cuộc tấn công với **0,4** báo nhầm mỗi ngày.

**Trên dữ liệu thật:** 28 bản ghi Zeek công khai của phòng lab Stratosphere (Đại học Kỹ thuật Séc), gồm 662 giờ và 664.922 flow từ các máy Windows nhiễm Trickbot, Dridex, Kovter, Bladabindi và Cridex. Hệ thống phát hiện **14/18 ngày-máy bị nhiễm**, độ chính xác cảnh báo **73%**, **2,2 báo nhầm/ngày** và không báo nhầm lần nào trên các ngày sạch. Dữ liệu thật làm lộ một lỗi mà lab mô phỏng không có: gói multicast IPv6 bị coi là máy trên Internet. Sau khi sửa lỗi này, độ chính xác tăng từ 34% lên 95% trước khi khai báo mạng nội bộ. Cridex vẫn là điểm yếu (1/5).

**Kiểm tra mù trên IoT-23:** bộ phát hiện được giữ nguyên và chạy đúng một lần trên 20 bản ghi thiết bị IoT nhiễm Mirai, Torii, Hajime, Okiru và các botnet khác (1,5 triệu flow). Kết quả: phát hiện **16/20 thiết bị**, độ chính xác **80%**, 4,2 báo nhầm/ngày. Các ca bỏ sót là mã độc rất "im lặng" (Torii, Trojan) chỉ có 4–16 flow độc hại.

---

Built by **Vu The Vinh** · [Portfolio](https://vuthevinh2125.github.io/portfolio/) · MIT License
