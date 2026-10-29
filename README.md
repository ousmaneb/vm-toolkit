# vmtoolkit

A vulnerability management toolkit for a security team. It collects scan results from Nessus,
OpenVAS/Greenbone and Trivy, adds threat intelligence to every CVE, ranks open findings by real risk,
and turns them into a patch plan, tickets, alerts and plain-English reports for the CEO and CISO.

Most vulnerability backlogs are too long to fix in order of severity score. The toolkit answers the
questions a team actually has to decide on:

- **Which findings matter now?** It checks every CVE against CISA's Known Exploited
  Vulnerabilities list, EPSS exploit likelihood, NVD details and public exploit code, then weighs
  them against how important and how exposed each machine is. Every rank comes with its reasons.
- **What is the least work that removes the most risk?** It groups findings into fixes (one update
  often closes dozens of findings on many machines) and orders them by risk removed.
- **Are we keeping up?** It tracks deadlines per severity, forecasts which findings will miss
  them, and keeps a day-by-day history of the numbers, rankings and plans.
- **What do leaders need to know?** It writes CEO and CISO reports with a red/amber/green status,
  trends, recommendations and questions to ask, in language people outside security can follow.

It runs as one command, `vmt`, with a subcommand per tool, and a dashboard in the browser that runs
every tool. Every tool reads and writes the same SQLite database (`data/vmt.db` by default). In
production it runs as one container that pulls from Nessus, processes, alerts and backs up every
morning on its own.

Works on Windows, macOS and Linux with Python 3.11 or newer.

## Vulnerability management steps

Vulnerability management is a repeating cycle. This table shows which steps the toolkit covers and
which tools do the work.

| # | Step | Status | Tools |
|---|---|---|---|
| 1 | **Know your assets**: every machine, how important it is, whether it's reachable from the internet | Partial | Machines are recorded from scans; importance and exposure are set in `[assets]` in `config.toml`. No owners yet. |
| 2 | **Discover vulnerabilities**: regular scans of machines, containers and code dependencies | Built | `vmt nessus pull`, `vmt import` (Nessus, OpenVAS/Greenbone, Trivy), `vmt deps` |
| 3 | **Combine and clean up**: one format, no duplicates, false positives removed | Built | `vmt import`, `vmt dedupe`, `vmt fp` |
| 4 | **Add threat context**: is it exploited, how likely, how severe, is there exploit code | Built | `vmt enrich` (CISA KEV, EPSS, NVD, Exploit-DB, Metasploit), `vmt monitor`, `vmt exploit-model`, `vmt classify`, `vmt extract` |
| 5 | **Prioritise by risk**: likelihood × impact × machine importance × exposure | Built | `vmt prioritize`, with written reasons for every rank |
| 6 | **Plan the fixes**: group findings into updates, set deadlines by severity | Built | `vmt plan`, `[sla_days]` |
| 7 | **Fix or reduce the risk**: patch, reconfigure, isolate, or accept the risk | Partial | `vmt tickets` (files, Jira, ServiceNow), `vmt triage` for fix steps. No formal risk acceptance with an expiry date yet. |
| 8 | **Verify**: confirm each fix with a later scan | Built | A finding is marked fixed only when a later scan of the same machine stops reporting it; tickets close when all their findings are fixed. |
| 9 | **Monitor continuously**: newly exploited CVEs, deadline risks, failed runs | Built | `vmt alert`, `vmt forecast`, `vmt daily` with `vmt schedule` or `vmt serve` |
| 10 | **Measure and report**: open, overdue, time to fix, on-time rate, trends | Built | `vmt dashboard`, `vmt history`, `vmt report` (CEO and CISO PDFs) |
| 11 | **Improve the process**: find and fix root causes | Partial | Report recommendations and the History page show the trend. No breakdown by team or software yet. |

8 of the 11 steps are built and 3 are partial. Planned next: risk acceptance with an expiry and
approver (step 7), machine owners and teams (step 1), and root-cause breakdowns (step 11).

## Architecture

![System diagram: scan files, Nessus over Tailscale, threat feeds, GitHub and news, and an optional AI provider feed one service. Inside it, vmt serve runs the dashboard and a scheduler, both run vmt commands, and the commands read and write the /data volume. The service reaches the team over HTTPS with sign-in, alert channels, CEO and CISO reports, ticketing and off-site backups.](docs/architecture.svg)

Everything runs in one service. `vmt serve` hosts the dashboard and a scheduler; both run the same
`vmt` commands, each in its own process, and every command reads and writes one SQLite database on
the `/data` volume. The only way in from the internet is the team's HTTPS connection to the
dashboard, behind sign-in. Nessus is reached over a private Tailscale network.

![The daily routine: pull from Nessus, enrich, find duplicates, prioritize, patch plan, forecast, save history, GitHub and news, back up, alerts, and the report on report day. If the pull fails, the routine skips the processing steps, still backs up, and sends an alert.](docs/daily-routine.svg)

Once a day the scheduler runs `vmt daily`. If the Nessus pull fails, it skips the steps that would
only re-process yesterday's data, still backs up, and alerts you instead of writing a report. The
weekly report only goes out after a clean run.

To run it for a team in the cloud (Railway, Azure or AWS), see [DEPLOY.md](DEPLOY.md). The rest
of this file covers running it on one computer.

## Setup

### macOS and Linux

```sh
cd vm-toolkit
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dashboard,ml,llm,report,backup]"
vmt init
```

### Windows (PowerShell)

```powershell
cd vm-toolkit
py -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e ".[dashboard,ml,llm,report,backup]"
vmt init
```

If PowerShell refuses to run `Activate.ps1`, run
`Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once, or use `.venv\Scripts\activate.bat` from `cmd`.

### Folder names containing `:`

Python's `venv` refuses to create an environment inside a path containing the path-list separator
(`:` on macOS and Linux, `;` on Windows), for example `~/dev/AI:ML Engineer/`. Either rename the
folder or put the environment elsewhere:

```sh
python3 -m venv ~/.venvs/vmtoolkit
source ~/.venvs/vmtoolkit/bin/activate
pip install -e ".[dashboard,ml,llm,report,backup]"
```

### Configuration

`vmt init` creates two files in the current folder:

- `config.toml`: settings (Nessus URL, fix deadlines, alert channels, cache times). Relative paths in
  it are resolved against the folder the file is in.
- `.env`: API keys and passwords. Nothing secret goes in `config.toml`. Secrets are never printed;
  log lines are scrubbed of any secret the toolkit has read.

Both are in `.gitignore`. `vmt` looks for `config.toml` in the current folder; use
`vmt --config path/to/config.toml ...` or set `VMT_CONFIG` to run it from anywhere.

Global options that work with every command:

| Option | Effect |
|---|---|
| `--config PATH` | Use this config file. |
| `--db PATH` | Use this database file instead of `<data_dir>/vmt.db`. |
| `--offline` | Answer only from the web cache; fail clearly if something isn't cached yet. |

## 1. Nessus connector: `vmt nessus`

Pulls every completed run of every scan from the Nessus API, saves the raw responses as a backup,
and imports them.

Setup:

1. In Nessus, go to Settings > My Account > API Keys and generate keys. Put them in `.env` as
   `NESSUS_ACCESS_KEY` and `NESSUS_SECRET_KEY`. You can use `NESSUS_USERNAME` and `NESSUS_PASSWORD`
   instead.
2. Set `[nessus] url` in `config.toml`.
3. Nessus uses a self-signed certificate. The safe fix is to download its CA from
   `https://<nessus-host>:8834/getcert`, save it (e.g. `nessus-ca.pem`) and set
   `ca_cert = "nessus-ca.pem"`. The certificate is issued for the Nessus host name, so use that
   name in `url`, not an IP address. As a last resort, `verify_tls = false` turns checks off and
   prints a warning on every run.

```sh
vmt nessus check        # log in and show the Nessus version
vmt nessus scans        # list scans and how many runs each has
vmt nessus pull         # download and import everything new
vmt nessus pull --scan 12 --scan 15
vmt nessus reimport     # rebuild the database from the backups, without contacting Nessus
```

- **Backups:** raw files go to `data/raw/nessus/<scan id>-<name>/<run id>/`. Each run folder holds
  `scan.json` (the API's scan details) and `report.nessus` (the full export). If the export
  endpoint is unavailable, the connector falls back to per-host and per-plugin JSON in `hosts/`.
- **Repeat pulls:** runs already on disk are not downloaded again.
- **Incomplete runs:** only completed runs are used. A cancelled or aborted scan could otherwise
  make findings look fixed.
- **Expired license:** keep the `data/raw` folder. `vmt nessus reimport` rebuilds everything from
  it.

## 2. Normalizer: `vmt import`

Every scanner's output is converted to one finding format and stored in the database.

```sh
vmt import scan1.nessus gvm-report.xml
vmt import trivy.json --host docker-01.lab     # attach Trivy results to a machine
```

| Scanner | Input |
|---|---|
| Nessus | `.nessus` v2 files (from the UI or the API) |
| OpenVAS / Greenbone | GVM XML report (Reports > Download > XML) |
| Trivy | `trivy image|fs|rootfs|vm ... --format json` |

The format is detected from the file contents; `--format` overrides it.

### How first seen, last seen and fixed are worked out

- **Matching across scans:** each finding is identified by scanner, machine, rule or plugin ID,
  port and package.
- **First and last seen:** the earliest and latest scans that reported it.
- **Fixed:** a finding is marked fixed on the date of the first later scan by the same scanner
  that reached the same machine and no longer reported it.
- **Unreachable machines:** a machine missing from a scan proves nothing, so its findings stay open.
- **Credentialed scans:** a finding last seen by a credentialed scan is not marked fixed by an
  uncredentialed one, because that scan can't see local checks. The finding's `status_note` says
  so.
- **Import order:** dates are recalculated from the full history on every import, so scans can be
  imported in any order.
- **Limitation:** if you remove a plugin family from a scan policy, its findings will look fixed.

Other details:

- Nessus "info" findings (inventory such as open ports and OS detection) are skipped unless
  `[import] include_info = true`.
- Trivy's `UNKNOWN` severity is stored as `low` so those findings stay visible.

## 3. Enrichment: `vmt enrich` and `vmt cve`

```sh
vmt enrich                     # every CVE in the database
vmt enrich --cve CVE-2021-44228
vmt enrich --no-nvd            # skip the slow NVD step
vmt cve CVE-2021-44228         # explain one CVE in plain words
```

| Data | Source | Cached for |
|---|---|---|
| Known exploited | CISA KEV JSON feed (whole catalog) | 12 h |
| EPSS score and percentile, kept as daily history | api.first.org | 12 h |
| CVSS score and vector, attack vector, CWE, description, NVD status | NVD API 2.0 | 7 days |
| Public exploit | Exploit-DB `files_exploits.csv` and Metasploit `modules_metadata_base.json` (exploit modules only) | 7 days |

- **NVD rate limits:** NVD allows 5 requests per 30 seconds without a key, so a few hundred CVEs
  take a while the first time. Request a free key at https://nvd.nist.gov/developers/request-an-api-key
  and put it in `.env` as `NVD_API_KEY`. The key is sent as a header and is not stored in the cache
  file.
- **Exploit answers:** "Public exploit: yes" names the matching Exploit-DB ID or Metasploit module.
  "No" only means neither list has one.
- **CVSS version:** NVD's own CVSS v3.1 score is preferred, then v3.0, v4.0 and v2.
- **Non-CVE IDs:** advisories without a CVE (for example a GHSA-only Trivy finding) can't be
  enriched.
- **Cache times:** change them in `[cache]` in `config.toml`. The cache lives in
  `data/cache.sqlite`.

## 4. Dependency checker: `vmt deps`

```sh
vmt deps requirements.txt
vmt deps path/to/project              # finds requirements*.txt, package.json, package-lock.json
vmt deps path/to/project --save --host app-01.lab
```

Results come from OSV.dev, cached for 24 hours.

- **`requirements.txt`:**
  - `==` pins are checked exactly.
  - Ranges such as `>=2.0` or `~=1.4` are checked at their lowest allowed version and labelled as
    a range, because the installed version may be newer.
  - Lines with no lower bound are listed as skipped.
  - `-r` includes are followed.
- **`package.json`:** only has version ranges (`^4.17.0`). If a `package-lock.json` sits next to
  it, the lock file is used instead, because it has the exact installed versions.
- **Duplicates:** OSV often lists one problem under several IDs (GHSA and PYSEC). These are merged
  into one result, keeping the entry that has a severity rating. Entries with no rating at all
  show as `UNRATED`.
- **`--save`:** stores the results as findings (scanner `osv`). They show up in the dashboard and
  are marked fixed when a later `--save` run no longer finds them.

## 5. Alert bot: `vmt alert`

```sh
vmt alert --dry-run     # show what would be sent
vmt alert               # refresh KEV and EPSS, then send new alerts
```

It alerts on CVEs that belong to open findings when:

- **KEV:** the CVE is on the CISA KEV list.
- **EPSS:** the CVE's EPSS score rose by at least `[alerts] epss_jump` (default 0.10) since the
  previous stored score.

Each alert says why it fired and which machines are affected. It is sent once per channel, and a
channel that fails (Slack down, say) is retried on the next run.

Channels, set in `[alerts] channels`:

- `console`: prints, and appends to `data/alerts.log`. For scheduled runs, the log file is where
  you'll see them.
- `slack`: create an incoming webhook (Slack > Apps > Incoming Webhooks) and put it in `.env` as
  `SLACK_WEBHOOK_URL`.
- `email`: fill in `[email]` in `config.toml`, and put `SMTP_USERNAME` and `SMTP_PASSWORD` in
  `.env`. Port 587 uses STARTTLS and port 465 uses implicit TLS.

### Running it daily

`vmt daily` runs `vmt alert` as one of its steps; see [Automatic daily run](#automatic-daily-run-vmt-daily-and-vmt-schedule).
To schedule only the alert instead, the commands below still work. Use full paths, because schedulers
don't run your shell profile. The examples assume the project is at `~/vm-toolkit` (Windows:
`C:\vm-toolkit`).

**Windows (Task Scheduler)**, from `cmd` or PowerShell:

```powershell
schtasks /Create /SC DAILY /ST 08:00 /TN "vmtoolkit alert" /TR "\"C:\vm-toolkit\.venv\Scripts\vmt.exe\" --config \"C:\vm-toolkit\config.toml\" alert"
```

Check it with `schtasks /Query /TN "vmtoolkit alert"` and remove it with
`schtasks /Delete /TN "vmtoolkit alert"`. To run it while you're logged out, open Task Scheduler,
edit the task and choose "Run whether user is logged on or not".

**Linux (cron)**: run `crontab -e` and add:

```
0 8 * * * $HOME/vm-toolkit/.venv/bin/vmt --config $HOME/vm-toolkit/config.toml alert >> $HOME/vm-toolkit/data/cron.log 2>&1
```

**macOS (launchd, recommended)**: launchd runs a missed job when the Mac wakes up, which cron
doesn't. Save this as `~/Library/LaunchAgents/com.vmtoolkit.alert.plist`, replacing `YOU` with your
user name:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.vmtoolkit.alert</string>
  <key>ProgramArguments</key>
  <array>
    <string>/Users/YOU/vm-toolkit/.venv/bin/vmt</string>
    <string>--config</string><string>/Users/YOU/vm-toolkit/config.toml</string>
    <string>alert</string>
  </array>
  <key>StartCalendarInterval</key><dict><key>Hour</key><integer>8</integer><key>Minute</key><integer>0</integer></dict>
  <key>StandardOutPath</key><string>/Users/YOU/vm-toolkit/data/launchd.log</string>
  <key>StandardErrorPath</key><string>/Users/YOU/vm-toolkit/data/launchd.log</string>
</dict>
</plist>
```

Then run `launchctl load ~/Library/LaunchAgents/com.vmtoolkit.alert.plist`. Test it right away with
`launchctl start com.vmtoolkit.alert`.

**macOS (cron)** also works: use the Linux line above. cron may need Full Disk Access
(System Settings > Privacy & Security) if the project is in Documents or Desktop.

## 6. Dashboard: `vmt dashboard`

```sh
vmt dashboard                         # real data
vmt --db data/fake.db dashboard       # fake demo data
```

It starts a local web page at http://localhost:8501 (change with `--port`), reachable only from this
computer. It follows your system's light or dark setting.

The menu on the left groups the pages by workflow step: **Overview** (Home, Dashboard, History and Reports), **Bring in
data**, **Understand the risk**, **Fix and report**, **Threat intelligence**, **AI assistant** and
**Settings**. Below the menu, **Database** picks which `.db` file in `data/` every page uses ("Live
data" is `vmt.db`, "Demo data" is `fake.db`), and **Offline mode** makes tools use cached web data
only.

A yellow banner appears on every page whenever the database contains fake data.

### Home

- **Headline numbers:** open findings, critical or high, overdue, and open findings whose CVE is
  known-exploited (on CISA KEV).
- **Next step:** what to do next, worked out from the database: import scans, enrich CVEs, prioritize,
  make a patch plan, or review the dashboard.
- **Workflow:** one card per step, with a link to each tool.

### Dashboard

The database is opened read-only. Info-level findings and false positives are left out.

- **Filters** by machine and scanner, at the top.
- **Summary:** open findings, critical and high open, overdue count, and average days to fix.
- Tabs:
  - **Open findings:** count by severity, and how long they have been open. Age counts from the first
    scan that found the problem.
  - **Top priorities:** the latest Prioritize ranking with its explanations.
  - **Overdue:** findings past their deadline, from `[sla_days]` in `config.toml` (defaults:
    critical 15, high 30, medium 90, low 180 days), and the ones Deadline forecast expects to miss it.
  - **Time to fix:** average and median days per severity.
  - **Trend:** open findings per week, and found vs. fixed per week, with a table view.

### Reports and Automation

- **Reports:** create the CEO and CISO PDFs for any period and download them straight away, or
  download saved ones. See
  [Leadership reports](#leadership-reports-vmt-report).
- **Automation** (under Settings): whether `vmt daily` is scheduled, buttons to install or remove the
  schedule (installing needs a tick first), a button to run the routine now, and the recent runs
  with their logs. See [Automatic daily run](#automatic-daily-run-vmt-daily-and-vmt-schedule).

### Tool pages

Each tool has its own page: a one-line description, badges (Ready or which `.env` key is missing,
Uses the internet, Updates the database, Takes minutes, Can cost money), its options, and a **Run**
button. Results show below, with how long the command took. **Run it from a terminal instead** shows
the exact `vmt` command. The last result of each tool stays until you close the tab.

- **Uploads:** Import scan files, Check dependencies and Read an advisory take files from the
  browser. They are saved to a temporary folder under their own file name and passed to the command.
- **Confirmation:** anything that costs money or reaches outside this computer needs a tick first:
  LLM calls (Read an advisory with the LLM, Triage without preview, Ask a question), sending tickets to
  Jira or ServiceNow, and alerts to Slack or email. Triage starts in preview mode, which is free.
- **Long jobs:** Exploit prediction, Weakness classifier and GitHub and news can take minutes. Keep
  the page open; leaving it stops the command.
- **Setup status** (under Settings) lists which `.env` keys are filled in, by name only. Restart the
  dashboard after editing `.env`.
- Tool pages write to the database picked in the sidebar; the Home and Dashboard pages don't.

## Machine settings

Tools 7–10 use per-machine settings from `config.toml`:

```toml
[assets."web-01.lab"]
criticality = "high"          # low | medium | high | critical
internet_facing = true
aliases = ["192.168.56.10", "docker-web"]   # other names scanners use for this machine

[assets."*-dev-*"]            # wildcards work; exact names win over wildcards
criticality = "low"
```

Use the machine names as the scanners report them (`vmt prioritize` shows them). Machines not listed
count as `medium` and not internet-facing, and the explanations say so.

## 7. Prioritization: `vmt prioritize`

```sh
vmt prioritize                 # top 20
vmt prioritize --top 50 --machine db-01.lab
vmt prioritize --explain 412   # full reasoning for finding 412
```

Each open finding gets a score from 0 to 100:

```
score = 100 x likelihood x impact x machine importance x exposure
```

| Factor | Where it comes from |
|---|---|
| Likelihood | 1.0 if any of its CVEs is on CISA KEV. Otherwise the highest EPSS score among its CVEs, raised to `exploit_floor` (0.5) if Exploit-DB or Metasploit has a public exploit. Without an EPSS score (no CVE, or not enriched yet) a default per severity is used. |
| Impact | CVSS / 10: the scanner's score, else NVD's, else a typical value for the severity. |
| Machine importance | low 0.25, medium 0.5, high 0.75, critical 1.0. |
| Exposure | 1.0 if the machine is internet-facing and the CVE is network-exploitable (unknown vectors count as network), otherwise `internal_factor` (0.8). |

How the ranking is put together:

- **Duplicates:** it runs `vmt dedupe` first and counts each duplicate group once, using the CVEs
  from every report in the group.
- **Ties:** findings with equal scores are ordered by how long they've been open.
- **Explanations:** `--explain` lists every factor with its source, the arithmetic, and why the
  finding sits below the one above it.
- **Storage:** the ranking is saved in the `priorities` table, and the dashboard shows the top 15.
- **Tuning:** weights and defaults are in `[prioritize]` in `config.toml`. The formula is a
  heuristic, not a calibrated model.

## 8. Patch planner: `vmt plan`

```sh
vmt plan                     # fixes that cover 80% of the risk
vmt plan --target 95
vmt plan --max-fixes 5
vmt plan --explain 1         # what fix 1 closes and why it ranks first
```

Open findings are grouped into fixes:

- **Package findings** (Trivy, OSV, Nessus local checks): one upgrade per package. The target is
  the highest fixed version any of its findings needs, so a single upgrade across all affected
  machines closes all of them.
- **Other findings:** grouped by the scanner's solution text.
- **No solution text:** the finding becomes its own fix.

How the order is worked out:

- **Order:** each fix's risk is the sum of the priority scores of the findings it closes, and
  fixes are listed from most to least risk removed, with a running total.
- **Why this is optimal:** every finding belongs to exactly one fix, so the first N fixes in this
  order always remove the most risk any N fixes can.

Limitations:

- **Separate Nessus plugins:** they are only merged when their solution text matches, so two
  OpenSSL plugins that recommend different versions show up as two fixes.
- **Effort:** it isn't modelled. Every fix counts as one unit of work.

## 9. Duplicate detector: `vmt dedupe`

```sh
vmt dedupe
```

Finds findings from different scanners that describe the same problem on the same machine. It runs
automatically before `vmt prioritize`, `vmt plan` and `vmt tickets`.

- **Same machine:** the same name, a shared IP, the same short host name (`web-01` and
  `web-01.lab`), or listed as `aliases` in `[assets]`.
- **Same problem:** checked in this order:
  1. A shared CVE (high confidence).
  2. The same package and installed version (high confidence).
  3. For findings with no CVE: the same port and protocol with titles at least 80% alike (medium
     confidence).
- **One scanner, two reports:** never treated as duplicates. They are separate ports or packages.

Every match prints the reason, for example "fake-app-01.lab (nessus) and fake-app-01.lab (openvas)
both report CVE-2099-1001". Nothing is deleted: duplicates are listed in the `duplicates` table, and
the most severe report in each group is the one that gets counted.

## 10. Ticket generator: `vmt tickets`

```sh
vmt tickets                       # one ticket per fix from the plan
vmt tickets --max-fixes 10
vmt tickets --push jira
vmt tickets --push servicenow
```

Each ticket is written as Markdown and JSON to `data/vmt-tickets/`. With `--db data/fake.db` they go
to `data/fake-tickets/` instead. Each ticket covers one fix:

- the fix steps and affected machines
- every finding it closes, with score and CVEs
- a priority with its reason: P1 at score 70 and up, P2 at 40 and up, P3 at 15 and up, otherwise P4
- a due date with its reason: the earliest `[sla_days]` deadline among its findings

How tickets change over time:

- **Stable IDs:** ticket IDs (`VMT-1c474547`) come from the fix, so running the command again
  updates the same tickets.
- **Resolving:** after a rescan, a ticket whose findings are all fixed is marked resolved, and
  reopened if they come back.
- **Pushed updates:** an existing Jira issue or ServiceNow incident is only updated when the
  findings, scores, priority or due date change. A shift in plan position alone doesn't trigger
  an update.

**Jira Cloud.** Set `[jira] url` and `project` in `config.toml`, and put `JIRA_EMAIL` and
`JIRA_API_TOKEN` in `.env` (create a token at https://id.atlassian.com/manage-profile/security/api-tokens).

- Issues are created with the REST API v2, labelled `vmtoolkit`, the priority and the ticket ID.
- Jira workflows differ between projects, so when a ticket resolves, vmtoolkit adds a comment
  instead of moving the issue. You close it yourself.

**ServiceNow.** Set `[servicenow] instance` in `config.toml`, and put `SN_USERNAME` and
`SN_PASSWORD` in `.env`.

- Records are created in the `incident` table (change it with `table`), with `correlation_id` set
  to the ticket ID and urgency and impact taken from the priority.
- On resolve, it sets `state` to `resolved_state` (6) with `close_code` and close notes. Check that
  these values match your instance.

Pushing sends machine names and finding details to your Jira or ServiceNow instance. The Jira and
ServiceNow code is tested against mocked responses only.

## 11. Exploit prediction model: `vmt exploit-model`

Needs `pip install -e ".[ml]"`.

```sh
vmt exploit-model evaluate     # backtest against EPSS as of a year ago (both feature sets)
vmt exploit-model evaluate --cutoff-days 540 --window-days 730
vmt exploit-model train        # train on all CVEs with today's KEV labels
vmt exploit-model score        # score the CVEs in your database
vmt cve CVE-2024-3400          # also shows the model's score once you've run `score`
```

A logistic regression predicts whether a CVE ends up on CISA KEV.

**Training data:**

- NVD's yearly JSON 2.0 feeds from `[exploit_model] first_year` (2015) onward: about 25 MB per
  year, kept in `data/raw/nvd-feeds/`.
- The KEV catalog as the label.

**Features:** only things known when the CVE is published:

- the issuer's (CNA's) CVSS vector and CWE
- affected vendors
- the words in the description

**Left out on purpose,** because they reveal exploitation after the fact:

- the `cisa*` fields, which mark KEV membership directly
- CISA's SSVC data, which says "exploitation: active"
- references, which gain "Exploit" tags later
- the NVD analysis status

**Feature sets:**

- `strict` (default): only issuer-provided data.
- `full`: adds NVD's own CVSS, CWE and CPE vendors. NVD analyses KEV entries first, so the mere
  presence of NVD data partly gives the answer away. `evaluate` runs both so you can see how much
  that inflates the result.

**How `evaluate` compares with EPSS:**

- It picks a cutoff date (default 365 days ago).
- The model trains on CVEs published before the cutoff, with KEV labels as of that date.
- Both the model and EPSS (its published scores from the cutoff day, from the EPSS archive) score
  the CVEs published in the 2 years before the cutoff that weren't on KEV yet.
- They're judged on which of those CVEs were added to KEV afterwards.
- Reported: average precision with a bootstrap 95% range on the difference, and the hit rate in
  each method's top 1%. The report is saved to `data/models/exploit-evaluation.txt`.

**First real backtest** (cutoff 2025-10-29, 326,781 CVEs from 2015-2026, 1,606 on KEV):

| Feature set | Model AP | EPSS AP | Difference (95% range) |
|---|---|---|---|
| strict | 0.0068 | 0.0140 | -0.0072 (-0.049 to +0.012) |
| full | 0.0112 | 0.0140 | -0.0027 (-0.045 to +0.028) |

AP is average precision; random guessing would score 0.0003. Reading the result:

- **EPSS came out ahead,** but within the noise. Only 66 CVEs that already existed at the cutoff
  were added to KEV in the following year, which is too few to separate the two methods.
- **Most new KEV entries are newly published CVEs,** which can't be part of a fair comparison,
  because EPSS had no score for them on the cutoff date.
- **The `full` feature set does better** than `strict`, as expected from the NVD-analysis leak.

**Running time and memory:**

- The first run downloads about 300 MB and needs about 6 GB of RAM while reading the feeds.
- Later runs read the cached records in `data/models/nvd-records/` and peak at about 3 GB.
- A full `evaluate` takes 4-6 minutes on a laptop.

**Limitations:**

- EPSS uses live exploitation data this model can't see, so expect EPSS to win. The model is an
  explainable second opinion, not a replacement.
- NVD only publishes the current version of each record, so later edits to descriptions or CNA
  data can still leak some hindsight.
- KEV favours vendors that US federal agencies use, and the model learns that bias too.
- Predictions are stored in `exploit_predictions` with their reasons ("Raised by: vendor ivanti,
  CVSS privileges required is none ..."). They do not change `vmt prioritize`.

## 12. False-positive predictor: `vmt fp`

```sh
vmt fp mark 412 413 --reason "banner check; Debian backports the fix"
vmt fp mark 500 --real              # confirm a finding is a real issue
vmt fp unmark 412
vmt fp list
vmt fp predict                      # flag open findings that look like your false positives
```

Marks are stored in the `fp_labels` table and never delete anything. Findings marked false positive
are left out of `vmt prioritize`, `vmt plan`, `vmt tickets`, `vmt alert` and the dashboard until you
unmark them.

`predict` learns from three kinds of example:

- findings you marked false positive
- findings you marked `--real`
- findings that were later fixed, which count as "real" at half weight, since a finding going away
  after patching usually means it was real

It works in one of two modes:

- **Fewer than 30 false-positive marks: similarity.**
  - An open finding is flagged when it comes from the same scanner rule as findings you marked.
  - The estimate is (false positives + 0.5) / (false positives + real-or-fixed + 1), so a single
    mark never means certainty.
  - It gets +0.10 when the scanner output is at least 80% alike to a marked false positive, and
    more alike to it than to any real one.
  - Example reason: "You marked 2 finding(s) from the same nessus rule 7001 as false positives (on
    web-01, web-02) and none as real or fixed; its scanner output is 99% alike to finding 18's."
- **30 or more: model.**
  - A logistic regression uses the scanner, rule, severity, port, whether the scan was
    credentialed, and the words in the title and scanner output.
  - Its quality is cross-validated on your explicit marks only (fixed findings would flatter it),
    with a warning while there are fewer than 100.
  - Each flag lists the features that pushed it toward "false positive".

Findings are flagged above `[fp] threshold` (0.5). Flags are stored in `fp_predictions` and are only
suggestions. Nothing is hidden until you confirm it with `vmt fp mark`.

The fake data includes a false-positive pattern (banner-based version checks on a vendor that
backports fixes) with about 70 fake marks, so you can try model mode. The model scores perfectly on
it because the pattern is easy. Expect lower numbers on your own marks.

## 13. Fix-time forecaster: `vmt forecast`

```sh
vmt forecast                     # open findings likely to miss their deadline, with reasons
vmt forecast --all               # every open finding
vmt forecast --backtest-days 60  # check forecasts made 60 days ago against what happened
```

**Why not a plain average.** Averaging the time-to-fix of fixed findings understates it, because
the slowest findings are still open and left out. The forecaster uses Kaplan-Meier survival curves,
which count an open finding as "not fixed yet after N days". The dashboard's time-to-fix table shows
this estimate next to the plain average as `median_days_incl_open`.

**Which history it learns from.** It uses the most specific group with at least 10 past fixes:

1. the same severity on the same machine
2. the same severity on machines with the same `criticality` in `[assets]`
3. the same severity on all machines
4. all findings

**What it predicts.** For each open finding it gives the chance of being fixed by its
`[sla_days]` deadline, given how long it has already been open. Example: "Based on 37 past fixes
of high findings on low-importance machines: of those still open at day 25, 30% were fixed by day
30 (its deadline, 2026-11-03), and half of them were fixed by day 41."

- **At risk:** below 50%.
- **Overdue:** findings already past their deadline are listed as overdue, not forecast.
- **Alerts:** at-risk critical and high findings are included in `vmt alert` (turn off with
  `[alerts] deadline_warnings = false`), and at-risk findings appear on the dashboard.

**How much to trust it.** The backtest makes forecasts as of an earlier date and compares them with
what happened, for findings whose deadline has passed since then. It reports:

- the Brier score (0 is perfect), next to the score from always guessing the overall on-time rate
- how often each forecast range (0-25%, 25-50%, ...) actually came true

On the fake data it does better than that constant guess (0.179 vs 0.201).

**Limitations:**

- A new install won't have enough fix history for this to say much at first. Below 20 findings with a
  passed deadline, the backtest says so instead of reporting numbers.
- Fix dates are scan dates, so with weekly scans the forecasts are accurate to about a week.

## 14. Weakness and attack-vector classifier: `vmt classify`

Needs `pip install -e ".[ml]"`, and uses the NVD feeds that `vmt exploit-model` downloads (it
fetches them itself if needed).

```sh
vmt classify evaluate      # train on older CVEs, test on the past year
vmt classify train         # train on everything and save the model
vmt classify predict       # predict for your CVEs that NVD hasn't analysed
```

It reads a CVE's description and predicts two things:

- **Weakness type:** one of the 50 most common CWEs, or "other".
- **CVSS attack vector:** network, adjacent, local or physical.

Training labels come from NVD's analysis where it exists, and from the CVE issuer's data otherwise.
The model is word and phrase counts plus a linear classifier, so it runs offline and each prediction
names the words behind it, for example: "Predicted CWE-79 (71%) because the description mentions
'script', 'stored'; next most likely: CWE-80 9%, CWE-116 4%."

How predictions are used:

- **Which CVEs:** `predict` only covers your CVEs that are missing a CWE or attack vector, or that
  NVD lists as received, awaiting or undergoing analysis, or deferred.
- **Where they're kept:** in the `cve_predictions` table, never mixed into NVD's data. `vmt cve`
  shows them labelled "Not from NVD - predicted".
- **Effect on rankings:** when NVD has no attack vector and the prediction is at least 80%
  confident, `vmt prioritize` uses the prediction instead of assuming "network", and says so in
  the explanation.

## LLM features

Three tools can use a large language model: `vmt extract --llm`, `vmt triage` and `vmt ask`. They
are off until you configure them:

```toml
[llm]
provider = "..."   # the provider implemented in src/vmtoolkit/llm_provider.py
model = "..."      # that provider's model ID
effort = "medium"
send_hostnames = false

[llm.prices]       # optional, dollars per million [input, output] tokens, for the cost line
"model-id" = [1.0, 5.0]
```

Put the provider's API key in `.env` as `LLM_API_KEY`. All provider-specific code is in
`src/vmtoolkit/llm_provider.py`; the rest of the toolkit goes through `src/vmtoolkit/llm.py`, so a
different provider means replacing that one file.

## 15. Advisory extractor: `vmt extract`

```sh
vmt extract vendor-advisory.html
vmt extract https://httpd.apache.org/security/vulnerabilities_24.html
vmt extract advisory.pdf --llm           # use the LLM instead of the offline rules
```

It reads an HTML page, text or Markdown file, or PDF, and pulls out for each CVE:

- the affected versions ("2.4.0 through 2.4.58", "before 2.4.57", "Affects: 2.4.49")
- the fixed versions ("fixed in 2.4.59", "upgrade to 2.4.59 or later")
- the exploitation status: exploited in the wild, public proof of concept, not known to be
  exploited, or not stated
- the sentence each fact came from

Results are saved in `advisories` and `advisory_items`. Each CVE is listed with the machines where
it's still open, and `vmt triage` uses these facts as sources.

**Default: offline rules.**

- Scripts, navigation and footers are ignored.
- A sentence that names no CVE is credited to the CVE named just before it, which matches
  per-CVE sections on vendor pages.
- Text before the first CVE applies to all of them, but only on short advisories naming 3 CVEs or fewer.
- Rules miss unusual phrasing, so use `--llm` for messy articles.

**`--llm`: the LLM.**

- Needs `pip install -e ".[llm]"`, `[llm]` settings and `LLM_API_KEY`, and costs a few cents per advisory. Each
  run prints its token use and cost.
- The LLM must give every fact with a short quote copied from the document. The quote is checked
  against the text, and any fact whose quote isn't there, or that names a CVE the document doesn't
  contain, is dropped and counted.
- The advisory is sent as untrusted data: the LLM gets no tools, the answer must match a fixed
  schema, and instructions inside the advisory are ignored.
- Only the advisory text is sent, never anything from your database.

## 16. GitHub and news monitor: `vmt monitor`

```sh
vmt monitor      # then `vmt alert` to send any spikes
```

It looks for mentions of your open CVEs in two places:

- **GitHub:** new repositories, issues and pull requests created in the last 15 days. New repos
  are often proof-of-concept exploits.
- **News:** the RSS/Atom feeds in `[monitor.feeds]`. The defaults are CISA advisories, SANS ISC,
  BleepingComputer and The Hacker News, and you can add or remove feeds.

Mentions are stored in `mentions`, one row per CVE and item, so nothing is counted twice. On its first
run it fetches 15 days of GitHub history, so spike detection works right away.

**What counts as a spike:** at least 3 new mentions in the last 24 hours, and more than 3 standard
deviations above the average of the previous 14 days. Example: "CVE-2099-0001: 6 new mentions in
the 24 hours to 2099-06-01 (5 github repo, 1 news: SANS ISC), against an average of 0.0 a day over
the previous 14 days." A CVE that is always busy, like Log4Shell with its stream of dependency-update
PRs, doesn't trigger it. Spikes are saved in `chatter_spikes`, and `vmt alert` sends each one once.

**Rate limits:**

- GitHub allows 10 searches a minute without a token, so only the top `[monitor] max_cves` (50)
  open CVEs by priority are searched there, which takes about 10 minutes a day.
- A `GITHUB_TOKEN` in `.env` (a fine-grained token with no permissions is enough) raises that to
  30 a minute. The token is not stored in the cache.
- News feeds are checked for all open CVEs.
- Results are cached for 6 hours.

Only CVE IDs are sent to GitHub; nothing about your machines.

## 17. AI triage assistant: `vmt triage`

Needs `pip install -e ".[llm]"`, the `[llm]` settings (see [LLM features](#llm-features)) and `LLM_API_KEY` in `.env`.

```sh
vmt notes add CVE-2024-3400 "GlobalProtect is disabled on our firewall"
vmt notes add 412 "only reachable from the management VLAN"      # a finding number
vmt triage CVE-2024-3400 --show-prompt                    # see exactly what would be sent; sends nothing
vmt triage CVE-2024-3400
vmt triage 412 --refresh
```

The LLM explains the vulnerability in plain English under fixed headings:

- What it is
- Does it matter for us
- How to fix it
- How to check the fix worked
- Confidence and gaps

**Sources.** The answer is built only from documents assembled from your database, each sent with
citations turned on:

- the NVD record
- the CISA KEV entry
- EPSS and public exploits
- each scanner finding (with its output, suggested fix, machine importance and priority
  explanation)
- facts from advisories you ran through `vmt extract`
- model predictions, labelled as predictions
- your notes

Every claim is marked [1], [2], ... and the cited documents are listed at the end. If the sources
don't cover something, the answer says so.

**Privacy.**

- By default (`[llm] send_hostnames = false`), every name a machine goes by (name, FQDN and short
  host name) becomes one placeholder such as `MACHINE_1`, and IP addresses become `IP_1`. This
  happens everywhere, including scanner output and your notes. The real names are put back on your
  machine after the answer arrives.
- Version numbers that look like IPs but aren't valid addresses are left alone.
- `--show-prompt` prints the exact system prompt and documents that would be sent.
- Scanner output can contain other details, such as user names or paths, which are not removed, so
  check `--show-prompt` if that matters to you.

**Cost and caching.**

- The provider, model and effort come from `[llm]` (medium effort by default).
- Each run prints its token use, and its approximate cost if `[llm.prices]` lists the model.
- Answers are saved in `triage_results` and reused until the sources change. `--refresh` asks
  again.

**Safety.** The documents are marked as data, not instructions, which guards against prompt
injection from scanner output or advisories. If the AI provider's safety filter declines a
security question, the request falls back automatically to the model the provider recommends, and
the cost line says which model answered.

## 18. Plain-English questions: `vmt ask`

Needs `pip install -e ".[llm]"`, the `[llm]` settings (see [LLM features](#llm-features)) and `LLM_API_KEY` in `.env`.

```sh
vmt ask "which machines have known-exploited vulnerabilities older than 30 days?"
vmt ask "how many open critical findings does web-01 have?"
vmt --db data/fake.db ask --eval      # score it on the 20-question test set (20 API calls)
```

The LLM writes one SQLite `SELECT`, which runs on your machine. You see:

- what the query does, in plain words, so you can check it matches what you meant
- the SQL itself
- the results as a table

**What is sent.** Only the database layout (table definitions), some conventions, and your
question. Rows are never sent. Machine names in your question are replaced with placeholders
(`MACHINE_1`) and filled back into the SQL locally. `[llm] send_hostnames` turns this off.

**Why a query can't change anything:**

1. The database is opened read-only.
2. SQLite's authorizer allows only reading. Writes, `ATTACH`, `PRAGMA` and `load_extension` are
   refused.
3. Only one statement that starts with `SELECT` or `WITH` is accepted.
4. Queries stop after 10 seconds and 200 rows.

The tests try deletes, updates, drops, attaches, writable-schema pragmas and stacked statements, and
check the database is unchanged.

By default, findings you marked as false positives and duplicate reports are left out, the same as
in the rest of the toolkit.

**How well it works.** `--eval` asks 20 questions with known answers, such as "which machines have
open findings for CVEs known to be used in ransomware?", and compares each answer with a reference
query. An answer counts as right if any of its columns holds exactly the expected values, since
The LLM may pick different columns. Run it on the fake database to see how reliable the tool is
before trusting it with your own questions. It costs about 20 small API calls.

## Automatic daily run: `vmt daily` and `vmt schedule`

```sh
vmt daily                       # run the whole routine once
vmt schedule install            # run it every day at 07:00
vmt schedule install --time 06:30
vmt schedule status
vmt schedule remove
```

`vmt daily` runs these steps in order, each as its own `vmt` command:

1. `nessus pull`
2. `enrich`, `dedupe`, `prioritize`, `plan`, `forecast`, `history save`
3. `monitor`
4. `backup`, which runs even if the Nessus pull failed
5. `alert`
6. `report`, on `report_weekday` or whenever the newest report is more than 7 days old (so a
   missed day is caught up)

What happens when something fails:

- **Nessus pull fails** (server down, expired keys): steps 2, 3 and 5 are skipped, so yesterday's
  data isn't reported as today's. The alert step still runs and sends the failure through your
  alert channels.
- **Any other step fails:** the rest still run, the failure is sent as an alert, and the weekly
  reports wait until a run succeeds.
- Every step's output goes to `data/logs/daily-<date>.log`, and each run is recorded in the
  `daily_runs` table. The dashboard's **Automation** page shows the recent runs and their logs.

Settings, in `config.toml`:

```toml
[daily]
nessus = true              # turn off if you only import files by hand
monitor = true             # about a minute per 10 CVEs without a GITHUB_TOKEN
report_weekday = "monday"
```

`vmt schedule install` uses launchd on macOS (a run missed while the Mac was asleep happens when it
wakes), cron on Linux, and Task Scheduler on Windows. The scheduled run always uses the main
database from `config.toml`. Scheduler output goes to `data/logs/scheduler.log`. On Windows the task
only runs while you're logged in unless you edit it in Task Scheduler and choose "Run whether user
is logged on or not".

## History: `vmt history`

```sh
vmt history save                  # save today's numbers (vmt daily does this)
vmt history save --backfill 365   # also rebuild the past year from scan dates
vmt history show --days 90        # one line per day
vmt history on 2026-10-01         # numbers, top risks and patch plan on that day
```

Nothing that changes over time is thrown away:

- **Scans and findings:** every scan, which findings it saw, and each finding's first-seen,
  last-seen and fixed dates. Raw Nessus downloads stay in `data/raw/nessus/`.
- **Rankings and plans:** `vmt prioritize` and `vmt plan` replace the current ranking and plan, but
  each run is also copied into `priority_history` and `plan_history` under its date. A second run on
  the same day replaces that day's copy.
- **Daily numbers:** `vmt daily` saves one row per day in `history_snapshots`: open, critical or high,
  past deadline, actively exploited, found and fixed that day, on-time rate, total risk, and status.
- **Rebuilt days:** `--backfill` fills in days before history was kept, using first-seen and fixed
  dates. Those rows are marked rebuilt and have counts only, because the status, on-time rate and
  risk weren't recorded at the time. Days that already have a snapshot are never overwritten.
- Also kept: EPSS scores over time, alerts sent, every daily run with its log, and every report PDF.

"On a day" means the latest ranking and plan saved on or before that day. The top-risks list also
shows if and when each finding was fixed afterwards.

The dashboard's **History** page shows the numbers over time, lets you pick any day to see that
day's numbers, top risks and plan, and downloads the whole history as CSV.

Everything lives in `data/vmt.db`, so back up that file (and `data/raw/`) to keep the history safe.

## Leadership reports: `vmt report`

Needs `pip install -e ".[report]"`.

```sh
vmt report                      # both reports, last 7 days
vmt report --days 30            # last 30 days
vmt report --audience ceo --days 90
```

Create them whenever you need them, for any number of days, from the command line or the dashboard's
**Reports** page, which offers the PDFs for download as soon as they're made. `vmt daily` also
makes a weekly pair on `report_weekday`.

Files go to `data/reports/`:

- `<date>-ceo.pdf` and `<date>-ciso.pdf` for a 7-day report
- `<date>-ceo-30d.pdf` for other periods
- reports from another database get its name added, for example `2026-10-29-fake-ceo.pdf`

Nothing is emailed: review the reports and send them yourself.

**CEO summary (2 pages), written for readers without a security background:**

- **Page 1:**
  - **Status:** red, amber or green, with the reason.
    - Red: an actively exploited (CISA KEV) or critical vulnerability is past its deadline.
    - Amber: anything else past its deadline, or under 90% of recent fixes on time.
    - Green: neither.
  - **Headline numbers**, with the change since the start of the period.
  - A summary, a 12-week trend chart, the three highest-value fixes, and what needs attention.
- **Page 2, in plain business language:**
  - **What this means for the business:** how many weaknesses criminals are using against systems
    like ours, how many are linked to ransomware or reachable from the internet, what being past
    deadline means for insurers, customers and regulators, whether the backlog is growing, and how
    often fixes are on time.
  - **What we recommend:** numbered actions, most urgent first, for example fixing overdue actively
    exploited problems this week, approving time for the top updates, setting a maintenance window,
    or reviewing the computer with the most overdue problems.
  - **Questions to ask your team.**
  - **Terms used in this report:** a short glossary.

Both pages are worked out from the data each time, so the advice changes with the situation. When
there are no scan results from before the period, the report says there is no trend yet instead of
guessing one.

**CISO report:** the same two pages, then:

- Deadline compliance per severity: fixes in the last 90 days, share on time, average days to fix,
  open, past deadline
- Open actively exploited vulnerabilities
- The patch plan, with the share of risk each fix removes
- The top 10 individual risks
- Findings likely to miss their deadline in the next 30 days
- Machines with the most past-deadline findings
- When the data was last updated

Counts follow the dashboard: info-level findings and false positives are left out. Numbers for the
start of the period are rebuilt from first-seen and fixed dates, so the first report already has a
comparison. The patch plan and rankings come from the latest `vmt plan` and `vmt prioritize`, which
`vmt daily` runs first. Reports from demo data carry a FAKE DATA watermark on every page.

## Accounts, server mode and backups

```sh
vmt users add alice          # dashboard account; asks for the password
vmt users list
vmt users passwd alice       # new password; also clears a lockout
vmt users remove alice
vmt serve                    # dashboard + daily routine + backup, for containers
vmt backup                   # dated copy in data/backups/ (keeps 14), uploaded to [backup] target if set
```

**Sign-in:**

- Once any account exists, the dashboard asks everyone to sign in. With `VMT_ENV=production` it
  always does.
- Passwords are stored as salted scrypt hashes and must be at least 12 characters.
- Five wrong passwords lock an account for 15 minutes, and twenty failed sign-ins from one address
  block that address for 15 minutes.
- A sign-in lasts 8 hours across reloads, until you sign out or your password changes.
- Sign-ins and every tool run are logged with the username.

**`vmt serve`** runs the dashboard, plus `vmt daily` once a day at `[daily] time`. It is what the
container runs; see [DEPLOY.md](DEPLOY.md).

**Off-site backups:** set `[backup] target` to `s3://bucket/prefix` (AWS S3 or any S3-compatible
store) or `azure://container/prefix`, and `vmt backup` uploads each copy there and keeps the newest
`remote_keep`. Needs `pip install -e ".[backup]"`; see [DEPLOY.md](DEPLOY.md#backups) for the
credentials.

**Production mode:** `VMT_ENV=production` turns off demo data and hides the database picker.

## Fake data: `vmt fake-data`

A new install doesn't have enough history for trends or forecasting, so this generates a year
of weekly scans for 40 made-up machines:

```sh
vmt fake-data                    # writes data/fake.db
vmt fake-data --machines 10 --days 180 --seed 3 --force
```

Fake data is labelled four ways:

- It goes to its own file, never `vmt.db`.
- Every scan, machine and finding row has `is_fake = 1`.
- Machine names start with `fake-`, IPs come from 192.0.2.0/24 (a documentation-only range), CVE
  IDs use the year 2099, and titles start with `FAKE:`.
- The dashboard shows a banner.

It also has a few patterns for the ML tools to find:

- Dev machines fix about 2.5x slower, and database and domain-controller machines about 1.7x faster.
- A handful of banner-based checks misfire like real-world false positives, and about 70% of them
  carry fake false-positive marks (`fp_labels.is_fake = 1`).

The generator refuses to overwrite a file that contains any real scans. The same seed always
produces the same data.

## Data layout

```
data/
  vmt.db          the shared database
  fake.db         generated demo data (only if you ran vmt fake-data)
  cache.sqlite    cached responses from outside websites
  raw/nessus/     raw Nessus API backups
  alerts.log      console alerts
  vmt-tickets/    remediation tickets (fake-tickets/ for fake.db)
  reports/        weekly CEO and CISO PDFs
  logs/           daily run and scheduler logs
```

Main tables:

| Table | Contents |
|---|---|
| `assets` | Machines |
| `scans` | One row per scan run |
| `scan_hosts` | Which machines each scan reached |
| `findings` | One row per problem on a machine, with first seen, last seen and fixed dates |
| `finding_cves` | CVEs for each finding |
| `observations` | Which scans saw which findings |
| `cves` | NVD details |
| `kev` | The CISA KEV catalog |
| `epss_history` | EPSS scores over time |
| `exploits` | Public exploit matches |
| `alerts_sent` | Alerts already sent, per channel |
| `duplicates` | Findings that repeat another scanner's report |
| `priorities` | The latest ranking |
| `plan_fixes`, `plan_items` | The latest plan, and the findings each fix closes |
| `tickets`, `ticket_items` | Tickets, their Jira or ServiceNow IDs, and the findings each covers |
| `fp_labels`, `fp_predictions` | Your false-positive and real marks, and lookalikes flagged by `vmt fp predict` |
| `exploit_predictions` | Exploit-model scores for your CVEs, with reasons |
| `cve_predictions` | Predicted CWE and attack vector for CVEs NVD hasn't analysed |
| `advisories`, `advisory_items` | Advisories read by `vmt extract`, and the facts pulled from them |
| `mentions`, `chatter_spikes` | GitHub and news mentions of your CVEs, and the spikes found |
| `notes`, `triage_results` | Your notes, and saved `vmt triage` answers |
| `daily_runs` | Each `vmt daily` run: status, failed steps, log file, reports written |
| `history_snapshots` | Headline numbers for each day (rebuilt days are marked) |
| `priority_history`, `plan_history` | Every day's ranking and patch plan |

## Tests

```sh
pip install -e ".[dev,dashboard,report]"
pytest
```

The tests use only synthetic data (fake hosts, 192.0.2.x addresses, CVE-2099-* IDs) and never call
the network: HTTP is mocked with `responses` and SMTP with a stand-in class.
`.github/workflows/tests.yml` runs them on Windows, macOS and Linux with Python 3.11 and 3.13.
