# Demo 01 - Basic Threat Hunt

This demo runs EVTXSIFT against a small set of exported Windows Security
events (`security_events.json`) that simulate a realistic intrusion chain
from logs you own / are authorized to analyze.

## The story in the logs

1. **Brute force** - source `203.0.113.66` hammers the `administrator`
   account with many failed logons (Event 4625) inside a few minutes, then
   finally gets a **successful** logon (Event 4624). That success after the
   failures escalates the finding to **critical** (possible compromise).
2. **Password spray** - source `198.51.100.23` tries one password against
   many different usernames (several 4625s across distinct accounts).
3. **Persistence** - a new service is installed (Event 7045) whose binary
   is a base64-encoded PowerShell command - a classic LOLBin persistence
   pattern - plus a new local account is created (4720).
4. **Lateral movement** - the compromised `administrator` identity then
   authenticates over the network/RDP (logon types 3/10) to several
   different hosts (multiple 4624s across `WS01`, `WS02`, `DC01`).

## Run it

```bash
# Human-readable table
python -m evtxsift hunt demos/01-basic/security_events.json

# Machine-readable for pipelines (jq, SIEM ingest, etc.)
python -m evtxsift hunt demos/01-basic/security_events.json --format json

# Shareable self-contained HTML report (the "UI")
python -m evtxsift hunt demos/01-basic/security_events.json \
    --format html -o report.html
```

Exit code is **1** when any finding is produced (so it plugs into CI), and
**0** on a clean log.

## Exporting your own logs

EVTXSIFT reads *normalized* events, not raw binary `.evtx`. Export first:

```powershell
# Last 5000 Security events to JSON (run as admin on a host you own)
Get-WinEvent -LogName Security -MaxEvents 5000 |
  Select-Object Id, TimeCreated, MachineName,
    @{n='TargetUserName';e={$_.Properties[5].Value}},
    @{n='IpAddress';e={$_.Properties[19].Value}},
    @{n='LogonType';e={$_.Properties[8].Value}} |
  ConvertTo-Json | Out-File events.json
```

(Field indexes vary by Event ID; the example above is illustrative.)
