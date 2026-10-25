# Exercise 4 - MITRE Caldera: research, benign operation plan, isolation and cleanup

> Draft for you to rewrite in your own words. Live execution is optional; this document is written so
> it stands on its own if you do not run it. **Benign discovery only** (identity, hostname, OS,
> process). No credential dumping, persistence, lateral movement, evasion, destructive actions or
> exfiltration.

## 1. Purpose and architecture

Caldera is an open-source **adversary emulation / automated red-team platform** built on the MITRE
ATT&CK framework. It lets a defender run realistic, repeatable adversary behaviours against
endpoints they own, then observe what their detection and response stack saw. (Verified Oct 2026:
the project is now hosted at `github.com/apache/caldera`, Apache-2.0 licence, still described as a MITRE
research project. Older docs and blog posts refer to `mitre/caldera`.)

| Concept | What it is | How they relate |
|---------|-----------|-----------------|
| **Core server** | Python application (REST API + web UI, default port 8888) holding the data model, scheduling and the planner engine. | The hub: agents beacon to it, operators drive it, plugins extend it. |
| **Plugins** | Optional modules that extend the server: e.g. `sandcat` (agent), `stockpile` (ability/adversary library), `compass` (ATT&CK Navigator layers), `atomic` (import Atomic Red Team tests), `training`, `debrief`/reporting, `manx` (reverse-shell agent) and others. | Provide abilities, agents, UI, reporting. Enable only what you need to shrink attack surface. |
| **Agents** | Small implants installed on target hosts that beacon to the server, fetch instructions, run them and return output. Sandcat (Go) is the default. Grouped by a label (e.g. `lab-red`). | Operations target a *group* of agents. |
| **Abilities** | The atomic unit: one command/script for a platform and executor (sh, psh, cmd...), mapped to an ATT&CK tactic + technique, optionally with payloads, input facts, parsers and cleanup. | Abilities are the building blocks of adversary profiles. |
| **Adversary profiles** | An ordered/related set of abilities representing a threat actor's behaviour or a test scenario. | An operation *runs* an adversary profile. |
| **Operations** | A run of an adversary profile against a group of agents, with settings: planner, fact source, obfuscator, jitter, visibility, and whether it runs autonomously or needs manual approval for each step. | The unit you analyse afterwards (report, timeline). |
| **Planners** | Decide *which* ability runs *when* (e.g. `atomic` runs abilities in profile order; others make choices based on available facts/relationships). | Planner + facts determine the path the operation takes. |
| **Facts** | Key/value observations (username, host, file path...) collected by parsers or seeded from a **fact source**. Abilities reference them as variables, and *relationships* link facts (e.g. user -> host). | Facts let later abilities adapt to what earlier ones discovered. |

**Version/security note (verified):** a remote code execution vulnerability (CVE-2025-27364) was fixed
in Caldera 5.1.0; run a current release, never an old image. The upstream README also warns that a
prebuilt `ghcr.io/apache/caldera:latest` image may be out of date and recommends running Caldera on a
secure, non-internet-exposed network. The server is a **command-and-control platform**; treat it as
dangerous infrastructure.

## 2. Three benign abilities mapped to ATT&CK

Use the UI (Abilities page, search by name/technique) to pick the stockpile/atomic abilities that
match; ability names vary by version, so record the exact ability you chose.

| # | Ability (benign) | Example command | ATT&CK technique | Detection telemetry I would expect |
|---|------------------|-----------------|------------------|-------------------------------------|
| 1 | Identify current user | `whoami` (Linux/Windows) | **T1033** System Owner/User Discovery | Process creation for `whoami` (Sysmon EID 1 / auditd `execve` / EDR); parent chain *agent -> shell -> whoami*; user context; command line; very short-lived process |
| 2 | OS / host information | `uname -a`, `hostname` (Linux) or `systeminfo`/`hostname` (Windows) | **T1082** System Information Discovery | Process creation for the utility; Windows may add `systeminfo` WMI/registry reads; same agent-parented lineage; burst of discovery commands in a short window |
| 3 | List running processes | `ps aux` (Linux) / `tasklist` (Windows) | **T1057** Process Discovery | Process creation for `ps`/`tasklist`; on Linux reads of `/proc/*` visible to auditd/eBPF sensors; again agent-parented |

**Telemetry around the agent itself (often the better detection):** the agent binary landing on disk
and being executed from a writable path (file create + process create; related to **T1105** Ingress Tool
Transfer when it is downloaded from the server), periodic HTTP beaconing to `server:8888` at a regular
interval with small POST bodies (network flow/proxy/DNS logs, beacon-interval analytics), an unusual
process name or location, and the short sequence of discovery commands as a *cluster* (single
commands are noisy; sequences are meaningful). Write the expected detections down **before** running,
then compare to what actually fired - the gap is the finding.

## 3. Operation plan (works as a paper exercise or a live run)

1. **Adversary profile** `lab-benign-discovery`: abilities #1-#3 only, atomic planner (profile order).
2. **Group** `lab-red`: one disposable Linux container/VM agent.
3. **Operation settings:** planner `atomic`; obfuscator `plain-text` (we are *not* testing evasion);
   visibility normal; **"require manual approval"** so each step is approved by you; no auto-run.
4. **Pre-run:** write the expected-telemetry table; start log collection on the target (auditd or
   Sysmon-for-Linux, or simply capture `docker logs`/process accounting for the lab).
5. **Run:** approve the 3 steps one at a time; note timestamps.
6. **Review:** Caldera operation report/timeline vs. logs: what was seen, what was missed, why.
7. **Output:** detection gaps list + proposed rules (below), then clean up.

If you do not run it: submit sections 1-3 and 5 and explain "to validate safely I would do exactly
this in a disposable VM on an isolated network; the success criteria are X, Y, Z".

## 4. How adversary emulation improves blue-team work

- **Control validation (purple teaming):** replace "we believe we detect T1057" with "we ran T1057 on
  Tuesday and the alert fired in 40 s / did not fire". Gaps become tickets with an ATT&CK tag.
- **Detection engineering:** use emulation as a unit test for detection rules (Sigma/EDR queries).
  Re-run the same operation after each rule change and after platform changes (agent upgrade, log
  pipeline change) to catch regressions. Measure coverage by technique, time-to-detect and
  false-positive behaviour against normal admin activity.
- **Response practice:** feed benign operations into SOC playbooks to test triage, enrichment and
  escalation without a real incident.
- **Deception security campaigns:** place decoys (honeytoken files, canary credentials in a lab,
  fake service banners, honeypot hosts) in the target and check that the *discovery behaviour* an
  emulated adversary exhibits actually *touches* them and that the alert is routed correctly,
  with enough context (which decoy, which host, which process). It also shows whether decoys look
  plausible next to what real discovery output returns. For this assessment this is *conceptual
  only*: no credential-access abilities are run.
- **Prioritisation and metrics:** ATT&CK-mapped coverage heatmaps (Compass/Navigator layers) show
  where to invest; repeated runs show whether investment worked.

## 5. Lab isolation and cleanup considerations

**Isolation (before starting):**
- Disposable VM or containers only; no bridged networking to your home/work LAN; no real data or
  credentials anywhere in the lab. Snapshot the VM first.
- Run the server and agent on an **internal Docker network** (`docker network create --internal`).
  The server needs to be reachable by the agent but should not expose port 8888 beyond loopback.
- Publish the UI on `127.0.0.1` only; set non-default credentials in the Caldera config (the
  well-known `red`/`admin` defaults must never be used on anything reachable). The Docker image
  generates its own keys/credentials on first start - read them from the container config/logs.
- Enable only the plugins you need. Disable ones that provide shells or other features you will not use.
- Use an obviously named agent binary and group; do **not** use Caldera's masquerading/obfuscation
  features - they are out of scope.
- Decide and record the **stop conditions**: unexpected outbound traffic, agent on the wrong host,
  anything not benign -> kill the operation and tear down.

**Cleanup (after):**
- Terminate agents (UI: kill agent / stop operation), delete the operation, adversary and group.
- `docker rm -f` server and agent containers; `docker network rm` the lab networks;
  `docker volume rm` any volumes; delete downloaded payloads and compiled agent binaries.
- Verify nothing remained: `docker ps -a`, `docker network ls`, `docker volume ls`, process list,
  no listeners on 8888, and revert the VM snapshot if a VM was used.
- Keep only sanitized evidence (operation report, your telemetry comparison); no secrets or tokens.

## 6. Optional live-run recipe (draft - verify against current Caldera docs)

```bash
git clone https://github.com/apache/caldera.git --recursive     # use a release >= 5.1.0
cd caldera
docker build --build-arg VARIANT=full -t caldera-lab .          # per upstream README
docker network create --internal caldera-int
docker run -d --name caldera -p 127.0.0.1:8888:8888 caldera-lab
docker network connect caldera-int caldera                      # server also reachable on the internal net
docker build -t caldera-agent-lab /path/to/this/repo/caldera/agent
docker run -d --name caldera-agent --network caldera-int caldera-agent-lab
```
Then in the UI: Agents -> **Deploy an agent** (sandcat, linux) and copy the *generated* command for the
agent container (the server address on the internal network is `http://caldera:8888`). Run it with
`docker exec caldera-agent sh -c '<command>'`. Create the adversary and operation per section 3.
This repo does not automate Caldera: the UI-generated commands change between versions, and live
execution is explicitly optional.
