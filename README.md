SEMI-CREST TECHNOLOGIES · THREAT HUNT CASE STUDY

# Operation QUARTZFANG

An AI-directed intrusion reconstructed from Microsoft Sentinel telemetry, from initial access through triage of lookalike activity

Prepared by **Shad Hillestad** · 2 November 2026 · 28 / 28 flags solved · 2,650 / 2,850 points

## Executive summary

This guided hunt reconstructed an intrusion chain in SemiCrest Technologies’ simulated environment. An external source exploited the document-preview endpoint on `sc-portal01` through server-side request forgery (SSRF). A failed `file://` request was replaced by an accepted `gopher://` request 18 seconds later. The request reached local Redis; subsequent process telemetry showed cron launching Python, establishing remote code execution on the portal host.

The investigation then followed the hunt’s sequence: the portal foothold read `/etc/semicrest/portal.conf`; exposed service credentials were used in database, Harbor registry, and admin API activity; two AI-agent extraction claims were checked against infrastructure logs; an account and SSH key provided persistence; an encrypted archive was staged before an outbound HTTPS connection; reconnaissance and event timing were compared with scheduled scanning and expected human activity; and three tempting lookalikes were separated from the intrusion.

This project is modeled on the operating pattern described in Anthropic’s [November 2025 report on the AI-orchestrated espionage campaign](https://www.anthropic.com/news/disrupting-AI-espionage), catalogued by MITRE ATT&CK as [Campaign C0062](https://attack.mitre.org/campaigns/C0062/). The exercise let me test that idea against a full hunt: identify human decision gates, recognize machine-speed tactical work, and verify the agent’s claims against service and host telemetry. The SemiCrest hosts, addresses, credentials, and events below are synthetic training data; this report does not claim they came from Anthropic’s real-world investigation.

**Assessment.** The evidence supports a human-assisted, AI-directed operation. It confirms SSRF-to-RCE, configuration credential access, broad database queries, Harbor and admin API activity, a privileged local account, archive staging, and an outbound connection. The admin secrets request was denied. The available network telemetry does not prove that the archive transfer completed or that a remote system accepted it.

## Scope and method

The hunt covered workspace `LAW-HuntPractice` for 20 September 2026, 06:30–08:30 UTC. Systems: `sc-portal01` (10.5.0.10), `sc-db01` (10.5.0.20), `sc-registry01` (10.5.0.30), and `sc-admin01` (10.5.0.40).

Sources included Microsoft Defender process, network, file, logon, and device-event tables; `Syslog`; `PortalAccessLog_CL`; `ContainerRegistryLog_CL`; and `LLMAgentLogs_CL`. The investigation correlated host, time, source, process ancestry, request or query content, and response. Agent narration was treated as a lead, not as ground truth. Conclusions below distinguish observed activity, analytic inference, and evidence gaps.

**Field and time note:** MDE tables use `Timestamp` and `DeviceName`; custom tables use `TimeGenerated` and `Computer`. Screenshots come from the hunt interface and may render timestamps in its local display zone. Narrative chronology uses UTC.

**Screenshot note:** All 25 unique screenshots from the investigation Word document are included below; the admin API screenshot appears in both sections where it supports separate findings. Each figure explains what the screenshot shows. Credential strings and exploit payload details are visually redacted in the public-facing copies.

## Section 1: Initial Access

At 06:52 UTC, `203.0.113.87` sent two requests to `/api/v1/preview` on `sc-portal01`. The first attempted the `file://` scheme and received HTTP 400. Eighteen seconds later, a `gopher://` request received HTTP 200. Its destination was the host’s own Redis service at `127.0.0.1:6379`. This rapid scheme change is a useful operational signal: a failed approach was replaced within seconds.

![Evidence screenshot](images/screenshot-01.png)

*Portal access rows identify /api/v1/preview as the targeted endpoint and show the two requests from the same source. Payload text is redacted.*

![Evidence screenshot](images/screenshot-02.png)

*The request sequence shows file:// rejected and gopher:// accepted 18 seconds later; status and timing support the self-correction finding. Payload text is redacted.*

Process telemetry then showed `python3` started by `cron`, an abnormal parent-child relationship for the portal application. Correlated with the successful SSRF request, it supports a chain from the public-facing preview feature through local Redis and cron to Python socket-based remote code execution (RCE).

![Evidence screenshot](images/screenshot-03.png)

*Process telemetry shows cron launching Python with a socket-based command, supporting the RCE link after the accepted request. The command payload is redacted.*

    PortalAccessLog_CL
    | where Computer =~ "sc-portal01" and SrcIpAddr == "203.0.113.87"
    | project TimeGenerated, UrlOriginal, HttpStatusCode
    | order by TimeGenerated asc

The exploit source is an observed lab address, not attribution to a person or group. Reconnaissance came from a separate cluster, and the outbound connection later used a third address.

## Section 2: Credential Harvest

Between 07:00 and 07:10, process events on the portal host showed a rapid discovery and file-read burst. `cat /etc/semicrest/portal.conf` ran as a child of Python reverse-shell process PID 4401, which was itself launched by cron (PID 4400). The parent chain ties a normally benign file-reading command back to the web foothold.

![Evidence screenshot](images/screenshot-04.png)

*Process evidence shows cat reading portal.conf beneath the Python foothold; env and find commands appear in the same burst.*

The configuration contained credentials for two services: `portal_svc` for PostgreSQL on `sc-db01` (10.5.0.20) and `ci-builder` for Harbor on `sc-registry01` (10.5.0.30). Password values are intentionally redacted from this report. The registry host is 10.5.0.30; `sc-admin01` is 10.5.0.40.

![Evidence screenshot](images/screenshot-05.png)

*The recovered agent response exposes the PostgreSQL connection string in the config-file contents; the password is redacted, while service and target context remain visible.*

![Evidence screenshot](images/screenshot-06.png)

*The configuration evidence includes Harbor registry credentials. The password is redacted; the report preserves the account and distinguishes the registry host from the admin host.*

An `env` command also ran in the burst, but its output was not captured. The evidence establishes command execution only; it cannot tell us whether additional environment credentials were present. This is a visibility gap, not evidence that the environment was clean.

    DeviceProcessEvents_CL
    | where DeviceName =~ "sc-portal01"
    | where ProcessCommandLine has "portal.conf" or ProcessCommandLine == "env"
    | project Timestamp, FileName, ProcessCommandLine,
              InitiatingProcessFileName, InitiatingProcessId

## Section 3: Lateral Movement

### PostgreSQL query behavior

The account `portal_svc` is used by the legitimate application as well as in attacker activity, so the username alone is not a discriminator. On `sc-db01`, Syslog showed a rapid sequence of broad, unparameterized statements against `customers`, `users`, and `projects`, together with schema/catalog enumeration through `information_schema` and `pg_catalog`. Routine application queries were narrower and parameterized, for example with `$1`, and appeared in their normal rhythm. The evidence supports enumeration, but does not establish the exact rows returned or their contents.

![Evidence screenshot](images/screenshot-07.png)

*Database Syslog evidence shows repeated broad SELECT statements against application tables; returned rows are not shown.*

![Evidence screenshot](images/screenshot-08.png)

*A second query screenshot shows the selected database tables and fields, illustrating what the enumeration targeted; it does not expose returned records.*

### Harbor registry access

On `sc-registry01`, `ci-builder` activity from `sc-portal01` (10.5.0.10) included `login`, `list_repository`, `pull_manifest`, and `inspect_layer`. The lead-in baseline from CI server 10.5.0.100 was `pull_artifact` and `push_artifact`. Repository browsing and layer inspection from the compromised portal differ from that baseline. Registry request logs show operations, not the contents of the inspected layer.

![Evidence screenshot](images/screenshot-09.png)

*Harbor API operations from the portal host include repository listing, manifest pulls, and layer inspection.*

### Admin API access

Requests from `sc-portal01` to `sc-admin01` queried services, topology, and the secrets endpoint. The first two returned HTTP 200; `/api/v1/secrets` returned **403 Forbidden**. This response becomes important when checking the agent’s claim of a successful secret extraction.

![Evidence screenshot](images/screenshot-10.png)

*Syslog on sc-admin01 records GET /api/v1/secrets from 10.5.0.10 with HTTP 403.*

    Syslog
    | where Computer =~ "sc-admin01"
    | where SyslogMessage has "secrets" and SyslogMessage has "10.5.0.10"
    | project TimeGenerated, SyslogMessage

## Section 4: AI Hallucination

The recovered agent log contained two notable extraction claims. The first said Kubernetes secrets had been extracted from `sc-admin01`. The corresponding host request to `/api/v1/secrets` returned 403, directly contradicting a successful extraction. The agent’s claim that secrets were obtained is therefore unreliable.

![Evidence screenshot](images/screenshot-11.png)

*The agent log claims Kubernetes secret extraction; admin host telemetry records a 403 response.*

![Evidence screenshot](images/screenshot-10.png)

*This repeated admin API screenshot is the infrastructure-side check of the agent claim: the secrets request returned 403 Forbidden, so the claimed successful extraction is contradicted.*

![Evidence screenshot](images/screenshot-12.png)

*The recovered agent narration claims Kubernetes secrets were obtained. Compare this claim with the repeated 403 evidence above; the log records what the agent said, not proof that the extraction succeeded.*

![Evidence screenshot](images/screenshot-13.png)

*Container registry telemetry shows the portal-originated inspect_layer operation. It confirms layer inspection, but the log does not contain the image layer contents.*

The second claim said admin database credentials were found in a Harbor image layer. The registry logs confirm manifest and layer inspection but do not expose layer contents. That claim is **unverified** by the available infrastructure telemetry; it should not be repeated as a confirmed finding.

Together, these examples show a practical limitation of AI-assisted operations: the agent may overstate or fabricate results and cannot independently prove that its own output matches what a service returned. A human operator must validate claims and decide whether to proceed. Agent logs are useful evidence of reasoning and intent, but infrastructure telemetry determines whether an action succeeded.

## Section 5: Exfiltration and Persistence

### Staging and outbound connection

On `sc-portal01`, the archive preparation sequence used `tar`, `gzip`, and `openssl`, producing `/tmp/.portal-cache/report.tar.gz.enc`. At 08:15 UTC, `DeviceNetworkEvents_CL` recorded an outbound TCP/TLS connection to `198.51.100.210:443`. This is consistent with an attempted HTTPS transfer.

![Evidence screenshot](images/screenshot-14.png)

*DeviceNetworkEvents_CL records the outbound connection from sc-portal01 to 198.51.100.210:443, initiated in the Python foothold context. It proves a connection, not successful receipt of the archive.*

![Evidence screenshot](images/screenshot-15.png)

*DeviceFileEvents_CL records creation of report.tar.gz.enc in /tmp/.portal-cache, the staging location before the outbound connection.*

![Evidence screenshot](images/screenshot-16.png)

*File telemetry records the encrypted report archive in the hidden .portal-cache staging directory.*

The staged archive and outbound connection do not prove that all data left the host, that the remote server accepted it, or what exact records it contained. Confirming completion would require packet/proxy detail, destination-side evidence, or other transfer records.

### Persistence artifact

The attacker created the local account `svc_monitor`, added it to sudo, and created an Ed25519 SSH key under `/home/svc_monitor/.ssh/`. The account and key provide a separate access path beyond the initial web foothold.

![Evidence screenshot](images/screenshot-17.png)

*Process lineage shows creation of svc_monitor, sudo-group modification, and SSH key generation.*

![Evidence screenshot](images/screenshot-18.png)

*File events show the svc_monitor Ed25519 private and public key files under its .ssh directory, corroborating the persistence setup.*

HTTPS port 443 is also used for legitimate SaaS and API traffic. The discriminators here are the unfamiliar remote destination and process lineage: the observed transfer process ran under the reverse-shell context, unlike normal `gunicorn`-initiated application traffic.

## Section 6: Reconnaissance and Timing

Before exploitation, three external sources—`198.51.100.62`, `198.51.100.31`, and `198.51.100.45`—made rapid, broad path probes using a `python-requests` user agent. The internal scanner at `10.5.0.250` identified itself as `Nessus/10.6.2` and followed a more gradual, plugin-driven pattern. Source, user agent, path breadth, and cadence separate external reconnaissance from the scheduled scan.

![Evidence screenshot](images/screenshot-19.png)

*Portal access summary groups the external scanner cluster separately from internal 10.5.0.250.*

The roughly two-hour chain does not look like one person continuously operating at a single pace. A human working manually would be expected to pause irregularly to review output, research, and choose the next step. This telemetry instead shows tightly grouped, systematic actions with seconds between many tactical events, separated by longer decision pauses. The exercise’s timing analysis found roughly 3–15 minute pauses around phase boundaries. That burst-and-gate pattern is consistent with automation between human approvals.

## Section 7: Autonomy Synthesis

`LLMAgentLogs_CL.user_input` records the operator’s strategic directives. The hunt grouped them into four decision gates: initial tasking for reconnaissance and exploitation; foothold confirmation before credential harvesting and lateral movement; lateral movement before database collection and admin enumeration; and collection review before documentation, staging, and exfiltration. The log has separate review and authorization messages near the final transition, but they belong to the same broader collection-to-staging decision point.

![Evidence screenshot](images/screenshot-20.png)

*The recovered agent log’s user_input field records operator tasking and authorization at phase boundaries.*

![Evidence screenshot](images/screenshot-21.png)

*The grouped directives make the human decision gates easier to compare: each authorization marks a strategic transition between phases.*

![Evidence screenshot](images/screenshot-22.png)

*The screenshot maps the operation’s AI capability use to ATT&CK T1588.007; it contextualizes the AI role but is not itself host telemetry.*

The human evidence is the operator’s directives. The machine-execution evidence includes the 18-second failed-scheme correction in `PortalAccessLog_CL.UrlOriginal`, `HttpStatusCode`, and `TimeGenerated`, plus rapid systematic enumeration across process and service logs. The result is **human-assisted**: a person set goals and approved transitions while the AI agent performed much of the tactical work between gates.

The exercise’s novel AI-capability mapping is `T1588.007 — Obtain Capabilities: Artificial Intelligence`. This describes AI as an offensive capability used to carry out the operation; it does not imply that the underlying SSRF or credential-harvesting methods were themselves novel.

## Section 8: Real or Noise

### Credential reuse across services

`portal_svc` appeared in legitimate application sessions and attacker access. Context separates them: attacker requests originated from compromised `sc-portal01` (10.5.0.10) under the reverse-shell context and included broad, unparameterized database queries; routine app sessions followed the expected `gunicorn` and parameterized-query pattern. Admin API requests from the portal source also differed from normal admin-source traffic. The exposed credential should be rotated, but a username match alone is not enough to label every session malicious.

![Evidence screenshot](images/screenshot-23.png)

*The comparison screenshot shows the same service identity across database and admin activity; source host, query behavior, and response distinguish attacker use from routine application use.*

### Nightly pg_dump

The `pg_dump` activity under `portal_svc` appeared in the 48-hour lead-in at approximately 03:00 on consecutive days, with `application_name=pg_dump`. Its recurring schedule predates the attack window and marks it as normal backup activity.

![Evidence screenshot](images/screenshot-24.png)

*Syslog shows pg_dump authorization at a consistent time on consecutive nights in the lead-in baseline.*

### 07:30 PostgreSQL connection spike

The apparent spike was a dead end: Syslog showed repeated `FATAL: sorry, too many clients already` and reserved-connection-slot errors, alongside routine parameterized application queries. That points to database connection-pool exhaustion or an application concurrency problem, not the attacker’s broad SQL enumeration. Volume alone did not establish malicious activity; statement content and error context did.

![Evidence screenshot](images/screenshot-25.png)

*The database spike contains repeated connection-limit errors and routine queries, unlike the later broad enumeration.*

## Response priorities

1.  Contain `sc-portal01` and preserve disk, process, cron, file, and network evidence before removing the foothold.
2.  Disable `svc_monitor`, revoke its SSH key, remove sudo membership, and inspect for other accounts, keys, cron entries, and startup changes.
3.  Rotate exposed `portal_svc` and `ci-builder` credentials, invalidate dependent sessions/tokens, and coordinate service updates to limit outage risk. The secret values are not reproduced in this report.
4.  Review PostgreSQL audit data and any available query results; inspect Harbor artifact digests and provenance; use proxy, firewall, or destination-side records to determine whether the archive transfer completed.
5.  Constrain the preview feature to required URL schemes and destinations, block loopback/private-network access, and prevent the web process from reaching Redis or writing cron configuration.
6.  Investigate and correct the database connection-pool issue separately from the intrusion.
7.  Improve evidence capture so command outputs and API responses are available to investigators without logging secret values.

### ATT&CK behavior mapping

| Behavior                             | Technique                                                                                                |
|--------------------------------------|----------------------------------------------------------------------------------------------------------|
| Exploit the exposed preview feature  | `T1190` · Exploit Public-Facing Application                                                              |
| Python command execution             | `T1059.006` · Command and Scripting Interpreter: Python                                                  |
| Read credentials from configuration  | `T1552.001` · Unsecured Credentials: Credentials In Files                                                |
| Database access and enumeration      | `T1213.006` · Data from Information Repositories: Databases                                              |
| Reuse legitimate service credentials | `T1078` · Valid Accounts                                                                                 |
| Stage and archive data               | `T1074.001` · Data Staged: Local Data Staging; `T1560.001` · Archive Collected Data: Archive via Utility |
| Create a local persistence account   | `T1136.001` · Create Account: Local Account                                                              |
| Attempt web-protocol exfiltration    | `T1567` · Exfiltration Over Web Service (attempt observed; transfer unconfirmed)                         |
| Use AI as an offensive capability    | `T1588.007` · Obtain Capabilities: Artificial Intelligence                                               |
| Rapid external path discovery        | `T1595.001` · Active Scanning: Scanning IP Blocks                                                        |

## Conclusion

The hunt reconstructed a coherent intrusion path in the SemiCrest simulation: SSRF at `/api/v1/preview` led to Redis and cron-based Python execution; the resulting foothold accessed configuration credentials and pivoted to database, registry, and admin services; a privileged local account established persistence; and an encrypted archive was staged before an outbound HTTPS connection. Reconnaissance and timing data, together with the recovered operator directives, support a human-assisted model with machine-speed tactical activity between human decision points.

The evidence also establishes important limits. The environment command’s output is missing; one agent extraction claim is contradicted by a 403 response; another cannot be verified without image-layer contents; and an outbound connection does not prove a completed transfer. Keeping those boundaries clear is part of the hunt’s main result: the analyst validates the agent, separates attack from noise, and reports only what the telemetry supports.

### References

- [Anthropic, “Disrupting the first reported AI-orchestrated cyber espionage campaign” (13 November 2025)](https://www.anthropic.com/news/disrupting-AI-espionage)
- [MITRE ATT&CK, Campaign C0062: Anthropic AI-orchestrated Campaign](https://attack.mitre.org/campaigns/C0062/)

These sources provide background for the training scenario. QUARTZFANG is a simulated exercise and its indicators are not attributed to the public campaign.
