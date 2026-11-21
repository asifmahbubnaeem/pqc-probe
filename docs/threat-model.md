# Threat model: pqc-probe-web

The CLI runs on your own machine against targets you choose. The web service is different: it
connects, from the operator's network, to hosts chosen by strangers, parses what those hosts
send back, and shows the result to the visitor. This page lists what can go wrong and what the
code does about it. "Test" means a unit test pins the behaviour; "design" means it follows from
how the code is built; "operator" means the deployment has to provide it.

## What is protected

| Asset | Why it matters |
|---|---|
| The operator's internal network and cloud metadata service | The probe makes outbound connections; it must not become a way in. |
| The operator's IP reputation | Targets will see probes coming from this address. |
| Third-party servers | They must not be hammered or port-scanned through this service. |
| The service's own capacity | CPU, processes, memory and connections are limited. |
| Visitors | Report pages show text chosen by a hostile server. |

## Who is a threat

1. **A visitor** sending crafted targets or floods.
2. **A scanned server** answering with hostile data (huge or malformed handshakes, hostile
   strings in certificates and banners, hangs).
3. **A DNS authority** for a name the visitor submits (rebinding, many records, slow answers).
4. **A network neighbour** reaching the service directly, bypassing the reverse proxy.

## Threats and mitigations

### Server-side request forgery (SSRF)

| Threat | Mitigation | Evidence |
|---|---|---|
| Target is, or resolves to, a private, loopback, link-local, metadata or other special address. | Resolve once; every returned IPv4 address is checked against a blocklist (0/8, 10/8, 100.64/10, 127/8, 169.254/16 including 169.254.169.254 and 169.254.170.2, 168.63.129.16, 172.16/12, 192.0.0/24, 192.0.2/24, 192.88.99/24, 192.168/16, 198.18/15, 198.51.100/24, 203.0.113/24, multicast, 240/4). One bad record refuses the whole target. | Test: `policy_tests::blocked_ranges_are_blocked_including_boundaries`, `mixed_public_and_private_records_are_refused`, `private_target_is_refused`. |
| DNS rebinding: a name answers public for the check and private for the connection. | The probe connects to the address that was checked (`Target.resolved`), not to the name. `openssl` and `ssh` are given the IP; the name is used only for SNI. | Test: `connect_host_prefers_resolved_address`. Design. |
| Numeric tricks (`0x7f.1`, `2130706433`, `127.1`). | The host syntax is strict (ASCII letters, digits, dots and hyphens; no label starting or ending with a hyphen), which refuses `-oProxyCommand=x`, `user@host`, URLs and IPv6 literals. Forms such as `0x7f.1` or `127.1` pass the syntax check, are normalised by the resolver, and are caught by the address check after resolution. | Test: `numeric_host_tricks_are_caught_after_resolution`, `host_syntax_rejects_hostile_input`. |
| IPv6 or a v4-mapped address as a way around the check. | Only A records are used and probes force `-4`. IPv6 literals are not accepted as targets. | Design. |
| Redirects or referrals. | None: the probe speaks TLS or SSH once to one address and follows nothing. | Design. |

### Port scanning and abuse of third parties

| Threat | Mitigation | Evidence |
|---|---|---|
| Using the service to scan ports. | Only an allowlist of ports is accepted (default 22, 443, 465, 636, 853, 993, 995, 2222, 8443; configurable). Port 0 is always refused. | Test: `default_port_allowlist`, `any_port_policy_still_rejects_port_zero`. |
| Repeated probes against one target. | A repeat of the same request within a minute gets the earlier job back and costs no connection (`PQC_WEB_TARGET_COOLDOWN_SECS`). A repeat that arrives while the first is still being prepared waits for that job (at most 15 s, charged as a poll) instead of resolving and spending budget again. SSH algorithm checks are sequential and paced (one handshake per 1.1 s, at most 8). | Test: `a_repeat_request_returns_the_earlier_job_and_costs_nothing`, `a_triple_click_while_dns_is_slow_makes_one_job_and_costs_one_request`, `a_repeat_of_a_refused_request_gets_its_own_refusal`; pacing tests in core. |
| OpenSSH 9.8+ servers penalise sources that open many connections (`PerSourcePenalties`). | Pacing keeps one client near one connection per second. Operators should still expect some targets to briefly penalise the service address. | Observed on the test bench; documented in `docs/web.md`. |
| Scanning many different targets from one client. | Per-client limits: burst 5, 6 per minute, 2 in flight, 60 per day. | Test: `ratelimit::tests::*`, API tests for 429. |
| Hitting one server through many names or from many clients. | A limit per server address across all clients (burst 6, 12 a minute): `429 target_busy`. One DNS lookup per request, so both protocols hit the same checked address. | Test: `one_server_address_is_not_probed_more_than_its_budget_whatever_the_name`, `both_protocols_cost_one_dns_lookup`. |

### Denial of service against the service

| Threat | Mitigation | Evidence |
|---|---|---|
| Flooding with requests. | Per-client token bucket, in-flight cap and daily budget for submissions, and a separate bucket for status, report and result-page requests (burst 60, 120 a minute). The table of tracked clients is bounded (10,000); when full, new clients are refused rather than memory growing. | Test: `a_full_table_refuses_new_clients_and_recovers_after_pruning`. |
| Many clients together. | Global cap on concurrent probes (default 4), a bounded queue (default 50, then `503` with `Retry-After`), a hard per-job deadline (default 90 s; the probe task is aborted and child processes are killed on drop). | Test: `concurrency_is_capped`, `the_queue_limit_rejects_new_jobs_when_full`, `a_slow_prober_times_out`. |
| A hung or slow target. | Per-connection timeout (default 15 s) plus the job deadline. | Test: `a_slow_prober_times_out`; core timeout paths. |
| Huge request bodies. | Bodies over 8 KB are refused before parsing. | Test: `malformed_requests_get_stable_error_codes`. |
| Memory growth from stored results. | Results expire after an hour (default) and are swept every minute; the job table is bounded by the queue limit plus retained results. | Test: `finished_jobs_expire_but_running_ones_do_not`. |
| A panic inside a probe. | Probes run in their own task; a panic marks the job failed and frees its slot. | Test: `a_panicking_prober_fails_the_job_instead_of_hanging_it`. |
| Slow or failing DNS. | Each lookup is limited to 5 s and retried once only for a timeout. At most 32 lookups hold a resolver thread at once, counted until the thread really ends (a lookup past its limit keeps its slot); when all are taken, new lookups are refused at once with `503 resolver_busy` and `Retry-After`, and that is not retried. | Test: `a_timeout_is_retried_once`, `a_stuck_lookup_keeps_its_slot_until_its_thread_ends`, `a_busy_resolver_is_not_retried`, `a_busy_resolver_is_503_with_retry_after`. |

### Hostile servers

| Threat | Mitigation | Evidence |
|---|---|---|
| A server sends an enormous or malformed SSH key exchange message. | The reader caps packet size (35,000 bytes), pre-banner text at 32 lines and 8 KB, and treats malformed data as a protocol error. | Test: `rejects_non_kexinit_and_malformed_packets`, `non_ssh_server_is_a_protocol_error_not_a_hang`. |
| A server that accepts and then says nothing. | Read timeouts on every step. | Test: `server_that_hangs_up_is_an_error_not_an_empty_success`. |
| Hostile text in certificates, banners and algorithm names reaching a visitor's browser (stored or reflected XSS). | Every value from a scanned server is HTML-escaped, including control characters; pages use no JavaScript and no inline styles; a strict CSP forbids scripts and framing even if escaping failed. | Test: `html::tests::*` render a hostile fixture through every field and check the output. |
| Hostile text breaking JSON or logs. | JSON is produced by serde. Server-controlled strings are not written to logs. | Design; no test for logs. |

### Command and argument injection

The probe starts `openssl` and `ssh` as child processes with a host from a stranger.

| Threat | Mitigation | Evidence |
|---|---|---|
| Host or port becomes a command-line option (`-oProxyCommand=...`). | Strict host syntax (no leading `-`, no spaces, no `@`), and the host is passed as exactly one argument after the port, with no shell. | Test: `host_syntax_rejects_hostile_input`, `host_is_one_argument_after_the_port`. |
| User or system SSH configuration changes behaviour. | `ssh` is started so it ignores the user's and the system's configuration. | Test: `ignores_user_and_system_ssh_config`. |
| Tool paths set by a visitor. | Paths come only from operator environment variables, never from a request. | Design. |

### Access to results

| Threat | Mitigation | Evidence |
|---|---|---|
| Guessing another visitor's job id. | Ids are UUID v4 (122 random bits) as 32 hex characters; anything else is rejected before lookup and never echoed. | Test: `ids_are_32_hex_and_distinct`, `unknown_or_malformed_ids_are_404_and_never_echoed`. |
| Learning the operator's internal addressing from error messages. | A refused address is reported by its range only, never the resolved address; resolver error text goes to the log and not to the visitor; tool paths and spawn errors are not shown. | Test: `public_errors_do_not_leak_details`, `lookup_failure_and_missing_ipv4_are_told_apart`. |
| Spoofing the client address to dodge limits. | `X-Forwarded-For` is believed only when the direct peer is a configured proxy and is read from the right. | Test: `x_forwarded_for_counts_only_from_a_trusted_proxy`, `forwarded_for_is_read_from_the_right`. |

## What the operator must provide

The service does not sandbox itself. For a public deployment:

1. **Run it in a container as a non-root user** with a read-only root file system, no
   capabilities, and CPU, memory and process limits. The probe tools are child processes of the
   service.
2. **Filter egress at the network layer** as well: block private ranges, the metadata address
   and the operator's own services. The application check is the first line of defence, not the
   only one.
3. **Put it behind a reverse proxy** that terminates TLS, sets HSTS, and sets
   `PQC_WEB_TRUSTED_PROXIES` to the proxy's address. Bind the service to loopback or a private
   interface, so nobody reaches it without passing the proxy.
4. **Keep the OQS builds separate** from system OpenSSL and OpenSSH, and update them like any
   other security-relevant software.
5. **Log requests at the proxy** (client address, target, time). The service keeps no
   persistent logs of who probed what.

## Known gaps

- **The cooldown that returns an earlier job matches the target as written** (lower-cased, one
  trailing dot removed), not the resolved address, because many sites share an address and
  would get each other's reports. Aliases and other spellings of one server are held back by
  the per-server-address limit (burst 6, 12 a minute across all clients), which also applies to
  new probes of shared addresses such as CDNs, so a busy shared address can be refused to
  everyone for a short time.
- **Different protocol or mode combinations for one host** (`tls` vs `both`) are separate
  cooldown entries; the per-client and per-address limits still bound them.
- **State is in memory.** A restart forgets jobs, limits and cooldowns, which gives a client a
  fresh budget.
- **A stalled DNS lookup keeps its thread** until the system resolver gives up, even after the
  5 s limit has passed. At most 32 such threads exist; past that, everyone's new lookups get
  `503 resolver_busy` until some finish, so a hostile slow DNS server can make the service
  briefly unavailable, but not exhaust its threads.
- **Users behind one NAT or one IPv6 /64 share a budget.**
- **No authentication and no abuse reporting.** Anyone can use the service within the limits;
  there is no way to block a target at a target owner's request except by changing the policy
  or the proxy.
- **The probe reveals the operator's address to every target.** That is inherent.
- **The generated report is only as honest as the tools.** A server can lie about what it
  supports. The report states what a handshake showed, not what the server's configuration is.
