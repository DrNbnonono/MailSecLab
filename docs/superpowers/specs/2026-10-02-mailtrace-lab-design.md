# MailTrace research workspace 0.5

User-approved scope: deterministic MailForge, one-variable sweeps, adjacent-snapshot HeaderDiff, versioned experiment manifests, automatic local archives, CLI/API/Web integration. No SMTP transport, MTA orchestration, limit verdicts, DNS, or complex MIME generation.

Core MailReport 0.1 and single-message analysis remain unchanged. Add independent mailtrace-lab package with pure generation/diff functions and a separate ExperimentStore. CaseSpec retains ordered headers, explicit byte dimensions, seed and fixed base time. Archive all resolved cases, original messages, reports, differences, and SHA-256 references. Sweep groups are not transport chains.

Byte comparison uses decoded header_base64 slices, never replacement-text reencoding. Match exact bytes, then explicit format equivalence, then unique same-name instances within stable anchor intervals. Preserve ambiguous duplicate correspondence and capture gaps. Report changes between observation points without assigning causality to an MTA. Existing heuristic findings remain distinct.

Store under MAILTRACE_EXPERIMENT_DIR or startup-directory/local-experiments. Create a fresh UUID staging directory, publish only after all artifacts and manifest are written; never overwrite existing runs. Verify all artifact hashes before reads/reproduction. Failed staging directories remain outside complete history. Existing single-message analysis does not persist inputs; research mode explicitly labels automatic persistence.

Limits: message 10 MiB, run 50 MiB, 20 cases/snapshots, generator Received count 10,000. Lab HTTP body 52 MiB and proxy timeout 120 seconds; existing analysis stays 12 MiB/45 seconds. History page 50, UI diff/header lists page 50, graph existing cap 100. Cancellation stops browser waiting, not guaranteed server archival.

Deliver generation, capture ordering/metadata, two-sided evidence, archive history, immutable reproduction, EML/JSON/ZIP/CSV exports. Keep future SMTP/log/delivery observations null. Test byte determinism, target dimensions, ambiguities, prefix insertion vs reorder, corrupt archives, interrupted writes, endpoints, CLI, and real desktop/mobile browser workflows.
