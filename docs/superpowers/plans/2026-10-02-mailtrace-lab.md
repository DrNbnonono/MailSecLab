# MailTrace research workspace implementation plan

Goal: reproducible generation → ordered evidence comparison → automatic archival → reopening/reproduction.
Architecture: independent mailtrace-lab package wraps unchanged mailtrace-core; API owns local storage, Next.js proxies lab routes; browser receives artifacts on demand.
Tech stack: Python/Pydantic/email/hashlib/pathlib/zipfile/csv, existing FastAPI and Next.js/React.

- [x] Define strict versioned CaseSpec/SweepSpec/Manifest/DiffReport and failing generation/diff/store tests.
- [x] Implement byte generator, exact dimension padding and one-variable expansion; verify deterministic hashes and count/line-size boundaries.
- [x] Implement raw-byte matching, format classification, unique anchor-local modifications, ambiguous duplicates and Received component differences.
- [x] Implement transactional archives, bounded input, checksummed reads, history, immutable reproduction and ZIP/CSV downloads.
- [x] Add CLI forge/diff/reproduce; meaningful subprocess tests including binary files and failures.
- [x] Add API lab router, request limits, disk-error sanitization, artifact downloads; test real archive endpoints and original interfaces.
- [x] Add same-origin bounded lab proxy, generation/diff/history UI and two-sided evidence. Preserve existing workbench.
- [x] Run Python regression, Node tests, TypeScript and production build; browser generation/sweep/compare/history/export/mobile/error validation.
- [x] Independent review and fixes; document schema, sample cases, setup, actual verification and version locks.
- [ ] Commit/push to tool/mailtrace; verify local/remote equality and unchanged research branch.
