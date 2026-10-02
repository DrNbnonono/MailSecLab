# Week 2 causal

Gate passed: False

Signatures are created once. Later edits do not change `b=`.
The reference selects header instances from the bottom of the header block, RFC 6376 section 3.5.
A top-down oracle is recorded only as a contrast. Canonicalization pairs are relaxed/relaxed and simple/relaxed.

Matrix rows: 144. Verifier splits: 24.

## Problems
- unexplained verifier results: from-relaxed-n1-h2-unchanged,from-simple-n1-h2-unchanged,subject-relaxed-n1-h2-unchanged,subject-simple-n1-h2-unchanged,message-id-relaxed-n1-h2-unchanged,message-id-simple-n1-h2-unchanged

## Splits
- from-relaxed-n1-h1-insert-before: verifiers={'dkimpy': 'fail', 'perl': 'pass', 'go': 'pass', 'rspamd': 'fail'} reference=pass/fail causes={'dkimpy': 'matches-top-down-oracle', 'perl': 'matches-rfc6376-bottom-up-section-3.5', 'go': 'matches-rfc6376-bottom-up-section-3.5', 'rspamd': 'matches-top-down-oracle'}
- from-relaxed-n2-h1-unchanged: verifiers={'dkimpy': 'fail', 'perl': 'pass', 'go': 'pass', 'rspamd': 'fail'} reference=pass/fail causes={'dkimpy': 'matches-top-down-oracle', 'perl': 'matches-rfc6376-bottom-up-section-3.5', 'go': 'matches-rfc6376-bottom-up-section-3.5', 'rspamd': 'matches-top-down-oracle'}
- from-relaxed-n2-h1-edit-first: verifiers={'dkimpy': 'fail', 'perl': 'pass', 'go': 'pass', 'rspamd': 'fail'} reference=pass/fail causes={'dkimpy': 'matches-top-down-oracle', 'perl': 'matches-rfc6376-bottom-up-section-3.5', 'go': 'matches-rfc6376-bottom-up-section-3.5', 'rspamd': 'matches-top-down-oracle'}
- from-relaxed-n2-h2-unchanged: verifiers={'dkimpy': 'pass', 'perl': 'pass', 'go': 'pass', 'rspamd': 'fail'} reference=pass/fail causes={'dkimpy': 'matches-rfc6376-bottom-up-section-3.5', 'perl': 'matches-rfc6376-bottom-up-section-3.5', 'go': 'matches-rfc6376-bottom-up-section-3.5', 'rspamd': 'matches-top-down-oracle'}
- from-simple-n1-h1-insert-before: verifiers={'dkimpy': 'fail', 'perl': 'pass', 'go': 'pass', 'rspamd': 'fail'} reference=pass/fail causes={'dkimpy': 'matches-top-down-oracle', 'perl': 'matches-rfc6376-bottom-up-section-3.5', 'go': 'matches-rfc6376-bottom-up-section-3.5', 'rspamd': 'matches-top-down-oracle'}
- from-simple-n2-h1-unchanged: verifiers={'dkimpy': 'fail', 'perl': 'pass', 'go': 'pass', 'rspamd': 'fail'} reference=pass/fail causes={'dkimpy': 'matches-top-down-oracle', 'perl': 'matches-rfc6376-bottom-up-section-3.5', 'go': 'matches-rfc6376-bottom-up-section-3.5', 'rspamd': 'matches-top-down-oracle'}
- from-simple-n2-h1-edit-first: verifiers={'dkimpy': 'fail', 'perl': 'pass', 'go': 'pass', 'rspamd': 'fail'} reference=pass/fail causes={'dkimpy': 'matches-top-down-oracle', 'perl': 'matches-rfc6376-bottom-up-section-3.5', 'go': 'matches-rfc6376-bottom-up-section-3.5', 'rspamd': 'matches-top-down-oracle'}
- from-simple-n2-h2-unchanged: verifiers={'dkimpy': 'pass', 'perl': 'pass', 'go': 'pass', 'rspamd': 'fail'} reference=pass/fail causes={'dkimpy': 'matches-rfc6376-bottom-up-section-3.5', 'perl': 'matches-rfc6376-bottom-up-section-3.5', 'go': 'matches-rfc6376-bottom-up-section-3.5', 'rspamd': 'matches-top-down-oracle'}
- subject-relaxed-n1-h1-insert-before: verifiers={'dkimpy': 'pass', 'perl': 'pass', 'go': 'pass', 'rspamd': 'fail'} reference=pass/fail causes={'dkimpy': 'matches-rfc6376-bottom-up-section-3.5', 'perl': 'matches-rfc6376-bottom-up-section-3.5', 'go': 'matches-rfc6376-bottom-up-section-3.5', 'rspamd': 'matches-top-down-oracle'}
- subject-relaxed-n2-h1-unchanged: verifiers={'dkimpy': 'pass', 'perl': 'pass', 'go': 'pass', 'rspamd': 'fail'} reference=pass/fail causes={'dkimpy': 'matches-rfc6376-bottom-up-section-3.5', 'perl': 'matches-rfc6376-bottom-up-section-3.5', 'go': 'matches-rfc6376-bottom-up-section-3.5', 'rspamd': 'matches-top-down-oracle'}
- subject-relaxed-n2-h1-edit-first: verifiers={'dkimpy': 'pass', 'perl': 'pass', 'go': 'pass', 'rspamd': 'fail'} reference=pass/fail causes={'dkimpy': 'matches-rfc6376-bottom-up-section-3.5', 'perl': 'matches-rfc6376-bottom-up-section-3.5', 'go': 'matches-rfc6376-bottom-up-section-3.5', 'rspamd': 'matches-top-down-oracle'}
- subject-relaxed-n2-h2-unchanged: verifiers={'dkimpy': 'pass', 'perl': 'pass', 'go': 'pass', 'rspamd': 'fail'} reference=pass/fail causes={'dkimpy': 'matches-rfc6376-bottom-up-section-3.5', 'perl': 'matches-rfc6376-bottom-up-section-3.5', 'go': 'matches-rfc6376-bottom-up-section-3.5', 'rspamd': 'matches-top-down-oracle'}
- subject-simple-n1-h1-insert-before: verifiers={'dkimpy': 'pass', 'perl': 'pass', 'go': 'pass', 'rspamd': 'fail'} reference=pass/fail causes={'dkimpy': 'matches-rfc6376-bottom-up-section-3.5', 'perl': 'matches-rfc6376-bottom-up-section-3.5', 'go': 'matches-rfc6376-bottom-up-section-3.5', 'rspamd': 'matches-top-down-oracle'}
- subject-simple-n2-h1-unchanged: verifiers={'dkimpy': 'pass', 'perl': 'pass', 'go': 'pass', 'rspamd': 'fail'} reference=pass/fail causes={'dkimpy': 'matches-rfc6376-bottom-up-section-3.5', 'perl': 'matches-rfc6376-bottom-up-section-3.5', 'go': 'matches-rfc6376-bottom-up-section-3.5', 'rspamd': 'matches-top-down-oracle'}
- subject-simple-n2-h1-edit-first: verifiers={'dkimpy': 'pass', 'perl': 'pass', 'go': 'pass', 'rspamd': 'fail'} reference=pass/fail causes={'dkimpy': 'matches-rfc6376-bottom-up-section-3.5', 'perl': 'matches-rfc6376-bottom-up-section-3.5', 'go': 'matches-rfc6376-bottom-up-section-3.5', 'rspamd': 'matches-top-down-oracle'}
- subject-simple-n2-h2-unchanged: verifiers={'dkimpy': 'pass', 'perl': 'pass', 'go': 'pass', 'rspamd': 'fail'} reference=pass/fail causes={'dkimpy': 'matches-rfc6376-bottom-up-section-3.5', 'perl': 'matches-rfc6376-bottom-up-section-3.5', 'go': 'matches-rfc6376-bottom-up-section-3.5', 'rspamd': 'matches-top-down-oracle'}
- message-id-relaxed-n1-h1-insert-before: verifiers={'dkimpy': 'pass', 'perl': 'pass', 'go': 'pass', 'rspamd': 'fail'} reference=pass/fail causes={'dkimpy': 'matches-rfc6376-bottom-up-section-3.5', 'perl': 'matches-rfc6376-bottom-up-section-3.5', 'go': 'matches-rfc6376-bottom-up-section-3.5', 'rspamd': 'matches-top-down-oracle'}
- message-id-relaxed-n2-h1-unchanged: verifiers={'dkimpy': 'pass', 'perl': 'pass', 'go': 'pass', 'rspamd': 'fail'} reference=pass/fail causes={'dkimpy': 'matches-rfc6376-bottom-up-section-3.5', 'perl': 'matches-rfc6376-bottom-up-section-3.5', 'go': 'matches-rfc6376-bottom-up-section-3.5', 'rspamd': 'matches-top-down-oracle'}
- message-id-relaxed-n2-h1-edit-first: verifiers={'dkimpy': 'pass', 'perl': 'pass', 'go': 'pass', 'rspamd': 'fail'} reference=pass/fail causes={'dkimpy': 'matches-rfc6376-bottom-up-section-3.5', 'perl': 'matches-rfc6376-bottom-up-section-3.5', 'go': 'matches-rfc6376-bottom-up-section-3.5', 'rspamd': 'matches-top-down-oracle'}
- message-id-relaxed-n2-h2-unchanged: verifiers={'dkimpy': 'pass', 'perl': 'pass', 'go': 'pass', 'rspamd': 'fail'} reference=pass/fail causes={'dkimpy': 'matches-rfc6376-bottom-up-section-3.5', 'perl': 'matches-rfc6376-bottom-up-section-3.5', 'go': 'matches-rfc6376-bottom-up-section-3.5', 'rspamd': 'matches-top-down-oracle'}
- message-id-simple-n1-h1-insert-before: verifiers={'dkimpy': 'pass', 'perl': 'pass', 'go': 'pass', 'rspamd': 'fail'} reference=pass/fail causes={'dkimpy': 'matches-rfc6376-bottom-up-section-3.5', 'perl': 'matches-rfc6376-bottom-up-section-3.5', 'go': 'matches-rfc6376-bottom-up-section-3.5', 'rspamd': 'matches-top-down-oracle'}
- message-id-simple-n2-h1-unchanged: verifiers={'dkimpy': 'pass', 'perl': 'pass', 'go': 'pass', 'rspamd': 'fail'} reference=pass/fail causes={'dkimpy': 'matches-rfc6376-bottom-up-section-3.5', 'perl': 'matches-rfc6376-bottom-up-section-3.5', 'go': 'matches-rfc6376-bottom-up-section-3.5', 'rspamd': 'matches-top-down-oracle'}
- message-id-simple-n2-h1-edit-first: verifiers={'dkimpy': 'pass', 'perl': 'pass', 'go': 'pass', 'rspamd': 'fail'} reference=pass/fail causes={'dkimpy': 'matches-rfc6376-bottom-up-section-3.5', 'perl': 'matches-rfc6376-bottom-up-section-3.5', 'go': 'matches-rfc6376-bottom-up-section-3.5', 'rspamd': 'matches-top-down-oracle'}
- message-id-simple-n2-h2-unchanged: verifiers={'dkimpy': 'pass', 'perl': 'pass', 'go': 'pass', 'rspamd': 'fail'} reference=pass/fail causes={'dkimpy': 'matches-rfc6376-bottom-up-section-3.5', 'perl': 'matches-rfc6376-bottom-up-section-3.5', 'go': 'matches-rfc6376-bottom-up-section-3.5', 'rspamd': 'matches-top-down-oracle'}

## Malformed series

- obs-from-before: reference=parse-error verifiers={'dkimpy': 'pass', 'perl': 'pass', 'go': 'pass', 'rspamd': 'pass'} issues=[] syntax=['modern', 'obs', 'modern', 'modern', 'modern', 'modern', 'modern', 'modern']
- blank-line-before-from: reference=fail verifiers={'dkimpy': 'fail', 'perl': 'fail', 'go': 'fail', 'rspamd': 'fail'} issues=[] syntax=['modern']


# Week 2 root cause

The signature bytes are fixed before each edit. The reference implements RFC 6376 section 3.5 bottom-up selection.
A single-row match to the top-down oracle is not treated as proof of that algorithm when the opposite insertion fails as well.

dkimpy 1.1.8 default `h=` is `from:to:date:subject:message-id:from`. Its `select_headers()` does not hash a missing extra name.
Signatures in the main matrix that repeat a name with no remaining instance include that null field. All four verifiers reject those unchanged controls.
The omit-missing series below signs the same repeated `h=` without the null field.

## Position pairs

- from relaxed/relaxed h= once: {'dkimpy': 'fails-when-either-instance-is-added', 'perl': 'bottom-up-instance', 'go': 'bottom-up-instance', 'rspamd': 'fails-when-either-instance-is-added'}
- from simple/relaxed h= once: {'dkimpy': 'fails-when-either-instance-is-added', 'perl': 'bottom-up-instance', 'go': 'bottom-up-instance', 'rspamd': 'fails-when-either-instance-is-added'}
- subject relaxed/relaxed h= once: {'dkimpy': 'bottom-up-instance', 'perl': 'bottom-up-instance', 'go': 'bottom-up-instance', 'rspamd': 'fails-when-either-instance-is-added'}
- subject simple/relaxed h= once: {'dkimpy': 'bottom-up-instance', 'perl': 'bottom-up-instance', 'go': 'bottom-up-instance', 'rspamd': 'fails-when-either-instance-is-added'}
- message-id relaxed/relaxed h= once: {'dkimpy': 'bottom-up-instance', 'perl': 'bottom-up-instance', 'go': 'bottom-up-instance', 'rspamd': 'fails-when-either-instance-is-added'}
- message-id simple/relaxed h= once: {'dkimpy': 'bottom-up-instance', 'perl': 'bottom-up-instance', 'go': 'bottom-up-instance', 'rspamd': 'fails-when-either-instance-is-added'}

## Omit-missing oversign

- omit-from-relaxed-unchanged: reference=pass verifiers={'dkimpy': 'pass', 'perl': 'pass', 'go': 'pass', 'rspamd': 'pass'}
- omit-from-relaxed-insert-before: reference=fail verifiers={'dkimpy': 'fail', 'perl': 'fail', 'go': 'fail', 'rspamd': 'fail'}
- omit-from-relaxed-insert-after: reference=fail verifiers={'dkimpy': 'fail', 'perl': 'fail', 'go': 'fail', 'rspamd': 'fail'}
- omit-from-simple-unchanged: reference=pass verifiers={'dkimpy': 'pass', 'perl': 'pass', 'go': 'pass', 'rspamd': 'pass'}
- omit-from-simple-insert-before: reference=fail verifiers={'dkimpy': 'fail', 'perl': 'fail', 'go': 'fail', 'rspamd': 'fail'}
- omit-from-simple-insert-after: reference=fail verifiers={'dkimpy': 'fail', 'perl': 'fail', 'go': 'fail', 'rspamd': 'fail'}
- omit-subject-relaxed-unchanged: reference=pass verifiers={'dkimpy': 'pass', 'perl': 'pass', 'go': 'pass', 'rspamd': 'pass'}
- omit-subject-relaxed-insert-before: reference=fail verifiers={'dkimpy': 'fail', 'perl': 'fail', 'go': 'fail', 'rspamd': 'fail'}
- omit-subject-relaxed-insert-after: reference=fail verifiers={'dkimpy': 'fail', 'perl': 'fail', 'go': 'fail', 'rspamd': 'fail'}
- omit-subject-simple-unchanged: reference=pass verifiers={'dkimpy': 'pass', 'perl': 'pass', 'go': 'pass', 'rspamd': 'pass'}
- omit-subject-simple-insert-before: reference=fail verifiers={'dkimpy': 'fail', 'perl': 'fail', 'go': 'fail', 'rspamd': 'fail'}
- omit-subject-simple-insert-after: reference=fail verifiers={'dkimpy': 'fail', 'perl': 'fail', 'go': 'fail', 'rspamd': 'fail'}
- omit-message-id-relaxed-unchanged: reference=pass verifiers={'dkimpy': 'pass', 'perl': 'pass', 'go': 'pass', 'rspamd': 'pass'}
- omit-message-id-relaxed-insert-before: reference=fail verifiers={'dkimpy': 'fail', 'perl': 'fail', 'go': 'fail', 'rspamd': 'fail'}
- omit-message-id-relaxed-insert-after: reference=fail verifiers={'dkimpy': 'fail', 'perl': 'fail', 'go': 'fail', 'rspamd': 'fail'}
- omit-message-id-simple-unchanged: reference=pass verifiers={'dkimpy': 'pass', 'perl': 'pass', 'go': 'pass', 'rspamd': 'pass'}
- omit-message-id-simple-insert-before: reference=fail verifiers={'dkimpy': 'fail', 'perl': 'fail', 'go': 'fail', 'rspamd': 'fail'}
- omit-message-id-simple-insert-after: reference=fail verifiers={'dkimpy': 'fail', 'perl': 'fail', 'go': 'fail', 'rspamd': 'fail'}
