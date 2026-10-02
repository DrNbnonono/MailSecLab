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
