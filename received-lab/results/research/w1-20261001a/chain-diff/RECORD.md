# SMTP chain differential

- from-insert-before: delivered before={'dkimpy': 'fail', 'perl': 'pass', 'go': 'pass', 'rspamd': 'fail'} after={'dkimpy': 'fail', 'perl': 'pass', 'go': 'pass', 'rspamd': 'none'}
- subject-insert-before: delivered before={'dkimpy': 'pass', 'perl': 'pass', 'go': 'pass', 'rspamd': 'fail'} after={'dkimpy': 'pass', 'perl': 'pass', 'go': 'pass', 'rspamd': 'none'}
- from-insert-after: delivered before={'dkimpy': 'fail', 'perl': 'fail', 'go': 'fail', 'rspamd': 'fail'} after={'dkimpy': 'fail', 'perl': 'fail', 'go': 'fail', 'rspamd': 'none'}
