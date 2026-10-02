# Week 3 end to end

Gate passed: True

Lab DNS publishes DMARC p=none. That is the experimental zone, not a product default. rspamd in this image has SPF and DMARC modules disabled.

Roundcube and SnappyMail were not started in this run; no DOM or screenshot is invented.

- legit: attacker=none delivery=delivered before={'dkimpy': 'pass', 'perl': 'pass', 'go': 'pass', 'rspamd': 'pass'} after={'dkimpy': 'pass', 'perl': 'pass', 'go': 'pass', 'rspamd': 'none'}
- mutate-only: attacker=can mutate a signed message and does not have the lab.test private key delivery=delivered before={'dkimpy': 'fail', 'perl': 'pass', 'go': 'pass', 'rspamd': 'fail'} after={'dkimpy': 'fail', 'perl': 'pass', 'go': 'pass', 'rspamd': 'none'}
- unsigned: attacker=no signature delivery=delivered before={'dkimpy': 'none', 'perl': 'none', 'go': 'none', 'rspamd': 'none'} after={'dkimpy': 'none', 'perl': 'none', 'go': 'none', 'rspamd': 'none'}
- own-key: attacker=holds only the evil.test key delivery=delivered before={'dkimpy': 'fail', 'perl': 'parse-error', 'go': 'fail', 'rspamd': 'fail'} after={'dkimpy': 'fail', 'perl': 'parse-error', 'go': 'fail', 'rspamd': 'none'}
