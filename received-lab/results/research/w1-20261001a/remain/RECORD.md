# Remaining week-5 and week-6 measurements

## Versions

```
{
  "postfix37": [
    "3.7.11"
  ],
  "postfix311": [
    "3.11.6"
  ],
  "exim": [
    "Exim version 4.96 #2 built 27-May-2026 16:52:26",
    "Copyright (c) University of Cambridge, 1995 - 2018"
  ],
  "opensmtpd": "6.8.0p2 from the existing image; the previous 60s run did not relay",
  "exim492": "no local image; positive control not run"
}
```

## Paths

- w5-osmtpd-postfix: delivered after={'dkimpy': 'fail', 'perl': 'pass', 'go': 'pass', 'rspamd': 'none'} received_count_approx=3 error=None
- w5-osmtpd-exim: delivered after={'dkimpy': 'fail', 'perl': 'pass', 'go': 'pass', 'rspamd': 'none'} received_count_approx=3 error=None
- w5-exim-postfix: delivered after={'dkimpy': 'fail', 'perl': 'pass', 'go': 'pass', 'rspamd': 'none'} received_count_approx=3 error=None
- w5-postfix-exim: delivered after={'dkimpy': 'fail', 'perl': 'pass', 'go': 'pass', 'rspamd': 'none'} received_count_approx=3 error=None
- w5-osmtpd-osmtpd: delivered after={'dkimpy': 'fail', 'perl': 'pass', 'go': 'pass', 'rspamd': 'none'} received_count_approx=3 error=None
- w5-postfix311: delivered after={'dkimpy': 'fail', 'perl': 'pass', 'go': 'pass', 'rspamd': 'none'} received_count_approx=2 error=None

## OpenSMTPD 60s cap

- {'label': 'loop-normal', 'smtp': {'client_ip': '10.88.0.11', 'reply': '250 2.0.0 e4a6432c Message accepted for delivery', 'queued_id': '', 'bytes': 153, 'sha256': '6d8a9de2d0ca297909f60ec1b2b5fd657ddb0102d61467aab2797c94c1b3035b', 'accepted': True, 'banner_ok': True, 'ehlo_ok': True, 'mail_ok': True, 'rcpt_ok': True}, 'stopped_after_seconds': 60, 'log_bytes': 167158, 'relay_mentions': 924, 'queue': '', 'queue_rc': 0}
- {'label': 'loop-obs', 'smtp': {'client_ip': '10.88.0.11', 'reply': '250 2.0.0 3ba129bc Message accepted for delivery', 'queued_id': '', 'bytes': 140, 'sha256': 'f9d1ce33813dbbb75dc8a726cb33a31bc7dd7882594121200a438b761790ffb7', 'accepted': True, 'banner_ok': True, 'ehlo_ok': True, 'mail_ok': True, 'rcpt_ok': True}, 'stopped_after_seconds': 60, 'log_bytes': 136679, 'relay_mentions': 799, 'queue': '', 'queue_rc': 0}

## Defense timing

```
{
  "python": {
    "implementation": "in-process ambiguity and display-binding rules",
    "warmup": 100,
    "rounds": [
      {
        "seconds": 0.007634,
        "messages": 500,
        "flagged": 100
      },
      {
        "seconds": 0.005915,
        "messages": 500,
        "flagged": 100
      },
      {
        "seconds": 0.004289,
        "messages": 500,
        "flagged": 100
      }
    ]
  },
  "rspamd": {
    "exit": 0,
    "seconds_lines": [
      "3",
      "13",
      "10",
      "10"
    ],
    "stderr": ""
  }
}
```

List-rewrite messages are duplicate-From by construction. The ambiguity rule flags that whole family; direct, forward, multilingual, and folded messages in the 10k set are not flagged. That flag is a false reject for legitimate list mail, and it is separate from an expected DKIM failure after a list rewrite.
