# Week 1 bootstrap

Gate passed: True

This run does not modify historical RECORD files, signatures, or the old Mailpit volume.
Postfix is the on-disk image, not a claim that the 2026-09-01 freeze id was restored.

## Environment drift

- Postfix image on disk is not the 2026-09-01 freeze id. Week-1 chain reuses the on-disk received-lab-postfix images and records mail_version.
- dkimpy, Mail::DKIM, go-msgauth, dnsmasq and rspamd images were not present and are built for this project.

- Postfix mail_version: 3.7.11
- Mailpit freeze prefix match: True

## Calibration

| case | dkimpy | perl | go-msgauth | rspamd | exact DNS query |
| --- | --- | --- | --- | --- | --- |
| legal | pass | pass | pass | pass | True |
| header-tamper | fail | fail | fail | fail | True |
| body-tamper | fail | fail | fail | fail | True |
| wrong-key | fail | fail | fail | fail | True |
| unsigned | none | none | none | none | True |
| legal-lf | pass | pass | pass | pass | True |

## I2

File scans use rspamd `get_from_ip()` after `H_SOURCE_IP` was registered. SPF, DMARC and RBL are off in this image, and `maps.rspamd.com` resolves to 127.0.0.1. The symbol reads the from-address of the top Received header. On the pre-relay consistent and inconsistent messages that address is 203.0.113.11. After the three-hop chain the top Received is Mailpit's record of postfix3, so the symbol is 10.88.0.23. It is not the client address 10.88.0.11 and not the broken by-host.

- plain: delivery=delivered join_ok=True reasons=[] rspamd={'input': {'status': 'none', 'action': 'no action', 'score': 2.4, 'source': ['NO_IP|nil'], 'rescan': 'after H_SOURCE_IP registration; same stored bytes'}, 'stored': {'status': 'none', 'action': 'no action', 'score': 0.0, 'source': ['10.88.0.23|msl-postfix3.mailseclab-research-net.'], 'rescan': 'after H_SOURCE_IP registration; same stored bytes'}}
- consistent: delivery=delivered join_ok=True reasons=[] rspamd={'input': {'status': 'none', 'action': 'no action', 'score': 0.0, 'source': ['203.0.113.11|relay.example'], 'rescan': 'after H_SOURCE_IP registration; same stored bytes'}, 'stored': {'status': 'none', 'action': 'no action', 'score': 0.0, 'source': ['10.88.0.23|msl-postfix3.mailseclab-research-net.'], 'rescan': 'after H_SOURCE_IP registration; same stored bytes'}}
- inconsistent: delivery=delivered join_ok=False reasons=['by-host forged.example != from-host client.lab.test', 'forged by-clause does not contain the client IP'] rspamd={'input': {'status': 'none', 'action': 'no action', 'score': 0.0, 'source': ['203.0.113.11|relay.example'], 'rescan': 'after H_SOURCE_IP registration; same stored bytes'}, 'stored': {'status': 'none', 'action': 'no action', 'score': 0.0, 'source': ['10.88.0.23|msl-postfix3.mailseclab-research-net.'], 'rescan': 'after H_SOURCE_IP registration; same stored bytes'}}

## G4

Headers are modern folded fields: each physical line is 78 octets or shorter, and each unfolded X-Received field is about 78000 octets. This is not a replay of the earlier 9096191-byte figure. postcat output was saved for every hop.
- G4-N1: bytes=80240 smtp=250 2.0.0 Ok: queued as 13B879C585 delivery=delivered stored_x_received=1 gaps=[]
- G4-N50: bytes=4000391 smtp=250 2.0.0 Ok: queued as D53689C635 delivery=delivered stored_x_received=50 gaps=[]
- G4-N100: bytes=8000545 smtp=250 2.0.0 Ok: queued as 0D2C89C63F delivery=delivered stored_x_received=100 gaps=[]

## Gate

- Controls passed. No week-1 row is counted as a new finding.
