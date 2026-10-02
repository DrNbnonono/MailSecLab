# Disclosure draft (not sent)

No vendor has been contacted. This file is not a notice and has not been sent.

If a later run shows a consequence beyond RFC 6376 instance selection, a notice would name the versions below, attach the fixed-signature mutant, and describe what each program displayed. The evidence in this run does not support that notice.

Versions observed here:

- dkimpy 1.1.8, perl Mail::DKIM, go-msgauth 0.6.8, rspamd 3.4
- Roundcube 1.6.19 and SnappyMail 2.38.2
- OpenDKIM 2.11.0 and OpenDMARC 1.4.2
- Exim 4.92 #5 built 04-Jan-2024, as a local positive-control image only

The mutant is `causal/cases/from-relaxed-n1-h1-insert-before/mutant.eml`. Its SHA-256 is in that case's `case.json`. On this object, perl and go-msgauth pass, dkimpy and rspamd fail, Roundcube displays Author, and SnappyMail displays Attacker. OpenDMARC's `header.from` is `evil.test`. OpenDKIM reported that the key was not found in DNS; the lab resolver did publish it.
