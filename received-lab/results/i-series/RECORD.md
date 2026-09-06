# I 系列实验记录（2026-09-06）

**I1 · SMTP 走私（RFC 5321 §4.1.1.4 / CVE-2023-51764 家族）**：BDAT(CHUNKING) 接收
不解释点字节；若 MTA1 中继时只对 CRLF.CRLF 做 dot-stuffing、payload 中的裸 `LF.LF`
未处理，而 MTA2 对裸点宽容，则攻击者可在一条 BDAT 报文里注入第二条 SMTP 报文。
**I2 · Received 链自洽伪造**：攻击者知道自己的 EHLO 名与 IP，可构造与真实中继头
完全衔接的伪造链 —— 测试 rspamd 链一致性校验是否拦截（承接 H3）。

[19:31:26] == PRE-UP ==
[19:31:31] == I0: EHLO probe ==
-- postfix1
250-PIPELINING
250 CHUNKING
-- exim
-- opensmtpd
-- postfix1n
-- mailpit
[19:32:17] == payload build ==
345
335
[19:32:17] == I1 matrix: MTA1(BDAT) x MTA2 x separator ==
  I1-exim-to-postfix2-crlf ->  first/smug=0/0
  I1-exim-to-postfix2-lf ->  first/smug=0/0
  I1-exim-to-opensmtpd-crlf ->  first/smug=0/0
  I1-exim-to-opensmtpd-lf ->  first/smug=0/0
  I1-exim-to-mailpit-crlf ->  first/smug=0/0
  I1-exim-to-mailpit-lf ->  first/smug=0/0
  I1-opensmtpd-to-postfix2-crlf ->  first/smug=0/0
  I1-opensmtpd-to-postfix2-lf ->  first/smug=0/0
  I1-opensmtpd-to-exim-crlf ->  first/smug=0/0
  I1-opensmtpd-to-exim-lf ->  first/smug=0/0
  I1-opensmtpd-to-mailpit-crlf ->  first/smug=0/0
  I1-opensmtpd-to-mailpit-lf ->  first/smug=0/0
[19:36:40] == I1b: direct receiver leniency (client DATA with bare LF dot) ==
  I1b postfix1 -> first/smug=1/0
  I1b exim -> first/smug=1/0
  I1b opensmtpd -> first/smug=1/0
  I1b mailpit -> first/smug=1/0
  I1b postfix1n -> first/smug=1/0
[19:37:52] == I1 DONE ==
[19:39:36] == I1 v2: self-healing matrix ==
  I1-postfix1-to-postfix2-crlf ->  first/smug=0/0
  I1-postfix1-to-postfix2-lf ->  first/smug=0/0
  I1-postfix1-to-postfix2n-crlf ->  first/smug=0/0
  I1-postfix1-to-postfix2n-lf ->  first/smug=0/0
  I1-postfix1-to-exim-crlf ->  first/smug=0/0
  I1-postfix1-to-exim-lf ->  first/smug=0/0
  I1-postfix1-to-opensmtpd-crlf ->  first/smug=0/0
  I1-postfix1-to-opensmtpd-lf ->  first/smug=0/0
  I1-postfix1-to-mailpit-crlf ->  first/smug=0/0
  I1-postfix1-to-mailpit-lf ->  first/smug=0/0
  I1-exim-to-postfix2-crlf ->  first/smug=0/0
  I1-exim-to-postfix2-lf ->  first/smug=0/0
  I1-exim-to-postfix2n-crlf ->  first/smug=0/0
  I1-exim-to-postfix2n-lf ->  first/smug=0/0
  I1-exim-to-opensmtpd-crlf ->  first/smug=0/0
  I1-exim-to-opensmtpd-lf ->  first/smug=0/0
  I1-exim-to-mailpit-crlf ->  first/smug=0/0
  I1-exim-to-mailpit-lf ->  first/smug=0/0
  I1-opensmtpd-to-postfix2-crlf ->  first/smug=0/0
  I1-opensmtpd-to-postfix2-lf ->  first/smug=0/0
  I1-opensmtpd-to-postfix2n-crlf ->  first/smug=0/0
  I1-opensmtpd-to-postfix2n-lf ->  first/smug=0/0
  I1-opensmtpd-to-postfix1n-crlf ->  first/smug=0/0
  I1-opensmtpd-to-postfix1n-lf ->  first/smug=0/0
  I1-opensmtpd-to-mailpit-crlf ->  first/smug=0/0
  I1-opensmtpd-to-mailpit-lf ->  first/smug=0/0
[19:50:06] == I1 v2 DONE ==
[19:50:52] == I1 v2: self-healing matrix ==
  I1-postfix1-to-postfix2-crlf ->  first/smug=0/0
  I1-postfix1-to-postfix2-lf ->  first/smug=0/0
  I1-postfix1-to-postfix2n-crlf ->  first/smug=0/0
  I1-postfix1-to-postfix2n-lf ->  first/smug=0/0
  I1-postfix1-to-exim-crlf ->  first/smug=0/0
  I1-postfix1-to-exim-lf ->  first/smug=0/0
  I1-postfix1-to-opensmtpd-crlf ->  first/smug=0/0
  I1-postfix1-to-opensmtpd-lf ->  first/smug=0/0
  I1-postfix1-to-mailpit-crlf ->  first/smug=0/0
  I1-postfix1-to-mailpit-lf ->  first/smug=0/0
  I1-exim-to-postfix2-crlf ->  first/smug=0/0
  I1-exim-to-postfix2-lf ->  first/smug=0/0
  I1-exim-to-postfix2n-crlf ->  first/smug=0/0
  I1-exim-to-postfix2n-lf ->  first/smug=0/0
  I1-exim-to-opensmtpd-crlf ->  first/smug=0/0
  I1-exim-to-opensmtpd-lf ->  first/smug=0/0
  I1-exim-to-mailpit-crlf ->  first/smug=0/0
  I1-exim-to-mailpit-lf ->  first/smug=0/0
  I1-opensmtpd-to-postfix2-crlf ->  first/smug=0/0
  I1-opensmtpd-to-postfix2-lf ->  first/smug=0/0
  I1-opensmtpd-to-postfix2n-crlf ->  first/smug=0/0
  I1-opensmtpd-to-postfix2n-lf ->  first/smug=0/0
  I1-opensmtpd-to-postfix1n-crlf ->  first/smug=0/0
  I1-opensmtpd-to-postfix1n-lf ->  first/smug=0/0
  I1-opensmtpd-to-mailpit-crlf ->  first/smug=0/0
  I1-opensmtpd-to-mailpit-lf ->  first/smug=0/0
[20:01:20] == I1 v2 DONE ==
[20:01:46] == I1 v2: self-healing matrix ==
  I1-postfix1-to-postfix2-crlf ->  first/smug=0/0
  I1-postfix1-to-postfix2-lf ->  first/smug=0/0
  I1-postfix1-to-postfix2n-crlf ->  first/smug=0/0
  I1-postfix1-to-postfix2n-lf ->  first/smug=0/0
  I1-postfix1-to-exim-crlf ->  first/smug=0/0
  I1-postfix1-to-exim-lf ->  first/smug=0/0
  I1-postfix1-to-opensmtpd-crlf ->  first/smug=0/0
  I1-postfix1-to-opensmtpd-lf ->  first/smug=0/0
  I1-postfix1-to-mailpit-crlf ->  first/smug=0/0
  I1-postfix1-to-mailpit-lf ->  first/smug=0/0
  I1-exim-to-postfix2-crlf ->  first/smug=0/0
  I1-exim-to-postfix2-lf ->  first/smug=0/0
  I1-exim-to-postfix2n-crlf ->  first/smug=0/0
  I1-exim-to-postfix2n-lf ->  first/smug=0/0
  I1-exim-to-opensmtpd-crlf ->  first/smug=0/0
  I1-exim-to-opensmtpd-lf ->  first/smug=0/0
  I1-exim-to-mailpit-crlf ->  first/smug=0/0
  I1-exim-to-mailpit-lf ->  first/smug=0/0
  I1-opensmtpd-to-postfix2-crlf ->  first/smug=0/0
  I1-opensmtpd-to-postfix2-lf ->  first/smug=0/0
  I1-opensmtpd-to-postfix2n-crlf ->  first/smug=0/0
  I1-opensmtpd-to-postfix2n-lf ->  first/smug=0/0
  I1-opensmtpd-to-postfix1n-crlf ->  first/smug=0/0
  I1-opensmtpd-to-postfix1n-lf ->  first/smug=0/0
  I1-opensmtpd-to-mailpit-crlf ->  first/smug=0/0
  I1-opensmtpd-to-mailpit-lf ->  first/smug=0/0
[20:12:11] == I1 v2 DONE ==
[20:12:54] == I1 v3: per-pair payload, self-healing ==
  I1-postfix1-to-postfix2-crlf ->  first/smug=0/0
  I1-postfix1-to-postfix2-lf ->  first/smug=0/0
  I1-postfix1-to-postfix2n-crlf ->  first/smug=0/0
  I1-postfix1-to-postfix2n-lf ->  first/smug=0/0
  I1-postfix1-to-exim-crlf ->  first/smug=0/0
  I1-postfix1-to-exim-lf ->  first/smug=0/0
  I1-postfix1-to-opensmtpd-crlf ->  first/smug=0/0
  I1-postfix1-to-opensmtpd-lf ->  first/smug=0/0
  I1-postfix1-to-mailpit-crlf ->  first/smug=0/0
  I1-postfix1-to-mailpit-lf ->  first/smug=0/0
  I1-exim-to-postfix2-crlf ->  first/smug=0/0
  I1-exim-to-postfix2-lf ->  first/smug=0/0
  I1-exim-to-postfix2n-crlf ->  first/smug=0/0
  I1-exim-to-postfix2n-lf ->  first/smug=0/0
  I1-exim-to-opensmtpd-crlf ->  first/smug=0/0
  I1-exim-to-opensmtpd-lf ->  first/smug=0/0
  I1-exim-to-mailpit-crlf ->  first/smug=0/0
  I1-exim-to-mailpit-lf ->  first/smug=0/0
  I1-opensmtpd-to-postfix2-crlf ->  first/smug=0/0
  I1-opensmtpd-to-postfix2-lf ->  first/smug=0/0
  I1-opensmtpd-to-postfix2n-crlf ->  first/smug=0/0
  I1-opensmtpd-to-postfix2n-lf ->  first/smug=0/0
  I1-opensmtpd-to-postfix1n-crlf ->  first/smug=0/0
  I1-opensmtpd-to-postfix1n-lf ->  first/smug=0/0
  I1-opensmtpd-to-mailpit-crlf ->  first/smug=0/0
  I1-opensmtpd-to-mailpit-lf ->  first/smug=0/0
[20:23:20] == I1 v3 DONE ==
[20:24:10] == I1 v3: per-pair payload, self-healing ==
  I1-postfix1-to-postfix2-crlf ->  first/smug=0/0
  I1-postfix1-to-postfix2-lf ->  first/smug=0/0
  I1-postfix1-to-postfix2n-crlf ->  first/smug=0/0
  I1-postfix1-to-postfix2n-lf ->  first/smug=0/0
  I1-postfix1-to-exim-crlf ->  first/smug=0/0
  I1-postfix1-to-exim-lf ->  first/smug=0/0
  I1-postfix1-to-opensmtpd-crlf ->  first/smug=0/0
  I1-postfix1-to-opensmtpd-lf ->  first/smug=0/0
  I1-postfix1-to-mailpit-crlf ->  first/smug=0/0
  I1-postfix1-to-mailpit-lf ->  first/smug=0/0
  I1-exim-to-postfix2-crlf ->  first/smug=0/0
  I1-exim-to-postfix2-lf ->  first/smug=0/0
  I1-exim-to-postfix2n-crlf ->  first/smug=0/0
  I1-exim-to-postfix2n-lf ->  first/smug=0/0
  I1-exim-to-opensmtpd-crlf ->  first/smug=0/0
  I1-exim-to-opensmtpd-lf ->  first/smug=0/0
  I1-exim-to-mailpit-crlf ->  first/smug=0/0
  I1-exim-to-mailpit-lf ->  first/smug=0/0
  I1-opensmtpd-to-postfix2-crlf ->  first/smug=0/0
  I1-opensmtpd-to-postfix2-lf ->  first/smug=0/0
  I1-opensmtpd-to-postfix2n-crlf ->  first/smug=0/0
  I1-opensmtpd-to-postfix2n-lf ->  first/smug=0/0
  I1-opensmtpd-to-postfix1n-crlf ->  first/smug=0/0
  I1-opensmtpd-to-postfix1n-lf ->  first/smug=0/0
  I1-opensmtpd-to-mailpit-crlf ->  first/smug=0/0
  I1-opensmtpd-to-mailpit-lf ->  first/smug=0/0
[20:34:38] == I1 v3 DONE ==
[20:35:23] == I1 v3: per-pair payload, self-healing ==
  I1-postfix1-to-postfix2-crlf -> CHUNKING=True BDAT_REPLY: 250 2.0.0 Ok: 429 bytes queued as B112935CB  first/smug=1/0
  I1-postfix1-to-postfix2-lf -> CHUNKING=True BDAT_REPLY: 250 2.0.0 Ok: 421 bytes queued as D0B3B39B2  first/smug=1/0
  I1-postfix1-to-postfix2n-crlf -> CHUNKING=True BDAT_REPLY: 250 2.0.0 Ok: 433 bytes queued as D6D1639B2  first/smug=0/0
  I1-postfix1-to-postfix2n-lf -> CHUNKING=True BDAT_REPLY: 250 2.0.0 Ok: 425 bytes queued as 0FDF935C8  first/smug=0/0
  I1-postfix1-to-exim-crlf -> CHUNKING=True BDAT_REPLY: 250 2.0.0 Ok: 413 bytes queued as EAEA7DCC4  first/smug=0/0
  I1-postfix1-to-exim-lf -> CHUNKING=True BDAT_REPLY: 250 2.0.0 Ok: 405 bytes queued as 1CD06DCC8  first/smug=0/0
  I1-postfix1-to-opensmtpd-crlf -> CHUNKING=True BDAT_REPLY: 250 2.0.0 Ok: 433 bytes queued as DF5B735CB  first/smug=0/0
  I1-postfix1-to-opensmtpd-lf -> CHUNKING=True BDAT_REPLY: 250 2.0.0 Ok: 425 bytes queued as 0F92216E51  first/smug=0/0
  I1-postfix1-to-mailpit-crlf -> CHUNKING=True BDAT_REPLY: 250 2.0.0 Ok: 425 bytes queued as EA2ADDCAE  first/smug=0/0
  I1-postfix1-to-mailpit-lf -> CHUNKING=True BDAT_REPLY: 250 2.0.0 Ok: 417 bytes queued as 28BB926968  first/smug=0/0
  I1-exim-to-postfix2-crlf -> CHUNKING=True BDAT_REPLY: 250 OK id=1x3C9a-00000E-1K  first/smug=0/0
  I1-exim-to-postfix2-lf -> CHUNKING=True BDAT_REPLY: 250 OK id=1x3C9w-00000G-2B  first/smug=0/0
  I1-exim-to-postfix2n-crlf -> CHUNKING=True BDAT_REPLY: 250 OK id=1x3CAL-00000D-1s  first/smug=0/0
  I1-exim-to-postfix2n-lf -> CHUNKING=True BDAT_REPLY: 250 OK id=1x3CAh-00000F-2J  first/smug=0/0
  I1-exim-to-opensmtpd-crlf -> CHUNKING=True BDAT_REPLY: 250 OK id=1x3CB6-00000E-1T  first/smug=0/0
  I1-exim-to-opensmtpd-lf -> CHUNKING=True BDAT_REPLY: 250 OK id=1x3CBS-00000G-2K  first/smug=0/0
  I1-exim-to-mailpit-crlf -> CHUNKING=True BDAT_REPLY: 250 OK id=1x3CBr-00000E-1m  first/smug=0/0
  I1-exim-to-mailpit-lf -> CHUNKING=True BDAT_REPLY: 250 OK id=1x3CCD-00000G-2S  first/smug=0/0
  I1-opensmtpd-to-postfix2-crlf -> CHUNKING=False BDAT_REPLY: 500 5.5.1 Invalid command: Command unrecognized  first/smug=0/0
  I1-opensmtpd-to-postfix2-lf -> CHUNKING=False BDAT_REPLY: 500 5.5.1 Invalid command: Command unrecognized  first/smug=0/0
  I1-opensmtpd-to-postfix2n-crlf -> CHUNKING=False BDAT_REPLY: 500 5.5.1 Invalid command: Command unrecognized  first/smug=0/0
  I1-opensmtpd-to-postfix2n-lf -> CHUNKING=False BDAT_REPLY: 500 5.5.1 Invalid command: Command unrecognized  first/smug=0/0
  I1-opensmtpd-to-postfix1n-crlf -> CHUNKING=False BDAT_REPLY: 500 5.5.1 Invalid command: Command unrecognized  first/smug=0/0
  I1-opensmtpd-to-postfix1n-lf -> CHUNKING=False BDAT_REPLY: 500 5.5.1 Invalid command: Command unrecognized  first/smug=0/0
  I1-opensmtpd-to-mailpit-crlf -> CHUNKING=False BDAT_REPLY: 500 5.5.1 Invalid command: Command unrecognized  first/smug=0/0
  I1-opensmtpd-to-mailpit-lf -> CHUNKING=False BDAT_REPLY: 500 5.5.1 Invalid command: Command unrecognized  first/smug=0/0
[20:45:39] == I1 v3 DONE ==
[20:48:07] == I1 v3: per-pair payload, self-healing ==
  I1-postfix1-to-postfix2-crlf -> CHUNKING=True BDAT_REPLY: 250 2.0.0 Ok: 429 bytes queued as C5AFCC35E  first/smug=1/0
  I1-postfix1-to-postfix2-lf -> CHUNKING=True BDAT_REPLY: 250 2.0.0 Ok: 421 bytes queued as DA676C35E  first/smug=1/0
  I1-postfix1-to-postfix2n-crlf -> CHUNKING=True BDAT_REPLY: 250 2.0.0 Ok: 433 bytes queued as AB57D67F  first/smug=0/0
  I1-postfix1-to-postfix2n-lf -> CHUNKING=True BDAT_REPLY: 250 2.0.0 Ok: 425 bytes queued as DCE45C35D  first/smug=0/0
  I1-postfix1-to-exim-crlf -> CHUNKING=True BDAT_REPLY: 250 2.0.0 Ok: 413 bytes queued as C6AA0BB55  first/smug=0/0
  I1-postfix1-to-exim-lf -> CHUNKING=True BDAT_REPLY: 250 2.0.0 Ok: 405 bytes queued as E6048DCA8  first/smug=0/0
  I1-postfix1-to-opensmtpd-crlf -> CHUNKING=True BDAT_REPLY: 250 2.0.0 Ok: 433 bytes queued as B3115C35E  first/smug=0/0
  I1-postfix1-to-opensmtpd-lf -> CHUNKING=True BDAT_REPLY: 250 2.0.0 Ok: 425 bytes queued as C604348E69  first/smug=0/0
  I1-postfix1-to-mailpit-crlf -> CHUNKING=True BDAT_REPLY: 250 2.0.0 Ok: 425 bytes queued as E69F050686  first/smug=0/0
  I1-postfix1-to-mailpit-lf -> CHUNKING=True BDAT_REPLY: 250 2.0.0 Ok: 417 bytes queued as 07A9D48E76  first/smug=0/0
  I1-exim-to-postfix2-crlf -> CHUNKING=True BDAT_REPLY: 250 OK id=1x3CLt-00000D-13  first/smug=0/0
  I1-exim-to-postfix2-lf -> CHUNKING=True BDAT_REPLY: 250 OK id=1x3CMF-00000F-1a  first/smug=0/0
  I1-exim-to-postfix2n-crlf -> CHUNKING=True BDAT_REPLY: 250 OK id=1x3CMe-00000E-2I  first/smug=0/0
  I1-exim-to-postfix2n-lf -> CHUNKING=True BDAT_REPLY: 250 OK id=1x3CN0-00000G-2y  first/smug=0/0
  I1-exim-to-opensmtpd-crlf -> CHUNKING=True BDAT_REPLY: 250 OK id=1x3CNQ-00000E-0F  first/smug=0/0
  I1-exim-to-opensmtpd-lf -> CHUNKING=True BDAT_REPLY: 250 OK id=1x3CNm-00000G-10  first/smug=0/0
  I1-exim-to-mailpit-crlf -> CHUNKING=True BDAT_REPLY: 250 OK id=1x3COB-00000E-0b  first/smug=0/0
  I1-exim-to-mailpit-lf -> CHUNKING=True BDAT_REPLY: 250 OK id=1x3COX-00000G-12  first/smug=0/0
  I1-opensmtpd-to-postfix2-crlf -> CHUNKING=False BDAT_REPLY: 500 5.5.1 Invalid command: Command unrecognized  first/smug=0/0
  I1-opensmtpd-to-postfix2-lf -> CHUNKING=False BDAT_REPLY: 500 5.5.1 Invalid command: Command unrecognized  first/smug=0/0
  I1-opensmtpd-to-postfix2n-crlf -> CHUNKING=False BDAT_REPLY: 500 5.5.1 Invalid command: Command unrecognized  first/smug=0/0
  I1-opensmtpd-to-postfix2n-lf -> CHUNKING=False BDAT_REPLY: 500 5.5.1 Invalid command: Command unrecognized  first/smug=0/0
  I1-opensmtpd-to-postfix1n-crlf -> CHUNKING=False BDAT_REPLY: 500 5.5.1 Invalid command: Command unrecognized  first/smug=0/0
  I1-opensmtpd-to-postfix1n-lf -> CHUNKING=False BDAT_REPLY: 500 5.5.1 Invalid command: Command unrecognized  first/smug=0/0
  I1-opensmtpd-to-mailpit-crlf -> CHUNKING=False BDAT_REPLY: 500 5.5.1 Invalid command: Command unrecognized  first/smug=0/0
  I1-opensmtpd-to-mailpit-lf -> CHUNKING=False BDAT_REPLY: 500 5.5.1 Invalid command: Command unrecognized  first/smug=0/0
[20:58:23] == I1 v3 DONE ==
[20:59:37] == I1 retry: previously infrastructure-failed pairs ==
  retry I1R-postfix1-to-postfix2n-crlf ->  first/smug=0/0
  retry I1R-postfix1-to-postfix2n-lf -> BDAT_REPLY: 250 2.0.0 Ok: 429 bytes queued as 743FE16F2 first/smug=1/0
  retry I1R-postfix1-to-exim-crlf -> BDAT_REPLY: 250 2.0.0 Ok: 417 bytes queued as 01AEE35CB first/smug=0/0
  retry I1R-postfix1-to-exim-lf -> BDAT_REPLY: 250 2.0.0 Ok: 409 bytes queued as 8AD82DCCF first/smug=0/0
  retry I1R-postfix1-to-mailpit-crlf -> BDAT_REPLY: 250 2.0.0 Ok: 429 bytes queued as 20D4D35C8 first/smug=1/0
  retry I1R-postfix1-to-mailpit-lf -> BDAT_REPLY: 250 2.0.0 Ok: 421 bytes queued as 51DC916F2 first/smug=1/0
  retry I1R-exim-to-postfix2-crlf -> BDAT_REPLY: 250 OK id=1x3CYG-00000E-2H first/smug=0/0
