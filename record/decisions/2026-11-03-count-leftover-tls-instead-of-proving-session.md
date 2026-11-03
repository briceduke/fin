---
id: 2026-11-03-count-leftover-tls-instead-of-proving-session
kind: decision
date: 2026-11-03
supersedes:
  - 2026-10-21-ccs-follows-ssl-packet-from-server
  - 2026-10-21-ssl-set-server-on-clienthello-entry
  - 2026-10-21-tls-session-version-is-unknown-sticky-or-1-3
  - 2026-10-21-tls-version-sticks-on-the-tcp-conversation
  - 2026-10-21-tls-1-3-serverhello-unsticks-grease-records
  - 2026-10-21-non-clienthello-handshake-sticks-tls-version
  - 2026-10-21-empty-handshake-next-byte-sticks-the-tls-session
  - 2026-10-21-length-0-tls-records-do-not-stick-the-session
  - 2026-10-21-empty-ccs-leftover-sets-ccs-frame
  - 2026-10-21-follow-tshark-encrypted-handshake
  - 2026-10-21-abort-later-handshake-messages-after-a-throw
  - 2026-10-21-abort-payload-after-a-throwing-certificateurl
  - 2026-10-21-abort-payload-after-a-throwing-heartbeat
  - 2026-10-21-handshake-throw-leaves-leftover-unprocessed
  - 2026-10-21-heartbeat-throw-leaves-leftover-unprocessed
  - 2026-10-27-clienthello-compress-certificate-quic-tp-and-esni-throw-bounds
  - 2026-10-27-last-ext-alpn-status-request-v2-oid-filters-trusted-ca-keys-throw-quic-tp
  - 2026-10-27-last-ext-psk-cert-authorities-and-refined-alpn-ocsp-ber-throws
  - 2026-10-27-quic-tp-parameter-type-hello-tvb-reads-throw
---

## Context
PR #11 proved CCS, GREASE stickiness, encrypted handshake, and throwing handshake messages so leftover ClientHellos still printed SNI. Wave 3 counts those frames instead. GREASE after CCS must be Unproved, not silent Other.

## Options
- Keep TlsSession, after_ccs, set_server, and the throw matrix so more names print
- Prove at most one ClientHello per payload and count leftover, CCS, GREASE, later hellos, and throws
- Share HTTP nxtseq with TLS

## Choice
A TCP payload proves at most one ClientHello; leftover, CCS, GREASE, later hellos, and handshake throws are counted.

## Why
A counted miss is allowed; an extra server name is not. Dropping SslSession and the throw ports deletes the hand-ported dissect_ssl edges. TLS keeps tls_need abutment. parse_client_hello_sni stays for QUIC.
