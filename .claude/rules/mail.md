---
paths:
  - "crates/hlb-mail/**/*.rs"
  - "crates/hlb-users/**/*.rs"
  - "crates/hlb-identity/**/*.rs"
  - "crates/hlb-controller/src/{accounts,bitwarden}.rs"
  - "crates/hlb-engine/src/submission.rs"
  - "crates/hlb-engine/src/mail_*.rs"
  - "crates/hlb-api/src/mail_*.rs"
  - "crates/hlb-controller/src/mail_*.rs"
  - "catalog/_platform/stalwart/**"
---

# Mail

Stalwart, JMAP, Sieve, aliases and PocketID. The JMAP ones bite on the second call, not
the first.

- **Stalwart has no REST API for accounts.** Everything goes through JMAP (`POST /jmap/`,
  capability `urn:stalwart:jmap`, methods `x:Account/set` and `x:Domain/query`), from
  **v0.16** only. The discriminator is `@type`, `emailAddress` is computed by the
  server, and a failing `/set` still returns HTTP 200 — the failure lives in
  `notCreated`. **A filter condition carries only ONE property**: each key overwrites
  the previous, so you need an `AND` of separate conditions.
- **🔴 1.0 renamed settings, and refuses the old name the way it refuses a typo**:
  `invalidPatch — Invalid key for object`, under HTTP 200 — no alias, no 587, no
  postmaster. An installed 0.16 stays 0.16 until migrated (a 1.0 refuses to open its
  store), so `hlb-mail` speaks both: `Stalwart::generation` reads the JMAP session once
  (1.0 announces `urn:ietf:params:jmap:metadata`; no version is served anywhere), and
  every renamed field is a `match` on `Generation`. A field both default alike is left
  out instead (an alias's `enabled`/`enable`). Found by diffing the two schemas
  `stalwart-migrate` ships (`mapping/schema/`) against the crates' string literals:
  249 names gone, 7 of them ours. `HLB_STALWART_IMAGE` runs the live suites on either.
  Not in any diff: 1.0 opens an `x:AcmeProvider` with its directory, then refuses to
  store it without a `description` — `validationFailed`, no reason — which 0.16
  computes and refuses given ("Cannot modify server set property").
- **JMAP `update` REPLACES the whole property.** There is no "add an alias" operation:
  writing a single alias would erase all the others, without raising an error. Hence
  read-modify-write — and two simultaneous updates would lose the first.
- **🔴 Stalwart with no configuration is a setup page for whoever comes first.** 0.16
  starts in bootstrap mode — no SMTP, port 8080 open "for initial setup". One line
  ends that: `/etc/stalwart/config.json` = `{"@type":"RocksDb","path":…}`; the rest
  lives in its database. Its data goes in `/var/lib/stalwart` (owned by its user), and
  it needs `NET_BIND_SERVICE` back: the binary carries that file capability, and with
  every capability dropped the kernel refuses to execute it.
- **🔴 A fresh Stalwart sends nobody's mail.** 0.16.26 to 1.0.0 listen on 25, 465, 993, 995,
  4190, 443 and 8080 — not 587, which every app was handed. A listener added over JMAP
  (`x:NetworkListener/set`) is stored at once and BOUND AT THE NEXT RESTART only:
  `ReloadSettings` does not bind it. A certificate (`x:Certificate/set`) is served by
  SNI at once after `ReloadTlsCertificates`. Its own is `CN=rcgen self signed cert`,
  naming nothing: every app refuses it, so Stalwart's overlay name gets one under
  Homelabus's root (`hlb_engine::submission`), and every `kind: smtp` app that root.
- **`AUTH` takes the full address, over TLS only.** `vikunja` is refused,
  `vikunja@example.org` accepted; PLAIN and LOGIN are offered only `if local_port !=
  25 && is_tls` — a clear-text 587 would authenticate nobody. And `mustMatchSender`
  defaults to true: an account sending as another address gets `501` at `MAIL FROM`.
  The trial job checks both before `ProvisionSmtpAccount` is done;
  `tests/live_stalwart.rs` holds them against a real server.
- **An app saying "sent" has sent nothing.** Vikunja's `testmail` prints "Testmail
  successfully sent" when the certificate was refused and nothing left; `gitea admin
  sendmail` says "Sent" before the mail is even tried. Only the recipient's mailbox
  proves a mail.
- **In Roundcube `tls://` is STARTTLS, `ssl://` is TLS from the first byte.** `tls://`
  on 993 waited for a greeting that never came ("Empty startup greeting"), and nobody
  could sign in. `ssl://` on 993, `tls://` on 587.
- **Registry lists are MAPS keyed by index.** `credentials` and `aliases` are
  `{"0": {…}}`: an array is refused with `invalidPatch` under HTTP 200, and an array
  READ finds nothing — the next write then erases every alias. Checked on 0.16.26 and
  1.0.0.
- **`SieveScript/*` needs `urn:ietf:params:jmap:sieve` in `using`**, or it is an
  `unknownMethod`. And a fresh server hosts no domain: `ensure_account` creates it.
- **A Sieve script does not travel in the JMAP call.** `SieveScript` only carries a
  `blobId`: upload the content, then reference it. And **without
  `onSuccessActivateScript` the script exists and sorts NOTHING** — a completely silent
  failure, the rules visible in Roundcube and having no effect.
- **A Sieve script is a SINGLE file per account.** Rewriting it wholesale would erase
  hand-written rules — hours of tuning, lost without warning, for a simple alias
  creation. Hence a marker-delimited block: Homelabus writes only between the markers,
  and the block goes at the END (at the top it would catch messages before the user's
  own rules).
- **An unescaped quote in a folder name breaks the WHOLE script**, including the user's
  rules, which Stalwart then rejects wholesale. The name comes from the user: escape it.
- **`NULL` ≠ empty string for a sorting folder.** `NULL` = "nothing was decided", offer
  a default; `""` = "I do NOT want sorting", an explicit choice. Confusing them
  re-imposes a folder on every regeneration.
- **A mail server CANNOT expire an alias.** A Stalwart account's `aliases` list has no
  dates: what is written stays. Hence **three** states, not two: valid,
  expired-and-removed, and 🔴 expired-but-STILL-ACTIVE.
- **A guessable alias defeats compartmentalisation.** If Amazon's is
  `amazon@example.org`, then `paypal@`, `bank@` and `tax@` probably exist too, and a
  bulk sender tries them all for the price of one. The hint never *is* the address: it
  is followed by a random suffix.
- **The point of a disposable alias is not disposal, it is attribution.** One address per
  recipient tells you *who* leaked it. Hence keeping the readable hint: fifty purely
  random addresses lose the only real benefit.
- **Disabling beats deleting.** A deleted alias rejects mail and teaches nothing;
  disabled, it also rejects but lets you count what still hits it — so you learn how long
  a merchant kept selling the address.
- **Marking an alias "purged" without removing it from the server is worse than doing
  nothing.** The address would still receive AND nothing would say so: the silence would
  sustain the belief that the door is closed. The state is only marked AFTER the actual
  removal, and a purge without Stalwart refuses rather than lying.
- **What matters in a purge is what stays OPEN, not the error count.** An error-free
  purge that removed nothing leaves as many doors open as one that failed loudly.
- **🔴 `ensure_account` KEEPS an account that exists — it never says whose it is.** The
  self-service mailbox and sign-up handed `vikunja@` (an app's own) or a hand-made
  account to whoever asked, its mail with it. Every path goes through
  `hlb_engine::mailbox`: reserved names (RFC 2142), an installed app's name and another
  person's mailbox refused; an existing Stalwart account refused to a person, adopted
  only by an administrator and said. One owner per address (`0045_mailbox_owner`).
- **A half-created account looks functional.** Identity without a mailbox: the person
  signs in everywhere and their address receives nothing. It only shows on the first lost
  email, often a password reset. The state is named, and creation is resumable.
- **A one-time token names its person in the BODY.** PocketID 1.16 reads `userId`
  from the request body and ignores the `:id` in the path: sent the path alone, it
  inserted a token for nobody and answered 500 on a foreign key. Every enrolment link
  had failed against a real server; `a_new_person_gets_a_link_that_signs_them_in_once`
  exchanges one now.
- **An enrolment link is built on PocketID's PUBLIC name.** The API URL Homelabus talks
  to is `http://pocket-id:1411`, on the overlay: a link on it is the first thing an
  invited person receives, and it opens on no machine outside the cluster
  (`access::pocketid_public`).
- **🔴 PocketID's `email_verified` decides whether Fluxer signs anyone in.** Fluxer, in
  its `email` mode, refuses a sign-in whose address is not verified, with no setting to
  relax it — and the lab's two people were unverified, although every path creating one
  sends `emailVerified: true` (PocketID 2.18 keeps it, measured). The role sync says a
  person's OWN mailbox verified when PocketID holds it unverified; an address typed in
  PocketID itself is nobody's to vouch for, and stays as it is
  (`roles::unverified_own`, `tests/live_roles.rs`).
- **PocketID has no password**: passkey authentication. So you do not hand over an
  initial secret but a **single-use token**, shown once and never stored.
- **🔴 idmail and `hlb-mail` cannot coexist.** idmail does not talk to Stalwart: it
  REPLACES its directory (external sqlite `directory`). Together they would produce an
  alias created over JMAP in a directory Stalwart no longer consults — the address would
  receive nothing, with nothing to signal it. Hence the addy.io-compatible API on the
  Homelabus side rather than integrating idmail.
- **The addy.io API contract is imposed by BITWARDEN**, not by us. Read from its source
  (`libs/tools/generator/core/src/integration/addy-io.ts`): the response must be
  `{data:{email}}` — at the root the client reads `undefined` and the alias exists
  server-side without anyone knowing.
- **The addy.io protocol has no field for choosing the mailbox.** Bitwarden only sends
  `domain` and `description`. The destination therefore lives on the TOKEN — one token
  per mailbox — and a token pointing at a vanished mailbox FAILS rather than falling
  back to the default: the user would believe their aliases are filed where they are not.
- **🔴 Stalwart bans an address FOR EVER after 100 failed sign-ins a day** (0.16.26 to 1.0.0:
  `x:Security` `authBanRate`, `authBanPeriod: null`), and the right password is refused
  after. A webmail signs in for every person from its container's one address: a
  hundred wrong guesses through Roundcube shut the whole household out of it.
  `hlb_engine::submission::protect_platform` exempts the platform network's subnet
  (`x:AllowedIp`, effective at `ReloadSettings`; a ban already there lifted, then
  `ReloadBlockedIps`) and makes a ban last a day. Roundcube's own lock — three failures
  a minute per account — stays in front.
- **A Stalwart `Group` is a shared mailbox, not a list.** Mail to it and to its aliases
  lands once in its own mailbox, which each member opens beside theirs (a second JMAP
  account, an IMAP shared folder). `postmaster@` (with `abuse@`) is one per domain,
  read by the administrators' mailboxes. Membership is `memberGroupIds/<id>` patched
  alone — a rewrite of the map would drop groups Homelabus did not make.
- **Stalwart closes an idle HTTP connection.** A pooled one reused a minute later failed
  `IncompleteMessage`: the client keeps one five seconds at most. Reused after 30 s,
  closed by 65 s — 0.16.27 and 1.0.0 alike.
- **🔴 Stalwart says its container's name until it is given one.** 0.16.26 to 1.0.0
  leave `defaultHostname` empty, so the banner, `EHLO` and every MX and SRV record of
  `Domain.dnsZoneFile` read the task's id (`220 7f3a9c0e21b4`) — what a receiver checks
  against reverse DNS. `submission::name_server` writes its route's host, with the mail
  domain as `defaultDomainId`: the singleton is validated WHOLE, and a fresh one's
  `defaultDomainId` names no domain, so the name alone is refused. Effective at
  `ReloadSettings`; read again every night, so a route moved is followed.
- **A mail record is judged by what a PUBLIC resolver answers** (`hlb_mail::public_dns`,
  DNS over HTTPS, Cloudflare then Google), never the house's: a split-horizon zone
  answers inside for a name Gmail never sees. The expected lines are Stalwart's own
  (`Domain.dnsZoneFile`, `hlb_api::mail_dns`), so a key it rotates is what is expected the
  next night. ⚠️ Cloudflare's JSON quotes a TXT and splits a long one into strings;
  Google's gives it bare — `txt_value` reads both. Two SPF or two DMARC records are
  NONE for a receiver (RFC 7208, 7489): judged `differs`, and `hlb mail dns` says to
  merge, never to add. Tried on `example.org` itself: its revoked wildcard DKIM
  (`p=`) and its null MX (`0 .`) both read `differs`.
- **🔴 Stalwart publishes DKIM through a provider, and four ways it fails without a word**
  (0.16.26 to 1.0.0, `hlb_engine::mail_dns`, tried on a real BIND over RFC 2136). A domain
  switched to `dnsManagement: Automatic` with `publishRecords: {"dkim": true}` publishes
  the keys already active and rotates them every 90 days — but: (1) a publishing task
  that fails is FAILED for good, never retried, so a key the night reads missing is
  asked for again (`publish_again`, a `DnsManagement` task made by hand) — 1.0 retries
  it itself, for ever (`Retry`, then `Stalled` after `x:TaskManager.alertAfter` = 5
  attempts, backoff 1 min doubling to 6 h), so a task not `Failed` is left to it. A key
  missing says why beside it — the task's reason, a refused credential (`read`); (2) over UDP
  the RSA key's signed update, past 512 bytes, never reached the server and the task
  counted as done (0.16.26; asked again, it reached BIND 9.20 on 0.16.27 and 1.0.0 —
  Homelabus's own `Tsig` says `tcp` all the same); (3) at the switch the publishing
  races the rotation's scheduling, which rewrites each key — one read mid-rewrite is
  skipped, the RSA key one switch in two, six in six switched as the domain is made
  (0.16.27 and 1.0.0). `switch` waits until every active key has its
  `nextTransitionAt`, then asks again; (4) 1.0 switched while the domain's first keys
  are being made — its `DkimManagement` task still pending — schedules NO rotation,
  ever: no task left, no `nextTransitionAt` (0.16 schedules it either way). `switch`
  waits for that task first, and `live_mail` holds the dates on both. A `DnsServer` is accepted offline and its secret reads back `****`: Homelabus
  marks its own by description, `Homelabus: <provider> <fingerprint>`. DuckDNS keeps one
  TXT a name, the certificate challenge's: refused. With DNS published by hand, Stalwart
  never rotates a key at all.
- **🔴 Stalwart's defaults hand a relay's password to whoever is in the way** (0.16.26;
  the same `default` and `invalid-tls` strategies on 1.0.0).
  The `default` TLS strategy takes STARTTLS when offered (`startTls: optional`) — a
  Mailpit offering none got the AUTH in the clear — and the outbound strategy retries a
  TLS error with `invalid-tls`, which accepts any certificate. `hlb_engine::mail_relay`
  gives the relay `relay-tls`: `startTls: require`, `allowInvalidCerts: false`, and
  `mtaSts`/`dane` OFF — the recipient's policies name its own MX, never the relay, and
  an enforcing domain would refuse every message handed over. Offered no STARTTLS, the
  message bounces at once ("STARTTLS not advertised by host") and nothing is sent. The
  strategy is FOLLOWED at `ReloadSettings` only: written alone, the next message still
  left by MX — straight to Gmail from the test machine, whose port 25 is open. Test
  recipients are at `example.net`, whose null MX sends nothing anywhere. Stalwart
  verifies through the system's roots (`rustls-platform-verifier`): `SSL_CERT_FILE`
  hands it a test root.
- **🔴 A message Stalwart cannot hand over says nothing for three days** (0.16.26; the same
  schedules on 1.0.0): retried
  (the first time 2 min after), its sender told after a day (`nextNotify`), bounced at three
  (`expires.expiresAt`, a TTL) — and port 25 closed by the line makes EVERY remote
  message do it. `x:QueuedMessage/get` reads the queue: recipients are a map keyed by
  address, each with its own `status` (`Scheduled`, `TemporaryFailure`, `Completed`,
  `PermanentFailure`) — a message delivered to its house recipient stays queued for the
  remote one, so judge per recipient, never per message. The last error is
  `responseHostname` with `responseCode`/`responseMessage` when a server answered,
  `errorMessage` (`Connection refused`) when none did. A `/get` with no ids answers at
  most `getMaxResults` (500). `hlb_controller::mail_queue` puts a recipient waiting past
  the hour in the inbox by its domain and notifies it once, when it goes late.
- **🔴 People's clients met Stalwart's own certificate on 465 and 993** (`CN=rcgen self
  signed cert`; Homelabus's was the overlay name's, for the apps). Stalwart picks one by
  SNI — and of two naming the same name serves the one ending LAST, whichever came first (0.16.26 to 1.0.0, measured): a
  ten-year leaf under Homelabus's root beside a 90-day ACME one hides every renewal.
  `hlb_engine::mail_tls` keeps the id of the leaf it gives (`mail-public-certificate`)
  and takes it back once ACME's is there. Stalwart's own ACME: `x:AcmeProvider` opens
  the account AT CREATION — a directory it cannot reach or verify refuses it —, its
  `contact` a set (`{"mailto:…": true}`, `{"0": …}` refused); a domain switched to
  `certificateManagement: Automatic` is requested at once and renewed at two thirds of
  its life. 🔴 Give the names: empty over HTTP-01 it also asks for `autoconfig.`,
  `mta-sts.`…, which nothing routes, and the order fails. HTTP-01 reaches Stalwart through
  Caddy (port 80 redirected to 443, proxied to 8080 — Pebble follows the redirect);
  DNS-01 needs `dnsManagement: Automatic` (refused otherwise) and waits up to the
  server's `propagationTimeout` to see the TXT through Stalwart's OWN resolver before
  answering, then answers anyway. A private ACME root goes in through `trust::mount`
  (`SSL_CERT_DIR`, added to the image's): `SSL_CERT_FILE` REPLACES the system's roots,
  and Stalwart's spam-rule download from GitHub failed under it.
- **🔴 Stalwart's traces went nowhere.** 0.16.26 to 1.0.0 have one tracer, a `Log` writing to
  `/var/log/stalwart`, a directory the image does not have: the writer is never built and
  every event is dropped — `docker logs` empty, an ACME or delivery failure said nowhere.
  `submission::trace` adds a `Stdout` tracer (`x:Tracer/set`, effective at
  `ReloadSettings`, no restart) at install and every night; events go to stderr, which
  `docker service logs` reads. The queue and the tasks (`x:QueuedMessage`, `x:Task`) still
  say what failed, which is what Homelabus reads. A failed ACME order is RETRIED by
  Stalwart (`x:Task` status `Retry`, `attemptNumber`), unlike a DKIM publication on 0.16
  — 1.0 retries both.
- **🔴 A trial verifies with what Stalwart verifies.** The relay's trial checked the
  relay's certificate against curl's public roots; Stalwart, under a private ACME
  authority, also trusts that authority's root (`trust::mount`) — a relay under it was
  refused by the trial and would have been taken by Stalwart (lab, 2026-10-20). Both
  read `submission::trusted_roots`; the trial adds them with `--capath`, beside the
  image's bundle — `--cacert` would replace it.
- **🔴 A blocklist behind a public resolver checks nothing, and says so only in a tag.**
  Spamhaus answers 1.1.1.1 or 9.9.9.9 `127.255.255.254` (`127.255.255.255` when asked
  too much); URIBL, SURBL, DNSWL and SenderScore have their own refusal codes. Stalwart
  0.16.26 to 1.0.0 tag it (`RBL_SPAMHAUS_BLOCKED_OPENRESOLVER`, `DBL_BLOCKED_OPENRESOLVER`,
  `URIBL_BLOCKED`, `DNSWL_BLOCKED`…, from the rules it downloads at start — empty for
  the first seconds) and scores it ZERO: every message passes. Its resolver is the
  system's, the node's. Through a router forwarding to an ISP, Spamhaus answered and
  URIBL still refused (measured 2026-10-20). `Stalwart::refused_blocklists` asks
  `x:Action/set` `ClassifySpam` — a message classified, nothing received — from a
  documentation address (loopback is skipped; PBL lists TEST-NET, a listing, not a
  refusal), with a link to a domain nobody owns for the domain lists; the recipients
  (`envRcptTo`, 1.0 `rcptTo`) are a set keyed by address.
  Read with the mail records every night, a notice per refusing list. The probe's
  address and linked domain are NEW each time: a refusal stays an hour in Stalwart's
  resolver cache (TTL 3600), and a probe asking the same names after a resolver change
  reads the old refusal.
- **🔴 The cure is Stalwart's own resolver, and it takes an ADDRESS.** Stalwart's
  manifest deploys `stalwart-resolver`, Unbound (`klutchell/unbound`, recursing from
  the root, no forwarder; RFC 1918 clients allowed; `localhost` answered offline, its
  probe). It needs `NET_BIND_SERVICE`, `SETUID`, `SETGID` and a WRITABLE root — it
  rewrites `root.key` and dies on a read-only one. `x:DnsResolver` (a singleton,
  `System` by default) becomes `Custom` with `servers` a MAP of `{protocol, address,
  port}` — an IP only, so `submission::own_resolver` writes the companion's Swarm VIP
  (`Orchestrator::service_address`), at install and every night. Effective at
  `ReloadSettings`, no restart (measured). Through it every list answered on the
  pinned image, where 1.1.1.1 had five refuse — and on the lab's Swarm, through the
  VIP. ⚠️ `docker restart` of its task makes Swarm replace it: SIGHUP reloads Unbound. ⚠️ It resolves only what the internet
  holds: a relay named in a private zone is not found.
- **`Domain.dnsZoneFile` lists what Stalwart COULD serve, not what the house does.**
  `autoconfig.`, `autodiscover.`, `mta-sts.`, `ua-auto-config.` are CNAMEs to its name,
  which the ingress does not route for them; `_pop3s` points at 995, which the manifest
  does not publish. `hlb_api::mail_dns::served` keeps an SRV on a forwarded port, no
  CNAME and no TXT announcing a CNAME's name (`_mta-sts.`); `hlb mail dns` counts what
  it left out.
- **Stalwart's own name has an SPF too** (`mail.example.org. IN TXT "v=spf1 a -all"`,
  in `Domain.dnsZoneFile`): a receiver checks it against `EHLO`, and alone for a bounce,
  which has no sender. Judged with the domain's, the relay's term never added to it —
  Stalwart only ever greets the relay.
- **🔴 An ACME directory may refuse a nonce, and Stalwart does not ask again.** RFC 8555
  has a client retry `badNonce`; Stalwart opens an `x:AcmeProvider` at creation and
  fails it whole (0.16.26 to 1.0.0: 5 and 3 in 10 at half the nonces refused) —
  `mail_tls` asks three times. 0.16 retries an order INSIDE its task after 32, 64 and
  128 s, the task "Pending" meanwhile; 1.0 has no `maxRetries`: the task goes `Retry`
  at once and is retried whole, `x:TaskManager`'s backoff (about 1, 2, 4 min…). Pebble refuses 5 %
  of nonces ON PURPOSE (`PEBBLE_WFE_NONCEREJECT`): an order failed four times in ten,
  and the DNS-01 test lost its certificate past its wait — 0 % in the tests now, 76 s
  every run. An unverified directory and an unreachable one read alike, "error sending
  request for url": only a directory that answered a status is known verified.
