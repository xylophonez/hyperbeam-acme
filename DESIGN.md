# Design & rationale

## The problem, precisely

PermawebOS ships HyperBEAM as an appliance. A **LapEE** is that appliance
hardened and remotely attested: the operator does not hold custody of its keys,
and what it runs is measured. Its HTTP listener starts with
`cowboy:start_clear` — **cleartext**. The only TLS path in stock HyperBEAM is the
HTTP/3 (`cowboy:start_quic`) branch, and it loads a **static self-signed test
cert**. There is no CA-issued certificate and no ACME anywhere in the base.

So to put a LapEE on the public internet over HTTPS you place a **terminator** in
front of it (we used Caddy). That terminator:

1. holds the TLS private key **off** the attested appliance, in operator custody —
   the exact trust property a LapEE exists to remove; and
2. for a **wildcard** name it must use the **DNS-01** ACME challenge (HTTP-01
   cannot validate `*.example.com`), so it also holds **DNS API credentials**.

The terminator is therefore both a key-custody weakness *and* a credential
holder, sitting in front of an appliance whose whole point is to not need to be
trusted that way.

## The idea

Move ACME **into the node**. `acme@1.0` runs the DNS-01 flow itself, driving a
DNS provider the operator already configures, and ends holding a real wildcard
certificate in the node's store. Once the node can also **terminate** with that
cert (M2), the terminator disappears and the key never leaves the appliance.

Issuance and termination are separable, which is what makes an incremental,
low-risk path possible:

- **Issuing/renewing/storing** a cert is cleanly a **device** — it is just
  HTTP + crypto + store writes. **Zero base changes.** This is M1, and it is done.
- **Applying** a cert to serve public TLS. A device does not own the node's
  primary listener startup, but it *can* open a **second** listener of its own.
  So M2 has the device start its own `cowboy:start_tls` on 443 and reverse-proxy
  to the existing cleartext port — no base change at all. (A cleaner-but-core
  alternative, a generic `start_tls` hook in `hb_http_server`, was considered and
  deliberately not taken; see "M2 — termination" below.)

## Why "acme@1.0"

HyperBEAM devices are named `name@version` (`tunnel@1.0`, `meta@1.0`,
`hyperbuddy@1.0`, `arweave@2.9`). The capability here is **ACME** — the IETF
Automatic Certificate Management Environment, **RFC 8555** — so the device is
`acme@1.0`: first stable version of the ACME capability, addressed and resolved
like any other AO-Core device. A future protocol-breaking revision would be
`acme@2.0`; additive changes, `acme@1.1`.

## The DNS-01 flow

`acme_client:issue/1` implements RFC 8555 §7 end to end:

1. **directory** — fetch the CA's endpoint map.
2. **newNonce** — seed the anti-replay nonce; every subsequent POST consumes one
   and the response's `Replay-Nonce` header supplies the next.
3. **newAccount** — a JWS signed with the account key's **`jwk`** (ES256),
   returning the account URL used as **`kid`** thereafter.
4. **newOrder** — one order carrying every identifier (`*.tunnel.permaweb.space`
   and `tunnel.permaweb.space`).
5. **authorizations** — for each, pick the `dns-01` challenge and compute the TXT
   value: `base64url(SHA-256(token "." base64url(jwk-thumbprint)))` (RFC 8555
   §8.4). The wildcard and its apex share the name `_acme-challenge.tunnel` with
   **two distinct values**; the provider keeps both.
6. **provision + settle** — write the TXT records, wait for propagation to the
   authoritative nameservers (`dns_settle`, default configurable).
7. **trigger + poll** — POST each challenge to tell the CA to validate, then poll
   each authorization to `valid` (or fail fast on `invalid`).
8. **finalize** — generate the certificate key + CSR (`acme_csr`) and POST it;
   poll the order to `valid`.
9. **download** — POST-as-GET the certificate URL for the PEM chain.
10. **cleanup** — remove the challenge TXT records (best-effort; issuance has
    already succeeded).

## Crypto specifics that bite

- **ES256 signature encoding.** `crypto:sign(ecdsa, ...)` yields a DER
  `ECDSA-Sig-Value`; JOSE requires the **raw `r ‖ s`** concatenation, each
  coordinate fixed at 32 bytes on P-256. `acme_jose` converts and left-pads.
- **JWK thumbprint (RFC 7638).** SHA-256 over canonical JSON of the required
  members **only** (`crv`,`kty`,`x`,`y`), keys in lexicographic order, no
  whitespace. Any deviation and the CA rejects the dns-01 challenge.
- **CSR (PKCS#10).** Built with a ~40-line DER encoder rather than OTP's ASN.1
  open-type handling, so the SubjectAltName carrying the wildcard + apex is under
  our control. A wildcard label is not a valid CN, so the apex is the CN and
  every name lives in the SAN — which is what CAs validate. Output verifies under
  `openssl req -verify`.

## Security model

- **ES256 only.** The one algorithm every ACME CA supports and the smallest to
  carry in an attested image; no RSA account keys.
- **No wallet, no persisted secrets beyond the cert material.** The ACME account
  key and issued cert/key are the only things to persist, and they are **not** the
  node's Arweave wallet. (In-appliance they belong in the encrypted store.)
- **DNS blast-radius containment.** Every Namecheap mutation is
  read-modify-write; a bug can add or remove a `_acme-challenge` TXT but cannot
  clobber the node's A/CNAME records. Proven: the tunnel's `*.tunnel`/`tunnel` A
  records and an unrelated `google-site-verification` TXT survived every write.
- **IP whitelisting.** Namecheap requires the caller's public IP to be
  whitelisted; in production the flow runs on the provider node, whose IP already
  is. Nothing about the credentials is embedded in the base image — they arrive
  via config, the generic LapEE/AndEE pattern.

## M2 — termination (device-only)

M2 makes the node terminate its own TLS. Two shapes were possible:

- **Core edit.** Add an `https` branch to `hb_http_server`'s protocol `case` that
  calls `cowboy:start_tls` with the cert from config/store. One listener, no
  extra hop, and a clean upstream PR — but it edits the base repo.
- **Device-only (chosen).** The `acme@1.0` device opens **its own**
  `cowboy:start_tls` listener and reverse-proxies to the node's existing
  cleartext port. The base repo is untouched; everything ships as the published
  device ID + config.

The device-only path was chosen to keep base pristine (the same rule that keeps
custom devices out of base). It is "Caddy internalised as a device": the TLS key
lives in the appliance's store and never leaves it, but no `hb_http_server`
change is needed.

Mechanics:

- `acme_store:tls_opts/2` turns the stored leaf+chain+key into `ssl` listener
  options (`cert`/`key`/`cacerts`). **Proven** by `test/tls_check.escript`: a
  client verifies the live terminator against the issuing CA, with hostname
  checking, for both the apex and a wildcard name — so the chain it serves is
  complete and trusted.
- `acme_tls` starts the `cowboy:start_tls` listener with those options and a
  route that sends everything to `acme_tls_proxy`.
- `acme_tls_proxy` relays each request to `127.0.0.1:<clear-port>` over `gun`,
  **preserving the Host header** (so a tunnel provider still routes public
  traffic to the right registered node) and passing status/redirects/content
  types/bodies of any size through untouched. Hop-by-hop headers are stripped.
- `dev_acme` is the on/start hook: load the cert from the store, issue via
  `acme_client` if it is missing or within `renew-days` of expiry, then start the
  terminator. The ACME account key is persisted and reused across renewals.

The one runtime cost versus the core edit is a second listener and an in-process
loopback hop — negligible on localhost, and the same idiom the tunnel device
already uses.

## What is deliberately not here yet

- **In-node M2 integration test.** `acme_tls`/`acme_tls_proxy`/`dev_acme` compile
  and target the cowboy/gun already on a HyperBEAM node; the end-to-end
  terminate-and-relay test (large bodies, redirects, Host routing) runs on a
  HyperBEAM harness, not the offline suite.
- **Renewal loop + A record (M3).** A ~60-day timer that re-runs `issue/1` and
  swaps the live cert, and publishing the node's own wildcard **A record** via
  the same DNS API (M1/M2 only write the `_acme-challenge` TXT). Then packaging
  as the loadable `acme@1.0` device (published Arweave ID referenced from optional
  config, never source in base).
- **More DNS providers.** The behaviour is provider-agnostic; Namecheap is the
  reference. Route53/Cloudflare/etc. are additive.
