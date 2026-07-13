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
- **Applying** a cert to the running `cowboy` listener cannot be done from a
  device (a device does not own listener startup). It needs a **small, generic**
  hook in `hb_http_server`: "if a cert is configured/in the store, `start_tls`
  with it, else `start_clear` as today." That is a base *capability*, not a
  custom device in base — and it is the only base change the whole effort needs.
  This is M2.

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

## What is deliberately not here yet

- **Termination (M2).** The generic `hb_http_server` `start_tls` hook + hot
  reload on renewal. Requires the one small base change described above.
- **Renewal (M3).** A ~60-day timer that re-runs `issue/1` and swaps the live
  cert, plus packaging as the loadable `acme@1.0` device (published Arweave ID
  referenced from optional config, never source in base).
- **More DNS providers.** The behaviour is provider-agnostic; Namecheap is the
  reference. Route53/Cloudflare/etc. are additive.
