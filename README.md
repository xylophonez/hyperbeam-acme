# hyperbeam-acme

Self-contained **ACME (RFC 8555)** certificate issuance for HyperBEAM /
PermawebOS nodes, built to become the `acme@1.0` device. A node can obtain — and
later renew and terminate with — its own CA-issued **wildcard** TLS certificate,
using **DNS-01** so wildcards are actually possible.

```
*.tunnel.permaweb.space   ->  one Let's Encrypt wildcard cert, obtained by the node itself
```

Everything is pure OTP (`crypto`, `public_key`, `ssl`, `inets`, `json`) plus a
pluggable DNS provider. **No `openssl` process, no external ACME client, no shell
outs** — so the same code runs unchanged inside an attested LapEE image or a
plain `escript`.

## Why this exists

A PermawebOS **LapEE** is a hardened, attested appliance that serves **cleartext**
(`cowboy:start_clear`) — it has no TLS of its own. To expose it publicly over
HTTPS today, a **companion box** (Caddy) sits in front and terminates TLS. That
works, but it reintroduces exactly the thing LapEE removes: an **unattested,
operator-custody trust link** holding the private key and the plaintext.

Wildcard certs make this worse, because a wildcard (`*.tunnel.permaweb.space`)
can **only** be issued via the **DNS-01** challenge — HTTP-01 cannot prove a
wildcard. So the terminator also needs DNS API credentials.

`hyperbeam-acme` dissolves the companion box by moving certificate issuance
*into the node*: the node runs the ACME DNS-01 flow itself, driving a DNS
provider it already trusts, and ends up holding a real wildcard cert. Once the
node can also **terminate** with that cert (see the roadmap), the Caddy box —
and its off-appliance key custody — goes away entirely.

See [DESIGN.md](DESIGN.md) for the full rationale, the wire/crypto details, and
why the device is named `acme@1.0`.

## Status

**Milestone 1 — issuance — is done and proven.** The client obtained a real
Let's Encrypt **staging** wildcard certificate for `*.tunnel.permaweb.space` via
DNS-01 against the live Namecheap API:

```
issuer  = (STAGING) Let's Encrypt
subject = CN=tunnel.permaweb.space
SAN     = DNS:*.tunnel.permaweb.space, DNS:tunnel.permaweb.space
```

The generated CSR key matches the issued leaf, the chain verifies, and the
`_acme-challenge` TXT records were provisioned and then cleaned up with the rest
of the zone left untouched. The offline crypto is independently anchored:
`test/jose_check.escript` verifies our ES256 signatures under `crypto`, and the
hand-rolled CSR passes `openssl`'s own PKCS#10 self-signature + SAN checks.

### Roadmap

| Milestone | Scope | Base change |
| --- | --- | --- |
| **M1 — issuance** ✅ | DNS-01 order → wildcard cert in the store | none (pure device) |
| **M2 — termination** | minimal generic `start_tls` hook reading the cert from the store; retire Caddy | one small, generic listener hook |
| **M3 — renewal + device** | ~60-day renewal loop; packaged `acme@1.0` device | none beyond M2 |

M1 deliberately requires **zero** base changes — issuing/storing certs is cleanly
a device. Only *applying* a cert to the running listener needs a small,
**generic** hook in `hb_http_server` (not a custom device in base); that is M2.

## Architecture

| Module | Responsibility |
| --- | --- |
| `acme_jose` | ES256/JWS, JWK thumbprint, dns-01 keyAuthorization (RFC 7515/7518/7638) |
| `acme_csr` | PKCS#10 CSR with a SubjectAltName over the wildcard + apex, via a tiny DER encoder |
| `acme_client` | the RFC 8555 DNS-01 state machine, with a pluggable DNS callback |
| `acme_dns_namecheap` | Namecheap DNS provider — read-modify-write, never clobbers existing records |

## DNS providers

`acme_client` calls a provider through a small behaviour so the wildcard-capable
DNS side is never hard-wired:

```erlang
-callback set_txt(State, FqdnName, Value)   -> {ok, State} | {error, term()}.
-callback clear_txt(State, FqdnName, Value) -> {ok, State} | {error, term()}.
```

`acme_dns_namecheap` is the reference provider. **Namecheap's `setHosts`
replaces the entire record set**, so every mutation is read-modify-write
(`getHosts` → edit → `setHosts`) and can never wipe a node's own A/CNAME records.
The caller's public IP must be Namecheap-whitelisted; in production this runs on
the node whose IP is already whitelisted.

## Running the staging proof

Issues a real Let's Encrypt **staging** cert (safe to run; staging has generous
rate limits). Requires a Namecheap-whitelisted source IP.

```sh
erlc -o ebin src/*.erl
NAMECHEAP_API_USER=... NAMECHEAP_API_KEY=... \
NAMECHEAP_USERNAME=... NAMECHEAP_CLIENT_IP=<whitelisted-ip> \
  escript test/staging_proof.escript
# -> staging-cert.pem, staging-key.pem
```

Offline checks (no network, no credentials):

```sh
erlc -o ebin src/acme_jose.erl && escript test/jose_check.escript
```

## Relationship to hyperbeam-tunnel

[`hyperbeam-tunnel`](https://github.com/xylophonez/hyperbeam-tunnel) gives a node
a stable public URL; `hyperbeam-acme` gives the **provider** end of that tunnel
its own TLS without an off-appliance terminator. They compose: a LapEE tunnel
provider that issues and terminates its own wildcard cert is a fully attested
public entry point.

## License

MIT
