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
| **M2 — termination** 🚧 | in-node TLS terminator proxying the local clear port; retire Caddy | **none** (device-only) |
| **M3 — renewal + device** | ~60-day renewal loop; A-record publish; packaged `acme@1.0` device | none |

**M2 keeps base pristine too.** The clean alternative — a generic `start_tls`
hook in `hb_http_server` — would be one small, upstreamable core edit, but it was
deliberately *not* taken. Instead the device opens **its own** `cowboy:start_tls`
listener and reverse-proxies to the node's cleartext port, so the whole thing
still ships as a published device ID + config with **zero** changes to the base
repo. See [DESIGN.md](DESIGN.md#m2-termination-device-only).

**M2 status:** the load-bearing part — turning stored cert material into a live,
chain-complete, *trusted* TLS listener — is proven offline
(`test/tls_check.escript`: a client verifies the terminator against its CA with
hostname checking, for both the apex and a wildcard host). The cowboy terminator
(`acme_tls`), the faithful gun reverse-proxy (`acme_tls_proxy`), and the device
hook (`dev_acme`) are written and compile-clean; their in-node integration test
runs on a HyperBEAM harness.

## Architecture

| Module | Responsibility | Runs |
| --- | --- | --- |
| `acme_jose` | ES256/JWS, JWK thumbprint, dns-01 keyAuthorization (RFC 7515/7518/7638) | anywhere |
| `acme_csr` | PKCS#10 CSR with a SubjectAltName over the wildcard + apex, via a tiny DER encoder | anywhere |
| `acme_client` | the RFC 8555 DNS-01 state machine, with a pluggable DNS callback | anywhere |
| `acme_dns_namecheap` | Namecheap DNS provider — read-modify-write, never clobbers existing records | anywhere |
| `acme_store` | stored PEM chain+key → TLS listener options; leaf expiry / renewal check | anywhere |
| `acme_tls` | opens the in-node `cowboy:start_tls` terminator (M2) | in HyperBEAM |
| `acme_tls_proxy` | cowboy handler: faithfully relay each request to the local clear port | in HyperBEAM |
| `dev_acme` | the `acme@1.0` device on/start hook: ensure cert, start terminator | in HyperBEAM |

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
