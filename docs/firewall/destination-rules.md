# Destination Rules

**Firewall > Destination Rules**, also in the RustWarden menu.

Per-program rules decide *whether* a program may connect. Destination rules decide *where to*. You can:

- **Block** a program, or every program, from reaching a destination, or
- **Only allow** a program to reach a destination, which blocks everything else for it.

## Destinations

| Type | Example | How the addresses are found |
|---|---|---|
| **Domain** | `example.com`, `*.example.com` | The addresses this PC has looked up for that name, remembered for two weeks. `*.example.com` covers the name and everything below it. |
| **AS number** | `AS15169` (Google) | The free DB-IP ASN database. It is downloaded only when you press its button. |
| **Country** | `DE`, or pick from a flag list as you type | Your offline country database. See [Countries](../protection/countries.md). |

## Adding a rule

1. Choose the **program**, or **any program** (Block only).
2. Choose **Block** or **Only allow**.
3. Type the destination: a domain, an `AS…` number or a country.
4. Add it.

## How it works

Windows Firewall can only filter by IP address. RustWarden turns each rule into the address ranges it can find and keeps them current as new lookups come in. Long lists are split across several firewall rules. These are RustWarden's own rules, so **Restore firewall defaults** removes them along with everything else.

### Built-in safety

- Your **local network, gateways and DNS servers are never blocked**, whatever a rule says.
- **Only allow** isn't accepted for "any program", because it would cut the whole PC off.
- **Only allow** a domain waits for the first lookup of that domain before it starts blocking everything else.

### Limits

- A program's **first** connection to a server it hasn't looked up yet can get through, or fail, once, before the rule learns that address.
- Addresses **shared** with other sites (CDNs) are shared by the rule too. Blocking one site on a CDN can block others on the same addresses.
- Programs that use their **own encrypted DNS** (DNS-over-HTTPS) aren't seen, so their lookups don't feed domain rules. See [Block DNS-over-HTTPS resolvers](../protection/privacy-vpn.md#block-dns-over-https-resolvers).

This needs administrator rights. Demo mode shows sample rules.

## Block by domain (Driver mode)

With [Driver mode](../driver-mode.md) on and the driver installed, a **Block by domain** card appears below the table. It blocks a domain and **everything under it** (`example.com` covers `www.example.com`) for **every program** on this PC. This is something address-based rules can't do on shared servers.

The driver drops:

- the DNS lookup for the name, and
- the start of an HTTPS connection whose TLS hello names the domain (SNI).

**Adding domains.** Type them by hand, or press **Import list** to download a hosts-style or one-domain-per-line blocklist from an `https` address you choose. Nothing is downloaded until you press the button. The list is kept in RustWarden's data folder, and **Remove list** deletes it.

**Limits.** Programs that use DNS-over-HTTPS *together with* Encrypted Client Hello, and QUIC (HTTP/3), can get past it. Use [QUIC fallback](../driver-mode.md#quic-fallback) to push chosen programs back to TCP.

**Restore firewall defaults** clears the rules and the list. Demo mode shows sample rules.
