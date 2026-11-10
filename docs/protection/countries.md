# Countries and lookups

**Settings > Countries & Network** controls where RustWarden gets country flags, map positions, company names and whois information. It has three tabs: **Downloads**, **Geolocation** and **Lookups**.

## Downloads

Free databases from [DB-IP](https://db-ip.com) (Lite editions, CC BY 4.0), one line each with its size and status. Hover a line to see where the file is saved.

| Database | Used for |
|---|---|
| **Country** | Flags, the world map, country [destination rules](../firewall/destination-rules.md), the baseline |
| **City** | Placing connections at their city on the map, and the Speedtest route map |
| **ASN** | AS numbers and company names offline, and AS [destination rules](../firewall/destination-rules.md) |

**Download**, **Update** or **Update all** first ask in a short popup that shows the source and total size. One progress bar, weighted by size, covers the whole batch. Nothing about you is sent.

DB-IP publishes no checksums, so each file is unpacked **beside** the old one and only used if it opens as a database of the right kind and holds data. A database that's already in use updates after a restart.

| Setting | Meaning |
|---|---|
| **Keep downloaded databases up to date** | Re-download automatically |
| **Update the databases** | Hours between updates. DB-IP publishes once a month. |

The setup wizard offers the same downloads.

## Geolocation

- **Custom country database (.mmdb)**: use your own MaxMind GeoLite2/GeoIP2 or DB-IP country or city file. Leave it empty to use the downloaded one.
- **Use the city database on the map**: places connections at their city instead of the middle of the country. Nearby ones still merge when zoomed out. It uses about 130 MB of memory.

## Lookups

### AS number and company

**Lookup service** shows, for example, *AS15169 · Google LLC* next to remote addresses on the Firewall and Traffic tabs. The choices are:

- **Off**: nothing is sent.
- **Team Cymru (DNS)**: a DNS-based lookup.
- **Custom web API**: your own address, where `{ip}` is replaced by the remote address. The answer must contain an `asn` and/or `org` (or `as`) field, as ipinfo.io, ip-api.com and ipwho.is do.

Whichever service you choose receives the remote addresses. The company filter on the Traffic tab needs this.

### Public IP address

**Watch my public IP address** (off by default, because it goes online). Every ten minutes it asks the https service you enter (such as `api.ipify.org` or `icanhazip.com`) for this PC's address, and raises a [Public IP address](../alerts/alert-types.md#public-ip-address-monitor) alert when it, or the ISP, changes.

### Whois

The **(i)** icon next to every IP address shows who it belongs to:

- **Open Shodan in the browser**, or
- **Show the answer in RustWarden**, using a free rdap.org lookup. The address is sent to rdap.org.

## Removing the databases

**Settings > Other > Backup > Clean up** deletes the GeoIP and ASN databases and switches off the features that used them. See [Clean up](../maintenance.md#clean-up).
