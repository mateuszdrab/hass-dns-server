# hass-dns-server

Lightweight DNS server that discovers hosts from Home Assistant DHCP discovery and serves DNS records for them. 

Useful when your ISP provides you a modem that does not provide a DNS service for your LAN, e.g. Virgin Media and you don't have enough control over the specific network to introduce a proper router with that basic feature.

Does not implement all record types, but is designed to work with dns2promsd by providing a standard zone transfer, so that you can deploy blackbox monitoring of discovered hosts in that particular network, as an example.

I've added an extra feature for people like me who (are a 'managed service provider' and therefore) have to connect to various Virgin Media networks to maintain Home Assistant though Wireguard. To avoid IP conflicts with multiple fixed `192.168.0.0/24`, I perform DNAT translation on arriving traffic in the Wireguard add-on. For example, the below snippet translates traffic to `192.168.69.0/24` to `192.168.0.0/24`.

```
  post_up: >-
    iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT;
    iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE; iptables -t nat -A
    PREROUTING -d 192.168.69.0/24 -i %i -j NETMAP --to 192.168.0.0/24
```
The environment variables `SOURCE_PREFIX` and `DEST_PREFIX` would take `192.168.0` and `192.168.69` respectively, and perform translation of those CIDR ranges on both forward and reverse DNS queries. This, in combination with the DNAT and a custom DNS zone allow me to address the remote network as if it had a fully working local DNS.

Final note, this has been coded by VS Copilot, I needed something quick. 


## Build

Build the Docker image (from project root):

```bash
docker build -t hass-dns-server .
```

## Run

Run with ports mapped for both UDP and TCP DNS (port 53):

```bash
docker run -d \
  -e HASS_TOKEN="your_home_assistant_long_lived_token" \
  -e HASS_URL="ws://homeassistant:8123/api/websocket" \
  -p 53:53/udp -p 53:53/tcp \
  --name hass-dns-server \
  hass-dns-server
```

Notes:
- `HASS_TOKEN` is required. The container will exit if this is not provided.
- To avoid port mapping issues on some systems, you can run with host networking:

```bash
docker run -d --network host -e HASS_TOKEN="..." --name hass-dns-server hass-dns-server:latest
```

## Environment variables

- `HASS_TOKEN` (required): Home Assistant long-lived access token.
- `HASS_URL` (optional): WebSocket URL for Home Assistant (default: `ws://localhost:8123/api/websocket`).
- `DNS_ZONE` (optional): DNS zone to serve (default: `local`).
- `DNS_PORT` (optional): Port to listen on (default: `53`).
- `DNS_TTL` (optional): Default TTL for DNS records in seconds (default: `300`)
- `DEBUG` (optional): `true` or `false` to enable debug logging.
- `CUSTOM_HOSTS_FILE` / `CUSTOM_HOSTS_JSON` (optional): Inject extra host records. Example: `[{"hostname":"modem","ip_address":"192.168.0.1"}]`
- `DNS_SOA_NS_HOSTNAME` (optional): Sets the nameserver hostname used in the SOA `mname` and NS records. Accepts a short
  name (e.g. `ns`) or a fully-qualified domain name (e.g. `ns.example.com` or `ns.example.com.`). If a short name is
  provided it will be expanded to `<short>.<DNS_ZONE>` (for example, `DNS_SOA_NS_HOSTNAME=ns` with `DNS_ZONE=local` becomes
  `ns.local.`). When `DNS_SOA_NS_HOSTNAME` matches a discovered or custom host, the server will rely on that host's A record
  for the NS (no duplicate NS A record is added). If it does not match an existing host, only the NS record will be
  present in the zone (no automatic A record is created).
- `SOURCE_PREFIX`, `DEST_PREFIX` (optional): Prefix translation for forward and reverse DNS queries.
- `TRANSLATION_ALLOWED_CIDRS` (optional): Comma-separated list of CIDR ranges (IPv4 or IPv6)
  that restrict which requester IPs will have A-record translations applied. If empty, any
  requester will receive translated addresses when `SOURCE_PREFIX` and `DEST_PREFIX` are set.
  Example: `TRANSLATION_ALLOWED_CIDRS=10.0.0.0/8,192.168.69.0/24`.

## Development / Quick test

Run locally (python must be installed) from project folder:

```bash
pip install -r requirements.txt
HASS_TOKEN="your_token" python dns_server.py
```