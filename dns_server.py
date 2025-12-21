#!/usr/bin/env python3
"""
DNS Server that discovers hosts from Home Assistant DHCP discovery
and serves DNS records for them.
"""

import asyncio
import json
import logging
import os
import time
from typing import Dict, List, Tuple
import signal
import hashlib

import aiohttp
import dns.name
import dns.message
import dns.rdatatype
import dns.rdata
import dns.rdataclass
import dns.rrset
from dns.rdatatype import RdataType

# Environment variables
DEBUG = os.getenv("DEBUG", "false").lower() in ("true", "1", "yes")
HASS_URL = os.getenv("HASS_URL", "ws://localhost:8123/api/websocket")
HASS_TOKEN = os.getenv("HASS_TOKEN", "")
DNS_ZONE = os.getenv("DNS_ZONE", "local")
DNS_PORT = int(os.getenv("DNS_PORT", "53"))
RECONNECT_DELAY = int(os.getenv("RECONNECT_DELAY", "5"))  # Initial reconnection delay in seconds
MAX_RECONNECT_DELAY = int(os.getenv("MAX_RECONNECT_DELAY", "300"))  # Max delay (5 minutes)
DNS_TTL = int(os.getenv("DNS_TTL", "300"))  # Default TTL for DNS records (seconds)

# Nameserver configuration (optional)
NS_HOSTNAME = os.getenv("NS_HOSTNAME", "")  # Short name (e.g. 'ns') or FQDN (e.g. 'ns.example.com' or 'ns.example.com.')
# Custom hosts configuration (optional)
CUSTOM_HOSTS_FILE = os.getenv("CUSTOM_HOSTS_FILE", "")  # Path to JSON file with custom hosts
CUSTOM_HOSTS_JSON = os.getenv("CUSTOM_HOSTS_JSON", "")  # Direct JSON string with custom hosts

# Configure logging

logging.basicConfig(
    level=logging.DEBUG if DEBUG else logging.CRITICAL + 1,  # Suppress all logs
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'

logger = logging.getLogger(__name__)

# Network prefix translation (optional)
# Translate IP addresses from SOURCE_PREFIX to DEST_PREFIX in DNS responses
# Example: SOURCE_PREFIX=192.168.0 DEST_PREFIX=192.168.67 translates 192.168.0.x to 192.168.67.x
SOURCE_PREFIX = os.getenv("SOURCE_PREFIX", "")
DEST_PREFIX = os.getenv("DEST_PREFIX", "")

# Global storage for discovered hosts (hostname -> list of host records)
discovered_hosts: Dict[str, List[Dict]] = {}
lock = asyncio.Lock()


def load_custom_hosts() -> Dict[str, List[Dict]]:
    """Load custom hosts from JSON file or environment variable.
    
    Expected JSON format (single host or array of hosts):
    {
        "hostname": "myhost",
        "ip_address": "192.168.1.100",
        "mac_address": "00:11:22:33:44:55"
    }
    
    or array:
    [
        {
            "hostname": "host1",
            "ip_address": "192.168.1.100",
            "mac_address": "00:11:22:33:44:55"
        },
        {
            "hostname": "host2",
            "ip_address": "192.168.1.101",
            "mac_address": "00:11:22:33:44:66"
        }
    ]
    
    Returns dict mapping hostname -> list of host records
    """
    custom_hosts: Dict[str, List[Dict]] = {}
    hosts_data = None
    
    # Try loading from file first
    if CUSTOM_HOSTS_FILE:
        try:
            logger.info(f"Loading custom hosts from file: {CUSTOM_HOSTS_FILE}")
            with open(CUSTOM_HOSTS_FILE, 'r') as f:
                hosts_data = json.load(f)
            logger.info(f"Successfully loaded custom hosts from file")
        except FileNotFoundError:
            logger.error(f"Custom hosts file not found: {CUSTOM_HOSTS_FILE}")
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse custom hosts file: {e}")
        except Exception as e:
            logger.error(f"Error reading custom hosts file: {e}")
    
    # Try loading from environment variable if file didn't work or wasn't specified
    if not hosts_data and CUSTOM_HOSTS_JSON:
        try:
            logger.info("Loading custom hosts from environment variable CUSTOM_HOSTS_JSON")
            hosts_data = json.loads(CUSTOM_HOSTS_JSON)
            logger.info("Successfully loaded custom hosts from environment variable")
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse CUSTOM_HOSTS_JSON: {e}")
        except Exception as e:
            logger.error(f"Error parsing custom hosts from environment: {e}")
    
    # Process the loaded hosts data
    if hosts_data:
        # Normalize to list format
        hosts_list = hosts_data if isinstance(hosts_data, list) else [hosts_data]
        
        for host in hosts_list:
            try:
                hostname_raw = host.get("hostname", "")
                ip = host.get("ip_address", "")
                mac = host.get("mac_address", "")
                
                if not hostname_raw or not ip:
                    logger.warning(f"Skipping invalid custom host (missing hostname or ip_address): {host}")
                    continue
                
                hostname = hostname_raw.lower()
                
                # Initialize or append to host list
                if hostname not in custom_hosts:
                    custom_hosts[hostname] = []
                
                custom_hosts[hostname].append({
                    "hostname": hostname_raw,
                    "ip_address": ip,
                    "mac_address": mac or ""
                })
                
                logger.info(f"Loaded custom host: {hostname_raw} ({ip})" + 
                           (f" - MAC: {mac}" if mac else ""))
                
            except Exception as e:
                logger.error(f"Error processing custom host entry {host}: {e}")
    
    return custom_hosts



class ZoneSerialTracker:
    """In-memory SOA serial tracker keyed off a stable hash of zone data."""

    def __init__(self):
        self.base = int(time.time())  # Epoch at process start (seconds)
        self.counter = 0
        self.last_hash = None
        self.serial = self._compose_serial()

    def _compose_serial(self) -> int:
        # Keep serial within unsigned 32-bit range expected by SOA
        serial = self.base + self.counter
        if serial > 0xFFFFFFFF:
            serial = 0xFFFFFFFF
        return serial

    def _compute_hash(self, hosts: Dict[str, List[Dict]]) -> str:
        canonical = []
        for hostname in sorted(hosts.keys()):
            entries = hosts[hostname]
            normalized = [
                {
                    "hostname": entry.get("hostname", ""),
                    "ip": entry.get("ip_address", ""),
                    "mac": entry.get("mac_address", ""),
                }
                for entry in entries
            ]
            normalized.sort(key=lambda e: (e["ip"], e["mac"], e["hostname"]))
            canonical.append({"host": hostname, "entries": normalized})

        payload = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode()).hexdigest()

    def update_if_changed(self, hosts: Dict[str, List[Dict]]) -> int:
        new_hash = self._compute_hash(hosts)
        if self.last_hash is None or new_hash != self.last_hash:
            if self.last_hash is not None:
                self.counter += 1
            self.last_hash = new_hash
            self.serial = self._compose_serial()
        return self.serial


zone_serial_tracker = ZoneSerialTracker()

# Message ID counter for Home Assistant communication
message_id_counter = 0
last_refresh_time = 0  # Timestamp of last refresh
REFRESH_INTERVAL = int(os.getenv("REFRESH_INTERVAL", "60"))  # Minimum 60 seconds between refreshes


class HomeAssistantClient:
    """Client for connecting to Home Assistant and receiving DHCP discovery events."""
    
    def __init__(self, url: str, token: str):
        self.url = url
        self.token = token
        self.session = None
        self.ws = None
        self.message_id = 0
        self.last_refresh_time = 0
        self.should_reconnect = True
        self.reconnect_delay = RECONNECT_DELAY
        
    def _get_next_message_id(self) -> int:
        """Get the next message ID (counter starting from 0)."""
        self.message_id += 1
        return self.message_id
        
    async def start(self):
        """Connect to Home Assistant and subscribe to DHCP discovery with auto-reconnect."""
        while self.should_reconnect:
            try:
                await self._connect_and_listen()
            except Exception as e:
                logger.error(f"Connection error: {e}")
                
                if self.should_reconnect:
                    logger.info(f"Reconnecting in {self.reconnect_delay} seconds...")
                    await asyncio.sleep(self.reconnect_delay)
                    
                    # Exponential backoff with maximum cap
                    self.reconnect_delay = min(self.reconnect_delay * 2, MAX_RECONNECT_DELAY)
                else:
                    break
    
    async def _connect_and_listen(self):
        """Establish connection and listen for events."""
        if not self.session or self.session.closed:
            self.session = aiohttp.ClientSession()
        
        try:
            logger.info(f"Connecting to Home Assistant at {self.url}")
            self.ws = await self.session.ws_connect(self.url)
            
            # Reset reconnect delay on successful connection
            self.reconnect_delay = RECONNECT_DELAY
            
            # Authenticate
            await self._authenticate()
            
            # Subscribe to DHCP discovery
            await self._subscribe_to_dhcp()
            
            # Listen for events (blocks until connection closes)
            await self._listen_for_events()
            
        except aiohttp.ClientError as e:
            logger.error(f"WebSocket error: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            raise
        finally:
            if self.ws and not self.ws.closed:
                await self.ws.close()
            self.ws = None
    
    async def _authenticate(self):
        """Authenticate with Home Assistant."""
        # Wait for auth_required message
        auth_required = await self.ws.receive_json()
        if auth_required.get("type") != "auth_required":
            raise Exception(f"Expected auth_required, got: {auth_required}")
        
        # Send authentication token
        auth_msg = {
            "type": "auth",
            "access_token": self.token
        }
        await self.ws.send_json(auth_msg)
        
        response = await self.ws.receive_json()
        if response.get("type") == "auth_ok":
            logger.info("Successfully authenticated with Home Assistant")
        else:
            raise Exception(f"Authentication failed: {response}")
    
    async def _subscribe_to_dhcp(self):
        """Subscribe to DHCP discovery events."""
        msg_id = self._get_next_message_id()
        sub_msg = {
            "type": "dhcp/subscribe_discovery",
            "id": msg_id
        }
        await self.ws.send_json(sub_msg)
        logger.info(f"Subscribed to DHCP discovery with message ID {msg_id}")
    
    async def _listen_for_events(self):
        """Listen for incoming events and update discovered hosts."""
        async for msg in self.ws:
            try:
                data = json.loads(msg.data)
                
                if isinstance(data, list):
                    # Can receive multiple messages in one response
                    for item in data:
                        await self._process_message(item)
                else:
                    await self._process_message(data)
                    
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse message: {e}")
            except Exception as e:
                logger.error(f"Error processing event: {e}")
    
    async def _process_message(self, msg: dict):
        """Process a single message from Home Assistant."""
        if msg.get("type") == "result":
            logger.info("Subscription result received")
        elif msg.get("type") == "event":
            event = msg.get("event", {})
            
            # Process added hosts
            for host in event.get("add", []):
                await self._add_host(host)
            
            # Process removed hosts
            for host in event.get("remove", []):
                await self._remove_host(host)
            
            # Process updated hosts
            for host in event.get("update", []):
                await self._add_host(host)
    
    async def _add_host(self, host: dict):
        """Add or update a discovered host."""
        async with lock:
            hostname_raw = host.get("hostname", "")
            mac = host.get("mac_address", "")
            ip = host.get("ip_address", "")
            hostname = hostname_raw.lower()
            
            if hostname and mac and ip:
                host_entries = discovered_hosts.setdefault(hostname, [])

                # Update matching record (by MAC or IP) or append new one
                for entry in host_entries:
                    if entry.get("mac_address") == mac or entry.get("ip_address") == ip:
                        entry.update({
                            "hostname": hostname_raw,
                            "mac_address": mac,
                            "ip_address": ip
                        })
                        break
                else:
                    host_entries.append({
                        "hostname": hostname_raw,
                        "mac_address": mac,
                        "ip_address": ip
                    })

                logger.info(f"Added host: {hostname_raw} ({ip}) - MAC: {mac}")
                zone_serial_tracker.update_if_changed(discovered_hosts)
    
    async def _remove_host(self, host: dict):
        """Remove a discovered host."""
        async with lock:
            hostname = host.get("hostname", "").lower()
            ip = host.get("ip_address", "")
            mac = host.get("mac_address", "")

            if hostname in discovered_hosts:
                entries = discovered_hosts[hostname]

                if ip or mac:
                    entries = [
                        entry for entry in entries
                        if not (
                            (ip and entry.get("ip_address") == ip) or
                            (mac and entry.get("mac_address") == mac)
                        )
                    ]
                else:
                    entries = []

                if entries:
                    discovered_hosts[hostname] = entries
                else:
                    del discovered_hosts[hostname]

                logger.info(f"Removed host: {hostname}")
                zone_serial_tracker.update_if_changed(discovered_hosts)
    
    async def request_refresh(self) -> bool:
        """Request a refresh of DHCP records from Home Assistant.
        
        Returns True if refresh was sent, False if skipped due to rate limiting.
        """
        current_time = time.time()
        
        # Check if enough time has passed since last refresh (minimum 60 seconds)
        if current_time - self.last_refresh_time < REFRESH_INTERVAL:
            return False
        
        try:
            if self.ws and not self.ws.closed:
                msg_id = self._get_next_message_id()
                refresh_msg = {
                    "type": "dhcp/get_discovery",
                    "id": msg_id
                }
                await self.ws.send_json(refresh_msg)
                self.last_refresh_time = current_time
                logger.debug(f"Requested DHCP refresh with message ID {msg_id}")
                return True
        except Exception as e:
            logger.error(f"Error requesting refresh: {e}")
        
        return False
    
    async def cleanup(self):
        """Clean up resources and stop reconnection."""
        self.should_reconnect = False
        
        if self.ws and not self.ws.closed:
            await self.ws.close()
        
        if self.session and not self.session.closed:
            await self.session.close()
        if self.session:
            await self.session.close()


class DNSServer:
    """DNS server that responds to queries for discovered hosts."""
    
    def __init__(self, zone: str, ha_client: 'HomeAssistantClient', port: int = 53):
        self.zone = zone
        self.ha_client = ha_client
        self.port = port
        self.udp_server = None
        self.tcp_server = None
    
    async def start(self):
        """Start the DNS server (both UDP and TCP)."""
        loop = asyncio.get_event_loop()
        
        # Start UDP server
        self.udp_server = await loop.create_datagram_endpoint(
            lambda: DNSUDPHandler(self.zone, self.ha_client),
            local_addr=("0.0.0.0", self.port)
        )
        logger.info(f"DNS server listening on UDP 0.0.0.0:{self.port} for zone {self.zone}")
        
        # Start TCP server
        self.tcp_server = await asyncio.start_server(
            lambda r, w: DNSTCPHandler(self.zone, self.ha_client).handle_connection(r, w),
            host="0.0.0.0",
            port=self.port
        )
        logger.info(f"DNS server listening on TCP 0.0.0.0:{self.port} for zone {self.zone}")
    
    async def stop(self):
        """Stop the DNS server."""
        if self.udp_server:
            transport, protocol = self.udp_server
            transport.close()
        
        if self.tcp_server:
            self.tcp_server.close()
            await self.tcp_server.wait_closed()


class DNSUDPHandler(asyncio.DatagramProtocol):
    """DNS protocol handler for UDP."""
    
    def __init__(self, zone: str, ha_client: 'HomeAssistantClient'):
        self.zone = zone
        self.ha_client = ha_client
        self.transport = None
        self.translation_enabled = bool(SOURCE_PREFIX and DEST_PREFIX)
        if self.translation_enabled:
            logger.info(f"Network prefix translation enabled: {SOURCE_PREFIX} -> {DEST_PREFIX}")
    
    def translate_ip_forward(self, ip: str) -> str:
        """Translate IP from source prefix to destination prefix (for A records)."""
        if not self.translation_enabled:
            return ip
        if ip.startswith(SOURCE_PREFIX + "."):
            # Replace the source prefix with destination prefix
            translated = DEST_PREFIX + ip[len(SOURCE_PREFIX):]
            logger.debug(f"Translated IP forward: {ip} -> {translated}")
            return translated
        return ip
    
    def translate_ip_reverse(self, ip: str) -> str:
        """Translate IP from destination prefix to source prefix (for PTR lookups)."""
        if not self.translation_enabled:
            return ip
        if ip.startswith(DEST_PREFIX + "."):
            # Replace the destination prefix with source prefix
            translated = SOURCE_PREFIX + ip[len(DEST_PREFIX):]
            logger.debug(f"Translated IP reverse: {ip} -> {translated}")
            return translated
        return ip
    
    def connection_made(self, transport):
        self.transport = transport
    
    def datagram_received(self, data: bytes, addr: Tuple):
        """Handle incoming DNS query."""
        try:
            # Request a refresh of records (rate-limited to once per minute)
            asyncio.create_task(self.ha_client.request_refresh())
            
            # Parse the DNS query
            request = dns.message.from_wire(data)
            
            # Log query summary
            if request.question:
                q = request.question[0]
                logger.info(f"DNS query from {addr}: name={q.name}, type={dns.rdatatype.to_text(q.rdtype)}")

            # Build response
            response = self._build_response(request)
            
            # Send response
            self.transport.sendto(response.to_wire(), addr)
            
        except Exception as e:
            logger.error(f"Error processing DNS query from {addr}: {e}")
    
    def _build_response(self, request: dns.message.Message) -> dns.message.Message:
        """Build a DNS response for the given request."""
        response = dns.message.make_response(request)
        response.flags |= dns.flags.AA  # Authoritative answer
        
        for question in request.question:
            qname = question.name
            qtype = question.rdtype
            
            # Get the hostname and record type requested
            hostname_parts = str(qname).rstrip('.').split('.')
            
            rrsets = self._get_rrsets(qname, qtype, hostname_parts)
            for rrset in rrsets:
                response.answer.append(rrset)
        
        return response
    
    def _get_rrsets(self, qname: dns.name.Name, qtype: RdataType, 
                    hostname_parts: List[str]) -> List[dns.rrset.RRset]:
        """Get RRsets for the query."""
        rrsets = []
        
        # Check for zone match
        zone_parts = self.zone.split('.')
        # Reverse IPv4 zone detection: *.in-addr.arpa
        is_reverse_v4 = len(hostname_parts) >= 2 and hostname_parts[-2:] == ["in-addr", "arpa"]

        # Convenience: allow PTR queries for plain dotted IPv4 names like "192.168.67.1"
        # Rewrite internally to reverse lookup semantics and answer under the original name.
        if qtype in (dns.rdatatype.PTR, dns.rdatatype.ANY) and not is_reverse_v4:
            if self._is_plain_ipv4(hostname_parts):
                rrsets.extend(self._get_ptr_records_for_dotted_ip(qname, hostname_parts))
                # For ANY, continue to also include other potential records (none expected here)
                return rrsets

        if is_reverse_v4:
            # Handle reverse IPv4 PTR lookups
            if qtype in (dns.rdatatype.PTR, dns.rdatatype.ANY):
                rrsets.extend(self._get_reverse_ptr_records(qname, hostname_parts))
        else:
            # Forward zone handling
            if len(hostname_parts) >= len(zone_parts):
                # Check if it's in our zone
                if hostname_parts[-len(zone_parts):] == zone_parts:
                    # Handle different record types
                    if qtype == dns.rdatatype.A:
                        rrsets = self._get_a_records(qname, hostname_parts, zone_parts)
                    elif qtype == dns.rdatatype.PTR:
                        rrsets = self._get_ptr_records(qname, hostname_parts, zone_parts)
                    elif qtype == dns.rdatatype.TXT:
                        rrsets = self._get_txt_records(qname, hostname_parts, zone_parts)
                    elif qtype == dns.rdatatype.ANY:
                        rrsets.extend(self._get_a_records(qname, hostname_parts, zone_parts))
                        rrsets.extend(self._get_ptr_records(qname, hostname_parts, zone_parts))
                        rrsets.extend(self._get_txt_records(qname, hostname_parts, zone_parts))
        
        return rrsets

    def _is_plain_ipv4(self, hostname_parts: List[str]) -> bool:
        """Return True if the hostname parts represent a plain dotted IPv4 address."""
        if len(hostname_parts) != 4:
            return False
        for part in hostname_parts:
            if not part.isdigit():
                return False
            try:
                val = int(part)
            except ValueError:
                return False
            if val < 0 or val > 255:
                return False
        return True

    def _get_ptr_records_for_dotted_ip(self, qname: dns.name.Name, hostname_parts: List[str]) -> List[dns.rrset.RRset]:
        """Handle PTR lookups where the query name is a plain dotted IPv4 (e.g., 192.168.67.1)."""
        rrsets: List[dns.rrset.RRset] = []
        # Build dotted IP
        ip = ".".join(hostname_parts)

        # Apply reverse translation if enabled (query IP -> actual stored IP)
        lookup_ip = self.translate_ip_reverse(ip)

        # Find hosts by IP
        target_hosts = []
        for _, host_entries in discovered_hosts.items():
            for info in host_entries:
                if info.get("ip_address") == lookup_ip:
                    target_hosts.append(info)

        if target_hosts:
            rrset = dns.rrset.RRset(qname, dns.rdataclass.IN, dns.rdatatype.PTR)
            rrset.ttl = DNS_TTL
            added = set()
            for target in target_hosts:
                fqdn = f"{target['hostname']}.{self.zone}."
                if fqdn in added:
                    continue
                added.add(fqdn)
                rrset.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.PTR, fqdn))

            if len(rrset) > 0:
                rrsets.append(rrset)

        return rrsets
    
    def _get_a_records(self, qname: dns.name.Name, hostname_parts: List[str],
                       zone_parts: List[str]) -> List[dns.rrset.RRset]:
        """Get A records for the query."""
        rrsets = []
        
        # Extract hostname from query
        # hostname_parts[-len(zone_parts):] is the zone
        # hostname_parts[:-len(zone_parts)] is the host part
        host_parts = hostname_parts[:-len(zone_parts)]
        
        if host_parts:
            hostname = host_parts[-1].lower()  # Last part is the hostname, case-insensitive

            if hostname in discovered_hosts:
                host_entries = discovered_hosts[hostname]

                rrset = dns.rrset.RRset(qname, dns.rdataclass.IN, dns.rdatatype.A)
                rrset.ttl = DNS_TTL
                seen_ips = set()

                for entry in host_entries:
                    ip = entry["ip_address"]
                    translated_ip = self.translate_ip_forward(ip)

                    if translated_ip in seen_ips:
                        continue

                    seen_ips.add(translated_ip)
                    rrset.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, translated_ip))

                if len(rrset) > 0:
                    rrsets.append(rrset)
        
        return rrsets
    
    def _get_ptr_records(self, qname: dns.name.Name, hostname_parts: List[str],
                        zone_parts: List[str]) -> List[dns.rrset.RRset]:
        """Get PTR records for the query."""
        rrsets = []
        
        # Check if this is a reverse lookup or a special PTR query
        host_parts = hostname_parts[:-len(zone_parts)]
        
        if host_parts:
            hostname = host_parts[-1].lower()

            if hostname in discovered_hosts and discovered_hosts[hostname]:
                host_info = discovered_hosts[hostname][0]
                fqdn = f"{host_info['hostname']}.{self.zone}."

                rrset = dns.rrset.RRset(qname, dns.rdataclass.IN, dns.rdatatype.PTR)
                rrset.ttl = DNS_TTL
                rrset.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.PTR, fqdn))
                rrsets.append(rrset)
        
        return rrsets

    def _get_reverse_ptr_records(self, qname: dns.name.Name, hostname_parts: List[str]) -> List[dns.rrset.RRset]:
        """Get PTR records for reverse IPv4 lookups (in-addr.arpa)."""
        rrsets = []
        # hostname_parts example: ['1','0','168','192','in-addr','arpa'] -> IP 192.168.0.1
        octets = hostname_parts[:-2]
        if len(octets) == 4:
            ip = ".".join(reversed(octets))
            
            # Apply reverse translation if enabled (query IP -> actual stored IP)
            lookup_ip = self.translate_ip_reverse(ip)
            
            # Find host by IP
            target_hosts = []
            for _, host_entries in discovered_hosts.items():
                for info in host_entries:
                    if info.get("ip_address") == lookup_ip:
                        target_hosts.append(info)

            if target_hosts:
                rrset = dns.rrset.RRset(qname, dns.rdataclass.IN, dns.rdatatype.PTR)
                rrset.ttl = DNS_TTL
                added = set()
                for target in target_hosts:
                    fqdn = f"{target['hostname']}.{self.zone}."
                    if fqdn in added:
                        continue
                    added.add(fqdn)
                    rrset.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.PTR, fqdn))

                if len(rrset) > 0:
                    rrsets.append(rrset)
        return rrsets
    
    def _get_txt_records(self, qname: dns.name.Name, hostname_parts: List[str],
                        zone_parts: List[str]) -> List[dns.rrset.RRset]:
        """Get TXT records for MAC addresses."""
        rrsets = []
        
        host_parts = hostname_parts[:-len(zone_parts)]
        
        if len(host_parts) >= 2 and host_parts[0].lower() == "_mac":
            # _mac.hostname.zone format
            hostname = host_parts[1].lower()
            
            if hostname in discovered_hosts and discovered_hosts[hostname]:
                rrset = dns.rrset.RRset(qname, dns.rdataclass.IN, dns.rdatatype.TXT)
                rrset.ttl = DNS_TTL
                seen_pairs = set()

                for entry in discovered_hosts[hostname]:
                    mac = entry.get("mac_address")
                    ip = entry.get("ip_address")
                    if not mac or not ip:
                        continue

                    translated_ip = self.translate_ip_forward(ip)
                    pair = (translated_ip, mac)
                    if pair in seen_pairs:
                        continue

                    seen_pairs.add(pair)
                    rrset.add(dns.rdata.from_text(
                        dns.rdataclass.IN,
                        dns.rdatatype.TXT,
                        f'"{translated_ip}={mac}"'
                    ))

                if len(rrset) > 0:
                    rrsets.append(rrset)
        
        return rrsets
    
    def _build_axfr_response(self, request: dns.message.Message) -> List[dns.message.Message]:
        """Build AXFR (zone transfer) response messages."""
        messages = []
        zone_name = request.question[0].name
        serial = zone_serial_tracker.update_if_changed(discovered_hosts)
        
        # Determine SOA primary nameserver name (mname) and optional NS/A creation
        # If NS_HOSTNAME is provided, use it; otherwise fall back to ns.<zone> for SOA mname.
        if NS_HOSTNAME:
            # Normalize provided NS_HOSTNAME into target (FQDN with trailing dot) and owner text
            if NS_HOSTNAME.endswith('.'):
                ns_target = NS_HOSTNAME
                ns_owner_text = NS_HOSTNAME.rstrip('.')
            elif '.' in NS_HOSTNAME:
                ns_target = NS_HOSTNAME + '.'
                ns_owner_text = NS_HOSTNAME
            else:
                ns_target = f"{NS_HOSTNAME}.{self.zone}."
                ns_owner_text = f"{NS_HOSTNAME}.{self.zone}"

            soa_mname = ns_target
        else:
            soa_mname = f"ns.{self.zone}."

        # Create SOA record
        soa_rrset = dns.rrset.RRset(zone_name, dns.rdataclass.IN, dns.rdatatype.SOA)
        soa_rrset.ttl = DNS_TTL
        soa_rrset.add(dns.rdata.from_text(
            dns.rdataclass.IN,
            dns.rdatatype.SOA,
            f"{soa_mname} admin.{self.zone}. {serial} {DNS_TTL} 1800 604800 86400"
        ))

        # Start first message with SOA
        response = dns.message.make_response(request)
        response.flags |= dns.flags.AA  # Authoritative answer
        response.answer.append(soa_rrset)

        # If NS_HOSTNAME provided, add NS record. Do NOT add an explicit A record
        # when the corresponding host is present in `discovered_hosts` to avoid
        # duplicating the same A record later in the AXFR host list.
        if NS_HOSTNAME:
            ns_rrset = dns.rrset.RRset(zone_name, dns.rdataclass.IN, dns.rdatatype.NS)
            ns_rrset.ttl = DNS_TTL
            ns_rrset.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.NS, ns_target))
            response.answer.append(ns_rrset)

            host_label = ns_owner_text.split('.')[0].lower()
            if host_label in discovered_hosts and discovered_hosts.get(host_label):
                logger.debug(f"Host entries exist for NS_HOSTNAME '{NS_HOSTNAME}'; skipping explicit NS A record to avoid duplicate")
            else:
                logger.debug(f"No host entries found for NS_HOSTNAME '{NS_HOSTNAME}'; no NS A record will be created")

        messages.append(response)
        
        # Add hosts in batches to keep messages under 64KB
        current_response = dns.message.make_response(request)
        current_response.flags |= dns.flags.AA
        records_in_current = 0
        max_records_per_message = 10  # Keep small to avoid DNS message size limits
        
        added_hosts = set()
        for hostname, entries in discovered_hosts.items():
            if hostname in added_hosts:
                continue
            added_hosts.add(hostname)
            
            # Create FQDN
            fqdn = dns.name.from_text(f"{hostname}.{self.zone}")
            
            # Add A records for this host
            a_rrset = dns.rrset.RRset(fqdn, dns.rdataclass.IN, dns.rdatatype.A)
            a_rrset.ttl = DNS_TTL
            seen_ips = set()
            for entry in entries:
                ip = entry["ip_address"]
                translated_ip = self.translate_ip_forward(ip)
                if translated_ip not in seen_ips:
                    seen_ips.add(translated_ip)
                    a_rrset.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, translated_ip))
            
            if len(a_rrset) > 0:
                current_response.answer.append(a_rrset)
                records_in_current += 1
            
            # Add TXT records with IP-to-MAC mapping
            mac_fqdn = dns.name.from_text(f"_mac.{hostname}.{self.zone}")
            txt_rrset = dns.rrset.RRset(mac_fqdn, dns.rdataclass.IN, dns.rdatatype.TXT)
            txt_rrset.ttl = DNS_TTL
            seen_pairs = set()

            for entry in entries:
                mac = entry.get("mac_address")
                ip = entry.get("ip_address")
                if not mac or not ip:
                    continue

                translated_ip = self.translate_ip_forward(ip)
                pair = (translated_ip, mac)
                if pair in seen_pairs:
                    continue

                seen_pairs.add(pair)
                txt_rrset.add(dns.rdata.from_text(
                    dns.rdataclass.IN,
                    dns.rdatatype.TXT,
                    f'"{translated_ip}={mac}"'
                ))
            
            if len(txt_rrset) > 0:
                current_response.answer.append(txt_rrset)
                records_in_current += 1
            
            # If we've added enough records, start a new message
            if records_in_current >= max_records_per_message:
                messages.append(current_response)
                current_response = dns.message.make_response(request)
                current_response.flags |= dns.flags.AA
                records_in_current = 0
        
        # Add any remaining records
        if records_in_current > 0:
            messages.append(current_response)
        
        # Final message with closing SOA
        final_response = dns.message.make_response(request)
        final_response.flags |= dns.flags.AA
        final_response.answer.append(soa_rrset)
        messages.append(final_response)
        
        return messages


class DNSTCPHandler:
    """Handler for DNS queries over TCP, including AXFR zone transfers."""
    
    def __init__(self, zone: str, ha_client: 'HomeAssistantClient'):
        self.zone = zone
        self.ha_client = ha_client
        self.translation_enabled = bool(SOURCE_PREFIX and DEST_PREFIX)
        if self.translation_enabled:
            logger.debug(f"TCP handler: Network prefix translation enabled: {SOURCE_PREFIX} -> {DEST_PREFIX}")
    
    def translate_ip_forward(self, ip: str) -> str:
        """Translate IP from source prefix to destination prefix (for A records)."""
        if not self.translation_enabled:
            return ip
        if ip.startswith(SOURCE_PREFIX + "."):
            translated = DEST_PREFIX + ip[len(SOURCE_PREFIX):]
            logger.debug(f"Translated IP forward: {ip} -> {translated}")
            return translated
        return ip
    
    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle a TCP connection."""
        addr = writer.get_extra_info('peername')
        logger.info(f"TCP connection from {addr}")
        
        try:
            # Request a refresh of records (rate-limited)
            await self.ha_client.request_refresh()
            
            # Read the 2-byte length prefix
            length_data = await reader.readexactly(2)
            msg_length = int.from_bytes(length_data, byteorder='big')
            
            # Read the DNS message
            data = await reader.readexactly(msg_length)
            request = dns.message.from_wire(data)
            
            # Log query
            if request.question:
                q = request.question[0]
                logger.info(f"TCP DNS query from {addr}: name={q.name}, type={dns.rdatatype.to_text(q.rdtype)}")
            
            # Check if this is an AXFR request
            if request.question and request.question[0].rdtype == dns.rdatatype.AXFR:
                # Handle zone transfer
                logger.info(f"AXFR request from {addr} for zone {request.question[0].name}")
                
                # Create DNS protocol instance to reuse methods
                protocol = DNSUDPHandler(self.zone, self.ha_client)
                messages = protocol._build_axfr_response(request)
                
                # Send all messages
                for msg in messages:
                    response_data = msg.to_wire()
                    response_length = len(response_data).to_bytes(2, byteorder='big')
                    writer.write(response_length + response_data)
                    await writer.drain()
                
                logger.info(f"AXFR transfer completed to {addr}")
            else:
                # Handle regular query
                protocol = DNSUDPHandler(self.zone, self.ha_client)
                response = protocol._build_response(request)
                
                # Send response with length prefix
                response_data = response.to_wire()
                response_length = len(response_data).to_bytes(2, byteorder='big')
                writer.write(response_length + response_data)
                await writer.drain()
        
        except asyncio.IncompleteReadError:
            logger.debug(f"Client {addr} disconnected")
        except Exception as e:
            logger.error(f"Error handling TCP connection from {addr}: {e}")
        finally:
            writer.close()
            await writer.wait_closed()


async def main():
    """Main entry point."""
    global discovered_hosts
    
    if not HASS_TOKEN:
        logger.error("HASS_TOKEN environment variable is required")
        return
    
    # Load custom hosts first
    custom_hosts = load_custom_hosts()
    
    # Merge custom hosts with discovered hosts
    for hostname, entries in custom_hosts.items():
        if hostname not in discovered_hosts:
            discovered_hosts[hostname] = []
        discovered_hosts[hostname].extend(entries)
    
    if custom_hosts:
        logger.info(f"Merged {len(custom_hosts)} custom host(s) with discovered hosts")
        zone_serial_tracker.update_if_changed(discovered_hosts)
    
    # Create clients
    ha_client = HomeAssistantClient(HASS_URL, HASS_TOKEN)
    dns_server = DNSServer(DNS_ZONE, ha_client, DNS_PORT)
    
    # Log configured DNS zone at startup
    logger.info(f"DNS zone configured: {DNS_ZONE}")
    
    # Start DNS server
    await dns_server.start()
    
    # Set up signal handlers for graceful shutdown
    loop = asyncio.get_event_loop()
    
    def signal_handler(signum, frame):
        logger.info("Shutdown signal received")
        asyncio.create_task(cleanup())
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    async def cleanup():
        logger.info("Cleaning up...")
        await dns_server.stop()
        await ha_client.cleanup()
    
    try:
        # Start Home Assistant client (runs continuously with auto-reconnect)
        await ha_client.start()
    except KeyboardInterrupt:
        logger.info("Interrupted")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
    finally:
        await cleanup()


if __name__ == "__main__":
    asyncio.run(main())
