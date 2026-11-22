# dnspbr (DNS Policy-Based Routing for linux)

`dnspbr` is a high-performance, lightweight C++ network daemon and OpenWrt package designed to perform policy-based routing (PBR) using dynamic DNS resolution tracking.

It intercepts DNS queries for target domains, maps resolved IP addresses into virtual subnet pools, tags matching traffic using `nftables` firewall marks (`fwmark`), and routes the packets through dedicated network interfaces (e.g., WireGuard, AmneziaWG, OpenVPN, or OpenWrt WAN gateways).

## Key Features

* **High Performance & Low Latency:** Written in native C++ with multi-threading support (`libpthread`).
* **Dynamic IP Mapping:** Automatically intercepts DNS responses and maps resolved IPs into a predefined internal subnet (`route_subnet`).
* **`nftables` Integration:** Automatically applies firewall marks (`0x40`) for targeted routing rules.
* **Modern OpenWrt Support:** Dynamic discovery of jail/chroot paths for `dnsmasq` (`/tmp/dnsmasq.*.d/`).
* **Multi-Arch & Multi-Version Builds:** Pre-compiled binaries for `aarch64_cortex-a53` and `mipsel_24kc` supporting OpenWrt versions `24.10.x` (`.ipk`) and `25.12.x` (`.apk`).

## Packet Flow Architecture

Below is the conceptual diagram showing how DNS requests and data traffic are processed by `dnspbr` and the Linux kernel routing stack.

```
[ Client Device ]
       │
       │ 1. DNS Query (e.g., target.com)
       ▼
[ dnsmasq / Unbound ] ───(Forward matching domains)───► [ dnspbr Daemon ] (Port 5353)
                                                                │
                                                                │ 2. Upstream Resolver (Port 5354)
                                                                ▼
                                                        [ Upstream DNS / DoH ]
                                                                │
[ Client Device ] ◄───(3. Modified IP response)───────── [ dnspbr Daemon ]
       │
       │ 4. HTTP/TLS Traffic to Mapped IP (e.g., 10.30.0.X)
       ▼
[ Linux Kernel (nftables) ] ───(Matches 10.30.0.0/16)───► Set mark (0x40)
       │
       │ 5. PBR Rule (ip rule fwmark 0x40 lookup 100)
       ▼
[ Target Interface ] (e.g., awg0 / wg0 / tun0)
```

### Detailed Flow Steps:

1. **DNS Interception:** Client sends a request for a target domain. `dnsmasq` forwards targeted domains to `dnspbr` listening on port `5353`.
2. **Upstream Resolution:** `dnspbr` forwards the query to the designated upstream DNS server on port `5354`.
3. **Subnet Mapping:** Upon receiving the real IP from the upstream server, `dnspbr` maps the IP into a synthetic internal IP pool (e.g., `10.30.0.0/16`) and returns this mapped address back to the client.
4. **Packet Tagging:** When the client sends IP traffic to the mapped IP range, `nftables` detects the target subnet and marks the IP packets with `fwmark 0x40`.
5. **Policy Routing:** The Linux kernel routing table evaluates `fwmark 0x40` and redirects the traffic through the specified interface (e.g., AmneziaWG interface `awg0`).

### Notice
Restarting the firewall clears DNAT and mark rules, which is why the dnspbr daemon also needs to be restarted.
## License

This project is licensed under the [MIT License](LICENSE).