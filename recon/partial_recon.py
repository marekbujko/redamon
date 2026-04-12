"""
Partial Recon - Entry point for per-tool partial reconnaissance runs.

This script is invoked by the orchestrator as a container command
(instead of main.py) for running individual recon phases on demand.

Configuration is passed via a JSON file whose path is in the
PARTIAL_RECON_CONFIG environment variable.

Currently supported tool_ids:
  - SubdomainDiscovery: runs discover_subdomains() from domain_recon.py
  - Naabu: runs run_port_scan() from port_scan.py
  - Masscan: runs run_masscan_scan() from masscan_scan.py
  - Nmap: runs run_nmap_scan() from nmap_scan.py
  - Masscan: runs run_masscan_scan() from masscan_scan.py
"""

import os
import sys
import json
import uuid
from pathlib import Path
from datetime import datetime

# Add project root to path (same pattern as main.py)
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


def load_config() -> dict:
    """Load partial recon configuration from JSON file."""
    config_path = os.environ.get("PARTIAL_RECON_CONFIG")
    if not config_path:
        print("[!][Partial] PARTIAL_RECON_CONFIG not set")
        sys.exit(1)

    try:
        with open(config_path, "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"[!][Partial] Failed to load config from {config_path}: {e}")
        sys.exit(1)


def run_subdomain_discovery(config: dict) -> None:
    """
    Run partial subdomain discovery using the exact same functions
    as the full pipeline in domain_recon.py.
    """
    from recon.domain_recon import discover_subdomains, resolve_all_dns, run_puredns_resolve
    from recon.project_settings import get_settings

    domain = config["domain"]
    user_inputs = config.get("user_inputs", [])

    user_id = os.environ.get("USER_ID", "")
    project_id = os.environ.get("PROJECT_ID", "")

    # Fetch settings via the same API conversion as main.py (camelCase -> UPPER_SNAKE_CASE)
    # This ensures tool toggles and parameters are in the correct format
    print(f"[*][Partial Recon] Loading project settings...")
    settings = get_settings()

    print(f"\n{'=' * 50}")
    print(f"[*][Partial Recon] Subdomain Discovery")
    print(f"[*][Partial Recon] Domain: {domain}")
    if user_inputs:
        print(f"[*][Partial Recon] User inputs: {len(user_inputs)} custom subdomains")
    print(f"{'=' * 50}\n")

    # Create UserInput node in graph if user provided custom values
    user_input_id = None
    if user_inputs:
        user_input_id = str(uuid.uuid4())
        try:
            from graph_db import Neo4jClient
            with Neo4jClient() as graph_client:
                if graph_client.verify_connection():
                    graph_client.create_user_input_node(
                        domain=domain,
                        user_input_data={
                            "id": user_input_id,
                            "input_type": "subdomains",
                            "values": user_inputs,
                            "tool_id": "SubdomainDiscovery",

                        },
                        user_id=user_id,
                        project_id=project_id,
                    )
                    print(f"[+][Partial Recon] Created UserInput node: {user_input_id}")
                else:
                    print("[!][Partial Recon] Neo4j not reachable, skipping UserInput node")
                    user_input_id = None
        except Exception as e:
            print(f"[!][Partial Recon] Failed to create UserInput node: {e}")
            user_input_id = None

    # Run the standard subdomain discovery (same function as full pipeline)
    print(f"[*][Partial Recon] Running subdomain discovery tools...")
    result = discover_subdomains(
        domain=domain,
        anonymous=settings.get("USE_TOR_FOR_RECON", False),
        bruteforce=settings.get("USE_BRUTEFORCE_FOR_SUBDOMAINS", False),
        resolve=True,
        save_output=False,  # Don't save intermediate JSON
        project_id=project_id,
        settings=settings,
    )

    discovered_subs = result.get("subdomains", [])
    print(f"[+][Partial Recon] Discovery found {len(discovered_subs)} subdomains")

    # Merge user-added subdomains into the result
    if user_inputs:
        # Filter user inputs: must be valid subdomains of the target domain
        valid_user_subs = []
        for sub in user_inputs:
            sub = sub.strip().lower()
            if sub and (sub == domain or sub.endswith("." + domain)):
                valid_user_subs.append(sub)
            elif sub:
                print(f"[!][Partial Recon] Skipping invalid user input: {sub} (not a subdomain of {domain})")

        # Add user subdomains not already in the discovered list
        new_user_subs = [s for s in valid_user_subs if s not in discovered_subs]
        if new_user_subs:
            print(f"[*][Partial Recon] Adding {len(new_user_subs)} user-provided subdomains")
            all_subs = sorted(set(discovered_subs + new_user_subs))

            # Run puredns wildcard filtering on the new combined list
            all_subs = run_puredns_resolve(all_subs, domain, settings)

            # Re-resolve DNS for the full combined list
            print(f"[*][Partial Recon] Resolving DNS for {len(all_subs)} subdomains...")
            result["subdomains"] = all_subs
            result["subdomain_count"] = len(all_subs)
            result["dns"] = resolve_all_dns(domain, all_subs)

            # Rebuild subdomain status map
            subdomain_status_map = {}
            if result["dns"]:
                dns_subs = result["dns"].get("subdomains", {})
                for s in all_subs:
                    info = result["dns"].get("domain", {}) if s == domain else dns_subs.get(s, {})
                    if info.get("has_records", False):
                        subdomain_status_map[s] = "resolved"
            result["subdomain_status_map"] = subdomain_status_map

    final_count = len(result.get("subdomains", []))
    print(f"[+][Partial Recon] Final subdomain count: {final_count}")

    # Update the graph database
    print(f"[*][Partial Recon] Updating graph database...")
    try:
        from graph_db import Neo4jClient
        with Neo4jClient() as graph_client:
            if graph_client.verify_connection():
                stats = graph_client.update_graph_from_partial_discovery(
                    recon_data=result,
                    user_id=user_id,
                    project_id=project_id,
                    user_input_id=user_input_id,
                )

                # Update UserInput node status
                if user_input_id:
                    graph_client.update_user_input_status(
                        user_input_id, "completed", stats
                    )

                print(f"[+][Partial Recon] Graph updated successfully")
                print(f"[+][Partial Recon] Stats: {json.dumps(stats, default=str)}")
            else:
                print("[!][Partial Recon] Neo4j not reachable, graph not updated")
    except Exception as e:
        print(f"[!][Partial Recon] Graph update failed: {e}")
        # Try to mark UserInput as errored
        if user_input_id:
            try:
                from graph_db import Neo4jClient
                with Neo4jClient() as gc:
                    if gc.verify_connection():
                        gc.update_user_input_status(user_input_id, "error", {"error": str(e)})
            except Exception:
                pass
        raise

    print(f"\n[+][Partial Recon] Subdomain discovery completed successfully")


def _classify_ip(address: str, version: str = None) -> str:
    """Return 'ipv4' or 'ipv6' for an IP address."""
    if version:
        v = version.lower()
        if "4" in v:
            return "ipv4"
        if "6" in v:
            return "ipv6"
    import ipaddress as _ipaddress
    try:
        return "ipv4" if _ipaddress.ip_address(address).version == 4 else "ipv6"
    except ValueError:
        return "ipv4"


def _build_recon_data_from_graph(domain: str, user_id: str, project_id: str) -> dict:
    """
    Query Neo4j to build the recon_data dict that run_port_scan expects.

    Returns a dict with 'domain' and 'dns' keys matching the structure
    produced by domain_recon.py (domain IPs + subdomain IPs).
    """
    from graph_db import Neo4jClient

    recon_data = {
        "domain": domain,
        "dns": {
            "domain": {"ips": {"ipv4": [], "ipv6": []}, "has_records": False},
            "subdomains": {},
        },
    }

    with Neo4jClient() as graph_client:
        if not graph_client.verify_connection():
            print("[!][Partial Recon] Neo4j not reachable, cannot fetch graph inputs")
            return recon_data

        driver = graph_client.driver
        with driver.session() as session:
            # Query domain -> IP relationships
            result = session.run(
                """
                MATCH (d:Domain {name: $domain, user_id: $uid, project_id: $pid})
                      -[:RESOLVES_TO]->(i:IP)
                RETURN i.address AS address, i.version AS version
                """,
                domain=domain, uid=user_id, pid=project_id,
            )
            for record in result:
                addr = record["address"]
                bucket = _classify_ip(addr, record["version"])
                recon_data["dns"]["domain"]["ips"][bucket].append(addr)

            if (recon_data["dns"]["domain"]["ips"]["ipv4"]
                    or recon_data["dns"]["domain"]["ips"]["ipv6"]):
                recon_data["dns"]["domain"]["has_records"] = True

            # Query subdomain -> IP relationships
            result = session.run(
                """
                MATCH (d:Domain {name: $domain, user_id: $uid, project_id: $pid})
                      -[:HAS_SUBDOMAIN]->(s:Subdomain)
                      -[:RESOLVES_TO]->(i:IP)
                RETURN s.name AS subdomain, i.address AS address, i.version AS version
                """,
                domain=domain, uid=user_id, pid=project_id,
            )
            for record in result:
                sub = record["subdomain"]
                addr = record["address"]
                bucket = _classify_ip(addr, record["version"])

                if sub not in recon_data["dns"]["subdomains"]:
                    recon_data["dns"]["subdomains"][sub] = {
                        "ips": {"ipv4": [], "ipv6": []},
                        "has_records": True,
                    }
                recon_data["dns"]["subdomains"][sub]["ips"][bucket].append(addr)

    return recon_data


def _resolve_hostname(hostname: str) -> dict:
    """
    Resolve a hostname to IPs via socket.getaddrinfo.

    Returns {"ipv4": [...], "ipv6": [...]}.
    """
    import socket
    ips = {"ipv4": [], "ipv6": []}
    try:
        results = socket.getaddrinfo(hostname, None)
        for family, _, _, _, sockaddr in results:
            addr = sockaddr[0]
            if family == socket.AF_INET and addr not in ips["ipv4"]:
                ips["ipv4"].append(addr)
            elif family == socket.AF_INET6 and addr not in ips["ipv6"]:
                ips["ipv6"].append(addr)
    except socket.gaierror:
        pass
    return ips


def _is_ip_or_cidr(value: str) -> bool:
    """Check if value is an IP address or CIDR range."""
    import ipaddress as _ipaddress
    try:
        if "/" in value:
            _ipaddress.ip_network(value, strict=False)
        else:
            _ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


_HOSTNAME_RE = None

def _is_valid_hostname(value: str) -> bool:
    """Check if value looks like a valid hostname/subdomain."""
    global _HOSTNAME_RE
    if _HOSTNAME_RE is None:
        import re
        _HOSTNAME_RE = re.compile(r'^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')
    return bool(_HOSTNAME_RE.match(value))


def _run_port_scanner(config: dict, tool_id: str, scan_fn, label: str,
                      pre_settings: dict = None, normalize_fn=None) -> None:
    """
    Shared logic for port-scanner partial recon (Naabu, Masscan, etc.).

    Args:
        config: Partial recon config dict from orchestrator.
        tool_id: Tool identifier for UserInput nodes (e.g. "Naabu", "Masscan").
        scan_fn: The scan function to call (e.g. run_port_scan, run_masscan_scan).
        label: Display label for log messages.
        pre_settings: Settings to force before calling scan_fn (e.g. MASSCAN_ENABLED).
        normalize_fn: Optional post-scan normalizer -- receives recon_data, mutates in place.
    """
    import ipaddress as _ipaddress
    from recon.project_settings import get_settings

    domain = config["domain"]
    user_inputs = config.get("user_inputs", [])

    user_id = os.environ.get("USER_ID", "")
    project_id = os.environ.get("PROJECT_ID", "")

    print(f"[*][Partial Recon] Loading project settings...")
    settings = get_settings()

    if pre_settings:
        settings.update(pre_settings)

    print(f"\n{'=' * 50}")
    print(f"[*][Partial Recon] Port Scanning ({label})")
    print(f"[*][Partial Recon] Domain: {domain}")
    print(f"{'=' * 50}\n")

    # Parse user targets (structured format from new modal, or legacy flat list)
    user_targets = config.get("user_targets") or {}
    user_ips = []
    user_hostnames = []
    ip_attach_to = None
    user_input_id = None

    if user_targets:
        # New structured format: {subdomains: [...], ips: [...], ip_attach_to: "..." | null}
        for entry in user_targets.get("subdomains", []):
            entry = entry.strip().lower()
            if entry and _is_valid_hostname(entry):
                user_hostnames.append(entry)
            elif entry:
                print(f"[!][Partial Recon] Skipping invalid subdomain: {entry}")

        for entry in user_targets.get("ips", []):
            entry = entry.strip()
            if entry and _is_ip_or_cidr(entry):
                user_ips.append(entry)
            elif entry:
                print(f"[!][Partial Recon] Skipping invalid IP: {entry}")

        ip_attach_to = user_targets.get("ip_attach_to")  # subdomain name or None

    elif user_inputs:
        # Legacy flat list fallback: classify each entry
        for entry in user_inputs:
            entry = entry.strip().lower()
            if not entry:
                continue
            if _is_ip_or_cidr(entry):
                user_ips.append(entry)
            elif _is_valid_hostname(entry):
                user_hostnames.append(entry)
            else:
                print(f"[!][Partial Recon] Skipping invalid target: {entry}")

    if user_ips:
        print(f"[+][Partial Recon] Validated {len(user_ips)} custom IPs/CIDRs")
        if ip_attach_to:
            print(f"[+][Partial Recon] IPs will be attached to subdomain: {ip_attach_to}")
        else:
            print(f"[+][Partial Recon] IPs will be tracked via UserInput (generic)")
    if user_hostnames:
        print(f"[+][Partial Recon] Validated {len(user_hostnames)} custom hostnames")

    # Create UserInput node only when IPs are generic (no subdomain attachment)
    if user_ips and not ip_attach_to:
        user_input_id = str(uuid.uuid4())
        try:
            from graph_db import Neo4jClient
            with Neo4jClient() as graph_client:
                if graph_client.verify_connection():
                    graph_client.create_user_input_node(
                        domain=domain,
                        user_input_data={
                            "id": user_input_id,
                            "input_type": "ips",
                            "values": user_ips,
                            "tool_id": tool_id,

                        },
                        user_id=user_id,
                        project_id=project_id,
                    )
                    print(f"[+][Partial Recon] Created UserInput node for IPs: {user_input_id}")
                else:
                    print("[!][Partial Recon] Neo4j not reachable, skipping UserInput node")
                    user_input_id = None
        except Exception as e:
            print(f"[!][Partial Recon] Failed to create UserInput node: {e}")
            user_input_id = None

    # Build recon_data from Neo4j graph (or start empty if user unchecked graph targets)
    include_graph = config.get("include_graph_targets", True)
    if include_graph:
        print(f"[*][Partial Recon] Querying graph for targets (IPs and subdomains)...")
        recon_data = _build_recon_data_from_graph(domain, user_id, project_id)
    else:
        print(f"[*][Partial Recon] Skipping graph targets (user opted out)")
        recon_data = {
            "domain": domain,
            "dns": {
                "domain": {"ips": {"ipv4": [], "ipv6": []}, "has_records": False},
                "subdomains": {},
            },
        }

    # STEP 1: Resolve user-provided hostnames FIRST (before IP injection)
    resolved_hostnames = {}
    if user_hostnames:
        print(f"[*][Partial Recon] Resolving {len(user_hostnames)} user-provided hostnames...")
        for hostname in user_hostnames:
            if hostname in recon_data["dns"]["subdomains"]:
                print(f"[*][Partial Recon] {hostname} already in graph, skipping")
                continue
            ips = _resolve_hostname(hostname)
            if ips["ipv4"] or ips["ipv6"]:
                recon_data["dns"]["subdomains"][hostname] = {
                    "ips": ips,
                    "has_records": True,
                }
                resolved_hostnames[hostname] = ips
                print(f"[+][Partial Recon] Resolved {hostname} -> {ips['ipv4'] + ips['ipv6']}")
            else:
                print(f"[!][Partial Recon] Could not resolve {hostname}, skipping")

        # Create Subdomain + IP + relationships in Neo4j for newly resolved hostnames
        if resolved_hostnames:
            print(f"[*][Partial Recon] Creating graph nodes for {len(resolved_hostnames)} user hostnames...")
            try:
                from graph_db import Neo4jClient
                with Neo4jClient() as graph_client:
                    if graph_client.verify_connection():
                        driver = graph_client.driver
                        with driver.session() as session:
                            for hostname, ips in resolved_hostnames.items():
                                # MERGE Subdomain node
                                session.run(
                                    """
                                    MERGE (s:Subdomain {name: $name, user_id: $uid, project_id: $pid})
                                    SET s.has_dns_records = true,
                                        s.status = coalesce(s.status, 'resolved'),
                                        s.discovered_at = coalesce(s.discovered_at, datetime()),
                                        s.updated_at = datetime(),
                                        s.source = 'partial_recon_user_input'
                                    """,
                                    name=hostname, uid=user_id, pid=project_id,
                                )
                                # MERGE Domain <-> Subdomain relationships
                                session.run(
                                    """
                                    MATCH (d:Domain {name: $domain, user_id: $uid, project_id: $pid})
                                    MATCH (s:Subdomain {name: $sub, user_id: $uid, project_id: $pid})
                                    MERGE (s)-[:BELONGS_TO]->(d)
                                    MERGE (d)-[:HAS_SUBDOMAIN]->(s)
                                    """,
                                    domain=domain, sub=hostname, uid=user_id, pid=project_id,
                                )
                                # MERGE IP nodes + RESOLVES_TO relationships
                                for ip_version in ("ipv4", "ipv6"):
                                    for ip_addr in ips.get(ip_version, []):
                                        session.run(
                                            """
                                            MERGE (i:IP {address: $addr, user_id: $uid, project_id: $pid})
                                            SET i.version = $version, i.updated_at = datetime()
                                            """,
                                            addr=ip_addr, uid=user_id, pid=project_id, version=ip_version,
                                        )
                                        record_type = "A" if ip_version == "ipv4" else "AAAA"
                                        session.run(
                                            """
                                            MATCH (s:Subdomain {name: $sub, user_id: $uid, project_id: $pid})
                                            MATCH (i:IP {address: $addr, user_id: $uid, project_id: $pid})
                                            MERGE (s)-[:RESOLVES_TO {record_type: $rtype}]->(i)
                                            """,
                                            sub=hostname, addr=ip_addr, uid=user_id, pid=project_id, rtype=record_type,
                                        )
                                print(f"[+][Partial Recon] Created graph nodes for {hostname}")
                    else:
                        print("[!][Partial Recon] Neo4j not reachable, skipping subdomain node creation")
            except Exception as e:
                print(f"[!][Partial Recon] Failed to create subdomain nodes: {e}")

    # STEP 2: Inject user-provided IPs/CIDRs into recon_data (AFTER hostname resolution)
    # If ip_attach_to is set, inject into that subdomain's entry; otherwise into domain IPs
    # Safety: if ip_attach_to points to a subdomain that failed resolution, fall back to generic
    if ip_attach_to and ip_attach_to not in recon_data["dns"]["subdomains"]:
        # Check if the subdomain exists in Neo4j graph already
        _sub_exists = False
        try:
            from graph_db import Neo4jClient
            with Neo4jClient() as _gc:
                if _gc.verify_connection():
                    with _gc.driver.session() as _s:
                        _res = _s.run(
                            "MATCH (s:Subdomain {name: $name, user_id: $uid, project_id: $pid}) RETURN s LIMIT 1",
                            name=ip_attach_to, uid=user_id, pid=project_id,
                        )
                        _sub_exists = _res.single() is not None
        except Exception:
            pass
        if not _sub_exists:
            print(f"[!][Partial Recon] Subdomain {ip_attach_to} not found in graph, falling back to generic UserInput for IPs")
            ip_attach_to = None
            # Create UserInput node since we're now generic
            if user_ips:
                user_input_id = str(uuid.uuid4())
                try:
                    from graph_db import Neo4jClient
                    with Neo4jClient() as graph_client:
                        if graph_client.verify_connection():
                            graph_client.create_user_input_node(
                                domain=domain,
                                user_input_data={
                                    "id": user_input_id,
                                    "input_type": "ips",
                                    "values": user_ips,
                                    "tool_id": tool_id,
        
                                },
                                user_id=user_id,
                                project_id=project_id,
                            )
                            print(f"[+][Partial Recon] Created fallback UserInput node: {user_input_id}")
                except Exception:
                    user_input_id = None

    user_ip_addrs = []
    if user_ips:
        if ip_attach_to:
            # Ensure the target subdomain entry exists (may have been created by hostname resolution above)
            if ip_attach_to not in recon_data["dns"]["subdomains"]:
                recon_data["dns"]["subdomains"][ip_attach_to] = {
                    "ips": {"ipv4": [], "ipv6": []},
                    "has_records": True,
                }
            target_ips = recon_data["dns"]["subdomains"][ip_attach_to]["ips"]
            print(f"[*][Partial Recon] Adding {len(user_ips)} user-provided IPs/CIDRs -> {ip_attach_to}")
        else:
            target_ips = recon_data["dns"]["domain"]["ips"]
            print(f"[*][Partial Recon] Adding {len(user_ips)} user-provided IPs/CIDRs -> domain (generic)")

        for ip_str in user_ips:
            if "/" in ip_str:
                try:
                    network = _ipaddress.ip_network(ip_str, strict=False)
                    if network.num_addresses > 256:
                        print(f"[!][Partial Recon] CIDR {ip_str} too large ({network.num_addresses} hosts), max /24 (256). Skipping.")
                        continue
                    for host_ip in network.hosts():
                        addr = str(host_ip)
                        bucket = _classify_ip(addr)
                        if addr not in target_ips[bucket]:
                            target_ips[bucket].append(addr)
                        user_ip_addrs.append(addr)
                    if not ip_attach_to:
                        recon_data["dns"]["domain"]["has_records"] = True
                except ValueError:
                    print(f"[!][Partial Recon] Invalid CIDR: {ip_str}")
            else:
                bucket = _classify_ip(ip_str)
                if ip_str not in target_ips[bucket]:
                    target_ips[bucket].append(ip_str)
                    if not ip_attach_to:
                        recon_data["dns"]["domain"]["has_records"] = True
                user_ip_addrs.append(ip_str)

    # Check we have targets
    domain_ips = recon_data["dns"]["domain"]["ips"]
    sub_count = len(recon_data["dns"]["subdomains"])
    ip_count = len(domain_ips["ipv4"]) + len(domain_ips["ipv6"])
    for sub_data in recon_data["dns"]["subdomains"].values():
        ip_count += len(sub_data["ips"]["ipv4"]) + len(sub_data["ips"]["ipv6"])

    if ip_count == 0:
        print("[!][Partial Recon] No scannable targets found (graph is empty and no valid user targets resolved).")
        print("[!][Partial Recon] Run Subdomain Discovery first, or provide IPs/subdomains manually.")
        sys.exit(1)

    print(f"[+][Partial Recon] Found {ip_count} IPs across {sub_count} subdomains + domain")

    # Run scan (same function as full pipeline)
    print(f"[*][Partial Recon] Running {label} port scan...")
    result = scan_fn(recon_data, output_file=None, settings=settings)

    # Normalize scan results if needed (e.g. masscan_scan -> port_scan)
    if normalize_fn:
        normalize_fn(result)

    # Update the graph database
    print(f"[*][Partial Recon] Updating graph database...")
    try:
        from graph_db import Neo4jClient
        with Neo4jClient() as graph_client:
            if graph_client.verify_connection():
                stats = graph_client.update_graph_from_port_scan(
                    recon_data=result,
                    user_id=user_id,
                    project_id=project_id,
                )

                # Link user-provided IPs to graph
                if user_ip_addrs:
                    driver = graph_client.driver
                    with driver.session() as session:
                        if ip_attach_to and not user_input_id:
                            # IPs attached to a subdomain: create RESOLVES_TO relationships
                            for ip_addr in user_ip_addrs:
                                ip_version = _classify_ip(ip_addr)
                                record_type = "A" if ip_version == "ipv4" else "AAAA"
                                session.run(
                                    """
                                    MERGE (i:IP {address: $addr, user_id: $uid, project_id: $pid})
                                    SET i.version = $version, i.updated_at = datetime()
                                    WITH i
                                    MATCH (s:Subdomain {name: $sub, user_id: $uid, project_id: $pid})
                                    MERGE (s)-[:RESOLVES_TO {record_type: $rtype}]->(i)
                                    """,
                                    addr=ip_addr, uid=user_id, pid=project_id,
                                    version=ip_version, sub=ip_attach_to, rtype=record_type,
                                )
                            print(f"[+][Partial Recon] Linked {len(user_ip_addrs)} IPs to {ip_attach_to} via RESOLVES_TO")
                        elif user_input_id:
                            # Generic IPs: link via UserInput -[:PRODUCED]-> IP
                            for ip_addr in user_ip_addrs:
                                session.run(
                                    """
                                    MATCH (ui:UserInput {id: $ui_id})
                                    MATCH (i:IP {address: $addr, user_id: $uid, project_id: $pid})
                                    MERGE (ui)-[:PRODUCED]->(i)
                                    """,
                                    ui_id=user_input_id, addr=ip_addr, uid=user_id, pid=project_id,
                                )
                            graph_client.update_user_input_status(
                                user_input_id, "completed", stats
                            )
                            print(f"[+][Partial Recon] Linked {len(user_ip_addrs)} IPs via UserInput PRODUCED")

                print(f"[+][Partial Recon] Graph updated successfully")
                print(f"[+][Partial Recon] Stats: {json.dumps(stats, default=str)}")
            else:
                print("[!][Partial Recon] Neo4j not reachable, graph not updated")
    except Exception as e:
        print(f"[!][Partial Recon] Graph update failed: {e}")
        if user_input_id:
            try:
                from graph_db import Neo4jClient
                with Neo4jClient() as gc:
                    if gc.verify_connection():
                        gc.update_user_input_status(user_input_id, "error", {"error": str(e)})
            except Exception:
                pass
        raise

    print(f"\n[+][Partial Recon] {label} port scanning completed successfully")


def _normalize_masscan_result(result: dict) -> None:
    """Copy masscan_scan data into port_scan key for update_graph_from_port_scan()."""
    masscan_data = result.get("masscan_scan", {})
    if masscan_data:
        result["port_scan"] = {
            "scan_metadata": masscan_data.get("scan_metadata", {}),
            "by_host": dict(masscan_data.get("by_host", {})),
            "by_ip": dict(masscan_data.get("by_ip", {})),
            "all_ports": list(masscan_data.get("all_ports", [])),
            "ip_to_hostnames": dict(masscan_data.get("ip_to_hostnames", {})),
            "summary": dict(masscan_data.get("summary", {})),
        }


def run_naabu(config: dict) -> None:
    """Run partial port scanning using Naabu (run_port_scan from port_scan.py)."""
    from recon.port_scan import run_port_scan
    _run_port_scanner(config, tool_id="Naabu", scan_fn=run_port_scan, label="Naabu")


def run_masscan(config: dict) -> None:
    """Run partial port scanning using Masscan (run_masscan_scan from masscan_scan.py)."""
    from recon.masscan_scan import run_masscan_scan
    _run_port_scanner(
        config, tool_id="Masscan", scan_fn=run_masscan_scan, label="Masscan",
        pre_settings={"MASSCAN_ENABLED": True},
        normalize_fn=_normalize_masscan_result,
    )


def _build_port_scan_data_from_graph(domain: str, user_id: str, project_id: str) -> dict:
    """
    Query Neo4j to build the recon_data dict that run_nmap_scan expects.

    Returns a dict with 'port_scan' key containing by_ip, by_host, and
    ip_to_hostnames structures matching what build_nmap_targets() consumes.
    Also populates a 'dns' section for user-IP linking logic.
    """
    from graph_db import Neo4jClient

    recon_data = {
        "domain": domain,
        "port_scan": {
            "by_ip": {},
            "by_host": {},
            "ip_to_hostnames": {},
            "all_ports": [],
            "scan_metadata": {"scanners": ["naabu"]},
            "summary": {},
        },
        "dns": {
            "domain": {"ips": {"ipv4": [], "ipv6": []}, "has_records": False},
            "subdomains": {},
        },
    }

    all_ports_set = set()

    with Neo4jClient() as graph_client:
        if not graph_client.verify_connection():
            print("[!][Partial Recon] Neo4j not reachable, cannot fetch graph inputs")
            return recon_data

        driver = graph_client.driver
        with driver.session() as session:
            # Query domain -> IP -> Port relationships
            result = session.run(
                """
                MATCH (d:Domain {name: $domain, user_id: $uid, project_id: $pid})
                      -[:RESOLVES_TO]->(i:IP)
                OPTIONAL MATCH (i)-[:HAS_PORT]->(p:Port)
                RETURN i.address AS ip, i.version AS version,
                       collect(DISTINCT {number: p.number, protocol: p.protocol}) AS ports
                """,
                domain=domain, uid=user_id, pid=project_id,
            )
            for record in result:
                ip_addr = record["ip"]
                ip_version = record["version"]
                ports_data = record["ports"]

                # Populate dns section
                bucket = _classify_ip(ip_addr, ip_version)
                if ip_addr not in recon_data["dns"]["domain"]["ips"][bucket]:
                    recon_data["dns"]["domain"]["ips"][bucket].append(ip_addr)
                    recon_data["dns"]["domain"]["has_records"] = True

                # Filter out null ports (from OPTIONAL MATCH when no ports exist)
                port_numbers = []
                port_details = []
                for p in ports_data:
                    if p["number"] is not None:
                        pnum = int(p["number"])
                        port_numbers.append(pnum)
                        all_ports_set.add(pnum)
                        port_details.append({
                            "port": pnum,
                            "protocol": p["protocol"] or "tcp",
                            "service": "",
                        })

                if ip_addr not in recon_data["port_scan"]["by_ip"]:
                    recon_data["port_scan"]["by_ip"][ip_addr] = {
                        "ip": ip_addr,
                        "hostnames": [domain],
                        "ports": port_numbers,
                        "port_details": port_details,
                    }
                else:
                    existing = recon_data["port_scan"]["by_ip"][ip_addr]
                    for pnum in port_numbers:
                        if pnum not in existing["ports"]:
                            existing["ports"].append(pnum)
                    for pd in port_details:
                        if not any(epd["port"] == pd["port"] for epd in existing["port_details"]):
                            existing["port_details"].append(pd)

                recon_data["port_scan"]["ip_to_hostnames"].setdefault(ip_addr, [])
                if domain not in recon_data["port_scan"]["ip_to_hostnames"][ip_addr]:
                    recon_data["port_scan"]["ip_to_hostnames"][ip_addr].append(domain)

                # Populate by_host for domain IPs (build_nmap_targets reads by_host too)
                if domain not in recon_data["port_scan"]["by_host"]:
                    recon_data["port_scan"]["by_host"][domain] = {
                        "host": domain,
                        "ip": ip_addr,
                        "ports": list(port_numbers),
                        "port_details": list(port_details),
                    }
                else:
                    existing = recon_data["port_scan"]["by_host"][domain]
                    for pnum in port_numbers:
                        if pnum not in existing["ports"]:
                            existing["ports"].append(pnum)
                    for pd in port_details:
                        if not any(epd["port"] == pd["port"] for epd in existing["port_details"]):
                            existing["port_details"].append(pd)

            # Query subdomain -> IP -> Port relationships
            result = session.run(
                """
                MATCH (d:Domain {name: $domain, user_id: $uid, project_id: $pid})
                      -[:HAS_SUBDOMAIN]->(s:Subdomain)-[:RESOLVES_TO]->(i:IP)
                OPTIONAL MATCH (i)-[:HAS_PORT]->(p:Port)
                RETURN s.name AS subdomain, i.address AS ip, i.version AS version,
                       collect(DISTINCT {number: p.number, protocol: p.protocol}) AS ports
                """,
                domain=domain, uid=user_id, pid=project_id,
            )
            for record in result:
                subdomain = record["subdomain"]
                ip_addr = record["ip"]
                ip_version = record["version"]
                ports_data = record["ports"]

                # Populate dns section
                bucket = _classify_ip(ip_addr, ip_version)
                if subdomain not in recon_data["dns"]["subdomains"]:
                    recon_data["dns"]["subdomains"][subdomain] = {
                        "ips": {"ipv4": [], "ipv6": []},
                        "has_records": True,
                    }
                sub_ips = recon_data["dns"]["subdomains"][subdomain]["ips"]
                if ip_addr not in sub_ips[bucket]:
                    sub_ips[bucket].append(ip_addr)

                # Filter out null ports
                port_numbers = []
                port_details = []
                for p in ports_data:
                    if p["number"] is not None:
                        pnum = int(p["number"])
                        port_numbers.append(pnum)
                        all_ports_set.add(pnum)
                        port_details.append({
                            "port": pnum,
                            "protocol": p["protocol"] or "tcp",
                            "service": "",
                        })

                # Populate by_ip
                if ip_addr not in recon_data["port_scan"]["by_ip"]:
                    recon_data["port_scan"]["by_ip"][ip_addr] = {
                        "ip": ip_addr,
                        "hostnames": [subdomain],
                        "ports": port_numbers,
                        "port_details": port_details,
                    }
                else:
                    existing = recon_data["port_scan"]["by_ip"][ip_addr]
                    if subdomain not in existing["hostnames"]:
                        existing["hostnames"].append(subdomain)
                    for pnum in port_numbers:
                        if pnum not in existing["ports"]:
                            existing["ports"].append(pnum)
                    for pd in port_details:
                        if not any(epd["port"] == pd["port"] for epd in existing["port_details"]):
                            existing["port_details"].append(pd)

                # Populate by_host
                if subdomain not in recon_data["port_scan"]["by_host"]:
                    recon_data["port_scan"]["by_host"][subdomain] = {
                        "host": subdomain,
                        "ip": ip_addr,
                        "ports": port_numbers,
                        "port_details": port_details,
                    }
                else:
                    existing = recon_data["port_scan"]["by_host"][subdomain]
                    for pnum in port_numbers:
                        if pnum not in existing["ports"]:
                            existing["ports"].append(pnum)
                    for pd in port_details:
                        if not any(epd["port"] == pd["port"] for epd in existing["port_details"]):
                            existing["port_details"].append(pd)

                # Populate ip_to_hostnames
                recon_data["port_scan"]["ip_to_hostnames"].setdefault(ip_addr, [])
                if subdomain not in recon_data["port_scan"]["ip_to_hostnames"][ip_addr]:
                    recon_data["port_scan"]["ip_to_hostnames"][ip_addr].append(subdomain)

    recon_data["port_scan"]["all_ports"] = sorted(all_ports_set)
    return recon_data


def run_nmap(config: dict) -> None:
    """
    Run partial Nmap service detection + NSE vulnerability scanning
    using the exact same function as the full pipeline in nmap_scan.py.

    Nmap runs on IPs+Ports already in the graph (from prior port scanning).
    It enriches existing Port nodes with product/version/CPE and creates
    Technology, Vulnerability, and CVE nodes from NSE script findings.
    """
    import ipaddress as _ipaddress
    from recon.nmap_scan import run_nmap_scan
    from recon.main import merge_nmap_into_port_scan
    from recon.project_settings import get_settings

    domain = config["domain"]
    user_inputs = config.get("user_inputs", [])

    user_id = os.environ.get("USER_ID", "")
    project_id = os.environ.get("PROJECT_ID", "")

    print(f"[*][Partial Recon] Loading project settings...")
    settings = get_settings()

    # Force-enable Nmap since the user explicitly chose to run it
    settings['NMAP_ENABLED'] = True

    print(f"\n{'=' * 50}")
    print(f"[*][Partial Recon] Nmap Service Detection + NSE Vuln Scripts")
    print(f"[*][Partial Recon] Domain: {domain}")
    print(f"{'=' * 50}\n")

    # Parse user targets -- Nmap accepts IPs and Ports
    user_targets = config.get("user_targets") or {}
    user_ips = []           # validated IPs and CIDRs
    user_ports = []         # validated port numbers
    ip_attach_to = None     # subdomain to attach IPs to (None = UserInput)
    user_input_id = None    # only created when IPs are generic (no subdomain attachment)

    if user_targets:
        for entry in user_targets.get("ips", []):
            entry = entry.strip()
            if entry and _is_ip_or_cidr(entry):
                user_ips.append(entry)
            elif entry:
                print(f"[!][Partial Recon] Skipping invalid IP: {entry}")

        for entry in user_targets.get("ports", []):
            try:
                port = int(entry)
                if 1 <= port <= 65535:
                    user_ports.append(port)
                else:
                    print(f"[!][Partial Recon] Skipping out-of-range port: {entry}")
            except (ValueError, TypeError):
                print(f"[!][Partial Recon] Skipping invalid port: {entry}")

        ip_attach_to = user_targets.get("ip_attach_to")  # subdomain name or None

    elif user_inputs:
        # Legacy flat list fallback: only accept IPs
        for entry in user_inputs:
            entry = entry.strip()
            if not entry:
                continue
            if _is_ip_or_cidr(entry):
                user_ips.append(entry)
            else:
                print(f"[!][Partial Recon] Skipping non-IP target (Nmap only accepts IPs): {entry}")

    if user_ips:
        print(f"[+][Partial Recon] Validated {len(user_ips)} custom IPs/CIDRs")
        if ip_attach_to:
            print(f"[+][Partial Recon] IPs will be attached to subdomain: {ip_attach_to}")
        else:
            print(f"[+][Partial Recon] IPs will be tracked via UserInput (generic)")
    if user_ports:
        print(f"[+][Partial Recon] Validated {len(user_ports)} custom ports: {user_ports}")

    # Create UserInput node only when IPs are generic (no subdomain attachment)
    if user_ips and not ip_attach_to:
        user_input_id = str(uuid.uuid4())
        try:
            from graph_db import Neo4jClient
            with Neo4jClient() as graph_client:
                if graph_client.verify_connection():
                    graph_client.create_user_input_node(
                        domain=domain,
                        user_input_data={
                            "id": user_input_id,
                            "input_type": "ips",
                            "values": user_ips,
                            "tool_id": "Nmap",

                        },
                        user_id=user_id,
                        project_id=project_id,
                    )
                    print(f"[+][Partial Recon] Created UserInput node for IPs: {user_input_id}")
                else:
                    print("[!][Partial Recon] Neo4j not reachable, skipping UserInput node")
                    user_input_id = None
        except Exception as e:
            print(f"[!][Partial Recon] Failed to create UserInput node: {e}")
            user_input_id = None

    # Build recon_data from Neo4j graph (or start empty if user unchecked graph targets)
    include_graph = config.get("include_graph_targets", True)
    if include_graph:
        print(f"[*][Partial Recon] Querying graph for targets (IPs, ports, subdomains)...")
        recon_data = _build_port_scan_data_from_graph(domain, user_id, project_id)
    else:
        print(f"[*][Partial Recon] Skipping graph targets (user opted out)")
        recon_data = {
            "domain": domain,
            "port_scan": {
                "by_ip": {}, "by_host": {}, "ip_to_hostnames": {},
                "all_ports": [], "scan_metadata": {"scanners": ["naabu"]}, "summary": {},
            },
            "dns": {
                "domain": {"ips": {"ipv4": [], "ipv6": []}, "has_records": False},
                "subdomains": {},
            },
        }

    # Inject user-provided IPs/CIDRs into port_scan structure
    # Safety: if ip_attach_to points to a subdomain that failed resolution, fall back to generic
    if ip_attach_to and ip_attach_to not in recon_data["dns"]["subdomains"]:
        # Check if the subdomain exists in Neo4j graph already
        _sub_exists = False
        try:
            from graph_db import Neo4jClient
            with Neo4jClient() as _gc:
                if _gc.verify_connection():
                    with _gc.driver.session() as _s:
                        _res = _s.run(
                            "MATCH (s:Subdomain {name: $name, user_id: $uid, project_id: $pid}) RETURN s LIMIT 1",
                            name=ip_attach_to, uid=user_id, pid=project_id,
                        )
                        _sub_exists = _res.single() is not None
        except Exception:
            pass
        if not _sub_exists:
            print(f"[!][Partial Recon] Subdomain {ip_attach_to} not found in graph, falling back to generic UserInput for IPs")
            ip_attach_to = None
            # Create UserInput node since we're now generic
            if user_ips:
                user_input_id = str(uuid.uuid4())
                try:
                    from graph_db import Neo4jClient
                    with Neo4jClient() as graph_client:
                        if graph_client.verify_connection():
                            graph_client.create_user_input_node(
                                domain=domain,
                                user_input_data={
                                    "id": user_input_id,
                                    "input_type": "ips",
                                    "values": user_ips,
                                    "tool_id": "Nmap",
        
                                },
                                user_id=user_id,
                                project_id=project_id,
                            )
                            print(f"[+][Partial Recon] Created fallback UserInput node: {user_input_id}")
                except Exception:
                    user_input_id = None

    user_ip_addrs = []  # flat list of individual IPs from user (after CIDR expansion)
    if user_ips:
        print(f"[*][Partial Recon] Adding {len(user_ips)} user-provided IPs/CIDRs to scan targets")
        for ip_str in user_ips:
            if "/" in ip_str:
                try:
                    network = _ipaddress.ip_network(ip_str, strict=False)
                    if network.num_addresses > 256:
                        print(f"[!][Partial Recon] CIDR {ip_str} too large ({network.num_addresses} hosts), max /24 (256). Skipping.")
                        continue
                    for host_ip in network.hosts():
                        addr = str(host_ip)
                        user_ip_addrs.append(addr)
                        if addr not in recon_data["port_scan"]["by_ip"]:
                            recon_data["port_scan"]["by_ip"][addr] = {
                                "ip": addr,
                                "hostnames": [ip_attach_to] if ip_attach_to else [],
                                "ports": [],
                                "port_details": [],
                            }
                except ValueError:
                    print(f"[!][Partial Recon] Invalid CIDR: {ip_str}")
            else:
                user_ip_addrs.append(ip_str)
                if ip_str not in recon_data["port_scan"]["by_ip"]:
                    recon_data["port_scan"]["by_ip"][ip_str] = {
                        "ip": ip_str,
                        "hostnames": [ip_attach_to] if ip_attach_to else [],
                        "ports": [],
                        "port_details": [],
                    }

        # Also populate dns section for user IPs (needed for post-scan IP linking)
        if ip_attach_to:
            if ip_attach_to not in recon_data["dns"]["subdomains"]:
                recon_data["dns"]["subdomains"][ip_attach_to] = {
                    "ips": {"ipv4": [], "ipv6": []},
                    "has_records": True,
                }
            target_dns_ips = recon_data["dns"]["subdomains"][ip_attach_to]["ips"]
        else:
            target_dns_ips = recon_data["dns"]["domain"]["ips"]

        for addr in user_ip_addrs:
            bucket = _classify_ip(addr)
            if addr not in target_dns_ips[bucket]:
                target_dns_ips[bucket].append(addr)
                if not ip_attach_to:
                    recon_data["dns"]["domain"]["has_records"] = True

    # Inject user-provided ports into port_scan (global -- applies to all IPs)
    if user_ports:
        for port in user_ports:
            if port not in recon_data["port_scan"]["all_ports"]:
                recon_data["port_scan"]["all_ports"].append(port)
            # Add to each IP's port list so build_nmap_targets picks them up
            for ip_data in recon_data["port_scan"]["by_ip"].values():
                if port not in ip_data["ports"]:
                    ip_data["ports"].append(port)
                    ip_data["port_details"].append({
                        "port": port, "protocol": "tcp", "service": "",
                    })
            for host_data in recon_data["port_scan"]["by_host"].values():
                if port not in host_data["ports"]:
                    host_data["ports"].append(port)
                    host_data["port_details"].append({
                        "port": port, "protocol": "tcp", "service": "",
                    })
        recon_data["port_scan"]["all_ports"].sort()
        print(f"[+][Partial Recon] Injected {len(user_ports)} custom ports into scan targets")

    # Check we have scannable targets
    port_count = len(recon_data["port_scan"]["all_ports"])
    ip_count = len(recon_data["port_scan"]["by_ip"])

    if ip_count == 0:
        print("[!][Partial Recon] No scannable targets found (graph is empty and no valid user targets provided).")
        print("[!][Partial Recon] Run Subdomain Discovery + Naabu first, or provide IPs manually.")
        sys.exit(1)

    if port_count == 0:
        print("[!][Partial Recon] No ports to scan. Provide custom ports or run Naabu first to discover open ports.")
        sys.exit(1)

    print(f"[+][Partial Recon] Found {ip_count} IPs with {port_count} unique ports to scan")

    # Run Nmap scan (same function as full pipeline)
    print(f"[*][Partial Recon] Running Nmap service detection + NSE vuln scripts...")
    result = run_nmap_scan(recon_data, output_file=None, settings=settings)

    # Merge Nmap service versions into port_scan.port_details
    if "nmap_scan" in result:
        merge_nmap_into_port_scan(result)
        print(f"[+][Partial Recon] Merged Nmap results into port_scan data")
    else:
        print("[!][Partial Recon] Nmap scan produced no results (nmap_scan key missing)")

    # Update the graph database
    print(f"[*][Partial Recon] Updating graph database...")
    try:
        from graph_db import Neo4jClient
        with Neo4jClient() as graph_client:
            if graph_client.verify_connection():
                stats = {}

                # If user provided custom ports, create Port nodes first
                # (update_graph_from_nmap uses MATCH, so Port nodes must exist)
                if user_ports and "port_scan" in result:
                    ps_stats = graph_client.update_graph_from_port_scan(
                        recon_data=result,
                        user_id=user_id,
                        project_id=project_id,
                    )
                    print(f"[+][Partial Recon] Created Port nodes for custom ports: {json.dumps(ps_stats, default=str)}")

                if "nmap_scan" in result:
                    stats = graph_client.update_graph_from_nmap(
                        recon_data=result,
                        user_id=user_id,
                        project_id=project_id,
                    )

                # Link user-provided IPs to graph
                if user_ip_addrs:
                    driver = graph_client.driver
                    with driver.session() as session:
                        if ip_attach_to and not user_input_id:
                            # IPs attached to a subdomain: create RESOLVES_TO relationships
                            for ip_addr in user_ip_addrs:
                                ip_version = _classify_ip(ip_addr)
                                record_type = "A" if ip_version == "ipv4" else "AAAA"
                                session.run(
                                    """
                                    MERGE (i:IP {address: $addr, user_id: $uid, project_id: $pid})
                                    SET i.version = $version, i.updated_at = datetime()
                                    WITH i
                                    MATCH (s:Subdomain {name: $sub, user_id: $uid, project_id: $pid})
                                    MERGE (s)-[:RESOLVES_TO {record_type: $rtype}]->(i)
                                    """,
                                    addr=ip_addr, uid=user_id, pid=project_id,
                                    version=ip_version, sub=ip_attach_to, rtype=record_type,
                                )
                            print(f"[+][Partial Recon] Linked {len(user_ip_addrs)} IPs to {ip_attach_to} via RESOLVES_TO")
                        elif user_input_id:
                            # Generic IPs: link via UserInput -[:PRODUCED]-> IP
                            for ip_addr in user_ip_addrs:
                                session.run(
                                    """
                                    MATCH (ui:UserInput {id: $ui_id})
                                    MATCH (i:IP {address: $addr, user_id: $uid, project_id: $pid})
                                    MERGE (ui)-[:PRODUCED]->(i)
                                    """,
                                    ui_id=user_input_id, addr=ip_addr, uid=user_id, pid=project_id,
                                )
                            graph_client.update_user_input_status(
                                user_input_id, "completed", stats
                            )
                            print(f"[+][Partial Recon] Linked {len(user_ip_addrs)} IPs via UserInput PRODUCED")

                print(f"[+][Partial Recon] Graph updated successfully")
                print(f"[+][Partial Recon] Stats: {json.dumps(stats, default=str)}")
            else:
                print("[!][Partial Recon] Neo4j not reachable, graph not updated")
    except Exception as e:
        print(f"[!][Partial Recon] Graph update failed: {e}")
        if user_input_id:
            try:
                from graph_db import Neo4jClient
                with Neo4jClient() as gc:
                    if gc.verify_connection():
                        gc.update_user_input_status(user_input_id, "error", {"error": str(e)})
            except Exception:
                pass
        raise

    print(f"\n[+][Partial Recon] Nmap service detection completed successfully")


def main():
    config = load_config()
    tool_id = config.get("tool_id", "")

    print(f"[*][Partial Recon] Starting partial recon for tool: {tool_id}")
    print(f"[*][Partial Recon] Timestamp: {datetime.now().isoformat()}")

    if tool_id == "SubdomainDiscovery":
        run_subdomain_discovery(config)
    elif tool_id == "Naabu":
        run_naabu(config)
    elif tool_id == "Masscan":
        run_masscan(config)
    elif tool_id == "Nmap":
        run_nmap(config)
    else:
        print(f"[!][Partial Recon] Unknown tool_id: {tool_id}")
        sys.exit(1)


if __name__ == "__main__":
    main()
