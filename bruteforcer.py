import asyncio
import subprocess
import json
import random
import ipaddress
import os
from pprint import pprint
from datetime import datetime
import sys

MAX_CONCURRENT = 300
PING_RETRIES = 50
TRACEROUTE_TIMEOUT = 120
ASRANK_FILE = "asns.jsonl"
TRACEROUTE_CMD = 'gtraceroute'
PING_CMD = 'gping'
ASN_PREFIXES_FILE = "asn_prefixes.json"
OUTPUT_DIR = "outputs"

semaphore = asyncio.Semaphore(MAX_CONCURRENT)

def ip_range_to_cidr(start_ip, end_ip):
    start = int(ipaddress.IPv4Address(start_ip))
    end = int(ipaddress.IPv4Address(end_ip))
    cidrs = list(ipaddress.summarize_address_range(ipaddress.IPv4Address(start), ipaddress.IPv4Address(end)))
    return [str(cidr) for cidr in cidrs]

def load_smallest_asns(n=10):
    asns = []
    asn_prefix_map = {}

    # Parse the ip2asn-v4.tsv file to build a mapping of ASN to prefixes
    with open("ip2asn-v4.tsv", "r") as f:
        for line in f:
            parts = line.strip().split("\t")
            if len(parts) < 3:
                continue
            start_ip, end_ip, asn = parts[:3]
            if asn.isdigit():  # Ensure ASN is valid
                if asn not in asn_prefix_map:
                    asn_prefix_map[asn] = []
                # Convert IP range to CIDR blocks
                asn_prefix_map[asn].extend(ip_range_to_cidr(start_ip, end_ip))

    # Parse the asns.jsonl file to get the smallest ASNs
    with open(ASRANK_FILE, "r") as f:
        for line in f:
            j = json.loads(line)
            asn = str(j['asn'])
            if asn in asn_prefix_map:  # Only include ASNs with prefixes in ip2asn-v4.tsv
                asns.append({
                    'asn': asn,
                    'org_name': j['org']['name'] if j.get('org') else '',
                    'prefixes': asn_prefix_map[asn],
                    'rank': j['rank']
                })

    # Sort by rank ascending (smallest networks)
    return sorted(asns, key=lambda x: x['rank'], reverse=True)[:n]

async def find_live_ip(prefix):
    """
    Finds a list of live IP addresses within the given prefix:
    1. Always test the first usable IP.
    2. Always test the last usable IP.
    3. If neither is pingable, randomly test other IPs in the prefix.
    Returns a list of pingable IPs.
    """
    net = ipaddress.ip_network(prefix)
    live_ips = []

    # Test the first usable IP
    first_ip = str(next(net.hosts()))
    if await is_pingable(first_ip):
        live_ips.append(first_ip)

    # Test the last usable IP
    last_ip = str(list(net.hosts())[-1])
    if await is_pingable(last_ip):
        live_ips.append(last_ip)

    # If no live IPs found yet, randomly test other IPs in the prefix
    if not live_ips:
        random_ips = random.sample(list(net.hosts()), min(100, net.num_addresses - 2))
        for ip in random_ips:
            if await is_pingable(str(ip)):
                live_ips.append(str(ip))
                break

    # Return the list of live IPs
    return live_ips

async def is_pingable(ip):
    """
    Checks if an IP address is reachable using a single ping.
    """
    try:
        res = await asyncio.create_subprocess_exec(
            PING_CMD, '-c', '1', '-W', '1', ip,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL
        )
        await res.wait()
        return res.returncode == 0
    except:
        return False

async def run_traceroute(ip, asn_data, prefix, results, longest):
    asn = asn_data['asn']
    try:
        print(f"[ASN {asn}] Traceroute to {ip} started")

        proc = await asyncio.create_subprocess_exec(
            TRACEROUTE_CMD, '-q', '1', '-w', '1', '-m', '50','-I', ip,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=TRACEROUTE_TIMEOUT)
            output = stdout.decode().splitlines()
            errout = stderr.decode()

            # Print stderr for debugging (optional)
            if len(errout) > 0:
                pprint(f"found error: {errout}")

            # Parse traceroute output
            filtered = [line for line in output if "*" not in line and line.strip()]
            hop_count = len(filtered)

            # Extract the last hop IP
            last_hop_ip = None
            if filtered:
                last_hop_ip = filtered[-1].split()[1]  # Extract IP from the last hop line

            # Verify if the last hop matches the target IP
            if last_hop_ip != ip:
                print(f"[ASN {asn}] Last hop ({last_hop_ip}) does not match target IP ({ip}). Ignoring result.")
                return

            print(f"[ASN {asn}] {ip} - {hop_count} hops")

            # Separate list for successful hops
            successful_hops = [line for line in output if line.split()[1] == ip]

            entry = {
                "asn": asn,
                "org_name": asn_data.get('org_name', ''),
                "prefix": prefix,
                "ip": ip,
                "hops": hop_count,
                "successful_hops": len(successful_hops),
                "route": filtered
            }
            results.append(entry)

            # Update longest route found so far
            if hop_count > longest['hops']:
                longest.update(entry)
                print(f"\n📈 New longest route ({hop_count} hops) to {ip} (ASN {asn})\n")
                # print("\n".join(output))
                print("\n".join(successful_hops))

        except asyncio.TimeoutError:
            proc.kill()
            print(f"[ASN {asn}] Traceroute to {ip} timed out")
    except Exception as e:
        print(f"[ASN {asn}] Traceroute failed: {e}")


async def handle_asn(asn_data, results, longest):
    """
    Handles scanning for a given ASN:
    1. Finds live IPs in the ASN's prefixes.
    2. Runs traceroute for each live IP.
    """
    for prefix in asn_data['prefixes']:
        # Get a list of live IPs (first, last, and random usable IPs if pingable)
        live_ips = await find_live_ip(prefix)

        # Scan each live IP
        for ip in live_ips:
            async with semaphore:  # Limit concurrency
                await run_traceroute(ip, asn_data, prefix, results, longest)

def save_results(results, longest, last_asn):
    """
    Saves the traceroute results and the longest route to the outputs/ directory.
    Filenames include a timestamp, the number of results, and the longest route quality.
    """
    # Ensure the outputs directory exists
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Generate a timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Get the number of results and the longest route quality
    results_count = len(results)
    longest_hops = longest.get("hops", 0)

    # Generate filenames
    traceroutes_filename = f"{OUTPUT_DIR}/traceroutes_{timestamp}_{results_count}results_{longest_hops}hops_{last_asn}last.json"
    longest_route_filename = f"{OUTPUT_DIR}/longest_route_{timestamp}_{results_count}results_{longest_hops}hops_{last_asn}last.json"

    # Save traceroute results
    with open(traceroutes_filename, "w") as f:
        json.dump(results, f, indent=4)
    print(f"Traceroute results saved to {traceroutes_filename}")

    # Save the longest route
    with open(longest_route_filename, "w") as f:
        json.dump(longest, f, indent=4)
    print(f"Longest route saved to {longest_route_filename}")

async def main():
    start_asn, n = 0, 10
    if len(sys.argv) > 2:
        start_asn = int(sys.argv[1])  # Take the first argument as the starting ASN
        n = int(sys.argv[2])
        print(f"Starting from ASN: {start_asn}, number asns to scan: {n}")

    # Check if the ASN-to-prefixes mapping file exists
    if os.path.exists(ASN_PREFIXES_FILE):
        print(f"Loading ASN-to-prefixes mapping from {ASN_PREFIXES_FILE}")
        with open(ASN_PREFIXES_FILE, "r") as f:
            asns = json.load(f)
    else:
        print("Generating ASN-to-prefixes mapping...")
        asns = load_smallest_asns(100000)  # Generate the mapping and save it to a file
        with open(ASN_PREFIXES_FILE, "w") as f:
            huj = json.dump(asns, f, indent=2)

    start_index = next((i for i, asn in enumerate(asns) if asn['asn'] == start_asn), None)
    if start_index is None:
        start_index = 0
    asns = asns[start_index:start_index + n]

    # Initialize the scan using the loaded or generated mapping
    pprint(asns[:10])
    if len(asns) == 0:
        print("No ASNs found. Exiting.")
        return

    results = []
    longest_result = {"hops": 0}

    tasks = [asyncio.create_task(handle_asn(asn, results, longest_result)) for asn in asns]
    await asyncio.gather(*tasks)

    last_asn = asns[-1]['asn']
    # Save all traceroute results
    save_results(results, longest_result, last_asn)

    print(f"\n✅ Saved {len(results)} traceroutes")
    print(f"📌 Longest route: {longest_result['hops']} hops to {longest_result['ip']}")


if __name__ == "__main__":
    asyncio.run(main())
