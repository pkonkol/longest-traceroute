import asyncio
import subprocess
import json
import random
import ipaddress

MAX_CONCURRENT = 300
PING_RETRIES = 50
TRACEROUTE_TIMEOUT = 120
ASRANK_FILE = "asns.jsonl"
TRACEROUTE_CMD = 'gtraceroute'
PING_CMD = 'gping'

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
    net = ipaddress.ip_network(prefix)
    for _ in range(PING_RETRIES):
        ip = str(random.choice(list(net.hosts())))
        try:
            res = await asyncio.create_subprocess_exec(
                PING_CMD, '-c', '1', '-W', '1', ip,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            await res.wait()
            if res.returncode == 0:
                return ip
        except:
            continue
    return None

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
    for prefix in asn_data['prefixes']:
        ip = await find_live_ip(prefix)
        if ip:
            async with semaphore:  # Acquire semaphore only for the traceroute operation
                await run_traceroute(ip, asn_data, prefix, results, longest)
            break

import json
from pprint import pprint

async def main():
    asns = load_smallest_asns(1000)
    pprint(asns)
    if len(asns) == 0:
        print("No ASNs found. Exiting.")
        return


    results = []
    longest_result = {"hops": 0}

    tasks = [asyncio.create_task(handle_asn(asn, results, longest_result)) for asn in asns]
    await asyncio.gather(*tasks)

    # Save all traceroute results
    with open("traceroutes.json", "w") as f:
        json.dump(results, f, indent=2)

    # Save the longest route separately
    with open("longest_route.json", "w") as f:
        json.dump(longest_result, f, indent=2)

    print(f"\n✅ Saved {len(results)} traceroutes")
    print(f"📌 Longest route: {longest_result['hops']} hops to {longest_result['ip']}")


if __name__ == "__main__":
    asyncio.run(main())
