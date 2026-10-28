#!/usr/bin/env python3
"""Plans the switch side of a new VLAN from a FastIron running-config.

The VLAN goes on the trunk ports only: the ports tagged in every existing VLAN except
the default one. Access ports and partial trunks are left alone. VLAN membership of a
LAG is set on its primary port, so LAG members are replaced by their primary port.

Usage: fastiron-vlan-plan.py <running-config> <tag>   (output: JSON)
"""
import json
import re
import sys


def port_key(port):
    return tuple(int(part) for part in port.split("/"))


def expand(spec):
    """'ethe 1/1/1 to 1/1/4 ethe 1/1/21' -> ['1/1/1', '1/1/2', '1/1/3', '1/1/4', '1/1/21']"""
    tokens = spec.split()
    ports = []
    i = 0
    while i < len(tokens):
        if not tokens[i].startswith("eth") or i + 1 >= len(tokens):
            raise ValueError(f"unexpected port list: {spec!r}")
        first = tokens[i + 1]
        i += 2
        if i < len(tokens) and tokens[i] == "to":
            last = tokens[i + 1]
            i += 2
            unit, slot, start = first.split("/")
            unit2, slot2, end = last.split("/")
            if (unit, slot) != (unit2, slot2):
                raise ValueError(f"range across modules: {spec!r}")
            ports += [f"{unit}/{slot}/{n}" for n in range(int(start), int(end) + 1)]
        else:
            ports.append(first)
    return ports


def parse(lines):
    vlans, lags = {}, {}
    current = None
    for line in lines:
        line = line.rstrip()
        if not line.startswith(" "):
            current = None
            m = re.match(r"vlan (\d+)(?: name (\S+))? by port", line)
            if m:
                current = vlans.setdefault(int(m.group(1)), {"name": m.group(2), "tagged": [], "untagged": []})
                continue
            m = re.match(r"lag (\S+) \w+ id (\d+)", line)
            if m:
                current = lags.setdefault(m.group(1), {"id": int(m.group(2)), "ports": [], "primary": None})
            continue
        if current is None:
            continue
        words = line.split(None, 1)
        if words[0] in ("tagged", "untagged") and "tagged" in current:
            current[words[0]] += expand(words[1])
        elif words[0] == "ports" and "primary" in current:
            current["ports"] += expand(words[1])
        elif words[0] == "primary-port" and "primary" in current:
            current["primary"] = words[1].strip()
    return vlans, lags


def main():
    path, tag = sys.argv[1], int(sys.argv[2])
    with open(path, encoding="utf-8", errors="replace") as handle:
        vlans, lags = parse(handle)

    others = {vid: v for vid, v in vlans.items() if vid != 1 and vid != tag}
    if not others:
        sys.exit("no VLAN besides the default one: cannot tell the trunk ports")
    trunk = set.intersection(*(set(v["tagged"]) for v in others.values()))
    if not trunk:
        sys.exit("no port is tagged in every VLAN: no trunk ports found")

    command_ports = set()
    for port in trunk:
        lag = next((lag for lag in lags.values() if port in lag["ports"]), None)
        if lag is None:
            command_ports.add(port)
            continue
        if not set(lag["ports"]) <= trunk or not lag["primary"]:
            sys.exit(f"LAG {lag['id']} is only partly a trunk, or has no primary port")
        command_ports.add(lag["primary"])

    trunk_sorted = sorted(trunk, key=port_key)
    ports_sorted = sorted(command_ports, key=port_key)
    print(json.dumps({
        "exists": tag in vlans,
        "existing": vlans.get(tag),
        "trunk_ports": trunk_sorted,
        "untouched_ports": sorted(
            {p for v in others.values() for p in v["tagged"] + v["untagged"]} - trunk, key=port_key),
        "lags": {name: lag for name, lag in lags.items()},
        "commands": [
            "configure terminal",
            f"vlan {tag} name V{tag} by port",
            "tagged " + " ".join(f"ethe {p}" for p in ports_sorted),
            "spanning-tree 802-1w",
            "exit",
            "exit",
            "write memory",
        ],
    }, indent=2))


if __name__ == "__main__":
    main()
