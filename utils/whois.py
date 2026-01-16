# simple whois server with hardcoded parsing to make my life easier
import ipaddress
import os
import re
import socketserver
import sys

from dumbschema import dumb_parse_object, pretty_print_object

REGEXES = {
    r"^(((?!25?[6-9])[12]\d|[1-9])?\d\.?\b){4}$": ["inetnum", "route"],
    r"^[\w-]*-IW$": ["person", "role"],
    r"^AS\d+$": ["aut-num"],
    r"^.*\.iw$": ["dns"],
    r"^iw$": ["dns"],  # 'iw' zone
}

FOOTER = "% This query was served by the Intranet WHOIS query server"


def lookup_inetnum(query: str) -> str:
    query_net = ipaddress.IPv4Network(query)
    target_net: ipaddress.IPv4Network | None = None
    for entry in os.scandir("data/inetnum"):
        entry_net = ipaddress.IPv4Network(entry.name.replace("_", "/"))
        if query_net.subnet_of(entry_net):
            if target_net is None or entry_net.subnet_of(target_net):
                target_net = entry_net

    if target_net is None:
        return ""
    with open(f"data/inetnum/{str(target_net).replace('/', '_')}") as file:
        obj = dumb_parse_object(file.read())

    output = pretty_print_object(obj) + "\n"

    EXTRA_LOOKUPS = ["admin-c", "tech-c", "org"]
    extra_objects = set()

    for extra_key in EXTRA_LOOKUPS:
        if extra_key in obj:
            if type(obj[extra_key]) is list:
                for value in obj[extra_key]:
                    if value not in extra_objects:
                        output += lookup(value)
                        extra_objects.add(value)
            else:
                value = obj[extra_key]
                if value not in extra_objects:
                    output += lookup(value)  # pyright: ignore[reportArgumentType]
                    extra_objects.add(value)

    return output


def lookup_route(query: str) -> str:
    query_net = ipaddress.IPv4Network(query)
    target_net: ipaddress.IPv4Network | None = None
    for entry in os.scandir("data/route"):
        entry_net = ipaddress.IPv4Network(entry.name.replace("_", "/"))
        if query_net.subnet_of(entry_net):
            if target_net is None or entry_net.subnet_of(target_net):
                target_net = entry_net

    if target_net is None:
        return ""
    with open(f"data/route/{str(target_net).replace('/', '_')}") as file:
        return pretty_print_object(dumb_parse_object(file.read())) + "\n"


def lookup_person(query: str) -> str:
    if not os.path.exists(f"data/person/{query}"):
        return ""

    with open(f"data/person/{query}") as file:
        return pretty_print_object(dumb_parse_object(file.read())) + "\n"


def lookup_dns(query: str) -> str:
    if not os.path.exists(f"data/dns/{query}"):
        return ""

    with open(f"data/dns/{query}") as file:
        obj = dumb_parse_object(file.read())

    EXTRA_LOOKUPS = ["admin-c", "tech-c", "org"]
    extra_objects = set()

    output = pretty_print_object(obj) + "\n"

    for extra_key in EXTRA_LOOKUPS:
        if extra_key in obj:
            if type(obj[extra_key]) is list:
                for value in obj[extra_key]:
                    if value not in extra_objects:
                        output += lookup(value)
                        extra_objects.add(value)
            else:
                value = obj[extra_key]
                if value not in extra_objects:
                    output += lookup(value)  # pyright: ignore[reportArgumentType]
                    extra_objects.add(value)

    return output


def lookup(query: str) -> str:
    query = query.strip()
    output = ""
    for key, values in REGEXES.items():
        if re.fullmatch(key, query):
            # found a match, lookup values
            for value in values:
                match value:
                    case "inetnum":
                        output += lookup_inetnum(query)
                    case "route":
                        output += lookup_route(query)
                    case "person":
                        output += lookup_person(query)
                    case "dns":
                        output += lookup_dns(query)

    return output


class WhoisRequestHandler(socketserver.StreamRequestHandler):
    def handle(self):
        data = self.rfile.readline(1024).decode()
        self.wfile.write(
            (
                f"% This is Intraweb Whois server on Python {sys.version}\r\n\r\n"
            ).encode()
        )
        output = lookup(data.strip())
        if output == "":
            self.wfile.write(b"% Your query returned zero results.\r\n")
        else:
            self.wfile.write(output.replace("\n", "\r\n").encode())


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("-H", "--host", default="localhost")
    parser.add_argument("-p", "--port", default=43, type=int)
    ns = parser.parse_args()

    host = ns.host
    port = ns.port

    print(f"Starting WHOIS server on {host}:{port}")
    print(f"Access me with `whois -h {host} -p {port} ...`")
    with socketserver.ForkingTCPServer((host, port), WhoisRequestHandler) as server:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\n --- Ctrl-C caught, quitting nicely.")
