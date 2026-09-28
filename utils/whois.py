"""whois server for the registry objects"""

import argparse
import ipaddress
import platform
import socketserver

from rpsl import Registry, RegistryObject, file_name

CONTACT_KINDS = ("person", "role", "organisation")
NETWORK_KINDS = ("inetnum", "route")
BANNER = f"% This is Intraweb Whois server on Python {platform.python_version()}\n\n"
FOOTER = "% This query was served by the Intranet WHOIS query server\n"


def matches(registry: Registry, query: str) -> list[tuple[str, str]]:
    try:
        network = ipaddress.ip_network(query, strict=False)
    except ValueError:
        pass
    else:
        found = [(kind, registry.enclosing(kind, network)) for kind in NETWORK_KINDS]
        return [(kind, name) for kind, name in found if name]

    found = []
    for kind, objects in registry.objects.items():
        for name in (query, query.upper(), query.lower()):
            if file_name(name) in objects:
                found.append((kind, file_name(name)))
                break
    return found


def contacts(registry: Registry, kind: str, obj: RegistryObject) -> list[tuple[str, str]]:
    schema = registry.schemas.get(kind)
    if schema is None:
        return []
    found = []
    for key, value in obj.attrs:
        definition = schema.keys.get(key)
        for ref in definition.lookups if definition else ():
            target = registry.refs.get(ref)
            if target in CONTACT_KINDS and registry.find(target, value):
                found.append((target, file_name(value)))
    return found


def lookup(registry: Registry, query: str) -> list[RegistryObject]:
    """objects matching the query, each followed by the contacts it references"""
    seen: set[tuple[str, str]] = set()
    output: list[RegistryObject] = []

    def visit(kind: str, name: str):
        if (kind, name) in seen:
            return
        seen.add((kind, name))
        obj = registry.objects[kind][name]
        output.append(obj)
        for contact in contacts(registry, kind, obj):
            visit(*contact)

    for match in matches(registry, query):
        visit(*match)
    return output


class WhoisRequestHandler(socketserver.StreamRequestHandler):
    timeout = 10

    def handle(self):
        try:
            query = self.rfile.readline(1024).decode(errors="replace").strip()
        except TimeoutError:
            return
        objects = lookup(Registry(), query) if query else []
        if objects:
            body = "\n".join(str(obj) for obj in objects)
        else:
            body = "% Your query returned zero results.\n"
        response = f"{BANNER}{body}\n{FOOTER}"
        self.wfile.write(response.replace("\n", "\r\n").encode())


class WhoisServer(socketserver.ForkingTCPServer):
    allow_reuse_address = True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-H", "--host", default="localhost")
    parser.add_argument("-p", "--port", default=43, type=int)
    args = parser.parse_args()

    print(f"Starting WHOIS server on {args.host}:{args.port}")
    print(f"Access me with `whois -h {args.host} -p {args.port} ...`")
    with WhoisServer((args.host, args.port), WhoisRequestHandler) as server:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\n --- Ctrl-C caught, quitting nicely.")
