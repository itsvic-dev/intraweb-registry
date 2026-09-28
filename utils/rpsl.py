"""parser, schema loader and validator for the registry objects"""

import ipaddress
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
KEY_WIDTH = 20
NAME_RE = re.compile(r"[a-zA-Z]([a-zA-Z0-9_\-]*[a-zA-Z0-9])?")
DNS_LABEL = r"(?!-)[a-z0-9-]{1,63}(?<!-)"
DOMAIN_RE = re.compile(rf"(?:{DNS_LABEL}\.)*iw", re.IGNORECASE)


class RegistryObject:
    def __init__(self, attrs: list[tuple[str, str]]):
        self.attrs = attrs

    @classmethod
    def parse(cls, text: str) -> "RegistryObject":
        attrs = []
        for number, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            if line[0] in " \t+":
                if not attrs:
                    raise ValueError(f"line {number} continues a missing attribute")
                key, value = attrs[-1]
                attrs[-1] = (key, f"{value}\n{line[1:].strip()}")
                continue
            key, colon, value = line.partition(":")
            if not colon or not NAME_RE.fullmatch(key):
                raise ValueError(f"line {number} is not a 'key: value' pair: {line!r}")
            attrs.append((key, value.strip()))
        if not attrs:
            raise ValueError("object is empty")
        return cls(attrs)

    @classmethod
    def load(cls, path: Path) -> "RegistryObject":
        return cls.parse(path.read_text())

    def get(self, key: str) -> str | None:
        return next((v for k, v in self.attrs if k == key), None)

    def get_all(self, key: str) -> list[str]:
        return [v for k, v in self.attrs if k == key]

    def __str__(self) -> str:
        lines = []
        for key, value in self.attrs:
            first, *rest = value.split("\n")
            lines.append(f"{key + ':':<{KEY_WIDTH - 1}} {first}")
            lines += [" " * KEY_WIDTH + line if line else "+" for line in rest]
        return "".join(f"{line}\n" for line in lines)


def _matches(pattern: str):
    return lambda value: re.fullmatch(pattern, value) is not None


def _parses(parser):
    def check(value: str) -> bool:
        try:
            parser(value)
        except ValueError:
            return False
        return True

    return check


# a [label] in a key spec is checked with the type of the same name, other labels accept any word
TYPES = {
    "asn": _matches(r"AS\d+"),
    "domain-name": lambda value: DOMAIN_RE.fullmatch(value) is not None,
    "ip-addr": _parses(ipaddress.ip_address),
    "ipv4-addr": _parses(ipaddress.IPv4Address),
    "ipv4-network": _parses(ipaddress.IPv4Network),
    "lat-c": _parses(float),
    "long-c": _parses(float),
    "number": _matches(r"\d+"),
    "hex": _matches(r"[0-9A-Fa-f]+"),
    "ssh-key-type": _matches(r"(ssh-|ecdsa-sha2-|sk-ssh-|sk-ecdsa-)[\w@.-]+"),
}


@dataclass(frozen=True)
class Label:
    name: str
    repeat: bool

    def accepts(self, word: str) -> bool:
        return TYPES.get(self.name, lambda _: True)(word)


@dataclass(frozen=True)
class Choice:
    options: tuple[str, ...]
    optional: bool

    def accepts(self, word: str) -> bool:
        for option in self.options:
            if option.startswith("<") and option.endswith(">"):
                if TYPES[option[1:-1]](word):
                    return True
            elif option == word:
                return True
        return False


@dataclass(frozen=True)
class Literal:
    text: str


Spec = list[Label | Choice | Literal]


def parse_spec(words: list[str]) -> Spec:
    spec: Spec = []
    for word in words:
        if match := re.fullmatch(r"\[([^\]]+)\](\.\.\.)?", word):
            if not NAME_RE.fullmatch(match[1]):
                raise ValueError(f"bad label {word!r}")
            spec.append(Label(match[1], bool(match[2])))
        elif match := re.fullmatch(r"\{([^{}]*)\}", word):
            options = match[1].split("|")
            for option in options:
                if option.startswith("<") and option.endswith(">"):
                    if option[1:-1] not in TYPES:
                        raise ValueError(f"unknown type {option!r} in {word!r}")
                elif option and not NAME_RE.fullmatch(option):
                    raise ValueError(f"bad option {option!r} in {word!r}")
            spec.append(Choice(tuple(o for o in options if o), "" in options))
        elif match := re.fullmatch(r"'([^'\s]+)'", word):
            spec.append(Literal(match[1]))
        else:
            raise ValueError(f"bad spec token {word!r}")
    return spec


def check_spec(spec: Spec, value: str) -> str | None:
    """describe why value does not match spec, or return None if it does"""
    if not spec:
        return None
    words = value.split()
    for token in spec:
        match token:
            case Label(name, True):
                bad = [word for word in words if not token.accepts(word)]
                if bad:
                    return f"{bad[0]!r} is not a valid {name}"
                words = []
            case Label(name, False):
                if not words:
                    return f"missing [{name}]"
                if not token.accepts(words[0]):
                    return f"{words[0]!r} is not a valid {name}"
                words.pop(0)
            case Choice(options, optional):
                if words and token.accepts(words[0]):
                    words.pop(0)
                elif not optional:
                    got = repr(words[0]) if words else "nothing"
                    return f"expected one of {{{'|'.join(options)}}}, got {got}"
            case Literal(text):
                if not words or words[0] != text:
                    return f"expected {text!r}"
                words.pop(0)
    if words:
        return f"unexpected {' '.join(words)!r}"
    return None


PRESENCES = ("required", "optional", "recommend", "deprecate")

# key lines are checked by KeyDef.parse, their spec in SCHEMA-SCHEMA is only prose
DESCRIPTIVE_SPECS = {("schema", "key")}

# checks the schemas do not carry, applied on top of the schema spec
EXTRA_SPECS = {
    ("aut-num", "aut-num"): parse_spec(["[asn]"]),
    ("dns", "domain"): parse_spec(["[domain-name]"]),
    ("dns", "ds-rdata"): parse_spec(["[number]", "[number]", "[number]", "[hex]"]),
    ("inetnum", "cidr"): parse_spec(["[ipv4-network]"]),
    ("route", "route"): parse_spec(["[ipv4-network]"]),
}


@dataclass(frozen=True)
class KeyDef:
    name: str
    presence: str
    multiple: bool
    primary: bool
    schema: bool
    lookups: tuple[str, ...]
    spec: Spec

    @classmethod
    def parse(cls, line: str, dir_name: str) -> "KeyDef":
        words = line.split()
        spec_words: list[str] = []
        if ">" in words:
            index = words.index(">")
            words, spec_words = words[:index], words[index + 1 :]
        if len(words) < 3:
            raise ValueError(f"key {line!r} needs a name, a presence and a count")
        name, presence, count, *options = words
        if not NAME_RE.fullmatch(name):
            raise ValueError(f"bad key name {name!r}")
        if presence not in PRESENCES:
            raise ValueError(f"key {name}: presence must be one of {'|'.join(PRESENCES)}")
        if count not in ("single", "multiple"):
            raise ValueError(f"key {name}: count must be single or multiple")

        primary = schema = False
        lookups: tuple[str, ...] = ()
        for option in options:
            if option == "primary":
                primary = True
            elif option == "schema":
                schema = True
            elif option.startswith("lookup="):
                lookups = tuple(option.removeprefix("lookup=").split(","))
            else:
                raise ValueError(f"key {name}: unknown option {option!r}")

        spec: Spec = []
        if (dir_name, name) not in DESCRIPTIVE_SPECS:
            spec = parse_spec(spec_words)
        return cls(name, presence, count == "multiple", primary, schema, lookups, spec)


@dataclass(frozen=True)
class Schema:
    name: str
    ref: str
    dir_name: str
    keys: dict[str, KeyDef]
    primary_key: str
    type_key: str

    @classmethod
    def from_object(cls, obj: RegistryObject) -> "Schema":
        name, ref, dir_name = obj.get("schema"), obj.get("ref"), obj.get("dir-name")
        if not (name and ref and dir_name):
            raise ValueError("a schema needs schema, ref and dir-name")

        keys: dict[str, KeyDef] = {}
        for line in obj.get_all("key"):
            key = KeyDef.parse(line, dir_name)
            if key.name in keys:
                raise ValueError(f"key {key.name} is defined twice")
            keys[key.name] = key

        primary = [key for key in keys.values() if key.primary]
        type_keys = [key for key in keys.values() if key.schema]
        if len(primary) != 1 or len(type_keys) != 1:
            raise ValueError("a schema needs exactly one primary and one schema key")
        for key in primary + type_keys:
            if key.presence != "required" or key.multiple:
                raise ValueError(f"key {key.name} must be required and single")
        return cls(name, ref, dir_name, keys, primary[0].name, type_keys[0].name)


Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def file_name(value: str) -> str:
    return value.replace("/", "_")


def check_inetnum(obj: RegistryObject) -> str | None:
    first, _, last = (obj.get("inetnum") or "").partition(" - ")
    try:
        network = ipaddress.IPv4Network(obj.get("cidr") or "")
        if (ipaddress.IPv4Address(first), ipaddress.IPv4Address(last)) == (
            network.network_address,
            network.broadcast_address,
        ):
            return None
    except ValueError:
        pass
    return "inetnum range does not match cidr"


OBJECT_CHECKS = {"inetnum": check_inetnum}


@dataclass(frozen=True)
class Problem:
    path: Path
    message: str
    error: bool = True


class Registry:
    """every object in the data directory, keyed by directory and file name"""

    def __init__(self, root: Path = DATA_DIR):
        self.root = root
        self.problems: list[Problem] = []
        self.objects: dict[str, dict[str, RegistryObject]] = {}
        self.schemas: dict[str, Schema] = {}

        for directory in sorted(root.iterdir()):
            if directory.name.startswith("."):
                continue
            if not directory.is_dir():
                self.report(directory, "is not inside an object directory")
                continue
            objects = self.objects.setdefault(directory.name, {})
            for path in sorted(directory.iterdir()):
                if path.name.startswith("."):
                    continue
                try:
                    objects[path.name] = RegistryObject.load(path)
                except (ValueError, UnicodeDecodeError) as error:
                    self.report(path, str(error))

        for name, obj in self.objects.get("schema", {}).items():
            try:
                schema = Schema.from_object(obj)
            except ValueError as error:
                self.report(root / "schema" / name, str(error))
                continue
            self.schemas[schema.dir_name] = schema
        self.refs = {schema.ref: schema.dir_name for schema in self.schemas.values()}

    def report(self, path: Path, message: str, error: bool = True):
        self.problems.append(Problem(path, message, error))

    def find(self, kind: str, name: str) -> RegistryObject | None:
        return self.objects.get(kind, {}).get(file_name(name))

    def enclosing(self, kind: str, network: Network, strict: bool = False) -> str | None:
        """name of the most specific object of a kind that contains network"""
        best = None
        for name in self.objects.get(kind, {}):
            try:
                candidate = ipaddress.ip_network(name.replace("_", "/"))
            except ValueError:
                continue
            if candidate.version != network.version or not network.subnet_of(candidate):
                continue
            if strict and candidate == network:
                continue
            if best is None or candidate.prefixlen > best.prefixlen:
                best = candidate
        return file_name(str(best)) if best else None

    def validate(self) -> list[Problem]:
        for schema in self.schemas.values():
            for key in schema.keys.values():
                for ref in key.lookups:
                    if ref not in self.refs:
                        self.report(self.root / "schema" / schema.name, f"key {key.name}: unknown ref {ref}")

        for kind, objects in self.objects.items():
            schema = self.schemas.get(kind)
            for name, obj in objects.items():
                path = self.root / kind / name
                if schema is None:
                    self.report(path, f"no schema has dir-name {kind}")
                else:
                    self.check(schema, path, obj)
        return self.problems

    def check(self, schema: Schema, path: Path, obj: RegistryObject):
        if obj.attrs[0][0] != schema.type_key:
            self.report(path, f"object must start with {schema.type_key}")
        primary = obj.get(schema.primary_key)
        if primary is not None and file_name(primary) != path.name:
            self.report(path, f"{schema.primary_key} {primary!r} does not match the file name")

        for key, value in obj.attrs:
            definition = schema.keys.get(key)
            if definition is None:
                self.report(path, f"unknown key {key}")
                continue
            if definition.presence == "deprecate":
                self.report(path, f"key {key} is deprecated", error=False)
            for spec in (definition.spec, EXTRA_SPECS.get((schema.dir_name, key), [])):
                if message := check_spec(spec, value):
                    self.report(path, f"{key}: {message}")
            if definition.lookups and not any(
                self.find(self.refs.get(ref, ""), value) for ref in definition.lookups
            ):
                self.report(path, f"{key}: {value!r} not found in {', '.join(definition.lookups)}")

        counts = Counter(key for key, _ in obj.attrs)
        for key, definition in schema.keys.items():
            if counts[key] == 0 and definition.presence == "required":
                self.report(path, f"missing required key {key}")
            elif counts[key] == 0 and definition.presence == "recommend":
                self.report(path, f"missing recommended key {key}", error=False)
            elif counts[key] > 1 and not definition.multiple:
                self.report(path, f"key {key} may only appear once")

        if (object_check := OBJECT_CHECKS.get(schema.dir_name)) and (message := object_check(obj)):
            self.report(path, message)

    def valid(self, kind: str) -> dict[str, RegistryObject]:
        """objects of a kind that passed validate() without errors"""
        broken = {problem.path for problem in self.problems if problem.error}
        return {
            name: obj
            for name, obj in self.objects.get(kind, {}).items()
            if self.root / kind / name not in broken
        }
