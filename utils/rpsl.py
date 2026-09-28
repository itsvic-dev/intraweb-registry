"""parser and printer for the registry objects"""

from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
KEY_WIDTH = 20


class RegistryObject:
    def __init__(self, attrs: list[tuple[str, str]]):
        self.attrs = attrs

    @classmethod
    def parse(cls, text: str) -> "RegistryObject":
        attrs = []
        for number, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            if line[0] in " \t+" and attrs:
                key, value = attrs[-1]
                attrs[-1] = (key, f"{value}\n{line[1:].strip()}")
                continue
            if ":" not in line:
                raise ValueError(f"line {number} has no key: {line!r}")
            key, value = line.split(":", 1)
            attrs.append((key.strip(), value.strip()))
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
