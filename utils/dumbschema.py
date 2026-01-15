"""a dumb parser for the registry objects"""


def dumb_parse_object(input: str) -> dict[str, str | list[str]]:
    ret_val: dict[str, str | list[str]] = {}
    for line in input.splitlines():
        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()
        if key in ret_val:
            if type(ret_val[key]) is str:
                # we already verified it's a string, not a list of strings smh
                ret_val[key] = [ret_val[key]]  # pyright: ignore[reportArgumentType]
            ret_val[key].append(value)  # pyright: ignore[reportAttributeAccessIssue]
        else:
            ret_val[key] = value
    return ret_val


def pretty_print_object(obj: dict[str, str | list[str]]) -> str:
    ret_val = ""
    for key, value in obj.items():
        delim = "\t"
        if len(key) < 7:
            delim = "\t\t"
        if type(value) is list:
            for v in value:
                ret_val += f"{key}:{delim}{v}\n"
        else:
            ret_val += f"{key}:{delim}{value}\n"
    return ret_val
