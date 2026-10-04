#!/usr/bin/env python3
"""Export a compiled SELinux policy (policy.bin / policy.NN) as JSON.

Uses setools (python3-setools). The extension attaches source locations; this
script only reports what the kernel policy actually contains.
"""
import json
import sys

import setools


def names(items):
    return sorted(str(x) for x in items)


def main(path):
    p = setools.SELinuxPolicy(path)
    types = []
    for t in p.types():
        types.append({"name": str(t), "attrs": names(t.attributes()), "aliases": names(t.aliases()),
                      "permissive": bool(t.ispermissive)})
    attributes = [{"name": str(a)} for a in p.typeattributes()]
    roles = [{"name": str(r), "types": names(r.types())} for r in p.roles()]
    users = []
    for u in p.users():
        entry = {"name": str(u), "roles": names(u.roles)}
        if p.mls:
            entry["range"] = str(u.mls_range)
            entry["level"] = str(u.mls_level)
        users.append(entry)
    bools = [{"name": str(b), "state": bool(b.state)} for b in p.bools()]
    classes = []
    for c in p.classes():
        try:
            common = str(c.common)
            inherited = names(c.common.perms)
        except setools.exception.NoCommon:
            common, inherited = None, []
        classes.append({"name": str(c), "perms": names(c.perms), "common": common, "inherited": inherited})
    # Domain transitions: type_transition <domain> <entrypoint>:process <new domain>
    transitions = [{"source": str(r.source), "entry": str(r.target), "result": str(r.default)}
                   for r in setools.TERuleQuery(p, ruletype=["type_transition"], tclass=["process"]).results()]
    json.dump({
        "version": p.version, "mls": p.mls, "handleUnknown": str(p.handle_unknown),
        "counts": {"types": p.type_count, "attributes": p.type_attribute_count, "roles": p.role_count,
                   "users": p.user_count, "booleans": p.boolean_count, "classes": p.class_count,
                   "allow": p.allow_count, "dontaudit": p.dontaudit_count, "type_transition": p.type_transition_count},
        "types": types, "attributes": attributes, "roles": roles, "users": users,
        "bools": bools, "classes": classes, "transitions": transitions,
    }, sys.stdout)


if __name__ == "__main__":
    main(sys.argv[1])
