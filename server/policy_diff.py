#!/usr/bin/env python3
"""Compare two compiled SELinux policies (policy.bin) with setools; print JSON.

Rules are keyed by (rule type, source, target, class, conditional) and
compared permission by permission (or by default type for type_* rules), so a
rule that gains one permission shows as modified with just that permission.
Element changes cover types, attributes and their members, roles and their
types, users and their roles, booleans and classes.
"""
import json
import sys

import setools

MAX_RULES = 5000


def te_rules(p):
    out = {}
    for r in p.terules():
        try:
            cond = "%s:%s" % (r.conditional, str(r.conditional_block).lower())
        except setools.exception.RuleNotConditional:
            cond = ""
        key = (str(r.ruletype), str(r.source), str(r.target), str(r.tclass), cond)
        try:
            val = {str(x) for x in r.perms}
        except setools.exception.RuleUseError:
            val = {str(r.default)}
        out.setdefault(key, set()).update(val)
    return out


def elements(p):
    types = {str(t): {"attrs": {str(a) for a in t.attributes()}, "aliases": {str(a) for a in t.aliases()}} for t in p.types()}
    return {
        "types": types,
        "attributes": {str(a) for a in p.typeattributes()},
        "roles": {str(r): {str(t) for t in r.types()} for r in p.roles()},
        "users": {str(u): {str(r) for r in u.roles} for u in p.users()},
        "bools": {str(b): bool(b.state) for b in p.bools()},
        "classes": {str(c) for c in p.classes()},
    }


def set_diff(a, b):
    return {"added": sorted(b - a), "removed": sorted(a - b)}


def main(path_a, path_b):
    pa, pb = setools.SELinuxPolicy(path_a), setools.SELinuxPolicy(path_b)
    ra, rb = te_rules(pa), te_rules(pb)
    rules = []
    for k in sorted(set(ra) | set(rb)):
        a, b = ra.get(k, set()), rb.get(k, set())
        if a == b:
            continue
        kind = "added" if not a else "removed" if not b else "modified"
        rules.append({"rt": k[0], "s": k[1], "t": k[2], "c": k[3], "cond": k[4], "kind": kind,
                      "add": sorted(b - a), "del": sorted(a - b), "had": sorted(a & b)})
    ea, eb = elements(pa), elements(pb)
    membership = []
    for t in sorted(set(ea["types"]) & set(eb["types"])):
        d = set_diff(ea["types"][t]["attrs"], eb["types"][t]["attrs"])
        if d["added"] or d["removed"]:
            membership.append({"type": t, **d})
    role_types = [{"role": r, **set_diff(ea["roles"][r], eb["roles"][r])} for r in sorted(set(ea["roles"]) & set(eb["roles"]))
                  if ea["roles"][r] != eb["roles"][r]]
    user_roles = [{"user": u, **set_diff(ea["users"][u], eb["users"][u])} for u in sorted(set(ea["users"]) & set(eb["users"]))
                  if ea["users"][u] != eb["users"][u]]
    bools_changed = [{"name": b, "from": ea["bools"][b], "to": eb["bools"][b]} for b in sorted(set(ea["bools"]) & set(eb["bools"]))
                     if ea["bools"][b] != eb["bools"][b]]
    # Attribute membership on each side, only for types in changed rules: used
    # to explain rules that come from an attribute rule.
    involved = {r["s"] for r in rules[:MAX_RULES]} | {r["t"] for r in rules[:MAX_RULES]}
    attrs_of = lambda e: {t: sorted(e["types"][t]["attrs"]) for t in involved if t in e["types"]}
    aliases_of = lambda e: {a: t for t, v in e["types"].items() for a in v["aliases"]}
    json.dump({
        "rules": rules[:MAX_RULES], "ruleCount": len(rules), "truncated": len(rules) > MAX_RULES,
        "types": set_diff(set(ea["types"]), set(eb["types"])),
        "attributes": set_diff(ea["attributes"], eb["attributes"]),
        "membership": membership,
        "roles": set_diff(set(ea["roles"]), set(eb["roles"])), "roleTypes": role_types,
        "users": set_diff(set(ea["users"]), set(eb["users"])), "userRoles": user_roles,
        "bools": set_diff(set(ea["bools"]), set(eb["bools"])), "boolDefaults": bools_changed,
        "classes": set_diff(ea["classes"], eb["classes"]),
        "attrsA": attrs_of(ea), "attrsB": attrs_of(eb),
        "aliasesA": aliases_of(ea), "aliasesB": aliases_of(eb),
    }, sys.stdout)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
