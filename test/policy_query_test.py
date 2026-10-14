"""Unit tests for server/policy_query.py without setools: a small fake policy
(types, roles, users, classes, rules, constraints, range transitions, levels)
stands in for setools, so the analysis code runs anywhere Python 3 does.
Run through test/policy-query-test.js (npm test) or directly:
    python3 test/policy_query_test.py
"""
import os
import sys
import tempfile
import types

failures = 0


def check(cond, what, extra=None):
    global failures
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        failures += 1
        if extra is not None:
            print("      " + repr(extra)[:2000])


# ---------- a fake setools ----------

class NoCommon(Exception):
    pass


class RuleUseError(Exception):
    pass


class RuleNotConditional(Exception):
    pass


class Named(object):
    def __init__(self, name):
        self.name = name

    def __str__(self):
        return self.name


class Level(object):
    """s0, s0:c1,c2, s0:c1.c3: dominance is sensitivity >= and categories superset."""
    def __init__(self, text):
        text = text.strip()
        sens, _, cats = text.partition(":")
        if not sens.startswith("s") or not sens[1:].isdigit() or int(sens[1:]) > 0:
            raise ValueError("%s is not a valid level" % text)
        self.sens = int(sens[1:])
        self.cats = set()
        for part in filter(None, cats.split(",")):
            a, _, b = part.partition(".")
            lo, hi = int(a[1:]), int((b or a)[1:])
            if hi > 1023:
                raise ValueError("%s is not a valid level" % text)
            self.cats.update(range(lo, hi + 1))

    def __ge__(self, o):
        return self.sens >= o.sens and self.cats >= o.cats

    def __le__(self, o):
        return o >= self

    def __eq__(self, o):
        return self.sens == o.sens and self.cats == o.cats

    def __ne__(self, o):
        return not self == o

    def __xor__(self, o):
        return not (self >= o) and not (o >= self)

    def __hash__(self):
        return hash((self.sens, tuple(sorted(self.cats))))

    def __str__(self):
        c = sorted(self.cats)
        out, i = [], 0
        while i < len(c):
            j = i
            while j + 1 < len(c) and c[j + 1] == c[j] + 1:
                j += 1
            out.append("c%d.c%d" % (c[i], c[j]) if j > i else "c%d" % c[i])
            i = j + 1
        return "s%d" % self.sens + (":" + ",".join(out) if out else "")


class Range(object):
    def __init__(self, text):
        lo, _, hi = text.replace(" ", "").partition("-")
        self.low, self.high = Level(lo), Level(hi or lo)

    def __str__(self):
        return "%s - %s" % (self.low, self.high) if self.low != self.high else str(self.low)


class FType(Named):
    def __init__(self, name, attrs=(), aliases=(), permissive=False):
        Named.__init__(self, name)
        self._attrs, self._aliases, self.ispermissive = [Named(a) for a in attrs], [Named(a) for a in aliases], permissive

    def attributes(self):
        return self._attrs

    def aliases(self):
        return self._aliases


class FRole(Named):
    def __init__(self, name, ts):
        Named.__init__(self, name)
        self._types = [Named(t) for t in ts]

    def types(self):
        return self._types


class FUser(Named):
    def __init__(self, name, roles, rng):
        Named.__init__(self, name)
        self.roles = [Named(r) for r in roles]
        self.mls_range = Range(rng)


class FClass(Named):
    def __init__(self, name, perms):
        Named.__init__(self, name)
        self.perms = [Named(p) for p in perms]

    @property
    def common(self):
        raise NoCommon()


class FRule(object):
    def __init__(self, rt, s, t, c, perms=None, default=None, cond=None):
        self.ruletype, self.source, self.target, self.tclass = Named(rt), Named(s), Named(t), Named(c)
        self._perms, self.default, self._cond = perms, Named(default) if default else None, cond

    @property
    def perms(self):
        if self._perms is None:
            raise RuleUseError()
        return [Named(p) for p in self._perms]

    @property
    def conditional(self):
        if not self._cond:
            raise RuleNotConditional()
        return self._cond

    @property
    def filename(self):
        raise RuleUseError()


class Expr(object):
    """A constraint expression: postfix tokens (operands, operators, frozensets) and its text."""
    def __init__(self, text, tokens):
        self.text, self.tokens = text, tokens

    def __iter__(self):
        return iter([Named(t) if isinstance(t, str) else t for t in self.tokens])

    def __str__(self):
        return self.text


class FConstraint(object):
    def __init__(self, rt, cls, perms, expr):
        self.ruletype, self.tclass, self.perms, self.expression = Named(rt), Named(cls), [Named(p) for p in perms], expr


class FMLSRule(object):
    def __init__(self, s, t, c, rng):
        self.source, self.target, self.tclass, self.default = Named(s), Named(t), Named(c), rng


class FBool(Named):
    def __init__(self, name, state):
        Named.__init__(self, name)
        self.state = state


MCS = frozenset(["mcs_constrained_type"])
NOT_MCS = ["h1", "h2", "dom", "t1", MCS, "!=", "or"]          # ( h1 dom h2 ) or ( t1 != mcs_constrained_type )
TYPES = [
    FType("init_t", ["domain", "mlsfilewrite"]), FType("container_t", ["domain", "mcs_constrained_type", "container_domain"]),
    FType("svirt_t", ["domain", "mcs_constrained_type"]), FType("staff_t", ["domain"]), FType("setrans_t", ["domain"]),
    FType("container_file_t", ["file_type"]), FType("etc_t", ["file_type", "mlstrustedobject"], aliases=["etc_alias_t"]),
    FType("container_exec_t", ["file_type"]), FType("setrans_exec_t", ["file_type"]),
]
CLASSES = [FClass("file", ["read", "write", "open", "getattr", "execute", "entrypoint", "create", "append"]), FClass("dir", ["search", "read", "write"]),
           FClass("process", ["transition", "signal"]), FClass("unix_stream_socket", ["connectto", "read", "write"]),
           FClass("shm", ["read", "write"]), FClass("msg", ["send", "receive"])]
RULES = [
    FRule("allow", "container_t", "container_file_t", "file", ["read", "write", "open", "create"]),
    FRule("allow", "container_t", "container_file_t", "dir", ["search", "read"]),
    FRule("allow", "container_t", "container_t", "unix_stream_socket", ["connectto", "read", "write"]),
    FRule("allow", "container_t", "container_t", "shm", ["read", "write"]),
    FRule("allow", "container_t", "etc_t", "file", ["read", "open"]),
    FRule("allow", "init_t", "container_exec_t", "file", ["execute"]), FRule("allow", "container_t", "container_exec_t", "file", ["entrypoint"]),
    FRule("allow", "init_t", "container_t", "process", ["transition"]), FRule("type_transition", "init_t", "container_exec_t", "process", default="container_t"),
    FRule("allow", "init_t", "setrans_exec_t", "file", ["execute"]), FRule("allow", "setrans_t", "setrans_exec_t", "file", ["entrypoint"]),
    FRule("allow", "init_t", "setrans_t", "process", ["transition"]), FRule("type_transition", "init_t", "setrans_exec_t", "process", default="setrans_t"),
    FRule("allow", "staff_t", "etc_t", "file", ["read"]),
]
CONSTRAINTS = [
    FConstraint("mlsconstrain", "file", ["open", "create"], Expr("( h1 dom h2 ) or ( t1 != mcs_constrained_type )", NOT_MCS)),
    FConstraint("mlsconstrain", "process", ["transition", "signal"], Expr("( h1 dom h2 ) or ( t1 != mcs_constrained_type )", NOT_MCS)),
    FConstraint("mlsconstrain", "shm", ["write"], Expr("( h1 dom h2 ) or ( t1 != mcs_constrained_type )", NOT_MCS)),
    FConstraint("mlsconstrain", "dir", ["read"], Expr("h1 dom h2", ["h1", "h2", "dom"])),
    FConstraint("mlsconstrain", "file", ["write"], Expr("( l1 eq l2 ) or ( t1 == mlsfilewrite )", ["l1", "l2", "==", "t1", frozenset(["mlsfilewrite"]), "==", "or"])),
    FConstraint("mlsconstrain", "msg", ["send"], Expr("( l1 dom l2 ) or ( t2 == mlstrustedobject )", ["l1", "l2", "dom", "t2", frozenset(["mlstrustedobject"]), "==", "or"])),
    FConstraint("constrain", "file", ["read"], Expr("( u1 == u2 ) or ( t1 == init_t )", ["u1", "u2", "==", "t1", frozenset(["init_t"]), "==", "or"])),
]
PERMMAP = {("file", "read"): ("r", 10), ("file", "write"): ("w", 10), ("file", "append"): ("w", 10), ("file", "open"): ("r", 1), ("file", "create"): ("w", 1),
           ("file", "execute"): ("r", 10), ("dir", "search"): ("r", 10), ("dir", "read"): ("r", 10), ("unix_stream_socket", "connectto"): ("w", 1),
           ("unix_stream_socket", "read"): ("r", 10), ("unix_stream_socket", "write"): ("w", 10), ("shm", "read"): ("r", 10), ("shm", "write"): ("w", 10),
           ("process", "transition"): ("w", 5), ("process", "signal"): ("w", 1)}


class SELinuxPolicy(object):
    mls = True

    def __init__(self, path):
        self.path = path

    def types(self):
        return TYPES

    def roles(self):
        return [FRole("system_r", ["init_t", "container_t", "svirt_t", "setrans_t"]), FRole("staff_r", ["staff_t"]), FRole("object_r", [])]

    def users(self):
        return [FUser("system_u", ["system_r", "object_r"], "s0-s0:c0.c1023"), FUser("staff_u", ["staff_r"], "s0-s0:c0.c1023"), FUser("user_u", ["staff_r"], "s0")]

    def lookup_user(self, u):
        return [x for x in self.users() if x.name == u][0]

    def classes(self):
        return CLASSES

    def terules(self):
        return RULES

    def bools(self):
        return [FBool("some_bool", False)]

    def constraints(self):
        return CONSTRAINTS

    def mlsrules(self):
        return [FMLSRule("init_t", "setrans_exec_t", "process", "s0 - s0:c0.c1023")]

    def sensitivities(self):
        return [Named("s0")]

    def categories(self):
        return [Named("c%d" % i) for i in range(1024)]

    def lookup_range(self, text):
        return Range(text)


class Perm(object):
    def __init__(self, perm, direction, weight):
        self.perm, self.direction, self.weight, self.enabled = perm, direction, weight, True


class PermissionMap(object):
    def classes(self):
        return sorted(set(c for c, _ in PERMMAP))

    def perms(self, c):
        return [Perm(p, d, w) for (cc, p), (d, w) in sorted(PERMMAP.items()) if cc == c]


fake = types.ModuleType("setools")
fake.SELinuxPolicy, fake.PermissionMap = SELinuxPolicy, PermissionMap
fake.exception = types.SimpleNamespace(NoCommon=NoCommon, RuleUseError=RuleUseError, RuleNotConditional=RuleNotConditional)
sys.modules["setools"] = fake
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "server"))
import policy_query  # noqa: E402

fd, path = tempfile.mkstemp(suffix=".bin")
os.close(fd)
idx = policy_query.Index(path)

# ---------- index basics ----------
check(idx.domains == {"init_t", "container_t", "svirt_t", "staff_t", "setrans_t"}, "domains = types with the domain attribute", sorted(idx.domains))
check(idx.names(["mcs_constrained_type"]) == {"container_t", "svirt_t"} and idx.names(["etc_alias_t"]) == {"etc_t"}, "names(): attributes expand, aliases resolve")
try:
    idx.names(["nosuch_t"])
    check(False, "an unknown name raises KeyError")
except KeyError:
    check(True, "an unknown name raises KeyError")

# ---------- who ignores levels ----------
L = idx.levels()
groups = {tuple(g["domains"]): g for g in L["groups"]}
check(L["mls"] and L["kind"] == "mcs" and L["sensitivities"] == 1 and L["categories"] == 1024 and len(L["constraints"]) == 6,
      "levels(): an MCS policy, the 6 mlsconstrain statements (not the plain constrain)", (L["kind"], len(L["constraints"])))
check(("container_t", "svirt_t") in groups and groups[("container_t", "svirt_t")]["constraints"] == [], "domains in mcs_constrained_type are held to every constraint", list(groups))
gi = groups.get(("init_t",))
check(gi and len(gi["constraints"]) == 4 and gi["via"] == ["in mlsfilewrite", "not in mcs_constrained_type"] and gi["classes"]["file"] == ["create", "open", "write"],
      "init_t: 4 constraints, because of both forms (not in mcs_constrained_type; in mlsfilewrite)", gi)
gs = groups.get(("setrans_t", "staff_t"))
check(gs and len(gs["constraints"]) == 3 and gs["via"] == ["not in mcs_constrained_type"], "domains outside the attribute pass the 3 upstream-style constraints", gs)
check(L["groups"][0]["domains"] == ["init_t"] and L["groups"][-1]["constraints"] == [], "groups sorted, most bypassed first")
check(L["targetTerms"] == [{"term": "in mlstrustedobject", "constraints": 1, "types": 1}], "terms on the object's type are listed", L["targetTerms"])
v, why = idx.eval_levels(["h1", "h2", "dom", "t1", MCS, "!=", "or", "not"], "init_t")
check(v is False and why == [], "not: inverts a known value")
check(idx.eval_levels(["h1", "h2", "dom"], "init_t") == (None, []), "a level comparison alone: unknown")

# ---------- checks ----------
res = {c["id"]: c for c in (dict(id=c["id"], **idx.check(c)) for c in [
    {"id": 1, "kind": "never-levels", "sources": ["container_t", "svirt_t"]},
    {"id": 2, "kind": "never-levels", "sources": ["init_t"]},
    {"id": 3, "kind": "only-levels", "sources": ["init_t"]},
    {"id": 4, "kind": "never-levels", "sources": ["init_t"], "classes": ["dir"]},
    {"id": 5, "kind": "never-levels", "sources": ["init_t"], "classes": ["nosuch"]},
    {"id": 6, "kind": "never-levels", "sources": ["nosuch_t"]},
    {"id": 7, "kind": "require-isolated", "sources": ["container_t"]},
    {"id": 8, "kind": "require-isolated", "sources": ["container_t"], "classes": ["process"]},
    {"id": 9, "kind": "require-isolated", "sources": ["etc_t"]},
])}
check(res[1]["ok"] and not res[2]["ok"] and res[2]["levels"][0]["via"] == ["in mlsfilewrite", "not in mcs_constrained_type"], "never ... may ignore levels: holds for held domains, fails for init_t with why")
check(not res[3]["ok"] and res[3]["count"] == 2 and sorted(d for g in res[3]["levels"] for d in g["domains"]) == ["setrans_t", "staff_t"], "only init_t may ignore levels: the others are reported", res[3])
check(res[4]["ok"], "on dir: init_t is held to the dir constraint (no exemption there)")
check(not res[5]["ok"] and "no level constraint covers nosuch" in res[5]["error"] and "unknown type or attribute nosuch_t" in res[6]["error"], "errors: a class no constraint covers, an unknown type")
check(not res[7]["ok"] and res[7]["count"] == 1 and res[7]["isolation"][0]["domain"] == "container_t", "require container_t isolated by levels: fails", res[7])
check(res[8]["ok"], "isolated on process only: holds (no process access is unchecked)")
check(not res[9]["ok"] and "none of these is a domain" in res[9]["error"], "isolated for a non-domain: error")

# ---------- isolation ----------
iso = idx.isolation({"container_t"})[0]
items = {(u["target"], u["class"]): u for u in iso["unchecked"]}
check(iso["binds"] == 6 and iso["constraints"] == 6 and iso["scope"] == "own", "container_t is bound by all 6 level constraints", iso)
check(set(items) == {("container_file_t", "file"), ("container_file_t", "dir"), ("container_t", "shm"), ("container_t", "unix_stream_socket")},
      "own objects only (its type and types it creates); etc_t left out", sorted(items))
check(items[("container_file_t", "file")]["perms"] == ["read"] and items[("container_file_t", "file")]["fdOnly"], "file read unchecked (write is covered by the mlsfilewrite constraint), but opening is checked: fdOnly", items[("container_file_t", "file")])
check(items[("container_file_t", "dir")]["perms"] == ["search"], "dir: search unchecked (read is covered)")
check(items[("container_t", "shm")]["perms"] == ["read"] and not items[("container_t", "shm")]["fdOnly"], "shm: read unchecked (write covered); shm has no open, so not fdOnly")
check(items[("container_t", "unix_stream_socket")]["perms"] == ["connectto"], "sockets: only connectto counts (its own socket read/write isn't shared), whatever its weight")
check(iso["unchecked"][-1]["fdOnly"] and iso["open"] == 3, "fd-only accesses sort last; open counts the others", [u["fdOnly"] for u in iso["unchecked"]])
alls = {(u["target"], u["class"]) for u in idx.isolation({"container_t"}, scope="all")[0]["unchecked"]}
check(("etc_t", "file") in alls and ("container_t", "unix_stream_socket") in alls, "scope all: every target, sockets with all their permissions")
check(idx.isolation({"init_t"})[0]["binds"] == 2, "init_t: bound by the 2 constraints it has no exemption for")

# ---------- range transitions ----------
out = {t["target"]: t for t in idx.transitions("init_t", "out")}
check(out["setrans_t"]["ranges"] == [{"entry": "setrans_exec_t", "range": "s0-s0:c0.c1023"}] and out["container_t"]["ranges"] == [] and out["setrans_t"]["auto"] == ["setrans_exec_t"],
      "transitions carry range_transition ranges per entrypoint", out)
fi = idx.fileinfo("setrans_exec_t")
check(fi["entrypointOf"][0]["from"][0]["range"] == "s0-s0:c0.c1023", "fileinfo: the range a program starts at", fi["entrypointOf"])

# ---------- context check ----------
c = idx.context_check("system_u:system_r:container_t:s0:c1,c2", "system_u:object_r:container_file_t:s0:c1,c3", "file", ["read", "open"], {})
failing = [x for x in c["constraints"] if not x["ok"]]
check(c["problems"] == [] and c["te"]["read"]["status"] == "allowed" and c["te"]["open"]["status"] == "allowed", "two containers: the type rules allow it", c["te"])
check(len(failing) == 1 and failing[0]["perms"] == ["open"] and any(l["text"] == "h1 dom h2" and not l["ok"] and l["a"] == "s0:c1.c2" and l["b"] == "s0:c1,c3" for l in failing[0]["leaves"]),
      "...but h1 dom h2 fails for open, with the values", failing)
check(any(x["kind"] == "constrain" and x["ok"] for x in c["constraints"]) and c["levels"]["user"] == "s0 - s0:c0.c1023", "plain constraints are evaluated too; the user's range is reported")
c = idx.context_check("system_u:system_r:container_t:s0:c1,c2", "system_u:object_r:container_file_t:s0:c1,c2", "file", ["read", "open"], {})
check(not [x for x in c["constraints"] if not x["ok"]], "same categories: every constraint holds")
c = idx.context_check("user_u:sysadm_r:staff_t:s0:c5", "system_u:object_r:etc_t", "file", ["read"], {})
kinds = sorted(p["kind"] for p in c["problems"])
check(kinds == ["level", "range", "role", "role"], "invalid source: role not the user's, unknown role, level outside the range; missing target level assumed", c["problems"])
c = idx.context_check("staff_u:staff_r:staff_t:s0", "staff_u:object_r:etc_alias_t:s0", "file", ["read"], {})
check(c["te"]["read"]["status"] == "allowed" and any(x["kind"] == "constrain" and x["ok"] for x in c["constraints"]), "aliases resolve in contexts")
check("is not a permission of file" in idx.context_check("a:b:staff_t:s0", "a:b:etc_t:s0", "file", ["fly"], {})["error"]
      and "is not a class" in idx.context_check("a:b:staff_t:s0", "a:b:etc_t:s0", "nosuch", ["read"], {})["error"]
      and "is not a type" in idx.context_check("a:b:nosuch_t:s0", "a:b:etc_t:s0", "file", ["read"], {})["error"]
      and "user:role:type" in idx.context_check("a:b", "a:b:etc_t:s0", "file", ["read"], {})["error"]
      and "Not a valid level" in idx.context_check("a:b:staff_t:s9", "a:b:etc_t:s0", "file", ["read"], {})["error"], "errors: permission, class, type, malformed, level")

os.remove(path)
print("\n%d check(s) failed" % failures if failures else "\nall policy_query checks passed")
sys.exit(1 if failures else 0)
