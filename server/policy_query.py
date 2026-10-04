#!/usr/bin/env python3
"""Long-running setools helper: answers rule queries on a compiled policy.

Reads one JSON request per line on stdin, writes one JSON response per line:
  {"id": 1, "op": "rules", "bin": "/path/policy.bin", "name": "syslogd_t",
   "dir": "source" | "target", "kinds": ["allow", ...]}
  -> {"id": 1, "rules": [{"rt", "s", "t", "c", "perms", "cond"}], "via": [...attrs]}

The policy is indexed once (rules bucketed by source and target name, each
type's attributes) and re-indexed when the file changes, so a query is a
dictionary lookup instead of a scan of every rule.
"""
import json
import os
import sys

import setools


class Index:
    def __init__(self, path):
        self.path = path
        self.mtime = os.stat(path).st_mtime
        p = setools.SELinuxPolicy(path)
        self.attrs = {str(t): [str(a) for a in t.attributes()] for t in p.types()}
        self.members = {}
        for t, attrs in self.attrs.items():
            for a in attrs:
                self.members.setdefault(a, []).append(t)
        self.domains = {t for t, attrs in self.attrs.items() if "domain" in attrs}
        self.aliases = {str(a): str(t) for t in p.types() for a in t.aliases()}
        self.classperms = {}
        for c in p.classes():
            perms = {str(x) for x in c.perms}
            try:
                perms |= {str(x) for x in c.common.perms}
            except setools.exception.NoCommon:
                pass
            self.classperms[str(c)] = perms
        self.rules = []
        self.by_src, self.by_tgt = {}, {}
        for r in p.terules():
            try:
                cond = "%s:%s" % (r.conditional, str(r.conditional_block).lower())
            except setools.exception.RuleNotConditional:
                cond = ""
            try:
                perms = sorted(str(x) for x in r.perms)
            except setools.exception.RuleUseError:
                perms = [str(r.default)]
            rule = {"rt": str(r.ruletype), "s": str(r.source), "t": str(r.target), "c": str(r.tclass), "perms": perms, "cond": cond}
            i = len(self.rules)
            self.rules.append(rule)
            self.by_src.setdefault(rule["s"], []).append(i)
            self.by_tgt.setdefault(rule["t"], []).append(i)

    # ----- domain transitions (what setools' DomainTransitionAnalysis checks, without networkx) -----

    def expand(self, name):
        """Types an attribute stands for (a type stands for itself)."""
        return self.members.get(name, [name])

    def with_perm(self, names, bucket, cls, perm, rt="allow"):
        for n in names:
            for i in bucket.get(n, ()):
                r = self.rules[i]
                if r["rt"] == rt and r["c"] == cls and perm in r["perms"]:
                    yield r

    def side_types(self, r, field, subject):
        return [subject] if r[field] == "self" else self.expand(r[field])

    def exec_types(self, s):
        sn = [s] + self.attrs.get(s, [])
        out = set()
        for r in self.with_perm(sn, self.by_src, "file", "execute"):
            out.update(self.side_types(r, "t", s))
        return out

    def entrypoints(self, t):
        tn = [t] + self.attrs.get(t, [])
        out = set()
        for r in self.with_perm(tn, self.by_src, "file", "entrypoint"):
            out.update(self.side_types(r, "t", t))
        return out

    def auto_entries(self, s, t):
        """Entrypoint types for which type_transition s E:process t exists."""
        sn = [s] + self.attrs.get(s, [])
        out = set()
        for n in sn:
            for i in self.by_src.get(n, ()):
                r = self.rules[i]
                if r["rt"] == "type_transition" and r["c"] == "process" and r["perms"] and r["perms"][0] == t:
                    out.update(self.side_types(r, "t", s))
        return out

    def can(self, s, perm, target_self=True):
        sn = [s] + self.attrs.get(s, [])
        return any(r["t"] in ("self", s) or s in self.expand(r["t"]) for r in self.with_perm(sn, self.by_src, "process", perm))

    def transition(self, s, t, rules):
        eps = self.entrypoints(t) & self.exec_types(s)
        auto = self.auto_entries(s, t) & eps
        return {"source": s, "target": t, "entrypoints": sorted(eps), "auto": sorted(auto),
                "setexec": self.can(s, "setexec"), "conditional": sorted({r["cond"] for r in rules if r["cond"]})}

    def transitions(self, name, direction):
        if name not in self.attrs:
            return []
        out = []
        if direction == "out":
            targets = {}
            sn = [name] + self.attrs.get(name, [])
            for r in self.with_perm(sn, self.by_src, "process", "transition"):
                for t in self.side_types(r, "t", name):
                    if t != name and t in self.attrs:
                        targets.setdefault(t, []).append(r)
            dyn = {}
            for r in self.with_perm(sn, self.by_src, "process", "dyntransition"):
                for t in self.side_types(r, "t", name):
                    if t != name:
                        dyn.setdefault(t, []).append(r)
            for t in sorted(set(targets) | set(dyn)):
                tr = self.transition(name, t, targets.get(t, []))
                tr["dynamic"] = t in dyn and self.can(name, "setcurrent")
                if tr["entrypoints"] or tr["dynamic"]:
                    out.append(tr)
        else:
            sources = {}
            tn = [name] + self.attrs.get(name, [])
            for r in self.with_perm(tn, self.by_tgt, "process", "transition"):
                for s in self.expand(r["s"]):
                    if s != name and s in self.attrs:
                        sources.setdefault(s, []).append(r)
            for s in sorted(sources):
                tr = self.transition(s, name, sources[s])
                tr["dynamic"] = False
                if tr["entrypoints"]:
                    out.append(tr)
        return out

    # ----- property checks -----

    def names(self, items):
        """Types for a list of type/attribute names ('*' = every domain); unknown names raise."""
        out = set()
        for n in items:
            n = self.aliases.get(n, n)
            if n == "*":
                out |= self.domains
            elif n in self.members:
                out.update(self.members[n])
            elif n in self.attrs:
                out.add(n)
            else:
                raise KeyError(n)
        return out

    def granting(self, t, classes, perms):
        """allow rules that grant any of `perms` ('*' = any) on type t in `classes`: (rule, sources, perms)."""
        tn = [t] + self.attrs.get(t, [])
        seen = set()
        for n in tn + ["self"]:
            for i in self.by_tgt.get(n, ()):
                if i in seen:
                    continue
                seen.add(i)
                r = self.rules[i]
                if r["rt"] != "allow" or (classes and r["c"] not in classes):
                    continue
                hit = r["perms"] if perms == "*" else [p for p in r["perms"] if p in perms]
                if not hit:
                    continue
                if r["t"] == "self":
                    srcs = {t} if t in self.expand(r["s"]) else set()
                else:
                    srcs = set(self.expand(r["s"]))
                if srcs:
                    yield r, srcs, hit

    def transition_path(self, sources, targets, limit=8):
        """Shortest domain-transition path from any source to any target (BFS), or None."""
        prev = {s: None for s in sources}
        frontier = list(sources)
        for _ in range(limit):
            nxt = []
            for s in frontier:
                for tr in self.transitions(s, "out"):
                    t = tr["target"]
                    if t in prev:
                        continue
                    prev[t] = (s, tr)
                    if t in targets:
                        steps = []
                        while prev[t] is not None:
                            s0, tr0 = prev[t]
                            steps.append({"from": s0, "to": t, "entrypoints": tr0["entrypoints"][:3], "auto": bool(tr0["auto"]),
                                          "conditional": tr0["conditional"]})
                            t = s0
                        return list(reversed(steps))
                    nxt.append(t)
            frontier = nxt
            if not frontier:
                break
        return None

    def check(self, c):
        try:
            kind = c["kind"]
            if kind == "reaches":
                srcs, tgts = self.names(c["sources"]), self.names(c["targets"])
                p = self.transition_path(srcs, tgts)
                return {"ok": p is None, "path": p}
            tgts = self.names(c["targets"])
            perms = c["perms"]
            classes = set(c.get("classes") or [])
            if kind in ("only", "never"):
                who = self.names(c["sources"])
                bad = {}
                for t in sorted(tgts):
                    for r, srcs, hit in self.granting(t, classes, perms):
                        violators = (srcs - who) if kind == "only" else (srcs & who)
                        if violators:
                            k = id(r)
                            v = bad.setdefault(k, {"rule": r, "target": t, "perms": hit, "sources": set()})
                            v["sources"] |= violators
                out = [{"rule": v["rule"], "target": v["target"], "perms": v["perms"], "sources": sorted(v["sources"])} for v in bad.values()]
                out.sort(key=lambda v: (-len(v["sources"]), v["rule"]["s"], v["target"]))
                return {"ok": not out, "violations": out[:200], "count": len(out),
                        "domains": len(set().union(*[set(v["sources"]) for v in out])) if out else 0}
            if kind == "require":
                srcs = self.names(c["sources"])
                missing = []
                for s in sorted(srcs):
                    for t in sorted(tgts):
                        for cl in sorted(classes or {"file"}):
                            have = set()
                            for r, rs, hit in self.granting(t, {cl}, perms):
                                if s in rs:
                                    have.update(hit)
                            # A permission group only asks for what the class has (no add_name on files).
                            wanted = set(perms) & self.classperms.get(cl, set(perms)) if perms != "*" else None
                            lack = sorted(wanted - have) if wanted is not None else ([] if have else ["*"])
                            if lack:
                                missing.append({"source": s, "target": t, "class": cl, "missing": lack})
                return {"ok": not missing, "missing": missing[:200], "count": len(missing)}
            return {"ok": False, "error": "unknown check kind %s" % kind}
        except KeyError as e:
            return {"ok": False, "error": "unknown type or attribute %s in the compiled policy" % e.args[0]}

    def query(self, name, direction, kinds):
        # A type matches rules written for it or for any attribute it has.
        names = [name] + self.attrs.get(name, [])
        bucket = self.by_src if direction == "source" else self.by_tgt
        hits = set()
        for n in names:
            hits.update(bucket.get(n, ()))
        if direction == "target":
            # `allow X self:...` targets every type in X.
            for n in names:
                hits.update(i for i in self.by_src.get(n, ()) if self.rules[i]["t"] == "self")
        out = [self.rules[i] for i in sorted(hits) if not kinds or self.rules[i]["rt"] in kinds]
        return out, names[1:]


def main():
    idx = None
    for line in sys.stdin:
        try:
            req = json.loads(line)
        except ValueError:
            continue
        resp = {"id": req.get("id")}
        try:
            path = req["bin"]
            if idx is None or idx.path != path or idx.mtime != os.stat(path).st_mtime:
                idx = Index(path)
            if req.get("op") == "rules":
                rules, via = idx.query(req["name"], req.get("dir", "source"), req.get("kinds") or [])
                resp.update(rules=rules, via=via, count=len(rules))
            elif req.get("op") == "transitions":
                resp.update(transitions=idx.transitions(req["name"], req.get("dir", "out")))
            elif req.get("op") == "check":
                resp.update(results=[dict(id=c.get("id"), **idx.check(c)) for c in req.get("checks", [])])
            else:
                resp["error"] = "unknown op"
        except Exception as e:  # report and keep serving
            resp["error"] = "%s: %s" % (type(e).__name__, e)
        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
