#!/usr/bin/env python3
"""Long-running setools helper: answers rule queries on a compiled policy.

Reads one JSON request per line on stdin, writes one JSON response per line:
  {"id": 1, "op": "rules", "bin": "/path/policy.bin", "name": "syslogd_t",
   "dir": "source" | "target", "kinds": ["allow", ...]}
  -> {"id": 1, "rules": [{"rt", "s", "t", "c", "perms", "cond"}], "via": [...attrs]}
Other ops: "transitions", "check" (property checks) and "avc" (is each denied
permission allowed, allowed under other boolean settings, or missing).

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
        self.policy = p
        self.attrs = {str(t): [str(a) for a in t.attributes()] for t in p.types()}
        self.members = {}
        for t, attrs in self.attrs.items():
            for a in attrs:
                self.members.setdefault(a, []).append(t)
        self.domains = {t for t, attrs in self.attrs.items() if "domain" in attrs}
        self.aliases = {str(a): str(t) for t in p.types() for a in t.aliases()}
        self.role_types = {str(r): {str(t) for t in r.types()} for r in p.roles()}
        self.user_roles = {str(u): {str(r) for r in u.roles} for u in p.users()}
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
        self._pmap, self._rflow = None, {}
        self.conds = {}  # rule index -> (ConditionalExpr, block): the rule is active when expr == block
        self.bool_defaults = {str(b): bool(b.state) for b in p.bools()}
        self.permissive = {str(t) for t in p.types() if t.ispermissive}
        for r in p.terules():
            try:
                cond = "%s:%s" % (r.conditional, str(r.conditional_block).lower())
                self.conds[len(self.rules)] = (r.conditional, bool(r.conditional_block))
            except setools.exception.RuleNotConditional:
                cond = ""
            try:
                perms = sorted(str(x) for x in r.perms)
            except setools.exception.RuleUseError:
                perms = [str(r.default)]
            rule = {"rt": str(r.ruletype), "s": str(r.source), "t": str(r.target), "c": str(r.tclass), "perms": perms, "cond": cond}
            try:
                rule["name"] = str(r.filename)  # named type_transition
            except Exception:  # not a named transition
                pass
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

    def range_rules(self):
        """range_transition rules for processes: [(source, target, range text)] (names as written)."""
        if getattr(self, "_rr", None) is None:
            out = []
            if self.policy.mls:
                for r in self.policy.mlsrules():
                    try:
                        if str(r.tclass) == "process":
                            out.append((str(r.source), str(r.target), str(r.default).replace(" - ", "-")))
                    except Exception:
                        pass
            self._rr = out
        return self._rr

    def ranges_for(self, s, entries):
        """The ranges range_transition gives s running each of the entrypoint types: [{entry, range}]."""
        if not entries or not self.range_rules():
            return []
        sn = set([s] + self.attrs.get(s, []))
        out = []
        for e in sorted(entries):
            en = set([e] + self.attrs.get(e, []))
            for rs, rt, rng in self.range_rules():
                if rs in sn and rt in en:
                    out.append({"entry": e, "range": rng})
                    break
        return out

    def transition(self, s, t, rules):
        eps = self.entrypoints(t) & self.exec_types(s)
        auto = self.auto_entries(s, t) & eps
        return {"source": s, "target": t, "entrypoints": sorted(eps), "auto": sorted(auto),
                "setexec": self.can(s, "setexec"), "conditional": sorted({r["cond"] for r in rules if r["cond"]}),
                "ranges": self.ranges_for(s, eps)}

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

    # ----- what a login can reach (logins view) -----

    def rbac(self):
        """role allow (R → roles it may change to) and role_transition ((R, exec type) → R2) for processes."""
        if not hasattr(self, "_role_allow"):
            self._role_allow, self._role_trans = {}, {}
            for r in setools.RBACRuleQuery(self.policy, ruletype=["allow"]).results():
                self._role_allow.setdefault(str(r.source), set()).add(str(r.target))
            for r in setools.RBACRuleQuery(self.policy, ruletype=["role_transition"]).results():
                if str(r.tclass) == "process":
                    for t in self.expand(str(r.target)):
                        self._role_trans.setdefault((str(r.source), t), set()).add(str(r.default))
        return self._role_allow, self._role_trans

    def proc_ok(self, u, r1, t1, r2, t2, perm):
        """Whether the policy's (non-MLS) constraints let u:r1:t1 → u:r2:t2 for process `perm`."""
        if not hasattr(self, "_proc_cons"):
            self._proc_cons = {}
            for c in self.policy.constraints():
                if str(c.tclass) == "process" and hasattr(c, "perms") and not c.ruletype.name.startswith("mls"):
                    for x in c.perms:
                        self._proc_cons.setdefault(str(x), []).append(c.expression)
        vals = {"u1": u, "r1": r1, "t1": t1, "u2": u, "r2": r2, "t2": t2}
        return all(self.eval_constraint(e, vals, []) for e in self._proc_cons.get(perm, ()))

    def reach(self, user, starts, limit=12, roles=None, avoid=frozenset()):
        """What a session of `user` can reach: BFS over (role, domain) states from
        the start contexts. A domain transition s → t needs the transition rule
        and an entrypoint s may execute (or dyntransition + setcurrent); t must be
        in the role's types. The role changes to R2 (a role of the user that
        `allow R R2` permits and that may run t) by a role_transition on the
        entrypoint or, when s has setexec, explicitly (newrole, sudo -r); the
        policy's constraints must allow the change. Each reached domain keeps
        the step that first reached it."""
        # roles: the user's roles when the policy has no such user yet (one semanage will create).
        roles = set(roles) if roles else self.user_roles.get(user, set())
        ra, rt = self.rbac()
        reached, steps, seen, frontier = {}, {}, set(), []
        for s in starts:
            st = (s["role"], s["type"])
            if s["type"] in self.attrs and s["role"] in roles and st not in seen:
                seen.add(st)
                frontier.append(st)
                key = "%s:%s" % st
                steps[key] = {"depth": 0, "start": True, "role": s["role"], "type": s["type"]}
                reached.setdefault(s["type"], key)
        ep_cache, ex_cache, cand_cache = {}, {}, {}
        for depth in range(1, limit + 1):
            nxt = []
            for role, s in frontier:
                if s not in cand_cache:
                    sn = [s] + self.attrs.get(s, [])
                    cand = {}
                    for r in self.with_perm(sn, self.by_src, "process", "transition"):
                        for t in self.side_types(r, "t", s):
                            if t != s and t in self.domains:
                                cand.setdefault(t, []).append(r)
                    dyn = set()
                    if self.can(s, "setcurrent"):
                        for r in self.with_perm(sn, self.by_src, "process", "dyntransition"):
                            dyn.update(t for t in self.side_types(r, "t", s) if t != s and t in self.domains)
                    cand_cache[s] = (cand, dyn, self.can(s, "setexec"))
                cand, dyn, setexec = cand_cache[s]
                for t in sorted(set(cand) | dyn):
                    if t in avoid:  # paths through these don't count (a wrapper that is the allowed way in)
                        continue
                    # Deterministic (a set's order changes between runs): the same role, the role named
                    # like the domain (sysadm_r for sysadm_t), then by name.
                    order = sorted(roles, key=lambda r2: (r2 != role, r2[:-2] != t[:-2], r2))
                    targets = [r2 for r2 in order if t in self.role_types.get(r2, ()) and (r2 == role or r2 in ra.get(role, ()))]
                    targets = [r2 for r2 in targets if (r2, t) not in seen]
                    if not targets:
                        continue
                    if t not in ep_cache:
                        ep_cache[t] = self.entrypoints(t)
                    if s not in ex_cache:
                        ex_cache[s] = self.exec_types(s)
                    eps = ep_cache[t] & ex_cache[s]
                    if not eps and t not in dyn:
                        continue
                    auto_roles = set()
                    for e in eps:
                        auto_roles |= rt.get((role, e), set())
                    for r2 in targets:
                        how = None
                        if r2 != role:
                            if r2 in auto_roles:
                                how = "role_transition"
                            elif setexec and eps:
                                how = "setexec"
                            else:
                                continue
                        perm = "transition" if eps else "dyntransition"
                        if not self.proc_ok(user, role, s, r2, t, perm):
                            continue
                        seen.add((r2, t))
                        nxt.append((r2, t))
                        conds = sorted({r["cond"] for r in cand.get(t, []) if r["cond"]})
                        if any(not r["cond"] for r in cand.get(t, [])):
                            conds = []
                        key = "%s:%s" % (r2, t)
                        steps[key] = {"depth": depth, "from": "%s:%s" % (role, s), "role": r2, "type": t, "roleChange": how,
                                      "entrypoints": sorted(eps)[:3], "dynamic": not eps, "conditional": conds}
                        reached.setdefault(t, key)
            frontier = nxt
            if not frontier:
                break
        return {"roles": sorted({r for r, _ in seen}), "reached": reached, "steps": steps}

    def reach_access(self, domains, t, classes, perms):
        """Of `domains`, which may access type t ({domain: [rule, perms]}, one rule each)."""
        t = self.aliases.get(t, t)
        if t not in self.attrs:
            raise KeyError(t)
        out = {}
        for r, srcs, hit in self.granting(t, classes, perms):
            for d in srcs & domains:
                if d not in out or (out[d][0]["cond"] and not r["cond"]):
                    out[d] = (r, hit)
        return {d: {"rule": r, "perms": hit} for d, (r, hit) in out.items()}

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

    def transition_path(self, sources, targets, limit=8, avoid=frozenset()):
        """Shortest domain-transition path from any source to any target (BFS), or None.
        Paths through `avoid` (e.g. the wrapper that is the only allowed way in) don't count."""
        prev = {s: None for s in sources}
        for a in avoid:
            prev.setdefault(a, None)
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

    # ----- information flow (setools' permission map: each permission reads, writes, both or neither) -----

    def permmap(self):
        if self._pmap is None:
            pm = setools.PermissionMap()
            self._pmap = {(str(c), x.perm): (x.direction, x.weight if x.enabled else 0) for c in pm.classes() for x in pm.perms(c)}
        return self._pmap

    def rule_flow(self, i):
        """Strongest read and write weights among an allow rule's permissions."""
        f = self._rflow.get(i)
        if f is None:
            r, pm, rd, wr = self.rules[i], self.permmap(), 0, 0
            for p in r["perms"]:
                d, w = pm.get((r["c"], p), ("n", 0))
                if d in ("r", "b"):
                    rd = max(rd, w)
                if d in ("w", "b"):
                    wr = max(wr, w)
            f = self._rflow[i] = (rd, wr)
        return f

    def flow_perms(self, i, d, min_weight):
        """The permissions of rule i that carry information in direction d ('r'/'w') at min_weight or more."""
        r, pm = self.rules[i], self.permmap()
        want = ("r", "b") if d == "r" else ("w", "b")
        out = []
        for p in r["perms"]:
            direction, weight = pm.get((r["c"], p), ("n", 0))
            if direction in want and weight >= min_weight:
                out.append(p)
        return out

    def flow_path(self, sources, targets, min_weight=10, exclude=frozenset()):
        """Shortest information-flow path from any source type to any target type, or None.

        A domain reads from the target of a rule granting a read-like permission
        (data flows target -> domain) and writes to it with a write-like one
        (domain -> target). Each rule is expanded once per direction: later
        visits through it would only reach types already seen.
        """
        prev = {s: None for s in sources}
        used = set()
        frontier = sorted(sources)
        while frontier:
            nxt = []
            for x in frontier:
                for n in [x] + self.attrs.get(x, []):
                    for d, bucket in (("w", self.by_src), ("r", self.by_tgt)):
                        for i in bucket.get(n, ()):
                            r = self.rules[i]
                            if r["rt"] != "allow" or r["t"] == "self" or (i, d) in used:
                                continue
                            if self.rule_flow(i)[0 if d == "r" else 1] < min_weight:
                                continue
                            used.add((i, d))
                            for y in self.expand(r["t"] if d == "w" else r["s"]):
                                if y in prev or y in exclude:
                                    continue
                                prev[y] = (x, i, d)
                                if y in targets:
                                    steps = []
                                    while prev[y] is not None:
                                        x0, i0, d0 = prev[y]
                                        steps.append({"from": x0, "to": y, "rule": self.rules[i0], "perms": self.flow_perms(i0, d0, min_weight),
                                                      "dir": "write" if d0 == "w" else "read"})
                                        y = x0
                                    return list(reversed(steps))
                                nxt.append(y)
            frontier = nxt
        return None

    def check_rbac(self, kind, sources, targets):
        """only|never <roles> may run <types> / only|never <users> may use <roles>."""
        mode, what = kind.split("-")
        if what == "run":
            holders, known = self.role_types, set(self.role_types)
            want = self.names(targets)          # types (attributes expanded)
        else:
            holders, known = self.user_roles, set(self.user_roles)
            want = set(targets)
            bad = [t for t in want if t not in self.role_types]
            if bad:
                raise KeyError(bad[0])
        unknown = [s for s in sources if s not in known]
        if unknown:
            raise KeyError(unknown[0])
        who = set(sources)
        violations = []
        for holder, items in sorted(holders.items()):
            hit = sorted(items & want)
            if not hit:
                continue
            if (mode == "only" and holder not in who) or (mode == "never" and holder in who):
                violations.append({"holder": holder, "items": hit})
        return {"ok": not violations, "rbac": violations[:200], "count": len(violations)}

    def check(self, c):
        try:
            kind = c["kind"]
            if kind.endswith("-run") or kind.endswith("-use"):
                return self.check_rbac(kind, c["sources"], c["targets"])
            if kind in ("only-levels", "never-levels"):
                return self.check_levels(kind, c["sources"], set(c.get("classes") or []))
            if kind == "require-isolated":
                if not self.policy.mls:
                    return {"ok": False, "error": "this policy has no levels (built without MLS or MCS)"}
                doms = self.names(c["sources"]) & self.domains
                if not doms:
                    return {"ok": False, "error": "none of these is a domain"}
                res = [x for x in self.isolation(doms, c.get("weight") or 10, set(c.get("classes") or []) or None, limit=8) if x["count"]]
                return {"ok": not res, "isolation": res[:20], "count": len(res)}
            if kind == "reaches":
                srcs, tgts = self.names(c["sources"]), self.names(c["targets"])
                p = self.transition_path(srcs, tgts, avoid=frozenset(self.names(c.get("through") or [])) - srcs - tgts)
                return {"ok": p is None, "path": p}
            if kind == "flows":
                srcs, tgts = self.names(c["sources"]), self.names(c["targets"])
                exclude = self.names(c.get("except") or [])
                both = srcs & tgts
                if both:
                    return {"ok": False, "error": "%s is both a source and a target" % sorted(both)[0]}
                p = self.flow_path(srcs, tgts, c.get("weight") or 10, frozenset(exclude - srcs - tgts))
                return {"ok": p is None, "flow": p}
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

    # ----- denials: is an access allowed, and under which boolean settings -----

    def cond_active(self, i, states):
        expr, block = self.conds[i]
        vals = {str(b): states.get(str(b), self.bool_defaults.get(str(b), False)) for b in expr.booleans}
        return expr.evaluate(**vals) == block

    def cond_options(self, i, states):
        """Boolean settings (only the changed ones) that make conditional rule i active, fewest changes first."""
        expr, block = self.conds[i]
        names = sorted(str(b) for b in expr.booleans)
        cur = {b: states.get(b, self.bool_defaults.get(b, False)) for b in names}
        out = []
        if len(names) > 8:
            return out
        for mask in range(1 << len(names)):
            vals = {b: bool(mask >> k & 1) for k, b in enumerate(names)}
            if expr.evaluate(**vals) == block:
                out.append({b: v for b, v in vals.items() if v != cur[b]})
        out.sort(key=len)
        return out[:4]

    def avc(self, checks, states):
        """For each {s, t, c, perms}: per permission 'allowed' | 'boolean' (with the settings that allow it) | 'missing'."""
        out = []
        for ch in checks:
            s = self.aliases.get(ch["s"], ch["s"])
            t = self.aliases.get(ch["t"], ch["t"])
            cl, perms = ch["c"], ch["perms"]
            res = {"id": ch.get("id"), "permissiveDomain": s in self.permissive}
            unknown = [n for n in (s, t) if n not in self.attrs]
            if unknown:
                res["unknown"] = unknown
                out.append(res)
                continue
            if cl not in self.classperms:
                res["unknownClass"] = cl
                out.append(res)
                continue
            tn = set([t] + self.attrs[t])
            hits = {p: [] for p in perms}
            for n in [s] + self.attrs[s]:
                for i in self.by_src.get(n, ()):
                    r = self.rules[i]
                    if r["rt"] != "allow" or r["c"] != cl:
                        continue
                    if not (r["t"] in tn or (r["t"] == "self" and s == t)):
                        continue
                    for p in perms:
                        if p in r["perms"]:
                            hits[p].append(i)
            per = {}
            for p, idxs in hits.items():
                plain = [i for i in idxs if i not in self.conds]
                active = [i for i in idxs if i in self.conds and self.cond_active(i, states)]
                if plain or active:
                    per[p] = {"status": "allowed", "rules": [self.rules[i] for i in (plain + active)[:3]], "conditional": not plain}
                elif idxs:
                    # Settings from rules on the type itself first (httpd_can_network_relay for
                    # http_cache_port_t rather than httpd_can_network_connect for every port).
                    idxs = sorted(idxs, key=lambda i: (self.rules[i]["t"] not in (t, "self"), i))
                    opts = []
                    for i in idxs:
                        for o in self.cond_options(i, states):
                            if o and o not in opts:
                                opts.append(o)
                    per[p] = {"status": "boolean", "options": opts[:6], "rules": [self.rules[i] for i in idxs[:3]]}
                else:
                    per[p] = {"status": "missing"}
            res["perms"] = per
            out.append(res)
        return out

    # ----- constraints (constrain / mlsconstrain) on a denied access -----

    OPERANDS = {"u1", "u2", "u3", "r1", "r2", "r3", "t1", "t2", "t3", "l1", "l2", "h1", "h2"}

    def context_check(self, scontext, tcontext, cls, perms, states):
        """May a process with scontext do perms on an object with tcontext? The source context's
        validity (user → role → type, level within the user's range), the type rules (avc), and
        every constraint on those permissions with its comparisons."""
        p = self.policy
        problems = []
        s, t = scontext.strip().split(":"), tcontext.strip().split(":")
        for parts, what in ((s, "source"), (t, "target")):
            if len(parts) < 3:
                return {"error": "The %s context needs at least user:role:type (and a level, e.g. :s0:c1,c2)." % what}
        if p.mls:
            if len(s) == 3:
                s.append("s0")
                problems.append({"kind": "level", "text": "No level given for the source; s0 assumed."})
            if len(t) == 3:
                t.append("s0")
                problems.append({"kind": "level", "text": "No level given for the target; s0 assumed."})
        if cls not in self.classperms:
            return {"error": "%s is not a class in this policy." % cls}
        bad = [x for x in perms if x not in self.classperms[cls]]
        if bad:
            return {"error": "%s %s not a permission of %s." % (" ".join(bad), "is" if len(bad) == 1 else "are", cls)}
        st, tt = self.aliases.get(s[2], s[2]), self.aliases.get(t[2], t[2])
        s[2], t[2] = st, tt
        for n, what in ((st, "source"), (tt, "target")):
            if n not in self.attrs:
                return {"error": "%s (the %s type) is not a type in this policy." % (n, what)}
        u, r = s[0], s[1]
        if u not in self.user_roles:
            problems.append({"kind": "user", "text": "There is no SELinux user %s." % u})
        elif r not in self.user_roles[u]:
            problems.append({"kind": "role", "text": "%s may not use %s (its roles: %s)." % (u, r, " ".join(sorted(self.user_roles[u])))})
        if r not in self.role_types:
            problems.append({"kind": "role", "text": "There is no role %s." % r})
        elif r != "object_r" and st not in self.role_types[r]:
            problems.append({"kind": "role", "text": "%s isn't authorized for %s, so no process can run with that context." % (r, st)})
        levels = {}
        if p.mls:
            try:
                sr = p.lookup_range(":".join(s[3:]))
                tr = p.lookup_range(":".join(t[3:]))
                levels = {"source": {"low": str(sr.low), "high": str(sr.high)}, "target": {"low": str(tr.low), "high": str(tr.high)}}
                if u in self.user_roles:
                    ur = p.lookup_user(u).mls_range
                    levels["user"] = str(ur)
                    if not (sr.low >= ur.low and ur.high >= sr.high):
                        problems.append({"kind": "range", "text": "%s is outside %s's range %s, so no process of %s gets it." % (":".join(s[3:]), u, ur, u)})
            except Exception as e:
                return {"error": "Not a valid level or range for this policy: %s" % e}
        te = self.avc([{"s": st, "t": tt, "c": cls, "perms": list(perms)}], states)[0]
        cons = self.constraints(":".join(s), ":".join(t), cls, set(perms), everything=True)
        return {"problems": problems, "te": te.get("perms", {}), "permissiveDomain": te.get("permissiveDomain", False),
                "constraints": cons, "levels": levels, "mls": bool(p.mls)}

    def constraints(self, scontext, tcontext, cls, perms, everything=False):
        """The constraints for cls on any of perms that the two contexts fail, each with the
        comparisons it is made of (operands' values and whether each held). everything: the
        ones they pass too, each with ok."""
        p = self.policy
        def ctx(raw):
            parts = raw.split(":")
            out = {"u": parts[0], "r": parts[1], "t": parts[2], "low": None, "high": None}
            if len(parts) > 3 and p.mls:
                rng = p.lookup_range(":".join(parts[3:]))
                out["low"], out["high"] = rng.low, rng.high
            return out
        s, t = ctx(scontext), ctx(tcontext)
        vals = {"u1": s["u"], "r1": s["r"], "t1": s["t"], "l1": s["low"], "h1": s["high"],
                "u2": t["u"], "r2": t["r"], "t2": t["t"], "l2": t["low"], "h2": t["high"]}
        failing = []
        for c in p.constraints():
            if str(c.tclass) != cls or not hasattr(c, "perms"):
                continue
            hit = sorted(str(x) for x in c.perms if str(x) in perms)
            if not hit:
                continue
            if c.ruletype.name.startswith("mls") and not p.mls:
                continue
            leaves = []
            ok = self.eval_constraint(c.expression, vals, leaves)
            if not ok or everything:
                failing.append({"kind": str(c.ruletype), "perms": hit, "text": str(c.expression), "leaves": leaves, "ok": bool(ok)})
        return failing

    def eval_constraint(self, expr, vals, leaves):
        stack = []
        def show(v):
            return "{ %s }" % " ".join(sorted(v)[:6]) + (" …" if len(v) > 6 else "") if isinstance(v, set) else str(v)
        for tok in expr:
            if isinstance(tok, (set, frozenset)):
                stack.append(("set", {str(x) for x in tok}))
                continue
            s = str(tok)
            if s in self.OPERANDS:
                stack.append(("op", s))
            elif s in ("and", "or"):
                b, a = stack.pop(), stack.pop()
                stack.append(("bool", (a[1] and b[1]) if s == "and" else (a[1] or b[1])))
            elif s == "not":
                a = stack.pop()
                stack.append(("bool", not a[1]))
            else:
                b, a = stack.pop(), stack.pop()
                av = vals.get(a[1])
                if b[0] == "set":
                    names = b[1]
                    if a[1].startswith("t"):
                        member = av in names or any(x in names for x in self.attrs.get(av, []))
                    else:
                        member = av in names
                    res = member if s == "==" else not member
                    leaves.append({"text": "%s %s %s" % (a[1], s, show(names)), "ok": res, "a": str(av)})
                else:
                    bv = vals.get(b[1])
                    if av is None or bv is None:
                        res = True  # no levels in this policy or context
                    elif s == "==":
                        res = av == bv
                    elif s == "!=":
                        res = av != bv
                    elif s == "dom":
                        res = av >= bv
                    elif s == "domby":
                        res = av <= bv
                    elif s == "incomp":
                        res = bool(av ^ bv)
                    else:
                        res = True
                    leaves.append({"text": "%s %s %s" % (a[1], s, b[1]), "ok": res, "a": str(av), "b": str(bv)})
                stack.append(("bool", res))
        return stack[-1][1] if stack else True

    # ----- levels (MLS / MCS): which domains pass level constraints whatever the levels -----

    def level_constraints(self):
        """The policy's mlsconstrain statements: class, permissions, text and postfix expression."""
        if getattr(self, "_lc", None) is None:
            out = []
            if self.policy.mls:
                for c in self.policy.constraints():
                    if not c.ruletype.name.startswith("mls") or not hasattr(c, "perms"):
                        continue
                    out.append({"cls": str(c.tclass), "perms": sorted(str(x) for x in c.perms),
                                "text": str(c.expression), "expr": list(c.expression)})
            self._lc = out
        return self._lc

    @staticmethod
    def _set_text(names):
        names = sorted(names)
        return names[0] if len(names) == 1 else "{ %s }" % " ".join(names[:6]) + (" …" if len(names) > 6 else "")

    def eval_levels(self, expr, d):
        """Three-valued evaluation of a constraint for source domain d: the source type is known,
        everything else (levels, users, roles, the target) is not. Returns (True | False | None,
        the source-type terms that make it true)."""
        dn = set([d] + self.attrs.get(d, []))
        stack = []
        for tok in expr:
            if isinstance(tok, (set, frozenset)):
                stack.append(("set", {str(x) for x in tok}))
                continue
            s = str(tok)
            if s in self.OPERANDS:
                stack.append(("op", s))
            elif s in ("and", "or"):
                (bv, bw), (av, aw) = stack.pop()[1], stack.pop()[1]
                if s == "and":
                    v = False if av is False or bv is False else (True if av and bv else None)
                    w = aw + bw if v else []
                else:
                    v = True if av is True or bv is True else (False if av is False and bv is False else None)
                    w = (aw if av is True else []) + (bw if bv is True else []) if v else []
                stack.append(("bool", (v, w)))
            elif s == "not":
                av, aw = stack.pop()[1]
                stack.append(("bool", (None if av is None else not av, [])))
            else:
                b, a = stack.pop(), stack.pop()
                if a[1] == "t1" and b[0] == "set":
                    member = bool(dn & b[1])
                    v = member if s == "==" else not member
                    w = ["%s %s" % ("in" if s == "==" else "not in", self._set_text(b[1]))] if v else []
                    stack.append(("bool", (v, w)))
                else:
                    stack.append(("bool", (None, [])))
        return stack[-1][1] if stack else (True, [])

    def levels(self, classes=None, domains=None):
        """Domains grouped by the level constraints they pass whatever the levels (and why)."""
        p = self.policy
        lcs = [c for c in self.level_constraints() if not classes or c["cls"] in classes]
        groups = {}
        for d in sorted(self.domains if domains is None else domains):
            sig, why = [], set()
            for i, c in enumerate(lcs):
                v, w = self.eval_levels(c["expr"], d)
                if v is True:
                    sig.append(i)
                    why.update(w)
            groups.setdefault((tuple(sig), tuple(sorted(why))), []).append(d)
        # Terms on the target type: objects any domain may use whatever their level (MLS mlstrustedobject).
        target_terms = {}
        for c in lcs:
            stack = []
            for tok in c["expr"]:
                if isinstance(tok, (set, frozenset)):
                    stack.append({str(x) for x in tok})
                elif str(tok) in self.OPERANDS:
                    stack.append(str(tok))
                elif str(tok) in ("==", "!=") and len(stack) >= 2 and stack[-2] == "t2" and isinstance(stack[-1], set):
                    names = stack.pop()
                    stack.pop()
                    k = "%s %s" % ("in" if str(tok) == "==" else "not in", self._set_text(names))
                    target_terms.setdefault(k, {"term": k, "constraints": 0, "types": len(set().union(*[set(self.expand(n)) for n in names]))})
                    target_terms[k]["constraints"] += 1
                    stack.append(None)
                elif str(tok) == "not":
                    pass
                else:
                    if len(stack) >= 2:
                        stack.pop()
                        stack.pop()
                    stack.append(None)
        out = []
        for (sig, why), doms in groups.items():
            per = {}
            for i in sig:
                per.setdefault(lcs[i]["cls"], set()).update(lcs[i]["perms"])
            out.append({"constraints": list(sig), "via": list(why), "domains": doms,
                        "classes": {k: sorted(v) for k, v in sorted(per.items())}})
        out.sort(key=lambda g: (-len(g["constraints"]), -len(g["domains"])))
        try:
            sens, cats = len(list(p.sensitivities())), len(list(p.categories()))
        except Exception:
            sens, cats = 0, 0
        return {"mls": bool(p.mls), "kind": ("mls" if sens > 1 else "mcs") if p.mls else None, "sensitivities": sens, "categories": cats,
                "constraints": [{"cls": c["cls"], "perms": c["perms"], "text": c["text"]} for c in lcs],
                "groups": out, "targetTerms": sorted(target_terms.values(), key=lambda x: -x["constraints"]),
                "domains": sum(len(g["domains"]) for g in out)}

    # Objects two processes of a domain can share by name: file system objects, System V IPC,
    # keys, processes; for sockets only reaching another process's (its own sockets aren't shared).
    SHAREABLE = {"file", "dir", "lnk_file", "chr_file", "blk_file", "sock_file", "fifo_file",
                 "sem", "msgq", "msg", "shm", "ipc", "key", "process"}
    SHARE_PERMS = {"unix_stream_socket": {"connectto"}, "unix_dgram_socket": {"sendto"}}

    def isolation(self, domains, min_weight=10, classes=None, limit=300, scope="own"):
        """For each domain: its allowed accesses that carry information (setools permission map,
        weight >= min_weight) but that no level constraint checks for it — what categories can't
        keep apart between two processes of that domain at different levels (two containers share
        container_t, so their own files and sockets are told apart only by level).
        scope "own": only objects such a process is or creates (its own type, types it may
        create), the ones two of them can share; "all": every target."""
        lcs = self.level_constraints()
        cov = {}
        for i, c in enumerate(lcs):
            for p in c["perms"]:
                cov.setdefault((c["cls"], p), []).append(i)
        pm = self.permmap()
        out = []
        for d in sorted(domains):
            checked = {}
            dn = [d] + self.attrs.get(d, [])
            binds = sum(1 for c in lcs if self.eval_levels(c["expr"], d)[0] is not True)
            own = None
            if scope == "own":
                own = {d}
                for n in dn:
                    for i in self.by_src.get(n, ()):
                        r = self.rules[i]
                        if r["rt"] == "allow" and "create" in r["perms"]:
                            own.update(self.side_types(r, "t", d))
            groups = {}
            for n in dn:
                for i in self.by_src.get(n, ()):
                    r = self.rules[i]
                    if r["rt"] != "allow" or (classes and r["c"] not in classes):
                        continue
                    if own is not None and not own.intersection(self.side_types(r, "t", d)):
                        continue
                    if scope == "own" and r["c"] not in self.SHAREABLE and r["c"] not in self.SHARE_PERMS:
                        continue
                    for p in r["perms"]:
                        direction, weight = pm.get((r["c"], p), ("n", 0))
                        if scope == "own" and r["c"] in self.SHARE_PERMS:
                            # Sockets: only reaching another process's socket (connectto, sendto) is shared.
                            if p not in self.SHARE_PERMS[r["c"]]:
                                continue
                            direction, weight = direction if direction != "n" else "w", max(weight, min_weight)
                        if direction == "n" or weight < min_weight:
                            continue
                        key = (r["c"], p)
                        if key not in checked:
                            checked[key] = any(self.eval_levels(lcs[j]["expr"], d)[0] is not True for j in cov.get(key, []))
                        if checked[key]:
                            continue
                        g = groups.setdefault((r["t"], r["c"]), {"target": r["t"], "class": r["c"], "perms": set(), "dirs": set(), "rules": [], "cond": set()})
                        g["perms"].add(p)
                        g["dirs"].add({"r": "read", "w": "write", "b": "read/write"}[direction])
                        if r not in g["rules"] and len(g["rules"]) < 3:
                            g["rules"].append(r)
                        if r["cond"]:
                            g["cond"].add(r["cond"])
            # Where opening the object is level-checked, these accesses need a descriptor someone passed it.
            def open_checked(cls):
                k = (cls, "open")
                if k not in checked:
                    checked[k] = any(self.eval_levels(lcs[j]["expr"], d)[0] is not True for j in cov.get(k, []))
                return checked[k] and "open" in self.classperms.get(cls, ())
            for g in groups.values():
                g["fdOnly"] = open_checked(g["class"]) and "open" not in g["perms"]
            items = sorted(groups.values(), key=lambda g: (g["fdOnly"], g["target"] not in ("self", d), -len(g["perms"]), g["target"], g["class"]))
            out.append({"domain": d, "binds": binds, "constraints": len(lcs), "count": len(items), "scope": scope,
                        "open": sum(1 for g in items if not g["fdOnly"]),
                        "unchecked": [{"target": g["target"], "class": g["class"], "perms": sorted(g["perms"]), "dirs": sorted(g["dirs"]),
                                       "rules": g["rules"], "conditional": sorted(g["cond"]), "fdOnly": g["fdOnly"]} for g in items[:limit]]})
        return out

    def check_levels(self, kind, sources, classes):
        if not self.policy.mls:
            return {"ok": False, "error": "this policy has no levels (built without MLS or MCS)"}
        if classes and not any(c["cls"] in classes for c in self.level_constraints()):
            return {"ok": False, "error": "no level constraint covers %s" % " ".join(sorted(classes))}
        who = self.names(sources)
        cand = (self.domains - who) if kind == "only-levels" else (who & self.domains)
        res = self.levels(classes, cand)
        bad = [g for g in res["groups"] if g["constraints"]]
        return {"ok": not bad, "count": sum(len(g["domains"]) for g in bad),
                "levels": [{"domains": g["domains"][:60], "count": len(g["domains"]), "via": g["via"], "classes": g["classes"]} for g in bad[:20]]}

    def hostfacts(self):
        """What comparing a host's local changes needs: types and attributes, boolean defaults,
        users (roles, range), roles, and the port / interface / node labels."""
        p = self.policy
        out = {"types": sorted(set(self.attrs) | set(self.members)), "bools": dict(self.bool_defaults),
               "users": {}, "roles": sorted(self.role_types), "ports": [], "netifs": {}, "nodes": []}
        for u in p.users():
            rng = None
            try:
                rng = str(u.mls_range).replace(" - ", "-") if p.mls else None
            except Exception:
                pass
            out["users"][str(u)] = {"roles": sorted(self.user_roles[str(u)]), "range": rng}
        try:
            for pc in p.portcons():
                out["ports"].append({"proto": str(pc.protocol).lower(), "low": int(pc.ports.low), "high": int(pc.ports.high), "type": str(pc.context.type_)})
        except Exception:
            pass
        try:
            for n in p.netifcons():
                out["netifs"][str(n.netif)] = str(n.context.type_)
        except Exception:
            pass
        try:
            for n in p.nodecons():
                net = n.network
                out["nodes"].append({"addr": str(net.network_address), "mask": str(net.netmask), "proto": "ipv6" if net.version == 6 else "ipv4", "type": str(n.context.type_)})
        except Exception:
            pass
        return out

    def entrypoint_domains(self, types):
        """For each file type: the domains it is an entrypoint of (a program with that label starts them),
        from rules written for the type itself (attribute rules make e.g. container domains enter anything)."""
        out = {}
        for ft in types:
            ft2 = self.aliases.get(ft, ft)
            doms = set()
            for n in [ft2]:
                for i in self.by_tgt.get(n, ()):
                    r = self.rules[i]
                    if r["rt"] == "allow" and r["c"] == "file" and "entrypoint" in r["perms"] and not r["cond"]:
                        doms.update(d for d in self.expand(r["s"]) if d in self.domains)
            out[ft] = sorted(doms)
        return out

    def typeinfo(self, names, source_rules):
        """For ranking interfaces: what each name is ({attr, size, attrs}), and the allow
        rules written for attributes an interface would add to a domain."""
        info = {}
        for n in names:
            n2 = self.aliases.get(n, n)
            if n2 in self.members or (n2 not in self.attrs and n2 in self.by_src):
                info[n] = {"attr": True, "size": len(self.members.get(n2, []))}
            elif n2 in self.attrs:
                info[n] = {"attr": False, "size": 1, "attrs": self.attrs[n2]}
        rules = {}
        for a in source_rules:
            rules[a] = [self.rules[i] for i in self.by_src.get(a, ()) if self.rules[i]["rt"] == "allow"][:400]
        return {"info": info, "rules": rules}

    def fileinfo(self, t, limit=400):
        """What the policy lets happen to objects of type t (file lookup): allow rules on it
        (written for it or for its attributes), the domains it is an entrypoint of and who
        transitions into them through it, type_transitions creating it, and those for new
        objects inside it (t as the parent directory)."""
        t2 = self.aliases.get(t, t)
        if t2 not in self.attrs:
            raise KeyError(t)
        own_attrs = self.attrs[t2]
        names = [t2] + own_attrs
        groups = {}
        for n in names:
            for i in self.by_tgt.get(n, ()):
                r = self.rules[i]
                if r["rt"] != "allow":
                    continue
                g = groups.setdefault((r["s"], r["t"], r["cond"]), {"s": r["s"], "t": r["t"], "cond": r["cond"], "classes": {}})
                g["classes"].setdefault(r["c"], set()).update(r["perms"])
        access = []
        for g in groups.values():
            members = self.members.get(g["s"])
            access.append({"s": g["s"], "t": g["t"], "cond": g["cond"], "attr": members is not None,
                           "size": len(members) if members is not None else 1,
                           "domains": sum(1 for m in members if m in self.domains) if members is not None else int(g["s"] in self.domains),
                           "classes": {c: sorted(p) for c, p in sorted(g["classes"].items())}})
        # Entrypoints: written for t itself, or through one of its attributes (counted apart).
        entries, via_attr = {}, {}
        for n in names:
            for i in self.by_tgt.get(n, ()):
                r = self.rules[i]
                if r["rt"] == "allow" and r["c"] == "file" and "entrypoint" in r["perms"]:
                    for d in self.expand(r["s"]):
                        if d in self.domains:
                            (entries if n == t2 else via_attr).setdefault(d, set()).add(r["s"])
        domains = []
        for d in sorted(entries):
            froms = [tr for tr in self.transitions(d, "in") if t2 in tr["entrypoints"]]
            domains.append({"domain": d, "via": sorted(entries[d]), "permissive": d in self.permissive,
                            "from": [{"source": tr["source"], "auto": t2 in tr["auto"], "setexec": tr["setexec"], "conditional": tr["conditional"],
                                      "range": next((x["range"] for x in tr.get("ranges", []) if x["entry"] == t2), None)} for tr in froms[:60]],
                            "fromCount": len(froms)})
        created, inside = [], []
        for i, r in enumerate(self.rules):
            if r["rt"] != "type_transition" or r["c"] == "process":
                continue
            if r["perms"] and r["perms"][0] == t2:
                created.append(r)
            elif r["t"] in names:
                inside.append(r)
        def some(rules):
            # Rules on the type itself first; named (file name) transitions come last in setools' order, keep some of each.
            rules = sorted(rules, key=lambda r: (r["t"] != t2, "name" in r))
            return [r for r in rules if "name" not in r][:limit // 2] + [r for r in rules if "name" in r][:limit // 2]
        return {"type": t2, "alias": t if t2 != t else None, "attrs": own_attrs, "permissive": t2 in self.permissive,
                "isDomain": t2 in self.domains, "access": access[:limit], "accessCount": len(access),
                "entrypointOf": domains, "entryViaAttr": len(via_attr),
                "created": some(created), "createdCount": len(created), "inside": some(inside), "insideCount": len(inside)}

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
            elif req.get("op") == "constraints":
                resp.update(failing=idx.constraints(req["s"], req["t"], req["c"], set(req.get("perms") or [])))
            elif req.get("op") == "hostfacts":
                resp.update(idx.hostfacts())
            elif req.get("op") == "levels":
                resp.update(idx.levels(set(req.get("classes") or []) or None))
            elif req.get("op") == "isolation":
                doms = idx.names(req.get("domains") or []) & idx.domains
                resp.update(results=idx.isolation(doms, req.get("weight") or 10, set(req.get("classes") or []) or None, scope=req.get("scope") or "own"), mls=bool(idx.policy.mls))
            elif req.get("op") == "context":
                resp.update(idx.context_check(req["s"], req["t"], req["c"], req.get("perms") or [], req.get("bools") or {}))
            elif req.get("op") == "entrypoints":
                resp.update(domains=idx.entrypoint_domains(req.get("types") or []))
            elif req.get("op") == "fileinfo":
                resp.update(idx.fileinfo(req["type"]))
            elif req.get("op") == "typeinfo":
                resp.update(idx.typeinfo(req.get("names", []), req.get("sourceRules", [])))
            elif req.get("op") == "avc":
                resp.update(results=idx.avc(req.get("checks", []), req.get("bools") or {}))
            elif req.get("op") == "users":
                # Users with their roles and range; each role's types among `types`; which `names` exist.
                want = set(req.get("types", []))
                users = {}
                for u in idx.policy.users():
                    rng = None
                    try:
                        rng = str(u.mls_range) if idx.policy.mls else None
                    except Exception:
                        pass
                    users[str(u)] = {"roles": sorted(idx.user_roles[str(u)]), "range": rng}
                resp.update(users=users, roleTypes={r: sorted(ts & want) for r, ts in idx.role_types.items()},
                            exists=[n for n in req.get("names", []) if n in idx.attrs or n in idx.members])
            elif req.get("op") == "reach":
                res = idx.reach(req["user"], req.get("starts", []), req.get("limit", 12), req.get("roles"), frozenset(idx.names(req.get("avoid") or [])))
                doms = set(res["reached"])
                acc = {}
                for a in req.get("access", []):
                    try:
                        if a.get("attr"):
                            acc[a["id"]] = {d: {} for d in doms if a["attr"] in idx.attrs.get(d, [])} if a["attr"] in idx.members else None
                        else:
                            acc[a["id"]] = idx.reach_access(doms, a["t"], a.get("classes") or [], a.get("perms") or "*")
                    except KeyError:
                        acc[a["id"]] = None
                resp.update(res, access=acc)
            elif req.get("op") == "access_any":
                # Which of `domains` may access any of `targets` (types or attributes): the first hits.
                doms, hits = set(req.get("domains", [])), []
                for t in sorted(idx.names(req.get("targets", []))):
                    for d, x in sorted(idx.reach_access(doms, t, req.get("classes") or [], req.get("perms") or "*").items()):
                        hits.append({"domain": d, "target": t, "rule": x["rule"], "perms": x["perms"]})
                    if len(hits) >= 50:
                        break
                resp.update(hits=hits)
            elif req.get("op") == "names":
                resp.update(types=sorted(idx.names(req.get("names", []))))
            elif req.get("op") == "access":
                resp.update(access=idx.reach_access(set(req.get("domains", [])), req["t"], req.get("classes") or [], req.get("perms") or "*"))
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
