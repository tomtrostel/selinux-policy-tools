'use strict';
/*
 * Structural parser for refpolicy-style SELinux policy source.
 *
 * This does NOT emulate m4. It tokenizes the source, tracks m4 call/quote
 * nesting, and records what an editor needs: definitions (interfaces,
 * templates, m4 defines), declarations (types, attributes, roles, booleans),
 * calls with their arguments, gen_require contents, access-vector rules, and
 * every identifier occurrence for find-references.
 *
 * Declarations that contain $N inside a template/define body are recorded as
 * patterns on that definition so the indexer can expand them at call sites
 * (e.g. network_port(http, ...) -> http_port_t).
 */

const DEF_MACROS = new Set(['interface', 'template', 'define']);
const REQUIRE_MACROS = new Set(['gen_require']);
const BOOL_MACROS = new Set(['gen_tunable', 'gen_bool']);
const AV_RULES = new Set(['allow', 'dontaudit', 'auditallow', 'neverallow',
  'allowxperm', 'dontauditxperm', 'auditallowxperm', 'neverallowxperm']);
// Policy-language keywords that may be written directly before '(' without being m4 calls.
const PAREN_KEYWORDS = new Set(['if', 'constrain', 'mlsconstrain', 'validatetrans', 'mlsvalidatetrans', 'not', 'and', 'or']);
const DECL_KEYWORDS = new Set(['type', 'attribute', 'attribute_role', 'typealias', 'role', 'bool']);
// Calls whose argument tokens are kept with positions (validated in diagnostics.js).
const TOKENIZED_CALLS = new Set(['gen_user']);
// m4 conditionals whose branches are recorded (ifelse compares strings and is left alone).
const CONDITIONALS = new Set(['ifdef', 'ifndef']);
// Arguments of these are human-readable messages, not code: `foo() is deprecated'.
const MESSAGE_MACROS = new Set(['refpolicywarn', 'refpolicyerr']);

const IDENT_RE = /[A-Za-z0-9_$]/;

function tokenize(text) {
  const toks = [];
  const comments = [];
  const n = text.length;
  let i = 0, line = 0, col = 0, lastTokLine = -1;
  const adv = () => {
    if (text.charCodeAt(i) === 10) { line++; col = 0; } else { col++; }
    i++;
  };
  while (i < n) {
    const c = text[i];
    if (c === '\n' || c === ' ' || c === '\t' || c === '\r' || c === '\f') { adv(); continue; }
    if (c === '#') {
      const s = i, l = line, cc = col;
      while (i < n && text[i] !== '\n') adv();
      comments.push({ l, c: cc, text: text.slice(s, i), own: lastTokLine !== l });
      continue;
    }
    if (c === '"') {
      const t = { t: 'str', s: i, l: line, c: col };
      adv();
      while (i < n && text[i] !== '"' && text[i] !== '\n') adv();
      if (i < n && text[i] === '"') adv();
      t.e = i; t.v = text.slice(t.s, i);
      toks.push(t); lastTokLine = t.l;
      continue;
    }
    if (IDENT_RE.test(c)) {
      const t = { t: 'id', s: i, l: line, c: col };
      while (i < n && IDENT_RE.test(text[i])) adv();
      t.e = i; t.v = text.slice(t.s, i);
      if (t.v === 'dnl') { // m4: discard to end of line
        while (i < n && text[i] !== '\n') adv();
        continue;
      }
      toks.push(t); lastTokLine = t.l;
      continue;
    }
    lastTokLine = line;
    toks.push({ t: 'sym', v: c, s: i, e: i + 1, l: line, c: col });
    adv();
  }
  return { toks, comments };
}

/* ---------- refpolicy XML doc comments ---------- */

function stripTags(s) {
  return s.replace(/<\/?p>/g, '\n').replace(/<[^>]+>/g, '')
    .split('\n').map(x => x.trim()).filter(Boolean).join(' ').trim();
}

function parseDoc(lines) {
  if (!lines.length) return null;
  const xmlLines = lines.filter(l => l.startsWith('##'));
  if (xmlLines.length) {
    const raw = xmlLines.map(l => l.replace(/^##\s?/, '')).join('\n');
    const params = [];
    const paramRe = /<param\s+name="([^"]+)"([^>]*)>([\s\S]*?)<\/param>/g;
    let m;
    while ((m = paramRe.exec(raw))) {
      params.push({
        name: m[1],
        optional: /optional="true"/.test(m[2]),
        unused: /unused="true"/.test(m[2]),
        summary: stripTags(m[3]),
      });
    }
    const rest = raw.replace(paramRe, '');
    const sm = /<summary>([\s\S]*?)<\/summary>/.exec(rest);
    const dm = /<desc>([\s\S]*?)<\/desc>/.exec(rest);
    return {
      summary: sm ? stripTags(sm[1]) : '',
      desc: dm ? stripTags(dm[1]) : '',
      params,
      rolecap: /<rolecap\/>/.test(rest),
    };
  }
  // Plain '#' comments (support .spt files)
  const plain = lines.map(l => l.replace(/^#+\s?/, '').trim()).filter(Boolean).join(' ');
  return plain ? { summary: plain, desc: '', params: [] } : null;
}

function docAbove(commentByLine, line) {
  const lines = [];
  for (let l = line - 1; l >= 0; l--) {
    const c = commentByLine.get(l);
    if (!c || !c.own) break;
    lines.unshift(c.text.trim());
  }
  // Drop leading separator lines like "########"
  while (lines.length && /^#+$/.test(lines[0])) lines.shift();
  return parseDoc(lines.filter(l => !/^#{3,}$/.test(l)));
}

/* ---------- main parser ---------- */

function cleanArg(s) {
  return s.replace(/[`']/g, '').replace(/#.*$/gm, '').trim();
}

function parsePolicy(text) {
  const { toks, comments } = tokenize(text);
  const commentByLine = new Map();
  for (const c of comments) commentByLine.set(c.l, c);

  const out = {
    kind: 'policy',
    module: null,
    defs: [],        // real (non-pattern) definitions in this file
    decls: [],       // concrete declarations
    calls: [],       // m4 calls: {name, l, c, args, argRanges, inDef}
    requires: [],    // names required at file level (in .te require blocks)
    avRules: [],
    refs: new Map(), // name -> [[line, col], ...]
    problems: [],
    branches: [],    // ifdef/ifndef branches: { sym, want, s:{l,c}, e:{l,c} }
  };

  const stack = [];
  let quote = 0;
  let stmtStart = true;
  let decl = null;   // declaration statement in progress
  let av = null;     // AV rule in progress

  const addRef = (tk) => {
    let a = out.refs.get(tk.v);
    if (!a) out.refs.set(tk.v, a = []);
    a.push([tk.l, tk.c]);
  };
  const currentDef = () => {
    for (let k = stack.length - 1; k >= 0; k--) {
      const f = stack[k];
      if (f.k === 'call' && f.def && f.argIdx >= 1) return f.def;
    }
    return null;
  };
  // Inside the innermost definition: is the current point in an optional_policy
  // or an m4 conditional of its body? (Such requirements aren't unconditional.)
  const condInDef = () => {
    for (let k = stack.length - 1; k >= 0; k--) {
      const f = stack[k];
      if (f.k !== 'call') continue;
      if (f.def && f.argIdx >= 1) return false;
      if (f.name === 'optional_policy' || CONDITIONALS.has(f.name) || f.name === 'ifelse') return true;
    }
    return false;
  };
  // Enclosing ifelse(`a', `b', then, else) branches inside the innermost
  // definition, as [{ a, b, then: bool }], so a call with concrete arguments
  // can tell whether the branch applies. Only the 4-argument form counts;
  // anything else (comparison arguments, longer chains) is left undecided.
  // `below`: start under this stack index (a definition's own frame).
  const ifelseWhen = (below = stack.length) => {
    const out = [];
    for (let k = below - 1; k >= 0; k--) {
      const f = stack[k];
      if (f.k !== 'call') continue;
      if (f.def && f.argIdx >= 1) break;
      if (f.name !== 'ifelse' || (f.argIdx !== 2 && f.argIdx !== 3)) continue;
      const a0 = f.args[0], a1 = f.args[1];
      if (!a0 || !a1 || a0.e === undefined || a1.e === undefined) continue;
      out.push({ a: cleanArg(text.slice(a0.s, a0.e)), b: cleanArg(text.slice(a1.s, a1.e)), then: f.argIdx === 2 });
    }
    return out.length ? out : null;
  };
  const withWhen = (o, below) => { const w = ifelseWhen(below); if (w) o.when = w; return o; };
  const inRequire = () => stack.some(f => (f.k === 'call' && REQUIRE_MACROS.has(f.name)) || (f.k === 'brace' && f.req));
  const resetStmt = () => { stmtStart = true; decl = null; av = null; };

  const recordDecl = (kind, tk, extra) => {
    const req = inRequire();
    const def = currentDef();
    if (req) {
      if (def) def.requires.push(withWhen(condInDef() ? { kind, name: tk.v, cond: true } : { kind, name: tk.v }));
      else out.requires.push({ kind, name: tk.v, l: tk.l, c: tk.c });
      return null;
    }
    if (tk.v.includes('$')) {
      if (def) def.declPatterns.push(withWhen({ kind, pattern: tk.v }));
      return null;
    }
    const d = { kind, name: tk.v, l: tk.l, c: tk.c, len: tk.v.length, attrs: [], ...extra };
    if (def) d.inDef = def.name;
    out.decls.push(d);
    return d;
  };

  for (let i = 0; i < toks.length; i++) {
    const tk = toks[i];
    const nx = toks[i + 1];

    if (tk.t === 'id') {
      addRef(tk);
      const top = stack[stack.length - 1];
      if (top && top.k === 'call' && top.argIdx === 0 && !top.firstIdent) top.firstIdent = tk;

      // m4 call: identifier immediately followed by '('
      if (nx && nx.t === 'sym' && nx.v === '(' && nx.s === tk.e && !PAREN_KEYWORDS.has(tk.v)) {
        const frame = { k: 'call', name: tk.v, tok: tk, q: quote, argIdx: 0, args: [{ s: nx.e }], parentDef: currentDef() };
        stack.push(frame);
        i++;
        resetStmt();
        continue;
      }

      if (stmtStart) {
        stmtStart = false;
        if (DECL_KEYWORDS.has(tk.v)) { decl = { kw: tk.v, stage: 'name', cur: null }; continue; }
        if (AV_RULES.has(tk.v)) { av = { kw: tk.v, l: tk.l, stage: 'types', classes: [], perms: [], brace: false }; continue; }
        continue;
      }

      if (decl) {
        if (decl.stage === 'name') {
          if (decl.kw === 'typealias') { decl.stage = 'post'; continue; }
          if (decl.kw === 'role') {
            if (inRequire()) { recordDecl('role', tk); decl.stage = 'post'; continue; }
            if (nx && nx.v === ';') recordDecl('role', tk);
            decl = null;
            continue;
          }
          decl.cur = recordDecl(decl.kw, tk);
          decl.stage = 'post';
          continue;
        }
        if (decl.stage === 'post' && tk.v === 'alias') { decl.stage = 'alias'; continue; }
        if (decl.stage === 'alias') { recordDecl('type', tk, { alias: true }); continue; }
        if (decl.stage === 'attrs') {
          // In a require block, `type a, b;` lists several requirements.
          // In a declaration, `type a, attr1, attr2;` lists attributes.
          if (inRequire()) recordDecl(decl.kw, tk);
          else if (decl.cur && decl.kw === 'type') decl.cur.attrs.push(tk.v);
          continue;
        }
        continue;
      }

      if (av) {
        if (av.stage === 'cls') {
          av.classes.push({ v: tk.v, l: tk.l, c: tk.c });
          if (!av.brace) av.stage = 'perms';
        } else if (av.stage === 'perms') {
          av.perms.push({ v: tk.v, l: tk.l, c: tk.c });
        }
      }
      continue;
    }

    if (tk.t === 'str') continue;

    // symbols
    switch (tk.v) {
      case '`':
        quote++;
        resetStmt();
        break;
      case "'":
        if (quote > 0) quote--;
        resetStmt();
        break;
      case '(':
        stack.push({ k: 'paren' });
        break;
      case ')': {
        let f;
        while ((f = stack.pop()) && f.k === 'brace') { /* tolerate unbalanced braces */ }
        if (!f) { out.problems.push({ l: tk.l, c: tk.c, msg: "Unmatched ')'" }); break; }
        if (f.k === 'call') { f.args[f.args.length - 1].e = tk.s; closeBranch(f, tk); finishCall(f, tk); resetStmt(); }
        break;
      }
      case ',': {
        const top = stack[stack.length - 1];
        if (top && top.k === 'call' && quote === top.q) {
          top.args[top.args.length - 1].e = tk.s;
          top.args.push({ s: tk.e });
          top.argIdx++;
          if (top.argIdx === 1 && DEF_MACROS.has(top.name)) startDef(top);
          if (CONDITIONALS.has(top.name)) { closeBranch(top, tk); if (top.argIdx <= 2) top.br = { idx: top.argIdx, s: { l: tk.l, c: tk.c + 1 } }; }
          resetStmt();
        } else if (decl && (decl.stage === 'post' || decl.stage === 'alias')) {
          decl.stage = 'attrs';
        }
        break;
      }
      case '{': {
        const prev = toks[i - 1];
        stack.push({ k: 'brace', req: !!(prev && prev.t === 'id' && prev.v === 'require') });
        if (av && av.stage !== 'types') av.brace = true;
        else if (!decl && !av) resetStmt();
        break;
      }
      case '}': {
        const top = stack[stack.length - 1];
        if (top && top.k === 'brace') stack.pop();
        if (av && av.brace) { av.brace = false; if (av.stage === 'cls') av.stage = 'perms'; }
        else if (!decl && !av) resetStmt();
        break;
      }
      case ':':
        if (av && av.stage === 'types') av.stage = 'cls';
        break;
      case ';':
        if (av && !av.kw.endsWith('xperm')) out.avRules.push({ kw: av.kw, l: av.l, classes: av.classes, perms: av.perms });
        resetStmt();
        break;
      default:
        break;
    }
  }

  for (const f of stack) {
    if (f.k === 'call') out.problems.push({ l: f.tok.l, c: f.tok.c, msg: `Unterminated call to '${f.name}' (missing ')')` });
  }
  if (quote !== 0) out.problems.push({ l: 0, c: 0, msg: `Unbalanced m4 quotes in file (${quote} unclosed \`)` });
  return out;

  /* -- helpers that close over parser state -- */

  /**
   * End the open branch of an ifdef/ifndef frame at `tk` (a ',' or ')').
   * Records { sym, want, s, e }: the text between s and e is used by m4 only
   * when `sym` being defined equals `want`.
   */
  function closeBranch(frame, tk) {
    if (!frame.br || !CONDITIONALS.has(frame.name)) return;
    const a0 = frame.args[0];
    const sym = cleanArg(text.slice(a0.s, a0.e === undefined ? a0.s : a0.e));
    if (/^\w+$/.test(sym)) {
      const want = frame.name === 'ifdef' ? frame.br.idx === 1 : frame.br.idx === 2;
      out.branches.push({ sym, want, s: frame.br.s, e: { l: tk.l, c: tk.c } });
    }
    frame.br = null;
  }

  function startDef(frame) {
    const nameTok = frame.firstIdent;
    if (!nameTok) return;
    const def = {
      kind: frame.name, name: nameTok.v,
      l: nameTok.l, c: nameTok.c, len: nameTok.v.length,
      callLine: frame.tok.l,
      doc: docAbove(commentByLine, frame.tok.l),
      declPatterns: [], bodyCalls: [], requires: [], reqBlocks: [],
      bodyStart: { l: frame.tok.l, c: frame.tok.c },
    };
    frame.def = def;
    if (nameTok.v.includes('$')) {
      def.isPattern = true;
      if (frame.parentDef) frame.parentDef.declPatterns.push(withWhen({ kind: frame.name, pattern: nameTok.v, doc: def.doc }, stack.lastIndexOf(frame)));
    } else {
      out.defs.push(def);
    }
  }

  function finishCall(frame, closeTok) {
    const args = frame.args.map(a => cleanArg(text.slice(a.s, a.e === undefined ? a.s : a.e)));
    if (frame.def) {
      frame.def.bodyEnd = { l: closeTok.l, c: closeTok.c };
      const body = text.slice(frame.args[0].e === undefined ? frame.args[0].s : frame.args[0].e, closeTok.s);
      let max = 0;
      for (const m of body.matchAll(/\$(\d)/g)) max = Math.max(max, +m[1]);
      frame.def.maxArg = max;
      return;
    }
    if (stack.some(f => f.k === 'call' && MESSAGE_MACROS.has(f.name))) return;
    const enclosing = currentDef();
    const call = {
      name: frame.name, l: frame.tok.l, c: frame.tok.c, len: frame.name.length,
      args, argRanges: frame.args, endL: closeTok.l, endC: closeTok.c,
      inOptional: stack.some(f => f.k === 'call' && f.name === 'optional_policy'),
      // Names whose definedness guards this call: ifdef(`X', <here>, ...).
      ifdefGuards: stack.filter(f => f.k === 'call' && f.name === 'ifdef' && f.argIdx === 1 && f.firstIdent)
        .map(f => f.firstIdent.v),
    };
    // gen_user(): keep each argument's identifier tokens with positions, for
    // role/MLS validation (role lists can contain nested ifdefs).
    if (TOKENIZED_CALLS.has(frame.name)) {
      call.argTokens = frame.args.map(a => toks.filter(t => t.t === 'id' && t.s >= a.s && (a.e === undefined || t.s < a.e)).map(t => ({ v: t.v, l: t.l, c: t.c })));
    }
    if (enclosing) {
      call.inDef = enclosing.name;
      enclosing.bodyCalls.push(withWhen(condInDef() ? { name: frame.name, args, cond: true } : { name: frame.name, args }));
      if (REQUIRE_MACROS.has(frame.name)) {
        enclosing.reqBlocks.push({ l: frame.tok.l, c: frame.tok.c, endL: closeTok.l, endC: closeTok.c });
      }
    }
    out.calls.push(call);

    // gen_tunable(`$1_exec_content', ...) in a template declares a pattern (recordDecl → declPatterns).
    if (BOOL_MACROS.has(frame.name) && args[0] && /^[\w$]+$/.test(args[0])) {
      const t = frame.firstIdent;
      if (t) {
        const d = recordDecl('bool', t, { tunable: frame.name === 'gen_tunable', default: args[1] || '' });
        if (d) d.doc = docAbove(commentByLine, frame.tok.l);
      }
    }
    if (frame.name === 'policy_module' && args[0]) out.module = args[0];
  }
}

/* ---------- file contexts (.fc) ---------- */

function parseFc(text) {
  const out = { kind: 'fc', entries: [], refs: new Map(), calls: [], decls: [], defs: [], avRules: [], requires: [], problems: [] };
  // .fc files are m4 too (ifdef(`distro_debian', ...)); reuse the policy parser for their branches.
  out.branches = parsePolicy(text).branches;
  const lines = text.split('\n');
  const ctxRe = /gen_context\(\s*([A-Za-z0-9_$]+):([A-Za-z0-9_$]+):([A-Za-z0-9_$]+)/g;
  lines.forEach((line, l) => {
    const t = line.trim();
    if (!t || t.startsWith('#')) return;
    let m;
    ctxRe.lastIndex = 0;
    while ((m = ctxRe.exec(line))) {
      const type = m[3];
      const c = m.index + m[0].length - type.length;
      let a = out.refs.get(type);
      if (!a) out.refs.set(type, a = []);
      a.push([l, c]);
      const path = t.split(/\s+/)[0];
      out.entries.push({ spec: path, type, l, c });
    }
  });
  return out;
}

/* ---------- flask: security_classes / access_vectors ---------- */

function parseFlask(text, which) {
  const { toks } = tokenize(text);
  const out = { kind: 'flask', classes: [], commons: [] };
  if (which === 'security_classes') {
    for (let i = 0; i < toks.length - 1; i++) {
      if (toks[i].v === 'class' && toks[i + 1].t === 'id') {
        const t = toks[i + 1];
        out.classes.push({ name: t.v, l: t.l, c: t.c, perms: [], inherits: null, declOnly: true });
      }
    }
    return out;
  }
  for (let i = 0; i < toks.length; i++) {
    const t = toks[i];
    if ((t.v === 'common' || t.v === 'class') && toks[i + 1] && toks[i + 1].t === 'id') {
      const nameTok = toks[i + 1];
      const ent = { name: nameTok.v, l: nameTok.l, c: nameTok.c, perms: [], inherits: null };
      let j = i + 2;
      if (toks[j] && toks[j].v === 'inherits') { ent.inherits = toks[j + 1] && toks[j + 1].v; j += 2; }
      let braced = false;
      if (toks[j] && toks[j].v === '{') {
        braced = true;
        j++;
        while (j < toks.length && toks[j].v !== '}') { if (toks[j].t === 'id') ent.perms.push(toks[j].v); j++; }
      }
      (t.v === 'common' ? out.commons : out.classes).push(ent);
      i = braced ? j : j - 1;
    }
  }
  return out;
}

module.exports = { tokenize, parsePolicy, parseFc, parseFlask, parseDoc, AV_RULES, DEF_MACROS };
