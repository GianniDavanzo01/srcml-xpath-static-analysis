"""
common.py
---------
Utility di base condivise da tutti gli altri moduli del motore:
caricamento regole, helper di posizione/snippet sui nodi srcML,
costruzione dei finding e verifica di sanificazione/presenza source.
"""

import json
import re
from pathlib import Path


from collections import defaultdict

from functools import lru_cache

from lxml import etree

NS = {"src": "http://www.srcML.org/srcML/src", "pos": "http://www.srcML.org/srcML/position"}



#VERIFICA DELLE MACRO
_macro_map_cache = {}   # da svuotare in reset_caches() perché dipende dalla unit
def macro_map(imports) -> dict:
    key = id(imports)
    m = _macro_map_cache.get(key)
    if m is None:
        m = _macro_map_cache[key] = {b.local_name: b.canonical_name
                                     for b in (imports or []) if getattr(b, "is_macro", False)}
    return m


def expand_macro_name(name, macros):
    seen = set()
    while macros and name in macros and name not in seen:
        seen.add(name)
        name = macros[name]
    return name
#----------------------------------------------------------------------


#Controllo di codice non raggiungibile----------------------
def _branch_const(br, adapter):
    """True/False se la condizione del ramo è un letterale costante, altrimenti None."""
    cond = br.xpath("./src:condition | ./src:if/src:condition", namespaces=NS)
    if not cond:
        return None
    lit = cond[0].xpath("./src:expr[count(*)=1]/src:literal", namespaces=NS)
    if not lit:
        return None
    t = "".join(lit[0].itertext())
    if adapter.is_true_constant(t):  return True
    if adapter.is_false_constant(t): return False
    return None

def _branch_is_dead(br, adapter):
    r = _branch_dead_cache.get(br)
    if r is None:
        tag = br.tag.rsplit("}", 1)[-1]
        # <elseif><if>...</if></elseif>: i fratelli precedenti stanno a livello di <elseif>
        parent = br.getparent()
        owner = parent if (tag == "if" and parent is not None
                           and parent.tag.endswith("}elseif")) else br
        r = (tag != "else" and _branch_const(br, adapter) is False) or any(
            _branch_const(p, adapter) is True
            for p in owner.xpath("preceding-sibling::*[self::src:if or self::src:elseif]",
                                 namespaces=NS)
        )
        _branch_dead_cache[br] = r
    return r

#POTREBBE COPRIRE LA CWE 561 DEAD-CODE, PERò NEI TESTCASES, SOPRATTUTTO DELLA JULIET TEST-SUITE GENERA MOLTO RUMORE
_BRANCH_TAGS = ("if", "elseif", "else")
def _is_dead_code_uncached(node, adapter) -> bool:
    """True se `node` sta nel blocco di un ramo if/elseif/else che non può eseguire."""
    child = node
    for br in node.iterancestors():
        tag = br.tag.rsplit("}", 1)[-1]
        # il ramo conta solo se il nodo è nel suo <block> (non nella condizione)
        if tag in _BRANCH_TAGS and child.tag.endswith("}block"):
            if _branch_is_dead(br, adapter):
                return True
        child = br
    return False

def is_dead_code(node, adapter) -> bool:
    r = _dead_code_cache.get(node)
    if r is None:
        r = _is_dead_code_uncached(node, adapter)
        _dead_code_cache[node] = r
    return r

#----------------------------------------------------------------------------------------


#RISOLVONO IL MATCH ESATTO E NON PIù PER SUFFISSO---------------------

#Le concatenazioni vengono rappresentate tutte come var1.var2.var3 per semplificazione evitanto var1->var2
@lru_cache(maxsize=None)
def _norm(name: str, adapter) -> str:
    return adapter.normalize_member_access(name)          # C: s->fn == s.fn

def call_matches(call_name, pattern, adapter) -> bool:
    """Esatto sul nome canonico risolto.
    '*.x[.y]' = 'x[.y]' oppure '<qualsiasi>.x[.y]' (ricevente non risolto, dichiarato)."""
    if not call_name or not pattern:
        return False
    cn, pat = _norm(call_name, adapter), _norm(pattern, adapter)
    if pat.startswith("*."):
        pat = pat[2:]
        return cn == pat or cn.endswith("." + pat)
    return cn == pat

def call_lookup_keys(call_name, adapter) -> list:
    """Chiavi da cercare nell'indice: nome esatto + tutte le forme '*.<coda>'."""
    cn = _norm(call_name, adapter)
    parts = cn.split(".")
    return [cn] + ["*." + ".".join(parts[i:]) for i in range(len(parts))]

# ---------------------------------------------------------------


def function_nodes(tree, adapter, name=None):
    """Nodi funzione/costruttore dello scope, secondo i tag dell'adapter.
    Se `name` è dato, filtra per nome dichiarato."""
    cond = " or ".join(f"self::src:{t}" for t in adapter.function_tags())
    if name is None:
        return tree.xpath(f".//*[{cond}]", namespaces=NS)
    return tree.xpath(f".//*[({cond}) and src:name[text()=$n]]", namespaces=NS, n=name)

_opaque_xpath_cache = {} #Dipende solo dall'adapter, non va svuotata ad ogni unit
def in_opaque_tag(node, adapter) -> bool:
    """True se `node` sta dentro un costrutto che non propaga taint (es. sizeof)."""
    xp = _opaque_xpath_cache.get(adapter.name)
    if xp is None:
        tags = adapter.taint_opaque_tags()
        xp = etree.XPath(
            "ancestor::*[" + " or ".join(f"self::src:{t}" for t in tags) + "]",
            namespaces=NS,
        ) if tags else False
        _opaque_xpath_cache[adapter.name] = xp
    return bool(xp(node)) if xp else False


_scope_xp_cache = {}  #dipende solo dall'adapter, non va svuotata in reset_caches()

def scope_xp(adapter, with_lambda=False):
    """XPath precompilato verso la funzione (o lambda) che racchiude il nodo."""
    key = (adapter.name, with_lambda)
    xp = _scope_xp_cache.get(key)
    if xp is None:
        extra = adapter.lambda_tags() if with_lambda else ()
        xp = _scope_xp_cache[key] = etree.XPath(adapter.scope_axis(extra), namespaces=NS)
    return xp

def enclosing_scope(node, adapter):
    r = scope_xp(adapter)(node)
    return r[0] if r else None

def block_exits_flow(block, adapter, imports) -> bool:
    fn = scope_xp(adapter, with_lambda=True)
    my_scope = fn(block)
    same = lambda n: fn(n) == my_scope

    tags = " | ".join(f".//src:{t}" for t in adapter.flow_exit_tags())
    if any(same(n) for n in block.xpath(tags, namespaces=NS)):
        return True

    exits = adapter.flow_exit_calls()
    for c in block.xpath(".//src:call", namespaces=NS):
        cn = get_call_name(c, adapter, imports)
        if cn and any(call_matches(cn, e, adapter) for e in exits) and same(c):
            return True
    return False


_NAME_TEXT_XP = etree.XPath(
    ".//text()[count(ancestor::src:index) = count($n/ancestor::src:index)]", namespaces=NS)

def name_text(name_node) -> str:
    """Testo di un <name> senza i suffissi [..] della propria dichiarazione/accesso
    ('names[]' -> 'names', 'a[i].b[0]' -> 'a.b'). Per un nome semplice è identico a prima."""
    return "".join(_NAME_TEXT_XP(name_node, n=name_node)).strip()


_member_ops_cache = {}
_INIT_TAG = f"{{{NS['src']}}}init"
def is_member_name(n, adapter) -> bool:
    """True se il <name> è una proprietà/membro e NON una variabile autonoma."""
    ops = _member_ops_cache.get(adapter.name)
    if ops is None:
        ops = _member_ops_cache[adapter.name] = frozenset(adapter.member_access_operator())

    # 1. Chiave di un object literal: { user: 1 } -> property/decl/name
    parent = n.getparent()
    if parent is not None and parent.tag.endswith("}decl"):
        gp = parent.getparent()
        if gp is not None and gp.tag.endswith("}property"):
            # (a) { user: 1 }: il valore è nel <init> fratello -> n è la chiave
            if parent.find(_INIT_TAG) is not None:
                return True
            # (b) senza init: shorthand { user } oppure binding di destructuring.
            #     Comportamento precedente: è un binding/chiave solo se
            #     l'object non sta dentro un valore (init).
            if not any(a.tag.endswith("}init") for a in n.iterancestors()):
                return True

    # 2. Preceduto da operatore membro (. o ?.)
    prev = n.getprevious()
    while prev is not None and (not isinstance(prev.tag, str) or prev.tag.endswith("}comment")):
        prev = prev.getprevious()
    if prev is not None and prev.tag.endswith("}operator") and "".join(prev.itertext()).strip() in ops:
        return True

    # 3. Forma annidata srcML: <name><name>other</name><operator>.</operator><name>user</name></name>
    if parent is not None and parent.tag.endswith("}name"):
        first_child = parent.xpath("./*[not(self::src:comment)][1]", namespaces=NS)
        if first_child and first_child[0] is not n:
            return True

    return False


#Matching dei nomi sensibili per token ----------------
_TOK = re.compile(r'[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+')

def name_tokens(n: str) -> list:
    return [t.lower() for t in _TOK.findall(n.replace("_", " "))]

def name_matches(var: str, patterns, excluded=frozenset()) -> bool:
    toks = name_tokens(var)
    if excluded & set(toks):
        return False
    for p in patterns:
        pt = name_tokens(p)
        if pt and any(toks[i:i+len(pt)] == pt for i in range(len(toks) - len(pt) + 1)):
            return True
    return False

def literal_value_ok(node, adapter, min_len=1, placeholders=()):
    """True se `node` contiene un letterale stringa 'plausibile' come segreto."""
    for lit in node.xpath("self::src:literal[@type='string'] | .//src:literal[@type='string']", namespaces=NS):
        v = adapter.normalize_string_literal("".join(lit.itertext()))
        if len(v) < min_len or v.lower() in placeholders:
            continue
        return True
    return False
#-----------------------------------------------------


def load_rules(rules_path: Path) -> list:
    """
    Carica le regole da:
      - un singolo file .json (comportamento originale), oppure
      - una cartella contenente più file .json, che vengono uniti in un'unica lista di regole.
    Segnala (senza bloccare l'esecuzione) eventuali rule_id duplicati tra file diversi.
    """
    if rules_path.is_dir():
        rules = []
        seen_ids = {}
        for rule_file in sorted(rules_path.glob("*.json")):
            file_rules = json.loads(rule_file.read_text(encoding="utf-8"))
            if not isinstance(file_rules, list):
                raise ValueError(
                    f"{rule_file.name}: atteso un array di regole, trovato {type(file_rules).__name__}. "
                )
            for rule in file_rules:
                rule_id = rule.get("rule_id", "UNKNOWN")
                if rule_id in seen_ids:
                    print(
                        f"[ATTENZIONE] rule_id duplicato '{rule_id}': "
                        f"già caricato da {seen_ids[rule_id]}, ora ripetuto in {rule_file.name}"
                    )
                else:
                    seen_ids[rule_id] = rule_file.name
            rules.extend(file_rules)
        return rules

    return json.loads(rules_path.read_text(encoding="utf-8"))


def node_position(node) -> str:
    n = node
    while n is not None:
        start = n.get("{http://www.srcML.org/srcML/position}start")
        if start:
            return start
        n = n.getparent()
    return "?:?"


def node_snippet(node, max_len: int = 140) -> str:
    text = "".join(node.itertext())
    text = re.sub(r"\s+", " ", text).strip()
    return text[:max_len] + ("…" if len(text) > max_len else "")

_call_name_cache = {}
_assign_pairs_cache = {}
_scope_index_cache = {}
_dead_code_cache = {}
_branch_dead_cache = {}
_decl_index_cache = {}
_field_decl_index_cache = {}

_ALL_DECLS_XP = etree.XPath(".//src:decl", namespaces=NS)
_CLASS_FIELDS_XP = etree.XPath("./src:block/src:decl_stmt/src:decl", namespaces=NS)
_DECL_DIRECT_NAME_XP = etree.XPath("./src:name", namespaces=NS)

def get_decl_index(container_node) -> dict:
    """Mappa {testo_nome: [nodi <decl>]} per tutti i <decl> dentro container_node.
    Identico a container_node.xpath('.//src:decl[src:name[text()=$v]]'), ma O(1)."""
    idx = _decl_index_cache.get(container_node)
    if idx is None:
        idx = defaultdict(list)
        for d in _ALL_DECLS_XP(container_node):
            for n in _DECL_DIRECT_NAME_XP(d):
                if n.text:
                    idx[n.text].append(d)
        _decl_index_cache[container_node] = idx
    return idx

def get_class_field_index(class_node) -> dict:
    """Mappa {testo_nome: [nodi <decl>]} per i campi diretti di una <class>."""
    idx = _field_decl_index_cache.get(class_node)
    if idx is None:
        idx = defaultdict(list)
        for d in _CLASS_FIELDS_XP(class_node):
            for n in _DECL_DIRECT_NAME_XP(d):
                if n.text:
                    idx[n.text].append(d)
        _field_decl_index_cache[class_node] = idx
    return idx

_matcher_cache = {} #Non deve essere svuotata, dipende solo da regola ed adapter, NON dalla Unit
def _get_matcher(patterns, adapter):
    key = (tuple(patterns), adapter.name)
    m = _matcher_cache.get(key)
    if m is None:
        m = _matcher_cache[key] = CallMatcher(patterns, adapter)
    return m

def reset_caches():
    _call_name_cache.clear()
    _assign_pairs_cache.clear()
    _scope_index_cache.clear()
    _dead_code_cache.clear() 
    _branch_dead_cache.clear()
    _macro_map_cache.clear()
    _decl_index_cache.clear()
    _field_decl_index_cache.clear()
    _rhs_cands_cache.clear()
    _assign_index_cache.clear()


_X_CHILD_NAME  = etree.XPath("./src:name", namespaces=NS)
_X_CHILD_OP    = etree.XPath("./src:operator", namespaces=NS)
_X_PARENT_CALL = etree.XPath("parent::src:call", namespaces=NS)

def get_scope_index(scope_node, adapter, macros=None):
    """
    Indice per scope, calcolato una volta e condiviso da tutte le regole:
      names:  testo del nodo <name> -> [nodi]
      interp: nome variabile interpolata -> [letterali stringa che la usano]
    """
    idx = _scope_index_cache.get(scope_node)
    if idx is None:
        names = defaultdict(list)

        for n in scope_node.xpath(".//src:name", namespaces=NS):
            if is_member_name(n, adapter):
                continue

            # Se è una foglia semplice
            if n.text and not n.xpath("./src:name", namespaces=NS):
                names[n.text].append(n)
                if macros and n.text in macros and not adapter.is_in_macro_definition(n):
                    names[expand_macro_name(n.text, macros)].append(n)

            # Se è un nome composto (es. a.b)
            elif _X_CHILD_OP(n) and _X_CHILD_NAME(n) and not _X_PARENT_CALL(n):
                key = name_text(n)
                if key:
                    names[key].append(n)

        interp = defaultdict(list)
        for lit in scope_node.xpath(".//src:literal[@type='string']", namespaces=NS):
            testo = "".join(lit.itertext())
            if adapter.is_interpolated_string(testo):
                for v in set(adapter.get_interpolated_variables(testo)):
                    interp[v].append(lit)

        idx = (names, interp)
        _scope_index_cache[scope_node] = idx
    return idx

def assignment_pairs(scope_node, adapter, include_bindings=False) -> list:
    """
    (stmt, lhs, rhs) di ogni assegnazione nello scope, calcolate una volta sola.

    Gli statement candidati sono scelti dall'adapter (`potential_assignment_xpath`)
    e confermati da `is_assignment`; lhs e rhs sono estratti da
    `get_assignment_lhs_rhs`.

    include_bindings: se True include anche i binding di iterazione
        (`for x in y`, `for (T x : y)`), in cui `stmt` è il nodo <control>,
        `lhs` la variabile del ciclo e `rhs` l'espressione iterata. Serve al
        motore taint (il taint dell'iterabile passa alla variabile); le regole
        strutturali lasciano il default False per non trattare
        `for key in ["a", "b"]` come `key = "..."` hardcoded."""
    
    key = (scope_node, include_bindings)
    pairs = _assign_pairs_cache.get(key)
    if pairs is None:
        pairs = []
        taint_skip = adapter.structural_only_assignment_tags() if include_bindings else ()
        for stmt in scope_node.xpath(adapter.potential_assignment_xpath(), namespaces=NS):
            if not include_bindings and stmt.tag.endswith("}control"):
                continue
            # if not adapter.is_assignment(stmt, NS):
            #     continue
            if not adapter.is_assignment(stmt, NS):
                # 'x += y' / 'x ??= y': solo per il taint (le regole strutturali non li vedono)
                if include_bindings and adapter.is_compound_assignment(stmt, NS):
                    lhs, rhs = adapter.get_compound_assignment_lhs_rhs(stmt, NS)
                    if lhs is not None and rhs is not None:
                        pairs.append((stmt, lhs, rhs))
                continue
            if taint_skip and stmt.tag.rsplit("}", 1)[-1] in taint_skip:
                continue
            for lhs, rhs in adapter.get_assignment_chain(stmt, NS):
                pairs.append((stmt, lhs, rhs))
        _assign_pairs_cache[key] = pairs
    return pairs

def get_call_name(call, adapter, imports):
    
    if call in _call_name_cache:
        return _call_name_cache[call]

    if call.xpath("./src:name", namespaces=NS):
        result = adapter.resolve_call_name(call, NS, imports)
    else:
        result = None

    _call_name_cache[call] = result
    return result

def build_finding(rule: dict, node, extra: dict | None = None) -> dict:
    """Costruisce il dizionario di finding"""
    file_path = node.xpath("ancestor::src:unit[1]/@filename", namespaces=NS)
    finding = {
        "rule_id": rule.get("rule_id", "UNKNOWN"),
        "vulnerabilities": rule.get("vulnerabilities", []),
        "source_file": file_path[0] if file_path else "Sconosciuto",
        "line": node_position(node),
        "snippet": node_snippet(node),
    }
    if extra:
        finding.update(extra)
    return finding

def _chain_downstream(call, adapter):
    """Call successive nella stessa catena fluente (escluso `call`)."""
    node = adapter._chain_next(call, NS)
    while node is not None:
        yield node
        node = adapter._chain_next(node, NS)

def _in_nested_function(node, call, adapter) -> bool:
    """True se tra `node` e `call` c'è una funzione/lambda (uso dentro una callback)."""
    tags = set(adapter.function_tags()) | set(adapter.lambda_tags())
    cond = " or ".join(f"self::src:{t}" for t in tags)
    for fn in node.xpath(f"ancestor::*[{cond}]", namespaces=NS):
        if call in fn.iterancestors():
            return True
    return False

def is_chain_sanitized(node, spec, adapter, imports) -> bool:
    """spec singolo: {"type": "chain", "through": [...], "then": [...]}.
    Sanificato se una call antenata matcha 'through' e, a valle nella stessa
    catena, c'è una call che matcha 'then'."""
    through = _get_matcher(tuple(spec["through"]), adapter)
    then    = _get_matcher(tuple(spec["then"]), adapter)
    for call in node.xpath("ancestor::src:call", namespaces=NS):
        cname = get_call_name(call, adapter, imports)
        if not cname or not through(cname):
            continue
        if _in_nested_function(node, call, adapter):
            continue
        if any((cn := get_call_name(c, adapter, imports)) and then(cn)
               for c in _chain_downstream(call, adapter)):
            return True
    return False


SANITIZER_MATCHERS = {
    "chain": is_chain_sanitized,
}


def is_sanitized(node, sanitizers: list, adapter, imports) -> bool:
    plain = [s for s in sanitizers if isinstance(s, str)]
    specs = [s for s in sanitizers if isinstance(s, dict)]

    for call in node.xpath("ancestor::src:call", namespaces=NS):
        cname = get_call_name(call, adapter, imports)
        if cname and any(call_matches(cname, san, adapter) for san in plain):
            return True

    return any((m := SANITIZER_MATCHERS.get(s.get("type"))) and m(node, s, adapter, imports)
               for s in specs)


_rhs_cands_cache = {}
_member_ws_rx = {}
def _compact_member_ws(text, adapter):
    """Toglie gli spazi/a capo attorno agli operatori di accesso a membro."""
    rx = _member_ws_rx.get(adapter.name)
    if rx is None:
        ops = sorted(adapter.member_access_operator(), key=len, reverse=True)  # '?.' prima di '.'
        rx = _member_ws_rx[adapter.name] = re.compile(
            r"\s*(" + "|".join(map(re.escape, ops)) + r")\s*")
    return rx.sub(r"\1", text)

def _rhs_candidates(rhs_node, adapter, imports):
    cands = _rhs_cands_cache.get(rhs_node)
    if cands is None:
        cands = []
        for call in rhs_node.xpath(".//src:call | self::src:call", namespaces=NS):
            cn = get_call_name(call, adapter, imports)
            if cn:
                cands.append(((cn,), call))
        prefixes = adapter.source_name_prefixes()
        for n in rhs_node.xpath(".//src:name | self::src:name", namespaces=NS):
            if is_member_name(n, adapter):
                continue
            text = "".join(n.itertext()).strip().split('[')[0].split('(')[0].strip()
            text = _compact_member_ws(text, adapter)
            parent = n.getparent()
            is_inner = parent is not None and parent.tag == n.tag
            if not is_inner:
                text = adapter.resolve_name_text(text, imports, node=n)
            keys = [text]
            if not is_inner and prefixes:
                parts = text.split(".")
                keys += [".".join(parts[:i]) for i in range(1, len(parts))]
            cands.append((tuple(keys), n))

        for lit in rhs_node.xpath(
                "self::src:literal[@type='string'] | .//src:literal[@type='string']",
                namespaces=NS):
            t = "".join(lit.itertext())
            if adapter.is_interpolated_string(t):
                for v in adapter.get_interpolated_variables(t):
                    cands.append(((adapter.resolve_name_text(v, imports, node=lit),), lit))

        _rhs_cands_cache[rhs_node] = cands
    return cands
    

def source_present(sources, rhs_node, *, adapter, imports, block=None) -> bool:
    matcher = _get_matcher(sources, adapter)
    for keys, node in _rhs_candidates(rhs_node, adapter, imports):
        if any(matcher(k) for k in keys) and not (block and is_sanitized(node, block, adapter, imports)):
            return True
    return False


_OWN_LITERALS_XP = etree.XPath(
    "./src:argument_list//src:literal[@type=$t]"
    "[count(ancestor::src:call[1] | $c) = 1]",
    namespaces=NS,
)

_OWN_NAMES_XP = etree.XPath(
    "./src:argument_list//src:name"
    "[count(ancestor::src:call[1] | $c) = 1]",
    namespaces=NS,
)

def own_literals(call_node, lit_type: str) -> list:
    """
    Letterali di tipo `lit_type` che appartengono direttamente a `call_node`:
    stanno nella sua argument_list e la call più vicina che li racchiude è
    proprio `call_node`, non una call annidata.
    """
    return _OWN_LITERALS_XP(call_node, t=lit_type, c=call_node)

def own_names(call_node) -> list:
    """
    Nomi di variabili che appartengono direttamente a `call_node`:
    stanno nella sua argument_list e la call più vicina che li racchiude è
    proprio `call_node`, ignorando call annidate.
    """
    return _OWN_NAMES_XP(call_node, c=call_node)

#HELPER PER I VALORI BOOL per ogni linguaggio
def _bool_text(value, adapter) -> str:
    """Valore atteso dal catalogo (bool JSON o stringa) -> forma canonica."""
    if isinstance(value, bool):
        value = "true" if value else "false"
    return adapter.canonical_literal(str(value))

def call_arguments_match_ast(call_node, spec: dict, adapter, imports) -> bool:
    """
    Motore universale AST per validare gli argomenti di una chiamata a funzione.
    """
    target_calls = spec.get("call", [])

    if isinstance(target_calls, str):
        target_calls = [target_calls]

    if target_calls:
        call_name = get_call_name(call_node, adapter, imports)
        if not call_name or not any(call_matches(call_name, c, adapter) for c in target_calls):
            return False

    arg_list_nodes = call_node.xpath("./src:argument_list", namespaces=NS)
    arguments = arg_list_nodes[0].xpath("./src:argument", namespaces=NS) if arg_list_nodes else []

    if "exact_args_count" in spec:
        if len(arguments) != spec["exact_args_count"]:
            return False

    bool_sequence = spec.get("args_boolean_sequence")
    if bool_sequence:
        if len(arguments) != len(bool_sequence):
            return False
        for arg, expected in zip(arguments, bool_sequence):
            if expected is None:
                continue
            if adapter.is_kwarg(arg, NS):
                return False  # kwarg: la posizione nel sorgente non è affidabile
            bool_lits = arg.xpath(
                "./src:expr/src:literal[@type='boolean'] | ./src:literal[@type='boolean']",
                namespaces=NS,
            )
            if not bool_lits:
                return False
            actual = adapter.canonical_literal("".join(bool_lits[0].itertext()))
            if actual != _bool_text(expected, adapter):
                return False
            
    #Richiede esattamente i nomi indicati
    required_names = spec.get("contains_names", [])
    if required_names:
        found_names = ["".join(n.itertext()).strip() for n in own_names(call_node)]

        # Estende la ricerca dentro le stringhe interpolate (es. f-string):
        str_lits = own_literals(call_node, "string")
        for lit in str_lits:
            testo = "".join(lit.itertext())
            if adapter.is_interpolated_string(testo):
                found_names.extend(adapter.get_interpolated_variables(testo))

        if not all(req in found_names for req in required_names):
            return False

    #Richiede almeno uno dei nomi indicati (CWE-532)
    required_names_any = spec.get("contains_any_name", [])
    if required_names_any:
        found_names = [name_text(n) for n in own_names(call_node)]

        # chiavi di subscript con letterale stringa: creds["password"]
        for lit in call_node.xpath(
                "./src:argument_list//src:index//src:literal[@type='string']"
                "[count(ancestor::src:call[1] | $c) = 1]", namespaces=NS):
            found_names.append(adapter.normalize_string_literal("".join(lit.itertext()).strip()))

        for lit in own_literals(call_node, "string"):
            testo = "".join(lit.itertext())
            if adapter.is_interpolated_string(testo):
                found_names.extend(adapter.get_interpolated_variables(testo))

        # case-insensitive, match per sottostringa
        lowered_found = [f.lower() for f in found_names]
        lowered_reqs = [req.lower() for req in required_names_any]

        if not any(req in f for req in lowered_reqs for f in lowered_found):
            return False

        
    substr_targets = spec.get("contains_string_containing", [])
    if substr_targets:
        found_texts = [
            adapter.normalize_string_literal("".join(l.itertext()))
            for l in _resolve_string_literals(call_node, adapter)
        ]
        if spec.get("case_insensitive", False):
            found_texts = [t.lower() for t in found_texts]
            substr_targets = [t.lower() for t in substr_targets]

        if not any(t in txt for t in substr_targets for txt in found_texts):
            return False

    banned_numbers = spec.get("contains_numbers", [])
    if banned_numbers:
        found_values = {v for _, v in _resolve_numeric_args(call_node, adapter, NS)}
        found_texts = [str(v) for v in found_values]

        def _num_ok(req):
            return req in found_texts or adapter.parse_numeric_literal(str(req)) in found_values

        if not any(_num_ok(req) for req in banned_numbers):
            return False

    if "arg_less_than" in spec:
        limit_spec = spec["arg_less_than"]
        found_pairs = _resolve_numeric_args(call_node, adapter, NS)

        if isinstance(limit_spec, dict):
            # Forma posizionale: {"index": N, "value": X} -> controlla SOLO
            # l'argomento all'indice N, non un numero qualsiasi nella call.
            target_index = limit_spec.get("index")
            limit = limit_spec.get("value")
            found_less_than_limit = any(
                idx == target_index and v < limit for idx, v in found_pairs
            )
        else:
            #qualunque argomento numerico sotto soglia.
            limit = limit_spec
            found_less_than_limit = any(v < limit for _, v in found_pairs)

        if not found_less_than_limit:
            return False

    banned_booleans = spec.get("contains_booleans", [])
    if banned_booleans:
        found_bools = [adapter.canonical_literal("".join(b.itertext()))
               for b in own_literals(call_node, "boolean")]
        if not any(_bool_text(req, adapter) in found_bools for req in banned_booleans):
            return False

    return True


def _pos_key(node) -> tuple:
    """
    Converte la posizione 'line:col' (stringa) in una tupla numerica (line, col) 
    confrontabile correttamente in maniera numerica e non lessicografica.
    """
    pos = node_position(node)
    if pos == "?:?":
        return (0, 0)
    try:
        line, col = pos.split(":")
        return (int(line), int(col))
    except ValueError:
        return (0, 0)


def _is_pure_literal_expr(node) -> bool:
    """
    True se l'espressione e' composta ESCLUSIVAMENTE da letterali (anche concatenati), 
    senza alcun <src:name> (variabile) ne' alcuna <src:call> al suo interno.
    """
    if node is None:
        return False
    if node.xpath("self::src:call | .//src:call", namespaces=NS):
        return False
    if node.xpath("self::src:name | .//src:name", namespaces=NS):
        return False
    return bool(node.xpath("self::src:literal | .//src:literal", namespaces=NS))



def _is_hardcoded_string(rhs, adapter) -> bool:
    if not _is_pure_literal_expr(rhs):
        return False
    lits = rhs.xpath("self::src:literal[@type='string'] | .//src:literal[@type='string']",
                     namespaces=NS)
    return any(not adapter.is_interpolated_string("".join(l.itertext())) for l in lits)



_assign_index_cache = {}

def _assign_index(scope_node, adapter):
    ent = _assign_index_cache.get(scope_node)
    if ent is None:
        by_var, allp = defaultdict(list), []
        for stmt, lhs, rhs in assignment_pairs(scope_node, adapter):
            if lhs is not None and lhs.tag.endswith("name"):
                t = (stmt, lhs, rhs)
                allp.append(t)
                by_var[name_text(lhs)].append(t)
        ent = _assign_index_cache[scope_node] = (by_var, allp)
    return ent

def find_assignments(scope_node, adapter, var_name=None):
    by_var, allp = _assign_index(scope_node, adapter)
    return list(allp) if var_name is None else list(by_var.get(var_name, ()))



def _last_literal_assignment(call_node, var_name: str, adapter):
    """
    RHS dell'ultima assegnazione di `var_name` che precede `call_node` nello stesso
    scope e che e' composta SOLO da letterali; altrimenti None.
    Non verifica la dominanza: l'ultima assegnazione testuale vince.
    """
    scope_node = enclosing_scope(call_node, adapter)
    if scope_node is None:
        unit_scope = call_node.xpath("ancestor::src:unit[1]", namespaces=NS)
        scope_node = unit_scope[0] if unit_scope else call_node
    call_key = _pos_key(call_node)
    prior = [
        (stmt, rhs) for stmt, _, rhs in find_assignments(scope_node, adapter, var_name)
        if _pos_key(stmt) < call_key and rhs is not None and _is_pure_literal_expr(rhs)
    ]
    return max(prior, key=lambda t: _pos_key(t[0]))[1] if prior else None


def _resolve_string_literals(call_node, adapter) -> list:
    """
    Letterali stringa che arrivano a `call_node`:
    1. quelli passati direttamente (func("MD5"));
    2. quelli di una variabile passata come argomento, se la sua ultima assegnazione
       precedente e' un letterale puro (alg = "MD5"; func(alg)).
    Le stringhe interpolate risolte tramite variabile vengono scartate.
    """
    lits = list(own_literals(call_node, "string"))
    arg_list = call_node.xpath("./src:argument_list", namespaces=NS)
    if not arg_list:
        return lits
    for arg in arg_list[0].xpath("./src:argument", namespaces=NS):
        expr = arg.xpath("./src:expr", namespaces=NS)
        expr = expr[0] if expr else arg
        names = expr.xpath("./src:name[not(src:index)]", namespaces=NS)
        if len(names) != 1 or len(list(expr)) != 1:
            continue
        rhs = _last_literal_assignment(call_node, "".join(names[0].itertext()).strip(), adapter)
        if rhs is None:
            continue
        for lit in rhs.xpath("self::src:literal[@type='string'] | .//src:literal[@type='string']", namespaces=NS):
            if not adapter.is_interpolated_string("".join(lit.itertext())):
                lits.append(lit)
    return lits

def _resolve_numeric_args(call_node, adapter, ns) -> list:
    """
    Estrae gli argomenti numerici di una chiamata sotto forma di coppie `(indice, valore)`.
    Rileva con precisione due scenari:
    1. Letterali diretti passati alla funzione (es. `func(1024)`).
    2. Variabili a cui è stato assegnato in precedenza un numero puro (es. `size = 1024; func(size)`).
    L'indice corrisponde alla posizione dell'argomento, permettendo validazioni mirate su parametri specifici.
    """
    values = []
    arg_list = call_node.xpath("./src:argument_list", namespaces=ns)
    if not arg_list:
        return values

    call_key = _pos_key(call_node)
    scope_node = enclosing_scope(call_node, adapter)
    if scope_node is None:
        unit_scope = call_node.xpath("ancestor::src:unit[1]", namespaces=ns)
        scope_node = unit_scope[0] if unit_scope else call_node

    for idx, arg in enumerate(arg_list[0].xpath("./src:argument", namespaces=ns)):
        expr_nodes = arg.xpath("./src:expr", namespaces=ns)
        expr = expr_nodes[0] if expr_nodes else arg

        lits = expr.xpath(".//src:literal[@type='number']", namespaces=ns)
        for lit in lits:
            v = adapter.parse_numeric_literal("".join(lit.itertext()).strip())
            if v is not None:
                values.append((idx, v))

        names = expr.xpath("./src:name[not(src:index)]", namespaces=ns)
        if names and not lits and len(names) == 1 and len(list(expr)) == 1:
            var_name = "".join(names[0].itertext()).strip()
            prior = [
                (stmt, rhs) for stmt, _, rhs in find_assignments(scope_node, adapter, var_name)
                if _pos_key(stmt) < call_key and rhs is not None and _is_pure_literal_expr(rhs)
            ]
            if prior:
                _, rhs = max(prior, key=lambda t: _pos_key(t[0]))
                for lit in rhs.xpath("descendant-or-self::src:literal[@type='number']", namespaces=ns):
                    v = adapter.parse_numeric_literal("".join(lit.itertext()).strip())
                    if v is not None:
                        values.append((idx, v))

    return values


# Helper utili per controllare i receiver dei parametri (introdotto con javascript)
def call_root_name(call_node, adapter):
    """Testa del receiver: res.status(404).send(x) -> 'res'. None se non è una chiamata a metodo."""
    node = call_node
    while (recv := adapter._chain_receiver(node, NS)) is not None:
        node = recv
    nm = node.xpath("./src:name", namespaces=NS)
    parts = nm[0].xpath("./src:name", namespaces=NS) if nm else []
    return name_text(parts[0]) if len(parts) >= 2 else None

def is_enclosing_param(node, head, adapter) -> bool:
    """True se `head`, visto da `node`, è un parametro di una funzione/lambda che
    racchiude `node` e non è nascosto da una variabile locale (shadowing).
    Si risale dalla funzione più interna verso l'esterno: la prima che lega `head`
    (come parametro o come dichiarazione locale) decide."""
    cond = " or ".join(f"self::src:{t}" for t in
                       set(adapter.function_tags()) | set(adapter.lambda_tags()))
    scope_of = scope_xp(adapter, with_lambda=True)

    for fn in reversed(node.xpath(f"ancestor::*[{cond}]", namespaces=NS)):   # dalla più interna
        is_param = any(
            name_text(n) == head
            for p in fn.xpath(adapter.parameters_xpath(), namespaces=NS)
            for n in adapter.get_parameter_name_nodes(p, NS)
        )
        # dichiarazioni locali di `head` nello scope di QUESTA fn (non delle callback annidate)
        local = [
            d for d in get_decl_index(fn).get(head, [])
            if not d.xpath("ancestor::src:parameter", namespaces=NS)
            and scope_of(d) and scope_of(d)[0] is fn
        ]
        if local:
            return False        # variabile locale: nasconde il parametro (sia suo che esterno)
        if is_param:
            return True
    return False

# --------------------------------------------------------------------------- #
# Indice di dispatch per regole
# --------------------------------------------------------------------------- #

class CompiledRuleset:
    
    def __init__(self, rules: list, adapter):
        # Appiattisce eventuali liste annidate per evitare errori di tipo
        flattened_rules = []
        for r in rules:
            if isinstance(r, list):
                flattened_rules.extend(r)
            else:
                flattened_rules.append(r)
                
        self.rules = flattened_rules
        self.forbidden_functions_index = {} 

        # Spec senza nome di funzione (non indicizzabili): valutate su ogni call. 
        # (Utile se una regola non viene scritta bene ad esempio un call_matches_ast senza la lista di call, ma basata solo sugli argomenti)    
        self.unindexed_forbidden_functions = []  

        for rule in self.rules:
            for spec in rule.get("forbidden_functions", []):
                if isinstance(spec, str):
                    self.forbidden_functions_index.setdefault(_norm(spec, adapter), []).append((rule, spec))
                elif isinstance(spec, dict):
                    stype = spec.get("type")
                    if stype == "exact_name" and spec.get("name"):
                        self.forbidden_functions_index.setdefault(_norm(spec["name"],adapter), []).append((rule, spec))
                    elif stype == "call_matches_ast" and spec.get("call"):
                        calls = spec.get("call")
                        if isinstance(calls, str):
                            calls = [calls]
                        for c in calls:
                            self.forbidden_functions_index.setdefault(_norm(c,adapter), []).append((rule, spec))
                    else:
                        self.unindexed_forbidden_functions.append((rule, spec))

    def __iter__(self):
        return iter(self.rules)

    def __len__(self):
        return len(self.rules)

def compile_rules(rules: list, adapter) -> "CompiledRuleset":
    return CompiledRuleset(rules, adapter)



class CallMatcher:
    """Equivalente di any(call_matches(n, p, adapter) for p in patterns), ma con lookup su set."""
    __slots__ = ("adapter", "exact", "suffix")

    def __init__(self, patterns, adapter):
        self.adapter = adapter
        self.exact, self.suffix = set(), set()
        for p in patterns:
            p = _norm(p, adapter)
            if p.startswith("*."):
                self.suffix.add(p[2:])
            else:
                self.exact.add(p)

    def __call__(self, name) -> bool:
        if not name:
            return False
        n = _norm(name, self.adapter)
        if n in self.exact or n in self.suffix:
            return True
        # '*.x.y' matcha qualunque coda per segmenti: 'a.b.x.y' -> 'x.y'
        i = n.find(".")
        while i != -1:
            if n[i + 1:] in self.suffix:
                return True
            i = n.find(".", i + 1)
        return False


class CallTable:
    """Come next(v for k, v in mapping.items() if call_matches(name, k)), ma con dizionari."""
    __slots__ = ("adapter", "exact", "suffix")

    def __init__(self, mapping, adapter):
        self.adapter = adapter
        self.exact, self.suffix = {}, {}
        for k, v in mapping.items():
            k = _norm(k, adapter)
            if k.startswith("*."):
                self.suffix.setdefault(k[2:], v)
            else:
                self.exact.setdefault(k, v)

    def get(self, name, default=None):
        n = _norm(name, self.adapter)
        if n in self.exact:
            return self.exact[n]
        if n in self.suffix:
            return self.suffix[n]
        i = n.find(".")
        while i != -1:
            r = self.suffix.get(n[i + 1:])
            if r is not None:
                return r
            i = n.find(".", i + 1)
        return default