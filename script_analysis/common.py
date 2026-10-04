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

# from language_adapter import  C_TYPE_WORDS as _C_TYPE_WORDS

from collections import defaultdict

NS = {"src": "http://www.srcML.org/srcML/src", "pos": "http://www.srcML.org/srcML/position", "cpp": "http://www.srcML.org/srcML/cpp",}



#VERIFICA DELLE MACRO


def macro_map(imports) -> dict:
    return {b.local_name: b.canonical_name for b in (imports or []) if getattr(b, "is_macro", False)}

def expand_macro_name(name, macros):
    seen = set()
    while macros and name in macros and name not in seen:
        seen.add(name)
        name = macros[name]
    return name


# --------------------------------------------------------------------------- #
# Utility di base
# --------------------------------------------------------------------------- #



#RISOLVONO IL MATCH ESATTO E NON PIù PER SUFFISSO---------------------

#Le concatenazioni vengono rappresentate tutte come var1.var2.var3 per semplificazione evitanto var1->var2
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

def in_opaque_tag(node, adapter) -> bool:
    """True se `node` sta dentro un costrutto che non propaga taint (es. sizeof)."""
    tags = adapter.taint_opaque_tags()
    if not tags:
        return False
    cond = " or ".join(f"self::src:{t}" for t in tags)
    return bool(node.xpath(f"ancestor::*[{cond}]", namespaces=NS))


def scope_xpath(adapter, with_lambda=False):
    tags = adapter.function_tags() + (adapter.lambda_tags() if with_lambda else [])
    return "ancestor::*[" + " or ".join(f"self::src:{t}" for t in tags) + "][1]"

def enclosing_scope(node, adapter):
    """Nodo funzione/costruttore che racchiude `node`, o None."""
    r = node.xpath(scope_xpath(adapter), namespaces=NS)
    return r[0] if r else None

def block_exits_flow(block, adapter, imports) -> bool:
    fn = scope_xpath(adapter, with_lambda=True)
    my_scope = block.xpath(fn, namespaces=NS)
    same = lambda n: n.xpath(fn, namespaces=NS) == my_scope

    tags = " | ".join(f".//src:{t}" for t in adapter.flow_exit_tags())
    if any(same(n) for n in block.xpath(tags, namespaces=NS)):
        return True

    exits = adapter.flow_exit_calls()
    for c in block.xpath(".//src:call", namespaces=NS):
        cn = get_call_name(c, adapter, imports)
        if cn and any(call_matches(cn, e, adapter) for e in exits) and same(c):
            return True
    return False



def name_text(name_node) -> str:
    """Testo di un <name> senza i suffissi [..] della propria dichiarazione/accesso
    ('names[]' -> 'names', 'a[i].b[0]' -> 'a.b'). Per un nome semplice è identico a prima."""
    parts = name_node.xpath(
        ".//text()[count(ancestor::src:index) = count($n/ancestor::src:index)]",
        namespaces=NS, n=name_node,
    )
    return "".join(parts).strip()



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
_rhs_keys_cache = {}
_assign_pairs_cache = {}
_scope_index_cache = {}

def reset_caches():
    _call_name_cache.clear()
    _rhs_keys_cache.clear()
    _assign_pairs_cache.clear()
    _scope_index_cache.clear()


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
            if n.text:
                names[n.text].append(n)
                if macros and n.text in macros \
                   and not n.xpath("ancestor::cpp:define", namespaces=NS):
                    names[expand_macro_name(n.text, macros)].append(n)

        interp = defaultdict(list)
        for lit in scope_node.xpath(".//src:literal[@type='string']", namespaces=NS):
            testo = "".join(lit.itertext())
            if adapter.is_interpolated_string(testo):
                for v in set(adapter.get_interpolated_variables(testo)):
                    interp[v].append(lit)

        idx = (names, interp)
        _scope_index_cache[scope_node] = idx
    return idx

def assignment_pairs(scope_node, adapter) -> list:
    """(stmt, lhs, rhs) di ogni assegnazione nello scope, calcolate una volta sola."""
    pairs = _assign_pairs_cache.get(scope_node)
    if pairs is None:
        pairs = []
        for stmt in scope_node.xpath(".//src:expr_stmt | .//src:decl_stmt", namespaces=NS):
            if not adapter.is_assignment(stmt, NS):
                continue
            lhs, rhs = adapter.get_assignment_lhs_rhs(stmt, NS)
            pairs.append((stmt, lhs, rhs))
        _assign_pairs_cache[scope_node] = pairs
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



def is_sanitized(node, sanitizers: list, adapter, imports) -> bool:
    """Verifica se `node` e' passato come argomento a una delle funzioni sanitizer."""
    call_ancestors = node.xpath("ancestor::src:call", namespaces=NS)
    for call in call_ancestors:
        cname = get_call_name(call, adapter, imports)
        if cname and any(call_matches(cname, san, adapter) for san in sanitizers):
            return True
    return False


def source_present(sources: list, rhs_node, source_form: str | None = None,
                   *, adapter, imports) -> bool:
    op = adapter.member_access_operator()[0]

    # 1. Estraiamo solo i nomi completi reali
    keys = _rhs_keys_cache.get(rhs_node)
    if keys is None:
        call_names, var_names = set(), set()
        for call in rhs_node.xpath(".//src:call | self::src:call", namespaces=NS):
            cname = get_call_name(call, adapter, imports)
            if cname:
                call_names.add(cname)

        for name_node in rhs_node.xpath(".//src:name | self::src:name", namespaces=NS):
            text = "".join(name_node.itertext()).strip()
            text = text.split('[')[0].split('(')[0].strip()
            parent = name_node.getparent()
            is_inner = parent is not None and parent.tag == name_node.tag
            if not is_inner:
                text = adapter.resolve_name_text(text, imports)
            var_names.add(text)

        _rhs_keys_cache[rhs_node] = (call_names, var_names)
        call_keys, name_keys = call_names, var_names
    else:
        call_keys, name_keys = keys

    # 2. Match rigoroso tramite la tua funzione call_matches
    for source in sources:
        if source_form == "regex":
            text = "".join(rhs_node.itertext())
            if re.search(source, text):
                return True
            continue

        if source_form == "call":
            if any(call_matches(ck, source, adapter) for ck in call_keys):
                return True
            continue

        if source_form == "subscript":
            for outer_name in rhs_node.xpath(".//src:name[src:index] | self::src:name[src:index]", namespaces=NS):
                parts = outer_name.xpath("./src:name", namespaces=NS)
                dotted = op.join("".join(p.itertext()).strip() for p in parts) if parts else (outer_name.text or "").strip()
                dotted = adapter.resolve_name_text(dotted, imports)
                if call_matches(dotted, source, adapter):
                    return True
            continue

        # Nessuna forma: controlla se una qualsiasi chiamata o variabile matcha il pattern della sorgente
        if any(call_matches(k, source, adapter) for k in call_keys | name_keys):
            return True

    return False

def own_literals(call_node, lit_type: str) -> list:
    """
    Letterali di tipo `lit_type` che appartengono direttamente a `call_node`:
    stanno nella sua argument_list e la call più vicina che li racchiude è
    proprio `call_node`, non una call annidata.
    """
    return call_node.xpath(
        "./src:argument_list//src:literal[@type=$t]"
        "[count(ancestor::src:call[1] | $c) = 1]",
        namespaces=NS, t=lit_type, c=call_node,
    )


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
            actual = "".join(bool_lits[0].itertext()).strip().lower()
            if actual != str(expected).lower():
                return False
            
    #Richiede esattamente i nomi indicati
    required_names = spec.get("contains_names", [])
    if required_names:
        names = call_node.xpath(".//src:argument_list//src:name", namespaces=NS)
        found_names = ["".join(n.itertext()).strip() for n in names]

        # Estende la ricerca dentro le stringhe interpolate (es. f-string):
        
        str_lits = call_node.xpath(".//src:argument_list//src:literal[@type='string']", namespaces=NS)
        for lit in str_lits:
            testo = "".join(lit.itertext())
            if adapter.is_interpolated_string(testo):
                found_names.extend(adapter.get_interpolated_variables(testo))

        if not all(req in found_names for req in required_names):
            return False

    #Richiede almeno uno dei nomi indicati (CWE-532)
    required_names_any = spec.get("contains_any_name", [])
    if required_names_any:
        names = call_node.xpath(".//src:argument_list//src:name", namespaces=NS)
        found_names = ["".join(n.itertext()).strip() for n in names]

        str_lits = call_node.xpath(".//src:argument_list//src:literal[@type='string']", namespaces=NS)
        for lit in str_lits:
            testo = "".join(lit.itertext())
            if adapter.is_interpolated_string(testo):
                found_names.extend(adapter.get_interpolated_variables(testo))
        
        #case-insensitive e matcha sottostringhe
        lowered = [f.lower() for f in found_names]
        if not any(req.lower() in f for req in required_names_any for f in lowered):
            return False

    substr_targets = spec.get("contains_string_containing", [])
    if substr_targets:
        found_texts = [
            adapter.normalize_string_literal("".join(l.itertext()))
            for l in own_literals(call_node, "string")
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
        found_bools = ["".join(b.itertext()).strip().lower()
                    for b in own_literals(call_node, "boolean")]
        if not any(str(req).lower() in found_bools for req in banned_booleans):
            return False

    return True


def check_required_imports(rule_spec, imports) -> bool:
    required = rule_spec.get("required_imports")
    if not required:
        return True
    imports = [b for b in imports if not b.is_macro]
    imported = {b.canonical_name for b in imports} | {b.canonical_name.split(".")[0] for b in imports}
    return any(req in imported for req in required)


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


def find_assignments(scope_node, adapter, var_name: str | None = None) -> list:
    out = []
    for stmt, lhs, rhs in assignment_pairs(scope_node, adapter):
        if lhs is None or not lhs.tag.endswith("name"):
            continue
        if var_name is not None and name_text(lhs) != var_name:
            continue
        out.append((stmt, lhs, rhs))
    return out


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