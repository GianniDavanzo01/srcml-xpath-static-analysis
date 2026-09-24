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

from language_adapter import PythonAdapter

NS = {"src": "http://www.srcML.org/srcML/src", "pos": "http://www.srcML.org/srcML/position"}


# --------------------------------------------------------------------------- #
# Utility di base
# --------------------------------------------------------------------------- #

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

def get_call_name(call, adapter=None, imports=None) -> str | None:
    name_nodes = call.xpath("./src:name", namespaces=NS)
    if not name_nodes:
        return None
    raw = "".join(name_nodes[0].itertext()).strip()
    if adapter is not None and imports is not None:
        return adapter.resolve_call_name(call, NS, imports)
    return raw


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



def is_sanitized(node, sanitizers: list, adapter=None, imports=None) -> bool:
    """Verifica se `node` e' passato come argomento a una delle funzioni sanitizer."""
    call_ancestors = node.xpath("ancestor::src:call", namespaces=NS)
    for call in call_ancestors:
        cname = get_call_name(call, adapter, imports)
        if cname and any(cname == san or cname.endswith(f".{san}") for san in sanitizers):
            return True
    return False

def source_present(sources: list, rhs_node, source_form: str | None = None,
                    node=None, adapter=None, imports=None) -> bool:
    """
    Verifica se una delle source compare nel RHS (rhs_node) in forma
    strutturale, navigando l'AST invece di fare match testuale su una
    stringa appiattita.
    source_form (opzionale):
    - "call": la source deve essere il nome di una <src:call> dentro rhs_node.
    - "subscript": la source deve essere un <src:name> seguito da <src:index>.
    - "regex": la source è una regex cruda, valutata sul testo di rhs_node.
    - assente: basta che la source compaia come <src:name>, in qualunque forma.
    """
    op = adapter.member_access_operator()[0] if adapter and adapter.member_access_operator() else "."

    for source in sources:
        if source == "function_parameters":
            if node is not None and is_function_parameter(node):
                return True
            continue

        if source_form == "regex":
            text = "".join(rhs_node.itertext())
            if re.search(source, text):
                return True
            continue

        if source_form == "call":
            for call in rhs_node.xpath(".//src:call | self::src:call", namespaces=NS):
                cname = get_call_name(call, adapter, imports)
                if cname and (cname == source or cname.endswith(f".{source}")):
                    return True
            continue

        if source_form == "subscript":
            for outer_name in rhs_node.xpath(".//src:name[src:index] | self::src:name[src:index]", namespaces=NS):
                parts = outer_name.xpath("./src:name", namespaces=NS)
                dotted = op.join("".join(p.itertext()).strip() for p in parts) if parts else (outer_name.text or "").strip()
                if dotted == source or dotted.endswith(f".{source}"):
                    return True
            continue

        # nessuna forma specificata: il nome compare ovunque, invocato o no
        for name_node in rhs_node.xpath(".//src:name | self::src:name", namespaces=NS):
            name_text = "".join(name_node.itertext()).strip()

            #Bisogna eliminare le parentesi per fare match sul nome della funzione
            clean_name = name_text.split('[')[0].split('(')[0].strip()

            if clean_name == source or clean_name.endswith(f".{source}") or clean_name.startswith(f"{source}."):
                return True

    return False


def call_arguments_match_ast(call_node, spec: dict, adapter=None, imports=None) -> bool:
    """
    Motore universale AST per validare gli argomenti di una chiamata a funzione.
    Usata sia per cercare chiamate vietate (structural) sia per validare mitigazioni (safe context).
    """
    target_calls = spec.get("call", [])

    if isinstance(target_calls, str):
        target_calls = [target_calls]

    if target_calls:
        # call_name = get_call_name(call_node)
        call_name = get_call_name(call_node, adapter, imports)
        if not call_name or not any(call_name == c or call_name.endswith(f".{c}") for c in target_calls):
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
            if adapter is not None and adapter.is_kwarg(arg, NS):
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
        # srcML non le scompone in <src:name> figli, quindi senza questo un
        # nome usato solo dentro un'interpolazione sarebbe invisibile qui.
        if adapter is not None:
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

        if adapter is not None:
            str_lits = call_node.xpath(".//src:argument_list//src:literal[@type='string']", namespaces=NS)
            for lit in str_lits:
                testo = "".join(lit.itertext())
                if adapter.is_interpolated_string(testo):
                    found_names.extend(adapter.get_interpolated_variables(testo))

        if not any(req in found_names for req in required_names_any):
            return False

    substr_targets = spec.get("contains_string_containing", [])
    if substr_targets:
        str_lits = call_node.xpath(".//src:argument_list//src:literal[@type='string']", namespaces=NS)
        found_texts = ["".join(l.itertext()).strip() for l in str_lits]
        if not any(any(t in txt for txt in found_texts) for t in substr_targets):
            return False

    banned_numbers = spec.get("contains_numbers", [])
    if banned_numbers:
        _adapter = adapter or PythonAdapter()
        found_values = {v for _, v in _resolve_numeric_args(call_node, _adapter, NS)}
        found_texts = [str(v) for v in found_values]

        def _num_ok(req):
            return req in found_texts or _adapter.parse_numeric_literal(str(req)) in found_values

        if not any(_num_ok(req) for req in banned_numbers):
            return False

    if "arg_less_than" in spec:
        limit_spec = spec["arg_less_than"]
        _adapter = adapter or PythonAdapter()
        found_pairs = _resolve_numeric_args(call_node, _adapter, NS)

        if isinstance(limit_spec, dict):
            # Forma posizionale: {"index": N, "value": X} -> controlla SOLO
            # l'argomento all'indice N, non un numero qualsiasi nella call.
            target_index = limit_spec.get("index")
            limit = limit_spec.get("value")
            found_less_than_limit = any(
                idx == target_index and v < limit for idx, v in found_pairs
            )
        else:
            # Forma scalare originale: qualunque argomento numerico sotto soglia.
            limit = limit_spec
            found_less_than_limit = any(v < limit for _, v in found_pairs)

        if not found_less_than_limit:
            return False

    banned_booleans = spec.get("contains_booleans", [])
    if banned_booleans:
        bools = call_node.xpath(".//src:argument_list//src:literal[@type='boolean']", namespaces=NS)
        found_bools = ["".join(b.itertext()).strip().lower() for b in bools]
        if not any(str(req).lower() in found_bools for req in banned_booleans):
            return False

    return True


def is_function_parameter(node) -> bool:
    """
    Verifica se il nodo corrente (es. un identificativo di variabile) 
    corrisponde a uno dei parametri definiti nella firma della funzione circostante.
    """
    if node is None:
        return False
        
    node_text = "".join(node.xpath(".//text()")).strip()
    if not node_text:
        return False

    param_names = node.xpath(
        "ancestor::src:function[1]//src:parameter_list//src:name/text()", 
        namespaces=NS
    )
    
    return node_text in param_names


def check_required_imports(unit_node, rule_spec: dict, namespaces: dict, imports=None) -> bool:
    required_imports = rule_spec.get("required_imports")
    if not required_imports:
        return True

    if imports is not None:
        imported_modules = {b.canonical_name for b in imports} | {b.canonical_name.split(".")[0] for b in imports}
    else:
        xpath_query = ".//src:import//src:name"
        imported_modules = {"".join(n.itertext()).replace(" ", "")
                             for n in unit_node.xpath(xpath_query, namespaces=namespaces)}

    return any(req in imported_modules for req in required_imports)


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
    """
    Ritorna gli statement di assegnazione (expr_stmt/decl_stmt) nello scope
    dato, tramite adapter.is_assignment/get_assignment_lhs_rhs invece di
    XPath hardcoded su '='. Se var_name e' fornito, filtra solo le
    assegnazioni il cui LHS e' quella variabile.
    Ogni elemento ritornato e' una tupla (stmt, lhs_node, rhs_node).
    """
    out = []
    for stmt in scope_node.xpath(".//src:expr_stmt | .//src:decl_stmt", namespaces=NS):
        if not adapter.is_assignment(stmt, NS):
            continue
        lhs, rhs = adapter.get_assignment_lhs_rhs(stmt, NS)
        if lhs is None or not lhs.tag.endswith("name"):
            continue
        if var_name is not None and "".join(lhs.itertext()).strip() != var_name:
            continue
        out.append((stmt, lhs, rhs))
    return out


def _resolve_numeric_args(call_node, adapter, ns) -> list:
    """
    Numeri trovati negli argomenti di call_node, come coppie (indice, valore):
    letterali diretti, oppure variabili risolte tramite l'ultima assegnazione
    precedente nello stesso scope, solo se quell'assegnazione è un letterale
    numerico puro (nessuna call, nessun'altra variabile in mezzo) - evita di
    leggere un numero "a caso" dentro un'espressione composta come RHS.
    L'indice è la posizione dell'ARGOMENTO (non del singolo letterale), utile
    per validare puntualmente un parametro specifico di una call (es. il
    secondo argomento di RSA_generate_key_ex, non un esponente qualsiasi).
    """
    values = []
    arg_list = call_node.xpath("./src:argument_list", namespaces=ns)
    if not arg_list:
        return values

    call_key = _pos_key(call_node)
    scope_candidates = call_node.xpath("ancestor::src:function[1] | ancestor::src:unit[1]", namespaces=ns)
    scope_node = scope_candidates[0] if scope_candidates else call_node

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
    
    def __init__(self, rules: list):
        # Appiattisce eventuali liste annidate per evitare errori di tipo
        flattened_rules = []
        for r in rules:
            if isinstance(r, list):
                flattened_rules.extend(r)
            else:
                flattened_rules.append(r)
                
        self.rules = flattened_rules
        self.forbidden_functions_index = {}   # nome -> [(rule, spec), ...]
        self.forbidden_names_index = {}       # nome -> [rule, ...]
        self.forbidden_name_prefixes = []     # [(prefix, rule), ...]
        self.unindexed_forbidden_functions = [] 

        for rule in self.rules:
            for spec in rule.get("forbidden_functions", []):
                if isinstance(spec, str):
                    self.forbidden_functions_index.setdefault(spec, []).append((rule, spec))
                elif isinstance(spec, dict):
                    stype = spec.get("type")
                    if stype == "exact_name" and spec.get("name"):
                        self.forbidden_functions_index.setdefault(spec["name"], []).append((rule, spec))
                    elif stype == "call_matches_ast" and spec.get("call"):
                        calls = spec.get("call")
                        if isinstance(calls, str):
                            calls = [calls]
                        for c in calls:
                            self.forbidden_functions_index.setdefault(c, []).append((rule, spec))
                    else:
                        self.unindexed_forbidden_functions.append((rule, spec))

            for name in rule.get("forbidden_names", []):
                self.forbidden_names_index.setdefault(name, []).append(rule)

            for prefix in rule.get("forbidden_name_prefixes", []):
                self.forbidden_name_prefixes.append((prefix, rule))

    def __iter__(self):
        return iter(self.rules)

    def __len__(self):
        return len(self.rules)

def compile_rules(rules: list) -> "CompiledRuleset":
    return CompiledRuleset(rules)