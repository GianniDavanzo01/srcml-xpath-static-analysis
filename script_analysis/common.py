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


def get_call_name(call) -> str | None:
    """Ritorna il nome della funzione/metodo invocato da un nodo src:call, o None."""
    name_nodes = call.xpath("./src:name", namespaces=NS)
    if not name_nodes:
        return None
    return "".join(name_nodes[0].itertext()).strip()


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


def is_sanitized(node, sanitizers: list) -> bool:
    """Verifica se `node` e' passato come argomento a una delle funzioni sanitizer."""
    for san in sanitizers:
        if node.xpath(f"ancestor::src:call[.//src:name[last()][text()='{san}']]", namespaces=NS):
            return True
    return False


def source_present(sources: list, text: str, source_form: str | None = None, node=None) -> bool:
    """
    Richiede un confine di parola subito prima del source, per evitare match su suffissi di identificatori.
    source_form (opzionale): vincola la FORMA SINTATTICA con cui la source deve
    comparire subito dopo il prefisso:
    - "call": richiede '(' subito dopo il prefisso.
    - "subscript": richiede '[' subito dopo.
    - "regex": la regola specifica che la source è una regex cruda.
    """
    suffix = {"call": r"\(", "subscript": r"\["}.get(source_form)
    for source in sources:
        if source == "function_parameters":
            if node is not None and is_function_parameter(node):
                return True
            continue

        if source_form == "regex":
            if re.search(source, text):
                return True
            continue

        pattern = rf"\b{re.escape(source)}"
        if suffix:
            pattern += rf"(?:\.[a-zA-Z_]\w*)?\s*{suffix}"
        if re.search(pattern, text):
            return True
    return False


def call_arguments_match_ast(call_node, spec: dict) -> bool:
    """
    Motore universale AST per validare gli argomenti di una chiamata a funzione.
    Usata sia per cercare chiamate vietate (structural) sia per validare mitigazioni (safe context).
    """
    target_calls = spec.get("call", [])

    if isinstance(target_calls, str):
        target_calls = [target_calls]

    if target_calls:
        call_name = get_call_name(call_node)
        if not call_name or not any(call_name == c or call_name.endswith(f".{c}") for c in target_calls):
            return False

    arg_list_nodes = call_node.xpath("./src:argument_list", namespaces=NS)
    arguments = arg_list_nodes[0].xpath("./src:argument", namespaces=NS) if arg_list_nodes else []

    if "exact_args_count" in spec:
        if len(arguments) != spec["exact_args_count"]:
            return False
        if spec.get("no_commas_in_args"):
            args_text = "".join(arg_list_nodes[0].itertext()) if arg_list_nodes else ""
            if "," in args_text:
                return False

    if spec.get("require_bare_arg"):
        if len(arguments) == 0:
            pass  
        elif len(arguments) == 1:
            text = "".join(arguments[0].itertext()).strip()
            if not re.fullmatch(r"[a-zA-Z0-9_]*", text):
                return False
        else:
            return False

    required_names = spec.get("contains_names", [])
    if required_names:
        names = call_node.xpath(".//src:argument_list//src:name", namespaces=NS)
        found_names = ["".join(n.itertext()).strip() for n in names]
        if not all(req in found_names for req in required_names):
            return False

    banned_numbers = spec.get("contains_numbers", [])
    if banned_numbers:
        nums = call_node.xpath(".//src:argument_list//src:literal[@type='number']", namespaces=NS)
        found_nums = ["".join(n.itertext()).strip() for n in nums]
        if not any(req in found_nums for req in banned_numbers):
            return False

    args_text_contains = spec.get("args_text_contains", [])
    exact_list_element = spec.get("exact_list_element")
    
    if args_text_contains or exact_list_element:
        if not arg_list_nodes:
            return False
        args_text = "".join(arg_list_nodes[0].itertext()).replace(" ", "").replace("\n", "").replace("'", '"')
        
        if exact_list_element and f'["{exact_list_element}"]' not in args_text:
            return False
            
        if args_text_contains:
            clean_targets = [val.replace("'", '"').replace(" ", "") for val in args_text_contains]
            if not any(t in args_text for t in clean_targets):
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


def check_required_imports(unit_node, rule_spec: dict, namespaces: dict) -> bool:
    """
    Verifica se il file (rappresentato da unit_node) importa i moduli richiesti dalla regola.
    """
    required_imports = rule_spec.get("required_imports")
    
    if not required_imports:
        return True

    xpath_query = ".//src:import//src:name | .//src:import_from/src:name[1]"
    import_nodes = unit_node.xpath(xpath_query, namespaces=namespaces)
    
    imported_modules = {"".join(node.itertext()).replace(" ", "") for node in import_nodes}

    for req_import in required_imports:
        if req_import in imported_modules:
            return True
            
    return False


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


def source_arg_is_traceable_literal(call_node, scope_node, arg_index: int = 0) -> bool:
    """
    Verifica se l'argomento POSIZIONALE all'indice `arg_index` (default: il
    primo) e', direttamente o tramite un'unica assegnazione precedente nello 
    stesso scope, un letterale puro. Gli altri argomenti/kwargs vengono ignorati.
    """
    arg_list = call_node.xpath("./src:argument_list", namespaces=NS)
    if not arg_list:
        return True

    arguments = arg_list[0].xpath("./src:argument", namespaces=NS)

    def is_kwarg(a):
        return bool(a.xpath("./src:name[1]", namespaces=NS) and a.xpath("./src:operator[1][text()='=']", namespaces=NS))

    positional = [a for a in arguments if not is_kwarg(a)]
    if arg_index >= len(positional):
        return False  

    target_arg = positional[arg_index]
    expr_nodes = target_arg.xpath("./src:expr", namespaces=NS)
    expr = expr_nodes[0] if expr_nodes else target_arg
    call_key = _pos_key(call_node)

    if _is_pure_literal_expr(expr):
        return True

    names = expr.xpath("./src:name[not(src:index)]", namespaces=NS)
    if len(names) != 1 or len(expr) != 1:
        return False

    var_name = "".join(names[0].itertext()).strip()
    candidates = scope_node.xpath(
        f".//src:expr_stmt[src:expr/src:name[1][text()='{var_name}']"
        f" and src:expr/src:operator[text()='=']]",
        namespaces=NS,
    )
    prior = [c for c in candidates if _pos_key(c) < call_key]
    if not prior:
        return False

    last_assign = max(prior, key=_pos_key)
    op = last_assign.xpath(".//src:operator[text()='='][1]", namespaces=NS)
    rhs = op[0].xpath("./following-sibling::*[1]", namespaces=NS) if op else []
    return bool(rhs and _is_pure_literal_expr(rhs[0]))