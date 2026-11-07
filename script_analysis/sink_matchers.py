"""
sink_matchers.py
----------------
Predicati SINK per il motore: sia i pattern semplici basati su stringa
(concat/fstring/call_arg/...) sia quelli tipizzati
(oggetto {"type": "..."}), con il relativo registro e dispatcher.
"""

from common import NS, get_call_name, call_matches, own_literals, name_text, call_root_name, is_enclosing_param, CallMatcher

from lxml import etree
_X = lambda s: etree.XPath(s, namespaces=NS)

_X_ANC_CALL = _X("ancestor::src:call")
_X_ANC_ARG  = _X("ancestor::src:argument[1]")
_X_ARG_POS  = _X("count(preceding-sibling::src:argument)")

def _sink_string_pattern(uso, pattern_name: str, adapter, imports, fstring_nodes) -> bool:
    """
    Pattern strutturali basati sul TIPO di utilizzo della variabile.
    Totalmente guidati dal LanguageAdapter.
    """
    if pattern_name == "concat":
        ops = adapter.string_concat_operators()
        if not ops:
            return False
        op_xpath = " | ".join([f"preceding-sibling::src:operator[1][text()='{op}']" for op in ops]) + " | " + \
                   " | ".join([f"following-sibling::src:operator[1][text()='{op}']" for op in ops])
        return bool(uso.xpath(op_xpath, namespaces=NS))

    if pattern_name == "fstring":

        if fstring_nodes is not None:
            return uso in fstring_nodes
        return False

    if pattern_name == "return":
        return uso.xpath("boolean(ancestor::src:return[1] and not(ancestor::src:call))", namespaces=NS)
    
    return False


def _sink_method_call(uso, spec, fstring_nodes, adapter, imports) -> bool:
    """{"type": "method_call", "method": "read" | ["read", "*.Tipo.read"],
        "arg_contains": [".com/"]}

    True se la variabile taintata `uso` è il receiver (testa della catena) di
    una chiamata di metodo tra quelle indicate.
      "read"        -> uguaglianza sul solo nome del metodo, ignora il tipo
      "*.Tipo.read" -> match sul nome canonico risolto della call (call_matches);
                       richiede che l'adapter risolva il tipo del receiver
    `arg_contains` (opzionale, per l'intera spec): almeno un letterale stringa
    della call contiene uno dei valori (case-insensitive).
    """
    methods = spec.get("method")
    if not methods:
        return False
    if isinstance(methods, str):
        methods = [methods]

    ops_xpath = " or ".join(f"text()='{o}'" for o in adapter.member_access_operator())

    # uso deve essere la testa del receiver, non un membro (obj.data.read)
    if uso.xpath(f"preceding-sibling::*[1][self::src:operator and ({ops_xpath})]", namespaces=NS):
        return False

    method_nodes = uso.xpath(
        f"following-sibling::src:operator[1][{ops_xpath}]/following-sibling::src:name[1]",
        namespaces=NS,
    )
    if not method_nodes:
        return False
    found = name_text(method_nodes[0]).strip()

    # call valida solo se il <name> composto (x.read) è il nome chiamato
    anc = uso.xpath("parent::src:name/parent::src:call", namespaces=NS)
    call_node = anc[0] if anc else None
    cn = get_call_name(call_node, adapter, imports) if call_node is not None else None

    def _hit(m):
        m = adapter.normalize_member_access(m)
        if "." in m or m.startswith("*"):
            return bool(cn) and call_matches(cn, m, adapter)
        return found == m

    if not any(_hit(m) for m in methods):
        return False

    n_args = (len(call_node.xpath("./src:argument_list/src:argument", namespaces=NS)) if call_node is not None else None)
    
    if "arg_count_max" in spec and (n_args is None or n_args > spec["arg_count_max"]):
        return False
    if "arg_count_min" in spec and (n_args is None or n_args < spec["arg_count_min"]):
        return False

    arg_calls = spec.get("arg_call_matches")
    if arg_calls:
        if call_node is None:
            return False
        ok = False
        for c in call_node.xpath("./src:argument_list//src:call", namespaces=NS):
            cn2 = get_call_name(c, adapter, imports)
            if cn2 and any(call_matches(cn2, p, adapter) for p in arg_calls):
                ok = True
                break
        if not ok:
            return False

    arg_contains = spec.get("arg_contains", [])
    if not arg_contains:
        return True
    if call_node is None:
        return False
    return any(
        any(v.upper() in adapter.normalize_string_literal("".join(l.itertext())).upper()
            for v in arg_contains)
        for l in own_literals(call_node, "string")
    )

#Helper per le funzioni di callback
def _inside_callback_arg(uso, call_node, adapter) -> bool:
    """
    Ritorna True se `uso` si trova dentro il corpo di una funzione o lambda
    passata come argomento a `call_node`.
    """
    tags = set(adapter.function_tags()) | set(adapter.lambda_tags())
    cond = " or ".join(f"self::src:{t}" for t in tags)
    
    # Prende tutte le funzioni/lambda tra `uso` e la radice del documento
    for fn in uso.xpath(f"ancestor::*[{cond}]", namespaces=NS):
        # Risale alla call a cui questa funzione fa da argomento
        parent_call = fn.xpath(
            "ancestor::src:argument[1]/parent::src:argument_list/parent::src:call",
            namespaces=NS
        )
        if parent_call and parent_call[0] is call_node:
            return True
            
    return False


_SPEC_MATCHER = {}
def _spec_matcher(spec, adapter):
    k = (id(spec), adapter.name)
    m = _SPEC_MATCHER.get(k)
    if m is None:
        m = _SPEC_MATCHER[k] = CallMatcher(spec.get("call", []), adapter)
    return m

def _sink_call_with_var_arg(uso, spec, fstring_nodes, adapter, imports):
    """
    {"type": "call_with_var_arg", "call": ["re.sub", "sub", "executeQuery"], "literal_contains": ["SELECT"]}
    """
    target_calls = spec.get("call", [])
    if not target_calls:
        return False
    
    call_nodes = _X_ANC_CALL(uso)
    if not call_nodes:
        return False

    for call_node in call_nodes:
        call_name = get_call_name(call_node, adapter, imports)
        if call_name is None:
            continue

        if not _spec_matcher(spec, adapter)(call_name):
            continue

        if spec.get("receiver_is_param"):
            head = call_root_name(call_node, adapter)
            if not head or not is_enclosing_param(call_node, head, adapter):
                continue

        arg_list = call_node.xpath("./src:argument_list", namespaces=NS)
        if not arg_list:
            continue
            

        # if uso not in arg_list[0].iter():
        #     continue
        if arg_list[0] not in uso.iterancestors():
            continue

        if _inside_callback_arg(uso, call_node, adapter):
                continue

        idx = spec.get("arg_index")
        if idx is not None:
            arg = _X_ANC_ARG(uso)  
            if not arg or arg[0].getparent() is not arg_list[0]:
                continue
            if int(_X_ARG_POS(arg[0])) != idx:
                continue

        literal_contains = spec.get("literal_contains", [])
        if not literal_contains:
            return True 


        string_literals = own_literals(call_node, "string")
        
        for literal_node in string_literals:
            raw_text = "".join(literal_node.itertext())

            clean_text = adapter.normalize_string_literal(raw_text).upper()
            

            if any(val.upper() in clean_text for val in literal_contains):
                return True

    return False


def _sink_matches_xpath(uso, spec: dict, fstring_nodes: list, adapter, imports) -> bool:
    """{"type": "matches_xpath", "xpath": "./src:index and (ancestor::src:argument or ancestor::src:index)"}"""
    xpath_query = spec.get("xpath")
    if not xpath_query:
        return False
        
    return bool(uso.xpath(xpath_query, namespaces=NS))


def _sink_loop_condition(uso, spec: dict, fstring_nodes: list, adapter, imports) -> bool:
    """{"type": "loop_condition"}
    Verifica se la variabile taintata viene usata nel costrutto di controllo di un ciclo.
    Copre le condizioni classiche (while, do, for C/Java) e gli iteratori (for Python/Java).
    """
    xpath_query = (
    "ancestor::src:condition[parent::src:while or parent::src:do or parent::src:control/parent::src:for] | "
    "ancestor::src:control[parent::src:for]"
    )
    return bool(uso.xpath(xpath_query, namespaces=NS))


def _sink_assigned_property(uso, spec, fstring_nodes, adapter, imports):
    """{"type": "assigned_property", "name": ["*.innerHTML", "*.outerHTML"]}
    uso e' il valore assegnato: el.innerHTML = <uso>"""
    stmt = uso.xpath("ancestor::src:expr_stmt[1]", namespaces=NS)
    if not stmt:
        return False
    op = stmt[0].xpath("./src:expr/src:operator[text()='=' or text()='+='][1]", namespaces=NS)
    if not op:
        return False
    lhs = op[0].xpath("preceding-sibling::*[not(self::src:comment)][1]", namespaces=NS)
    if not lhs or not lhs[0].tag.endswith("}name") or uso in lhs[0].iter():
        return False
    if op[0] not in uso.xpath("ancestor-or-self::*/preceding-sibling::*", namespaces=NS):
        return False                                   # l'uso deve stare DOPO l'operatore
    target = adapter.resolve_name_text(name_text(lhs[0]), imports, node=lhs[0])
    return any(call_matches(target, n, adapter) for n in spec.get("name", []))


SINK_MATCHERS = {
    "method_call": _sink_method_call,
    "call_with_var_arg": _sink_call_with_var_arg,
    "matches_xpath": _sink_matches_xpath,
    "loop_condition": _sink_loop_condition,
    "assigned_property": _sink_assigned_property
}


SIMPLE_SINKS = frozenset({"concat", "fstring", "return"})

def match_sink(uso, sink_spec, fstring_nodes, adapter, imports) -> bool:
    if isinstance(sink_spec, str):
        return _sink_string_pattern(uso, sink_spec, adapter, imports, fstring_nodes)
    if isinstance(sink_spec, dict):
        t = sink_spec.get("type")
        if t in SIMPLE_SINKS:
            return _sink_string_pattern(uso, t, adapter, imports, fstring_nodes)
        m = SINK_MATCHERS.get(t)
        return bool(m and m(uso, sink_spec, fstring_nodes, adapter, imports))
    return False


def matches_any_sink(uso, sinks, fstring_nodes, adapter, imports):
    return any(match_sink(uso, s, fstring_nodes, adapter, imports) for s in sinks)