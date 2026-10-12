"""
sink_matchers.py
----------------
Predicati SINK per il motore: sia i pattern semplici basati su stringa
(concat/fstring/call_arg/...) sia quelli tipizzati
(oggetto {"type": "..."}), con il relativo registro e dispatcher.
"""

from common import NS, get_call_name, call_matches, own_literals, name_text, call_arguments_match_ast



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


def _sink_call_with_var_arg(uso, spec, fstring_nodes, adapter, imports):
    """
    {"type": "call_with_var_arg", "call": ["re.sub", "sub", "executeQuery"], "literal_contains": ["SELECT"]}
    """
    target_calls = spec.get("call", [])
    if not target_calls:
        return False
    
    call_nodes = uso.xpath("ancestor::src:call", namespaces=NS)
    if not call_nodes:
        return False

    for call_node in call_nodes:
        call_name = get_call_name(call_node, adapter, imports)
        if call_name is None:
            continue

        if not any(call_matches(call_name,c, adapter) for c in target_calls):
            continue

        arg_list = call_node.xpath("./src:argument_list", namespaces=NS)
        if not arg_list:
            continue
            

        if uso not in arg_list[0].iter():
            continue

        idx = spec.get("arg_index")
        if idx is not None:
            arg = uso.xpath("ancestor::src:argument[1]", namespaces=NS)
            if not arg or arg[0].getparent() is not arg_list[0]:
                continue
            if int(arg[0].xpath("count(preceding-sibling::src:argument)", namespaces=NS)) != idx:
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


SINK_MATCHERS = {
    "method_call": _sink_method_call,
    "call_with_var_arg": _sink_call_with_var_arg,
    "matches_xpath": _sink_matches_xpath,
    "loop_condition": _sink_loop_condition,
}


def match_sink(uso, sink_spec, fstring_nodes: list, adapter, imports) -> bool:
    """
    Dispatcher: supporta pattern semplici (str) e tipizzati (dict).
    """
    is_match = False

    if isinstance(sink_spec, str):
        is_match = _sink_string_pattern(uso, sink_spec, adapter, imports, fstring_nodes)

    elif isinstance(sink_spec, dict):
        sink_type = sink_spec.get("type")

        simple_patterns = ["concat", "fstring", "return"]
        if sink_type in simple_patterns:
            is_match = _sink_string_pattern(uso, sink_type, adapter, imports, fstring_nodes)
        else:
            matcher = SINK_MATCHERS.get(sink_type)
            is_match = matcher(uso, sink_spec, fstring_nodes, adapter, imports) if matcher else False

    if not is_match:
        return False
    
    return True


def matches_any_sink(uso, sinks, fstring_nodes, adapter, imports):
    return any(match_sink(uso, s, fstring_nodes, adapter, imports) for s in sinks)