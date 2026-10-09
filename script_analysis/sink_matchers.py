"""
sink_matchers.py
----------------
Predicati SINK per il motore: sia i pattern semplici basati su stringa
(concat/fstring/call_arg/...) sia quelli tipizzati
(oggetto {"type": "..."}), con il relativo registro e dispatcher.
"""

from common import NS, get_call_name, call_matches, own_literals, name_text



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


def _sink_method_call(uso, spec: dict, fstring_nodes: list, adapter, imports) -> bool:
    """{"type": "method_call", "method": "endswith", "arg_contains": [".com/"]}
        Cerca l'uso della variabile taintata uso come receiver (chiamante) di uno specifico metodo.
    """
    method = spec.get("method")
    if not method:
        return False

    ops = adapter.member_access_operator()
    ops_xpath = " or ".join(f"text()='{op}'" for op in ops)

    method_nodes = uso.xpath(
        f"following-sibling::src:operator[1][{ops_xpath}]/following-sibling::src:name[1]",
        namespaces=NS,
    )

    # 1. Utilizzo name_text() per evitare inclusioni di sottonodi
    if not method_nodes or name_text(method_nodes[0]).strip() != method:
        return False

    arg_contains = spec.get("arg_contains", [])
    if not arg_contains:
        return True

    call_node = uso.xpath("ancestor::src:call[1]", namespaces=NS)
    if not call_node:
        return False

    # 2. Confiniamo la ricerca dei letterali ESCLUSIVAMENTE a questa chiamata
    string_literals = own_literals(call_node[0], "string")
    
    for literal_node in string_literals:
        raw_text = "".join(literal_node.itertext())
        # 3. Normalizzazione e check case-insensitive coerente col resto del motore
        clean_text = adapter.normalize_string_literal(raw_text).upper()
        
        if any(val.upper() in clean_text for val in arg_contains):
            return True
            
    return False


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
        "ancestor::src:condition[ancestor::src:while or ancestor::src:do or ancestor::src:for] | "
        "ancestor::src:control[ancestor::src:for]"
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