"""
sink_matchers.py
----------------
Predicati SINK per il motore: sia i pattern semplici basati su stringa
(concat/fstring/call_arg/method_chain/colon_suffix/...) sia quelli tipizzati
(oggetto {"type": "..."}), con il relativo registro e dispatcher.
"""

from common import NS, get_call_name


def _sink_string_pattern(uso, pattern_name: str, fstring_nodes: list) -> bool:
    """
    Pattern semplici basati solo sul TIPO di utilizzo della variabile,
    senza guardare metodo/argomento specifici.
    """
    if pattern_name == "concat":
        op_xpath = (
            "preceding-sibling::src:operator[1][text()='+' or text()='%'] | "
            "following-sibling::src:operator[1][text()='+' or text()='%']"
        )
        return bool(uso.xpath(op_xpath, namespaces=NS))

    if pattern_name == "fstring":
        return uso in fstring_nodes

    if pattern_name == "call_arg":
        return bool(uso.xpath("ancestor::src:argument", namespaces=NS))

    if pattern_name == "method_chain":
        has_dot = uso.xpath("following-sibling::src:operator[1][text()='.']", namespaces=NS)
        is_method_call = uso.xpath("parent::src:name/parent::src:call", namespaces=NS)
        return bool(has_dot and is_method_call)

    if pattern_name == "colon_suffix":
        if uso.xpath("following-sibling::src:operator[1][text()=':']", namespaces=NS):
            return True
        if not uso.xpath("following-sibling::*"):
            parent = uso.getparent()
            if parent is not None and parent.tag.endswith("}expr"):
                tail = (parent.tail or "").strip()
                if tail.startswith(":"):
                    return True
        return False
    
    if pattern_name == "reassign":                       
        return bool(uso.xpath("following-sibling::src:operator[1][text()='=']", namespaces=NS))

    if pattern_name == "return":
        return uso.xpath("boolean(ancestor::src:return[1] and not(ancestor::src:call))", namespaces=NS)
    
    if pattern_name == "any_use":
        return True
    
    if pattern_name == "assign_rhs":
        if uso.xpath("ancestor::src:call", namespaces=NS):
            return False
        is_rhs = bool(uso.xpath(
            "parent::src:expr[preceding-sibling::src:operator[1][text()='=']] | "
            "self::src:name[preceding-sibling::src:operator[1][text()='=']]",
            namespaces=NS,
        ))
        is_in_args = bool(uso.xpath("ancestor::src:argument_list", namespaces=NS))
        return is_rhs and not is_in_args

    return False


def _sink_method_call(uso, spec: dict, fstring_nodes: list) -> bool:
    """{"type": "method_call", "method": "endswith", "arg_contains": [".com/"]}
        Cerca l'uso della variabile taintata uso come receiver (chiamante) di uno specifico metodo.
    """
    method = spec.get("method")
    if not method:
        return False

    method_nodes = uso.xpath(
        "following-sibling::src:operator[1][text()='.']/following-sibling::src:name[1]",
        namespaces=NS,
    )
    if not method_nodes or "".join(method_nodes[0].itertext()).strip() != method:
        return False

    arg_contains = spec.get("arg_contains", [])
    if not arg_contains:
        return True

    call_node = uso.xpath("ancestor::src:call[1]", namespaces=NS)
    if not call_node:
        return False
    arg_list = call_node[0].xpath("./src:argument_list", namespaces=NS)
    if not arg_list:
        return False

    args_text = "".join(arg_list[0].itertext())
    return any(val in args_text for val in arg_contains)


def _sink_call_with_var_arg(uso, spec: dict, fstring_nodes: list) -> bool:
    """{"type": "call_with_var_arg", "call": ["re.sub", "sub"], "literal_contains": ["<script", "javascript:"]}"""
    target_calls = spec.get("call", [])
    if not target_calls:
        return False

    call_node = uso.xpath("ancestor::src:call[1]", namespaces=NS)
    if not call_node:
        return False

    call_name = get_call_name(call_node[0])
    if call_name is None:
        return False
    if not any(call_name == c or call_name.endswith(f".{c}") for c in target_calls):
        return False

    literal_contains = spec.get("literal_contains", [])
    if not literal_contains:
        return True

    arg_list = call_node[0].xpath("./src:argument_list", namespaces=NS)
    if not arg_list:
        return False
    args_text = "".join(arg_list[0].itertext())
    return any(val in args_text for val in literal_contains)


def _sink_flat_call_arg(uso, spec: dict, fstring_nodes: list) -> bool:
    """{"type": "flat_call_arg"}
        Rileva se la variabile taintata è passata come argomento a una call, purché quella call non contenga altre call annidate 
        tra i suoi argomenti (nessuna coppia di parentesi extra oltre a quella della call stessa).
    """
    call = uso.xpath("ancestor::src:call[1]", namespaces=NS)
    if not call:
        return False
    call = call[0]

    arg_list = call.xpath("./src:argument_list", namespaces=NS)
    if not arg_list:
        return False
    arg_list = arg_list[0]

    nested_calls = arg_list.xpath(".//src:call", namespaces=NS)
    return not nested_calls


def _sink_return_method_call(uso, spec: dict, fstring_nodes: list) -> bool:
    """{"type": "return_method_call", "method": "match"}"""
    method = spec.get("method")
    if not method:
        return False

    method_nodes = uso.xpath(
        "following-sibling::src:operator[1][text()='.']/following-sibling::src:name[1]",
        namespaces=NS,
    )
    if not method_nodes or "".join(method_nodes[0].itertext()).strip() != method:
        return False

    call_node = uso.xpath("ancestor::src:call[1]", namespaces=NS)
    if not call_node:
        return False

    is_returned = call_node[0].xpath("parent::src:expr/parent::src:return", namespaces=NS)
    
    return bool(is_returned)


def _sink_receiver_of_method_with_kwarg(uso, spec: dict, fstring_nodes: list) -> bool:
    """{"type": "receiver_of_method_with_kwarg", "method": "add_argument", "kwargs": {"required": "True"}}"""
    method_name = spec.get("method")
    kwargs = spec.get("kwargs", {})
    if not method_name or not kwargs:
        return False

    call_node = uso.xpath("ancestor::src:call[1]", namespaces=NS)
    if not call_node:
        return False
        
    call_name_nodes = call_node[0].xpath("./src:name", namespaces=NS)
    if not call_name_nodes:
        return False
    
    call_name_text = "".join(call_name_nodes[0].itertext()).replace(" ", "").replace("\n", "")
    if not call_name_text.endswith(f".{method_name}"):
        return False
        
    arg_list_nodes = call_node[0].xpath("./src:argument_list", namespaces=NS)
    if not arg_list_nodes:
        return False
        
    arg_text = "".join(arg_list_nodes[0].itertext()).replace(" ", "").replace("\n", "")
    
    for k, v in kwargs.items():
        target = f"{k}={v}"
        if target not in arg_text:
            return False
            
    return True


def _sink_argument_to(uso, spec: dict, fstring_nodes: list) -> bool:
    """{"type": "argument_to", "functions": ["print"]}
        la funzione verifica che uso sia argomento di una call il cui nome è esattamente uno di functions
    """
    functions = spec.get("functions", [])
    if not functions:
        return False

    call_node = uso.xpath("ancestor::src:call[1]", namespaces=NS)
    if not call_node:
        return False
        
    call_name_nodes = call_node[0].xpath("./src:name", namespaces=NS)
    if not call_name_nodes:
        return False
        
    call_name = "".join(call_name_nodes[0].itertext()).replace(" ", "").replace("\n", "")
    
    return call_name in functions
    

def _sink_method_call_in_if(uso, spec: dict, fstring_nodes: list) -> bool:
    """{"type": "method_call_in_if", "method": "locked"}"""
    method = spec.get("method")
    if not method:
        return False

    method_nodes = uso.xpath(
        "following-sibling::src:operator[1][text()='.']/following-sibling::src:name[1]",
        namespaces=NS,
    )
    if not method_nodes or "".join(method_nodes[0].itertext()).strip() != method:
        return False

    in_condition = uso.xpath("ancestor::src:if_stmt//src:condition", namespaces=NS)
    
    return bool(in_condition)


def _sink_keyword_argument(uso, spec: dict, fstring_nodes: list) -> bool:
    """{"type": "keyword_argument", "keyword": "env"}"""
    keyword = spec.get("keyword")
    if not keyword:
        return False

    parent_arg = uso.xpath("ancestor::src:argument[1]", namespaces=NS)
    if parent_arg:
        arg_node = parent_arg[0]
        name_nodes = arg_node.xpath("./src:name[1]", namespaces=NS)
        op_nodes = arg_node.xpath("./src:operator[1]", namespaces=NS)
        
        if name_nodes and op_nodes:
            kw_name = "".join(name_nodes[0].itertext()).strip()
            op = "".join(op_nodes[0].itertext()).strip()
            
            if kw_name == keyword and op == "=":
                return True
                
    return False


def _sink_subscript_key_assign_rhs(uso, spec: dict, fstring_nodes: list) -> bool:
    """{"type": "subscript_key_assign_rhs"}"""
    rhs_holder = uso.xpath(
        "ancestor-or-self::*[preceding-sibling::src:operator[1][text()='=']]",
        namespaces=NS,
    )
    if not rhs_holder or uso.xpath("ancestor::src:argument_list", namespaces=NS):
        return False

    op = rhs_holder[0].xpath("preceding-sibling::src:operator[1]", namespaces=NS)[0]
    lhs_nodes = op.xpath("preceding-sibling::*", namespaces=NS)
    if not lhs_nodes:
        return False
    lhs = lhs_nodes[-1] 

    if not lhs.tag.endswith("name"):
        return False

    return bool(lhs.xpath("./src:index//src:literal[@type='string']", namespaces=NS))


def _sink_subscript_usage(uso, spec: dict, fstring_nodes: list) -> bool:
    """
    Motore universale per i sink basati su subscript.
    Accorpa: assign_or_concat, colon_suffix, return, method_call.
    """
    if not uso.xpath("following-sibling::src:index[1]", namespaces=NS):
        return False

    outer = uso.xpath("parent::src:name[1]", namespaces=NS)
    target = outer[0] if outer else uso

    subtype = spec.get("subtype")
    if not subtype:
        subtype = spec.get("type", "").replace("subscript_", "")

    if subtype == "assign_or_concat":
        op = target.xpath("preceding-sibling::src:operator[1]", namespaces=NS)
        if not op:
            return False
        op_text = "".join(op[0].itertext()).strip()
        return op_text.endswith("+") or op_text.endswith("=")
        
    elif subtype == "colon_suffix":
        if target.xpath("following-sibling::src:operator[1][text()=':']", namespaces=NS):
            return True
        if not target.xpath("following-sibling::*"):
            parent = target.getparent()
            if parent is not None and parent.tag.endswith("}expr"):
                tail = (parent.tail or "").strip()
                if tail.startswith(":"):
                    return True
        return False
        
    elif subtype == "return":
        return bool(target.xpath("boolean(ancestor::src:return[1] and not(ancestor::src:call))", namespaces=NS))
        
    elif subtype == "method_call":
        return bool(target.xpath("following-sibling::src:operator[1][text()='.']", namespaces=NS))
        
    return False


def _sink_matches_xpath(uso, spec: dict, fstring_nodes: list) -> bool:
    """{"type": "matches_xpath", "xpath": "./src:index and (ancestor::src:argument or ancestor::src:index)"}"""
    xpath_query = spec.get("xpath")
    if not xpath_query:
        return False
        
    return bool(uso.xpath(xpath_query, namespaces=NS))


SINK_MATCHERS = {
    "method_call": _sink_method_call,
    "call_with_var_arg": _sink_call_with_var_arg,
    "flat_call_arg": _sink_flat_call_arg,
    "return_method_call": _sink_return_method_call,
    "argument_to": _sink_argument_to,
    "receiver_of_method_with_kwarg": _sink_receiver_of_method_with_kwarg,
    "method_call_in_if": _sink_method_call_in_if,
    "keyword_argument": _sink_keyword_argument,
    "subscript_key_assign_rhs": _sink_subscript_key_assign_rhs,
    "subscript_assign_or_concat": _sink_subscript_usage,
    "subscript_colon_suffix": _sink_subscript_usage,
    "subscript_return": _sink_subscript_usage,              
    "subscript_method_call": _sink_subscript_usage,
    "matches_xpath": _sink_matches_xpath,
}


def match_sink(uso, sink_spec, fstring_nodes: list) -> bool:
    """
    Dispatcher potenziato: 
    Supporta pattern semplici (str), tipizzati (dict) e aggiunge un
    filtro globale 'requires_text_any' per validazioni ibride AST+Testo (es. SQLi).
    """
    is_match = False
    
    if isinstance(sink_spec, str):
        is_match = _sink_string_pattern(uso, sink_spec, fstring_nodes)
        
    elif isinstance(sink_spec, dict):
        sink_type = sink_spec.get("type")
        
        simple_patterns = ["concat", "fstring", "call_arg", "method_chain", "colon_suffix", "reassign", "return", "any_use", "assign_rhs"]
        if sink_type in simple_patterns:
            is_match = _sink_string_pattern(uso, sink_type, fstring_nodes)
        else:
            matcher = SINK_MATCHERS.get(sink_type)
            is_match = matcher(uso, sink_spec, fstring_nodes) if matcher else False

    if not is_match:
        return False
        
    if isinstance(sink_spec, dict) and "requires_text_any" in sink_spec:
        required_keywords = sink_spec["requires_text_any"]
        if required_keywords:
            stmt = uso.xpath("ancestor::src:expr_stmt[1] | ancestor::src:return[1] | ancestor::src:if_stmt[1]", namespaces=NS)
            target_node = stmt[0] if stmt else uso
            
            node_text = "".join(target_node.itertext()).upper()
            
            if not any(kw.upper() in node_text for kw in required_keywords):
                return False
                
    return True


def matches_any_sink(uso, sinks: list, fstring_nodes: list) -> bool:
    if not sinks:
        return True
    return any(match_sink(uso, s, fstring_nodes) for s in sinks)