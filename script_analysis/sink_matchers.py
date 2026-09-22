"""
sink_matchers.py
----------------
Predicati SINK per il motore: sia i pattern semplici basati su stringa
(concat/fstring/call_arg/method_chain/colon_suffix/...) sia quelli tipizzati
(oggetto {"type": "..."}), con il relativo registro e dispatcher.
"""

from common import NS, get_call_name



def _sink_string_pattern(uso, pattern_name: str, adapter=None, imports=None, fstring_nodes=None) -> bool:
    """
    Pattern strutturali basati sul TIPO di utilizzo della variabile.
    Totalmente guidati dal LanguageAdapter.
    """
    if pattern_name == "concat":
        # Questo andava già bene, ma possiamo renderlo più sicuro
        ops = adapter.string_concat_operators() if adapter else ["+", "%"]
        op_xpath = " | ".join([f"preceding-sibling::src:operator[1][text()='{op}']" for op in ops]) + " | " + \
                   " | ".join([f"following-sibling::src:operator[1][text()='{op}']" for op in ops])
        return bool(uso.xpath(op_xpath, namespaces=NS))

    if pattern_name == "fstring":
        # Sfruttiamo la lista pre-calcolata dal tuo taint_engine,
        # che gestisce correttamente la scomposizione fatta da srcML!
        if fstring_nodes is not None:
            return uso in fstring_nodes
        return False

    if pattern_name == "call_arg":
        return bool(uso.xpath("ancestor::src:argument", namespaces=NS))

    if pattern_name == "method_chain":
        # Deleghiamo all'adapter l'operatore di accesso ai membri (es. "." per Python/Java)
        # NOTA: Devi aggiungere `member_access_operator()` nel tuo LanguageAdapter!
        member_op = adapter.member_access_operator() if hasattr(adapter, "member_access_operator") else "."
        has_member_access = uso.xpath(f"following-sibling::src:operator[1][text()='{member_op}']", namespaces=NS)
        is_method_call = uso.xpath("parent::src:name/parent::src:call", namespaces=NS)
        return bool(has_member_access and is_method_call)

    if pattern_name == "colon_suffix":
        # Questo sembra un pattern molto specifico di Python (es. dizionari o type hinting)
        # Se è vitale, andrebbe astratto nell'adapter (es. adapter.is_dict_key(uso))
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
        # Ok, l'operatore di assegnazione è dinamico
        assign_op = adapter.assignment_operator_token() if adapter else "="
        return bool(uso.xpath(f"following-sibling::src:operator[1][text()='{assign_op}']", namespaces=NS))

    if pattern_name == "return":
        return uso.xpath("boolean(ancestor::src:return[1] and not(ancestor::src:call))", namespaces=NS)
    
    if pattern_name == "assign_rhs":
        if uso.xpath("ancestor::src:call", namespaces=NS):
            return False
            
        # MAGIA DELL'ADAPTER: Troviamo il blocco di codice che contiene l'assegnazione
        assign_stmt = uso.xpath("ancestor::src:expr_stmt | ancestor::src:decl_stmt", namespaces=NS)
        if not assign_stmt or not adapter:
            return False
            
        # Chiediamo all'adapter di dividere LHS e RHS per noi!
        lhs, rhs = adapter.get_assignment_lhs_rhs(assign_stmt[0], NS)
        if rhs is not None:
            # Controlliamo se il nostro "uso" fa parte del sotto-albero di destra (RHS)
            # In lxml, iter() attraversa tutti i figli di un nodo.
            return uso in rhs.iter() or uso == rhs
            
        return False

    if pattern_name == "any_use":
        return True

    return False


# def _sink_method_call(uso, spec: dict, fstring_nodes: list) -> bool:
def _sink_method_call(uso, spec: dict, fstring_nodes: list, adapter=None, imports=None) -> bool:

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


# def _sink_call_with_var_arg(uso, spec: dict, fstring_nodes: list) -> bool:
# def _sink_call_with_var_arg(uso, spec, fstring_nodes, adapter=None, imports=None):
#     """{"type": "call_with_var_arg", "call": ["re.sub", "sub"], "literal_contains": ["<script", "javascript:"]}"""
#     target_calls = spec.get("call", [])
#     if not target_calls:
#         return False

#     call_node = uso.xpath("ancestor::src:call[1]", namespaces=NS)
#     if not call_node:
#         return False

#     # call_name = get_call_name(call_node[0])
#     call_name = get_call_name(call_node[0], adapter, imports)
#     if call_name is None:
#         return False
#     if not any(call_name == c or call_name.endswith(f".{c}") for c in target_calls):
#         return False

#     literal_contains = spec.get("literal_contains", [])
#     if not literal_contains:
#         return True

#     arg_list = call_node[0].xpath("./src:argument_list", namespaces=NS)
#     if not arg_list:
#         return False
#     args_text = "".join(arg_list[0].itertext())
#     return any(val in args_text for val in literal_contains)

def _sink_call_with_var_arg(uso, spec, fstring_nodes, adapter=None, imports=None):
    """
    {"type": "call_with_var_arg", "call": ["re.sub", "sub", "executeQuery"], "literal_contains": ["SELECT"]}
    """
    target_calls = spec.get("call", [])
    if not target_calls:
        return False

    # 1. Prendiamo TUTTE le chiamate "padre", "nonno", ecc. per gestire i casi annidati
    call_nodes = uso.xpath("ancestor::src:call", namespaces=NS)
    if not call_nodes:
        return False

    # 2. Iteriamo dalla chiamata più profonda a quella più esterna
    for call_node in call_nodes:
        call_name = get_call_name(call_node, adapter, imports)
        if call_name is None:
            continue
            
        # È una delle chiamate che stiamo cercando?
        if not any(call_name == c or call_name.endswith(f".{c}") for c in target_calls):
            continue

        # 3. Definiamo arg_list all'interno del ciclo per questa specifica chiamata
        arg_list = call_node.xpath("./src:argument_list", namespaces=NS)
        if not arg_list:
            continue
            
        # Assicuriamoci che 'uso' sia davvero un ARGOMENTO (e non il receiver)
        if uso not in arg_list[0].iter():
            continue

        # 4. Controllo strutturale (AST puro) sui letterali stringa
        literal_contains = spec.get("literal_contains", [])
        if not literal_contains:
            return True 

        # Peschiamo SOLO i letterali di tipo stringa appartenenti a QUESTA argument_list
        string_literals = arg_list[0].xpath(".//src:literal[@type='string']", namespaces=NS)
        
        for literal_node in string_literals:
            raw_text = "".join(literal_node.itertext())
            clean_text = adapter.normalize_string_literal(raw_text) if adapter else raw_text
            
            # Cerchiamo la parola (es. "SELECT") solo dentro le vere stringhe
            if any(val in clean_text for val in literal_contains):
                return True

    return False


# def _sink_flat_call_arg(uso, spec: dict, fstring_nodes: list) -> bool:
def _sink_flat_call_arg(uso, spec: dict, fstring_nodes: list, adapter=None, imports=None) -> bool:
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


# def _sink_return_method_call(uso, spec: dict, fstring_nodes: list) -> bool:
def _sink_return_method_call(uso, spec: dict, fstring_nodes: list, adapter=None, imports=None) -> bool:

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


# def _sink_receiver_of_method_with_kwarg(uso, spec: dict, fstring_nodes: list) -> bool:
def _sink_receiver_of_method_with_kwarg(uso, spec: dict, fstring_nodes: list, adapter=None, imports=None) -> bool:

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


# def _sink_argument_to(uso, spec: dict, fstring_nodes: list, adapter=None, imports=None) -> bool:

#     """{"type": "argument_to", "functions": ["print"]}
    
#         la funzione verifica che uso sia argomento di una call il cui nome è esattamente uno di functions
#     """
#     functions = spec.get("functions", [])
#     if not functions:
#         return False

#     call_node = uso.xpath("ancestor::src:call[1]", namespaces=NS)
#     if not call_node:
#         return False
        
#     call_name_nodes = call_node[0].xpath("./src:name", namespaces=NS)
#     if not call_name_nodes:
#         return False
        
#     call_name = "".join(call_name_nodes[0].itertext()).replace(" ", "").replace("\n", "")
    
#     return call_name in functions

# def _sink_argument_to(uso, spec: dict, fstring_nodes: list = None, adapter=None, imports=None) -> bool:
#     """{"type": "argument_to", "functions": ["print"]}
#     Verifica che il nodo 'uso' sia effettivamente contenuto in un argomento 
#     di una chiamata presente nella lista 'functions'.
#     """
#     functions = spec.get("functions", [])
#     if not functions:
#         return False

#     # 1. Trova la call più vicina
#     call_ancestors = uso.xpath("ancestor::src:call[1]", namespaces=NS)
#     if not call_ancestors:
#         return False
#     call_node = call_ancestors[0]

#     # 2. Verifica strutturale: 'uso' deve trovarsi dentro l'argument_list della call,
#     #    non nel nodo del nome della call stessa (es. esclude foo(bar) dove uso è 'foo')
#     arg_list = uso.xpath("ancestor::src:argument_list[1]", namespaces=NS)
#     if not arg_list or arg_list[0].getparent() is not call_node:
#         return False

#     # 3. Risoluzione del nome via adapter/imports anziché tramite appiattimento di stringhe
#     call_name = get_call_name(call_node, adapter, imports)
#     if not call_name:
#         return False

#     # 4. Match sul nome completo o con prefisso di modulo/oggetto
#     return any(call_name == fn or call_name.endswith(f".{fn}") for fn in functions)
    

# def _sink_method_call_in_if(uso, spec: dict, fstring_nodes: list) -> bool:
def _sink_method_call_in_if(uso, spec: dict, fstring_nodes: list, adapter=None, imports=None) -> bool:

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


# def _sink_keyword_argument(uso, spec: dict, fstring_nodes: list) -> bool:
    # """{"type": "keyword_argument", "keyword": "env"}"""
    # keyword = spec.get("keyword")
    # if not keyword:
    #     return False

    # parent_arg = uso.xpath("ancestor::src:argument[1]", namespaces=NS)
    # if parent_arg:
    #     arg_node = parent_arg[0]
    #     name_nodes = arg_node.xpath("./src:name[1]", namespaces=NS)
    #     op_nodes = arg_node.xpath("./src:operator[1]", namespaces=NS)
        
    #     if name_nodes and op_nodes:
    #         kw_name = "".join(name_nodes[0].itertext()).strip()
    #         op = "".join(op_nodes[0].itertext()).strip()
            
    #         if kw_name == keyword and op == "=":
    #             return True
                
    # return False

def _sink_keyword_argument(uso, spec: dict, fstring_nodes: list, adapter=None, imports=None) -> bool:
    """{"type": "keyword_argument", "keyword": "env"}"""
    keyword = spec.get("keyword")
    if not keyword:
        return False

    parent_arg = uso.xpath("ancestor::src:argument[1]", namespaces=NS)
    if parent_arg:
        arg_node = parent_arg[0]
        if adapter and adapter.is_kwarg(arg_node, NS):
            name_nodes = arg_node.xpath("./src:name[1]", namespaces=NS)
            kw_name = "".join(name_nodes[0].itertext()).strip()
            if kw_name == keyword:
                return True

    return False

# def _sink_subscript_key_assign_rhs(uso, spec: dict, fstring_nodes: list) -> bool:
def _sink_subscript_key_assign_rhs(uso, spec: dict, fstring_nodes: list, adapter=None, imports=None) -> bool:
 
    """{"type": "subscript_key_assign_rhs"}"""
    assign_op = adapter.assignment_operator_token() if adapter else "="
    rhs_holder = uso.xpath(
        f"ancestor-or-self::*[preceding-sibling::src:operator[1][text()='{assign_op}']]",
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

# def _sink_subscript_usage(uso, spec: dict, fstring_nodes: list) -> bool:
def _sink_subscript_usage(uso, spec: dict, fstring_nodes: list, adapter=None, imports=None) -> bool:

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
        
        # Chiediamo i token corretti all'adattatore
        assign_op = adapter.assignment_operator_token() if adapter else "="
        concat_ops = adapter.string_concat_operators() if adapter else ["+"]
        
        # Verifichiamo se l'operatore finisce con il token di assegnazione (es: "=" o "+=")
        is_assign = op_text.endswith(assign_op)
        # Verifichiamo se l'operatore finisce con un token di concatenazione
        is_concat = any(op_text.endswith(c) for c in concat_ops)
        
        return is_assign or is_concat
        
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


# def _sink_matches_xpath(uso, spec: dict, fstring_nodes: list) -> bool:
def _sink_matches_xpath(uso, spec: dict, fstring_nodes: list, adapter=None, imports=None) -> bool:
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
    # "argument_to": _sink_argument_to,
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


def match_sink(uso, sink_spec, fstring_nodes: list, adapter=None, imports=None) -> bool:
    """
    Dispatcher potenziato: 
    Supporta pattern semplici (str), tipizzati (dict) e aggiunge un
    filtro globale 'requires_text_any' per validazioni ibride AST+Testo (es. SQLi).
    """
    is_match = False

    if isinstance(sink_spec, str):
        is_match = _sink_string_pattern(uso, sink_spec, adapter, imports, fstring_nodes)

    elif isinstance(sink_spec, dict):
        sink_type = sink_spec.get("type")

        simple_patterns = ["concat", "fstring", "call_arg", "method_chain", "colon_suffix", "reassign", "return", "any_use", "assign_rhs"]
        if sink_type in simple_patterns:
            is_match = _sink_string_pattern(uso, sink_type, adapter, imports, fstring_nodes)
        else:
            matcher = SINK_MATCHERS.get(sink_type)
            is_match = matcher(uso, sink_spec, fstring_nodes, adapter, imports) if matcher else False

    if not is_match:
        return False

    if isinstance(sink_spec, dict) and "requires_text_any" in sink_spec:
            required_keywords = sink_spec["requires_text_any"]
            if required_keywords:
                # Riprendiamo l'XPath originale pulito (che restituisce sicuramente una lista)
                stmt = uso.xpath("ancestor::src:expr_stmt | ancestor::src:return | ancestor::src:if_stmt", namespaces=NS)
                
                # usiamo [-1] per prendere l'elemento più vicino/interno
                target_node = stmt[-1] if stmt else uso

                node_text = "".join(target_node.itertext()).upper()

                if not any(kw.upper() in node_text for kw in required_keywords):
                    return False

    return True


# def matches_any_sink(uso, sinks: list, fstring_nodes: list) -> bool:
def matches_any_sink(uso, sinks, fstring_nodes, adapter=None, imports=None):
    if not sinks:
        return True
    # return any(match_sink(uso, s, fstring_nodes) for s in sinks)
    return any(match_sink(uso, s, fstring_nodes, adapter, imports) for s in sinks)