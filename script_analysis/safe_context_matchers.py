"""
safe_context_matchers.py
-------------------------
Predicati SAFE-CONTEXT per il motore. Include contesti semplici basati su stringa 
(tag strutturale o funzione guardia) e quelli tipizzati (oggetto {"type": "..."}), 
con il relativo registro e dispatcher.
"""

import re

from common import NS, get_call_name, call_arguments_match_ast


def _safe_context_current_call_matches(node, spec: dict, var_name: str | None = None) -> bool:
    """Verifica se il nodo corrente o il genitore diretto è una chiamata che rispetta i requisiti."""
    target_node = node
    
    if not target_node.tag.endswith("call"):
        call_ancestors = node.xpath("ancestor-or-self::src:call[1]", namespaces=NS)
        if not call_ancestors:
            return False
        target_node = call_ancestors[0]

    return call_arguments_match_ast(target_node, spec)


def _safe_context_function_has_call_matching(node, spec: dict, var_name: str | None = None) -> bool:
    """Cerca in tutta la funzione una chiamata che rispetti i requisiti degli argomenti."""
    target = _function_or_unit_scope(node)
    return any(call_arguments_match_ast(c, spec) for c in target.xpath(".//src:call", namespaces=NS))


def _function_or_unit_scope(node):
    """Ritorna la <src:function> più vicina che racchiude `node`, o l'intero <src:unit>."""
    parent_func = node.xpath("ancestor::src:function[1]", namespaces=NS)
    return parent_func[0] if parent_func else node.xpath("ancestor::src:unit[1]", namespaces=NS)[0]


def _safe_context_parametrized_query(node, spec: dict, var_name: str | None = None) -> bool:
    call_node = node.xpath("ancestor::src:call[.//src:name[last()][text()='execute']][1]", namespaces=NS)
    if not call_node:
        return False

    arg_list = call_node[0].xpath("./src:argument_list", namespaces=NS)
    if not arg_list:
        return False

    args_text = "".join(arg_list[0].itertext())
    has_placeholder = "%s" in args_text or "?" in args_text
    has_param_tuple = bool(arg_list[0].xpath(".//src:argument[position()>1]", namespaces=NS))
    return has_placeholder and has_param_tuple


def _safe_context_receiver_of_method(node, spec: dict, var_name: str | None = None) -> bool:
    """{"type": "receiver_of_method", "method": "replace"}
    Rileva: la variabile taintata è il chiamante di un metodo specifico.
    Es: VAR.replace(...) rende il contesto sicuro, ma stringa.replace(VAR) no.
    """
    target_method = spec.get("method")
    if not target_method:
        return False

    method_nodes = node.xpath(
        "following-sibling::src:operator[1][text()='.']/following-sibling::src:name[1]",
        namespaces=NS,
    )
    
    if method_nodes and "".join(method_nodes[0].itertext()).strip() == target_method:
        return True
    return False


def _safe_context_rhs_call(node, spec: dict, var_name: str | None = None) -> bool:
    """{"type": "rhs_call", "call": ["os.environ.get", "os.getenv"]}
        Rileva se il lato destro dell'assegnazione/confronto in cui compare 'node'
        contiene una chiamata a una delle funzioni considerate sicure.
    """
    calls = spec.get("call", [])
    expr = node.xpath("ancestor::src:expr_stmt[1]//src:call | ancestor::src:condition[1]//src:call", namespaces=NS)
    for c in expr:
        cn = get_call_name(c)
        if cn and any(cn == t or cn.endswith(f".{t}") for t in calls):
            return True
    return False


def _safe_context_lower_ne_literal(node, spec: dict, var_name: str = None) -> bool:
    call = node.xpath("ancestor-or-self::src:call[1]", namespaces=NS)
    if not call:
        return False
    cname = get_call_name(call[0])
    if cname != "lower" and not (cname and cname.endswith(".lower")):
        return False
    cmp = call[0].xpath(
        "following-sibling::src:operator[1][text()='!=']"
        "/following-sibling::src:literal[1][@type='string']",
        namespaces=NS,
    )
    return bool(cmp)


def _safe_context_function_has_method_call(node, spec: dict, var_name: str | None = None) -> bool:
    """{"type": "function_has_method_call", "method": "replace", "args_contain": ["';'", "'&'"]}"""
    method = spec.get("method")
    args_contain = spec.get("args_contain", [])
    
    if not method:
        return False
        
    target_node = _function_or_unit_scope(node)
    calls = target_node.xpath(
        f".//src:call[.//src:operator[text()='.']/following-sibling::src:name[1][text()='{method}']]", 
        namespaces=NS
    )
    
    for c in calls:
        arg_list = c.xpath("./src:argument_list", namespaces=NS)
        if not arg_list:
            continue
            
        args_text = "".join(arg_list[0].itertext()).replace(" ", "").replace('"', "'")
        if all(arg.replace('"', "'").replace(" ", "") in args_text for arg in args_contain):
            return True
            
    return False


def _safe_context_whitelist_membership_then_run(node, spec: dict, var_name: str | None = None) -> bool:
    """{"type": "whitelist_membership_then_run", "call": ["subprocess.run"]}
        Rileva: node si trova dentro un if_stmt la cui condizione contiene un
        controllo di membership generico (un operatore 'in'). E che nel proprio corpo contiene
        una chiamata a una delle funzioni indicate con un argomento che usa
        subscript (es. "if X in Y: subprocess.run(Z[...])
    """
    calls = spec.get("call", [])
    if_stmt = node.xpath("ancestor::src:if_stmt[1]", namespaces=NS)
    if not if_stmt:
        return False
    if_stmt = if_stmt[0]
 
    condition = if_stmt.xpath("./src:condition", namespaces=NS)
    if not condition:
        return False
    cond_text = "".join(condition[0].itertext())
    if not re.search(r"\bin\b", cond_text):
        return False
 
    for call_node in if_stmt.xpath(".//src:call", namespaces=NS):
        cname = get_call_name(call_node)
        if cname and any(cname == c or cname.endswith(f".{c}") for c in calls):
            arg_list = call_node.xpath("./src:argument_list", namespaces=NS)
            if arg_list and "[" in "".join(arg_list[0].itertext()):
                return True
    return False


def _safe_context_function_calls_and_call_has_kwarg(node, spec: dict, var_name: str | None = None) -> bool:
    """{"type": "function_calls_and_call_has_kwarg", "function_call": "default_backend", "kwarg": "backend"}
        Rileva: la chiamata vietata possiede uno specifico parametro nominato (kwarg)
        E all'interno della stessa funzione (o file) è presente una chiamata a un'altra 
        funzione specifica.
    """
    target_func = spec.get("function_call")
    target_kwarg = spec.get("kwarg")
    
    if not target_func or not target_kwarg:
        return False
        
    arg_list = node.xpath("./src:argument_list", namespaces=NS)
    if not arg_list:
        return False
    args_text = "".join(arg_list[0].itertext()).replace(" ", "").replace("\n", "")
    if f"{target_kwarg}=" not in args_text:
        return False
        
    scope = _function_or_unit_scope(node)
    calls = scope.xpath(".//src:call", namespaces=NS)
    for c in calls:
        cname = get_call_name(c)
        if cname and (cname == target_func or cname.endswith(f".{target_func}")):
            return True
            
    return False


def _safe_context_args_contain_string_literal(node, spec: dict, var_name: str | None = None) -> bool:
    arg_list = node.xpath("./src:argument_list", namespaces=NS)
    if not arg_list:
        return False
        
    if arg_list[0].xpath(".//src:name", namespaces=NS):
        return False
        
    string_literals = arg_list[0].xpath(".//src:literal[@type='string']", namespaces=NS)
    if not string_literals:
        return False
        
    for literal in string_literals:
        testo_stringa = "".join(literal.itertext()).strip().lower()
        if testo_stringa.startswith('f"') or testo_stringa.startswith("f'"):
            return False
            
    return True


def _safe_context_args_contain_call_with_literal_arg(node, spec: dict, var_name: str | None = None) -> bool:
    """{"type": "args_contain_call_with_literal_arg", "call": "encode", "literal": "utf-8"}"""
    target_call = spec.get("call")
    literal_val = spec.get("literal", "")
    if not target_call:
        return False

    for nc in node.xpath(".//src:argument_list//src:call", namespaces=NS):
        nc_name = get_call_name(nc)
        if not nc_name or not (nc_name == target_call or nc_name.endswith(f".{target_call}")):
            continue
        if not literal_val:
            return True
        arg_list = nc.xpath("./src:argument_list", namespaces=NS)
        if not arg_list:
            continue
        args_text = "".join(arg_list[0].itertext()).replace(" ", "").replace("'", "").replace('"', "")
        if literal_val.replace(" ", "").strip("'\"") in args_text:
            return True
    return False


def _safe_context_in_function_name(node, spec: dict, var_name: str | None = None) -> bool:
    """{"type": "in_function_name", "name": "is_valid_pkcs1v15_padding"}
        Rileva se il nodo si trova all'interno di una funzione con il nome specificato.
    """
    target = spec.get("name")
    func = node.xpath("ancestor::src:function[1]", namespaces=NS)
    if func:
        name_nodes = func[0].xpath("./src:name", namespaces=NS)
        if name_nodes and "".join(name_nodes[0].itertext()).strip() == target:
            return True
    return False


def _safe_context_file_has_header_check(node, spec: dict, var_name: str | None = None) -> bool:
    """{"type": "file_has_header_check"}
        pattern_not di HTTP-SERVER-003
    """
    unit = node.xpath("ancestor::src:unit[1]", namespaces=NS)
    target = unit[0] if unit else node
    
    conditions = target.xpath(".//src:if_stmt//src:condition", namespaces=NS)
    for cond in conditions:
        cond_text = "".join(cond.itertext()).replace(" ", "").replace('"', "'")
        if "'Transfer-Encoding'in" in cond_text and ".header" in cond_text:
            return True
        if "'Content-Lenght'in" in cond_text and ".header" in cond_text:
            return True
        if "'Content-Length'in" in cond_text and ".header" in cond_text:
            return True
            
    calls = target.xpath(".//src:call", namespaces=NS)
    has_te_get = False
    has_cl_get = False
    
    for c in calls:
        cname = get_call_name(c)
        if cname and cname.endswith(".get"):
            args = c.xpath("./src:argument_list", namespaces=NS)
            if args:
                arg_text = "".join(args[0].itertext()).replace(" ", "").replace('"', "'")
                if "'Transfer-Encoding'" in arg_text:
                    has_te_get = True
                if "'Content-Length'" in arg_text:
                    has_cl_get = True
                    
    return has_te_get and has_cl_get


def _safe_context_function_has_overflow_check(node, spec: dict, var_name: str | None = None) -> bool:
    """{"type": "function_has_overflow_check", "operator": "-"}"""
    operator = spec.get("operator", "-")
    target_text = f"a>0andb>0anda>(2**31-1){operator}b"
    target = _function_or_unit_scope(node)
    
    conditions = target.xpath(".//src:if_stmt//src:condition", namespaces=NS)
    for cond in conditions:
        text = "".join(cond.itertext()).replace(" ", "")
        if target_text in text:
            return True
    return False


def _safe_context_args_do_not_contain_call(node, spec: dict, var_name: str | None = None) -> bool:
    """{"type": "args_do_not_contain_call", "call": "redirect"}
    Rende il contesto sicuro se la funzione target NON è presente tra gli argomenti.
    """
    target = spec.get("call")
    if not target:
        return True
        
    calls_in_args = node.xpath("./src:argument_list//src:call", namespaces=NS)
    for c in calls_in_args:
        c_name_nodes = c.xpath("./src:name", namespaces=NS)
        if c_name_nodes:
            cname = "".join(c_name_nodes[0].itertext()).replace(" ", "")
            if cname == target or cname.endswith(f".{target}"):
                return False
    return True


def _safe_context_function_calls_method_on_var(node, spec: dict, var_name: str | None = None) -> bool:
    """{"type": "function_calls_method_on_var", "method": "set_handle_timeout"}"""
    if not var_name:
        return False
        
    method_name = spec.get("method")
    if not method_name:
        return False
        
    target_str = f"{var_name}.{method_name}("
    target = _function_or_unit_scope(node)
    
    calls = target.xpath(".//src:call", namespaces=NS)
    for call in calls:
        call_text = "".join(call.itertext()).replace(" ", "")
        if target_str in call_text:
            return True
    return False


def _safe_context_function_is_not(node, spec: dict, var_name: str | None = None) -> bool:
    """{"type": "function_is_not", "name": "encode_structured_data"}"""
    target_func = spec.get("name")
    if not target_func:
        return False
        
    parent_func = node.xpath("ancestor::src:function[1]", namespaces=NS)
    if not parent_func:
        return True 

    name_nodes = parent_func[0].xpath("./src:name", namespaces=NS)
    if name_nodes:
        func_name = "".join(name_nodes[0].itertext()).strip()
        if func_name != target_func:
            return True
            
    return False


def _safe_context_function_has_hmac_sha512_digest(node, spec: dict, var_name: str | None = None) -> bool:
    """{"type": "function_has_hmac_sha512_digest"}
        pattern_not di HMAC-NEW-001
    """
    target = _function_or_unit_scope(node)
    calls = target.xpath(".//src:call", namespaces=NS)
    for c in calls:
        c_text = "".join(c.itertext()).replace(" ", "").replace("\n", "")
        if re.search(r"hmac\.new\(.*hashlib\.sha512\)\.(digest|hexdigest)\(", c_text):
            return True
    return False


def _safe_context_function_has_file_size_check(node, spec: dict, var_name: str | None = None) -> bool:
    """{"type": "function_has_file_size_check"}
        pattern_not di FILE-DIM-001 
    """
    target = _function_or_unit_scope(node)
    
    has_file_size = target.xpath(".//src:operator[text()='.']/following-sibling::*[1][self::src:name[text()='file_size']]", namespaces=NS)
    if has_file_size:
        return True
        
    conditions = target.xpath(".//src:if_stmt//src:condition", namespaces=NS)
    for cond in conditions:
        if cond.xpath(".//src:operator[text()='.']/following-sibling::*[1][self::src:name[text()='size']]", namespaces=NS):
            return True
    return False


def _safe_context_file_has_logger_info_add(node, spec: dict, var_name: str | None = None) -> bool:
    """{"type": "file_has_logger_info_add"}
        pattern_not di LOGORU-LOGGER-001
    """
    unit = node.xpath("ancestor::src:unit[1]", namespaces=NS)
    target = unit[0] if unit else node
    
    calls = target.xpath(".//src:call", namespaces=NS)
    for c in calls:
        cname = get_call_name(c)
        if cname and (cname == "logger.add" or cname.endswith(".logger.add") or cname == "add"):
            arg_list = c.xpath("./src:argument_list", namespaces=NS)
            if not arg_list:
                continue
            args_text = "".join(arg_list[0].itertext()).replace(" ", "").replace("'", '"')
            if 'level="INFO"' in args_text:
                return True
    return False


def _safe_context_args_contain_masking(node, spec: dict, var_name: str | None = None) -> bool:
    """{"type": "args_contain_masking"}
        Verifica se negli argomenti della chiamata è presente un offuscamento tramite
        stringa di asterischi e funzione len().
    """
    node_text = "".join(node.itertext())
    pattern = r"['\"]\*['\"]\s*\*?\s*len\("
    return bool(re.search(pattern, node_text))


def _safe_context_unit_has_os_path_join_and_commonprefix(node, spec: dict, var_name: str | None = None) -> bool:
    """{"type": "unit_has_os_path_join_and_commonprefix"}"""
    target = _function_or_unit_scope(node)
    text = "".join(target.itertext()).replace(" ", "")
    return "os.path.join(" in text and "os.path.commonprefix(" in text


def _safe_context_unit_has_os_path_abspath_and_commonpath(node, spec: dict, var_name: str | None = None) -> bool:
    """{"type": "unit_has_os_path_abspath_and_commonpath"}"""
    target = _function_or_unit_scope(node)
    text = "".join(target.itertext())
    return "os.path.abspath(" in text and "os.path.commonpath(" in text


def _safe_context_unit_has_os_path_abspath_and_startswith(node, spec: dict, var_name: str | None = None) -> bool:
    """{"type": "unit_has_os_path_abspath_and_startswith"}"""
    target = _function_or_unit_scope(node)
    text = "".join(target.itertext())
    return "os.path.abspath(" in text and ".startswith(" in text


def _safe_context_var_truthiness_check(node, spec: dict, var_name: str | None = None) -> bool:
    """{"type": "var_truthiness_check", "scope": "enclosing" | "function" | "file"}
        Rileva i check di truthiness (es. 'if not var')
    """
    if not var_name:
        return False
        
    search_scope = spec.get("scope", "enclosing")
    
    if search_scope == "enclosing":
        conditions = node.xpath("ancestor::src:if_stmt/src:condition", namespaces=NS)
    elif search_scope in ("file", "unit"):
        unit_node = node.xpath("ancestor::src:unit[1]", namespaces=NS)
        target = unit_node[0] if unit_node else _function_or_unit_scope(node)
        conditions = target.xpath(".//src:if_stmt//src:condition", namespaces=NS)
    else: 
        target = _function_or_unit_scope(node)
        conditions = target.xpath(".//src:if_stmt//src:condition", namespaces=NS)
        
    for cond in conditions:
        text = "".join(cond.itertext()).replace(" ", "").replace("\n", "")
        if f"not{var_name}" in text:
            return True
        if f"{var_name}isNone" in text:
            return True
            
    return False



def _safe_context_condition_matches_xpath(node, spec: dict, var_name: str | None = None) -> bool:
    """{"type": "condition_matches_xpath", "xpath": ".//src:call[src:name='isinstance']"}
        Permette query strutturali XPath native sull'AST in questo caso all'interno di una <condition>.
    """
    xpath_template = spec.get("xpath")
    if not xpath_template:
        return False
        
    search_scope = spec.get("scope", "function")
    target = _function_or_unit_scope(node)
    
    if search_scope == "enclosing":
        conditions = node.xpath("ancestor::src:if_stmt//src:condition", namespaces=NS)
    else:
        conditions = target.xpath(".//src:if_stmt//src:condition", namespaces=NS)
        
    xpath_query = xpath_template.replace("$VAR", var_name) if var_name else xpath_template

    for cond in conditions:
        if cond.xpath(xpath_query, namespaces=NS):
            return True
            
    return False


def _safe_context_matches_xpath(node, spec: dict, var_name: str | None = None) -> bool:
    """{"type": "matches_xpath", "xpath": ".//src:call[.//src:name[text()='hmac']]"}
        Query XPath arbitrarie sull'intero scope.
    """
    xpath_template = spec.get("xpath")
    if not xpath_template:
        return False
        
    target = _function_or_unit_scope(node)
    xpath_query = xpath_template.replace("$VAR", var_name) if var_name else xpath_template
    return bool(target.xpath(xpath_query, namespaces=NS))


def _safe_context_node_matches_xpath(node, spec: dict, var_name: str | None = None) -> bool:
    """{"type": "node_matches_xpath", "xpath": "ancestor::src:call[1]..."}
        Valuta una query XPath partendo ESATTAMENTE dal nodo individuato.
    """
    xpath_query = spec.get("xpath")
    if not xpath_query:
        return False
    result = node.xpath(xpath_query, namespaces=NS)
    return bool(result)


def _safe_context_var_has_attribute(node, spec: dict, var_name: str | None = None) -> bool:
    """{"type": "var_has_attribute", "attribute": "text"}
        Verifica se la variabile taintata è immediatamente seguita da un accesso all'attributo specificato.
    """
    attr = spec.get("attribute")
    if not attr:
        return False

    attr_nodes = node.xpath(
        "following-sibling::src:operator[1][text()='.']/following-sibling::src:name[1]",
        namespaces=NS,
    )
    
    if attr_nodes and "".join(attr_nodes[0].itertext()).strip() == attr:
        return True
    return False


def _safe_context_binary_comparison(node, spec: dict, var_name: str | None = None) -> bool:
    """{"type": "binary_comparison", "operators": ["<"], "left_exact": ["size"], "right_exact": ["0"]}
        Verifica un confronto binario all'interno di un if_stmt.
        Sfrutta l'AST per separare lato sinistro (LHS) e destro (RHS), ignorando i commenti.
    """
    target = _function_or_unit_scope(node)
    operators = spec.get("operators", [])
    left_exact = spec.get("left_exact", [])
    left_contains = spec.get("left_contains", [])
    right_exact = spec.get("right_exact", [])
    right_contains = spec.get("right_contains", [])
    
    conditions = target.xpath(".//src:if_stmt//src:condition", namespaces=NS)
    for cond in conditions:
        for op_val in operators:
            ops = cond.xpath(f".//src:operator[text()='{op_val}']", namespaces=NS)
            for op_node in ops:
                lhs_nodes = op_node.xpath("./preceding-sibling::*[not(self::src:comment)]", namespaces=NS)
                rhs_nodes = op_node.xpath("./following-sibling::*[not(self::src:comment)]", namespaces=NS)
                
                lhs_text = "".join("".join(n.itertext()) for n in lhs_nodes).replace(" ", "").replace("\n", "")
                rhs_text = "".join("".join(n.itertext()) for n in rhs_nodes).replace(" ", "").replace("\n", "")
                
                left_ok = True
                if left_exact or left_contains:
                    left_ok = (lhs_text in left_exact) or any(c in lhs_text for c in left_contains)
                    
                right_ok = True
                if right_exact or right_contains:
                    right_ok = (rhs_text in right_exact) or any(c in rhs_text for c in right_contains)
                    
                if left_ok and right_ok:
                    return True
    return False


def _safe_context_membership_check(node, spec: dict, var_name: str | None = None) -> bool:
    """{"type": "membership_check", "scope": "enclosing", "operators": ["in", "not in"]}
        Verifica controlli di appartenenza (in / not in).
    """
    search_scope = spec.get("scope", "function")
    target_for_assignments = _function_or_unit_scope(node)
    
    if search_scope == "enclosing":
        conditions = node.xpath("ancestor::src:if_stmt[1]//src:condition", namespaces=NS)
    else:
        conditions = target_for_assignments.xpath(".//src:if_stmt//src:condition", namespaces=NS)
        
    operators = spec.get("operators", ["in", "not in"])
    left_exact = spec.get("left_exact", [])
    left_contains = spec.get("left_contains", [])
    right_exact = spec.get("right_exact", [])
    right_starts_with = spec.get("right_starts_with", [])
    
    require_var_left = spec.get("require_var_left", False)
    require_var_right = spec.get("require_var_right", False)
    right_is_bare_identifier = spec.get("right_is_bare_identifier", False)
    
    require_any_call = spec.get("require_any_call", False)
    require_collection_assignment = spec.get("require_collection_assignment", False)

    if require_collection_assignment:
        assignments = target_for_assignments.xpath(".//src:expr_stmt[.//src:operator[text()='=']]", namespaces=NS)
        has_coll_assign = False
        for assign in assignments:
            op = assign.xpath(".//src:operator[text()='='][1]", namespaces=NS)
            if op:
                rhs_nodes = op[0].xpath("./following-sibling::*[not(self::src:comment)]", namespaces=NS)
                rhs_text = "".join("".join(n.itertext()) for n in rhs_nodes).replace(" ", "").replace("\n", "")
                if rhs_text.startswith("[") or rhs_text.startswith("{") or rhs_text.startswith("("):
                    has_coll_assign = True
                    break
        if not has_coll_assign:
            return False

    for cond in conditions:
        if require_any_call:
            cond_text = "".join(cond.itertext()).replace(" ", "")
            if "any(" not in cond_text:
                continue

        in_ops = cond.xpath(".//src:operator[text()='in']", namespaces=NS)
        for op_node in in_ops:
            prev_nodes = op_node.xpath("./preceding-sibling::*[not(self::src:comment)]", namespaces=NS)
            is_not_in = False
            
            if prev_nodes:
                last_prev = prev_nodes[-1]
                if last_prev.tag.endswith("operator") and "".join(last_prev.itertext()).strip() == "not":
                    is_not_in = True
                    prev_nodes = prev_nodes[:-1]

            current_op = "not in" if is_not_in else "in"
            
            if operators and current_op not in operators:
                continue

            lhs_nodes = prev_nodes
            rhs_nodes = op_node.xpath("./following-sibling::*[not(self::src:comment)]", namespaces=NS)

            lhs_text = "".join("".join(n.itertext()) for n in lhs_nodes).replace(" ", "").replace("\n", "")
            rhs_text = "".join("".join(n.itertext()) for n in rhs_nodes).replace(" ", "").replace("\n", "")

            left_ok = True
            if require_var_left and var_name:
                if not re.search(rf"(^|[^a-zA-Z0-9_]){re.escape(var_name)}$", lhs_text):
                    left_ok = False
            if left_exact and not any(t == lhs_text for t in left_exact):
                left_ok = False
            if left_contains and not any(c in lhs_text for c in left_contains):
                left_ok = False

            right_ok = True
            if require_var_right and var_name:
                if not re.search(rf"^{re.escape(var_name)}([^a-zA-Z0-9_]|$)", rhs_text):
                    right_ok = False
            if right_exact and not any(t == rhs_text for t in right_exact):
                right_ok = False
            if right_starts_with and not any(rhs_text.startswith(c) for c in right_starts_with):
                right_ok = False

            if right_is_bare_identifier:
                if not re.fullmatch(r"[a-zA-Z_]\w*", rhs_text):
                    right_ok = False
                    
            if right_exact and not any(t == rhs_text for t in right_exact):
                right_ok = False

            if left_ok and right_ok:
                return True

    return False


def _safe_context_url_validation(node, spec: dict, var_name: str | None = None) -> bool:
    """{"type": "url_validation", "require": "both" | "any" | "netloc_in"}
        Verifica controlli su attributi URL (scheme, netloc).
    """
    if not var_name:
        return False
        
    search_scope = spec.get("scope", "function") 
    target = _function_or_unit_scope(node)
    require_mode = spec.get("require", "both")
    
    if require_mode == "netloc_in":
        in_ops = target.xpath(".//src:operator[text()='in']", namespaces=NS)
        for op_node in in_ops:
            prev_nodes = op_node.xpath("./preceding-sibling::*[not(self::src:comment)]", namespaces=NS)
            if prev_nodes:
                last_prev = prev_nodes[-1]
                if last_prev.tag.endswith("operator") and "".join(last_prev.itertext()).strip() == "not":
                    prev_nodes = prev_nodes[:-1]
            
            lhs_text = "".join("".join(n.itertext()) for n in prev_nodes).replace(" ", "").replace("\n", "")
            
            if re.search(rf"(^|[^a-zA-Z0-9_]){re.escape(var_name)}\.netloc$", lhs_text):
                return True
        return False

    if search_scope == "enclosing":
        conditions = node.xpath("ancestor::src:if_stmt/src:condition", namespaces=NS)
    else:
        conditions = target.xpath(".//src:if_stmt//src:condition", namespaces=NS)
        
    for cond in conditions:
        cond_nodes = cond.xpath(".//*[not(self::src:comment)]", namespaces=NS)
        cond_text = "".join("".join(n.itertext()) for n in cond_nodes).replace(" ", "").replace("\n", "")
        
        has_scheme = bool(re.search(rf"(^|[^a-zA-Z0-9_]){re.escape(var_name)}\.scheme($|[^a-zA-Z0-9_])", cond_text))
        has_netloc = bool(re.search(rf"(^|[^a-zA-Z0-9_]){re.escape(var_name)}\.netloc($|[^a-zA-Z0-9_])", cond_text))
        
        if require_mode == "both" and has_scheme and has_netloc:
            return True
        elif require_mode == "any" and (has_scheme or has_netloc):
            return True
            
    return False


def _safe_context_unit_has_function_def(node, spec: dict, var_name: str | None = None) -> bool:
    """{"type": "unit_has_function_def", "name": "sanitize_git_reference"}"""
    target_name = spec.get("name")
    param_contains = spec.get("param_contains", "")
    if not target_name:
        return False
        
    unit = node.xpath("ancestor-or-self::src:unit[1]", namespaces=NS)
    if not unit:
        return False
        
    functions = unit[0].xpath(f".//src:function[src:name[text()='{target_name}']]", namespaces=NS)
    for func in functions:
        if not param_contains:
            return True
            
        params = func.xpath(".//src:parameter_list", namespaces=NS)
        if params:
            p_text = "".join(params[0].itertext()).replace(" ", "").replace("\n", "")
            if param_contains in p_text:
                return True
                
    return False


def _safe_context_call_has_kwargs(node, spec: dict, var_name: str | None = None) -> bool:
    calls = spec.get("call", [])
    
    call_node = node.xpath("ancestor-or-self::src:call[1]", namespaces=NS)
    if not call_node:
        return False
        
    call_name = get_call_name(call_node[0])
    if call_name is None or not any(call_name == c or call_name.endswith(f".{c}") for c in calls):
        return False

    arg_list = call_node[0].xpath("./src:argument_list", namespaces=NS)
    if not arg_list:
        return not spec.get("kwargs") and not spec.get("dict_key") and not spec.get("allowed_values")
        
    args_text = "".join(arg_list[0].itertext()).replace(" ", "").replace("\n", "").replace("'", '"')
    
    kwarg_name = spec.get("kwarg")
    
    if kwarg_name and spec.get("dict_key"):
        dict_key = spec.get("dict_key")
        dict_val = spec.get("dict_value")
        pattern = rf"{kwarg_name}=\{{[^\}}]*\"{dict_key}\":{dict_val}"
        return bool(re.search(pattern, args_text))
        
    if kwarg_name and spec.get("allowed_values"):
        for val in spec.get("allowed_values", []):
            target = f'{kwarg_name}=["{val}"]'
            if target in args_text:
                return True
        return False
        
    kwargs = spec.get("kwargs", {})
    if kwargs:
        require_mode = spec.get("require", "any")
        if require_mode == "all":
            return all(f"{k}={v}" in args_text for k, v in kwargs.items())
        else:
            return any(f"{k}={v}" in args_text for k, v in kwargs.items())
            
    return True


def _safe_context_receiver_of_method_with_arg(node, spec: dict, var_name: str | None = None) -> bool:
    """{"type": "receiver_of_method_with_arg", "method": "endswith", "arg_value": ".png"}"""
    target_method = spec.get("method")
    target_arg = spec.get("arg_value")
    
    if not target_method or not target_arg:
        return False

    method_nodes = node.xpath(
        "following-sibling::src:operator[1][text()='.']/following-sibling::src:name[1]",
        namespaces=NS,
    )
    
    if not method_nodes or "".join(method_nodes[0].itertext()).strip() != target_method:
        return False
        
    call_node = node.xpath("ancestor::src:call[1]", namespaces=NS)
    if not call_node:
        return False
        
    arg_list = call_node[0].xpath("./src:argument_list", namespaces=NS)
    if not arg_list:
        return False
        
    args_text = "".join(arg_list[0].itertext()).replace(" ", "").replace("\n", "").replace('"', "'")
    normalized_target = target_arg.replace(" ", "").replace('"', "'")
    
    if not normalized_target.startswith("'"):
        normalized_target = f"'{normalized_target}'"
        
    return normalized_target in args_text


def _safe_context_function_has_call_with_var_arg(node, spec: dict, var_name: str | None = None) -> bool:
    """{"type": "function_has_call_with_var_arg", "call": ["os.path.isfile"]}"""
    if not var_name:
        return False
    target_calls = spec.get("call", [])
    if not target_calls:
        return False

    target = _function_or_unit_scope(node)
    for call_node in target.xpath(".//src:call", namespaces=NS):
        call_name = get_call_name(call_node)
        if not call_name or not any(call_name == c or call_name.endswith(f".{c}") for c in target_calls):
            continue

        arg_list = call_node.xpath("./src:argument_list", namespaces=NS)
        if not arg_list:
            continue

        for arg in arg_list[0].xpath("./src:argument", namespaces=NS):
            arg_text = "".join(arg.itertext()).strip()
            if arg_text == var_name:
                return True

    return False


def _safe_context_call_in_try_with_kwarg(node, spec: dict, var_name: str | None = None) -> bool:
    """{"type": "call_in_try_with_kwarg", "kwarg": "check", "values": ["True", "true"]}
        Sicuro solo se ENTRAMBE le condizioni sono vere: la call è dentro un
        blocco try, E possiede il kwarg con uno dei valori indicati.
    """
    kwarg = spec.get("kwarg")
    values = spec.get("values", [])
    if not kwarg:
        return False

    call_node = node if node.tag.endswith("call") else node.xpath("ancestor-or-self::src:call[1]", namespaces=NS)
    call_node = call_node[0] if isinstance(call_node, list) else call_node
    if call_node is None or not call_node.xpath("ancestor::src:try", namespaces=NS):
        return False

    arg_list = call_node.xpath("./src:argument_list", namespaces=NS)
    if not arg_list:
        return False
    args_text = "".join(arg_list[0].itertext()).replace(" ", "").replace("\n", "")

    return any(f"{kwarg}={v}" in args_text for v in values)


def _safe_context_csv_injection_sanitizer(node, spec: dict, var_name: str | None = None) -> bool:
    """{"type": "csv_injection_sanitizer"}
    pattern not: EXCEL-INJC-001
    """
    target = _function_or_unit_scope(node)
    candidates = target.xpath(
        ".//src:expr_stmt | .//src:return | .//src:expr[not(ancestor::src:expr_stmt) and not(ancestor::src:return)]",
        namespaces=NS,
    )
    for stmt in candidates:
        text = "".join(stmt.itertext())

        has_isinstance_str = bool(
            stmt.xpath(".//src:call[.//src:name[text()='isinstance']][.//src:name[text()='str']]", namespaces=NS)
        )
        has_startswith_eq = bool(
            stmt.xpath(
                ".//src:call[.//src:name[last()][text()='startswith']]"
                "[.//src:literal[@type='string'][contains(text(),'=')]]",
                namespaces=NS,
            )
        )
        has_fstring = any(
            lit_text.strip().startswith(("f'", 'f"'))
            for lit_text in (
                "".join(lit.itertext())
                for lit in stmt.xpath(".//src:literal[@type='string']", namespaces=NS)
            )
        )

        if has_isinstance_str and has_startswith_eq and has_fstring:
            return True

    return False


def _safe_context_try_after_source(node, spec: dict, var_name: str | None = None) -> bool:
    """{"type": "try_after_source"}
        sicuro SOLO se il <try> che racchiude l'uso non racchiude anche l'assegnazione della source
        (cioe' il try si apre dopo la source, non prima/attorno).
    """
    if not var_name:
        return False

    try_ancestors = node.xpath("ancestor::src:try", namespaces=NS)
    if not try_ancestors:
        return False
    try_node = try_ancestors[0]

    scope = _function_or_unit_scope(node)
    for assign in scope.xpath(".//src:expr_stmt[src:expr[src:operator[text()='=']]]", namespaces=NS):
        lhs = assign.xpath("./src:expr/src:name[1]", namespaces=NS)
        if lhs and "".join(lhs[0].itertext()).strip() == var_name:
            assign_try = assign.xpath("ancestor::src:try[1]", namespaces=NS)
            if assign_try and assign_try[0] is try_node:
                return False  
    return True


SAFE_CONTEXT_MATCHERS = {
    "parametrized_query": _safe_context_parametrized_query,
    "receiver_of_method": _safe_context_receiver_of_method,
    "rhs_call": _safe_context_rhs_call,
    "lower_ne_literal": _safe_context_lower_ne_literal,
    "function_has_method_call": _safe_context_function_has_method_call,
    "whitelist_membership_then_run": _safe_context_whitelist_membership_then_run,
    "function_calls_and_call_has_kwarg": _safe_context_function_calls_and_call_has_kwarg,
    "args_contain_string_literal": _safe_context_args_contain_string_literal,
    "args_contain_call_with_literal_arg": _safe_context_args_contain_call_with_literal_arg,
    "in_function_name": _safe_context_in_function_name,
    "file_has_header_check": _safe_context_file_has_header_check,
    "function_has_overflow_check": _safe_context_function_has_overflow_check,
    "args_do_not_contain_call": _safe_context_args_do_not_contain_call,
    "function_calls_method_on_var": _safe_context_function_calls_method_on_var,
    "function_is_not": _safe_context_function_is_not,
    "function_has_hmac_sha512_digest": _safe_context_function_has_hmac_sha512_digest,
    "function_has_file_size_check": _safe_context_function_has_file_size_check,
    "file_has_logger_info_add": _safe_context_file_has_logger_info_add,
    "args_contain_masking": _safe_context_args_contain_masking,
    "unit_has_os_path_join_and_commonprefix": _safe_context_unit_has_os_path_join_and_commonprefix,
    "unit_has_os_path_abspath_and_commonpath": _safe_context_unit_has_os_path_abspath_and_commonpath,
    "unit_has_os_path_abspath_and_startswith": _safe_context_unit_has_os_path_abspath_and_startswith,
    "var_truthiness_check": _safe_context_var_truthiness_check,
    "var_has_attribute": _safe_context_var_has_attribute,
    "binary_comparison": _safe_context_binary_comparison,
    "current_call_matches_ast": _safe_context_current_call_matches,
    "function_has_call_matching_ast": _safe_context_function_has_call_matching,
    "membership_check": _safe_context_membership_check,
    "url_validation": _safe_context_url_validation,
    "condition_matches_xpath": _safe_context_condition_matches_xpath,
    "matches_xpath": _safe_context_matches_xpath,
    "node_matches_xpath": _safe_context_node_matches_xpath,
    "unit_has_function_def": _safe_context_unit_has_function_def,
    "call_has_kwargs": _safe_context_call_has_kwargs,
    "call_with_kwarg": _safe_context_call_has_kwargs,
    "call_with_dict_kwarg": _safe_context_call_has_kwargs, 
    "call_with_kwarg_exact_list": _safe_context_call_has_kwargs,
    "receiver_of_method_with_arg": _safe_context_receiver_of_method_with_arg,
    "function_has_call_with_var_arg": _safe_context_function_has_call_with_var_arg,
    "try_after_source": _safe_context_try_after_source,
    "call_in_try_with_kwarg": _safe_context_call_in_try_with_kwarg,
    "csv_injection_sanitizer": _safe_context_csv_injection_sanitizer,
}


def match_safe_context(node, ctx_spec, var_name: str | None = None) -> bool:
    """Dispatcher: ctx_spec puo' essere una stringa o un dict tipizzato."""
    if isinstance(ctx_spec, str):
        if node.xpath(f"ancestor::src:{ctx_spec}", namespaces=NS):
            return True
        if node.xpath(f"ancestor::src:if_stmt[.//src:call//src:name[text()='{ctx_spec}']]", namespaces=NS):
            return True
        return False
    if isinstance(ctx_spec, dict):
        matcher = SAFE_CONTEXT_MATCHERS.get(ctx_spec.get("type"))
        return matcher(node, ctx_spec, var_name) if matcher else False
    return False


def is_in_safe_context(node, safe_contexts: list, var_name: str | None = None) -> bool:
    return any(match_safe_context(node, ctx, var_name) for ctx in safe_contexts)