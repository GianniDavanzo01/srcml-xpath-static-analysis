"""
safe_context_matchers.py
-------------------------
Predicati SAFE-CONTEXT per il motore. Include contesti semplici basati su stringa 
(tag strutturale o funzione guardia) e quelli tipizzati (oggetto {"type": "..."}), 
con il relativo registro e dispatcher.
"""

import re

from common import NS, get_call_name, call_arguments_match_ast, find_assignments

from language_adapter import PythonAdapter


def _safe_context_current_call_matches(node, spec: dict, var_name: str | None = None, adapter=None, imports=None) -> bool:
    """Verifica se il nodo corrente o il genitore diretto è una chiamata che rispetta i requisiti."""
    target_node = node
    
    if not target_node.tag.endswith("call"):
        call_ancestors = node.xpath("ancestor-or-self::src:call[1]", namespaces=NS)
        if not call_ancestors:
            return False
        target_node = call_ancestors[0]

    # return call_arguments_match_ast(target_node, spec)
    return call_arguments_match_ast(target_node, spec, adapter, imports)


def _safe_context_function_has_call_matching(node, spec: dict, var_name: str | None = None, adapter=None, imports=None) -> bool:
    """Cerca in tutta la funzione una chiamata che rispetti i requisiti degli argomenti."""
    target = _function_or_unit_scope(node)
    # return any(call_arguments_match_ast(c, spec) for c in target.xpath(".//src:call", namespaces=NS))
    return any(call_arguments_match_ast(c, spec, adapter, imports) for c in target.xpath(".//src:call", namespaces=NS))


def _function_or_unit_scope(node):
    """Ritorna la <src:function> più vicina che racchiude `node`, o l'intero <src:unit>."""
    parent_func = node.xpath("ancestor::src:function[1]", namespaces=NS)
    return parent_func[0] if parent_func else node.xpath("ancestor::src:unit[1]", namespaces=NS)[0]


# def _safe_context_parametrized_query(node, spec: dict, var_name: str | None = None, adapter=None, imports=None) -> bool:
#     call_node = node.xpath("ancestor::src:call[.//src:name[last()][text()='execute']][1]", namespaces=NS)
#     if not call_node:
#         return False

#     arg_list = call_node[0].xpath("./src:argument_list", namespaces=NS)
#     if not arg_list:
#         return False

#     args_text = "".join(arg_list[0].itertext())
#     has_placeholder = "%s" in args_text or "?" in args_text
#     has_param_tuple = bool(arg_list[0].xpath(".//src:argument[position()>1]", namespaces=NS))
#     return has_placeholder and has_param_tuple

def _safe_context_parametrized_query(node, spec: dict, var_name: str | None = None, adapter=None, imports=None) -> bool:
    """{"type": "parametrized_query", "method": "execute", "placeholders": ["%s", "?"]}"""
    # Configurabilità tramite JSON (default per compatibilità col codice Python legacy)
    target_method = spec.get("method", "execute")
    placeholders = spec.get("placeholders", ["%s", "?"])
    
    # 1. Trova la chiamata al metodo di esecuzione
    call_node = node.xpath(f"ancestor::src:call[.//src:name[last()][text()='{target_method}']][1]", namespaces=NS)
    if not call_node:
        return False

    arg_list = call_node[0].xpath("./src:argument_list", namespaces=NS)
    if not arg_list:
        return False
        
    # 2. Verifica strutturale: ci deve essere più di un argomento (es. execute(query, parametri))
    arguments = arg_list[0].xpath("./src:argument", namespaces=NS)
    if len(arguments) < 2:
        return False

    _adapter = adapter or PythonAdapter()
    
    # 3. Cerca i placeholder ESCLUSIVAMENTE all'interno dei letterali stringa reali
    for lit in arg_list[0].xpath(".//src:literal[@type='string']", namespaces=NS):
        lit_text = "".join(lit.itertext()).strip()
        normalized_lit = _adapter.normalize_string_literal(lit_text)
        
        # Verifica se uno dei placeholder è presente nella stringa SQL normalizzata
        if any(p in normalized_lit for p in placeholders):
            return True
            
    return False


def _safe_context_receiver_of_method(node, spec: dict, var_name: str | None = None, adapter=None, imports=None) -> bool:
    """{"type": "receiver_of_method", "method": "replace"}
    Rileva: la variabile taintata è il chiamante di un metodo specifico.
    """
    target_method = spec.get("method")
    if not target_method:
        return False

    _adapter = adapter or PythonAdapter()
    
    # 1. Recupera la lista degli operatori (es. ["."] o [".", "->"])
    ops = _adapter.member_access_operator()
    
    # 2. Costruisce la condizione OR per l'XPath
    ops_xpath = " or ".join(f"text()='{op}'" for op in ops)

    # 3. Inserisce la condizione dinamica nell'XPath
    method_nodes = node.xpath(
        f"following-sibling::src:operator[1][{ops_xpath}]/following-sibling::src:name[1]",
        namespaces=NS,
    )
    
    if method_nodes and "".join(method_nodes[0].itertext()).strip() == target_method:
        return True
    return False


def _safe_context_rhs_call(node, spec: dict, var_name: str | None = None, adapter=None, imports=None) -> bool:
    """{"type": "rhs_call", "call": ["os.environ.get", "os.getenv"]}
        Rileva se il lato destro dell'assegnazione/confronto in cui compare 'node'
        contiene una chiamata a una delle funzioni considerate sicure.
    """
    calls = spec.get("call", [])
    expr = node.xpath("ancestor::src:expr_stmt[1]//src:call | ancestor::src:condition[1]//src:call", namespaces=NS)
    for c in expr:
        # cn = get_call_name(c)
        cn = get_call_name(c, adapter, imports)
        if cn and any(cn == t or cn.endswith(f".{t}") for t in calls):
            return True
    return False


def _safe_context_function_has_method_call(node, spec: dict, var_name: str | None = None, adapter=None, imports=None) -> bool:
    """{"type": "function_has_method_call", "method": "replace", "args_contain": [";", "&"]}"""
    method = spec.get("method")
    args_contain = spec.get("args_contain", [])
    
    if not method or not args_contain:
        return False
        
    _adapter = adapter or PythonAdapter()
        
    target_node = _function_or_unit_scope(node)
    
    # 1. Trova tutte le chiamate che riguardano il metodo specificato (es. replace) nello scope
    calls = target_node.xpath(
        f".//src:call[./src:name//src:name[text()='{method}'] or ./src:name[text()='{method}']]", 
        namespaces=NS
    )
    
    found_literals = set()
    for c in calls:
        # 2. Controllo di pertinenza tramite Method Chaining:
        # Verifichiamo se var_name è presente nell'intera espressione (<src:expr>) che racchiude la chiamata,
        # coprendo così sia la chiamata iniziale che le successive concatenate con il punto (.)
        if var_name:
            enclosing_expr = c.xpath("ancestor::src:expr[1]", namespaces=NS)
            if enclosing_expr:
                expr_names = enclosing_expr[0].xpath(".//src:name", namespaces=NS)
                variable_matched = any("".join(n.itertext()).strip() == var_name for n in expr_names)
                if not variable_matched:
                    continue
            else:
                continue
                
        # 3. Estrazione sicura dei letterali stringa dagli argomenti
        arg_list = c.xpath("./src:argument_list", namespaces=NS)
        if not arg_list:
            continue
            
        arguments = arg_list[0].xpath("./src:argument", namespaces=NS)
        for arg in arguments:
            literals = arg.xpath(".//src:literal[@type='string']", namespaces=NS)
            for lit in literals:
                lit_text = "".join(lit.itertext()).strip()
                normalized_val = _adapter.normalize_string_literal(lit_text)
                found_literals.add(normalized_val)
                
    # 4. Verifica finale: l'insieme globale dei caratteri neutralizzati copre tutto ciò che è richiesto?
    if all(required_arg in found_literals for required_arg in args_contain):
        return True
        
    return False


def _safe_context_args_contain_string_literal(node, spec: dict, var_name: str | None = None, adapter=None, imports=None) -> bool:
    arg_list = node.xpath("./src:argument_list", namespaces=NS)
    if not arg_list:
        return False
        
    if arg_list[0].xpath(".//src:name", namespaces=NS):
        return False
        
    string_literals = arg_list[0].xpath(".//src:literal[@type='string']", namespaces=NS)
    if not string_literals:
        return False


    for literal in string_literals:
        testo_stringa = "".join(literal.itertext()).strip()
        if adapter and adapter.is_interpolated_string(testo_stringa):
            return False
            
    return True
            

def _safe_context_in_function_name(node, spec: dict, var_name: str | None = None, adapter=None, imports=None) -> bool:
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


def _safe_context_function_has_file_size_check(node, spec: dict, var_name: str | None = None, adapter=None, imports=None) -> bool:
    """{"type": "function_has_file_size_check"}
       Verifica se nello scope della funzione esiste un controllo sulla dimensione.
       Agnostica: ricava le proprietà da `spec` e gli operatori dal LanguageAdapter.
    """
    target = _function_or_unit_scope(node)
    
    _adapter = adapter or PythonAdapter()
    
    # 1. Recupera la lista degli operatori (es. ["."] o [".", "->"])
    ops = _adapter.member_access_operator()
    
    # 2. Costruisce la condizione OR per l'XPath
    ops_xpath = " or ".join(f"text()='{op}'" for op in ops)
    
    # 3. Preleva dal catalogo JSON le proprietà/metodi validi (default: ["file_size", "size"])
    size_properties = spec.get("size_properties", ["file_size", "size"])
    
    # 4. Ricerca generica nello scope della funzione
    for prop in size_properties:
        xpath_query = f".//src:operator[{ops_xpath}]/following-sibling::*[1][self::src:name[text()='{prop}']]"
        if target.xpath(xpath_query, namespaces=NS):
            return True
            
    # 5. Ricerca specifica dentro i blocchi condizionali (es. if file.size > 100)
    conditions = target.xpath(".//src:if_stmt//src:condition", namespaces=NS)
    for cond in conditions:
        for prop in size_properties:
            xpath_query = f".//src:operator[{ops_xpath}]/following-sibling::*[1][self::src:name[text()='{prop}']]"
            if cond.xpath(xpath_query, namespaces=NS):
                return True
                
    return False



def _safe_context_var_truthiness_check(node, spec: dict, var_name=None, adapter=None, imports=None) -> bool:
    """{"type": "var_truthiness_check", "scope": "enclosing", "require_state": "truthy"}
    "require_state": "truthy" quando il codice vulnerabile si trova all'interno del blocco if
    l'esecuzione avviene solo se la condizione è vera, la condizione deve esplicitamente affermare che il dato esiste ed è valido (non è nullo).
    "require_state": "falsy" quando il codice vulnerabile si trova fuori e dopo il blocco if"""
    if not var_name:
        return False

    search_scope = spec.get("scope", "enclosing")
    required_state = spec.get("require_state", "truthy" if search_scope == "enclosing" else "any")

    if search_scope == "enclosing":
        conditions = node.xpath("ancestor::src:if_stmt//src:condition", namespaces=NS)
    elif search_scope in ("file", "unit"):
        unit_node = node.xpath("ancestor::src:unit[1]", namespaces=NS)
        target = unit_node[0] if unit_node else _function_or_unit_scope(node)
        conditions = target.xpath(".//src:if_stmt//src:condition", namespaces=NS)
    else:
        target = _function_or_unit_scope(node)
        conditions = target.xpath(".//src:if_stmt//src:condition", namespaces=NS)

    _adapter = adapter or PythonAdapter()
    neg_op = _adapter.negation_operator()

    null_ops = _adapter.null_comparison_operators()
    falsy_ops = null_ops["falsy"]
    truthy_ops = null_ops["truthy"]

    all_ops = falsy_ops + truthy_ops
    xpath_op_condition = " or ".join(f"text()='{op}'" for op in all_ops)

    for cond in conditions:
        # --- A. Controllo Booleano Unario (es. !var o not var) ---
        negations = cond.xpath(f".//src:operator[text()='{neg_op}']", namespaces=NS)
        for nop in negations:
            next_node = nop.xpath("./following-sibling::*[not(self::src:comment)][1]", namespaces=NS)
            if next_node and next_node[0].tag.endswith("name"):
                if "".join(next_node[0].itertext()).strip() == var_name:
                    if required_state in ("falsy", "any"):
                        return True

        # --- B. Controllo Esplicito con Null (es. var == null, var != null) ---
        equality_ops = cond.xpath(f".//src:operator[{xpath_op_condition}]", namespaces=NS)
        for eq_op in equality_ops:
            op_text = "".join(eq_op.itertext()).strip()
            lhs = eq_op.xpath("./preceding-sibling::*[not(self::src:comment)][1]", namespaces=NS)
            rhs = eq_op.xpath("./following-sibling::*[not(self::src:comment)][1]", namespaces=NS)

            if not lhs or not rhs:
                continue

            lhs_text = "".join(lhs[0].itertext()).strip()
            rhs_text = "".join(rhs[0].itertext()).strip()

            is_null_check = (lhs_text == var_name and _adapter.is_none_literal(rhs_text)) or \
                            (_adapter.is_none_literal(lhs_text) and rhs_text == var_name)

            if is_null_check:
                if required_state == "truthy" and op_text in truthy_ops:
                    return True
                if required_state == "falsy" and op_text in falsy_ops:
                    return True
                if required_state == "any":
                    return True

        # --- C. Controllo Booleano nudo (es. if var:) ---
        if required_state in ("truthy", "any"):
            expr_children = cond.xpath("./src:expr", namespaces=NS)
            if len(expr_children) == 1:
                bare_names = expr_children[0].xpath("./src:name", namespaces=NS)
                if len(bare_names) == 1 and len(list(expr_children[0])) == 1:
                    if "".join(bare_names[0].itertext()).strip() == var_name:
                        return True

    return False



def _safe_context_condition_matches_xpath(node, spec: dict, var_name: str | None = None, adapter=None, imports=None) -> bool:
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


def _safe_context_matches_xpath(node, spec: dict, var_name: str | None = None, adapter=None, imports=None) -> bool:
    """{"type": "matches_xpath", "xpath": ".//src:call[.//src:name[text()='hmac']]"}
        Query XPath arbitrarie sull'intero scope.
    """
    xpath_template = spec.get("xpath")
    if not xpath_template:
        return False
        
    target = _function_or_unit_scope(node)
    xpath_query = xpath_template.replace("$VAR", var_name) if var_name else xpath_template
    return bool(target.xpath(xpath_query, namespaces=NS))


def _safe_context_node_matches_xpath(node, spec: dict, var_name: str | None = None, adapter=None, imports=None) -> bool:
    """{"type": "node_matches_xpath", "xpath": "ancestor::src:call[1]..."}
        Valuta una query XPath partendo ESATTAMENTE dal nodo individuato.
    """
    xpath_query = spec.get("xpath")
    if not xpath_query:
        return False
    result = node.xpath(xpath_query, namespaces=NS)
    return bool(result)


def _safe_context_var_has_attribute(node, spec: dict, var_name: str | None = None, adapter=None, imports=None) -> bool:
    """{"type": "var_has_attribute", "attribute": "text"}
        Verifica se la variabile taintata è immediatamente seguita da un accesso all'attributo specificato.
    """
    attr = spec.get("attribute")
    if not attr:
        return False

    _adapter = adapter or PythonAdapter()
    
    # 1. Recupera la lista degli operatori (es. ["."] o [".", "->"])
    ops = _adapter.member_access_operator()
    
    # 2. Costruisce la condizione OR per l'XPath
    ops_xpath = " or ".join(f"text()='{op}'" for op in ops)

    # 3. Inserisce la condizione dinamica nell'XPath
    attr_nodes = node.xpath(
        f"following-sibling::src:operator[1][{ops_xpath}]/following-sibling::src:name[1]",
        namespaces=NS,
    )
    
    if attr_nodes and "".join(attr_nodes[0].itertext()).strip() == attr:
        return True
    return False


def _safe_context_binary_comparison(node, spec: dict, var_name: str | None = None, adapter=None, imports=None) -> bool:
    """{"type": "binary_comparison", "operators": ["<"], "left_exact": ["size"], "right_exact": ["0"]}
        Verifica un confronto binario all'interno di un if_stmt.
        Sfrutta l'AST per separare lato sinistro (LHS) e destro (RHS), ignorando i commenti.
        left_exact/right_exact/... possono contenere il placeholder "$VAR",
        sostituito dinamicamente con var_name (es. la variabile usata come
        indice in un accesso subscript), per confronti legati al contesto.
    """
    target = _function_or_unit_scope(node)
    operators = spec.get("operators", [])

    def _resolve(values):
        return [v.replace("$VAR", var_name) if var_name else v for v in values]

    left_exact = _resolve(spec.get("left_exact", []))
    left_contains = _resolve(spec.get("left_contains", []))
    right_exact = _resolve(spec.get("right_exact", []))
    right_contains = _resolve(spec.get("right_contains", []))
    
    _adapter = adapter or PythonAdapter()

    conditions = target.xpath(".//src:if_stmt//src:condition", namespaces=NS)
    for cond in conditions:
        for op_val in operators:
            ops = cond.xpath(f".//src:operator[text()='{op_val}']", namespaces=NS)
            for op_node in ops:
                # 1. ISOLAMENTO STRUTTURALE: Prendiamo ESATTAMENTE il nodo precedente e successivo
                lhs_nodes = op_node.xpath("./preceding-sibling::*[not(self::src:comment)][1]", namespaces=NS)
                rhs_nodes = op_node.xpath("./following-sibling::*[not(self::src:comment)][1]", namespaces=NS)
                
                if not lhs_nodes or not rhs_nodes:
                    continue
                    
                # 2. ESTRAZIONE INTELLIGENTE: Deleghiamo all'adapter se è una stringa,
                # compattiamo solo se è un nome di variabile o un numero.
                def _extract_operand_text(operand_node):
                    if operand_node.tag.endswith("literal") and operand_node.get("type") == "string":
                        lit_text = "".join(operand_node.itertext()).strip()
                        return _adapter.normalize_string_literal(lit_text)
                        
                    return "".join(operand_node.itertext()).replace(" ", "").replace("\n", "")

                lhs_text = _extract_operand_text(lhs_nodes[0])
                rhs_text = _extract_operand_text(rhs_nodes[0])

                # 3. VERIFICA
                left_ok = True
                if left_exact or left_contains:
                    left_ok = (lhs_text in left_exact) or any(c in lhs_text for c in left_contains)

                right_ok = True
                if right_exact or right_contains:
                    right_ok = (rhs_text in right_exact) or any(c in rhs_text for c in right_contains)

                if left_ok and right_ok:
                    return True
                    
    return False


def _safe_context_membership_check(node, spec: dict, var_name: str | None = None, adapter=None, imports=None) -> bool:
    """{"type": "membership_check", "scope": "enclosing"}
        Versione agnostica e basata sull'AST per il controllo di appartenenza (Allowlist).
        Elimina il flattening in stringhe e de-lega la semantica al LanguageAdapter.
    """
    if not adapter:
        return False

    search_scope = spec.get("scope", "function")
    target_for_assignments = _function_or_unit_scope(node)
    
    if search_scope == "enclosing":
        conditions = node.xpath("ancestor::src:if_stmt[1]//src:condition", namespaces=NS)
    else:
        conditions = target_for_assignments.xpath(".//src:if_stmt//src:condition", namespaces=NS)
        
    require_var_left = spec.get("require_var_left", False)
    require_var_right = spec.get("require_var_right", False)
    left_exact = spec.get("left_exact", [])
    right_exact = spec.get("right_exact", [])
    right_is_bare_identifier = spec.get("right_is_bare_identifier", False)
    require_collection_assignment = spec.get("require_collection_assignment", False)
    
    # Sostituisce l'hardcoding ["in", "not in"] con una specifica booleana generale
    allowed_negation = spec.get("allowed_negation", [True, False]) 

    # 1. Analisi delle assegnazioni di collezioni (Totalmente guidata dai tag AST)
    if require_collection_assignment:
        assign_op = adapter.assignment_operator_token()
        assignments = target_for_assignments.xpath(f".//src:expr_stmt[.//src:operator[text()='{assign_op}']]", namespaces=NS)
        
        has_coll_assign = False
        for assign in assignments:
            # L'adapter analizza i tag specifici del linguaggio (es. <src:list> in Python, <src:array> in Java)
            if adapter.is_collection_assignment(assign, NS):
                has_coll_assign = True
                break
        if not has_coll_assign:
            return False

    # 2. Analisi Strutturale delle Condizioni
    for cond in conditions:
        # L'adapter identifica il costrutto ('in' per Python, '.contains()' per Java, array interation per C)
        # Ritorna una lista di dizionari: {"lhs": nodo, "rhs": nodo, "is_negated": bool}
        membership_relations = adapter.extract_membership_relations(cond, NS)
        
        for relation in membership_relations:
            lhs_node = relation.get("lhs")
            rhs_node = relation.get("rhs")
            is_negated = relation.get("is_negated", False)
            
            if is_negated not in allowed_negation:
                continue

            # --- LATO SINISTRO (LHS) ---
            left_ok = True
            if require_var_left and var_name:
                # Ricerca nativa XPath sul tag nome, elimina la necessità delle regex
                if not lhs_node.xpath(f"descendant-or-self::src:name[text()='{var_name}']", namespaces=NS):
                    left_ok = False
                    
            if left_exact:
                # Estrae in modo sicuro solo i valori letterali, ignorando commenti o token spuri
                lhs_values = [n.text for n in lhs_node.xpath("descendant-or-self::src:name | descendant-or-self::src:literal", namespaces=NS) if n.text]
                if not any(val in left_exact for val in lhs_values):
                    left_ok = False

            # --- LATO DESTRO (RHS) ---
            right_ok = True
            if require_var_right and var_name:
                if not rhs_node.xpath(f"descendant-or-self::src:name[text()='{var_name}']", namespaces=NS):
                    right_ok = False
                    
            if right_exact:
                rhs_values = [n.text for n in rhs_node.xpath("descendant-or-self::src:name | descendant-or-self::src:literal", namespaces=NS) if n.text]
                if not any(val in right_exact for val in rhs_values):
                    right_ok = False

            if right_is_bare_identifier:
                # Verifica AST rigorosa: ammette esattamente UN tag <src:name> e NESSUN costrutto complesso
                names = rhs_node.xpath("descendant-or-self::src:name", namespaces=NS)
                complex_tags = rhs_node.xpath("descendant-or-self::src:call | descendant-or-self::src:index | descendant-or-self::src:operator", namespaces=NS)
                if len(names) != 1 or len(complex_tags) > 0:
                    right_ok = False

            if left_ok and right_ok:
                return True

    return False



def _safe_context_call_has_kwargs(node, spec: dict, var_name: str | None = None, adapter=None, imports=None) -> bool:
    calls = spec.get("call", [])
    _adapter = adapter or PythonAdapter()
    
    call_node = node.xpath("ancestor-or-self::src:call[1]", namespaces=NS)
    if not call_node:
        return False
        
    call_name = get_call_name(call_node[0], _adapter, imports)
    if call_name is None or not any(call_name == c or call_name.endswith(f".{c}") for c in calls):
        return False

    arg_list_nodes = call_node[0].xpath("./src:argument_list", namespaces=NS)
    if not arg_list_nodes:
        return not spec.get("kwargs") and not spec.get("dict_key") and not spec.get("allowed_values")
        
    arguments = arg_list_nodes[0].xpath("./src:argument", namespaces=NS)
    
    found_kwargs = {}
    found_kwarg_nodes = {}
    for arg in arguments:
        if _adapter.is_kwarg(arg, NS):
            name_node = arg.xpath("./src:name[1]", namespaces=NS)
            if not name_node:
                continue
            key_name = "".join(name_node[0].itertext()).strip()

            val_nodes = arg.xpath("./src:expr[1] | ./src:literal[1]", namespaces=NS)
            if val_nodes:
                found_kwarg_nodes[key_name] = val_nodes[0]
                val_text = "".join(val_nodes[0].itertext()).strip()
                found_kwargs[key_name] = _adapter.normalize_string_literal(val_text)

    kwarg_name = spec.get("kwarg")

    # Caso: valore del kwarg e' un dict letterale, richiediamo una coppia chiave/valore specifica
    if kwarg_name and spec.get("dict_key"):
        value_node = found_kwarg_nodes.get(kwarg_name)
        if value_node is None:
            return False
        dict_key = spec.get("dict_key")
        dict_val = spec.get("dict_value")
        # Navigazione strutturale: literal-stringa che rappresenta la chiave,
        # poi il suo valore tramite l'operatore ':' che lo segue nell'AST.
        for kl in value_node.xpath(".//src:literal[@type='string']", namespaces=NS):
            if _adapter.normalize_string_literal("".join(kl.itertext()).strip()) != dict_key:
                continue
            colon = kl.xpath("following-sibling::src:operator[1][text()=':']", namespaces=NS)
            if not colon:
                continue
            val_sib = colon[0].xpath("following-sibling::*[1]", namespaces=NS)
            if val_sib:
                raw_val = "".join(val_sib[0].itertext()).strip()
                normalized_val = _adapter.normalize_string_literal(raw_val)
                if normalized_val == str(dict_val):
                    return True
        return False

    # Caso: valore del kwarg e' una lista letterale, richiediamo uno degli elementi ammessi
    if kwarg_name and spec.get("allowed_values"):
        value_node = found_kwarg_nodes.get(kwarg_name)
        if value_node is None:
            return False
        found_elements = {
            _adapter.normalize_string_literal("".join(e.itertext()).strip())
            for e in value_node.xpath(".//src:literal[@type='string']", namespaces=NS)
        }
        return bool(found_elements & {str(v) for v in spec.get("allowed_values", [])})

    kwargs = spec.get("kwargs", {})
    if kwargs:
        require_mode = spec.get("require", "any")
        if require_mode == "all":
            return all(found_kwargs.get(k) == _adapter.normalize_string_literal(str(v)) for k, v in kwargs.items())
        else:
            return any(found_kwargs.get(k) == _adapter.normalize_string_literal(str(v)) for k, v in kwargs.items())
            
    return True


def _safe_context_receiver_of_method_with_arg(node, spec: dict, var_name: str | None = None, adapter=None, imports=None) -> bool:
    """{"type": "receiver_of_method_with_arg", "method": "endswith", "arg_value": ".png"}"""
    target_method = spec.get("method")
    target_arg = spec.get("arg_value")
    
    if not target_method or not target_arg or not var_name:
        return False

    _adapter = adapter or PythonAdapter()
    
    ops = _adapter.member_access_operator()
    ops_xpath = " or ".join(f"text()='{op}'" for op in ops)

    conditions = node.xpath("ancestor::src:if_stmt//src:condition", namespaces=NS)
    
    for cond in conditions:
        var_nodes = cond.xpath(f".//src:name[text()='{var_name}']", namespaces=NS)
        
        for v_node in var_nodes:
            method_nodes = v_node.xpath(
                f"following-sibling::src:operator[1][{ops_xpath}]/following-sibling::src:name[1]",
                namespaces=NS,
            )
            
            if method_nodes and "".join(method_nodes[0].itertext()).strip() == target_method:
                
                call_node = v_node.xpath("ancestor::src:call[1]", namespaces=NS)
                if not call_node:
                    continue
                    
                arg_list = call_node[0].xpath("./src:argument_list", namespaces=NS)
                if not arg_list:
                    continue
                    
                arguments = arg_list[0].xpath("./src:argument", namespaces=NS)
                for arg in arguments:
                    literals = arg.xpath(".//src:literal[@type='string']", namespaces=NS)
                    for lit in literals:
                        lit_text = "".join(lit.itertext()).strip()
                        normalized_lit = _adapter.normalize_string_literal(lit_text)
                        
                        if normalized_lit == target_arg:
                            return True
                            
    return False


def _safe_context_function_has_call_with_var_arg(node, spec: dict, var_name: str | None = None, adapter=None, imports=None) -> bool:
    """{"type": "function_has_call_with_var_arg", "call": ["os.path.isfile"]}"""
    if not var_name:
        return False
    target_calls = spec.get("call", [])
    if not target_calls:
        return False

    target = _function_or_unit_scope(node)
    for call_node in target.xpath(".//src:call", namespaces=NS):
        # call_name = get_call_name(call_node)
        call_name = get_call_name(call_node, adapter, imports)
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



def _safe_context_try_after_source(node, spec: dict, var_name: str | None = None, adapter=None, imports=None) -> bool:
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
    _adapter = adapter or PythonAdapter()
    for assign, _, _ in find_assignments(scope, _adapter, var_name):
        assign_try = assign.xpath("ancestor::src:try[1]", namespaces=NS)
        # if assign_try and assign_try[0] is try_node:
        if assign_try and assign_try[0] == try_node:
            return False
    return True


SAFE_CONTEXT_MATCHERS = {
    "parametrized_query": _safe_context_parametrized_query,
    "receiver_of_method": _safe_context_receiver_of_method,
    "rhs_call": _safe_context_rhs_call,
    "function_has_method_call": _safe_context_function_has_method_call,
    "args_contain_string_literal": _safe_context_args_contain_string_literal,
    "in_function_name": _safe_context_in_function_name,
    "function_has_file_size_check": _safe_context_function_has_file_size_check,
    "var_truthiness_check": _safe_context_var_truthiness_check,
    "var_has_attribute": _safe_context_var_has_attribute,
    "binary_comparison": _safe_context_binary_comparison,
    "current_call_matches_ast": _safe_context_current_call_matches,
    "function_has_call_matching_ast": _safe_context_function_has_call_matching,
    "membership_check": _safe_context_membership_check,
    "condition_matches_xpath": _safe_context_condition_matches_xpath,
    "matches_xpath": _safe_context_matches_xpath,
    "node_matches_xpath": _safe_context_node_matches_xpath,
    "call_has_kwargs": _safe_context_call_has_kwargs,
    "call_with_kwarg": _safe_context_call_has_kwargs,
    "call_with_dict_kwarg": _safe_context_call_has_kwargs, 
    "call_with_kwarg_exact_list": _safe_context_call_has_kwargs,
    "receiver_of_method_with_arg": _safe_context_receiver_of_method_with_arg,
    "function_has_call_with_var_arg": _safe_context_function_has_call_with_var_arg,
    "try_after_source": _safe_context_try_after_source,
}


def match_safe_context(node, ctx_spec, var_name: str | None = None, adapter=None, imports=None) -> bool:
    """Dispatcher: ctx_spec puo' essere un dict tipizzato o una stringa (scorciatoia strutturale)."""
    
    # 1. Shorthand Strutturale (es. "try", "while", "if_stmt")
    # Cerca esclusivamente il tag XML corrispondente tra gli ancestor.
    if isinstance(ctx_spec, str):
        return bool(node.xpath(f"ancestor::src:{ctx_spec}", namespaces=NS))
        
    # 2. Matcher Tipizzato (es. {"type": "var_truthiness_check", ...})
    if isinstance(ctx_spec, dict):
        matcher = SAFE_CONTEXT_MATCHERS.get(ctx_spec.get("type"))
        return matcher(node, ctx_spec, var_name, adapter, imports) if matcher else False
        
    return False


def is_in_safe_context(node, safe_contexts: list, var_name: str | None = None, adapter=None, imports=None) -> bool:
    return any(match_safe_context(node, ctx, var_name, adapter, imports) for ctx in safe_contexts)