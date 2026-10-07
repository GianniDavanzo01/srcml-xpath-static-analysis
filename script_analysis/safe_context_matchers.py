"""
safe_context_matchers.py
-------------------------
Predicati SAFE-CONTEXT per il motore. Include contesti semplici basati su stringa 
(tag strutturale o funzione guardia) e quelli tipizzati (oggetto {"type": "..."}), 
con il relativo registro e dispatcher.
"""

from common import NS, get_call_name, call_arguments_match_ast, find_assignments,_pos_key, block_exits_flow, enclosing_scope, \
    call_matches, own_literals, assignment_pairs, name_text

import re


#HELPER PER _safe_context_parametrized_query e _safe_context_function_has_method_call
def _spec_call_patterns(spec: dict) -> list:
    """Pattern di call dallo spec. 'call' ha la precedenza; 'method' = '*.method' (retrocompatibile)."""
    calls = spec.get("call")
    if isinstance(calls, str):
        calls = [calls]
    if calls:
        return calls
    method = spec.get("method")
    return [f"*.{method}"] if method else []



def _safe_context_current_call_matches(node, spec: dict, var_name, adapter, imports) -> bool:
    """Verifica se il nodo corrente o il genitore diretto è una chiamata che rispetta i requisiti."""
    target_node = node
    
    if not target_node.tag.endswith("call"):
        call_ancestors = node.xpath("ancestor-or-self::src:call[1]", namespaces=NS)
        if not call_ancestors:
            return False
        target_node = call_ancestors[0]

    return call_arguments_match_ast(target_node, spec, adapter, imports)


def _safe_context_function_has_call_matching(node, spec: dict, var_name, adapter, imports) -> bool:
    """Cerca in tutta la funzione una chiamata che rispetti i requisiti degli argomenti."""
    target = _function_or_unit_scope(node, adapter)
    return any(call_arguments_match_ast(c, spec, adapter, imports) for c in target.xpath(".//src:call", namespaces=NS))



def _function_or_unit_scope(node, adapter):
    scope = enclosing_scope(node, adapter)
    return scope if scope is not None else node.xpath("ancestor::src:unit[1]", namespaces=NS)[0]


def _safe_context_parametrized_query(node, spec, var_name, adapter, imports) -> bool:
    """{"type": "parametrized_query", "call": ["*.cursor.execute"],
        "placeholders": ["%s", "?"], "min_args": 2, "query_arg_index": 0}"""
     
    targets = _spec_call_patterns(spec)
    placeholders = spec.get("placeholders")
    if not targets:
        return False

    # call più vicina che racchiude il nodo ed è tra quelle cercate
    call_node = None
    for c in reversed(node.xpath("ancestor::src:call", namespaces=NS)):
        cn = get_call_name(c, adapter, imports)
        if cn and any(call_matches(cn, t, adapter) for t in targets):
            call_node = c
            break
    if call_node is None:
        return False

    arg_list = call_node.xpath("./src:argument_list", namespaces=NS)
    if not arg_list:
        return False

    args = arg_list[0].xpath("./src:argument", namespaces=NS)
    if len(args) < spec.get("min_args", 1):
        return False

    q_idx = spec.get("query_arg_index", 0)
    if q_idx >= len(args):
        return False
    query_arg = args[q_idx]

    if node is query_arg or query_arg in node.iterancestors():
        return False

    def _query_literals(call_node, query_arg, adapter):
        """Letterali stringa della query: diretti, oppure dell'ultima assegnazione
        della variabile se l'argomento e' un nome semplice."""
        direct = [l for l in own_literals(call_node, "string")
                if query_arg in l.iterancestors()]
        if direct:
            return direct

        expr = query_arg.xpath("./src:expr", namespaces=NS)
        expr = expr[0] if expr else query_arg
        names = expr.xpath("./src:name[not(src:index)]", namespaces=NS)
        if len(names) != 1 or len(list(expr)) != 1:
            return []
        var = "".join(names[0].itertext()).strip()

        scope = _function_or_unit_scope(call_node, adapter)
        key = _pos_key(call_node)
        prior = [(s, r) for s, _, r in find_assignments(scope, adapter, var)
                if r is not None and _pos_key(s) < key]
        if not prior:
            return []
        _, rhs = max(prior, key=lambda t: _pos_key(t[0]))
        return rhs.xpath("self::src:literal[@type='string'] | .//src:literal[@type='string']",
                        namespaces=NS)

    # placeholder solo nei letterali stringa di QUESTA call (non di call annidate)
    for lit in _query_literals(call_node, query_arg, adapter):
        text = "".join(lit.itertext()).strip()
        if adapter.is_interpolated_string(text):
            continue
        if any(p in adapter.normalize_string_literal(text) for p in placeholders):
            return True
    return False




def _safe_context_rhs_call(node, spec: dict, var_name, adapter, imports) -> bool:
    """{"type": "rhs_call", "call": ["os.environ.get", "os.getenv"]}
        Rileva se il lato destro dell'assegnazione/confronto in cui compare 'node'
        contiene una chiamata a una delle funzioni considerate sicure.
    """
    calls = spec.get("call", [])
    expr = node.xpath("ancestor::src:expr_stmt[1]//src:call | ancestor::src:condition[1]//src:call", namespaces=NS)
    for c in expr:
        cn = get_call_name(c, adapter, imports)
        if cn and any(call_matches(cn, t, adapter) for t in calls):
            return True
    return False


def _safe_context_function_has_method_call(node, spec, var_name, adapter, imports) -> bool:
    """{"type": "function_has_method_call", "call": ["*.replace"], "args_contain": [";", "&"]}"""
    targets = _spec_call_patterns(spec)
    args_contain = spec.get("args_contain", [])
    if not targets or not args_contain:
        return False

    scope = _function_or_unit_scope(node, adapter)
    found_literals = set()

    for c in scope.xpath(".//src:call", namespaces=NS):
        cn = get_call_name(c, adapter, imports)
        if not cn or not any(call_matches(cn, t, adapter) for t in targets):
            continue

        # pertinenza: var_name compare nell'espressione che racchiude la call (method chaining)
        if var_name:
            expr = c.xpath("ancestor::src:expr[1]", namespaces=NS)
            if not expr:
                continue
            names = expr[0].xpath(".//src:name", namespaces=NS)
            if not any("".join(n.itertext()).strip() == var_name for n in names):
                continue

        for lit in own_literals(c, "string"):
            text = "".join(lit.itertext()).strip()
            found_literals.add(adapter.normalize_string_literal(text) )

    return all(a in found_literals for a in args_contain)


def _safe_context_args_contain_string_literal(node, spec: dict, var_name, adapter, imports) -> bool:
    """
    Verifica che una chiamata a funzione utilizzi stringhe letterali statiche.
    Ritorna `True` solo se vengono rispettate tutte le seguenti condizioni:
    1. Non sono presenti variabili negli argomenti (ignorando le chiavi dei kwargs).
    2. Non ci sono chiamate a funzioni annidate (es. `eval("1", func())`).
    3. È presente almeno una stringa letterale pura, senza alcuna interpolazione o formattazione.
    """
    # 1. partiamo sempre dal nodo Call che racchiude l'istruzione
    call_nodes = node.xpath("ancestor-or-self::src:call[1]", namespaces=NS)
    if not call_nodes:
        return False
        
    arg_lists = call_nodes[0].xpath("./src:argument_list", namespaces=NS)
    if not arg_lists:
        return False
        
    # 2. Controllo granulare delle variabili (ignorando le chiavi dei kwargs)
    arguments = arg_lists[0].xpath("./src:argument", namespaces=NS)
    for arg in arguments:
        names = arg.xpath(".//src:name", namespaces=NS)
        if names:
            if adapter.is_kwarg(arg, NS):
                # Se è un kwarg e ha più di un nome, significa che anche il valore è una variabile
                if len(names) > 1:
                    return False
            else:
                # E' un argomento posizionale che contiene una variabile
                return False
                
        # Blocchiamo anche funzioni annidate: es. eval("1", request.get())
        if arg.xpath(".//src:call", namespaces=NS):
            return False

    # 3. Requisito base: ci DEVE essere almeno una stringa letterale
    string_literals = arg_lists[0].xpath(".//src:literal[@type='string']", namespaces=NS)
    if not string_literals:
        return False

    # 4. Deleghiamo il controllo dell'interpolazione all'adapter passando il NODO
    for literal in string_literals:
        # L'adapter gestirà l'estrazione testuale o l'analisi dei sottonodi
        testo = "".join(literal.itertext())
        if adapter.is_interpolated_string(testo):
            return False
            
    return True
            

def _safe_context_in_function_name(node, spec: dict, var_name, adapter, imports) -> bool:
    """{"type": "in_function_name", "name": "is_valid_pkcs1v15_padding"}
        Rileva se il nodo si trova all'interno di una funzione con il nome specificato.
    """
    target = spec.get("name")
    func = enclosing_scope(node, adapter)
    if func is not None:
        name_nodes = func.xpath("./src:name", namespaces=NS)
        if name_nodes and "".join(name_nodes[0].itertext()).strip() == target:
            return True
    return False

def _safe_context_function_has_file_size_check(node, spec: dict, var_name, adapter, imports) -> bool:
    """{"type": "function_has_file_size_check"}
       Sicuro solo se il sink e' effettivamente protetto da un controllo di
       dimensione: o si trova DENTRO il blocco 'if size <= MAX:', oppure
       si trova DOPO un guard-clause 'if size > MAX: <exit>'.
    """
    
    ops = adapter.member_access_operator()
    ops_xpath = " or ".join(f"text()='{op}'" for op in ops)
    size_properties = spec.get("size_properties", ["file_size", "size"])

    upper_bound_ops = [">", ">="]
    lower_bound_ops = ["<", "<="]

    node_key = _pos_key(node)

    def _find_logical_comparisons(cond):
        """Ritorna l'operatore LOGICO rispetto alla proprietà 'size'."""
        matches = []
        for prop in size_properties:
            prop_nodes = cond.xpath(
                f".//src:operator[{ops_xpath}]/following-sibling::*[1][self::src:name[text()='{prop}']]",
                namespaces=NS
            )
            for pnode in prop_nodes:
                # Se la proprietà è invocata come metodo (es. file.getSize()), l'operatore
                # relazionale si trova allo stesso livello gerarchico del tag <call>. 
                # Se è una variabile pura (es. file.size in Python), sarà fratello del <name>.
                outer_call = pnode.xpath("ancestor::src:call[1]", namespaces=NS)
                outer_name = pnode.xpath("ancestor::src:name[not(ancestor::src:name)]", namespaces=NS)
                
                search_node = outer_call[0] if outer_call else (outer_name[0] if outer_name else pnode)

                # Proprietà a SINISTRA (es. file.getSize() > MAX)
                following_op = search_node.xpath("following-sibling::src:operator[1]", namespaces=NS)
                if following_op:
                    op_text = "".join(following_op[0].itertext()).strip()
                    if op_text in upper_bound_ops + lower_bound_ops:
                        matches.append(op_text)

                # Proprietà a DESTRA (es. MAX < file.getSize()) -> Invertiamo l'operatore
                preceding_op = search_node.xpath("preceding-sibling::src:operator[1]", namespaces=NS)
                if preceding_op:
                    op_text = "".join(preceding_op[0].itertext()).strip()
                    if op_text == "<": matches.append(">")
                    elif op_text == "<=": matches.append(">=")
                    elif op_text == ">": matches.append("<")
                    elif op_text == ">=": matches.append("<=")
                    
        return matches

    # --- Caso A: il sink è DENTRO il blocco 'if size <= MAX:' ---
    enclosing_ifs = node.xpath("ancestor::src:if_stmt", namespaces=NS)
    for if_stmt in enclosing_ifs:
        cond = if_stmt.xpath("./src:if/src:condition", namespaces=NS)
        block = if_stmt.xpath("./src:if/src:block", namespaces=NS)
        if not cond or not block:
            continue
            
        if node not in block[0].iter():
            continue
            
        cmp_found = _find_logical_comparisons(cond[0])
        if any(op in lower_bound_ops for op in cmp_found):
            return True

    # --- Caso B: guard-clause precedente 'if size > MAX: <exit>' ---
    scope = _function_or_unit_scope(node, adapter)
    all_if_stmts = scope.xpath(".//src:if_stmt", namespaces=NS)
    
    for if_stmt in all_if_stmts:
        if _pos_key(if_stmt) >= node_key:
            continue
            
        cond = if_stmt.xpath("./src:if/src:condition", namespaces=NS)
        block = if_stmt.xpath("./src:if/src:block", namespaces=NS)
        if not cond or not block:
            continue
            
        # FIX CRITICO: Il nodo NON deve trovarsi all'interno del blocco 'if' che funge da guard clause!
        # Se si trova lì dentro, viene eseguito proprio quando il limite è superato, quindi è vulnerabile.
        if node in block[0].iter():
            continue
            

        if not block_exits_flow(block[0], adapter, imports):
            continue
            
        cmp_found = _find_logical_comparisons(cond[0])
        if any(op in upper_bound_ops for op in cmp_found):
            return True

    return False



def _safe_context_var_truthiness_check(node, spec: dict, var_name, adapter, imports) -> bool:
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
        target = unit_node[0] if unit_node else _function_or_unit_scope(node, adapter)
        conditions = target.xpath(".//src:if_stmt//src:condition", namespaces=NS)
    else:
        target = _function_or_unit_scope(node, adapter)
        conditions = target.xpath(".//src:if_stmt//src:condition", namespaces=NS)

    neg_op = adapter.negation_operator()

    null_ops = adapter.null_comparison_operators()
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
                # if "".join(next_node[0].itertext()).strip() == var_name:
                if name_text(next_node[0]) == var_name:
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

            # lhs_text = "".join(lhs[0].itertext()).strip()
            # rhs_text = "".join(rhs[0].itertext()).strip()
            # name_text() per i nomi di variabili, altrimenti teniamo il testo grezzo (es. per 'null')
            lhs_text = name_text(lhs[0]) if lhs[0].tag.endswith("name") else "".join(lhs[0].itertext()).strip()
            rhs_text = name_text(rhs[0]) if rhs[0].tag.endswith("name") else "".join(rhs[0].itertext()).strip()

            is_null_check = (lhs_text == var_name and adapter.is_none_literal(rhs_text)) or \
                            (adapter.is_none_literal(lhs_text) and rhs_text == var_name)

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
                    # if "".join(bare_names[0].itertext()).strip() == var_name:
                    if name_text(bare_names[0]) == var_name:
                        return True

    return False



def _safe_context_condition_matches_xpath(node, spec: dict, var_name, adapter, imports) -> bool:
    """{"type": "condition_matches_xpath", "xpath": ".//src:call[src:name='isinstance']"}
        Permette query strutturali XPath native sull'AST in questo caso all'interno di una <condition>.
    """
    xpath_template = spec.get("xpath")
    if not xpath_template:
        return False
        
    search_scope = spec.get("scope", "function")
    target = _function_or_unit_scope(node, adapter)
    
    if search_scope == "enclosing":
        conditions = node.xpath("ancestor::src:if_stmt//src:condition", namespaces=NS)
    else:
        conditions = target.xpath(".//src:if_stmt//src:condition", namespaces=NS)
        
    xpath_query = xpath_template.replace("$VAR", var_name) if var_name else xpath_template

    for cond in conditions:
        if cond.xpath(xpath_query, namespaces=NS):
            return True
            
    return False


def _safe_context_matches_xpath(node, spec: dict, var_name, adapter, imports) -> bool:
    """{"type": "matches_xpath", "xpath": ".//src:call[.//src:name[text()='hmac']]"}
        Query XPath arbitrarie sull'intero scope.
    """
    xpath_template = spec.get("xpath")
    if not xpath_template:
        return False
        
    target = _function_or_unit_scope(node, adapter)
    xpath_query = xpath_template.replace("$VAR", var_name) if var_name else xpath_template
    return bool(target.xpath(xpath_query, namespaces=NS))


def _safe_context_node_matches_xpath(node, spec: dict, var_name, adapter, imports) -> bool:
    """{"type": "node_matches_xpath", "xpath": "ancestor::src:call[1]..."}
        Valuta una query XPath partendo ESATTAMENTE dal nodo individuato.
    """
    xpath_query = spec.get("xpath")
    if not xpath_query:
        return False
    result = node.xpath(xpath_query, namespaces=NS)
    return bool(result)


def _safe_context_binary_comparison(node, spec: dict, var_name, adapter, imports) -> bool:
    """{"type": "binary_comparison", "operators": ["<"], "left_exact": ["size"], "right_exact": ["0"]}
        Verifica un confronto binario all'interno di un if_stmt.
        Sfrutta l'AST per separare lato sinistro (LHS) e destro (RHS), ignorando i commenti.
        left_exact/right_exact/... possono contenere il placeholder "$VAR",
        sostituito dinamicamente con var_name (es. la variabile usata come
        indice in un accesso subscript), per confronti legati al contesto.
    """
    target = _function_or_unit_scope(node, adapter)
    operators = spec.get("operators", [])

    def _resolve(values):
        return [v.replace("$VAR", var_name) if var_name else v for v in values]

    left_exact = _resolve(spec.get("left_exact", []))
    left_contains = _resolve(spec.get("left_contains", []))
    right_exact = _resolve(spec.get("right_exact", []))
    right_contains = _resolve(spec.get("right_contains", []))
    left_not = _resolve(spec.get("left_not_exact", []))
    right_not = _resolve(spec.get("right_not_exact", []))
    

    conditions = target.xpath(".//src:if_stmt//src:condition", namespaces=NS)
    for cond in conditions:
        for op_val in operators:
            ops = cond.xpath(f".//src:operator[text()='{op_val}']", namespaces=NS)
            for op_node in ops:
                # Prendiamo ESATTAMENTE il nodo precedente e successivo
                lhs_nodes = op_node.xpath("./preceding-sibling::*[not(self::src:comment)][1]", namespaces=NS)
                rhs_nodes = op_node.xpath("./following-sibling::*[not(self::src:comment)][1]", namespaces=NS)
                
                if not lhs_nodes or not rhs_nodes:
                    continue
                    
                # Deleghiamo all'adapter se è una stringa,
                # compattiamo solo se è un nome di variabile o un numero.
                def _extract_operand_text(operand_node):
                    if operand_node.tag.endswith("literal") and operand_node.get("type") == "string":
                        lit_text = "".join(operand_node.itertext()).strip()
                        return adapter.normalize_string_literal(lit_text)

                    if operand_node.tag.endswith("name"):
                        return name_text(operand_node)
                    
                    return "".join(operand_node.itertext()).replace(" ", "").replace("\n", "")

                lhs_text = _extract_operand_text(lhs_nodes[0])
                rhs_text = _extract_operand_text(rhs_nodes[0])

                # # VERIFICA CON REGEX WORD BOUNDARIES PER I 'CONTAINS'
                left_ok = True
                if left_exact or left_contains:
                    # left_ok = (lhs_text in left_exact) or any(c in lhs_text for c in left_contains)
                    left_ok = (lhs_text in left_exact) or any(
                        re.search(rf'\b{re.escape(c)}\b', lhs_text) for c in left_contains
                    )

                right_ok = True
                if right_exact or right_contains:
                    # right_ok = (rhs_text in right_exact) or any(c in rhs_text for c in right_contains)
                    right_ok = (rhs_text in right_exact) or any(
                        re.search(rf'\b{re.escape(c)}\b', rhs_text) for c in right_contains
                    )

                if left_not and lhs_text in left_not:
                    left_ok = False
                if right_not and rhs_text in right_not:
                    right_ok = False

                if left_ok and right_ok:
                    return True
                    
    return False


def _safe_context_membership_check(node, spec: dict, var_name, adapter, imports) -> bool:
    """{"type": "membership_check", "scope": "enclosing"}
        Verifica controllo di appartenenza (Allowlist).
    """

    search_scope = spec.get("scope", "function")
    target_for_assignments = _function_or_unit_scope(node, adapter)
    
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
        if not any(adapter.is_collection_assignment(stmt, NS)
                for stmt, _, _ in assignment_pairs(target_for_assignments, adapter)):
            return False

    # 2. Analisi Strutturale delle Condizioni
    for cond in conditions:
        # L'adapter identifica il costrutto ('in' per Python, '.contains()' per Java)
        # Ritorna una lista di dizionari: {"lhs": nodo, "rhs": nodo, "is_negated": bool}
        membership_relations = adapter.extract_membership_relations(cond, NS)
        
        for relation in membership_relations:
            lhs_node = relation.get("lhs")
            rhs_node = relation.get("rhs")
            is_negated = relation.get("is_negated", False)
            
            if is_negated not in allowed_negation:
                continue

            # HELPER PER L'ESTRAZIONE CORRETTA: name_text() per le variabili, itertext per i letterali
            def _get_node_val(n):
                return name_text(n) if n.tag.endswith("name") else "".join(n.itertext()).strip()

            # --- LATO SINISTRO (LHS) ---
            left_ok = True
            if require_var_left and var_name:
                # Ricerca nativa XPath sul tag nome
                if not lhs_node.xpath(f"descendant-or-self::src:name[text()='{var_name}']", namespaces=NS):
                    left_ok = False
                    
            if left_exact:
                # Estrae in modo sicuro solo i valori letterali, ignorando commenti o token spuri
                # lhs_values = [n.text for n in lhs_node.xpath("descendant-or-self::src:name | descendant-or-self::src:literal", namespaces=NS) if n.text]
                raw_lhs = lhs_node.xpath("descendant-or-self::src:name | descendant-or-self::src:literal", namespaces=NS)
                lhs_values = [_get_node_val(n) for n in raw_lhs]
                lhs_values = [v for v in lhs_values if v]  # filtra stringhe vuote

                if not any(val in left_exact for val in lhs_values):
                    left_ok = False

            # --- LATO DESTRO (RHS) ---
            right_ok = True
            if require_var_right and var_name:
                if not rhs_node.xpath(f"descendant-or-self::src:name[text()='{var_name}']", namespaces=NS):
                    right_ok = False
                    
            if right_exact:
                # rhs_values = [n.text for n in rhs_node.xpath("descendant-or-self::src:name | descendant-or-self::src:literal", namespaces=NS) if n.text]
                raw_rhs = rhs_node.xpath("descendant-or-self::src:name | descendant-or-self::src:literal", namespaces=NS)
                rhs_values = [_get_node_val(n) for n in raw_rhs]
                rhs_values = [v for v in rhs_values if v]  # filtra stringhe vuote
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


def _safe_context_call_has_kwargs(node, spec: dict, var_name, adapter, imports) -> bool:
    """
    Verifica la presenza di parametri passati per parola chiave (kwargs) in una chiamata a funzione (utilizzabile in python).
    Ritorna `True` se la chiamata include i kwargs specificati nel contesto di sicurezza. 
    È fondamentale per validare configurazioni esplicite che rendono sicura una funzione 
    altrimenti vulnerabile (es. `yaml.load(..., Loader=SafeLoader)` o cookie con `secure=True`).
    """
    calls = spec.get("call", [])
    
    call_node = node.xpath("ancestor-or-self::src:call[1]", namespaces=NS)
    if not call_node:
        return False
        
    call_name = get_call_name(call_node[0], adapter, imports)
    if call_name is None or not any(call_matches(call_name, c, adapter) for c in calls):
        return False

    arg_list_nodes = call_node[0].xpath("./src:argument_list", namespaces=NS)
    if not arg_list_nodes:
        return not spec.get("kwargs") and not spec.get("dict_key") and not spec.get("allowed_values")
        
    arguments = arg_list_nodes[0].xpath("./src:argument", namespaces=NS)
    
    found_kwargs = {}
    found_kwarg_nodes = {}
    for arg in arguments:
        if adapter.is_kwarg(arg, NS):
            name_node = arg.xpath("./src:name[1]", namespaces=NS)
            if not name_node:
                continue
            key_name = "".join(name_node[0].itertext()).strip()

            val_nodes = arg.xpath("./src:expr[1] | ./src:literal[1]", namespaces=NS)
            if val_nodes:
                found_kwarg_nodes[key_name] = val_nodes[0]
                val_text = "".join(val_nodes[0].itertext()).strip()
                found_kwargs[key_name] = adapter.normalize_string_literal(val_text)

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
            if adapter.normalize_string_literal("".join(kl.itertext()).strip()) != dict_key:
                continue
            val_node = adapter.get_dict_entry_value_node(kl, NS)
            if val_node is None:
                continue
            raw_val = "".join(val_node.itertext()).strip()
            if adapter.normalize_string_literal(raw_val) == str(dict_val):
                return True
        return False

    # Caso: valore del kwarg e' una lista letterale, richiediamo uno degli elementi ammessi
    if kwarg_name and spec.get("allowed_values"):
        value_node = found_kwarg_nodes.get(kwarg_name)
        if value_node is None:
            return False
        found_elements = {
            adapter.normalize_string_literal("".join(e.itertext()).strip())
            for e in value_node.xpath(".//src:literal[@type='string']", namespaces=NS)
        }
        return bool(found_elements & {str(v) for v in spec.get("allowed_values", [])})

    kwargs = spec.get("kwargs", {})
    if kwargs:
        require_mode = spec.get("require", "any")
        if require_mode == "all":
            return all(found_kwargs.get(k) == adapter.normalize_string_literal(str(v)) for k, v in kwargs.items())
        else:
            return any(found_kwargs.get(k) == adapter.normalize_string_literal(str(v)) for k, v in kwargs.items())
            
    return True


def _safe_context_receiver_of_method_with_arg(node, spec: dict, var_name, adapter, imports) -> bool:
    target_method = spec.get("method")
    dangerous_values = spec.get("dangerous_values")
    target_arg = spec.get("arg_value")  # retrocompatibilità
    if not target_method or not var_name or (dangerous_values is None and not target_arg):
        return False

    # Normalizzazione MAIUSCOLA per il catalogo
    dangerous_values_upper = [v.upper() for v in dangerous_values] if dangerous_values else None
    target_arg_upper = target_arg.upper() if target_arg else None

    op = adapter.member_access_operator()
    ops_xpath = " or ".join(f"text()='{o}'" for o in op) if isinstance(op, list) else f"text()='{op}'"
    neg_op = adapter.negation_operator()
    conditions = node.xpath("ancestor::src:if_stmt//src:condition", namespaces=NS)

    for cond in conditions:
        var_nodes = cond.xpath(f".//src:name[text()='{var_name}']", namespaces=NS)
        for v_node in var_nodes:
            current = v_node
            method_nodes = []
            while True:
                next_hop = current.xpath(
                    f"following-sibling::src:operator[1][{ops_xpath}]/following-sibling::src:name[1]",
                    namespaces=NS
                )
                if not next_hop:
                    break
                method_nodes = next_hop
                # if "".join(next_hop[0].itertext()).strip() == target_method:
                if name_text(next_hop[0]).strip() == target_method:
                    break
                current = next_hop[0]

            # if not method_nodes or "".join(method_nodes[0].itertext()).strip() != target_method:
            if not method_nodes or name_text(method_nodes[0]).strip() != target_method:
                continue

            call_node = method_nodes[0].xpath("ancestor::src:call[1]", namespaces=NS)
            if not call_node:
                continue

            string_literals = own_literals(call_node[0], "string")
            if not string_literals:
                continue

            # Normalizzazione MAIUSCOLA per i valori trovati nell'AST
            found_values_upper = [
                adapter.normalize_string_literal("".join(lit.itertext()).strip()).upper()
                for lit in string_literals
            ]
            if not found_values_upper:
                continue

            is_negated = bool(
                call_node[0].xpath(f"preceding-sibling::src:operator[1][text()='{neg_op}']", namespaces=NS)
            )

            if dangerous_values_upper is not None:
                # Confronto case-insensitive sicuro
                any_dangerous = any(v in dangerous_values_upper for v in found_values_upper)
                if not any_dangerous:
                    return True
                if any_dangerous and is_negated:
                    return True
            else:
                if target_arg_upper in found_values_upper:
                    return True
    return False


def _safe_context_function_has_call_with_var_arg(node, spec: dict, var_name, adapter, imports) -> bool:
    """{"type": "function_has_call_with_var_arg", "call": ["os.path.isfile"]}"""
    if not var_name:
        return False
    target_calls = spec.get("call", [])
    if not target_calls:
        return False

    target = _function_or_unit_scope(node, adapter)
    for call_node in target.xpath(".//src:call", namespaces=NS):
        call_name = get_call_name(call_node, adapter, imports)
        if not call_name or not any(call_matches(call_name,c, adapter) for c in target_calls):
            continue

        arg_list = call_node.xpath("./src:argument_list", namespaces=NS)
        if not arg_list:
            continue

        for arg in arg_list[0].xpath("./src:argument", namespaces=NS):
            arg_text = "".join(arg.itertext()).strip()
            if arg_text == var_name:
                return True

    return False



def _safe_context_try_after_source(node, spec: dict, var_name, adapter, imports) -> bool:
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

    scope = _function_or_unit_scope(node, adapter)

    for assign, _, _ in find_assignments(scope, adapter, var_name):
        assign_try = assign.xpath("ancestor::src:try[1]", namespaces=NS)
        if assign_try and assign_try[0] == try_node:
            return False
    return True


def _safe_context_var_falsy_guard_clause(node, spec: dict, var_name, adapter, imports) -> bool:
    if not var_name:
        return False

    neg_op = adapter.negation_operator()
    null_ops = adapter.null_comparison_operators()
    falsy_ops = null_ops["falsy"]

    scope = _function_or_unit_scope(node, adapter)
    all_if_stmts = scope.xpath(".//src:if_stmt", namespaces=NS)
    node_key = _pos_key(node)

    def _adjacent_is_and(boundary_node, direction: str, adapter) -> bool:
        axis = "preceding-sibling" if direction == "prev" else "following-sibling"
        adj = boundary_node.xpath(f"./{axis}::*[not(self::src:comment)][1]", namespaces=NS)
        if not adj or not adj[0].tag.endswith("}operator"):
            return False
        return "".join(adj[0].itertext()).strip() in adapter.logical_and_operator()
            

    for if_stmt in all_if_stmts:
        if _pos_key(if_stmt) >= node_key:
            continue

        cond = if_stmt.xpath("./src:if/src:condition", namespaces=NS)
        if not cond:
            continue
        cond = cond[0]

        block = if_stmt.xpath("./src:if/src:block[1]", namespaces=NS)

        if not block or not block_exits_flow(block[0], adapter, imports):
            continue

        # --- Condizione falsy: negazione (not var) ---
        for nop in cond.xpath(f".//src:operator[text()='{neg_op}']", namespaces=NS):
            next_node = nop.xpath("./following-sibling::*[not(self::src:comment)][1]", namespaces=NS)
            if next_node and next_node[0].tag.endswith("name"):
                # if "".join(next_node[0].itertext()).strip() == var_name:
                if name_text(next_node[0]) == var_name:
                    #scarta se "not var" e' congiunto in AND con altro -->anche se fosse True che la variabile è nulla 
                    #se l'altra condizione è False non si entra nell'if e si rischia di eseguire un operazione con la variabile nulla.
                    if _adjacent_is_and(nop, "prev",adapter) or _adjacent_is_and(next_node[0], "next",adapter):
                        continue
                    return True

        # --- Condizione falsy: confronto esplicito (var is None) ---
        for eq_op in cond.xpath(".//src:operator", namespaces=NS):
            op_text = "".join(eq_op.itertext()).strip()
            if op_text not in falsy_ops:
                continue
            lhs = eq_op.xpath("./preceding-sibling::*[not(self::src:comment)][1]", namespaces=NS)
            rhs = eq_op.xpath("./following-sibling::*[not(self::src:comment)][1]", namespaces=NS)
            if not lhs or not rhs:
                continue
            # lhs_text = "".join(lhs[0].itertext()).strip()
            # rhs_text = "".join(rhs[0].itertext()).strip()

            # name_text() per i nomi di variabili
            lhs_text = name_text(lhs[0]) if lhs[0].tag.endswith("name") else "".join(lhs[0].itertext()).strip()
            rhs_text = name_text(rhs[0]) if rhs[0].tag.endswith("name") else "".join(rhs[0].itertext()).strip()

            if (lhs_text == var_name and adapter.is_none_literal(rhs_text)) or \
               (adapter.is_none_literal(lhs_text) and rhs_text == var_name):
                # NUOVO: scarta se "var is None" e' congiunto in AND con altro
                if _adjacent_is_and(lhs[0], "prev",adapter) or _adjacent_is_and(rhs[0], "next",adapter):
                    continue
                return True

    return False


def _safe_context_all_args_are_literals(node, spec: dict, var_name, adapter, imports) -> bool:
    """
    {"type": "all_args_are_literals"}
    Verifica strutturalmente che tutti gli argomenti di una chiamata siano
    esclusivamente letterali, rifiutando qualsiasi variabile, chiamata a
    funzione o stringa con interpolazione (es. f-string Python, cioe' una
    stringa letterale che pero' incorpora una variabile al suo interno).
    """
    # 1. Identifica la chiamata nell'AST
    call_nodes = node.xpath("ancestor-or-self::src:call[1]", namespaces=NS)
    if not call_nodes:
        return False

    arg_lists = call_nodes[0].xpath("./src:argument_list", namespaces=NS)
    if not arg_lists:
        return False  # Chiamata senza argomenti (es. func()), non c'e' input dinamico, ma non rispetta la richiesta di argomenti letterali-->non si applica il safe_context

    # 2. Iterazione strutturale sui singoli argomenti (nodi <src:argument>)
    arguments = arg_lists[0].xpath("./src:argument", namespaces=NS)

    for arg in arguments:
        # A. Controllo chiamate annidate: se esiste un nodo <src:call> e' subito dinamico
        if arg.xpath(".//src:call", namespaces=NS):
            return False

        # B. Estrazione dei nodi variabile (<src:name>)
        names = arg.xpath(".//src:name", namespaces=NS)

        # C. Valutazione logica basata esclusivamente sul conteggio dei nodi
        if names:
            # Deleghiamo all'adapter (Indipendenza dal Linguaggio) la verifica del Keyword Argument
            if adapter.is_kwarg(arg, NS):
                # Strutturalmente, in un kwarg il primo <src:name> e' la chiave (es. 'timeout' in timeout=5)
                # Se c'e' PIU' di un <src:name>, significa che anche il valore assegnato e' una variabile.
                if len(names) > 1:
                    return False
            else:
                # Se non e' un kwarg, la presenza di QUALSIASI <src:name> indica
                # l'uso di una variabile posizionale.
                return False

        # D. Controllo interpolazione: una f-string e' un <src:literal> "opaco"
        
        string_literals = arg.xpath(".//src:literal[@type='string']", namespaces=NS)
        for lit in string_literals:
            testo = "".join(lit.itertext())
            if adapter.is_interpolated_string(testo):
                return False

    # Se arriviamo qui, gli argomenti contengono solo nodi <src:literal> non
    # interpolati o nodi strutturali innocui (come <src:operator> per creare
    # tuple o liste).
    return True


def _safe_context_member_access_name(node, spec: dict, var_name, adapter, imports) -> bool:
    """{"type": "receiver_of_method", "method": "replace"}
       {"type": "var_has_attribute", "attribute": "text"}
    Rileva se la variabile taintata è immediatamente seguita da un accesso
    (metodo o attributo, indistintamente) con quel nome: VAR.nome
    UNIFICA LE PRECEDENTI: receiver_of_method; var_has_attribute --> sono ancora due entry diverse
    mappare su questa stessa funzione
    """
    target = spec.get("method") or spec.get("attribute")
    if not target:
        return False

    ops = adapter.member_access_operator()
    ops_xpath = " or ".join(f"text()='{op}'" for op in ops)

    name_nodes = node.xpath(
        f"following-sibling::src:operator[1][{ops_xpath}]/following-sibling::src:name[1]",
        namespaces=NS,
    )

    return bool(name_nodes) and "".join(name_nodes[0].itertext()).strip() == target


def _safe_context_check_format_arg_position(node, spec, var_name, adapter, imports):

        
    vulnerable_indices = spec.get("vulnerable_indices", {})
    if not vulnerable_indices:
        return False
        
    # 1. Trova l'argomento (src:argument) in cui si trova il nodo infetto
    arg_node = node.xpath("ancestor-or-self::src:argument[1]", namespaces=NS)
    if not arg_node:
        return False
        
    # 2. Risale alla chiamata (src:call) genitrice
    call_node = arg_node[0].xpath("ancestor::src:call[1]", namespaces=NS)
    if not call_node:
        return False
        
    # 3. Ottiene il nome reale della funzione
    call_name = adapter.resolve_call_name(call_node[0], NS, imports)
    if not call_name:
        return False
        
    target_index = None
    for target_name, idx in vulnerable_indices.items():
        if call_matches(call_name, target_name, adapter):
            target_index = idx
            break
            
    # Se la funzione non è nel catalogo, non disinnescare
    if target_index is None:
        return False
        
    # 4. Conta matematicamente quanti argomenti precedono questo nodo
    preceding_args = int(arg_node[0].xpath("count(preceding-sibling::src:argument)", namespaces=NS))
    
    # 5. È sicuro se la sua posizione NON coincide con l'indice vulnerabile.
    return preceding_args != target_index

SAFE_CONTEXT_MATCHERS = {
    "parametrized_query": _safe_context_parametrized_query,
    "receiver_of_method": _safe_context_member_access_name,
    "var_has_attribute": _safe_context_member_access_name,
    "rhs_call": _safe_context_rhs_call,
    "function_has_method_call": _safe_context_function_has_method_call,
    "args_contain_string_literal": _safe_context_args_contain_string_literal,
    "in_function_name": _safe_context_in_function_name,
    "function_has_file_size_check": _safe_context_function_has_file_size_check,
    "var_truthiness_check": _safe_context_var_truthiness_check,
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
    "var_falsy_guard_clause":_safe_context_var_falsy_guard_clause,
    "all_args_are_literals": _safe_context_all_args_are_literals,
    "check_format_arg_position":_safe_context_check_format_arg_position
}


def match_safe_context(node, ctx_spec, var_name, adapter, imports) -> bool:
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


def is_in_safe_context(node, safe_contexts: list, var_name, adapter, imports) -> bool:
    return any(match_safe_context(node, ctx, var_name, adapter, imports) for ctx in safe_contexts)