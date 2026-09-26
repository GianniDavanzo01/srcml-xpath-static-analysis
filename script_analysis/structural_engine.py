"""
structural_engine.py
---------------------
Motore Strutturale
"""

import re

from common import NS, get_call_name, build_finding, call_arguments_match_ast, check_required_imports,_pos_key, find_assignments
from safe_context_matchers import is_in_safe_context


from language_adapter import PythonAdapter


def _run_source_operator_usage(tree, rule, findings, adapter, imports, catalog=None):
    catalog = catalog or {}
    op_roles = adapter.string_formatting_operator_roles()
    eq_op = adapter.equality_operator() if hasattr(adapter, "equality_operator") else "=="

    mappings = {"source_comparisons": {"operator": eq_op}}
    if "concat" in op_roles:
        mappings["source_concats"] = {"operator": op_roles["concat"]}
    if "percent_format" in op_roles:
        mappings["source_percent_formats"] = {"operator": op_roles["percent_format"]}
    
    active_specs = []
    for json_key, behavior in mappings.items():
        for spec in rule.get(json_key, []):
            enriched_spec = spec.copy()
            enriched_spec["operator"] = behavior["operator"]
            active_specs.append(enriched_spec)
            
    if not active_specs:
        return

    # 1. Risoluzione dinamica dei Sanitizers dal catalogo 
    # (es. converte "cast_to_integer" in ["int", "float"])
    raw_sanitizers = rule.get("sanitizers", [])
    resolved_sanitizers = []
    for san in raw_sanitizers:
        san_key = san.get("tag") if isinstance(san, dict) else san
        if san_key in catalog.get("sanitizers", {}):
            resolved_sanitizers.extend(catalog["sanitizers"][san_key])
        else:
            resolved_sanitizers.append(san_key)

    safe_contexts = rule.get("safe_contexts", [])

    for spec in active_specs:
        target_op = spec.get("operator")
        source_def = spec.get("source")
        
        # 2. Risoluzione dinamica delle Sorgenti dal catalogo
        # (es. converte {"tag": "http_input"} in ["request.data", "input", ...])
        source_names = []
        if isinstance(source_def, str):
            source_names = [source_def]
        elif isinstance(source_def, dict) and "tag" in source_def:
            tag = source_def["tag"]
            source_names = catalog.get("sources", {}).get(tag, [])
            
        if not source_names:
            continue

        for op_node in tree.xpath(f".//src:operator[text()='{target_op}']", namespaces=NS):
            
            # Trova esattamente il nodo a sinistra e a destra dell'operatore (+ o %)
            lhs_nodes = op_node.xpath("./preceding-sibling::*[not(self::src:comment)]", namespaces=NS)
            rhs_nodes = op_node.xpath("./following-sibling::*[not(self::src:comment)]", namespaces=NS)
            
            lhs = lhs_nodes[-1] if lhs_nodes else None
            rhs = rhs_nodes[0] if rhs_nodes else None
            
            match_found = False
            matched_source = None
            
            # Valuta sia la sinistra che la destra
            for sibling in (lhs, rhs):
                if sibling is None:
                    continue
                    
                # CASO 1: La sorgente è una funzione (es. input())
                if sibling.tag.endswith("call"):
                    c_name = get_call_name(sibling, adapter, imports)
                    if c_name in source_names:
                        match_found = True
                        matched_source = c_name
                        break
                        
                # CASO 2: La sorgente è una variabile o proprietà (es. request.data)
                # Estraiamo in modo sicuro il testo dai nodi name ignorando i tag intermedi.
                # Per ciascun candidato ricostruiamo il nome puntato solo dai <name> figli
                # diretti (escludendo eventuali <index>), cosi' un subscript come
                # request.args['id'] non contamina il confronto col contenuto tra [ ].
                names = sibling.xpath("descendant-or-self::src:name", namespaces=NS)
                for n in names:
                    op = adapter.member_access_operator()[0] if adapter and adapter.member_access_operator() else "."
                    parts = n.xpath("./src:name", namespaces=NS)
                    if parts:
                        n_text = op.join("".join(p.itertext()).strip() for p in parts)
                    else:
                        n_text = "".join(n.itertext()).replace(" ", "")
                    if n_text in source_names:
                        match_found = True
                        matched_source = n_text
                        break
                        
                if match_found:
                    break
                    
            if not match_found:
                continue
                
            expr_node = op_node.xpath("ancestor::src:expr[1]", namespaces=NS)
            if not expr_node:
                continue
            expr_node = expr_node[0]

            if is_in_safe_context(expr_node, safe_contexts, None, adapter, imports):
                continue

            # 3. Verifica Sanitizers applicati 
            is_escaped = False
            if resolved_sanitizers:
                for c_node in expr_node.xpath(".//src:call", namespaces=NS):
                    c_name = get_call_name(c_node, adapter, imports)
                    # Se trova una chiamata al sanitizer (es. int())
                    if c_name in resolved_sanitizers:
                        c_text = "".join(c_node.itertext()).replace(" ", "")
                        # Se la nostra sorgente si trova dentro la chiamata del sanitizer
                        if matched_source in c_text:
                            is_escaped = True
                            break
                            
            if is_escaped:
                continue

            findings.append(build_finding(rule, expr_node))

            break


def _run_forbidden_function_defs(tree, rule, findings, adapter, imports):
    specs = rule.get("forbidden_function_defs", [])
    if not specs:
        return

    safe_contexts = rule.get("safe_contexts", [])

    for spec in specs:
        if isinstance(spec, dict):
            target_name = spec.get("name")
            is_async = spec.get("is_async", False)
            max_params = spec.get("max_params")
            exact_body = spec.get("exact_body")
        elif isinstance(spec, str):
            target_name = spec
            is_async = False
            max_params = None
            exact_body = None
        else:
            continue

        if not target_name:
            continue

        for func_node in tree.xpath(f".//src:function[src:name[text()='{target_name}']]", namespaces=NS):
            if is_async:
                modifiers = func_node.xpath("./src:type/src:modifier[text()='async']", namespaces=NS)
                if not modifiers:
                    continue
                    
            if max_params is not None:
                params = func_node.xpath(".//src:parameter_list//src:parameter", namespaces=NS)
                if len(params) > max_params:
                    continue
                    
            if exact_body in ["{}", "empty"]:
                block_content = func_node.xpath("./src:block/src:block_content", namespaces=NS)
                if not block_content:
                    continue

                valid_stmts = block_content[0].xpath(
                    "./*[not(self::src:comment or self::src:pass or self::src:return[not(src:expr)])]",
                    namespaces=NS
                )
                if len(valid_stmts) > 0:
                    continue

            if is_in_safe_context(func_node, safe_contexts, None, adapter, imports):
                continue

            findings.append(build_finding(rule, func_node))



def _run_missing_while_increments(tree, rule, findings, adapter, imports):
    specs = rule.get("missing_while_increments", [])
    if not specs:
        return

    safe_contexts = rule.get("safe_contexts", [])
    while_nodes = tree.xpath(".//src:while", namespaces=NS)

    for w_node in while_nodes:
        cond = w_node.xpath("./src:condition//src:operator[text()='<']", namespaces=NS)
        if not cond:
            continue

        op_node = cond[0]
        lhs_nodes = op_node.xpath("./preceding-sibling::*[not(self::src:comment)]", namespaces=NS)
        if not lhs_nodes:
            continue

        var_name = "".join(lhs_nodes[-1].itertext()).strip()
        if not var_name.isidentifier():
            continue

        block = w_node.xpath("./src:block", namespaces=NS)
        if not block:
            continue

        aug_assign = block[0].xpath(
            f".//src:expr[src:name[1][text()='{var_name}'] and src:operator[1][text()='+=']]",
            namespaces=NS
        )

        assign_op = adapter.assignment_operator_token()
        exp_assign = block[0].xpath(
            f".//src:expr[src:name[1][text()='{var_name}'] and src:operator[1][text()='{assign_op}']"
            f" and .//src:name[text()='{var_name}'] and .//src:operator[text()='+']]",   # '+' hardcoded, universale
            namespaces=NS
        )

        has_increment = bool(aug_assign or exp_assign)

        if not has_increment:
            if is_in_safe_context(w_node, safe_contexts, None, adapter, imports):
                continue
            findings.append(build_finding(rule, w_node))


# def _run_unsafe_file_reads(tree, rule, findings, adapter, imports):
#     specs = rule.get("unsafe_file_reads", [])
#     if not specs:
#         return

#     safe_contexts = rule.get("safe_contexts", [])
#     with_nodes = tree.xpath(".//src:with", namespaces=NS)

#     for w_node in with_nodes:
#         with_text = "".join(w_node.itertext())

#         if not re.search(r"\bopen\s*\(", with_text) or not re.search(r"\bas\b", with_text):
#             continue

#         if not re.search(r"\.read\s*\(", with_text):
#             continue

#         open_calls = w_node.xpath(".//src:call[.//src:name[text()='open']]", namespaces=NS)
#         if not open_calls:
#             continue

#         arg_list = open_calls[0].xpath("./src:argument_list", namespaces=NS)
#         if not arg_list:
#             continue

#         first_arg = arg_list[0].xpath("./src:argument[1]", namespaces=NS)
#         if not first_arg:
#             continue

#         arg_text_clean = "".join(first_arg[0].itertext()).strip()
        
#         literal_nodes = first_arg[0].xpath("./src:literal[@type='string']", namespaces=NS)
#         is_pure_literal = bool(literal_nodes) and len(first_arg[0]) == 1 and \
#             "".join(literal_nodes[0].itertext()).strip() == arg_text_clean
#         if is_pure_literal:
#             continue

#         var_name = arg_text_clean
#         if not var_name:
#             continue

#         if is_in_safe_context(w_node, safe_contexts, var_name=var_name, adapter=adapter, imports=imports):
#             continue

#         findings.append(build_finding(rule, w_node))

 

def _run_reference_comparisons(tree, rule, findings, adapter, imports):
    ref_ops = adapter.reference_comparison_operators()
    if not ref_ops:
        return

    safe_contexts = rule.get("safe_contexts", [])
    op_xpath = " or ".join(f"text()='{op}'" for op in ref_ops)
    operators = tree.xpath(f".//src:operator[{op_xpath}]", namespaces=NS)
    needs_pointer_check = adapter.requires_pointer_type_for_reference_comparison()

    for op in operators:
        lhs_nodes = op.xpath("./preceding-sibling::*[not(self::src:comment)]", namespaces=NS)
        rhs_nodes = op.xpath("./following-sibling::*[not(self::src:comment)]", namespaces=NS)
        if not rhs_nodes:
            continue

        rhs_text = "".join(rhs_nodes[0].itertext()).strip()

        if adapter.is_none_literal(rhs_text) or adapter.is_boolean_literal(rhs_text):
            continue

        if needs_pointer_check:
            if not lhs_nodes:
                continue
            lhs_text = "".join(lhs_nodes[-1].itertext()).strip()
            lhs_type = adapter.resolve_variable_type(op, lhs_text, NS)
            rhs_type = adapter.resolve_variable_type(op, rhs_text, NS)
            if not (lhs_type and "*" in lhs_type and rhs_type and "*" in rhs_type):
                continue   # non entrambi puntatori -> confronto numerico legittimo, non segnalare

        if is_in_safe_context(op, safe_contexts, None, adapter, imports):
            continue

        findings.append(build_finding(rule, op))



def _run_empty_catch_blocks(tree, rule, findings, adapter, imports):
    if not rule.get("empty_catch_blocks"):
        return

    safe_contexts = rule.get("safe_contexts", [])
    catches = tree.xpath(".//src:catch", namespaces=NS)

    for catch in catches:
        block_content = catch.xpath("./src:block/src:block_content", namespaces=NS)
        if not block_content:
            continue

        # Stesso criterio già usato per i corpi funzione vuoti:
        # nessun figlio reale a parte commenti (e 'pass' per Python)
        valid_stmts = block_content[0].xpath(
            "./*[not(self::src:comment or self::src:pass)]", namespaces=NS
        )
        if len(valid_stmts) > 0:
            continue  # il blocco fa QUALCOSA: logging, re-raise, cleanup, ecc.

        if is_in_safe_context(catch, safe_contexts, None, adapter, imports):
            continue

        findings.append(build_finding(rule, catch))


def _check_use_after_free(tree, rule, findings, adapter, imports):
    """
    {"use_after_free": {"call": ["free"], "safe_allocation_calls": [...], "safe_reassignments": [...]}}
    """
    spec = rule.get("use_after_free")
    if not spec:
        return

    _adapter = adapter or PythonAdapter()
    target_calls = spec.get("call", ["free"])
    safe_allocations = spec.get("safe_allocation_calls", [])
    safe_reassignments = spec.get("safe_reassignments", [])

    for node in tree.xpath(".//src:call", namespaces=NS):
        call_name = get_call_name(node, _adapter, imports)
        if not call_name or call_name not in target_calls:
            continue

        func_scope = node.xpath("ancestor::src:function[1]", namespaces=NS)
        if not func_scope:
            continue
        scope = func_scope[0]

        target_nodes = node.xpath(".//src:argument//src:name", namespaces=NS)
        if not target_nodes:
            continue
            
        original_target = target_nodes[0].text
        if not original_target:
            continue
            
        aliased_pointers = {original_target}
        node_key = _pos_key(node)

        # --- BACKWARD SCAN ---
        all_assignments = find_assignments(scope, _adapter)
        
        prior_assignments = sorted(
            [(s, l, r) for s, l, r in all_assignments if _pos_key(s) < node_key],
            key=lambda t: _pos_key(t[0]),
            reverse=True 
        )
        
        for stmt, lhs, rhs in prior_assignments:
            if lhs is None or rhs is None:
                continue
                
            # FIX 2: descendant-or-self garantisce di catturare il name anche se coincide col nodo stesso
            lhs_names = set(n.text for n in lhs.xpath("descendant-or-self::src:name", namespaces=NS) if n.text)
            rhs_names = set(n.text for n in rhs.xpath("descendant-or-self::src:name[not(following-sibling::src:argument_list)]", namespaces=NS) if n.text)
            
            # Se LHS è un alias e RHS non è una chiamata a funzione (es. per evitare di tracciare 'malloc')
            if aliased_pointers.intersection(lhs_names):
                if not rhs.xpath(".//src:call", namespaces=NS):
                    aliased_pointers.update(rhs_names)
            # Se RHS è un alias
            elif aliased_pointers.intersection(rhs_names):
                aliased_pointers.update(lhs_names)

        # --- FORWARD SCAN ---
        usages = []
        
        for p in aliased_pointers:
            for u in scope.xpath(f".//src:name[text()='{p}']", namespaces=NS):
                if u in node.iter():
                    continue
                    
                if _pos_key(u) > node_key:
                    usages.append((p, u))
                    
        usages.sort(key=lambda item: _pos_key(item[1]))

        for p, uso in usages:
            if p not in aliased_pointers:
                continue 
                
            enclosing_stmt = uso.xpath("ancestor::src:expr_stmt[1] | ancestor::src:decl_stmt[1] | ancestor::src:return_stmt[1]", namespaces=NS)
            if not enclosing_stmt:
                findings.append(build_finding(rule, uso))
                aliased_pointers.discard(p) # Segnala e smette di tracciare questo specifico alias
                continue
                
            stmt_node = enclosing_stmt[0]
            is_sanitized = False

            if _adapter.is_assignment(stmt_node, NS):
                lhs, rhs = _adapter.get_assignment_lhs_rhs(stmt_node, NS)
                if lhs is not None and rhs is not None:
                    
                    if (uso in lhs.iter() or uso is lhs):
                        rhs_names = [n.text for n in rhs.xpath("descendant-or-self::src:name", namespaces=NS) if n.text]
                        
                        if p not in rhs_names:
                            rhs_text = "".join(rhs.itertext()).strip()
                            is_safe_val = _adapter.is_none_literal(rhs_text) or rhs_text in safe_reassignments
                            
                            is_safe_alloc = False
                            if safe_allocations:
                                xp = " or ".join(f"text()='{a}'" for a in safe_allocations)
                                query = (
                                    f"descendant-or-self::src:call[.//src:name[{xp}]] | "
                                    f"following-sibling::src:call[.//src:name[{xp}]] | "
                                    f"following-sibling::*//src:call[.//src:name[{xp}]]"
                                )
                                is_safe_alloc = bool(rhs.xpath(query, namespaces=NS))
                                
                            if is_safe_val or is_safe_alloc:
                                is_sanitized = True
                                aliased_pointers.discard(p)
                                
            if not is_sanitized:
                findings.append(build_finding(rule, uso))
                aliased_pointers.discard(p) # Segnala e smette di tracciare questo specifico alias


def run_structural_rule(tree, rule: dict, adapter=None, imports=None, ctx=None) -> list:
    adapter = adapter or PythonAdapter()
    imports = imports if imports is not None else []

    findings = []

    if not check_required_imports(tree, rule, NS, imports):
        return findings

    if "required_calls" in rule:
        all_calls = {node.text for node in tree.xpath(".//src:call//src:name", namespaces=NS) if node.text}
        if not all(req in all_calls for req in rule["required_calls"]):
            return findings

    bad_assignments = rule.get("bad_assignments", {})
    if bad_assignments:
        safe_contexts = rule.get("safe_contexts", []) 
        
        # Troviamo tutti gli statement di assegnazione usando l'adapter
        expr_stmts = tree.xpath(".//src:expr_stmt | .//src:decl_stmt", namespaces=NS)
        
        for assign in expr_stmts:
            if not adapter.is_assignment(assign, NS):
                continue
            
            # Sfruttiamo il metodo nativo del LanguageAdapter
            lhs_node, rhs_node = adapter.get_assignment_lhs_rhs(assign, NS)
            if lhs_node is None or rhs_node is None:
                continue
            
            # Estraiamo il testo della parte sinistra preservando la struttura dei nomi (es. app.debug)
            lhs_text = "".join(lhs_node.itertext()).strip().replace(" ", "")
            
            # Normalizziamo la parte destra usando l'adapter (gestisce apici, booleani, ecc.)
            rhs_text = "".join(rhs_node.itertext()).strip()
            
            rhs_text = adapter.normalize_string_literal(rhs_text)
            
            for attr, val in bad_assignments.items():
                # Confronto strutturale sicuro
                if (lhs_text == attr or lhs_text.endswith(f".{attr}")) and rhs_text == val:
                    if is_in_safe_context(assign, safe_contexts, None, adapter, imports): 
                        continue
                    findings.append(build_finding(rule, assign))



    sensitive_patterns = rule.get("sensitive_var_patterns", [])
    if sensitive_patterns:
        safe_contexts = rule.get("safe_contexts", [])
        name_regex = re.compile("|".join(re.escape(p) for p in sensitive_patterns), re.IGNORECASE)
 
        for assign, lhs, rhs in find_assignments(tree, adapter):
            if rhs is None:
                continue
 
            rhs_nodes = rhs.xpath("self::* | following-sibling::*", namespaces=NS)
 
            has_string_literal = any(
                n.xpath(".//src:literal[@type='string']", namespaces=NS) or 
                (n.tag == f"{{{NS['src']}}}literal" and n.get("type") == "string") 
                for n in rhs_nodes
            )
            
            has_dynamic_content = any(
                n.xpath(".//src:call | .//src:name", namespaces=NS) or 
                (n.tag in [f"{{{NS['src']}}}call", f"{{{NS['src']}}}name"]) 
                for n in rhs_nodes
            )
 
            if not has_string_literal or has_dynamic_content:
                continue
 
            var_name = "".join(lhs.itertext()).strip()
            if name_regex.search(var_name) and not is_in_safe_context(lhs, safe_contexts, None, adapter, imports):
                findings.append(build_finding(rule, assign))
 
        conditions = tree.xpath(".//src:if_stmt//src:condition", namespaces=NS)
        eq_op = adapter.equality_operator()
        for cond in conditions:
            if cond.xpath(".//src:call", namespaces=NS):
                continue

            for op_node in cond.xpath(f".//src:operator[text()='{eq_op}']", namespaces=NS):
                lhs_nodes = op_node.xpath("preceding-sibling::*[not(self::src:comment)]", namespaces=NS)
                rhs_nodes = op_node.xpath("following-sibling::*[not(self::src:comment)]", namespaces=NS)
                if not lhs_nodes or not rhs_nodes:
                    continue

                for name_side, literal_side in ((lhs_nodes[-1], rhs_nodes[0]), (rhs_nodes[0], lhs_nodes[-1])):
                    name_nodes = name_side.xpath("self::src:name | .//src:name", namespaces=NS)
                    literal_nodes = literal_side.xpath(
                        "self::src:literal[@type='string'] | .//src:literal[@type='string']", namespaces=NS
                    )
                    if not name_nodes or not literal_nodes:
                        continue
                    var_name = "".join(name_nodes[0].itertext()).strip()
                    if name_regex.search(var_name) and not is_in_safe_context(name_nodes[0], safe_contexts, None, adapter, imports):
                        findings.append(build_finding(rule, cond))
                        break

    forbidden_imports = rule.get("forbidden_imports", [])
    if forbidden_imports:
        safe_contexts = rule.get("safe_contexts", [])
        
        # 'imports' è la lista di ImportBinding già calcolata dall'adapter!
        for binding in imports:
            # Controlla se il nome canonico importato è tra quelli vietati
            is_forbidden = any(
                binding.canonical_name == bad or binding.canonical_name.startswith(f"{bad}.")
                for bad in forbidden_imports
            )
            
            if is_forbidden:
                # Controllo safe_context
                if is_in_safe_context(binding.node, safe_contexts, None, adapter, imports):
                    continue
                    
                findings.append(build_finding(rule, binding.node))

    forbidden_returns = rule.get("forbidden_returns", [])
    if forbidden_returns:
        safe_contexts = rule.get("safe_contexts", [])
        returns = tree.xpath(".//src:return", namespaces=NS)
        for ret in returns:
            if is_in_safe_context(ret, safe_contexts, None, adapter, imports):
                continue
            
            for spec in forbidden_returns:
                if spec.get("type") == "fstring":
                    fstrings = ret.xpath(".//src:literal[@type='string']", namespaces=NS)
                    has_fstring_with_interpolation = False

                    for fs in fstrings:
                        fs_text = "".join(fs.itertext()).strip()
                        if adapter and adapter.is_interpolated_string(fs_text):
                            has_fstring_with_interpolation = True
                            break
                    if has_fstring_with_interpolation:
                        findings.append(build_finding(rule, ret))
                        break


    bad_function_defs = rule.get("bad_function_defs", [])
    if bad_function_defs:
        safe_contexts = rule.get("safe_contexts", [])
        
        functions = tree.xpath(".//src:function", namespaces=NS)
        for func in functions:
            name_nodes = func.xpath("./src:name", namespaces=NS)
            if not name_nodes:
                continue
            func_name = "".join(name_nodes[0].itertext()).strip()
            
            # 1. Estrazione semantica dei parametri delegata all'adapter
            param_names = set()
            params_nodes = func.xpath(".//src:parameter_list//src:parameter", namespaces=NS)
            for param in params_nodes:
                p_name, _ = adapter.get_parameter_name_and_type(param, NS)
                if p_name:
                    param_names.add(p_name)
            
            for bfd in bad_function_defs:
                target_name = bfd.get("name")
                target_param = bfd.get("param")
                
                # Ripuliamo l'input del catalogo (trasforma "return true;" in "true")
                raw_return = bfd.get("return_expr", bfd.get("return_value", ""))
                target_return = raw_return.replace("return", "").replace(";", "").strip().lower()
                
                if func_name == target_name and target_param in param_names:
                    returns = func.xpath(".//src:block/src:block_content/src:return", namespaces=NS)
                    match_return = False
                    
                    # 2. Validazione strutturale dell'espressione di ritorno
                    for ret in returns:
                        expr = ret.xpath("./src:expr", namespaces=NS)
                        if expr:
                            # Estraiamo solo l'espressione (es. "true" o "True") e normalizziamo
                            expr_text = "".join(expr[0].itertext()).strip().lower()
                            if expr_text == target_return:
                                match_return = True
                                break
                                
                    if match_return:
                        if is_in_safe_context(func, safe_contexts, None, adapter, imports):
                            continue
                        findings.append(build_finding(rule, func))

    
    bad_param_types = rule.get("bad_param_types", [])
    if bad_param_types:
        safe_contexts = rule.get("safe_contexts", [])
        
        functions = tree.xpath(".//src:function", namespaces=NS)
        for func in functions:
            params_nodes = func.xpath("./src:parameter_list/src:parameter", namespaces=NS)
            
            for param in params_nodes:
                # Deleghiamo all'adapter l'estrazione strutturale
                param_name, type_text = adapter.get_parameter_name_and_type(param, NS)
                
                if not type_text:
                    continue
                
                for bad_type in bad_param_types:
                    if bad_type == type_text:
                        if is_in_safe_context(func, safe_contexts, var_name=param_name, adapter=adapter, imports=imports):
                            continue
                            
                        findings.append(build_finding(rule, param))
                        break

    forbidden_calls_with_kwargs = rule.get("forbidden_calls_with_kwargs", [])
    if forbidden_calls_with_kwargs:
        safe_contexts = rule.get("safe_contexts", [])
        
        calls = tree.xpath(".//src:call", namespaces=NS)
        for call in calls:
            call_name = get_call_name(call, adapter, imports)
            if not call_name:
                continue
            
            for fcwk in forbidden_calls_with_kwargs:
                targets = fcwk.get("call", [])
                if isinstance(targets, str):
                    targets = [targets]
                kwargs = fcwk.get("kwargs", {})

                is_target = any(call_name == t or call_name.endswith(f".{t}") for t in targets)
                if is_target:
                    all_kwargs_match = True
                    
                    found_kwargs = {}
                    for arg in call.xpath("./src:argument_list/src:argument", namespaces=NS):
                        if adapter.is_kwarg(arg, NS):
                            name_node = arg.xpath("./src:name[1]", namespaces=NS)
                            kw_name = "".join(name_node[0].itertext()).strip() if name_node else ""
                            expr_node = arg.xpath("./src:expr[1] | ./src:literal[1]", namespaces=NS)
                            val_text = adapter.normalize_string_literal(
                                "".join(expr_node[0].itertext()).strip()
                            ) if expr_node else ""
                            found_kwargs[kw_name] = val_text
                            
                    for k, v in kwargs.items():
                        if k not in found_kwargs or found_kwargs[k] != adapter.normalize_string_literal(v):
                            all_kwargs_match = False
                            break
                    
                    if all_kwargs_match:
                        if is_in_safe_context(call, safe_contexts, None, adapter, imports):
                            continue
                        findings.append(build_finding(rule, call))


    forbidden_subscripts = rule.get("forbidden_subscripts", [])
    if forbidden_subscripts:
        safe_contexts = rule.get("safe_contexts", [])
        
        # Cerca tutti i nodi che hanno un accesso tramite indice (es. dict[chiave] o array[i])
        for node in tree.xpath(".//src:name[src:index]", namespaces=NS):
            if node.xpath("ancestor::src:parameter", namespaces=NS):
                continue
            
            # Estraiamo il nome dell'oggetto a cui si sta accedendo usando l'AST puro
            parts = node.xpath("./src:name", namespaces=NS)
            if parts:
                # NORMALIZZAZIONE:
                # Ignoriamo l'operatore reale (., ->, ::) e uniamo i pezzi sempre col punto.
                # 'request->form' (C) e 'request.form' (Python) diventano internamente 'request.form'.
                base_name = ".".join("".join(p.itertext()).strip() for p in parts)
            else:
                # Gestisce nomi singoli come 'environ'
                base_name = (node.text or "").strip()

            index_var = None
            index_expr = node.xpath("./src:index/src:expr", namespaces=NS)
            if index_expr:
                idx_names = index_expr[0].xpath("./src:name", namespaces=NS)
                if len(idx_names) == 1 and len(list(index_expr[0])) == 1:
                    index_var = "".join(idx_names[0].itertext()).strip()
                
            # Verifica se l'oggetto a cui si accede è nella blacklist
            for subscript in forbidden_subscripts:
                # Ora questo controllo con il punto funzionerà perfettamente per ogni linguaggio
                if base_name == subscript or base_name.endswith(f".{subscript}"):
                    if is_in_safe_context(node, safe_contexts, var_name=index_var, adapter=adapter, imports=imports):
                        break
                    findings.append(build_finding(rule, node))
                    break

    
    if rule.get("forbidden_asserts"):
        safe_contexts = rule.get("safe_contexts", [])
        asserts = tree.xpath(".//src:assert", namespaces=NS)
        for ass_node in asserts:
            if is_in_safe_context(ass_node, safe_contexts, None, adapter, imports):
                continue
            findings.append(build_finding(rule, ass_node))

    if rule.get("forbidden_function_defs"):
        _run_forbidden_function_defs(tree, rule, findings, adapter, imports)

    if rule.get("missing_while_increments"):
        _run_missing_while_increments(tree, rule, findings, adapter, imports)

    if rule.get("empty_catch_blocks"):
        _run_empty_catch_blocks(tree, rule, findings, adapter, imports)

    # if rule.get("unsafe_file_reads"):
    #     _run_unsafe_file_reads(tree, rule, findings, adapter, imports)

    if rule.get("reference_comparisons"):
        _run_reference_comparisons(tree, rule, findings, adapter, imports)

    if rule.get("use_after_free"):
        _check_use_after_free(tree, rule, findings, adapter, imports)

    xpath_queries = rule.get("xpath_rules", [])
    if xpath_queries:
        safe_contexts = rule.get("safe_contexts", [])
        for xp in xpath_queries:
            for node in tree.xpath(xp, namespaces=NS):
                if is_in_safe_context(node, safe_contexts, None, adapter, imports):
                    continue
                findings.append(build_finding(rule, node))

    # Estrae il catalogo dal contesto (se disponibile)
    catalog_obj = getattr(ctx, "catalog", {}) if ctx else {}
    
    _run_source_operator_usage(tree, rule, findings, adapter, imports, catalog=catalog_obj)

    return findings


def run_forbidden_functions_indexed(ctx, compiled, findings, adapter, imports):
    for call in ctx.calls:
        call_name = get_call_name(call, adapter, imports)
        if not call_name:
            continue

        seen = set()
        candidates = []
        
        parts = call_name.split('.')
        suffixes = [".".join(parts[i:]) for i in range(len(parts))]
        
        # 1. Ricerca tramite indice (suffissi)
        for suff in suffixes:
            for item in compiled.forbidden_functions_index.get(suff, []):
                rule_obj = item[0]  # item[0] contiene la reference al dizionario della regola
                
                # Il filtro agisce sull'ID della regola, evitando duplicati per spec ridondanti
                if id(rule_obj) not in seen:
                    seen.add(id(rule_obj))
                    candidates.append(item)
                    
        # 2. Ricerca tra le funzioni non indicizzate (es. pattern AST complessi)
        for item in compiled.unindexed_forbidden_functions:
            rule_obj = item[0]
            if id(rule_obj) not in seen:
                seen.add(id(rule_obj))
                candidates.append(item)

        # 3. Validazione finale ed emissione del finding
        for rule, spec in candidates:
            if not check_required_imports(ctx.unit, rule, NS, imports=imports):
                continue
            if call_name in rule.get("excluded_functions", []):
                continue
            if is_in_safe_context(call, rule.get("safe_contexts", []), None, adapter, imports):
                continue

            # Verifica rigorosa del match effettivo
            if isinstance(spec, str):
                if call_name == spec or call_name.endswith(f".{spec}"):
                    findings.append(build_finding(rule, call))
            elif spec.get("type") == "exact_name":
                if call_name == spec.get("name"):
                    findings.append(build_finding(rule, call))
            elif spec.get("type") == "call_matches_ast":
                if call_arguments_match_ast(call, spec, adapter, imports):
                    findings.append(build_finding(rule, call))

def run_forbidden_names_indexed(ctx, compiled, findings, adapter, imports):

    for name_node in ctx.names:
        # Ottimizzazione: usiamo la cache di ctx invece di join e itertext ripetuti
        full_text = ctx.text_of(name_node).strip()

        for rule in compiled.forbidden_names_index.get(full_text, []):
            if not check_required_imports(ctx.unit, rule, NS, imports=imports):
                continue
            # Propaga adapter e imports
            if is_in_safe_context(name_node, rule.get("safe_contexts", []), None, adapter, imports):
                continue
            findings.append(build_finding(rule, name_node))

        for prefix, rule in compiled.forbidden_name_prefixes:
            if full_text.startswith(prefix):
                if not check_required_imports(ctx.unit, rule, NS, imports=imports):
                    continue
                # Propaga adapter e imports
                if is_in_safe_context(name_node, rule.get("safe_contexts", []), None, adapter, imports):
                    continue
                findings.append(build_finding(rule, name_node))