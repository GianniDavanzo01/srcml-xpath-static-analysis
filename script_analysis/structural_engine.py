"""
structural_engine.py
---------------------
Motore Strutturale
"""

import re

from common import NS, get_call_name, build_finding, call_arguments_match_ast, check_required_imports,_pos_key, find_assignments
from safe_context_matchers import is_in_safe_context


from language_adapter import PythonAdapter

#USATA SOLO DA MESSAGE-TEMPLATE-001 IN RULESET_BUILTIN
def _forbidden_message_template_render(call, spec: dict, adapter=None, imports=None) -> bool:
    """{"type": "message_template_render"}
    Rileva strutturalmente la catena MessageTemplate(...).render(key=value).
    Le due call sono FRATELLI separati da <operator>.</operator> (non
    annidate in <name>), perché il receiver è a sua volta una call.
    """
    call_name = get_call_name(call, adapter, imports)
    if not call_name or not (call_name == "render" or call_name.endswith(".render")):
        return False

    receiver_calls = call.xpath("preceding-sibling::src:call[1]", namespaces=NS)
    if not receiver_calls:
        return False

    receiver_name = get_call_name(receiver_calls[0], adapter, imports)
    if not receiver_name or not receiver_name.endswith("MessageTemplate"):
        return False

    arg_list_nodes = call.xpath("./src:argument_list", namespaces=NS)
    if not arg_list_nodes or adapter is None:
        return False

    return any(
        adapter.is_kwarg(arg, NS)
        for arg in arg_list_nodes[0].xpath("./src:argument", namespaces=NS)
    )


def _run_forbidden_names(tree, rule, findings, adapter, imports):
    exact = rule.get("forbidden_names", [])
    prefixes = rule.get("forbidden_name_prefixes", [])
    if not exact and not prefixes:
        return
    safe_contexts = rule.get("safe_contexts", [])
    for name_node in tree.xpath(".//src:name", namespaces=NS):
        full_text = "".join(name_node.itertext()).strip()
        hit = full_text in exact or any(full_text.startswith(p) for p in prefixes)
        if hit:
            if is_in_safe_context(name_node, safe_contexts, None, adapter, imports):
                continue
            findings.append(build_finding(rule, name_node))


def _run_source_operator_usage(tree, rule, findings, adapter, imports):
    """
    Motore unificato per source_comparisons (==), source_concats e source_percent_formats.
    Gli operatori vengono chiesti all'adapter per RUOLO SEMANTICO, non per
    posizione: se un linguaggio non ha un ruolo, quella categoria di regola
    resta semplicemente inattiva per lui.
    """
    op_roles = adapter.string_formatting_operator_roles()
    eq_op = adapter.equality_operator() if hasattr(adapter, "equality_operator") else "=="

    mappings = {"source_comparisons": {"operator": eq_op}}
    if "concat" in op_roles:
        mappings["source_concats"] = {"operator": op_roles["concat"]}
    if "percent_format" in op_roles:
        mappings["source_percent_formats"] = {"operator": op_roles["percent_format"]}
    
    active_specs = []
    target_ops = set()
    
    for json_key, behavior in mappings.items():
        specs = rule.get(json_key, [])
        for spec in specs:
            enriched_spec = spec.copy()
            enriched_spec["operator"] = behavior["operator"]
            active_specs.append(enriched_spec)
            target_ops.add(behavior["operator"])
            
    if not active_specs:
        return

    sanitizers = rule.get("sanitizers", [])
    safe_contexts = rule.get("safe_contexts", [])
    
    op_xpath = " or ".join([f"text()='{op}'" for op in target_ops])
    exprs = tree.xpath(f".//src:expr[.//src:operator[{op_xpath}]]", namespaces=NS)

    for expr in exprs:
        expr_text = "".join(expr.itertext())

        for spec in active_specs:
            source = spec.get("source")
            form = spec.get("source_form", rule.get("source_form"))
            operator = spec.get("operator")
            
            if not source:
                continue

            suffix = {"call": r"\(", "subscript": r"\["}.get(form)
            pattern = rf"\b{re.escape(source)}"
            if suffix:
                pattern += rf"(?:\.[a-zA-Z_]\w*)?\s*{suffix}"

            match = re.search(pattern, expr_text)
            if not match:
                continue

            has_before = bool(re.search(rf"{re.escape(operator)}\s*$", expr_text[:match.start()]))
            has_after = operator in expr_text[match.end():]
            
            if not (has_before or has_after):
                continue

            #Verifica Safe Contexts strutturali
            if is_in_safe_context(expr, safe_contexts, None, adapter, imports):
                continue

            # Verifica Sanitizers applicati come funzioni
            is_escaped = False
            for san in sanitizers:
                escape_pattern = rf"{re.escape(san)}\s*\(\s*{re.escape(source)}"
                
                if re.search(escape_pattern, expr_text):
                    is_escaped = True
                    break
                    
            if is_escaped:
                continue

            findings.append(build_finding(rule, expr))
            break


def _run_weak_key_sizes(tree, rule, findings, adapter, imports):
    specs = rule.get("weak_key_sizes", [])
    if not specs:
        return
 
    safe_contexts = rule.get("safe_contexts", [])
 
    for name_node in tree.xpath(".//src:name[text()='key_size']", namespaces=NS):
        
        if name_node.xpath("ancestor::src:parameters", namespaces=NS):
            continue 
 
        nodo_valore = None
        
        assign_op = adapter.assignment_operator_token()
        op = name_node.xpath(f"following-sibling::src:operator[1][text()='{assign_op}']", namespaces=NS)
        if op:
            nodi_dopo = op[0].xpath("following-sibling::*", namespaces=NS)
            if nodi_dopo:
                nodo_valore = nodi_dopo[0]
        else:
            expr_sibling = name_node.xpath("following-sibling::src:expr[1]", namespaces=NS)
            if expr_sibling:
                nodo_valore = expr_sibling[0]
            else:
                sibling = name_node.xpath("following-sibling::*[1]", namespaces=NS)
                if sibling and sibling[0].tag.endswith('literal'):
                    nodo_valore = sibling[0]
 
        if nodo_valore is None:
            continue
 
        parent_stmt = name_node.xpath("ancestor::*[self::src:expr_stmt or self::src:argument or self::src:keyword][1]", namespaces=NS)
        stmt_node = parent_stmt[0] if parent_stmt else name_node
        
        valore_numerico = None
 
        lit = nodo_valore.xpath("descendant-or-self::src:literal[@type='number']", namespaces=NS)
        if lit:
            valore_numerico = adapter.parse_numeric_literal("".join(lit[0].itertext()).strip())
        else:
            var_nodes = nodo_valore.xpath("descendant-or-self::src:name", namespaces=NS)
            if var_nodes:
                var_name = "".join(var_nodes[0].itertext()).strip()
                
                query_ass = f".//src:name[text()='{var_name}'][following-sibling::src:operator[1][text()='{assign_op}']]"
                var_assegnazioni = tree.xpath(query_ass, namespaces=NS)
                
                if var_assegnazioni:
                    ultima_ass = var_assegnazioni[-1]
                    op_ass = ultima_ass.xpath("following-sibling::src:operator[1]", namespaces=NS)[0]
                    fratelli_ass = op_ass.xpath("following-sibling::*", namespaces=NS)
                    
                    if fratelli_ass:
                        nodo_valore_ass = fratelli_ass[0]
                        lit_ass = nodo_valore_ass.xpath("descendant-or-self::src:literal[@type='number']", namespaces=NS)
                        if lit_ass:
                            valore_numerico = adapter.parse_numeric_literal("".join(lit_ass[0].itertext()).strip())
 
        if valore_numerico is not None:
            for spec in specs:
                max_val = spec.get("max_value", 2048)
                if valore_numerico < max_val:
                    if is_in_safe_context(stmt_node, safe_contexts,None, adapter, imports):
                        continue
                    findings.append(build_finding(rule, stmt_node))
                    break


def _run_forbidden_function_defs(tree, rule, findings, adapter, imports):
    specs = rule.get("forbidden_function_defs", [])
    if not specs:
        return

    safe_contexts = rule.get("safe_contexts", [])

    for spec in specs:
        exact_body = None
        max_params = None
        
        if isinstance(spec, dict):
            target_name = spec.get("name")
            is_async = spec.get("is_async", False)
            exact_body = spec.get("exact_body")
            max_params = spec.get("max_params")
        elif isinstance(spec, str):
            target_name = spec
            is_async = False
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
                    
            if exact_body:
                block = func_node.xpath("./src:block", namespaces=NS)
                if not block:
                    continue
                block_text = "".join(block[0].itertext()).replace(" ", "").replace("\n", "").replace(":", "")
                if block_text != exact_body.replace(" ", ""):
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
        concat_op = adapter.string_formatting_operator_roles().get("concat")
        exp_assign = []
        if concat_op:
            exp_assign = block[0].xpath(
                f".//src:expr[src:name[1][text()='{var_name}'] and src:operator[1][text()='{assign_op}']"
                f" and .//src:name[text()='{var_name}'] and .//src:operator[text()='{concat_op}']]",
                namespaces=NS
            )
 
        has_increment = bool(aug_assign or exp_assign)
 
        if not has_increment:
            if is_in_safe_context(w_node, safe_contexts, None, adapter, imports):
                continue
            findings.append(build_finding(rule, w_node))


def _run_unsafe_file_reads(tree, rule, findings, adapter, imports):
    specs = rule.get("unsafe_file_reads", [])
    if not specs:
        return

    safe_contexts = rule.get("safe_contexts", [])
    with_nodes = tree.xpath(".//src:with", namespaces=NS)

    for w_node in with_nodes:
        with_text = "".join(w_node.itertext())

        if not re.search(r"\bopen\s*\(", with_text) or not re.search(r"\bas\b", with_text):
            continue

        if not re.search(r"\.read\s*\(", with_text):
            continue

        open_calls = w_node.xpath(".//src:call[.//src:name[text()='open']]", namespaces=NS)
        if not open_calls:
            continue

        arg_list = open_calls[0].xpath("./src:argument_list", namespaces=NS)
        if not arg_list:
            continue

        first_arg = arg_list[0].xpath("./src:argument[1]", namespaces=NS)
        if not first_arg:
            continue

        arg_text_clean = "".join(first_arg[0].itertext()).strip()
        
        literal_nodes = first_arg[0].xpath("./src:literal[@type='string']", namespaces=NS)
        is_pure_literal = bool(literal_nodes) and len(first_arg[0]) == 1 and \
            "".join(literal_nodes[0].itertext()).strip() == arg_text_clean
        if is_pure_literal:
            continue

        var_name = arg_text_clean
        if not var_name:
            continue

        if is_in_safe_context(w_node, safe_contexts, var_name=var_name, adapter=adapter, imports=imports):
            continue

        findings.append(build_finding(rule, w_node))


def _run_local_var_forbidden_calls(tree, rule, findings, adapter, imports):
    """
    Rileva chiamate a funzioni pericolose (es. os.chmod) in cui l'argomento
    è una variabile locale il cui valore, assegnato in precedenza nello
    stesso scope, è un letterale numerico che corrisponde ESATTAMENTE a uno
    dei valori vietati.
    """
    specs = rule.get("local_var_forbidden_calls", [])
    if not specs:
        return
 
    safe_contexts = rule.get("safe_contexts", [])
 
    for spec in specs:
        target_calls = spec.get("call", [])
        if isinstance(target_calls, str):
            target_calls = [target_calls]
        forbidden_nums = set(spec.get("forbidden_numbers", []))
        if not target_calls or not forbidden_nums:
            continue
 
        for c_node in tree.xpath(".//src:call", namespaces=NS):
            # call_name = get_call_name(c_node)
            call_name= get_call_name(c_node, adapter, imports)
            if not call_name:
                continue
            if not any(call_name == tc or call_name.endswith(f".{tc}") for tc in target_calls):
                continue
 
            call_key = _pos_key(c_node)
            args = c_node.xpath("./src:argument_list/src:argument", namespaces=NS)
 
            for arg in args:
                names = arg.xpath("./src:expr/src:name | ./src:name", namespaces=NS)
                if len(names) != 1:
                    continue
                name_node = names[0]
                if name_node.xpath("./src:index | ./src:name", namespaces=NS):
                    continue 
 
                var_name = "".join(name_node.itertext()).strip()
                if not var_name.isidentifier():
                    continue
 
                scope_candidates = c_node.xpath(
                    "ancestor::src:function[1] | ancestor::src:block[1]",
                    namespaces=NS,
                )
                scope_node = scope_candidates[0] if scope_candidates else tree
 
                assigns = [stmt for stmt, _, _ in find_assignments(scope_node, adapter, var_name)]
                prior = [a for a in assigns if _pos_key(a) < call_key]
                if not prior:
                    continue
                last_assign = max(prior, key=_pos_key)
 
                _, rhs = adapter.get_assignment_lhs_rhs(last_assign, NS)
                if rhs is None:
                    continue
 
                lit = rhs.xpath(
                    "descendant-or-self::src:literal[@type='number']", namespaces=NS
                )
                if not lit:
                    continue 
 
                num_text = "".join(lit[0].itertext()).strip()
                if num_text not in forbidden_nums:
                    continue
 
                if is_in_safe_context(c_node, safe_contexts, var_name=var_name, adapter=adapter, imports=imports):
                    continue
 
                finding = build_finding(rule, c_node, extra={"tainted_variable": var_name})
                if finding not in findings:
                    findings.append(finding)
 


def _run_reference_comparisons(tree, rule, findings, adapter, imports):
    ref_ops = adapter.reference_comparison_operators()
    if not ref_ops:
        return

    safe_contexts = rule.get("safe_contexts", [])
    op_xpath = " or ".join(f"text()='{op}'" for op in ref_ops)
    operators = tree.xpath(f".//src:operator[{op_xpath}]", namespaces=NS)

    for op in operators:
        rhs_nodes = op.xpath("./following-sibling::*[not(self::src:comment)]", namespaces=NS)
        if not rhs_nodes:
            continue

        rhs_text = "".join(rhs_nodes[0].itertext()).strip()

        if adapter.is_none_literal(rhs_text) or adapter.is_boolean_literal(rhs_text):
            continue

        if is_in_safe_context(op, safe_contexts, None, adapter, imports):
            continue

        findings.append(build_finding(rule, op))


# def run_structural_rule(tree, rule: dict) -> list:
# def run_structural_rule(tree, rule: dict, adapter=None, imports=None) -> list:
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

    # bad_assignments = rule.get("bad_assignments", {})
    # if bad_assignments:
    #     safe_contexts = rule.get("safe_contexts", []) 
    #     assign_op = adapter.assignment_operator_token()
    #     assignments = tree.xpath(f".//src:expr_stmt[.//src:operator[text()='{assign_op}']]", namespaces=NS)
 
    #     for assign in assignments:
    #         op = assign.xpath(f".//src:operator[text()='{assign_op}'][1]", namespaces=NS)
    #         if not op:
    #             continue
                
    #         lhs_nodes = op[0].xpath("./preceding-sibling::*", namespaces=NS)
    #         rhs_nodes = op[0].xpath("./following-sibling::*", namespaces=NS)
            
    #         lhs_text = "".join(n.text or "".join(n.itertext()) for n in lhs_nodes).strip()
    #         rhs_text = "".join(n.text or "".join(n.itertext()) for n in rhs_nodes).strip()
            
    #         for attr, val in bad_assignments.items():
    #             if (lhs_text == attr or lhs_text.endswith(f".{attr}")) and rhs_text == val:
    #                 if is_in_safe_context(assign, safe_contexts,None, adapter, imports): 
    #                     continue
    #                 findings.append(build_finding(rule, assign))

    bad_assignments = rule.get("bad_assignments", {})
    if bad_assignments:
        safe_contexts = rule.get("safe_contexts", []) 
        
        # Troviamo tutti gli statement di assegnazione usando l'adapter
        expr_stmts = tree.xpath(".//src:expr_stmt", namespaces=NS)
        
        for assign in expr_stmts:
            if not adapter.is_assignment(assign, NS):
                continue
            
            # Sfruttiamo il metodo nativo del LanguageAdapter!
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


    bad_calls = rule.get("bad_calls", {})
    if bad_calls:
        calls = tree.xpath(".//src:call", namespaces=NS)
        for call in calls:
            call_name = get_call_name(call, adapter, imports)
            if not call_name:
                continue

            for func, kwargs in bad_calls.items():
                if call_name == func or call_name.endswith(f".{func}"):
                    is_vulnerable = False

                    for arg in call.xpath("./src:argument_list/src:argument", namespaces=NS):
                        if adapter.is_kwarg(arg, NS):
                            name_node = arg.xpath("./src:name[1]", namespaces=NS)
                            kw_name = "".join(name_node[0].itertext()).strip() if name_node else ""

                            if kw_name in kwargs:
                                expr_node = arg.xpath("./src:expr[1] | ./src:literal[1]", namespaces=NS)
                                val_text = adapter.normalize_string_literal(
                                    "".join(expr_node[0].itertext()).strip()
                                ) if expr_node else ""

                                if val_text == adapter.normalize_string_literal(kwargs[kw_name]):
                                    is_vulnerable = True
                                    break

                    if is_vulnerable:
                        findings.append(build_finding(rule, call))


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
 
        conditions = tree.xpath(".//src:if_stmt//src:condition[.//src:operator[text()='==']]", namespaces=NS)
        for cond in conditions:
            names = cond.xpath(".//src:name", namespaces=NS)
            literals = cond.xpath(".//src:literal[@type='string']", namespaces=NS)
            calls = cond.xpath(".//src:call", namespaces=NS)
            
            if not literals or calls:
                continue
                
            for n in names:
                var_name = "".join(n.itertext()).strip()
                if name_regex.search(var_name) and not is_in_safe_context(n, safe_contexts,None, adapter, imports):
                    findings.append(build_finding(rule, cond))
                    break

    forbidden_imports = rule.get("forbidden_imports", [])
    if forbidden_imports:
        excluded_imports = rule.get("excluded_imports", [])
        required_safe_calls = rule.get("required_safe_calls", [])
        safe_contexts = rule.get("safe_contexts", [])
        
        file_is_safe = False
        if required_safe_calls:
            all_calls = tree.xpath(".//src:call", namespaces=NS)
            for call_node in all_calls:
                # call_name = get_call_name(call_node)
                call_name= get_call_name(call_node, adapter, imports)
                if not call_name:
                    continue
                arg_list_nodes = call_node.xpath("./src:argument_list", namespaces=NS)
                args_text = "".join(arg_list_nodes[0].itertext()).replace(" ", "").replace("\n", "") if arg_list_nodes else ""
                
                for safe_spec in required_safe_calls:
                    target_calls = safe_spec.get("call", [])
                    target_kwargs = safe_spec.get("kwargs", {})
                    if any(call_name == c or call_name.endswith(f".{c}") for c in target_calls):
                        if all(f"{k}={v}" in args_text for k, v in target_kwargs.items()):
                            file_is_safe = True
                            break
                if file_is_safe:
                    break
        
        if not file_is_safe:
            import_nodes = tree.xpath(".//src:import", namespaces=NS)
            for imp in import_nodes:
                imp_text = "".join(imp.itertext()).replace(" ", "").replace("\n", "")
                
                is_excluded = False
                for excl in excluded_imports:
                    clean_excl = excl.replace(" ", "")
                    target_excl_import = f"import{clean_excl}"
                    target_excl_from = ""
                    if "." in clean_excl:
                        parts = clean_excl.rsplit('.', 1)
                        target_excl_from = f"from{parts[0]}import{parts[1]}"
                    
                    if target_excl_import in imp_text or (target_excl_from and target_excl_from in imp_text) or clean_excl in imp_text:
                        is_excluded = True
                        break
                        
                if is_excluded:
                    continue

                for bad_import in forbidden_imports:
                    clean_bad = bad_import.replace(" ", "")
                    target_import = f"import{clean_bad}"
                    target_from = ""
                    
                    parts = None
                    if "." in clean_bad:
                        parts = clean_bad.rsplit('.', 1)
                        target_from = f"from{parts[0]}import{parts[1]}"
                    
                    match_from_multiple = parts and f"from{parts[0]}import" in imp_text and parts[1] in imp_text
                    
                    if target_import in imp_text or (target_from and target_from in imp_text) or match_from_multiple:
                        if is_in_safe_context(imp, safe_contexts,None, adapter, imports):
                            continue
                        findings.append(build_finding(rule, imp))
                        break

    inline_sources = rule.get("inline_source_as_arg", [])
    if inline_sources:
        for c in tree.xpath(".//src:call", namespaces=NS):
            # if get_call_name(c) in inline_sources:
            if  get_call_name(c, adapter, imports) in inline_sources:
                if c.xpath("ancestor::src:argument | ancestor::src:parameter", namespaces=NS):
                    findings.append(build_finding(rule, c))

    # if rule.get("forbidden_names") or rule.get("forbidden_name_prefixes"):
    #     _run_forbidden_names(tree, rule, findings, adapter, imports)

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
                    # for fs in fstrings:
                    #     fs_text = "".join(fs.itertext()).strip()
                    #     if fs_text.startswith("f") and "{" in fs_text:
                    #         has_fstring_with_interpolation = True
                    #         break
                    for fs in fstrings:
                        fs_text = "".join(fs.itertext()).strip()
                        if adapter and adapter.is_interpolated_string(fs_text):
                            has_fstring_with_interpolation = True
                            break
                    if has_fstring_with_interpolation:
                        findings.append(build_finding(rule, ret))
                        break


    bad_returns = rule.get("bad_returns", [])
    if bad_returns:
        safe_contexts = rule.get("safe_contexts", [])
        
        return_nodes = tree.xpath(".//src:return", namespaces=NS)
        for ret in return_nodes:
            ret_text = "".join(ret.itertext()).replace(" ", "")
            
            for target in bad_returns:
                if target in ret_text:
                    if is_in_safe_context(ret, safe_contexts, None, adapter, imports):
                        continue
                        
                    findings.append(build_finding(rule, ret))
                    break 

    if rule.get("weak_key_sizes"):
        _run_weak_key_sizes(tree, rule, findings, adapter, imports)

    if rule.get("forbidden_function_defs"):
        _run_forbidden_function_defs(tree, rule, findings, adapter, imports)

    forbidden_conditions = rule.get("forbidden_conditions", [])
    if forbidden_conditions:
        safe_contexts = rule.get("safe_contexts", [])
        
        conditions = tree.xpath(".//src:if_stmt//src:condition", namespaces=NS)
        for cond in conditions:
            cond_text = "".join(cond.itertext()).replace(" ", "").replace("\n", "")
            
            for fc in forbidden_conditions:
                target = fc.replace(" ", "")
                if target in cond_text:
                    if is_in_safe_context(cond, safe_contexts, None, adapter, imports):
                        continue
                        
                    findings.append(build_finding(rule, cond))

    forbidden_expressions = rule.get("forbidden_expressions", [])
    if forbidden_expressions:
        safe_contexts = rule.get("safe_contexts", [])
        
        exprs = tree.xpath(".//src:expr", namespaces=NS)
        for expr in exprs:
            expr_text = "".join(expr.itertext()).replace(" ", "").replace("\n", "")
            
            for fe in forbidden_expressions:
                target = fe.replace(" ", "")
                if target in expr_text:
                    if is_in_safe_context(expr, safe_contexts, None, adapter, imports):
                        continue
                        
                    findings.append(build_finding(rule, expr))

    bad_function_defs = rule.get("bad_function_defs", [])
    if bad_function_defs:
        safe_contexts = rule.get("safe_contexts", [])
        
        functions = tree.xpath(".//src:function", namespaces=NS)
        for func in functions:
            name_nodes = func.xpath("./src:name", namespaces=NS)
            if not name_nodes:
                continue
            func_name = "".join(name_nodes[0].itertext()).strip()
            
            params_nodes = func.xpath(".//src:parameter_list", namespaces=NS)
            # params_text = "".join(params_nodes[0].itertext()).replace(" ", "") if params_nodes else ""
            param_names = {
            "".join(n.itertext()).strip()
            for n in func.xpath(".//src:parameter_list//src:name", namespaces=NS)
        }
            
            return_nodes = func.xpath(".//src:return", namespaces=NS)
            return_text = "".join(return_nodes[0].itertext()).replace(" ", "").replace("\n", "") if return_nodes else ""
            
            for bfd in bad_function_defs:
                target_name = bfd.get("name")
                target_param = bfd.get("param")
                raw_return_expr = bfd.get("return_expr")
                target_return = raw_return_expr.replace(" ", "") if raw_return_expr else ""
                
                if func_name == target_name and target_param in param_names and target_return in return_text:
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
                # Deleghiamo all'adapter l'estrazione strutturale!
                param_name, type_text = adapter.get_parameter_name_and_type(param, NS)
                
                if not type_text:
                    continue
                
                for bad_type in bad_param_types:
                    if bad_type in type_text:
                        if is_in_safe_context(func, safe_contexts, var_name=param_name, adapter=adapter, imports=imports):
                            continue
                            
                        findings.append(build_finding(rule, param))
                        break

    # forbidden_calls_with_kwargs = rule.get("forbidden_calls_with_kwargs", [])
    # if forbidden_calls_with_kwargs:
    #     safe_contexts = rule.get("safe_contexts", [])
        
    #     calls = tree.xpath(".//src:call", namespaces=NS)
    #     for call in calls:
    #         name_nodes = call.xpath("./src:name", namespaces=NS)
    #         if not name_nodes:
    #             continue
            
    #         call_name = "".join(name_nodes[0].itertext()).replace(" ", "").replace("\n", "")
            
    #         arg_nodes = call.xpath("./src:argument_list", namespaces=NS)
    #         arg_text = "".join(arg_nodes[0].itertext()).replace(" ", "").replace("\n", "") if arg_nodes else ""
            
    #         for fcwk in forbidden_calls_with_kwargs:
    #             target_prefix = fcwk.get("call_prefix")  
    #             kwargs = fcwk.get("kwargs", {})
                
    #             if call_name.startswith(target_prefix):
                    
    #                 all_kwargs_match = True
    #                 for k, v in kwargs.items():
    #                     if f"{k}={v}" not in arg_text:
    #                         all_kwargs_match = False
    #                         break
                    
    #                 if all_kwargs_match:
    #                     if is_in_safe_context(call, safe_contexts, None, adapter, imports):
    #                         continue
                            
    #                     findings.append(build_finding(rule, call))

    forbidden_calls_with_kwargs = rule.get("forbidden_calls_with_kwargs", [])
    if forbidden_calls_with_kwargs:
        safe_contexts = rule.get("safe_contexts", [])
        
        calls = tree.xpath(".//src:call", namespaces=NS)
        for call in calls:
            call_name = get_call_name(call, adapter, imports)
            if not call_name:
                continue
            
            for fcwk in forbidden_calls_with_kwargs:
                target_prefix = fcwk.get("call_prefix")  
                kwargs = fcwk.get("kwargs", {})
                
                if call_name == target_prefix or call_name.endswith(f".{target_prefix}"):
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
    #CONSIDERARE QUESTO è USATO SOLO DA DUE REGOLE ALL'INTERNO DI RULESET_OS-->IN FUTURO POTREBBE ESSERE ABOLITO
    forbidden_calls_with_arg = rule.get("forbidden_calls_with_arg_pattern", [])
    if forbidden_calls_with_arg:
        safe_contexts = rule.get("safe_contexts", [])

        calls = tree.xpath(".//src:call", namespaces=NS)
        for call in calls:
            call_name = get_call_name(call, adapter, imports)
            if not call_name:
                continue

            arg_nodes = call.xpath("./src:argument_list", namespaces=NS)
            arguments = arg_nodes[0].xpath("./src:argument", namespaces=NS) if arg_nodes else []

            for fca in forbidden_calls_with_arg:
                target_call = fca.get("call")
                required_substr = fca.get("arg_contains")

                if call_name != target_call:
                    continue

                match_found = any(
                    required_substr in "".join(arg.itertext()).replace(" ", "").replace("\n", "")
                    for arg in arguments
                )
                if match_found:
                    if is_in_safe_context(call, safe_contexts, None, adapter, imports):
                        continue
                    findings.append(build_finding(rule, call))

    forbidden_subscripts = rule.get("forbidden_subscripts", [])
    if forbidden_subscripts:
        safe_contexts = rule.get("safe_contexts", [])
        
        for node in tree.xpath(".//src:name[src:index]", namespaces=NS):
            node_text = "".join(node.itertext()).replace(" ", "").replace("\n", "")
            base_name = node_text.split("[")[0]
            
            for subscript in forbidden_subscripts:
                if base_name == subscript or base_name.endswith(f".{subscript}"):
                    if is_in_safe_context(node, safe_contexts, var_name=None, adapter=adapter, imports=imports):
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

    if rule.get("missing_while_increments"):
        _run_missing_while_increments(tree, rule, findings, adapter, imports)

    if rule.get("unsafe_file_reads"):
        _run_unsafe_file_reads(tree, rule, findings, adapter, imports)

    if rule.get("local_var_forbidden_calls"):
        _run_local_var_forbidden_calls(tree, rule, findings, adapter, imports)

    if rule.get("reference_comparisons"):
        _run_reference_comparisons(tree, rule, findings, adapter, imports)

    xpath_queries = rule.get("xpath_rules", [])
    if xpath_queries:
        safe_contexts = rule.get("safe_contexts", [])
        for xp in xpath_queries:
            for node in tree.xpath(xp, namespaces=NS):
                if is_in_safe_context(node, safe_contexts, None, adapter, imports):
                    continue
                findings.append(build_finding(rule, node))

    _run_source_operator_usage(tree, rule, findings, adapter, imports)

    return findings



def run_forbidden_functions_indexed(ctx, compiled, findings, adapter, imports):
    """Sostituisce la sezione 3 di run_structural_rule: un solo giro su
    ctx.calls con lookup O(1) invece di un giro per ogni regola.
    (Versione aggiornata con LanguageAdapter per supporto FQDN e tutti i suffissi)"""
    for call in ctx.calls:
        # 1. Usa l'adattatore per ottenere il nome canonico risolto
        call_name = get_call_name(call, adapter, imports)
        if not call_name:
            continue

        seen = set()
        candidates = []
        
        # 2. Genera TUTTI i suffissi possibili
        # es: "mysql.connector.connect" -> ["mysql.connector.connect", "connector.connect", "connect"]
        parts = call_name.split('.')
        suffixes = [".".join(parts[i:]) for i in range(len(parts))]
        
        # 3. Lookup O(1) per tutti i suffissi validi
        for suff in suffixes:
            for item in compiled.forbidden_functions_index.get(suff, []):
                if id(item[1]) not in seen:
                    seen.add(id(item[1]))
                    candidates.append(item)
                    
        # 4. Aggiunta delle regole non indicizzabili
        for item in compiled.unindexed_forbidden_functions:
            if id(item[1]) not in seen:
                seen.add(id(item[1]))
                candidates.append(item)

        for rule, spec in candidates:
            if not check_required_imports(ctx.unit, rule, NS, imports=imports):
                continue
            if call_name in rule.get("excluded_functions", []):
                continue
            if is_in_safe_context(call, rule.get("safe_contexts", []), None, adapter, imports):
                continue

            # 5. Verifica rigorosa del match
            if isinstance(spec, str):
                if call_name == spec or call_name.endswith(f".{spec}"):
                    findings.append(build_finding(rule, call))
            elif spec.get("type") == "exact_name":
                if call_name == spec.get("name"):
                    findings.append(build_finding(rule, call))
            elif spec.get("type") == "message_template_render":
                if _forbidden_message_template_render(call, spec, adapter, imports):
                    findings.append(build_finding(rule, call))
            elif spec.get("type") == "call_matches_ast":
                if call_arguments_match_ast(call, spec, adapter, imports):
                    findings.append(build_finding(rule, call))


def run_forbidden_names_indexed(ctx, compiled, findings, adapter, imports):
    """Sostituisce la sezione 7 (forbidden_names esatti) con lookup O(1).
    I forbidden_name_prefixes restano a scan lineare (non indicizzabili
    per uguaglianza), ma su un solo giro di ctx.names invece che per regola.
    (Versione aggiornata con LanguageAdapter per supporto FQDN)"""
    for name_node in ctx.names:
        # Ottimizzazione bonus: usiamo la cache di ctx invece di join e itertext ripetuti
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