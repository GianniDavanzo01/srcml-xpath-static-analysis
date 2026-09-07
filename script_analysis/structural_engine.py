#!/usr/bin/env python3
"""
structural_engine.py
---------------------
Motore Strutturale
"""

import re

from common import NS, get_call_name, build_finding, call_arguments_match_ast, check_required_imports
from safe_context_matchers import is_in_safe_context


def _forbidden_message_template_render(call, spec: dict) -> bool:
    """{"type": "message_template_render"}"""
    call_text = "".join(call.itertext()).replace(" ", "").replace("\n", "")
    if "MessageTemplate(" not in call_text or ".render(" not in call_text:
        return False
        
    arg_list_nodes = call.xpath("./src:argument_list", namespaces=NS)
    if not arg_list_nodes:
        return False
        
    args_text = "".join(arg_list_nodes[0].itertext()).replace(" ", "")
    
    if re.search(r"[a-zA-Z0-9_]+=[a-zA-Z0-9_]+", args_text):
        return True
        
    return False


def _run_forbidden_names(tree, rule, findings):
    exact = rule.get("forbidden_names", [])
    prefixes = rule.get("forbidden_name_prefixes", [])
    if not exact and not prefixes:
        return
    safe_contexts = rule.get("safe_contexts", [])
    for name_node in tree.xpath(".//src:name", namespaces=NS):
        full_text = "".join(name_node.itertext()).strip()
        hit = full_text in exact or any(full_text.startswith(p) for p in prefixes)
        if hit:
            if is_in_safe_context(name_node, safe_contexts, None):
                continue
            findings.append(build_finding(rule, name_node))


def _run_source_operator_usage(tree, rule, findings):
    """
    Motore unificato per source_comparisons (==), source_concats (+) e source_percent_formats (%).
    Mappa dinamicamente le vecchie chiavi JSON ai rispettivi operatori e comportamenti
    senza richiedere alcuna modifica ai file delle regole.
    """
    # 1. Dizionario di traduzione: {chiave_json_originale: {operatore, posizione_rispetto_alla_source}}
    mappings = {
        "source_comparisons": {"operator": "==", "position": "after"},
        "source_concats": {"operator": "+", "position": "before"},
        "source_percent_formats": {"operator": "%", "position": "after"}
    }
    
    # 2. Raccogliamo e standardizziamo le regole attive
    active_specs = []
    target_ops = set()
    
    for json_key, behavior in mappings.items():
        specs = rule.get(json_key, [])
        for spec in specs:
            # Creiamo un dizionario arricchito per ogni regola trovata
            enriched_spec = spec.copy()
            enriched_spec["operator"] = behavior["operator"]
            enriched_spec["position"] = behavior["position"]
            active_specs.append(enriched_spec)
            target_ops.add(behavior["operator"])
            
    # Se nessuna delle 3 chiavi è presente nel JSON, usciamo subito
    if not active_specs:
        return

    sanitizers = rule.get("sanitizers", [])
    safe_contexts = rule.get("safe_contexts", [])
    
    # 3. Ottimizzazione AST: cerchiamo solo le espressioni che contengono gli operatori attivi
    op_xpath = " or ".join([f"text()='{op}'" for op in target_ops])
    exprs = tree.xpath(f".//src:expr[.//src:operator[{op_xpath}]]", namespaces=NS)

    # 4. Motore di validazione (scritto una volta, vale per tutti)
    for expr in exprs:
        expr_text = "".join(expr.itertext())

        for spec in active_specs:
            source = spec.get("source")
            form = spec.get("source_form", rule.get("source_form"))
            operator = spec.get("operator")
            position = spec.get("position")
            
            if not source:
                continue

            # A. Trova la Source tramite Regex
            suffix = {"call": r"\(", "subscript": r"\["}.get(form)
            pattern = rf"\b{re.escape(source)}"
            if suffix:
                pattern += rf"(?:\.[a-zA-Z_]\w*)?\s*{suffix}"

            match = re.search(pattern, expr_text)
            if not match:
                continue

            # B. Verifica la posizione dell'operatore (es. "+" prima, "==" o "%" dopo)
            if position == "after" and operator not in expr_text[match.end():]:
                continue
            if position == "before" and not re.search(rf"\{operator}\s*$", expr_text[:match.start()]):
                continue

            # C. Verifica Safe Contexts strutturali
            if is_in_safe_context(expr, safe_contexts):
                continue

            # D. Verifica Sanitizers applicati come funzioni
            is_escaped = False
            for san in sanitizers:
                if position == "before":
                    # Es: + escape(request.args.get()
                    escape_pattern = rf"\{operator}\s*{re.escape(san)}\s*\(\s*{re.escape(source)}"
                else:
                    # Es: escape(request.args.get()) == 
                    escape_pattern = rf"{re.escape(san)}\s*\(\s*{re.escape(source)}"
                
                if re.search(escape_pattern, expr_text):
                    is_escaped = True
                    break
                    
            if is_escaped:
                continue

            # Se tutti i controlli falliscono, genera la vulnerabilità
            findings.append(build_finding(rule, expr))
            break # Un finding per espressione è sufficiente


def _run_weak_key_sizes(tree, rule, findings):
    specs = rule.get("weak_key_sizes", [])
    if not specs:
        return

    safe_contexts = rule.get("safe_contexts", [])

    for name_node in tree.xpath(".//src:name[text()='key_size']", namespaces=NS):
        
        if name_node.xpath("ancestor::src:parameters", namespaces=NS):
            continue 

        nodo_valore = None
        
        op = name_node.xpath("following-sibling::src:operator[1][text()='=']", namespaces=NS)
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
            try:
                valore_numerico = int("".join(lit[0].itertext()).strip())
            except ValueError:
                pass
        else:
            var_nodes = nodo_valore.xpath("descendant-or-self::src:name", namespaces=NS)
            if var_nodes:
                var_name = "".join(var_nodes[0].itertext()).strip()
                
                query_ass = f".//src:name[text()='{var_name}'][following-sibling::src:operator[1][text()='=']]"
                var_assegnazioni = tree.xpath(query_ass, namespaces=NS)
                
                if var_assegnazioni:
                    ultima_ass = var_assegnazioni[-1]
                    op_ass = ultima_ass.xpath("following-sibling::src:operator[1]", namespaces=NS)[0]
                    fratelli_ass = op_ass.xpath("following-sibling::*", namespaces=NS)
                    
                    if fratelli_ass:
                        nodo_valore_ass = fratelli_ass[0]
                        lit_ass = nodo_valore_ass.xpath("descendant-or-self::src:literal[@type='number']", namespaces=NS)
                        if lit_ass:
                            try:
                                valore_numerico = int("".join(lit_ass[0].itertext()).strip())
                            except ValueError:
                                pass

        if valore_numerico is not None:
            for spec in specs:
                max_val = spec.get("max_value", 2048)
                if valore_numerico < max_val:
                    if is_in_safe_context(stmt_node, safe_contexts):
                        continue
                    findings.append(build_finding(rule, stmt_node))
                    break


def _run_forbidden_function_defs(tree, rule, findings):
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

            if is_in_safe_context(func_node, safe_contexts):
                continue

            findings.append(build_finding(rule, func_node))


def _run_missing_while_increments(tree, rule, findings):
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

        exp_assign = block[0].xpath(
            f".//src:expr[src:name[1][text()='{var_name}'] and src:operator[1][text()='='] and .//src:name[text()='{var_name}'] and .//src:operator[text()='+']]", 
            namespaces=NS
        )

        has_increment = bool(aug_assign or exp_assign)

        if not has_increment:
            if is_in_safe_context(w_node, safe_contexts):
                continue
            findings.append(build_finding(rule, w_node))


def _run_unsafe_file_reads(tree, rule, findings):
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

        if is_in_safe_context(w_node, safe_contexts, var_name=var_name):
            continue

        findings.append(build_finding(rule, w_node))


def _run_local_var_forbidden_calls(tree, rule, findings):
    specs = rule.get("local_var_forbidden_calls", [])
    if not specs:
        return

    for spec in specs:
        target_calls = spec.get("call", [])
        if isinstance(target_calls, str):
            target_calls = [target_calls]
        forbidden_nums = spec.get("forbidden_numbers", [])

        call_nodes = tree.xpath(".//src:call", namespaces=NS)
        
        for c_node in call_nodes:
            name_nodes = c_node.xpath("./src:name", namespaces=NS)
            if not name_nodes:
                continue
            call_name = "".join(name_nodes[0].itertext()).strip()

            matched_call = any(call_name == tc or call_name.endswith(f".{tc}") for tc in target_calls)
            if not matched_call:
                continue

            args = c_node.xpath("./src:argument_list/src:argument", namespaces=NS)
            for arg in args:
                name_in_arg = arg.xpath(".//src:name", namespaces=NS)
                if not name_in_arg:
                    continue
                var_name = "".join(name_in_arg[0].itertext()).strip()

                scope_node = c_node.xpath("ancestor::src:block[1] | ancestor::src:function[1]", namespaces=NS)
                if not scope_node:
                    continue

                expr_stmts = scope_node[0].xpath(".//src:expr_stmt", namespaces=NS)
                for stmt in expr_stmts:
                    stmt_text = "".join(stmt.itertext())
                    
                    if stmt_text.startswith(var_name) and "=" in stmt_text:
                        for fnum in forbidden_nums:
                            if fnum in stmt_text:
                                finding = build_finding(rule, c_node)
                                if finding not in findings:
                                    findings.append(finding)
                                break


def _run_reference_comparisons(tree, rule, findings):
    safe_contexts = rule.get("safe_contexts", [])
    operators = tree.xpath(".//src:operator[text()='is' or text()='is not']", namespaces=NS)
    
    for op in operators:
        rhs_nodes = op.xpath("./following-sibling::*[not(self::src:comment)]", namespaces=NS)
        if not rhs_nodes:
            continue
            
        rhs_text = "".join(rhs_nodes[0].itertext()).strip()
        
        if rhs_text in ["None", "True", "False"]:
            continue
            
        if is_in_safe_context(op, safe_contexts):
            continue
            
        findings.append(build_finding(rule, op))


def run_structural_rule(tree, rule: dict) -> list:
    findings = []

    if not check_required_imports(tree, rule, NS):
        return findings

    if "required_calls" in rule:
        all_calls = {node.text for node in tree.xpath(".//src:call//src:name", namespaces=NS) if node.text}
        if not all(req in all_calls for req in rule["required_calls"]):
            return findings

    bad_assignments = rule.get("bad_assignments", {})
    if bad_assignments:
        safe_contexts = rule.get("safe_contexts", []) 
        assignments = tree.xpath(".//src:expr_stmt[.//src:operator[text()='=']]", namespaces=NS)

        for assign in assignments:
            op = assign.xpath(".//src:operator[text()='='][1]", namespaces=NS)
            if not op:
                continue
                
            lhs_nodes = op[0].xpath("./preceding-sibling::*", namespaces=NS)
            rhs_nodes = op[0].xpath("./following-sibling::*", namespaces=NS)
            
            lhs_text = "".join(n.text or "".join(n.itertext()) for n in lhs_nodes).strip()
            rhs_text = "".join(n.text or "".join(n.itertext()) for n in rhs_nodes).strip()
            
            for attr, val in bad_assignments.items():
                if (lhs_text == attr or lhs_text.endswith(f".{attr}")) and rhs_text == val:
                    if is_in_safe_context(assign, safe_contexts): 
                        continue
                    findings.append(build_finding(rule, assign))

    bad_calls = rule.get("bad_calls", {})
    if bad_calls:
        calls = tree.xpath(".//src:call", namespaces=NS)
        for call in calls:
            arg_list_nodes = call.xpath("./src:argument_list", namespaces=NS)
            call_name = get_call_name(call)
            if not call_name or not arg_list_nodes:
                continue

            args_text = "".join(arg_list_nodes[0].itertext()).replace(" ", "").replace("\n", "")

            for func, kwargs in bad_calls.items():
                if call_name == func or call_name.endswith(f".{func}"):
                    is_vulnerable = any(f"{kwarg}={val}" in args_text for kwarg, val in kwargs.items())
                    if is_vulnerable:
                        findings.append(build_finding(rule, call))

    forbidden_functions = rule.get("forbidden_functions", [])
    if forbidden_functions:
        excluded_functions = rule.get("excluded_functions", [])
        safe_contexts = rule.get("safe_contexts", [])

        calls = tree.xpath(".//src:call", namespaces=NS)
        for call in calls:
            if is_in_safe_context(call, safe_contexts):
                continue

            call_name = get_call_name(call)
            if not call_name or call_name in excluded_functions:
                continue

            for spec in forbidden_functions:
                if isinstance(spec, str):
                    if call_name == spec or call_name.endswith(f".{spec}"):
                        findings.append(build_finding(rule, call))
                        
                elif isinstance(spec, dict) and spec.get("type") == "exact_name":
                    if call_name == spec.get("name"):
                        findings.append(build_finding(rule, call))

                elif isinstance(spec, dict) and spec.get("type") == "message_template_render":
                    if _forbidden_message_template_render(call, spec):
                        findings.append(build_finding(rule, call))
                        
                elif isinstance(spec, dict) and spec.get("type") == "call_matches_ast":
                    if call_arguments_match_ast(call, spec):
                        findings.append(build_finding(rule, call))

    sensitive_patterns = rule.get("sensitive_var_patterns", [])
    if sensitive_patterns:
        safe_contexts = rule.get("safe_contexts", [])
        name_regex = re.compile("|".join(re.escape(p) for p in sensitive_patterns), re.IGNORECASE)

        assignments = tree.xpath(".//src:expr_stmt[src:expr[src:operator[text()='=']]]", namespaces=NS)
        for assign in assignments:
            lhs = assign.xpath("./src:expr/src:name[1]", namespaces=NS)
            op = assign.xpath("./src:expr/src:operator[text()='='][1]", namespaces=NS)
            
            if not lhs or not op:
                continue
            
            rhs_nodes = op[0].xpath("./following-sibling::*", namespaces=NS)
            
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

            var_name = "".join(lhs[0].itertext()).strip()
            if name_regex.search(var_name) and not is_in_safe_context(lhs[0], safe_contexts):
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
                if name_regex.search(var_name) and not is_in_safe_context(n, safe_contexts):
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
                call_name = get_call_name(call_node)
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
                        if is_in_safe_context(imp, safe_contexts):
                            continue
                        findings.append(build_finding(rule, imp))
                        break

    inline_sources = rule.get("inline_source_as_arg", [])
    if inline_sources:
        for c in tree.xpath(".//src:call", namespaces=NS):
            if get_call_name(c) in inline_sources:
                if c.xpath("ancestor::src:argument | ancestor::src:parameter", namespaces=NS):
                    findings.append(build_finding(rule, c))

    if rule.get("forbidden_names") or rule.get("forbidden_name_prefixes"):
        _run_forbidden_names(tree, rule, findings)

    forbidden_returns = rule.get("forbidden_returns", [])
    if forbidden_returns:
        safe_contexts = rule.get("safe_contexts", [])
        returns = tree.xpath(".//src:return", namespaces=NS)
        for ret in returns:
            if is_in_safe_context(ret, safe_contexts):
                continue
            
            for spec in forbidden_returns:
                if spec.get("type") == "fstring":
                    fstrings = ret.xpath(".//src:literal[@type='string']", namespaces=NS)
                    has_fstring_with_interpolation = False
                    for fs in fstrings:
                        fs_text = "".join(fs.itertext()).strip()
                        if fs_text.startswith("f") and "{" in fs_text:
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
                    if is_in_safe_context(ret, safe_contexts):
                        continue
                        
                    findings.append(build_finding(rule, ret))
                    break 

    if rule.get("weak_key_sizes"):
        _run_weak_key_sizes(tree, rule, findings)

    if rule.get("forbidden_function_defs"):
        _run_forbidden_function_defs(tree, rule, findings)

    forbidden_conditions = rule.get("forbidden_conditions", [])
    if forbidden_conditions:
        safe_contexts = rule.get("safe_contexts", [])
        
        conditions = tree.xpath(".//src:if_stmt//src:condition", namespaces=NS)
        for cond in conditions:
            cond_text = "".join(cond.itertext()).replace(" ", "").replace("\n", "")
            
            for fc in forbidden_conditions:
                target = fc.replace(" ", "")
                if target in cond_text:
                    if is_in_safe_context(cond, safe_contexts):
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
                    if is_in_safe_context(expr, safe_contexts):
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
            params_text = "".join(params_nodes[0].itertext()).replace(" ", "") if params_nodes else ""
            
            return_nodes = func.xpath(".//src:return", namespaces=NS)
            return_text = "".join(return_nodes[0].itertext()).replace(" ", "").replace("\n", "") if return_nodes else ""
            
            for bfd in bad_function_defs:
                target_name = bfd.get("name")
                target_param = bfd.get("param")
                raw_return_expr = bfd.get("return_expr")
                target_return = raw_return_expr.replace(" ", "") if raw_return_expr else ""
                
                if func_name == target_name and target_param in params_text and target_return in return_text:
                    if is_in_safe_context(func, safe_contexts):
                        continue
                        
                    findings.append(build_finding(rule, func))

    bad_param_types = rule.get("bad_param_types", [])
    if bad_param_types:
        safe_contexts = rule.get("safe_contexts", [])
        
        functions = tree.xpath(".//src:function", namespaces=NS)
        for func in functions:
            params_nodes = func.xpath(".//src:parameter", namespaces=NS)
            
            for param in params_nodes:
                param_text = "".join(param.itertext()).replace(" ", "").replace("\n", "")
                
                for bad_type in bad_param_types:
                    target = f":{bad_type}"
                    if target in param_text:
                        param_name = param_text.split(":")[0]
                        
                        if is_in_safe_context(func, safe_contexts, var_name=param_name):
                            continue
                            
                        findings.append(build_finding(rule, param))

    forbidden_calls_with_kwargs = rule.get("forbidden_calls_with_kwargs", [])
    if forbidden_calls_with_kwargs:
        safe_contexts = rule.get("safe_contexts", [])
        
        calls = tree.xpath(".//src:call", namespaces=NS)
        for call in calls:
            name_nodes = call.xpath("./src:name", namespaces=NS)
            if not name_nodes:
                continue
            
            call_name = "".join(name_nodes[0].itertext()).replace(" ", "").replace("\n", "")
            
            arg_nodes = call.xpath("./src:argument_list", namespaces=NS)
            arg_text = "".join(arg_nodes[0].itertext()).replace(" ", "").replace("\n", "") if arg_nodes else ""
            
            for fcwk in forbidden_calls_with_kwargs:
                target_prefix = fcwk.get("call_prefix")  
                kwargs = fcwk.get("kwargs", {})
                
                if call_name.startswith(target_prefix):
                    
                    all_kwargs_match = True
                    for k, v in kwargs.items():
                        if f"{k}={v}" not in arg_text:
                            all_kwargs_match = False
                            break
                    
                    if all_kwargs_match:
                        if is_in_safe_context(call, safe_contexts):
                            continue
                            
                        findings.append(build_finding(rule, call))

    forbidden_calls_with_arg = rule.get("forbidden_calls_with_arg_pattern", [])
    if forbidden_calls_with_arg:
        safe_contexts = rule.get("safe_contexts", [])
        
        calls = tree.xpath(".//src:call", namespaces=NS)
        for call in calls:
            name_nodes = call.xpath("./src:name", namespaces=NS)
            if not name_nodes:
                continue
            
            call_name = "".join(name_nodes[0].itertext()).replace(" ", "").replace("\n", "")
            
            arg_nodes = call.xpath("./src:argument_list", namespaces=NS)
            arg_text = "".join(arg_nodes[0].itertext()).replace(" ", "").replace("\n", "") if arg_nodes else ""
            
            for fca in forbidden_calls_with_arg:
                target_call = fca.get("call")         
                required_substr = fca.get("arg_contains")
                
                if call_name == target_call and required_substr in arg_text:
                    if is_in_safe_context(call, safe_contexts):
                        continue
                        
                    findings.append(build_finding(rule, call))

    forbidden_string_patterns = rule.get("forbidden_string_patterns", [])
    if forbidden_string_patterns:
        safe_contexts = rule.get("safe_contexts", [])
        
        string_literals = tree.xpath(".//src:literal[@type='string']", namespaces=NS)
        for string_node in string_literals:
            string_text = "".join(string_node.itertext())
            
            for pattern in forbidden_string_patterns:
                if re.search(pattern, string_text):
                    if is_in_safe_context(string_node, safe_contexts):
                        continue
                        
                    findings.append(build_finding(rule, string_node))
                    break 

    forbidden_subscripts = rule.get("forbidden_subscripts", [])
    if forbidden_subscripts:
        safe_contexts = rule.get("safe_contexts", [])
        
        for node in tree.xpath(".//src:name[src:index]", namespaces=NS):
            node_text = "".join(node.itertext()).replace(" ", "").replace("\n", "")
            base_name = node_text.split("[")[0]
            
            for subscript in forbidden_subscripts:
                if base_name == subscript or base_name.endswith(f".{subscript}"):
                    if is_in_safe_context(node, safe_contexts, var_name=None):
                        break
                    findings.append(build_finding(rule, node))
                    break
    
    if rule.get("forbidden_asserts"):
        safe_contexts = rule.get("safe_contexts", [])
        asserts = tree.xpath(".//src:assert", namespaces=NS)
        for ass_node in asserts:
            if is_in_safe_context(ass_node, safe_contexts):
                continue
            findings.append(build_finding(rule, ass_node))

    if rule.get("missing_while_increments"):
        _run_missing_while_increments(tree, rule, findings)

    if rule.get("unsafe_file_reads"):
        _run_unsafe_file_reads(tree, rule, findings)

    if rule.get("local_var_forbidden_calls"):
        _run_local_var_forbidden_calls(tree, rule, findings)


    if rule.get("reference_comparisons"):
        _run_reference_comparisons(tree, rule, findings)

    xpath_queries = rule.get("xpath_rules", [])
    if xpath_queries:
        safe_contexts = rule.get("safe_contexts", [])
        for xp in xpath_queries:
            for node in tree.xpath(xp, namespaces=NS):
                if is_in_safe_context(node, safe_contexts):
                    continue
                findings.append(build_finding(rule, node))

    _run_source_operator_usage(tree, rule, findings)

    return findings