"""
structural_engine.py
---------------------
Motore Strutturale
"""

import re

from common import NS, get_call_name, build_finding, call_arguments_match_ast, check_required_imports,_pos_key, find_assignments,_is_pure_literal_expr, assignment_pairs, enclosing_scope, extract_output_buffer_name
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
                    
                # CASO 1: La sorgente è una funzione 
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
    
    # Intercetta sia while che do-while
    loop_nodes = tree.xpath(".//src:while | .//src:do", namespaces=NS)

    for loop_node in loop_nodes:
        # Cerca qualsiasi operatore di confronto, non solo '<'
        cond_ops = loop_node.xpath(
            "./src:condition//src:operator[text()='<' or text()='<=' or text()='>' or text()='>=' or text()='!=' or text()='==']", 
            namespaces=NS
        )
        
        # Gestione speciale per cicli palesemente infiniti: while(1), while(true)
        is_literal_true = False
        literals = loop_node.xpath("./src:condition//src:literal", namespaces=NS)
        if literals:
            lit_text = "".join(literals[0].itertext()).strip()
            if lit_text == "1" or adapter.is_boolean_literal(lit_text):
                if lit_text not in ("0", "false", "False"): # Assicurati che non sia while(0)
                    is_literal_true = True

        block = loop_node.xpath("./src:block", namespaces=NS)
        if not block:
            continue
            
        # Se il ciclo è infinito (while(true) o while(1)), DEVE esserci un break/return
        if is_literal_true:
            has_break_or_return = bool(block[0].xpath(".//src:break | .//src:return", namespaces=NS))
            if not has_break_or_return:
                if not is_in_safe_context(loop_node, safe_contexts, None, adapter, imports):
                    findings.append(build_finding(rule, loop_node))
            continue

        # Se non ci sono operatori e non è while(1), passiamo oltre
        if not cond_ops:
            continue

        op_node = cond_ops[0]
        lhs_nodes = op_node.xpath("./preceding-sibling::*[not(self::src:comment)]", namespaces=NS)
        if not lhs_nodes:
            continue

        var_name = "".join(lhs_nodes[-1].itertext()).strip()
        if not var_name.isidentifier():
            continue

        # Cerca l'incremento: +=, -=, ++, --, oppure var = var + X
        aug_assign = block[0].xpath(
            f".//src:expr[src:name[1][text()='{var_name}'] and src:operator[1][text()='+=' or text()='-=']]",
            namespaces=NS
        )
        
        inc_dec = block[0].xpath(
            f".//src:expr[.//src:name[text()='{var_name}'] and .//src:operator[text()='++' or text()='--']]",
            namespaces=NS
        )

        assign_op = adapter.assignment_operator_token()
        exp_assign = block[0].xpath(
            f".//src:expr[src:name[1][text()='{var_name}'] and src:operator[1][text()='{assign_op}']"
            f" and .//src:name[text()='{var_name}']]", 
            namespaces=NS
        )

        has_increment = bool(aug_assign or exp_assign or inc_dec)
        
        # Controlla anche se c'è un break (che rende sicuro il ciclo anche se manca l'incremento palese)
        has_break = bool(block[0].xpath(".//src:break | .//src:return", namespaces=NS))

        if not has_increment and not has_break:
            if is_in_safe_context(loop_node, safe_contexts, None, adapter, imports):
                continue
            findings.append(build_finding(rule, loop_node))

 

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

        lhs_node = lhs_nodes[-1] if lhs_nodes else None
        rhs_node = rhs_nodes[0]

        def is_primitive_literal(node):
            if node is None:
                return False
            # Verifica se il nodo è esattamente un letterale numerico o di carattere
            return node.tag.endswith("literal") and node.get("type") in ["number", "char"]

        if is_primitive_literal(lhs_node) or is_primitive_literal(rhs_node):
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
    {"use_after_free": {"deallocation_calls": ["free"], "safe_allocation_calls": [...], "safe_reassignments": [...]}}
    Classifica ogni finding come CWE-415 (double-free) o CWE-416 (use-after-free generico)
    in base alla natura dell'uso non sanificato trovato.
    """
    spec = rule.get("use_after_free")
    if not spec:
        return

    _adapter = adapter or PythonAdapter()
    target_calls = spec.get("deallocation_calls", ["free"])
    safe_allocations = spec.get("safe_allocation_calls", [])
    safe_reassignments = spec.get("safe_reassignments", [])

    for node in tree.xpath(".//src:call", namespaces=NS):
        call_name = get_call_name(node, _adapter, imports)
        if not call_name or call_name not in target_calls:
            continue

        scope = enclosing_scope(node, _adapter)
        if scope is None:
            continue

        arg_nodes = node.xpath("./src:argument_list/src:argument[1]", namespaces=NS)
        if not arg_nodes:
            continue

        # accessi a membro (s->buf, a.b): il forward scan cerca <name> semplici,
        # quindi non vengono tracciati (comportamento invariato rispetto a prima)
        if arg_nodes[0].xpath(".//src:name[src:name]", namespaces=NS):
            continue

        original_target = extract_output_buffer_name(arg_nodes[0])
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
            lhs_names = set(n.text for n in lhs.xpath("descendant-or-self::src:name", namespaces=NS) if n.text)
            rhs_names = set(
                n.text for n in rhs.xpath(
                    "descendant-or-self::src:name[not(following-sibling::src:argument_list)]", namespaces=NS
                ) if n.text
            )
            if aliased_pointers.intersection(lhs_names):
                if not rhs.xpath(".//src:call", namespaces=NS):
                    aliased_pointers.update(rhs_names)
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

            enclosing_stmt = uso.xpath(
                "ancestor::*[self::src:expr_stmt or self::src:decl_stmt][1]", namespaces=NS
            )
            is_sanitized = False

            if enclosing_stmt and _adapter.is_assignment(enclosing_stmt[0], NS):
                lhs, rhs = _adapter.get_assignment_lhs_rhs(enclosing_stmt[0], NS)
                if lhs is not None and rhs is not None and (uso in lhs.iter() or uso is lhs):
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
                call_ancestor = uso.xpath("ancestor::src:call[1]", namespaces=NS)
                is_double_free = False
                if call_ancestor:
                    ancestor_call_name = get_call_name(call_ancestor[0], _adapter, imports)
                    if ancestor_call_name in target_calls:
                        is_double_free = True

                extra = {"vulnerabilities": ["CWE-415"]} if is_double_free else {"vulnerabilities": ["CWE-416"]}
                findings.append(build_finding(rule, uso, extra=extra))
                aliased_pointers.discard(p)


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
        
        for assign, lhs_node, rhs_node in assignment_pairs(tree, adapter):
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

            # dichiarazione di array (char buf[1024]; struct { int a[4]; }): non è un accesso
            if node.xpath("parent::src:decl", namespaces=NS):
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
                # 1. Controllo diretto: è un letterale puro? (es. array[2])
                is_literal_index = _is_pure_literal_expr(index_expr[0])
                
                idx_names = index_expr[0].xpath("./src:name", namespaces=NS)
                if len(idx_names) == 1 and len(list(index_expr[0])) == 1:
                    index_var = "".join(idx_names[0].itertext()).strip()
                    
                    # 2. Risoluzione basata su resolve_numeric_args
                    # Se non è un letterale diretto, facciamo un backward scan
                    # per vedere se l'ultima assegnazione era un letterale sicuro.
                    if not is_literal_index and rule.get("skip_literal_subscript_index"):
                        node_key = _pos_key(node)
                        scope_node = enclosing_scope(node, adapter)
                        if scope_node is None:
                            scope_node = tree
                        
                        prior_assigns = [
                            (stmt, rhs) for stmt, _, rhs in find_assignments(scope_node, adapter, index_var)
                            if _pos_key(stmt) < node_key and rhs is not None and _is_pure_literal_expr(rhs)
                        ]
                        
                        if prior_assigns:
                            # Trovata un'assegnazione hardcodata precedente! Scartiamo il finding.
                            is_literal_index = True
                
                # Se la regola lo consente e abbiamo appurato che è un letterale (diretto o assegnato), saltiamo.
                if rule.get("skip_literal_subscript_index") and is_literal_index:
                    continue
                
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

        parts = call_name.split('.')
        suffixes = [".".join(parts[i:]) for i in range(len(parts))]

        # 1. Candidati: dedup per (regola, spec), non per sola regola.
        #    Serve solo a non contare due volte la stessa spec trovata
        #    tramite suffissi diversi ('os.system' e 'system').
        seen = set()
        candidates = []

        for suff in suffixes:
            for rule_obj, spec in compiled.forbidden_functions_index.get(suff, []):
                key = (id(rule_obj), id(spec))
                if key not in seen:
                    seen.add(key)
                    candidates.append((rule_obj, spec))

        for rule_obj, spec in compiled.unindexed_forbidden_functions:
            key = (id(rule_obj), id(spec))
            if key not in seen:
                seen.add(key)
                candidates.append((rule_obj, spec))

        # 2. Validazione: al massimo un finding per regola per call,
        #    ma DOPO aver verificato che la spec abbia davvero matchato.
        reported_rules = set()
        for rule, spec in candidates:
            if id(rule) in reported_rules:
                continue
            if not check_required_imports(ctx.unit, rule, NS, imports=imports):
                continue
            if call_name in rule.get("excluded_functions", []):
                continue
            if is_in_safe_context(call, rule.get("safe_contexts", []), None, adapter, imports):
                continue

            if isinstance(spec, str):
                matched = call_name == spec or call_name.endswith(f".{spec}")
            elif spec.get("type") == "exact_name":
                matched = call_name == spec.get("name")
            elif spec.get("type") == "call_matches_ast":
                matched = call_arguments_match_ast(call, spec, adapter, imports)
            else:
                matched = False

            if matched:
                findings.append(build_finding(rule, call))
                reported_rules.add(id(rule))

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