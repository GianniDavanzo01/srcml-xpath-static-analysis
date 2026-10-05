"""
structural_engine.py
---------------------
Motore Strutturale
"""

import re

from common import NS, get_call_name, build_finding, call_arguments_match_ast, check_required_imports,_pos_key, find_assignments,_is_pure_literal_expr,  \
assignment_pairs, enclosing_scope, node_snippet, call_matches, call_lookup_keys, function_nodes, scope_xpath
from safe_context_matchers import is_in_safe_context



def _run_source_operator_usage(tree, rule, findings, adapter, imports, catalog=None):
    catalog = catalog or {}
    op_roles = adapter.string_formatting_operator_roles()
    eq_op = adapter.equality_operator()

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
            matched_node = None
            
            # Valuta sia la sinistra che la destra
            for sibling in (lhs, rhs):
                if sibling is None:
                    continue
                    
                # CASO 1: La sorgente è una funzione 
                if sibling.tag.endswith("call"):
                    c_name = get_call_name(sibling, adapter, imports)
                    if any(call_matches(c_name, s, adapter) for s in source_names):
                        match_found = True
                        matched_source = c_name
                        matched_node = sibling
                        break
                        
                # CASO 2: La sorgente è una variabile o proprietà (es. request.data)
                # Estraiamo in modo sicuro il testo dai nodi name ignorando i tag intermedi.
                # Per ciascun candidato ricostruiamo il nome puntato solo dai <name> figli
                # diretti (escludendo eventuali <index>), cosi' un subscript come
                # request.args['id'] non contamina il confronto col contenuto tra [ ].
                names = sibling.xpath("descendant-or-self::src:name", namespaces=NS)
                for n in names:
                    op = adapter.member_access_operator()[0]
                    parts = n.xpath("./src:name", namespaces=NS)
                    if parts:
                        n_text = op.join("".join(p.itertext()).strip() for p in parts)
                    else:
                        n_text = "".join(n.itertext()).replace(" ", "")

                    n_text = adapter.resolve_name_text(n_text, imports)
                    if any(call_matches(n_text, s, adapter) for s in source_names):
                        match_found = True
                        matched_source = n_text
                        matched_node = n
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
                    if c_name and any(call_matches(c_name, s, adapter) for s in resolved_sanitizers):
                        # il nodo sorgente deve stare davvero dentro la call sanitizer
                        if matched_node is c_node or matched_node in c_node.iterdescendants():
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

        fn = " or ".join(f"self::src:{t}" for t in adapter.function_tags())
        noop = " or ".join(f"self::src:{t}" for t in ["comment"] + adapter.noop_statement_tags())
        for func_node in function_nodes(tree, adapter, name=target_name):
            if is_async and not adapter.is_async_function(func_node, NS):
                continue
                    
            if max_params is not None:
                params = func_node.xpath(".//src:parameter_list//src:parameter", namespaces=NS)
                if len(params) > max_params:
                    continue
                    
            if exact_body in ["{}", "empty"]:
                block_content = func_node.xpath("./src:block/src:block_content", namespaces=NS)
                if not block_content:
                    continue
                valid_stmts = block_content[0].xpath(f"./*[not({noop})]", namespaces=NS)
                if len(valid_stmts) > 0:
                    continue

            if is_in_safe_context(func_node, safe_contexts, None, adapter, imports):
                continue

            findings.append(build_finding(rule, func_node))


#HELPER PER _run_missing_while_increments
def _loop_has_exit(loop_node, block, adapter) -> bool:
    """True se nel corpo c'è un'uscita che riguarda DAVVERO questo ciclo."""
    exit_tags = adapter.loop_exit_tags()
    if not exit_tags:
        return False

    exits_xp = " | ".join(f".//src:{t}" for t in exit_tags)
    target_xp = " or ".join(f"self::src:{t}" for t in adapter.break_target_tags())
    scope_xp = scope_xpath(adapter, with_lambda=True)
    my_scope = loop_node.xpath(scope_xp, namespaces=NS)
    break_tag = f"{{{NS['src']}}}break"

    for n in block.xpath(exits_xp, namespaces=NS):
        # return/throw dentro una lambda o funzione annidata non esce dal nostro ciclo
        if n.xpath(scope_xp, namespaces=NS) != my_scope:
            continue
        # break semplice: vale solo se il costrutto più vicino che lo cattura è questo ciclo
        # (un break con etichetta, 'break outer;', lo conto sempre come uscita: scelta prudente)
        if n.tag == break_tag and not n.xpath("./src:name", namespaces=NS):
            nearest = n.xpath(f"ancestor::*[{target_xp}][1]", namespaces=NS)
            if not nearest or nearest[0] is not loop_node:
                continue
        return True
    return False


def _run_missing_while_increments(tree, rule, findings, adapter, imports):
    specs = rule.get("missing_while_increments", [])
    if not specs:
        return

    safe_contexts = rule.get("safe_contexts", [])
    
    # Intercetta sia while che do-while
    loop_nodes = tree.xpath(".//src:while | .//src:do", namespaces=NS)

    for loop_node in loop_nodes:
        # Cerca qualsiasi operatore di confronto, non solo '<'
        cmp_xp = " or ".join(f"text()='{o}'" for o in adapter.comparison_operators())
        cond_ops = loop_node.xpath(
            f"./src:condition//src:operator[{cmp_xp}]",
            namespaces=NS
        )
        
        # Gestione speciale per cicli palesemente infiniti: while(1), while(true)
        literals = loop_node.xpath("./src:condition/src:expr[count(*)=1]/src:literal", namespaces=NS)
        is_literal_true = bool(literals) and adapter.is_true_constant("".join(literals[0].itertext()))
        
        block = loop_node.xpath("./src:block", namespaces=NS)
        if not block:
            continue
            
        # Se il ciclo è infinito (while(true) o while(1)), DEVE esserci un break/return
        if is_literal_true:
            has_break_or_return = _loop_has_exit(loop_node, block[0], adapter)
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
        if not adapter.is_identifier(var_name):
            continue

        # Cerca l'incremento: +=, -=, ++, --, oppure var = var + X
        upd = adapter.loop_update_operators()
        op_cond = lambda ops: " or ".join(f"text()='{o}'" for o in ops) or "false()"
        comp_xp = op_cond(upd["compound"])
        unary_xp = op_cond(upd["unary"])

        aug_assign = block[0].xpath(
            f".//src:expr[src:name[1][text()='{var_name}'] and src:operator[1][{comp_xp}]]",
            namespaces=NS
        )
        
        inc_dec = block[0].xpath(
            f".//src:expr[.//src:name[text()='{var_name}'] and .//src:operator[{unary_xp}]]",
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
        has_break = _loop_has_exit(loop_node, block[0], adapter)

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

    def is_primitive_literal(node):
        return (node is not None and node.tag.endswith("literal")
                and node.get("type") in ("number", "char"))

    def is_signed_number(nodes):          # -1 / +1: operatore + letterale
        return (len(nodes) >= 2 and nodes[0].tag.endswith("operator")
                and "".join(nodes[0].itertext()).strip() in ("-", "+")
                and nodes[1].tag.endswith("literal") and nodes[1].get("type") == "number")

    for op in tree.xpath(f".//src:operator[{op_xpath}]", namespaces=NS):
        lhs_nodes = op.xpath("./preceding-sibling::*[not(self::src:comment)]", namespaces=NS)
        rhs_nodes = op.xpath("./following-sibling::*[not(self::src:comment)]", namespaces=NS)
        if not rhs_nodes:
            continue

        rhs_text = "".join(rhs_nodes[0].itertext()).strip()
        if adapter.is_none_literal(rhs_text) or adapter.is_boolean_literal(rhs_text):
            continue

        lhs_node = lhs_nodes[-1] if lhs_nodes else None
        rhs_node = rhs_nodes[0]
        if is_primitive_literal(lhs_node) or is_primitive_literal(rhs_node) or is_signed_number(rhs_nodes):
            continue

        lhs_type = adapter.resolve_operand_type(lhs_node, NS)
        rhs_type = adapter.resolve_operand_type(rhs_node, NS)
        if not adapter.is_reference_comparison(lhs_type, rhs_type):
            continue

        if is_in_safe_context(op, safe_contexts, None, adapter, imports):
            continue

        lhs_txt = node_snippet(lhs_node, 60) if lhs_node is not None else "?"
        rhs_txt = node_snippet(rhs_node, 60)
        op_txt = "".join(op.itertext()).strip()
        findings.append(build_finding(
            rule, op,
            extra={"snippet": f"{lhs_txt} {op_txt} {rhs_txt}",
                   "operand_types": [lhs_type, rhs_type]},
        ))



def _run_empty_catch_blocks(tree, rule, findings, adapter, imports):
    if not rule.get("empty_catch_blocks"):
        return

    safe_contexts = rule.get("safe_contexts", [])
    catches = tree.xpath(".//src:catch", namespaces=NS)

    noop = " or ".join(f"self::src:{t}" for t in ["comment"] + adapter.noop_statement_tags())
    for catch in catches:
        block_content = catch.xpath("./src:block/src:block_content", namespaces=NS)
        if not block_content:
            continue

        # Stesso criterio già usato per i corpi funzione vuoti:
        # nessun figlio reale a parte commenti (e 'pass' per Python)
        valid_stmts = block_content[0].xpath(f"./*[not({noop})]", namespaces=NS)
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

    target_calls = spec.get("deallocation_calls")
    safe_allocations = spec.get("safe_allocation_calls", [])
    safe_reassignments = spec.get("safe_reassignments", [])

    for node in tree.xpath(".//src:call", namespaces=NS):
        call_name = get_call_name(node, adapter, imports)
        if not call_name or not any(call_matches(call_name, t, adapter) for t in target_calls):
            continue

        scope = enclosing_scope(node, adapter)
        if scope is None:
            continue

        arg_nodes = node.xpath("./src:argument_list/src:argument[1]", namespaces=NS)
        if not arg_nodes:
            continue

        # accessi a membro (s->buf, a.b): il forward scan cerca <name> semplici,
        # quindi non vengono tracciati (comportamento invariato rispetto a prima)
        if arg_nodes[0].xpath(".//src:name[src:name]", namespaces=NS):
            continue

        original_target = adapter.extract_output_buffer_name(arg_nodes[0], NS)
        if not original_target:
            continue

        aliased_pointers = {original_target}
        node_key = _pos_key(node)

        # --- BACKWARD SCAN ---
        all_assignments = find_assignments(scope, adapter)
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

            if enclosing_stmt and adapter.is_assignment(enclosing_stmt[0], NS):
                lhs, rhs = adapter.get_assignment_lhs_rhs(enclosing_stmt[0], NS)
                if lhs is not None and rhs is not None and (uso in lhs.iter() or uso is lhs):
                    rhs_names = [n.text for n in rhs.xpath("descendant-or-self::src:name", namespaces=NS) if n.text]
                    if p not in rhs_names:
                        rhs_text = "".join(rhs.itertext()).strip()
                        is_safe_val = adapter.is_none_literal(rhs_text) or rhs_text in safe_reassignments
                        is_safe_alloc = False

                        if safe_allocations:
                            calls = rhs.xpath(
                                "descendant-or-self::src:call | following-sibling::src:call | "
                                "following-sibling::*//src:call", namespaces=NS)
                            is_safe_alloc = any(
                                (cn := get_call_name(c, adapter, imports))
                                and any(call_matches(cn, a, adapter) for a in safe_allocations)
                                for c in calls
                            )


                        if is_safe_val or is_safe_alloc:
                            is_sanitized = True
                            aliased_pointers.discard(p)

            if not is_sanitized:
                call_ancestor = uso.xpath("ancestor::src:call[1]", namespaces=NS)
                is_double_free = False
                if call_ancestor:
                    ancestor_call_name = get_call_name(call_ancestor[0], adapter, imports)

                    if ancestor_call_name and any(call_matches(ancestor_call_name, t, adapter) for t in target_calls):
                        is_double_free = True

                extra = {"vulnerabilities": ["CWE-415"]} if is_double_free else {"vulnerabilities": ["CWE-416"]}
                findings.append(build_finding(rule, uso, extra=extra))
                aliased_pointers.discard(p)


def run_structural_rule(tree, rule: dict, adapter, imports, ctx) -> list:

    findings = []

    if "required_calls" in rule:

        all_calls = {get_call_name(c, adapter, imports)
             for c in tree.xpath(".//src:call", namespaces=NS)} - {None}
        if not all(any(call_matches(c, r, adapter) for c in all_calls) for r in rule["required_calls"]):
            return findings

    bad_assignments = rule.get("bad_assignments", {})
    if bad_assignments:
        safe_contexts = rule.get("safe_contexts", []) 
        
        for assign, lhs_node, rhs_node in assignment_pairs(tree, adapter):
            if lhs_node is None or rhs_node is None:
                continue
            
            # Estraiamo il testo della parte sinistra preservando la struttura dei nomi (es. app.debug)
            lhs_text = "".join(lhs_node.itertext()).strip().replace(" ", "")
            lhs_text = adapter.resolve_name_text(lhs_text, imports)
            
            # Normalizziamo la parte destra usando l'adapter (gestisce apici, booleani, ecc.)
            rhs_text = "".join(rhs_node.itertext()).strip()
            
            rhs_text = adapter.normalize_string_literal(rhs_text)
            if rhs_node.tag.endswith("}name"):          # solo identificatori, mai stringhe
                rhs_text = adapter.resolve_name_text(rhs_text, imports)
            
            for attr, val in bad_assignments.items():
                # Confronto strutturale sicuro
                if call_matches(lhs_text, attr, adapter) and rhs_text == val:
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
            
            if binding.is_macro:      
                continue

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
                        if adapter.is_interpolated_string(fs_text):
                            has_fstring_with_interpolation = True
                            break
                    if has_fstring_with_interpolation:
                        findings.append(build_finding(rule, ret))
                        break


    bad_function_defs = rule.get("bad_function_defs", [])
    if bad_function_defs:
        safe_contexts = rule.get("safe_contexts", [])
        
        functions = function_nodes(tree, adapter)
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
                target_return = adapter.canonical_literal(bfd.get("return_expr", ""))
                
                if func_name == target_name and target_param in param_names:
                    returns = func.xpath(".//src:block/src:block_content/src:return", namespaces=NS)
                    match_return = False
                    
                    # 2. Validazione strutturale dell'espressione di ritorno
                    for ret in returns:
                        expr = ret.xpath("./src:expr", namespaces=NS)
                        if expr:
                            # Estraiamo solo l'espressione (es. "true" o "True") e normalizziamo
                            expr_text = adapter.canonical_literal("".join(expr[0].itertext()))
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
        
        functions = function_nodes(tree, adapter)
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

                is_target = any(call_matches(call_name,t, adapter) for t in targets)
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

            base_name = adapter.resolve_name_text(base_name, imports)

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

                if call_matches(base_name, subscript, adapter):
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
    catalog_obj = ctx.catalog
    
    _run_source_operator_usage(tree, rule, findings, adapter, imports, catalog=catalog_obj)

    return findings


def run_forbidden_functions_indexed(ctx, compiled, findings, adapter, imports):
    # Applicabilità della regola in base agli import: dipende solo da (rule, imports),
    # quindi è costante per tutta la unit. Calcolata una volta per regola, al bisogno.
    applicable = {}

    def rule_applies(rule) -> bool:
        rid = id(rule)
        res = applicable.get(rid)
        if res is None:
            res = check_required_imports(rule, imports)
            applicable[rid] = res
        return res

    for call in ctx.calls:
        call_name = get_call_name(call, adapter, imports)
        if not call_name:
            continue

        seen, candidates = set(), []
        for key in call_lookup_keys(call_name, adapter):
            for rule_obj, spec in compiled.forbidden_functions_index.get(key, []):
                k = (id(rule_obj), id(spec))
                if k not in seen:
                    seen.add(k)
                    candidates.append((rule_obj, spec))

        for rule_obj, spec in compiled.unindexed_forbidden_functions:
            k = (id(rule_obj), id(spec))
            if k not in seen:
                seen.add(k)
                candidates.append((rule_obj, spec))

        reported_rules = set()
        for rule, spec in candidates:
            if id(rule) in reported_rules:
                continue
            if not rule_applies(rule):
                continue
            if any(call_matches(call_name, e, adapter) for e in rule.get("excluded_functions", [])):
                continue

            # Prima il match della spec (economico), poi il safe_context (costoso).
            if isinstance(spec, str):
                matched = call_matches(call_name, spec, adapter)
            elif spec.get("type") == "exact_name":
                matched = call_matches(call_name, spec.get("name"), adapter)
            elif spec.get("type") == "call_matches_ast":
                matched = call_arguments_match_ast(call, spec, adapter, imports)
            else:
                matched = False

            if not matched:
                continue
            if is_in_safe_context(call, rule.get("safe_contexts", []), None, adapter, imports):
                continue

            findings.append(build_finding(rule, call))
            reported_rules.add(id(rule))
