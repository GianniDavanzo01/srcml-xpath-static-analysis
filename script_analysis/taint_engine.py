"""
taint_engine.py
----------------
Motore Taint (Flusso Dati): individua le variabili taintate (assegnate a
partire da una source), ne segue gli usi nell'albero srcML e genera un
finding per ciascun uso che raggiunge un sink senza passare per un
safe-context o un sanitizer.

"""

import re

from common import NS, build_finding, is_sanitized, source_present, get_call_name 
from sink_matchers import matches_any_sink
from safe_context_matchers import is_in_safe_context

from language_adapter import PythonAdapter



def run_taint_rule(tree, rule: dict, adapter=None, imports=None, ctx=None) -> list:
    adapter = adapter or PythonAdapter()
    imports = imports if imports is not None else []

    findings = []
    sources = rule.get("sources", [])
    source_form = rule.get("source_form")
    sanitizers = rule.get("sanitizers", [])
    safe_contexts = rule.get("safe_contexts", [])
    sinks = rule.get("sinks", [])

    if not sources or not sinks:
        return []

    tainted_vars_with_scope = []
    
    for direct_name in rule.get("direct_taint_names", []):
        tainted_vars_with_scope.append((direct_name, tree))

    # Parametri di funzione
    if "function_parameters" in sources:
        param_nodes = tree.xpath(".//src:function//src:parameter_list//src:name", namespaces=NS)
        for p_node in param_nodes:
            param_name = "".join(p_node.itertext()).strip()
            if param_name:
                parent_func = p_node.xpath("ancestor::src:function[1]", namespaces=NS)
                scope_node = parent_func[0] if parent_func else tree
                tainted_vars_with_scope.append((param_name, scope_node))

    # Variabili per descrivere le eccezioni
    if "exception_variable" in sources:
        for var_name, scope_node in adapter.find_exception_bindings(tree, NS):
            tainted_vars_with_scope.append((var_name, scope_node))


    if ctx is not None:
        assignments = ctx.assignments
    else:
        assignments = [
            stmt for stmt in tree.xpath(".//src:expr_stmt | .//src:decl_stmt", namespaces=NS)
            if adapter.is_assignment(stmt, NS)
        ]

    def _scope_of(stmt):
        parent_func = stmt.xpath("ancestor::src:function[1]", namespaces=NS)
        return parent_func[0] if parent_func else tree

    for assign in assignments:
        lhs, rhs = adapter.get_assignment_lhs_rhs(assign, NS)
        if lhs is None or not lhs.tag.endswith("name"):
            continue
        var_name = "".join(lhs.itertext()).strip()

        if rhs is not None and source_present(sources, rhs, source_form, adapter=adapter, imports=imports):

            parent_func = assign.xpath("ancestor::src:function[1]", namespaces=NS)
            scope_node = parent_func[0] if parent_func else tree

            tainted_vars_with_scope.append((var_name, scope_node))

    # Passo 2: propagazione a catena
    if rule.get("propagate_taint", True):

        if rule.get("ignore_taint_block_functions", False):
            block = sanitizers
        else:
            block = sanitizers + adapter.taint_block_functions()

        propagating_calls = adapter.taint_propagating_calls()

        changed = True
        guard = 0
        while changed and guard < 5:  # guard di sicurezza, massimo 5 iterazioni (Euristica)
            changed = False
            guard += 1

            tainted_by_scope = {}
            for name, scope in tainted_vars_with_scope:
                tainted_by_scope.setdefault(id(scope), set()).add(name)

            # Propagazione via call che scrivono su un argomento "di
            # output" invece che tramite il valore di ritorno (es. C:
            # sprintf(buf, fmt, tainted) -> buf diventa taintato)
            if propagating_calls:
                scope_nodes = {id(s): s for _, s in tainted_vars_with_scope}
                for scope_id, scope_node in scope_nodes.items():
                    already_tainted = tainted_by_scope.get(scope_id, set())
                    if not already_tainted:
                        continue
                    for call in scope_node.xpath(".//src:call", namespaces=NS):
                        cname = get_call_name(call, adapter, imports)
                        if cname not in propagating_calls:
                            continue
                        out_idx = propagating_calls[cname]
                        args = call.xpath("./src:argument_list/src:argument", namespaces=NS)
                        if out_idx >= len(args):
                            continue

                        out_names = args[out_idx].xpath(".//src:name", namespaces=NS)
                        if not out_names:
                            continue
                        out_var = "".join(out_names[0].itertext()).strip()
                        if not out_var or out_var in already_tainted:
                            continue

                        source_found = False
                        for i, arg in enumerate(args):
                            if i == out_idx:
                                continue
                            for n in arg.xpath(".//src:name", namespaces=NS):
                                n_text = "".join(n.itertext()).strip()
                                if n_text in already_tainted and not is_sanitized(n, block, adapter, imports):
                                    source_found = True
                                    break
                            if source_found:
                                break

                        if source_found:
                            tainted_vars_with_scope.append((out_var, scope_node))
                            already_tainted.add(out_var)
                            changed = True

            for assign in assignments:
                lhs, rhs = adapter.get_assignment_lhs_rhs(assign, NS)
                if lhs is None or rhs is None or not lhs.tag.endswith("name"):
                    continue
                var_name = "".join(lhs.itertext()).strip()
                scope_node = _scope_of(assign)
                already_tainted = tainted_by_scope.get(id(scope_node), set())
                if var_name in already_tainted:
                    continue

                # rhs ottenuto tramite l'adapter  è solo il PRIMO fratello dopo l'operatore di assegnazione, dobbiamo coprire tutta l'espressione
                #ES: "SELECT..." + user_id
                rhs_all_nodes = rhs.xpath("self::* | following-sibling::*", namespaces=NS)

                propagates = False
                for rn in rhs_all_nodes:
                    
                    for n in rn.xpath("self::src:name | .//src:name", namespaces=NS):
                        n_text = "".join(n.itertext()).strip()
                        if n_text in already_tainted and not is_sanitized(n, block, adapter, imports):
                            propagates = True
                            break
                    if propagates:
                        break

                    # stringhe interpolate nel RHS (query = f"...{user_id}")
                    for lit in rn.xpath(
                        "self::src:literal[@type='string'] | .//src:literal[@type='string']",
                        namespaces=NS,
                    ):
                        testo = "".join(lit.itertext())
                        if adapter.is_interpolated_string(testo):
                            interpolated_vars = adapter.get_interpolated_variables(testo)
                            if any(v in already_tainted for v in interpolated_vars) \
                               and not is_sanitized(lit, block, adapter, imports):
                                propagates = True
                                break
                    if propagates:
                        break

                if propagates:
                    tainted_vars_with_scope.append((var_name, scope_node))
                    tainted_by_scope.setdefault(id(scope_node), set()).add(var_name)
                    changed = True

    if not tainted_vars_with_scope:
        return findings

    # Cerca gli utilizzi SOLO all'interno dello Scope calcolato
    for var, scope_node in tainted_vars_with_scope:

        usi_potenziali = scope_node.xpath(".//src:name[text()=$v]", namespaces=NS, v=var)
        
        usi_diretti = []
        for uso in usi_potenziali:
            
            # Scartiamo il nodo se è il nome sinistro di un keyword argument (kwarg)
            parent_arg = uso.xpath("parent::src:argument", namespaces=NS)
            if parent_arg and adapter.is_kwarg(parent_arg[0], NS):
                
                # Verifichiamo se 'uso' è la CHIAVE (il primo nome) o il VALORE
                name_node = parent_arg[0].xpath("./src:name[1]", namespaces=NS)
                if name_node and name_node[0] is uso:
                    continue
                    
            usi_diretti.append(uso)
        
        fstrings_in_scope = scope_node.xpath(".//src:literal[@type='string']", namespaces=NS)

        usi_fstring = []
        for fs in fstrings_in_scope:
            testo = "".join(fs.itertext())
            if adapter and adapter.is_interpolated_string(testo):
                if var in adapter.get_interpolated_variables(testo):
                    usi_fstring.append(fs)

        tutti_gli_usi = usi_diretti + usi_fstring

        for uso in tutti_gli_usi:
        
            enclosing_stmt = uso.xpath("ancestor::src:expr_stmt[1] | ancestor::src:decl_stmt[1]", namespaces=NS)
            if enclosing_stmt and adapter.is_assignment(enclosing_stmt[0], NS):
                lhs, _ = adapter.get_assignment_lhs_rhs(enclosing_stmt[0], NS)
                if lhs is not None and lhs is uso:
                    continue

            # Filtri per ignorare dichiarazioni e definizioni (Evita FP sulle firme delle funzioni)
            if uso.xpath("ancestor::src:parameter", namespaces=NS):
                continue
            if uso.xpath("parent::src:function", namespaces=NS):
                continue
            if uso.xpath("parent::src:class", namespaces=NS):
                continue

            # Verifica vulnerabilità (Sink, Mitigazioni, Sanitizzazioni)
            if not matches_any_sink(uso, sinks, usi_fstring, adapter, imports):
                continue

            if is_in_safe_context(uso, safe_contexts, var, adapter, imports):
                continue

            if is_sanitized(uso, sanitizers, adapter, imports):
                continue

            stmt = uso.xpath("ancestor::*[@pos:start][1]", namespaces=NS)
            nodo_snippet = stmt[0] if stmt else uso

            findings.append(build_finding(rule, nodo_snippet, extra={"tainted_variable": var}))


    return findings