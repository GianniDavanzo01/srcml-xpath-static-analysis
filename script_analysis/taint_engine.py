"""
taint_engine.py
----------------
Motore Taint (Flusso Dati): individua le variabili taintate (assegnate a
partire da una source), ne segue gli usi nell'albero srcML e genera un
finding per ciascun uso che raggiunge un sink senza passare per un
safe-context o un sanitizer.

"""

import re

from common import NS, build_finding, is_sanitized, source_present, source_arg_is_traceable_literal, get_call_name
from sink_matchers import matches_any_sink
from safe_context_matchers import is_in_safe_context

from language_adapter import PythonAdapter


# def run_taint_rule(tree, rule: dict) -> list:
# def run_taint_rule(tree, rule: dict, adapter=None, imports=None) -> list:
def run_taint_rule(tree, rule: dict, adapter=None, imports=None, ctx=None) -> list:
    adapter = adapter or PythonAdapter()
    imports = imports if imports is not None else []

    findings = []
    sources = rule.get("sources", [])
    source_form = rule.get("source_form")
    sanitizers = rule.get("sanitizers", [])
    safe_contexts = rule.get("safe_contexts", [])
    sinks = rule.get("sinks", [])

    tainted_vars_with_scope = []
    
    for direct_name in rule.get("direct_taint_names", []):
        tainted_vars_with_scope.append((direct_name, tree))

    # (Parametri di funzione) AGGIUNTA DALLA REGOLA 24 DEL RULESET V1 ---
    if "function_parameters" in sources:
        param_nodes = tree.xpath(".//src:function//src:parameter_list//src:name", namespaces=NS)
        for p_node in param_nodes:
            param_name = "".join(p_node.itertext()).strip()
            if param_name:
                parent_func = p_node.xpath("ancestor::src:function[1]", namespaces=NS)
                scope_node = parent_func[0] if parent_func else tree
                tainted_vars_with_scope.append((param_name, scope_node))
    # ---------------------------------------------------------


    if ctx is not None:
        assignments = ctx.assignments
    else:
        assignments = [
            stmt for stmt in tree.xpath(".//src:expr_stmt | .//src:decl_stmt", namespaces=NS)
            if adapter.is_assignment(stmt, NS)
        ]

    for assign in assignments:
        lhs, _ = adapter.get_assignment_lhs_rhs(assign, NS)
        if lhs is None or not lhs.tag.endswith("name"):
            continue
        var_name = "".join(lhs.itertext()).strip()
        assign_text = "".join(assign.itertext())
        if source_present(sources, assign_text, source_form):

            parent_func = assign.xpath("ancestor::src:function[1]", namespaces=NS)
            scope_node = parent_func[0] if parent_func else tree

            if rule.get("require_non_literal_source_arg"):
                source_call = None
                for c in assign.xpath(".//src:call", namespaces=NS):
                    # cname = get_call_name(c)
                    cname = get_call_name(c, adapter, imports)
                    if cname and any(cname == s or cname.endswith(f".{s}") for s in sources):
                        source_call = c
                        break

                # if source_call is not None and source_arg_is_traceable_literal(source_call, scope_node):
                if source_call is not None and source_arg_is_traceable_literal(source_call, scope_node, adapter=adapter):
                    continue  # se l'argomento è letterale -> non taintare

            tainted_vars_with_scope.append((var_name, scope_node))

    if not tainted_vars_with_scope:
        return findings

    # Cerca gli utilizzi SOLO all'interno dello Scope calcolato
    for var, scope_node in tainted_vars_with_scope:
        
        try:
            if "'" in var:
                xpath_query = (
                    f'.//src:name[.="{var}" and not('
                    f'parent::src:argument'
                    f' and parent::src:argument/src:name[1]=self::node()'
                    f' and following-sibling::text()[1][contains(., "=")]'
                    f')]'
                )
            else:
                xpath_query = (
                    f".//src:name[.='{var}' and not("
                    f"parent::src:argument"
                    f" and parent::src:argument/src:name[1]=self::node()"
                    f" and following-sibling::text()[1][contains(., '=')]"
                    f")]"
                )
            
            usi_diretti = scope_node.xpath(xpath_query, namespaces=NS)

        except Exception as e:
            print("\n--- [DEBUG XPATH CRASH DETECTED] ---")
            print(f"Rule ID      : {rule.get('rule_id')}")
            print(f"Valore di var: {repr(var)}")
            print(f"XPath Fallito: .//src:name[text()='{var}' and not(...)]")
        
        fstrings_in_scope = scope_node.xpath(".//src:literal[@type='string']", namespaces=NS)
        # usi_fstring = [
        #     fs for fs in fstrings_in_scope
        #     if re.search(rf"\{{\s*{re.escape(var)}\s*[!:]?.*?\}}", "".join(fs.itertext()))
        # ]
        usi_fstring = []
        for fs in fstrings_in_scope:
            testo = "".join(fs.itertext())
            if adapter and adapter.is_interpolated_string(testo):
                if var in adapter.get_interpolated_variables(testo):
                    usi_fstring.append(fs)

        tutti_gli_usi = usi_diretti + usi_fstring

        for uso in tutti_gli_usi:
        
            # parent_assign = uso.xpath(
            #     "ancestor::src:expr_stmt[src:expr[src:operator[text()='=']]]/src:expr/src:name[1]",
            #     namespaces=NS,
            # )
            # if parent_assign and parent_assign[0] == uso:
            #     continue
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
            # if not matches_any_sink(uso, sinks, usi_fstring):
            if not matches_any_sink(uso, sinks, usi_fstring, adapter, imports):
                continue

            if is_in_safe_context(uso, safe_contexts, var, adapter, imports):
                continue

            # if is_sanitized(uso, sanitizers):
            if is_sanitized(uso, sanitizers, adapter, imports):
                continue

            stmt = uso.xpath("ancestor::*[@pos:start][1]", namespaces=NS)
            nodo_snippet = stmt[0] if stmt else uso

            findings.append(build_finding(rule, nodo_snippet, extra={"tainted_variable": var}))

    return findings