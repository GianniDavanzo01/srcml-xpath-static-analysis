"""
taint_engine.py
----------------
Motore Taint (Flusso Dati): individua le variabili taintate (assegnate a
partire da una source), ne segue gli usi nell'albero srcML e genera un
finding per ciascun uso che raggiunge un sink senza passare per un
safe-context o un sanitizer.

"""

import re

from common import NS, build_finding, is_sanitized, source_present, get_call_name, _pos_key, name_text, get_scope_index,  \
    extract_output_buffer_name, enclosing_scope, in_opaque_tag, macro_map, expand_macro_name, call_matches
from sink_matchers import matches_any_sink
from safe_context_matchers import is_in_safe_context


# [MODIFICA 1] helper che pre-calcola lhs/rhs/scope di ogni assegnazione
from unit_context import build_assign_infos



PSEUDO_SOURCES = {"function_parameters", "exception_variable"}

_COND_ANCESTORS = (
    "ancestor::*[self::src:if or self::src:else or self::src:while or "
    "self::src:for or self::src:do or self::src:switch or "
    "self::src:try or self::src:catch or self::src:finally]"
)

def _sanitized_reassign_reaches(uso, var, scope_node, assign_infos, tainted_names,
                                sanitizers, adapter, imports) -> bool:
    """True se l'ultima assegnazione a `var` prima di `uso`:
       - non propaga taint (ogni nome taintato nell'RHS e' sanificato),
       - contiene almeno un nome passato da un sanitizer,
       - domina l'uso (nessun if/else/ciclo/catch che racchiuda lei ma non l'uso)."""
    key = _pos_key(uso)
    prior = [i for i in assign_infos
             if i.var == var and i.scope is scope_node and _pos_key(i.stmt) < key]
    if not prior:
        return False
    last = max(prior, key=lambda i: _pos_key(i.stmt))

    saw_sanitized = False
    for text, n in last.rhs_names:
        if is_sanitized(n, sanitizers, adapter, imports):
            saw_sanitized = True
        elif text in tainted_names:
            return False          # un valore taintato arriva ancora non sanificato
    if not saw_sanitized:
        return False

    anc = set(uso.iterancestors())
    return all(c in anc for c in last.stmt.xpath(_COND_ANCESTORS, namespaces=NS))


def run_taint_rule(tree, rule: dict, adapter=None, imports=None, ctx=None) -> list:
    adapter = adapter 
    imports = imports if imports is not None else []
    macros = macro_map(imports)

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
        fn = " or ".join(f"self::src:{t}" for t in adapter.function_tags())
        xp = f".//*[{fn}]/src:parameter_list/src:parameter"
        for param in tree.xpath(xp, namespaces=NS):
            name_node = adapter.get_parameter_name_node(param, NS)
            if name_node is None:
                continue
            param_name = name_text(name_node)
            if param_name:
                scope = enclosing_scope(param, adapter)
                tainted_vars_with_scope.append(
                    (param_name, scope if scope is not None else tree)
                )
    # Variabili per descrivere le eccezioni
    if "exception_variable" in sources:
        for var_name, scope_node in adapter.find_exception_bindings(tree, NS):
            tainted_vars_with_scope.append((var_name, scope_node))

    # [MODIFICA 2] Assegnazioni: se c'e' il ctx si riusano quelle GIA' calcolate
    # per l'unit (una volta sola, condivise da tutte le regole). Altrimenti si
    # calcolano qui con lo stesso helper.
    if ctx is not None:
        assign_infos = ctx.assign_infos
        assign_by_stmt = ctx.assign_by_stmt
    else:
        assignments = [
            stmt for stmt in tree.xpath(".//src:expr_stmt | .//src:decl_stmt", namespaces=NS)
            if adapter.is_assignment(stmt, NS)
        ]
        assign_infos = build_assign_infos(assignments, adapter, tree)
        assign_by_stmt = {i.stmt: i for i in assign_infos}

    # (la vecchia funzione _scope_of e' stata eliminata: lo scope e' in info.scope)

    # ------------------------------------------------------------------ #
    # Source "per side-effect": funzioni che RIEMPIONO un argomento
    # (C: recv, read, fread, scanf, ...) invece di restituire il dato.
    # ------------------------------------------------------------------ #
    output_arg_table = adapter.taint_source_output_args()

    # Source valide per il pattern "var = func()": escludiamo quelle che
    # restituiscono solo un contatore (recv, read, scanf, ...)
    return_sources = [
    s for s in sources
    if s not in PSEUDO_SOURCES
    and (s not in output_arg_table or output_arg_table[s].get("return_tainted", False))
    ]

    source_origin_pos = {}     # (var, id(scope)) -> posizione della prima call che riempie var
    source_call_nodes = set()  # call-sorgente: gli usi al loro interno non sono usi reali

    active_output_sources = {s for s in sources if s in output_arg_table}
    if active_output_sources:
        all_calls = ctx.calls if ctx is not None else tree.xpath(".//src:call", namespaces=NS)
        for call in all_calls:
            cname = get_call_name(call, adapter, imports)
            if not cname:
                continue
            # matched = next(
            #     (s for s in active_output_sources if cname == s or cname.endswith(f".{s}")),
            #     None,
            # )
            matched = next(
                (s for s in active_output_sources if call_matches(cname, s)),
                None,
            )
            if matched is None:
                continue

            source_call_nodes.add(call)

            spec = output_arg_table[matched]
            args = call.xpath("./src:argument_list/src:argument", namespaces=NS)
            idxs = set(spec.get("indices", []))
            if "variadic_from" in spec:
                idxs.update(range(spec["variadic_from"], len(args)))

            # parent_func = call.xpath("ancestor::src:function[1]", namespaces=NS)
            # call_scope = parent_func[0] if parent_func else tree
            call_scope = enclosing_scope(call, adapter)
            if call_scope is None:
                call_scope = tree

            for i in sorted(idxs):
                if i >= len(args):
                    continue

                out_var = expand_macro_name(extract_output_buffer_name(args[i]) or "", macros) or None
                if not out_var:
                    continue

                key = (out_var, id(call_scope))
                pos = _pos_key(call)
                if key not in source_origin_pos:
                    # prima volta che vediamo questa variabile: la registriamo una sola volta
                    tainted_vars_with_scope.append((out_var, call_scope))
                    source_origin_pos[key] = pos
                elif pos < source_origin_pos[key]:
                    source_origin_pos[key] = pos

    # [MODIFICA 3] Seed: assegnazioni da source. lhs/scope sono gia' pronti.

    for info in assign_infos:
        if info.rhs is None:
            continue
        if any(
            source_present(return_sources, n, source_form, adapter=adapter, imports=imports)
            for n in info.rhs_all
        ):
            tainted_vars_with_scope.append((info.var, info.scope))

    # Passo 2: propagazione a catena
    if rule.get("propagate_taint", True):

        only_through = rule.get("propagate_only_through_calls") or []
        if rule.get("ignore_taint_block_functions", False):
            block = sanitizers
        else:
             block = sanitizers + [
        f for f in adapter.taint_block_functions() if f not in only_through]

        propagating_calls = adapter.taint_propagating_calls()

        def _blocked_by_call_allowlist(n):
            """Con allowlist attiva, un nome dentro una call propaga solo se
            tutte le call che lo racchiudono sono nell'allowlist."""
            if not only_through:
                return False
            for c in n.xpath("ancestor::src:call", namespaces=NS):
                cname = get_call_name(c, adapter, imports)
                # if not cname or not any(
                #     cname == a or cname.endswith(f".{a}") for a in only_through
                # ):
                if not cname or not any(
                    call_matches(cname, a) for a in only_through
                ):
                    return True
            return False


        changed = True
        guard = 0

        skip_source_args = not rule.get("source_call_args_propagate",adapter.source_call_args_propagate_to_return())

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
                        # if cname not in propagating_calls:
                        #     continue

                        if not cname:
                            continue
                        out_idx = next((i for k, i in propagating_calls.items() if call_matches(cname, k)), None)
                        if out_idx is None:
                            continue

                        
                        out_idx = propagating_calls[cname]
                        args = call.xpath("./src:argument_list/src:argument", namespaces=NS)
                        if out_idx >= len(args):
                            continue

                        out_var = expand_macro_name(extract_output_buffer_name(args[out_idx]) or "", macros) or None
                        if not out_var or out_var in already_tainted:
                            continue

                        source_found = False
                        for i, arg in enumerate(args):
                            if i == out_idx:
                                continue
                            for n in arg.xpath(".//src:name", namespaces=NS):
                                if in_opaque_tag(n, adapter):
                                    continue
                                n_text = expand_macro_name("".join(n.itertext()).strip(), macros)
                                if n_text in already_tainted and not is_sanitized(n, block, adapter, imports):
                                    source_found = True
                                    break
                            if source_found:
                                break

                        if source_found:
                            tainted_vars_with_scope.append((out_var, scope_node))
                            already_tainted.add(out_var)
                            changed = True

            # [MODIFICA 4] Propagazione via assegnazione: nessuna query XPath
            # per ricavare lhs/rhs/scope/rhs_all, sono gia' in `info`.
            for info in assign_infos:
                if info.rhs is None:
                    continue
                var_name = info.var
                scope_node = info.scope
                already_tainted = tainted_by_scope.get(id(scope_node), set())
                if var_name in already_tainted:
                    continue

                # info.rhs_all = primo fratello dopo l'operatore + tutti i successivi,
                # per coprire l'intera espressione (es: "SELECT..." + user_id)
                # [MODIFICA 7] nomi e stringhe interpolate dell'RHS sono pre-calcolati in
                # AssignInfo (indipendenti dalla regola): qui nessuna query XPath, solo
                # confronti con l'insieme delle variabili gia' taintate.
                propagates = False
                for n_text, n in info.rhs_names:
                    eff = expand_macro_name(n_text, macros)
                    if eff in already_tainted and not is_sanitized(n, block, adapter, imports):
                        origin = source_origin_pos.get((eff, id(scope_node)))
                        if origin is not None and _pos_key(info.stmt) < origin:
                            continue
                        if in_opaque_tag(n, adapter):
                            continue
                        if skip_source_args and source_call_nodes and any(
                            c in source_call_nodes
                            for c in n.xpath("ancestor::src:call", namespaces=NS)
                        ):
                            continue
                        if _blocked_by_call_allowlist(n):
                            continue
                        propagates = True
                        break

                if not propagates:
                    # stringhe interpolate nel RHS (query = f"...{user_id}")
                    for lit, interpolated_vars in info.rhs_interp:
                        if any(v in already_tainted for v in interpolated_vars) \
                           and not is_sanitized(lit, block, adapter, imports):
                            propagates = True
                            break

                if propagates:
                    tainted_vars_with_scope.append((var_name, scope_node))
                    tainted_by_scope.setdefault(id(scope_node), set()).add(var_name)
                    changed = True

    if not tainted_vars_with_scope:
        return findings

    # Cerca gli utilizzi SOLO all'interno dello Scope calcolato
    for var, scope_node in tainted_vars_with_scope:

        # [MODIFICA 6] indice per scope: calcolato una volta e condiviso da tutte le regole
        names_idx, interp_idx = get_scope_index(scope_node, adapter, macros)
        usi_potenziali = names_idx.get(var, [])

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

        usi_fstring = interp_idx.get(var, [])

        tutti_gli_usi = usi_diretti + usi_fstring

        for uso in tutti_gli_usi:
            if in_opaque_tag(uso, adapter):
                continue
            # uso interno a una call-sorgente (buf, sizeof(buf), ...) -> non è un uso reale
            if source_call_nodes and any(
                c in source_call_nodes
                for c in uso.xpath("ancestor::src:call", namespaces=NS)
            ):
                continue

            # uso testualmente PRIMA della call che riempie la variabile
            origin = source_origin_pos.get((var, id(scope_node)))
            if origin is not None and _pos_key(uso) < origin:
                continue

            # [MODIFICA 5] Scarta l'uso se e' proprio il nome a sinistra di
            # un'assegnazione: lookup nel dizionario invece di get_assignment_lhs_rhs.
            enclosing_stmt = uso.xpath("ancestor::src:expr_stmt[1] | ancestor::src:decl_stmt[1]", namespaces=NS)
            if enclosing_stmt:
                info = assign_by_stmt.get(enclosing_stmt[0])
                if info is not None and info.lhs is uso:
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

            if rule.get("sanitizer_kills_taint",True):
                tainted_names = {v for v, s in tainted_vars_with_scope if s is scope_node}
                if _sanitized_reassign_reaches(uso, var, scope_node, assign_infos,
                                               tainted_names, sanitizers, adapter, imports):
                    continue

            if is_sanitized(uso, sanitizers, adapter, imports):
                continue

            stmt = uso.xpath("ancestor::*[@pos:start][1]", namespaces=NS)
            nodo_snippet = stmt[0] if stmt else uso

            findings.append(build_finding(rule, nodo_snippet, extra={"tainted_variable": var}))

    return findings