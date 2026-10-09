"""
taint_engine.py
----------------
Motore Taint (Flusso Dati): individua le variabili taintate (assegnate a
partire da una source), ne segue gli usi nell'albero srcML e genera un
finding per ciascun uso che raggiunge un sink senza passare per un
safe-context o un sanitizer.

"""

from common import NS, build_finding, is_sanitized, source_present, get_call_name, _pos_key, name_text, get_scope_index,  \
    enclosing_scope, in_opaque_tag, macro_map, expand_macro_name, call_matches, is_dead_code, CallTable, _is_pure_literal_expr
from sink_matchers import matches_any_sink
from safe_context_matchers import is_in_safe_context


from lxml import etree

_X = lambda s: etree.XPath(s, namespaces=NS)
_X_PARENT_ARG = _X("parent::src:argument")
_X_FIRST_NAME = _X("./src:name[1]")
_X_ANC_CALL   = _X("ancestor::src:call")
_X_ENCL_STMT  = _X("ancestor::src:expr_stmt[1] | ancestor::src:decl_stmt[1]")
_X_ANC_PARAM  = _X("ancestor::src:parameter")
_X_POS_ANC    = _X("ancestor::*[@pos:start][1]")
_X_ARGS       = _X("./src:argument_list/src:argument")
_X_NAMES      = _X(".//src:name")
_X_CALLS      = _X(".//src:call")

_DECL_NAME_XP = {}
def _decl_name_xp(adapter):
    x = _DECL_NAME_XP.get(adapter.name)
    if x is None:
        tags = adapter.function_tags() + adapter.class_tags()
        x = _DECL_NAME_XP[adapter.name] = _X("parent::*[" + " or ".join(f"self::src:{t}" for t in tags) + "]")
    return x



PSEUDO_SOURCES = {"function_parameters", "exception_variable","null_literal", "string_literal"}

_RULE_PRE = {}   # (id(rule), adapter.name) -> (rule, return_sources, active, spec_by_source)

def _rule_pre(rule, sources, adapter):
    key = (id(rule), adapter.name)
    ent = _RULE_PRE.get(key)
    if ent is None:
        table = adapter.taint_source_output_args()
        return_sources = [
            s for s in sources
            if s not in PSEUDO_SOURCES
            and not any(
                call_matches(k, s, adapter) and not table[k].get("return_tainted", False)
                for k in table
            )
        ]
        active = {
            s for s in sources
            if s not in PSEUDO_SOURCES
            and any(call_matches(k, s, adapter) for k in table)
        }
        spec_by_source = CallTable(
            {s: next(table[k] for k in table if call_matches(k, s, adapter)) for s in active},
            adapter,
        )
        ent = _RULE_PRE[key] = (rule, return_sources, active, spec_by_source)
    return ent[1], ent[2], ent[3]


_PROP_TABLES = {}
def _prop_table(adapter):
    t = _PROP_TABLES.get(adapter.name)
    if t is None:
        t = _PROP_TABLES[adapter.name] = CallTable(adapter.taint_propagating_calls(), adapter)
    return t

_COND_ANCESTORS = (
    "ancestor::*[self::src:if or self::src:else or self::src:while or "
    "self::src:for or self::src:do or self::src:switch or "
    "self::src:try or self::src:catch or self::src:finally]"
)
_X_COND_ANC = _X(_COND_ANCESTORS)

def _is_hardcoded_string(rhs, adapter) -> bool:
    if not _is_pure_literal_expr(rhs):
        return False
    lits = rhs.xpath("self::src:literal[@type='string'] | .//src:literal[@type='string']",
                     namespaces=NS)
    return any(not adapter.is_interpolated_string("".join(l.itertext())) for l in lits)


def _killed_by_reassign(uso, var, scope_node, assign_infos, is_killing) -> bool:
    """True se l'ultima assegnazione a `var` prima di `uso`:
       - soddisfa `is_killing` (non propaga più il taint),
       - domina l'uso (nessun if/else/ciclo/catch che racchiuda lei ma non l'uso)."""
    key = _pos_key(uso)
    prior = [i for i in assign_infos
             if i.var == var and i.scope is scope_node and _pos_key(i.stmt) < key]
    if not prior:
        return False
    last = max(prior, key=lambda i: _pos_key(i.stmt))
    if last.rhs is None or not is_killing(last):
        return False
    anc = set(uso.iterancestors())
    return all(c in anc for c in _X_COND_ANC(last.stmt))


def _rhs_fully_sanitized(info, tainted_names, sanitizers, adapter, imports) -> bool:
    """Criterio 'sanitizer': l'RHS contiene almeno un nome sanificato
    e nessun nome taintato ancora non sanificato."""
    saw_sanitized = False
    for text, n in info.rhs_names:
        if is_sanitized(n, sanitizers, adapter, imports):
            saw_sanitized = True
        elif text in tainted_names:
            return False
    return saw_sanitized


def run_taint_rule(tree, rule: dict, adapter, imports, ctx) -> list:
    macros = macro_map(imports)

    findings = []
    sources = rule.get("sources", [])
    sanitizers = rule.get("sanitizers", [])
    safe_contexts = rule.get("safe_contexts", [])
    sinks = rule.get("sinks", [])

    if not sources or not sinks:
        return []

    tainted_vars_with_scope = []

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

    # Assegnazioni si riusano quelle GIA' calcolate

    assign_infos = ctx.assign_infos
    assign_by_stmt = ctx.assign_by_stmt


    # ------------------------------------------------------------------ #
    # Source "per side-effect": funzioni che RIEMPIONO un argomento
    # (C: recv, read, fread, scanf, ...) invece di restituire il dato.
    # ------------------------------------------------------------------ #
    return_sources, active_output_sources, out_spec_table = _rule_pre(rule, sources, adapter)

    source_origin_pos = {}     # (var, id(scope)) -> posizione della prima call che riempie var
    source_call_nodes = set()  # call-sorgente: gli usi al loro interno non sono usi reali



    if active_output_sources:
        
        for call in ctx.calls:
            cname = get_call_name(call, adapter, imports)
            if not cname:
                continue

            spec = out_spec_table.get(cname)
            if spec is None:
                continue

            source_call_nodes.add(call)


            args = _X_ARGS(call)
            idxs = set(spec.get("indices", []))
            if "variadic_from" in spec:
                idxs.update(range(spec["variadic_from"], len(args)))


            call_scope = enclosing_scope(call, adapter)
            if call_scope is None:
                call_scope = tree

            for i in sorted(idxs):
                if i >= len(args):
                    continue

                out_var = expand_macro_name(adapter.extract_output_buffer_name(args[i], NS) or "", macros) or None
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

    # Seed: assegnazioni da source. lhs/scope sono gia' pronti.
    null_seed = "null_literal" in sources
    literal_seed = "string_literal" in sources

    for info in assign_infos:
        if info.rhs is None:
            continue
        if null_seed and adapter.is_none_literal("".join(info.rhs.itertext())):
            tainted_vars_with_scope.append((info.var, info.scope))
            continue
        if literal_seed and _is_hardcoded_string(info.rhs, adapter):
            tainted_vars_with_scope.append((info.var, info.scope))
            continue
        if any(
            source_present(return_sources, n, adapter=adapter, imports=imports)
            for n in info.rhs_all
        ):
            tainted_vars_with_scope.append((info.var, info.scope))

    if not tainted_vars_with_scope:
        return findings
    
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
            for c in _X_ANC_CALL(n):
                cname = get_call_name(c, adapter, imports)

                if not cname or not any(
                    call_matches(cname, a, adapter) for a in only_through
                ):
                    return True
            return False


        changed = True
        guard = 0

        skip_source_args = not adapter.source_call_args_propagate_to_return()

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
                    for call in _X_CALLS(scope_node):
                        cname = get_call_name(call, adapter, imports)
                        if not cname:
                            continue
                        spec = _prop_table(adapter).get(cname)
                        if spec is None:
                            continue
                        if isinstance(spec, int):                     # retrocompatibile
                            spec = {"out": [spec]}

                        args = _X_ARGS(call)
                        out_idxs = set(spec.get("out", []))
                        if "out_variadic_from" in spec:
                            out_idxs.update(range(spec["out_variadic_from"], len(args)))
                        in_idxs = spec.get("in")                      # None = tutti gli altri argomenti

                        source_found = False
                        for i, arg in enumerate(args):
                            if i in out_idxs or (in_idxs is not None and i not in in_idxs):
                                continue
                            for n in _X_NAMES(arg):
                                if in_opaque_tag(n, adapter):
                                    continue
                                n_text = expand_macro_name("".join(n.itertext()).strip(), macros)
                                if n_text in already_tainted and not is_sanitized(n, block, adapter, imports):
                                    source_found = True
                                    break
                            if source_found:
                                break
                        if not source_found:
                            continue

                        for out_idx in sorted(out_idxs):
                            if out_idx >= len(args):
                                continue
                            out_var = expand_macro_name(
                                adapter.extract_output_buffer_name(args[out_idx], NS) or "", macros) or None
                            if out_var and out_var not in already_tainted:
                                tainted_vars_with_scope.append((out_var, scope_node))
                                already_tainted.add(out_var)
                                changed = True

            # Propagazione via assegnazione: nessuna query XPath
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

                # nomi e stringhe interpolate dell'RHS sono pre-calcolati in
                # AssignInfo (indipendenti dalla regola): qui nessuna query XPath, solo
                # confronti con l'insieme delle variabili gia' taintate.
                propagates = False
                for n_text, n in info.rhs_names:
                    eff = expand_macro_name(n_text, macros)
                    if eff in already_tainted and not is_sanitized(n, block, adapter, imports):
                        origin = source_origin_pos.get((eff, id(scope_node)))
                        if origin is not None and _pos_key(info.stmt) < origin:
                            continue
                        if skip_source_args and source_call_nodes and any(
                            c in source_call_nodes
                            for c in _X_ANC_CALL(n)
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

    # Deduplica (variabile, scope) mantenendo l'ordine di inserimento
    _seen = set()
    _unique = []
    for _var, _scope in tainted_vars_with_scope:
        _k = (_var, id(_scope))
        if _k not in _seen:
            _seen.add(_k)
            _unique.append((_var, _scope))
    tainted_vars_with_scope = _unique

    def _null_kill(i):
        """Kill-by-reassign per null. (x = new Foo() blocca il taint; x = map.get(k) no, perché può restituire null)"""
        return (not adapter.is_none_literal("".join(i.rhs.itertext()))
                and not any(source_present(return_sources, n, adapter=adapter, imports=imports)
                            for n in i.rhs_all))

    def _literal_kill(i):
        """Kill-by-reassign per letterali hardcoded. (pwd = os.environ["P"] blocca il taint; pwd = "abc" no)."""
        return not _is_hardcoded_string(i.rhs, adapter)

    tainted_names_by_scope = {}
    for _v, _s in tainted_vars_with_scope:
        tainted_names_by_scope.setdefault(id(_s), set()).add(_v)

    def _sanitizer_kill(i):
        """"Kill-by-reassign per sanificazione. (x = int(x) blocca il taint; x = int(a) + b no)"""
        return _rhs_fully_sanitized(
            i, tainted_names_by_scope.get(id(i.scope), set()),
            sanitizers, adapter, imports)

    # Criteri di "kill by reassign" attivi per QUESTA regola, decisi una volta sola.
    # Tutti guardano la stessa "ultima assegnazione che domina l'uso": basta un solo
    killers = []
    if rule.get("null_reassign_kills_taint", False):
        killers.append(_null_kill)
    if rule.get("literal_reassign_kills_taint", False):
        killers.append(_literal_kill)
    if rule.get("sanitizer_kills_taint", True):      # default ON, disattivabile nella regola
        killers.append(_sanitizer_kill)
    kill_any = (lambda i: any(k(i) for k in killers)) if killers else None

    # Cerca gli utilizzi SOLO all'interno dello Scope calcolato
    for var, scope_node in tainted_vars_with_scope:

        #indice per scope: calcolato una volta e condiviso da tutte le regole
        names_idx, interp_idx = get_scope_index(scope_node, adapter, macros)
        usi_potenziali = names_idx.get(var, [])

        usi_diretti = []
        for uso in usi_potenziali:

            # Scartiamo il nodo se è il nome sinistro di un keyword argument (kwarg)
            parent_arg = _X_PARENT_ARG(uso)
            if parent_arg and adapter.is_kwarg(parent_arg[0], NS):

                # Verifichiamo se 'uso' è la CHIAVE (il primo nome) o il VALORE
                name_node = _X_FIRST_NAME(parent_arg[0])
                if name_node and name_node[0] is uso:
                    continue

            usi_diretti.append(uso)

        usi_fstring = interp_idx.get(var, [])

        tutti_gli_usi = usi_diretti + usi_fstring

        for uso in tutti_gli_usi:
            if in_opaque_tag(uso, adapter):
                continue

            if is_dead_code(uso, adapter):
                continue
            # uso interno a una call-sorgente (buf, sizeof(buf), ...) -> non è un uso reale
            if source_call_nodes and any(
                c in source_call_nodes
                for c in _X_ANC_CALL(uso)
            ):
                continue

            # uso testualmente PRIMA della call che riempie la variabile
            origin = source_origin_pos.get((var, id(scope_node)))
            if origin is not None and _pos_key(uso) < origin:
                continue

            # Scarta l'uso se e' proprio il nome a sinistra di
            # un'assegnazione: lookup nel dizionario invece di get_assignment_lhs_rhs.
            enclosing_stmt = _X_ENCL_STMT(uso)
            if enclosing_stmt:
                info = assign_by_stmt.get(enclosing_stmt[0])
                if info is not None and info.lhs is uso:
                    continue

            # Filtri per ignorare dichiarazioni e definizioni (Evita FP sulle firme delle funzioni)
            if _X_ANC_PARAM(uso):
                continue
            if _decl_name_xp(adapter)(uso):
                continue

            # Verifica vulnerabilità (Sink, Mitigazioni, Sanitizzazioni)
            if not matches_any_sink(uso, sinks, usi_fstring, adapter, imports):
                continue

            if is_in_safe_context(uso, safe_contexts, var, adapter, imports):
                continue

            if kill_any is not None and _killed_by_reassign(
                    uso, var, scope_node, assign_infos, kill_any):
                continue

            if is_sanitized(uso, sanitizers, adapter, imports):
                continue

            stmt = _X_POS_ANC(uso)
            nodo_snippet = stmt[0] if stmt else uso

            findings.append(build_finding(rule, nodo_snippet, extra={"tainted_variable": var}))

    return findings