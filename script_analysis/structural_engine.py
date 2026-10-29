"""
structural_engine.py
---------------------
Motore Strutturale

Esegue le regole di tipo "structural" invocando gli handler registrati in
structural_handlers.py e applica il passo sulle funzioni vietate, che usa
l'indice costruito in fase di compilazione delle regole.
"""

from common import get_call_name, build_finding, call_arguments_match_ast, call_matches, call_lookup_keys
from safe_context_matchers import is_in_safe_context
from structural_handlers import STRUCTURAL_HANDLERS


def run_structural_rule(tree, rule: dict, adapter, imports, ctx) -> list:
    findings = []
    for key, val in rule.items():
        if val and (handler := STRUCTURAL_HANDLERS.get(key)) is not None:
            handler(tree, rule, findings, adapter, imports)
    return findings



def run_forbidden_functions_indexed(ctx, compiled, findings, adapter, imports):

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