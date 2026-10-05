"""
validator_rules.py
------------------
Controlla, dopo l'espansione dei tag, che ogni "type" usato nelle regole
esista nel registro della sezione in cui compare.
"""

import sys

from safe_context_matchers import SAFE_CONTEXT_MATCHERS
from sink_matchers import SINK_MATCHERS

SIMPLE_SINKS = {"concat", "fstring", "call_arg", "method_chain",
                "reassign", "return", "any_use", "assign_rhs"}
FORBIDDEN_FN_TYPES = {"exact_name", "call_matches_ast"}

REGISTRIES = {
    "safe_contexts": set(SAFE_CONTEXT_MATCHERS),
    "sinks": set(SINK_MATCHERS) | SIMPLE_SINKS,
    "forbidden_functions": FORBIDDEN_FN_TYPES,
}


def validate_rule(rule: dict) -> list[str]:
    """Ritorna la lista di errori trovati in una regola già espansa."""
    errors = []
    rid = rule.get("rule_id", "UNKNOWN")
    for section, valid_types in REGISTRIES.items():
        for item in rule.get(section, []):
            if isinstance(item, dict):
                t = item.get("type")
                if t not in valid_types:
                    errors.append(f"{rid}/{section}: type '{t}' sconosciuto")
    return errors


def collect_errors(rules: list) -> list[str]:
    """Errori di tutte le regole, senza interrompere l'esecuzione."""
    errors = []
    for rule in rules:
        errors.extend(validate_rule(rule))
    return errors


def validate_or_exit(rules: list, lang: str = "") -> None:
    """Stampa tutti gli errori trovati e interrompe l'esecuzione."""
    errors = collect_errors(rules)
    if not errors:
        return
    prefix = f"[{lang}] " if lang else ""
    print("Regole non valide:", file=sys.stderr)
    for e in errors:
        print(f"  {prefix}{e}", file=sys.stderr)
    sys.exit(1)