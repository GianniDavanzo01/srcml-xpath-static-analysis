"""
validator_rules.py
------------------
Controlla, dopo l'espansione dei tag, che:
1. Il campo "type" della regola sia uno dei tipi gestiti dal motore.
2. Ogni chiave di primo livello sia riconosciuta e coerente con il tipo
   della regola (una regola taint non usa chiavi strutturali e viceversa).
3. Non siano rimasti dizionari {"tag": ...} non espansi.
4. Ogni "type" (o sink semplice) usato nelle sezioni esista nel relativo registro.
5. Le sezioni che ammettono solo stringhe non contengano altro.
"""

import sys

from safe_context_matchers import SAFE_CONTEXT_MATCHERS
from sink_matchers import SINK_MATCHERS
from structural_handlers import STRUCTURAL_HANDLERS

SIMPLE_SINKS = {"concat", "fstring", "return"}
FORBIDDEN_FN_TYPES = {"exact_name", "call_matches_ast"}

REGISTRIES = {
    "safe_contexts": set(SAFE_CONTEXT_MATCHERS),
    "sinks": set(SINK_MATCHERS) | SIMPLE_SINKS,
    "forbidden_functions": FORBIDDEN_FN_TYPES,
}

RULE_TYPES = ("taint", "structural")

# Metadati, validi per qualunque tipo di regola
META_KEYS = {"rule_id", "type", "languages", "vulnerabilities", "description"}

# Chiavi usate da entrambi i motori (il passo sulle funzioni vietate
# è indipendente dal tipo della regola)
SHARED_KEYS = {"safe_contexts", "forbidden_functions", "excluded_functions"}

# Chiavi del solo motore taint
TAINT_KEYS = {
    "sources", "sinks", "sanitizers",
    "propagate_taint", "propagate_only_through_calls", "ignore_taint_block_functions",
    "clean_reassign_kills_taint", "sanitizer_kills_taint", "numeric_types_sanitize",
}

# Chiavi del solo motore strutturale: gli handler registrati più le opzioni
# accessorie che gli handler leggono
STRUCTURAL_OPTION_KEYS = {
    "sensitive_var_exclusions", "sensitive_value_min_len", "sensitive_value_placeholders",
    "skip_literal_subscript_index",
}
STRUCTURAL_KEYS = set(STRUCTURAL_HANDLERS) | STRUCTURAL_OPTION_KEYS

ALLOWED_KEYS = {
    "taint": META_KEYS | SHARED_KEYS | TAINT_KEYS,
    "structural": META_KEYS | SHARED_KEYS | STRUCTURAL_KEYS,
}

# Sezioni che dopo la compilazione devono contenere solo stringhe (niente dict)
STRING_ONLY_SECTIONS = (
    "sources", "sanitizers", "excluded_functions", "propagate_only_through_calls",
)


def _validate_keys(rule: dict, rid: str) -> list[str]:
    """Chiavi di primo livello: tipo valido, chiavi note e coerenti con il tipo."""
    errors = []
    rtype = rule.get("type")

    if rtype not in RULE_TYPES:
        errors.append(f"{rid}: type '{rtype}' non valido (validi: {list(RULE_TYPES)})")
        # senza un tipo valido non si può dire quali chiavi siano ammesse
        return errors

    allowed = ALLOWED_KEYS[rtype]
    for key in rule:
        if key in allowed:
            continue
        if key in (TAINT_KEYS | STRUCTURAL_KEYS):
            other = "structural" if rtype == "taint" else "taint"
            errors.append(
                f"{rid}: chiave '{key}' appartiene al motore {other} "
                f"e viene ignorata da una regola {rtype}"
            )
        else:
            errors.append(f"{rid}: chiave '{key}' non riconosciuta dal motore")
    return errors


def _validate_unexpanded_tags(rule: dict, rid: str) -> list[str]:
    """Intercetta {"tag": ...} rimasti in sezioni che RuleCompiler non espande."""
    errors = []
    for key, val in rule.items():
        if isinstance(val, list):
            for item in val:
                if isinstance(item, dict) and "tag" in item:
                    errors.append(
                        f"{rid}/{key}: tag '{item['tag']}' non espanso "
                        f"(sezione non supportata da RuleCompiler)"
                    )
    return errors


def _validate_types(rule: dict, rid: str) -> list[str]:
    """Ogni "type" (o sink semplice) deve esistere nel registro della sezione."""
    errors = []
    for section, valid_types in REGISTRIES.items():
        for item in rule.get(section, []):
            if isinstance(item, dict):
                if "tag" in item:
                    continue  # già segnalato da _validate_unexpanded_tags
                t = item.get("type")
                if t not in valid_types:
                    errors.append(
                        f"{rid}/{section}: type '{t}' sconosciuto (validi: {sorted(valid_types)})"
                    )
            elif isinstance(item, str):
                # in 'sinks' una stringa semplice deve essere in SIMPLE_SINKS
                if section == "sinks" and item not in SIMPLE_SINKS:
                    errors.append(
                        f"{rid}/sinks: sink semplice '{item}' sconosciuto (validi: {sorted(SIMPLE_SINKS)})"
                    )
            else:
                errors.append(f"{rid}/{section}: elemento di tipo '{type(item).__name__}' non valido")
    return errors


def _validate_string_sections(rule: dict, rid: str) -> list[str]:
    """Le sezioni che ammettono solo stringhe non devono contenere altro."""
    errors = []
    for section in STRING_ONLY_SECTIONS:
        for item in rule.get(section, []):
            if not isinstance(item, str):
                errors.append(
                    f"{rid}/{section}: atteso 'str' dopo espansione tag, trovato {item!r}"
                )
    return errors


def validate_rule(rule: dict) -> list[str]:
    """Ritorna la lista di errori trovati in una regola già espansa."""
    rid = rule.get("rule_id", "UNKNOWN")
    return (
        _validate_keys(rule, rid)
        + _validate_unexpanded_tags(rule, rid)
        + _validate_types(rule, rid)
        + _validate_string_sections(rule, rid)
    )


def collect_errors(rules: list) -> list[str]:
    """Errori di tutte le regole, senza interrompere l'esecuzione."""
    errors = []
    for rule in rules:
        errors.extend(validate_rule(rule))
    return errors


def validate_or_exit(rules: list, lang: str = "", extra_errors=None) -> None:
    """Stampa tutti gli errori trovati e interrompe l'esecuzione."""
    errors = list(extra_errors or []) + collect_errors(rules)
    if not errors:
        return
    prefix = f"[{lang}] " if lang else ""
    print("Regole non valide:", file=sys.stderr)
    for e in errors:
        print(f"  {prefix}{e}", file=sys.stderr)
    sys.exit(1)