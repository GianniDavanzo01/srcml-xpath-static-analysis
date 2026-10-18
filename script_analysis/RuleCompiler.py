import json

class RuleCompiler:
    def __init__(self, catalog_path: str, lang: str, known_languages):
        self.catalog_path = catalog_path
        with open(catalog_path, 'r', encoding='utf-8') as f:
            self.catalog = json.load(f)
        self.errors = []      # tag non risolti
        self.warnings = []    # tag presenti ma vuoti
        self.skipped = []                      # (rule_id, motivo)
        self.lang = lang.lower()
        self.known_languages = {l.lower() for l in known_languages}
        self._current_rule = "?"

    def _applies_to_language(self, rule: dict) -> bool:
        langs = rule.get("languages")
        if langs is None:                      # assente = tutti i linguaggi
            return True

        rid = rule.get("rule_id", "UNKNOWN")
        if (not isinstance(langs, list) or not langs
                or not all(isinstance(l, str) for l in langs)):
            self.errors.append(f"{rid}/languages: atteso una lista non vuota di stringhe")
            return False

        unknown = [l for l in langs if l.lower() not in self.known_languages]
        if unknown:
            self.errors.append(
                f"{rid}/languages: linguaggi sconosciuti {unknown} "
                f"(validi: {sorted(self.known_languages)})")
            return False

        if self.lang not in {l.lower() for l in langs}:
            self.skipped.append((rid, f"non applicabile a '{self.lang}' (languages={langs})"))
            return False
        return True

    def _expand_tags(self, items_list: list, catalog_section: str) -> list:
        expanded = []
        for item in items_list:
            if isinstance(item, dict) and "tag" in item:
                tag_name = item["tag"]
                values = self.catalog.get(catalog_section, {}).get(tag_name)
                where = f"{self._current_rule}/{catalog_section}"
                if values is None:
                    self.errors.append(
                        f"{where}: tag '{tag_name}' non trovato in '{catalog_section}'")
                    continue

                expanded.extend(values)
            else:
                expanded.append(item)
        return expanded

    def compile(self, abstract_rule):
        if isinstance(abstract_rule, list):
            compiled = (self.compile(r) for r in abstract_rule)
            return [c for c in compiled if c is not None]

        if not self._applies_to_language(abstract_rule):
            return None  
        
        concrete_rule = abstract_rule.copy()
        concrete_rule["numeric_types_sanitize"] = any(
        (s.get("tag") if isinstance(s, dict) else s) == "cast_to_integer"
        for s in abstract_rule.get("sanitizers", []))
        
        self._current_rule = abstract_rule.get("rule_id", "UNKNOWN")

        mapping = {
            "sources": "sources",
            "sinks": "sinks",
            "forbidden_functions": "forbidden_functions",
            "excluded_functions": "excluded_functions",
            "xpath_rules":"xpath_rules",
            "sanitizers": "sanitizers",
            "safe_contexts": "safe_contexts",
        }
        for rule_key, catalog_section in mapping.items():
            if rule_key in abstract_rule:
                concrete_rule[rule_key] = self._expand_tags(abstract_rule[rule_key], catalog_section)

        if "patterns" in concrete_rule:
            for item in concrete_rule.pop("patterns"):
                if not (isinstance(item, dict) and "tag" in item):
                    continue
                tag_name = item["tag"]
                pattern_data = self.catalog.get("patterns", {}).get(tag_name)
                where = f"{self._current_rule}/patterns"
                if pattern_data is None:
                    self.errors.append(f"{where}: tag '{tag_name}' non trovato in 'patterns'")
                    continue
                for engine_key, engine_values in pattern_data.items():
                    if isinstance(engine_values, list):
                        concrete_rule.setdefault(engine_key, [])
                        concrete_rule[engine_key] = concrete_rule[engine_key] + list(engine_values) 
                    elif isinstance(engine_values, dict):
                        concrete_rule.setdefault(engine_key, {})
                        concrete_rule[engine_key] = {**concrete_rule[engine_key], **engine_values}  
                    else:
                        concrete_rule[engine_key] = engine_values

        return concrete_rule