import json

class RuleCompiler:
    def __init__(self, catalog_path: str):
        self.catalog_path = catalog_path
        with open(catalog_path, 'r') as f:
            self.catalog = json.load(f)

    def _expand_tags(self, items_list: list, catalog_section: str) -> list:
        expanded = []
        for item in items_list:
            if isinstance(item, dict) and "tag" in item:
                tag_name = item["tag"]
                values = self.catalog.get(catalog_section, {}).get(tag_name)
                if values is None:
                    print(f"[ATTENZIONE] tag '{tag_name}' non trovato nella sezione '{catalog_section}' del catalogo {self.catalog_path}")
                    values = []
                expanded.extend(values)
            else:
                expanded.append(item)
        return expanded

    def compile(self, abstract_rule):
        if isinstance(abstract_rule, list):
            return [self.compile(r) for r in abstract_rule]

        concrete_rule = abstract_rule.copy()

        mapping = {
            "sources": "sources",
            "sinks": "sinks",
            "forbidden_functions": "forbidden_functions",
            "excluded_functions": "excluded_functions",
            "forbidden_imports": "forbidden_imports",
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
                if pattern_data is None:
                    print(f"[ATTENZIONE] tag '{tag_name}' non trovato in 'patterns' ({self.catalog_path})")
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