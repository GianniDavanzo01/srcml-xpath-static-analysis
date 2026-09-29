from collections import namedtuple

from common import NS, name_text, assignment_pairs

# [MODIFICA] due campi nuovi: rhs_names e rhs_interp (vedi build_assign_infos)
AssignInfo = namedtuple("AssignInfo", "stmt lhs rhs var scope rhs_all rhs_names rhs_interp")


def build_assign_infos(assignments, adapter, unit):
    """Calcola UNA volta lhs/rhs/scope e i contenuti dell'RHS di ogni assegnazione con LHS <name>."""
    pair_map = {stmt: (lhs, rhs) for stmt, lhs, rhs in assignment_pairs(unit, adapter)}

    infos = []
    for stmt in assignments:
        if stmt in pair_map:
            lhs, rhs = pair_map[stmt]
        else:  # sicurezza: statement non presente nella cache
            lhs, rhs = adapter.get_assignment_lhs_rhs(stmt, NS)
        if lhs is None or not lhs.tag.endswith("name"):
            continue
        parent_func = stmt.xpath("ancestor::src:function[1]", namespaces=NS)
        scope = parent_func[0] if parent_func else unit
        rhs_all = rhs.xpath("self::* | following-sibling::*", namespaces=NS) if rhs is not None else []

        # [MODIFICA] Contenuti dell'RHS, indipendenti dalla regola: calcolati una volta
        # e riusati dal ciclo di propagazione (che gira per ogni regola e iterazione).
        #   rhs_names:  [(testo, nodo <name>)]
        #   rhs_interp: [(nodo letterale, [variabili interpolate])]
        rhs_names = []
        rhs_interp = []
        for rn in rhs_all:
            for n in rn.xpath("self::src:name | .//src:name", namespaces=NS):
                rhs_names.append(("".join(n.itertext()).strip(), n))
            for lit in rn.xpath(
                "self::src:literal[@type='string'] | .//src:literal[@type='string']",
                namespaces=NS,
            ):
                testo = "".join(lit.itertext())
                if adapter.is_interpolated_string(testo):
                    rhs_interp.append((lit, adapter.get_interpolated_variables(testo)))

        infos.append(AssignInfo(stmt, lhs, rhs, name_text(lhs), scope, rhs_all, rhs_names, rhs_interp))
    return infos


class UnitContext:
    __slots__ = (
        "unit", "calls", "names", "strings", "imports_nodes",
        "assignments", "conditions", "_itertext_cache", "catalog",
        "assign_infos", "assign_by_stmt",
    )

    def __init__(self, unit, adapter, catalog=None):
        self.unit = unit
        self.calls = unit.xpath(".//src:call", namespaces=NS)
        self.names = unit.xpath(".//src:name", namespaces=NS)
        self.strings = unit.xpath(".//src:literal[@type='string']", namespaces=NS)
        self.imports_nodes = unit.xpath(".//src:import", namespaces=NS)
        self.conditions = unit.xpath(".//src:if_stmt//src:condition", namespaces=NS)

        self.assignments = [stmt for stmt, _, _ in assignment_pairs(unit, adapter)]
        self.assign_infos = build_assign_infos(self.assignments, adapter, unit)
        self.assign_by_stmt = {i.stmt: i for i in self.assign_infos}

        self._itertext_cache = {}
        self.catalog = catalog or {}

    def text_of(self, node) -> str:
        key = id(node)
        cached = self._itertext_cache.get(key)
        if cached is None:
            cached = "".join(node.itertext())
            self._itertext_cache[key] = cached
        return cached