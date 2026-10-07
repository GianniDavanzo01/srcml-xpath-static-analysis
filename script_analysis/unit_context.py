from collections import namedtuple

from common import NS, name_text, assignment_pairs, enclosing_scope, in_opaque_tag, is_dead_code

AssignInfo = namedtuple("AssignInfo", "stmt lhs rhs var scope rhs_all rhs_names rhs_interp")


def build_assign_infos(assignments, adapter, unit):
    """Calcola UNA volta lhs/rhs/scope e i contenuti dell'RHS di ogni assegnazione con LHS <name>."""
    pair_map = {stmt: (lhs, rhs) for stmt, lhs, rhs in assignment_pairs(unit, adapter)}

    infos = []
    for stmt in assignments:
        if is_dead_code(stmt, adapter):
            continue
        if stmt in pair_map:
            lhs, rhs = pair_map[stmt]
        else:  # sicurezza: statement non presente nella cache
            lhs, rhs = adapter.get_assignment_lhs_rhs(stmt, NS)
        if lhs is None or not lhs.tag.endswith("name"):
            continue

        scope = enclosing_scope(stmt, adapter)
        if scope is None:
            scope = unit

        rhs_all = rhs.xpath("self::* | following-sibling::*", namespaces=NS) if rhs is not None else []

        # [MODIFICA] Contenuti dell'RHS, indipendenti dalla regola: calcolati una volta
        # e riusati dal ciclo di propagazione (che gira per ogni regola e iterazione).
        #   rhs_names:  [(testo, nodo <name>)]
        #   rhs_interp: [(nodo letterale, [variabili interpolate])]
        rhs_names = []
        rhs_interp = []
        for rn in rhs_all:
            for n in rn.xpath("self::src:name | .//src:name", namespaces=NS):
                if in_opaque_tag(n, adapter):
                    continue
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
        "unit", "calls", "assignments", "catalog",
        "assign_infos", "assign_by_stmt",
    )

    def __init__(self, unit, adapter, catalog=None):
        self.unit = unit
        self.calls = unit.xpath(".//src:call", namespaces=NS)

        self.assignments = [stmt for stmt, _, _ in assignment_pairs(unit, adapter)]
        self.assign_infos = build_assign_infos(self.assignments, adapter, unit)
        self.assign_by_stmt = {i.stmt: i for i in self.assign_infos}

        self.catalog = catalog or {}