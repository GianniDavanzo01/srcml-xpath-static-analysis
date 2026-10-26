from collections import namedtuple

from common import NS, name_text, assignment_pairs, enclosing_scope, in_opaque_tag, is_dead_code

AssignInfo = namedtuple("AssignInfo", "stmt lhs rhs var scope rhs_all rhs_names rhs_interp numeric_lhs")



def build_assign_infos(assignments, adapter, unit):
    """Calcola UNA volta lhs/rhs/scope e i contenuti dell'RHS di ogni assegnazione con LHS <name>."""

    infos = []
    for stmt, lhs, rhs in assignment_pairs(unit, adapter, include_bindings=True):
        if is_dead_code(stmt, adapter):
            continue
        if lhs is None or not lhs.tag.endswith("name"):
            continue
        scope = enclosing_scope(stmt, adapter)
        if scope is None:
            scope = unit
        rhs_all = rhs.xpath("self::* | following-sibling::*", namespaces=NS) if rhs is not None else []
        
        #  Contenuti dell'RHS, indipendenti dalla regola: calcolati una volta
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

        var = name_text(lhs)
        # numerico solo se il nome non ha indici: 'char buf[256]' ha tipo 'char' ma è un buffer
        numeric_lhs = (
            not lhs.xpath("./src:index", namespaces=NS)
            and adapter.is_numeric_type(adapter.resolve_variable_type(lhs, var, NS))
        )

        infos.append(AssignInfo(stmt, lhs, rhs, name_text(lhs), scope, rhs_all, rhs_names, rhs_interp, numeric_lhs))
    return infos

class UnitContext:
    __slots__ = (
        "unit", "calls", "assignments",
        "assign_infos", "assign_by_stmt","assign_lhs"
    )

    def __init__(self, unit, adapter, catalog=None):
        self.unit = unit
        self.calls = unit.xpath(".//src:call", namespaces=NS)

        self.assignments = [stmt for stmt, _, _ in assignment_pairs(unit, adapter, include_bindings=True)]
        self.assign_infos = build_assign_infos(self.assignments, adapter, unit)
        self.assign_by_stmt = {i.stmt: i for i in self.assign_infos}
        self.assign_lhs = {i.lhs for i in self.assign_infos}
