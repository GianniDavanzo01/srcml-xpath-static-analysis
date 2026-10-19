"""
language_adapter.py
--------------------

Il motore generico (taint_engine.py, structural_engine.py,
safe_context_matchers.py, sink_matchers.py) NON deve più contenere stringhe
hardcoded per un linguaggio, ma Deve invece interrogare un LanguageAdapter:

    adapter.is_assignment(node)
    adapter.resolve_call_name(call_node, imports)
    adapter.is_interpolated_string(text)
    ...

Aggiungere un linguaggio (Java, C#, ...) significa scrivere una nuova classe
che implementa LanguageAdapter. In modo da lasciare il motore sempre uguale
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass

from lxml import etree

from common import macro_map, expand_macro_name, _pos_key, find_assignments, enclosing_scope, name_text, get_decl_index, get_class_field_index


_MACRO_ALIAS_RE = re.compile(r"^\s*\(?\s*([A-Za-z_]\w*)\s*\)?\s*$")  # #define FOPEN fopen
_MACRO_FWD_RE   = re.compile(r"^\s*([A-Za-z_]\w*)\s*\(")             # #define F(p) fopen(p,"r")


@dataclass
class ImportBinding:
    """Rappresenta un binding di import risolto a un nome canonico.

    Esempio Python:  'import os as sys'      -> local_name='sys',  canonical_name='os'
    Esempio Python:  'from os import system as run' -> local_name='run', canonical_name='os.system'
    """
    local_name: str
    canonical_name: str
    node: etree._Element = None
    is_macro: bool = False 

class LanguageAdapter(ABC):

    name: str  # "python", "java", ...

    @abstractmethod
    def potential_assignment_xpath(self) -> str:
        """Potenziale statement di assegnazione"""
    
    @abstractmethod
    def is_assignment(self, node, ns) -> bool:
        """True se `node` (tipicamente <src:expr_stmt> o <src:expr>) è
        un'assegnazione semplice (LHS = RHS)."""

    @abstractmethod
    def get_assignment_lhs_rhs(self, node, ns) -> tuple:
        """Ritorna (lhs_node, rhs_first_node) o (None, None). """

    @abstractmethod
    def is_kwarg(self, argument_node, ns) -> bool:
        """True se l'argomento usa la sintassi nome=valore. In Java/C non
        esiste: l'adapter per quei linguaggi ritorna sempre False."""

    @abstractmethod
    def string_concat_operators(self) -> list:
        """Operatori che contano come concatenazione/formattazione stringhe.
        Python: ['+', '%']. Java/C#: ['+']."""

    @abstractmethod
    def is_interpolated_string(self, literal_text: str) -> bool:
        """f-string Python, template string JS, text block Java, ecc."""

    @abstractmethod
    def is_none_literal(self, text: str) -> bool:
        """'None' in Python, 'null' in Java/C#/JS."""

    @abstractmethod
    def parse_numeric_literal(self, text: str):
        """Gestisce le notazioni numeriche language-specific (0o755 ottale
        Python, 0x.. esadecimale, underscore come separatori, ecc). Ritorna
        un int o None se non interpretabile."""

    @abstractmethod
    def normalize_string_literal(self, text: str) -> str:
        """Normalizza apici/prefissi (f/r/b in Python) per confronti safe."""


    @abstractmethod
    def resolve_imports(self, unit_node, ns) -> list:
        """Analizza tutte le direttive di import del file e ritorna una
        lista di ImportBinding, gestendo alias (import x as y), import
        parziali (from x import y), wildcard, ecc."""

    @abstractmethod
    def resolve_call_name(self, call_node, ns, imports: list) -> str:
        """Ritorna il nome CANONICO e completo della funzione invocata,
        risolvendo gli import. Es: con `import os as sys`, la chiamata
        `sys.system(...)` deve risolvere a 'os.system', non a 'sys.system'.
        Se non risolvibile, fallback sul nome letterale (comportamento
        attuale di get_call_name in common.py)."""


    @abstractmethod
    def get_interpolated_variables(self, literal_text: str) -> list[str]:
        """Estrae l'elenco dei nomi di variabili usate dentro una stringa interpolata."""

    @abstractmethod
    def string_formatting_operator_roles(self) -> dict:
        """Mappa RUOLO SEMANTICO -> operatore, per i costrutti che il motore
        deve distinguere esplicitamente (concatenazione vs formattazione
        printf-style). Un linguaggio che non ha un certo ruolo (es. Java non ha
        l'equivalente di '%' per le stringhe) semplicemente non lo include nel
        dict, e la regola corrispondente resta inattiva senza bisogno di
        toccare il motore."""

    @abstractmethod
    def negation_operator(self) -> str:
        """Operatore di negazione booleana. Python: 'not' (parola chiave,
        separata da spazio dall'operando). C/Java/C#: '!' (prefisso, attaccato)."""

    @abstractmethod
    def is_boolean_literal(self, text: str) -> bool:
        """Scrittura dei letterali booleani del relativo linguaggio"""

    @abstractmethod
    def reference_comparison_operators(self) -> list:
        """Operatori di confronto per identità/riferimento. Python: ['is', 'is not'].
        Java/C/C#: l'identità si confronta con '=='."""


    @abstractmethod
    def assignment_operator_token(self) -> str:
        """Il token letterale dell'operatore di assegnazione semplice, per i
        pochi punti del motore che devono costruirlo dentro una query XPath
        dinamica invece di passare da is_assignment/get_assignment_lhs_rhs
        (es. pattern kwarg-like 'nome = valore' senza uno statement completo
        a disposizione). Python: '='."""

    @abstractmethod
    def equality_operator(self) -> str:
        """Operatore testuale usato per il confronto di uguaglianza (es. '==')."""

    @abstractmethod
    def logical_and_operator(self) -> list:
        """Operatori logici AND. Python: ['and']. C/Java: ['&&']."""

    @abstractmethod
    def logical_or_operator(self) -> list:
        """Operatori logici OR. Python: ['or']. C/Java: ['||']."""

    @abstractmethod
    def get_parameter_name_and_type(self, param_node, namespaces):
            """Estrae nome e tipo da un parametro (<src:parameter>)."""

    @abstractmethod
    def member_access_operator(self) -> list:
        """Operatore usato per accedere a metodi e attributi.
        Python/Java/C#: '.'  -  PHP: '->'"""


    @abstractmethod
    def taint_block_functions(self) -> list:
        """Nomi di funzioni/metodi built-in del linguaggio il cui valore di
        ritorno non può più contenere il contenuto originale di una stringa
        taintata (es. len, hash, bool in Python restituiscono un tipo
        completamente diverso dall'input). Un argomento taintato passato a
        una di queste NON propaga il taint attraverso quella chiamata."""

    @abstractmethod
    def taint_propagating_calls(self) -> dict:
        """Mappa nome_funzione -> indice dell'argomento di OUTPUT (scritto per
        side-effect, non tramite valore di ritorno). Se un qualsiasi altro
        argomento della call e' taintato, l'argomento a quell'indice diventa
        taintato a sua volta. Es. C: sprintf(buf, fmt, tainted) -> buf
        (indice 0) diventa taintato. Linguaggi senza questo pattern (Python,
        Java) ritornano un dict vuoto."""


    @abstractmethod
    def extract_membership_relations(self, condition_node, ns) -> list[dict]:
        """Estrae i nodi LHS, RHS e lo stato di negazione per le condizioni di appartenenza 
        (es. 'x in y' in Python, 'y.contains(x)' in Java).
        Ritorna una lista di dict: [{"lhs": node, "rhs": node, "is_negated": bool}]"""

    @abstractmethod
    def is_collection_assignment(self, assignment_node, ns) -> bool:
        """True se il lato destro dell'assegnazione inizializza una collezione
        nativa (lista, array, dizionario, set).
        Python: [1,2,3], {1,2,3}. Java/C: {1,2,3}."""

    @abstractmethod
    def find_exception_bindings(self, tree, ns) -> list:
        """Ritorna una lista di tuple (nome_variabile, scope_node) - una per
        ogni blocco except/catch che lega l'eccezione catturata a un nome.
        Lo scope_node e' il blocco di codice del catch, cosi' la variabile
        viene considerata taintata SOLO li' dentro, non in tutta la funzione."""


    @abstractmethod
    def resolve_variable_type(self, name_node, var_name, ns) -> str | None:
        """Cerca la dichiarazione (locale o parametro) di var_name nello scope
        di name_node e ritorna il tipo dichiarato (es. 'char *'), o None se non
        trovato."""


    @abstractmethod
    def null_comparison_operators(self) -> dict:
        """
        Restituisce gli operatori usati per i confronti col null divisi per semantica.
        - 'falsy': verificano che la variabile SIA nulla (es. ==, is)
        - 'truthy': verificano che la variabile NON SIA nulla (es. !=, is not)
        """


    @abstractmethod
    def taint_source_output_args(self) -> dict:
        """Mappa nome_funzione -> spec degli argomenti che la funzione RIEMPIE con
        dati esterni (source per side-effect, non per valore di ritorno).
        spec = {
            "indices": [int, ...],       # argomenti di output fissi
            "variadic_from": int,        # (opz.) tutti gli argomenti da questo indice in poi
            "return_tainted": bool,      # (opz., default False) il valore di ritorno e' anch'esso source
        }
        Linguaggi senza questo pattern ritornano {}."""


    @abstractmethod
    def get_parameter_name_node(self, param_node, ns):
        """Nodo <name> dell'identificatore del parametro, o None."""

    @abstractmethod
    def function_tags(self) -> list:
        """Tag srcML che definiscono uno scope di funzione (es. ['function'])."""

    @abstractmethod
    def lambda_tags(self) -> list:
        """Tag srcML delle funzioni anonime: confine di flusso, non scope di taint."""

    @abstractmethod
    def flow_exit_tags(self) -> list:
        """Tag srcML che interrompono il flusso (return, throw, ...)."""

    @abstractmethod
    def flow_exit_calls(self) -> list:
        """Nomi di chiamate che terminano il flusso (exit, abort, ...)."""

    @abstractmethod
    def noop_statement_tags(self) -> list:
        """Tag srcML di statement che non hanno effetto (es. 'pass' in Python)."""

    @abstractmethod
    def class_tags(self) -> list:
        """Tag srcML che definiscono un tipo/classe (es. ['class']). Lista vuota se il
        linguaggio non ha classi (C)."""


    def scope_axis(self, extra=()) -> str:
        """Asse XPath verso la funzione/costruttore che racchiude il nodo,
        con eventuali tag di ripiego (es. 'class', 'unit')."""
        tags = list(self.function_tags()) + list(extra)
        return "ancestor::*[" + " or ".join(f"self::src:{t}" for t in tags) + "][1]"

    def source_call_args_propagate_to_return(self) -> bool:
        """True se 'x = source(args...)' propaga il taint degli argomenti al
        valore di ritorno. False per linguaggi con source per side-effect (C)."""
        return True

    def taint_opaque_tags(self) -> list:
        """Tag srcML il cui contenuto non trasporta taint verso l'espressione
        che li racchiude (es. sizeof in C: il risultato dipende dal tipo, non
        dal contenuto). Default: nessuno."""
        return []

    def resolve_operand_type(self, node, ns):
        """Tipo dichiarato di un operando che sia un semplice identificatore, altrimenti None."""
        if node is None or not node.tag.endswith("}name"):
            return None
        text = "".join(node.itertext()).strip()
        if not text.isidentifier():
            return None
        return self.resolve_variable_type(node, text, ns)


    def is_cast_type_name(self, name_node) -> bool:
        """True se <name> fa parte del tipo di un cast. Default: nessun cast sintattico
        riconoscibile (Python, Java: il cast è un nodo a parte o non esiste)."""
        return False

    def extract_output_buffer_name(self, arg_node, ns) -> str | None:
        """Nome della variabile in un <src:argument>, ignorando tipi, indici,
        costrutti opachi (taint_opaque_tags) e cast."""      
        skip = ["ancestor::src:index", "ancestor::src:type"]
        skip += [f"ancestor::src:{t}" for t in self.taint_opaque_tags()]
        skip_xpath = " | ".join(skip)

        for n in arg_node.xpath(".//src:name[not(src:name)]", namespaces=ns):
            if n.xpath(skip_xpath, namespaces=ns):
                continue
            if self.is_cast_type_name(n):
                continue
            txt = name_text(n)
            if txt:
                return txt
        return None

    def is_reference_comparison(self, lhs_type, rhs_type) -> bool:
        """True se il confronto va segnalato. Default: nel dubbio segnala."""
        return True


    def resolve_name_text(self, text: str, imports: list) -> str:
        """Nome puntato (non call) -> nome canonico. Default: invariato."""
        return text

    
    def _chain_receiver(self, call_node, ns):
        ops = " or ".join(f"text()='{o}'" for o in self.member_access_operator())
        op = call_node.xpath(
            f"preceding-sibling::*[1][self::src:operator and ({ops})]", namespaces=ns)
        if not op:
            return None
        prev = op[0].xpath("preceding-sibling::*[1][self::src:call]", namespaces=ns)
        return prev[0] if prev else None


    def normalize_member_access(self, name: str) -> str:
        """Riporta gli accessi a membro alla forma canonica '.' (C: s->fn == s.fn)."""
        for op in self.member_access_operator():
            if op != ".":
                name = name.replace(op, ".")
        return name

    def is_async_function(self, func_node, ns) -> bool:
        """True se la funzione è dichiarata async. Default: False (C, Java)."""
        return False

    def is_true_constant(self, text: str) -> bool:
        """True se il letterale è una costante sempre vera (while(true))."""
        t = text.strip()
        return self.is_boolean_literal(t) and t.lower() == "true"

    def is_false_constant(self, text: str) -> bool:
        t = text.strip()
        return self.is_boolean_literal(t) and t.lower() == "false"


    def loop_update_operators(self) -> dict:
        """Operatori che modificano la variabile di un ciclo.
        compound: 'x op= n'; unary: 'x++' / '--x'."""
        return {
            "compound": ["+=", "-=", "*=", "/=", "%=", "<<=", ">>=", "&=", "|=", "^="],
            "unary": ["++", "--"],
        }

    def is_identifier(self, text: str) -> bool:
        """True se `text` è un identificatore semplice (non un accesso a membro)."""
        return bool(re.match(r"^[A-Za-z_$][\w$]*$", text))

    def comparison_operators(self) -> list:
        return ["<", "<=", ">", ">=", "!=", "=="]

    def loop_exit_tags(self) -> list:
        """Tag che possono far uscire dal ciclo che li racchiude (come flow_exit_tags, senza 'continue')."""
        return [t for t in self.flow_exit_tags() if t != "continue"]

    def break_target_tags(self) -> list:
        """Costrutti che catturano un 'break' (un break dentro un loop annidato o uno switch
        non esce dal ciclo esterno)."""
        return ["while", "do", "for", "switch"]

    def canonical_literal(self, text: str) -> str:
        """Forma canonica per confrontare valori letterali (True/true -> true, None/null -> null)."""
        t = text.strip()
        if self.is_boolean_literal(t):
            return t.lower()
        if self.is_none_literal(t):
            return "null"
        return self.normalize_string_literal(t)



    def is_in_macro_definition(self, node) -> bool:
        """True se `node` sta dentro la definizione di una macro del preprocessore.
        Default: False (Python, Java non hanno macro)."""
        return False


    def call_receiver_name(self, call_node, ns) -> str | None:
        """Nome della variabile su cui e' invocato il metodo ('x' in x.add(...)).
        Solo per la forma semplice 'var.metodo(...)'; altrimenti None."""
        nm = call_node.xpath("./src:name", namespaces=ns)
        if not nm:
            return None
        parts = nm[0].xpath("./src:name", namespaces=ns)
        ops = nm[0].xpath("./src:operator", namespaces=ns)
        if len(parts) != 2 or len(ops) != 1:
            return None
        if "".join(ops[0].itertext()).strip() not in self.member_access_operator():
            return None
        return name_text(parts[0]) or None


    def parameter_annotation_names(self, param_node, ns) -> list:
        """Nomi (semplici) delle annotazioni/decoratori di un parametro. Default: nessuno."""
        return []

    def is_implicit_receiver_param(self, param_node, ns) -> bool:
        """True se il parametro è il ricevente implicito (self/cls): non è input esterno."""
        return False


    def is_numeric_type(self, type_text) -> bool:
        """True se il tipo dichiarato non può trasportare una stringa arbitraria
        (interi, float, booleani). Default: False (nel dubbio, resta taintato)."""
        return False

    def get_parameter_type(self, param_node, ns) -> str:
        return self.get_parameter_name_and_type(param_node, ns)[1] or ""



    def chain_ops_xpath(self, rhs, ns) -> str:
        """XPath (relativo a `rhs`) degli operatori '=' di una catena 'a = b = c'.
        Forma 'init': l'RHS è l'<expr> intera e gli '=' sono suoi figli diretti.
        Forma piatta: gli '=' sono i fratelli che seguono l'RHS."""
        tok = self.assignment_operator_token()
        if rhs.tag.endswith("}expr"):
            return f"./src:operator[text()='{tok}']"
        return f"./following-sibling::src:operator[text()='{tok}']"

    def _chain_rhs(self, op, ns):
        """RHS di un anello della catena: primo fratello non-commento dopo l''='."""
        r = op.xpath("./following-sibling::*[not(self::src:comment)][1]", namespaces=ns)
        return r[0] if r else None

    def get_assignment_chain(self, node, ns) -> list:
        """[(lhs, rhs), ...] per 'a = b = c'. Ogni anello della catena condivide
        l'RHS finale: 'a = b = src' -> (a, src), (b, src). Così l'RHS di 'a' non
        contiene 'b' (che viene sovrascritta), evitando falsi positivi nella
        sanificazione e nel kill-by-reassign."""
        lhs, rhs = self.get_assignment_lhs_rhs(node, ns)
        if lhs is None or rhs is None:
            return []
        chain = [(lhs, rhs)]

        if node.tag.endswith("}control"):      # binding di iterazione: nessuna catena
            return chain

        for op in rhs.xpath(self.chain_ops_xpath(rhs, ns), namespaces=ns):
            l = op.xpath("./preceding-sibling::*[not(self::src:comment)][1]", namespaces=ns)
            r = self._chain_rhs(op, ns)
            if l and l[0].tag.endswith("}name") and r is not None:
                chain.append((l[0], r))
        if len(chain) > 1:
            final_rhs = chain[-1][1]
            chain = [(l, final_rhs) for l, _ in chain]
        return chain
# ---------------------------------------------------------------------- #
# Implementazione Python
# ---------------------------------------------------------------------- #

class PythonAdapter(LanguageAdapter):
    name = "python"

    OCTAL_RE = re.compile(r"^0[oO][0-7]+$")
    HEX_RE = re.compile(r"^0[xX][0-9a-fA-F]+$")
    BIN_RE = re.compile(r"^0[bB][01]+$")

    def potential_assignment_xpath(self) -> str:
        return ".//src:expr_stmt | .//src:control[parent::src:for]"

    def is_assignment(self, node, ns) -> bool:
        if node.tag.endswith("expr_stmt"):
            return bool(node.xpath(".//src:operator[text()='='][1]", namespaces=ns))
            
        # Supporto per iterazione Python: cerca il tag <range>
        if node.tag.endswith("control") and node.getparent() is not None and node.getparent().tag.endswith("for"):
            return bool(node.xpath(".//src:range", namespaces=ns))
            
        return False

    def get_assignment_lhs_rhs(self, node, ns):
        if node.tag.endswith("expr_stmt"):
            op = node.xpath(".//src:operator[text()='='][1]", namespaces=ns)
            if not op:
                return None, None
            op = op[0]
            lhs_nodes = op.xpath("./preceding-sibling::*[not(self::src:annotation)]", namespaces=ns)
            rhs_nodes = op.xpath("./following-sibling::*", namespaces=ns)
            lhs = lhs_nodes[-1] if lhs_nodes else None
            rhs = rhs_nodes[0] if rhs_nodes else None
            return (lhs, rhs)

        # Estrazione LHS e RHS per i loop: for x in y:
        if node.tag.endswith("control"):
            lhs_expr = node.xpath("./src:expr[1]", namespaces=ns)
            range_expr = node.xpath(".//src:range/src:expr[1]", namespaces=ns)
            
            if not lhs_expr or not range_expr:
                return None, None
            
            # Estrae il nome della variabile. Nell'unpacking, per ora prenderà solo la prima.
            lhs_name = lhs_expr[0].xpath(".//src:name[1]", namespaces=ns)
            lhs = lhs_name[0] if lhs_name else None
            rhs = range_expr[0]
            
            return (lhs, rhs)

        return None, None

    def is_kwarg(self, argument_node, ns) -> bool:
        # Cerca il nome del parametro
        name_nodes = argument_node.xpath("./src:name[1]", namespaces=ns)
        if not name_nodes:
            return False
            
        # Caso 1: srcML lo incapsula in un tag <operator> (comportamento standard)
        if argument_node.xpath("./src:operator[1][text()='=']", namespaces=ns):
            return True
            
        # Caso 2: srcML lo lascia come testo "libero" subito dopo il tag <name>
        tail_text = name_nodes[0].tail
        if tail_text:
            t = tail_text.strip()
            if t.startswith("=") and not t.startswith("=="):
                return True
            
        return False

    def string_concat_operators(self) -> list:
        return ["+", "%"]  

    def is_interpolated_string(self, literal_text: str) -> bool:
        t = literal_text.strip()
        return t.startswith(("f'", 'f"', "F'", 'F"', "rf'", 'rf"', "fr'", 'fr"'))

    def is_none_literal(self, text: str) -> bool:
        return text.strip() == "None"

    def parse_numeric_literal(self, text: str):
        t = text.strip().replace("_", "")
        try:
            if self.OCTAL_RE.match(t):
                return int(t, 8)
            if self.HEX_RE.match(t):
                return int(t, 16)
            if self.BIN_RE.match(t):
                return int(t, 2)
            return int(t)
        except ValueError:
            try:
                return int(float(t))
            except ValueError:
                return None

    def normalize_string_literal(self, text: str) -> str:
        t = text.strip()
        # rimuove prefissi f/r/b/u in qualsiasi combinazione e uniforma gli apici
        t = re.sub(r"^[fFrRbBuU]{1,2}(?=['\"])", "", t)
        if len(t) >= 2 and t[0] in "'\"" and t[-1] == t[0]:
            t = t[1:-1]
        return t

    def resolve_imports(self, unit_node, ns) -> list:
        
        bindings = []
 
        for imp in unit_node.xpath(".//src:import", namespaces=ns):
            from_nodes = imp.xpath("./src:from", namespaces=ns)
 
            if from_nodes:
                # from MODULO import simbolo [as alias], simbolo2 [as alias2], ...
                module_name_nodes = from_nodes[0].xpath("./src:name", namespaces=ns)
                module = "".join(module_name_nodes[0].itertext()).strip() if module_name_nodes else ""
 
                imported_names = imp.xpath(
                    "./src:name[not(ancestor::src:from) and not(ancestor::src:alias)]",
                    namespaces=ns,
                )
                for n in imported_names:
                    symbol = "".join(n.itertext()).strip()
                    if not symbol:
                        continue
                    canonical = f"{module}.{symbol}" if module else symbol
                    alias_nodes = n.xpath("following-sibling::src:alias[1]//src:name", namespaces=ns)
                    local = "".join(alias_nodes[0].itertext()).strip() if alias_nodes else symbol
                    bindings.append(ImportBinding(local_name=local, canonical_name=canonical, node=imp))
 
            else:
                # # import MODULO [as alias] [, MODULO2 [as alias2]]
                names = imp.xpath("./src:name[not(ancestor::src:alias)]", namespaces=ns)
                for n in names:
                    canonical = "".join(n.itertext()).strip()
                    if not canonical:
                        continue
                    alias_nodes = n.xpath("following-sibling::src:alias[1]//src:name", namespaces=ns)
                    head = canonical.split(".")[0]

                    if alias_nodes:
                        local = "".join(alias_nodes[0].itertext()).strip()
                        bindings.append(ImportBinding(local_name=local, canonical_name=canonical, node=imp))
                    else:
                        # 'import os.path' rende disponibile 'os', non 'os.path'
                        bindings.append(ImportBinding(local_name=head, canonical_name=head, node=imp))
                        if canonical != head:   # serve a required_imports
                            bindings.append(ImportBinding(local_name=canonical, canonical_name=canonical, node=imp))
 
        return bindings


    _MAX_RESOLVE_DEPTH = 5 #Guardia per evitare ricorsione infinita di catene eccessivamente lunghe all'interno di resolve_call_name
    
    # Funzioni factory built-in (non richiedono import) i cui oggetti restituiti
    # hanno metodi tracciati nel catalogo (es. f = open(...); f.read() -> 'open.read').
    _BUILTIN_FACTORIES = {"open"}

    def resolve_call_name(self, call_node, ns, imports: list, _depth: int = 0) -> str:
        if _depth > self._MAX_RESOLVE_DEPTH:
            return None

        name_nodes = call_node.xpath("./src:name", namespaces=ns)
        if not name_nodes:
            return None
        raw = "".join(name_nodes[0].itertext()).strip()
        if not raw:
            return None

        # 0. call concatenata: 'a.b().c()'
        if "." not in raw:
            recv = self._chain_receiver(call_node, ns)
            if recv is not None:
                recv_name = self.resolve_call_name(recv, ns, imports, _depth + 1)
                if recv_name:
                    return f"{recv_name}.{raw}"

        # 1. prevenzione doppio prefisso
        for binding in imports:
            if raw == binding.canonical_name or raw.startswith(f"{binding.canonical_name}."):
                return raw

        head, _, rest = raw.partition(".")

        # 2. moduli importati
        for binding in imports:
            if binding.local_name == head:
                return f"{binding.canonical_name}.{rest}" if rest else binding.canonical_name

        # 3. instance tracking con risalita lessicale
        if rest:
            rhs = self._reaching_rhs(call_node, head, ns)
            if rhs is not None:
                first_call = rhs.xpath("descendant-or-self::src:call[1]", namespaces=ns)
                chain = self._call_chain_names(rhs, ns)
                if first_call and chain:
                    resolved = self.resolve_call_name(first_call[0], ns, imports, _depth + 1) or chain[0]
                    if len(chain) > 1:
                        resolved += "." + ".".join(chain[1:])
                    # Sostituisce il receiver solo se l'RHS risolve a un nome qualificato,
                    # a un modulo importato o a una factory built-in, evitando che helper
                    # locali (es. conn = get_db()) sovrascrivano 'conn.execute' in 'get_db.execute'.
                    if (
                        "." in resolved
                        or resolved in self._BUILTIN_FACTORIES
                        or any(
                            resolved == b.canonical_name or resolved.startswith(f"{b.canonical_name}.")
                            for b in imports
                        )
                    ):
                        return f"{resolved}.{rest}"

        return raw
                

    def get_interpolated_variables(self, literal_text: str) -> list[str]:
        # Cerca tutto quello che c'è tra { e } ignorando eventuali specificatori di formato
        matches = re.findall(r"\{([a-zA-Z0-9_]+)[^}]*\}", literal_text)
        return matches

    def string_formatting_operator_roles(self) -> dict:
        return {"concat": "+", "percent_format": "%"}

    def negation_operator(self) -> str:
        return "not"


    def is_boolean_literal(self, text: str) -> bool:
        return text.strip() in ("True", "False")

    def reference_comparison_operators(self) -> list:
        return ["is", "is not"]

    def assignment_operator_token(self) -> str:
        return "="

    def equality_operator(self) -> str:
        return "=="

    def logical_and_operator(self) -> list:
        return ["and"]

    def logical_or_operator(self) -> list:
        return ["or"]

    def get_parameter_name_and_type(self, param_node, namespaces):
        """Estrae nome e tipo da un parametro (<src:parameter>) in Python."""
        # In Python il tipo è dentro l'annotazione
        type_nodes = param_node.xpath("./src:annotation/src:expr", namespaces=namespaces)
        type_text = "".join(type_nodes[0].itertext()).strip() if type_nodes else ""
        
        
        name_nodes = param_node.xpath("./src:name[1]", namespaces=namespaces)
        pname = "".join(name_nodes[0].itertext()).strip() if name_nodes else ""
        
        return pname, type_text


    def member_access_operator(self) -> list:
        return ["."]


    def taint_block_functions(self) -> list:
        return ["len", "hash", "bool", "isinstance", "id", "type", "int","float"]

    def taint_propagating_calls(self) -> dict:
        recv = {"out_receiver": True}
        return {"*.append": recv, "*.extend": recv, "*.insert": recv,
                "*.add": recv, "*.update": recv, "*.setdefault": recv}


    def extract_membership_relations(self, condition_node, ns) -> list[dict]:
        relations = []
        # srcML raggruppa nativamente sia 'in' che 'not in' in un singolo nodo <operator>
        membership_ops = condition_node.xpath(".//src:operator[text()='in' or text()='not in']", namespaces=ns)
        
        for op_node in membership_ops:
            op_text = "".join(op_node.itertext()).strip()
            is_negated = (op_text == "not in")
            
            # LHS: Il nodo precedente (tipicamente un <name> o un <expr>)
            prev_nodes = op_node.xpath("./preceding-sibling::*[not(self::src:comment)]", namespaces=ns)
            if not prev_nodes:
                continue
            lhs_node = prev_nodes[-1]
            
            # RHS: Il nodo successivo (es. un <name>, <array>, o <tuple>)
            rhs_nodes = op_node.xpath("./following-sibling::*[not(self::src:comment)]", namespaces=ns)
            if not rhs_nodes:
                continue
            rhs_node = rhs_nodes[0]
            
            relations.append({
                "lhs": lhs_node,
                "rhs": rhs_node,
                "is_negated": is_negated
            })
            
        return relations

    def is_collection_assignment(self, assignment_node, ns) -> bool:
        op = assignment_node.xpath(".//src:operator[text()='='][1]", namespaces=ns)
        if not op:
            return False
            
        rhs = op[0].xpath("./following-sibling::*[not(self::src:comment)][1]", namespaces=ns)
        if not rhs:
            return False
            
        rhs_node = rhs[0]
        # Adattato ai tag reali di srcML per Python: <array> e <dictionary>
        tag = rhs_node.tag.split('}')[-1] if '}' in rhs_node.tag else rhs_node.tag
        return tag in ("array", "dictionary", "set")


    def find_exception_bindings(self, tree, ns) -> list:
        bindings = []
        for catch in tree.xpath(".//src:catch", namespaces=ns):
            alias_names = catch.xpath("./src:alias//src:name", namespaces=ns)
            if not alias_names:
                continue   # 'except Exception:' senza 'as e' -> nessuna variabile da tracciare
            var_name = "".join(alias_names[0].itertext()).strip()
            block = catch.xpath("./src:block[1]", namespaces=ns)
            if block:
                bindings.append((var_name, block[0]))
        return bindings

    def resolve_variable_type(self, name_node, var_name, ns) -> str | None:
        return None

    def null_comparison_operators(self) -> dict:
        return {
            "falsy": ["==", "is"],
            "truthy": ["!=", "is not"]
        }

    def taint_source_output_args(self) -> dict:
        return {}

    def get_parameter_name_node(self, param_node, ns):
        n = param_node.xpath("./src:name[1]", namespaces=ns)
        return n[0] if n else None

    def function_tags(self):   return ["function"]
    def lambda_tags(self):     return ["lambda"]
    def flow_exit_tags(self):  return ["return", "throw", "continue", "break"]
    def flow_exit_calls(self): return ["sys.exit", "exit", "quit", "os._exit"]
    def noop_statement_tags(self): return ["pass"]
    def class_tags(self): return ["class"]


    def resolve_name_text(self, text, imports):
        if not text or not imports:
            return text
        # già canonico: 'os.environ' con 'import os' (evita il doppio prefisso)
        for b in imports:
            if b.is_macro:
                continue
            if text == b.canonical_name or text.startswith(b.canonical_name + "."):
                return text
        head, _, rest = text.partition(".")
        for b in imports:
            if not b.is_macro and b.local_name == head:
                return f"{b.canonical_name}.{rest}" if rest else b.canonical_name
        return text

    #HELPER PER call concatenate
    def _call_chain_names(self, rhs, ns):
        """Nomi delle call concatenate a destra di '=': a.b().c().d() -> ['a.b', 'c', 'd']."""
        start = rhs.xpath("descendant-or-self::src:call[1]", namespaces=ns)
        if not start:
            return None
        node = start[0]
        first = node.xpath("./src:name", namespaces=ns)
        if not first:
            return None
        names = ["".join(first[0].itertext()).strip()]
        while True:
            op = node.xpath("following-sibling::*[1][self::src:operator and text()='.']", namespaces=ns)
            if not op:
                break
            nxt = op[0].xpath("following-sibling::*[1][self::src:call]", namespaces=ns)
            if not nxt:
                break
            nm = nxt[0].xpath("./src:name", namespaces=ns)
            if not nm:
                break
            names.append("".join(nm[0].itertext()).strip())
            node = nxt[0]
        return names



    def _reaching_rhs(self, call_node, head, ns):
        """RHS dell'assegnazione di `head` che raggiunge `call_node`, cercando dallo
        scope più interno verso l'esterno (funzioni annidate -> funzione -> modulo).
        Ritorna None se non c'è, o se `head` è un parametro (shadowing)."""
        

        call_key = _pos_key(call_node)
        call_ancestors = set(call_node.iterancestors())     
        fn_cond = " or ".join(f"self::src:{t}" for t in self.function_tags())

        funcs = call_node.xpath(f"ancestor::*[{fn_cond}]", namespaces=ns)
        unit = call_node.xpath("ancestor::src:unit[1]", namespaces=ns)
        scopes = list(reversed(funcs)) + unit

        for scope_node in scopes:
            is_unit = scope_node.tag.endswith("}unit")

            if not is_unit:
                for p in scope_node.xpath("./src:parameter_list/src:parameter", namespaces=ns):
                    n = self.get_parameter_name_node(p, ns)
                    if n is not None and "".join(n.itertext()).strip() == head:
                        return None

            prior = []
            for stmt, lhs, rhs in find_assignments(scope_node, self, head):
                if rhs is None or _pos_key(stmt) >= call_key:
                    continue
                if stmt in call_ancestors:                  
                    continue
                owner = enclosing_scope(stmt, self)
                if (owner is None) if is_unit else (owner is scope_node):
                    prior.append((stmt, rhs))

            if prior:
                return max(prior, key=lambda t: _pos_key(t[0]))[1]

        return None


    def is_async_function(self, func_node, ns) -> bool:
        return bool(func_node.xpath("./src:specifier[text()='async']", namespaces=ns))


    def is_true_constant(self, text: str) -> bool:
        '''anche 1 è una condizione sempre vera, quindi esegue l'override'''
        return text.strip() == "1" or super().is_true_constant(text)

    def is_false_constant(self, text: str) -> bool:
        return text.strip() == "0" or super().is_false_constant(text)


    def loop_update_operators(self) -> dict:
        return {
            "compound": ["+=", "-=", "*=", "/=", "//=", "%=", "**=", "<<=", ">>=", "&=", "|=", "^="],
            "unary": [],
        }

    def is_identifier(self, text: str) -> bool:
        return text.isidentifier()


    def is_implicit_receiver_param(self, param_node, ns) -> bool:
        if param_node.get("type") in ("args", "kwargs"):
            return False                      # *args / **kwargs sono input veri
        plist = param_node.getparent()
        first = plist.xpath("./src:parameter[1]", namespaces=ns)
        if not first or first[0] is not param_node:
            return False                      # solo il primo parametro
        func = plist.getparent()
        owner = func.xpath("ancestor::*[self::src:class or self::src:function][1]", namespaces=ns)
        if not owner or not owner[0].tag.endswith("}class"):
            return False                      # non è un metodo
        # @staticmethod: il primo parametro è un argomento vero
        return not func.xpath("./src:attribute//src:name[text()='staticmethod']", namespaces=ns)

    def is_numeric_type(self, type_text) -> bool:
        return (type_text or "").strip() in ("int", "float", "bool", "complex")


# ---------------------------------------------------------------------- #
# Implementazione Java
# ---------------------------------------------------------------------- #


class JavaAdapter(LanguageAdapter):
    name = "java"


    _SCOPE_CLASS_UNIT_XP = etree.XPath(
        "ancestor::*[self::src:function or self::src:constructor or self::src:class or self::src:unit][1]",
        namespaces={"src": "http://www.srcML.org/srcML/src"},
    )
    _ANC_CLASS_XP = etree.XPath(
        "ancestor::src:class[1]",
        namespaces={"src": "http://www.srcML.org/srcML/src"},
    )

    _GENERIC_FREE_TEXT_XP = etree.XPath(
        ".//text()[not(ancestor::src:argument_list[@type='generic'])]",
        namespaces={"src": "http://www.srcML.org/srcML/src"},
    )

    def _find_decls(self, node, var_name: str, include_fields: bool = False) -> list:
        # 1. Scope locale + parametri (function/constructor/class/unit)
        containers = self._SCOPE_CLASS_UNIT_XP(node)
        if containers:
            decls = get_decl_index(containers[0]).get(var_name)
            if decls:
                return decls
        # 2. Fallback sui campi della classe che racchiude il metodo
        if include_fields:
            classes = self._ANC_CLASS_XP(node)
            if classes:
                decls = get_class_field_index(classes[0]).get(var_name)
                if decls:
                    return decls
        return []

    def _canonicalize(self, name, imports):
        head, _, rest = name.partition(".")
        for b in imports or []:
            if b.is_macro or b.local_name != head:
                continue
            return f"{b.canonical_name}.{rest}" if rest else b.canonical_name
        return name

    def potential_assignment_xpath(self) -> str:
        return ".//src:expr_stmt | .//src:decl_stmt | .//src:control[parent::src:for]"

    def is_assignment(self, node, ns) -> bool:
        if node.tag.endswith("expr_stmt"):
            return bool(node.xpath(".//src:operator[text()='='][1]", namespaces=ns))
        if node.tag.endswith("decl_stmt"):
            return bool(node.xpath(".//src:init", namespaces=ns))
            
        # Supporto nativo per i cicli for-each in Java
        if node.tag.endswith("control") and node.getparent() is not None and node.getparent().tag.endswith("for"):
            return bool(node.xpath(".//src:range", namespaces=ns))
            
        return False


    def get_assignment_lhs_rhs(self, node, ns):
        if node.tag.endswith("expr_stmt"):
            op = node.xpath(".//src:operator[text()='='][1]", namespaces=ns)
            if not op:
                return None, None
            lhs_nodes = op[0].xpath("./preceding-sibling::*", namespaces=ns)
            rhs_nodes = op[0].xpath("./following-sibling::*", namespaces=ns)
            return (lhs_nodes[-1] if lhs_nodes else None, rhs_nodes[0] if rhs_nodes else None)
            
        if node.tag.endswith("decl_stmt"):
            decl = node.xpath(".//src:decl[1]", namespaces=ns)
            if not decl:
                return None, None
            lhs = decl[0].xpath("./src:name", namespaces=ns)
            rhs = decl[0].xpath("./src:init/src:expr | ./src:init/src:decl", namespaces=ns)
            return (lhs[0] if lhs else None, rhs[0] if rhs else None)
            
        # Estrazione LHS e RHS per i cicli for-each
        if node.tag.endswith("control"):
            decl = node.xpath(".//src:init/src:decl[1]", namespaces=ns)
            range_expr = node.xpath(".//src:range/src:expr[1]", namespaces=ns)
            
            if not decl or not range_expr:
                return None, None
            
            lhs = decl[0].xpath("./src:name", namespaces=ns)
            rhs = range_expr[0]
            
            return (lhs[0] if lhs else None, rhs)

        return None, None

    
    def is_kwarg(self, argument_node, ns) -> bool:
        # Java NON supporta i keyword arguments nelle chiamate a funzione
        return False

    def string_concat_operators(self) -> list:
        return ["+"]

    def is_interpolated_string(self, literal_text: str) -> bool:
        # Supporto per String Templates (es. STR."Hello \{name}")
        t = literal_text.strip()
        return t.startswith("STR.") or "\\{" in t

    def get_interpolated_variables(self, literal_text: str) -> list[str]:
        # Cattura le variabili dentro i blocchi \{ ... }
        return re.findall(r"\\\{([a-zA-Z0-9_]+)[^}]*\}", literal_text)

    def is_none_literal(self, text: str) -> bool:
        return text.strip() == "null"

    def parse_numeric_literal(self, text: str):
        t = text.strip().replace("_", "")
        is_hex = t.lower().startswith("0x")
        is_bin = t.lower().startswith("0b")

        if is_hex or is_bin:
            # In Java l'unico suffisso valido su hex/bin e' 'L' (long); mai
            # una cifra esadecimale, quindi rimovibile senza ambiguita'.
            core = re.sub(r'[lL]+$', '', t)
            try:
                return int(core, 16 if is_hex else 2)
            except ValueError:
                return None

        core = t
        if core.lower().endswith(('f', 'l', 'd')):
            core = core[:-1]
        try:
            # In Java i numeri che iniziano per 0 (es: 0755) sono ottali!
            if core.startswith("0") and len(core) > 1 and core[1:].isdigit():
                return int(core, 8)
            return int(core)
        except ValueError:
            try:
                return int(float(core))
            except ValueError:
                return None

    def normalize_string_literal(self, text: str) -> str:
        t = text.strip()
        if t.startswith("STR."):
            t = t[4:]
        if len(t) >= 2 and t[0] == '"' and t[-1] == '"':
            t = t[1:-1]
        return t

    def resolve_imports(self, unit_node, ns) -> list:
        bindings = []
        for imp in unit_node.xpath(".//src:import", namespaces=ns):
            name_nodes = imp.xpath("./src:name", namespaces=ns)
            if not name_nodes:
                continue
                
            full_name = "".join(name_nodes[0].itertext()).strip()
            if not full_name:
                continue

            # Gestione wildcard: import java.util.*;
            if full_name.endswith(".*"):
                bindings.append(ImportBinding(
                    local_name="*", 
                    canonical_name=full_name[:-2], 
                   
                    node=imp
                ))
            else:
                # import java.util.List; -> local: List, canonical: java.util.List
                local_name = full_name.split(".")[-1]
                bindings.append(ImportBinding(
                    local_name=local_name, 
                    canonical_name=full_name, 
                    
                    node=imp
                ))
                
        return bindings


    _MAX_RESOLVE_DEPTH = 5

    def resolve_call_name(self, call_node, ns, imports, _depth: int = 0) -> str:
        if _depth > self._MAX_RESOLVE_DEPTH:
            return None

        name_nodes = call_node.xpath("./src:name", namespaces=ns)
        if not name_nodes:
            return None

        # raw_name = "".join(name_nodes[0].itertext()).strip()
        raw_name = "".join(self._GENERIC_FREE_TEXT_XP(name_nodes[0])).strip()

        if not name_nodes[0].xpath("./src:name", namespaces=ns):   # nome semplice
            recv = self._chain_receiver(call_node, ns)
            if recv is not None:
                recv_name = self.resolve_call_name(recv, ns, imports, _depth + 1)
                if recv_name:
                    return f"{recv_name}.{raw_name}"

        parts = name_nodes[0].xpath("./src:name", namespaces=ns)
        ops = name_nodes[0].xpath("./src:operator[text()='.']", namespaces=ns)

        if len(parts) >= 2 and ops:
            var_name = "".join(parts[0].itertext()).strip()
            method_name = "".join(parts[-1].itertext()).strip()
            
            # xpath_query_local = (
            #     f"{self.scope_axis(('class', 'unit'))}"
            #     f"//src:decl[src:name[text()='{var_name}']]"
            # )
            
            # decls = call_node.xpath(xpath_query_local, namespaces=ns)

            # # --- 2. Fallback sui Parametri (Se la variabile non è nel blocco) ---
            # if not decls:
            #     xpath_query_param = (
            #         f"{self.scope_axis()}//src:parameter_list"
            #         f"//src:decl[src:name[text()='{var_name}']]"
            #     )
            #     decls = call_node.xpath(xpath_query_param, namespaces=ns)

            # # 3. Fallback: campi della classe che racchiude (se la call e' dentro un metodo)
            # if not decls:
            #     xpath_query_field = (
            #         f"ancestor::src:class[1]/src:block/src:decl_stmt"
            #         f"/src:decl[src:name[text()='{var_name}']]"
            #     )
            #     decls = call_node.xpath(xpath_query_field, namespaces=ns)

            decls = self._find_decls(call_node, var_name, include_fields=True)
    
            if decls:
                decl_node = decls[-1]
                var_type = None
                seen = set()

                # Risale attraverso <type ref="prev"/> nelle dichiarazioni multiple
                # a tipo condiviso (es. 'ScriptEngine a, b, c = ...') finché non
                # trova il <decl> che possiede davvero il <type>.
                while decl_node is not None and id(decl_node) not in seen:
                    seen.add(id(decl_node))

                    type_nodes = decl_node.xpath(
                        "./src:type//src:name[not(ancestor::src:annotation)]", namespaces=ns
                    )
                    if type_nodes:
                        var_type = "".join(type_nodes[0].itertext()).strip()
                        # Tronca la stringa alla prima parentesi angolare evita di considerare: Map<String<String>
                        var_type = var_type.split('<')[0].strip()
                        break

                    type_node = decl_node.xpath("./src:type", namespaces=ns)
                    if type_node and type_node[0].get("ref") == "prev":
                        prev_decl = decl_node.xpath("preceding-sibling::src:decl[1]", namespaces=ns)
                        decl_node = prev_decl[0] if prev_decl else None
                    else:
                        decl_node = None

                # Gestione 'var' (Java 10+): il tipo non è esplicito, si risale alla call nell'<init>
                # (es. 'var writer = response.getWriter()' -> 'HttpServletResponse.getWriter').
                if var_type == "var":
                    init_call = decls[-1].xpath("./src:init//src:call[1]", namespaces=ns)
                    if init_call:
                        var_type = self.resolve_call_name(init_call[0], ns, imports, _depth + 1)
                    else:
                        var_type = None

                if var_type:
                    return self._canonicalize(f"{var_type}.{method_name}", imports)
                
        return self._canonicalize(raw_name, imports)

    def string_formatting_operator_roles(self) -> dict:
        return {"concat": "+"}

    def negation_operator(self) -> str:
        return "!"

    def assignment_operator_token(self) -> str:
        return "="

    def reference_comparison_operators(self) -> list:
        # In Java == e != confrontano il reference in memoria degli oggetti
        return ["==", "!="]

    def is_boolean_literal(self, text: str) -> bool:
        return text.strip() in ("true", "false")

    def equality_operator(self) -> str:
        return "=="

    def logical_and_operator(self) -> list:
        return ["&&"]

    def logical_or_operator(self) -> list:
        return ["||"]

    def get_parameter_name_and_type(self, param_node, namespaces):
        decl = param_node.xpath("./src:decl[1]", namespaces=namespaces)
        if not decl:
            return None, None
        type_nodes = decl[0].xpath("./src:type[1]", namespaces=namespaces)
        type_text = "".join(type_nodes[0].itertext()).strip() if type_nodes else ""
        name_nodes = decl[0].xpath("./src:name[1]", namespaces=namespaces)
        pname = "".join(name_nodes[0].itertext()).strip() if name_nodes else ""
        return pname, type_text


    def member_access_operator(self) -> list:
        return ["."]


    def taint_block_functions(self) -> list:
        return ["*.length", "*.hashCode", "*.isEmpty", "*.equals", "*.compareTo"]

    def taint_propagating_calls(self) -> dict:
        # Metodi che modificano il RICEVENTE: x.add(tainted) rende taintato x.
        recv = {"out_receiver": True}
        return {"*.add": recv, "*.addAll": recv, "*.put": recv, "*.putAll": recv,
                "*.append": recv, "*.push": recv, "*.offer": recv}

    def extract_membership_relations(self, condition_node, ns) -> list[dict]:
        relations = []
        contains_calls = condition_node.xpath(".//src:call[.//src:name[last()][text()='contains']]", namespaces=ns)
        
        for call_node in contains_calls:
            # RHS (es. 'lista' in lista.contains)
            rhs_nodes = call_node.xpath("./src:name/src:name[1]", namespaces=ns)
            
            # LHS (es. 'x' passato come argomento)
            lhs_nodes = call_node.xpath("./src:argument_list/src:argument/src:expr/*[1]", namespaces=ns)
            
            if not rhs_nodes or not lhs_nodes:
                continue
                
            # Identifica l'operatore '!' che si trova prima della <call>
            is_negated = False
            prev_sibling = call_node.xpath("preceding-sibling::src:operator[1]", namespaces=ns)
            if prev_sibling and "".join(prev_sibling[0].itertext()).strip() == "!":
                is_negated = True
                
            relations.append({
                "lhs": lhs_nodes[0],
                "rhs": rhs_nodes[0],
                "is_negated": is_negated
            })
            
        return relations

    def is_collection_assignment(self, assignment_node, ns) -> bool:
        # Array initializer (es. int[] arr = {1, 2, 3};) -> srcML usa <block>
        init_block = assignment_node.xpath(".//src:init/src:expr/src:block", namespaces=ns)
        if init_block:
            return True
            
        # Inizializzazioni tramite 'new' (es. new ArrayList<>(Arrays.asList(...)))
        new_call = assignment_node.xpath(
            ".//src:init/src:expr[src:operator[text()='new']]/src:call/src:name", namespaces=ns)
        if new_call:
            text = "".join(new_call[0].itertext()).strip()
            if "List" in text or "Set" in text or "Collection" in text or "Array" in text:
                return True
                
        return False


    def find_exception_bindings(self, tree, ns) -> list:
        bindings = []
        for catch in tree.xpath(".//src:catch", namespaces=ns):
            param_names = catch.xpath("./src:parameter_list/src:parameter/src:decl/src:name[1]", namespaces=ns)
            if not param_names:
                continue
            var_name = "".join(param_names[0].itertext()).strip()
            block = catch.xpath("./src:block[1]", namespaces=ns)
            if block:
                bindings.append((var_name, block[0]))
        return bindings



    def null_comparison_operators(self) -> dict:
        return {
            "falsy": ["=="],
            "truthy": ["!="]
        }

    def taint_source_output_args(self) -> dict:
        return {}

    def get_parameter_name_node(self, param_node, ns):
        n = param_node.xpath("./src:decl/src:name[1]", namespaces=ns)
        return n[0] if n else None


    def function_tags(self):   return ["function", "constructor"]
    def lambda_tags(self):     return ["lambda"]
    def flow_exit_tags(self):  return ["return", "throw", "continue", "break"]
    def flow_exit_calls(self): return ["System.exit"]
    def noop_statement_tags(self): return ["empty_stmt"]
    def class_tags(self): return ["class"]


    def resolve_name_text(self, text, imports):
        return self._canonicalize(text, imports) if text else text

    # CWE-595: distinguere confronto di riferimenti da confronto di valori
    # ------------------------------------------------------------------ #
    # In Java '==' ha due significati: tra primitivi confronta i valori
    # (int == int), tra oggetti confronta gli indirizzi (String == String).
    # Dall'AST la forma è identica ('a == b'), quindi serve il TIPO DICHIARATO
    # degli operandi. Questa sezione fornisce al motore generico tre cose,
    # senza che structural_engine.py conosca nulla di Java:
    #   - resolve_operand_type():     tipo di un operando (identificatore o letterale stringa)
    #   - resolve_variable_type():    ricerca della dichiarazione locale/parametro/campo
    #   - is_reference_comparison():  decisione finale "segnalare o no"

    # Limiti noti: enum ('st == State.READY' è corretto ma resta segnalato),
    # operandi che sono call ('a.size() == b.size()'), tipi definiti in altri file.


    _PRIMS = {"byte", "short", "int", "long", "float", "double", "char", "boolean"}

    def _is_primitive(self, t: str) -> bool:
        t = re.sub(r"\b(final|static)\b", "", t).split("<")[0].strip()
        return t in self._PRIMS          # "int[]" non è primitivo: confronto di riferimenti

    def resolve_operand_type(self, node, ns):
        if node is not None and node.tag.endswith("}literal") and node.get("type") == "string":
            return "String"
        return super().resolve_operand_type(node, ns)

    def resolve_variable_type(self, name_node, var_name, ns):
        # decls = name_node.xpath(
        #     f"{self.scope_axis(('class', 'unit'))}//src:decl[src:name[text()=$v]]",
        #     namespaces=ns, v=var_name,
        # )
        decls = self._find_decls(name_node, var_name, include_fields=False)
        if not decls:
            return None
        key = _pos_key(name_node)
        before = [d for d in decls if _pos_key(d) <= key]
        decl = (before or decls)[-1]          # dichiarazione più vicina che precede l'uso

        seen = set()
        while decl is not None and id(decl) not in seen:
            seen.add(id(decl))
            t = decl.xpath("./src:type", namespaces=ns)
            if t and t[0].get("ref") != "prev":
                # Esclude eventuali annotazioni (es. @RequestParam("id") int -> int)
                texts = t[0].xpath(".//text()[not(ancestor::src:annotation)]", namespaces=ns)
                return "".join(texts).strip()
            prev = decl.xpath("preceding-sibling::src:decl[1]", namespaces=ns)
            decl = prev[0] if prev else None
        return None

    def is_reference_comparison(self, lhs_type, rhs_type) -> bool:
        # segnala, a meno che almeno un operando sia provabilmente primitivo
        return not any(t and self._is_primitive(t) for t in (lhs_type, rhs_type))


    #FINE SEZIONE CWE 595-----------------------------------------------------------------------------


    def parameter_annotation_names(self, param_node, ns) -> list:
        out = []
        for n in param_node.xpath("./src:decl/src:type/src:annotation/src:name[1]", namespaces=ns):
            full = name_text(n)
            if full:
                out.append(full.split(".")[-1])    # org.x.RequestParam -> RequestParam
        return out

    
    _NUMERIC_TYPES = {
    "byte","short","int","long","float","double","boolean",
    "Byte","Short","Integer","Long","Float","Double","Boolean",
    "BigInteger","BigDecimal",
    }

    def get_parameter_type(self, param_node, ns) -> str:
        t = param_node.xpath("./src:decl/src:type[1]", namespaces=ns)
        if not t:
            return ""
        texts = t[0].xpath(".//text()[not(ancestor::src:annotation)]", namespaces=ns)
        return "".join(texts).strip()

    def is_numeric_type(self, type_text) -> bool:
        if not type_text:
            return False
        t = re.sub(r"\b(final|static)\b", "", type_text).strip()
        return t in self._NUMERIC_TYPES      # "Long[]" e "List<Long>" restano non numerici


# ---------------------------------------------------------------------- #
# Helper per l'adapter C (cast)
# ---------------------------------------------------------------------- #

C_TYPE_WORDS = {
    "char", "int", "long", "short", "unsigned", "signed", "void",
    "float", "double", "struct", "union", "enum", "const", "volatile",
    "size_t", "ssize_t", "wchar_t",
    "uint8_t", "uint16_t", "uint32_t", "uint64_t",
    "int8_t", "int16_t", "int32_t", "int64_t",
}

def _lname(n): return n.tag.split('}')[-1]
def _ntxt(n):  return "".join(n.itertext()).strip()

def _skip_leading_casts(nodes):
    """Scarta i cast C iniziali '(' name+ '*'* ')' dalla lista di fratelli."""
    i = 0
    while i < len(nodes):
        if not (_lname(nodes[i]) == "operator" and _ntxt(nodes[i]) == "("):
            break
        j, names, stars = i + 1, [], 0
        while j < len(nodes) and _lname(nodes[j]) == "name":
            names.append(_ntxt(nodes[j])); j += 1
        while j < len(nodes) and _lname(nodes[j]) == "operator" and _ntxt(nodes[j]) and set(_ntxt(nodes[j])) == {"*"}:
            stars += 1; j += 1
        closed = j < len(nodes) and _lname(nodes[j]) == "operator" and _ntxt(nodes[j]) == ")"
        is_type = bool(names) and (stars > 0 or any(n in C_TYPE_WORDS for n in names))
        if not (closed and is_type):
            break
        i = j + 1
    return nodes[i:]


    
# ---------------------------------------------------------------------- #
# Implementazione C
# ---------------------------------------------------------------------- #

class CAdapter(LanguageAdapter):
    name = "c"

    _SCOPE_UNIT_XP = etree.XPath(
        "ancestor::*[self::src:function or self::src:unit][1]",
        namespaces={"src": "http://www.srcML.org/srcML/src"},
    )

    def _find_decls(self, node, var_name: str) -> list:
        containers = self._SCOPE_UNIT_XP(node)
        if containers:
            decls = get_decl_index(containers[0]).get(var_name)
            if decls:
                return decls
        return []


    def potential_assignment_xpath(self) -> str:
        return ".//src:expr_stmt | .//src:decl_stmt"
    
    def is_assignment(self, node, ns) -> bool:
        # Gestisce sia riassegnazioni (expr_stmt) che inizializzazioni (decl_stmt)
        if node.tag.endswith("expr_stmt"):
            return bool(node.xpath(".//src:operator[text()='='][1]", namespaces=ns))
        if node.tag.endswith("decl_stmt"):
            return bool(node.xpath(".//src:init", namespaces=ns))
        return False

    def get_assignment_lhs_rhs(self, node, ns):
        if node.tag.endswith("expr_stmt"):
            op = node.xpath(".//src:operator[text()='='][1]", namespaces=ns)
            if not op:
                return None, None
            lhs_nodes = op[0].xpath("./preceding-sibling::*", namespaces=ns)
            rhs_nodes = _skip_leading_casts(op[0].xpath("./following-sibling::*", namespaces=ns))
            return (lhs_nodes[-1] if lhs_nodes else None, rhs_nodes[0] if rhs_nodes else None)
            
        if node.tag.endswith("decl_stmt"):
            decl = node.xpath(".//src:decl[1]", namespaces=ns)
            if not decl:
                return None, None
            lhs = decl[0].xpath("./src:name", namespaces=ns)
            rhs = decl[0].xpath("./src:init/src:expr | ./src:init/src:decl", namespaces=ns)
            return (lhs[0] if lhs else None, rhs[0] if rhs else None)
            
        return None, None

    def is_kwarg(self, argument_node, ns) -> bool:
        # Il linguaggio C non supporta keyword arguments
        return False

    def string_concat_operators(self) -> list:
        # In C l'operatore '+' su char* esegue aritmetica dei puntatori, non concatenazione
        return []

    def is_interpolated_string(self, literal_text: str) -> bool:
        # Il C non ha stringhe interpolate native (si usa sprintf/snprintf)
        return False

    def get_interpolated_variables(self, literal_text: str) -> list[str]:
        return []

    def is_none_literal(self, text: str) -> bool:
        # In C si usa NULL per i puntatori
        return text.strip() == "NULL"

    def parse_numeric_literal(self, text: str):
        t = text.strip()

        is_hex = t.lower().startswith("0x")
        is_bin = t.lower().startswith("0b")

        if is_hex or is_bin:
            # Per hex/bin, SOLO u/l sono suffissi validi: mai f/d/z, che
            # collidono con cifre esadecimali reali (A-F).
            core = re.sub(r'[uUlL]+$', '', t)
            try:
                return int(core, 16 if is_hex else 2)
            except ValueError:
                return None

        # Per i letterali decimali, la classe più ampia è sicura: nessuna
        # cifra decimale (0-9) è mai in [uUlLfFdDzZ].
        core = re.sub(r'[uUlLfFdDzZ]+$', '', t)
        try:
            if core.startswith("0") and len(core) > 1 and core[1:].isdigit():
                return int(core, 8)
            return int(core)
        except ValueError:
            try:
                return int(float(core))
            except ValueError:
                return None

    def normalize_string_literal(self, text: str) -> str:
        t = text.strip()
        # Rimuove prefissi wide-char o utf (L, u8, u, U)
        t = re.sub(r'^(L|u8|u|U)', '', t)
        if len(t) >= 2 and t[0] == '"' and t[-1] == '"':
            t = t[1:-1]
        return t

    def resolve_imports(self, unit_node, ns) -> list:
        bindings = []
        # Per C, srcML usa il namespace cpp per le direttive del preprocessore
        cpp_ns = {"cpp": "http://www.srcML.org/srcML/cpp"}
        
        for inc in unit_node.xpath(".//cpp:include", namespaces=cpp_ns):
            file_nodes = inc.xpath("./cpp:file", namespaces=cpp_ns)
            if file_nodes:
                file_text = "".join(file_nodes[0].itertext()).strip()
                # Rimuove < > o " " dal nome del file incluso
                clean_name = file_text.strip('<>"')
                
                # In C non ci sono alias, il file importato mappa se stesso globalmente
                bindings.append(ImportBinding(
                    local_name=clean_name, 
                    canonical_name=clean_name, 
                    
                    node=inc
                ))

        full_ns = {**ns, **cpp_ns}
        for d in unit_node.xpath(".//cpp:define", namespaces=full_ns):
            name_n = d.xpath("./cpp:macro/src:name[1]", namespaces=full_ns)
            val_n = d.xpath("./cpp:value[1]", namespaces=full_ns)
            if not name_n or not val_n:
                continue   # es. include guard: #define FOO_H

            local = "".join(name_n[0].itertext()).strip()
            value = "".join(val_n[0].itertext()).strip()
            is_fn_like = bool(d.xpath("./cpp:macro/src:parameter_list", namespaces=full_ns))

            m = (_MACRO_FWD_RE if is_fn_like else _MACRO_ALIAS_RE).match(value)
            if not m or m.group(1) == local:
                continue

            bindings.append(ImportBinding(
                local_name=local, canonical_name=m.group(1),
                 node=d, is_macro=True))
            
        return bindings


    def resolve_call_name(self, call_node, ns, imports) -> str:
        name_nodes = call_node.xpath("./src:name", namespaces=ns)
        if not name_nodes:
            return None

        raw_name = "".join(name_nodes[0].itertext()).strip()

        raw_name = expand_macro_name(raw_name, macro_map(imports))

        parts = name_nodes[0].xpath("./src:name", namespaces=ns)
        ops = name_nodes[0].xpath("./src:operator[text()='.' or text()='->']", namespaces=ns)

        if len(parts) >= 2 and ops:
            var_name = "".join(parts[0].itertext()).strip()
            method_name = "".join(parts[-1].itertext()).strip()

            decls = self._find_decls(call_node, var_name)

            if decls:
                decl_node = decls[-1]
                var_type = None
                seen = set()

                while decl_node is not None and id(decl_node) not in seen:
                    seen.add(id(decl_node))

                    type_nodes = decl_node.xpath("./src:type//src:name", namespaces=ns)
                    if type_nodes:
                        var_type = "".join(type_nodes[0].itertext()).strip()
                        break

                    type_node = decl_node.xpath("./src:type", namespaces=ns)
                    if type_node and type_node[0].get("ref") == "prev":
                        prev_decl = decl_node.xpath("preceding-sibling::src:decl[1]", namespaces=ns)
                        decl_node = prev_decl[0] if prev_decl else None
                    else:
                        decl_node = None

                if var_type:
                    return f"{var_type}.{method_name}"

        return raw_name

    def string_formatting_operator_roles(self) -> dict:
        # Non ci sono operatori di formato nativi inline (si usano funzioni di libreria)
        return {}

    def negation_operator(self) -> str:
        return "!"

    def assignment_operator_token(self) -> str:
        return "="

    def reference_comparison_operators(self) -> list:
        # In C, == e != confrontano i valori diretti, che per i puntatori sono gli indirizzi di memoria
        return ["==", "!="]

    def is_boolean_literal(self, text: str) -> bool:
        return text.strip() in ("true", "false")

    def equality_operator(self) -> str:
        return "=="

    def logical_and_operator(self) -> list:
        return ["&&"]

    def logical_or_operator(self) -> list:
        return ["||", "or"]

    def get_parameter_name_and_type(self, param_node, namespaces):
        decl = param_node.xpath("./src:decl[1]", namespaces=namespaces)
        if not decl:
            return None, None
            
        type_nodes = decl[0].xpath("./src:type[1]", namespaces=namespaces)
        # Unisce il nome del tipo (es: char) con eventuali modificatori (es: *)
        type_text = "".join(type_nodes[0].itertext()).strip() if type_nodes else ""
        type_text = re.sub(r'\s+', ' ', type_text) # Pulisce spazi extra
        
        name_nodes = decl[0].xpath("./src:name[1]", namespaces=namespaces)
        pname = "".join(name_nodes[0].itertext()).strip() if name_nodes else ""
        
        return pname, type_text

    def member_access_operator(self) -> list:
        # Operatore base per l'accesso ai membri. L'adapter gestisce esplicitamente 
        
        return [".", "->"]

    def taint_block_functions(self) -> list:
        # Funzioni C che restituiscono numeri o bool analizzando buffer/stringhe,
        # interrompendo la propagazione del taint come stringa.
        return ["strlen", "atoi", "atol", "atof", "strcmp", "strncmp"]

    def taint_propagating_calls(self) -> dict:
        # Funzioni libc che scrivono il risultato in un buffer passato come
        # argomento (side-effect), non tramite valore di ritorno: se un
        # qualsiasi altro argomento e' taintato, il buffer di output lo
        # diventa a sua volta. Indice = posizione dell'argomento di output.
        return {
            "sprintf": 0, "snprintf": 0,
            "strcpy": 0, "strncpy": 0,
            "strcat": 0, "strncat": 0,
            "memcpy": 0,  "_snprintf": 0,
            "sscanf": {"in": [0], "out_variadic_from": 2},
        }

    def extract_membership_relations(self, condition_node, ns) -> list[dict]:
        # Il linguaggio C non ha un costrutto 'in' o un metodo '.contains()' nativo.
        # L'analisi di membership richiede funzioni custom (es. strchr per stringhe)
        # o iterazioni su array. Riconoscerlo in una singola condizione non è fattibile in modo generico.
        return []

    def is_collection_assignment(self, assignment_node, ns) -> bool:
        # Inizializzazione di array statici (es. int arr[] = {1, 2, 3};)
        init_block = assignment_node.xpath(".//src:init/src:expr/src:block", namespaces=ns)
        if init_block:
            return True
        return False

    def find_exception_bindings(self, tree, ns) -> list:
        return []   # il C non ha un meccanismo di eccezioni: CWE-209 in questa forma
                # (variabile d'eccezione -> risposta HTTP) non è applicabile

    def resolve_variable_type(self, name_node, var_name, ns) -> str | None:
        """Cerca la dichiarazione (locale o parametro) di var_name e ritorna
        il suo tipo dichiarato, es. 'char *'."""

        decls = self._find_decls(name_node, var_name)

        if not decls:
            return None

        decl_node = decls[-1]
        seen = set()
        while decl_node is not None and id(decl_node) not in seen:
            seen.add(id(decl_node))
            type_nodes = decl_node.xpath("./src:type", namespaces=ns)
            if type_nodes and type_nodes[0].get("ref") != "prev":
                return "".join(type_nodes[0].itertext()).strip()
            prev_decl = decl_node.xpath("preceding-sibling::src:decl[1]", namespaces=ns)
            decl_node = prev_decl[0] if prev_decl else None
        return None


    def null_comparison_operators(self) -> dict:
        return {
            "falsy": ["=="],
            "truthy": ["!="]
        }


    def taint_source_output_args(self) -> dict:
        return {
            "recv":     {"indices": [1]},
            "recvfrom": {"indices": [1]},
            "recvmsg":  {"indices": [1]},
            "read":     {"indices": [1]},
            "pread":    {"indices": [1]},
            "fread":    {"indices": [0]},
            "fgets":    {"indices": [0], "return_tainted": True},
            "gets":     {"indices": [0], "return_tainted": True},
            "getline":  {"indices": [0]},
            "scanf":    {"variadic_from": 1},
            "fscanf":   {"variadic_from": 2},
            "sscanf":   {"variadic_from": 2},
            "WSARecv":     {"indices": [1], "return_tainted": False},
            "WSARecvFrom": {"indices": [1], "return_tainted": False},
        }

    def get_parameter_name_node(self, param_node, ns):
        n = param_node.xpath(
            "./src:decl/src:name[1] | ./src:function_decl/src:name[1]", namespaces=ns)
        return n[0] if n else None


    def function_tags(self):   return ["function"]
    def lambda_tags(self):     return []
    def flow_exit_tags(self):  return ["return", "goto", "continue", "break"]
    def flow_exit_calls(self): return ["exit", "abort", "_exit", "_Exit"]
    def noop_statement_tags(self): return ["empty_stmt"]
    def class_tags(self): return []


    def source_call_args_propagate_to_return(self) -> bool:
        return False

    def taint_opaque_tags(self) -> list:
        return ["sizeof"]


    def is_reference_comparison(self, lhs_type, rhs_type) -> bool:
        return bool(lhs_type and rhs_type and "*" in lhs_type and "*" in rhs_type)


    def is_cast_type_name(self, name_node) -> bool:
        """'(char*)x', '(struct foo *)x': sequenza piatta '(' name+ '*'* ')'."""
        if _ntxt(name_node) in C_TYPE_WORDS:
            return True

        prev = name_node.getprevious()
        while prev is not None and _lname(prev) == "name":
            prev = prev.getprevious()
        if prev is None or _lname(prev) != "operator" or _ntxt(prev) != "(":
            return False

        nxt = name_node.getnext()
        while nxt is not None and _lname(nxt) == "name":
            nxt = nxt.getnext()
        stars = 0
        while nxt is not None and _lname(nxt) == "operator" and _ntxt(nxt) == "*":
            stars += 1
            nxt = nxt.getnext()

        # serve almeno un '*' (altrimenti '(buf)' sembrerebbe un cast) e la ')' finale
        return stars > 0 and nxt is not None and _lname(nxt) == "operator" and _ntxt(nxt) == ")"


    def is_true_constant(self, text: str) -> bool:
        '''anche 1 è una condizione sempre vera, quindi esegue l'override'''
        return text.strip() == "1" or super().is_true_constant(text)

    def is_false_constant(self, text: str) -> bool:
        return text.strip() == "0" or super().is_false_constant(text)


    _C_NUMERIC_WORDS = {"char","int","long","short","unsigned","signed","float","double",
                        "size_t","ssize_t","uint8_t","uint16_t","uint32_t","uint64_t",
                        "int8_t","int16_t","int32_t","int64_t","const","bool"}

    def is_numeric_type(self, type_text) -> bool:
        if not type_text or "*" in type_text or "[" in type_text:
            return False
        words = type_text.split()
        # 'char' da solo è un tipo scalare, ma 'char *' o 'char[]' no (già esclusi sopra)
        return bool(words) and all(w in self._C_NUMERIC_WORDS for w in words)

    def _chain_rhs(self, op, ns):
        nodes = _skip_leading_casts(op.xpath("./following-sibling::*", namespaces=ns))
        return nodes[0] if nodes else None


    _CPP_NS = {"cpp": "http://www.srcML.org/srcML/cpp"}
    def is_in_macro_definition(self, node) -> bool:
        return bool(node.xpath("ancestor::cpp:define", namespaces=self._CPP_NS))




# ---------------------------------------------------------------------- #
# Implementazione C++
# ---------------------------------------------------------------------- #
# C++ e' un'estensione di C: si eredita CAdapter e si sovrascrive solo cio' che
# cambia in srcML 1.1.0 (verificato su XML reali):
#   - nomi qualificati  <name><name>std</name><operator>::</operator><name>x</name></name>
#   - template          <argument_list type="generic"> dentro/accanto al <name>
#   - costruttori       <decl> con <argument_list> diretta (niente <init>): T x(a), T x{a}
#   - decl nelle condizioni  if (int r = f()), while (auto q = g())
#   - range-for         <init><decl>..<range>: <expr/></range></decl></init>  (oppure forma piatta)
#   - using / namespace alias / typedef, <cast type="static|...">, <lambda>, <constructor>,
#     <destructor>, <struct>, campi dentro <public>/<private>/<protected>

_SRC_NS = {"src": "http://www.srcML.org/srcML/src"}

# Tipi che compaiono nei cast e non esistono in C
_CPP_EXTRA_TYPE_WORDS = {"bool", "auto", "char16_t", "char32_t", "char8_t", "nullptr_t"}

_TEMPLATE_ARGS_RE = re.compile(r"<[^<>]*>")
_RAW_STRING_RE = re.compile(r'^(?:u8|u|U|L)?R"([^()\\\s]{0,16})\((.*)\)\1"$', re.DOTALL)
_STR_PREFIX_RE = re.compile(r'^(?:u8|u|U|L)(?=["\'])')


class CppAdapter(CAdapter):
    name = "cpp"

    # ------------------------------------------------------------------ #
    # Nomi: canonicalizzazione
    # ------------------------------------------------------------------ #

    def normalize_member_access(self, name: str) -> str:
        """Forma canonica usata da TUTTI i confronti del motore (call_matches, CallTable,
        CallMatcher): '->' e '::' diventano '.', sparisce il '::' iniziale (global scope),
        gli argomenti template e il prefisso 'std.'.
          std::system -> system     ::system -> system     p->open -> p.open
          std::cin.getline -> cin.getline     std::vector<int>::iterator -> vector.iterator"""
        if not name:
            return name
        name = name.replace("->", ".").replace("::", ".")
        while True:
            reduced = _TEMPLATE_ARGS_RE.sub("", name)
            if reduced == name:
                break
            name = reduced
        if name.startswith("."):
            name = name[1:]
        if name.startswith("std."):
            name = name[4:]
        elif name.startswith("*.std."):
            name = "*." + name[6:]
        return name

    def _name_parts(self, name_node) -> list:
        """Segmenti di un <name> (semplice o composto), SENZA argomenti template, indici
        e operatori. 'std::cin.getline' -> ['std','cin','getline']."""
        own = (name_node.text or "").strip()
        kids = [c for c in name_node if isinstance(c.tag, str)]
        child_names = [c for c in kids if _lname(c) == "name"]
        if not child_names:
            return [own] if own else []
        if own == "operator":                       # operator<name>==</name>
            return ["operator" + "".join(_ntxt(c) for c in child_names)]
        parts = []
        for c in kids:
            if _lname(c) == "name":
                parts.extend(self._name_parts(c))
        return parts

    def _canonicalize(self, name: str, imports) -> str:
        """Applica gli alias using/namespace al primo segmento (Str.x -> std.string.x)."""
        head, _, rest = name.partition(".")
        for b in imports or []:
            if b.is_macro or b.local_name != head:
                continue
            if b.node is None or _lname(b.node) not in ("using", "namespace"):
                continue
            return f"{b.canonical_name}.{rest}" if rest else b.canonical_name
        return name

    def resolve_name_text(self, text, imports):
        if not text:
            return text
        return self._canonicalize(self.normalize_member_access(text), imports)

    # ------------------------------------------------------------------ #
    # Dichiarazioni e tipi
    # ------------------------------------------------------------------ #

    def _decl_candidates(self, node, var_name, ns) -> list:
        """Dichiarazioni di var_name visibili da `node`, in ordine di priorita':
        scope funzione (locali + parametri), campi della classe, file/namespace scope."""
        v = var_name
        queries = [
            f"{self.scope_axis()}//src:decl[src:name[text()=$v]]",
            ("ancestor::*[" + " or ".join(f"self::src:{t}" for t in self.class_tags()) + "][1]"
             "/src:block/*/src:decl_stmt/src:decl[src:name[text()=$v]]"),
            ("ancestor::src:unit[1]//src:decl_stmt[not(ancestor::src:function or "
             "ancestor::src:constructor or ancestor::src:destructor or ancestor::src:lambda)]"
             "/src:decl[src:name[text()=$v]]"),
        ]
        for q in queries:
            found = node.xpath(q, namespaces=ns, v=v)
            if found:
                return found
        return []

    def _pick_decl(self, node, decls):
        key = _pos_key(node)
        before = [d for d in decls if _pos_key(d) <= key]
        return (before or decls)[-1]

    def _decl_type_node(self, decl, ns):
        """(type_node_con_nome, modificatori_propri) risalendo i <type ref="prev"/>."""
        t = decl.xpath("./src:type", namespaces=ns)
        if not t:
            return None, ""
        own_mods = " ".join(_ntxt(m) for m in t[0].xpath("./src:modifier", namespaces=ns))
        seen, cur = set(), decl
        while cur is not None and id(cur) not in seen:
            seen.add(id(cur))
            tt = cur.xpath("./src:type", namespaces=ns)
            if tt and tt[0].get("ref") != "prev":
                return tt[0], own_mods
            prev = cur.xpath("preceding-sibling::src:decl[1]", namespaces=ns)
            cur = prev[0] if prev else None
        return None, own_mods

    def _decl_type_text(self, decl, ns):
        """'const char *' ; per 'char *a, *b' il tipo di b e' 'char *' (modificatori propri)."""
        tnode, own_mods = self._decl_type_node(decl, ns)
        if tnode is None:
            return None
        if decl.xpath("./src:type", namespaces=ns)[0].get("ref") != "prev":
            return re.sub(r"\s+", " ", _ntxt(tnode))
        base = " ".join(_ntxt(c) for c in tnode if isinstance(c.tag, str) and _lname(c) != "modifier")
        return re.sub(r"\s+", " ", f"{base} {own_mods}").strip()

    def _decl_type_name(self, decl, ns):
        """Nome canonico del tipo ('ifstream', 'vector'); None per 'auto'/non risolvibile."""
        tnode, _ = self._decl_type_node(decl, ns)
        if tnode is None:
            return None
        tn = tnode.xpath("./src:name[1]", namespaces=ns)
        if not tn:
            return None
        parts = self._name_parts(tn[0])
        if not parts or parts == ["auto"]:
            return None
        return self.normalize_member_access(".".join(parts))

    def resolve_variable_type(self, name_node, var_name, ns) -> str | None:
        decls = self._decl_candidates(name_node, var_name, ns)
        if not decls:
            return None
        return self._decl_type_text(self._pick_decl(name_node, decls), ns)

    # ------------------------------------------------------------------ #
    # Import / alias / macro
    # ------------------------------------------------------------------ #

    def resolve_imports(self, unit_node, ns) -> list:
        # include + macro: identici a C
        bindings = super().resolve_imports(unit_node, ns)

        def dotted(n):
            return self.normalize_member_access(".".join(self._name_parts(n)))

        for u in unit_node.xpath(".//src:using", namespaces=ns):
            ns_decl = u.xpath("./src:namespace/src:name", namespaces=ns)
            if ns_decl:                                       # using namespace X;
                bindings.append(ImportBinding("*", dotted(ns_decl[0]), node=u))
                continue
            alias_type = u.xpath("./src:init/src:type/src:name", namespaces=ns)
            first = u.xpath("./src:name", namespaces=ns)
            if alias_type and first:                          # using Str = std::string;
                bindings.append(ImportBinding(dotted(first[0]), dotted(alias_type[0]), node=u))
            elif first:                                       # using std::string;
                canonical = dotted(first[0])
                bindings.append(ImportBinding(canonical.split(".")[-1], canonical, node=u))

        for n in unit_node.xpath(".//src:namespace[not(src:block)]", namespaces=ns):
            parts = n.xpath("./src:name", namespaces=ns)       # namespace fs = std::filesystem;
            if len(parts) == 2:
                bindings.append(ImportBinding(dotted(parts[0]), dotted(parts[1]), node=n))
        return bindings

    # ------------------------------------------------------------------ #
    # Nome delle chiamate
    # ------------------------------------------------------------------ #

    def resolve_call_name(self, call_node, ns, imports, _depth: int = 0) -> str:
        if _depth > 10:
            return None
        name_nodes = call_node.xpath("./src:name", namespaces=ns)
        if not name_nodes:
            return None
        parts = self._name_parts(name_nodes[0])
        if not parts:
            return None

        # call concatenate: a.b().c(x) -> <call/><operator>.</operator><call/>
        recv = self._chain_receiver(call_node, ns)
        if recv is not None:
            recv_name = self.resolve_call_name(recv, ns, imports, _depth + 1)
            if recv_name:
                return self.normalize_member_access(f"{recv_name}.{'.'.join(parts)}")

        if len(parts) == 1:
            return self._canonicalize(
                self.normalize_member_access(expand_macro_name(parts[0], macro_map(imports))), imports)

        if parts[0] == "std":
            parts = parts[1:]
        head = parts[0]
        # var.metodo / ptr->metodo: se head e' una variabile dichiarata, usa il TIPO
        if len(parts) >= 2:
            decls = self._decl_candidates(call_node, head, ns)
            if decls:
                tname = self._decl_type_name(self._pick_decl(call_node, decls), ns)
                if tname:
                    return self._canonicalize(
                        self.normalize_member_access(f"{tname}.{'.'.join(parts[1:])}"), imports)
        return self._canonicalize(self.normalize_member_access(".".join(parts)), imports)

    # ------------------------------------------------------------------ #
    # Assegnazioni
    # ------------------------------------------------------------------ #

    def potential_assignment_xpath(self) -> str:
        return (".//src:expr_stmt | .//src:decl_stmt | .//src:control[parent::src:for]"
                " | .//src:condition/src:decl"
                " | .//src:init[parent::src:control]/src:decl[not(src:range)]")

    def _expr_stmt_lhs_rhs(self, node, ns):
        op = node.xpath("./src:expr/src:operator[text()='='][1]", namespaces=ns)
        if not op:
            return None, None
        op = op[0]
        lhs_all = op.xpath("./preceding-sibling::*[not(self::src:comment)]", namespaces=ns)
        rhs_all = _skip_leading_casts(op.xpath("./following-sibling::*", namespaces=ns))
        if not lhs_all or not rhs_all:
            return None, None
        lhs = lhs_all[-1]
        # 'auto [k, v] = pair;' (structured binding): non e' un'assegnazione a 'auto'
        if len(lhs_all) >= 2 and _lname(lhs) == "index" and _ntxt(lhs_all[-2]) == "auto":
            return None, None
        # '*p = x' scrive il pointee, non la variabile p. ('auto* o = ...' invece e' una
        # dichiarazione: il '*' e' preceduto da un nome-tipo)
        before = lhs.getprevious()
        if before is not None and _lname(before) == "operator" and _ntxt(before) == "*":
            bb = before.getprevious()
            if bb is None or _lname(bb) == "operator":
                return None, None
        return lhs, rhs_all[0]

    def _decl_lhs_rhs(self, decl, ns):
        """LHS/RHS di un <decl>: 'T x = e' | 'T x(a)' | 'T x{a, b}'."""
        lhs = decl.xpath("./src:name[1]", namespaces=ns)
        if not lhs:
            return None, None
        rhs = decl.xpath("./src:init/src:expr | ./src:init/src:decl", namespaces=ns)
        if rhs:
            return lhs[0], rhs[0]
        args = decl.xpath("./src:argument_list", namespaces=ns)
        if args:
            single = args[0].xpath("./src:argument[count(../src:argument)=1]/src:expr", namespaces=ns)
            return lhs[0], (single[0] if single else args[0])
        return None, None

    def _range_for_lhs_rhs(self, control, ns):
        decl = control.xpath("./src:init/src:decl[src:range]", namespaces=ns)
        if decl:                                            # for (T x : v)
            lhs = decl[0].xpath("./src:name[1]", namespaces=ns)
            rhs = decl[0].xpath("./src:range/src:expr[1]", namespaces=ns)
            return (lhs[0], rhs[0]) if lhs and rhs else (None, None)
        # forma piatta: <init><expr>auto & x : v</expr></init>
        colon = control.xpath("./src:init/src:expr/src:operator[text()=':'][1]", namespaces=ns)
        if not colon:
            return None, None
        before = colon[0].xpath("./preceding-sibling::*[not(self::src:comment)]", namespaces=ns)
        after = colon[0].xpath("./following-sibling::*[not(self::src:comment)]", namespaces=ns)
        if not before or not after or _lname(before[-1]) != "name":
            return None, None                               # structured binding: ignorato
        return before[-1], after[0]

    def is_assignment(self, node, ns) -> bool:
        lhs, rhs = self.get_assignment_lhs_rhs(node, ns)
        return lhs is not None and rhs is not None

    def get_assignment_lhs_rhs(self, node, ns):
        tag = _lname(node)
        if tag == "expr_stmt":
            return self._expr_stmt_lhs_rhs(node, ns)
        if tag == "decl_stmt":
            # primo dichiaratore con inizializzatore/argomenti: 'int a, b = f();' -> b
            for d in node.xpath("./src:decl", namespaces=ns):
                lhs, rhs = self._decl_lhs_rhs(d, ns)
                if lhs is not None:
                    return lhs, rhs
            return None, None
        if tag == "decl":
            return self._decl_lhs_rhs(node, ns)
        if tag == "control":
            return self._range_for_lhs_rhs(node, ns)
        return None, None

    # ------------------------------------------------------------------ #
    # Letterali
    # ------------------------------------------------------------------ #

    def string_concat_operators(self) -> list:
        return ["+"]                    # std::string + ...

    def string_formatting_operator_roles(self) -> dict:
        return {"concat": "+"}

    def is_none_literal(self, text: str) -> bool:
        return text.strip() in ("NULL", "nullptr")

    def parse_numeric_literal(self, text: str):
        return super().parse_numeric_literal(text.replace("'", ""))   # separatori 1'000

    def normalize_string_literal(self, text: str) -> str:
        t = text.strip()
        m = _RAW_STRING_RE.match(t)
        if m:
            return m.group(2)
        t = _STR_PREFIX_RE.sub("", t)   # solo se seguito da apice: non tocca 'Lib', 'uid'...
        if len(t) >= 2 and t[0] in "\"'" and t[-1] == t[0]:
            t = t[1:-1]
        return t

    # ------------------------------------------------------------------ #
    # Operatori
    # ------------------------------------------------------------------ #

    def logical_and_operator(self) -> list:
        return ["&&", "and"]

    def logical_or_operator(self) -> list:
        return ["||", "or"]

    def get_parameter_name_and_type(self, param_node, namespaces):
        decl = param_node.xpath("./src:decl[1]", namespaces=namespaces)
        if not decl:
            return None, None
        type_text = self._decl_type_text(decl[0], namespaces) or ""
        n = decl[0].xpath("./src:name[1]", namespaces=namespaces)
        return (name_text(n[0]) if n else ""), type_text

    # ------------------------------------------------------------------ #
    # Taint
    # ------------------------------------------------------------------ #

    def taint_block_functions(self) -> list:
        return ["strlen", "atoi", "atol", "atoll", "atof", "strcmp", "strncmp",
                "stoi", "stol", "stoll", "stoul", "stoull", "stof", "stod",
                "*.size", "*.length", "*.empty", "*.compare", "*.count"]

    def taint_propagating_calls(self) -> dict:
        def out(*idx): return {"out": list(idx)}
        recv = {"out_receiver": True}                 # x.append(t) rende taintato x
        table = {
            "sprintf": out(0), "snprintf": out(0), "_snprintf": out(0), "vsnprintf": out(0),
            "strcpy": out(0), "strncpy": out(0), "strcat": out(0), "strncat": out(0),
            "memcpy": out(0), "memmove": out(0),
            "wcscpy": out(0), "wcsncpy": out(0), "wcscat": out(0), "wcsncat": out(0),
            "wmemcpy": out(0), "swprintf": out(0), "_snwprintf": out(0),
            "sscanf": {"in": [0], "out_variadic_from": 2},
            "swscanf": {"in": [0], "out_variadic_from": 2},
        }
        for m in ("append", "assign", "push_back", "push_front", "insert",
                  "emplace", "emplace_back", "replace"):
            table[f"*.{m}"] = recv
        return table

    def taint_source_output_args(self) -> dict:
        table = dict(super().taint_source_output_args())
        table.update({
            # std::getline(stream, out) -> out e' l'indice 1; getline POSIX -> indice 0
            "getline": {"indices": [0, 1]},
            # istream::getline(buf, n) / istream::read(buf, n): il buffer e' l'indice 0.
            # Le chiavi 'cin.*' servono perche' _rule_pre accoppia sorgente (catalogo) e chiave
            # della tabella con call_matches(chiave, sorgente): 'cin.getline' deve esistere
            # come chiave per attivare la sorgente 'cin.getline' del catalogo.
            "cin.getline": {"indices": [0]},
            "cin.read": {"indices": [0]},
            "*.getline": {"indices": [0]},
            "*.read": {"indices": [0]},
            "*.readsome": {"indices": [0]},
            "fgetws": {"indices": [0], "return_tainted": True},
            "wscanf": {"variadic_from": 1},
            "fwscanf": {"variadic_from": 2},
            "swscanf": {"variadic_from": 2},
        })
        return table

    def taint_opaque_tags(self) -> list:
        return ["sizeof", "alignof", "decltype", "typeid", "noexcept"]

    def extract_output_buffer_name(self, arg_node, ns) -> str | None:
        """Come la base, ma salta i qualificatori di namespace ('std' in std::cin) e i nomi
        negli argomenti template, altrimenti 'std' risulterebbe una variabile taintata."""
        skip = ["ancestor::src:index", "ancestor::src:type",
                "ancestor::src:argument_list[@type='generic']"]
        skip += [f"ancestor::src:{t}" for t in self.taint_opaque_tags()]
        skip_xpath = " | ".join(skip)
        for n in arg_node.xpath(".//src:name[not(src:name)]", namespaces=ns):
            if n.xpath(skip_xpath, namespaces=ns):
                continue
            nxt = n.getnext()
            if nxt is not None and _lname(nxt) == "operator" and _ntxt(nxt) == "::":
                continue
            if self.is_cast_type_name(n):
                continue
            txt = name_text(n)
            if txt:
                return txt
        return None

    def is_cast_type_name(self, name_node) -> bool:
        """static_cast<char*>(x): 'char' sta in <argument_list type="generic"> -> tipo."""
        if name_node.xpath("ancestor::src:argument_list[@type='generic']", namespaces=_SRC_NS):
            return True
        if _ntxt(name_node) in _CPP_EXTRA_TYPE_WORDS:
            return True
        return super().is_cast_type_name(name_node)

    # ------------------------------------------------------------------ #
    # Condizioni / membership / eccezioni
    # ------------------------------------------------------------------ #

    def extract_membership_relations(self, condition_node, ns) -> list[dict]:
        """set.contains(x) / set.count(x) (anche negati: !s.count(x), s.count(x) == 0)."""
        relations = []
        calls = condition_node.xpath(
            ".//src:call[src:name/src:name[last()][text()='contains' or text()='count']]",
            namespaces=ns)
        for call in calls:
            recv = call.xpath("./src:name/src:name[last()-1]", namespaces=ns)
            arg = call.xpath("./src:argument_list/src:argument/src:expr/*[1]", namespaces=ns)
            if not recv or not arg:
                continue
            prev = call.xpath("preceding-sibling::*[not(self::src:comment)][1]", namespaces=ns)
            negated = bool(prev) and _lname(prev[0]) == "operator" and _ntxt(prev[0]) == "!"
            nxt = call.xpath("following-sibling::*[not(self::src:comment)][position()<=2]", namespaces=ns)
            if len(nxt) == 2 and _lname(nxt[0]) == "operator" and _ntxt(nxt[1]) == "0":
                op = _ntxt(nxt[0])
                if op == "==":
                    negated = True                     # count(x) == 0
                elif op in ("!=", ">"):
                    negated = False
            relations.append({"lhs": arg[0], "rhs": recv[0], "is_negated": negated})
        return relations

    def is_collection_assignment(self, assignment_node, ns) -> bool:
        if super().is_collection_assignment(assignment_node, ns):      # T v = {1,2}
            return True
        for al in assignment_node.xpath(".//src:decl/src:argument_list", namespaces=ns):
            if _ntxt(al).startswith("{"):                              # T v{1,2}
                return True
        return False

    def find_exception_bindings(self, tree, ns) -> list:
        bindings = []
        for catch in tree.xpath(".//src:catch", namespaces=ns):
            names = catch.xpath("./src:parameter_list/src:parameter/src:decl/src:name[1]", namespaces=ns)
            if not names:                       # catch (...) / catch (const T&) senza nome
                continue
            block = catch.xpath("./src:block[1]", namespaces=ns)
            if block:
                bindings.append((name_text(names[0]), block[0]))
        return bindings

    # ------------------------------------------------------------------ #
    # Tag srcML
    # ------------------------------------------------------------------ #

    def function_tags(self):   return ["function", "constructor", "destructor"]
    def lambda_tags(self):     return ["lambda"]
    def flow_exit_tags(self):  return ["return", "throw", "goto", "continue", "break"]
    def flow_exit_calls(self): return ["exit", "abort", "_exit", "_Exit", "quick_exit", "terminate"]
    def class_tags(self):      return ["class", "struct", "union"]


    
# ---------------------------------------------------------------------- #
# Registro / dispatch
# ---------------------------------------------------------------------- #

ADAPTERS = {
    "python": PythonAdapter(),
    "java": JavaAdapter(),
    "c": CAdapter(),
    "c++": CppAdapter(), #DA VALIDARE
}

def get_adapter(unit_node) -> LanguageAdapter:
    """Sceglie l'adapter leggendo l'attributo language="..." che srcML scrive
    su ogni <unit> (es. language="Python", language="Java", language="C").
    """
    raw = unit_node.get("language")
    if not raw:
        raise ValueError(f"<unit> senza attributo language (file: {unit_node.get('filename')}). "
                         "Rigenera l'XML con srcML indicando --language.")
    adapter = ADAPTERS.get(raw.lower())
    if adapter is None:
        raise NotImplementedError(f"Nessun adapter per '{raw}'. Disponibili: {sorted(ADAPTERS)}")
    return adapter