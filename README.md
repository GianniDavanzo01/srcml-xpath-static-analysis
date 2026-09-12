## Struttura del Progetto

Il repository è organizzato nelle seguenti directory principali:

* **`script_analysis/`**: Contiene gli script python per il funzionamento del motore di analisi statica.
* **`Ruleset/`**: Archivia i file JSON contenenti le regole di sicurezza.
* **`Testset/`**: Raccoglie i dataset e gli snippet di codice sorgente Python vulnerabile e sicuro, utilizzati per validare l'efficacia del motore.
* **`xml_archivi/`**: Contiene le rappresentazioni AST (Abstract Syntax Tree) in formato XML generate da srcML a partire dal codice Python.
* **`Result/`**: Archivia i report e i risultati finali generati dal motore al termine dell'analisi statica.

## Come eseguire il motore di analisi

Il motore si avvia da riga di comando richiamando lo script principale `srcml_engine.py`. 

Dal terminale, lancia il seguente comando sostituendo i segnaposto `< >` con i percorsi effettivi ai tuoi file:

```bash
python srcml_engine.py --xml <percorso/al/file.xml> --rules <percorso/cartella_regole/> -o <percorso/output.json>
```
## Dataset e Fonti di Test

Per l'esecuzione dei test del motore di analisi, le regole sono state validate su snippet di codice estratti da dataset e progetti open-source. 

I casi di test presenti nella cartella `Testset/` derivano dalle seguenti repository:

* **[DeVAIC](https://github.com/dessertlab/DeVAIC/tree/main)**
* **[PoisonPy](https://github.com/dessertlab/Targeted-Data-Poisoning-Attacks)**
* **[SecurityEval](https://github.com/s2e-lab/SecurityEval)**

