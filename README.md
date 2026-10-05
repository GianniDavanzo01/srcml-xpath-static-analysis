## Struttura del Progetto

* **`script_analysis/`**: Script Python del motore di analisi statica e dell'orchestrazione (Engine, Adapter di linguaggio e Context).
* **`cataloghi/`**: File JSON dei cataloghi (`java_catalog.json`, `python_catalog.json`, `c_catalog.json`). Sono dizionari di traduzione che mappano i concetti astratti di sicurezza (sorgenti, sink, sanitizer, safe-context) sulle funzioni e librerie dei singoli linguaggi. Nome file obbligatorio: `<linguaggio>_catalog.json`.
* **`regole/`**: Ruleset semantico e astratto (CWE), indipendente dal linguaggio (es. `ruleset_abstract.json`). Può contenere uno o più file `.json`, ciascuno con un array di regole.
* **`Testset/`**: Dataset e snippet di codice sorgente usati per validare il motore.
* **`xml_archivi/`**: Rappresentazioni AST in XML generate da srcML a partire dal codice sorgente originale.
* **`Result/`**: Report finali generati dal motore, in JSON strutturato.

> ⚠️ **Se `--rules` punta a una cartella**, questa non deve contenere i cataloghi:
> il motore carica tutti i `*.json` che trova aspettandosi array di regole, e un catalogo (oggetto JSON) provocherebbe un errore. Con `--rules` su un singolo file non c'è alcun vincolo. Per tenere l'ordine, è comunque consigliato separare regole/` e `cataloghi/`.

## Come eseguire il motore di analisi

```bash
python srcml_engine.py \
    --xml <percorso/al/file.xml> \
    --rules <file_regole.json | cartella_regole/> \
    --catalog-dir <cartella_cataloghi/> \
    -o <percorso/output.json>
```

| Opzione | Descrizione |
|---|---|
| `--xml` | Uno o più file `.xml` generati da srcML |
| `--xml-dir` | Cartella con più file `.xml` da analizzare in batch |
| `--rules` | Singolo file JSON di regole **oppure** cartella con più file `.json` |
| `--catalog-dir` | Cartella dei cataloghi `<linguaggio>_catalog.json`. Se omessa, usa la cartella dello script. Se --rules è una cartella, deve essere diversa da questa |
| `-o`, `--output` | File JSON di output (default: stdout) |


## Dataset e Fonti di Test

Per l'esecuzione dei test del motore di analisi, le regole sono state validate su snippet di codice estratti da dataset e progetti open-source. 

I casi di test presenti nella cartella `Testset/` derivano dalle seguenti repository:

* **[DeVAIC](https://github.com/dessertlab/DeVAIC/tree/main)**
* **[PoisonPy](https://github.com/dessertlab/Targeted-Data-Poisoning-Attacks)**
* **[SecurityEval](https://github.com/s2e-lab/SecurityEval)**

