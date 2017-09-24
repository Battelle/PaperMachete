     ____                        __  __            _          _            ________
    |  _ \ __ _ _ __  ___ _ __  |  \/  | __ _  ___| |__   ___| |_ ___     /_______/
    | |_) / _` | '_ \/ _ \ '__| | |\/| |/ _` |/ __| '_ \ / _ \ __/ _ \    \_______\
    |  __/ (_| | |_)|  __/ |    | |  | | (_| | (__| | | |  __/ ||  __/    /_______/
    |_|   \__,_| .__/\___|_|    |_|  |_|\__,_|\___|_| |_|\___|\__\___|   @==|;;;;;;>
               |_|

## About
Paper Machete (PM) orchestrates [Binary Ninja](https://binary.ninja) and [Grakn.ai](https://grakn.ai) to aid static binary analysis for the purpose of finding bugs in software. PM leverages the Binary Ninja MLIL SSA to extract semantic meaning about individual instructions, operations, register/variable state, and overall control flow.

PM migrates this data into Grakn - a knowledge graph that gives us the ability to define domain-specific ontologies for data and write powerful inference rules to form relationships between data we don't want to (or can't) explicitly store. [Heeh, how neat is that](https://www.youtube.com/watch?v=Hm3JodBR-vs)?

Currently, the public release of PM is exceptionally juvenile, and not for the faint of heart. You have been warned (and stuff). You will encounter issues and limitations which we are actively working towards resolving.

This project was released in conjunction with a DerbyCon 2017 talk titled "Aiding Static Analysis: Discovering Vulnerabilities in Binary Targets through Knowledge Graph Inferences." 

## Why BNIL?
The BNIL suite of ILs is easy to work with, plesantly verbose, and human-readable. At any point we can decide to leverage other levels and forms of the IL with little development effort on our part. When you add to that the ability to [lift multiple architectures](https://binary.ninja/faq/) and [write custom lifters](https://github.com/joshwatson/binaryninja-msp430), we have little reason not to use BNIL.

## Why Grakn?
Grakn's query language (Graql) is easy to learn and intuitive, which is extremely important in the early stages of this research while we're still hand-writing queries to model the patterns vulnerability reasearchers look for when performing static analysis. 

The ability to write our own domain-specific ontologies lets us quickly experiment with new query ideas and ways of making our queries less complex. When we run into a case where we think "gee, if I just had access to the relationship between..." we can modify our ontology and inference rules to get that information.

While the end game for PM is to eliminate the need for human-written queries, the fact is we're starting from square one. Which means hand-jamming a lot queries to model the patterns human vulnerability researchers look for when bug hunting.


## Dependencies
Paper Machete requires [BinaryNinja v1.1](https://binary.ninja), [Grakn v0.16.0](https://github.com/graknlabs/grakn/releases/tag/v0.16.0), the [Grakn Python Driver](http://github.com/graknlabs/grakn-python), and the [Java JRE](http://www.oracle.com/technetwork/java/javase/downloads/index.html)

## Setup
1. Install Python-3.6 (the Grakn Python driver requires it) and Grakn-Python
```bash
sudo add-apt-repository ppa:jonathonf/python-3.6
sudo apt-get update
sudo apt-get install python3.6
git clone https://github.com/graknlabs/grakn-python
cd grakn-python
sudo python3.6 setup.py install
```

2. Add Binaray Ninja's python directory to your Python path by adding the following to `~/.profile`.
`export PYTHONPATH=$PYTHONPATH:[PATH/TO/binaryninja/python]` then run `source ~/.profile`.

3. Install Java
```bash
sudo apt-get update
sudo apt-get install default-jre
```

4. Update the 'config' file to reflect install location of Grakn.
```
[PATH]
Grakn=/FULL/PATH/TO/GRAKN
(NOTE: Currently using ~/ does not work, please use /home/username instead)
```

5. (Optional) Open Binary Ninja then navigate to *edit -> preferences* and ensure the update channel is set to 1.1 and check the box for "Enable plugin developement debugging mode." (this will let you view MLIL SSA in the UI).

## Usage
The `paper_machete.py` script handles generating and migrating `.graql` files into Grakn and running CWE queries. The current options are:

`[1]` Run's all scripts in `/cwe_queries` against the default Grakn keyspace ("Grakn"). This requires Grakn to be started before use.

`[2]` Runs a user-specified script in `/cwe_queries` against the "Grakn" keyspace.

`[3]` Invokes `pm_analyze.py` to create a `.graql` file for the specified binary.

`[4]` Cleans and restarts Grakn before uploading the specified `.graql` file.

`[5]` Exits the program.

While `paper_machete.py` will do a lot of this stuff automatically, you can certainly run the underlying processes yourself. The process typically goes something like this:

1. Start Grakn with `/<grakn_dir>/bin/grakn.sh start`
2. Analyze a binary `/<pm_dir>/pm_analyze.py somebinary`
3. Insert the data (sombinary.graql) into a Grakn keyspace `/<grakn_dir>/bin/graql.sh -f somebinary.graql -k grakn`
4. Run the queries in `/cwe_queries` (currently configured to run only against the "Grakn" keyspace name)

Want to see your data? Visit `http://127.0.0.1:4567/` and run the query `match $f isa function;`. This will show all functions. Left-click and hold to display a contextual menu where you can display data on the visible nodes. Double-click on nodes to display all related children. Continue this process to drill down into your data. 

For more control, we suggest using the Python Grakn Driver which is currently only available for Python3.6.

## Query Scripts
We've included some basic queries to get you started if you want to play around with PM. As you can imagine, there is no "silver bullet" query that will find all manifestations of a specific vulnerability class. Because of this, we've included versions for each CWE query. As we add new methods of finding the same CWE, we'll add scripts with incremented the version numbers to differentiate. 

`cwe_120_v1.py` - Tests for use of unsafe 'gets()' function ([CWE-120](https://cwe.mitre.org/data/definitions/120.html))

`cwe_121_v1.py` - Tests for buffer overflows ([CWE-121](https://cwe.mitre.org/data/definitions/121.html))

`cwe_129_v1.py` - Tests for missing bounds checks ([CWE-129](https://cwe.mitre.org/data/definitions/129.html))

`cwe_134_v1.py` - Tests for format string vulerabilities ([CWE-134](https://cwe.mitre.org/data/definitions/134.html))

`cwe_788_v1.py` - Tests for missing bounds check on array indexes ([CWE-788](https://cwe.mitre.org/data/definitions/788.html))


## Limitations
* PM requires the ability to run Binary Ninja in headless mode, which is only available with the commercial version. We'll add a UI plugin in the near future that will allow personal/student Binary Ninja license holders to use PM.

* Our current data migration strategy (dump a .graql and YOLO) is flawed, and will trigger the Java memory overhead limit when migrating complex binaries. We're actively working on the required Grakn templates to leverage Grakn's `migration.sh` interface. This will let us migrate the amount of data we need without issues. Unfortunately this means we lose some ability to quickly change the ontology on a whim without possibly requiring changes to these migration templates. Basically, we're working on it.


## Planned Features
* We're completely overhauling the data migration process to leverage Grakn's Migration interface. This means you won't get anymore Java memory overhead issues with complex binaries. Hallelujah!
* A Binja UI plugin is planned that will work with Student/Personal licenses.
* Increasing performance of data collection. This process can be very slow on some systems, especically during instruction AST parsing of complex binaries!
* Allowing demangled names to be passed to `pmanalyze.py` when specifiying fuctions to analyze. Right now you have to supply the mangled name, which is annoying.
* So much more...

## Troubleshooting Issues
Error when running cwe test scripts (option 1)
  * Errors here are usually a result of problems when creating or injesting the `.graql` files. 

Failure to build `.graql` file (option 3)

>AttributeError: 'NoneType' object has no attribute 'functions'
  * This is usually caused when PM can't find the right file. Check your spelling and the path of the file.

Error when ingesting `.graql` files (option 4)
  * When Grakn returns control to `paper_machete.py` before it finishes starting a large error is thrown. Generally trying the injest a few more times will solve the issue. This issue is in Grakn's code, but we are actively searchcing for a solution.

| Large Ingesting Error | Small Ingesting Error |
| :----: | :----: |
| ![Large Ingestion Error](/img/grakn_crash.png) | ![Small Ingestion Error](/img/grakn_crash_2.png) |


Websocket closed (option 4)
  * Most errors like this mean Grakn is not running properly. Try restarting Grakn.
  * Restart Grakn with (run from garkn-dist folder): `./bin/grakn.sh clean` `./bin/grakn.sh start`
  
