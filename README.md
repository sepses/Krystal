# KRYSTAL: Knowledge Graph-based Framework for Tactical Attack Discovery in Audit Data
## What is Krystal?
KRYSTAL is a modular framework for tactical attack discovery in audit data. The proposed framework integrates a variety of attack discovery mechanisms and takes advantage of its semantic model to include internal and external knowledge in the analysis. 
## Krystal Components

![ ](https://raw.githubusercontent.com/kabulkurniawan/Krystal/main/architecture-latest3.png)<p align="center"> **Figure 1** Krystal Architecture.

Figure 1 gives an overview of the KRYSTAL attack discovery framework which consists of three main components, i.e., *(i) provenance graph building, (ii) threat detection and alerting, and (iii) attack graph and scenario reconstruction*. Each component may leverage background knowledge to contextualize, link, and enrich the graph over both internal and external cybersecurity information (e.g. IT Assets, Vulnerabilities, CTI, etc.)

KRYSTAL imports each log event (currently Audit Data) in sequence from potentially heterogeneous hosts (e.g., Linux, Windows, FreeBSD), i.e., in an online mode. It then generates an RDF-based provenance graph, taking advantage of the defined ontology (i.e. [Krystal Ontology](https://sepses.ifs.tuwien.ac.at/vocab/event/log/index-en.html)) and background knowledge (e.g. [SEPSES CS-KG](http://sepses.ifs.tuwien.ac.at/)) in the *"Provenance Graph Building"* module. Subsequently, several threat detection and alerting approaches can be applied to the provenance graphs in the *"Threat Detection and Alerting Module"*, including:
 (i) tag propagation, 
 (ii) attenuation & decay, and 
 (iii) signature-based detection based on Indicators of Compromise (IoCs), e.g. through [Sigma Rule](https://github.com/SigmaHQ/sigma).
 *The "Attack Graph Reconstruction"* module then facilitates (offline) attack graph generation via several graph construction techniques, including 
 (i) Backward-forward chaining and 
 (ii) attack pattern matching via Graph Querying 
 over the provenance graph. 

## Requirements
Krystal Framework is built based on the Java Application Platform that can be deployed in most OS with a JVM. Therefore, it requires a JVM to be installed on the system beforehand. Please follow this [documentation](https://www.oracle.com/java/technologies/downloads/) to download and run the JVM.
Furthermore, An RDF-graph database with a built-in SPARQL Query will also be required to store the output RDF data, perform data/attack analysis, i.e. *attack graph construction and graph queries* as well as to *visualize* the resulting graph. For example, we used Stardog and Graph DB for example during our experiment. For GraphDB Installation, please follow this [installation page](https://graphdb.ontotext.com/documentation/standard/installation.html). For Stardog, please follow this [documentation](https://docs.stardog.com/). 

## Dataset for Testing and Evaluation
Krystal currently only supports audit data, especially from well-established datasets from red vs. blue team adversarial engagements produced as part of the third Transparent Computing (TC) program organized by [DARPA](https://drive.google.com/drive/folders/1QlbUFWAGq3Hpl8wVdzOdIoZLFxkII4EK). The datasets are organized into five categories, namely Cadets, Trace, Theia, FiveDirections, and ClearScope. We include several examples of the dataset under the directory [experiment/input](https://github.com/sepses/Krystal/tree/main/experiment/input).

## Installation and Configuration

## Installation

This project can be set up by cloning and installing and running it as follows:

```bash
$ git clone https://github.com/sepses/Krystal.git
$ cd Krystal
$ mvn clean install
```

### Configuration
Some configurations should be made prior to running the application. We include some explanations directly in the configuration comments. Please take a look at it ([config.yaml](https://github.com/sepses/Krystal/blob/main/config.yaml)). 


```bash
#----------------------------- BASIC CONFIGURATION --------------------------------------
#Log-sources input directory, see the dataset example (cadets,trace,theia,fivedirections) 
input-dir: experiment/input/cadets/

#Minimum log line number to be processed (minimum 1)
line-number: 100000

#Save the output in RDF and .HDT (yes/no)
backup-file: no

#Output directory, any output file (.rdf/hdt) will be stored in this folder 
output-dir: experiment/output/

#----------------------------- TARGETED TRIPLE STORE AND NAMEGRAPH ------------------------
#Option for storing output data to the triplestore continuously (yes/no)
live-store: no

#Triple Store type (e.g., graphdb, virtuoso)
triple-store: graphdb

#Endpoint for storing rdf output to triple Store
sparql-endpoint: http://localhost:7200/repositories/cadets

#Namegraph of the RDF graph on the triplestore (the output filename will be generated based on this namegraph
namegraph: http://w3id.org/sepses/graph/cadets

#----------------------------- SYSTEM SETTING -------------------------------------------
#Jena TDB directory, this directory is required for storing jena TDB temporary file
tdb-dir: experiment/tdb

#Directory for Krystal Ontology 
ontology: experiment/ontology/log-ontology.ttl

#OS platform of the log sources, (e.g. ubuntu14 for cadets, trace ; freebsd for theia ; windows for fivedirections)
os-platform: ubuntu14

#----------------------------- THREAT DETECTION TECHNIQUES -------------------------------
#List of possible threat detection techniques, set to "true" to apply otherwise set to "false"
tag-propagation: true 

#Setting tag-attenuation into true requires tag-propagation to be true 
tag-attenuation: true
ab: 0.2 #attenuation value for benign
ae: 0.1 #attenuation value for suspect  

#Setting tag-decay into true requires tag-propagation to be true 
tag-decay: true
period: 0.25 #decay half live (second)
tb: 0.75 #quiescent tag values for benign
te: 0.45 #aquiescent tag values for suspect

#Setting policy-based-rule into true requires tag-propagation and tag-attenuation-decay to be true 
policy-based-rule: true

#Signature base detection, currently it only supports rule detection from Sigma Rule 
signature-based-rule: true 

#Sigma rule directory for linux 
rule-dir : experiment/rule/

#Sigma rule directory for windows
rule-dir-win : experiment/rule_win/ 

#----------------------------- CONFIDENTIAL DIRECTORY -------------------------------
#List of any confidential directory on the targetted hosts / logsources 
#These will be used as  initialization of confidentiality score in tag-propagation technique during provenance graph building)
confidential-dir:
 - /etc/passwd
 - /var/log
 - /etc/shadow
 - /documents/

 #----------------------------- AUDIT EVENTS-----------------------------------------
#List of any events from audit data that need to be included in the provenance graph building. 
#Event filter for log processing (filter only the uncommented events (event with #))
field-filter:
 #- EVENT_FORK
 - EVENT_EXIT
 - EVENT_MPROTECT
 - EVENT_LOGIN
 #- EVENT_CLONE
 #- EVENT_LOADLIBRARY
 #- EVENT_EXECUTE
 - EVENT_ACCEPT
 - EVENT_RECVMSG
 - EVENT_SENDMSG
 #- EVENT_SENDTO
 #- EVENT_MODIFY_FILE_ATTRIBUTES
....
```

### Running the Application:

To run the compiled project: 

```bash
$ java -jar java -jar ./target/Krystal-1.1.0-jar-with-dependencies.jar
```
The log processing will take a couple of times depending on the size of the input data. After processing the input data, several output files will be produced, such as the dependency (provenance) graphs (in RDF/.ttl file), the alert data (in RDF-star/.ttl), and the compressed version of the RDF graph (in .hdt). We provided several example RDF output (in RDF and .HDT) file under the directory [experiment/output](https://github.com/sepses/Krystal/tree/main/experiment/output). 


## Running Example
See the example process below:

```bash
$ java -jar java -jar ./target/Krystal-1.1.0-jar-with-dependencies.jar
    __ __                 __        __   ______                                             __
   / //_/_______  _______/ /_____ _/ /  / ____/________ _____ ___  ___ _      ______  _____/ /__
  / ,<  / ___/ / / / ___/ __/ __ `/ /  / /_  / ___/ __ `/ __ `__ \/ _ \ | /| / / __ \/ ___/ //_/
 / /| |/ /  / /_/ (__  ) /_/ /_/ / /  / __/ / /  / /_/ / / / / / /  __/ |/ |/ / /_/ / /  / ,<
/_/ |_/_/   \__, /____/\__/\__,_/_/  /_/   /_/   \__,_/_/ /_/ /_/\___/|__/|__/\____/_/  /_/|_|
           /____/


Start running ubuntu14 parser...
Appled Techniques:
- Tag-Propagation: true
- Tag-Attenuation: true
- Tag-Decay: true
- Policy-Rule: true
- Signature-Rule: true
processing file: cadets100000.json
reading from line : 1
parsing 1 of 100000 finished in 9679
Total Time: 10194338400
the rest is less than 100000 which is 3
Total Time: 10195279400
finish processing file:experiment/input/cadets/cadets100000.json
generate alert from community ruleexperiment/rule/
number of events :94050
Statictics:
http://w3id.org/sepses/resource/rule/corrupt-file-rule : 6
http://w3id.org/sepses/resource/rule/change-permission-rule : 20
http://w3id.org/sepses/resource/sigma/sigma-444ade84-c362-4260-b1f3-e45e20e1a905 : 1
```
## Analyzing / Querying the Graph
The resulting output data (the RDF data) can already be queried for analysis e.g. for root cause analysis, attack graph reconstruction (via graph query or forward chaining technique), etc. The directory [experiment/query](https://github.com/sepses/Krystal/tree/main/experiment/query) contains several example queries that can be used for analysis. Figure 2 shows an example output of attack graph construction using *backward-forward* chaining technique. 

![ ](https://raw.githubusercontent.com/kabulkurniawan/Krystal/main/cadets_03.png)<p align="center"> **Figure 2** Attack Graph Construction Output Example.

**Nginx backdoor w/ Drakon in-memory** (FreeBSD/Cadets). *The attack begins with a vulnerable Nginx installed on a FreeBSD host that gets exploited by an attacker. The attacker sends a malformed HTTP request that results in downloading several malicious files on the local system. One of the files i.e. /tmp/pEja72mA then gets executed, which spawns a process pEja72mA. This process reads sensitive information/etc/passwd) and connects remotely via C&C to the attacker console*.

## License

The Krystal Framework is written by [Kabul Kurniawan](https://kabulkurniawan.github.io/) and released under the [MIT license](http://opensource.org/licenses/MIT).

