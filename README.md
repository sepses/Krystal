# Krystal Framework
KRYSTAL is a modular framework for tactical attack discovery in audit data. The proposed framework integrates a variety of attack discovery mechanisms and takes advantage of its semantic model to include internal and external knowledge in the analysis. Figure 1 gives an overview of the KRYSTAL attack discovery framework which consists of three main parts, i.e., (i) provenance graph building, (ii) threat detection and alerting, and (iii) attack graph and scenario reconstruction.

![ ](https://raw.githubusercontent.com/kabulkurniawan/Krystal/main/architecture-latest3.png)<p align="center"> **Figure 1** Krystal Architecture.

KRYSTAL imports each log event in sequence from potentially heterogeneous hosts (e.g., Linux, Windows, FreeBSD), i.e., in an online mode. It then generates an RDF-based provenance graph, taking advantage of the defined ontology and background knowledge in the Provenance Graph Building module. Subsequently, a number of threat detection and alerting approaches can be applied on the provenance graphs, including (i) tag propagation, (ii) attenuation & decay, and (iii) signature-based detection based on Indicators of Compromise (IoCs). These techniques are provided by the Threat Detection & Alerting module. The Attack Graph Reconstruction module then facilitates (offline) attack graph generation via Backward-forward chaining and attack pattern matching via Graph Querying over the provenance graph. 

## Pre Installation and Configuration

### TripleStore Installation
To be able to store the output data and perform data analyze, i.e. for Attack Reconstruction, A triple store with a built-in SPARQL query interface and visualization is need it. For example GraphDB, we can follow this [installation page](https://graphdb.ontotext.com/documentation/standard/installation.html) for further GraphDB installation instruction. 

### Configuration File
There are some configuration should be made prior running the application. Please take a look at the configuration file ([config.yaml](https://github.com/sepses/Krystal/blob/main/config.yaml)).


```bash
input-dir: experiment/input/ #log-sources directory, see the dataset example
output-dir: experiment/output/ #output directory 
tdb-dir: experiment/tdb #Jena TDB directory
ontology: experiment/ontology/log-ontology.ttl #Krystal ontology
rule-dir : experiment/rule/ #Rule directory i.e. Sigma Rule
rule-dir-win : experiment/rule_win/ #Rule directory for windows i.e. Sigma Rule for windows 
os-platform: ubuntu14 #OS platform
triple-store: graphdb #Triple Store directory
decay-rule: yes #Option to perform decay
live-store: no #Option for storing output data continuously
backup-file: yes #Backup RDF output in .HDT

confidential-dir: #Setting for any confidential directories
 - /etc/passwd 
 - /var/log
 - /etc/shadow
 - /documents/

field-filter: #Event filter for log processing (filter only the uncommented events (event with #))
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
 ...
```


## Run the Code

This project can be setup by cloning and installing and running it as follows:

```bash
$ git clone https://github.com/sepses/Krystal.git
$ cd Krystal
$ mvn clean install
```
To run the compiled project: 

```bash
$ java -jar ./target/SimpleLogProvenance-0.0.1-SNAPSHOT-jar-with-dependencies.jar
```

## Dataset for Evaluation
we used well-established datasets from red vs. blue team adversarial engagements produced as part of the third Transparent Computing (TC) program organized by [DARPA](https://drive.google.com/drive/folders/1QlbUFWAGq3Hpl8wVdzOdIoZLFxkII4EK). The datasets are organized into five categories, namely Cadets, Trace, Theia, FiveDirections and ClearScope.

### Example Dataset
We include several example of the dataset under directory [experiment/input](https://github.com/sepses/Krystal/tree/main/experiment/input).

### Example Output
We provided example output of the process (in RDF and .HDT) file under directory [experiment/output](https://github.com/sepses/Krystal/tree/main/experiment/output).


## License

Krystal Framework is written by [Kabul Kurniawan](https://kabulkurniawan.github.io/) released under the [MIT license](http://opensource.org/licenses/MIT).

