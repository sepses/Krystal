See the example process below:

```bash
$ java -jar .\target\SimpleLogProvenance-0.0.1-SNAPSHOT-jar-with-dependencies.jar
Start running ubuntu14 parser...
processing file: cadets100000.json
reading from line : 1
parsing 1 of 100000 finished in 11293
the rest is less than 100000 which is 3
0
finish processing file:experiment/input/cadets/cadets100000.json
generate alert from community ruleexperiment/rule/
number of events :94050
Statictics:
http://w3id.org/sepses/resource/rule/corrupt-file-rule : 6
http://w3id.org/sepses/resource/rule/change-permission-rule : 20
http://w3id.org/sepses/resource/sigma/sigma-444ade84-c362-4260-b1f3-e45e20e1a905 : 1
Save model to rdf file...Done!
Save model to rdf file...Done!
Save model rdf to hdt....Done!
```