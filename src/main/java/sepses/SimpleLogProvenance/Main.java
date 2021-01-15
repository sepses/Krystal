package sepses.SimpleLogProvenance;

import java.util.ArrayList;
import java.util.Map;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.Options;
import org.apache.jena.rdf.model.InfModel;

import helper.Utility;



public class Main {
	public static void main( String[] args ) throws Exception
    {
		//======yaml config=================
		  Map<String, Object> s = Utility.readYamlFile("config.yaml");
	       String outputdir= s.get("output-dir").toString();
	       String inputdir= s.get("input-dir").toString();
	       String ruledir= s.get("rule-dir").toString();
	       String osplatform= s.get("os-platform").toString();
	       String triplestore= s.get("triple-store").toString();
	       String backupfile= s.get("backup-file").toString();
	       String livestore= s.get("live-store").toString();
	       String tdbdir= s.get("tdb-dir").toString();
	       String ontology= s.get("ontology").toString();
	       ArrayList<String> fieldfilter= (ArrayList<String>) s.get("field-filter");
	       ArrayList<String> confidentialdir= (ArrayList<String>) s.get("confidential-dir");
	       
		//=====commandline argument===========
		  Options options = new Options();
	      options.addOption("t", true, "Type of parser (elastic, darpa)");
	      options.addOption("f", true, "folder file location");
	      options.addOption("l", true, "line number to process for each iteration");
	      options.addOption("e", true, "sparql endpoint");
	      options.addOption("n", true, "namegraph");
	      options.addOption("sl", true, "starting line, default 0");
	      
	      CommandLineParser parser = new DefaultParser();
	      CommandLine cmd = parser.parse(options, args); 
	      String type = cmd.getOptionValue("t");
	      String filefolder = cmd.getOptionValue("f");
	      String line = cmd.getOptionValue("l");
	      String sparqlEp = cmd.getOptionValue("e");
	      String namegraph = cmd.getOptionValue("n");
	      String startingLine = cmd.getOptionValue("sl");
	    //=====end commandline argument===========
	      
	  	//====== only for experiment in IDE, please uncomment this lines when you compile ========= 
	      
	      type = "darpa";
	      filefolder = inputdir+"darpa/";
	  	  line = "100000";
	      if(triplestore.equals("virtuoso")) {  	  
	  	     sparqlEp ="http://localhost:8890/sparql";
	      }else if(triplestore.equals("graphdb")){
	  	     sparqlEp = "http://localhost:7200/repositories/RDFSTAR";
	      }else {
	  	    //default: graphdb	 
	  	     sparqlEp = "http://localhost:7200/repositories/fd10000";
	  	   }
	      namegraph = "http://w3id.org/sepses/graph/fd10000";
	  	  startingLine = "0";

	  	  //=======end of experiment in IDE=============
	    
	  /* general algorithm 	  
	  	  1. Log Parsing (convert raw log data into structured, interpretable format e.g. (JSON)
	  	  2. RDF Mapping (transform structured data e.g. (JSON) into RDF)
	  	  3. Event Extraction (construct RDF data into meaningful event i.e. high level event, provenance)
	  	  4. Propagation & alerting (do propagation to construct attack event & generate alert from the propagated vent  )
	  	*/    	    	  
	  	  //clean tdb dir
	  	  Utility.deleteFileInDirectory(tdbdir);
	      
	      JsonRDFReader.readJson(type, filefolder, line, sparqlEp, namegraph, startingLine, 
	    		  outputdir, inputdir, triplestore, backupfile, fieldfilter,
	    		  livestore, confidentialdir, tdbdir, ontology, ruledir, osplatform);
	    		  
	    
	  	
    }
	
	public static void generateAlertUsingRule(InfModel infModel, String ruledir) {
		// TODO Auto-generated method stub
		
	}
}
