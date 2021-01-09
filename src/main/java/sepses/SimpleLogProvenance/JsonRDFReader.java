package sepses.SimpleLogProvenance;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

import org.apache.jena.query.Dataset;
import org.apache.jena.rdf.model.InfModel;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.riot.RDFDataMgr;
import org.apache.jena.tdb.TDBFactory;

import helper.Utility;
import sepses.parsing.LogParser;

public class JsonRDFReader {
	public static void readJson(String t, String filefolder, String l, String se, String ng, String sl, String outputdir, String inputdir, String triplestore, String backupfile,  ArrayList<String> fieldfilter, String livestore, ArrayList<String> confidentialdir, String tdbdir, String ontology, String ruledir) throws Exception {
		
		  
		Integer lineNumber = 1; // 1 here means the minimum line to be extracted
		if(l!=null) {lineNumber=Integer.parseInt(l);}
		String sparqlEp = se;
		String namegraph = ng;
		Integer startingLine = 1; // 1 means start from the beginning
		if(sl!=null) {startingLine=Integer.parseInt(sl);}
		
		// create in one json object
		Integer countLine=0;
		Integer templ = 0;
		Integer group=0;
			
		//provenance Model store in TDB
		Dataset d = TDBFactory.createDataset(tdbdir);
		Model jsonModel = d.getDefaultModel();
		long time1 = System.currentTimeMillis();
	

		//alert model store in jena model
		Model alertModel = ModelFactory.createDefaultModel();
	
	
		
	    Set<String> Process = new HashSet<>();
		Set<String> File = new HashSet<>();
		Set<String> Network = new HashSet<>();
		Set<String> lastEvent = new HashSet<>();

		HashMap<String, String> uuIndex = new HashMap<String, String>();
		HashMap<String, String> NetworkObject = new HashMap<String, String>();
		HashMap<String, String> ForkObject = new HashMap<String, String>();
		HashMap<String, String> UserObject = new HashMap<String, String>();
		String lastAccess = "";
		
		
		File folder = new File(filefolder);
		
		ArrayList<String> listFiles = Utility.listFilesForFolder(folder);
		Collections.sort(listFiles);
		
		 if (listFiles.size()==0) { System.out.print("folder is empty!"); System.exit(0);}
	     for (String file : listFiles) {
	    	 	System.out.println("processing file: "+file);
	    	 	String filename = filefolder+file;
	
			InputStream jf = new FileInputStream(filename);
			BufferedReader in = new BufferedReader(new InputStreamReader(jf));	
		
					while (in.ready()) {
						String line = in.readLine();
						//System.out.println(countLine);
						if (countLine.equals(startingLine)) {
							System.out.println("reading from line : "+ startingLine);
								group=((int) Math.ceil((startingLine-1)/lineNumber));
						}
						if(countLine >= startingLine) {
							//line = cleanLine(line); // sometimes the data should be cleaned first
							//skip strange character inside line
							try {		
									LogParser lp = new LogParser(line);
									lastAccess = lp.parseJSONtoRDF(jsonModel,alertModel,fieldfilter, confidentialdir, uuIndex, Process, File, 
											                  Network, NetworkObject, ForkObject, lastEvent, lastAccess, UserObject);
									//System.out.println(lastAccess);
							} catch (Exception e) {
								System.out.print("strange character skipped => ");
								System.out.println(line);
							}
							
							templ++;
							
							if(templ.equals(lineNumber)) {
								
								group++;
								System.out.print("parsing "+group+" of "+lineNumber+" finished in "+(System.currentTimeMillis() - time1));
								System.out.println(" triple: "+jsonModel.size());
								
								if(livestore!="false") {
									//add rdfs reasoner first
									InfModel infModel = ModelFactory.createRDFSModel(RDFDataMgr.loadModel(ontology), jsonModel);
									 //detect alert from rule dir (i.e. sigma rule)
									AlertRule.generateAlertFromRuleDir(infModel, ruledir);
									String rdfFile = Utility.saveToRDF(infModel, outputdir, namegraph);
									//Utility.storeFileInRepo(triplestore, rdfFile, sparqlEp, namegraph, "dba", "dba");
								}	
								templ=0;
							}
							
							
						  }
						countLine++;
				}
		// check the rest 
		in.close();
		if(templ!=0) {
			
			System.out.println("the rest is less than "+lineNumber+" which is "+templ);
			
			if(livestore!="false") {
				
				    InfModel infModel = ModelFactory.createRDFSModel(RDFDataMgr.loadModel(ontology), jsonModel);
				    //detect alert from rule dir (i.e. sigma rule)
					AlertRule.generateAlertFromRuleDir(infModel, ruledir);
					String rdfFile = Utility.saveToRDF(infModel, outputdir, namegraph);
					//Utility.storeFileInRepo(triplestore, rdfFile, sparqlEp, namegraph, "dba", "dba");
					}	
			
			templ=0;
		}
			//end of a file	
		   System.out.println("finish processing file:"+filename);
	   }
	       //end of folder
	     
	     
			InfModel infModel = ModelFactory.createRDFSModel(RDFDataMgr.loadModel(ontology), jsonModel);
			
	     if(backupfile!="false") {
			 	String rdfFile = Utility.saveToRDF(infModel, outputdir, namegraph);
				Utility.exportHDT(rdfFile, outputdir, namegraph);
				//detect alert from rule dir (i.e. sigma rule)
				//AlertRule.generateAlertFromRuleDir(infModel, ruledir);
				String alertFile = Utility.saveToRDF(alertModel, outputdir, namegraph+"_alert");
				if(livestore=="false") {
					Utility.storeFileInRepo(triplestore, rdfFile, sparqlEp, namegraph, "dba", "dba");
					Utility.storeFileInRepo(triplestore, alertFile, sparqlEp, namegraph, "dba", "dba");
				}	
			} 
	   
	  System.out.println("Finish!, Generating query for attack construction.. ");
 	  //generate query for attack construction
	  String q = AttackConstruction.AttackGeneration(infModel.union(alertModel));
	  
	  System.out.println(q);
	  
	  
	  
	}

	




	
}
