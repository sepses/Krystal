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

import org.apache.jena.atlas.lib.Alarm;
import org.apache.jena.query.Dataset;
import org.apache.jena.rdf.model.InfModel;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.reasoner.Reasoner;
import org.apache.jena.reasoner.ReasonerRegistry;
import org.apache.jena.riot.RDFDataMgr;
import org.apache.jena.tdb.TDBFactory;

import helper.Utility;
import sepses.parsing.LogParserFreeBSD;
import sepses.parsing.LogParserWin;
import sepses.parsing.LogParserUbuntu12;
import sepses.parsing.LogParserUbuntu14;
import sepses.parsing.LogParserLinux20;

public class JsonRDFReader {
	
	public static long timer;
	public static long duration;
	
	public static void readJson(String filefolder, String l, String se, String ng, String sl, String outputdir, 
									String triplestore, String backupfile,  ArrayList<String> fieldfilter,
										String livestore, ArrayList<String> confidentialdir, String tdbdir, String ontology, 
										String ruledir, String os, String decayrule) throws Exception {
		
		  
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
		Set<String> Registry = new HashSet<>();
		Set<String> lastEvent = new HashSet<>();

		HashMap<String, String> uuIndex = new HashMap<String, String>();
		HashMap<String, String> NetworkObject = new HashMap<String, String>();
		HashMap<String, String> FileObject = new HashMap<String, String>();
		HashMap<String, String> ForkObject = new HashMap<String, String>();
		HashMap<String, String> UserObject = new HashMap<String, String>();
		HashMap<String, String> SubjectCmd = new HashMap<String, String>();
		HashMap<String, Long> SubjectTime = new HashMap<String, Long>();
		HashMap<String, String> CloneObject = new HashMap<String, String>();
		HashMap<String, String> RegistryObject = new HashMap<String, String>();
		ArrayList<Integer> counter = new ArrayList<Integer>(); 
		counter.add(0);
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
						if (countLine.equals(startingLine)) {
							System.out.println("reading from line : "+ startingLine);
								group=((int) Math.ceil((startingLine-1)/lineNumber));
						}
						if(countLine >= startingLine) {
							//line = cleanLine(line); // sometimes the data should be cleaned first
							//skip strange character inside line
							try {	
									if(os.equals("windows")) {
										int lastChar =  line.length() - 1;
										if(line.substring(lastChar, line.length()).equals(",")) {
											line = line.substring(0, line.length() - 1);
										}	
										LogParserWin lp = new LogParserWin(line); //fivedirection
										lastAccess = lp.parseJSONtoRDF(jsonModel,alertModel,fieldfilter, confidentialdir, uuIndex, Process, File, 
								                  Network, NetworkObject, ForkObject, lastEvent, lastAccess, UserObject, Registry, RegistryObject, SubjectCmd, file, SubjectTime, decayrule, counter);
									}else if (os.equals("ubuntu12")){
										LogParserUbuntu12 lp = new LogParserUbuntu12(line); //ubuntu
										lastAccess = lp.parseJSONtoRDF(jsonModel,alertModel,fieldfilter, confidentialdir, uuIndex, Process, File, 
								                  Network, NetworkObject, ForkObject, lastEvent, lastAccess, UserObject, FileObject, SubjectCmd, file, CloneObject, decayrule, counter);
									}else  if (os.equals("ubuntu14")){
										LogParserUbuntu14 lp = new LogParserUbuntu14(line); //freebsd
										lastAccess = lp.parseJSONtoRDF(jsonModel,alertModel,fieldfilter, confidentialdir, uuIndex, Process, File, 
								                  Network, NetworkObject, ForkObject, lastEvent, lastAccess, UserObject, SubjectTime, decayrule, counter, SubjectCmd);
									}else {
										LogParserFreeBSD lp = new LogParserFreeBSD(line); //freebsd
										lastAccess = lp.parseJSONtoRDF(jsonModel,alertModel,fieldfilter, confidentialdir, uuIndex, Process, File, 
								                  Network, NetworkObject, ForkObject, lastEvent, lastAccess, UserObject, SubjectTime, decayrule, counter);
									}
									
							} catch (Exception e) {
								System.out.print("strange character skipped => ");
								System.out.println(line);
							}
							
							templ++;
							
							if(templ.equals(lineNumber)) {
								
								group++;
								System.out.println("parsing "+group+" of "+lineNumber+" finished in "+(System.currentTimeMillis() - time1));
								
														
								if(livestore!="false") {
									//add rdfs reasoner first
									//InfModel infModel = ModelFactory.createRDFSModel(RDFDataMgr.loadModel(ontology), jsonModel);
									 //detect alert from rule dir (i.e. sigma rule)
									//AlertRule.generateAlertFromRuleDir(infModel, alertModel, ruledir);
									//String rdfFile = Utility.saveToRDF(infModel, outputdir, namegraph);
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
			System.out.println(duration);
			if(livestore!="false") {
				
				    //InfModel infModel = ModelFactory.createRDFSModel(RDFDataMgr.loadModel(ontology), jsonModel);
				    //detect alert from rule dir (i.e. sigma rule)
					//AlertRule.generateAlertFromRuleDir(infModel, alertModel, ruledir);
					//String rdfFile = Utility.saveToRDF(infModel, outputdir, namegraph);
					//Utility.storeFileInRepo(triplestore, rdfFile, sparqlEp, namegraph, "dba", "dba");
					}	
			
			templ=0;
		}
			//end of a file	
		   System.out.println("finish processing file:"+filename);
	   }
	       //end of folder
	    // System.out.println("Perform reasoning...");
	     Reasoner reasoner = ReasonerRegistry.getOWLMicroReasoner();
	     reasoner = reasoner.bindSchema(RDFDataMgr.loadModel(ontology));
	     InfModel infModel = ModelFactory.createInfModel(reasoner, jsonModel);
	     //InfModel infModel = ModelFactory.createRDFSModel(RDFDataMgr.loadModel(ontology), jsonModel);
		    
	     
	     
	     //detect alert from rule dir (i.e. sigma rule)
	     AlertRule.generateAlertFromRuleDir(infModel,alertModel, ruledir);
		  
	     System.out.println("number of events :"+counter.get(0));
	     Statistic.countAlarm(alertModel);
	         
	     if(backupfile!="false") {
	    	 	String rdfFile = Utility.saveToRDF(infModel, outputdir, namegraph);
			    String alertFile = Utility.saveToRDF(alertModel, outputdir, namegraph+"_alert");
			    Utility.exportHDT(rdfFile, outputdir, namegraph);
				if(livestore=="false") {
					//Utility.storeFileInRepo(triplestore, rdfFile, sparqlEp, namegraph, "dba", "dba");
					//Utility.storeFileInRepo(triplestore, alertFile, sparqlEp, namegraph, "dba", "dba");
				}	
			} 
	     
	   //System.out.println("Finish!, get the primary alarm.. ");
	  // AttackConstruction.getMostWeightedAlert(infModel,alertModel);
	
	   
	}

}
