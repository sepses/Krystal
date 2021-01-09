package sepses.SimpleLogProvenance;

import java.io.File;
import java.util.ArrayList;
import java.util.Collections;

import org.apache.jena.query.Query;
import org.apache.jena.query.QueryExecution;
import org.apache.jena.query.QueryExecutionFactory;
import org.apache.jena.query.QueryFactory;
import org.apache.jena.query.QuerySolution;
import org.apache.jena.query.ResultSet;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.rdf.model.Property;
import org.apache.jena.rdf.model.RDFNode;
import org.apache.jena.rdf.model.Resource;
import org.apache.jena.rdf.model.Statement;
import org.apache.jena.rdf.model.StmtIterator;
import org.apache.jena.riot.RDFDataMgr;

import helper.Utility;

public class AlertRule {
	public String prefix; 
	public String process; 
	public String file;
	public String network;
	public String alert;
	public  String timestamp;
	
	public AlertRule(){
		prefix = "PREFIX darpa: <http://ss.l/dp#>\r\n";
		timestamp = "<http://ss.l/dp#timestamp>";
		
	}
	
	public void execAlert(Model jsonModel, Model alertModel, String proc, String objectString, String ts) {
		process = "<http://ss.r/dp/proc/"+proc+">";
		file = "<http://ss.r/dp/obj#"+objectString+">";
		String time = "\""+ts + "\"^^<http://www.w3.org/2001/XMLSchema#dateTime>";
		
		String q ="CONSTRUCT { << "+file+" darpa:isExecutedBy "+process+" >> "
					+ "darpa:hasAlert <http://ss.r/dp/alert#exec-alert>; \r\n"
					+ "			             darpa:timestamp "+time+"."
						+ " \r\n}"+
				   "WHERE { \r\n" + 
				    file+" darpa:intTag  ?oit.\r\n"+
					file+" darpa:isExecutedBy "+process+" .\r\n"
					+process+" darpa:subjTag  ?sst.\r\n"
					+"FILTER (?oit < 0.5).\r\n"
					+"FILTER (?sst >= 0.5).\r\n"
					+ "\r\n"+
				"}";
		
	    QueryExecution qe = QueryExecutionFactory.create(prefix+q, jsonModel);
        Model currentAlert = qe.execConstruct();
        alertModel.add(currentAlert);
        currentAlert.close();
	    
	}
	
	public void dataLeakAlert(Model jsonModel, Model alertModel, String proc, String net, String ts) {
		
		process = "<http://ss.r/dp/proc/"+proc+">";
		network = "<http://ss.r/dp/obj#"+net+">";
		String time = "\""+ts + "\"^^<http://www.w3.org/2001/XMLSchema#dateTime>";
		
		String q ="CONSTRUCT { << "+process+" darpa:sends "+network+" >> "
								+ "darpa:hasAlert <http://ss.r/dp/alert#data-leak-alert>; \r\n"+
								"darpa:timestamp "+time+"."+
						   " \r\n}"+
				"WHERE { \r\n" + 
				    network+" darpa:confTag  ?oct.\r\n"+
					process+" darpa:sends "+network+" .\r\n"
					+process+" darpa:intTag  ?sit.\r\n"
					+process+" darpa:confTag  ?sct.\r\n"
					+"FILTER (?oct >= 0.5).\r\n"
					+"FILTER (?sct < 0.5).\r\n"
					+"FILTER (?sit < 0.5).\r\n"
					+ "\r\n"+
				"}";
		
		QueryExecution qe = QueryExecutionFactory.create(prefix+q, jsonModel);
        Model currentAlert = qe.execConstruct();
        alertModel.add(currentAlert);
        currentAlert.close();
	}
	
	public void corruptFileAlert(Model jsonModel, Model alertModel, String proc, String objectString, String ts) {
		process = "<http://ss.r/dp/proc/"+proc+">";
		file = "<http://ss.r/dp/obj#"+objectString+">";
		String time = "\""+ts + "\"^^<http://www.w3.org/2001/XMLSchema#dateTime>";
		
		String q ="CONSTRUCT { << "+process+" darpa:writes "+file+" >> "
								+ "darpa:hasAlert <http://ss.r/dp/alert#corrupt-file-alert>;\r\n"+
						  			"darpa:timestamp "+time+"."+
						   " \r\n}"+
				   "WHERE { \r\n" + 
				    file+" darpa:intTag  ?oit.\r\n"+
					process+" darpa:writes "+file+" .\r\n"
					+process+" darpa:intTag  ?sit.\r\n"
					+"FILTER (?oit >= 0.5).\r\n"
					+"FILTER (?sit < 0.5).\r\n"
					+ "\r\n"+
				"}";
	
		QueryExecution qe = QueryExecutionFactory.create(prefix+q, jsonModel);
        Model currentAlert = qe.execConstruct();
        alertModel.add(currentAlert);
	    
	}
	
	public static void generateAlertFromRuleDir(Model jsonModel, String ruledir) {
		System.out.println("generate alert from community rule");
		
		Model addJsonModel = ModelFactory.createDefaultModel();
	
		//get rule-query from ruledir
		File rulefolder = new File(ruledir);
		Model ruleModel = ModelFactory.createDefaultModel();
		ArrayList<String> listFiles = Utility.listFilesForFolder(rulefolder);
		Collections.sort(listFiles);
		for(int i=0;i<listFiles.size();i++) {
			Model temprule = RDFDataMgr.loadModel(ruledir+listFiles.get(i));
			ruleModel.add(temprule);
		}
		
		Property hasDetection = ruleModel.createProperty("http://w3id.org/sepses/vocab/rule/sigma#hasDetection");
		StmtIterator iter = ruleModel.listStatements((Resource) null, hasDetection,(RDFNode) null);
		
		 while (iter.hasNext()) {
			 Statement s = iter.next();
			 Resource subj = s.getSubject();
			 String ruleQuery = s.getObject().asLiteral().toString().replace("\\\"","\"");
			 
				//apply (iteratively) rule query from infModel
			 if(!ruleQuery.isEmpty()) {
				 
				 Query rq = QueryFactory.create(ruleQuery);
			     QueryExecution qe = QueryExecutionFactory.create(rq, jsonModel);
		         ResultSet qres = qe.execSelect();
		         
		       //add detection triple to infModel while matching
		         while (qres.hasNext()) {
			            QuerySolution qs = qres.nextSolution();
			            Resource res = qs.get("?s").asResource();
			            Property detectedRule = ruleModel.createProperty("http://ss.l/dp#hasDetectedRule");
			            addJsonModel.add(res, detectedRule, subj);
			    	  }
		            }
			      
			   }
			jsonModel.add(addJsonModel);  
			 
		  }
}
