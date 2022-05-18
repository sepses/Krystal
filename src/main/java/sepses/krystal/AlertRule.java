package sepses.krystal;

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

import sepses.krystal.helper.Utility;

public class AlertRule {
	public String prefix; 
	public String process; 
	public String file;
	public String network;
	public String alert;
	public  String timestamp;
	
	public AlertRule(){
		prefix = "PREFIX sepses: <http://w3id.org/sepses/vocab/event/log#>\r\n"
				+ "PREFIX rule: <http://w3id.org/sepses/vocab/rule#>\r\n";
		timestamp = "<http://w3id.org/sepses/vocab/event/log#timestamp>";
		
		
	}	


//	public void dataCollectionAlert(Model jsonModel, Model alertModel, String proc, String objectString, String ts) {
//		process = "<http://w3id.org/sepses/resource/proc"+proc+">";
//		file = "<http://w3id.org/sepses/resource/file#"+objectString+">";
//		String time = "\""+ts + "\"^^<http://www.w3.org/2001/XMLSchema#long>";
//		
//		String q ="CONSTRUCT { << "+file+" sepses:isReadBy "+process+" >> "
//					+ "rule:hasDetectedRule <http://w3id.org/sepses/resource/rule/data-collection-rule>; \r\n"
//					+ "rule:alertWeight 0; \r\n"
//					+ "rule:timestamp "+time+";\r\n"
//					+ "rule:alertType \"internal\" .\r\n"
//					+file+" sepses:isReadBy "+process
//						+ " \r\n}"+
//				   "WHERE { \r\n" + 
//				    file+" rule:intTag  ?oit.\r\n"+
//					file+" sepses:isReadBy "+process+" .\r\n"
//					+file+" rule:confTag  ?oct.\r\n"
//					+process+" rule:intTag  ?sit.\r\n"
//					+"FILTER (?oct < 0.5).\r\n"
//					+"FILTER (?sit < 0.5).\r\n"
//					+ "\r\n"+
//				"}";
//		
//	    QueryExecution qe = QueryExecutionFactory.create(prefix+q, jsonModel);
//        Model currentAlert = qe.execConstruct();
//        alertModel.add(currentAlert);
//        currentAlert.close();
//	    
//	}
	
	
	public void reconnaissanceAlert(Model jsonModel, Model alertModel, String proc, String net, String ts) {
		process = "<http://w3id.org/sepses/resource/proc"+proc+">";
		net = "<http://w3id.org/sepses/resource/soc#"+net+">";
		String time = "\""+ts + "\"^^<http://www.w3.org/2001/XMLSchema#long>";
		
		String q ="CONSTRUCT { << "+net+" sepses:isReceivedBy "+process+" >> "
					+ "rule:hasDetectedRule <http://w3id.org/sepses/resource/rule/reconnaissance-rule>; \r\n"
					+ "rule:alertWeight 0; \r\n"
					+ "rule:timestamp "+time+";\r\n"
					+ "rule:alertType \"internal\" .\r\n"
						+ " \r\n}"+
				   "WHERE { \r\n" + 
				     net+" sepses:isReceivedBy "+process+" .\r\n"
					 + "?f sepses:isReadBy "+process+" .\r\n"+
					process+ " rule:subjTag  ?sst.\r\n"+
					"?f rule:confTag  ?oct.\r\n"
					+"FILTER (?oct < 0.5).\r\n"
					+"FILTER (?sst >= 0.5).\r\n"
					+ "\r\n"+
				"}";
		
	    QueryExecution qe = QueryExecutionFactory.create(prefix+q, jsonModel);
        Model currentAlert = qe.execConstruct();
        alertModel.add(currentAlert);
        currentAlert.close();
	    
	}
	

	public void reconnaissanceReadAlert(Model jsonModel, Model alertModel, String proc, String file, String ts) {
		process = "<http://w3id.org/sepses/resource/proc"+proc+">";
		file = "<http://w3id.org/sepses/resource/file#"+file+">";
		String time = "\""+ts + "\"^^<http://www.w3.org/2001/XMLSchema#long>";
		
		String q ="CONSTRUCT { << ?n sepses:isReceivedBy "+process+" >> "
					+ "rule:hasDetectedRule <http://w3id.org/sepses/resource/rule/reconnaissance-rule>; \r\n"
					+ "rule:alertWeight 0; \r\n"
					+ "rule:timestamp "+time+";\r\n"
					+ "rule:alertType \"internal\" .\r\n"
						+ " \r\n}"+
				   "WHERE { \r\n" + 
				     "?n sepses:isReceivedBy "+process+" .\r\n"
					 +file+" sepses:isReadBy "+process+" .\r\n"+
					process+ " rule:subjTag  ?sst.\r\n"+
					"?f rule:confTag  ?oct.\r\n"
					+"FILTER (?oct < 0.5).\r\n"
					+"FILTER (?sst >= 0.5).\r\n"
					+ "\r\n"+
				"}";
		
	    QueryExecution qe = QueryExecutionFactory.create(prefix+q, jsonModel);
        Model currentAlert = qe.execConstruct();
        alertModel.add(currentAlert);
        currentAlert.close();
	    
	}
	
	
	public void execAlert(Model jsonModel, Model alertModel, String proc, String objectString, String ts) {
		process = "<http://w3id.org/sepses/resource/proc"+proc+">";
		file = "<http://w3id.org/sepses/resource/file#"+objectString+">";
		String time = "\""+ts + "\"^^<http://www.w3.org/2001/XMLSchema#long>";
		
		String q ="CONSTRUCT { << "+file+" sepses:isExecutedBy "+process+" >> "
					+ "rule:hasDetectedRule <http://w3id.org/sepses/resource/rule/exec-rule>; \r\n"
					+ "rule:alertWeight 0; \r\n"
					+ "rule:timestamp "+time+";\r\n"
					+ "rule:alertType \"internal\" .\r\n"
					+file+" sepses:isExecutedBy "+process
						+ " \r\n}"+
				   "WHERE { \r\n" + 
				    file+" rule:intTag  ?oit.\r\n"+
					file+" sepses:isExecutedBy "+process+" .\r\n"
					+process+" rule:subjTag  ?sst.\r\n"
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
		
		process = "<http://w3id.org/sepses/resource/proc"+proc+">";
		network = "<http://w3id.org/sepses/resource/soc#"+net+">";
		String time = "\""+ts + "\"^^<http://www.w3.org/2001/XMLSchema#long>";
		
		String q ="CONSTRUCT { << "+process+" sepses:sends "+network+" >> "
								+ "rule:hasDetectedRule <http://w3id.org/sepses/resource/rule/data-leak-rule>; \r\n"+
								   "rule:alertWeight 0; \r\n"+
								"rule:timestamp "+time+";\r\n"+
								 "rule:alertType \"internal\" .\r\n"+
								process+" sepses:sends "+network+
						   " \r\n}"+
				"WHERE { \r\n" + 
				    network+" rule:confTag  ?oct.\r\n"+
					process+" sepses:sends "+network+" .\r\n"
					+process+" rule:intTag  ?sit.\r\n"
					+process+" rule:confTag  ?sct.\r\n"
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
		process = "<http://w3id.org/sepses/resource/proc"+proc+">";
		file = "<http://w3id.org/sepses/resource/file#"+objectString+">";
		String time = "\""+ts + "\"^^<http://www.w3.org/2001/XMLSchema#long>";
		
		String q ="CONSTRUCT { << "+process+" sepses:writes "+file+" >> "
								+ "rule:hasDetectedRule <http://w3id.org/sepses/resource/rule/corrupt-file-rule>;\r\n"+
								  "rule:alertWeight 0; \r\n"+
						  			"sepses:timestamp "+time+";\r\n"+
						  			 "rule:alertType \"internal\" .\r\n"+
						  			process+" sepses:writes "+file+
						   " \r\n}"+
				   "WHERE { \r\n" + 
				    file+" rule:intTag  ?oit.\r\n"+
					process+" sepses:writes "+file+" .\r\n"
					+process+" rule:intTag  ?sit.\r\n"
					+"FILTER (?oit >= 0.5).\r\n"
					+"FILTER (?sit < 0.5).\r\n"
					+ "\r\n"+
				"}";
	
		QueryExecution qe = QueryExecutionFactory.create(prefix+q, jsonModel);
        Model currentAlert = qe.execConstruct();
        alertModel.add(currentAlert);
	    
	}
	
	public void changePermAlert(Model jsonModel, Model alertModel, String proc, String objectString, String ts) {
		process = "<http://w3id.org/sepses/resource/proc"+proc+">";
		file = "<http://w3id.org/sepses/resource/file#"+objectString+">";
		String time = "\""+ts + "\"^^<http://www.w3.org/2001/XMLSchema#long>";
		
		String q ="CONSTRUCT { << ?p sepses:changesPermission "+file+" >> "
								+ "rule:hasDetectedRule <http://w3id.org/sepses/resource/rule/change-permission-rule>;\r\n"+
								  "rule:alertWeight 0; \r\n"+
						  		"sepses:timestamp "+time+";\r\n"+
						  		"rule:alertType \"internal\" .\r\n"+
						   " \r\n}"+
				   "WHERE { \r\n" +
				   "?p sepses:changesPermission "+file+" .\r\n"+
					file+" rule:intTag  ?oit.\r\n"
					+"FILTER (?oit < 0.5).\r\n"
					+ "\r\n"+
				"}";
	
		QueryExecution qe = QueryExecutionFactory.create(prefix+q, jsonModel);
        Model currentAlert = qe.execConstruct();
        alertModel.add(currentAlert);
	    
	}
	
	public void memExec(Model jsonModel, Model alertModel, String proc, String objectString, String ts) {
		process = "<http://w3id.org/sepses/resource/proc"+proc+">";
		file = "<http://w3id.org/sepses/resource/file#"+objectString+">";
		String time = "\""+ts + "\"^^<http://www.w3.org/2001/XMLSchema#long>";
		
		String q ="CONSTRUCT { << ?p sepses:mprotect "+file+" >> "
								+ "rule:hasDetectedRule <http://w3id.org/sepses/resource/rule/change-permission-rule>;\r\n"+
								  "rule:alertWeight 0; \r\n"+
						  		"sepses:timestamp "+time+";\r\n"+
						  		"rule:alertType \"internal\" .\r\n"+
						   " \r\n}"+
				   "WHERE { \r\n" +
				   "?p sepses:mprotect "+file+" .\r\n"+
				  // file+" sepses:isExecutedBy "+process+" .\r\n"+
					file+" rule:intTag  ?oit.\r\n"
					+"FILTER (?oit < 0.5).\r\n"
					+ "\r\n"+
				"}";
	
		QueryExecution qe = QueryExecutionFactory.create(prefix+q, jsonModel);
        Model currentAlert = qe.execConstruct();
        alertModel.add(currentAlert);
	    
	}
	
	
	public static void generateAlertFromRuleDir(Model jsonModel, Model alertModel, String ruledir) {
		System.out.println("generate alert from sigma rule "+ruledir);
		
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
			 if(ruledir.contains("rule_win")) {
				 ruleQuery = ruleQuery.replace("\\\\","\\\\\\\\");
			 }
			 
				//apply (iteratively) rule query from infModel
			 if(!ruleQuery.isEmpty()) {
				 Query rq = QueryFactory.create(ruleQuery);
			     QueryExecution qe = QueryExecutionFactory.create(rq, jsonModel);
		         ResultSet qres = qe.execSelect();
		         
		       //add detection triple to infModel while matching
		         while (qres.hasNext()) {
			            QuerySolution qs = qres.nextSolution();
			            Resource res = qs.get("?s").asResource();
			            Property detectedRule = ruleModel.createProperty("http://w3id.org/sepses/vocab/rule#hasDetectedRule");
			            alertModel.add(res, detectedRule, subj);
			    	  }
		            }
			   }
			
			 
		  }
}
