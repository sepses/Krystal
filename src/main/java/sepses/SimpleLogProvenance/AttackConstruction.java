package sepses.SimpleLogProvenance;

import java.util.ArrayList;

import org.apache.jena.query.QueryExecution;
import org.apache.jena.query.QueryExecutionFactory;
import org.apache.jena.query.QuerySolution;
import org.apache.jena.query.ResultSet;
import org.apache.jena.rdf.model.InfModel;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.rdf.model.RDFNode;
import org.apache.jena.riot.RDFDataMgr;

public class AttackConstruction {
	
	public static void main(String[] args) {
		
		Model jsonModel = RDFDataMgr.loadModel("experiment/input/rdfsample/cadet31_output.ttl") ;
		Model ontology = RDFDataMgr.loadModel("experiment/ontology/sepses-ontology.ttl");
		InfModel infmodel = ModelFactory.createRDFSModel(ontology, jsonModel);
		System.out.print(AttackGeneration(infmodel));
		
	}
	
	public static String AttackGeneration(Model jsonModel){
		
		String walert = getMostWeightedAlert(jsonModel);
		String ralert = findRootAlert(jsonModel, walert);
		String query = constructAttackGraph(jsonModel, ralert);
		return query;
	}
	
	public static String getMostWeightedAlert(Model jsonModel){
		//get the most weighted alert
		
		String q = "PREFIX sepses: <http://w3id.org/sepses/ns/log#>\r\n"
				+ "PREFIX rule: <http://w3id.org/sepses/ns/rule#>\r\n" + 
				"select ?s (count (?s) as ?c) where { \r\n" + 
				"   ?s a sepses:Process.\r\n" + 
				"	<< ?s ?p ?o >> rule:hasAlert ?a\r\n" + 
				"} group by ?s\r\n" + 
				"order by DESC(?c)\r\n";
		
		
		  	QueryExecution qe = QueryExecutionFactory.create(q, jsonModel);
	        ResultSet rs = qe.execSelect();
	        String s ="";
	        
	        while (rs.hasNext()) {
	            QuerySolution qs = rs.nextSolution();
	            RDFNode ns = qs.get("?s");
	            s = ns.toString();
	          
	        }
	        
	        qe.close();
	        return s;
	}
	
	public static String findRootAlert(Model jsonModel, String source){
		//perform backward search to find root alert
		String root="";
		if(!source.isEmpty()) {
			String q ="PREFIX sepses: <http://w3id.org/sepses/ns/log#>\r\n"
					+ "PREFIX rule: <http://w3id.org/sepses/ns/rule#>\r\n" + 
					"   SELECT  ?s\r\n" + 
					"     WHERE {  \r\n" + 
					"     <"+source+"> ^sepses:connects* ?s .\r\n" + 
					"    <<?s ?p ?o>> rule:hasAlert ?alert . \r\n" + 
					"    \r\n" + 
					"}";
		
		  	QueryExecution qe = QueryExecutionFactory.create(q,jsonModel);
		    ResultSet rs = qe.execSelect();
		    ArrayList<String> s = new ArrayList<String>();
		    while (rs.hasNext()) {
		        QuerySolution qs = rs.nextSolution();
		        RDFNode ns = qs.get("?s");
		        s.add(ns.toString());
		    }
		    qe.close();
		    if(s.size()==1) {
		    	root = s.get(0);
		    }else if (s.size()>1) {
		       root =  s.get(s.size()-1);
		    }
		 }else {
			root = ""; 
		 }
    return root;
   }
	
	public static String constructAttackGraph(Model jsonModel, String source){
		//perform forward search to construct attack graph
		if(!source.isEmpty()) {
		String q = "PREFIX sepses: <http://w3id.org/sepses/ns/log#>\r\n"
				+ "PREFIX rule: <http://w3id.org/sepses/ns/rule#>\r\n" + 
				"   CONSTRUCT {?s ?p ?o. ?s2 ?p2 ?s}\r\n" + 
				"     WHERE {  \r\n" + 
				"     <"+source+"> sepses:connects* ?s .\r\n" + 
				"      ?s ?p ?o.\r\n" + 
				"    OPTIONAL {?s2 ?p2 ?s. ?s2 sepses:confTag ?sct. \r\n" + 
				"              FILTER (?sct < 0.5 && ?p2!=sepses:connects)\r\n" + 
				"}\r\n" + 
				"      ?s  rule:intTag ?spt.\r\n" + 
				" 	  ?o rule:intTag ?opt.\r\n" + 
				"   	FILTER ( \r\n" + 
				"        ?spt < 0.5 && ?opt < 0.5  && ?p!=sepses:connects)\r\n" + 
				"    \r\n" + 
				"}";
		return q;
	  }else {
		return "no alert";
	  }
	}
	
}
