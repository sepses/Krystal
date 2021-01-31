package sepses.SimpleLogProvenance;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.*; 
import org.apache.jena.query.QueryExecution;
import org.apache.jena.query.QueryExecutionFactory;
import org.apache.jena.query.QuerySolution;
import org.apache.jena.query.ResultSet;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.RDFNode;
import org.apache.jena.riot.RDFDataMgr;
import org.apache.jena.update.UpdateAction;
import org.apache.jena.update.UpdateFactory;
import org.apache.jena.update.UpdateRequest;

public class AttackConstruction {
	
	
	public static void main(String[] args) {
		
		Model alertModel = RDFDataMgr.loadModel("experiment/input/rdfsample/fd10000_alert_output.ttl") ;
		Model jsonModel = RDFDataMgr.loadModel("experiment/input/rdfsample/fd10000_output.ttl") ;
		getMostWeightedAlert(jsonModel,alertModel);
		
	}
	public static void getMostWeightedAlert(Model jsonModel, Model alertModel){
		  HashMap<String, Integer> alertCount = new HashMap<String, Integer>();
		
		System.out.println("Start attack construction");
		String q = "PREFIX sepses: <http://w3id.org/sepses/vocab/event/log#>\r\n"
				+ "PREFIX rule: <http://w3id.org/sepses/vocab/rule#>\r\n" + 
				"SELECT distinct ?s WHERE { \r\n" + 
				"	<< ?s ?p ?o >> rule:hasDetectedRule ?a;\r\n"
				+ "				   rule:alertType \"internal\". \r\n" + 
				"} \r\n";
		
		    ArrayList<String> alert = new ArrayList<String>();
		
		  	QueryExecution qe = QueryExecutionFactory.create(q, alertModel);
	        ResultSet rs = qe.execSelect();
	        
	        String s ="";
	        
	        while (rs.hasNext()) {
	        	
	            QuerySolution qs = rs.nextSolution();
	            RDFNode ns = qs.get("?s");            
	            s = ns.toString();
	            alert.add(s);
	        }
	       for(int i=0; i<alert.size();i++) {
	    	   String rootAlert =  findRootAlert(alertModel.union(jsonModel), alert.get(i));
	    	   addAlertWeighted(alertModel,rootAlert);
	    	   //accumulateAlertWeight(rootAlert, alertCount);
	       }
	       
	       System.out.println("get most weighted alarm!");
	        getMostWeightedAlert(alertModel);
	        
	}
	
	private static void getMostWeightedAlert(Model alertModel) {
		System.out.println("Top 10 process");
		String q = "PREFIX sepses: <http://w3id.org/sepses/vocab/event/log#>\r\n"
				+ "PREFIX rule: <http://w3id.org/sepses/vocab/rule#>\r\n" + 
				"SELECT distinct ?s ?o ?aw WHERE { \r\n" + 
				"	<< ?s ?p ?o >> rule:hasDetectedRule ?a; \r\n"
				+ "                rule:alertWeight ?aw \r\n" + 
				"} ORDER by DESC(?aw)\r\n"
				+ "LIMIT 10";
		    
		  	QueryExecution qe = QueryExecutionFactory.create(q, alertModel);
	        ResultSet rs = qe.execSelect();
	        while (rs.hasNext()) {
	            QuerySolution qs = rs.nextSolution();
	            RDFNode ns = qs.get("?s");     
	            RDFNode no = qs.get("?o");   
	            RDFNode nw = qs.get("?aw");            
	            System.out.println(ns +" "+no+" : "+nw.asLiteral().getInt());
                
	        }
	
	}

	private static  void accumulateAlertWeight(String process, HashMap<String, Integer> alertCount) {
		System.out.println(process);
		if(!process.isEmpty()) {
			if(alertCount.containsKey(process)) {
				int w = alertCount.get(process);
				alertCount.remove(process);
				alertCount.put(process, w+1);
			}
		}
	}
	
	private static void printTopProcess(HashMap<String, Integer> alertCount) {
		Map<String, Integer> hm1 = sortByValue(alertCount); 
		  
        // print the sorted hashmap 
        for (Map.Entry<String, Integer> en : hm1.entrySet()) { 
            System.out.println("Key = " + en.getKey() +  
                          ", Value = " + en.getValue()); 
        } 
	}
	private static void addAlertWeighted(Model alertModel, String rootAlert) {
		//System.out.println("add weigh on alert "+rootAlert);
		if(!rootAlert.isEmpty()) {
			String q = "PREFIX sepses: <http://w3id.org/sepses/vocab/event/log#>\r\n"
					+ "PREFIX rule: <http://w3id.org/sepses/vocab/rule#>\r\n" + 
					  "DELETE { "+rootAlert+" rule:alertWeight ?aw.}\r\n"+
					  "INSERT {"+rootAlert+"  rule:alertWeight ?naw.}\r\n"+
					 "WHERE { \r\n" + 
					  		rootAlert+" rule:alertWeight ?aw.\r\n"+
					  		"BIND (?aw+1 as ?naw)"+
					  		"} \r\n";
			UpdateRequest execRequest = UpdateFactory.create(q);
	        UpdateAction.execute(execRequest,alertModel) ;
		}
	}

	public static String findRootAlert(Model jsonModel, String source){
		//perform backward search to find root alert
		String root="";
		if(!source.isEmpty()) {
			String q ="PREFIX sepses: <http://w3id.org/sepses/vocab/event/log#>\r\n"
					+ "PREFIX rule: <http://w3id.org/sepses/vocab/rule#>\r\n" + 
					"   SELECT  ?s ?p ?o \r\n" + 
					"     WHERE {  \r\n" + 
					"     <"+source+"> ^sepses:provRel* ?s .\r\n" + 
					"    <<?s ?p ?o>> rule:hasDetectedRule ?alert . \r\n" + 
					"    \r\n" + 
					"}";
		
		  	QueryExecution qe = QueryExecutionFactory.create(q,jsonModel);
		    ResultSet rs = qe.execSelect();
		    ArrayList<String> s = new ArrayList<String>();
		    while (rs.hasNext()) {
		        QuerySolution qs = rs.nextSolution();
		        RDFNode ns = qs.get("?s");
		        RDFNode np = qs.get("?p");
		        RDFNode no = qs.get("?o");
		        String rdf = "<< <"+ns.toString()+"> <"+np.toString()+"> <"+no.toString()+"> >>";
		        s.add(rdf);
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

	
	
	// function to sort hashmap by values 
    public static HashMap<String, Integer> sortByValue(HashMap<String, Integer> hm) 
    { 
        // Create a list from elements of HashMap 
        List<Map.Entry<String, Integer> > list = 
               new LinkedList<Map.Entry<String, Integer> >(hm.entrySet()); 
  
        // Sort the list 
        Collections.sort(list, new Comparator<Map.Entry<String, Integer> >() { 
            public int compare(Map.Entry<String, Integer> o1,  
                               Map.Entry<String, Integer> o2) 
            { 
                return (o1.getValue()).compareTo(o2.getValue()); 
            } 
        }); 
          
        // put data from sorted list to hashmap  
        HashMap<String, Integer> temp = new LinkedHashMap<String, Integer>(); 
        for (Map.Entry<String, Integer> aa : list) { 
            temp.put(aa.getKey(), aa.getValue()); 
        } 
        return temp; 
    } 
  
}
