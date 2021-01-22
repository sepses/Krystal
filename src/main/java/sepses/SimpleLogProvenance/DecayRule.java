package sepses.SimpleLogProvenance;

import org.apache.jena.rdf.model.Model;
import org.apache.jena.update.UpdateAction;
import org.apache.jena.update.UpdateFactory;
import org.apache.jena.update.UpdateRequest;

public class DecayRule {
	
	public  void decayModel(Model jsonModel) {
		// TODO Auto-generated method stub
		System.out.print("run decay..");
		String execQuery = "prefix xsd:<http://www.w3.org/2001/XMLSchema#>\r\n"
				+ "prefix log:<http://w3id.org/sepses/vocab/event/log#>\r\n"
				+ "prefix rule:<http://w3id.org/sepses/vocab/rule#>\r\n" + 
        		  "DELETE { ?s rule:intTag ?sit. }\r\n"
        		+ "INSERT {?s rule:intTag ?max.}\r\n" +
        		"WHERE { \r\n" 
        		+ "?s rule:intTag ?sit.\r\n"
        		+ "?s rule:subjTag ?st .\r\n"
        		+ "FILTER (?st >= 0.5)\r\n" //benign subj, s.tag >=
        		+ "BIND(((?sit*0.25)+0.47) as ?nsit)\r\n"
        		+ "BIND( IF( ?sit>?nsit, ?sit, ?nsit ) AS ?max)"
        		+"}";

        UpdateRequest execRequest = UpdateFactory.create(execQuery);
        UpdateAction.execute(execRequest,jsonModel) ;
        
        String execQuery2 = "prefix xsd:<http://www.w3.org/2001/XMLSchema#>\r\n"
				+ "prefix log:<http://w3id.org/sepses/vocab/event/log#>\r\n"
				+ "prefix rule:<http://w3id.org/sepses/vocab/rule#>\r\n" + 
        		  "DELETE {?s rule:confTag ?sct. }\r\n"
        		+ "INSERT {?s rule:confTag ?max.}\r\n" +
        		"WHERE { \r\n" 
        		+ "?s rule:confTag ?sct.\r\n"
        		+ "?s rule:subjTag ?st .\r\n"
        		+ "FILTER (?st >= 0.5)\r\n"
        		+ "BIND(((?sct*0.25)+0.47) as ?nsct)\r\n"
        		+ "BIND( IF( ?sct>?nsct, ?sct, ?nsct ) AS ?max)\r\n"
        		+"}";

        UpdateRequest execRequest2 = UpdateFactory.create(execQuery2);
        UpdateAction.execute(execRequest2,jsonModel) ;
		
	}

	public static void subjectDecay(Model jsonModel, long now, double period) {
		
		double periodNano = period*1000000000;
		double T = 0.75;
		String execQuery = "PREFIX : <http://w3id.org/sepses/vocab/rule#>\r\n" + 
				"PREFIX log: <http://w3id.org/sepses/vocab/event/log#>\r\n" + 
				"\r\n" + 
				"DELETE { ?s :intTag ?it.\r\n" + 
				"	?s :counter ?c.}\r\n" + 
				"INSERT  {?s :intTag ?max.\r\n" + 
				"    ?s :counter ?nc.}\r\n" + 
				"WHERE {\r\n" + 
				" ?s log:timestamp ?t;\r\n" + 
				"            :counter ?c.\r\n" + 
				" ?s :intTag ?it.\r\n" +  
				" ?s :subjTag ?st.\r\n" + 
				" FILTER (?st >= 0.5) \r\n" + //benign
				" BIND (("+now+" - ?t) as ?age). \r\n" + //age for now 
				" BIND ((?c + 1) as ?nc). \r\n" +  //increase the counter
				" FILTER (?age >= (?c * "+periodNano+"))  \r\n" + //chose age > 0.25 sec and it's multiply
				" BIND (((?it*"+period+") + (1 - "+period+") * "+T+") as ?nit) \r\n" + //bind to a new intTag value 
				" BIND (IF(?it>?nit, ?it, ?nit ) AS ?max) \r\n" + //compare with the old it, take the maximum one 
				"}";
		
		//System.out.println(execQuery);
//		System.exit(0);
		
		
        UpdateRequest execRequest = UpdateFactory.create(execQuery);
        UpdateAction.execute(execRequest,jsonModel) ;
        		
	}

	
	public void getTheAdultEvent(Model jsonModel, long now, long period){
		
		String execQuery = "PREFIX : <http://w3id.org/sepses/vocab/ref/rule#>\r\n" + 
				"PREFIX log: <http://w3id.org/sepses/vocab/event/log#>\r\n" + 
				"\r\n" + 
				"SELECT ?s ?p ?o ?t ?c ?age\r\n" + 
				"WHERE {\r\n" + 
				" <<?s ?p ?o>> log:timestamp ?t;\r\n" + 
				"            :counter ?c.\r\n" + 
				" BIND (("+now+" - ?t) as ?age). \r\n" + //age for now 
				" FILTER (?age >= (?c * "+period+"))  \r\n" + // chose age > 0.25 sec and it's multiply
				"}";
		
	}
}
