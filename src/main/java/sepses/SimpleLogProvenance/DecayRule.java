package sepses.SimpleLogProvenance;

import org.apache.jena.rdf.model.Model;
import org.apache.jena.update.UpdateAction;
import org.apache.jena.update.UpdateFactory;
import org.apache.jena.update.UpdateRequest;

public class DecayRule {
	private static void decayModel(Model jsonModel) {
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

	private static void subjectDecay(Model jsonModel, long now, long period) {
		
		long nanoDevide = 1000000000;
		float periodSec = period/nanoDevide;
		
		String execQuery = "PREFIX : <http://w3id.org/sepses/vocab/ref/rule#>\r\n" + 
				"PREFIX log: <http://w3id.org/sepses/vocab/event/log#>\r\n" + 
				"\r\n" + 
				"DELETE { ?s :intTag ?it.\r\n" + 
				"	<<?s ?p ?o>> :counter ?c.}\r\n" + 
				"INSERT  {?s :intTag ?max.\r\n" + 
				"    <<?s ?p ?o>> :counter ?nc.}\r\n" + 
				"WHERE {\r\n" + 
				" <<?s ?p ?o>> log:timestamp ?t;\r\n" + 
				"            :counter ?c.\r\n" + 
				" ?s :intTag ?it.\r\n" + 
				" ?s :subjTag ?st.\r\n" + 
				" FILTER (?st >= 0.5) \r\n" + //benign
				" BIND (("+now+" - ?t) as ?age). \r\n" + //age for now 
				" BIND ((?c + 1) as ?c). \r\n" +  //increase the counter
				" FILTER (?age >= (?c * "+period+"))  \r\n" + //chose age > 0.25 sec and it's multiply
				" BIND (((?it*"+periodSec+") + (1 - ?it) * "+periodSec+") as ?nit) \r\n" + //bind to a new intTag value 
				" BIND (IF(?it>?nit, ?sit, ?nit ) AS ?max) \r\n" + //compare with the old it, take the maximum one 
				"}";

        UpdateRequest execRequest = UpdateFactory.create(execQuery);
        UpdateAction.execute(execRequest,jsonModel) ;
        		
	}

	private static void objectDecay(Model jsonModel, long now, long period) {
		long nanoDevide = 1000000000;
		float periodSec = period/nanoDevide;
		
		String execQuery = "PREFIX : <http://w3id.org/sepses/vocab/ref/rule#>\r\n" + 
				"PREFIX log: <http://w3id.org/sepses/vocab/event/log#>\r\n" + 
				"\r\n" + 
				"DELETE { ?o :intTag ?it.\r\n" + 
				"	<<?s ?p ?o>> :counter ?c.}\r\n" + 
				"INSERT  {?o :intTag ?max.\r\n" + 
				"    <<?s ?p ?o>> :counter ?nc.}\r\n" + 
				"WHERE {\r\n" + 
				" <<?s ?p ?o>> log:timestamp ?t;\r\n" + 
				"            :counter ?c.\r\n" + 
				" ?o :intTag ?it.\r\n" + 
				" ?o :subjTag ?st.\r\n" + 
				" FILTER (?st >= 0.5)\r\n" +  //benign
				" BIND (("+now+" - ?t) as ?age). \r\n" + //age for now 
				" BIND ((?c + 1) as ?c).  \r\n" + //increase the counter
				" FILTER (?age >= (?c * "+period+"))  \r\n" +  // chose age > 0.25 sec and it's multiply 
				" BIND (((?it*"+periodSec+")+(1 - ?it) * "+periodSec+") as ?nit) \r\n" + //bind to a new intTag value 
				" BIND (IF(?it>?nit, ?sit, ?nit ) AS ?max)\r\n" +  //compare with the old it, take the maximum one 
				"}";

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
