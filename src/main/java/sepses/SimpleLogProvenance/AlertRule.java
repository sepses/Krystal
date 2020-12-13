package sepses.SimpleLogProvenance;

import org.apache.jena.rdf.model.Model;
import org.apache.jena.update.UpdateAction;
import org.apache.jena.update.UpdateFactory;
import org.apache.jena.update.UpdateRequest;

public class AlertRule {
	public  String prefix; 
	public  String process; 
	public String file;
	public String network;
	public String alert;
	
	public AlertRule(){
		prefix = "PREFIX darpa: <http://ss.l/dp#>\r\n";

	}
	
	public void execAlert(Model jsonModel, String proc, String objectString) {
		process = "<http://ss.r/dp/proc/"+proc+">";
		file = "<http://ss.r/dp/obj#"+objectString+">";
		
		String q =prefix+""
				+ "INSERT { "+file+" darpa:isIllegallyExecutedBy "+process+". \r\n}"+
				   "WHERE { \r\n" + 
				    file+" darpa:intTag  ?oit.\r\n"+
					file+" darpa:isExecutedBy "+process+" .\r\n"
					+process+" darpa:subjTag  ?sst.\r\n"
					+"FILTER (?oit < 0.5).\r\n"
					+"FILTER (?sst >= 0.5).\r\n"
					+ "\r\n"+
				"}";
		
		UpdateRequest e = UpdateFactory.create(q);
	    UpdateAction.execute(e,jsonModel) ;
	    
	}
	
	public void dataLeakAlert(Model jsonModel, String proc, String net) {
		process = "<http://ss.r/dp/proc/"+proc+">";
		network = "<http://ss.r/dp/obj#"+net+">";
		
		String q =prefix+""
				+ "INSERT { "+process+" darpa:leaksDataTo "+network+". \r\n}"+
				   "WHERE { \r\n" + 
				    network+" darpa:confTag  ?oct.\r\n"+
					process+" darpa:writes "+network+" .\r\n"
					+process+" darpa:intTag  ?sit.\r\n"
					+process+" darpa:confTag  ?sct.\r\n"
					+"FILTER (?oct >= 0.5).\r\n"
					+"FILTER (?sct < 0.5).\r\n"
					+"FILTER (?sit < 0.5).\r\n"
					+ "\r\n"+
				"}";
		
		
		UpdateRequest e = UpdateFactory.create(q);
	    UpdateAction.execute(e,jsonModel) ;
	    
	}
	
	public void corruptFileAlert(Model jsonModel, String proc, String objectString) {
		process = "<http://ss.r/dp/proc/"+proc+">";
		file = "<http://ss.r/dp/obj#"+objectString+">";
		
		String q =prefix+""
				+ "INSERT { "+process+" darpa:corruptFile "+file+". \r\n}"+
				   "WHERE { \r\n" + 
				    file+" darpa:intTag  ?oit.\r\n"+
					process+" darpa:writes "+file+" .\r\n"
					+process+" darpa:intTag  ?sit.\r\n"
					+"FILTER (?oit >= 0.5).\r\n"
					+"FILTER (?sit < 0.5).\r\n"
					+ "\r\n"+
				"}";
	
		
		UpdateRequest e = UpdateFactory.create(q);
	    UpdateAction.execute(e,jsonModel) ;
	    
	}
	
}
