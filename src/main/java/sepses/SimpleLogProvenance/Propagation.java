package sepses.SimpleLogProvenance;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.rdf.model.Property;
import org.apache.jena.rdf.model.RDFNode;
import org.apache.jena.rdf.model.Resource;
import org.apache.jena.rdf.model.Statement;
import org.apache.jena.rdf.model.StmtIterator;
import org.apache.jena.update.UpdateAction;
import org.apache.jena.update.UpdateFactory;
import org.apache.jena.update.UpdateRequest;


public class Propagation {
	public  String prefDarpa ; 
	public  String prefXSD ;
	public  String prefix; 
	public  String process; 
	public String file;
	public Property confTag;
	public Property intTag;
	public Property subjTag;
				
	public Propagation() {
		Model model = ModelFactory.createDefaultModel();		
		prefDarpa = "http://ss.l/dp#";
		confTag = model.createProperty(prefDarpa+"confTag");
		intTag = model.createProperty(prefDarpa+"intTag");
		subjTag = model.createProperty(prefDarpa+"subjTag");
		prefix = "PREFIX darpa: <http://ss.l/dp#>\r\n"
				+  "PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>\r\n"
				+ "PREFIX afn: <http://jena.apache.org/ARQ/function#>";

		
	}
	
	public void readTag(Model jsonModel, String subject, String exec, String objectString) {
		intRead(jsonModel, subject, exec, objectString);
		confRead(jsonModel, subject, exec, objectString);
	}
	
	public void writeTag(Model jsonModel, String subject, String exec, String objectString) {
		confWrite(jsonModel, subject, exec, objectString);
		intWrite(jsonModel, subject, exec, objectString);
	}
	
	public void execTag(Model jsonModel, String subject, String exec, String objectString) {
		subjExec(jsonModel, subject, exec, objectString);
		intExec(jsonModel, subject, exec, objectString);
		confExec(jsonModel, subject, exec, objectString);
	}

	//===================READ ==============================
	
	public void confRead(Model jsonModel, String subject, String exec, String objectString) {
		
		process = "<http://ss.r/dp/proc/"+subject+"#"+exec+">";
		file = "<http://ss.r/dp/obj#"+objectString+">";
		
		String q = prefix+
				"DELETE {"+process+" darpa:confTag ?sct.\r\n}"+
				"INSERT { "+process+" darpa:confTag ?nct. \r\n}"+
				"WHERE { \r\n" + 
					file+" darpa:confTag  ?oct.\r\n"
					+ file+" darpa:isReadBy "+process+".\r\n"
					+process+" darpa:confTag  ?sct."
					+"FILTER (?oct != ?sct).\r\n"
				    + "BIND (afn:min(?oct,?sct) AS ?nct)."
					+ "\r\n"+
				"}";

		UpdateRequest e = UpdateFactory.create(q);
	    UpdateAction.execute(e,jsonModel) ;	
		
	}
	
		
	public  void intRead(Model jsonModel,String subject, String exec, String objectString) {
		
		String q = prefix+
				"DELETE {"+process+" darpa:intTag ?sit.\r\n}"+
				"INSERT { "+process+" darpa:intTag ?nit. \r\n}"+
				"WHERE { \r\n" + 
					file+" darpa:intTag  ?oit.\r\n"
					+ file+" darpa:isReadBy "+process+".\r\n"
					+process+" darpa:intTag  ?sit."
					+"FILTER (?oit != ?sit).\r\n"
				    + "BIND (afn:min(?oit,?sit) AS ?nit)."
					+ "\r\n"+
				"}";

		UpdateRequest e = UpdateFactory.create(q);
	    UpdateAction.execute(e,jsonModel) ;	
			
	}
				  
	//================WRITE===========================
			
	public  void confWrite(Model jsonModel, String subject, String exec, String objectString) {
	    
		process = "http://ss.r/dp/proc/"+subject+"#"+exec;
		Resource respro = jsonModel.createResource(process);
		
		double rsst = getEntityTag(jsonModel, subjTag, respro);
		String q = "";
	    if(rsst >= 0.5) {
	    	//benign
	    	q = prefix+
					"DELETE {"+file+" darpa:confTag ?oct.\r\n}"+
					"INSERT { "+file+" darpa:confTag ?noct. \r\n}"+
					"WHERE { \r\n" + 
						file+" darpa:confTag  ?oct.\r\n"
						+ process+" darpa:writes "+file+".\r\n"
						+process+" darpa:confTag  ?sct."
						+"FILTER (?oct != ?sct).\r\n"
						+"FILTER (?oct != ?noct).\r\n"
						+ "BIND (?sct + 0.2 AS ?nsct)."
						+ "BIND (afn:min(?oct,?nsct) AS ?noct)."
						+ "\r\n"+
					"}";
	       	      
	    }else {
	    	//suspect
	    	q = prefix+
					"DELETE {"+file+" darpa:confTag ?oct.\r\n}"+
					"INSERT { "+file+" darpa:confTag ?cct. \r\n}"+
					"WHERE { \r\n" + 
						file+" darpa:confTag  ?oct.\r\n"
						+ process+" darpa:writes "+file+".\r\n"
						+process+" darpa:confTag  ?sct."
						+"FILTER (?oct != ?sct).\r\n"
						+ "BIND (afn:min(?oct,?sct) AS ?cct)."
						+ "\r\n"+
					"}";
	       	      }
	    
		UpdateRequest e = UpdateFactory.create(q);
	    UpdateAction.execute(e,jsonModel) ;	
	}
	
	public  void intWrite(Model jsonModel, String subject, String exec, String objectString) {
		process = "http://ss.r/dp/proc/"+subject+"#"+exec;
		
		Resource respro = jsonModel.createResource(process);
		
		double rsst = getEntityTag(jsonModel, subjTag, respro);
		String q="";	    
	    if(rsst >= 0.5) {
	      //benign
	    	q = prefix+
					"DELETE {"+file+" darpa:intTag ?oit.\r\n}"+
					"INSERT { "+file+" darpa:intTag ?noit. \r\n}"+
					"WHERE { \r\n" + 
						file+" darpa:intTag  ?oit.\r\n"
						+ process+" darpa:writes "+file+".\r\n"
						+process+" darpa:intTag  ?sit."
						+"FILTER (?oit != ?sit).\r\n"
						+"FILTER (?oit != ?noit).\r\n"
						+ "BIND (?sit + 0.2 AS ?nsit)."
						+ "BIND (afn:min(?oit,?nsit) AS ?noit)."
						+ "\r\n"+
					"}";
		
	    }else {
	     //suspect

	    	q = prefix+
					"DELETE {"+file+" darpa:intTag ?oit.\r\n}"+
					"INSERT { "+file+" darpa:intTag ?nit. \r\n}"+
					"WHERE { \r\n" + 
						file+" darpa:intTag  ?oit.\r\n"
						+ process+" darpa:writes "+file+".\r\n"
						+process+" darpa:intTag  ?sit."
						+"FILTER (?oit != ?sit).\r\n"
						+ "BIND (afn:min(?oit,?nsit) AS ?nit)."
						+ "\r\n"+
					"}";
	    }
		UpdateRequest e = UpdateFactory.create(q);
	    UpdateAction.execute(e,jsonModel) ;		    	
	  }
	
	//================EXEC===========================
			
	public  void subjExec(Model jsonModel, String subject, String exec, String objectString) {
		
		process = "http://ss.r/dp/proc/"+subject+"#"+exec;
		
		Resource respro = jsonModel.createResource(process);
		double rsst = getEntityTag(jsonModel, subjTag, respro);
		String q="";
	    if(rsst >= 0.5) {
	    	//benign
	    	 q = prefix+
					"DELETE {"+process+" darpa:subjTag ?sst.\r\n}"+
					"INSERT { "+process+" darpa:subjTag ?oit. \r\n}"+
					"WHERE { \r\n" + 
						file+" darpa:intTag  ?oit.\r\n"
						+ file+" darpa:isExecutedBy "+process+".\r\n"
						+process+" darpa:subjTag  ?sst."
						+"FILTER (?sst != ?oit).\r\n"
						+ "\r\n"+
					"}";
   
	    }else {
	    	//suspect
	    	q = prefix+
					"DELETE {"+process+" darpa:subjTag ?sst.\r\n}"+
					"INSERT { "+process+" darpa:subjTag ?cit. \r\n}"+
					"WHERE { \r\n" + 
						file+" darpa:intTag  ?oit.\r\n"
						+ file+" darpa:isExecutedBy "+process+".\r\n"
						+process+" darpa:subjTag  ?sst."
						+"FILTER (?sst != ?oit).\r\n"
						+ "BIND (afn:min(?oit,?sst) AS ?cit)."
						+ "\r\n"+
					"}";
	    }

		UpdateRequest e = UpdateFactory.create(q);
	    UpdateAction.execute(e,jsonModel) ;	
	}
	
	
	

	public  void confExec(Model jsonModel, String subject, String exec, String objectString) {
		
		process = "http://ss.r/dp/proc/"+subject+"#"+exec;
		
		Resource respro = jsonModel.createResource(process);		
		double rsst = getEntityTag(jsonModel, subjTag, respro);
		String q ="";
		
		if(rsst < 0.5) {
			//suspect
			q = prefix+
					"DELETE {"+process+" darpa:confTag ?sct.\r\n}"+
					"INSERT { "+process+" darpa:confTag ?oct. \r\n}"+
					"WHERE { \r\n" + 
						file+" darpa:confTag  ?oct.\r\n"
						+ file+" darpa:isExecutedBy "+process+".\r\n"
						+process+" darpa:confTag  ?sct."
						+"FILTER (?sct != ?oct).\r\n"
						+ "BIND (afn:min(?oct,?sct) AS ?cct)."
						+ "\r\n"+
					"}";
   
			}else {
			//benign
				q = prefix+
						"DELETE {"+process+" darpa:confTag ?sct.\r\n}"+
						"INSERT { "+process+" darpa:confTag 1.0^^xsd:double. \r\n}"+
						"WHERE { \r\n" + 
							 file+" darpa:isExecutedBy "+process+".\r\n"
							+process+" darpa:confTag  ?sct."
							+ "\r\n"+
						"}";
			}

		UpdateRequest e = UpdateFactory.create(q);
	    UpdateAction.execute(e,jsonModel) ;	
	 }

	public  void intExec(Model jsonModel, String subject, String exec, String objectString) {

		process = "http://ss.r/dp/proc/"+subject+"#"+exec;
		
		Resource respro = jsonModel.createResource(process);
		
		double rsst = getEntityTag(jsonModel, subjTag, respro);
		String q="";
		if(rsst < 0.5) {
			//suspect
			q = prefix+
					"DELETE {"+process+" darpa:intTag ?sit.\r\n}"+
					"INSERT { "+process+" darpa:intTag ?cit. \r\n}"+
					"WHERE { \r\n" + 
						file+" darpa:confTag  ?oit.\r\n"
						+ file+" darpa:isExecutedBy "+process+".\r\n"
						+process+" darpa:intTag  ?sit."
						+"FILTER (?sit != ?oit).\r\n"
						+ "BIND (afn:min(?oit,?sit) AS ?cit)."
						+ "\r\n"+
					"}";
			}else {
				q = prefix+
						"DELETE {"+process+" darpa:intTag ?sit.\r\n}"+
						"INSERT { "+process+" darpa:intTag 1.0^^xsd:double. \r\n}"+
						"WHERE { \r\n" + 
							 file+" darpa:isExecutedBy "+process+".\r\n"
							+process+" darpa:intTag  ?sit."
							+ "\r\n"+
						"}";
			}
		UpdateRequest e = UpdateFactory.create(q);
	    UpdateAction.execute(e,jsonModel) ;	
		}
	
	
	//================FORK============

		public  void forkTag(Model jsonModel, String prevProc, String proc) {
			String prevProcess = "<http://ss.r/dp/proc/"+prevProc+">";
			process = "<http://ss.r/dp/proc/"+proc+">";
			
			String q = prefix+
					"DELETE {"+process+" darpa:subjTag ?sst."
					          +process+" darpa:confTag ?sct." 
					          +process+" darpa:intTag ?sit.}" +
					"INSERT {"+process+" darpa:subjTag ?psst."
					          +process+" darpa:confTag ?psct." 
					          +process+" darpa:intTag ?sit.}" +
					          "WHERE { \r\n" + 
						process+" darpa:subjTag  ?sst.\r\n"+
						process+" darpa:confTag  ?sct.\r\n"+
						process+" darpa:intTag  ?sit.\r\n"
						+ prevProcess+" darpa:forks "+process+".\r\n"
						+prevProcess+" darpa:subjTag  ?psst."
						+prevProcess+" darpa:confTag  ?psct."
						+prevProcess+" darpa:intTag  ?psit."
						+ "\r\n"+
					"}";

			UpdateRequest e = UpdateFactory.create(q);
		    UpdateAction.execute(e,jsonModel) ;	
			
		}
		

	public double getEntityTag(Model jsonModel, Property prop, Resource entity) {
		double ptag = 0;
		StmtIterator iter = jsonModel.listStatements(entity, prop,(RDFNode) null);
		  while (iter.hasNext()) {
			  Statement s = iter.next();
			  ptag = s.getObject().asLiteral().getDouble();
		  }
		  return ptag;
	}
	
	
}
