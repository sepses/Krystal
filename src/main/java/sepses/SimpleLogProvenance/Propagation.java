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
		
		process = "http://ss.r/dp/proc/"+subject+"#"+exec;
		file = "http://ss.r/dp/obj#"+objectString;
		Resource respro = jsonModel.createResource(process);
		Resource resfile = jsonModel.createResource(file);
		
		double rsit = getEntityTag(jsonModel, intTag, respro);
		double roit = getEntityTag(jsonModel, intTag, resfile);
		
		if(roit!=rsit) {
	         double nit = min(roit,rsit);
	         jsonModel.removeAll(respro, intTag, null);
	         jsonModel.addLiteral(respro, intTag, nit);
	    }
		
	}
				  
	//================WRITE===========================
			
	public  void confWrite(Model jsonModel, String subject, String exec, String objectString) {
	    process = "http://ss.r/dp/proc/"+subject+"#"+exec;
		file = "http://ss.r/dp/obj#"+objectString;
		
		Resource respro = jsonModel.createResource(process);
		Resource resfile = jsonModel.createResource(file);
		
		double rsst = getEntityTag(jsonModel, subjTag, respro);
		double rsct = getEntityTag(jsonModel, confTag, respro);
		double roct = getEntityTag(jsonModel, confTag, resfile);

	    if(rsst >= 0.5) {
	    	//benign
	       if(roct!=rsct) {
	         double noct = min(rsct+0.2,roct);
	          if(noct!=roct) {
	             jsonModel.removeAll(resfile, confTag, null);
		         jsonModel.addLiteral(resfile, confTag, noct);
		     }  
	      }	      
	    }else {
	    	//suspect
	    	 if(roct!=rsct) {
	           double noct = min(rsct,roct);
	           	 jsonModel.removeAll(resfile, confTag, null);
	           	 jsonModel.addLiteral(resfile, confTag, noct);
	    	 }
	    }
	}
	
	public  void intWrite(Model jsonModel, String subject, String exec, String objectString) {
		process = "http://ss.r/dp/proc/"+subject+"#"+exec;
		file = "http://ss.r/dp/obj#"+objectString;
		
		Resource respro = jsonModel.createResource(process);
		Resource resfile = jsonModel.createResource(file);
		
		double rsst = getEntityTag(jsonModel, subjTag, respro);
		double rsit = getEntityTag(jsonModel, intTag, respro);
		double roit = getEntityTag(jsonModel, intTag, resfile);
			    
	    if(rsst >= 0.5) {
	      //benign
	    	if(roit!=rsit) {
	         double noit = min(rsit+0.2,roit);
	         if(noit!=roit) {
	        	 jsonModel.removeAll(resfile, intTag, null);
		         jsonModel.addLiteral(resfile, intTag, noit);
		     }  
	     }   
	    }else {
	     //suspect
	    	if(roit!=rsit) {
	         double noit = min(rsit,roit);
	         jsonModel.removeAll(resfile, intTag, null);
	         jsonModel.addLiteral(resfile, intTag, noit);
	    	}
	    }
	    	
	  }
	
	//================EXEC===========================
			
	public  void subjExec(Model jsonModel, String subject, String exec, String objectString) {
		
		process = "http://ss.r/dp/proc/"+subject+"#"+exec;
		file = "http://ss.r/dp/obj#"+objectString;
		
		Resource respro = jsonModel.createResource(process);
		Resource resfile = jsonModel.createResource(file);
		double rsst = getEntityTag(jsonModel, subjTag, respro);
		double roit = getEntityTag(jsonModel, intTag, resfile);		
	    
	    if(rsst >= 0.5) {
	    	//benign
			if(roit!=rsst) {
		         jsonModel.removeAll(respro, subjTag, null);
		         jsonModel.addLiteral(respro, subjTag, roit);
		    }
	    }else {
	    	//suspect
	    	if(roit!=rsst) {
	    		 double nsst = min(rsst,roit);
		         jsonModel.removeAll(respro, subjTag, null);
		         jsonModel.addLiteral(respro, subjTag, nsst);
		    }
	    }
	}
	
	
	

	public  void confExec(Model jsonModel, String subject, String exec, String objectString) {
		
		process = "http://ss.r/dp/proc/"+subject+"#"+exec;
		file = "http://ss.r/dp/obj#"+objectString;
		
		Resource respro = jsonModel.createResource(process);
		Resource resfile = jsonModel.createResource(file);
		
		double rsst = getEntityTag(jsonModel, subjTag, respro);
		double rsct = getEntityTag(jsonModel, confTag, respro);
		double roct = getEntityTag(jsonModel, confTag, resfile);
		
		if(rsst < 0.5) {
			//suspect
			if(roct!=rsct) {
		         double nsct = min(rsct,roct);
		         jsonModel.removeAll(respro, confTag, null);
		         jsonModel.addLiteral(respro, confTag, nsct);
				}
			}else {
			//benign
				double nrsst = 1.0;	
			    jsonModel.removeAll(respro, confTag, null);
			    jsonModel.addLiteral(respro, confTag, nrsst);
			
			}
	 }

	public  void intExec(Model jsonModel, String subject, String exec, String objectString) {

		process = "http://ss.r/dp/proc/"+subject+"#"+exec;
		file = "http://ss.r/dp/obj#"+objectString;
		
		Resource respro = jsonModel.createResource(process);
		Resource resfile = jsonModel.createResource(file);
		
		double rsst = getEntityTag(jsonModel, subjTag, respro);
		double rsit = getEntityTag(jsonModel, intTag, respro);
		double roit = getEntityTag(jsonModel, intTag, resfile);
		
		if(rsst < 0.5) {
			//suspect
			if(roit!=rsit) {
		         double nsit = min(rsit,roit);
		         jsonModel.removeAll(respro, intTag, null);
		         jsonModel.addLiteral(respro, intTag, nsit);
				}
			}else {
			//benign
				double nrsit = 1.0;	
			    jsonModel.removeAll(respro, intTag, null);
			    jsonModel.addLiteral(respro, intTag, nrsit);
			
			}
		
		}
	
	
	//================FORK============

		public  void forkTag(Model jsonModel, String prevProcess, String process) {
			String prevProc = "http://ss.r/dp/proc/"+prevProcess;
			process = "http://ss.r/dp/proc/"+process;
			
			Resource resPrevPro = jsonModel.createResource(prevProc);
			Resource respro = jsonModel.createResource(process);
			
			double rpsst = getEntityTag(jsonModel, subjTag, resPrevPro);
			double rpsct = getEntityTag(jsonModel, confTag, resPrevPro);
			double rpsit = getEntityTag(jsonModel, intTag, resPrevPro);
			
			jsonModel.removeAll(respro, subjTag, null);
			jsonModel.addLiteral(respro, subjTag, rpsst);
			jsonModel.removeAll(respro, confTag,  null);
			jsonModel.addLiteral(respro, confTag, rpsct);
			jsonModel.removeAll(respro, intTag,  null);
			jsonModel.addLiteral(respro, intTag, rpsit);
			
		}
		

	public double min(double s, double o){
		if(s<o) {
			return s;
		}else {
			return o;
		}
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
