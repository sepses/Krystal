package sepses.SimpleLogProvenance;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.rdf.model.Property;
import org.apache.jena.rdf.model.RDFNode;
import org.apache.jena.rdf.model.Resource;
import org.apache.jena.rdf.model.Statement;
import org.apache.jena.rdf.model.StmtIterator;


public class PropagationRule {
	public  String prefRule ; 
	public  String prefXSD ;
	public  String prefix; 
	public  String process; 
	public String file;
	public String net;
	public Property confTag;
	public Property intTag;
	public Property subjTag;
				
	public PropagationRule() {
		Model model = ModelFactory.createDefaultModel();		
		prefRule = "http://w3id.org/sepses/vocab/rule#";
		confTag = model.createProperty(prefRule+"confTag");
		intTag = model.createProperty(prefRule+"intTag");
		subjTag = model.createProperty(prefRule+"subjTag");
		
	}
	
	public void readTag(Model jsonModel, String subject, String exec, String objectString) {
		intRead(jsonModel, subject, exec, objectString);
		confRead(jsonModel, subject, exec, objectString);
	}
	
	public void writeTag(Model jsonModel, String subject, String exec, String objectString) {
		confWrite(jsonModel, subject, exec, objectString);
		intWrite(jsonModel, subject, exec, objectString);
	}
	
	public void receiveTag(Model jsonModel, String subject, String exec, String objectString) {
		intReceive(jsonModel, subject, exec, objectString);
		confReceive(jsonModel, subject, exec, objectString);
	}
	
	public void sendTag(Model jsonModel, String subject, String exec, String objectString) {
		confSend(jsonModel, subject, exec, objectString);
		intSend(jsonModel, subject, exec, objectString);
	}
	
	public void execTag(Model jsonModel, String subject, String exec, String objectString) {
		subjExec(jsonModel, subject, exec, objectString);
		intExec(jsonModel, subject, exec, objectString);
		confExec(jsonModel, subject, exec, objectString);
	}

	//===================READ ==============================
	
	public void confRead(Model jsonModel, String subject, String exec, String objectString) {
		
		process = "http://w3id.org/sepses/resource/proc"+subject+"#"+exec;
		file = "http://w3id.org/sepses/resource/file#"+objectString;
		
		Resource respro = jsonModel.createResource(process);
		Resource resfile = jsonModel.createResource(file);
		double rsct = getEntityTag(jsonModel, confTag, respro);
		double roct = getEntityTag(jsonModel, confTag, resfile);		
	    	
		if(roct!=rsct) {
	         double nct = min(roct,rsct);
	         jsonModel.removeAll(respro, confTag, null);
	         jsonModel.addLiteral(respro, confTag, nct);
	    }
	}
	
		
	public  void intRead(Model jsonModel,String subject, String exec, String objectString) {
		
		process = "http://w3id.org/sepses/resource/proc"+subject+"#"+exec;
		file = "http://w3id.org/sepses/resource/file#"+objectString;
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
	
	//===================RECEIVE ==============================
	
	public void confReceive(Model jsonModel, String subject, String exec, String objectString) {
		
		process = "http://w3id.org/sepses/resource/proc"+subject+"#"+exec;
		net = "http://w3id.org/sepses/resource/soc#"+objectString;
		
		Resource respro = jsonModel.createResource(process);
		Resource resnet = jsonModel.createResource(net);
		double rsct = getEntityTag(jsonModel, confTag, respro);
		double roct = getEntityTag(jsonModel, confTag, resnet);		
	    	
		if(roct!=rsct) {
	         double nct = min(roct,rsct);
	         jsonModel.removeAll(respro, confTag, null);
	         jsonModel.addLiteral(respro, confTag, nct);
	    }
	}
	
		
	public  void intReceive(Model jsonModel,String subject, String exec, String objectString) {
		
		process = "http://w3id.org/sepses/resource/proc"+subject+"#"+exec;
		net = "http://w3id.org/sepses/resource/soc#"+objectString;
		Resource respro = jsonModel.createResource(process);
		Resource resnet = jsonModel.createResource(net);
		
		double rsit = getEntityTag(jsonModel, intTag, respro);
		double roit = getEntityTag(jsonModel, intTag, resnet);
		
		if(roit!=rsit) {
	         double nit = min(roit,rsit);
	         jsonModel.removeAll(respro, intTag, null);
	         jsonModel.addLiteral(respro, intTag, nit);
	    }
		
	}
				  
	//================SEND===========================
			
	public  void confSend(Model jsonModel, String subject, String exec, String objectString) {
	    process = "http://w3id.org/sepses/resource/proc"+subject+"#"+exec;
		net = "http://w3id.org/sepses/resource/soc#"+objectString;
		
		Resource respro = jsonModel.createResource(process);
		Resource resnet = jsonModel.createResource(net);
		
		double rsst = getEntityTag(jsonModel, subjTag, respro);
		double rsct = getEntityTag(jsonModel, confTag, respro);
		double roct = getEntityTag(jsonModel, confTag, resnet);

	    if(rsst >= 0.5) {
	    	//benign
	       if(roct!=rsct) {
	         double noct = min(rsct+0.2,roct);
	          if(noct!=roct) {
	             jsonModel.removeAll(resnet, confTag, null);
		         jsonModel.addLiteral(resnet, confTag, noct);
		     }  
	      }	      
	    }else {
	    	//suspect
	    	 if(roct!=rsct) {
	           double noct = min(rsct,roct);
	           	 jsonModel.removeAll(resnet, confTag, null);
	           	 jsonModel.addLiteral(resnet, confTag, noct);
	    	 }
	    }
	}
	
	public  void intSend(Model jsonModel, String subject, String exec, String objectString) {
		process = "http://w3id.org/sepses/resource/proc"+subject+"#"+exec;
		net = "http://w3id.org/sepses/resource/soc#"+objectString;
		
		Resource respro = jsonModel.createResource(process);
		Resource resnet = jsonModel.createResource(net);
		
		double rsst = getEntityTag(jsonModel, subjTag, respro);
		double rsit = getEntityTag(jsonModel, intTag, respro);
		double roit = getEntityTag(jsonModel, intTag, resnet);
			    
	    if(rsst >= 0.5) {
	      //benign
	    	if(roit!=rsit) {
	         double noit = min(rsit+0.2,roit);
	         if(noit!=roit) {
	        	 jsonModel.removeAll(resnet, intTag, null);
		         jsonModel.addLiteral(resnet, intTag, noit);
		     }  
	     }   
	    }else {
	     //suspect
	    	if(roit!=rsit) {
	         double noit = min(rsit,roit);
	         jsonModel.removeAll(resnet, intTag, null);
	         jsonModel.addLiteral(resnet, intTag, noit);
	    	}
	    }
	    	
	  }
	
	//================WRITE===========================
	
		public  void confWrite(Model jsonModel, String subject, String exec, String objectString) {
		    process = "http://w3id.org/sepses/resource/proc"+subject+"#"+exec;
			file = "http://w3id.org/sepses/resource/file#"+objectString;
			
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
			process = "http://w3id.org/sepses/resource/proc"+subject+"#"+exec;
			file = "http://w3id.org/sepses/resource/file#"+objectString;
			
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
		
		process = "http://w3id.org/sepses/resource/proc"+subject+"#"+exec;
		file = "http://w3id.org/sepses/resource/file#"+objectString;
		
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
		
		process = "http://w3id.org/sepses/resource/proc"+subject+"#"+exec;
		file = "http://w3id.org/sepses/resource/file#"+objectString;
		
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

		process = "http://w3id.org/sepses/resource/proc"+subject+"#"+exec;
		file = "http://w3id.org/sepses/resource/file#"+objectString;
		
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
			String prevProc = "http://w3id.org/sepses/resource/proc"+prevProcess;
			process = "http://w3id.org/sepses/resource/proc"+process;
			
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
		double ptag = 1.0;
		StmtIterator iter = jsonModel.listStatements(entity, prop,(RDFNode) null);
		  while (iter.hasNext()) {
			  Statement s = iter.next();
			  ptag = s.getObject().asLiteral().getDouble();
		  }
		  return ptag;
	}
	
	
}
