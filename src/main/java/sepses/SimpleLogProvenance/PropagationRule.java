package sepses.SimpleLogProvenance;

import java.util.ArrayList;
import java.util.HashMap;

import org.apache.jena.query.QueryExecution;
import org.apache.jena.query.QueryExecutionFactory;
import org.apache.jena.query.QuerySolution;
import org.apache.jena.query.ResultSet;
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
	public Property suspEnv;
	public Property timestamp;
	public Property counter;
	
				
	public PropagationRule() {
		Model model = ModelFactory.createDefaultModel();		
		prefRule = "http://w3id.org/sepses/vocab/rule#";
		prefix = "http://w3id.org/sepses/vocab/event/log#";
		confTag = model.createProperty(prefRule+"confTag");
		intTag = model.createProperty(prefRule+"intTag");
		subjTag = model.createProperty(prefRule+"subjTag");
		suspEnv = model.createProperty(prefRule+"suspEnv");
		timestamp = model.createProperty(prefix+"timestamp");
		counter = model.createProperty(prefRule+"counter");
		
	}
	
	public void loadTag(Model jsonModel, String subject, String exec, String objectString) {
		subjLoad(jsonModel, subject, exec, objectString);
		intRead(jsonModel, subject, exec, objectString);
		confRead(jsonModel, subject, exec, objectString);
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
		intExec(jsonModel, subject, exec, objectString);
		confExec(jsonModel, subject, exec, objectString);
		subjExec(jsonModel, subject, exec, objectString);

	}
	
		//===================READ / LOAD ==============================
	
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
	
	//===================ONLY LOAD ==============================
public  void subjLoad(Model jsonModel, String subject, String exec, String objectString) {
		
		process = "http://w3id.org/sepses/resource/proc"+subject+"#"+exec;
		file = "http://w3id.org/sepses/resource/file#"+objectString;
		
		Resource respro = jsonModel.createResource(process);
		Resource resfile = jsonModel.createResource(file);
		double rsst = getEntityTag(jsonModel, subjTag, respro);
		double rost = getEntityTag(jsonModel, subjTag, resfile);		
	    
	    
	    	if(rost!=rsst) {
	    		 double nsst = min(rsst,rost);
		         jsonModel.removeAll(respro, subjTag, null);
		         jsonModel.addLiteral(respro, subjTag, nsst);
		
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
		boolean rsenv = getSuspEnvTag(jsonModel, suspEnv, respro);

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
	    	if(!rsenv) {
	    	//suspect
	    	 if(roct!=rsct) {
	           double noct = min(rsct,roct);
	           	 jsonModel.removeAll(resnet, confTag, null);
	           	 jsonModel.addLiteral(resnet, confTag, noct);
	    	 }
	    	}else {
	    	//suspect env	
	    		if(roct!=rsct) {
	   	         double noct = min(rsct+0.1,roct);
	   	          if(noct!=roct) {
	   	             jsonModel.removeAll(resnet, confTag, null);
	   		         jsonModel.addLiteral(resnet, confTag, noct);
	   		     }  
	   	      }	
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
		boolean rsenv = getSuspEnvTag(jsonModel, suspEnv, respro);
		
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
	    	if(!rsenv) {
	    		//suspect
	    	if(roit!=rsit) {
	         double noit = min(rsit,roit);
	         jsonModel.removeAll(resnet, intTag, null);
	         jsonModel.addLiteral(resnet, intTag, noit);
	    	}
	    }else {
	    	  //suspect env
	    	if(roit!=rsit) {
	         double noit = min(rsit+0.1,roit);
	         if(noit!=roit) {
	        	 jsonModel.removeAll(resnet, intTag, null);
		         jsonModel.addLiteral(resnet, intTag, noit);
		     }  
	     }  
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
			boolean rsenv = getSuspEnvTag(jsonModel, suspEnv, respro);
			
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
		    	if(!rsenv) {
		    	//suspect
		    	 if(roct!=rsct) {
		           double noct = min(rsct,roct);
		           	 jsonModel.removeAll(resfile, confTag, null);
		           	 jsonModel.addLiteral(resfile, confTag, noct);
		    	 }
		    	} else {
		    	//suspect env
		    		if(roct!=rsct) {
				         double noct = min(rsct+0.1,roct);
				          if(noct!=roct) {
				             jsonModel.removeAll(resfile, confTag, null);
					         jsonModel.addLiteral(resfile, confTag, noct);
					     }  
				      }
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
			boolean rsenv = getSuspEnvTag(jsonModel, suspEnv, respro);
				    
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
		     if(!rsenv) {
		     //suspect
		    	if(roit!=rsit) {
		         double noit = min(rsit,roit);
		         jsonModel.removeAll(resfile, intTag, null);
		         jsonModel.addLiteral(resfile, intTag, noit);
		    	}
		    }else {
		    	if(roit!=rsit) {
			         double noit = min(rsit+0.1,roit);
			         if(noit!=roit) {
			        	 jsonModel.removeAll(resfile, intTag, null);
				         jsonModel.addLiteral(resfile, intTag, noit);
				     }  
			     }  
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
		boolean rsenv = getSuspEnvTag(jsonModel, suspEnv, respro);		
	    
	    if(rsst >= 0.5) {
	    	//benign
			if(roit!=rsst) {
		         jsonModel.removeAll(respro, subjTag, null);
		         jsonModel.addLiteral(respro, subjTag, roit);
		    }
	    }else {
	    	if(!rsenv) {
	    	//suspect
	    	if(roit!=rsst) {
	    		 double nsst = min(rsst,roit);
		         jsonModel.removeAll(respro, subjTag, null);
		         jsonModel.addLiteral(respro, subjTag, nsst);
		         jsonModel.addLiteral(respro, suspEnv, true);
		    }
	    }else {
	    	//suspect env
	    	if(roit!=rsst) {
		         jsonModel.removeAll(respro, subjTag, null);
		         jsonModel.addLiteral(respro, subjTag, roit);
		    }
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
			    jsonModel.removeAll(respro, intTag, null);
			    jsonModel.addLiteral(respro, intTag, roit);
			
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
			boolean rpenv = getSuspEnvTag(jsonModel, suspEnv, resPrevPro);
			
			jsonModel.removeAll(respro, subjTag, null);
			jsonModel.addLiteral(respro, subjTag, rpsst);
			jsonModel.removeAll(respro, confTag,  null);
			jsonModel.addLiteral(respro, confTag, rpsct);
			jsonModel.removeAll(respro, intTag,  null);
			jsonModel.addLiteral(respro, intTag, rpsit);
			if(rpenv) {
				jsonModel.addLiteral(respro, suspEnv, true);
			}
			
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
	
	public boolean getSuspEnvTag(Model jsonModel, Property prop, Resource entity) {
		boolean suspEnv = false;
		StmtIterator iter = jsonModel.listStatements(entity, prop,(RDFNode) null);
		  while (iter.hasNext()) {
			  Statement s = iter.next();
			  suspEnv = s.getObject().asLiteral().getBoolean();
		  }
		  return suspEnv;
	}
	
	public int getCounter(Model jsonModel, Property prop, Resource entity) {
		int counter = 0;
		StmtIterator iter = jsonModel.listStatements(entity, prop,(RDFNode) null);
		  while (iter.hasNext()) {
			  Statement s = iter.next();
			  counter = s.getObject().asLiteral().getInt();
		  }
		  return counter;
	}
	
	public long getTimer(Model jsonModel, Property prop, Resource entity) {
		long timer = 0;
		StmtIterator iter = jsonModel.listStatements(entity, prop,(RDFNode) null);
		  while (iter.hasNext()) {
			  Statement s = iter.next();
			  timer = s.getObject().asLiteral().getLong();
		  }
		  return timer;
	}
	
	//=============add time for subject======================
	public void putProcessTime(Model jsonModel, String subject, String exec, long ts) {
		process = "http://w3id.org/sepses/resource/proc"+subject+"#"+exec;
//		System.out.println("init!"+process+ts);
		Resource respro = jsonModel.createResource(process);		
	    jsonModel.removeAll(respro, timestamp, null);
	    jsonModel.addLiteral(respro, timestamp, ts);
		
	}
	
	public void putCounter(Model jsonModel, String subject, String exec) {
		process = "http://w3id.org/sepses/resource/proc"+subject+"#"+exec;
		
		Resource respro = jsonModel.createResource(process);	
		int prevCounter = getCounter(jsonModel, counter, respro);
				
	    jsonModel.removeAll(respro, counter, null);
	    jsonModel.addLiteral(respro, counter, prevCounter+1);
		
	}
	//=================decay=========================
	
	public void decayProcess(Model jsonModel, long timer, double period, double T) {
		
		String execQuery = "PREFIX : <http://w3id.org/sepses/vocab/rule#>\r\n" + 
				"PREFIX log: <http://w3id.org/sepses/vocab/event/log#>\r\n" + 
				"SELECT ?s ?it \r\n"
				+ "WHERE {\r\n" + 
				" ?s :intTag ?it.\r\n" +
				" ?s :subjTag ?st.\r\n" + 
				" FILTER (?st >= 0.5) \r\n" +
				" FILTER (?it < 0.5) \r\n" +
				"}";
		
		 QueryExecution qexec = QueryExecutionFactory.create(execQuery, jsonModel);
		 ArrayList<HashMap<String, RDFNode>> list = new ArrayList<HashMap<String, RDFNode>>();
		 
		 ResultSet result = qexec.execSelect();
		 
		 while (result.hasNext()) {
			 HashMap<String, RDFNode> eachres = new HashMap<String, RDFNode>();
	         QuerySolution soln = result.nextSolution() ;         
	         eachres.put("s", soln.get("s"));
	         eachres.put("it",soln.get("it"));
	         list.add(eachres);
	        }
		 //System.out.println(list.size());
		  for(int i=0;i<list.size();i++) {
			  Resource s = list.get(i).get("s").asResource();
			  int c = getCounter(jsonModel, counter, s);
			  long t = getTimer(jsonModel, timestamp, s);
			  long age = timer - t;
			  //System.out.println(c+" : "+age);
	          double periodNano = period*1000000000;
	          //System.out.println(c+" "+age+" : "+(c*periodNano));
	 		if(age >= (c*periodNano)) {
	 			//System.out.println("yes, adult!");
	 			jsonModel.removeAll(s, counter, null);
		 	    jsonModel.addLiteral(s, counter, c+1);	
	 			double it = list.get(i).get("it").asLiteral().getDouble();
	 			double decayRateIntTag = (it*period)+((1-period)*T);	
	 			double nit = 0;	 		
	 			//System.out.println(s+"=>"+it+" => "+decayRateIntTag);
	 			if(it<decayRateIntTag) {
	 			 	 nit = decayRateIntTag;
	 				 jsonModel.removeAll(s, intTag, null);
		 			 jsonModel.addLiteral(s, intTag, nit);
	 			}
	 		}
		 }
	}	

public void decayIndividualProcess(Model jsonModel, String proc,long timer, double period, double Tb, double Te) {
	process = "http://w3id.org/sepses/resource/proc"+proc;
	//System.out.println(process);
	Resource s = jsonModel.createResource(process);
	double rsst = getEntityTag(jsonModel, subjTag, s);
	long t = getTimer(jsonModel, timestamp, s);
	long age = timer - t;
	double periodNano = period*1000000000;
	//System.out.println(process +" : "+timer+ " : "+t);
	
	//1. decay data integrity
	double rsit = getEntityTag(jsonModel, intTag, s); 
	if(rsit<0.5) { //get only low data tag integrity of subj 
	    if(rsst>=0.5) {  //if subject is benign   
		  if(age >= periodNano) {
			  System.out.println(s+" benign adult! "+age);
		    double decayRateIntTag = (rsit*period)+((1-period)*Tb); //add decay rate
		    if(rsit<decayRateIntTag) { 
			  jsonModel.removeAll(s, intTag, null);
			  jsonModel.addLiteral(s, intTag, decayRateIntTag);
	        }
		  }
		} else {  //if subject is suspect 
		  boolean rsEnv = getSuspEnvTag(jsonModel, suspEnv, s);
		  if(rsEnv) { //if suspect in environment
		    if(age >= periodNano) {
		 	  double decayRateIntTag = (rsit*period)+((1-period)*Te);
			  if(rsit<decayRateIntTag) {
				 jsonModel.removeAll(s, intTag, null);
				 jsonModel.addLiteral(s, intTag, decayRateIntTag);
				}
			 }
		  }
		} 
	  }
	//2. decay data confidentiality
		double rsct = getEntityTag(jsonModel, confTag, s); 
		if(rsct<0.5) { //get only low data tag integrity of subj 
		    if(rsst>=0.5) {  //if subject is benign   
			  if(age >= periodNano) {		  
			    double decayRateConfTag = (rsct*period)+((1-period)*Tb); //add decay rate
			    if(rsct<decayRateConfTag) { 
				  jsonModel.removeAll(s, confTag, null);
				  jsonModel.addLiteral(s, confTag, decayRateConfTag);
		        }
			  }    
			} else {  //if subject is suspect 
			  boolean rsEnv = getSuspEnvTag(jsonModel, suspEnv, s);
			  if(rsEnv) { //if suspect in environment
			    if(age >= periodNano) {
			 	  double decayRateConfTag = (rsct*period)+((1-period)*Te);
				  if(rsct<decayRateConfTag) {
					 jsonModel.removeAll(s, confTag, null);
					 jsonModel.addLiteral(s, confTag, decayRateConfTag);
					}
				 }   
			  }
			} 
		 }
    
  }
}