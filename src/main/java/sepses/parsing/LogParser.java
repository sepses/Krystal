package sepses.parsing;
import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Set;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.sparql.pfunction.library.splitIRI;

import com.jsoniter.JsonIterator;
import com.jsoniter.any.Any;

import sepses.SimpleLogProvenance.AlertRule;
import sepses.SimpleLogProvenance.PropagationRule;

public class LogParser {
	public String eventType;
	public Any eventNode;
	public Any networkNode;
	public Any datumNode;
	public String objectString;
	public String exec;
	public String subject;
	public String object;
	public String netObject;
	public String netAddress;
	public String cmdline;
	public HashMap<String, String> uuIndex;
	public ArrayList<String> fieldfilter;
	public ArrayList<String> confidentialdir;
	
	public LogParser(String line) {
		Any jsonNode=JsonIterator.deserialize(line);
			datumNode = jsonNode.get("datum");
	}
	
	public Set<String> parseJSONtoRDF(Model jsonModel, ArrayList<String> fieldfilter, ArrayList<String> confidentialdir, HashMap<String, String> uuIndex, Set<String> Process, Set<String> File, Set<String> Network, HashMap<String, String> NetworkObject, HashMap<String, String> ForkObject , Set<String> lastEvent, String lastAccess ) throws IOException{	
		
		//filter is the line is an event or not
		eventNode = datumNode.get("com.bbn.tc.schema.avro.cdm18.Event");
		if(eventNode.toBoolean()) {
			eventType = eventNode.toString();
			if(!filterLine(eventType, fieldfilter)){
				String mapper = "";
				LogMapping lm = new LogMapping();	
				subject = shortenUUID(eventNode.get("subject").get("com.bbn.tc.schema.avro.cdm18.UUID").toString(),uuIndex);
				exec = eventNode.get("properties").get("map").get("exec").toString();
				objectString = cleanLine(eventNode.get("predicateObjectPath").get("string").toString());	
				object = shortenUUID(eventNode.get("predicateObject").get("com.bbn.tc.schema.avro.cdm18.UUID").toString(),uuIndex);
				String processMap = "";
				String fileMap = "";
				String prevProcess="";
				String networkMap="";
				
				
				//is file new
				if(isEntityNew(objectString, File)) {
					//is file confidential
					if(isConfidentialFile(objectString, confidentialdir)) {
						fileMap = lm.initialConfFileTagMap(objectString);	
					}else {
					    fileMap = lm.initialFileTagMap(objectString);
					}
					
				}
				
				
				//is process new
				if(isEntityNew(subject+"#"+exec, Process)) {
					
					//is it forked by another previous process? 
					prevProcess = getPreviousForkProcess(subject, ForkObject);
						//if yes create fork Event
						if(!prevProcess.isEmpty() && !eventType.contains("EVENT_EXECUTE")) {
							forkEvent(lm, prevProcess, subject+"#"+exec, jsonModel);
						}else {
	                       //tag new process
							processMap = lm.initialProcessTagMap(subject+"#"+exec);
						}
					
				}
				
				
				  if(eventType.contains("EVENT_WRITE")) {
					  
						if(objectString!="" && !objectString.contains("<unknown>")) {
							String curWrite = subject+exec+"write"+objectString;
							if	(!lastEvent.contains(curWrite)) {				
								
								mapper = lm.writeMap(subject,exec,objectString)+fileMap+processMap;
						
								storeEntity(objectString, File);
								storeEntity(subject+"#"+exec, Process);
						
								
								Reader targetReader = new StringReader(mapper);
								jsonModel.read(targetReader, null, "N-TRIPLE");
								
								//AlertRule alert = new AlertRule();
								//alert.corruptFileAlert(jsonModel, subject+"#"+exec, objectString);
								
								PropagationRule prop = new PropagationRule();
								prop.writeTag(jsonModel, subject, exec, objectString);
								
								lastEvent.add(curWrite);
								
								//System.out.println(curWrite);
								
								
							}
					  }
					  
					}else if(eventType.contains("EVENT_READ")) {
					
						//check last read to reduce unnecessary duplicate event processing			
						String curRead = subject+exec+"read"+objectString;
							if(objectString!="" && !objectString.contains("<unknown>")) {
								if	(!lastEvent.contains(curRead)) {
									mapper = lm.readMap(subject,exec,objectString)+fileMap+processMap;
						
									storeEntity(objectString, File);
									storeEntity(subject+"#"+exec, Process);
									
									Reader targetReader = new StringReader(mapper);
									jsonModel.read(targetReader, null, "N-TRIPLE");
																
									PropagationRule prop = new PropagationRule();
									prop.readTag(jsonModel, subject, exec, objectString);										
									
									lastEvent.add(curRead);
									
									//System.out.println(curRead);
								}
							}
					
					}else if(eventType.contains("EVENT_EXECUTE")) {	
					
						 cmdline = eventNode.get("properties").get("map").get("cmdLine").toString();
						 cmdline = cleanCmd(cmdline);
						 
						 String process2 = "";
						 
						 if(!cmdline.isEmpty() || cmdline!=null) {
							    if(cmdline.contains(" ")) {
									String newproc = cmdline.substring(0,cmdline.indexOf(" "));
										String[] nnewproc = newproc.split("/"); //incase there is full path e.g. "/tmp/vUgefal"
										if(nnewproc.length>1) {
											process2 = nnewproc[nnewproc.length-1];
										}else {
											process2 = newproc;
										}
									}else {
										process2 = cmdline;
									}
							}
						 
						 if(!process2.isEmpty()) {
							
							 
							 if(prevProcess.isEmpty()) {
								 putNewForkObject(subject+"#"+exec, subject, ForkObject);
								 prevProcess = getPreviousForkProcess(subject, ForkObject);
							 }
							 
						
							 forkEvent(lm, prevProcess, subject+"#"+process2, jsonModel);

						 }
						 
						
						 
						 mapper = lm.executeMap(subject,process2, objectString, cmdline)+fileMap;
						 
						 storeEntity(objectString, File);
						 storeEntity(subject+"#"+exec, Process);
						 storeEntity(subject+"#"+process2, Process);
						 
						// System.out.print("execute");
						 Reader targetReader = new StringReader(mapper);
						 jsonModel.read(targetReader, null, "N-TRIPLE");
						 
						 AlertRule alert = new AlertRule();
						 alert.execAlert(jsonModel, subject+"#"+process2, objectString);
						 
						 
						 PropagationRule prop = new PropagationRule();
						 prop.execTag(jsonModel, subject, process2, objectString);
						 
						 
					
					}else if(eventType.contains("EVENT_FORK")) {
					
						putNewForkObject(subject+"#"+exec, object, ForkObject);
						
						storeEntity(subject+"#"+exec, Process);
					
						// System.out.println("fork");
						Reader targetReader = new StringReader(processMap);
						jsonModel.read(targetReader, null, "N-TRIPLE");
						 
						
						
					}else if(eventType.contains("EVENT_SENDTO")) {
					
						String IPAddress = getIpAddress(object, NetworkObject);
						
						if(!IPAddress.isEmpty()) {						
							if(isEntityNew(IPAddress, Network)) {
								 networkMap = lm.initialNetworkTagMap(IPAddress);
							}
							
						//	String curSend = subject+exec+"send"+IPAddress;
						//	if	(!lastEvent.contains(curSend)) {
								
								mapper = lm.sendMap(subject,exec,IPAddress) + networkMap+processMap;	
								
								storeEntity(IPAddress, Network);
								storeEntity(subject+"#"+exec, Process);
								
								 //System.out.println("sendto"+subject+"#"+exec+IPAddress);
								 
								Reader targetReader = new StringReader(mapper);
								jsonModel.read(targetReader, null, "N-TRIPLE");
								
								AlertRule alert = new AlertRule();
								alert.dataLeakAlert(jsonModel, subject+"#"+exec, IPAddress);
								
								PropagationRule prop = new PropagationRule();
								prop.writeTag(jsonModel, subject, exec, IPAddress);
								
							//	lastEvent.add(curSend);
								
							//}
							
						}
						
						
						
					}else if(eventType.contains("EVENT_RECVFROM")) {
					
				
						
						String IPAddress = getIpAddress(object, NetworkObject);
					
						
						if(!IPAddress.isEmpty()) {
							
							if(isEntityNew(IPAddress, Network)) {
								networkMap = lm.initialNetworkTagMap(IPAddress);
							}
							
							//String curReceive = subject+exec+"receive"+IPAddress;
							//if	(!lastEvent.contains(curReceive)) {
								
								mapper = lm.receiveMap(subject,exec,IPAddress) + networkMap+processMap;
								
								storeEntity(IPAddress, Network);
								storeEntity(subject+"#"+exec, Process);
								//System.out.println("receivefrom"+subject+"#"+exec+IPAddress);
								Reader targetReader = new StringReader(mapper);
								jsonModel.read(targetReader, null, "N-TRIPLE");
								
								PropagationRule prop = new PropagationRule();
								prop.readTag(jsonModel, subject, exec, IPAddress);
								
								//	lastEvent.add(curReceive);
							//}
														 
						}
					}
				}
			 
		}else if(datumNode.get("com.bbn.tc.schema.avro.cdm18.NetFlowObject").toBoolean()) {
			    networkNode = datumNode.get("com.bbn.tc.schema.avro.cdm18.NetFlowObject");
				netObject = shortenUUID(networkNode.get("uuid").toString(),uuIndex); 
				netAddress = networkNode.get("remoteAddress").toString()+":"+networkNode.get("remotePort").toString();
				putNewNetworkObject(netObject, netAddress, NetworkObject);


		}
		return lastEvent;
	
	}
	
	

	


	private void forkEvent(LogMapping lm, String prevProcess, String process, Model jsonModel) {
		
		if(!prevProcess.equals(process)) {
			String p[] = process.split("#",2);
			if(!p[1].isEmpty()) {
				String forkMap = lm.forkMap(prevProcess, process);
				Reader targetReader = new StringReader(forkMap);
				jsonModel.read(targetReader, null, "N-TRIPLE");
				PropagationRule prop = new PropagationRule();
				prop.forkTag(jsonModel, prevProcess, process);
			}
		}
		
	}


	private  static String shortenUUID(String uuid, HashMap<String, String> uuIndex) {
		String id="";
		if(!uuid.isEmpty()) {
			if(uuIndex.containsKey(uuid)) {
				id = uuIndex.get(uuid);
			}else {
				Integer lastId = uuIndex.size()+1;
				String currId  = lastId.toString();
				id = currId;
				uuIndex.put(uuid,currId);
			}
		}
		 return id;
	}

	private  static boolean isEntityNew(String entity, Set<String> store) {
		//process
		boolean entityNew = false;
		if(!entity.isEmpty()) {
			if(!store.contains(entity)) {
				entityNew=true;
			}
		}
		return entityNew;
	}
	
	private  static void storeEntity(String entity, Set<String> store) {
		if(!entity.isEmpty()) {
			if(!store.contains(entity)) {
				store.add(entity);
			}
		}
	}
		
	private  static String getIpAddress(String netObject, HashMap<String, String> NetworkObject) {
		//process
		String ipAddress="";
		if(!netObject.isEmpty()) {
			if(NetworkObject.containsKey(netObject)) {
				ipAddress = NetworkObject.get(netObject);
			}
		}
	
		 return ipAddress;	
	}
	
	private  static void putNewNetworkObject(String netObject, String netAddress, HashMap<String, String> NetworkObject) {
		//process
		if(!netObject.isEmpty() && !netAddress.isEmpty()) {
			if(!NetworkObject.containsKey(netObject)) {
				NetworkObject.put(netObject, netAddress);
				
			}
		}
		 
	}
	
	private  static void putNewForkObject(String process, String object, HashMap<String, String> ForkObject) {
		//process
		if(!process.isEmpty() && !object.isEmpty()) {
			if(!ForkObject.containsKey(object)) {
				ForkObject.put(object, process);
			}else {
				//update
				ForkObject.remove(object);
				ForkObject.put(object, process);
				//System.out.println("udah ada");
			}
		}
		 
	}
	
	private  static String getPreviousForkProcess(String subject,HashMap<String, String> ForkObject) {
		//process
		String prevProcess ="";
		if(!subject.isEmpty()) {
			
			if(ForkObject.containsKey(subject)) {
				
				prevProcess = ForkObject.get(subject);
				
			}
			
			
		}
		
		
		return prevProcess;
		 
	}
		

	private static Boolean filterLine(String eventType, ArrayList<String> fieldfilter) {
		Boolean result = false;
			for (int i = 0; i < fieldfilter.size(); i++) {
				if(eventType.contains(fieldfilter.get(i))) {
					result = true;
				}
			}
			
		return result;	
	}
	
	private static boolean isConfidentialFile(String file,  ArrayList<String> confidentialdir) {
		boolean fileexist=false;
		if(!file.isEmpty()) {
		for (int i=0;i<confidentialdir.size();i++) {
			if(file.contains(confidentialdir.get(i))){
				fileexist=true;
				break;
			}
		}}
		
		return fileexist;
	}
	
	private static String cleanLine(String line) {
		line = line.replaceAll("[#{}%\\]\\[\\s\\n:$=()]", "");
		
		return line;
	}
	
	private static String cleanCmd(String line) {
		line = line.replaceAll("[\\n\\t]", "");
		
		return line;
	}
	
	
	
}
