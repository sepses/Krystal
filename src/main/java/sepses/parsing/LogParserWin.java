package sepses.parsing;
import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Set;
import org.apache.jena.rdf.model.Model;
import com.jsoniter.JsonIterator;
import com.jsoniter.any.Any;

import sepses.SimpleLogProvenance.AlertRule;
import sepses.SimpleLogProvenance.PropagationRule;

public class LogParserWin {
	public String eventType;
	public Any eventNode;
	public Any networkNode;
	public Any subjectNode;
	public Any userNode;
	public Any registryNode;
	public Any memoryNode;
	public Any hostNode;
	public Any datumNode;
	public String objectString;
	public String exec;
	public String hostId;
	public String userId;
	public String registryId;
	public String memoryId;
	public String timestamp; 
	public String subject;
	public String object;
	public String netObject;
	public String netAddress;
	public String cmdline;
	public HashMap<String, String> uuIndex;
	public ArrayList<String> fieldfilter;
	public ArrayList<String> confidentialdir;
	
	public LogParserWin(String line) {
		
			Any jsonNode=JsonIterator.deserialize(line);
			datumNode = jsonNode.get("datum");
	}
	
	public String parseJSONtoRDF(Model jsonModel, Model alertModel, ArrayList<String> fieldfilter, ArrayList<String> confidentialdir, HashMap<String, String> uuIndex, Set<String> Process, Set<String> File, Set<String> Network, HashMap<String, String> NetworkObject, HashMap<String, String> ForkObject , Set<String> lastEvent, String lastAccess, HashMap<String, String> UserObject, Set<String> Registry, HashMap<String, String> RegistryObject ) throws IOException{	
		//filter is the line is an event or not
		eventNode = datumNode.get("Event");
		if(eventNode.toBoolean()) {
			eventType = eventNode.toString();
			if(!filterLine(eventType, fieldfilter)){
				String mapper = "";
				LogMapper lm = new LogMapper();	
				subject = shortenUUID(eventNode.get("subject").get("UUID").toString(),uuIndex);
				exec = eventNode.get("properties").get("map").get("exec").toString();
				hostId = eventNode.get("hostId").toString();
				long timestampNanos = eventNode.get("timestampNanos").toLong();
				timestamp = new Timestamp(timestampNanos/1000000).toString();
				userId = getUserId(subject, UserObject);
				objectString = cleanLine(eventNode.get("predicateObjectPath").get("string").toString());
				
				object = shortenUUID(eventNode.get("predicateObject").get("UUID").toString(),uuIndex);
				String processMap = "";
				String fileMap = "";
				String prevProcess="";
				String networkMap="";
				String registryMap="";
				
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
						if(!prevProcess.isEmpty()) {
							if(!eventType.contains("EVENT_EXECUTE")) {
  							    forkEvent(lm, prevProcess, subject+"#"+exec,timestamp, jsonModel);
							}
						}else {
	                       //tag new process
							processMap = lm.initialProcessTagMap(subject+"#"+exec);
						}
					
				}
				
				
				  if(eventType.contains("EVENT_WRITE")) {
					  
						if(objectString!="" && !objectString.contains("<unknown>")) {
							String curWrite = subject+exec+objectString+"write";
							if	(!lastAccess.contains(curWrite)) {				
								
								
								
								mapper = lm.writeMap(subject,exec,objectString,hostId,userId, timestamp)+fileMap+processMap;
								
								storeEntity(objectString, File);
								storeEntity(subject+"#"+exec, Process);
						
								
								Reader targetReader = new StringReader(mapper);
								jsonModel.read(targetReader, null, "N-TRIPLE");
								
								//AlertRule alert = new AlertRule();
								//alert.corruptFileAlert(jsonModel, subject+"#"+exec, objectString, timestamp);
								
								PropagationRule prop = new PropagationRule();
								prop.writeTag(jsonModel, subject, exec, objectString);
								
								lastAccess = curWrite;
								
								//System.out.println("write: "+curWrite);
								
								
							}
					  }else {
						  //could be registry
						  System.out.println(eventNode);
					  }
					  
					}else if(eventType.contains("EVENT_READ")) {
					
						//check last read to reduce unnecessary duplicate event processing			
						String curRead = subject+exec+objectString+"read";
							if(objectString!="" && !objectString.contains("<unknown>")) {
								if	(!lastAccess.contains(curRead)) {
									mapper = lm.readMap(subject,exec,objectString,hostId,userId,timestamp)+fileMap+processMap;
						
									storeEntity(objectString, File);
									storeEntity(subject+"#"+exec, Process);
									
									Reader targetReader = new StringReader(mapper);
									jsonModel.read(targetReader, null, "N-TRIPLE");
																
									PropagationRule prop = new PropagationRule();
									prop.readTag(jsonModel, subject, exec, objectString);										
									
									lastAccess = curRead;
									
									//System.out.println("read: "+curRead);
								}
							}else {
								//couldbe registry
								String registryKey = getRegistryKey(object, RegistryObject);
								
								
								if(!registryKey.isEmpty()) {
									
									if(isEntityNew(registryKey, Registry)) {
										registryMap = lm.initialRegistryTagMap(registryKey);
									}
									
									 curRead = subject+exec+registryKey+"read";
									if	(!lastAccess.contains(curRead)) {
										
										mapper = lm.readMap(subject,exec,registryKey,hostId,userId, timestamp) + registryMap+processMap;
										
										storeEntity(registryKey, Registry);
										storeEntity(subject+"#"+exec, Process);
										
										Reader targetReader = new StringReader(mapper);
										jsonModel.read(targetReader, null, "N-TRIPLE");
										
										PropagationRule prop = new PropagationRule();
										prop.readTag(jsonModel, subject, exec, registryKey);
										
											lastAccess=curRead;
									}
																 
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
							
							 //if prevProcess not empty => entity is new
							 //if prevProcess is empty => entity can be new or not
							 
							 if(prevProcess.isEmpty()) {
								 putNewForkObject(subject+"#"+exec, subject, ForkObject);
								 prevProcess = getPreviousForkProcess(subject, ForkObject);
							 }
							 
							    Reader targetReader = new StringReader(processMap);
							 	jsonModel.read(targetReader, null, "N-TRIPLE");
							 	
							 	
								forkEvent(lm, prevProcess, subject+"#"+process2, timestamp, jsonModel);
							 
								
								 mapper = lm.executeMap(subject,process2, objectString, cmdline, hostId, userId, timestamp)+fileMap;
								 
								 storeEntity(objectString, File);
								 storeEntity(subject+"#"+exec, Process);
								 storeEntity(subject+"#"+process2, Process);
								 
								// System.out.print("execute");
								 Reader targetReader2 = new StringReader(mapper);
								 jsonModel.read(targetReader2, null, "N-TRIPLE");
								 
								 AlertRule alert = new AlertRule();
								 alert.execAlert(jsonModel,alertModel, subject+"#"+process2, objectString, timestamp);
								 
								 
								 PropagationRule prop = new PropagationRule();
								 prop.execTag(jsonModel, subject, process2, objectString);
						}	 
						 
					
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
							
							String curSend = subject+exec+IPAddress+"send";
							if	(!lastAccess.contains(curSend)) {
								
								mapper = lm.sendMap(subject,exec,IPAddress,hostId,userId, timestamp) + networkMap+processMap;	
								
								storeEntity(IPAddress, Network);
								storeEntity(subject+"#"+exec, Process);
								
								// System.out.println("sendto"+subject+"#"+exec+IPAddress);
								 
								Reader targetReader = new StringReader(mapper);
								jsonModel.read(targetReader, null, "N-TRIPLE");
								
								AlertRule alert = new AlertRule();
								alert.dataLeakAlert(jsonModel,alertModel, subject+"#"+exec, IPAddress, timestamp);
								
								PropagationRule prop = new PropagationRule();
								prop.writeTag(jsonModel, subject, exec, IPAddress);
								
								lastAccess=curSend;
								
							}
							
						}
						
						
						
					}else if(eventType.contains("EVENT_RECVFROM")) {
					
				
						
						String IPAddress = getIpAddress(object, NetworkObject);
					
						
						if(!IPAddress.isEmpty()) {
							
							if(isEntityNew(IPAddress, Network)) {
								networkMap = lm.initialNetworkTagMap(IPAddress);
							}
							
							String curReceive = subject+exec+IPAddress+"receive";
							if	(!lastAccess.contains(curReceive)) {
								
								mapper = lm.receiveMap(subject,exec,IPAddress,hostId,userId, timestamp) + networkMap+processMap;
								
								storeEntity(IPAddress, Network);
								storeEntity(subject+"#"+exec, Process);
								//System.out.println("receivefrom"+subject+"#"+exec+IPAddress);
								Reader targetReader = new StringReader(mapper);
								jsonModel.read(targetReader, null, "N-TRIPLE");
								
								PropagationRule prop = new PropagationRule();
								prop.readTag(jsonModel, subject, exec, IPAddress);
								
									lastAccess=curReceive;
							}
														 
						}
					}
				}
			 
		}else if(datumNode.get("NetFlowObject").toBoolean()) {
			    networkNode = datumNode.get("NetFlowObject");
				netObject = shortenUUID(networkNode.get("uuid").toString(),uuIndex); 
				netAddress = networkNode.get("remoteAddress").toString()+":"+networkNode.get("remotePort").toString();
				putNewNetworkObject(netObject, netAddress, NetworkObject);


		}else if(datumNode.get("Subject").toBoolean()) {
		    subjectNode = datumNode.get("Subject");
			subject = shortenUUID(subjectNode.get("uuid").toString(),uuIndex); 
			String userId = shortenUUID(subjectNode.get("localPrincipal").toString(),uuIndex); 
			putNewUserObject(subject, userId, UserObject);
			
			
		}else if(datumNode.get("Principal").toBoolean()) {
			
				String mapper="";
				LogMapper lm = new LogMapper();	
			    userNode = datumNode.get("Principal");
				userId = shortenUUID(userNode.get("uuid").toString(),uuIndex); 
				String userType = getUserType(userNode.get("userId").toInt());
				String userName = userNode.get("username").get("string").toString(); 
				
				
				mapper = lm.userMap(userId,userType,userName);	
				//System.out.print(mapper);
				
				Reader targetReader = new StringReader(mapper);
				jsonModel.read(targetReader, null, "N-TRIPLE");
			
		
		}else if(datumNode.get("RegistryKeyObject").toBoolean()) {
		    registryNode = datumNode.get("RegistryKeyObject");
			registryId = shortenUUID(registryNode.get("uuid").toString(),uuIndex); 
			String registryKey = cleanLine(registryNode.get("key").toString());
			putNewRegistryObject(registryId, registryKey, RegistryObject);
	}/*
		else if(datumNode.get("MemoryObject").toBoolean()) {
		
		String mapper="";
		LogMapper lm = new LogMapper();	
	    memoryNode = datumNode.get("MemoryObject");
		memoryId = shortenUUID(memoryNode.get("uuid").toString(),uuIndex); 
		String memoryAddress = cleanLine(memoryNode.get("memoryAddress").toString());
		
		
		mapper = lm.memoryMap(memoryId,memoryAddress);	
		//System.out.print(mapper);
		
		Reader targetReader = new StringReader(mapper);
		jsonModel.read(targetReader, null, "N-TRIPLE");
	

		}*/
		
		return lastAccess;
	
	}
	
	

	


	private void forkEvent(LogMapper lm, String prevProcess, String process, String ts, Model jsonModel) {
		
		if(!prevProcess.equals(process)) {
				String forkMap = lm.forkMap(prevProcess, process, ts);
				Reader targetReader = new StringReader(forkMap);
				jsonModel.read(targetReader, null, "N-TRIPLE");
				PropagationRule prop = new PropagationRule();
				prop.forkTag(jsonModel, prevProcess, process);
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
	
	private  static String getRegistryKey(String registryObject, HashMap<String, String> RegistryObject) {
		//process
		String registryKey="";
		if(!registryObject.isEmpty()) {
			if(RegistryObject.containsKey(registryObject)) {
				registryKey = RegistryObject.get(registryObject);
			}
		}
	
		 return registryKey;	
	}
	
	private  static void putNewNetworkObject(String netObject, String netAddress, HashMap<String, String> NetworkObject) {
		//process
		if(!netObject.isEmpty() && !netAddress.isEmpty()) {
			if(!NetworkObject.containsKey(netObject)) {
				NetworkObject.put(netObject, netAddress);
				
			}
		}
		 
	}
	
	private  static void putNewRegistryObject(String registryId, String registryKey, HashMap<String, String> RegistryObject) {
		//process
		if(!registryId.isEmpty() && !registryKey.isEmpty()) {
			if(!RegistryObject.containsKey(registryId)) {
				RegistryObject.put(registryId, registryKey);
				
			}
		}
		 
	}
	
	private  static String getUserId(String subject, HashMap<String, String> UserObject) {
		//process
		String userId="";
		if(!subject.isEmpty()) {
			if(UserObject.containsKey(subject)) {
				userId = UserObject.get(subject);
			}
		}
	
		 return userId;	
	}
	private  static void putNewUserObject(String subject, String userId, HashMap<String, String> UserObject) {
		//process
		if(!subject.isEmpty() && !userId.isEmpty()) {
			if(!UserObject.containsKey(subject)) {
				UserObject.put(subject, userId);
				
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
		line = line.replaceAll("[#{}%\\]\\[\\s\\n$=()]", "");
		line = line.replace("\\", "_");
		return line;
	}
	
	private static String cleanCmd(String line) {
		line = line.replaceAll("[\\n\\t]", "");
		
		return line;
	}
	private String getUserType(Integer userType) {
		if(userType==0) {
			return "RootUser";
		}else if(userType>=1 && userType<=1000) {
			return "LocalUser";
		}else {
			return "SystemUser";
		}
		
	}	
	
	
}
