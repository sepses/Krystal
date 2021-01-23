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
	public Any registryNode;
	public Any subjectNode;
	public Any userNode;
	public Any hostNode;
	public Any datumNode;
	public String objectString;
	public String exec;
	public String hostId;
	public String userId;
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
			line = cleanRow(line);
			Any jsonNode=JsonIterator.deserialize(line);
			datumNode = jsonNode.get("datum");
	}
	
	public String parseJSONtoRDF(Model jsonModel, Model alertModel, ArrayList<String> fieldfilter, ArrayList<String> confidentialdir, HashMap<String, String> uuIndex, Set<String> Process, Set<String> File, Set<String> Network, HashMap<String, String> NetworkObject, HashMap<String, String> ForkObject , Set<String> lastEvent, String lastAccess, HashMap<String, String> UserObject,  Set<String> Registry, HashMap<String, String> RegistryObject, HashMap<String, String> SubjExecObject, String file ) throws IOException{	
		//filter is the line is an event or not
		eventNode = datumNode.get("Event");
		if(eventNode.toBoolean()) {
			eventType = eventNode.toString();
			if(!filterLine(eventType, fieldfilter)){
				String mapper = "";
				LogMapper lm = new LogMapper();	
				subject = shortenUUID(eventNode.get("subject").get("UUID").toString(),uuIndex);
				
				//exec = getSubjExec(subject, SubjExecObject);
				exec = eventNode.get("properties").get("map").get("exec").toString();
				
				hostId = eventNode.get("hostId").toString();
				int ts = eventNode.get("timestampNanos").toInt();
				String strTime = new Timestamp(ts/1000000).toString();
				String timestamp = eventNode.get("timestampNanos").toString();
				userId = getUserId(subject, UserObject);
				objectString = cleanLine(eventNode.get("predicateObjectPath").get("string").toString());	
				object = shortenUUID(eventNode.get("predicateObject").get("UUID").toString(),uuIndex);
				String processMap = "";
				String fileMap = "";
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
					     //tag new process
							processMap = lm.initialProcessTagMap(subject+"#"+exec);
					
				}
				
				
				  if(eventType.contains("EVENT_WRITE")) {
					  String curWrite = subject+exec+objectString+"write";
						if(objectString!="" && !objectString.contains("<unknown>")) {
							
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
				//			couldbe registry
//							String registryKey = getRegistryKey(object, RegistryObject);
//							registryKey = cleanLine(registryKey);
//							
//							
//							if(!registryKey.isEmpty()) {
//								
//								if(isEntityNew(registryKey, Registry)) {
//									registryMap = lm.initialRegistryTagMap(registryKey);
//								}
//								
//								 curWrite = subject+exec+registryKey+"write";
//								if	(!lastAccess.contains(curWrite)) {
//									
//									mapper = lm.writeMap(subject,exec,registryKey,hostId,userId, timestamp) + registryMap+processMap;
//									
//									storeEntity(registryKey, Registry);
//									storeEntity(subject+"#"+exec, Process);
//									
//									Reader targetReader = new StringReader(mapper);
//									jsonModel.read(targetReader, null, "N-TRIPLE");
//									
//									PropagationRule prop = new PropagationRule();
//									prop.writeTag(jsonModel, subject, exec, registryKey);
//									
//										lastAccess=curWrite;
//								}
//															 
//							}
							
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
//								String registryKey = getRegistryKey(object, RegistryObject);
//								registryKey = cleanLine(registryKey);	
//								
//								if(!registryKey.isEmpty()) {
//									
//									if(isEntityNew(registryKey, Registry)) {
//										registryMap = lm.initialRegistryTagMap(registryKey);
//									}
//									
//									 curRead = subject+exec+registryKey+"read";
//									if	(!lastAccess.contains(curRead)) {
//										
//										mapper = lm.readMap(subject,exec,registryKey,hostId,userId, timestamp) + registryMap+processMap;
//										
//										storeEntity(registryKey, Registry);
//										storeEntity(subject+"#"+exec, Process);
//										
//										Reader targetReader = new StringReader(mapper);
//										jsonModel.read(targetReader, null, "N-TRIPLE");
//										
//										PropagationRule prop = new PropagationRule();
//										prop.readTag(jsonModel, subject, exec, registryKey);
//										
//											lastAccess=curRead;
//									}
//																 
//								}
//								
							}
					
					
					}else if(eventType.contains("EVENT_EXECUTE")) {
						
						//check last read to reduce unnecessary duplicate event processing			
						String curExe = subject+exec+objectString+"execute";
							if(objectString!="" && !objectString.contains("<unknown>")) {
								if	(!lastAccess.contains(curExe)) {
									mapper = lm.executeWinMap(subject,exec,objectString,hostId,userId,timestamp)+fileMap+processMap;
						
									storeEntity(objectString, File);
									storeEntity(subject+"#"+exec, Process);
									
									// System.out.print("execute");
									 Reader targetReader2 = new StringReader(mapper);
									 jsonModel.read(targetReader2, null, "N-TRIPLE");
									 
									AlertRule alert = new AlertRule();
									 alert.execAlert(jsonModel,alertModel, subject+"#"+exec, objectString, strTime);
									 
									 
									 
									 PropagationRule prop = new PropagationRule();
									 prop.execTag(jsonModel, subject, exec, objectString);									lastAccess = curExe;
									
									//System.out.println("read: "+curRead);
								}
							
							
						}	 
						 
					
					}else if(eventType.contains("EVENT_LOADLIBRARY")) {
						
						//check last read to reduce unnecessary duplicate event processing			
						String curLoad = subject+exec+objectString+"execute";
							if(objectString!="" && !objectString.contains("<unknown>")) {
								if	(!lastAccess.contains(curLoad)) {
									mapper = lm.loadLibraryMap(subject,exec,objectString,hostId,userId,timestamp)+fileMap+processMap;
						
									storeEntity(objectString, File);
									storeEntity(subject+"#"+exec, Process);
									
									// System.out.print("execute");
									 Reader targetReader2 = new StringReader(mapper);
									 jsonModel.read(targetReader2, null, "N-TRIPLE");
									 
									AlertRule alert = new AlertRule();
									alert.execAlert(jsonModel,alertModel, subject+"#"+exec, objectString, strTime);
									 
									 
									 PropagationRule prop = new PropagationRule();
									 prop.loadTag(jsonModel, subject, exec, objectString);	
									 
									 lastAccess = curLoad;
									
									//System.out.println("read: "+curRead);
								}
							
							
						}	 
						 
					
					}else if(eventType.contains("EVENT_FORK")) { 
						
						String forkMap = lm.forkMap(subject+"#"+exec, object+"#", timestamp);
				  
						Reader targetReader = new StringReader(forkMap);
						jsonModel.read(targetReader, null, "N-TRIPLE");
						PropagationRule prop = new PropagationRule();
						prop.forkTag(jsonModel, subject+"#"+exec, object+"#");	
						
						
						
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
								alert.dataLeakAlert(jsonModel,alertModel, subject+"#"+exec, IPAddress, strTime);
								
								
								
								PropagationRule prop = new PropagationRule();
								prop.sendTag(jsonModel, subject, exec, IPAddress);
								
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
								prop.receiveTag(jsonModel, subject, exec, IPAddress);
								
									lastAccess=curReceive;
							}
														 
						}
					}
				}
			 
		}else if(datumNode.get("NetFlowObject").toBoolean()) {
			    networkNode = datumNode.get("NetFlowObject");
				netObject = shortenUUID(networkNode.get("uuid").toString(),uuIndex); 
				String ip = networkNode.get("remoteAddress").toString();
				String port =networkNode.get("remotePort").toString();
				netAddress = ip+":"+port;
				putNewNetworkObject(netObject, netAddress, NetworkObject);
				String mapper="";
				LogMapper lm = new LogMapper();	
			    
				mapper = lm.networkMap(netAddress,ip,port);	
				
				Reader targetReader = new StringReader(mapper);
				jsonModel.read(targetReader, null, "N-TRIPLE");

		}else if(datumNode.get("Subject").toBoolean()) {
		    subjectNode = datumNode.get("Subject");
			subject = shortenUUID(subjectNode.get("uuid").toString(),uuIndex); 
			long time = subjectNode.get("startTimestampNanos").toLong();
			String exec = subjectNode.get("cmdLine").get("string").toString(); 
			exec = exec.replace("\\", "\\\\");
			exec = exec.replace("\"", "\\\"");
			
			if(!exec.isEmpty()) {
				//System.out.println(exec);
				String mapper="";
				LogMapper lm = new LogMapper();	
			    
				mapper = lm.subjectMap(subject,"",exec);	
				
				Reader targetReader = new StringReader(mapper);
				jsonModel.read(targetReader, null, "N-TRIPLE");
			}
			//putNewSubjExecObject(subject, exec, SubjExecObject);
			
			String userId = shortenUUID(subjectNode.get("localPrincipal").toString(),uuIndex); 
			putNewUserObject(subject, userId, UserObject);
			
			
		}else if(datumNode.get("Principal").toBoolean()) {
			
				String mapper="";
				LogMapper lm = new LogMapper();	
			    userNode = datumNode.get("Principal");
				userId = shortenUUID(userNode.get("uuid").toString(),uuIndex); 
				//String usert = userNode.get("userId").toString();
				String usert="0";
				String userType = getUserType(usert);
				String userName = userNode.get("username").get("string").toString();
				
				
				mapper = lm.userMap(userId,userType,userName);	
		
				Reader targetReader = new StringReader(mapper);
				jsonModel.read(targetReader, null, "N-TRIPLE");
			
		
		}else if(datumNode.get("Host").toBoolean()) {
			String mapper="";
			LogMapper lm = new LogMapper();	
		    hostNode = datumNode.get("Host");
			hostId = hostNode.get("uuid").toString(); 
			//String hostType = hostNode.get("hostType").toString();
			String hostName = hostNode.get("hostName").toString();
			String hostOS = hostNode.get("osDetails").toString();
			String hostIP = hostNode.get("interfaces").get(1).get("ipAddresses").get(1).toString();
			
			mapper = lm.hostMap(hostId,hostName,hostOS,hostIP);	
			Reader targetReader = new StringReader(mapper);
			jsonModel.read(targetReader, null, "N-TRIPLE");
		
	
	}else if(datumNode.get("RegistryKeyObject").toBoolean()) {
		
		registryNode = datumNode.get("RegistryKeyObject");
		String registryId = shortenUUID(registryNode.get("uuid").toString(),uuIndex); 
		String registryKey = cleanLine(registryNode.get("key").toString());
		//System.out.println(registryKey);
		putNewRegistryObject(registryId, registryKey, RegistryObject);		
		
//		String registryValueName = registryNode.get("value").get("name").toString();
//		String registryValueType = registryNode.get("value").get("type").toString();
//		
//		String mapper="";
//		LogMapper lm = new LogMapper();	
//		mapper = lm.registryMap(registryId,registryKey,registryValueType,registryValueName);	
//
//		Reader targetReader = new StringReader(mapper);
//		jsonModel.read(targetReader, null, "N-TRIPLE");

	}
		
		return lastAccess;
	
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
	
	private static String cleanLine(String line) {
		line = line.replaceAll("[#{}%\\]\\[\\s\\n$=()]", "");
		line = line.replace("C:", "\\Device\\HarddiskVolume2");
		line = line.replace("\\SystemRoot", "\\Device\\HarddiskVolume2");
		line = line.replace("\\", "/");
		//line = line.toLowerCase();
		
		return line;
	}
	
	private static String cleanRow(String line) {
		line = line.replace("com.bbn.tc.schema.avro.cdm18.", "");
		return line;
	}
	
	
	
	private String getUserType(String ut) {
		Integer userType = 	Integer.parseInt(ut);
		if(userType==0) {
			return "RootUser";
		}else if(userType>=1 && userType<=1000) {
			return "LocalUser";
		}else {
			return "SystemUser";
		}
		
	}
	
	private  static boolean isEntityExists(String entity, Set<String> store) {
		//process
		boolean entityExists = false;
		if(!entity.isEmpty()) {
			if(store.contains(entity)) {
				entityExists=true;
			}
		}
		return entityExists;
	}
	
	
	private  static void putNewRegistryObject(String registryId, String registryKey, HashMap<String, String> RegistryObject) {
		//process
		if(!registryId.isEmpty() && !registryKey.isEmpty()) {
			if(!RegistryObject.containsKey(registryId)) {
				RegistryObject.put(registryId, registryKey);
				
			}
		}
		 
	}
	
}
