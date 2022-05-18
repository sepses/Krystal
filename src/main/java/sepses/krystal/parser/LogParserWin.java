package sepses.krystal.parser;	
import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Set;

import org.apache.jena.rdf.model.Model;

import com.jsoniter.JsonIterator;
import com.jsoniter.any.Any;

import sepses.krystal.AlertRule;
import sepses.krystal.PropagationRule;

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
	
	public String parseJSONtoRDF(Model jsonModel, Model alertModel, ArrayList<String> fieldfilter, ArrayList<String> confidentialdir, HashMap<String, String> uuIndex, Set<String> Process, Set<String> File, Set<String> Network, HashMap<String, String> NetworkObject, HashMap<String, String> ForkObject , Set<String> lastEvent, String lastAccess, HashMap<String, String> UserObject,  Set<String> Registry, HashMap<String, String> RegistryObject, HashMap<String, String> SubjectCmd, String file, HashMap<String, Long> SubjectTime,String propagation, String attenuation,double ab, double ae, String decayrule, double period, double Tb, double Te, String policyrule, String signaturerule,ArrayList<Integer> counter ) throws IOException{	
		//filter is the line is an event or not
		eventNode = datumNode.get("Event");
		if(eventNode.toBoolean()) {
			updateCounter(counter);
			eventType = eventNode.toString();
			if(!filterLine(eventType, fieldfilter)){
				String mapper = "";
				LogMapper lm = new LogMapper();	
				//subject = shortenUUID(eventNode.get("subject").get("UUID").toString(),uuIndex);
				subject = eventNode.get("subject").get("UUID").toString();
				hostId = eventNode.get("hostId").toString();
				userId = getUserId(subject, UserObject);
				objectString = cleanLine(eventNode.get("predicateObjectPath").get("string").toString());	
				//object = shortenUUID(eventNode.get("predicateObject").get("UUID").toString(),uuIndex);
				object = eventNode.get("predicateObject").get("UUID").toString();
				//event time
			    long ts = eventNode.get("timestampNanos").toLong();
				String sts = eventNode.get("timestampNanos").toString();
				
				//get exec from original subject because no exec in the event
				String subjCmd = getSubjectCmd(subject,SubjectCmd);
			    exec = getExecFromCmdLine(subjCmd);
				//use subj time for event
				long stime = getSubjectTime(subject, SubjectTime);
			    //to do : add cmdLine 
				PropagationRule prop = new PropagationRule();
				
			    
				String fileMap = "";
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
				
				if(!exec.isEmpty()) {
					//time initialization for each process
					if(stime!=0) {
						prop.putProcessTime(jsonModel, subject, exec, stime);
					}else {
						//if subject has no time, use event time instead
						putNewSubjectTime(subject, ts, SubjectTime);
						long nstime = getSubjectTime(subject, SubjectTime);
						prop.putProcessTime(jsonModel, subject, exec, nstime);
					}
					
					if (decayrule!="false") {
						  if(ts!=0 && !eventType.contains("EVENT_FORK")) {
							prop.decayIndividualProcess(jsonModel,  subject+"#"+exec, ts, period, Tb, Te);
						   }
						}
					
					if(eventType.contains("EVENT_WRITE")) {
					  
					  String curWrite = subject+exec+objectString+"write";
						if(objectString!="" && !objectString.contains("<unknown>")) {
							
							if	(!lastAccess.contains(curWrite)) {				

								mapper = lm.writeMap(subject,exec,objectString,hostId,userId, sts)+fileMap;
								
								storeEntity(objectString, File);
						
								Reader targetReader = new StringReader(mapper);
								jsonModel.read(targetReader, null, "N-TRIPLE");
								
								if(policyrule!="false") {
									AlertRule alert = new AlertRule();
									alert.corruptFileAlert(jsonModel, alertModel, subject+"#"+exec, objectString, sts);
								}
								
								prop.writeTag(jsonModel, subject, exec, objectString);
								
								lastAccess = curWrite;
								
							}
					  }
					  
					}else if(eventType.contains("EVENT_READ")) {
					
						//check last read to reduce unnecessary duplicate event processing			
						String curRead = subject+exec+objectString+"read";
							if(objectString!="" && !objectString.contains("<unknown>")) {
								if	(!lastAccess.contains(curRead)) {
									mapper = lm.readMap(subject,exec,objectString,hostId,userId,sts)+fileMap;
						
									storeEntity(objectString, File);
									
									Reader targetReader = new StringReader(mapper);
									jsonModel.read(targetReader, null, "N-TRIPLE");
									
									prop.readTag(jsonModel, subject, exec, objectString);		
									

									if(policyrule!="false") {
										AlertRule alert = new AlertRule();
										alert.reconnaissanceAlert(jsonModel,alertModel, subject+"#"+exec, objectString, sts);
										}
									lastAccess = curRead;
					
								}
							}
					
					}
					else if(eventType.contains("EVENT_EXECUTE")) {
						
						//check last read to reduce unnecessary duplicate event processing			
						String curExe = subject+exec+objectString+"execute";
							if(objectString!="" && !objectString.contains("<unknown>")) {
								if	(!lastAccess.contains(curExe)) {
									mapper = lm.executeWinMap(subject,exec,objectString,hostId,userId,sts)+fileMap;
						
									storeEntity(objectString, File);
									
									 Reader targetReader2 = new StringReader(mapper);
									 jsonModel.read(targetReader2, null, "N-TRIPLE");
									 
									 if(policyrule!="false") {
										 AlertRule alert = new AlertRule();
										 alert.execAlert(jsonModel,alertModel, subject+"#"+exec, objectString, sts);
									}
									 
									 
									 prop.execTag(jsonModel, subject, exec, objectString);									
									 lastAccess = curExe;
									
								}
							
							
						}	 
						 
					
					}else if(eventType.contains("EVENT_LOADLIBRARY")) {
						
						//check last read to reduce unnecessary duplicate event processing			
						String curLoad = subject+exec+objectString+"execute";
							if(objectString!="" && !objectString.contains("<unknown>")) {
								if	(!lastAccess.contains(curLoad)) {
									mapper = lm.loadLibraryMap(subject,exec,objectString,hostId,userId,sts)+fileMap;
						
									storeEntity(objectString, File);
									
									 Reader targetReader2 = new StringReader(mapper);
									 jsonModel.read(targetReader2, null, "N-TRIPLE");
									 
									 if(policyrule!="false") {
										 AlertRule alert = new AlertRule();
											alert.execAlert(jsonModel,alertModel, subject+"#"+exec, objectString, sts);
									}
									 
									 
									 prop.loadTag(jsonModel, subject, exec, objectString);	
									 
									 lastAccess = curLoad;
									
								}
							
							
						}	 
						 
					
					}else if(eventType.contains("EVENT_FORK")) { 
						
						String forkMap = lm.forkMap(subject+"#"+exec, object+"#", sts);
				  
						Reader targetReader = new StringReader(forkMap);
						jsonModel.read(targetReader, null, "N-TRIPLE");
						
						prop.forkTag(jsonModel, subject+"#"+exec, object+"#");	
						
					
					}else if(eventType.contains("EVENT_MODIFY_FILE_ATTRIBUTES")) {
						String curCh = subject+exec+objectString+"change";
						if	(!lastAccess.contains(curCh)) {				
	
							mapper = lm.changePerm(subject,exec,objectString,hostId,userId, sts);
								
							Reader targetReader = new StringReader(mapper);
							jsonModel.read(targetReader, null, "N-TRIPLE");
							
							 if(policyrule!="false") {
								 AlertRule alert = new AlertRule();
								 alert.changePermAlert(jsonModel, alertModel, subject+"#"+exec, objectString, sts);
							}
							lastAccess = curCh;
					
						 }
//					}else if(eventType.contains("EVENT_MPROTECT")) {
//						String curPro = subject+exec+objectString+"mprotect";
//						if	(!lastAccess.contains(curPro)) {				
//	
//							mapper = lm.mprotect(subject,exec,objectString,hostId,userId, sts);
//								
//							Reader targetReader = new StringReader(mapper);
//							jsonModel.read(targetReader, null, "N-TRIPLE");
//							
//		   					 if(policyrule!="false") {
//								AlertRule alert = new AlertRule();
//				   				alert.memExec(jsonModel, alertModel, subject+"#"+exec, objectString, sts);
//							}
//							lastAccess = curPro;
//					
//						 }
					}else if(eventType.contains("EVENT_SENDTO")) {
					
						String IPAddress = getIpAddress(object, NetworkObject);
						
						if(!IPAddress.isEmpty()) {						
							if(isEntityNew(IPAddress, Network)) {
								 networkMap = lm.initialNetworkTagMap(IPAddress);
							}
							
							String curSend = subject+exec+IPAddress+"send";
							//System.out.println("RECEIVE: "+IPAddress);
							if	(!lastAccess.contains(curSend)) {
								
								mapper = lm.sendMap(subject,exec,IPAddress,hostId,userId, sts) + networkMap;	
								
								storeEntity(IPAddress, Network);
								
								Reader targetReader = new StringReader(mapper);
								jsonModel.read(targetReader, null, "N-TRIPLE");
								
								 if(policyrule!="false") {
									 AlertRule alert = new AlertRule();
									 alert.dataLeakAlert(jsonModel,alertModel, subject+"#"+exec, IPAddress, sts);
								 }
								
								prop.sendTag(jsonModel, subject, exec, IPAddress);
								
								lastAccess=curSend;
								
							}
							
						}
						
						
						
					}else if(eventType.contains("EVENT_RECVFROM")) {
						
						String IPAddress = getIpAddress(object, NetworkObject);
						//System.out.println("RECEIVE: "+IPAddress);
						if(!IPAddress.isEmpty()) {
							
							if(isEntityNew(IPAddress, Network)) {
								networkMap = lm.initialNetworkTagMap(IPAddress);
							}
							
								mapper = lm.receiveMap(subject,exec,IPAddress,hostId,userId, sts) + networkMap;
								
								storeEntity(IPAddress, Network);
								
								Reader targetReader = new StringReader(mapper);
								jsonModel.read(targetReader, null, "N-TRIPLE");			
								
								 if(policyrule!="false") {
									 AlertRule alert = new AlertRule();
									alert.reconnaissanceAlert(jsonModel,alertModel, subject+"#"+exec, IPAddress, sts);
								 }
								
								
								prop.receiveTag(jsonModel, subject, exec, IPAddress);
								
								if(ts>stime) {
									putNewSubjectTime(subject, ts, SubjectTime);
								}
								
								
								
											
						  }	 
						}
					}
				}
			 
		}else if(datumNode.get("NetFlowObject").toBoolean()) {
			    networkNode = datumNode.get("NetFlowObject");
				//netObject = shortenUUID(networkNode.get("uuid").toString(),uuIndex); 
				netObject = networkNode.get("uuid").toString(); 
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
			//subject = shortenUUID(subjectNode.get("uuid").toString(),uuIndex);
		    subject = subjectNode.get("uuid").toString();
			//String userId = shortenUUID(subjectNode.get("localPrincipal").toString(),uuIndex);
			String userId = subjectNode.get("localPrincipal").toString();
			putNewUserObject(subject, userId, UserObject);
			long time = subjectNode.get("startTimestampNanos").toLong();
			String cmdLine = subjectNode.get("cmdLine").get("string").toString(); 
			
			if(!cmdLine.isEmpty()) {
				putNewSubjectCmd(subject, cmdLine, SubjectCmd);
				if(time!=0) {
					putNewSubjectTime(subject, time, SubjectTime);
				}
				String exec = getExecFromCmdLine(cmdLine);
				if(!exec.isEmpty()) {
					LogMapper lm = new LogMapper();	
					String processMap = lm.initialProcessTagMap(subject+"#"+exec); //initial tag for process
					String subjMap = lm.subjectWinMap(subject, exec, cleanCmd(cmdLine)); //initial tag for process
				    Reader targetReader = new StringReader(subjMap+processMap);
					jsonModel.read(targetReader, null, "N-TRIPLE");
				}
			}
			
			
		}else if(datumNode.get("Principal").toBoolean()) {
			
				String mapper="";
				LogMapper lm = new LogMapper();	
			    userNode = datumNode.get("Principal");
				//userId = shortenUUID(userNode.get("uuid").toString(),uuIndex); 
				userId = userNode.get("uuid").toString(); 
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
			String hostName = hostNode.get("hostName").toString();
			String hostOS = hostNode.get("osDetails").toString();
			String hostIP = hostNode.get("interfaces").get(1).get("ipAddresses").get(1).toString();
			
			mapper = lm.hostMap(hostId,hostName,hostOS,hostIP);	
			Reader targetReader = new StringReader(mapper);
			jsonModel.read(targetReader, null, "N-TRIPLE");
		
	
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
		line = line.replaceAll("[#{}%\\]\\[\\n$=()]", "");
		line = line.replace("\\Device\\HarddiskVolume2","C:");
		line = line.replace("\\SystemRoot", "C:");
		line = line.replace("\\", "/");
		line = line.replace(" ", "_");
		line = line.toLowerCase();
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
	
	
	
	private String getExecFromCmdLine(String cmdLine) {	
	if(!cmdLine.isEmpty()) {
		if(cmdLine.contains(" ") && cmdLine.contains(".")) {
			String cmdLine0 = cmdLine.substring(0,cmdLine.indexOf(".")); //get until first space
			String ext =cmdLine.substring(cmdLine.indexOf("."),cmdLine.indexOf(".")+4); //get until first space
			cmdLine = cmdLine0+ext;
			cmdLine = cmdLine.replace(" ", "_");
			cmdLine = cmdLine.replace("\\\\", "/");
			cmdLine = cmdLine.replace("\\", "/");
			cmdLine = cmdLine.replaceAll("[;\\\"]", "");
			cmdLine = cmdLine.toLowerCase();
		}else {
			cmdLine = cmdLine.replace(" ", "_");
			cmdLine = cmdLine.replace("\\\\", "/");
			cmdLine = cmdLine.replace("\\", "/");
			cmdLine = cmdLine.replaceAll("[;\\\"]", "");
			cmdLine = cmdLine.toLowerCase();
		}
		//System.out.println(cmdLine);
	}
		//System.exit(0);
		return cmdLine;
	}
	
	private  static void putNewSubjectCmd(String subject, String cmdLine, HashMap<String, String> SubjectCmd) {
		//process
		if(!subject.isEmpty() && !cmdLine.isEmpty()) {
			if(!SubjectCmd.containsKey(subject)) {
				SubjectCmd.put(subject, cmdLine);
				
			}
		}
		 
	}
	
	private static String cleanCmd(String line) {
		line = line.replace("\\", "\\\\");
		line = line.replace("\"", "");
		
		
		return line;
	}
	private  static String getSubjectCmd(String subject, HashMap<String, String> SubjectCmd) {
		//process
		String exec="";
		if(!subject.isEmpty()) {
			if(SubjectCmd.containsKey(subject)) {
				exec = SubjectCmd.get(subject);
			}
		}
	
		 return exec;	
	}

	private  static void putNewSubjectTime(String subject, long time, HashMap<String, Long> SubjectTime) {
		//process
		if(!subject.isEmpty()) {
			if(!SubjectTime.containsKey(subject)) {
				SubjectTime.put(subject, time);
			}else {
				SubjectTime.remove(subject);
				SubjectTime.put(subject,time);
			}
		}
		 
	}
	
	
	private  static void updateCounter(ArrayList<Integer> counter) {
		
		int lastCounter = counter.get(0);
		counter.remove(0);
		counter.add(lastCounter+1);
		 
	}
	
	
	private  static long getSubjectTime(String subject, HashMap<String, Long> SubjectTime) {
		//process
		long time=0;
		if(!subject.isEmpty()) {
			if(SubjectTime.containsKey(subject)) {
				time = SubjectTime.get(subject);
			}
		}
	
		 return time;	
	}
}
