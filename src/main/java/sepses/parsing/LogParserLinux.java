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

public class LogParserLinux {
	public String eventType;
	public Any eventNode;
	public Any networkNode;
	public Any fileNode;
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
	
	public LogParserLinux(String line) {
			Any jsonNode=JsonIterator.deserialize(line);
			datumNode = jsonNode.get("datum");
	}
	
	public String parseJSONtoRDF(Model jsonModel, Model alertModel, ArrayList<String> fieldfilter, ArrayList<String> confidentialdir, HashMap<String, String> uuIndex, Set<String> Process, Set<String> File, Set<String> Network, HashMap<String, String> NetworkObject, HashMap<String, String> ForkObject , Set<String> lastEvent, String lastAccess, HashMap<String, String> UserObject, HashMap<String, String> FileObject, HashMap<String, String> SubjExecObject ) throws IOException{	
		//filter is the line is an event or not
		eventNode = datumNode.get("com.bbn.tc.schema.avro.cdm18.Event");
		if(eventNode.toBoolean()) {
			eventType = eventNode.toString();
			if(!filterLine(eventType, fieldfilter)){
				String mapper = "";
				LogMapper lm = new LogMapper();	
				subject = shortenUUID(eventNode.get("subject").get("com.bbn.tc.schema.avro.cdm18.UUID").toString(),uuIndex);
				hostId = eventNode.get("hostId").toString();
			    exec = getProcessExec(subject, SubjExecObject);			
				long timestampNanos = eventNode.get("timestampNanos").toLong();
				timestamp = new Timestamp(timestampNanos/1000000).toString();
				userId = getUserId(subject, UserObject);
				object = shortenUUID(eventNode.get("predicateObject").get("com.bbn.tc.schema.avro.cdm18.UUID").toString(),uuIndex);
				String processMap = "";
				String fileMap = "";
				String prevProcess="";
				String networkMap="";
							
				
				//is process new
				if(isEntityNew(subject+"#"+exec, Process)) {
					
				          //tag new process
							processMap = lm.initialProcessTagMap(subject+"#"+exec);
					
				}
				
				
				  if(eventType.contains("EVENT_WRITE")) {
					 
					  String fileName = getFileName(object, FileObject);
						
						if(!fileName.isEmpty()) {						
							if(isEntityNew(fileName, File)) {
								if(isConfidentialFile(fileName, confidentialdir)) {
									fileMap = lm.initialConfFileTagMap(fileName);	
								}else {
								    fileMap = lm.initialFileTagMap(fileName);
								}
							}
							
						
							String curWrite = subject+exec+fileName+"write";
							if	(!lastAccess.contains(curWrite)) {				
								
								mapper = lm.writeMap(subject,exec,fileName,hostId,userId, timestamp)+fileMap+processMap;
								
								storeEntity(fileName, File);
								storeEntity(subject+"#"+exec, Process);
						
								
								Reader targetReader = new StringReader(mapper);
								jsonModel.read(targetReader, null, "N-TRIPLE");
								
								//AlertRule alert = new AlertRule();
								//alert.corruptFileAlert(jsonModel, subject+"#"+exec, objectString, timestamp);
								
								PropagationRule prop = new PropagationRule();
								prop.writeTag(jsonModel, subject, exec, fileName);
								
								lastAccess = curWrite;
								
								//System.out.println("write: "+curWrite);
								
								
							}
						}
					  
					}else if(eventType.contains("EVENT_READ")) {
						
						  String fileName = getFileName(object, FileObject);
						  					  
							if(!fileName.isEmpty()) {						
								if(isEntityNew(fileName, File)) {
									if(isConfidentialFile(fileName, confidentialdir)) {
										fileMap = lm.initialConfFileTagMap(fileName);	
									}else {
									    fileMap = lm.initialFileTagMap(fileName);
									}
								}
								String curRead = subject+exec+fileName+"read";
					
								if	(!lastAccess.contains(curRead)) {				
									
									mapper = lm.readMap(subject,exec,fileName,hostId,userId,timestamp)+fileMap+processMap;
									
									storeEntity(fileName, File);
									storeEntity(subject+"#"+exec, Process);
									
									Reader targetReader = new StringReader(mapper);
									jsonModel.read(targetReader, null, "N-TRIPLE");
																
									PropagationRule prop = new PropagationRule();
									prop.readTag(jsonModel, subject, exec, fileName);										
									
									lastAccess = curRead;
						
									
								}
							}
						
					
					}else if(eventType.contains("EVENT_EXECUTE")) {	
						
						String fileName = getFileName(object, FileObject);
						
						if(!fileName.isEmpty()) {						
							if(isEntityNew(fileName, File)) {
								if(isConfidentialFile(fileName, confidentialdir)) {
									fileMap = lm.initialConfFileTagMap(fileName);	
								}else {
								    fileMap = lm.initialFileTagMap(fileName);
								}
							}
							
							
							
							 mapper = lm.executeMap(subject,exec, fileName, cmdline, hostId, userId, timestamp)+fileMap+processMap;
							 
							 storeEntity(fileName, File);
							 storeEntity(subject+"#"+exec, Process);
							 storeEntity(subject+"#"+exec, Process);
							 
							// System.out.print("execute");
							 Reader targetReader2 = new StringReader(mapper);
							 jsonModel.read(targetReader2, null, "N-TRIPLE");
							 
							 AlertRule alert = new AlertRule();
							 alert.execAlert(jsonModel,alertModel, subject+"#"+exec, fileName, timestamp);
							 
							 
							 PropagationRule prop = new PropagationRule();
							 prop.execTag(jsonModel, subject, exec, fileName);		
					
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
			 
		}else if(datumNode.get("com.bbn.tc.schema.avro.cdm18.NetFlowObject").toBoolean()) {
			    networkNode = datumNode.get("com.bbn.tc.schema.avro.cdm18.NetFlowObject");
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

		}else if(datumNode.get("com.bbn.tc.schema.avro.cdm18.Subject").toBoolean()) {
		    subjectNode = datumNode.get("com.bbn.tc.schema.avro.cdm18.Subject");
			subject = shortenUUID(subjectNode.get("uuid").toString(),uuIndex);
			String cmdLine = subjectNode.get("cmdLine").get("string").toString();
			String exec = getExecFromCmdLine(cmdLine);
			putNewSubjExecObject(subject, exec, SubjExecObject);
			String userId = shortenUUID(subjectNode.get("localPrincipal").toString(),uuIndex); 
			putNewUserObject(subject, userId, UserObject);
//			String mapper="";
//			LogMapper lm = new LogMapper();	
//		    
//			mapper = lm.subjectMap(subject,exec,cmdLine);	
//			
//			Reader targetReader = new StringReader(mapper);
//			jsonModel.read(targetReader, null, "N-TRIPLE");
	
		}else if(datumNode.get("com.bbn.tc.schema.avro.cdm18.FileObject").toBoolean()) {
		    fileNode = datumNode.get("com.bbn.tc.schema.avro.cdm18.FileObject");
			String fileObject = shortenUUID(fileNode.get("uuid").toString(),uuIndex); 
			String fileName = cleanLine(fileNode.get("baseObject").get("properties").get("map").get("filename").toString()); 
			putNewFileObject(fileObject, fileName, FileObject);
			
			
		}else if(datumNode.get("com.bbn.tc.schema.avro.cdm18.Principal").toBoolean()) {
			
				String mapper="";
				LogMapper lm = new LogMapper();	
			    userNode = datumNode.get("com.bbn.tc.schema.avro.cdm18.Principal");
				userId = shortenUUID(userNode.get("uuid").toString(),uuIndex); 
				String userType = getUserType(userNode.get("userId").toInt());
				String userName = userNode.get("username").get("string").toString(); 
				
				mapper = lm.userMap(userId,userType,userName);	
		
				Reader targetReader = new StringReader(mapper);
				jsonModel.read(targetReader, null, "N-TRIPLE");
			
		
		}else if(datumNode.get("com.bbn.tc.schema.avro.cdm18.Host").toBoolean()) {
			String mapper="";
			LogMapper lm = new LogMapper();	
		    hostNode = datumNode.get("com.bbn.tc.schema.avro.cdm18.Host");
			hostId = hostNode.get("uuid").toString(); 
			//String hostType = hostNode.get("hostType").toString();
			String hostName = hostNode.get("hostName").toString();
			String hostOS = hostNode.get("osDetails").toString();
			String hostIP = hostNode.get("interfaces").get(1).get("ipAddresses").get(1).toString();
			
			mapper = lm.hostMap(hostId,hostName,hostOS,hostIP);	
			Reader targetReader = new StringReader(mapper);
			jsonModel.read(targetReader, null, "N-TRIPLE");
		
	
	}				
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
	private  static String getFileName(String fileObject, HashMap<String, String> FileObject) {
		//file
		String fileName="";
		if(!fileObject.isEmpty()) {
			if(FileObject.containsKey(fileObject)) {
				fileName = FileObject.get(fileObject);
			}
		}
	
		 return fileName;	
	}
	
	private  static String getProcessExec(String subject, HashMap<String, String> SubjExectObject) {
		//process
		String exec="";
		if(!subject.isEmpty()) {
			if(SubjExectObject.containsKey(subject)) {
				exec = SubjExectObject.get(subject);
			}
		}
	
		 return exec;	
	}
	private  static void putNewNetworkObject(String netObject, String netAddress, HashMap<String, String> NetworkObject) {
		//process
		if(!netObject.isEmpty() && !netAddress.isEmpty()) {
			if(!NetworkObject.containsKey(netObject)) {
				NetworkObject.put(netObject, netAddress);
				
			}
		}
		 
	}
	
	private  static void putNewSubjExecObject(String subject, String cmdLine, HashMap<String, String> SubjExecObject) {
		//process
		if(!subject.isEmpty() && !cmdLine.isEmpty()) {
			if(!SubjExecObject.containsKey(subject)) {
				SubjExecObject.put(subject, cmdLine);
				
			}
		}
		 
	}
	
	private  static void putNewFileObject(String fileObject, String fileName, HashMap<String, String> FileObject) {
		//process
		if(!fileObject.isEmpty() && !fileName.isEmpty()) {
			if(!FileObject.containsKey(fileObject)) {
				FileObject.put(fileObject, fileName);
				
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
		line = line.replaceAll("[#{}%\\]\\[\\s\\n:$=()]", "");
		
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
	
	private String getExecFromCmdLine(String cmdLine) {
		 cmdline = cleanCmd(cmdLine);
		 String exec = "";
		 if(!cmdline.isEmpty() || cmdline!=null) {
			    if(cmdline.contains(" ")) {
					String newproc = cmdline.substring(0,cmdline.indexOf(" "));
						String[] nnewproc = newproc.split("/"); //incase there is full path e.g. "/tmp/vUgefal"
						if(nnewproc.length>1) {
							exec = nnewproc[nnewproc.length-1];
						}else {
							exec = newproc;
						}
					}else {
						String[] nnewproc = cmdline.split("/"); //incase there is full path e.g. "/tmp/vUgefal"
						if(nnewproc.length>1) {
							exec = nnewproc[nnewproc.length-1];
						}else {
							exec = cmdline;
						}
					}
			}
		return exec;

	}
	
}
