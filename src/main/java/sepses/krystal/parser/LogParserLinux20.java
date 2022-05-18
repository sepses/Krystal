package sepses.krystal.parser;
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

import sepses.krystal.AlertRule;
import sepses.krystal.PropagationRule;

public class LogParserLinux20 {
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
	public long logTimer;
	
	public LogParserLinux20(String line) {
			Any jsonNode=JsonIterator.deserialize(line);
			datumNode = jsonNode.get("datum");
			long timer  = datumNode.get("com.bbn.tc.schema.avro.cdm20.Event").get("timestampNanos").toLong();
			if(timer > 0) {
				this.logTimer = timer;
			}
	}
	
	public String parseJSONtoRDF(Model jsonModel, Model alertModel, ArrayList<String> fieldfilter, ArrayList<String> confidentialdir, HashMap<String, String> uuIndex, Set<String> Process, Set<String> File, Set<String> Network, HashMap<String, String> NetworkObject, HashMap<String, String> ForkObject , Set<String> lastEvent, String lastAccess, HashMap<String, String> UserObject, HashMap<String, String> FileObject, HashMap<String, String> SubjectCmd, String file, HashMap<String, String> CloneObject, String propagation, String attenuation, String decayrule,String policyrule, String signaturerule, ArrayList<Integer> counter) throws IOException{	
		//filter is the line is an event or not
		eventNode = datumNode.get("com.bbn.tc.schema.avro.cdm20.Event");
		if(eventNode.toBoolean()) {
			updateCounter(counter);
			eventType = eventNode.toString();
			if(!filterLine(eventType, fieldfilter)){
				String mapper = "";
				LogMapper lm = new LogMapper();	
				subject = shortenUUID(eventNode.get("subject").get("com.bbn.tc.schema.avro.cdm20.UUID").toString(),uuIndex);
				hostId = eventNode.get("hostId").toString();
			    String subjCmd = getSubjectCmd(subject, SubjectCmd);
			    exec = getExecFromCmdLine(subjCmd);
				long ts = eventNode.get("timestampNanos").toLong();
				String sts = eventNode.get("timestampNanos").toString();
				String strTime = new Timestamp(ts/1000000).toString();
				userId = getUserId(subject, UserObject);
				object = shortenUUID(eventNode.get("predicateObject").get("com.bbn.tc.schema.avro.cdm20.UUID").toString(),uuIndex);
				String networkMap="";
				
				PropagationRule prop = new PropagationRule();
				
				//initial value for tag decay
				double period = 0.25;
				double Tb = 0.75;
				double Te = 0.45;
				
				if (decayrule!="false") {
				  if(ts!=0 && !eventType.contains("EVENT_CLONE")) {
					prop.decayIndividualProcess(jsonModel,  subject+"#"+exec, ts, period, Tb, Te);
				   }
				}
				
				
				  if(eventType.contains("EVENT_WRITE")) {
					 
					  String fileName = getFileName(object, FileObject);
					
						
					  
						if(!fileName.isEmpty()) {
							 
							String curWrite = subject+exec+fileName+"write";
							if	(!lastAccess.contains(curWrite)) {				
								mapper = lm.writeMap(subject,exec,fileName,hostId,userId, timestamp);
								Reader targetReader = new StringReader(mapper);
								jsonModel.read(targetReader, null, "N-TRIPLE");
		
								if(policyrule!="false") {
									AlertRule alert = new AlertRule();
									alert.corruptFileAlert(jsonModel, alertModel, subject+"#"+exec, fileName, sts);
								}
							

								if (attenuation!="false") {
									   prop.writeTagWithAttenuation(jsonModel, attenuation, decayrule, sts, Tb, Te);
									}else {
									   prop.writeTag(jsonModel, fileName, curWrite, sts);
									}
								
								
								lastAccess = curWrite;									
							}
						}
					  
					}else if(eventType.contains("EVENT_READ")) {
						
						  String fileName = getFileName(object, FileObject);
						  	if(!fileName.isEmpty()) {						
						  		String curRead = subject+exec+fileName+"read";
								if	(!lastAccess.contains(curRead)) {				
									mapper = lm.readMap(subject,exec,fileName,hostId,userId,timestamp);			
									Reader targetReader = new StringReader(mapper);
									jsonModel.read(targetReader, null, "N-TRIPLE");
																
									if(policyrule!="false") {
										AlertRule alert = new AlertRule();
										alert.reconnaissanceReadAlert(jsonModel,alertModel, subject+"#"+exec, fileName, sts);
									}
									
									prop.readTag(jsonModel, subject, exec, fileName);										
									lastAccess = curRead;
								}
							}	
						
					
					}else if(eventType.contains("EVENT_EXECUTE")) {	
						String fileName = getFileName(object, FileObject);
						//use new cmd line from file execution
						String newSubjCmd = eventNode.get("properties").get("map").get("cmdLine").toString();
						String newExec = getExecFromCmdLine(newSubjCmd);
						
						if(!newSubjCmd.equals(subjCmd)) {  //create new subj if new cmd is not the same with the parent cmd
						  if(isEntityNew(subject+"#"+newExec, Process)) {
								String newSubj = lm.subjectMap(subject,newExec,newSubjCmd);	
								String newProcessMap = lm.initialProcessTagMap(subject+"#"+newExec);
									Reader targetReader2 = new StringReader(newSubj+newProcessMap);
							  	    jsonModel.read(targetReader2, null, "N-TRIPLE");
									prop.putProcessTime(jsonModel, subject, newExec, ts);	
						  }
						}
						
						if(!fileName.isEmpty()) {						
							mapper = lm.executeMap(subject,newExec, fileName, newSubjCmd, hostId, userId, timestamp);
							Reader targetReader2 = new StringReader(mapper);
					  	    jsonModel.read(targetReader2, null, "N-TRIPLE");
							 				
							storeEntity(subject+"#"+newExec, Process);
							
							if(decayrule!="false") {
							  prop.decayIndividualProcess(jsonModel,  subject+"#"+newExec, ts, period, Tb, Te);
							}
							
							if(policyrule!="false") {
								AlertRule alert = new AlertRule();
								alert.changePermAlert(jsonModel, alertModel, subject+"#"+exec, fileName, sts);
								alert.execAlert(jsonModel,alertModel, subject+"#"+newExec, fileName, sts);
							}
						
							
							prop.execTag(jsonModel, subject, newExec, fileName);	
							
						}
					
					}else if(eventType.contains("EVENT_CLONE")) {
						String objCmd = getSubjectCmd(object, SubjectCmd);
						String objExec = getExecFromCmdLine(objCmd);
						forkEvent(lm, subject+"#"+exec, object+"#"+objExec, timestamp, jsonModel);
											
					}else if(eventType.contains("EVENT_MODIFY_FILE_ATTRIBUTES")) {
						
						String fileName = getFileName(object, FileObject);
						
						if(!fileName.isEmpty()) {						
							mapper = lm.changePerm(subject,exec,fileName,hostId,userId, timestamp);
								
								Reader targetReader = new StringReader(mapper);
								jsonModel.read(targetReader, null, "N-TRIPLE");
								
								
						}
					}
					else if(eventType.contains("EVENT_SENDTO")) {
						String IPAddress = getIpAddress(object, NetworkObject);
						if(!IPAddress.isEmpty() && !IPAddress.equals("NA:0") && !IPAddress.equals("NETLINK:0") ) {
							if(isEntityNew(IPAddress, Network)) {
								 networkMap = lm.initialNetworkTagMap(IPAddress);
							}
							
							String curSend = subject+exec+IPAddress+"send";
							if	(!lastAccess.contains(curSend)) {
								
								storeEntity(IPAddress, Network);
								mapper = lm.sendMap(subject,exec,IPAddress,hostId,userId, timestamp) + networkMap;	
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
						
						if(!IPAddress.isEmpty() && !IPAddress.equals("NA:0") && !IPAddress.equals("NETLINK:0")) {
							if(isEntityNew(IPAddress, Network)) {
								networkMap = lm.initialNetworkTagMap(IPAddress);
							}
							
								storeEntity(IPAddress, Network);
	
								mapper = lm.receiveMap(subject,exec,IPAddress,hostId,userId, timestamp) + networkMap;
								Reader targetReader = new StringReader(mapper);
								jsonModel.read(targetReader, null, "N-TRIPLE");
								
								prop.receiveTag(jsonModel, subject, exec, IPAddress);
					
						}
					}
				}
			 
		}else if(datumNode.get("com.bbn.tc.schema.avro.cdm20.NetFlowObject").toBoolean()) {
			networkNode = datumNode.get("com.bbn.tc.schema.avro.cdm20.NetFlowObject");
			netObject = shortenUUID(networkNode.get("uuid").toString(),uuIndex); 
			String ip = networkNode.get("remoteAddress").get("String").toString();
			String port =networkNode.get("remotePort").get("int").toString();
			netAddress = ip+":"+port;
			
			putNewNetworkObject(netObject, netAddress, NetworkObject);
			LogMapper lm = new LogMapper();	
			String mapper = lm.networkMap(netAddress,ip,port);		
			Reader targetReader = new StringReader(mapper);
			jsonModel.read(targetReader, null, "N-TRIPLE");

		}else if(datumNode.get("com.bbn.tc.schema.avro.cdm20.Subject").toBoolean()) {
		    subjectNode = datumNode.get("com.bbn.tc.schema.avro.cdm20.Subject");
			subject = shortenUUID(subjectNode.get("uuid").toString(),uuIndex);
			String userId = shortenUUID(subjectNode.get("localPrincipal").toString(),uuIndex); 
			String cmdLine = subjectNode.get("cmdLine").get("string").toString();
			exec = getExecFromCmdLine(cmdLine);
			
			putNewSubjectCmd(subject, cmdLine, SubjectCmd);
			putNewUserObject(subject, userId, UserObject);
			long time = subjectNode.get("startTimestampNanos").toLong();
			LogMapper lm = new LogMapper();	
			String processMap = lm.initialProcessTagMap(subject+"#"+exec); //initial tag for process
		    String mapper = lm.subjectMap(subject,exec,cmdLine);	
			Reader targetReader = new StringReader(mapper+processMap);
			jsonModel.read(targetReader, null, "N-TRIPLE");
			
			PropagationRule prop = new PropagationRule();  //these are for deca
			prop.putProcessTime(jsonModel, subject, exec, time);	
	
		}else if(datumNode.get("com.bbn.tc.schema.avro.cdm20.FileObject").toBoolean()) {
		    fileNode = datumNode.get("com.bbn.tc.schema.avro.cdm20.FileObject");
			String fileObject = shortenUUID(fileNode.get("uuid").toString(),uuIndex); 
			String fileName = cleanLine(fileNode.get("baseObject").get("properties").get("map").get("filename").toString()); 
			
			putNewFileObject(fileObject, fileName, FileObject);
			 LogMapper lm = new LogMapper();
			 
			String fileMap = ""; 
			 if(isConfidentialFile(fileName, confidentialdir)) {
					fileMap = lm.initialConfFileTagMap(fileName);	//initial tag for confidential file
				}else {
				    fileMap = lm.initialFileTagMap(fileName); //initial tag for file
				}
			 
			Reader targetReader = new StringReader(fileMap);
			jsonModel.read(targetReader, null, "N-TRIPLE");
			
		}else if(datumNode.get("com.bbn.tc.schema.avro.cdm20.Principal").toBoolean()) {
			userNode = datumNode.get("com.bbn.tc.schema.avro.cdm20.Principal");
			userId = shortenUUID(userNode.get("uuid").toString(),uuIndex); 
			String userType = getUserType(userNode.get("userId").toInt());
			String userName = userNode.get("username").get("string").toString(); 
				
			LogMapper lm = new LogMapper();	
			String mapper = lm.userMap(userId,userType,userName);	
			Reader targetReader = new StringReader(mapper);
			jsonModel.read(targetReader, null, "N-TRIPLE");
			
		}else if(datumNode.get("com.bbn.tc.schema.avro.cdm20.Host").toBoolean()) {
		    hostNode = datumNode.get("com.bbn.tc.schema.avro.cdm20.Host");
			hostId = hostNode.get("uuid").toString(); 
			//String hostType = hostNode.get("hostType").toString();
			String hostName = hostNode.get("hostName").toString();
			String hostOS = hostNode.get("osDetails").toString();
			String hostIP = hostNode.get("interfaces").get(1).get("ipAddresses").get(1).toString();
			
			LogMapper lm = new LogMapper();	
			String mapper = lm.hostMap(hostId,hostName,hostOS,hostIP);	
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
	private  static void putNewNetworkObject(String netObject, String netAddress, HashMap<String, String> NetworkObject) {
		//process
		if(!netObject.isEmpty() && !netAddress.isEmpty()) {
			if(!NetworkObject.containsKey(netObject)) {
				NetworkObject.put(netObject, netAddress);
				
			}
		}
		 
	}
	
	private  static void putNewSubjectCmd(String subject, String cmdLine, HashMap<String, String> SubjectCmd) {
		//process
		if(!subject.isEmpty() && !cmdLine.isEmpty()) {
			if(!SubjectCmd.containsKey(subject)) {
				SubjectCmd.put(subject, cmdLine);
				
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
		line = line.replaceAll("[\\n\\t:]", "");
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
	
private  static void updateCounter(ArrayList<Integer> counter) {
		
		int lastCounter = counter.get(0);
		counter.remove(0);
		counter.add(lastCounter+1);
		 
	}	
}
