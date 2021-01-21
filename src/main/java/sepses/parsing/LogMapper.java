package sepses.parsing;

public class LogMapper {
	public  String process;
	public  String timestamp;
	public  String counter;
	public  String writes;
	public  String sends;
	public  String isExecutedBy;
	public  String isLoadBy;
	public  String isReceivedBy;
	public  String isReadBy;
	public  String forks;
	public  String confTag;
	public  String intTag;
	public  String subjTag;
	public  String file;
	public  String network;
	public  String s;
	public  String a;
	public  String dot;
	public  String highTag;
	public  String lowTag;
	public  String cmdLine;
	public  String hasExe;
	public  String originatesFrom;
	public  String hasUser;
	public  String exe;
	public  String host;
	public  String user;
	public  String time;
	
	public LogMapper(){
	//property 
		writes = "<http://w3id.org/sepses/vocab/event/log#writes>";
		hasExe = "<http://w3id.org/sepses/vocab/event/log#hasExe>";
		originatesFrom = "<http://w3id.org/sepses/vocab/event/log#originatesFrom>";
		hasUser = "<http://w3id.org/sepses/vocab/event/log#hasUser>";
		sends = "<http://w3id.org/sepses/vocab/event/log#sends>";
		isExecutedBy = "<http://w3id.org/sepses/vocab/event/log#isExecutedBy>";
		isLoadBy = "<http://w3id.org/sepses/vocab/event/log#isLoadBy>";
		isReceivedBy = "<http://w3id.org/sepses/vocab/event/log#isReceivedBy>";
		isReadBy = "<http://w3id.org/sepses/vocab/event/log#isReadBy>";
		forks = "<http://w3id.org/sepses/vocab/event/log#forks>";
		cmdLine = "<http://w3id.org/sepses/vocab/event/log#cmdLine>";
		timestamp = "<http://w3id.org/sepses/vocab/event/log#timestamp>";
		a = "<http://www.w3.org/1999/02/22-rdf-syntax-ns#type>";
	//tag-property
		intTag = "<http://w3id.org/sepses/vocab/rule#intTag>";
		confTag = "<http://w3id.org/sepses/vocab/rule#confTag>";
		subjTag = "<http://w3id.org/sepses/vocab/rule#subjTag>";
		counter = "<http://w3id.org/sepses/vocab/rule#counter>";
	//tag-value
		highTag = "\"1.0\"^^<http://www.w3.org/2001/XMLSchema#double>";
		lowTag = "\"0.0\"^^<http://www.w3.org/2001/XMLSchema#double>";
	//others
		s = " ";
		dot = ".\r\n";
	}
	 
	public  String writeMap(String subject, String exec, String objectString, String hostId, String userId, String ts) {	
		process = "<http://w3id.org/sepses/resource/proc"+subject+"#"+exec+">";
		file = "<http://w3id.org/sepses/resource/file#"+objectString+">";
		
		return  process +s+ writes +s+ file +dot 
				+ addTriple(process, exec, hostId, userId)
				+ addTime(process,writes,file,ts);
	}
	
	

	public  String readMap(String subject, String exec, String objectString,  String hostId, String userId, String ts) {
		process = "<http://w3id.org/sepses/resource/proc"+subject+"#"+exec+">";
		file = "<http://w3id.org/sepses/resource/file#"+objectString+">";
		
		return	file +s+ isReadBy +s+ process +dot
				+ addTriple(process, exec, hostId, userId)
				+ addTime(file,isReadBy,process,ts);			         
		
	}

	public  String executeMap(String subject, String newproc, String objectString, String cmd, String hostId, String userId, String ts) {

		file = "<http://w3id.org/sepses/resource/file#"+objectString+">";
		String process2 = "<http://w3id.org/sepses/resource/proc"+subject+"#"+newproc+">";
		String cmdline = "\""+cmd+"\"^^<http://www.w3.org/2001/XMLSchema#string>";
				
		String executeMap =  
				   file +s+ isExecutedBy +s+ process2 +dot 
				   +process2 +s+ cmdLine +s+ cmdline + dot 
				   + addTriple(process2, newproc, hostId, userId)
				   + addTime(file,isExecutedBy,process2,ts);		
		
		return executeMap;
		
	}
	
	public  String sendMap(String subject, String exec, String ip, String hostId, String userId, String ts) {
		
		process = "<http://w3id.org/sepses/resource/proc"+subject+"#"+exec+">";
		String ipAddress = "<http://w3id.org/sepses/resource/soc#"+ip+">";
		
		return process +s+ sends +s+ ipAddress +dot
				+ addTriple(process, exec, hostId, userId)
				+ addTime(process, sends, ipAddress, ts);
		
	}
	
	public  String receiveMap(String subject, String exec, String ip, String hostId, String userId, String ts) {
		process = "<http://w3id.org/sepses/resource/proc"+subject+"#"+exec+">";
		String ipAddress = "<http://w3id.org/sepses/resource/soc#"+ip+">";
		
		return  ipAddress +s+ isReceivedBy +s+ process +dot 
				+ addTriple(process, exec, hostId, userId)
				+ addTime(ipAddress,isReceivedBy,process,ts);
		
	}
	
	public  String forkMap(String prevProcess, String process, String ts) {
		
		String prevProc = "<http://w3id.org/sepses/resource/proc"+prevProcess+">";
		String proc = "<http://w3id.org/sepses/resource/proc"+process+">";
		
		return prevProc +s+ forks +s+ proc +dot
				+ addTime(prevProc,forks,proc,ts);
				
	}
	
public  String userMap(String userId, String userType, String userName) {
		String user = "<http://w3id.org/sepses/resource/user#"+userId+">";
		String userT = "<http://w3id.org/sepses/vocab/event/log#"+userType+">";
		userName = "\""+userName+"\"^^<http://www.w3.org/2001/XMLSchema#string>";
		String username = "<http://w3id.org/sepses/vocab/event/log#userName>";
		return user +s+ a +s+ userT +s+ dot+
				user +s+ username +s+ userName +dot;
		
	}

public  String networkMap(String netObject, String ip, String port) {
	String network = "<http://w3id.org/sepses/resource/soc#"+netObject+">";
	String netip = "<http://w3id.org/sepses/resource/ip#"+ip+">";
	String netport = "\""+port+"\"^^<http://www.w3.org/2001/XMLSchema#integer>";
	String hasSocketIP = "<http://w3id.org/sepses/vocab/event/log#hasSocketIP>";
	String pport = "<http://w3id.org/sepses/vocab/event/log#port>";
	return network +s+ hasSocketIP +s+ netip +s+ dot+
			network +s+ pport +s+ netport +dot;
	
}

public  String hostMap(String hostObject,String hostName, String hostOS, String ip) {
	String host = "<http://w3id.org/sepses/resource/host#"+hostObject+">";
	String hostip = "<http://w3id.org/sepses/resource/ip#"+ip+">";
	String hostname = "\""+hostName+"\"^^<http://www.w3.org/2001/XMLSchema#string>";
	String hostos = "\""+hostOS+"\"^^<http://www.w3.org/2001/XMLSchema#string>";
	String hasHostIP = "<http://w3id.org/sepses/vocab/event/log#hasHostIP>";
	String phostname = "<http://w3id.org/sepses/vocab/event/log#hostName>";
	String phostos = "<http://w3id.org/sepses/vocab/event/log#hostOS>";
	return host +s+ hasHostIP +s+ hostip +s+ dot+
			host +s+ phostname +s+ hostname +dot+
			host +s+ phostos +s+ hostos +dot;
	
}


	public  String initialConfFileTagMap(String objectString) {
		file = "<http://w3id.org/sepses/resource/file#"+objectString+">";
		String initialFileTagMap = file +s+ intTag +s+ lowTag +dot+
								   file +s+ confTag +s+ lowTag +dot;         
		return initialFileTagMap;
	}
	
	public  String initialProcessTagMap(String process) {
		String proc = "<http://w3id.org/sepses/resource/proc"+process+">";
		String initialProcessTagMap =  proc +s+ subjTag +s+ highTag +dot+
				 						proc +s+ confTag +s+ highTag +dot+
				 						proc +s+ intTag +s+ highTag +dot;         
		return initialProcessTagMap;
	}
	public  String initialFileTagMap(String file) {
		String f = "<http://w3id.org/sepses/resource/file#"+file+">";
		String initialFileTagMap = f +s+ confTag +s+ highTag +dot+
								   f +s+ intTag +s+ highTag +dot;         
		return initialFileTagMap;
	}
	public  String initialNetworkTagMap(String network) {
		String n = "<http://w3id.org/sepses/resource/soc#"+network+">";
		String initialNetworkTagMap = n +s+ confTag +s+ highTag +dot+
								   n +s+ intTag +s+ lowTag +dot;         
		return initialNetworkTagMap;
	}
	
	private String addTriple(String proc, String exec, String hostId, String userId) {
		exe = "<http://w3id.org/sepses/resource/exe#"+exec+">";
		host = "<http://w3id.org/sepses/resource/host#"+hostId+">";
		user = "<http://w3id.org/sepses/resource/user#"+userId+">";
		
		return  proc +s+ hasExe +s+ exe +dot
				+ proc +s+ originatesFrom +s+ host +dot
				+ proc +s+ hasUser +s+ user +dot;
	}
	
	private String addTime(String subject, String predicate,String object, String time) {
		String strTime = "\""+time+"\"^^<http://www.w3.org/2001/XMLSchema#integer>";
		String initCounter = "\"0\"^^<http://www.w3.org/2001/XMLSchema#integer>";
		String addTimeTriple = "<<" +s+ subject +s+ predicate +s+ object +s+ ">>"+s+ timestamp +s+ strTime +dot;
		String addCounter = "<<" +s+ subject +s+ predicate +s+ object +s+ ">>"+s+ counter +s+ initCounter +dot;
		return addTimeTriple+addCounter;
	}
	
	//========Windows Only!===========================
	public  String registryMap(String regId, String regKey, String regValType, String regValName) {
		String registry = "<http://w3id.org/sepses/resource/reg#"+regId+">";
		String registryKey = "\""+regKey+"\"^^<http://www.w3.org/2001/XMLSchema#string>";
		String registryValueType = "\""+regValType+"\"^^<http://www.w3.org/2001/XMLSchema#string>";
		String registryValueName = "\""+regValName+"\"^^<http://www.w3.org/2001/XMLSchema#integer>";
		String registrykey = "<http://w3id.org/sepses/vocab/event/log#registryKey>";
		String registryvaluetype = "<http://w3id.org/sepses/vocab/event/log#registryValueType>";
		String registryvaluename = "<http://w3id.org/sepses/vocab/event/log#registryValueName>";
		
		return registry +s+ registrykey +s+ registryKey +dot+
				registry +s+ registryvaluetype +s+ registryValueType +dot+
				registry +s+ registryvaluename +s+ registryValueName +dot;
		
	}

	public  String memoryMap(String memId, String memAddress) {
		String memory = "<http://w3id.org/sepses/resource/mem#"+memId+">";
		String memoryAddress = "\""+memAddress+"\"^^<http://www.w3.org/2001/XMLSchema#string>";
		String memoryaddress = "<http://w3id.org/sepses/vocab/event/log#memoryAddress>";
		
		return memory +s+ memoryaddress +s+ memoryAddress +dot;
	}
	public  String initialRegistryTagMap(String registry) {
		String n = "<http://w3id.org/sepses/resource/reg#"+registry+">";
		String initialRegistryTagMap = n +s+ confTag +s+ highTag +dot+
								   n +s+ intTag +s+ highTag +dot;         
		return initialRegistryTagMap;
	}
	
	public  String subjectMap(String subject,String exec, String cmd) {
		process = "<http://w3id.org/sepses/resource/proc"+subject+"#"+exec+">";
		//String cmdline = cmd+"^^<http://www.w3.org/2001/XMLSchema#string>";
		String subjMap = process +s+ cmdLine +s+ "\""+cmd+"\"" +dot;     
		return subjMap;
	}
	
	public  String executeWinMap(String subject, String exec, String objectString, String hostId, String userId, String ts) {

		file = "<http://w3id.org/sepses/resource/file#"+objectString+">";
		String process = "<http://w3id.org/sepses/resource/proc"+subject+"#"+exec+">";
		//time = "\""+ts + "\"^^<http://www.w3.org/2001/XMLSchema#dateTime>";

		
		String executeMap =  
				   file +s+ isExecutedBy +s+ process +dot+ 
				   //"<<" +s+ file +s+ isExecutedBy +s+ process2 +s+ ">>"+s+ timestamp +s+ time +dot
				   addTriple(process, exec, hostId, userId);
		
		return executeMap;
		
	}
	
	public  String loadLibraryMap(String subject, String exec, String objectString, String hostId, String userId, String ts) {

		file = "<http://w3id.org/sepses/resource/file#"+objectString+">";
		String process = "<http://w3id.org/sepses/resource/proc"+subject+"#"+exec+">";
		//time = "\""+ts + "\"^^<http://www.w3.org/2001/XMLSchema#dateTime>";

		
		String loadMap =  
				   file +s+ isLoadBy +s+ process +dot+ 
				   //"<<" +s+ file +s+ isExecutedBy +s+ process2 +s+ ">>"+s+ timestamp +s+ time +dot
				   addTriple(process, exec, hostId, userId);
		
		return loadMap;
		
	}

	//================end windows only!==============
	
}