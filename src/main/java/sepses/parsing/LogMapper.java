package sepses.parsing;

public class LogMapper {
	public  String process;
	public  String timestamp;
	public  String writes;
	public  String sends;
	public  String isExecutedBy;
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
		//time = "\""+ts + "\"^^<http://www.w3.org/2001/XMLSchema#dateTime>";
		
		return  process +s+ writes +s+ file +dot 
				//"<<" +s+ process +s+ writes +s+ file +s+ ">>"+s+ timestamp +s+ time +dot 
				+ addTriple(process, exec, hostId, userId);
	}
	
	public  String readMap(String subject, String exec, String objectString,  String hostId, String userId, String ts) {
		process = "<http://w3id.org/sepses/resource/proc"+subject+"#"+exec+">";
		file = "<http://w3id.org/sepses/resource/file#"+objectString+">";
		//time = "\""+ts + "\"^^<http://www.w3.org/2001/XMLSchema#dateTime>";
		
		return	file +s+ isReadBy +s+ process +dot
				//"<<" +s+ file +s+ isReadBy +s+ process +s+ ">>"+s+ timestamp +s+ time +dot
				+ addTriple(process, exec, hostId, userId);
				         
		
	}

	public  String executeMap(String subject, String newproc, String objectString, String cmd, String hostId, String userId, String ts) {

		file = "<http://w3id.org/sepses/resource/file#"+objectString+">";
		String process2 = "<http://w3id.org/sepses/resource/proc"+subject+"#"+newproc+">";
		String cmdline = "\""+cmd+"\"^^<http://www.w3.org/2001/XMLSchema#string>";
		//time = "\""+ts + "\"^^<http://www.w3.org/2001/XMLSchema#dateTime>";

		
		String executeMap =  
				   file +s+ isExecutedBy +s+ process2 +dot 
				   //"<<" +s+ file +s+ isExecutedBy +s+ process2 +s+ ">>"+s+ timestamp +s+ time +dot
				   +process2 +s+ cmdLine +s+ cmdline + dot +
				   addTriple(process2, newproc, hostId, userId);
		
		return executeMap;
		
	}
	
	public  String sendMap(String subject, String exec, String ip, String hostId, String userId, String ts) {
		
		process = "<http://w3id.org/sepses/resource/proc"+subject+"#"+exec+">";
		String ipAddress = "<http://w3id.org/sepses/resource/soc#"+ip+">";
		//time = "\""+ts + "\"^^<http://www.w3.org/2001/XMLSchema#dateTime>";
		
		return process +s+ sends +s+ ipAddress +dot
				//"<<" +s+ process +s+ sends +s+ ipAddress +s+ ">>"+s+ timestamp +s+ time +dot
				+ addTriple(process, exec, hostId, userId);
		
	}
	
	public  String receiveMap(String subject, String exec, String ip, String hostId, String userId, String ts) {
		process = "<http://w3id.org/sepses/resource/proc"+subject+"#"+exec+">";
		String ipAddress = "<http://w3id.org/sepses/resource/soc#"+ip+">";
		//time = "\""+ts + "\"^^<http://www.w3.org/2001/XMLSchema#dateTime>";
		
		return  ipAddress +s+ isReceivedBy +s+ process +dot 
				//"<<" +s+ ipAddress +s+ isReceivedBy +s+ process +s+ ">>"+s+ timestamp +s+ time +dot
				+ addTriple(process, exec, hostId, userId);
		
	}
	
	public  String forkMap(String prevProcess, String process, String ts) {
		
		String prevProc = "<http://w3id.org/sepses/resource/proc"+prevProcess+">";
		String proc = "<http://w3id.org/sepses/resource/proc"+process+">";
		//time = "\""+ts + "\"^^<http://www.w3.org/2001/XMLSchema#dateTime>";
		
		return prevProc +s+ forks +s+ proc +dot;
				//"<<" +s+ prevProc +s+ forks +s+ proc +s+ ">>"+s+ timestamp +s+ time +dot;
				
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
	
	//========Windows Only!===========================
	public  String registryMap(String regId, String regKey, String regValType, String regValSize) {
		String registry = "<http://w3id.org/sepses/resource/reg#"+regId+">";
		String registryKey = "\""+regKey+"\"^^<http://www.w3.org/2001/XMLSchema#string>";
		String registryValueType = "\""+regValType+"\"^^<http://www.w3.org/2001/XMLSchema#string>";
		String registryValueSize = "\""+regValSize+"\"^^<http://www.w3.org/2001/XMLSchema#integer>";
		String registrykey = "<http://w3id.org/sepses/vocab/event/log#registryKey>";
		String registryvaluetype = "<http://w3id.org/sepses/vocab/event/log#registryValueType>";
		String registryvaluesize = "<http://w3id.org/sepses/vocab/event/log#registryValueSize>";
		
		return registry +s+ registrykey +s+ registryKey +dot+
				registry +s+ registryvaluetype +s+ registryValueType +dot+
				registry +s+ registryvaluesize +s+ registryValueSize +dot;
		
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

	//================end windows only!==============
	
}