package sepses.parsing;

public class LogMapping {
	public  String entitySubject;
	public  String entityObject;
	public  String entityNetwork;
	public  String process;
	public  String a;
	public  String hasSubject;
	public  String writes;
	public  String write;
	public  String read;
	public  String sends;
	public  String isReceivedBy;
	public  String isExecutedBy;
	public  String isReadBy;
	public  String remoteAddress;
	public  String forks;
	public  String confTag;
	public  String intTag;
	public  String subjTag;
	public  String file;
	public  String network;
	public  String fileType;
	public  String processType;
	public  String networkType;
	public  String s;
	public  String dot;
	public  String highTag;
	public  String lowTag;
	public  String cmdLine;
	public  String hasCmd;
	
	public LogMapping(){
	//property
		a =  "<http://www.w3.org/1999/02/22-rdf-syntax-ns#type>";
		hasSubject = "<http://ss.l/dp#hasSubject>"; 
		writes = "<http://ss.l/dp#writes>";
		write = "<http://ss.l/dp#write>";
		read = "<http://ss.l/dp#read>";
		sends = "<http://ss.l/dp#sends>";
		isReceivedBy = "<http://ss.l/dp#isReceivedBy>";
		isExecutedBy = "<http://ss.l/dp#isExecutedBy>";
		isReadBy = "<http://ss.l/dp#isReadBy>";
		remoteAddress= "<http://ss.l/dp#remoteAddress>";
		forks = "<http://ss.l/dp#forks>";
		hasCmd = "<http://ss.l/dp#hasCmd>";
	//type
		fileType = "<http://ss.l/dp#FileObject>";
		processType = "<http://ss.l/dp#Process>";
		networkType = "<http://ss.l/dp#Network>";
	//tag-property
		intTag = "<http://ss.l/dp#intTag>";
		confTag = "<http://ss.l/dp#confTag>";
		subjTag = "<http://ss.l/dp#subjTag>";
	//tag-value
		highTag = "\"1.0\"^^<http://www.w3.org/2001/XMLSchema#double>";
		lowTag = "\"0.0\"^^<http://www.w3.org/2001/XMLSchema#double>";
	//others
		s = " ";
		dot = ".\r\n";
	}
	 
	public  String writeMap(String subject, String exec, String objectString) {	
		process = "<http://ss.r/dp/proc/"+subject+"#"+exec+">";
		file = "<http://ss.r/dp/obj#"+objectString+">";
		
		String writeMap = process +s+ a +s+ processType + dot +
				          process +s+ writes +s+ file +dot +
				          file +s+ a +s+ fileType +dot;
		return writeMap;
	}
	
	public  String readMap(String subject, String exec, String objectString) {
		process = "<http://ss.r/dp/proc/"+subject+"#"+exec+">";
		file = "<http://ss.r/dp/obj#"+objectString+">";
		
		String readMap = file +s+ a +s+ fileType +dot+
				 		file +s+ isReadBy +s+ process +dot +
				 		process +s+ a +s+ processType + dot;
				         
		return readMap;
	}

	public  String executeMap(String subject, String newproc, String objectString, String cmdline) {

		file = "<http://ss.r/dp/obj#"+objectString+">";
		String process2 = "<http://ss.r/dp/proc/"+subject+"#"+newproc+">";
		cmdLine = "\""+cmdline+"\"^^<http://www.w3.org/2001/XMLSchema#string>";

		
		String executeMap =  file +s+ isExecutedBy +s+ process2 +dot +
				   process2 +s+ a +s+ processType + dot+
				   process2 +s+ hasCmd +s+ cmdLine + dot+
				   file +s+ a +s+ fileType +dot;
		
		return executeMap;
		
	}
	
	public  String sendMap(String subject, String exec, String ip) {
		
		process = "<http://ss.r/dp/proc/"+subject+"#"+exec+">";
		String ipAddress = "<http://ss.r/dp/obj#"+ip+">";
		
		String forkMap = process +s+ a +s+ processType + dot +
				         process +s+ writes +s+ ipAddress +dot+
				         ipAddress +s+ a +s+ networkType +dot; 
		
		
				         
		return forkMap;
	}
	
	public  String receiveMap(String subject, String exec, String ip) {
		process = "<http://ss.r/dp/proc/"+subject+"#"+exec+">";
		String ipAddress = "<http://ss.r/dp/obj#"+ip+">";
		String forkMap = process +s+ a +s+ processType + dot +
				         ipAddress +s+ isReadBy +s+ process +dot+
				         ipAddress +s+ a +s+ networkType +dot; 
		return forkMap;
	}
	
	
	public  String forkMap(String prevProcess, String process) {
		
		String prevProc = "<http://ss.r/dp/proc/"+prevProcess+">";
		String proc = "<http://ss.r/dp/proc/"+process+">";
		
		String forkMap = prevProc +s+ a +s+ processType + dot +
						 proc +s+ a +s+ processType + dot +
		          		 prevProc +s+ forks +s+ proc +dot;
		return forkMap;
	}
	
	public  String networkMap(String netObject, String netAddress) {
		entityNetwork ="<http://ss.r/dp/e#"+netObject+">";
		network = "<http://ss.r/dp/obj#"+netAddress+">";
				
		String networkMap = entityNetwork +s+ remoteAddress +s+ network +dot+
				            network +s+ a +s+ networkType +dot;         
		return networkMap;
	}
	
	
	public  String initialConfFileTagMap(String objectString) {
		file = "<http://ss.r/dp/obj#"+objectString+">";
		String initialFileTagMap = file +s+ intTag +s+ lowTag +dot+
								   file +s+ confTag +s+ lowTag +dot;         
		return initialFileTagMap;
	}
	
	public  String initialProcessTagMap(String process) {
		String proc = "<http://ss.r/dp/proc/"+process+">";
		String initialProcessTagMap =  proc +s+ subjTag +s+ highTag +dot+
				 						proc +s+ confTag +s+ highTag +dot+
				 						proc +s+ intTag +s+ highTag +dot;         
		return initialProcessTagMap;
	}
	public  String initialFileTagMap(String file) {
		String f = "<http://ss.r/dp/obj#"+file+">";
		String initialFileTagMap = f +s+ confTag +s+ highTag +dot+
								   f +s+ intTag +s+ highTag +dot;         
		return initialFileTagMap;
	}
	public  String initialNetworkTagMap(String network) {
		String n = "<http://ss.r/dp/obj#"+network+">";
		String initialNetworkTagMap = n +s+ confTag +s+ highTag +dot+
								   n +s+ intTag +s+ lowTag +dot;         
		return initialNetworkTagMap;
	}
	
	public  String writeNetMap(String subject, String exec, String object) {
		process = "<http://ss.r/dp/proc/"+subject+"#"+exec+">";
		entityObject = "<http://ss.r/dp/e#"+object+">";
		String writeNetMap = process +s+ a +s+ processType + dot +
				         process +s+ write +s+ entityObject +dot;
		return writeNetMap;
	}
	
	public  String readNetMap(String subject, String exec, String object) {
		process = "<http://ss.r/dp/proc/"+subject+"#"+exec+">";
		entityObject = "<http://ss.r/dp/e#"+object+">";
		String readNetMap = process +s+ a +s+ processType + dot +
				         process +s+ read +s+ entityObject +dot;
		return readNetMap;
	}
	
}