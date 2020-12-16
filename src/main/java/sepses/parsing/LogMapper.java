package sepses.parsing;

public class LogMapper {
	public  String entityNetwork;
	public  String process;
	public  String writes;
	public  String sends;
	public  String isExecutedBy;
	public  String isReceivedBy;
	public  String isReadBy;
	public  String remoteAddress;
	public  String forks;
	public  String confTag;
	public  String intTag;
	public  String subjTag;
	public  String file;
	public  String network;
	public  String s;
	public  String dot;
	public  String highTag;
	public  String lowTag;
	public  String cmdLine;
	public  String hasCmd;
	
	public LogMapper(){
	//property 
		writes = "<http://ss.l/dp#writes>";
		sends = "<http://ss.l/dp#sends>";
		isExecutedBy = "<http://ss.l/dp#isExecutedBy>";
		isReceivedBy = "<http://ss.l/dp#isReceivedBy>";
		isReadBy = "<http://ss.l/dp#isReadBy>";
		remoteAddress= "<http://ss.l/dp#remoteAddress>";
		forks = "<http://ss.l/dp#forks>";
		hasCmd = "<http://ss.l/dp#hasCmd>";
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
		
		return   process +s+ writes +s+ file +dot;
				        
	}
	
	public  String readMap(String subject, String exec, String objectString) {
		process = "<http://ss.r/dp/proc/"+subject+"#"+exec+">";
		file = "<http://ss.r/dp/obj#"+objectString+">";
		
		return	file +s+ isReadBy +s+ process +dot;
				         
		
	}

	public  String executeMap(String subject, String newproc, String objectString, String cmdline) {

		file = "<http://ss.r/dp/obj#"+objectString+">";
		String process2 = "<http://ss.r/dp/proc/"+subject+"#"+newproc+">";
		cmdLine = "\""+cmdline+"\"^^<http://www.w3.org/2001/XMLSchema#string>";

		
		String executeMap =  file +s+ isExecutedBy +s+ process2 +dot +
				   process2 +s+ hasCmd +s+ cmdLine + dot;
		
		return executeMap;
		
	}
	
	public  String sendMap(String subject, String exec, String ip) {
		
		process = "<http://ss.r/dp/proc/"+subject+"#"+exec+">";
		String ipAddress = "<http://ss.r/dp/obj#"+ip+">";
		return process +s+ sends +s+ ipAddress +dot;
		
	}
	
	public  String receiveMap(String subject, String exec, String ip) {
		process = "<http://ss.r/dp/proc/"+subject+"#"+exec+">";
		String ipAddress = "<http://ss.r/dp/obj#"+ip+">";
		return    ipAddress +s+ isReceivedBy +s+ process +dot; 
		
	}
	
	
	public  String forkMap(String prevProcess, String process) {
		
		String prevProc = "<http://ss.r/dp/proc/"+prevProcess+">";
		String proc = "<http://ss.r/dp/proc/"+process+">";
		
		return prevProc +s+ forks +s+ proc +dot;
		
	}
	
	public  String networkMap(String netObject, String netAddress) {
		entityNetwork ="<http://ss.r/dp/e#"+netObject+">";
		network = "<http://ss.r/dp/obj#"+netAddress+">";
				
		return entityNetwork +s+ remoteAddress +s+ network +dot;	 
		
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
	
	
}