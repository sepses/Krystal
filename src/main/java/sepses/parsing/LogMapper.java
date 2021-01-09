package sepses.parsing;

public class LogMapper {
	public  String entityNetwork;
	public  String process;
	public  String timestamp;
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
	public  String hasExe;
	public  String hasHost;
	public  String hasUser;
	public  String exe;
	public  String host;
	public  String user;
	
	public LogMapper(){
	//property 
		writes = "<http://ss.l/dp#writes>";
		hasExe = "<http://ss.l/dp#hasExe>";
		hasHost = "<http://ss.l/dp#hasHost>";
		hasUser = "<http://ss.l/dp#hasUser>";
		sends = "<http://ss.l/dp#sends>";
		isExecutedBy = "<http://ss.l/dp#isExecutedBy>";
		isReceivedBy = "<http://ss.l/dp#isReceivedBy>";
		isReadBy = "<http://ss.l/dp#isReadBy>";
		remoteAddress= "<http://ss.l/dp#remoteAddress>";
		forks = "<http://ss.l/dp#forks>";
		hasCmd = "<http://ss.l/dp#hasCmd>";
		timestamp = "<http://ss.l/dp#timestamp>";
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
	 
	public  String writeMap(String subject, String exec, String objectString, String hostId, String userId, String ts) {	
		process = "<http://ss.r/dp/proc/"+subject+"#"+exec+">";
		file = "<http://ss.r/dp/obj#"+objectString+">";
		exe = "<http://ss.r/dp/exe#"+exec+">";
		host = "<http://ss.r/dp/host#"+hostId+">";
		user = "<http://ss.r/dp/user#"+userId+">";
		String time = "\""+ts + "\"^^<http://www.w3.org/2001/XMLSchema#dateTime>";
		
		
		return  process +s+ writes +s+ file +dot 
				//"<<" +s+ process +s+ writes +s+ file +s+ ">>"+s+ timestamp +s+ time +dot 
				+ process +s+ hasExe +s+ exe +dot
				+ process +s+ hasHost +s+ host +dot
				+ process +s+ hasUser +s+ user +dot;
				        
	}
	
	public  String readMap(String subject, String exec, String objectString,  String hostId, String userId, String ts) {
		process = "<http://ss.r/dp/proc/"+subject+"#"+exec+">";
		file = "<http://ss.r/dp/obj#"+objectString+">";
		exe = "<http://ss.r/dp/exe#"+exec+">";
		host = "<http://ss.r/dp/host#"+hostId+">";
		user = "<http://ss.r/dp/user#"+userId+">";
		String time = "\""+ts + "\"^^<http://www.w3.org/2001/XMLSchema#dateTime>";
		
		return	file +s+ isReadBy +s+ process +dot
				//"<<" +s+ file +s+ isReadBy +s+ process +s+ ">>"+s+ timestamp +s+ time +dot
				+ process +s+ hasExe +s+ exe +dot
				+ process +s+ hasHost +s+ host +dot
				+ process +s+ hasUser +s+ user +dot;
				         
		
	}

	public  String executeMap(String subject, String newproc, String objectString, String cmdline, String hostId, String userId, String ts) {

		file = "<http://ss.r/dp/obj#"+objectString+">";
		String process2 = "<http://ss.r/dp/proc/"+subject+"#"+newproc+">";
		cmdLine = "\""+cmdline+"\"^^<http://www.w3.org/2001/XMLSchema#string>";
		exe = "<http://ss.r/dp/exe#"+newproc+">";
		host = "<http://ss.r/dp/host#"+hostId+">";
		user = "<http://ss.r/dp/user#"+userId+">";
		String time = "\""+ts + "\"^^<http://www.w3.org/2001/XMLSchema#dateTime>";

		
		String executeMap =  
				   file +s+ isExecutedBy +s+ process2 +dot 
				   //"<<" +s+ file +s+ isExecutedBy +s+ process2 +s+ ">>"+s+ timestamp +s+ time +dot
				   +process2 +s+ hasCmd +s+ cmdLine + dot +
				   process2 +s+ hasExe +s+ exe +dot
				   + process2 +s+ hasHost +s+ host +dot
				   + process2 +s+ hasUser +s+ user +dot;
		
		return executeMap;
		
	}
	
	public  String sendMap(String subject, String exec, String ip, String hostId, String userId, String ts) {
		
		process = "<http://ss.r/dp/proc/"+subject+"#"+exec+">";
		String ipAddress = "<http://ss.r/dp/obj#"+ip+">";
		exe = "<http://ss.r/dp/exe#"+exec+">";
		host = "<http://ss.r/dp/host#"+hostId+">";
		user = "<http://ss.r/dp/user#"+userId+">";
		String time = "\""+ts + "\"^^<http://www.w3.org/2001/XMLSchema#dateTime>";
		
		return process +s+ sends +s+ ipAddress +dot
				//"<<" +s+ process +s+ sends +s+ ipAddress +s+ ">>"+s+ timestamp +s+ time +dot
				+ process +s+ hasExe +s+ exe +dot
				 + process +s+ hasHost +s+ host +dot
				 + process +s+ hasUser +s+ user +dot;
		
	}
	
	public  String receiveMap(String subject, String exec, String ip, String hostId, String userId, String ts) {
		process = "<http://ss.r/dp/proc/"+subject+"#"+exec+">";
		String ipAddress = "<http://ss.r/dp/obj#"+ip+">";
		exe = "<http://ss.r/dp/exe#"+exec+">";
		host = "<http://ss.r/dp/host#"+hostId+">";
		user = "<http://ss.r/dp/user#"+userId+">";
		String time = "\""+ts + "\"^^<http://www.w3.org/2001/XMLSchema#dateTime>";
		
		return  ipAddress +s+ isReceivedBy +s+ process +dot 
				//"<<" +s+ ipAddress +s+ isReceivedBy +s+ process +s+ ">>"+s+ timestamp +s+ time +dot
				+ process +s+ hasExe +s+ exe +dot
				+ process +s+ hasHost +s+ host +dot
				+ process +s+ hasUser +s+ user +dot;
		
	}
	
	public  String forkMap(String prevProcess, String process, String ts) {
		
		String prevProc = "<http://ss.r/dp/proc/"+prevProcess+">";
		String proc = "<http://ss.r/dp/proc/"+process+">";
		String time = "\""+ts + "\"^^<http://www.w3.org/2001/XMLSchema#dateTime>";
		
		return prevProc +s+ forks +s+ proc +dot;
				//"<<" +s+ prevProc +s+ forks +s+ proc +s+ ">>"+s+ timestamp +s+ time +dot;
				
	}
	
public  String userMap(String userId, String userName) {
		String user = "<http://ss.r/dp/user#"+userId+">";
		userName = "\""+userName+"\"^^<http://www.w3.org/2001/XMLSchema#string>";
		String username = "<http://ss.l/dp#userName>";
		return user +s+ username +s+ userName +dot;
		
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