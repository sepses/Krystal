/*
 * Krystal framework is a free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * Contacting the authors:  Kabul Kurniawan (kabul.kurniawan@wu.ac.at)
 */

package sepses.krystal;

import java.util.ArrayList;
import java.util.Map;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.Options;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import sepses.krystal.helper.Utility;

/* general algorithm 	  
  1. Log Parsing (convert raw log data into structured, interpretable format e.g. (JSON)
  2. RDF Mapping (transform structured data e.g. (JSON) into RDF)
  3. Event Extraction (construct RDF data into meaningful event i.e. high level event, provenance)
  4. Propagation & alerting (do propagation to construct attack event & generate alert from the propagated vent  )
*/  

public class Main {
	
	private static final Logger log = LoggerFactory.getLogger(Main.class);
	
	public static void main( String[] args ) throws Exception
    {
		
		  Map<String, Object> s = Utility.readYamlFile("config.yaml");
		  //--------------basic configuration-------------------
		  String inputdir= s.get("input-dir").toString(); 
	      String line = s.get("line-number").toString();
	      String backupfile= s.get("backup-file").toString();
	      String outputdir= s.get("output-dir").toString();
	
	      //-------------targeted triple-store and namegraph-----
	       String livestore= s.get("live-store").toString();
	       String triplestore= s.get("triple-store").toString();
	       String sparqlEp =s.get("sparql-endpoint").toString();
	       String namegraph = s.get("namegraph").toString();
	       
	      //-------------system settings------------------------- 
	       String tdbdir= s.get("tdb-dir").toString();
	       String ontology= s.get("ontology").toString();
	       String osplatform= s.get("os-platform").toString();
	       
	       //------------threat detection techniques------------
	       String propagation = s.get("tag-propagation").toString();
	       String attenuation= s.get("tag-attenuation").toString();
	       //attenuation setting
		   double ab= Double.parseDouble(s.get("ab").toString());
		   double ae= Double.parseDouble(s.get("ae").toString());	       
		   String decayrule =s.get("tag-decay").toString();
		   //decay setting
		   double period= Double.parseDouble(s.get("period").toString());
		   double tb= Double.parseDouble(s.get("tb").toString());
		   double te= Double.parseDouble(s.get("te").toString());
	       String policyrule = s.get("policy-based-rule").toString();
	       String signaturerule =s.get("signature-based-rule").toString();
	       //sigma rule directory
	       String ruledir= s.get("rule-dir").toString();
	       String ruledirwin= s.get("rule-dir-win").toString();

		   
	       
	     //------------confidential directory--------------------
	       ArrayList<String> confidentialdir= (ArrayList<String>) s.get("confidential-dir");
	       
	     //------------audit events------------------------------
	       ArrayList<String> fieldfilter= (ArrayList<String>) s.get("field-filter");
	     
	       
		//=====commandline argument===========
		  Options options = new Options();
	      options.addOption("sl", true, "starting line, default 0");
	 
	      CommandLineParser parser = new DefaultParser();
	      CommandLine cmd = parser.parse(options, args); 
	      String startingLine = cmd.getOptionValue("sl");
	    //=====end commandline argument===========
	      
	
	      if(osplatform.contains("windows")) {
	    	  ruledir = ruledirwin;
	    	  
	      }
	    
  	    	  
	  	  //clean tdb dir
	  	  Utility.deleteFileInDirectory(tdbdir);
	  	  System.out.println(
	  			  "    __ __                 __        __   ______                                             __  \r\n"
	  	  		+ "   / //_/_______  _______/ /_____ _/ /  / ____/________ _____ ___  ___ _      ______  _____/ /__\r\n"
	  	  		+ "  / ,<  / ___/ / / / ___/ __/ __ `/ /  / /_  / ___/ __ `/ __ `__ \\/ _ \\ | /| / / __ \\/ ___/ //_/\r\n"
	  	  		+ " / /| |/ /  / /_/ (__  ) /_/ /_/ / /  / __/ / /  / /_/ / / / / / /  __/ |/ |/ / /_/ / /  / ,<   \r\n"
	  	  		+ "/_/ |_/_/   \\__, /____/\\__/\\__,_/_/  /_/   /_/   \\__,_/_/ /_/ /_/\\___/|__/|__/\\____/_/  /_/|_|  \r\n"
	  	  		+ "           /____/                                                                               \r\n"
	  	  		+ "\r\n"
	  	  		+ "");
	      
	  	System.out.println("Start running "+osplatform+" parser...");
	  	System.out.println("Threat detection techniques:");
	  	System.out.println("- Tag-Propagation: "+propagation);
	  	System.out.println("- Tag-Attenuation: "+attenuation);
	  	System.out.println("- Tag-Decay: "+decayrule);
	  	System.out.println("- Policy-Rule: "+policyrule);
	  	System.out.println("- Signature-Rule: "+signaturerule);
	  	  	
	  	
	      JsonRDFReader.readJson(inputdir, line, sparqlEp, namegraph, startingLine, 
	    		  outputdir, triplestore, backupfile, fieldfilter,
	    		  livestore, confidentialdir, tdbdir, ontology, ruledir, osplatform, propagation, attenuation,ab,ae,decayrule,period,tb,te,policyrule,signaturerule);
	    		  
    }
	
	
}
