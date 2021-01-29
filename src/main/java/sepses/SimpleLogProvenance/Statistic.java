package sepses.SimpleLogProvenance;

import org.apache.jena.query.QueryExecution;
import org.apache.jena.query.QueryExecutionFactory;
import org.apache.jena.query.QuerySolution;
import org.apache.jena.query.ResultSet;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.Resource;

public class Statistic {
	public static void countAlarm(Model alertModel){
		
		System.out.println("Statictics:");
		String query = "PREFIX rule: <http://w3id.org/sepses/vocab/rule#>\r\n" + 
				"select ?alert (count(?triple) as ?count) where { \r\n" + 
				"    ?triple rule:hasDetectedRule ?alert;\r\n" + 
				"} group by ?alert\r\n" + 
				"";
		
		QueryExecution qe = QueryExecutionFactory.create(query, alertModel);
        ResultSet rs = qe.execSelect();
        
        while (rs.hasNext()) {
            QuerySolution qs = rs.nextSolution();
            String a = qs.get("?alert").toString();
            int c = qs.get("?count").asLiteral().getInt();
            System.out.println(a+" : "+c);
        }
	}
}
