package helper;

import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.protocol.ClientContext;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.protocol.BasicHttpContext;
import org.apache.http.protocol.HttpContext;
import org.apache.jena.sparql.modify.UpdateProcessRemoteForm;
import org.apache.jena.update.UpdateExecutionFactory;
import org.apache.jena.update.UpdateFactory;
import org.apache.jena.update.UpdateProcessor;
import org.apache.jena.update.UpdateRequest;

public class StorageHelper {

    public static void executeUpdate(String endpoint, String query, Boolean isUseAuth, String user, String pass) {

        UpdateRequest updateRequest = UpdateFactory.create(query);
        UpdateProcessor processor;

        if (isUseAuth) {
            processor = UpdateExecutionFactory.createRemoteForm(updateRequest, endpoint);
            HttpContext httpContext = new BasicHttpContext();
            CredentialsProvider provider = new BasicCredentialsProvider();
            provider.setCredentials(new AuthScope(AuthScope.ANY_HOST, AuthScope.ANY_PORT),
                    new UsernamePasswordCredentials(user, pass));
            httpContext.setAttribute(ClientContext.CREDS_PROVIDER, provider);
            ((UpdateProcessRemoteForm) processor).setHttpContext(httpContext);
        } else {
            processor = UpdateExecutionFactory.createRemote(updateRequest, endpoint);
        }

        processor.execute();
    }
}
