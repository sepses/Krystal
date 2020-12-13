package helper;

import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;

public enum VirtuosoStorage implements Storage {

    INSTANCE();

    private static final Logger log = LoggerFactory.getLogger(VirtuosoStorage.class);

    public static VirtuosoStorage getInstance() {
        return INSTANCE;
    }

    public void storeData(String file, String endpoint, String namegraph, Boolean isUseAuth, String user,
            String pass) {
        try {
            log.info(file);
            if (!isUseAuth) {
                log.error("not handled yet");
                return;
            }

            long start = System.currentTimeMillis() / 1000;

            String url = endpoint + "-graph-crud-auth?graph-uri=" + namegraph;
            String command = "curl --digest -u " + user + ":" + pass + " -v -X POST -T " + file + " " + url;
            System.out.println(command);
            Process process = Runtime.getRuntime().exec(command);
            InputStream is = process.getInputStream();
            IOUtils.copy(is, System.out);
            is.close();
            log.info("Data stored successfully");

            long end = System.currentTimeMillis() / 1000;
            log.info("Writing process for '" + file + "' took " + (end - start) + " seconds");
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }

    }

    public void replaceData(String file, String endpoint, String namegraph, Boolean isUseAuth, String user,
            String pass) {
        try {

            long start = System.currentTimeMillis() / 1000;

            log.info(file);
            if (!isUseAuth) {
                log.error("not handled yet");
                return;
            }
            String url = endpoint + "-graph-crud-auth?graph-uri=" + namegraph;
            String command = "curl --digest -u " + user + ":" + pass + " -v -X PUT -T " + file + " " + url;
            Process process = Runtime.getRuntime().exec(command);
            InputStream is = process.getInputStream();
            IOUtils.copy(is, System.out);
            is.close();
            log.info("Data stored successfully");

            long end = System.currentTimeMillis() / 1000;
            log.info("Writing process for '" + file + "' took " + (end - start) + " seconds");
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }

    }

    public void executeUpdate(String endpoint, String query, Boolean isUseAuth, String user, String pass) {
        endpoint = endpoint + "-auth";
        StorageHelper.executeUpdate(endpoint, query, isUseAuth, user, pass);
    }
}
