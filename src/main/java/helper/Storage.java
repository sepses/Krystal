package helper;

public interface Storage {

    /**
     * store data within selected triplestore (append into existing data)
     */
    public void storeData(String file, String endpoint, String namegraph, Boolean isUseAuth, String user,
            String pass);

    /**
     * store data within selected triplestore
     */
    public void replaceData(String file, String endpoint, String namegraph, Boolean isUseAuth, String user,
            String pass);

    /**
     * execute update query in selected triplestore
     */
    public void executeUpdate(String endpoint, String query, Boolean isUseAuth, String user, String pass);

}
