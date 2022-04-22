package edu.duke.oit.idms.idmws.client.dbconn;

import edu.duke.oit.idms.idmws.client.cfg.IdMClientConfig;

/**
 * @author shilen
 */
public class ShibbolethDatabaseConnection extends DatabaseConnection {
  
  private static ShibbolethDatabaseConnection instance = null;
  
  protected ShibbolethDatabaseConnection() {
    super(IdMClientConfig.getInstance().getProperty("db.shibboleth.driver", true),
        IdMClientConfig.getInstance().getProperty("db.shibboleth.url", true), 
        IdMClientConfig.getInstance().getProperty("db.shibboleth.username", true), 
        IdMClientConfig.getInstance().getProperty("db.shibboleth.password", true),
        IdMClientConfig.getInstance().getProperty("db.shibboleth.pool.preferredTestQuery", true),
        IdMClientConfig.getInstance().getProperty("db.shibboleth.props", true));
    
    
  }

  protected static ShibbolethDatabaseConnection getInstance() {
    
    if (instance == null) {
      instance = new ShibbolethDatabaseConnection();
    }
    
    return instance;
  }
}