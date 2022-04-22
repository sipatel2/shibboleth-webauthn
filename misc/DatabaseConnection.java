package edu.duke.oit.idms.idmws.client.dbconn;

import java.beans.PropertyVetoException;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.Properties;

import com.mchange.v2.c3p0.ComboPooledDataSource;

import edu.duke.oit.idms.idmws.client.cfg.IdMClientConfig;

/**
 * @author shilen
 */
public abstract class DatabaseConnection {

  private ComboPooledDataSource cpds;

  protected DatabaseConnection(String driver, String url, String username, String password, String preferredTestQuery, String additionalProperties) {

    cpds = new ComboPooledDataSource();
    
    try {
      cpds.setDriverClass(driver);
    } catch (PropertyVetoException e) {
      throw new RuntimeException(e);
    }
    
    IdMClientConfig config = IdMClientConfig.getInstance();
    
    cpds.setJdbcUrl(url);
    cpds.setIdleConnectionTestPeriod(config.getPropertyInt("db.pool.idleConnectionTestPeriod", false, 100));
    cpds.setMaxIdleTime(config.getPropertyInt("db.pool.maxIdleTime", false, 100));
    cpds.setCheckoutTimeout(config.getPropertyInt("db.pool.checkoutTimeout", false, 30000));
    cpds.setMinPoolSize(config.getPropertyInt("db.pool.minPoolSize", false, 0));
    cpds.setPreferredTestQuery(preferredTestQuery);
    cpds.setMaxPoolSize(config.getPropertyInt("db.pool.maxPoolSize", false, 100));
    
    Properties props = new Properties();
    
    if (additionalProperties != null) {
      String[] additionalPropertiesArray = additionalProperties.split(",");
      for (int i = 0; i < additionalPropertiesArray.length; i++) {
        String[] keyValue = additionalPropertiesArray[i].split("=");
        props.setProperty(keyValue[0], keyValue[1]);
      }
    }

    props.setProperty("user", username);
    props.setProperty("password", password);

    cpds.setProperties(props);
  }
  
  protected Connection getConnection() throws SQLException {
    Connection conn = cpds.getConnection();
    conn.setAutoCommit(false);
    return conn;
  }
  
  protected void finalize() throws Throwable {
    if (cpds != null) {
      cpds.close();
    }
    
    super.finalize();
  }
}
