package edu.duke.oit.idms.idmws.client.dbconn;

import java.sql.Connection;
import java.sql.SQLException;


/**
 * @author shilen
 */
public class DatabaseConnectionFactory {

  /**
   * @return connection
   * @throws SQLException
   */
  public static Connection getShibbolethDatabaseConnection() throws SQLException {
    return ShibbolethDatabaseConnection.getInstance().getConnection();
  }
}
